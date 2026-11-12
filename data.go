package smtpd

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"time"
)

func (s *session) handleDATA(ctx context.Context, cmd *command) context.Context {
	ctx, _ = phasedLoggerFromContext(ctx, "data")

	// RFC 3030 keeps the two ways of sending a message apart. The dot that
	// ends a DATA message has no meaning in the octets of a chunk, and a
	// message that already arrived in chunks is not a DATA message.
	//
	// This stands before the envelope, and not after it: the handler of a
	// chunked message runs on a goroutine of its own and can write to the
	// envelope, so the session reads nothing out of it while that lasts.
	if s.chunk != nil {
		return s.replyEnhanced(ctx, 503, EnhancedCode{5, 5, 1}, "DATA cannot follow BDAT in the same transaction")
	}

	if s.envelope == nil || len(s.envelope.Recipients) == 0 {
		return s.replyEnhanced(ctx, 503, EnhancedCode{5, 5, 1}, "Missing RCPT TO command.")
	}

	if s.envelope.BodyType == BodyBinaryMIME {
		return s.replyEnhanced(ctx, 503, EnhancedCode{5, 5, 1}, "A BINARYMIME message needs BDAT")
	}

	ctx = s.reply(ctx, 354, "Go ahead. End your data with <CR><LF>.<CR><LF>")
	_ = s.conn.SetDeadline(time.Now().Add(s.server.DataTimeout))

	body := &dataReader{
		r:   &dotReader{r: s.reader},
		max: s.server.MaxMessageSize,
	}
	s.envelope.Data = body

	ctx, deliverErr := s.deliver(ctx)

	// Always drain+close so the SMTP stream stays in sync even if the
	// handler bailed out early or forgot to close.
	_ = body.Close()

	if body.tooBig {
		ctx = s.replyDeliveryError(ctx, Error{
			Code:     552,
			Enhanced: EnhancedCode{5, 3, 4},
			Message: fmt.Sprintf(
				"Message exceeded max message size of %d bytes",
				s.server.MaxMessageSize,
			),
		})

		// The client was still sending when the drain gave up, so the rest
		// of the message is on the wire. Reading it costs without bound, and
		// leaving it would make the session read the body of the message as
		// SMTP commands. Close instead.
		if body.abandoned {
			return s.close(ctx)
		}

		return s.reset(ctx)
	}

	if body.readErr != nil && !errors.Is(body.readErr, io.EOF) {
		// Network or protocol error reading DATA; the connection is likely
		// dead. Record the cause for the Disconnect hook and return -
		// the outer loop will observe the same error on next read and
		// exit the session.
		s.setErr(body.readErr)
		return ctx
	}

	if deliverErr != nil {
		return s.reset(s.replyDeliveryError(ctx, deliverErr))
	}

	return s.reset(s.replyDelivery(ctx, "Thank you."))

}

// dataReader wraps the DATA dot-stream. Read returns errMessageTooLarge
// once the body crosses MaxMessageSize; Close drains whatever the handler
// didn't read so the next SMTP command lands on a clean boundary.
type dataReader struct {
	r   io.Reader
	max int

	n         int
	tooBig    bool
	abandoned bool
	readErr   error
	closed    bool
}

func (d *dataReader) Read(p []byte) (int, error) {
	if d.closed {
		return 0, io.EOF
	}
	if d.tooBig {
		return 0, errMessageTooLarge
	}
	n, err := d.r.Read(p)
	d.n += n
	if d.n > d.max {
		d.tooBig = true
		// Truncate what we hand back so callers never see more than max.
		overflow := min(d.n-d.max, n)
		n -= overflow
		d.n = d.max
		return n, errMessageTooLarge
	}
	if err != nil && !errors.Is(err, io.EOF) {
		d.readErr = err
	}
	return n, err
}

func (d *dataReader) Close() error {
	if d.closed {
		return nil
	}
	d.closed = true

	// Keep draining to detect oversize even if the handler stopped reading
	// early, and to re-sync the protocol past <CRLF>.<CRLF>. Reading stops
	// at twice the limit: that reaches the end of a message that is a little
	// over it, and it bounds the work for a client that keeps sending. The
	// caller closes the connection when the message does not end by then.
	limit := d.max * 2

	buf := make([]byte, 4096)
	for d.n < limit {
		want := min(len(buf), limit-d.n)
		n, err := d.r.Read(buf[:want])
		d.n += n
		if d.n > d.max {
			d.tooBig = true
		}
		if err != nil {
			if !errors.Is(err, io.EOF) {
				d.readErr = err
				return err
			}
			return nil
		}
	}

	d.abandoned = true
	return nil
}

var errMessageTooLarge = errors.New("smtpd: message exceeded max size")

// dotState says what a dotReader took off the stream since the last line
// break.
type dotState int

const (
	// dotLineStart: nothing. The next octet is the first one of a line.
	dotLineStart dotState = iota

	// dotLeading: a dot, as the first octet of a line.
	dotLeading

	// dotLeadingCR: a dot and a CR, as the first two octets of a line.
	dotLeadingCR

	// dotCR: a CR. The octet after it says whether a line break stands here.
	dotCR

	// dotInLine: an octet of a line that is not one of the above.
	dotInLine

	// dotEnd: the line that ends the message.
	dotEnd
)

// dotReader reads the body of a DATA message and takes the framing of RFC
// 5321 section 4.5.2 off it. A line that holds one dot and nothing else ends
// the message, and a longer line that begins with a dot loses that dot.
//
// <CRLF> is the one line break that the reader knows. RFC 5321 section 2.3.8
// gives no other one, and section 4.1.1.4 names <LF>.<LF> as a sequence that
// must not end a message. A CR or an LF that stands alone is therefore an
// octet of the line it stands in. No line begins after it, so a dot after it
// does not end the message, and it stays in the body.
//
// The end of the message is where the session starts to read commands again.
// A reader that finds it too early gives the rest of the message to the
// command loop. A client behind a relay then writes commands of its own into
// the session of that relay. textproto.Reader.DotReader does that: it takes a
// bare LF as a line break, so it cannot stand here.
//
// Read gives each <CRLF> as "\n". A CR or an LF that stands alone arrives as
// it came.
type dotReader struct {
	r     *bufio.Reader
	state dotState
}

// Read gives io.EOF at the end of the message, and io.ErrUnexpectedEOF for a
// stream that stops before it.
func (d *dotReader) Read(p []byte) (int, error) {
	n := 0

	for n < len(p) && d.state != dotEnd {
		c, err := d.r.ReadByte()
		if err != nil {
			if errors.Is(err, io.EOF) {
				err = io.ErrUnexpectedEOF
			}
			return n, err
		}

		// bareCR says that the CR that the state holds stands alone, because
		// c is not the LF of a line break. The CR then goes to the caller, and
		// c goes back to the stream. The next turn reads c as an octet of the
		// line.
		bareCR := false

		switch d.state {
		case dotLineStart:
			if c == '.' {
				d.state = dotLeading
				continue
			}
			if c == '\r' {
				d.state = dotCR
				continue
			}
			d.state = dotInLine

		case dotLeading:
			if c == '\r' {
				d.state = dotLeadingCR
				continue
			}
			// The line goes on after the dot, so the dot was the escape.
			d.state = dotInLine

		case dotLeadingCR:
			if c == '\n' {
				d.state = dotEnd
				continue
			}
			// The line goes on after the dot, so the dot was the escape.
			bareCR = true

		case dotCR:
			if c == '\n' {
				d.state = dotLineStart
			} else {
				bareCR = true
			}

		case dotInLine:
			if c == '\r' {
				d.state = dotCR
				continue
			}
		}

		if bareCR {
			if err := d.r.UnreadByte(); err != nil {
				return n, fmt.Errorf("smtpd: put an octet of the message back on the stream: %w", err)
			}
			c = '\r'
			d.state = dotInLine
		}

		p[n] = c
		n++
	}

	if d.state == dotEnd {
		return n, io.EOF
	}
	return n, nil
}
