package smtpd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/textproto"
	"time"
)

func (s *session) handleDATA(ctx context.Context, cmd *command) context.Context {

	if s.envelope == nil || len(s.envelope.Recipients) == 0 {
		return s.reply(ctx, 502, "Missing RCPT TO command.")
	}

	ctx = s.reply(ctx, 354, "Go ahead. End your data with <CR><LF>.<CR><LF>")
	_ = s.conn.SetDeadline(time.Now().Add(s.server.DataTimeout))

	body := &dataReader{
		r:   textproto.NewReader(s.reader).DotReader(),
		max: s.server.MaxMessageSize,
	}
	s.envelope.Data = body

	ctx, deliverErr := s.deliver(ctx)

	// Always drain+close so the SMTP stream stays in sync even if the
	// handler bailed out early or forgot to close.
	_ = body.Close()

	if body.tooBig {
		return s.reset(s.reply(ctx, 552, fmt.Sprintf(
			"Message exceeded max message size of %d bytes",
			s.server.MaxMessageSize,
		)))
	}

	if body.readErr != nil && !errors.Is(body.readErr, io.EOF) {
		// Network or protocol error reading DATA; the connection is likely
		// dead. Return and let the outer loop observe it on next read.
		return ctx
	}

	if deliverErr != nil {
		return s.reset(s.replyError(ctx, deliverErr))
	}

	return s.reset(s.reply(ctx, 250, "Thank you."))

}

// dataReader wraps the DATA dot-stream. Read returns errMessageTooLarge
// once the body crosses MaxMessageSize; Close drains whatever the handler
// didn't read so the next SMTP command lands on a clean boundary.
type dataReader struct {
	r       io.Reader
	max     int
	n       int
	tooBig  bool
	readErr error
	closed  bool
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
		overflow := d.n - d.max
		if overflow > n {
			overflow = n
		}
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
	// early, and to re-sync the protocol past <CRLF>.<CRLF>.
	buf := make([]byte, 4096)
	for {
		n, err := d.r.Read(buf)
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
}

var errMessageTooLarge = errors.New("smtpd: message exceeded max size")
