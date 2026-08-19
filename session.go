package smtpd

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"runtime/debug"
	"time"
)

// Type session represents a client session with the SMTP server
type session struct {
	server *Server

	peer     Peer
	envelope *Envelope

	conn net.Conn

	reader *bufio.Reader
	writer *bufio.Writer

	// chunk carries the message of a BDAT transfer while it arrives. It is
	// nil outside such a transfer.
	chunk *chunkTransfer

	tls    bool
	closed bool

	// closeErr records the first non-nil I/O error that ended the session
	// - TLS handshake failure, a terminal read error, or an error while the
	// message arrived. Middleware-level rejection errors are not recorded here;
	// they already produced an SMTP reply. Surfaced to Disconnect hooks.
	closeErr error
}

func (s *session) setErr(err error) {
	if err != nil && s.closeErr == nil {
		s.closeErr = err
	}
}

func (srv *Server) newSession(ctx context.Context, c net.Conn) (context.Context, *session) {

	s := &session{
		server: srv,
		conn:   c,
		reader: bufio.NewReader(c),
		writer: bufio.NewWriter(c),
		peer: Peer{
			Addr:       c.RemoteAddr(),
			ServerName: srv.Hostname,
		},
	}

	ctx = contextWithLogger(ctx, srv.newLogger().With(slog.String("peer", c.RemoteAddr().String())))

	// Check if the underlying connection is already TLS.
	// This will happen if the Listerner provided Serve()
	// is from tls.Listen()

	var tlsConn *tls.Conn

	tlsConn, s.tls = c.(*tls.Conn)

	if s.tls {
		// Force the handshake now so ConnectionState is valid before the
		// first read/write. A failure here means the conn is dead;
		// record the cause so serve() can skip straight to its deferred
		// close and the Disconnect hook sees the handshake error.
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			s.closeErr = err
		} else {
			state := tlsConn.ConnectionState()
			s.peer.TLS = &state
		}
	}

	return ctx, s

}

// maxLineLength bounds one line from the client. RFC 5321 section 4.5.3.1
// gives 512 octets for a command line and 1000 for a line of a message, and
// the bound here is far above both, so that a long AUTH line or a long
// address still gets through.
//
// The session reads the command lines and the chunks of BDAT from one
// reader. Without a bound, a client that never writes a line break makes the
// server hold the memory of a line without end.
const maxLineLength = 64 * 1024

// readLine reads one line from the client. It gives the line without the
// line break at the end, in the way that bufio.ScanLines does: a "\n" ends
// the line, and a "\r" before it belongs to the break.
//
// A line longer than maxLineLength ends with bufio.ErrTooLong. The line break
// counts toward that length, because the bound is on what the server holds in
// memory for one line.
//
// The session reads its lines here and not through a bufio.Scanner, because
// a scanner reads ahead. The octets of a BDAT chunk follow the command line
// on the same stream, and a scanner takes them into a buffer of its own,
// where nothing can read them again.
func (s *session) readLine() (string, error) {
	var line []byte

	for {
		part, err := s.reader.ReadSlice('\n')

		if len(line)+len(part) > maxLineLength {
			return "", bufio.ErrTooLong
		}

		// ReadSlice gives a window into the buffer of the reader, and the
		// next read writes over it.
		line = append(line, part...)

		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}

		if err != nil {
			// A last line without a line break is still a command, which is
			// how the scanner of the standard library reads it.
			if errors.Is(err, io.EOF) && len(line) > 0 {
				return string(trimLineBreak(line)), nil
			}
			return "", err
		}

		return string(trimLineBreak(line)), nil
	}
}

// trimLineBreak takes the line break off the end of a line.
func trimLineBreak(line []byte) []byte {
	line = bytes.TrimSuffix(line, []byte("\n"))
	return bytes.TrimSuffix(line, []byte("\r"))
}

func (s *session) serve(ctx context.Context) {

	// Closure so the deferred close sees the latest ctx after handlers
	// have threaded values through it.
	defer func() { s.close(ctx) }()

	// Registered after the close defer, so it runs before it: the panic
	// becomes a 421 reply while the connection is still open, and the close
	// that follows reports it to the Disconnect hooks.
	defer func() {
		if v := recover(); v != nil {
			ctx = s.recovered(ctx, v)
		}
	}()

	// Implicit-TLS handshake (newSession) may have already failed; skip
	// straight to the deferred close so Disconnect fires with closeErr.
	if s.closeErr != nil {
		return
	}

	logger := LoggerFromContext(ctx)

	if !s.server.EnableProxyProtocol {
		ctx = s.welcome(ctx)
	}

	for {
		line, err := s.readLine()
		if err != nil {
			// A session that already finished through QUIT, or through a
			// close from a handler, reads from a closed connection here.
			// That error is not the one that ended the session.
			if s.closed || errors.Is(err, io.EOF) {
				return
			}

			s.setErr(err)
			if errors.Is(err, bufio.ErrTooLong) {
				ctx = s.replyEnhanced(ctx, 500, EnhancedCode{5, 5, 2}, "Line too long")
			}
			return
		}

		logger.DebugContext(ctx, "received", slog.String("line", redactLine(line)))
		ctx = s.handle(ctx, line)

		if s.closed {
			return
		}
	}

}

func (s *session) reject(ctx context.Context) context.Context {
	ctx = s.replyEnhanced(ctx, 421, EnhancedCode{4, 3, 2}, "Too busy. Try again later.")
	return s.close(ctx)
}

func (s *session) reset(ctx context.Context) context.Context {
	s.stopChunk(errChunkAborted)
	s.envelope = nil
	ctx = s.server.reset(ctx, s.peer)
	return contextWithoutSender(ctx)
}

func (s *session) welcome(ctx context.Context) context.Context {
	var err error
	ctx, err = s.server.checkConnection(ctx, s.peer)
	if err != nil {
		ctx = s.replyError(ctx, err)
		return s.close(ctx)
	}

	// The greeting carries no status code. RFC 2034 takes it out of the
	// extension, and the client has not sent EHLO at this point.
	return s.replyEnhanced(ctx, 220, EnhancedCode{}, s.server.WelcomeMessage)

}

// reply writes a single reply line with the generic status code for the
// class of code, such as "5.0.0" for a 550. Use replyEnhanced where a
// precise reason helps the client.
func (s *session) reply(ctx context.Context, code int, message string) context.Context {
	return s.replyEnhanced(ctx, code, defaultEnhancedCode(code), message)
}

// replyEnhanced writes a single reply line with the given status code. The
// zero value of enhanced leaves the status code out, which is what the
// greeting and the reply to HELO and EHLO need.
func (s *session) replyEnhanced(ctx context.Context, code int, enhanced EnhancedCode, message string) context.Context {
	status := s.status(enhanced)
	message = sanitizeReplyText(message)

	logger := LoggerFromContext(ctx)
	logger.DebugContext(ctx, "sending",
		slog.Int("code", code),
		slog.String("status", status),
		slog.String("message", message),
	)

	if status == "" {
		_, _ = fmt.Fprintf(s.writer, "%d %s\r\n", code, message)
		return s.flush(ctx)
	}

	_, _ = fmt.Fprintf(s.writer, "%d %s %s\r\n", code, status, message)
	return s.flush(ctx)
}

// replyMultiline writes first and rest as one reply, with the continuation
// mark on every line but the last. The lines carry no status code: this is
// the reply to EHLO, and RFC 2034 takes that reply out of the extension.
//
// The first line is a separate argument, so that a reply always has one.
func (s *session) replyMultiline(ctx context.Context, code int, first string, rest ...string) context.Context {
	logger := LoggerFromContext(ctx)

	lines := append([]string{first}, rest...)
	for _, line := range lines[:len(lines)-1] {
		line = sanitizeReplyText(line)
		logger.DebugContext(ctx, "sending",
			slog.Int("code", code),
			slog.String("message", line),
		)
		_, _ = fmt.Fprintf(s.writer, "%d-%s\r\n", code, line)
	}

	return s.replyEnhanced(ctx, code, EnhancedCode{}, lines[len(lines)-1])
}

// sanitizeReplyText makes text safe to write inside a reply line. Every
// control character becomes a space.
//
// The message of a middleware refusal often carries something that the client
// sent. The user name of an AUTH command is one example: the session decodes
// it from base64, so it holds any byte at all. A line break inside a reply
// ends that reply and starts a line of the client's choosing. The client then
// reads an answer to a command that the server never ran.
//
// A byte at 0x80 and above stays as it is, so a message in UTF-8 arrives
// whole.
func sanitizeReplyText(text string) string {
	if !hasControl(text) {
		return text
	}

	out := []byte(text)
	for i, c := range out {
		if isControl(c) {
			out[i] = ' '
		}
	}
	return string(out)
}

// hasControl reports whether text carries a control character, so that a
// text without one goes on the wire as it is.
func hasControl(text string) bool {
	for i := 0; i < len(text); i++ {
		if isControl(text[i]) {
			return true
		}
	}
	return false
}

// isControl reports whether c is a control character. RFC 5321 gives the text
// of a reply as printable characters.
func isControl(c byte) bool {
	return c < 0x20 || c == 0x7f
}

// status gives the text of the status code to write with a reply. It is
// empty when the client did not send EHLO.
//
// RFC 2034 makes the status code part of an extension, and the server
// offers that extension in the reply to EHLO. A client that sent HELO never
// saw the offer, so it gets the replies that it expects from RFC 5321.
func (s *session) status(enhanced EnhancedCode) string {
	if s.peer.Protocol != ESMTP {
		return ""
	}
	return enhanced.String()
}

func (s *session) flush(ctx context.Context) context.Context {
	_ = s.conn.SetWriteDeadline(time.Now().Add(s.server.WriteTimeout))
	_ = s.writer.Flush()
	_ = s.conn.SetReadDeadline(time.Now().Add(s.server.ReadTimeout))
	return ctx
}

func (s *session) replyError(ctx context.Context, err error) context.Context {
	var smtpErr Error
	if errors.As(err, &smtpErr) {
		return s.replyEnhanced(ctx, smtpErr.Code, smtpErr.enhanced(), smtpErr.Message)
	}
	return s.replyEnhanced(ctx, 502, EnhancedCode{5, 5, 1}, err.Error())
}

func (s *session) extensions() []string {

	extensions := []string{
		fmt.Sprintf("SIZE %d", s.server.MaxMessageSize),
		"8BITMIME",
		"BINARYMIME",
		"CHUNKING",
		"PIPELINING",
		"ENHANCEDSTATUSCODES",
	}

	if s.server.EnableDSN {
		extensions = append(extensions, "DSN")
	}

	if s.server.EnableXCLIENT {
		extensions = append(extensions, "XCLIENT")
	}

	if s.server.TLSConfig != nil && !s.tls {
		extensions = append(extensions, "STARTTLS")
	}

	if s.server.hasAuthenticator() && (s.tls || s.server.AllowInsecureAuth) {
		extensions = append(extensions, "AUTH PLAIN LOGIN")
	}

	return extensions

}

func (s *session) deliver(ctx context.Context) (context.Context, error) {
	return s.server.deliver(ctx, s.peer, s.envelope)
}

func (s *session) close(ctx context.Context) context.Context {
	if s.closed {
		return ctx
	}
	s.closed = true
	s.stopChunk(errChunkAborted)
	_ = s.writer.Flush()
	s.notifyDisconnect(ctx)
	_ = s.conn.Close()
	return ctx
}

// recovered turns a panic from a Handler or a phase hook into a PanicError on
// the session and a 421 reply. The connection closes afterwards, so the
// client does not continue on a session whose state is unknown.
func (s *session) recovered(ctx context.Context, v any) context.Context {
	return s.reportPanic(ctx, PanicError{Value: v, Stack: debug.Stack()})
}

// reportPanic writes a panic to the log and tells the client. The handler of
// a chunked message runs on a goroutine of its own and recovers its own
// panic, so it arrives here as a value and not through recover.
func (s *session) reportPanic(ctx context.Context, err PanicError) context.Context {
	s.setErr(err)

	LoggerFromContext(ctx).ErrorContext(ctx, "recovered a panic",
		slog.Any("panic", err.Value),
		slog.String("stack", string(err.Stack)),
	)

	if s.closed {
		return ctx
	}

	return s.replyEnhanced(ctx, 421, EnhancedCode{4, 3, 0}, "Service not available, closing transmission channel")
}

// notifyDisconnect runs the Disconnect hooks. A panic in a hook is contained
// here, because close runs from a deferred call in serve, after the recovery
// around the body of the session.
func (s *session) notifyDisconnect(ctx context.Context) {
	defer func() {
		if v := recover(); v != nil {
			LoggerFromContext(ctx).ErrorContext(ctx, "recovered a panic in a Disconnect hook",
				slog.Any("panic", v),
				slog.String("stack", string(debug.Stack())),
			)
		}
	}()

	s.server.disconnect(ctx, s.peer, s.closeErr)
}
