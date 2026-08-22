package smtpd

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
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

	// ranCommand says that the session ran a command already. A PROXY header
	// stands before everything else: the proxy writes it, and only then does
	// it pass on what the client sends. A PROXY command that comes later
	// therefore comes from the client behind the proxy, and it would write
	// the address that every hook after it reads.
	ranCommand bool

	// readErr holds the error that ended the reading of the connection. A
	// read that failed once fails from then on, in the way that a
	// bufio.Scanner stops for good. Without that, an AUTH command whose
	// continuation line is too long would leave the rest of that line in the
	// reader, and the session would read the credentials of the client as
	// commands.
	readErr error

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
// A read that failed once fails from then on. The rest of a line that was too
// long is still in the reader, and the session must not read it as commands.
//
// The session reads its lines here and not through a bufio.Scanner, because
// a scanner reads ahead. The octets of a BDAT chunk follow the command line
// on the same stream, and a scanner takes them into a buffer of its own,
// where nothing can read them again.
func (s *session) readLine() (string, error) {
	if s.readErr != nil {
		return "", s.readErr
	}

	var line []byte

	for {
		part, err := s.reader.ReadSlice('\n')

		if len(line)+len(part) > maxLineLength {
			s.readErr = bufio.ErrTooLong
			return "", s.readErr
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
			s.readErr = err
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
	result := s.stopChunk(errChunkAborted)

	ctx, done := s.reportChunkPanic(ctx, result)
	s.envelope = nil

	if done {
		// The panic closed the session, and the Disconnect hooks ran with
		// it. A Reset hook after them would come out of order.
		return contextWithoutSender(ctx)
	}

	// A handler that ended gives back a context, and what follows runs in
	// that one.
	if result != nil && result.ctx != nil {
		ctx = result.ctx
	}

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

func (s *session) flush(ctx context.Context) context.Context {
	_ = s.conn.SetWriteDeadline(time.Now().Add(s.server.WriteTimeout))
	_ = s.writer.Flush()
	_ = s.conn.SetReadDeadline(time.Now().Add(s.server.ReadTimeout))
	return ctx
}

func (s *session) deliver(ctx context.Context) (context.Context, error) {
	return s.server.deliver(ctx, s.peer, s.envelope)
}

func (s *session) close(ctx context.Context) context.Context {
	if s.closed {
		return ctx
	}
	s.closed = true

	// The session is closed already, so reportChunkPanic writes no reply and
	// the close inside it returns at once. The panic still reaches the log
	// and the Disconnect hooks below.
	ctx, _ = s.reportChunkPanic(ctx, s.stopChunk(errChunkAborted))

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
