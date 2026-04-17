package smtpd

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"time"
)

// Type session represents a client session with the SMTP server
type session struct {
	server *Server

	peer     Peer
	envelope *Envelope

	conn net.Conn

	reader  *bufio.Reader
	writer  *bufio.Writer
	scanner *bufio.Scanner

	tls    bool
	closed bool

	// closeErr records the first non-nil I/O error that ended the session
	// - TLS handshake failure, a terminal scanner error, or a DATA read
	// error. Middleware-level rejection errors are not recorded here;
	// they already produced an SMTP reply. Surfaced to Disconnect hooks.
	closeErr error

	log *slog.Logger
}

func (s *session) setErr(err error) {
	if err != nil && s.closeErr == nil {
		s.closeErr = err
	}
}

func (srv *Server) newSession(ctx context.Context, c net.Conn) (context.Context, *session) {

	logger := srv.newLogger()

	s := &session{
		server: srv,
		conn:   c,
		reader: bufio.NewReader(c),
		writer: bufio.NewWriter(c),
		peer: Peer{
			Addr:       c.RemoteAddr(),
			ServerName: srv.Hostname,
		},
		log: logger.With(slog.String("peer", c.RemoteAddr().String())),
	}

	ctx = contextWithLogger(ctx, s.log)

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

	s.scanner = bufio.NewScanner(s.reader)

	return ctx, s

}

func (s *session) serve(ctx context.Context) {

	// Closure so the deferred close sees the latest ctx after handlers
	// have threaded values through it.
	defer func() { s.close(ctx) }()

	// Implicit-TLS handshake (newSession) may have already failed; skip
	// straight to the deferred close so Disconnect fires with closeErr.
	if s.closeErr != nil {
		return
	}

	if !s.server.EnableProxyProtocol {
		ctx = s.welcome(ctx)
	}

	for s.scanner.Scan() {
		line := s.scanner.Text()
		s.log.DebugContext(ctx, "received", slog.String("line", strings.TrimSpace(line)))
		ctx = s.handle(ctx, line)
	}

	// Only inspect scanner.Err() if we didn't already finish via QUIT or
	// a handler-initiated close - reading from an already-closed conn
	// would otherwise clobber closeErr with a use-of-closed error.
	if s.closed {
		return
	}

	if err := s.scanner.Err(); err != nil {
		s.setErr(err)
		if errors.Is(err, bufio.ErrTooLong) {
			ctx = s.reply(ctx, 500, "Line too long")
		}
	}

}

func (s *session) reject(ctx context.Context) context.Context {
	ctx = s.reply(ctx, 421, "Too busy. Try again later.")
	return s.close(ctx)
}

func (s *session) reset(ctx context.Context) context.Context {
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

	return s.reply(ctx, 220, s.server.WelcomeMessage)

}

func (s *session) reply(ctx context.Context, code int, message string) context.Context {
	s.log.DebugContext(ctx, "sending",
		slog.Int("code", code),
		slog.String("message", message),
	)
	// TODO: interrupt send?
	_, _ = fmt.Fprintf(s.writer, "%d %s\r\n", code, message)
	return s.flush(ctx)
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
		return s.reply(ctx, smtpErr.Code, smtpErr.Message)
	}
	return s.reply(ctx, 502, err.Error())
}

func (s *session) extensions() []string {

	extensions := []string{
		fmt.Sprintf("SIZE %d", s.server.MaxMessageSize),
		"8BITMIME",
		"PIPELINING",
	}

	if s.server.EnableXCLIENT {
		extensions = append(extensions, "XCLIENT")
	}

	if s.server.TLSConfig != nil && !s.tls {
		extensions = append(extensions, "STARTTLS")
	}

	if s.server.hasAuthenticator() && s.tls {
		extensions = append(extensions, "AUTH PLAIN LOGIN")
	}

	return extensions

}

func (s *session) deliver(ctx context.Context) (context.Context, error) {
	var err error
	for _, h := range s.server.handlers {
		ctx, err = h(ctx, s.peer, s.envelope)
		if err != nil {
			return ctx, err
		}
	}
	if s.server.Handler != nil {
		return s.server.Handler(ctx, s.peer, s.envelope)
	}
	return ctx, nil
}

func (s *session) close(ctx context.Context) context.Context {
	if s.closed {
		return ctx
	}
	s.closed = true
	_ = s.writer.Flush()
	s.server.disconnect(ctx, s.peer, s.closeErr)
	_ = s.conn.Close()
	return ctx
}
