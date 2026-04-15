package smtpd

import (
	"bufio"
	"context"
	"crypto/tls"
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

	log *slog.Logger
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
		// run handshake otherwise it's done when we first
		// read/write and connection state will be invalid
		_ = tlsConn.HandshakeContext(ctx)
		state := tlsConn.ConnectionState()
		s.peer.TLS = &state
	}

	s.scanner = bufio.NewScanner(s.reader)

	return ctx, s

}

func (session *session) serve(ctx context.Context) {

	// Closure so the deferred close sees the latest ctx after handlers
	// have threaded values through it.
	defer func() { session.close(ctx) }()

	if !session.server.EnableProxyProtocol {
		ctx = session.welcome(ctx)
	}

	for !session.closed {

		for session.scanner.Scan() {
			line := session.scanner.Text()
			session.log.DebugContext(ctx, "received", slog.String("line", strings.TrimSpace(line)))
			ctx = session.handle(ctx, line)
		}

		err := session.scanner.Err()

		if err == bufio.ErrTooLong {
			ctx = session.reply(ctx, 500, "Line too long")
			ctx = session.close(ctx)
		}

		break
	}

}

func (session *session) reject(ctx context.Context) context.Context {
	ctx = session.reply(ctx, 421, "Too busy. Try again later.")
	return session.close(ctx)
}

func (session *session) reset(ctx context.Context) context.Context {
	session.envelope = nil
	return ctx
}

func (session *session) welcome(ctx context.Context) context.Context {
	var err error
	ctx, err = session.server.checkConnection(ctx, session.peer)
	if err != nil {
		ctx = session.error(ctx, err)
		return session.close(ctx)
	}

	return session.reply(ctx, 220, session.server.WelcomeMessage)

}

func (session *session) reply(ctx context.Context, code int, message string) context.Context {
	session.log.DebugContext(ctx, "sending",
		slog.Int("code", code),
		slog.String("message", message),
	)
	// TODO: interrupt send?
	_, _ = fmt.Fprintf(session.writer, "%d %s\r\n", code, message)
	return session.flush(ctx)
}

func (session *session) flush(ctx context.Context) context.Context {
	_ = session.conn.SetWriteDeadline(time.Now().Add(session.server.WriteTimeout))
	_ = session.writer.Flush()
	_ = session.conn.SetReadDeadline(time.Now().Add(session.server.ReadTimeout))
	return ctx
}

func (session *session) error(ctx context.Context, err error) context.Context {
	if smtpdError, ok := err.(Error); ok {
		return session.reply(ctx, smtpdError.Code, smtpdError.Message)
	}
	return session.reply(ctx, 502, fmt.Sprintf("%s", err))
}

func (session *session) extensions() []string {

	extensions := []string{
		fmt.Sprintf("SIZE %d", session.server.MaxMessageSize),
		"8BITMIME",
		"PIPELINING",
	}

	if session.server.EnableXCLIENT {
		extensions = append(extensions, "XCLIENT")
	}

	if session.server.TLSConfig != nil && !session.tls {
		extensions = append(extensions, "STARTTLS")
	}

	if session.server.hasAuthenticator() && session.tls {
		extensions = append(extensions, "AUTH PLAIN LOGIN")
	}

	return extensions

}

func (session *session) deliver(ctx context.Context) (context.Context, error) {
	if session.server.Handler != nil {
		return ctx, session.server.Handler.ServeSMTP(ctx, session.peer, session.envelope)
	}
	return ctx, nil
}

func (session *session) close(ctx context.Context) context.Context {
	if session.closed {
		return ctx
	}
	session.closed = true
	_ = session.writer.Flush()
	_ = session.conn.Close()
	return ctx
}
