// Package smtpd implements an SMTP server with support for STARTTLS, authentication (PLAIN/LOGIN), XCLIENT and optional restrictions on the different stages of the SMTP session.
package smtpd

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"runtime/debug"
	"sync"
	"sync/atomic"
	"time"
)

// ErrServerClosed is returned by Serve/ListenAndServe after Shutdown.
var ErrServerClosed = errors.New("smtpd: server closed")

// Protocol identifies the SMTP variant selected by the client's greeting:
// SMTP after HELO, ESMTP after EHLO. Read it from Peer.Protocol in phase
// hooks and handlers.
type Protocol string

const (
	// SMTP is set on Peer.Protocol after a HELO greeting.
	SMTP Protocol = "SMTP"
	// ESMTP is set on Peer.Protocol after an EHLO greeting, which also
	// enables extensions advertised in the 250 response.
	ESMTP Protocol = "ESMTP"
)

// Peer describes the remote client. Fields are populated progressively as
// the SMTP session advances: Addr and ServerName are set at connection
// time, HeloName after HELO/EHLO, Protocol at the same point, TLS after
// a successful (implicit or STARTTLS) handshake, and Username after AUTH.
// A Peer is passed by value to every phase hook and handler, so hook
// implementations observe the peer state as of the current phase.
type Peer struct {
	HeloName   string
	Username   string
	Protocol   Protocol
	ServerName string
	Addr       net.Addr
	TLS        *tls.ConnectionState
}

// Error is the SMTP protocol error returned by middleware phase hooks
// (CheckConnection, CheckHelo, CheckSender, CheckRecipient, Authenticate)
// and by Handler to signal a wire-level rejection. Code is the 3-digit
// SMTP status code (for example 550 or 421) and Message is the text after
// the code in the reply line. The session layer inspects the returned error
// via errors.As: an Error produces "{Code} {Message}" on the wire, while
// any other non-nil error is reported as a generic 502.
//
// Enhanced holds the RFC 3463 status code. It is optional: the zero value
// takes the generic code for the class of Code, such as "5.0.0" for a 550.
// Set it to give the client a precise reason, such as {5, 7, 1} for a
// refused relay.
//
// The server writes the status code only to a client that sent EHLO, and
// only after that command. See EnhancedCode.
type Error struct {
	Code     int
	Enhanced EnhancedCode
	Message  string
}

// Error writes the code, the status code and the message. It leaves out a
// status code that the caller did not set, because the server writes one
// only to a client that sent EHLO. The generic code that such an error
// takes on the wire is a property of the session, not of the error.
func (e Error) Error() string {
	if e.Enhanced.valid() {
		return fmt.Sprintf("%d %s %s", e.Code, e.Enhanced, e.Message)
	}
	return fmt.Sprintf("%d %s", e.Code, e.Message)
}

// enhanced gives the status code to write for this error. An error that
// carries none takes the generic code for the class of Code.
func (e Error) enhanced() EnhancedCode {
	if e.Enhanced.valid() {
		return e.Enhanced
	}
	return defaultEnhancedCode(e.Code)
}

// PanicError is the error recorded on a session when a Handler or a
// middleware hook panics. Value is the value given to panic and Stack is the
// stack trace taken at the point of recovery. Disconnect hooks receive it
// through their err argument, and callers match it with errors.As.
type PanicError struct {
	Value any
	Stack []byte
}

func (e PanicError) Error() string {
	return fmt.Sprintf("smtpd: panic: %v", e.Value)
}

// Handler delivers a received message. It is the terminal stage of an SMTP
// transaction: the server invokes Server.Handler once per accepted message,
// after every middleware-contributed Handler stage has run. The returned
// context replaces the session context for any subsequent commands on the
// connection.
//
// A message that arrives in BDAT chunks starts its handlers with the first
// chunk, on a goroutine of its own, and env.Data gives the chunks as they
// arrive. A handler that reads env.Data to the end therefore waits for the
// last chunk. The peer is the one of the moment the message started, because
// the session goes on reading commands while the handler runs.
//
// A panic in a Handler stops that session only: the server logs it, replies
// 421, closes the connection, and reports a PanicError to the Disconnect
// hooks. Other sessions continue.
type Handler func(ctx context.Context, peer Peer, env *Envelope) (context.Context, error)

// Middleware participates in one or more SMTP phases. Every field is optional;
// a nil field means "this middleware contributes nothing to that phase". When
// registered via Server.Use, all non-nil hooks for a given phase run in Use
// order; the first non-nil error short-circuits the phase.
//
// Handler is the middleware's pre-deliver stage. It runs once the message
// starts to arrive, before Server.Handler, and in series with every other
// middleware Handler in Use order. Middlewares may mutate the envelope
// - including replacing env.Data - to rewrite or enrich the message before
// delivery. A non-nil error aborts the transaction: later middleware Handlers
// and Server.Handler are not called. This is *not* an "around" wrapper; there
// is no next to call, the server invokes each stage in sequence.
type Middleware struct {
	// Handler runs as a pre-deliver stage, once the message starts to
	// arrive and before Server.Handler. nil = no contribution. Middlewares
	// may mutate env, including replacing env.Data. The first non-nil error
	// aborts delivery: subsequent middleware Handlers and Server.Handler are
	// skipped.
	Handler Handler

	// Per-phase hooks. nil = no contribution to that phase. Hooks run in
	// Use order; the first non-nil error short-circuits the phase.
	CheckConnection func(ctx context.Context, peer Peer) (context.Context, error)
	CheckHelo       func(ctx context.Context, peer Peer, name string) (context.Context, error)
	CheckSender     func(ctx context.Context, peer Peer, addr string) (context.Context, error)
	CheckRecipient  func(ctx context.Context, peer Peer, addr string) (context.Context, error)
	Authenticate    func(ctx context.Context, peer Peer, username, password string) (context.Context, error)
	Reset           func(ctx context.Context, peer Peer) context.Context

	// Disconnect runs exactly once per session, after the final reply is
	// flushed and before the underlying connection is closed. err is nil
	// when the session ended cleanly (QUIT or server shutdown) and non-nil
	// when a TLS handshake, a read, or a DATA read error terminated it.
	// Middleware-level rejections (CheckConnection, CheckSender, etc.) are
	// reported as clean ends - they already produced an SMTP reply.
	Disconnect func(ctx context.Context, peer Peer, err error)
}

// Server is an SMTP server. Configure it by setting fields on a zero
// value, register middleware with Use, then call ListenAndServe or Serve.
// All configuration fields must be set before Serve is called; the server
// reads them under no lock once the accept loop starts. Shutdown stops a
// running server and waits for in-flight sessions to drain.
type Server struct {
	// Identity
	Hostname       string // default: "localhost.localdomain"
	WelcomeMessage string // default: "{Hostname} ESMTP ready."

	// Timeouts
	ReadTimeout  time.Duration // per-read; default 60s
	WriteTimeout time.Duration // per-write; default 60s
	DataTimeout  time.Duration // DATA command; default 5m

	// Limits
	MaxConnections int // default 100; -1 unlimited
	MaxMessageSize int // default 10MB; enforced at protocol level
	MaxRecipients  int // default 100

	// Extensions
	EnableXCLIENT       bool
	EnableProxyProtocol bool

	// EnableDSN offers the DSN extension of RFC 3461 and takes its
	// parameters: RET and ENVID on MAIL FROM, NOTIFY and ORCPT on RCPT TO.
	// The server puts them on Envelope.DSN, where the handler reads them.
	//
	// The extension is off by default. A server that offers it tells the
	// client that a notification follows the request, and only the handler
	// can write one. Turn it on where the handler acts on Envelope.DSN, or
	// where it passes the parameters to a relay behind the server.
	//
	// Without it, the server answers 555 to each of the four parameters,
	// and a client that follows RFC 3461 sends none of them.
	EnableDSN bool

	// EnableSMTPUTF8 offers the SMTPUTF8 extension of RFC 6531 and takes its
	// parameter on MAIL FROM. A transaction that carries the parameter takes
	// an address of Unicode in UTF-8, and Envelope.SMTPUTF8 tells the handler
	// that it did.
	//
	// The extension is off by default. A server that offers it says that it
	// carries such a message onward, and the next server on the way has to
	// offer the extension as well. Turn it on where the handler keeps the
	// message, or where it relays to a server that takes one.
	//
	// A server that offers the extension holds every other transaction to
	// US-ASCII: it answers 550 to a non-ASCII sender and 553 to a non-ASCII
	// recipient that came without the parameter, which is what RFC 6531
	// section 3.5 asks for. Without EnableSMTPUTF8, the server answers 555 to
	// the parameter and reads an address as it did before.
	EnableSMTPUTF8 bool

	// TLS
	TLSConfig *tls.Config

	// AllowInsecureAuth permits AUTH on connections that have not negotiated
	// TLS. It is false by default: AUTH is neither advertised nor accepted in
	// plain text, because PLAIN and LOGIN both transmit the password in the
	// clear. RFC 4954 discourages offering them without a security layer.
	//
	// Set this only when the transport is trusted by other means - a listener
	// bound to loopback, a unix socket, or a private network segment. Pair it
	// with a CheckConnection middleware that rejects non-local peers so the
	// exposure is bounded explicitly rather than by assumption.
	AllowInsecureAuth bool

	// Logging
	Logger *slog.Logger // nil = silent

	// BaseContext optionally specifies a function that returns the base
	// context for incoming connections. If nil, context.Background() is used.
	// It runs once, before the accept loop, so a panic here stops Serve with
	// a PanicError.
	BaseContext func(net.Listener) context.Context

	// ConnContext optionally specifies a function that modifies the context
	// used for a new connection. The provided ctx is derived from BaseContext
	// and has a per-connection cancel. A panic here drops that connection
	// only: the server logs it and keeps accepting. Returning a nil context
	// stops Serve, because that fault repeats on every connection.
	ConnContext func(ctx context.Context, conn net.Conn) context.Context

	// Handler is the terminal delivery stage. It runs after every middleware
	// Handler stage has run successfully. nil is treated as a no-op handler
	// that accepts and discards the message.
	Handler Handler

	// Pre-resolved per-phase hook lists, populated by Use.
	handlers           []Handler
	connectionCheckers []func(ctx context.Context, peer Peer) (context.Context, error)
	heloCheckers       []func(ctx context.Context, peer Peer, name string) (context.Context, error)
	senderCheckers     []func(ctx context.Context, peer Peer, addr string) (context.Context, error)
	recipientCheckers  []func(ctx context.Context, peer Peer, addr string) (context.Context, error)
	authenticators     []func(ctx context.Context, peer Peer, username, password string) (context.Context, error)
	resetters          []func(ctx context.Context, peer Peer) context.Context
	disconnecters      []func(ctx context.Context, peer Peer, err error)

	mu         sync.Mutex
	listener   net.Listener
	active     map[*session]context.CancelFunc
	wg         sync.WaitGroup
	inShutdown atomic.Bool
}

// Use registers a Middleware. Each non-nil field is appended to the matching
// per-phase list and runs in Use order at the corresponding SMTP stage. Use
// is not safe to call concurrently with Serve; configure all middleware
// before starting the server.
func (srv *Server) Use(m Middleware) *Server {
	if m.Handler != nil {
		srv.handlers = append(srv.handlers, m.Handler)
	}
	if m.CheckConnection != nil {
		srv.connectionCheckers = append(srv.connectionCheckers, m.CheckConnection)
	}
	if m.CheckHelo != nil {
		srv.heloCheckers = append(srv.heloCheckers, m.CheckHelo)
	}
	if m.CheckSender != nil {
		srv.senderCheckers = append(srv.senderCheckers, m.CheckSender)
	}
	if m.CheckRecipient != nil {
		srv.recipientCheckers = append(srv.recipientCheckers, m.CheckRecipient)
	}
	if m.Authenticate != nil {
		srv.authenticators = append(srv.authenticators, m.Authenticate)
	}
	if m.Reset != nil {
		srv.resetters = append(srv.resetters, m.Reset)
	}
	if m.Disconnect != nil {
		srv.disconnecters = append(srv.disconnecters, m.Disconnect)
	}
	return srv
}

func (srv *Server) checkConnection(ctx context.Context, peer Peer) (context.Context, error) {
	var err error
	for _, h := range srv.connectionCheckers {
		ctx, err = h(ctx, peer)
		if err != nil {
			return ctx, err
		}
	}
	return ctx, nil
}

func (srv *Server) checkHelo(ctx context.Context, peer Peer, name string) (context.Context, error) {
	var err error
	for _, h := range srv.heloCheckers {
		ctx, err = h(ctx, peer, name)
		if err != nil {
			return ctx, err
		}
	}
	return ctx, nil
}

func (srv *Server) checkSender(ctx context.Context, peer Peer, addr string) (context.Context, error) {
	var err error
	for _, h := range srv.senderCheckers {
		ctx, err = h(ctx, peer, addr)
		if err != nil {
			return ctx, err
		}
	}
	return ctx, nil
}

func (srv *Server) checkRecipient(ctx context.Context, peer Peer, addr string) (context.Context, error) {
	var err error
	for _, h := range srv.recipientCheckers {
		ctx, err = h(ctx, peer, addr)
		if err != nil {
			return ctx, err
		}
	}
	return ctx, nil
}

func (srv *Server) authenticate(ctx context.Context, peer Peer, username, password string) (context.Context, error) {
	var err error
	for _, h := range srv.authenticators {
		ctx, err = h(ctx, peer, username, password)
		if err != nil {
			return ctx, err
		}
	}
	return ctx, nil
}

func (srv *Server) reset(ctx context.Context, peer Peer) context.Context {
	for _, h := range srv.resetters {
		ctx = h(ctx, peer)
	}
	return ctx
}

// deliver runs every middleware Handler and then Server.Handler. The peer
// comes as an argument, because a chunked message runs the handlers on a
// goroutine of its own, where the peer of the session can change under them.
func (srv *Server) deliver(ctx context.Context, peer Peer, env *Envelope) (context.Context, error) {
	var err error
	for _, h := range srv.handlers {
		ctx, err = h(ctx, peer, env)
		if err != nil {
			return ctx, err
		}
	}
	if srv.Handler != nil {
		return srv.Handler(ctx, peer, env)
	}
	return ctx, nil
}

func (srv *Server) disconnect(ctx context.Context, peer Peer, err error) {
	for _, h := range srv.disconnecters {
		h(ctx, peer, err)
	}
}

func (srv *Server) hasAuthenticator() bool {
	return len(srv.authenticators) > 0
}

func (srv *Server) trackSession(s *session, cancel context.CancelFunc) bool {
	srv.mu.Lock()
	defer srv.mu.Unlock()
	if srv.inShutdown.Load() {
		return false
	}
	if srv.active == nil {
		srv.active = make(map[*session]context.CancelFunc)
	}
	srv.active[s] = cancel
	return true
}

func (srv *Server) untrackSession(s *session) {
	srv.mu.Lock()
	defer srv.mu.Unlock()
	delete(srv.active, s)
}

func (srv *Server) configureDefaults() error {
	if srv.MaxMessageSize == 0 {
		srv.MaxMessageSize = 10240000
	}
	if srv.MaxConnections == 0 {
		srv.MaxConnections = 100
	}
	if srv.MaxRecipients == 0 {
		srv.MaxRecipients = 100
	}
	if srv.ReadTimeout == 0 {
		srv.ReadTimeout = 60 * time.Second
	}
	if srv.WriteTimeout == 0 {
		srv.WriteTimeout = 60 * time.Second
	}
	if srv.DataTimeout == 0 {
		srv.DataTimeout = 5 * time.Minute
	}
	if srv.Hostname == "" {
		srv.Hostname = "localhost.localdomain"
	}
	if srv.WelcomeMessage == "" {
		srv.WelcomeMessage = fmt.Sprintf("%s ESMTP ready.", srv.Hostname)
	}
	return nil
}

// errNilConnContext reports a ConnContext that returned a nil context. It
// separates that fault, which repeats on every connection, from a panic,
// which the accept loop survives.
var errNilConnContext = errors.New("smtpd: ConnContext returned nil")

// baseContext calls Server.BaseContext and contains a panic from it. The
// hook runs once, before the accept loop, so a panic there stops Serve.
func (srv *Server) baseContext(l net.Listener) (ctx context.Context, err error) {
	if srv.BaseContext == nil {
		return context.Background(), nil
	}

	defer func() {
		if v := recover(); v != nil {
			ctx, err = nil, PanicError{Value: v, Stack: debug.Stack()}
		}
	}()

	ctx = srv.BaseContext(l)
	if ctx == nil {
		return nil, errors.New("smtpd: BaseContext returned nil")
	}
	return ctx, nil
}

// connContext calls Server.ConnContext and contains a panic from it. The hook
// runs once per connection, so the caller drops that connection and keeps
// accepting.
func (srv *Server) connContext(in context.Context, conn net.Conn) (ctx context.Context, err error) {
	if srv.ConnContext == nil {
		return in, nil
	}

	defer func() {
		if v := recover(); v != nil {
			ctx, err = nil, PanicError{Value: v, Stack: debug.Stack()}
		}
	}()

	ctx = srv.ConnContext(in, conn)
	if ctx == nil {
		return nil, errNilConnContext
	}
	return ctx, nil
}

// ListenAndServe opens a TCP listener on addr and serves SMTP on it.
func (srv *Server) ListenAndServe(addr string) error {
	if srv.inShutdown.Load() {
		return ErrServerClosed
	}
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	return srv.Serve(l)
}

// Serve accepts connections on l and handles each in its own goroutine.
// It returns ErrServerClosed after Shutdown.
func (srv *Server) Serve(l net.Listener) error {
	if srv.inShutdown.Load() {
		return ErrServerClosed
	}
	if err := srv.configureDefaults(); err != nil {
		return err
	}

	defer func() { _ = l.Close() }()

	srv.mu.Lock()
	srv.listener = l
	srv.mu.Unlock()

	baseCtx, err := srv.baseContext(l)
	if err != nil {
		return err
	}

	var limiter chan struct{}
	if srv.MaxConnections > 0 {
		limiter = make(chan struct{}, srv.MaxConnections)
	}

	for {
		conn, err := l.Accept()
		if err != nil {
			if srv.inShutdown.Load() {
				return ErrServerClosed
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				time.Sleep(time.Second)
				continue
			}
			return err
		}

		connCtx, cancel := context.WithCancel(baseCtx)
		connCtx, err = srv.connContext(connCtx, conn)
		if err != nil {
			// Read the address before the close, so the log line still
			// names the peer.
			peer := conn.RemoteAddr().String()
			cancel()
			_ = conn.Close()

			// A nil context is a fault in the configuration and repeats on
			// every connection, so it stops the server. A panic stops the
			// one connection that caused it.
			if errors.Is(err, errNilConnContext) {
				return err
			}
			srv.newLogger().Error("dropped a connection",
				slog.String("peer", peer),
				slog.Any("error", err),
			)
			continue
		}

		ctx, s := srv.newSession(connCtx, conn)

		if !srv.trackSession(s, cancel) {
			cancel()
			_ = conn.Close()
			return ErrServerClosed
		}

		srv.wg.Add(1)
		go func() {
			defer srv.wg.Done()
			defer srv.untrackSession(s)
			defer cancel()
			if limiter != nil {
				select {
				case limiter <- struct{}{}:
					s.serve(ctx)
					<-limiter
				default:
					s.reject(ctx)
				}
			} else {
				s.serve(ctx)
			}
		}()
	}
}

// Shutdown stops accepting new connections and waits for in-flight sessions
// to finish. Each session's ctx is cancelled so ctx-aware handler work
// unwinds immediately; if ctx is cancelled before sessions exit on their
// own, Shutdown force-closes every live connection so blocked reads/writes
// return and returns ctx.Err(). Calling Shutdown more than once is safe.
func (srv *Server) Shutdown(ctx context.Context) error {
	srv.inShutdown.Store(true)

	srv.mu.Lock()
	var lnerr error
	if srv.listener != nil {
		lnerr = srv.listener.Close()
	}
	// Cancel every live session's ctx so handlers that honor ctx can bail.
	// We don't close the conns yet - give well-behaved sessions a chance
	// to finish cleanly, with a 250/QUIT reply.
	for _, cancel := range srv.active {
		cancel()
	}
	srv.mu.Unlock()

	done := make(chan struct{})
	go func() {
		srv.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		return lnerr
	case <-ctx.Done():
		// Deadline hit - force-close remaining conns so blocked network
		// I/O returns and sessions exit.
		srv.mu.Lock()
		for s := range srv.active {
			_ = s.conn.Close()
		}
		srv.mu.Unlock()
		<-done
		return ctx.Err()
	}
}

// Addr returns the listener's network address, or nil if Serve hasn't
// been called yet.
func (srv *Server) Addr() net.Addr {
	srv.mu.Lock()
	defer srv.mu.Unlock()
	if srv.listener == nil {
		return nil
	}
	return srv.listener.Addr()
}
