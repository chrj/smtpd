// Package smtpd implements an SMTP server with support for STARTTLS, authentication (PLAIN/LOGIN), XCLIENT and optional restrictions on the different stages of the SMTP session.
//
// Server.LMTP serves the Local Mail Transfer Protocol of RFC 2033 in the
// place of SMTP, with one reply for every recipient of a message.
package smtpd

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"runtime/debug"
	"sync"
	"sync/atomic"
	"time"
)

// ErrServerClosed is returned by Serve/ListenAndServe after Shutdown.
var ErrServerClosed = errors.New("smtpd: server closed")

// Protocol identifies the variant that the greeting of the client selected:
// SMTP after HELO, ESMTP after EHLO, LMTP after LHLO. Read it from
// Peer.Protocol in phase hooks and handlers.
type Protocol string

const (
	// SMTP is set on Peer.Protocol after a HELO greeting.
	SMTP Protocol = "SMTP"
	// ESMTP is set on Peer.Protocol after an EHLO greeting, which also
	// enables extensions advertised in the 250 response.
	ESMTP Protocol = "ESMTP"
	// LMTP is set on Peer.Protocol after an LHLO greeting, which a server
	// of Server.LMTP takes in the place of HELO and of EHLO. It enables the
	// same extensions as ESMTP, and the server writes one reply for every
	// recipient of a message.
	LMTP Protocol = "LMTP"
)

// extended reports whether the greeting of the client came with the
// extensions of ESMTP. RFC 5321 gives them to a client that sent EHLO, and
// RFC 2033 section 4.1 gives the same to a client that sent LHLO. A client
// that sent HELO saw no offer of them, so it reads the replies of RFC 5321.
func (p Protocol) extended() bool {
	return p == ESMTP || p == LMTP
}

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
// (CheckConnection, CheckHelo, CheckSender, CheckRecipient, Authenticate,
// Verify)
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

	// Verify runs for a VRFY command and looks the name up. name is the
	// argument of the command, as the client wrote it: RFC 5321 section
	// 3.5.1 gives a user name, a mailbox, or a string of another kind that
	// the site knows.
	//
	// A hook that finds the user returns the mailbox, and the client gets a
	// 250 reply with it. A hook that knows the name to be wrong returns an
	// Error, such as 550 for a user that the server does not carry, or 553
	// for a name that more than one user answers to.
	//
	// A hook that finds nothing returns the zero Verification and no error,
	// and the hook after it looks next. A name that no hook verified gets a
	// 252 reply, which RFC 5321 section 7.3 asks for: a server must never
	// look as though it verified a name that it did not.
	//
	// The message of an Error goes on the wire as the hook wrote it, and the
	// server writes it to every client. RFC 6531 section 3.7.4.2 holds a
	// reply to US-ASCII unless the client asked for UTF-8, and the hook does
	// not see that parameter, so keep the message to US-ASCII.
	//
	// The mailbox needs no such care. A mailbox of Unicode takes the reply of
	// RFC 6531 where the client asked for one, and a 252 where it did not.
	//
	// The hooks run in Use order. The first one that finds a mailbox or
	// returns an error ends the phase.
	Verify func(ctx context.Context, peer Peer, name string) (context.Context, Verification, error)

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
	WelcomeMessage string // default: "{Hostname} ESMTP ready.", and "{Hostname} LMTP ready." with LMTP

	// LMTP serves the Local Mail Transfer Protocol of RFC 2033 in the place
	// of SMTP. Such a server takes LHLO as the greeting and answers 500 to
	// HELO and to EHLO, and Peer.Protocol holds LMTP.
	//
	// The server writes one reply for every recipient of a message, in the
	// order that RCPT TO added them, so the client learns which of them the
	// server holds the message for. A handler that takes a message for some
	// of the recipients calls Envelope.RejectRecipient for each of the rest.
	//
	// LMTP keeps no queue: a client holds the message until the server
	// answers 250 for a recipient, and it delivers no message on its own.
	// Serve it where the local mail system reaches it and nothing else, such
	// as a unix socket or an address of the loopback interface. RFC 2033
	// section 5 keeps the protocol off port 25 and away from wide area
	// networks.
	LMTP bool

	// Timeouts
	ReadTimeout  time.Duration // per-read; default 60s
	WriteTimeout time.Duration // per-write; default 60s
	DataTimeout  time.Duration // DATA command; default 5m

	// Limits
	MaxConnections int // default 100; -1 unlimited
	MaxMessageSize int // default 10MB; enforced at protocol level
	MaxRecipients  int // default 100

	// MaxAuthAttempts is the number of AUTH commands that can fail on one
	// connection. The server answers the attempt that reaches the limit with
	// 421 and closes the connection.
	//
	// RFC 4954 section 6 asks for such a limit. PLAIN and LOGIN both carry a
	// password, and without a limit one connection takes as many guesses as
	// the client cares to send.
	//
	// Only a refusal from the Authenticate hooks counts. A command that does
	// not read, or one whose credentials are not base64, leaves the count
	// where it is. A successful AUTH sets the count back to zero.
	//
	// The limit counts the attempts of one connection, so a client that opens
	// another one starts over. Pair it with middleware.AuthRateLimit, which
	// holds the failures of an address across connections.
	MaxAuthAttempts int // default 5; -1 unlimited

	// TrustedProxies holds the addresses that may restate the identity of the
	// client that reaches the server, with a PROXY protocol header or an
	// XCLIENT command. Both write Peer.Addr, which the greylist, the RBL
	// check and the rate limit all read, so a client that reaches either one
	// takes the identity of any client it names.
	//
	// The server reads the address of the connection, and never Peer.Addr: a
	// header that arrived already wrote that one.
	//
	// An empty list trusts the addresses that the public internet does not
	// reach: the loopback addresses, the private ranges of RFC 1918 and RFC
	// 4193, and the link-local addresses. That covers a proxy that stands
	// beside the server or on the network of the server.
	//
	// Give the list where the proxy reaches the server from another network,
	// such as a load balancer with a public address:
	//
	//	srv.TrustedProxies = []netip.Prefix{
	//	    netip.MustParsePrefix("203.0.113.7/32"),
	//	}
	//
	// A client that is not trusted gets 550 for an XCLIENT command and for a
	// PROXY command, and its session ends without a reply for a PROXY header
	// of version 2. The address of the connection stays on Peer.Addr.
	//
	// A connection that carries no IP address, such as a unix socket, is
	// always trusted: a local process is at the other end of one.
	//
	// The list bounds who may speak for another client. It does not turn the
	// extensions on: without Server.EnableProxyProtocol or
	// Server.EnableXCLIENT the server takes neither, from any address.
	TrustedProxies []netip.Prefix

	// Extensions
	EnableXCLIENT bool

	// EnableProxyProtocol takes the header of the PROXY protocol of HAProxy
	// ahead of the SMTP session, and puts the address of the client on
	// Peer.Addr. The server takes version 1, which is a line of text, and
	// version 2, which is binary.
	//
	// A server with this field holds the greeting back until the header
	// arrives, so give it a listener that the proxy alone reaches. A client
	// that reaches it without a proxy gets no greeting, and a client that
	// sends a header of its own writes the address that the hooks read.
	//
	// A header of version 2 that the server cannot read ends the session
	// without a reply, and the Disconnect hooks get a ProxyError. A header
	// for a connection of the proxy itself, such as a health check, leaves
	// the addresses of the connection where they are.
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
	// A VRFY command takes the parameter as well, and the reply to that one
	// command can then carry a mailbox of Unicode. See Middleware.Verify.
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
	verifiers          []func(ctx context.Context, peer Peer, name string) (context.Context, Verification, error)
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
	if m.Verify != nil {
		srv.verifiers = append(srv.verifiers, m.Verify)
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

// verify runs the Verify hooks until one of them finds a mailbox or refuses
// the name. A hook that finds nothing lets the next one look, and a name that
// none of them verified comes back as the zero Verification.
func (srv *Server) verify(ctx context.Context, peer Peer, name string) (context.Context, Verification, error) {
	var (
		verified Verification
		err      error
	)

	for _, h := range srv.verifiers {
		ctx, verified, err = h(ctx, peer, name)
		if err != nil {
			return ctx, Verification{}, err
		}
		if verified.Mailbox != "" {
			return ctx, verified, nil
		}
	}
	return ctx, Verification{}, nil
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

// tooManyAuthFailures reports whether a session that saw failures refused
// attempts has reached MaxAuthAttempts. A limit of -1, or of any other value
// below one, closes no connection.
func (srv *Server) tooManyAuthFailures(failures int) bool {
	return srv.MaxAuthAttempts > 0 && failures >= srv.MaxAuthAttempts
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
	if srv.MaxAuthAttempts == 0 {
		srv.MaxAuthAttempts = 5
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

	// A prefix that does not read matches no address, so the server would
	// refuse every proxy and say only that the address is not trusted. The
	// zero value of netip.Prefix is the one that arrives here, from a
	// netip.ParsePrefix whose error the caller passed over.
	for i, prefix := range srv.TrustedProxies {
		if !prefix.IsValid() {
			return fmt.Errorf("smtpd: Server.TrustedProxies[%d] is not a prefix that reads, and it would match no address", i)
		}
	}
	if srv.WelcomeMessage == "" {
		protocol := ESMTP
		if srv.LMTP {
			protocol = LMTP
		}
		srv.WelcomeMessage = fmt.Sprintf("%s %s ready.", srv.Hostname, protocol)
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
		// I/O returns and sessions exit. Closing the connection of the
		// listener ends a session that upgraded to TLS as well, because the
		// TLS connection reads and writes through this one.
		srv.mu.Lock()
		for s := range srv.active {
			_ = s.rawConn.Close()
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
