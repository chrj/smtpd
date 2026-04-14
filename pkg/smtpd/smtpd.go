// Package smtpd implements an SMTP server with support for STARTTLS, authentication (PLAIN/LOGIN), XCLIENT and optional restrictions on the different stages of the SMTP session.
package smtpd

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// ErrServerClosed is returned by Serve/ListenAndServe after Shutdown.
var ErrServerClosed = errors.New("smtpd: server closed")

// Protocol represents the protocol used in the SMTP session
type Protocol string

const (
	SMTP  Protocol = "SMTP"
	ESMTP Protocol = "ESMTP"
)

type Peer struct {
	HeloName   string
	Username   string
	Protocol   Protocol
	ServerName string
	Addr       net.Addr
	TLS        *tls.ConnectionState
}

type Error struct {
	Code    int
	Message string
}

func (e Error) Error() string {
	return e.Message
}

type Handler interface {
	ServeSMTP(ctx context.Context, peer Peer, env Envelope) error
}

type ConnectionChecker interface {
	CheckConnection(ctx context.Context, peer Peer) (context.Context, error)
}

type HeloChecker interface {
	CheckHelo(ctx context.Context, peer Peer, name string) (context.Context, error)
}

type SenderChecker interface {
	CheckSender(ctx context.Context, peer Peer, addr string) (context.Context, error)
}

type RecipientChecker interface {
	CheckRecipient(ctx context.Context, peer Peer, addr string) (context.Context, error)
}

type Authenticator interface {
	Authenticate(ctx context.Context, peer Peer, username, password string) (context.Context, error)
}

type Middleware func(next Handler) Handler

func (srv *Server) Handler(h Handler) {
	srv.handler = h
	srv.checkHandlerCapabilities()
}

func (srv *Server) Use(m Middleware) {
	if srv.handler == nil {
		panic("SetHandler() must be called before Use()")
	}
	srv.handler = m(srv.handler)
	srv.checkHandlerCapabilities()
}

func (srv *Server) checkHandlerCapabilities() {
	if cc, ok := srv.handler.(ConnectionChecker); ok {
		srv.connectionCheckers = append(srv.connectionCheckers, cc)
	}
	if hc, ok := srv.handler.(HeloChecker); ok {
		srv.heloCheckers = append(srv.heloCheckers, hc)
	}
	if sc, ok := srv.handler.(SenderChecker); ok {
		srv.senderCheckers = append(srv.senderCheckers, sc)
	}
	if rc, ok := srv.handler.(RecipientChecker); ok {
		srv.recipientCheckers = append(srv.recipientCheckers, rc)
	}
	if aa, ok := srv.handler.(Authenticator); ok {
		srv.authenticators = append(srv.authenticators, aa)
	}
}

func (srv *Server) checkConnection(ctx context.Context, peer Peer) (context.Context, error) {
	var err error
	for _, c := range srv.connectionCheckers {
		ctx, err = c.CheckConnection(ctx, peer)
		if err != nil {
			return ctx, err
		}
	}
	return ctx, nil
}

func (srv *Server) checkHelo(ctx context.Context, peer Peer, name string) (context.Context, error) {
	var err error
	for _, c := range srv.heloCheckers {
		ctx, err = c.CheckHelo(ctx, peer, name)
		if err != nil {
			return ctx, err
		}
	}
	return ctx, nil
}

func (srv *Server) checkSender(ctx context.Context, peer Peer, addr string) (context.Context, error) {
	var err error
	for _, c := range srv.senderCheckers {
		ctx, err = c.CheckSender(ctx, peer, addr)
		if err != nil {
			return ctx, err
		}
	}
	return ctx, nil
}

func (srv *Server) checkRecipient(ctx context.Context, peer Peer, addr string) (context.Context, error) {
	var err error
	for _, c := range srv.recipientCheckers {
		ctx, err = c.CheckRecipient(ctx, peer, addr)
		if err != nil {
			return ctx, err
		}
	}
	return ctx, nil
}

func (srv *Server) authenticate(ctx context.Context, peer Peer, username, password string) (context.Context, error) {
	var err error
	for _, a := range srv.authenticators {
		ctx, err = a.Authenticate(ctx, peer, username, password)
		if err != nil {
			return ctx, err
		}
	}
	return ctx, nil
}

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

	AuthOptional bool

	// Extensions
	EnableXCLIENT       bool
	EnableProxyProtocol bool

	// TLS
	TLSConfig *tls.Config
	ForceTLS  bool

	// Logging
	Logger *slog.Logger // nil = silent

	// BaseContext optionally specifies a function that returns the base
	// context for incoming connections. If nil, context.Background() is used.
	BaseContext func(net.Listener) context.Context

	// ConnContext optionally specifies a function that modifies the context
	// used for a new connection. The provided ctx is derived from BaseContext
	// and has a per-connection cancel.
	ConnContext func(ctx context.Context, conn net.Conn) context.Context

	handler Handler

	// Middlewares get registered in these
	connectionCheckers []ConnectionChecker
	heloCheckers       []HeloChecker
	senderCheckers     []SenderChecker
	recipientCheckers  []RecipientChecker
	authenticators     []Authenticator

	mu         sync.Mutex
	listener   net.Listener
	active     map[*session]context.CancelFunc
	wg         sync.WaitGroup
	inShutdown atomic.Bool
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
	if srv.ForceTLS && srv.TLSConfig == nil {
		return errors.New("smtpd: ForceTLS requires TLSConfig")
	}
	return nil
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

	baseCtx := context.Background()
	if srv.BaseContext != nil {
		baseCtx = srv.BaseContext(l)
		if baseCtx == nil {
			return errors.New("smtpd: BaseContext returned nil")
		}
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
		if srv.ConnContext != nil {
			connCtx = srv.ConnContext(connCtx, conn)
			if connCtx == nil {
				cancel()
				_ = conn.Close()
				return errors.New("smtpd: ConnContext returned nil")
			}
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
	// We don't close the conns yet — give well-behaved sessions a chance
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
		// Deadline hit — force-close remaining conns so blocked network
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

// Address returns the listener's network address, or nil if Serve hasn't
// been called yet.
func (srv *Server) Address() net.Addr {
	srv.mu.Lock()
	defer srv.mu.Unlock()
	if srv.listener == nil {
		return nil
	}
	return srv.listener.Addr()
}

