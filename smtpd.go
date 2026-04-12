package smtpd

type Peer struct {
	HeloName   string
	Username   string
	Protocol   Protocol
	ServerName string
	Addr       net.Addr
	TLS        *tls.ConnectionState
}

type Envelope struct {
	Sender     string
	Recipients []string
	Data       io.Reader
}

type Error struct {
	Code int
	Message
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

func (srv *Server) checkHandlerCapabilities() {}
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
	for _, c := range p.recipientCheckers {
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
		ctx, err := a.Authenticate(ctx, peer, username, password)
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
	heloCheckers []HeloChecker
	senderCheckers []SenderChecker
	recipientCheckers []RecipientChecker
	authenticators []Authenticator
}

func (srv *Server) ListenAndServe(addr string) error
func (srv *Server) Serve(l net.Listener) error
func (srv *Server) Shutdown(ctx context.Context) error
func (srv *Server) Address() net.Addr

srv := &smtpd.Server{}
srv.Use(middleware.IPAddressRateLimit(10, 5))
srv.Use(middleware.SPFCheck())
