package smtpd

import (
	"context"
)

// Chain starts a middleware chain with the given base Handler. Add middleware
// with Use, then call Handler to obtain the composed Handler. Each Use adds a
// Middleware; when the resulting wrapping layer also satisfies one or more
// checker interfaces (ConnectionChecker, HeloChecker, SenderChecker,
// RecipientChecker, Authenticator, Resetter, Disconnecter), the layer is
// registered into the matching per-phase list.
//
// The leftmost Use wraps outermost (closest to the wire); the rightmost wraps
// innermost (closest to base). Per-phase checker lists run in Use order.
//
// A nil base is treated as a no-op terminal handler that accepts and discards
// every message.
//
//	srv.Handler = smtpd.Chain(base).
//	    Use(middleware.CheckConnection(rbl.ConnectionCheck)).
//	    Use(middleware.CheckHelo(spf.HeloCheck)).
//	    Use(middleware.CheckSender(spf.SenderCheck)).
//	    Use(middleware.CheckData(spf.DataCheck)).
//	    Handler()
func Chain(base Handler) *chain {
	return &chain{base: base}
}

// chain is the builder returned by Chain. Callers don't name it directly;
// they chain Use calls and end with Handler.
type chain struct {
	base Handler
	mws  []Middleware
}

// Use appends a Middleware to the chain and returns the chain for further
// calls. Order matters: leftmost Use wraps outermost.
func (c *chain) Use(m Middleware) *chain {
	c.mws = append(c.mws, m)
	return c
}

// Handler builds and returns the composed Handler. It is safe to call
// multiple times; each call produces an independent Handler snapshot of the
// current chain state.
func (c *chain) Handler() Handler {
	base := c.base
	if base == nil {
		base = HandlerFunc(func(context.Context, Peer, *Envelope) error { return nil })
	}

	out := &chainHandler{}
	out.collect(base)

	// Build wrapping layers innermost→outermost; layers[0] is the outermost
	// (matches leftmost Use). Collect checker interfaces from each layer in
	// outermost→innermost order so per-phase lists run in Use order.
	layers := make([]Handler, len(c.mws))
	h := base
	for i := len(c.mws) - 1; i >= 0; i-- {
		h = c.mws[i](h)
		layers[i] = h
	}
	for _, l := range layers {
		out.collect(l)
	}

	out.handler = h
	return out
}

// chainHandler is the composed Handler returned by chain.Handler. It holds
// pre-resolved per-phase checker lists so the server does not walk wrappers
// at runtime.
type chainHandler struct {
	handler            Handler
	connectionCheckers []ConnectionChecker
	heloCheckers       []HeloChecker
	senderCheckers     []SenderChecker
	recipientCheckers  []RecipientChecker
	authenticators     []Authenticator
	resetters          []Resetter
	disconnecters      []Disconnecter
}

func (c *chainHandler) collect(h Handler) {
	if cc, ok := h.(ConnectionChecker); ok {
		c.connectionCheckers = append(c.connectionCheckers, cc)
	}
	if hc, ok := h.(HeloChecker); ok {
		c.heloCheckers = append(c.heloCheckers, hc)
	}
	if sc, ok := h.(SenderChecker); ok {
		c.senderCheckers = append(c.senderCheckers, sc)
	}
	if rc, ok := h.(RecipientChecker); ok {
		c.recipientCheckers = append(c.recipientCheckers, rc)
	}
	if aa, ok := h.(Authenticator); ok {
		c.authenticators = append(c.authenticators, aa)
	}
	if r, ok := h.(Resetter); ok {
		c.resetters = append(c.resetters, r)
	}
	if d, ok := h.(Disconnecter); ok {
		c.disconnecters = append(c.disconnecters, d)
	}
}

func (c *chainHandler) ServeSMTP(ctx context.Context, peer Peer, env *Envelope) error {
	return c.handler.ServeSMTP(ctx, peer, env)
}

func (c *chainHandler) CheckConnection(ctx context.Context, peer Peer) (context.Context, error) {
	var err error
	for _, x := range c.connectionCheckers {
		ctx, err = x.CheckConnection(ctx, peer)
		if err != nil {
			return ctx, err
		}
	}
	return ctx, nil
}

func (c *chainHandler) CheckHelo(ctx context.Context, peer Peer, name string) (context.Context, error) {
	var err error
	for _, x := range c.heloCheckers {
		ctx, err = x.CheckHelo(ctx, peer, name)
		if err != nil {
			return ctx, err
		}
	}
	return ctx, nil
}

func (c *chainHandler) CheckSender(ctx context.Context, peer Peer, addr string) (context.Context, error) {
	var err error
	for _, x := range c.senderCheckers {
		ctx, err = x.CheckSender(ctx, peer, addr)
		if err != nil {
			return ctx, err
		}
	}
	return ctx, nil
}

func (c *chainHandler) CheckRecipient(ctx context.Context, peer Peer, addr string) (context.Context, error) {
	var err error
	for _, x := range c.recipientCheckers {
		ctx, err = x.CheckRecipient(ctx, peer, addr)
		if err != nil {
			return ctx, err
		}
	}
	return ctx, nil
}

func (c *chainHandler) Reset(ctx context.Context, peer Peer) context.Context {
	for _, x := range c.resetters {
		ctx = x.Reset(ctx, peer)
	}
	return ctx
}

func (c *chainHandler) Disconnect(ctx context.Context, peer Peer) {
	for _, x := range c.disconnecters {
		x.Disconnect(ctx, peer)
	}
}

// hasAuthenticator reports whether any layer implements Authenticator. The
// server uses this to decide whether to advertise AUTH — a structural type
// assertion would always succeed since chainHandler unconditionally defines
// Authenticate.
func (c *chainHandler) hasAuthenticator() bool { return len(c.authenticators) > 0 }

func (c *chainHandler) Authenticate(ctx context.Context, peer Peer, username, password string) (context.Context, error) {
	var err error
	for _, x := range c.authenticators {
		ctx, err = x.Authenticate(ctx, peer, username, password)
		if err != nil {
			return ctx, err
		}
	}
	return ctx, nil
}
