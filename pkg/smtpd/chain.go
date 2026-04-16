package smtpd

import (
	"context"
)

// Chain starts a middleware chain with the given base Handler. Add
// Middleware values with Use, then call Handler to obtain the composed
// Handler. Each Use appends a Middleware; its Wrap (if any) participates in
// ServeSMTP composition, and each non-nil On* hook is registered into the
// matching per-phase list.
//
// The leftmost Use wraps outermost (closest to the wire); the rightmost wraps
// innermost (closest to base). Per-phase hook lists run in Use order.
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

	// Build the ServeSMTP chain innermost→outermost so the rightmost Use
	// wraps closest to base.
	h := base
	for i := len(c.mws) - 1; i >= 0; i-- {
		if w := c.mws[i].Wrap; w != nil {
			h = w(h)
		}
	}

	out := &chainHandler{handler: h}
	// Per-phase hooks run in Use order (outermost→innermost).
	for _, m := range c.mws {
		if m.CheckConnection != nil {
			out.connectionCheckers = append(out.connectionCheckers, m.CheckConnection)
		}
		if m.CheckHelo != nil {
			out.heloCheckers = append(out.heloCheckers, m.CheckHelo)
		}
		if m.CheckSender != nil {
			out.senderCheckers = append(out.senderCheckers, m.CheckSender)
		}
		if m.CheckRecipient != nil {
			out.recipientCheckers = append(out.recipientCheckers, m.CheckRecipient)
		}
		if m.Authenticate != nil {
			out.authenticators = append(out.authenticators, m.Authenticate)
		}
		if m.Reset != nil {
			out.resetters = append(out.resetters, m.Reset)
		}
		if m.Disconnect != nil {
			out.disconnecters = append(out.disconnecters, m.Disconnect)
		}
	}
	return out
}

// chainHandler is the composed Handler returned by chain.Handler. It holds
// pre-resolved per-phase hook lists so the server does not walk wrappers
// at runtime.
type chainHandler struct {
	handler            Handler
	connectionCheckers []func(ctx context.Context, peer Peer) (context.Context, error)
	heloCheckers       []func(ctx context.Context, peer Peer, name string) (context.Context, error)
	senderCheckers     []func(ctx context.Context, peer Peer, addr string) (context.Context, error)
	recipientCheckers  []func(ctx context.Context, peer Peer, addr string) (context.Context, error)
	authenticators     []func(ctx context.Context, peer Peer, username, password string) (context.Context, error)
	resetters          []func(ctx context.Context, peer Peer) context.Context
	disconnecters      []func(ctx context.Context, peer Peer)
}

func (c *chainHandler) ServeSMTP(ctx context.Context, peer Peer, env *Envelope) error {
	return c.handler.ServeSMTP(ctx, peer, env)
}

func (c *chainHandler) CheckConnection(ctx context.Context, peer Peer) (context.Context, error) {
	var err error
	for _, h := range c.connectionCheckers {
		ctx, err = h(ctx, peer)
		if err != nil {
			return ctx, err
		}
	}
	return ctx, nil
}

func (c *chainHandler) CheckHelo(ctx context.Context, peer Peer, name string) (context.Context, error) {
	var err error
	for _, h := range c.heloCheckers {
		ctx, err = h(ctx, peer, name)
		if err != nil {
			return ctx, err
		}
	}
	return ctx, nil
}

func (c *chainHandler) CheckSender(ctx context.Context, peer Peer, addr string) (context.Context, error) {
	var err error
	for _, h := range c.senderCheckers {
		ctx, err = h(ctx, peer, addr)
		if err != nil {
			return ctx, err
		}
	}
	return ctx, nil
}

func (c *chainHandler) CheckRecipient(ctx context.Context, peer Peer, addr string) (context.Context, error) {
	var err error
	for _, h := range c.recipientCheckers {
		ctx, err = h(ctx, peer, addr)
		if err != nil {
			return ctx, err
		}
	}
	return ctx, nil
}

func (c *chainHandler) Reset(ctx context.Context, peer Peer) context.Context {
	for _, h := range c.resetters {
		ctx = h(ctx, peer)
	}
	return ctx
}

func (c *chainHandler) Disconnect(ctx context.Context, peer Peer) {
	for _, h := range c.disconnecters {
		h(ctx, peer)
	}
}

// hasAuthenticator reports whether any layer wired an Authenticate hook. The
// server uses this to decide whether to advertise AUTH — a structural type
// assertion would always succeed since chainHandler unconditionally defines
// Authenticate.
func (c *chainHandler) hasAuthenticator() bool { return len(c.authenticators) > 0 }

func (c *chainHandler) Authenticate(ctx context.Context, peer Peer, username, password string) (context.Context, error) {
	var err error
	for _, h := range c.authenticators {
		ctx, err = h(ctx, peer, username, password)
		if err != nil {
			return ctx, err
		}
	}
	return ctx, nil
}
