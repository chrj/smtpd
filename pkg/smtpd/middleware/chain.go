package middleware

import (
	"context"

	"github.com/chrj/smtpd/v2/pkg/smtpd"
)

// Chain is a builder that composes a base smtpd.Handler with middleware into a
// single Handler whose per-phase checker lists are resolved at build time.
//
// Construct with For, add middleware with With, then call Handler to obtain the
// composed smtpd.Handler. Each With adds an smtpd.Middleware; when the resulting
// wrapping layer also satisfies one or more checker interfaces
// (ConnectionChecker, HeloChecker, SenderChecker, RecipientChecker,
// Authenticator, Resetter, Disconnecter), the layer is registered into the
// matching per-phase list.
//
// The leftmost With wraps outermost (closest to the wire); the rightmost wraps
// innermost (closest to base). Per-phase checker lists run in With order.
//
//	srv.Handler = middleware.For(base).
//	    With(middleware.CheckConnection(rbl.Check)).
//	    With(middleware.CheckHelo(spf.Helo)).
//	    With(middleware.CheckSender(spf.MailFrom)).
//	    With(middleware.CheckData(spf.Data)).
//	    Handler()
type Chain struct {
	base smtpd.Handler
	mws  []smtpd.Middleware
}

// For starts a Chain with the given base Handler. A nil base is treated as a
// no-op terminal handler that accepts and discards every message.
func For(base smtpd.Handler) *Chain {
	return &Chain{base: base}
}

// With appends a Middleware to the chain and returns the chain for further
// calls. Order matters: leftmost With wraps outermost.
func (c *Chain) With(m smtpd.Middleware) *Chain {
	c.mws = append(c.mws, m)
	return c
}

// Handler builds and returns the composed smtpd.Handler. It is safe to call
// multiple times; each call produces an independent Handler snapshot of the
// current Chain state.
func (c *Chain) Handler() smtpd.Handler {
	base := c.base
	if base == nil {
		base = smtpd.HandlerFunc(func(context.Context, smtpd.Peer, *smtpd.Envelope) error { return nil })
	}

	out := &chain{}
	out.collect(base)

	// Build wrapping layers innermost→outermost; layers[0] is the outermost
	// (matches leftmost With). Collect checker interfaces from each layer in
	// outermost→innermost order so per-phase lists run in With order.
	layers := make([]smtpd.Handler, len(c.mws))
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

// chain is the composed Handler returned by Chain.Handler. It holds
// pre-resolved per-phase checker lists so the server does not walk wrappers at
// runtime.
type chain struct {
	handler            smtpd.Handler
	connectionCheckers []smtpd.ConnectionChecker
	heloCheckers       []smtpd.HeloChecker
	senderCheckers     []smtpd.SenderChecker
	recipientCheckers  []smtpd.RecipientChecker
	authenticators     []smtpd.Authenticator
	resetters          []smtpd.Resetter
	disconnecters      []smtpd.Disconnecter
}

func (c *chain) collect(h smtpd.Handler) {
	if cc, ok := h.(smtpd.ConnectionChecker); ok {
		c.connectionCheckers = append(c.connectionCheckers, cc)
	}
	if hc, ok := h.(smtpd.HeloChecker); ok {
		c.heloCheckers = append(c.heloCheckers, hc)
	}
	if sc, ok := h.(smtpd.SenderChecker); ok {
		c.senderCheckers = append(c.senderCheckers, sc)
	}
	if rc, ok := h.(smtpd.RecipientChecker); ok {
		c.recipientCheckers = append(c.recipientCheckers, rc)
	}
	if aa, ok := h.(smtpd.Authenticator); ok {
		c.authenticators = append(c.authenticators, aa)
	}
	if r, ok := h.(smtpd.Resetter); ok {
		c.resetters = append(c.resetters, r)
	}
	if d, ok := h.(smtpd.Disconnecter); ok {
		c.disconnecters = append(c.disconnecters, d)
	}
}

func (c *chain) ServeSMTP(ctx context.Context, peer smtpd.Peer, env *smtpd.Envelope) error {
	return c.handler.ServeSMTP(ctx, peer, env)
}

func (c *chain) CheckConnection(ctx context.Context, peer smtpd.Peer) (context.Context, error) {
	var err error
	for _, x := range c.connectionCheckers {
		ctx, err = x.CheckConnection(ctx, peer)
		if err != nil {
			return ctx, err
		}
	}
	return ctx, nil
}

func (c *chain) CheckHelo(ctx context.Context, peer smtpd.Peer, name string) (context.Context, error) {
	var err error
	for _, x := range c.heloCheckers {
		ctx, err = x.CheckHelo(ctx, peer, name)
		if err != nil {
			return ctx, err
		}
	}
	return ctx, nil
}

func (c *chain) CheckSender(ctx context.Context, peer smtpd.Peer, addr string) (context.Context, error) {
	var err error
	for _, x := range c.senderCheckers {
		ctx, err = x.CheckSender(ctx, peer, addr)
		if err != nil {
			return ctx, err
		}
	}
	return ctx, nil
}

func (c *chain) CheckRecipient(ctx context.Context, peer smtpd.Peer, addr string) (context.Context, error) {
	var err error
	for _, x := range c.recipientCheckers {
		ctx, err = x.CheckRecipient(ctx, peer, addr)
		if err != nil {
			return ctx, err
		}
	}
	return ctx, nil
}

func (c *chain) Reset(ctx context.Context, peer smtpd.Peer) context.Context {
	for _, x := range c.resetters {
		ctx = x.Reset(ctx, peer)
	}
	return ctx
}

func (c *chain) Disconnect(ctx context.Context, peer smtpd.Peer) {
	for _, x := range c.disconnecters {
		x.Disconnect(ctx, peer)
	}
}

// HasAuthenticator reports whether any layer of the chain implements
// smtpd.Authenticator. The server uses this to decide whether to advertise
// AUTH — a structural type assertion would always succeed since *chain
// unconditionally defines Authenticate.
func (c *chain) HasAuthenticator() bool { return len(c.authenticators) > 0 }

func (c *chain) Authenticate(ctx context.Context, peer smtpd.Peer, username, password string) (context.Context, error) {
	var err error
	for _, x := range c.authenticators {
		ctx, err = x.Authenticate(ctx, peer, username, password)
		if err != nil {
			return ctx, err
		}
	}
	return ctx, nil
}
