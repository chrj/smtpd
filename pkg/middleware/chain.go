package middleware

import (
	"context"

	"github.com/chrj/smtpd/v2/pkg/smtpd"
)

// MiddlewareFunc adapts a plain function into a smtpd.Middleware with no
// checker interfaces. Use it for inline wrappers that only participate in the
// DATA phase.
type MiddlewareFunc func(next smtpd.Handler) smtpd.Handler

func (f MiddlewareFunc) Wrap(next smtpd.Handler) smtpd.Handler { return f(next) }

// Chain composes a base smtpd.Handler with middleware and returns an immutable
// Handler whose checker lists are resolved at build time. Leftmost middleware
// runs outermost (closest to the wire); rightmost runs innermost (closest to
// base). A nil base is treated as a no-op terminal handler.
func Chain(base smtpd.Handler, mw ...smtpd.Middleware) smtpd.Handler {
	if base == nil {
		base = smtpd.HandlerFunc(func(context.Context, smtpd.Peer, *smtpd.Envelope) error { return nil })
	}
	c := &chain{}
	c.collect(base)
	for _, m := range mw {
		c.collect(m)
	}
	h := base
	for i := len(mw) - 1; i >= 0; i-- {
		h = mw[i].Wrap(h)
	}
	c.handler = h
	return c
}

// chain is the composed Handler returned by Chain. It holds pre-resolved
// per-phase checker lists so the server does not walk wrappers at runtime.
type chain struct {
	handler            smtpd.Handler
	connectionCheckers []smtpd.ConnectionChecker
	heloCheckers       []smtpd.HeloChecker
	senderCheckers     []smtpd.SenderChecker
	recipientCheckers  []smtpd.RecipientChecker
	authenticators     []smtpd.Authenticator
	resetters          []smtpd.Resetter
}

func (c *chain) collect(v any) {
	if cc, ok := v.(smtpd.ConnectionChecker); ok {
		c.connectionCheckers = append(c.connectionCheckers, cc)
	}
	if hc, ok := v.(smtpd.HeloChecker); ok {
		c.heloCheckers = append(c.heloCheckers, hc)
	}
	if sc, ok := v.(smtpd.SenderChecker); ok {
		c.senderCheckers = append(c.senderCheckers, sc)
	}
	if rc, ok := v.(smtpd.RecipientChecker); ok {
		c.recipientCheckers = append(c.recipientCheckers, rc)
	}
	if aa, ok := v.(smtpd.Authenticator); ok {
		c.authenticators = append(c.authenticators, aa)
	}
	if r, ok := v.(smtpd.Resetter); ok {
		c.resetters = append(c.resetters, r)
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

func (c *chain) OnReset(ctx context.Context, peer smtpd.Peer) context.Context {
	for _, x := range c.resetters {
		ctx = x.OnReset(ctx, peer)
	}
	return ctx
}

// HasAuthenticator reports whether any middleware in the chain implements
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
