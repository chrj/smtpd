package middleware

import "net"

type rateLimiter struct {
	limiters *keyrate.Limiters
	next     Handler
}

func IPAddressRateLimit(rps, burst int) Middleware {
	lims := keyrate.New[net.IP](rate.Limit(rps), burst)
	return func(next smtpd.Handler) smtpd.Handler {
		return &rateLimiter{limiter: lim, next: next}
	}
}

func (r *rateLimiter) CheckConnection(ctx context.Context, peer Peer) (context.Context, error) {
	if tcpAddr, ok := peer.Addr.(*net.TCPAddr); !ok || r.limiters.Allow(tcpAddr.IP) {
		return ctx, nil
	}
	return ctx, Error{Code: 450, Message: "rate-limited, try again later"}
}

func (r *rateLimiter) ServeSMTP(ctx context.Context, peer Peer, env smtpd.Envelope) error {
	// no-op during DATA
	return r.next.ServeSMTP(ctx, env)
}

type spfCheck struct {
	next Handler
}

func SPFCheck() Middleware {
	return func(next smtpd.Handler) smtpd.Handler {
		return &spfCHeck{spfClient: &spfClient{}, next: next}
	}
}

func (s *spfCheck) CheckSender(ctx context.Context, peer Peer, sender string) (context.Context, error) {
	if tcpAddr, ok := peer.Addr.(*net.TCPAddr); !ok || s.spfClient.Verify(sender, tcpAddr.IP) {
		return ctx, nil
	}
	return ctx, Error{Code: 550, Message: "spf verify failed"}
}

func (s *spfCheck) ServeSMTP(ctx context.Context, peer Peer, env smtpd.Envelope) error {
	// no-op during DATA
	return r.next.ServeSMTP(ctx, env)
}
