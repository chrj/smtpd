package middleware

import (
	"context"
	"net"

	"github.com/chrj/keyrate"
	"github.com/chrj/smtpd"
	"golang.org/x/time/rate"
)

type ipRateLimit struct {
	limiters *keyrate.Limiters[string]
	next     smtpd.Handler
}

// IPAddressRateLimit throttles inbound connections per remote IP. Each IP gets
// its own token bucket of size burst that refills at rps tokens/second.
// Non-TCP peers (e.g. unix sockets) are never throttled. Idle limiters are
// evicted automatically once their bucket would have refilled.
func IPAddressRateLimit(rps float64, burst int) smtpd.Middleware {
	lims := keyrate.New[string](rate.Limit(rps), burst, keyrate.WithAutoEvict())
	return func(next smtpd.Handler) smtpd.Handler {
		return &ipRateLimit{limiters: lims, next: next}
	}
}

func (r *ipRateLimit) ServeSMTP(ctx context.Context, peer smtpd.Peer, env smtpd.Envelope) error {
	return r.next.ServeSMTP(ctx, peer, env)
}

func (r *ipRateLimit) CheckConnection(ctx context.Context, peer smtpd.Peer) (context.Context, error) {
	tcpAddr, ok := peer.Addr.(*net.TCPAddr)
	if !ok {
		return ctx, nil
	}
	if !r.limiters.Allow(tcpAddr.IP.String()) {
		return ctx, smtpd.Error{Code: 450, Message: "rate-limited, try again later"}
	}
	return ctx, nil
}
