package middleware

import (
	"context"
	"net"

	"github.com/chrj/keyrate"
	"github.com/chrj/smtpd/v2/pkg/smtpd"
	"golang.org/x/time/rate"
)

// IPRateLimit throttles inbound connections per remote IP. Each IP gets its
// own token bucket of size burst that refills at rps tokens/second. Non-TCP
// peers (e.g. unix sockets) are never throttled. Idle limiters are evicted
// automatically once their bucket would have refilled.
//
// IPRateLimit is a smtpd.Middleware: pass it to smtpd.Chain.
type IPRateLimit struct {
	limiters *keyrate.Limiters[string]
}

var (
	_ smtpd.Middleware        = (*IPRateLimit)(nil)
	_ smtpd.ConnectionChecker = (*IPRateLimit)(nil)
)

// IPAddressRateLimit returns a per-IP connection rate limiter.
func IPAddressRateLimit(rps float64, burst int) *IPRateLimit {
	return &IPRateLimit{
		limiters: keyrate.New[string](rate.Limit(rps), burst, keyrate.WithAutoEvict()),
	}
}

func (r *IPRateLimit) Wrap(next smtpd.Handler) smtpd.Handler { return next }

func (r *IPRateLimit) CheckConnection(ctx context.Context, peer smtpd.Peer) (context.Context, error) {
	tcpAddr, ok := peer.Addr.(*net.TCPAddr)
	if !ok {
		return ctx, nil
	}
	if !r.limiters.Allow(tcpAddr.IP.String()) {
		return ctx, smtpd.Error{Code: 450, Message: "rate-limited, try again later"}
	}
	return ctx, nil
}
