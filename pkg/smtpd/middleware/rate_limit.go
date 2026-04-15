package middleware

import (
	"context"
	"net"

	"github.com/chrj/keyrate"
	"github.com/chrj/smtpd/v2/pkg/smtpd"
	"golang.org/x/time/rate"
)

// IPAddressRateLimit returns a PeerCheck that throttles inbound connections
// per remote IP. Each IP gets its own token bucket of size burst that refills
// at rps tokens/second. Non-TCP peers (e.g. unix sockets) are never throttled.
// Idle limiters are evicted automatically once their bucket would have refilled.
//
// Typical use:
//
//	srv.Handler = middleware.Chain(base,
//	    middleware.CheckConnection(middleware.IPAddressRateLimit(1, 10)),
//	)
func IPAddressRateLimit(rps float64, burst int) PeerCheck {
	lims := keyrate.New[string](rate.Limit(rps), burst, keyrate.WithAutoEvict())
	return func(ctx context.Context, peer smtpd.Peer) error {
		tcpAddr, ok := peer.Addr.(*net.TCPAddr)
		if !ok {
			return nil
		}
		if !lims.Allow(tcpAddr.IP.String()) {
			return smtpd.Error{Code: 450, Message: "rate-limited, try again later"}
		}
		return nil
	}
}
