package middleware

import (
	"context"
	"net"
	"net/netip"

	"github.com/chrj/keyrate"
	"github.com/chrj/smtpd/v2"
	"golang.org/x/time/rate"
)

// IPAddressRateLimit returns a PeerCheck that throttles inbound connections
// per remote IPv4 address, and per /64 for IPv6. Each one gets its own token
// bucket of size burst that refills at rps tokens/second. Non-TCP peers (e.g.
// unix sockets) are never throttled. Idle limiters are evicted automatically
// once their bucket would have refilled.
//
// Typical use:
//
//	srv.Handler = smtpd.Chain(base).
//	    Use(middleware.CheckConnection(middleware.IPAddressRateLimit(1, 10))).
//	    Handler()
func IPAddressRateLimit(rps float64, burst int) PeerCheck {
	lims := keyrate.New[string](rate.Limit(rps), burst, keyrate.WithAutoEvict())
	return func(ctx context.Context, peer smtpd.Peer) error {
		tcpAddr, ok := peer.Addr.(*net.TCPAddr)
		if !ok {
			return nil
		}
		if !lims.Allow(limitKey(tcpAddr.IP)) {
			return smtpd.Error{Code: 450, Enhanced: smtpd.EnhancedCode{4, 7, 1}, Message: "rate-limited, try again later"}
		}
		return nil
	}
}

// limitKey gives the key of the bucket that a client address spends. An IPv4
// address is the key as it is, also in the IPv6 form that a listener on "tcp"
// gives for an IPv4 client.
//
// An IPv6 address spends the bucket of its /64. RFC 4291 section 2.5.1 gives
// an interface identifier of 64 bits, so one network is a /64, and a client on
// it takes any of its 2^64 addresses. A bucket for each address would never
// limit that client.
func limitKey(ip net.IP) string {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return ip.String()
	}

	addr = addr.Unmap()
	if addr.Is4() {
		return addr.String()
	}

	network, err := addr.Prefix(64)
	if err != nil {
		return addr.String()
	}
	return network.String()
}
