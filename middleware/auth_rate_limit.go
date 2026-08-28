package middleware

import (
	"context"
	"log/slog"
	"net"

	"github.com/chrj/keyrate"
	"github.com/chrj/smtpd/v2"
	"golang.org/x/time/rate"
)

// errAuthRateLimited answers an address that has failed too often. RFC 4954
// section 6 gives 454 for a fault that passes, where 535 says that the
// credentials are wrong.
var errAuthRateLimited = smtpd.Error{
	Code:     454,
	Enhanced: smtpd.EnhancedCode{4, 7, 0},
	Message:  "Too many failed authentication attempts, try again later",
}

// AuthRateLimit wraps fn so that failed authentication attempts from one
// remote IP are rate limited. Each IP gets its own token bucket of size burst
// that refills at rps tokens per second.
//
// A failed attempt takes a token. A successful one takes none, so a client
// that always sends the right password never spends the bucket of its
// address. An IP with no tokens left gets a 454 reply, and fn does not run
// for it. The reply goes to every client at that address, a client with the
// right password included: the bucket belongs to the address.
//
// A successful attempt does not give back the tokens that earlier failures
// took, because a client that holds one good credential would then clear the
// count and go on guessing the rest. The bucket refills with time instead.
//
// Server.MaxAuthAttempts bounds the attempts of a single connection. This
// bounds the attempts of an address, which a client that opens a new
// connection for every guess would otherwise get around.
//
// Non-TCP peers, such as a unix socket, are never limited: the IP is what
// the bucket belongs to.
//
// Wrap the function that reads your credentials, and pass the result to
// Authenticator:
//
//	srv.Use(middleware.Authenticator(
//	    middleware.AuthRateLimit(myAuthFn, 1.0/60, 10),
//	))
//
// The bucket belongs to the address, so a client behind a shared address
// spends the tokens of every other client behind it. Idle buckets are
// dropped once they would have refilled.
func AuthRateLimit(fn AuthFunc, rps float64, burst int) AuthFunc {
	lims := keyrate.New[string](rate.Limit(rps), burst, keyrate.WithAutoEvict())

	return func(ctx context.Context, peer smtpd.Peer, user, pass string) error {
		tcpAddr, ok := peer.Addr.(*net.TCPAddr)
		if !ok {
			return fn(ctx, peer, user, pass)
		}

		// Tokens reads the bucket without taking from it, and it holds no
		// entry for an address that never failed. Two attempts of one address
		// can read the same token and both go on, which costs one attempt over
		// the burst and no more.
		key := tcpAddr.IP.String()
		if lims.Tokens(key) < 1 {
			smtpd.LoggerFromContext(ctx).WarnContext(ctx, "authentication rate-limited",
				slog.String("ip", key),
			)
			return errAuthRateLimited
		}

		err := fn(ctx, peer, user, pass)
		if err != nil {
			_ = lims.Allow(key)
		}
		return err
	}
}
