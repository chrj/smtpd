package middleware

import (
	"context"
	"log/slog"
	"net"
	"sync"

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
	l := &authLimiter{
		lims:     keyrate.New[string](rate.Limit(rps), burst, keyrate.WithAutoEvict()),
		fn:       fn,
		inFlight: make(map[string]int),
	}
	return l.check
}

// authLimiter holds the bucket of each address and the attempts that are
// running.
type authLimiter struct {
	lims *keyrate.Limiters[string]
	fn   AuthFunc

	mu sync.Mutex

	// inFlight counts the attempts of an address that the limiter let through
	// and that have not ended. The token of such an attempt is not taken
	// until the credential check answers, so the admission has to count them
	// itself. Without that, every attempt that overlaps reads the same token
	// and the whole set of them reaches the check.
	//
	// An address with nothing running holds no entry.
	inFlight map[string]int
}

func (l *authLimiter) check(ctx context.Context, peer smtpd.Peer, user, pass string) (err error) {
	tcpAddr, ok := peer.Addr.(*net.TCPAddr)
	if !ok {
		return l.fn(ctx, peer, user, pass)
	}

	key := tcpAddr.IP.String()
	if !l.admit(key) {
		smtpd.LoggerFromContext(ctx).WarnContext(ctx, "authentication rate-limited",
			slog.String("ip", key),
		)
		return errAuthRateLimited
	}

	// The deferred call runs for a check that panics as well, so that such an
	// attempt gives its place back. A panic is not a wrong password, and it
	// takes no token.
	defer func() { l.release(key, err != nil) }()

	return l.fn(ctx, peer, user, pass)
}

// admit takes a place for one attempt of the address, or reports that the
// bucket has nothing left for it.
func (l *authLimiter) admit(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	// Tokens reads the bucket without taking from it, and it writes no entry
	// for an address that never failed.
	if l.lims.Tokens(key)-float64(l.inFlight[key]) < 1 {
		return false
	}

	l.inFlight[key]++
	return true
}

// release gives back the place of an attempt that ended, and takes a token
// for one that failed. Both happen under the one lock that admit reads, so an
// attempt never sees a token that another one is about to take.
func (l *authLimiter) release(key string, failed bool) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if failed {
		_ = l.lims.Allow(key)
	}

	l.inFlight[key]--
	if l.inFlight[key] <= 0 {
		delete(l.inFlight, key)
	}
}
