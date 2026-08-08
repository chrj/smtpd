package middleware

import (
	"context"
	"log/slog"
	"net"
	"slices"
	"sync"
	"time"

	"github.com/chrj/smtpd/v2"
)

// GreylistChecker implements RFC 6647-style greylisting. The first time a
// (peer IP, sender, recipient) triple is seen, RCPT TO is temporarily
// rejected with 450. If the same triple retries after Delay has elapsed, it
// is accepted. Entries not retried within TTL are forgotten.
//
// Wire it into the RCPT TO phase:
//
//	g := middleware.Greylist()
//	srv.Handler = smtpd.Chain(base).
//	    Use(middleware.CheckRecipient(g.RecipientCheck)).
//	    Handler()
//
// The sender is read from context via smtpd.SenderFromContext.
//
// The checker holds at most MaxEntries triples and drops the oldest ones at
// that point, so a client that sends many different triples cannot take all
// the memory of the server. A dropped entry makes that triple start over,
// which delays mail but never accepts mail that the delay would have held.
type GreylistChecker struct {
	delay      time.Duration
	ttl        time.Duration
	maxEntries int
	sweepEvery time.Duration
	now        func() time.Time

	mu      sync.Mutex
	entries map[string]time.Time

	// nextSweep is the time of the next sweep for memory. Reclaiming memory
	// is separate from the TTL: RecipientCheck tests the age of an entry
	// itself, so a stale entry that is still in the map is treated as new.
	nextSweep time.Time

	// sweeps counts the sweeps that ran. Tests read it to prove that a sweep
	// does not run on every check.
	sweeps int
}

// defaultGreylistMaxEntries is the cap that Greylist uses when the caller
// gives none. At about 200 bytes for an entry, it is some 20MB.
const defaultGreylistMaxEntries = 100_000

// GreylistOption configures a GreylistChecker at construction time. Pass
// options to Greylist.
type GreylistOption func(*GreylistChecker)

// WithGreylistDelay sets how long a triple must wait between its first attempt
// and a successful retry. Default 5 minutes.
func WithGreylistDelay(d time.Duration) GreylistOption {
	return func(g *GreylistChecker) { g.delay = d }
}

// WithGreylistTTL sets how long an unsuccessful triple is remembered before it
// must start over. Default 24 hours.
func WithGreylistTTL(d time.Duration) GreylistOption {
	return func(g *GreylistChecker) { g.ttl = d }
}

// WithGreylistMaxEntries sets how many triples the checker holds. At the cap
// the oldest entries are dropped. Zero selects the default of 100000, which
// is about 20MB.
//
// A client that sends many different triples fills the map, so the cap is
// what stops it from taking all the memory of the server. A dropped entry
// makes that triple start over, which delays mail but never accepts mail that
// the delay would have held.
func WithGreylistMaxEntries(n int) GreylistOption {
	return func(g *GreylistChecker) { g.maxEntries = n }
}

// withGreylistClock is a test hook for overriding time.Now.
func withGreylistClock(now func() time.Time) GreylistOption {
	return func(g *GreylistChecker) { g.now = now }
}

// Greylist constructs a greylist checker with sensible defaults. The returned
// value is safe for concurrent use.
func Greylist(opts ...GreylistOption) *GreylistChecker {
	g := &GreylistChecker{
		delay:      5 * time.Minute,
		ttl:        24 * time.Hour,
		maxEntries: defaultGreylistMaxEntries,
		sweepEvery: time.Minute,
		now:        time.Now,
		entries:    make(map[string]time.Time),
	}
	for _, opt := range opts {
		opt(g)
	}

	// Zero means the default, as it does for the fields of smtpd.Server. A
	// cap below one would make the sweep drop every entry.
	if g.maxEntries < 1 {
		g.maxEntries = defaultGreylistMaxEntries
	}

	return g
}

// RecipientCheck is an AddrCheck suitable for CheckRecipient. Non-TCP peers
// bypass greylisting since the IP is the anti-spoof anchor of the triple.
func (g *GreylistChecker) RecipientCheck(ctx context.Context, peer smtpd.Peer, recipient string) error {
	tcpAddr, ok := peer.Addr.(*net.TCPAddr)
	if !ok {
		return nil
	}
	sender, _ := smtpd.SenderFromContext(ctx)
	key := tcpAddr.IP.String() + "|" + sender + "|" + recipient

	now := g.now()
	g.mu.Lock()
	defer g.mu.Unlock()

	g.maybeSweep(now)

	// An entry past the TTL is forgotten, whether or not the sweep already
	// removed it. Reading the age here keeps the answer the same at every
	// point between two sweeps.
	first, seen := g.entries[key]
	if !seen || now.Sub(first) > g.ttl {
		g.entries[key] = now
		smtpd.LoggerFromContext(ctx).InfoContext(ctx, "greylisted",
			slog.String("ip", tcpAddr.IP.String()),
			slog.String("sender", sender),
			slog.String("recipient", recipient))
		return smtpd.Error{Code: 450, Message: "greylisted, try again later"}
	}
	if now.Sub(first) < g.delay {
		return smtpd.Error{Code: 450, Message: "greylisted, try again later"}
	}
	return nil
}

// maybeSweep reclaims memory. It runs on an interval, and as soon as the map
// reaches the cap. A sweep on every check costs as much as the whole map, and
// holds the lock for that long.
func (g *GreylistChecker) maybeSweep(now time.Time) {
	if now.Before(g.nextSweep) && len(g.entries) < g.maxEntries {
		return
	}
	g.sweep(now)
	g.nextSweep = now.Add(g.sweepEvery)
	g.sweeps++
}

// sweep drops the entries past the TTL. When the map is still at the cap
// afterwards, it drops the oldest entries until the map is back under it.
func (g *GreylistChecker) sweep(now time.Time) {
	for k, t := range g.entries {
		if now.Sub(t) > g.ttl {
			delete(g.entries, k)
		}
	}

	if len(g.entries) < g.maxEntries {
		return
	}

	// The map is full of entries that are still live, so age decides. Sorting
	// the times gives the cut, and one more pass drops everything at or
	// before it. Going down to nine tenths of the cap keeps the next check
	// from starting another sweep.
	times := make([]time.Time, 0, len(g.entries))
	for _, t := range g.entries {
		times = append(times, t)
	}
	slices.SortFunc(times, func(a, b time.Time) int { return a.Compare(b) })

	// A small cap makes nine tenths of it round down, so keep at least one
	// entry and never more than the map holds.
	keep := min(max(g.maxEntries*9/10, 1), len(times))
	cut := times[len(times)-keep]
	for k, t := range g.entries {
		if !t.After(cut) {
			delete(g.entries, k)
		}
	}
}

// Compile-time check that RecipientCheck satisfies AddrCheck.
var _ AddrCheck = (*GreylistChecker)(nil).RecipientCheck
