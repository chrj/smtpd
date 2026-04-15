package middleware

import (
	"context"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/chrj/smtpd/v2/pkg/smtpd"
)

// GreylistChecker implements RFC 6647-style greylisting. The first time a
// (peer IP, sender, recipient) triple is seen, RCPT TO is temporarily
// rejected with 450. If the same triple retries after Delay has elapsed, it
// is accepted. Entries not retried within TTL are forgotten.
//
// Wire it into the RCPT TO phase:
//
//	g := middleware.Greylist()
//	srv.Handler = middleware.Chain(base,
//	    middleware.CheckRecipient(g.Check),
//	)
//
// The sender is read from context via smtpd.SenderFromContext.
type GreylistChecker struct {
	delay time.Duration
	ttl   time.Duration
	now   func() time.Time

	mu      sync.Mutex
	entries map[string]time.Time
}

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

// withGreylistClock is a test hook for overriding time.Now.
func withGreylistClock(now func() time.Time) GreylistOption {
	return func(g *GreylistChecker) { g.now = now }
}

// Greylist constructs a greylist checker with sensible defaults. The returned
// value is safe for concurrent use.
func Greylist(opts ...GreylistOption) *GreylistChecker {
	g := &GreylistChecker{
		delay:   5 * time.Minute,
		ttl:     24 * time.Hour,
		now:     time.Now,
		entries: make(map[string]time.Time),
	}
	for _, opt := range opts {
		opt(g)
	}
	return g
}

// Check is an AddrCheck suitable for CheckRecipient. Non-TCP peers bypass
// greylisting since the IP is the anti-spoof anchor of the triple.
func (g *GreylistChecker) Check(ctx context.Context, peer smtpd.Peer, recipient string) error {
	tcpAddr, ok := peer.Addr.(*net.TCPAddr)
	if !ok {
		return nil
	}
	sender, _ := smtpd.SenderFromContext(ctx)
	key := tcpAddr.IP.String() + "|" + sender + "|" + recipient

	now := g.now()
	g.mu.Lock()
	defer g.mu.Unlock()

	g.gc(now)

	first, seen := g.entries[key]
	if !seen {
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

func (g *GreylistChecker) gc(now time.Time) {
	for k, t := range g.entries {
		if now.Sub(t) > g.ttl {
			delete(g.entries, k)
		}
	}
}

// Compile-time check that Check satisfies AddrCheck.
var _ AddrCheck = (*GreylistChecker)(nil).Check
