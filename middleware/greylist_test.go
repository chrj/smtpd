package middleware

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/chrj/smtpd/v2"
)

func TestGreylist(t *testing.T) {
	t.Parallel()

	now := time.Unix(1_700_000_000, 0)
	g := Greylist(
		WithGreylistDelay(5*time.Minute),
		WithGreylistTTL(1*time.Hour),
		withGreylistClock(func() time.Time { return now }),
	)

	peer := smtpd.Peer{Addr: &net.TCPAddr{IP: net.ParseIP("10.0.0.1")}}
	ctx := contextWithSenderForTest(t, "alice@example.com")

	// First attempt: rejected.
	if err := g.RecipientCheck(ctx, peer, "bob@example.com"); err == nil {
		t.Fatal("expected first attempt to be greylisted")
	} else if smtpdErr, ok := err.(smtpd.Error); !ok || smtpdErr.Code != 450 {
		t.Fatalf("expected 450 error, got %v", err)
	}

	// Retry immediately: still rejected.
	if err := g.RecipientCheck(ctx, peer, "bob@example.com"); err == nil {
		t.Fatal("expected retry before delay to be greylisted")
	}

	// Retry after delay: accepted.
	now = now.Add(6 * time.Minute)
	if err := g.RecipientCheck(ctx, peer, "bob@example.com"); err != nil {
		t.Fatalf("expected retry after delay to pass, got %v", err)
	}

	// Different recipient: new triple, rejected.
	if err := g.RecipientCheck(ctx, peer, "carol@example.com"); err == nil {
		t.Fatal("expected different recipient to be greylisted")
	}

	// Different sender: new triple, rejected.
	ctx2 := contextWithSenderForTest(t, "mallory@example.com")
	if err := g.RecipientCheck(ctx2, peer, "bob@example.com"); err == nil {
		t.Fatal("expected different sender to be greylisted")
	}
}

func TestGreylistTTLExpiry(t *testing.T) {
	t.Parallel()

	now := time.Unix(1_700_000_000, 0)
	g := Greylist(
		WithGreylistDelay(5*time.Minute),
		WithGreylistTTL(1*time.Hour),
		withGreylistClock(func() time.Time { return now }),
	)

	peer := smtpd.Peer{Addr: &net.TCPAddr{IP: net.ParseIP("10.0.0.1")}}
	ctx := contextWithSenderForTest(t, "alice@example.com")

	// First attempt: greylisted.
	if err := g.RecipientCheck(ctx, peer, "bob@example.com"); err == nil {
		t.Fatal("expected first attempt to be greylisted")
	}

	// Wait past TTL without retrying - entry should be forgotten.
	now = now.Add(2 * time.Hour)

	// Next attempt starts over: rejected again rather than silently accepted.
	if err := g.RecipientCheck(ctx, peer, "bob@example.com"); err == nil {
		t.Fatal("expected greylist after TTL expiry")
	}
}

func TestGreylistNonTCP(t *testing.T) {
	t.Parallel()

	g := Greylist()
	peer := smtpd.Peer{Addr: &net.UnixAddr{Name: "/tmp/s.sock", Net: "unix"}}
	ctx := contextWithSenderForTest(t, "alice@example.com")

	// Non-TCP peers bypass greylisting entirely.
	if err := g.RecipientCheck(ctx, peer, "bob@example.com"); err != nil {
		t.Fatalf("expected non-TCP peer to bypass greylist, got %v", err)
	}
}

func contextWithSenderForTest(t *testing.T, sender string) context.Context {
	t.Helper()
	return smtpd.ContextWithSender(context.Background(), sender)
}

// TestGreylistKeepsTheTripleParts verifies that two different triples never
// share an entry. The key held the three parts in one string with a "|"
// between them, and RFC 5321 gives "|" to the local part of an address, so
// moving the boundary made two triples meet:
//
//	sender "a|b@example.org" with recipient "c@example.net"
//	sender "a"               with recipient "b@example.org|c@example.net"
//
// The second of them then read the entry of the first, and it passed the
// delay that it never waited.
func TestGreylistKeepsTheTripleParts(t *testing.T) {
	t.Parallel()

	now := time.Unix(1_700_000_000, 0)
	g := Greylist(
		WithGreylistDelay(5*time.Minute),
		WithGreylistTTL(1*time.Hour),
		withGreylistClock(func() time.Time { return now }),
	)

	peer := smtpd.Peer{Addr: &net.TCPAddr{IP: net.ParseIP("10.0.0.1")}}

	first := contextWithSenderForTest(t, "a|b@example.org")
	if err := g.RecipientCheck(first, peer, "c@example.net"); err == nil {
		t.Fatal("expected the first triple to be greylisted")
	}

	// The first triple waits out its delay and is let through.
	now = now.Add(6 * time.Minute)
	if err := g.RecipientCheck(first, peer, "c@example.net"); err != nil {
		t.Fatalf("expected the first triple to pass after the delay, got %v", err)
	}

	// The second triple is a triple of its own, and it has waited for
	// nothing. It must be greylisted like any other first attempt.
	second := contextWithSenderForTest(t, "a")
	if err := g.RecipientCheck(second, peer, "b@example.org|c@example.net"); err == nil {
		t.Fatal("the second triple read the entry of the first and passed the delay")
	}
}
