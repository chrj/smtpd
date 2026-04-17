package middleware

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/chrj/smtpd/v2"
)

func TestGreylist(t *testing.T) {
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
