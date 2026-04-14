package middleware

import (
	"context"
	"net"
	"testing"

	"github.com/chrj/smtpd/v2/pkg/smtpd"
)

func TestIPAddressRateLimit(t *testing.T) {
	// 1 request/sec, burst of 1.
	mw := IPAddressRateLimit(1, 1)
	next := smtpd.HandlerFunc(func(ctx context.Context, peer smtpd.Peer, env smtpd.Envelope) error {
		return nil
	})
	h := mw(next)
	cc := h.(smtpd.ConnectionChecker)

	peer := smtpd.Peer{
		Addr: &net.TCPAddr{IP: net.ParseIP("10.0.0.1")},
	}

	// First call succeeds.
	if _, err := cc.CheckConnection(context.Background(), peer); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Second call (immediate) should be rate-limited.
	_, err := cc.CheckConnection(context.Background(), peer)
	if err == nil {
		t.Fatal("expected 450 error, got nil")
	}

	smtpdErr, ok := err.(smtpd.Error)
	if !ok || smtpdErr.Code != 450 {
		t.Fatalf("expected 450 error, got %v", err)
	}

	// Different IP should succeed.
	peer2 := smtpd.Peer{
		Addr: &net.TCPAddr{IP: net.ParseIP("10.0.0.2")},
	}
	if _, err := cc.CheckConnection(context.Background(), peer2); err != nil {
		t.Fatalf("unexpected error for second IP: %v", err)
	}
}

func TestIPAddressRateLimit_NonTCP(t *testing.T) {
	mw := IPAddressRateLimit(1, 1)
	next := smtpd.HandlerFunc(func(ctx context.Context, peer smtpd.Peer, env smtpd.Envelope) error {
		return nil
	})
	h := mw(next)
	cc := h.(smtpd.ConnectionChecker)

	peer := smtpd.Peer{
		Addr: &net.UnixAddr{Name: "/tmp/smtpd.sock", Net: "unix"},
	}

	// First call succeeds.
	if _, err := cc.CheckConnection(context.Background(), peer); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Second call (immediate) should also succeed for non-TCP.
	if _, err := cc.CheckConnection(context.Background(), peer); err != nil {
		t.Fatalf("unexpected error for second call (non-TCP): %v", err)
	}
}
