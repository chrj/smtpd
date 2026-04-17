package middleware

import (
	"context"
	"net"
	"testing"

	"github.com/chrj/smtpd/v2"
)

func TestIPAddressRateLimit(t *testing.T) {
	t.Parallel()

	check := IPAddressRateLimit(1, 1) // 1 rps, burst 1

	peer := smtpd.Peer{Addr: &net.TCPAddr{IP: net.ParseIP("10.0.0.1")}}

	if err := check(context.Background(), peer); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	err := check(context.Background(), peer)
	if err == nil {
		t.Fatal("expected 450 error, got nil")
	}
	smtpdErr, ok := err.(smtpd.Error)
	if !ok || smtpdErr.Code != 450 {
		t.Fatalf("expected 450 error, got %v", err)
	}

	peer2 := smtpd.Peer{Addr: &net.TCPAddr{IP: net.ParseIP("10.0.0.2")}}
	if err := check(context.Background(), peer2); err != nil {
		t.Fatalf("unexpected error for second IP: %v", err)
	}
}

func TestIPAddressRateLimit_NonTCP(t *testing.T) {
	t.Parallel()

	check := IPAddressRateLimit(1, 1)

	peer := smtpd.Peer{Addr: &net.UnixAddr{Name: "/tmp/smtpd.sock", Net: "unix"}}

	if err := check(context.Background(), peer); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := check(context.Background(), peer); err != nil {
		t.Fatalf("unexpected error for second call (non-TCP): %v", err)
	}
}

func TestIPAddressRateLimit_CheckConnection(t *testing.T) {
	t.Parallel()

	mw := CheckConnection(IPAddressRateLimit(1, 1))
	peer := smtpd.Peer{Addr: &net.TCPAddr{IP: net.ParseIP("10.0.0.1")}}
	if _, err := mw.CheckConnection(context.Background(), peer); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, err := mw.CheckConnection(context.Background(), peer); err == nil {
		t.Fatal("expected rate-limit error")
	}
}
