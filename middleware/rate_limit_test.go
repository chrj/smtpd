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

// TestIPAddressRateLimitHoldsAnIPv6Network verifies that the addresses of one
// IPv6 /64 share a bucket. A client on such a network takes any address of
// it, so a bucket for each address would never limit that client.
func TestIPAddressRateLimitHoldsAnIPv6Network(t *testing.T) {
	t.Parallel()

	check := IPAddressRateLimit(0.001, 1)
	peer := func(ip string) smtpd.Peer { return smtpd.Peer{Addr: &net.TCPAddr{IP: net.ParseIP(ip)}} }

	if err := check(context.Background(), peer("2001:db8:1:2::1")); err != nil {
		t.Fatalf("the first address of the network = %v, want no error", err)
	}

	want := smtpd.Error{Code: 450, Enhanced: smtpd.EnhancedCode{4, 7, 1}, Message: "rate-limited, try again later"}
	if err := check(context.Background(), peer("2001:db8:1:2:ffff:ffff:ffff:ffff")); err != want {
		t.Fatalf("another address of the same /64 = %v, want %v", err, want)
	}

	if err := check(context.Background(), peer("2001:db8:1:3::1")); err != nil {
		t.Fatalf("an address of the next /64 = %v, want no error", err)
	}
}

// TestIPAddressRateLimitReadsAMappedAddressAsIPv4 verifies that an IPv4
// address in the IPv6 form spends the bucket of the IPv4 address. A listener
// on "tcp" gives such a form for an IPv4 client.
func TestIPAddressRateLimitReadsAMappedAddressAsIPv4(t *testing.T) {
	t.Parallel()

	check := IPAddressRateLimit(0.001, 1)

	if err := check(context.Background(), smtpd.Peer{Addr: &net.TCPAddr{IP: net.ParseIP("192.0.2.7")}}); err != nil {
		t.Fatalf("the IPv4 address = %v, want no error", err)
	}
	if err := check(context.Background(), smtpd.Peer{Addr: &net.TCPAddr{IP: net.ParseIP("::ffff:192.0.2.7")}}); err == nil {
		t.Fatal("the same address in the IPv6 form got a bucket of its own")
	}
	if err := check(context.Background(), smtpd.Peer{Addr: &net.TCPAddr{IP: net.ParseIP("192.0.2.8")}}); err != nil {
		t.Fatalf("the next IPv4 address = %v, want no error", err)
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
