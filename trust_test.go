package smtpd

import (
	"net"
	"net/netip"
	"strings"
	"testing"
)

// tcp gives a TCP address for an IP written as text.
func tcp(ip string) net.Addr {
	return &net.TCPAddr{IP: net.ParseIP(ip), Port: 2525}
}

// TestTrustsProxyByDefault covers the rule that a server without
// TrustedProxies takes: an address that the public internet does not reach
// may speak for the client behind it, and every other address may not.
func TestTrustsProxyByDefault(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		addr net.Addr
		want bool
	}{
		{name: "IPv4 loopback", addr: tcp("127.0.0.1"), want: true},
		{name: "IPv4 loopback of the whole range", addr: tcp("127.9.9.9"), want: true},
		{name: "IPv6 loopback", addr: tcp("::1"), want: true},
		{name: "RFC 1918 ten", addr: tcp("10.1.2.3"), want: true},
		{name: "RFC 1918 172.16", addr: tcp("172.16.0.1"), want: true},
		{name: "RFC 1918 192.168", addr: tcp("192.168.1.1"), want: true},
		{name: "RFC 4193 unique local", addr: tcp("fd00::1"), want: true},
		{name: "IPv4 link-local", addr: tcp("169.254.1.1"), want: true},
		{name: "IPv6 link-local", addr: tcp("fe80::1"), want: true},

		{name: "public IPv4", addr: tcp("203.0.113.7"), want: false},
		{name: "public IPv6", addr: tcp("2001:db8::1"), want: false},
		// 172.32 stands outside the /12 of RFC 1918, which ends at 172.31.
		{name: "just past RFC 1918 172.16/12", addr: tcp("172.32.0.1"), want: false},
		// RFC 6598 gives this range to carrier NAT. It is not private, and a
		// server on such a network names its proxy itself.
		{name: "carrier NAT", addr: tcp("100.64.0.1"), want: false},

		// A unix socket carries no IP, and a local process is at the far end.
		{name: "unix socket", addr: &net.UnixAddr{Name: "/run/smtpd.sock", Net: "unix"}, want: true},
	}

	srv := &Server{}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if got := srv.trustsProxy(test.addr); got != test.want {
				t.Fatalf("trustsProxy(%v) = %v, want %v", test.addr, got, test.want)
			}
		})
	}
}

// TestTrustsProxyFromTheList covers a server that names its proxies. The list
// replaces the default rule, so an address of a private range that the list
// leaves out is refused with the rest.
func TestTrustsProxyFromTheList(t *testing.T) {
	t.Parallel()

	srv := &Server{
		TrustedProxies: []netip.Prefix{
			netip.MustParsePrefix("203.0.113.0/24"),
			netip.MustParsePrefix("2001:db8::/32"),
		},
	}

	tests := []struct {
		name string
		addr net.Addr
		want bool
	}{
		{name: "inside the IPv4 prefix", addr: tcp("203.0.113.7"), want: true},
		{name: "the first address of the prefix", addr: tcp("203.0.113.0"), want: true},
		{name: "the last address of the prefix", addr: tcp("203.0.113.255"), want: true},
		{name: "outside the IPv4 prefix", addr: tcp("203.0.114.1"), want: false},
		{name: "inside the IPv6 prefix", addr: tcp("2001:db8::1"), want: true},
		{name: "outside the IPv6 prefix", addr: tcp("2001:db9::1"), want: false},

		// The list replaces the default rule. A server that names its proxies
		// says which addresses it trusts, and loopback is not one of them here.
		{name: "loopback that the list leaves out", addr: tcp("127.0.0.1"), want: false},
		{name: "private range that the list leaves out", addr: tcp("10.1.2.3"), want: false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if got := srv.trustsProxy(test.addr); got != test.want {
				t.Fatalf("trustsProxy(%v) = %v, want %v", test.addr, got, test.want)
			}
		})
	}
}

// TestTrustsProxyMatchesTheMappedForm verifies that an IPv4 address that
// arrives in the 4-in-6 form matches an IPv4 prefix.
//
// netip.Prefix.Contains matches neither prefix for such an address, so the
// reader takes the mapping off. A connection of a server that listens on a
// dual-stack socket carries an address of that form.
func TestTrustsProxyMatchesTheMappedForm(t *testing.T) {
	t.Parallel()

	// The 16-byte form of 203.0.113.7, which is what a dual-stack listener
	// gives for a client that reaches it over IPv4.
	mapped := &net.TCPAddr{IP: net.ParseIP("::ffff:203.0.113.7"), Port: 2525}
	if len(mapped.IP) != 16 {
		t.Fatalf("the test address is %d bytes, want the 16-byte form", len(mapped.IP))
	}

	srv := &Server{TrustedProxies: []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")}}
	if !srv.trustsProxy(mapped) {
		t.Fatal("the 4-in-6 form of a trusted address was refused")
	}

	// The same form takes the default rule as well.
	loopback := &net.TCPAddr{IP: net.ParseIP("::ffff:127.0.0.1"), Port: 2525}
	if !(&Server{}).trustsProxy(loopback) {
		t.Fatal("the 4-in-6 form of the loopback address was refused")
	}
}

// TestTrustsProxyRefusesAnEmptyPrefix verifies that a prefix that carries
// nothing matches no address. The zero value of netip.Prefix is not valid, and
// a list that holds one must not open the server to every client.
func TestTrustsProxyRefusesAnEmptyPrefix(t *testing.T) {
	t.Parallel()

	srv := &Server{TrustedProxies: []netip.Prefix{{}}}
	if srv.trustsProxy(tcp("203.0.113.7")) {
		t.Fatal("a zero prefix matched an address")
	}
}

// TestServeRefusesAnInvalidPrefix verifies that a prefix that does not read
// stops the server at Serve. Such a prefix matches no address, so the server
// would otherwise start and refuse every proxy.
func TestServeRefusesAnInvalidPrefix(t *testing.T) {
	t.Parallel()

	srv := &Server{TrustedProxies: []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"),
		{},
	}}

	err := srv.Serve(nil)
	if err == nil {
		t.Fatal("Serve took a prefix that does not read")
	}
	if !strings.Contains(err.Error(), "TrustedProxies[1]") {
		t.Fatalf("Serve() = %v, want an error that names the prefix", err)
	}
}
