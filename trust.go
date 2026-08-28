package smtpd

import (
	"net"
	"net/netip"
)

// connIP gives the address of a connection. ok is false for a connection that
// carries no IP address, such as a unix socket.
//
// The address comes back unmapped, because netip.Prefix.Contains matches an
// IPv4 address against an IPv4 prefix alone: the 4-in-6 form of the same
// address matches neither that prefix nor an IPv6 one.
func connIP(addr net.Addr) (netip.Addr, bool) {
	tcpAddr, ok := addr.(*net.TCPAddr)
	if !ok {
		return netip.Addr{}, false
	}

	ip, ok := netip.AddrFromSlice(tcpAddr.IP)
	if !ok {
		return netip.Addr{}, false
	}

	return ip.Unmap(), true
}

// trustsProxy reports whether the client at addr may restate the identity of
// the client behind it, with a PROXY protocol header or an XCLIENT command.
//
// addr is the address of the connection, and never Peer.Addr: a header that
// arrived already wrote that one, so reading it would let a client authorize
// itself with the address that it just sent.
func (srv *Server) trustsProxy(addr net.Addr) bool {
	ip, ok := connIP(addr)
	if !ok {
		// A unix socket and a pipe carry no address, and a local process is at
		// the other end of one. Every other address that carries no IP is one
		// that this reader cannot place, and a list of prefixes cannot name it
		// either, so trusting it would put a sender past a list that names the
		// proxies of the server.
		return isLocalTransport(addr)
	}

	if len(srv.TrustedProxies) == 0 {
		return defaultTrustedIP(ip)
	}

	for _, prefix := range srv.TrustedProxies {
		if prefix.Contains(ip) {
			return true
		}
	}

	return false
}

// isLocalTransport reports whether a connection reached the server without
// crossing a network. Such a connection carries no address to match, and a
// local process is at the other end of it.
//
// Server.Serve takes a listener of any kind, so an address of another kind can
// arrive here. This reader cannot place one, and it refuses what it cannot
// place: an address that no prefix can name must not stand where a list names
// the proxies of the server.
func isLocalTransport(addr net.Addr) bool {
	switch addr.Network() {
	case "unix", "unixgram", "unixpacket", "pipe":
		return true
	}
	return false
}

// defaultTrustedIP reports whether an address is one that the public internet
// does not reach. It is the rule that a server without Server.TrustedProxies
// takes, and it covers the deployment where a proxy stands beside the server
// or on the network of the server.
func defaultTrustedIP(ip netip.Addr) bool {
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast()
}
