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
		// A connection without an IP address is a unix socket or a pipe. A
		// local process is at the other end of one, and it reaches the server
		// without crossing a network.
		return true
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

// defaultTrustedIP reports whether an address is one that the public internet
// does not reach. It is the rule that a server without Server.TrustedProxies
// takes, and it covers the deployment where a proxy stands beside the server
// or on the network of the server.
func defaultTrustedIP(ip netip.Addr) bool {
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast()
}
