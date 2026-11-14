package smtpd

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

// handlePROXY answers a PROXY command that reaches the command loop.
//
// A server with Server.EnableProxyProtocol reads the header before the loop
// starts, so a PROXY command here comes after the header. The proxy writes
// its header before it passes on anything of the client, so this command
// comes from the client behind the proxy. A client that writes its own
// address takes the identity of another one: the greylist, the RBL check and
// the rate limit all read Peer.Addr.
func (s *session) handlePROXY(ctx context.Context, _ *command) context.Context {
	if !s.server.EnableProxyProtocol {
		return s.replyEnhanced(ctx, 550, EnhancedCode{5, 7, 0}, "Proxy Protocol not enabled")
	}

	return s.replyEnhanced(ctx, 503, EnhancedCode{5, 5, 1}, "PROXY comes first in a session, before every other command")
}

// readProxyHeader reads the header of the PROXY protocol, which stands first
// on the stream. The first octet tells the two versions apart: a header of
// version 2 begins with a CR, and a header of version 1 begins with "PROXY".
//
// The specification asks the receiver not to guess whether a header is there.
// A stream that begins with anything else is therefore a fault, and not a
// session without a proxy. Such a session would carry the address of the
// proxy in the place of the address of the client.
//
// Server.ReadTimeout bounds the whole header. The proxy writes it before
// anything else, so it arrives at the speed of the connection and not at the
// speed of a client.
func (s *session) readProxyHeader(ctx context.Context) (context.Context, error) {
	_ = s.conn.SetReadDeadline(time.Now().Add(s.server.ReadTimeout))

	first, err := s.reader.Peek(1)
	if err != nil {
		return ctx, err
	}

	if first[0] == proxyV2Signature[0] {
		return ctx, s.readProxyV2()
	}

	return s.readProxyV1(ctx)
}

// proxyV1Prefix is what a header of version 1 begins with: the keyword and one
// space. The specification writes the keyword in upper case alone.
const proxyV1Prefix = "PROXY "

// proxyV1MaxLen is the length of the longest header of version 1, with its
// CRLF. The specification gives 107 octets, for a header of the UNKNOWN
// protocol with two IPv6 addresses of the longest form.
const proxyV1MaxLen = 107

// readProxyV1 reads a header of version 1 and puts the address of the client
// on the peer.
//
// A header from a sender that the server does not trust gets a 550 reply,
// and the session ends. Every other header that the server cannot read ends
// the session without a reply. The sender of a header is a proxy and not a
// client, and the specification asks the receiver to drop such a connection.
func (s *session) readProxyV1(ctx context.Context) (context.Context, error) {
	line, err := s.readProxyV1Line()
	if err != nil {
		return ctx, err
	}

	// The header writes the address that every hook after it reads, so only
	// a proxy that the server trusts may send one. The decision comes before
	// the fields, so that such a sender learns nothing about them.
	if !s.server.trustsProxy(s.rawConn.RemoteAddr()) {
		ctx = s.replyEnhanced(ctx, 550, EnhancedCode{5, 7, 0}, "PROXY is not accepted from this address")
		return ctx, ProxyError{
			Reason: fmt.Sprintf("%s is not a trusted proxy, and only Server.TrustedProxies names one", s.rawConn.RemoteAddr()),
		}
	}

	addr, err := parseProxyV1(line)
	if err != nil {
		return ctx, err
	}

	// A client stands behind the proxy, and the proxy passes on what that
	// client sends from here. That holds for the UNKNOWN protocol as well:
	// the proxy says that it could not give the address of the client, and
	// not that it opened the connection for itself.
	s.proxied = true

	// The UNKNOWN protocol gives no address, and the ones of the connection
	// stay.
	if addr != nil {
		s.peer.Addr = addr
	}

	return ctx, nil
}

// readProxyV1Line reads the line of a header of version 1, and gives it
// without the CRLF.
//
// The specification gives CRLF as the end of the line, and it asks the
// receiver to take no CR or LF that stands alone. A line without a CRLF in
// its first 107 octets is not a header.
func (s *session) readProxyV1Line() (string, error) {
	line := make([]byte, 0, proxyV1MaxLen)

	for len(line) < proxyV1MaxLen {
		c, err := s.reader.ReadByte()
		if err != nil {
			// The caller saw the first octet before this read, so the stream
			// always ends inside the header here.
			if errors.Is(err, io.EOF) {
				err = io.ErrUnexpectedEOF
			}
			return "", ProxyError{
				Reason: fmt.Sprintf("the header stopped after %d octets, before its CRLF", len(line)),
				Err:    err,
			}
		}
		line = append(line, c)

		// The keyword stands first, so a stream of another kind ends here and
		// not at the end of its first line.
		if len(line) == len(proxyV1Prefix) && string(line) != proxyV1Prefix {
			return "", ProxyError{Reason: "the stream does not begin with a PROXY header"}
		}

		if c != '\n' {
			continue
		}

		end := len(line) - len("\r\n")
		if end < 0 || line[end] != '\r' {
			return "", ProxyError{Reason: "the header ends with a bare LF, and the specification gives CRLF"}
		}
		if end < len(proxyV1Prefix) {
			return "", ProxyError{Reason: "the stream does not begin with a PROXY header"}
		}

		return string(line[:end]), nil
	}

	return "", ProxyError{Reason: fmt.Sprintf("the header has no CRLF in its first %d octets", proxyV1MaxLen)}
}

// parseProxyV1 reads the fields of a header of version 1. line is the header
// without its CRLF, and it begins with proxyV1Prefix.
//
// The specification writes the header as:
//
//	PROXY TCP4 <source> <destination> <source port> <destination port>
//	PROXY TCP6 <source> <destination> <source port> <destination port>
//	PROXY UNKNOWN [<anything>]
//
// One space stands between two fields. An address is in its canonical form,
// and neither an address nor a port takes a zero in front. The destination
// fields say nothing about the client, and they are read so that a header
// that breaks the form is refused as a whole.
//
// The UNKNOWN protocol gives a nil address. The specification asks the
// receiver to ignore what follows the keyword, and to keep the addresses of
// the connection.
func parseProxyV1(line string) (net.Addr, error) {
	rest := line[len(proxyV1Prefix):]

	if rest == "UNKNOWN" || strings.HasPrefix(rest, "UNKNOWN ") {
		return nil, nil
	}

	fields := strings.Split(rest, " ")
	if len(fields) != 5 {
		return nil, ProxyError{Reason: fmt.Sprintf("the header has %d fields after PROXY, and the specification gives 5", len(fields))}
	}

	var ipv4 bool
	switch fields[0] {
	case "TCP4":
		ipv4 = true
	case "TCP6":
	default:
		return nil, ProxyError{Reason: fmt.Sprintf("the protocol %q is none of TCP4, TCP6 and UNKNOWN", fields[0])}
	}

	src, ok := parseProxyV1Addr(fields[1], ipv4)
	if !ok {
		return nil, ProxyError{Reason: fmt.Sprintf("the source address %q is not an address of %s", fields[1], fields[0])}
	}
	if _, ok := parseProxyV1Addr(fields[2], ipv4); !ok {
		return nil, ProxyError{Reason: fmt.Sprintf("the destination address %q is not an address of %s", fields[2], fields[0])}
	}

	srcPort, ok := parseProxyV1Port(fields[3])
	if !ok {
		return nil, ProxyError{Reason: fmt.Sprintf("the source port %q is not a port", fields[3])}
	}
	if _, ok := parseProxyV1Port(fields[4]); !ok {
		return nil, ProxyError{Reason: fmt.Sprintf("the destination port %q is not a port", fields[4])}
	}

	return &net.TCPAddr{IP: src.AsSlice(), Port: srcPort}, nil
}

// parseProxyV1Addr reads one address of a header of version 1. ipv4 says that
// the protocol is TCP4, and TCP6 takes an IPv6 address.
//
// netip.ParseAddr refuses a zero in front of an octet of an IPv4 address, as
// the specification does. A zone does not stand in the canonical form.
func parseProxyV1Addr(s string, ipv4 bool) (netip.Addr, bool) {
	addr, err := netip.ParseAddr(s)
	if err != nil || addr.Zone() != "" {
		return netip.Addr{}, false
	}

	if ipv4 {
		return addr, addr.Is4()
	}
	return addr, addr.Is6()
}

// parseProxyV1Port reads one port of a header of version 1: a decimal number
// from 0 to 65535, without a zero in front.
func parseProxyV1Port(s string) (int, bool) {
	if len(s) > 1 && s[0] == '0' {
		return 0, false
	}

	port, err := strconv.ParseUint(s, 10, 16)
	if err != nil {
		return 0, false
	}

	return int(port), true
}

// ProxyError reports a PROXY protocol header that the server refused, or a
// stream that does not begin with a header. Reason says what was wrong, such
// as a version that the server does not take. The session ends, and the
// Disconnect hooks read the error through their err argument.
//
// The session ends without a reply, with one exception: a header of version
// 1 from an address that the server does not trust gets a 550 first.
//
// Err holds the error that ended the read, where a read ended one: a header
// that stopped in the middle carries io.ErrUnexpectedEOF there, and one that
// stopped for the deadline of Server.ReadTimeout carries the error of the
// connection. errors.Is reads through it.
//
// Every header that the server could not read gives this error, from the
// first octet on. A caller therefore reads one type for a stream without a
// header, for a header that is not whole, and for a header that says
// something the server does not take.
type ProxyError struct {
	Reason string
	Err    error
}

func (e ProxyError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("smtpd: the PROXY header could not be read: %s: %v", e.Reason, e.Err)
	}
	return fmt.Sprintf("smtpd: the PROXY header could not be read: %s", e.Reason)
}

func (e ProxyError) Unwrap() error { return e.Err }

// proxyV2Signature is the first 12 octets of a PROXY protocol v2 header. The
// protocol takes these octets because no header of version 1 and no SMTP
// command begins with them, so the first octet alone tells the two apart.
var proxyV2Signature = []byte{0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A}

// proxyV2HeaderLen is the length of the part of a v2 header that every one of
// them carries: the signature, the version with the command, the address
// family with the transport protocol, and the length of the rest.
const proxyV2HeaderLen = 16

// The commands of a v2 header. LOCAL comes from the proxy itself, such as for
// a health check, and PROXY comes from a client behind it.
const (
	proxyV2Local = 0x0
	proxyV2Proxy = 0x1
)

// The address families of a v2 header.
const (
	proxyAFUnspec = 0x0
	proxyAFInet   = 0x1
	proxyAFInet6  = 0x2
	proxyAFUnix   = 0x3
)

// The transport protocols of a v2 header.
const (
	proxyTransportUnspec = 0x0
	proxyTransportStream = 0x1
	proxyTransportDgram  = 0x2
)

// The length of the address block of each family.
const (
	proxyAddrLenInet  = 12
	proxyAddrLenInet6 = 36
	proxyAddrLenUnix  = 216
)

// proxyUnixPathLen is the length of one path in the address block of the UNIX
// family. The path ends at the first NUL octet, and the rest of the field is
// NUL as well.
const proxyUnixPathLen = 108

// readProxyV2 reads a PROXY protocol v2 header and puts the address of the
// client on the peer. The caller saw the first octet of the signature.
//
// A header takes no reply, because the sender of it is a proxy and not a
// client. A header that the server cannot read therefore ends the session,
// which the specification asks for: the address of the client is unknown from
// that point, and a session that goes on carries the address of the proxy in
// its place.
func (s *session) readProxyV2() error {
	// A header stands here and nothing else does, so the trust of the sender
	// decides before the octets come off the stream. A header takes no reply,
	// so a sender that the server does not trust ends the session: it asked to
	// speak for another client, and the server cannot let it.
	if !s.server.trustsProxy(s.rawConn.RemoteAddr()) {
		return ProxyError{
			Reason: fmt.Sprintf("%s is not a trusted proxy, and only Server.TrustedProxies names one", s.rawConn.RemoteAddr()),
		}
	}

	// The first octet belongs to a header of version 2 and to nothing else,
	// so the session takes one from here on. A read that fails now is a
	// header that the server could not read, and not a stream of another
	// kind.
	header := make([]byte, proxyV2HeaderLen)
	if n, err := io.ReadFull(s.reader, header); err != nil {
		return ProxyError{
			Reason: fmt.Sprintf("the header takes %d octets and gave %d", proxyV2HeaderLen, n),
			Err:    err,
		}
	}

	// The octets are gone from the stream at this point, and nothing else
	// begins with them, so a signature that does not read ends the session.
	if !bytes.Equal(header[:len(proxyV2Signature)], proxyV2Signature) {
		return ProxyError{Reason: "the signature does not read"}
	}

	if version := header[12] >> 4; version != 2 {
		return ProxyError{Reason: fmt.Sprintf("version %d is not version 2", version)}
	}

	// The length covers the addresses and the values that follow them. It is
	// an unsigned 16-bit number, so the read below is bounded.
	block := make([]byte, binary.BigEndian.Uint16(header[14:16]))
	if n, err := io.ReadFull(s.reader, block); err != nil {
		return ProxyError{
			Reason: fmt.Sprintf("the header says %d octets follow it and gave %d", len(block), n),
			Err:    err,
		}
	}

	switch command := header[12] & 0x0F; command {
	case proxyV2Local:
		// The proxy opened this connection for itself, and the addresses of
		// the connection are the ones of the session.
		return nil
	case proxyV2Proxy:
		// A client stands behind the proxy, and the proxy passes on what that
		// client sends from here.
		s.proxied = true
	default:
		return ProxyError{Reason: fmt.Sprintf("command %d is neither LOCAL nor PROXY", command)}
	}

	addr, err := parseProxyV2Addr(header[13], block)
	if err != nil {
		return err
	}

	// A header of the unspecified family carries no address, and the ones of
	// the connection stay.
	if addr != nil {
		s.peer.Addr = addr
	}

	return nil
}

// parseProxyV2Addr reads the address of the client out of the address block
// of a v2 header. famProto is the octet that carries the address family and
// the transport protocol.
//
// A block of the unspecified family or the unspecified protocol gives a nil
// address, which leaves the addresses of the connection where they are.
//
// The values that a proxy writes after the addresses come off the stream with
// the block, and nothing here looks at them. They carry what the proxy knows
// about the connection, such as the name that the client asked for in a TLS
// handshake.
func parseProxyV2Addr(famProto byte, block []byte) (net.Addr, error) {
	family := famProto >> 4
	transport := famProto & 0x0F

	// The specification gives four families and three protocols, and it asks
	// the receiver to refuse every other value. This stands before the
	// unspecified value below, because one half of the octet says nothing
	// about the other half: 0xF0 carries a family that no version of the
	// protocol has, next to a protocol that says nothing.
	switch family {
	case proxyAFUnspec, proxyAFInet, proxyAFInet6, proxyAFUnix:
	default:
		return nil, ProxyError{Reason: fmt.Sprintf("address family %d is not one of the four families", family)}
	}

	switch transport {
	case proxyTransportUnspec, proxyTransportStream, proxyTransportDgram:
	default:
		return nil, ProxyError{Reason: fmt.Sprintf("transport protocol %d is not one of the three protocols", transport)}
	}

	// A family or a protocol that says nothing carries no address of a
	// client. The specification asks the receiver to read no address out of
	// such a block, so the addresses of the connection stay.
	if family == proxyAFUnspec || transport == proxyTransportUnspec {
		return nil, nil
	}

	// SMTP runs on a stream, so a header for datagrams describes another
	// connection than the one that the server took.
	if transport == proxyTransportDgram {
		return nil, ProxyError{Reason: "the transport protocol is datagram, and SMTP takes a stream"}
	}

	switch family {
	case proxyAFInet:
		if len(block) < proxyAddrLenInet {
			return nil, ProxyError{Reason: fmt.Sprintf("an address block of %d octets is too short for IPv4", len(block))}
		}
		return &net.TCPAddr{
			IP:   copyIP(block[0:4]),
			Port: int(binary.BigEndian.Uint16(block[8:10])),
		}, nil

	case proxyAFInet6:
		if len(block) < proxyAddrLenInet6 {
			return nil, ProxyError{Reason: fmt.Sprintf("an address block of %d octets is too short for IPv6", len(block))}
		}
		return &net.TCPAddr{
			IP:   copyIP(block[0:16]),
			Port: int(binary.BigEndian.Uint16(block[32:34])),
		}, nil

	case proxyAFUnix:
		if len(block) < proxyAddrLenUnix {
			return nil, ProxyError{Reason: fmt.Sprintf("an address block of %d octets is too short for a unix socket", len(block))}
		}
		path := block[:proxyUnixPathLen]
		if end := bytes.IndexByte(path, 0); end >= 0 {
			path = path[:end]
		}
		return &net.UnixAddr{Name: string(path), Net: "unix"}, nil
	}

	// The families above are the ones that the switch at the top lets
	// through, so nothing reaches this line.
	return nil, ProxyError{Reason: fmt.Sprintf("address family %d carries no address", family)}
}

// copyIP takes the address out of the block, so that the address on the peer
// holds no window into a buffer of the session.
func copyIP(src []byte) net.IP {
	ip := make(net.IP, len(src))
	copy(ip, src)
	return ip
}
