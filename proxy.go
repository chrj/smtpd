package smtpd

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"
)

func (s *session) handlePROXY(ctx context.Context, cmd *command) context.Context {
	fields := cmd.args()

	if !s.server.EnableProxyProtocol {
		return s.replyEnhanced(ctx, 550, EnhancedCode{5, 7, 0}, "Proxy Protocol not enabled")
	}

	// The proxy writes its header before it passes on anything of the client,
	// so a header that comes after a command comes from the client. A client
	// that writes its own address takes the identity of another one: the
	// greylist, the RBL check and the rate limit all read Peer.Addr.
	//
	// The message names the rule and not the command that closed the line,
	// because every command closes it: a session that ran one takes no header
	// at all from that point.
	if s.ranCommand {
		return s.replyEnhanced(ctx, 503, EnhancedCode{5, 5, 1}, "PROXY comes first in a session, before every other command")
	}

	if len(fields) < 5 {
		return s.replyEnhanced(ctx, 501, EnhancedCode{5, 5, 4}, "Couldn't decode the command.")
	}

	var (
		newAddr    net.IP
		newTCPPort uint64
		err        error
	)

	newAddr = net.ParseIP(fields[1])

	newTCPPort, err = strconv.ParseUint(fields[3], 10, 16)
	if err != nil {
		return s.replyEnhanced(ctx, 501, EnhancedCode{5, 5, 4}, "Couldn't decode the command.")
	}

	tcpAddr, ok := s.peer.Addr.(*net.TCPAddr)
	if !ok {
		return s.replyEnhanced(ctx, 502, EnhancedCode{5, 5, 1}, "Unsupported network connection")
	}

	updated := &net.TCPAddr{IP: tcpAddr.IP, Port: tcpAddr.Port, Zone: tcpAddr.Zone}
	if newAddr != nil {
		updated.IP = newAddr
	}
	if newTCPPort != 0 {
		updated.Port = int(newTCPPort)
	}
	s.peer.Addr = updated

	return s.welcome(ctx)

}

// ProxyError reports a PROXY protocol header that the server refused. Reason
// says what was wrong with it, such as a version that the server does not
// take. The session ends without a reply, and the Disconnect hooks read the
// error through their err argument.
type ProxyError struct {
	Reason string
}

func (e ProxyError) Error() string {
	return fmt.Sprintf("smtpd: the PROXY header could not be read: %s", e.Reason)
}

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
// client on the peer. found says that the header was there.
//
// A stream that begins with another octet stays where it is. A header of
// version 1 is a line of text, and the command loop reads that one as the
// PROXY command.
//
// A header takes no reply, because the sender of it is a proxy and not a
// client. A header that the server cannot read therefore ends the session,
// which the specification asks for: the address of the client is unknown from
// that point, and a session that goes on carries the address of the proxy in
// its place.
func (s *session) readProxyV2() (found bool, err error) {
	// The proxy writes the header before anything else, so it is there at the
	// speed of the connection and not at the speed of a client.
	_ = s.conn.SetReadDeadline(time.Now().Add(s.server.ReadTimeout))

	first, err := s.reader.Peek(1)
	if err != nil {
		return false, err
	}
	if first[0] != proxyV2Signature[0] {
		return false, nil
	}

	header := make([]byte, proxyV2HeaderLen)
	if _, err := io.ReadFull(s.reader, header); err != nil {
		return false, err
	}

	// The octets are gone from the stream at this point, and nothing else
	// begins with them, so a signature that does not read ends the session.
	if !bytes.Equal(header[:len(proxyV2Signature)], proxyV2Signature) {
		return true, ProxyError{Reason: "the signature does not read"}
	}

	if version := header[12] >> 4; version != 2 {
		return true, ProxyError{Reason: fmt.Sprintf("version %d is not version 2", version)}
	}

	// The length covers the addresses and the values that follow them. It is
	// an unsigned 16-bit number, so the read below is bounded.
	block := make([]byte, binary.BigEndian.Uint16(header[14:16]))
	if _, err := io.ReadFull(s.reader, block); err != nil {
		return true, err
	}

	switch command := header[12] & 0x0F; command {
	case proxyV2Local:
		// The proxy opened this connection for itself, and the addresses of
		// the connection are the ones of the session.
		return true, nil
	case proxyV2Proxy:
	default:
		return true, ProxyError{Reason: fmt.Sprintf("command %d is neither LOCAL nor PROXY", command)}
	}

	addr, err := parseProxyV2Addr(header[13], block)
	if err != nil {
		return true, err
	}

	// A header of the unspecified family carries no address, and the ones of
	// the connection stay.
	if addr != nil {
		s.peer.Addr = addr
	}

	return true, nil
}

// parseProxyV2Addr reads the address of the client out of the address block
// of a v2 header. famProto is the octet that carries the address family and
// the transport protocol.
//
// A block of the unspecified family or the unspecified protocol gives a nil
// address, which leaves the addresses of the connection where they are.
//
// The values that a proxy writes after the addresses stay unread. They carry
// what the proxy knows about the connection, such as the name that the client
// asked for in a TLS handshake.
func parseProxyV2Addr(famProto byte, block []byte) (net.Addr, error) {
	family := famProto >> 4
	transport := famProto & 0x0F

	if family == proxyAFUnspec || transport == proxyTransportUnspec {
		return nil, nil
	}

	// SMTP runs on a stream, so a header for datagrams describes another
	// connection than the one that the server took.
	if transport == proxyTransportDgram {
		return nil, ProxyError{Reason: "the transport protocol is datagram, and SMTP takes a stream"}
	}
	if transport != proxyTransportStream {
		return nil, ProxyError{Reason: fmt.Sprintf("transport protocol %d is not one of the protocols", transport)}
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

	return nil, ProxyError{Reason: fmt.Sprintf("address family %d is not one of the families", family)}
}

// copyIP takes the address out of the block, so that the address on the peer
// holds no window into a buffer of the session.
func copyIP(src []byte) net.IP {
	ip := make(net.IP, len(src))
	copy(ip, src)
	return ip
}
