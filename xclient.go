package smtpd

import (
	"context"
	"log/slog"
	"net"
	"strconv"
	"strings"
)

func (s *session) handleXCLIENT(ctx context.Context, cmd *command) context.Context {
	ctx, _ = phasedLoggerFromContext(ctx, "xclient")

	fields := cmd.args()
	if len(fields) < 1 {
		return s.replyEnhanced(ctx, 501, EnhancedCode{5, 5, 4}, "Invalid syntax.")
	}

	if !s.server.EnableXCLIENT {
		return s.replyEnhanced(ctx, 550, EnhancedCode{5, 7, 0}, "XCLIENT not enabled")
	}

	// The command writes Peer.Addr, Peer.HeloName, Peer.Username and
	// Peer.Protocol, so only a proxy that the server trusts may send one.
	//
	// The address of the connection decides, and never Peer.Addr: a PROXY
	// header that arrived first already wrote that one, and a client could
	// otherwise name an address of its own and then act on it.
	if !s.server.trustsProxy(s.rawConn.RemoteAddr()) {
		LoggerFromContext(ctx).WarnContext(ctx, "refused an XCLIENT command from an address that is not a trusted proxy",
			slog.String("address", s.rawConn.RemoteAddr().String()),
			slog.String("remedy", "add the address to Server.TrustedProxies"),
		)
		return s.replyEnhanced(ctx, 550, EnhancedCode{5, 7, 0}, "XCLIENT is not accepted from this address")
	}

	// A PROXY header stood for a client behind the proxy, and the proxy passes
	// on what that client sends. The address of the connection is still that
	// of the proxy, so it says nothing about who wrote this command, and the
	// client would take an identity of its own with it.
	if s.proxied {
		LoggerFromContext(ctx).WarnContext(ctx, "refused an XCLIENT command that followed a PROXY header",
			slog.String("address", s.rawConn.RemoteAddr().String()),
		)
		return s.replyEnhanced(ctx, 550, EnhancedCode{5, 7, 0}, "XCLIENT is not accepted after a PROXY header")
	}

	// The XCLIENT specification takes the command at any time, but not between
	// MAIL FROM and the end of the message. The hooks checked the sender of
	// that transaction for the client that the peer named then, and the
	// command gives the rest of the transaction to another client.
	if s.envelope != nil {
		return s.replyEnhanced(ctx, 503, EnhancedCode{5, 5, 1}, "XCLIENT is not accepted inside a mail transaction")
	}

	var (
		newHeloName, newUsername string
		newProto                 Protocol
		newAddr                  net.IP
		newTCPPort               uint64
	)

	for _, item := range fields {

		// Only the first equals sign splits the item. A value that carries
		// one of its own, such as the padding of base64, belongs to the
		// value.
		name, value, ok := strings.Cut(item, "=")
		if !ok {
			return s.replyEnhanced(ctx, 501, EnhancedCode{5, 5, 4}, "Couldn't decode the command.")
		}

		value = decodeXtext(value)

		// A control character has no place in a value. A handler writes
		// Peer.HeloName and Peer.Username into a Received header and into the
		// log, and a line break there starts a line that the client chose.
		if hasControl(value) {
			return s.replyEnhanced(ctx, 501, EnhancedCode{5, 5, 4}, "An XCLIENT value carries a control character")
		}

		// A value that says the proxy has no information leaves the
		// attribute as it was. The name of the attribute is still read, so
		// one that this server does not know is still refused.
		none := isUnavailable(value)

		switch name {

		case "NAME":
			// Unused in smtpd package

		case "HELO":
			if !none {
				newHeloName = value
			}

		case "ADDR":
			if !none {
				addr, ok := parseXclientAddr(value)
				if !ok {
					return s.replyEnhanced(ctx, 501, EnhancedCode{5, 5, 4}, "ADDR takes an IPv4 address, or an IPv6 address after IPV6:")
				}
				newAddr = addr
			}

		case "PORT":
			if !none {
				port, err := strconv.ParseUint(value, 10, 16)
				if err != nil {
					return s.replyEnhanced(ctx, 501, EnhancedCode{5, 5, 4}, "Couldn't decode the command.")
				}
				newTCPPort = port
			}

		case "LOGIN":
			if !none {
				newUsername = value
			}

		case "PROTO":
			// The specification gives SMTP and ESMTP. A value of another kind
			// leaves the protocol as it was, and with it the replies that the
			// client reads, so the command is refused.
			switch {
			case none:
			case equalASCIIFold(value, string(SMTP)):
				newProto = SMTP
			case equalASCIIFold(value, string(ESMTP)):
				newProto = ESMTP
			default:
				return s.replyEnhanced(ctx, 501, EnhancedCode{5, 5, 4}, "PROTO takes SMTP or ESMTP")
			}

		default:
			return s.replyEnhanced(ctx, 501, EnhancedCode{5, 5, 4}, "Couldn't decode the command.")
		}

	}

	tcpAddr, ok := s.peer.Addr.(*net.TCPAddr)
	if !ok {
		return s.replyEnhanced(ctx, 502, EnhancedCode{5, 5, 1}, "Unsupported network connection")
	}

	if newHeloName != "" {
		s.peer.HeloName = newHeloName
	}

	if newAddr != nil || newTCPPort != 0 {
		updated := &net.TCPAddr{IP: tcpAddr.IP, Port: tcpAddr.Port, Zone: tcpAddr.Zone}
		if newAddr != nil {
			updated.IP = newAddr
		}
		if newTCPPort != 0 {
			updated.Port = int(newTCPPort)
		}
		s.peer.Addr = updated
	}

	if newUsername != "" {
		s.peer.Username = newUsername
	}

	if newProto != "" {
		s.peer.Protocol = newProto
	}

	return s.welcome(ctx)

}

// xclientIPv6Prefix stands before an IPv6 address in the ADDR attribute of an
// XCLIENT command. The XCLIENT specification takes it in either case.
const xclientIPv6Prefix = "IPV6:"

// parseXclientAddr reads the value of the ADDR attribute of an XCLIENT
// command. The XCLIENT specification writes an IPv4 address as it is, and an
// IPv6 address after the prefix "IPV6:".
//
// An IPv6 address without the prefix is read as well. The specification does
// not give that form, but the value says one thing alone, and a proxy that
// sends it has a session that works.
//
// ok is false for every other value, and the caller refuses the command. A
// value that the caller drops leaves the address of the proxy on the peer.
// Every hook that reads Peer.Addr then reads the proxy in the place of the
// client.
func parseXclientAddr(value string) (ip net.IP, ok bool) {
	prefixed := len(value) >= len(xclientIPv6Prefix) &&
		equalASCIIFold(value[:len(xclientIPv6Prefix)], xclientIPv6Prefix)
	if prefixed {
		value = value[len(xclientIPv6Prefix):]
	}

	ip = net.ParseIP(value)
	if ip == nil {
		return nil, false
	}

	// The prefix says that an IPv6 address follows, and the text of every
	// IPv6 address carries a colon.
	if prefixed && !strings.Contains(value, ":") {
		return nil, false
	}

	return ip, true
}
