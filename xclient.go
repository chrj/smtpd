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
				newAddr = net.ParseIP(value)
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
			switch value {
			case "SMTP":
				newProto = SMTP
			case "ESMTP":
				newProto = ESMTP
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
