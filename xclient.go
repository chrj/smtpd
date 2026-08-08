package smtpd

import (
	"context"
	"net"
	"strconv"
	"strings"
)

func (s *session) handleXCLIENT(ctx context.Context, cmd *command) context.Context {
	ctx, _ = phasedLoggerFromContext(ctx, "xclient")

	fields := cmd.args()
	if len(fields) < 1 {
		return s.reply(ctx, 502, "Invalid syntax.")
	}

	if !s.server.EnableXCLIENT {
		return s.reply(ctx, 550, "XCLIENT not enabled")
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
			return s.reply(ctx, 502, "Couldn't decode the command.")
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
					return s.reply(ctx, 502, "Couldn't decode the command.")
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
			return s.reply(ctx, 502, "Couldn't decode the command.")
		}

	}

	tcpAddr, ok := s.peer.Addr.(*net.TCPAddr)
	if !ok {
		return s.reply(ctx, 502, "Unsupported network connection")
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
