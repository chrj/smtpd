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

		parts := strings.Split(item, "=")

		if len(parts) != 2 {
			return s.reply(ctx, 502, "Couldn't decode the command.")
		}

		name := parts[0]
		value := parts[1]

		switch name {

		case "NAME":
			// Unused in smtpd package
			continue

		case "HELO":
			newHeloName = value
			continue

		case "ADDR":
			newAddr = net.ParseIP(value)
			continue

		case "PORT":
			var err error
			newTCPPort, err = strconv.ParseUint(value, 10, 16)
			if err != nil {
				return s.reply(ctx, 502, "Couldn't decode the command.")
			}
			continue

		case "LOGIN":
			newUsername = value
			continue

		case "PROTO":
			switch value {
			case "SMTP":
				newProto = SMTP
			case "ESMTP":
				newProto = ESMTP
			}
			continue

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
