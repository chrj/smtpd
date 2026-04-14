package smtpd

import (
	"context"
	"net"
	"strconv"
	"strings"
)

func (session *session) handleXCLIENT(ctx context.Context, cmd command) context.Context {
	if len(cmd.fields) < 2 {
		return session.reply(ctx, 502, "Invalid syntax.")
	}

	if !session.server.EnableXCLIENT {
		return session.reply(ctx, 550, "XCLIENT not enabled")
	}

	var (
		newHeloName, newUsername string
		newProto                 Protocol
		newAddr                  net.IP
		newTCPPort               uint64
	)

	for _, item := range cmd.fields[1:] {

		parts := strings.Split(item, "=")

		if len(parts) != 2 {
			return session.reply(ctx, 502, "Couldn't decode the command.")
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
				return session.reply(ctx, 502, "Couldn't decode the command.")
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
			return session.reply(ctx, 502, "Couldn't decode the command.")
		}

	}

	tcpAddr, ok := session.peer.Addr.(*net.TCPAddr)
	if !ok {
		return session.reply(ctx, 502, "Unsupported network connection")
	}

	if newHeloName != "" {
		session.peer.HeloName = newHeloName
	}

	if newAddr != nil {
		tcpAddr.IP = newAddr
	}

	if newTCPPort != 0 {
		tcpAddr.Port = int(newTCPPort)
	}

	if newUsername != "" {
		session.peer.Username = newUsername
	}

	if newProto != "" {
		session.peer.Protocol = newProto
	}

	return session.welcome(ctx)

}
