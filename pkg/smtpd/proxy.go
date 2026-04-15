package smtpd

import (
	"context"
	"net"
	"strconv"
)

func (session *session) handlePROXY(ctx context.Context, cmd command) context.Context {

	if !session.server.EnableProxyProtocol {
		return session.reply(ctx, 550, "Proxy Protocol not enabled")
	}

	if len(cmd.fields) < 6 {
		return session.reply(ctx, 502, "Couldn't decode the command.")
	}

	var (
		newAddr    net.IP
		newTCPPort uint64
		err        error
	)

	newAddr = net.ParseIP(cmd.fields[2])

	newTCPPort, err = strconv.ParseUint(cmd.fields[4], 10, 16)
	if err != nil {
		return session.reply(ctx, 502, "Couldn't decode the command.")
	}

	tcpAddr, ok := session.peer.Addr.(*net.TCPAddr)
	if !ok {
		return session.reply(ctx, 502, "Unsupported network connection")
	}

	updated := &net.TCPAddr{IP: tcpAddr.IP, Port: tcpAddr.Port, Zone: tcpAddr.Zone}
	if newAddr != nil {
		updated.IP = newAddr
	}
	if newTCPPort != 0 {
		updated.Port = int(newTCPPort)
	}
	session.peer.Addr = updated

	return session.welcome(ctx)

}
