package smtpd

import (
	"context"
	"net"
	"strconv"
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
