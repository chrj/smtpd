package smtpd

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"
)

func (s *session) validateMailParams(params map[string]string) error {
	if len(params) == 0 {
		return nil
	}
	if s.peer.Protocol != ESMTP {
		return Error{Code: 555, Message: "MAIL FROM parameters not recognized or not implemented"}
	}

	for name, value := range params {
		switch name {
		case "SIZE":
			size, err := strconv.ParseInt(value, 10, 64)
			if err != nil || size < 0 {
				return Error{Code: 501, Message: "Invalid SIZE parameter"}
			}
			if size > int64(s.server.MaxMessageSize) {
				return Error{
					Code:    552,
					Message: fmt.Sprintf("Message size exceeds fixed maximum of %d bytes", s.server.MaxMessageSize),
				}
			}
		case "BODY":
			switch strings.ToUpper(value) {
			case "7BIT", "8BITMIME":
			default:
				return Error{Code: 501, Message: "Invalid BODY parameter"}
			}
		case "AUTH":
			// AUTH=<> and xtext-style identities are accepted as opaque values.
		default:
			return Error{Code: 555, Message: "MAIL FROM parameters not recognized or not implemented"}
		}
	}

	return nil
}

func (s *session) handle(ctx context.Context, line string) context.Context {
	cmd, err := parseCommand(line)
	if err != nil {
		return s.reply(ctx, 502, "Invalid syntax.")
	}

	// Commands are dispatched to the appropriate handler functions.
	// If a network error occurs during handling, the handler should
	// just return and let the error be handled on the next read.

	switch cmd.action {

	case "PROXY":
		return s.handlePROXY(ctx, cmd)

	case "HELO":
		return s.handleHELO(ctx, cmd)

	case "EHLO":
		return s.handleEHLO(ctx, cmd)

	case "MAIL":
		return s.handleMAIL(ctx, cmd)

	case "RCPT":
		return s.handleRCPT(ctx, cmd)

	case "STARTTLS":
		return s.handleSTARTTLS(ctx, cmd)

	case "DATA":
		return s.handleDATA(ctx, cmd)

	case "RSET":
		return s.handleRSET(ctx, cmd)

	case "NOOP":
		return s.handleNOOP(ctx, cmd)

	case "QUIT":
		return s.handleQUIT(ctx, cmd)

	case "AUTH":
		return s.handleAUTH(ctx, cmd)

	case "XCLIENT":
		return s.handleXCLIENT(ctx, cmd)

	}

	return s.reply(ctx, 502, "Unsupported command.")

}

func (s *session) handleHELO(ctx context.Context, cmd *command) context.Context {
	name, ok := cmd.singleArg()
	if !ok {
		return s.reply(ctx, 502, "Missing parameter")
	}

	if s.peer.HeloName != "" {
		// Reset envelope in case of duplicate HELO
		ctx = s.reset(ctx)
	}

	var err error
	ctx, err = s.server.checkHelo(ctx, s.peer, name)
	if err != nil {
		return s.replyError(ctx, err)
	}

	s.peer.HeloName = name
	s.peer.Protocol = SMTP
	return s.reply(ctx, 250, "Go ahead")

}

func (s *session) handleEHLO(ctx context.Context, cmd *command) context.Context {
	name, ok := cmd.singleArg()
	if !ok {
		return s.reply(ctx, 502, "Missing parameter")
	}

	if s.peer.HeloName != "" {
		// Reset envelope in case of duplicate EHLO
		ctx = s.reset(ctx)
	}

	var err error
	ctx, err = s.server.checkHelo(ctx, s.peer, name)
	if err != nil {
		return s.replyError(ctx, err)
	}

	s.peer.HeloName = name
	s.peer.Protocol = ESMTP

	_, _ = fmt.Fprintf(s.writer, "250-%s\r\n", s.server.Hostname)

	extensions := s.extensions()

	if len(extensions) > 1 {
		for _, ext := range extensions[:len(extensions)-1] {
			_, _ = fmt.Fprintf(s.writer, "250-%s\r\n", ext)
		}
	}

	return s.reply(ctx, 250, extensions[len(extensions)-1])

}

func (s *session) handleMAIL(ctx context.Context, cmd *command) context.Context {
	addrSpec, params, err := cmd.pathArg("FROM")
	if err != nil {
		return s.reply(ctx, 502, "Invalid syntax.")
	}

	if s.peer.HeloName == "" {
		return s.reply(ctx, 502, "Please introduce yourself first.")
	}

	if !s.tls && s.server.ForceTLS {
		return s.reply(ctx, 502, "Please turn on TLS by issuing a STARTTLS command.")
	}

	if s.envelope != nil {
		return s.reply(ctx, 502, "Duplicate MAIL")
	}

	addr := "" // null sender

	// We must accept a null sender as per rfc5321 section-6.1.
	if addrSpec != "<>" {
		addr, err = parseAddress(addrSpec)

		if err != nil {
			return s.reply(ctx, 502, "Malformed e-mail address")
		}
	}

	if err := s.validateMailParams(params); err != nil {
		return s.replyError(ctx, err)
	}

	ctx, err = s.server.checkSender(ctx, s.peer, addr)
	if err != nil {
		return s.replyError(ctx, err)
	}

	ctx = ContextWithSender(ctx, addr)

	s.envelope = &Envelope{
		Sender: addr,
	}

	return s.reply(ctx, 250, "Go ahead")

}

func (s *session) handleRCPT(ctx context.Context, cmd *command) context.Context {
	addrSpec, params, err := cmd.pathArg("TO")
	if err != nil {
		return s.reply(ctx, 502, "Invalid syntax.")
	}

	if s.envelope == nil {
		return s.reply(ctx, 502, "Missing MAIL FROM command.")
	}

	if len(s.envelope.Recipients) >= s.server.MaxRecipients {
		return s.reply(ctx, 452, "Too many recipients")
	}

	if len(params) > 0 {
		return s.reply(ctx, 555, "RCPT TO parameters not recognized or not implemented")
	}

	addr, err := parseAddress(addrSpec)

	if err != nil {
		return s.reply(ctx, 502, "Malformed e-mail address")
	}

	ctx, err = s.server.checkRecipient(ctx, s.peer, addr)
	if err != nil {
		return s.replyError(ctx, err)
	}

	s.envelope.Recipients = append(s.envelope.Recipients, addr)

	return s.reply(ctx, 250, "Go ahead")

}

func (s *session) handleSTARTTLS(ctx context.Context, cmd *command) context.Context {

	if s.tls {
		return s.reply(ctx, 502, "Already running in TLS")
	}

	if s.server.TLSConfig == nil {
		return s.reply(ctx, 502, "TLS not supported")
	}

	tlsConn := tls.Server(s.conn, s.server.TLSConfig)
	ctx = s.reply(ctx, 220, "Go ahead")

	if err := tlsConn.HandshakeContext(ctx); err != nil {
		s.log.ErrorContext(ctx, "tls handshake failed", slog.Any("err", err))
		s.setErr(err)
		// Best-effort 550 over the still-plain conn in case the client
		// hasn't sent ClientHello yet; then close - continuing from a
		// half-failed handshake leaves the byte stream unintelligible.
		ctx = s.reply(ctx, 550, "Handshake error")
		return s.close(ctx)
	}

	// Reset envelope as a new EHLO/HELO is required after STARTTLS
	ctx = s.reset(ctx)

	// Reset deadlines on the underlying connection before I replace it
	// with a TLS connection
	_ = s.conn.SetDeadline(time.Time{})

	// Replace connection with a TLS connection
	s.conn = tlsConn
	s.reader = bufio.NewReader(tlsConn)
	s.writer = bufio.NewWriter(tlsConn)
	s.scanner = bufio.NewScanner(s.reader)
	s.tls = true

	// Save connection state on peer
	state := tlsConn.ConnectionState()
	s.peer.TLS = &state

	// Flush the connection to set new timeout deadlines
	return s.flush(ctx)

}

func (s *session) handleRSET(ctx context.Context, cmd *command) context.Context {
	ctx = s.reset(ctx)
	return s.reply(ctx, 250, "Go ahead")
}

func (s *session) handleNOOP(ctx context.Context, cmd *command) context.Context {
	return s.reply(ctx, 250, "Go ahead")
}

func (s *session) handleQUIT(ctx context.Context, cmd *command) context.Context {
	ctx = s.reply(ctx, 221, "OK, bye")
	return s.close(ctx)
}
