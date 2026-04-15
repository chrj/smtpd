package smtpd

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"strings"
	"time"
)

type command struct {
	line   string
	action string
	fields []string
	params []string
}

func parseLine(line string) (cmd command) {

	cmd.line = line
	cmd.fields = strings.Fields(line)

	if len(cmd.fields) > 0 {

		cmd.action = strings.ToUpper(cmd.fields[0])

		if len(cmd.fields) > 1 {

			// Account for some clients breaking the standard and having
			// an extra whitespace after the ':' character. Example:
			//
			// MAIL FROM: <test@example.org>
			//
			// Should be:
			//
			// MAIL FROM:<test@example.org>
			//
			// Thus, we add a check if the second field ends with ':'
			// and appends the rest of the third field.

			if cmd.fields[1][len(cmd.fields[1])-1] == ':' && len(cmd.fields) > 2 {
				cmd.fields[1] = cmd.fields[1] + cmd.fields[2]
				cmd.fields = cmd.fields[0:2]
			}

			cmd.params = strings.Split(cmd.fields[1], ":")

		}

	}

	return

}

func (session *session) handle(ctx context.Context, line string) context.Context {

	cmd := parseLine(line)

	// Commands are dispatched to the appropriate handler functions.
	// If a network error occurs during handling, the handler should
	// just return and let the error be handled on the next read.

	switch cmd.action {

	case "PROXY":
		return session.handlePROXY(ctx, cmd)

	case "HELO":
		return session.handleHELO(ctx, cmd)

	case "EHLO":
		return session.handleEHLO(ctx, cmd)

	case "MAIL":
		return session.handleMAIL(ctx, cmd)

	case "RCPT":
		return session.handleRCPT(ctx, cmd)

	case "STARTTLS":
		return session.handleSTARTTLS(ctx, cmd)

	case "DATA":
		return session.handleDATA(ctx, cmd)

	case "RSET":
		return session.handleRSET(ctx, cmd)

	case "NOOP":
		return session.handleNOOP(ctx, cmd)

	case "QUIT":
		return session.handleQUIT(ctx, cmd)

	case "AUTH":
		return session.handleAUTH(ctx, cmd)

	case "XCLIENT":
		return session.handleXCLIENT(ctx, cmd)

	}

	return session.reply(ctx, 502, "Unsupported command.")

}

func (session *session) handleHELO(ctx context.Context, cmd command) context.Context {

	if len(cmd.fields) < 2 {
		return session.reply(ctx, 502, "Missing parameter")
	}

	if session.peer.HeloName != "" {
		// Reset envelope in case of duplicate HELO
		ctx = session.reset(ctx)
	}

	var err error
	ctx, err = session.server.checkHelo(ctx, session.peer, cmd.fields[1])
	if err != nil {
		return session.error(ctx, err)
	}

	session.peer.HeloName = cmd.fields[1]
	session.peer.Protocol = SMTP
	return session.reply(ctx, 250, "Go ahead")

}

func (session *session) handleEHLO(ctx context.Context, cmd command) context.Context {

	if len(cmd.fields) < 2 {
		return session.reply(ctx, 502, "Missing parameter")
	}

	if session.peer.HeloName != "" {
		// Reset envelope in case of duplicate EHLO
		ctx = session.reset(ctx)
	}

	var err error
	ctx, err = session.server.checkHelo(ctx, session.peer, cmd.fields[1])
	if err != nil {
		return session.error(ctx, err)
	}

	session.peer.HeloName = cmd.fields[1]
	session.peer.Protocol = ESMTP

	_, _ = fmt.Fprintf(session.writer, "250-%s\r\n", session.server.Hostname)

	extensions := session.extensions()

	if len(extensions) > 1 {
		for _, ext := range extensions[:len(extensions)-1] {
			_, _ = fmt.Fprintf(session.writer, "250-%s\r\n", ext)
		}
	}

	return session.reply(ctx, 250, extensions[len(extensions)-1])

}

func (session *session) handleMAIL(ctx context.Context, cmd command) context.Context {
	if len(cmd.params) != 2 || strings.ToUpper(cmd.params[0]) != "FROM" {
		return session.reply(ctx, 502, "Invalid syntax.")
	}

	if session.peer.HeloName == "" {
		return session.reply(ctx, 502, "Please introduce yourself first.")
	}

	if session.server.hasAuthenticator() && !session.server.AuthOptional && session.peer.Username == "" {
		return session.reply(ctx, 530, "Authentication Required.")
	}

	if !session.tls && session.server.ForceTLS {
		return session.reply(ctx, 502, "Please turn on TLS by issuing a STARTTLS command.")
	}

	if session.envelope != nil {
		return session.reply(ctx, 502, "Duplicate MAIL")
	}

	var err error
	addr := "" // null sender

	// We must accept a null sender as per rfc5321 section-6.1.
	if cmd.params[1] != "<>" {
		addr, err = parseAddress(cmd.params[1])

		if err != nil {
			return session.reply(ctx, 502, "Malformed e-mail address")
		}
	}

	ctx, err = session.server.checkSender(ctx, session.peer, addr)
	if err != nil {
		return session.error(ctx, err)
	}

	session.envelope = &Envelope{
		Sender: addr,
	}

	return session.reply(ctx, 250, "Go ahead")

}

func (session *session) handleRCPT(ctx context.Context, cmd command) context.Context {
	if len(cmd.params) != 2 || strings.ToUpper(cmd.params[0]) != "TO" {
		return session.reply(ctx, 502, "Invalid syntax.")
	}

	if session.envelope == nil {
		return session.reply(ctx, 502, "Missing MAIL FROM command.")
	}

	if len(session.envelope.Recipients) >= session.server.MaxRecipients {
		return session.reply(ctx, 452, "Too many recipients")
	}

	addr, err := parseAddress(cmd.params[1])

	if err != nil {
		return session.reply(ctx, 502, "Malformed e-mail address")
	}

	ctx, err = session.server.checkRecipient(ctx, session.peer, addr)
	if err != nil {
		return session.error(ctx, err)
	}

	session.envelope.Recipients = append(session.envelope.Recipients, addr)

	return session.reply(ctx, 250, "Go ahead")

}

func (session *session) handleSTARTTLS(ctx context.Context, cmd command) context.Context {

	if session.tls {
		return session.reply(ctx, 502, "Already running in TLS")
	}

	if session.server.TLSConfig == nil {
		return session.reply(ctx, 502, "TLS not supported")
	}

	tlsConn := tls.Server(session.conn, session.server.TLSConfig)
	ctx = session.reply(ctx, 220, "Go ahead")

	if err := tlsConn.HandshakeContext(ctx); err != nil {
		session.log.ErrorContext(ctx, "tls handshake failed", slog.Any("err", err))
		return session.reply(ctx, 550, "Handshake error")
	}

	// Reset envelope as a new EHLO/HELO is required after STARTTLS
	ctx = session.reset(ctx)

	// Reset deadlines on the underlying connection before I replace it
	// with a TLS connection
	_ = session.conn.SetDeadline(time.Time{})

	// Replace connection with a TLS connection
	session.conn = tlsConn
	session.reader = bufio.NewReader(tlsConn)
	session.writer = bufio.NewWriter(tlsConn)
	session.scanner = bufio.NewScanner(session.reader)
	session.tls = true

	// Save connection state on peer
	state := tlsConn.ConnectionState()
	session.peer.TLS = &state

	// Flush the connection to set new timeout deadlines
	return session.flush(ctx)

}

func (session *session) handleRSET(ctx context.Context, cmd command) context.Context {
	session.reset(ctx)
	return session.reply(ctx, 250, "Go ahead")
}

func (session *session) handleNOOP(ctx context.Context, cmd command) context.Context {
	return session.reply(ctx, 250, "Go ahead")
}

func (session *session) handleQUIT(ctx context.Context, cmd command) context.Context {
	ctx = session.reply(ctx, 221, "OK, bye")
	return session.close(ctx)
}
