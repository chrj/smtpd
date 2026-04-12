package smtpd

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/textproto"
	"strconv"
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
		return session.reset(ctx)
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

	if session.server.Authenticator != nil && !session.server.AuthOptional && session.peer.Username == "" {
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

	ctx, err = session.server.RecipientChecker(ctx, session.peer, addr)
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
		session.logError(ctx, err, "couldn't perform handshake")
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

func (session *session) handleDATA(ctx context.Context, cmd command) context.Context {

	if session.envelope == nil || len(session.envelope.Recipients) == 0 {
		return session.reply(ctx, 502, "Missing RCPT TO command.")
	}

	ctx = session.reply(ctx, 354, "Go ahead. End your data with <CR><LF>.<CR><LF>")
	_ = session.conn.SetDeadline(time.Now().Add(session.server.DataTimeout))

	data := &bytes.Buffer{}
	reader := textproto.NewReader(session.reader).DotReader()

	_, err := io.CopyN(data, reader, int64(session.server.MaxMessageSize))

	if err == io.EOF {

		// EOF was reached before MaxMessageSize
		// Accept and deliver message

		session.envelope.Data = data.Bytes()

		var err error

		ctx, err = session.deliver(ctx)
		if err != nil {
			ctx = session.error(ctx, err)
		} else {
			ctx = session.reply(ctx, 250, "Thank you.")
		}

		ctx = session.reset(ctx)

	}

	if err != nil {
		// Network error
		return ctx
	}

	// Discard the rest and report an error.
	_, err = io.Copy(io.Discard, reader)

	if err != nil {
		// Network error, ignore
		return ctx
	}

	session.reply(ctx, 552, fmt.Sprintf(
		"Message exceeded max message size of %d bytes",
		session.server.MaxMessageSize,
	))

	return session.reset(ctx)

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

func (session *session) handleAUTH(ctx context.Context, cmd command) context.Context {
	if len(cmd.fields) < 2 {
		return session.reply(ctx, 502, "Invalid syntax.")
	}

	if len(session.server.authenticators) == 0 {
		return session.reply(ctx, 502, "AUTH not supported.")
	}

	if session.peer.HeloName == "" {
		return session.reply(ctx, 502, "Please introduce yourself first.")
	}

	if !session.tls {
		return session.reply(ctx, 502, "Cannot AUTH in plain text mode. Use STARTTLS.")
	}

	mechanism := strings.ToUpper(cmd.fields[1])

	username := ""
	password := ""

	switch mechanism {

	case "PLAIN":

		auth := ""

		if len(cmd.fields) < 3 {
			ctx = session.reply(ctx, 334, "Give me your credentials")
			if !session.scanner.Scan() {
				return ctx
			}
			auth = session.scanner.Text()
		} else {
			auth = cmd.fields[2]
		}

		data, err := base64.StdEncoding.DecodeString(auth)

		if err != nil {
			return session.reply(ctx, 502, "Couldn't decode your credentials")
		}

		parts := bytes.Split(data, []byte{0})

		if len(parts) != 3 {
			return session.reply(ctx, 502, "Couldn't decode your credentials")
		}

		username = string(parts[1])
		password = string(parts[2])

	case "LOGIN":

		encodedUsername := ""

		if len(cmd.fields) < 3 {
			ctx = session.reply(ctx, 334, "VXNlcm5hbWU6")
			if !session.scanner.Scan() {
				return ctx
			}
			encodedUsername = session.scanner.Text()
		} else {
			encodedUsername = cmd.fields[2]
		}

		byteUsername, err := base64.StdEncoding.DecodeString(encodedUsername)

		if err != nil {
			return session.reply(ctx, 502, "Couldn't decode your credentials")
		}

		ctx = session.reply(ctx, 334, "UGFzc3dvcmQ6")

		if !session.scanner.Scan() {
			return ctx
		}

		bytePassword, err := base64.StdEncoding.DecodeString(session.scanner.Text())

		if err != nil {
			return session.reply(ctx, 502, "Couldn't decode your credentials")
		}

		username = string(byteUsername)
		password = string(bytePassword)

	default:

		session.logf("unknown authentication mechanism: %s", mechanism)
		return session.reply(ctx, 502, "Unknown authentication mechanism")

	}

	var err error
	ctx, err = session.server.authenticate(ctx, session.peer, username, password)
	if err != nil {
		return session.error(ctx, err)
	}

	session.peer.Username = username
	session.peer.Password = password

	return session.reply(ctx, 235, "OK, you are now authenticated")

}

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

	if newAddr != nil {
		tcpAddr.IP = newAddr
	}

	if newTCPPort != 0 {
		tcpAddr.Port = int(newTCPPort)
	}

	return session.welcome(ctx)

}
