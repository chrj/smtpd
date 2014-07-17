package smtpd

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"io/ioutil"
	"net/textproto"
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
	cmd.action = strings.ToUpper(cmd.fields[0])

	if len(cmd.fields) > 1 {
		cmd.params = strings.Split(cmd.fields[1], ":")
	}

	return

}

func (session *session) handle(line string) {

	cmd := parseLine(line)

	switch cmd.action {

	case "HELO":
		session.handleHELO(cmd)
		return

	case "EHLO":
		session.handleEHLO(cmd)
		return

	case "MAIL":
		session.handleMAIL(cmd)
		return

	case "RCPT":
		session.handleRCPT(cmd)
		return

	case "STARTTLS":
		session.handleSTARTTLS(cmd)
		return

	case "DATA":
		session.handleDATA(cmd)
		return

	case "RSET":
		session.handleRSET(cmd)
		return

	case "NOOP":
		session.handleNOOP(cmd)
		return

	case "QUIT":
		session.handleQUIT(cmd)
		return

	case "AUTH":
		session.handleAUTH(cmd)
		return

	}

	session.reply(502, "Unsupported command.")

}

func (session *session) handleHELO(cmd command) {

	if len(cmd.fields) < 2 {
		session.reply(502, "Missing parameter")
		return
	}

	if session.peer.HeloName != "" {
		// Reset envelope in case of duplicate HELO
		session.envelope = nil
	}

	session.peer.HeloName = cmd.fields[1]

	if session.server.HeloChecker != nil {
		err := session.server.HeloChecker(session.peer)
		if err != nil {
			session.error(err)
			return
		}
	}

	session.reply(250, "Go ahead")

	return

}

func (session *session) handleEHLO(cmd command) {

	if len(cmd.fields) < 2 {
		session.reply(502, "Missing parameter")
		return
	}

	if session.peer.HeloName != "" {
		// Reset envelope in case of duplicate EHLO
		session.envelope = nil
	}

	session.peer.HeloName = cmd.fields[1]

	if session.server.HeloChecker != nil {
		err := session.server.HeloChecker(session.peer)
		if err != nil {
			session.error(err)
			return
		}
	}

	extensions := session.extensions()

	if len(extensions) > 1 {
		for _, ext := range extensions[:len(extensions)-1] {
			fmt.Fprintf(session.writer, "250-%s\r\n", ext)
		}
	}

	session.reply(250, extensions[len(extensions)-1])

	return

}

func (session *session) handleMAIL(cmd command) {

	if session.peer.HeloName == "" {
		session.reply(502, "Please introduce yourself first.")
		return
	}

	if !session.tls && session.server.ForceTLS {
		session.reply(502, "Please turn on TLS by issuing a STARTTLS command.")
		return
	}

	if session.envelope != nil {
		session.reply(502, "Duplicate MAIL")
		return
	}

	addr, err := parseAddress(cmd.params[1])

	if err != nil {
		session.reply(502, "Ill-formatted e-mail address")
		return
	}

	if session.server.SenderChecker != nil {
		err = session.server.SenderChecker(session.peer, addr)
		session.error(err)
		return
	}

	session.envelope = &Envelope{
		Sender: addr,
	}

	session.reply(250, "Go ahead")

	return

}

func (session *session) handleRCPT(cmd command) {

	if session.envelope == nil {
		session.reply(502, "Missing MAIL FROM command.")
		return
	}

	if len(session.envelope.Recipients) >= session.server.MaxRecipients {
		session.reply(550, "Too many recipients")
		return
	}

	addr, err := parseAddress(cmd.params[1])

	if err != nil {
		session.reply(502, "Ill-formatted e-mail address")
		return
	}

	if session.server.RecipientChecker != nil {
		err = session.server.RecipientChecker(session.peer, addr)
		session.error(err)
		return
	}

	session.envelope.Recipients = append(session.envelope.Recipients, addr)

	session.reply(250, "Go ahead")

	return

}

func (session *session) handleSTARTTLS(cmd command) {

	if session.tls {
		session.reply(502, "Already running in TLS")
		return
	}

	if session.server.TLSConfig == nil {
		session.reply(502, "TLS not supported")
		return
	}

	tlsConn := tls.Server(session.conn, session.server.TLSConfig)
	session.reply(220, "Go ahead")

	if err := tlsConn.Handshake(); err != nil {
		session.reply(550, "Handshake error")
		return
	}

	// Reset envelope as a new EHLO/HELO is required after STARTTLS
	session.envelope = nil

	// Reset deadlines on the underlying connection before I replace it
	// with a TLS connection
	session.conn.SetDeadline(time.Time{})

	// Replace connection with a TLS connection
	session.conn = tlsConn
	session.reader = bufio.NewReader(tlsConn)
	session.writer = bufio.NewWriter(tlsConn)
	session.scanner = bufio.NewScanner(session.reader)
	session.tls = true

	// Flush the connection to set new timeout deadlines
	session.flush()

	return

}

func (session *session) handleDATA(cmd command) {

	if session.envelope == nil || len(session.envelope.Recipients) == 0 {
		session.reply(502, "Missing RCPT TO command.")
		return
	}

	session.reply(354, "Go ahead. End your data with <CR><LF>.<CR><LF>")
	session.conn.SetDeadline(time.Now().Add(session.server.DataTimeout))

	data := &bytes.Buffer{}
	reader := textproto.NewReader(session.reader).DotReader()

	_, err := io.CopyN(data, reader, int64(session.server.MaxMessageSize))

	if err == io.EOF {

		// EOF was reached before MaxMessageSize
		// Accept and deliver message

		session.envelope.Data = data.Bytes()

		if err := session.deliver(); err != nil {
			session.error(err)
		} else {
			session.reply(250, "Thank you.")
		}

		session.envelope = nil

	}

	if err != nil {
		// Network error, ignore
		return
	}

	// Discard the rest and report an error.
	_, err = io.Copy(ioutil.Discard, reader)

	if err != nil {
		// Network error, ignore
		return
	}

	session.reply(552, fmt.Sprintf(
		"Message exceeded max message size of %d bytes",
		session.server.MaxMessageSize,
	))

	session.envelope = nil

	return

}

func (session *session) handleRSET(cmd command) {
	session.envelope = nil
	session.reply(250, "Go ahead")
	return
}

func (session *session) handleNOOP(cmd command) {
	session.reply(250, "Go ahead")
	return
}

func (session *session) handleQUIT(cmd command) {
	session.reply(221, "OK, bye")
	session.close()
	return
}

func (session *session) handleAUTH(cmd command) {

	if session.server.Authenticator == nil {
		session.reply(502, "AUTH not supported.")
		return
	}

	if session.peer.HeloName == "" {
		session.reply(502, "Please introduce yourself first.")
		return
	}

	if !session.tls {
		session.reply(502, "Cannot AUTH in plain text mode. Use STARTTLS.")
		return
	}

	mechanism := strings.ToUpper(cmd.fields[1])

	username := ""
	password := ""

	switch mechanism {

	case "PLAIN":

		auth := ""

		if len(cmd.fields) < 3 {
			session.reply(334, "Give me your credentials")
			if !session.scanner.Scan() {
				return
			}
			auth = session.scanner.Text()
		} else {
			auth = cmd.fields[2]
		}

		data, err := base64.StdEncoding.DecodeString(auth)

		if err != nil {
			session.reply(502, "Couldn't decode your credentials")
			return
		}

		parts := bytes.Split(data, []byte{0})

		if len(parts) != 3 {
			session.reply(502, "Couldn't decode your credentials")
			return
		}

		username = string(parts[1])
		password = string(parts[2])

	case "LOGIN":

		session.reply(334, "VXNlcm5hbWU6")

		if !session.scanner.Scan() {
			return
		}

		byteUsername, err := base64.StdEncoding.DecodeString(session.scanner.Text())

		if err != nil {
			session.reply(502, "Couldn't decode your credentials")
			return
		}

		session.reply(334, "UGFzc3dvcmQ6")

		if !session.scanner.Scan() {
			return
		}

		bytePassword, err := base64.StdEncoding.DecodeString(session.scanner.Text())

		if err != nil {
			session.reply(502, "Couldn't decode your credentials")
			return
		}

		username = string(byteUsername)
		password = string(bytePassword)

	default:

		session.reply(502, "Unknown authentication mechanism")
		return

	}

	err := session.server.Authenticator(session.peer, username, password)
	if err != nil {
		session.error(err)
		return
	}

	session.peer.Username = username
	session.peer.Password = password

	session.reply(235, "OK, you are now authenticated")

}
