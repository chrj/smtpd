package smtpd

import (
	"fmt"
	"strings"
	"crypto/tls"
	"bufio"
	"log"
	"bytes"
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

func (session *session) handleHELO(cmd command) {

	if len(cmd.fields) < 2 {
		session.reply(502, "Missing parameter")
		return
	}

	session.peer.HeloName = cmd.fields[1]

	if session.server.HeloChecker != nil {
		err := session.server.HeloChecker(session.peer)
		if err != nil {
			session.error(err)
			session.close()
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

	session.peer.HeloName = cmd.fields[1]

	if session.server.HeloChecker != nil {
		err := session.server.HeloChecker(session.peer)
		if err != nil {
			session.error(err)
			session.close()
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

	addr, err := parseMailAddress(cmd.params[1])

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

	addr, err := parseMailAddress(cmd.params[1])

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

	tls_conn := tls.Server(session.conn, session.server.TLSConfig)
	session.reply(250, "Go ahead")

	if err := tls_conn.Handshake(); err != nil {
		log.Printf("TLS Handshake error:", err)
		session.reply(550, "Handshake error")
		return
	}

	session.conn = tls_conn
	session.reader = bufio.NewReader(tls_conn)
	session.writer = bufio.NewWriter(tls_conn)
	session.scanner = bufio.NewScanner(session.reader)
	session.tls = true

	return

}

func (session *session) handleDATA(cmd command) {

	if session.envelope == nil || len(session.envelope.Recipients) == 0 {
		session.reply(502, "Missing RCPT TO command.")
		return
	}

	session.reply(250, "Go ahead. End your data with <CR><LF>.<CR><LF>")

	data := &bytes.Buffer{}
	done := false

	for session.scanner.Scan() {

		line := session.scanner.Text()

		if line == "." {
			done = true
			break
		}

		data.Write([]byte(line))
		data.Write([]byte("\r\n"))

	}

	if !done {
		return
	}

	session.envelope.Data = data.Bytes()

	err := session.deliver()

	if err != nil {
		session.error(err)
	} else {
		session.reply(200, "Thank you.")
	}

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
	session.reply(250, "OK, bye")
	session.close()
	return
}
