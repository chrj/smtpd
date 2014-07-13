package smtpd

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"strings"
	"time"
)

type Server struct {
	Addr           string // Address to listen on
	WelcomeMessage string // Initial server banner

	ReadTimeout  time.Duration // Socket timeout for read operations (default: 60s)
	WriteTimeout time.Duration // Socket timeout for write operations (default: 60s)

	// New e-mails are handed off to this function.
	// If an error is returned, it will be reported in the SMTP session
	Handler func(peer Peer, env Envelope) error

	// Enable PLAIN/LOGIN authentication
	Authenticator func(peer Peer, username, password string) error

	TLSConfig *tls.Config // Enable STARTTLS support
	ForceTLS  bool        // Force STARTTLS usage

	MaxMessageSize int // Max message size in bytes (default: 10240000)
}

type sessionState int

const (
	_STATE_HELO sessionState = iota
	_STATE_AUTH
	_STATE_MAIL
	_STATE_RCPT
	_STATE_DATA
)

type session struct {
	server *Server
	conn   net.Conn
	reader *bufio.Reader
	writer *bufio.Writer
	peer   Peer
	state  sessionState
	tls    bool
}

type Peer struct {
	HeloName string // Server name used in HELO/EHLO command
	UserName string // Username from authentication
	Addr     net.Addr // Network address
}

type MailAddress string

type Envelope struct {
	MailFrom   MailAddress
	Recipients []MailAddress
	Data       []byte
	Peer       *Peer
}

func (srv *Server) newConnection(c net.Conn) (s *session, err error) {

	log.Printf("New connection from: %s", c.RemoteAddr())

	s = &session{
		server: srv,
		conn:   c,
		reader: bufio.NewReader(c),
		writer: bufio.NewWriter(c),
		peer:   Peer{Addr: c.RemoteAddr()},
	}

	return s, nil

}

func (srv *Server) ListenAndServe() error {
	l, err := net.Listen("tcp", srv.Addr)
	if err != nil {
		return err
	}
	return srv.Serve(l)
}

func (srv *Server) Serve(l net.Listener) error {

	srv.configureDefaults()

	defer l.Close()

	for {

		conn, e := l.Accept()
		if e != nil {
			if ne, ok := e.(net.Error); ok && ne.Temporary() {
				time.Sleep(time.Second)
				continue
			}
			return e
		}

		session, err := srv.newConnection(conn)
		if err != nil {
			continue
		}

		session.state = _STATE_HELO

		go session.serve()

	}

}

func (srv *Server) configureDefaults() {

	if srv.MaxMessageSize == 0 {
		srv.MaxMessageSize = 10240000
	}

	if srv.ReadTimeout == 0 {
		srv.ReadTimeout = time.Second * 60
	}

	if srv.WriteTimeout == 0 {
		srv.WriteTimeout = time.Second * 60
	}

	if srv.ForceTLS && srv.TLSConfig == nil {
		log.Fatal("Cannot use ForceTLS with no TLSConfig")
	}

}

func (session *session) serve() {

	log.Print("Serving")

	defer func() {
		session.writer.Flush()
		session.conn.Close()
	}()

	session.reply(220, session.server.WelcomeMessage)

	scanner := bufio.NewScanner(session.reader)

	var env Envelope
	var data *bytes.Buffer

	for scanner.Scan() {

		line := scanner.Text()
		command := ""
		fields := []string{}
		params := []string{}

		if session.state != _STATE_DATA {
			fields = strings.Fields(line)
			command = strings.ToUpper(fields[0])
			if len(fields) > 1 {
				params = strings.Split(fields[1], ":")
			}
		}

		log.Printf("Line: %s, fields: %#v, params: %#v", line, fields, params)

		if command == "QUIT" {
			session.reply(250, "Ok, bye")
			return
		}

		switch session.state {

		case _STATE_HELO:

			if command == "HELO" || command == "EHLO" {
				if len(fields) < 2 {
					session.reply(502, "Missing parameter")
					continue
				} else {
					session.peer.HeloName = fields[1]
				}
			} else {
				session.reply(502, "Command not recognized, expected HELO/EHLO")
				continue
			}

			if command == "EHLO" {
				session.WriteExtensions()
			} else {
				session.reply(250, "Go ahead")
			}

			if session.server.Authenticator == nil {
				session.state = _STATE_MAIL
			} else {
				session.state = _STATE_AUTH
			}

			continue

		case _STATE_MAIL:

			if !session.tls && command == "STARTTLS" && session.server.TLSConfig != nil {

				tls_conn := tls.Server(session.conn, session.server.TLSConfig)
				session.reply(250, "Go ahead")

				if err := tls_conn.Handshake(); err != nil {
					log.Printf("TLS Handshake error:", err)
					session.reply(550, "Handshake error")
					continue
				}

				session.conn = tls_conn

				session.reader = bufio.NewReader(tls_conn)
				session.writer = bufio.NewWriter(tls_conn)

				scanner = bufio.NewScanner(session.reader)

				session.tls = true
				session.state = _STATE_HELO

				continue

			}

			if !session.tls && session.server.ForceTLS {
				session.reply(550, "Must run STARTTLS first")
				continue
			}

			if command == "MAIL" && strings.ToUpper(params[0]) == "FROM" {

				addr, err := parseMailAddress(params[1])

				if err != nil {
					session.reply(502, "Ill-formatted e-mail address")
					continue
				}

				env = Envelope{
					Peer:     &session.peer,
					MailFrom: addr,
				}

				session.reply(250, "Go ahead")
				session.state = _STATE_RCPT
				continue

			} else {
				session.reply(502, "Command not recognized, expected MAIL FROM")
				continue
			}

		case _STATE_RCPT:

			if command == "RCPT" && strings.ToUpper(params[0]) == "TO" {

				addr, err := parseMailAddress(params[1])

				if err != nil {
					session.reply(502, "Ill-formatted e-mail address")
					continue
				}

				env.Recipients = append(env.Recipients, addr)

				session.reply(250, "Go ahead")
				continue

			} else if command == "DATA" && len(env.Recipients) > 0 {
				session.reply(250, "Go ahead. End your data with <CR><LF>.<CR><LF>")
				data = &bytes.Buffer{}
				session.state = _STATE_DATA
				continue
			}

			if len(env.Recipients) == 0 {
				session.reply(502, "Command not recognized, expected RCPT")
			} else {
				session.reply(502, "Command not recognized, expected RCPT or DATA")
			}

			continue

		case _STATE_DATA:

			if line == "." {
				env.Data = data.Bytes()
				data.Reset()
				err := session.handle(env)

				if err != nil {
					session.reply(502, fmt.Sprintf("%s", err))
				} else {
					session.reply(200, "Thank you.")
				}

				session.state = _STATE_MAIL
				continue
			}

		}

	}

}

func (session *session) reply(code int, message string) {

	fmt.Fprintf(session.writer, "%d %s\r\n", code, message)

	session.conn.SetWriteDeadline(time.Now().Add(session.server.WriteTimeout))
	session.writer.Flush()

	session.conn.SetReadDeadline(time.Now().Add(session.server.ReadTimeout))

}

func (session *session) WriteExtensions() {

	extensions := []string{
		"SIZE 10240000",
	}

	if session.server.TLSConfig != nil && !session.tls {
		extensions = append(extensions, "STARTTLS")
	}

	if session.tls {
		extensions = append(extensions, "AUTH PLAIN LOGIN")
	}

	if len(extensions) > 1 {
		for _, ext := range extensions[:len(extensions)-1] {
			fmt.Fprintf(session.writer, "250-%s\r\n", ext)
		}
	}

	session.reply(250, extensions[len(extensions)-1])

}

func (session *session) handle(env Envelope) error {
	if session.server.Handler != nil {
		return session.server.Handler(session.peer, env)
	} else {
		return nil
	}
}

func parseMailAddress(src string) (MailAddress, error) {
	if src[0] != '<' || src[len(src)-1] != '>' || strings.Count(src, "@") != 1 {
		return MailAddress(""), fmt.Errorf("Ill-formatted e-mail address: %s", src)
	}
	return MailAddress(src[1 : len(src)-1]), nil
}
