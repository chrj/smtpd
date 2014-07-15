// Package smtpd implements a SMTP server with support for STARTTLS, authentication (PLAIN/LOGIN) and optional restrictions on the different stages of the SMTP session.
package smtpd

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"os"
	"time"
)

// Server defines the parameters for running the SMTP server
type Server struct {
	Addr           string // Address to listen on when using ListenAndServe (default: "127.0.0.1:10025")
	WelcomeMessage string // Initial server banner (default: "<hostname> ESMTP ready.")

	ReadTimeout  time.Duration // Socket timeout for read operations (default: 60s)
	WriteTimeout time.Duration // Socket timeout for write operations (default: 60s)

	MaxMessageSize int // Max message size in bytes (default: 10240000)
	MaxConnections int // Max concurrent connections, use -1 to disable (default: 100)

	// New e-mails are handed off to this function.
	// Can be left empty for a NOOP server.
	// If an error is returned, it will be reported in the SMTP session.
	Handler func(peer Peer, env Envelope) error

	// Enable various checks during the SMTP session.
	// Can be left empty for no restrictions.
	// If an error is returned, it will be reported in the SMTP session.
	HeloChecker      func(peer Peer) error                   // Called after HELO/EHLO.
	SenderChecker    func(peer Peer, addr string) error // Called after MAIL FROM.
	RecipientChecker func(peer Peer, addr string) error // Called after each RCPT TO.

	// Enable PLAIN/LOGIN authentication, only available after STARTTLS.
	// Can be left empty for no authentication support.
	Authenticator func(peer Peer, username, password string) error

	TLSConfig *tls.Config // Enable STARTTLS support
	ForceTLS  bool        // Force STARTTLS usage
}

// Peer represents the client connecting to the server
type Peer struct {
	HeloName string   // Server name used in HELO/EHLO command
	Username string   // Username from authentication, if authenticated
	Password string   // Password from authentication, if authenticated
	Addr     net.Addr // Network address
}

// Envelope holds a message
type Envelope struct {
	Sender     string
	Recipients []string
	Data       []byte
}

type session struct {
	server *Server

	peer     Peer
	envelope *Envelope

	conn net.Conn

	reader  *bufio.Reader
	writer  *bufio.Writer
	scanner *bufio.Scanner

	tls bool
}

func (srv *Server) newSession(c net.Conn) (s *session, err error) {

	s = &session{
		server: srv,
		conn:   c,
		reader: bufio.NewReader(c),
		writer: bufio.NewWriter(c),
		peer:   Peer{Addr: c.RemoteAddr()},
	}

	s.scanner = bufio.NewScanner(s.reader)

	return s, nil

}

// ListenAndServe starts the SMTP server and listens on the address provided in Server.Addr
func (srv *Server) ListenAndServe() error {

	srv.configureDefaults()

	l, err := net.Listen("tcp", srv.Addr)
	if err != nil {
		return err
	}

	return srv.Serve(l)
}

// Serve starts the SMTP server and listens on the Listener provided
func (srv *Server) Serve(l net.Listener) error {

	srv.configureDefaults()

	defer l.Close()

	var limiter chan struct{}

	if srv.MaxConnections > 0 {
		limiter = make(chan struct{}, srv.MaxConnections)
	} else {
		limiter = nil
	}

	for {

		conn, e := l.Accept()
		if e != nil {
			if ne, ok := e.(net.Error); ok && ne.Temporary() {
				time.Sleep(time.Second)
				continue
			}
			return e
		}

		session, err := srv.newSession(conn)
		if err != nil {
			continue
		}

		if limiter != nil {
			go func() {
				select {
				case limiter <- struct{}{}:
					session.serve()
					<-limiter
				default:
					session.reject()
				}
			}()
		} else {
			go session.serve()
		}

	}

}

func (srv *Server) configureDefaults() {

	if srv.MaxMessageSize == 0 {
		srv.MaxMessageSize = 10240000
	}

	if srv.MaxConnections == 0 {
		srv.MaxConnections = 100
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

	if srv.Addr == "" {
		srv.Addr = "127.0.0.1:10025"
	}

	if srv.WelcomeMessage == "" {

		hostname, err := os.Hostname()

		if err != nil {
			log.Fatal("Couldn't determine hostname: %s", err)
		}

		srv.WelcomeMessage = fmt.Sprintf("%s ESMTP ready.", hostname)

	}

}

func (session *session) serve() {

	defer session.close()

	session.reply(220, session.server.WelcomeMessage)

	for session.scanner.Scan() {
		session.handle(session.scanner.Text())
	}

}

func (session *session) reject() {
	session.reply(450, "Too busy. Try again later.")
	session.close()
}

func (session *session) reply(code int, message string) {

	fmt.Fprintf(session.writer, "%d %s\r\n", code, message)

	session.conn.SetWriteDeadline(time.Now().Add(session.server.WriteTimeout))
	session.writer.Flush()

	session.conn.SetReadDeadline(time.Now().Add(session.server.ReadTimeout))

}

func (session *session) error(err error) {
	session.reply(502, fmt.Sprintf("%s", err))
}

func (session *session) extensions() []string {

	extensions := []string{
		fmt.Sprintf("SIZE %d", session.server.MaxMessageSize),
		"8BITMIME",
	}

	if session.server.TLSConfig != nil && !session.tls {
		extensions = append(extensions, "STARTTLS")
	}

	if session.server.Authenticator != nil && session.tls {
		extensions = append(extensions, "AUTH PLAIN LOGIN")
	}

	return extensions

}

func (session *session) deliver() error {
	if session.server.Handler != nil {
		return session.server.Handler(session.peer, *session.envelope)
	}
	return nil
}

func (session *session) close() {
	session.writer.Flush()
	session.conn.Close()
}
