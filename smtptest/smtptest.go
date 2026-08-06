// Package smtptest provides utilities for SMTP testing. It runs a real
// smtpd.Server on the loopback interface, so a test can drive an SMTP client
// end to end: over a plain connection, over STARTTLS, or over implicit TLS.
//
// The package follows net/http/httptest. A Server starts on a port that the
// system chooses, and it presents a self-signed certificate for "localhost"
// when the test supplies none. A setup error that a test cannot correct,
// such as a loopback interface that refuses a listener, causes a panic.
//
// Use a Recorder as the handler to read back the messages that the client
// sent. For a test that needs a client and not a client library, Dial
// returns a net/smtp client that already completed the handshake.
package smtptest

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/smtp"
	"strconv"
	"time"

	"github.com/chrj/smtpd/v2"
)

// shutdownTimeout is the time that Close gives the sessions that are still
// open before it closes their connections.
const shutdownTimeout = 5 * time.Second

// Server is an SMTP server that listens on a port of the loopback interface
// that the system chooses. Use it in end-to-end tests of an SMTP client.
type Server struct {
	// Addr is the "host:port" address of the listener. It is empty until a
	// Start method returns.
	Addr string

	// Host and Port are the two parts of Addr. Host is also the name that
	// smtp.PlainAuth expects. They stay empty and zero when the test replaced
	// Listener with a listener that is not TCP.
	Host string
	Port int

	// Listener is the loopback listener that the server accepts on. Replace
	// it before a Start method to serve on a listener of your own.
	Listener net.Listener

	// TLS is the TLS configuration of the server. Set it before a Start
	// method to present your own certificate. StartTLS and StartSTARTTLS
	// add the self-signed certificate for "localhost" only when this
	// configuration holds no certificate of its own. TLS stays nil after a
	// plain Start.
	TLS *tls.Config

	// Config is the server under test. Change its fields and register
	// middleware with Use before a Start method. The Start methods set
	// Config.TLSConfig, so do not set that field yourself: set Server.TLS.
	Config *smtpd.Server

	// transport records the choice of the Start method, so that Dial can
	// complete the same handshake as the server expects.
	transport transport

	// serveErr carries the result of Serve back to Close. It is nil until a
	// Start method runs, and Close sets it back to nil.
	serveErr chan error
}

// transport is the way a client reaches the server.
type transport int

const (
	// plain is SMTP without TLS.
	plain transport = iota
	// starttls is SMTP that a client upgrades with the STARTTLS command.
	starttls
	// implicitTLS is SMTP behind a TLS handshake, as SMTPS on port 465.
	implicitTLS
)

// NewServer starts a server that accepts plain connections and gives the
// messages to h. The caller must call Close when the test is complete.
func NewServer(h smtpd.Handler) *Server {
	s := NewUnstartedServer(h)
	s.Start()
	return s
}

// NewSTARTTLSServer starts a server that accepts plain connections and
// advertises STARTTLS. The caller must call Close when the test is complete.
func NewSTARTTLSServer(h smtpd.Handler) *Server {
	s := NewUnstartedServer(h)
	s.StartSTARTTLS()
	return s
}

// NewTLSServer starts a server that expects TLS from the first byte, as an
// SMTPS service on port 465 does. The caller must call Close when the test
// is complete.
func NewTLSServer(h smtpd.Handler) *Server {
	s := NewUnstartedServer(h)
	s.StartTLS()
	return s
}

// NewUnstartedServer opens a loopback listener and returns a server that
// gives the messages to h. Change Config and TLS, then call one of the Start
// methods.
func NewUnstartedServer(h smtpd.Handler) *Server {
	return &Server{
		Listener: newLocalListener(),
		Config: &smtpd.Server{
			Hostname: "localhost",
			Handler:  h,
		},
	}
}

// Start serves plain SMTP on the listener. The server does not offer
// STARTTLS.
func (s *Server) Start() {
	s.transport = plain
	s.serve(s.Listener)
}

// StartSTARTTLS serves plain SMTP on the listener and advertises STARTTLS in
// the reply to EHLO.
func (s *Server) StartSTARTTLS() {
	s.Config.TLSConfig = s.tlsConfig()
	s.transport = starttls
	s.serve(s.Listener)
}

// StartTLS wraps the listener in TLS, so the handshake comes before the SMTP
// greeting. This is the SMTPS deployment on port 465.
//
// The server does not advertise STARTTLS on such a connection, because it is
// already secure.
func (s *Server) StartTLS() {
	s.Config.TLSConfig = s.tlsConfig()
	s.transport = implicitTLS
	s.serve(tls.NewListener(s.Listener, s.Config.TLSConfig))
}

// Dial opens a connection to the server and returns a client that is ready
// for MAIL FROM. It completes the handshake that the transport of the server
// needs: it sends STARTTLS to a STARTTLS server, and it does the TLS
// handshake before the greeting for an implicit TLS server.
//
// Each call opens one connection. The caller must call Quit or Close on the
// client.
//
// Dial needs a TCP listener. A test that replaced Listener must open the
// connection itself.
func (s *Server) Dial() *smtp.Client {
	if s.Addr == "" {
		panic("smtptest: the server is not started")
	}

	if s.transport == implicitTLS {
		conn, err := tls.Dial("tcp", s.Addr, s.ClientTLSConfig())
		if err != nil {
			panic(fmt.Sprintf("smtptest: TLS dial %s: %v", s.Addr, err))
		}

		c, err := smtp.NewClient(conn, s.Host)
		if err != nil {
			_ = conn.Close()
			panic(fmt.Sprintf("smtptest: read the greeting of %s: %v", s.Addr, err))
		}
		return c
	}

	c, err := smtp.Dial(s.Addr)
	if err != nil {
		panic(fmt.Sprintf("smtptest: dial %s: %v", s.Addr, err))
	}

	if s.transport == starttls {
		if err := c.StartTLS(s.ClientTLSConfig()); err != nil {
			_ = c.Close()
			panic(fmt.Sprintf("smtptest: STARTTLS on %s: %v", s.Addr, err))
		}
	}

	return c
}

// Close stops the server and waits for the sessions that are still open. The
// second call and every call after it does nothing.
func (s *Server) Close() {
	serveErr := s.serveErr
	s.serveErr = nil

	if serveErr == nil {
		// The server never started, so only the listener holds a resource.
		// A close error on an unused listener tells a test nothing.
		_ = s.Listener.Close()
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()

	if err := s.Config.Shutdown(ctx); err != nil {
		panic(fmt.Sprintf("smtptest: stop the server on %s: %v", s.Addr, err))
	}

	// Serve reports every fault of the accept loop here. A test that ignores
	// it sees an empty Recorder and no reason for it.
	if err := <-serveErr; err != nil && !errors.Is(err, smtpd.ErrServerClosed) {
		panic(fmt.Sprintf("smtptest: serve on %s: %v", s.Addr, err))
	}
}

// Certificate returns the certificate that the server presents. It returns
// nil when the server serves no TLS.
func (s *Server) Certificate() *x509.Certificate {
	if s.TLS == nil || len(s.TLS.Certificates) == 0 {
		return nil
	}

	cert := s.TLS.Certificates[0]
	if cert.Leaf != nil {
		return cert.Leaf
	}
	if len(cert.Certificate) == 0 {
		return nil
	}

	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		panic(fmt.Sprintf("smtptest: parse the certificate of the server: %v", err))
	}
	return leaf
}

// CertPEM returns the certificate of the server in PEM form. Use it for a
// test that must write a trust anchor to a file. It returns nil when the
// server serves no TLS.
func (s *Server) CertPEM() []byte {
	cert := s.Certificate()
	if cert == nil {
		return nil
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
}

// ClientTLSConfig returns a TLS configuration for a client that connects to
// this server. It trusts the certificate of the server and it sets the name
// that the client expects. It returns nil when the server serves no TLS.
func (s *Server) ClientTLSConfig() *tls.Config {
	cert := s.Certificate()
	if cert == nil {
		return nil
	}

	pool := x509.NewCertPool()
	pool.AddCert(cert)

	name := "localhost"
	if len(cert.DNSNames) > 0 {
		name = cert.DNSNames[0]
	}

	return &tls.Config{
		RootCAs:    pool,
		ServerName: name,
		MinVersion: tls.VersionTLS12,
	}
}

// tlsConfig returns the TLS configuration for a Start method. It keeps a
// certificate that the test supplied, and it adds the self-signed
// certificate for "localhost" when the test supplied none.
func (s *Server) tlsConfig() *tls.Config {
	if s.TLS != nil {
		s.TLS = s.TLS.Clone()
	} else {
		s.TLS = &tls.Config{MinVersion: tls.VersionTLS12}
	}

	if len(s.TLS.Certificates) == 0 && s.TLS.GetCertificate == nil {
		s.TLS.Certificates = []tls.Certificate{localhostCert()}
	}

	return s.TLS
}

// serve records the address and runs the accept loop in its own goroutine.
// The goroutine stops when Close stops the server.
func (s *Server) serve(l net.Listener) {
	if s.Addr != "" {
		panic("smtptest: the server is already started")
	}

	s.Addr = s.Listener.Addr().String()
	s.Host, s.Port = splitAddr(s.Addr)

	// The goroutine keeps its own reference, because Close clears the field.
	serveErr := make(chan error, 1)
	s.serveErr = serveErr

	go func() {
		serveErr <- s.Config.Serve(l)
	}()
}

// splitAddr divides a "host:port" address. It returns an empty host and a
// zero port for an address that is not TCP, which a listener of the test can
// give.
func splitAddr(addr string) (host string, port int) {
	host, text, err := net.SplitHostPort(addr)
	if err != nil {
		return "", 0
	}

	port, err = strconv.Atoi(text)
	if err != nil {
		return "", 0
	}

	return host, port
}

// newLocalListener opens a listener on a port of the loopback interface that
// the system chooses.
func newLocalListener() net.Listener {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err == nil {
		return l
	}

	l6, err6 := net.Listen("tcp6", "[::1]:0")
	if err6 != nil {
		panic(fmt.Sprintf("smtptest: listen on the loopback interface: tcp: %v, tcp6: %v", err, err6))
	}
	return l6
}
