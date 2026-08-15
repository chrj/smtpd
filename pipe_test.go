package smtpd_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/chrj/smtpd/v2"
)

// The helpers in this file run a server over net.Pipe instead of TCP, so that
// a test of the read and write timeouts can run inside a synctest bubble.
//
// A bubble replaces the clock of the goroutines it holds. net.Pipe applies its
// deadlines in Go, so the bubble controls them and the test costs no real
// time. A TCP deadline comes from the operating system, which keeps the real
// clock. A goroutine that waits for a TCP read is also not durably blocked, so
// the bubble stops its clock and the test pays the full wait.

// pipeListener is a net.Listener that hands out one end of a net.Pipe for each
// call to dial. Close makes a waiting Accept return.
type pipeListener struct {
	conns  chan net.Conn
	closed chan struct{}
	once   sync.Once
}

func newPipeListener() *pipeListener {
	return &pipeListener{
		conns:  make(chan net.Conn),
		closed: make(chan struct{}),
	}
}

func (l *pipeListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.conns:
		return c, nil
	case <-l.closed:
		return nil, net.ErrClosed
	}
}

func (l *pipeListener) Close() error {
	l.once.Do(func() { close(l.closed) })
	return nil
}

// Addr reports a loopback address. The server logs it and the middleware reads
// it, but no test connects to it.
func (l *pipeListener) Addr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 25}
}

// dial gives the server one end of a new pipe and returns the other end.
func (l *pipeListener) dial(t *testing.T) net.Conn {
	t.Helper()

	client, server := net.Pipe()
	select {
	case l.conns <- server:
		return client
	case <-l.closed:
		t.Fatal("the listener closed before it accepted the connection")
		return nil
	}
}

// runpipeserver starts server on an in-memory listener. The caller runs inside
// a synctest bubble and closes the listener when the test ends.
func runpipeserver(t *testing.T, server *smtpd.Server) *pipeListener {
	t.Helper()

	l := newPipeListener()
	go func() { _ = server.Serve(l) }()

	return l
}

// bubbleCert is a self-signed certificate for "localhost". The validity window
// covers the year 2000, where a synctest bubble starts its clock, and it also
// covers the real time of a test that runs outside a bubble. A certificate cut
// for the current time only fails verification inside a bubble.
var bubbleCert = sync.OnceValue(newBubbleCert)

func newBubbleCert() tls.Certificate {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic("smtpd_test: generate the key of the test certificate: " + err.Error())
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		panic("smtpd_test: generate the serial number of the test certificate: " + err.Error())
	}

	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{Organization: []string{"smtpd_test"}, CommonName: "localhost"},
		NotBefore:             time.Date(1999, time.January, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:              time.Date(2100, time.January, 1, 0, 0, 0, 0, time.UTC),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		panic("smtpd_test: create the test certificate: " + err.Error())
	}

	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		panic("smtpd_test: parse the test certificate: " + err.Error())
	}

	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
}

// pipeServerTLS returns the TLS configuration that a server presents on a pipe.
func pipeServerTLS() *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{bubbleCert()},
		MinVersion:   tls.VersionTLS12,
	}
}

// pipeClientTLS returns a TLS configuration that trusts pipeServerTLS.
func pipeClientTLS() *tls.Config {
	pool := x509.NewCertPool()
	pool.AddCert(bubbleCert().Leaf)

	return &tls.Config{
		RootCAs:    pool,
		ServerName: "localhost",
		MinVersion: tls.VersionTLS12,
	}
}
