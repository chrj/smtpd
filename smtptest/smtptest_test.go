package smtptest_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/smtp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/chrj/smtpd/v2"
	"github.com/chrj/smtpd/v2/middleware"
	"github.com/chrj/smtpd/v2/smtptest"
)

const (
	testSender    = "sender@example.org"
	testRecipient = "recipient@example.net"
	testBody      = "Subject: test\r\n\r\nThis is the email body\r\n"
)

// dialPlain connects over a plain TCP connection and greets the server.
func dialPlain(t *testing.T, addr string) *smtp.Client {
	t.Helper()

	c, err := smtp.Dial(addr)
	if err != nil {
		t.Fatalf("Dial %s: %v", addr, err)
	}
	if err := c.Hello("client.example.org"); err != nil {
		t.Fatalf("EHLO: %v", err)
	}
	return c
}

// dialTLS connects with a TLS handshake before the SMTP greeting.
func dialTLS(t *testing.T, srv *smtptest.Server) *smtp.Client {
	t.Helper()

	conn, err := tls.Dial("tcp", srv.Addr, srv.ClientTLSConfig())
	if err != nil {
		t.Fatalf("TLS dial %s: %v", srv.Addr, err)
	}

	c, err := smtp.NewClient(conn, "localhost")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if err := c.Hello("client.example.org"); err != nil {
		t.Fatalf("EHLO: %v", err)
	}
	return c
}

// deliver sends one message and closes the session.
func deliver(t *testing.T, c *smtp.Client) {
	t.Helper()

	if err := smtptest.Send(c, testSender, []string{testRecipient}, testBody); err != nil {
		t.Fatalf("send the message: %v", err)
	}
}

func TestServerDelivery(t *testing.T) {
	tests := []struct {
		name    string
		start   func(smtpd.Handler) *smtptest.Server
		wantTLS bool
	}{
		{name: "plain", start: smtptest.NewServer, wantTLS: false},
		{name: "starttls", start: smtptest.NewSTARTTLSServer, wantTLS: true},
		{name: "implicit tls", start: smtptest.NewTLSServer, wantTLS: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			rec := &smtptest.Recorder{}
			srv := test.start(rec.Handler)
			defer srv.Close()

			if srv.Addr == "" {
				t.Fatal("Addr is empty after the server started")
			}

			// Dial completes the handshake that the transport needs.
			deliver(t, srv.Dial())

			messages := rec.Messages()
			if len(messages) != 1 {
				t.Fatalf("recorded %d messages, want 1", len(messages))
			}

			got := messages[0]
			if got.Sender != testSender {
				t.Errorf("Sender: got %q, want %q", got.Sender, testSender)
			}
			if len(got.Recipients) != 1 || got.Recipients[0] != testRecipient {
				t.Errorf("Recipients: got %q, want [%q]", got.Recipients, testRecipient)
			}
			if want := "Subject: test\n\nThis is the email body\n"; string(got.Data) != want {
				t.Errorf("Data: got %q, want %q", string(got.Data), want)
			}
			// net/smtp greets with "localhost" when the test sets no name.
			if got.Peer.HeloName != "localhost" {
				t.Errorf("HeloName: got %q, want %q", got.Peer.HeloName, "localhost")
			}
			if gotTLS := got.Peer.TLS != nil; gotTLS != test.wantTLS {
				t.Errorf("Peer.TLS is set: got %v, want %v", gotTLS, test.wantTLS)
			}
		})
	}
}

func TestServerSTARTTLSAdvertised(t *testing.T) {
	tests := []struct {
		name  string
		start func(smtpd.Handler) *smtptest.Server
		want  bool
	}{
		{name: "plain", start: smtptest.NewServer, want: false},
		{name: "starttls", start: smtptest.NewSTARTTLSServer, want: true},
		{name: "implicit tls", start: smtptest.NewTLSServer, want: false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			srv := test.start(nil)
			defer srv.Close()

			var c *smtp.Client
			if test.name == "implicit tls" {
				c = dialTLS(t, srv)
			} else {
				c = dialPlain(t, srv.Addr)
			}
			defer func() { _ = c.Quit() }()

			if got, _ := c.Extension("STARTTLS"); got != test.want {
				t.Errorf("STARTTLS advertised: got %v, want %v", got, test.want)
			}
		})
	}
}

func TestServerAuth(t *testing.T) {
	rec := &smtptest.Recorder{}
	srv := smtptest.NewUnstartedServer(rec.Handler)
	srv.Config.Use(middleware.Authenticator(
		func(_ context.Context, _ smtpd.Peer, user, pass string) error {
			if user != "joe" || pass != "secret" {
				return smtpd.Error{Code: 535, Message: "Denied"}
			}
			return nil
		},
	))
	srv.StartSTARTTLS()
	defer srv.Close()

	// PlainAuth compares the host against the name that the client dialed,
	// which is Host.
	c := srv.Dial()
	if err := c.Auth(smtp.PlainAuth("", "joe", "secret", srv.Host)); err != nil {
		t.Fatalf("AUTH: %v", err)
	}

	deliver(t, c)

	messages := rec.Messages()
	if len(messages) != 1 {
		t.Fatalf("recorded %d messages, want 1", len(messages))
	}
	if got := messages[0].Peer.Username; got != "joe" {
		t.Errorf("Username: got %q, want %q", got, "joe")
	}
}

func TestServerCertificate(t *testing.T) {
	srv := smtptest.NewSTARTTLSServer(nil)
	defer srv.Close()

	cert := srv.Certificate()
	if cert == nil {
		t.Fatal("Certificate returned nil for a TLS server")
	}
	if len(cert.DNSNames) != 1 || cert.DNSNames[0] != "localhost" {
		t.Errorf("DNSNames: got %q, want [\"localhost\"]", cert.DNSNames)
	}

	block, rest := pem.Decode(srv.CertPEM())
	if block == nil {
		t.Fatal("CertPEM did not return a PEM block")
	}
	if len(rest) != 0 {
		t.Errorf("CertPEM returned %d extra bytes after the block", len(rest))
	}
	if block.Type != "CERTIFICATE" {
		t.Errorf("PEM type: got %q, want %q", block.Type, "CERTIFICATE")
	}
	if string(block.Bytes) != string(cert.Raw) {
		t.Error("CertPEM does not hold the certificate of the server")
	}
}

// TestServerKeyPEM makes sure that CertPEM and KeyPEM are a pair, which a
// server under test can load from two files.
func TestServerKeyPEM(t *testing.T) {
	srv := smtptest.NewSTARTTLSServer(nil)
	defer srv.Close()

	pair, err := tls.X509KeyPair(srv.CertPEM(), srv.KeyPEM())
	if err != nil {
		t.Fatalf("X509KeyPair from CertPEM and KeyPEM: %v", err)
	}

	if len(pair.Certificate) != 1 || string(pair.Certificate[0]) != string(srv.Certificate().Raw) {
		t.Error("the pair does not hold the certificate of the server")
	}
}

func TestServerWithoutTLS(t *testing.T) {
	srv := smtptest.NewServer(nil)
	defer srv.Close()

	if got := srv.Certificate(); got != nil {
		t.Errorf("Certificate: got %v, want nil", got)
	}
	if got := srv.CertPEM(); got != nil {
		t.Errorf("CertPEM: got %q, want nil", got)
	}
	if got := srv.KeyPEM(); got != nil {
		t.Errorf("KeyPEM: got %q, want nil", got)
	}
	if got := srv.ClientTLSConfig(); got != nil {
		t.Errorf("ClientTLSConfig: got %v, want nil", got)
	}
}

// TestServerCustomCertificate makes sure that a Start method keeps a
// certificate that the test supplied. The certificate is out of date, so a
// client that verifies it must refuse the connection.
func TestServerCustomCertificate(t *testing.T) {
	expired := expiredCert(t)

	srv := smtptest.NewUnstartedServer(nil)
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{expired}}
	srv.StartSTARTTLS()
	defer srv.Close()

	if got := srv.Certificate().NotAfter; !got.Equal(expired.Leaf.NotAfter) {
		t.Errorf("NotAfter: got %v, want %v", got, expired.Leaf.NotAfter)
	}

	c := dialPlain(t, srv.Addr)
	defer func() { _ = c.Close() }()

	err := c.StartTLS(srv.ClientTLSConfig())
	if err == nil {
		t.Fatal("STARTTLS succeeded with an out of date certificate")
	}

	var invalid x509.CertificateInvalidError
	if !errors.As(err, &invalid) || invalid.Reason != x509.Expired {
		t.Errorf("STARTTLS error: got %v, want an out of date certificate", err)
	}
}

func TestServerHostAndPort(t *testing.T) {
	srv := smtptest.NewServer(nil)
	defer srv.Close()

	if want := net.JoinHostPort(srv.Host, strconv.Itoa(srv.Port)); want != srv.Addr {
		t.Errorf("Host and Port: got %q, want the parts of Addr %q", want, srv.Addr)
	}
	if srv.Port == 0 {
		t.Error("Port is zero after the server started")
	}
}

func TestServerDialNotStarted(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("Dial did not panic on a server that is not started")
		}
	}()

	srv := smtptest.NewUnstartedServer(nil)
	defer srv.Close()

	srv.Dial()
}

// TestServerDialAfterServeError makes sure that Dial reports why the server
// stopped. Without the report, a test only sees a dial error and no reason.
func TestServerDialAfterServeError(t *testing.T) {
	srv := smtptest.NewUnstartedServer(nil)
	srv.Config.BaseContext = func(net.Listener) context.Context { return nil }
	srv.Start()

	// Serve stops on its own here, so the test waits for that to happen.
	// Close would panic on the same error, so this test does not call it.
	deadline := time.Now().Add(5 * time.Second)
	for {
		got := dialPanic(srv)
		if got != nil && strings.Contains(fmt.Sprint(got), "BaseContext") {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("Dial did not report the reason of the stop: got %v", got)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// dialPanic returns the panic value of Dial, or nil when Dial did not panic.
func dialPanic(srv *smtptest.Server) (value any) {
	defer func() { value = recover() }()

	c := srv.Dial()
	_ = c.Close()
	return nil
}

func TestServerCloseUnstarted(t *testing.T) {
	srv := smtptest.NewUnstartedServer(nil)
	addr := srv.Listener.Addr().String()

	srv.Close()
	srv.Close()

	if _, err := net.DialTimeout("tcp", addr, time.Second); err == nil {
		t.Errorf("the listener on %s still accepts connections after Close", addr)
	}
}

// TestServerCloseRightAfterStart makes sure that Close frees the port even
// when it reaches the server before Serve did. Serve stops without a close of
// the listener in that order.
func TestServerCloseRightAfterStart(t *testing.T) {
	srv := smtptest.NewServer(nil)
	addr := srv.Addr
	srv.Close()

	conn, err := net.DialTimeout("tcp", addr, time.Second)
	if err == nil {
		_ = conn.Close()
		t.Errorf("the listener on %s still accepts connections after Close", addr)
	}
}

func TestServerCloseTwice(t *testing.T) {
	srv := smtptest.NewServer(nil)

	srv.Close()
	srv.Close()
}

// expiredCert returns a self-signed certificate for "localhost" that ran out
// one hour in the past.
func expiredCert(t *testing.T) tls.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate the key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "localhost"},
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              time.Now().Add(-time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create the certificate: %v", err)
	}

	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse the certificate: %v", err)
	}

	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
}
