package smtpd_test

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
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/textproto"
	"sync"
	"testing"
	"time"

	"github.com/chrj/smtpd/v2"
)

// testCert returns a freshly-minted self-signed localhost cert, cached for the
// rest of the test run so we only pay the keygen cost once.
var testCert = sync.OnceValues(generateLocalhostCert)

func generateLocalhostCert() (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, err
	}

	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "localhost"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}

	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return tls.Certificate{}, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	return tls.X509KeyPair(certPEM, keyPEM)
}

// localhostTLSCert fetches the cached test certificate, failing the test if
// generation ever errors.
func localhostTLSCert(t *testing.T) tls.Certificate {
	t.Helper()
	cert, err := testCert()
	if err != nil {
		t.Fatalf("generate test cert: %v", err)
	}
	return cert
}

// testLogger returns a discard logger so tests don't spam stdout.
// Flip to t.Log / os.Stdout during debugging.
func testLogger(_ *testing.T) *slog.Logger {
	return slog.New(slog.DiscardHandler)
}

// cmd issues a raw textproto command and asserts the expected reply code.
func cmd(c *textproto.Conn, expectedCode int, format string, args ...any) error {
	id, err := c.Cmd(format, args...)
	if err != nil {
		return err
	}
	c.StartResponse(id)
	_, _, err = c.ReadResponse(expectedCode)
	c.EndResponse(id)
	return err
}

// runserver starts an in-process server on a random localhost port and returns
// the address plus a closer that stops the listener. Optional middlewares are
// registered before Serve.
func runserver(t *testing.T, server *smtpd.Server, mws ...smtpd.Middleware) (addr string, closer func()) {
	t.Helper()

	for _, m := range mws {
		server.Use(m)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}

	go func() {
		_ = server.Serve(ln)
	}()

	done := make(chan bool)
	go func() {
		<-done
		_ = ln.Close()
	}()

	return ln.Addr().String(), func() {
		done <- true
	}
}

// runsslserver wires a localhost TLS cert into server.TLSConfig and delegates
// to runserver.
func runsslserver(t *testing.T, server *smtpd.Server, mws ...smtpd.Middleware) (addr string, closer func()) {
	t.Helper()

	server.TLSConfig = &tls.Config{Certificates: []tls.Certificate{localhostTLSCert(t)}}
	return runserver(t, server, mws...)
}

// runImplicitTLSServer starts a server on a tls.NewListener-wrapped listener,
// so that newSession sees a *tls.Conn and forces the handshake before the
// SMTP session begins. Mirrors the "SMTPS on :465" deployment.
func runImplicitTLSServer(t *testing.T, server *smtpd.Server, mws ...smtpd.Middleware) (addr string, closer func()) {
	t.Helper()

	for _, m := range mws {
		server.Use(m)
	}

	tlsCfg := &tls.Config{Certificates: []tls.Certificate{localhostTLSCert(t)}}

	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}
	ln := tls.NewListener(raw, tlsCfg)

	go func() { _ = server.Serve(ln) }()

	return ln.Addr().String(), func() { _ = ln.Close() }
}

// acceptAuth returns a Middleware that accepts every AUTH attempt.
func acceptAuth() smtpd.Middleware {
	return smtpd.Middleware{
		Authenticate: func(ctx context.Context, _ smtpd.Peer, _, _ string) (context.Context, error) {
			return ctx, nil
		},
	}
}

// rejectAuth returns a Middleware that rejects every AUTH attempt with 550.
func rejectAuth() smtpd.Middleware {
	return smtpd.Middleware{
		Authenticate: func(ctx context.Context, _ smtpd.Peer, _, _ string) (context.Context, error) {
			return ctx, smtpd.Error{Code: 550, Message: "Denied"}
		},
	}
}

// serveAssert returns a Handler that verifies envelope contents.
func serveAssert(t *testing.T) smtpd.Handler {
	return func(ctx context.Context, _ smtpd.Peer, env *smtpd.Envelope) (context.Context, error) {
		t.Helper()
		defer func() { _ = env.Data.Close() }()
		if env.Sender != "sender@example.org" {
			t.Fatalf("Unknown sender: %v", env.Sender)
		}
		if len(env.Recipients) != 1 {
			t.Fatalf("Too many recipients: %d", len(env.Recipients))
		}
		if env.Recipients[0] != "recipient@example.net" {
			t.Fatalf("Unknown recipient: %v", env.Recipients[0])
		}
		body, err := io.ReadAll(env.Data)
		if err != nil {
			t.Fatalf("Read body failed: %v", err)
		}
		if string(body) != "This is the email body\n" {
			t.Fatalf("Wrong message body: %v", string(body))
		}
		return ctx, nil
	}
}

// rejectServe returns a Handler that rejects every DATA with a 550.
func rejectServe() smtpd.Handler {
	return func(ctx context.Context, _ smtpd.Peer, env *smtpd.Envelope) (context.Context, error) {
		defer func() { _ = env.Data.Close() }()
		_, _ = io.Copy(io.Discard, env.Data)
		return ctx, smtpd.Error{Code: 550, Message: "Rejected"}
	}
}

// interruptServe returns a Handler that records the result of reading
// env.Data so the caller can observe whether an interrupted DATA stream
// surfaces as an error.
func interruptServe(readErr chan<- error) smtpd.Handler {
	return func(ctx context.Context, _ smtpd.Peer, env *smtpd.Envelope) (context.Context, error) {
		_, err := io.ReadAll(env.Data)
		_ = env.Data.Close()
		readErr <- err
		return ctx, err
	}
}

// xclientAssert returns a Middleware whose CheckSender verifies that XCLIENT
// overrode peer fields by the time MAIL FROM runs.
func xclientAssert(t *testing.T) smtpd.Middleware {
	return smtpd.Middleware{
		CheckSender: func(ctx context.Context, peer smtpd.Peer, _ string) (context.Context, error) {
			t.Helper()
			if peer.HeloName != "new.example.net" {
				t.Fatalf("Didn't override HELO name: %v", peer.HeloName)
			}
			if peer.Addr.String() != "42.42.42.42:4242" {
				t.Fatalf("Didn't override IP/Port: %v", peer.Addr)
			}
			if peer.Username != "newusername" {
				t.Fatalf("Didn't override username: %v", peer.Username)
			}
			if peer.Protocol != smtpd.SMTP {
				t.Fatalf("Didn't override protocol: %v", peer.Protocol)
			}
			return ctx, nil
		},
	}
}

// strictSender rejects anything that isn't "test@example.org".
func strictSender() smtpd.Middleware {
	return smtpd.Middleware{
		CheckSender: func(ctx context.Context, _ smtpd.Peer, addr string) (context.Context, error) {
			if addr != "test@example.org" {
				return ctx, smtpd.Error{Code: 502, Message: "Denied"}
			}
			return ctx, nil
		},
	}
}

// tlsAuthAssert returns a Middleware whose Authenticate verifies that the TLS
// connection state is populated when the server is handed an already-TLS
// listener.
func tlsAuthAssert(t *testing.T) smtpd.Middleware {
	return smtpd.Middleware{
		Authenticate: func(ctx context.Context, peer smtpd.Peer, _, _ string) (context.Context, error) {
			t.Helper()
			if peer.TLS == nil {
				t.Error("didn't correctly set connection state on TLS connection")
			}
			return ctx, nil
		},
	}
}

// rejectConnSMTPErr returns a Middleware that rejects every connection with a
// typed smtpd.Error.
func rejectConnSMTPErr() smtpd.Middleware {
	return smtpd.Middleware{
		CheckConnection: func(ctx context.Context, _ smtpd.Peer) (context.Context, error) {
			return ctx, smtpd.Error{Code: 552, Message: "Denied"}
		},
	}
}

// rejectConnPlainErr returns a Middleware that rejects every connection with a
// bare error (server should translate this to a generic 5xx).
func rejectConnPlainErr() smtpd.Middleware {
	return smtpd.Middleware{
		CheckConnection: func(ctx context.Context, _ smtpd.Peer) (context.Context, error) {
			return ctx, errors.New("Denied")
		},
	}
}

// heloAssert returns a Middleware whose CheckHelo asserts the HELO name and
// then rejects.
func heloAssert(t *testing.T) smtpd.Middleware {
	return smtpd.Middleware{
		CheckHelo: func(ctx context.Context, _ smtpd.Peer, name string) (context.Context, error) {
			t.Helper()
			if name != "foobar.local" {
				t.Fatal("Wrong HELO name")
			}
			return ctx, smtpd.Error{Code: 552, Message: "Denied"}
		},
	}
}

// rejectSender rejects every MAIL FROM.
func rejectSender() smtpd.Middleware {
	return smtpd.Middleware{
		CheckSender: func(ctx context.Context, _ smtpd.Peer, _ string) (context.Context, error) {
			return ctx, smtpd.Error{Code: 552, Message: "Denied"}
		},
	}
}

// rejectRecipient rejects every RCPT TO.
func rejectRecipient() smtpd.Middleware {
	return smtpd.Middleware{
		CheckRecipient: func(ctx context.Context, _ smtpd.Peer, _ string) (context.Context, error) {
			return ctx, smtpd.Error{Code: 552, Message: "Denied"}
		},
	}
}
