package smtpd_test

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/textproto"
	"testing"

	"github.com/chrj/smtpd/v2/pkg/smtpd"
)

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
// the address plus a closer that stops the listener.
func runserver(t *testing.T, server *smtpd.Server, handlers ...smtpd.Handler) (addr string, closer func()) {
	t.Helper()

	switch len(handlers) {
	case 0:
		// No handler — session.deliver nil-checks, so DATA is simply discarded.
	case 1:
		server.Handler(handlers[0])
	default:
		t.Fatalf("runserver: expected at most one handler, got %d", len(handlers))
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
func runsslserver(t *testing.T, server *smtpd.Server, handlers ...smtpd.Handler) (addr string, closer func()) {
	t.Helper()

	cert, err := tls.X509KeyPair(localhostCert, localhostKey)
	if err != nil {
		t.Fatalf("Cert load failed: %v", err)
	}
	server.TLSConfig = &tls.Config{Certificates: []tls.Certificate{cert}}
	return runserver(t, server, handlers...)
}

// acceptAuth satisfies Handler + Authenticator and accepts every AUTH.
type acceptAuth struct{}

func (acceptAuth) ServeSMTP(context.Context, smtpd.Peer, smtpd.Envelope) error { return nil }
func (acceptAuth) Authenticate(ctx context.Context, _ smtpd.Peer, _, _ string) (context.Context, error) {
	return ctx, nil
}

// rejectAuth satisfies Handler + Authenticator and rejects every AUTH.
type rejectAuth struct{}

func (rejectAuth) ServeSMTP(context.Context, smtpd.Peer, smtpd.Envelope) error { return nil }
func (rejectAuth) Authenticate(ctx context.Context, _ smtpd.Peer, _, _ string) (context.Context, error) {
	return ctx, smtpd.Error{Code: 550, Message: "Denied"}
}

// serveAssert asserts envelope contents in TestHandler.
type serveAssert struct{ t *testing.T }

func (s serveAssert) ServeSMTP(_ context.Context, _ smtpd.Peer, env smtpd.Envelope) error {
	s.t.Helper()
	defer func() { _ = env.Data.Close() }()
	if env.Sender != "sender@example.org" {
		s.t.Fatalf("Unknown sender: %v", env.Sender)
	}
	if len(env.Recipients) != 1 {
		s.t.Fatalf("Too many recipients: %d", len(env.Recipients))
	}
	if env.Recipients[0] != "recipient@example.net" {
		s.t.Fatalf("Unknown recipient: %v", env.Recipients[0])
	}
	body, err := io.ReadAll(env.Data)
	if err != nil {
		s.t.Fatalf("Read body failed: %v", err)
	}
	if string(body) != "This is the email body\n" {
		s.t.Fatalf("Wrong message body: %v", string(body))
	}
	return nil
}

// rejectServe rejects every DATA with a 550.
type rejectServe struct{}

func (rejectServe) ServeSMTP(_ context.Context, _ smtpd.Peer, env smtpd.Envelope) error {
	defer func() { _ = env.Data.Close() }()
	_, _ = io.Copy(io.Discard, env.Data)
	return smtpd.Error{Code: 550, Message: "Rejected"}
}

// interruptServe records the result of reading env.Data so the caller can
// observe whether an interrupted DATA stream surfaces as an error.
type interruptServe struct{ readErr chan<- error }

func (h interruptServe) ServeSMTP(_ context.Context, _ smtpd.Peer, env smtpd.Envelope) error {
	_, err := io.ReadAll(env.Data)
	_ = env.Data.Close()
	h.readErr <- err
	return err
}

// xclientAssert verifies that XCLIENT overrode peer fields by the time the
// SenderChecker runs.
type xclientAssert struct{ t *testing.T }

func (xclientAssert) ServeSMTP(context.Context, smtpd.Peer, smtpd.Envelope) error { return nil }
func (h xclientAssert) CheckSender(ctx context.Context, peer smtpd.Peer, _ string) (context.Context, error) {
	h.t.Helper()
	if peer.HeloName != "new.example.net" {
		h.t.Fatalf("Didn't override HELO name: %v", peer.HeloName)
	}
	if peer.Addr.String() != "42.42.42.42:4242" {
		h.t.Fatalf("Didn't override IP/Port: %v", peer.Addr)
	}
	if peer.Username != "newusername" {
		h.t.Fatalf("Didn't override username: %v", peer.Username)
	}
	if peer.Protocol != smtpd.SMTP {
		h.t.Fatalf("Didn't override protocol: %v", peer.Protocol)
	}
	return ctx, nil
}

// strictSender rejects anything that isn't "test@example.org".
type strictSender struct{}

func (strictSender) ServeSMTP(context.Context, smtpd.Peer, smtpd.Envelope) error { return nil }
func (strictSender) CheckSender(ctx context.Context, _ smtpd.Peer, addr string) (context.Context, error) {
	if addr != "test@example.org" {
		return ctx, smtpd.Error{Code: 502, Message: "Denied"}
	}
	return ctx, nil
}

// tlsAuthAssert checks that the TLS connection state is populated when the
// server is handed an already-TLS-wrapped listener.
type tlsAuthAssert struct{ t *testing.T }

func (tlsAuthAssert) ServeSMTP(context.Context, smtpd.Peer, smtpd.Envelope) error { return nil }
func (h tlsAuthAssert) Authenticate(ctx context.Context, peer smtpd.Peer, _, _ string) (context.Context, error) {
	h.t.Helper()
	if peer.TLS == nil {
		h.t.Error("didn't correctly set connection state on TLS connection")
	}
	return ctx, nil
}

// rejectConnSMTPErr rejects every connection with a typed smtpd.Error.
type rejectConnSMTPErr struct{}

func (rejectConnSMTPErr) ServeSMTP(context.Context, smtpd.Peer, smtpd.Envelope) error { return nil }
func (rejectConnSMTPErr) CheckConnection(ctx context.Context, _ smtpd.Peer) (context.Context, error) {
	return ctx, smtpd.Error{Code: 552, Message: "Denied"}
}

// rejectConnPlainErr rejects every connection with a bare error (server should
// translate this to a generic 5xx).
type rejectConnPlainErr struct{}

func (rejectConnPlainErr) ServeSMTP(context.Context, smtpd.Peer, smtpd.Envelope) error { return nil }
func (rejectConnPlainErr) CheckConnection(ctx context.Context, _ smtpd.Peer) (context.Context, error) {
	return ctx, errors.New("Denied")
}

// heloAssert asserts the HELO name and then rejects.
type heloAssert struct{ t *testing.T }

func (heloAssert) ServeSMTP(context.Context, smtpd.Peer, smtpd.Envelope) error { return nil }
func (h heloAssert) CheckHelo(ctx context.Context, _ smtpd.Peer, name string) (context.Context, error) {
	h.t.Helper()
	if name != "foobar.local" {
		h.t.Fatal("Wrong HELO name")
	}
	return ctx, smtpd.Error{Code: 552, Message: "Denied"}
}

// rejectSender rejects every MAIL FROM.
type rejectSender struct{}

func (rejectSender) ServeSMTP(context.Context, smtpd.Peer, smtpd.Envelope) error { return nil }
func (rejectSender) CheckSender(ctx context.Context, _ smtpd.Peer, _ string) (context.Context, error) {
	return ctx, smtpd.Error{Code: 552, Message: "Denied"}
}

// rejectRecipient rejects every RCPT TO.
type rejectRecipient struct{}

func (rejectRecipient) ServeSMTP(context.Context, smtpd.Peer, smtpd.Envelope) error { return nil }
func (rejectRecipient) CheckRecipient(ctx context.Context, _ smtpd.Peer, _ string) (context.Context, error) {
	return ctx, smtpd.Error{Code: 552, Message: "Denied"}
}
