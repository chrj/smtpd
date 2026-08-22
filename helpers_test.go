package smtpd_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"reflect"
	"testing"

	"github.com/chrj/smtpd/v2"
	"github.com/chrj/smtpd/v2/smtptest"
)

// testLogger returns a discard logger so tests don't spam stdout.
// Flip to t.Log / os.Stdout during debugging.
func testLogger(_ *testing.T) *slog.Logger {
	return slog.New(slog.DiscardHandler)
}

// newTestServer wraps server and its middlewares in a test server that stops
// when the test ends. The caller starts it.
func newTestServer(t *testing.T, server *smtpd.Server, mws []smtpd.Middleware) *smtptest.Server {
	t.Helper()

	ts := smtptest.NewUnstartedServer(nil)
	ts.Config = server

	for _, m := range mws {
		ts.Config.Use(m)
	}

	t.Cleanup(ts.Close)
	return ts
}

// runserver starts an in-process server on a random localhost port. Optional
// middlewares are registered before Serve.
func runserver(t *testing.T, server *smtpd.Server, mws ...smtpd.Middleware) *smtptest.Server {
	t.Helper()

	ts := newTestServer(t, server, mws)
	ts.Start()
	return ts
}

// runsslserver starts a server that advertises STARTTLS with a certificate
// for localhost. Dial on the result upgrades the connection.
func runsslserver(t *testing.T, server *smtpd.Server, mws ...smtpd.Middleware) *smtptest.Server {
	t.Helper()

	ts := newTestServer(t, server, mws)
	ts.StartSTARTTLS()
	return ts
}

// runImplicitTLSServer starts a server behind a TLS handshake, so that
// newSession sees a *tls.Conn and forces the handshake before the SMTP
// session begins. Mirrors the "SMTPS on :465" deployment.
func runImplicitTLSServer(t *testing.T, server *smtpd.Server, mws ...smtpd.Middleware) *smtptest.Server {
	t.Helper()

	ts := newTestServer(t, server, mws)
	ts.StartTLS()
	return ts
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

// verifier returns a Middleware whose Verify hook gives the same answer to
// every name.
func verifier(verified smtpd.Verification, err error) smtpd.Middleware {
	return smtpd.Middleware{
		Verify: func(ctx context.Context, _ smtpd.Peer, _ string) (context.Context, smtpd.Verification, error) {
			return ctx, verified, err
		},
	}
}

// dsnCapture returns a Handler that hands the DSN parameters of the envelope
// to the test. The channel is buffered, so the handler returns and the client
// gets its 250 before the test reads the value.
func dsnCapture(got chan<- *smtpd.DSN) smtpd.Handler {
	return func(ctx context.Context, _ smtpd.Peer, env *smtpd.Envelope) (context.Context, error) {
		got <- env.DSN
		return ctx, nil
	}
}

// write puts bytes on the connection and reads nothing back. A BDAT command
// and its chunk go out in one write, in the way that a client sends them.
func (c *rawClient) write(b []byte) {
	c.t.Helper()

	if _, err := c.conn.Write(b); err != nil {
		c.t.Fatalf("write failed: %v", err)
	}
}

// replies reads n complete replies. LMTP writes one for every recipient of a
// message (RFC 2033 section 4.2), and each of them is a reply of its own and
// not a continuation line of the one before it.
func (c *rawClient) replies(n int) []string {
	c.t.Helper()

	replies := make([]string, 0, n)
	for len(replies) < n {
		line := c.line()
		if len(line) >= 4 && line[3] == '-' {
			continue
		}
		replies = append(replies, line)
	}
	return replies
}

// message is what a handler read off an envelope.
type message struct {
	sender     string
	recipients []string
	bodyType   smtpd.BodyType
	smtputf8   bool
	body       string
	readErr    error
}

// assertMessage compares what a handler read with what the test expects. The
// error of the read is a failure of its own, because a message that stopped
// halfway explains every field that follows.
func assertMessage(t *testing.T, got, want message) {
	t.Helper()

	if got.readErr != nil {
		t.Fatalf("the handler read the body with the error %v", got.readErr)
	}
	if got.sender != want.sender {
		t.Errorf("sender = %q, want %q", got.sender, want.sender)
	}
	if !reflect.DeepEqual(got.recipients, want.recipients) {
		t.Errorf("recipients = %q, want %q", got.recipients, want.recipients)
	}
	if got.bodyType != want.bodyType {
		t.Errorf("body type = %q, want %q", got.bodyType, want.bodyType)
	}
	if got.smtputf8 != want.smtputf8 {
		t.Errorf("SMTPUTF8 = %v, want %v", got.smtputf8, want.smtputf8)
	}
	if got.body != want.body {
		t.Errorf("body = %q, want %q", got.body, want.body)
	}
}

// captureMessage returns a Handler that reads the whole body and hands the
// message to the test. The channel is buffered, so the handler returns and the
// client gets its reply before the test reads the value.
func captureMessage(got chan<- message) smtpd.Handler {
	return func(ctx context.Context, _ smtpd.Peer, env *smtpd.Envelope) (context.Context, error) {
		body, err := io.ReadAll(env.Data)
		_ = env.Data.Close()

		got <- message{
			sender:     env.Sender,
			recipients: env.Recipients,
			bodyType:   env.BodyType,
			smtputf8:   env.SMTPUTF8,
			body:       string(body),
			readErr:    err,
		}

		return ctx, nil
	}
}
