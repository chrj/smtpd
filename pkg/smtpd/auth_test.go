package smtpd_test

import (
	"context"
	"crypto/tls"
	"net/smtp"
	"testing"

	"github.com/chrj/smtpd/v2/pkg/smtpd"
)

// captureAuth records the credentials it was given and the peer.Username set
// by the server after it accepts.
type captureAuth struct {
	gotUser, gotPass string
	peerUser         string
}

func (captureAuth) ServeSMTP(context.Context, smtpd.Peer, smtpd.Envelope) error { return nil }
func (c *captureAuth) Authenticate(ctx context.Context, _ smtpd.Peer, u, p string) (context.Context, error) {
	c.gotUser, c.gotPass = u, p
	return ctx, nil
}
func (c *captureAuth) CheckSender(ctx context.Context, peer smtpd.Peer, _ string) (context.Context, error) {
	c.peerUser = peer.Username
	return ctx, nil
}

func TestAUTHNoArgs(t *testing.T) {
	addr, closer := runsslserver(t, &smtpd.Server{Logger: testLogger(t)}, acceptAuth{})
	defer closer()

	c, err := smtp.Dial(addr)
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}
	if err := c.StartTLS(&tls.Config{InsecureSkipVerify: true}); err != nil {
		t.Fatalf("STARTTLS failed: %v", err)
	}
	if err := cmd(c.Text, 502, "AUTH"); err != nil {
		t.Fatalf("AUTH with no mechanism didn't 502: %v", err)
	}
	_ = c.Quit()
}

func TestAUTHWithoutAuthenticator(t *testing.T) {
	// Handler has no Authenticate method, so AUTH must be rejected.
	addr, closer := runsslserver(t, &smtpd.Server{Logger: testLogger(t)}, serveAssert{t})
	defer closer()

	c, err := smtp.Dial(addr)
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}
	if err := c.StartTLS(&tls.Config{InsecureSkipVerify: true}); err != nil {
		t.Fatalf("STARTTLS failed: %v", err)
	}
	// StartTLS re-issues EHLO, so HeloName is already set.
	if err := cmd(c.Text, 502, "AUTH PLAIN Zm9vAGJhcgBxdXV4"); err != nil {
		t.Fatalf("AUTH without authenticator didn't 502: %v", err)
	}
	_ = c.Quit()
}

func TestAUTHBeforeHELO(t *testing.T) {
	addr, closer := runsslserver(t, &smtpd.Server{Logger: testLogger(t)}, acceptAuth{})
	defer closer()

	c, err := smtp.Dial(addr)
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}
	if err := c.StartTLS(&tls.Config{InsecureSkipVerify: true}); err != nil {
		t.Fatalf("STARTTLS failed: %v", err)
	}
	// Note: StartTLS re-does EHLO, so we need a fresh connection instead.
	_ = c.Quit()

	c2, err := smtp.Dial(addr)
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}
	if err := cmd(c2.Text, 502, "AUTH PLAIN Zm9vAGJhcgBxdXV4"); err != nil {
		t.Fatalf("AUTH before HELO didn't 502: %v", err)
	}
	_ = c2.Quit()
}

func TestAUTHWithoutTLS(t *testing.T) {
	addr, closer := runserver(t, &smtpd.Server{Logger: testLogger(t)}, acceptAuth{})
	defer closer()

	c, err := smtp.Dial(addr)
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}
	if err := c.Hello("localhost"); err != nil {
		t.Fatalf("HELO failed: %v", err)
	}
	if err := cmd(c.Text, 502, "AUTH PLAIN Zm9vAGJhcgBxdXV4"); err != nil {
		t.Fatalf("AUTH without TLS didn't 502: %v", err)
	}
	_ = c.Quit()
}

func TestAUTHUnknownMechanism(t *testing.T) {
	addr, closer := runsslserver(t, &smtpd.Server{Logger: testLogger(t)}, acceptAuth{})
	defer closer()

	c, err := smtp.Dial(addr)
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}
	if err := c.StartTLS(&tls.Config{InsecureSkipVerify: true}); err != nil {
		t.Fatalf("STARTTLS failed: %v", err)
	}
	if err := cmd(c.Text, 502, "AUTH WHATEVER"); err != nil {
		t.Fatalf("AUTH WHATEVER didn't 502: %v", err)
	}
	_ = c.Quit()
}

func TestAUTHPLAINBadBase64(t *testing.T) {
	addr, closer := runsslserver(t, &smtpd.Server{Logger: testLogger(t)}, acceptAuth{})
	defer closer()

	c, err := smtp.Dial(addr)
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}
	if err := c.StartTLS(&tls.Config{InsecureSkipVerify: true}); err != nil {
		t.Fatalf("STARTTLS failed: %v", err)
	}
	if err := cmd(c.Text, 502, "AUTH PLAIN !!!not-base64!!!"); err != nil {
		t.Fatalf("AUTH PLAIN bad base64 didn't 502: %v", err)
	}
	_ = c.Quit()
}

func TestAUTHPLAINWrongParts(t *testing.T) {
	addr, closer := runsslserver(t, &smtpd.Server{Logger: testLogger(t)}, acceptAuth{})
	defer closer()

	c, err := smtp.Dial(addr)
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}
	if err := c.StartTLS(&tls.Config{InsecureSkipVerify: true}); err != nil {
		t.Fatalf("STARTTLS failed: %v", err)
	}
	// "foo\x00bar" — only two parts, PLAIN requires three.
	if err := cmd(c.Text, 502, "AUTH PLAIN Zm9vAGJhcg=="); err != nil {
		t.Fatalf("AUTH PLAIN malformed didn't 502: %v", err)
	}
	_ = c.Quit()
}

func TestAUTHPLAINCapturesUsername(t *testing.T) {
	cap := &captureAuth{}
	addr, closer := runsslserver(t, &smtpd.Server{Logger: testLogger(t)}, cap)
	defer closer()

	c, err := smtp.Dial(addr)
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}
	if err := c.StartTLS(&tls.Config{InsecureSkipVerify: true}); err != nil {
		t.Fatalf("STARTTLS failed: %v", err)
	}
	// "\x00foo\x00bar"
	if err := c.Auth(smtp.PlainAuth("", "foo", "bar", "127.0.0.1")); err != nil {
		t.Fatalf("Auth failed: %v", err)
	}
	if err := c.Mail("sender@example.org"); err != nil {
		t.Fatalf("MAIL failed: %v", err)
	}
	if cap.gotUser != "foo" || cap.gotPass != "bar" {
		t.Fatalf("authenticator got %q/%q", cap.gotUser, cap.gotPass)
	}
	if cap.peerUser != "foo" {
		t.Fatalf("peer.Username after AUTH = %q, want %q", cap.peerUser, "foo")
	}
	_ = c.Quit()
}

func TestAUTHLOGINBadBase64Username(t *testing.T) {
	addr, closer := runsslserver(t, &smtpd.Server{Logger: testLogger(t)}, acceptAuth{})
	defer closer()

	c, err := smtp.Dial(addr)
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}
	if err := c.StartTLS(&tls.Config{InsecureSkipVerify: true}); err != nil {
		t.Fatalf("STARTTLS failed: %v", err)
	}
	if err := cmd(c.Text, 502, "AUTH LOGIN !!!"); err != nil {
		t.Fatalf("AUTH LOGIN bad base64 didn't 502: %v", err)
	}
	_ = c.Quit()
}

func TestAUTHLOGINBadBase64Password(t *testing.T) {
	addr, closer := runsslserver(t, &smtpd.Server{Logger: testLogger(t)}, acceptAuth{})
	defer closer()

	c, err := smtp.Dial(addr)
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}
	if err := c.StartTLS(&tls.Config{InsecureSkipVerify: true}); err != nil {
		t.Fatalf("STARTTLS failed: %v", err)
	}
	// Kick off LOGIN with valid username, then send a garbage password.
	if err := cmd(c.Text, 334, "AUTH LOGIN Zm9v"); err != nil {
		t.Fatalf("AUTH LOGIN failed: %v", err)
	}
	if err := cmd(c.Text, 502, "!!!"); err != nil {
		t.Fatalf("LOGIN bad-base64 password didn't 502: %v", err)
	}
	_ = c.Quit()
}

func TestAUTHRejected(t *testing.T) {
	addr, closer := runsslserver(t, &smtpd.Server{Logger: testLogger(t)}, rejectAuth{})
	defer closer()

	c, err := smtp.Dial(addr)
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}
	if err := c.StartTLS(&tls.Config{InsecureSkipVerify: true}); err != nil {
		t.Fatalf("STARTTLS failed: %v", err)
	}
	if err := cmd(c.Text, 550, "AUTH PLAIN Zm9vAGJhcgBxdXV4"); err != nil {
		t.Fatalf("authenticator error not mapped to 550: %v", err)
	}
	_ = c.Quit()
}
