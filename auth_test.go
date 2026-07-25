package smtpd_test

import (
	"context"
	"crypto/tls"
	"net/smtp"
	"strings"
	"testing"

	"github.com/chrj/smtpd/v2"
)

// captureAuthState records the credentials Authenticate was given plus the
// peer.Username observed from the subsequent MAIL FROM.
type captureAuthState struct {
	gotUser, gotPass string
	peerUser         string
}

// captureAuth returns a Middleware that fills state during Authenticate and
// records peer.Username during CheckSender.
func captureAuth(state *captureAuthState) smtpd.Middleware {
	return smtpd.Middleware{
		Authenticate: func(ctx context.Context, _ smtpd.Peer, u, p string) (context.Context, error) {
			state.gotUser, state.gotPass = u, p
			return ctx, nil
		},
		CheckSender: func(ctx context.Context, peer smtpd.Peer, _ string) (context.Context, error) {
			state.peerUser = peer.Username
			return ctx, nil
		},
	}
}

func TestAUTHNoArgs(t *testing.T) {
	t.Parallel()

	addr, closer := runsslserver(t, &smtpd.Server{Logger: testLogger(t)}, acceptAuth())
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
	t.Parallel()

	// No Authenticate middleware is registered, so AUTH must be rejected.
	addr, closer := runsslserver(t, &smtpd.Server{Logger: testLogger(t), Handler: serveAssert(t)})
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
	t.Parallel()

	addr, closer := runsslserver(t, &smtpd.Server{Logger: testLogger(t)}, acceptAuth())
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
	t.Parallel()

	addr, closer := runserver(t, &smtpd.Server{Logger: testLogger(t)}, acceptAuth())
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
	t.Parallel()

	addr, closer := runsslserver(t, &smtpd.Server{Logger: testLogger(t)}, acceptAuth())
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
	t.Parallel()

	addr, closer := runsslserver(t, &smtpd.Server{Logger: testLogger(t)}, acceptAuth())
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
	t.Parallel()

	addr, closer := runsslserver(t, &smtpd.Server{Logger: testLogger(t)}, acceptAuth())
	defer closer()

	c, err := smtp.Dial(addr)
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}
	if err := c.StartTLS(&tls.Config{InsecureSkipVerify: true}); err != nil {
		t.Fatalf("STARTTLS failed: %v", err)
	}
	// "foo\x00bar" - only two parts, PLAIN requires three.
	if err := cmd(c.Text, 502, "AUTH PLAIN Zm9vAGJhcg=="); err != nil {
		t.Fatalf("AUTH PLAIN malformed didn't 502: %v", err)
	}
	_ = c.Quit()
}

func TestAUTHPLAINCapturesUsername(t *testing.T) {
	t.Parallel()

	cap := &captureAuthState{}
	addr, closer := runsslserver(t, &smtpd.Server{Logger: testLogger(t)}, captureAuth(cap))
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
	t.Parallel()

	addr, closer := runsslserver(t, &smtpd.Server{Logger: testLogger(t)}, acceptAuth())
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
	t.Parallel()

	addr, closer := runsslserver(t, &smtpd.Server{Logger: testLogger(t)}, acceptAuth())
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
	t.Parallel()

	addr, closer := runsslserver(t, &smtpd.Server{Logger: testLogger(t)}, rejectAuth())
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

func TestAUTHInsecureAllowed(t *testing.T) {
	t.Parallel()

	state := &captureAuthState{}

	// No TLSConfig at all: AllowInsecureAuth is the only reason AUTH is
	// reachable on this listener.
	addr, closer := runserver(t, &smtpd.Server{
		Logger:            testLogger(t),
		AllowInsecureAuth: true,
	}, captureAuth(state))
	defer closer()

	c, err := smtp.Dial(addr)
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}
	if err := c.Hello("localhost"); err != nil {
		t.Fatalf("HELO failed: %v", err)
	}

	if supported, _ := c.Extension("AUTH"); !supported {
		t.Fatal("AUTH not advertised on a plain connection with AllowInsecureAuth")
	}
	if _, mechs := c.Extension("AUTH"); !strings.Contains(mechs, "PLAIN") {
		t.Fatalf("PLAIN not offered on a plain connection, got mechanisms %q", mechs)
	}

	if err := c.Auth(smtp.PlainAuth("", "foo", "bar", "127.0.0.1")); err != nil {
		t.Fatalf("AUTH over a plain connection failed: %v", err)
	}
	if state.gotUser != "foo" {
		t.Errorf("Authenticate got username %q, want %q", state.gotUser, "foo")
	}
	if state.gotPass != "bar" {
		t.Errorf("Authenticate got password %q, want %q", state.gotPass, "bar")
	}

	// The authenticated identity must survive onto the peer, same as it does
	// over TLS.
	if err := c.Mail("sender@example.org"); err != nil {
		t.Fatalf("MAIL FROM failed: %v", err)
	}
	if state.peerUser != "foo" {
		t.Errorf("peer.Username was %q, want %q", state.peerUser, "foo")
	}

	_ = c.Quit()
}

func TestAUTHInsecureDeniedByDefault(t *testing.T) {
	t.Parallel()

	// Same listener as above but with AllowInsecureAuth left at its zero
	// value, which must keep AUTH both unadvertised and unusable.
	addr, closer := runserver(t, &smtpd.Server{Logger: testLogger(t)}, acceptAuth())
	defer closer()

	c, err := smtp.Dial(addr)
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}
	if err := c.Hello("localhost"); err != nil {
		t.Fatalf("HELO failed: %v", err)
	}

	if supported, _ := c.Extension("AUTH"); supported {
		t.Fatal("AUTH advertised on a plain connection by default")
	}

	// With no TLSConfig, telling the client to use STARTTLS would be a dead
	// end, so the refusal says so instead.
	id, err := c.Text.Cmd("AUTH PLAIN Zm9vAGJhcgBxdXV4")
	if err != nil {
		t.Fatalf("sending AUTH failed: %v", err)
	}
	c.Text.StartResponse(id)
	_, msg, err := c.Text.ReadResponse(502)
	c.Text.EndResponse(id)
	if err != nil {
		t.Fatalf("AUTH without TLS didn't 502: %v", err)
	}
	if msg != "Cannot AUTH in plain text mode and STARTTLS is not available." {
		t.Errorf("got refusal %q, want the STARTTLS-unavailable message", msg)
	}

	_ = c.Quit()
}
