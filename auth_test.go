package smtpd_test

import (
	"context"
	"net/smtp"
	"strings"
	"testing"

	"github.com/chrj/smtpd/v2"
	"github.com/chrj/smtpd/v2/smtptest"
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

	srv := runsslserver(t, &smtpd.Server{Logger: testLogger(t)}, acceptAuth())

	c := srv.Dial()
	if err := smtptest.Cmd(c.Text, 502, "AUTH"); err != nil {
		t.Fatalf("AUTH with no mechanism didn't 502: %v", err)
	}
	_ = c.Quit()
}

func TestAUTHWithoutAuthenticator(t *testing.T) {
	t.Parallel()

	// No Authenticate middleware is registered, so AUTH must be rejected.
	srv := runsslserver(t, &smtpd.Server{Logger: testLogger(t), Handler: serveAssert(t)})

	c := srv.Dial()
	// StartTLS re-issues EHLO, so HeloName is already set.
	if err := smtptest.Cmd(c.Text, 502, "AUTH PLAIN Zm9vAGJhcgBxdXV4"); err != nil {
		t.Fatalf("AUTH without authenticator didn't 502: %v", err)
	}
	_ = c.Quit()
}

func TestAUTHBeforeHELO(t *testing.T) {
	t.Parallel()

	srv := runsslserver(t, &smtpd.Server{Logger: testLogger(t)}, acceptAuth())

	c := srv.Dial()
	// Note: StartTLS re-does EHLO, so we need a fresh connection instead.
	_ = c.Quit()

	// A fresh connection stays in plain text, so AUTH arrives before HELO.
	c2, err := smtp.Dial(srv.Addr)
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}
	if err := smtptest.Cmd(c2.Text, 502, "AUTH PLAIN Zm9vAGJhcgBxdXV4"); err != nil {
		t.Fatalf("AUTH before HELO didn't 502: %v", err)
	}
	_ = c2.Quit()
}

func TestAUTHWithoutTLS(t *testing.T) {
	t.Parallel()

	srv := runserver(t, &smtpd.Server{Logger: testLogger(t)}, acceptAuth())

	c := srv.Dial()
	if err := c.Hello("localhost"); err != nil {
		t.Fatalf("HELO failed: %v", err)
	}
	if err := smtptest.Cmd(c.Text, 502, "AUTH PLAIN Zm9vAGJhcgBxdXV4"); err != nil {
		t.Fatalf("AUTH without TLS didn't 502: %v", err)
	}
	_ = c.Quit()
}

func TestAUTHUnknownMechanism(t *testing.T) {
	t.Parallel()

	srv := runsslserver(t, &smtpd.Server{Logger: testLogger(t)}, acceptAuth())

	c := srv.Dial()
	if err := smtptest.Cmd(c.Text, 502, "AUTH WHATEVER"); err != nil {
		t.Fatalf("AUTH WHATEVER didn't 502: %v", err)
	}
	_ = c.Quit()
}

func TestAUTHPLAINBadBase64(t *testing.T) {
	t.Parallel()

	srv := runsslserver(t, &smtpd.Server{Logger: testLogger(t)}, acceptAuth())

	c := srv.Dial()
	if err := smtptest.Cmd(c.Text, 502, "AUTH PLAIN !!!not-base64!!!"); err != nil {
		t.Fatalf("AUTH PLAIN bad base64 didn't 502: %v", err)
	}
	_ = c.Quit()
}

func TestAUTHPLAINWrongParts(t *testing.T) {
	t.Parallel()

	srv := runsslserver(t, &smtpd.Server{Logger: testLogger(t)}, acceptAuth())

	c := srv.Dial()
	// "foo\x00bar" - only two parts, PLAIN requires three.
	if err := smtptest.Cmd(c.Text, 502, "AUTH PLAIN Zm9vAGJhcg=="); err != nil {
		t.Fatalf("AUTH PLAIN malformed didn't 502: %v", err)
	}
	_ = c.Quit()
}

func TestAUTHPLAINCapturesUsername(t *testing.T) {
	t.Parallel()

	cap := &captureAuthState{}
	srv := runsslserver(t, &smtpd.Server{Logger: testLogger(t)}, captureAuth(cap))

	c := srv.Dial()
	// "\x00foo\x00bar"
	if err := c.Auth(smtp.PlainAuth("", "foo", "bar", srv.Host)); err != nil {
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

	srv := runsslserver(t, &smtpd.Server{Logger: testLogger(t)}, acceptAuth())

	c := srv.Dial()
	if err := smtptest.Cmd(c.Text, 502, "AUTH LOGIN !!!"); err != nil {
		t.Fatalf("AUTH LOGIN bad base64 didn't 502: %v", err)
	}
	_ = c.Quit()
}

func TestAUTHLOGINBadBase64Password(t *testing.T) {
	t.Parallel()

	srv := runsslserver(t, &smtpd.Server{Logger: testLogger(t)}, acceptAuth())

	c := srv.Dial()
	// Kick off LOGIN with valid username, then send a garbage password.
	if err := smtptest.Cmd(c.Text, 334, "AUTH LOGIN Zm9v"); err != nil {
		t.Fatalf("AUTH LOGIN failed: %v", err)
	}
	if err := smtptest.Cmd(c.Text, 502, "!!!"); err != nil {
		t.Fatalf("LOGIN bad-base64 password didn't 502: %v", err)
	}
	_ = c.Quit()
}

func TestAUTHRejected(t *testing.T) {
	t.Parallel()

	srv := runsslserver(t, &smtpd.Server{Logger: testLogger(t)}, rejectAuth())

	c := srv.Dial()
	if err := smtptest.Cmd(c.Text, 550, "AUTH PLAIN Zm9vAGJhcgBxdXV4"); err != nil {
		t.Fatalf("authenticator error not mapped to 550: %v", err)
	}
	_ = c.Quit()
}

func TestAUTHInsecureAllowed(t *testing.T) {
	t.Parallel()

	state := &captureAuthState{}

	// No TLSConfig at all: AllowInsecureAuth is the only reason AUTH is
	// reachable on this listener.
	srv := runserver(t, &smtpd.Server{
		Logger:            testLogger(t),
		AllowInsecureAuth: true,
	}, captureAuth(state))

	c := srv.Dial()
	if err := c.Hello("localhost"); err != nil {
		t.Fatalf("HELO failed: %v", err)
	}

	if supported, _ := c.Extension("AUTH"); !supported {
		t.Fatal("AUTH not advertised on a plain connection with AllowInsecureAuth")
	}
	if _, mechs := c.Extension("AUTH"); !strings.Contains(mechs, "PLAIN") {
		t.Fatalf("PLAIN not offered on a plain connection, got mechanisms %q", mechs)
	}

	if err := c.Auth(smtp.PlainAuth("", "foo", "bar", srv.Host)); err != nil {
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
	srv := runserver(t, &smtpd.Server{Logger: testLogger(t)}, acceptAuth())

	c := srv.Dial()
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
