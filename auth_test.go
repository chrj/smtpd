package smtpd_test

import (
	"context"
	"encoding/base64"
	"net/smtp"
	"strings"
	"testing"
	"time"

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
	if err := smtptest.Cmd(c.Text, 501, "AUTH"); err != nil {
		t.Fatalf("AUTH with no mechanism didn't 501: %v", err)
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
	if err := smtptest.Cmd(c2.Text, 503, "AUTH PLAIN Zm9vAGJhcgBxdXV4"); err != nil {
		t.Fatalf("AUTH before HELO didn't 503: %v", err)
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
	if err := smtptest.Cmd(c.Text, 504, "AUTH WHATEVER"); err != nil {
		t.Fatalf("AUTH WHATEVER didn't 504: %v", err)
	}
	_ = c.Quit()
}

func TestAUTHPLAINBadBase64(t *testing.T) {
	t.Parallel()

	srv := runsslserver(t, &smtpd.Server{Logger: testLogger(t)}, acceptAuth())

	c := srv.Dial()
	if err := smtptest.Cmd(c.Text, 501, "AUTH PLAIN !!!not-base64!!!"); err != nil {
		t.Fatalf("AUTH PLAIN bad base64 didn't 501: %v", err)
	}
	_ = c.Quit()
}

func TestAUTHPLAINWrongParts(t *testing.T) {
	t.Parallel()

	srv := runsslserver(t, &smtpd.Server{Logger: testLogger(t)}, acceptAuth())

	c := srv.Dial()
	// "foo\x00bar" - only two parts, PLAIN requires three.
	if err := smtptest.Cmd(c.Text, 501, "AUTH PLAIN Zm9vAGJhcg=="); err != nil {
		t.Fatalf("AUTH PLAIN malformed didn't 501: %v", err)
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
	if err := smtptest.Cmd(c.Text, 501, "AUTH LOGIN !!!"); err != nil {
		t.Fatalf("AUTH LOGIN bad base64 didn't 501: %v", err)
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
	if err := smtptest.Cmd(c.Text, 501, "!!!"); err != nil {
		t.Fatalf("LOGIN bad-base64 password didn't 501: %v", err)
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
	// Hello sent EHLO, so the reply carries the status code of RFC 3463.
	if msg != "5.5.1 Cannot AUTH in plain text mode and STARTTLS is not available." {
		t.Errorf("got refusal %q, want the STARTTLS-unavailable message", msg)
	}

	_ = c.Quit()
}

// TestAUTHBeforeSTARTTLS verifies that a server which offers STARTTLS answers
// 530 to an AUTH in plain text. RFC 3207 gives that code for a command that
// needs the TLS layer first, and middleware.RequireTLS uses it too.
func TestAUTHBeforeSTARTTLS(t *testing.T) {
	t.Parallel()

	srv := runsslserver(t, &smtpd.Server{Logger: testLogger(t)}, acceptAuth())

	// A raw client, so that the connection stays in plain text. Dial on the
	// test server runs STARTTLS for itself.
	c := dialRaw(t, srv.Addr)
	c.send("EHLO client.example")

	if reply := c.send("AUTH PLAIN Zm9vAGJhcgBxdXV4"); !strings.HasPrefix(reply, "530") {
		t.Fatalf("AUTH in plain text = %q, want 530", reply)
	}
}

// TestAUTHContinuationTooLongEndsTheSession covers the credentials line of an
// AUTH command that is longer than the server reads.
//
// The rest of that line stays in the reader. A session that goes on would read
// it as commands, so the client could put a command of its own behind its
// credentials and the server would run it. The read is terminal instead: the
// server answers 500 and the session ends.
func TestAUTHContinuationTooLongEndsTheSession(t *testing.T) {
	t.Parallel()

	srv := runserver(t, &smtpd.Server{
		Logger:            testLogger(t),
		AllowInsecureAuth: true,
	}, acceptAuth())

	c := dialRaw(t, srv.Addr)
	c.send("EHLO localhost")

	if reply := c.send("AUTH PLAIN"); !strings.HasPrefix(reply, "334") {
		t.Fatalf("AUTH PLAIN = %q, want 334", reply)
	}

	// One line of credentials that is longer than the server reads, with a
	// command written behind it.
	c.write([]byte(strings.Repeat("A", 70*1024) + "\r\nNOOP\r\n"))

	if reply := c.line(); !strings.Contains(reply, "500") {
		t.Fatalf("the reply to the credentials = %q, want 500", reply)
	}

	// Nothing that followed the credentials runs, and the session is over.
	_ = c.conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if line, err := c.br.ReadString('\n'); err == nil {
		t.Errorf("the session wrote %q after the refusal, and it must be over", line)
	}
}

// authPLAIN is the argument of an AUTH PLAIN command for a user and a
// password, in the base64 that RFC 4954 section 4 asks for.
func authPLAIN(user, pass string) string {
	return base64.StdEncoding.EncodeToString([]byte("\x00" + user + "\x00" + pass))
}

// TestAUTHClosesAfterTooManyFailures verifies that the server closes a
// connection whose AUTH commands keep failing. RFC 4954 section 6 asks for a
// limit, because PLAIN and LOGIN both carry a password that a client guesses.
func TestAUTHClosesAfterTooManyFailures(t *testing.T) {
	t.Parallel()

	srv := runsslserver(t, &smtpd.Server{
		Logger:          testLogger(t),
		MaxAuthAttempts: 3,
	}, rejectAuth())

	c := srv.Dial()

	// The attempts before the last one get the reply of the hook.
	for i := range 2 {
		if err := smtptest.Cmd(c.Text, 550, "AUTH PLAIN %s", authPLAIN("user", "wrong")); err != nil {
			t.Fatalf("attempt %d did not get 550: %v", i+1, err)
		}
	}

	// The attempt that reaches the limit gets 421 in the place of the refusal.
	if err := smtptest.Cmd(c.Text, 421, "AUTH PLAIN %s", authPLAIN("user", "wrong")); err != nil {
		t.Fatalf("the attempt at the limit did not get 421: %v", err)
	}

	// The connection is gone, so the command after it never gets a reply.
	if err := smtptest.Cmd(c.Text, 250, "NOOP"); err == nil {
		t.Fatal("the session took a command after the limit")
	}
}

// TestAUTHKeepsTheSessionUnderTheLimit verifies that a session that fails
// fewer times than the limit stays open.
func TestAUTHKeepsTheSessionUnderTheLimit(t *testing.T) {
	t.Parallel()

	srv := runsslserver(t, &smtpd.Server{
		Logger:          testLogger(t),
		MaxAuthAttempts: 3,
	}, rejectAuth())

	c := srv.Dial()

	for i := range 2 {
		if err := smtptest.Cmd(c.Text, 550, "AUTH PLAIN %s", authPLAIN("user", "wrong")); err != nil {
			t.Fatalf("attempt %d did not get 550: %v", i+1, err)
		}
	}

	if err := smtptest.Cmd(c.Text, 250, "NOOP"); err != nil {
		t.Fatalf("the session did not take a command under the limit: %v", err)
	}
	_ = c.Quit()
}

// TestAUTHSuccessClearsTheFailures verifies that a successful AUTH sets the
// count of failures back to zero.
//
// RFC 4954 section 4 gives 503 to a second AUTH, so the count is read again
// only where STARTTLS opened the session to one. The handshake drops what the
// client sent in plain text, and an AUTH command can follow it.
func TestAUTHSuccessClearsTheFailures(t *testing.T) {
	t.Parallel()

	// The hook refuses the password "wrong" and takes every other one.
	auth := smtpd.Middleware{
		Authenticate: func(ctx context.Context, _ smtpd.Peer, _, pass string) (context.Context, error) {
			if pass == "wrong" {
				return ctx, smtpd.Error{Code: 535, Message: "Denied"}
			}
			return ctx, nil
		},
	}

	ts := newTestServer(t, &smtpd.Server{
		Logger:          testLogger(t),
		MaxAuthAttempts: 3,
		// The AUTH before the handshake needs a server that takes one.
		AllowInsecureAuth: true,
	}, []smtpd.Middleware{auth})
	ts.StartSTARTTLS()

	c := dialRaw(t, ts.Addr)
	c.send("EHLO before-tls.example")

	for i := range 2 {
		if reply := c.send("AUTH PLAIN %s", authPLAIN("user", "wrong")); !strings.HasPrefix(reply, "535") {
			t.Fatalf("attempt %d = %q, want 535", i+1, reply)
		}
	}

	if reply := c.send("AUTH PLAIN %s", authPLAIN("user", "right")); !strings.HasPrefix(reply, "235") {
		t.Fatalf("the good password = %q, want 235", reply)
	}

	c.startTLS()
	c.send("EHLO after-tls.example")

	// The count started over, so two more failures leave the session open.
	// Without the reset the first of them would be the third failure of the
	// session, and it would take a 421 and a closed connection.
	for i := range 2 {
		if reply := c.send("AUTH PLAIN %s", authPLAIN("user", "wrong")); !strings.HasPrefix(reply, "535") {
			t.Fatalf("attempt %d after the handshake = %q, want 535", i+1, reply)
		}
	}

	if reply := c.send("NOOP"); !strings.HasPrefix(reply, "250") {
		t.Fatalf("the session closed after a successful AUTH cleared the count: %q", reply)
	}
}

// TestAUTHUnlimitedAttempts verifies that a limit of -1 closes no connection,
// in the way that MaxConnections reads the same value.
func TestAUTHUnlimitedAttempts(t *testing.T) {
	t.Parallel()

	srv := runsslserver(t, &smtpd.Server{
		Logger:          testLogger(t),
		MaxAuthAttempts: -1,
	}, rejectAuth())

	c := srv.Dial()

	for i := range 12 {
		if err := smtptest.Cmd(c.Text, 550, "AUTH PLAIN %s", authPLAIN("user", "wrong")); err != nil {
			t.Fatalf("attempt %d did not get 550: %v", i+1, err)
		}
	}
	_ = c.Quit()
}

// TestAUTHBadCredentialsDoNotCount verifies that an AUTH command that does not
// decode leaves the count where it is. Such a command carries no guess: the
// Authenticate hooks never see it.
func TestAUTHBadCredentialsDoNotCount(t *testing.T) {
	t.Parallel()

	srv := runsslserver(t, &smtpd.Server{
		Logger:          testLogger(t),
		MaxAuthAttempts: 3,
	}, rejectAuth())

	c := srv.Dial()

	for i := range 6 {
		if err := smtptest.Cmd(c.Text, 501, "AUTH PLAIN not-base64!"); err != nil {
			t.Fatalf("attempt %d did not get 501: %v", i+1, err)
		}
	}

	if err := smtptest.Cmd(c.Text, 250, "NOOP"); err != nil {
		t.Fatalf("the session closed for commands that carried no guess: %v", err)
	}
	_ = c.Quit()
}

// TestAUTHDefaultAttemptLimit verifies that a server that sets no limit takes
// the default of five.
func TestAUTHDefaultAttemptLimit(t *testing.T) {
	t.Parallel()

	srv := runsslserver(t, &smtpd.Server{Logger: testLogger(t)}, rejectAuth())

	c := srv.Dial()

	for i := range 4 {
		if err := smtptest.Cmd(c.Text, 550, "AUTH PLAIN %s", authPLAIN("user", "wrong")); err != nil {
			t.Fatalf("attempt %d did not get 550: %v", i+1, err)
		}
	}

	if err := smtptest.Cmd(c.Text, 421, "AUTH PLAIN %s", authPLAIN("user", "wrong")); err != nil {
		t.Fatalf("the fifth attempt did not get 421: %v", err)
	}
}

// TestAUTHAfterSuccessIsRefused verifies that a second AUTH gets a 503. RFC
// 4954 section 4 asks the server to reject every AUTH command that follows a
// successful one in the same session.
func TestAUTHAfterSuccessIsRefused(t *testing.T) {
	t.Parallel()

	srv := runsslserver(t, &smtpd.Server{Logger: testLogger(t)}, acceptAuth())

	c := srv.Dial()

	if err := smtptest.Cmd(c.Text, 235, "AUTH PLAIN %s", authPLAIN("user", "pass")); err != nil {
		t.Fatalf("the first AUTH did not get 235: %v", err)
	}

	if err := smtptest.Cmd(c.Text, 503, "AUTH PLAIN %s", authPLAIN("user", "pass")); err != nil {
		t.Fatalf("the second AUTH did not get 503: %v", err)
	}

	// The session goes on: a refused sequence is not a reason to close it.
	if err := smtptest.Cmd(c.Text, 250, "NOOP"); err != nil {
		t.Fatalf("the session did not take a command after the refusal: %v", err)
	}
	_ = c.Quit()
}

// TestAUTHAfterFailureIsAllowed verifies that a refused AUTH leaves the
// session able to try again. Only a successful one closes the door.
func TestAUTHAfterFailureIsAllowed(t *testing.T) {
	t.Parallel()

	// The hook refuses the password "wrong" and takes every other one.
	auth := smtpd.Middleware{
		Authenticate: func(ctx context.Context, _ smtpd.Peer, _, pass string) (context.Context, error) {
			if pass == "wrong" {
				return ctx, smtpd.Error{Code: 535, Message: "Denied"}
			}
			return ctx, nil
		},
	}

	srv := runsslserver(t, &smtpd.Server{Logger: testLogger(t)}, auth)

	c := srv.Dial()

	if err := smtptest.Cmd(c.Text, 535, "AUTH PLAIN %s", authPLAIN("user", "wrong")); err != nil {
		t.Fatalf("the failed AUTH did not get 535: %v", err)
	}

	if err := smtptest.Cmd(c.Text, 235, "AUTH PLAIN %s", authPLAIN("user", "right")); err != nil {
		t.Fatalf("the AUTH after a failure did not get 235: %v", err)
	}
	_ = c.Quit()
}
