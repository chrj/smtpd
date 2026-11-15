package smtpd_test

import (
	"bytes"
	"encoding/base64"
	"log/slog"
	"net/smtp"
	"strings"
	"sync"
	"testing"

	"github.com/chrj/smtpd/v2"
)

// syncBuffer collects log output from the goroutine of the session while the
// test reads it.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// TestAuthCredentialsStayOutOfTheLog runs a real AUTH against a server that
// logs at the DEBUG level, and makes sure the credentials are not in the
// output. The server logs every line it receives, and the inline form of AUTH
// carries the credentials on that line.
func TestAuthCredentialsStayOutOfTheLog(t *testing.T) {
	t.Parallel()

	const (
		username = "hunter2user"
		password = "sup3rs3cr3t"
	)
	encoded := base64.StdEncoding.EncodeToString([]byte("\x00" + username + "\x00" + password))

	var out syncBuffer
	ts := newTestServer(t, &smtpd.Server{
		Logger:            slog.New(slog.NewTextHandler(&out, &slog.HandlerOptions{Level: slog.LevelDebug})),
		AllowInsecureAuth: true,
	}, []smtpd.Middleware{acceptAuth()})
	ts.Start()

	c, err := smtp.Dial(ts.Addr)
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}
	if err := c.Hello("client.example"); err != nil {
		t.Fatalf("HELO failed: %v", err)
	}
	if err := c.Text.PrintfLine("AUTH PLAIN %s", encoded); err != nil {
		t.Fatalf("AUTH failed: %v", err)
	}
	if _, _, err := c.Text.ReadResponse(235); err != nil {
		t.Fatalf("AUTH was not accepted: %v", err)
	}
	_ = c.Quit()

	logged := out.String()
	for _, secret := range []string{encoded, password} {
		if strings.Contains(logged, secret) {
			t.Errorf("the log contains the credentials:\n%s", logged)
		}
	}

	// The command still reaches the log, so an operator can see that a client
	// tried to authenticate.
	if !strings.Contains(logged, "AUTH PLAIN [redacted]") {
		t.Errorf("expected the redacted AUTH line in the log, got:\n%s", logged)
	}
}

// TestAuthRefusedIdentityStaysOutOfTheLog covers a PLAIN message that the
// server refuses for its authorization identity. The refusal goes to the log
// at the warning level, and the credentials of the message stay out of it as
// they do for an accepted one. A client that has not authenticated wrote
// them, and the user name can carry a password that a user typed into the
// wrong field.
func TestAuthRefusedIdentityStaysOutOfTheLog(t *testing.T) {
	t.Parallel()

	const (
		authzid  = "act4sadmin"
		username = "hunter2user"
		password = "sup3rs3cr3t"
	)
	encoded := base64.StdEncoding.EncodeToString([]byte(authzid + "\x00" + username + "\x00" + password))

	var out syncBuffer
	ts := newTestServer(t, &smtpd.Server{
		Logger:            slog.New(slog.NewTextHandler(&out, &slog.HandlerOptions{Level: slog.LevelDebug})),
		AllowInsecureAuth: true,
	}, []smtpd.Middleware{acceptAuth()})
	ts.Start()

	c, err := smtp.Dial(ts.Addr)
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}
	if err := c.Hello("client.example"); err != nil {
		t.Fatalf("HELO failed: %v", err)
	}
	if err := c.Text.PrintfLine("AUTH PLAIN %s", encoded); err != nil {
		t.Fatalf("AUTH failed: %v", err)
	}
	if _, _, err := c.Text.ReadResponse(535); err != nil {
		t.Fatalf("AUTH was not refused: %v", err)
	}
	_ = c.Quit()

	logged := out.String()
	for _, secret := range []string{encoded, authzid, username, password} {
		if strings.Contains(logged, secret) {
			t.Errorf("the log contains %q:\n%s", secret, logged)
		}
	}

	if !strings.Contains(logged, "refused an AUTH PLAIN command that asks to act as another user") {
		t.Errorf("expected the refusal in the log, got:\n%s", logged)
	}
}

// TestAuthRefusedBeforeItsPromptKeepsTheCredentialsOutOfTheLog covers a
// client that sends its credentials on lines of their own although the
// server refused its AUTH before the 334. The session reads those lines as
// commands, and they are no commands of the server, so they reach the log as
// redacted.
func TestAuthRefusedBeforeItsPromptKeepsTheCredentialsOutOfTheLog(t *testing.T) {
	t.Parallel()

	encodedUser := base64.StdEncoding.EncodeToString([]byte("hunter2user"))
	encodedPassword := base64.StdEncoding.EncodeToString([]byte("sup3rs3cr3t"))

	var out syncBuffer
	srv := runserver(t, &smtpd.Server{
		Logger: slog.New(slog.NewTextHandler(&out, &slog.HandlerOptions{Level: slog.LevelDebug})),
	}, acceptAuth())

	c := dialRaw(t, srv.Addr)
	c.send("EHLO client.example")

	// The connection is in plain text, and the server refuses AUTH there.
	if reply := c.send("AUTH LOGIN"); !strings.HasPrefix(reply, "502") {
		t.Fatalf("AUTH LOGIN = %q, want the 502 for plain text", reply)
	}
	for _, line := range []string{encodedUser, encodedPassword} {
		if reply := c.send("%s", line); !strings.HasPrefix(reply, "500") {
			t.Fatalf("%q = %q, want 500", line, reply)
		}
	}
	c.send("QUIT")

	logged := out.String()
	for _, secret := range []string{encodedUser, encodedPassword} {
		if strings.Contains(logged, secret) {
			t.Errorf("the log contains %q:\n%s", secret, logged)
		}
	}
	if !strings.Contains(logged, `line=[redacted]`) {
		t.Errorf("expected the lines in the log as redacted, got:\n%s", logged)
	}
}

// TestAuthContinuationStaysOutOfTheLog covers the form that sends the
// credentials on their own lines, after a 334 reply.
func TestAuthContinuationStaysOutOfTheLog(t *testing.T) {
	t.Parallel()

	const password = "sup3rs3cr3t"

	var out syncBuffer
	ts := newTestServer(t, &smtpd.Server{
		Logger:            slog.New(slog.NewTextHandler(&out, &slog.HandlerOptions{Level: slog.LevelDebug})),
		AllowInsecureAuth: true,
	}, []smtpd.Middleware{acceptAuth()})
	ts.Start()

	c, err := smtp.Dial(ts.Addr)
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}
	if err := c.Hello("client.example"); err != nil {
		t.Fatalf("HELO failed: %v", err)
	}
	if err := c.Text.PrintfLine("AUTH LOGIN"); err != nil {
		t.Fatalf("AUTH failed: %v", err)
	}
	if _, _, err := c.Text.ReadResponse(334); err != nil {
		t.Fatalf("expected a 334 reply: %v", err)
	}
	if err := c.Text.PrintfLine("%s", base64.StdEncoding.EncodeToString([]byte("hunter2user"))); err != nil {
		t.Fatalf("sending the user name failed: %v", err)
	}
	if _, _, err := c.Text.ReadResponse(334); err != nil {
		t.Fatalf("expected a second 334 reply: %v", err)
	}
	encodedPassword := base64.StdEncoding.EncodeToString([]byte(password))
	if err := c.Text.PrintfLine("%s", encodedPassword); err != nil {
		t.Fatalf("sending the password failed: %v", err)
	}
	if _, _, err := c.Text.ReadResponse(235); err != nil {
		t.Fatalf("AUTH was not accepted: %v", err)
	}
	_ = c.Quit()

	logged := out.String()
	for _, secret := range []string{encodedPassword, password} {
		if strings.Contains(logged, secret) {
			t.Errorf("the log contains the credentials:\n%s", logged)
		}
	}
}
