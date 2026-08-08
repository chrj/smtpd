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
