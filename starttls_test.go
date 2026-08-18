package smtpd_test

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/chrj/smtpd/v2"
)

// rawClient drives a session over a socket, so a test can leave out the
// greeting that a client library sends for itself after STARTTLS.
type rawClient struct {
	t    *testing.T
	conn net.Conn
	br   *bufio.Reader

	// banner holds the greeting that the server sent on connect.
	banner string
}

func dialRaw(t *testing.T, addr string) *rawClient {
	t.Helper()

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	c := &rawClient{t: t, conn: conn, br: bufio.NewReader(conn)}
	c.banner = c.line()
	return c
}

// line reads one reply line.
func (c *rawClient) line() string {
	c.t.Helper()

	_ = c.conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	l, err := c.br.ReadString('\n')
	if err != nil {
		c.t.Fatalf("read failed: %v", err)
	}
	return strings.TrimSpace(l)
}

// send writes one command and returns the last line of the reply.
func (c *rawClient) send(format string, args ...any) string {
	c.t.Helper()

	lines := c.replyLines(format, args...)
	return lines[len(lines)-1]
}

// replyLines writes one command and returns every line of the reply, with
// the continuation mark still on all lines but the last.
func (c *rawClient) replyLines(format string, args ...any) []string {
	c.t.Helper()

	if _, err := fmt.Fprintf(c.conn, format+"\r\n", args...); err != nil {
		c.t.Fatalf("write failed: %v", err)
	}

	var lines []string
	for {
		l := c.line()
		lines = append(lines, l)
		if len(l) < 4 || l[3] != '-' {
			return lines
		}
	}
}

// startTLS runs the handshake and points the client at the TLS connection.
func (c *rawClient) startTLS() {
	c.t.Helper()

	if reply := c.send("STARTTLS"); !strings.HasPrefix(reply, "220") {
		c.t.Fatalf("STARTTLS reply = %q, want 220", reply)
	}

	tconn := tls.Client(c.conn, &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         "127.0.0.1",
	})
	if err := tconn.HandshakeContext(context.Background()); err != nil {
		c.t.Fatalf("handshake failed: %v", err)
	}

	c.conn = tconn
	c.br = bufio.NewReader(tconn)
}

// TestSTARTTLSDiscardsTheGreeting verifies that the name from the greeting
// before TLS is discarded. RFC 3207 says the server must drop what it learned
// from the client outside the TLS negotiation, and the argument of EHLO is
// the example the RFC gives. A client that sends no new greeting has to be
// turned away.
func TestSTARTTLSDiscardsTheGreeting(t *testing.T) {
	t.Parallel()

	ts := newTestServer(t, &smtpd.Server{Logger: testLogger(t)}, nil)
	ts.StartSTARTTLS()

	c := dialRaw(t, ts.Addr)
	c.send("EHLO before-tls.example")
	c.startTLS()

	// No new greeting. The name from before TLS must not carry over.
	if reply := c.send("MAIL FROM:<s@example.org>"); !strings.HasPrefix(reply, "503") {
		t.Fatalf("MAIL without a new greeting = %q, want 503", reply)
	}
}

// TestSTARTTLSTakesTheNewGreeting verifies that the name from the greeting
// after TLS is the one the handler sees.
func TestSTARTTLSTakesTheNewGreeting(t *testing.T) {
	t.Parallel()

	var seen atomic.Value
	seen.Store("")

	ts := newTestServer(t, &smtpd.Server{
		Logger: testLogger(t),
		Handler: func(ctx context.Context, peer smtpd.Peer, env *smtpd.Envelope) (context.Context, error) {
			seen.Store(peer.HeloName)
			_ = env.Data.Close()
			return ctx, nil
		},
	}, nil)
	ts.StartSTARTTLS()

	c := dialRaw(t, ts.Addr)
	c.send("EHLO before-tls.example")
	c.startTLS()
	c.send("EHLO after-tls.example")

	c.send("MAIL FROM:<s@example.org>")
	c.send("RCPT TO:<r@example.net>")
	c.send("DATA")
	if reply := c.send("body\r\n."); !strings.HasPrefix(reply, "250") {
		t.Fatalf("end of message = %q, want 250", reply)
	}

	if got := seen.Load().(string); got != "after-tls.example" {
		t.Fatalf("the handler saw HeloName %q, want %q", got, "after-tls.example")
	}
}

// TestSTARTTLSDiscardsTheUsername verifies that a user name from an AUTH
// before TLS is discarded too.
func TestSTARTTLSDiscardsTheUsername(t *testing.T) {
	t.Parallel()

	var seen atomic.Value
	seen.Store("unset")

	ts := newTestServer(t, &smtpd.Server{
		Logger:            testLogger(t),
		AllowInsecureAuth: true,
		Handler: func(ctx context.Context, peer smtpd.Peer, env *smtpd.Envelope) (context.Context, error) {
			seen.Store(peer.Username)
			_ = env.Data.Close()
			return ctx, nil
		},
	}, []smtpd.Middleware{acceptAuth()})
	ts.StartSTARTTLS()

	c := dialRaw(t, ts.Addr)
	c.send("EHLO before-tls.example")
	// AGJlZm9yZQBwdw== is "\x00before\x00pw".
	if reply := c.send("AUTH PLAIN AGJlZm9yZQBwdw=="); !strings.HasPrefix(reply, "235") {
		t.Fatalf("AUTH before TLS = %q, want 235", reply)
	}
	c.startTLS()
	c.send("EHLO after-tls.example")

	c.send("MAIL FROM:<s@example.org>")
	c.send("RCPT TO:<r@example.net>")
	c.send("DATA")
	c.send("body\r\n.")

	if got := seen.Load().(string); got != "" {
		t.Fatalf("the handler saw Username %q, want it discarded", got)
	}
}

// TestSTARTTLSDiscardsPipelinedPlaintext verifies that commands sent in the
// same write as STARTTLS never run. An attacker in the middle sends them in
// plain text, and the client that follows the TLS negotiation never wrote
// them. The session builds a new reader on the TLS connection, so the bytes
// that were buffered are dropped. This test holds that property in place.
func TestSTARTTLSDiscardsPipelinedPlaintext(t *testing.T) {
	t.Parallel()

	var mu sync.Mutex
	var senders []string

	ts := newTestServer(t, &smtpd.Server{Logger: testLogger(t)}, []smtpd.Middleware{{
		CheckSender: func(ctx context.Context, _ smtpd.Peer, addr string) (context.Context, error) {
			mu.Lock()
			defer mu.Unlock()
			senders = append(senders, addr)
			return ctx, nil
		},
	}})
	ts.StartSTARTTLS()

	c := dialRaw(t, ts.Addr)
	c.send("EHLO before-tls.example")

	// STARTTLS and an injected transaction in one write. The sender of the
	// injected MAIL FROM is one that the client never sends itself, so it
	// names the injected command and nothing else.
	if _, err := fmt.Fprint(c.conn, "STARTTLS\r\nMAIL FROM:<injected@evil.example>\r\n"); err != nil {
		t.Fatalf("write failed: %v", err)
	}
	if reply := c.line(); !strings.HasPrefix(reply, "220") {
		t.Fatalf("STARTTLS reply = %q, want 220", reply)
	}

	tconn := tls.Client(c.conn, &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         "127.0.0.1",
	})
	if err := tconn.HandshakeContext(context.Background()); err != nil {
		t.Fatalf("handshake failed: %v", err)
	}
	c.conn = tconn
	c.br = bufio.NewReader(tconn)

	// A command over TLS proves the session is in step: a reply to the
	// injected command would have been answered here instead.
	if reply := c.send("EHLO after-tls.example"); !strings.HasPrefix(reply, "250") {
		t.Fatalf("EHLO after TLS = %q, want 250", reply)
	}
	c.send("MAIL FROM:<legit@example.org>")

	mu.Lock()
	defer mu.Unlock()
	for _, addr := range senders {
		if addr == "injected@evil.example" {
			t.Fatalf("the injected command ran: senders = %v", senders)
		}
	}
	if len(senders) != 1 || senders[0] != "legit@example.org" {
		t.Fatalf("senders = %v, want [legit@example.org]", senders)
	}
}
