package smtpd_test

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/chrj/smtpd/v2"
	"github.com/chrj/smtpd/v2/smtptest"
)

// lmtpserver starts a server that speaks LMTP and gives the messages to h.
func lmtpserver(t *testing.T, srv *smtpd.Server, mws ...smtpd.Middleware) *smtptest.Server {
	t.Helper()

	srv.LMTP = true
	srv.Logger = testLogger(t)
	return runserver(t, srv, mws...)
}

// openLMTP greets the server with LHLO and sends MAIL FROM and one RCPT TO
// for every recipient, so that the next command carries the message.
func openLMTP(t *testing.T, c *rawClient, recipients ...string) {
	t.Helper()

	if reply := c.send("LHLO localhost"); !strings.HasPrefix(reply, "250") {
		t.Fatalf("LHLO reply = %q, want 250", reply)
	}
	if reply := c.send("MAIL FROM:<sender@example.org>"); !strings.HasPrefix(reply, "250") {
		t.Fatalf("MAIL reply = %q, want 250", reply)
	}
	for _, recipient := range recipients {
		if reply := c.send("RCPT TO:<%s>", recipient); !strings.HasPrefix(reply, "250") {
			t.Fatalf("RCPT reply for %s = %q, want 250", recipient, reply)
		}
	}
}

// rejectRecipientAt returns a Handler that refuses the recipient at index i
// and takes the message for every other recipient.
func rejectRecipientAt(t *testing.T, i int, err error) smtpd.Handler {
	return func(ctx context.Context, _ smtpd.Peer, env *smtpd.Envelope) (context.Context, error) {
		t.Helper()

		if rejectErr := env.RejectRecipient(i, err); rejectErr != nil {
			t.Errorf("RejectRecipient(%d) failed: %v", i, rejectErr)
		}
		return ctx, nil
	}
}

// TestLMTPGreeting covers the LHLO command of RFC 2033 section 4.1: it has
// the semantics of EHLO, so the reply carries the extensions of the server.
func TestLMTPGreeting(t *testing.T) {
	t.Parallel()

	srv := lmtpserver(t, &smtpd.Server{})
	c := dialRaw(t, srv.Addr)

	if !strings.HasSuffix(c.banner, "LMTP ready.") {
		t.Errorf("banner = %q, want it to end with %q", c.banner, "LMTP ready.")
	}

	lines := c.replyLines("LHLO localhost")
	if !strings.HasPrefix(lines[0], "250") {
		t.Fatalf("LHLO reply = %q, want 250", lines[0])
	}

	for _, keyword := range []string{"CHUNKING", "PIPELINING", "ENHANCEDSTATUSCODES"} {
		if !strings.Contains(strings.Join(lines, "\n"), keyword) {
			t.Errorf("the reply to LHLO does not offer %s: %q", keyword, lines)
		}
	}

	// The extension of RFC 2034 is in the reply, so the replies that follow
	// carry a status code.
	if reply := c.send("NOOP"); reply != "250 2.0.0 Go ahead" {
		t.Errorf("NOOP reply = %q, want a status code with it", reply)
	}
}

// TestLMTPGreetingOfTheOtherProtocol covers the greeting that the server does
// not speak. RFC 2033 section 4.1 asks an LMTP server for a reply that is not
// a completion to HELO and to EHLO.
func TestLMTPGreetingOfTheOtherProtocol(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		lmtp    bool
		command string
		want    string
	}{
		{
			name:    "HELO on a server of LMTP",
			lmtp:    true,
			command: "HELO localhost",
			want:    "500 This server speaks LMTP. Send LHLO.",
		},
		{
			name:    "EHLO on a server of LMTP",
			lmtp:    true,
			command: "EHLO localhost",
			want:    "500 This server speaks LMTP. Send LHLO.",
		},
		{
			name:    "LHLO on a server of SMTP",
			command: "LHLO localhost",
			want:    "500 This server speaks SMTP. Send EHLO.",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			srv := runserver(t, &smtpd.Server{LMTP: tc.lmtp, Logger: testLogger(t)})
			c := dialRaw(t, srv.Addr)

			if reply := c.send("%s", tc.command); reply != tc.want {
				t.Errorf("reply to %q = %q, want %q", tc.command, reply, tc.want)
			}
		})
	}
}

// TestLMTPRepliesForEveryRecipient covers RFC 2033 section 4.2: after the
// final dot the server writes one reply for every recipient that RCPT TO
// added, in the order that the commands arrived.
func TestLMTPRepliesForEveryRecipient(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		recipients []string
		handler    smtpd.Handler
		want       []string
	}{
		{
			name:       "one reply for each recipient",
			recipients: []string{"one@example.net", "two@example.net"},
			want:       []string{"250 2.0.0 Thank you.", "250 2.0.0 Thank you."},
		},
		{
			name:       "the same address twice",
			recipients: []string{"one@example.net", "one@example.net"},
			want:       []string{"250 2.0.0 Thank you.", "250 2.0.0 Thank you."},
		},
		{
			name:       "one recipient of three refused",
			recipients: []string{"one@example.net", "two@example.net", "three@example.net"},
			handler:    rejectRecipientAt(t, 1, smtpd.Error{Code: 550, Enhanced: smtpd.EnhancedCode{5, 1, 1}, Message: "No such user"}),
			want: []string{
				"250 2.0.0 Thank you.",
				"550 5.1.1 No such user",
				"250 2.0.0 Thank you.",
			},
		},
		{
			name:       "the message refused for all of them",
			recipients: []string{"one@example.net", "two@example.net"},
			handler: func(ctx context.Context, _ smtpd.Peer, _ *smtpd.Envelope) (context.Context, error) {
				return ctx, smtpd.Error{Code: 451, Enhanced: smtpd.EnhancedCode{4, 3, 0}, Message: "Try later"}
			},
			want: []string{"451 4.3.0 Try later", "451 4.3.0 Try later"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			srv := lmtpserver(t, &smtpd.Server{Handler: tc.handler})
			c := dialRaw(t, srv.Addr)

			openLMTP(t, c, tc.recipients...)

			if reply := c.send("DATA"); !strings.HasPrefix(reply, "354") {
				t.Fatalf("DATA reply = %q, want 354", reply)
			}
			c.write([]byte("Subject: one\r\n\r\nA short body.\r\n.\r\n"))

			if got := c.replies(len(tc.want)); !reflect.DeepEqual(got, tc.want) {
				t.Errorf("replies = %q, want %q", got, tc.want)
			}

			// The transaction wrote as many replies as the client expects,
			// and no reply of it is left for the command that follows.
			if reply := c.send("NOOP"); reply != "250 2.0.0 Go ahead" {
				t.Errorf("NOOP reply = %q, want the answer to that command", reply)
			}
		})
	}
}

// TestLMTPRepliesForEveryRecipientBDAT covers the same rule for a message
// that arrives in chunks: the last chunk ends the message, so its reply is
// the one that every recipient gets.
func TestLMTPRepliesForEveryRecipientBDAT(t *testing.T) {
	t.Parallel()

	srv := lmtpserver(t, &smtpd.Server{
		Handler: rejectRecipientAt(t, 0, smtpd.Error{Code: 550, Enhanced: smtpd.EnhancedCode{5, 1, 1}, Message: "No such user"}),
	})
	c := dialRaw(t, srv.Addr)

	openLMTP(t, c, "one@example.net", "two@example.net")

	// A chunk that is not the last one ends no message, so it takes one
	// reply of its own.
	c.write([]byte("BDAT 6\r\nfirst "))
	if reply := c.line(); reply != "250 2.0.0 6 octets received" {
		t.Errorf("reply to the first chunk = %q, want one reply for the chunk", reply)
	}

	c.write([]byte("BDAT 6 LAST\r\nsecond"))

	want := []string{
		"550 5.1.1 No such user",
		"250 2.0.0 Message OK, 12 octets received",
	}
	if got := c.replies(len(want)); !reflect.DeepEqual(got, want) {
		t.Errorf("replies = %q, want %q", got, want)
	}

	if reply := c.send("NOOP"); reply != "250 2.0.0 Go ahead" {
		t.Errorf("NOOP reply = %q, want the answer to that command", reply)
	}
}

// TestLMTPRepliesForEveryRecipientRefusal covers a message that the server
// refuses on its own, without a handler: every recipient still gets a reply,
// because the client counts them.
func TestLMTPRepliesForEveryRecipientRefusal(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		// send writes the message and the command that carries it.
		send func(t *testing.T, c *rawClient)
		want []string
	}{
		{
			name: "a DATA message that is too large",
			send: func(t *testing.T, c *rawClient) {
				t.Helper()

				if reply := c.send("DATA"); !strings.HasPrefix(reply, "354") {
					t.Fatalf("DATA reply = %q, want 354", reply)
				}
				c.write([]byte(strings.Repeat("a", 150) + "\r\n.\r\n"))
			},
			want: []string{
				"552 5.3.4 Message exceeded max message size of 100 bytes",
				"552 5.3.4 Message exceeded max message size of 100 bytes",
			},
		},
		{
			name: "a last chunk that is too large",
			send: func(t *testing.T, c *rawClient) {
				t.Helper()

				c.write([]byte("BDAT 150 LAST\r\n" + strings.Repeat("a", 150)))
			},
			want: []string{
				"552 5.3.4 Message exceeded max message size of 100 bytes",
				"552 5.3.4 Message exceeded max message size of 100 bytes",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			srv := lmtpserver(t, &smtpd.Server{MaxMessageSize: 100})
			c := dialRaw(t, srv.Addr)

			openLMTP(t, c, "one@example.net", "two@example.net")
			tc.send(t, c)

			if got := c.replies(len(tc.want)); !reflect.DeepEqual(got, tc.want) {
				t.Errorf("replies = %q, want %q", got, tc.want)
			}

			if reply := c.send("NOOP"); reply != "250 2.0.0 Go ahead" {
				t.Errorf("NOOP reply = %q, want the answer to that command", reply)
			}
		})
	}
}

// TestLMTPTakesMailParameters covers the parameters of MAIL FROM and RCPT TO
// on an LMTP session. LHLO offers the extensions of the server in the same
// way as EHLO, so the parameters of those extensions arrive.
func TestLMTPTakesMailParameters(t *testing.T) {
	t.Parallel()

	got := make(chan *smtpd.DSN, 1)
	srv := lmtpserver(t, &smtpd.Server{EnableDSN: true, Handler: dsnCapture(got)})
	c := dialRaw(t, srv.Addr)

	if reply := c.send("LHLO localhost"); !strings.HasPrefix(reply, "250") {
		t.Fatalf("LHLO reply = %q, want 250", reply)
	}
	if reply := c.send("MAIL FROM:<sender@example.org> BODY=8BITMIME SIZE=100 RET=HDRS"); reply != "250 2.1.0 Go ahead" {
		t.Fatalf("MAIL reply = %q, want 250", reply)
	}
	if reply := c.send("RCPT TO:<one@example.net> NOTIFY=SUCCESS"); reply != "250 2.1.5 Go ahead" {
		t.Fatalf("RCPT reply = %q, want 250", reply)
	}
	if reply := c.send("DATA"); !strings.HasPrefix(reply, "354") {
		t.Fatalf("DATA reply = %q, want 354", reply)
	}
	c.write([]byte("body\r\n.\r\n"))
	c.replies(1)

	dsn := <-got
	if dsn == nil {
		t.Fatal("the envelope carries no DSN parameters")
	}
	if dsn.Return != smtpd.DSNReturnHeaders {
		t.Errorf("DSN.Return = %q, want %q", dsn.Return, smtpd.DSNReturnHeaders)
	}
}

// TestLMTPPeerProtocol covers what a hook and a handler read off the peer of
// an LMTP session.
func TestLMTPPeerProtocol(t *testing.T) {
	t.Parallel()

	got := make(chan smtpd.Protocol, 1)
	srv := lmtpserver(t, &smtpd.Server{
		Handler: func(ctx context.Context, peer smtpd.Peer, _ *smtpd.Envelope) (context.Context, error) {
			got <- peer.Protocol
			return ctx, nil
		},
	})

	c := dialRaw(t, srv.Addr)
	openLMTP(t, c, "one@example.net")

	if reply := c.send("DATA"); !strings.HasPrefix(reply, "354") {
		t.Fatalf("DATA reply = %q, want 354", reply)
	}
	c.write([]byte("body\r\n.\r\n"))
	c.replies(1)

	if protocol := <-got; protocol != smtpd.LMTP {
		t.Errorf("Peer.Protocol = %q, want %q", protocol, smtpd.LMTP)
	}
}

// TestRejectRecipientIndex covers the index that the caller gives.
func TestRejectRecipientIndex(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		index   int
		wantErr bool
	}{
		{name: "the first recipient", index: 0},
		{name: "the last recipient", index: 1},
		{name: "one past the last", index: 2, wantErr: true},
		{name: "a negative index", index: -1, wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			env := &smtpd.Envelope{Recipients: []string{"one@example.net", "two@example.net"}}

			err := env.RejectRecipient(tc.index, smtpd.Error{Code: 550, Message: "No such user"})
			if tc.wantErr && err == nil {
				t.Fatalf("RejectRecipient(%d) = nil, want an error", tc.index)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("RejectRecipient(%d) failed: %v", tc.index, err)
			}
		})
	}
}

// TestSMTPWritesOneReply covers a server of SMTP: the client there has one
// address for the message, so a recipient that a handler refused on its own
// changes nothing on the wire.
func TestSMTPWritesOneReply(t *testing.T) {
	t.Parallel()

	srv := runserver(t, &smtpd.Server{
		Logger:  testLogger(t),
		Handler: rejectRecipientAt(t, 1, smtpd.Error{Code: 550, Message: "No such user"}),
	})
	c := dialRaw(t, srv.Addr)

	if reply := c.send("EHLO localhost"); !strings.HasPrefix(reply, "250") {
		t.Fatalf("EHLO reply = %q, want 250", reply)
	}
	if reply := c.send("MAIL FROM:<sender@example.org>"); !strings.HasPrefix(reply, "250") {
		t.Fatalf("MAIL reply = %q, want 250", reply)
	}
	for _, recipient := range []string{"one@example.net", "two@example.net"} {
		if reply := c.send("RCPT TO:<%s>", recipient); !strings.HasPrefix(reply, "250") {
			t.Fatalf("RCPT reply = %q, want 250", reply)
		}
	}
	if reply := c.send("DATA"); !strings.HasPrefix(reply, "354") {
		t.Fatalf("DATA reply = %q, want 354", reply)
	}

	c.write([]byte("body\r\n.\r\n"))
	if reply := c.line(); reply != "250 2.0.0 Thank you." {
		t.Errorf("reply to the message = %q, want one reply for the whole message", reply)
	}

	if reply := c.send("NOOP"); reply != "250 2.0.0 Go ahead" {
		t.Errorf("NOOP reply = %q, want the answer to that command", reply)
	}
}
