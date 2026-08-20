package smtpd_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/chrj/smtpd/v2"
	"github.com/chrj/smtpd/v2/smtptest"
)

// TestVerifyReplies covers the reply to a VRFY command for every answer that
// a Verify hook can give.
func TestVerifyReplies(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		mws  []smtpd.Middleware
		cmd  string
		want string
	}{
		{
			name: "no hook at all",
			cmd:  "VRFY user@example.org",
			want: "252 2.0.0 Cannot VRFY user, but will accept message and attempt delivery",
		},
		{
			name: "a hook that finds nothing",
			mws:  []smtpd.Middleware{verifier(smtpd.Verification{}, nil)},
			cmd:  "VRFY user@example.org",
			want: "252 2.0.0 Cannot VRFY user, but will accept message and attempt delivery",
		},
		{
			name: "a mailbox alone",
			mws:  []smtpd.Middleware{verifier(smtpd.Verification{Mailbox: "user@example.org"}, nil)},
			cmd:  "VRFY user",
			want: "250 2.1.5 <user@example.org>",
		},
		{
			name: "a mailbox with the name of the user",
			mws: []smtpd.Middleware{verifier(smtpd.Verification{
				Mailbox:  "joe@example.org",
				FullName: "Joe Smith",
			}, nil)},
			cmd:  "VRFY Smith",
			want: "250 2.1.5 Joe Smith <joe@example.org>",
		},
		{
			// RFC 5321 section 3.5.1 leaves the name of the user out of the
			// reply, so a name of Unicode goes and the mailbox stays.
			name: "a name of Unicode",
			mws: []smtpd.Middleware{verifier(smtpd.Verification{
				Mailbox:  "joe@example.org",
				FullName: "Jörg Smith",
			}, nil)},
			cmd:  "VRFY Smith",
			want: "250 2.1.5 <joe@example.org>",
		},
		{
			// RFC 6531 section 3.7.4.2 gives a reply of UTF-8 to a client
			// that asked for one, and this server offers no SMTPUTF8.
			name: "a mailbox of Unicode",
			mws:  []smtpd.Middleware{verifier(smtpd.Verification{Mailbox: "jörg@example.org"}, nil)},
			cmd:  "VRFY Smith",
			want: "252 2.6.8 Cannot show the mailbox of the user without a reply in UTF-8",
		},
		{
			name: "a name that carries angle brackets",
			mws: []smtpd.Middleware{verifier(smtpd.Verification{
				Mailbox:  "user@example.org",
				FullName: "Joe <other@example.net>",
			}, nil)},
			cmd:  "VRFY Joe",
			want: "250 2.1.5 Joe other@example.net <user@example.org>",
		},
		{
			name: "a mailbox with a local part in quotes",
			mws:  []smtpd.Middleware{verifier(smtpd.Verification{Mailbox: `"a b"@example.org`}, nil)},
			cmd:  "VRFY a b",
			want: `250 2.1.5 <"a b"@example.org>`,
		},
		{
			name: "a mailbox that is not an address",
			mws:  []smtpd.Middleware{verifier(smtpd.Verification{Mailbox: "user"}, nil)},
			cmd:  "VRFY user",
			want: "252 2.0.0 Cannot VRFY user, but will accept message and attempt delivery",
		},
		{
			name: "a user that the server does not carry",
			mws: []smtpd.Middleware{verifier(smtpd.Verification{}, smtpd.Error{
				Code:     550,
				Enhanced: smtpd.EnhancedCode{5, 1, 1},
				Message:  "No such user here",
			})},
			cmd:  "VRFY nobody",
			want: "550 5.1.1 No such user here",
		},
		{
			name: "a name that more than one user answers to",
			mws: []smtpd.Middleware{verifier(smtpd.Verification{}, smtpd.Error{
				Code:     553,
				Enhanced: smtpd.EnhancedCode{5, 1, 4},
				Message:  "User ambiguous",
			})},
			cmd:  "VRFY Smith",
			want: "553 5.1.4 User ambiguous",
		},
		{
			// RFC 5321 section 3.5.3 reads a 500 and a 502 as the answer of a
			// server that does not carry the command, so a fault of the
			// directory takes a 451. The text of the error stays in the log.
			name: "a hook that fails",
			mws:  []smtpd.Middleware{verifier(smtpd.Verification{}, errors.New("the directory is down"))},
			cmd:  "VRFY user",
			want: "451 4.3.0 Cannot verify the user right now",
		},
		{
			name: "a command without a name",
			cmd:  "VRFY",
			want: "501 5.5.4 Missing parameter",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			srv := runserver(t, &smtpd.Server{Logger: testLogger(t)}, test.mws...)

			c := dialRaw(t, srv.Addr)
			if reply := c.send("EHLO localhost"); !strings.HasPrefix(reply, "250") {
				t.Fatalf("EHLO reply = %q, want 250", reply)
			}

			if reply := c.send("%s", test.cmd); reply != test.want {
				t.Errorf("%s reply = %q, want %q", test.cmd, reply, test.want)
			}

			// The session survives every one of these replies.
			if reply := c.send("NOOP"); !strings.HasPrefix(reply, "250") {
				t.Errorf("NOOP after the reply = %q, want 250", reply)
			}
		})
	}
}

// TestVerifyBeforeGreeting covers a client that sends VRFY as its first
// command. RFC 5321 section 4.1.4 lets it, because the command carries no
// transaction. The reply has no status code, because the client never saw the
// server offer the extension of RFC 2034.
func TestVerifyBeforeGreeting(t *testing.T) {
	t.Parallel()

	srv := runserver(t, &smtpd.Server{Logger: testLogger(t)},
		verifier(smtpd.Verification{Mailbox: "user@example.org"}, nil))

	c := dialRaw(t, srv.Addr)
	if reply := c.send("VRFY user"); reply != "250 <user@example.org>" {
		t.Errorf("VRFY reply = %q, want %q", reply, "250 <user@example.org>")
	}
}

// TestVerifyName covers the name that reaches the hook. RFC 5321 section
// 3.5.1 leaves its form to the site, so the argument goes through as it came.
func TestVerifyName(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		cmd  string
		want string
	}{
		{name: "a user name", cmd: "VRFY Crispin", want: "Crispin"},
		{name: "a mailbox", cmd: "VRFY user@example.org", want: "user@example.org"},
		{name: "a name with a space", cmd: "VRFY Sam Q. Smith", want: "Sam Q. Smith"},
		{name: "a name in quotes", cmd: `VRFY "Sam Smith"`, want: `"Sam Smith"`},
		{name: "spaces around the name", cmd: "VRFY   Crispin   ", want: "Crispin"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			got := make(chan string, 1)
			srv := runserver(t, &smtpd.Server{Logger: testLogger(t)}, smtpd.Middleware{
				Verify: func(ctx context.Context, _ smtpd.Peer, name string) (context.Context, smtpd.Verification, error) {
					got <- name
					return ctx, smtpd.Verification{}, nil
				},
			})

			c := dialRaw(t, srv.Addr)
			if reply := c.send("%s", test.cmd); !strings.HasPrefix(reply, "252") {
				t.Fatalf("%s reply = %q, want 252", test.cmd, reply)
			}

			if name := <-got; name != test.want {
				t.Errorf("the hook read the name %q, want %q", name, test.want)
			}
		})
	}
}

// TestVerifyHookOrder covers a server with more than one Verify hook. They run
// in Use order, and the first one that finds a mailbox ends the phase.
func TestVerifyHookOrder(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		first smtpd.Middleware
		want  string
		ran   bool
	}{
		{
			name:  "the first hook finds nothing",
			first: verifier(smtpd.Verification{}, nil),
			want:  "250 2.1.5 <second@example.org>",
			ran:   true,
		},
		{
			name:  "the first hook finds the user",
			first: verifier(smtpd.Verification{Mailbox: "first@example.org"}, nil),
			want:  "250 2.1.5 <first@example.org>",
		},
		{
			name:  "the first hook refuses the name",
			first: verifier(smtpd.Verification{}, smtpd.Error{Code: 550, Message: "No such user here"}),
			want:  "550 5.0.0 No such user here",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			second := make(chan struct{}, 1)
			srv := runserver(t, &smtpd.Server{Logger: testLogger(t)},
				test.first,
				smtpd.Middleware{
					Verify: func(ctx context.Context, _ smtpd.Peer, _ string) (context.Context, smtpd.Verification, error) {
						second <- struct{}{}
						return ctx, smtpd.Verification{Mailbox: "second@example.org"}, nil
					},
				})

			c := dialRaw(t, srv.Addr)
			if reply := c.send("EHLO localhost"); !strings.HasPrefix(reply, "250") {
				t.Fatalf("EHLO reply = %q, want 250", reply)
			}

			if reply := c.send("VRFY user"); reply != test.want {
				t.Errorf("VRFY reply = %q, want %q", reply, test.want)
			}

			if ran := len(second) == 1; ran != test.ran {
				t.Errorf("the second hook ran = %v, want %v", ran, test.ran)
			}
		})
	}
}

// TestVerifyPanicKeepsServerAlive covers a Verify hook that panics. The
// client that reached it gets a 421 and the session ends, in the same way as
// for every other hook, and the server carries on.
func TestVerifyPanicKeepsServerAlive(t *testing.T) {
	t.Parallel()

	boom := panicOnce("boom")
	srv := runserver(t, &smtpd.Server{Logger: testLogger(t)}, smtpd.Middleware{
		Verify: func(ctx context.Context, _ smtpd.Peer, _ string) (context.Context, smtpd.Verification, error) {
			boom()
			return ctx, smtpd.Verification{Mailbox: "user@example.org"}, nil
		},
	})

	c := dialRaw(t, srv.Addr)
	if reply := c.send("VRFY user"); !strings.HasPrefix(reply, "421") {
		t.Errorf("VRFY reply = %q, want 421", reply)
	}

	// The hook no longer panics, so a second connection proves that the
	// server kept running.
	second := dialRaw(t, srv.Addr)
	if reply := second.send("VRFY user"); reply != "250 <user@example.org>" {
		t.Errorf("VRFY reply = %q, want %q", reply, "250 <user@example.org>")
	}
}

// TestVerifyKeepsTheTransaction covers RFC 5321 section 4.1.1.6: the command
// has no effect on the reverse path, the forward path, or the message.
func TestVerifyKeepsTheTransaction(t *testing.T) {
	t.Parallel()

	got := make(chan message, 1)
	srv := runserver(t, &smtpd.Server{
		Logger:  testLogger(t),
		Handler: captureMessage(got),
	}, verifier(smtpd.Verification{Mailbox: "user@example.org"}, nil))

	c := srv.Dial()
	if err := c.Hello("localhost"); err != nil {
		t.Fatalf("EHLO failed: %v", err)
	}

	if err := smtptest.Cmd(c.Text, 250, "MAIL FROM:<sender@example.org>"); err != nil {
		t.Fatalf("MAIL FROM failed: %v", err)
	}
	if err := smtptest.Cmd(c.Text, 250, "VRFY user"); err != nil {
		t.Fatalf("VRFY failed: %v", err)
	}
	if err := smtptest.Cmd(c.Text, 250, "RCPT TO:<one@example.net>"); err != nil {
		t.Fatalf("RCPT TO failed: %v", err)
	}

	w, err := c.Data()
	if err != nil {
		t.Fatalf("DATA failed: %v", err)
	}
	if _, err := w.Write([]byte("body\r\n")); err != nil {
		t.Fatalf("write body failed: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close body failed: %v", err)
	}

	msg := <-got
	if msg.readErr != nil {
		t.Fatalf("the handler read the body with the error %v", msg.readErr)
	}
	if msg.sender != "sender@example.org" {
		t.Errorf("sender = %q, want %q", msg.sender, "sender@example.org")
	}
	if len(msg.recipients) != 1 || msg.recipients[0] != "one@example.net" {
		t.Errorf("recipients = %q, want %q", msg.recipients, []string{"one@example.net"})
	}
	if msg.body != "body\n" {
		t.Errorf("body = %q, want %q", msg.body, "body\n")
	}

	if err := c.Quit(); err != nil {
		t.Errorf("QUIT failed: %v", err)
	}
}
