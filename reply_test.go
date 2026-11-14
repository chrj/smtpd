package smtpd_test

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"

	"github.com/chrj/smtpd/v2"
)

// TestHookErrorStaysOutOfTheReply drives each hook with an error that is not
// an smtpd.Error. The client must read a 451 with a fixed text, and the text
// of the error must reach the log in its place.
//
// The text of such an error comes from the site, such as the address of a
// database, and a client of any kind reads a reply. RFC 5321 section 4.2.3
// gives 451 for a local error in processing. A 502 says that the server does
// not carry the command, which section 3.5.3 calls a fault for a command that
// it does carry.
func TestHookErrorStaysOutOfTheReply(t *testing.T) {
	t.Parallel()

	const internal = "dial tcp 10.1.2.3:5432: connect: connection refused"
	fail := errors.New(internal)

	tests := []struct {
		name      string
		configure func(s *smtpd.Server)
		mw        smtpd.Middleware
		run       func(c *rawClient) string
		want      string
	}{
		{
			name: "CheckConnection",
			mw: smtpd.Middleware{
				CheckConnection: func(ctx context.Context, _ smtpd.Peer) (context.Context, error) {
					return ctx, fail
				},
			},
			run:  func(c *rawClient) string { return c.banner },
			want: "451 Requested action aborted: local error in processing",
		},
		{
			name: "CheckHelo",
			mw: smtpd.Middleware{
				CheckHelo: func(ctx context.Context, _ smtpd.Peer, _ string) (context.Context, error) {
					return ctx, fail
				},
			},
			run:  func(c *rawClient) string { return c.send("HELO client.example") },
			want: "451 Requested action aborted: local error in processing",
		},
		{
			name: "CheckSender",
			mw: smtpd.Middleware{
				CheckSender: func(ctx context.Context, _ smtpd.Peer, _ string) (context.Context, error) {
					return ctx, fail
				},
			},
			run: func(c *rawClient) string {
				c.send("EHLO client.example")
				return c.send("MAIL FROM:<sender@example.org>")
			},
			want: "451 4.3.0 Requested action aborted: local error in processing",
		},
		{
			name: "CheckRecipient",
			mw: smtpd.Middleware{
				CheckRecipient: func(ctx context.Context, _ smtpd.Peer, _ string) (context.Context, error) {
					return ctx, fail
				},
			},
			run: func(c *rawClient) string {
				c.send("EHLO client.example")
				c.send("MAIL FROM:<sender@example.org>")
				return c.send("RCPT TO:<recipient@example.net>")
			},
			want: "451 4.3.0 Requested action aborted: local error in processing",
		},
		{
			name:      "Authenticate",
			configure: func(s *smtpd.Server) { s.AllowInsecureAuth = true },
			mw: smtpd.Middleware{
				Authenticate: func(ctx context.Context, _ smtpd.Peer, _, _ string) (context.Context, error) {
					return ctx, fail
				},
			},
			run: func(c *rawClient) string {
				c.send("EHLO client.example")
				return c.send("AUTH PLAIN %s", authPLAIN("user", "secret"))
			},
			want: "451 4.3.0 Requested action aborted: local error in processing",
		},
		{
			name: "Handler",
			configure: func(s *smtpd.Server) {
				s.Handler = func(ctx context.Context, _ smtpd.Peer, _ *smtpd.Envelope) (context.Context, error) {
					return ctx, fail
				}
			},
			run: func(c *rawClient) string {
				c.send("EHLO client.example")
				c.send("MAIL FROM:<sender@example.org>")
				c.send("RCPT TO:<recipient@example.net>")
				c.send("DATA")
				return c.send("Subject: test\r\n\r\nHello.\r\n.")
			},
			want: "451 4.3.0 Requested action aborted: local error in processing",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var out syncBuffer
			server := &smtpd.Server{Logger: slog.New(slog.NewTextHandler(&out, nil))}
			if tc.configure != nil {
				tc.configure(server)
			}
			srv := runserver(t, server, tc.mw)

			c := dialRaw(t, srv.Addr)
			if got := tc.run(c); got != tc.want {
				t.Errorf("the reply = %q, want %q", got, tc.want)
			}

			if !strings.Contains(out.String(), internal) {
				t.Errorf("the log lacks the text of the error:\n%s", out.String())
			}
		})
	}
}

// TestReplyTextStaysInsideItsReply drives a server whose middleware puts a
// control character into the message of a refusal. The client must read one
// reply, with the control character replaced.
//
// A middleware writes what it knows into the message, and some of that comes
// from the client. The user name of an AUTH command is one example: the
// session decodes it from base64, so it holds any byte at all.
func TestReplyTextStaysInsideItsReply(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		message string
		want    string
	}{
		{
			name:    "a plain message stays as it is",
			message: "No such user",
			want:    "550 5.0.0 No such user",
		},
		{
			name:    "a line break becomes a space",
			message: "No such user\r\n250 injected",
			want:    "550 5.0.0 No such user  250 injected",
		},
		{
			name:    "a line feed on its own becomes a space",
			message: "No such user\n250 injected",
			want:    "550 5.0.0 No such user 250 injected",
		},
		{
			name:    "a carriage return on its own becomes a space",
			message: "No such user\rmore",
			want:    "550 5.0.0 No such user more",
		},
		{
			name:    "a tab becomes a space",
			message: "No\tsuch\tuser",
			want:    "550 5.0.0 No such user",
		},
		{
			name:    "utf-8 arrives whole",
			message: "Ingen sådan brugér",
			want:    "550 5.0.0 Ingen sådan brugér",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			deny := smtpd.Middleware{
				CheckSender: func(ctx context.Context, _ smtpd.Peer, _ string) (context.Context, error) {
					return ctx, smtpd.Error{Code: 550, Message: test.message}
				},
			}

			srv := runserver(t, &smtpd.Server{Logger: testLogger(t)}, deny)
			c := dialRaw(t, srv.Addr)

			c.send("EHLO localhost")

			lines := c.replyLines("MAIL FROM:<sender@example.org>")
			if len(lines) != 1 {
				t.Fatalf("the server wrote %d lines, want 1: %q", len(lines), lines)
			}
			if lines[0] != test.want {
				t.Errorf("got %q, want %q", lines[0], test.want)
			}
		})
	}
}
