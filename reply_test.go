package smtpd_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"slices"
	"strings"
	"testing"
	"time"

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
			// The hook chose its reply with an smtpd.Error, and joined a
			// fault to it. The reply is the one of the hook, and the fault
			// goes to the log.
			name: "CheckSender with an smtpd.Error joined to a fault",
			mw: smtpd.Middleware{
				CheckSender: func(ctx context.Context, _ smtpd.Peer, _ string) (context.Context, error) {
					return ctx, errors.Join(smtpd.Error{Code: 550, Enhanced: smtpd.EnhancedCode{5, 7, 1}, Message: "Sender refused"}, fail)
				},
			},
			run: func(c *rawClient) string {
				c.send("EHLO client.example")
				return c.send("MAIL FROM:<sender@example.org>")
			},
			want: "550 5.7.1 Sender refused",
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
			// The attempt that reaches the limit gets the 421 in the place of
			// the reply to the error, and the error still goes to the log.
			name: "Authenticate at the limit of attempts",
			configure: func(s *smtpd.Server) {
				s.AllowInsecureAuth = true
				s.MaxAuthAttempts = 1
			},
			mw: smtpd.Middleware{
				Authenticate: func(ctx context.Context, _ smtpd.Peer, _, _ string) (context.Context, error) {
					return ctx, fail
				},
			},
			run: func(c *rawClient) string {
				c.send("EHLO client.example")
				return c.send("AUTH PLAIN %s", authPLAIN("user", "secret"))
			},
			want: "421 4.7.0 Too many failed authentication attempts",
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

// TestHookErrorOfLMTPGoesToTheLogOnce drives an LMTP message with three
// recipients to a handler that fails. RFC 2033 section 4.2 gives a reply for
// each recipient, so the client reads three 451 replies. The handler failed
// once, and the log holds the error once.
func TestHookErrorOfLMTPGoesToTheLogOnce(t *testing.T) {
	t.Parallel()

	const internal = "dial tcp 10.1.2.3:5432: connect: connection refused"

	var out syncBuffer
	srv := runserver(t, &smtpd.Server{
		LMTP:   true,
		Logger: slog.New(slog.NewTextHandler(&out, nil)),
		Handler: func(ctx context.Context, _ smtpd.Peer, _ *smtpd.Envelope) (context.Context, error) {
			return ctx, errors.New(internal)
		},
	})

	c := dialRaw(t, srv.Addr)
	openLMTP(t, c, "one@example.net", "two@example.net", "three@example.net")
	if reply := c.send("DATA"); !strings.HasPrefix(reply, "354") {
		t.Fatalf("DATA reply = %q, want 354", reply)
	}
	c.write([]byte("Subject: one\r\n\r\nA short body.\r\n.\r\n"))

	want := "451 4.3.0 Requested action aborted: local error in processing"
	for i, got := range c.replies(3) {
		if got != want {
			t.Errorf("the reply for recipient %d = %q, want %q", i+1, got, want)
		}
	}

	// The session writes its log lines before its replies, so the log is
	// whole once the client has read the last reply.
	if got := strings.Count(out.String(), internal); got != 1 {
		t.Errorf("the log holds the error %d times, want 1:\n%s", got, out.String())
	}
}

// TestHandlerErrorGoesToTheLogOnce drives a handler that fails through paths
// where its error and the reply do not match one to one. A 552 for a message
// that is too large stands in the place of the reply to the handler, and a
// BDAT transfer answers every chunk after the failure with it. The handler
// failed once in each, so the log holds its error once, whatever the replies.
//
// An error that the body gave the handler, such as the one for a message that
// is too large, is the session's own and not a fault of the handler. A handler
// that returns it leaves nothing in the log.
func TestHandlerErrorGoesToTheLogOnce(t *testing.T) {
	t.Parallel()

	const internal = "dial tcp 10.1.2.3:5432: connect: connection refused"

	// bdat sends a BDAT command with its chunk, and reads the reply.
	bdat := func(c *rawClient, chunk string, last bool) string {
		cmd := fmt.Sprintf("BDAT %d", len(chunk))
		if last {
			cmd += " LAST"
		}
		c.write([]byte(cmd + "\r\n" + chunk))
		return c.replies(1)[0]
	}

	tests := []struct {
		name    string
		handler smtpd.Handler
		run     func(c *rawClient) []string
		want    []string
		logged  int
	}{
		{
			name: "a DATA message that is too large, to a handler that failed without reading it",
			handler: func(ctx context.Context, _ smtpd.Peer, _ *smtpd.Envelope) (context.Context, error) {
				return ctx, errors.New(internal)
			},
			run: func(c *rawClient) []string {
				c.send("DATA")
				return []string{c.send("%s\r\n.", strings.Repeat("x", 200))}
			},
			want:   []string{"552 5.3.4 Message exceeded max message size of 100 bytes"},
			logged: 1,
		},
		{
			name: "a DATA message that is too large, to a handler that returns the error of the body",
			handler: func(ctx context.Context, _ smtpd.Peer, env *smtpd.Envelope) (context.Context, error) {
				_, err := io.ReadAll(env.Data)
				return ctx, err
			},
			run: func(c *rawClient) []string {
				c.send("DATA")
				return []string{c.send("%s\r\n.", strings.Repeat("x", 200))}
			},
			want:   []string{"552 5.3.4 Message exceeded max message size of 100 bytes"},
			logged: 0,
		},
		{
			name: "a DATA message that is too large, to a handler that wraps the error of the body",
			handler: func(ctx context.Context, _ smtpd.Peer, env *smtpd.Envelope) (context.Context, error) {
				_, err := io.ReadAll(env.Data)
				return ctx, fmt.Errorf("read the message: %w", err)
			},
			run: func(c *rawClient) []string {
				c.send("DATA")
				return []string{c.send("%s\r\n.", strings.Repeat("x", 200))}
			},
			want:   []string{"552 5.3.4 Message exceeded max message size of 100 bytes"},
			logged: 0,
		},
		{
			// The error of the handler joins the one of the body with a fault
			// of its own, and the log needs that fault.
			name: "a DATA message that is too large, to a handler that joins the error of the body with its own",
			handler: func(ctx context.Context, _ smtpd.Peer, env *smtpd.Envelope) (context.Context, error) {
				_, err := io.ReadAll(env.Data)
				return ctx, errors.Join(err, errors.New(internal))
			},
			run: func(c *rawClient) []string {
				c.send("DATA")
				return []string{c.send("%s\r\n.", strings.Repeat("x", 200))}
			},
			want:   []string{"552 5.3.4 Message exceeded max message size of 100 bytes"},
			logged: 1,
		},
		{
			// The session ends the transfer with a 552, which is an
			// smtpd.Error, and the handler reads it from the body. It joins
			// that error with a fault of its own, and the log needs the fault.
			name: "a BDAT message that is too large, to a handler that joins the error of the body with its own",
			handler: func(ctx context.Context, _ smtpd.Peer, env *smtpd.Envelope) (context.Context, error) {
				_, err := io.ReadAll(env.Data)
				return ctx, errors.Join(err, errors.New(internal))
			},
			run: func(c *rawClient) []string {
				return []string{
					bdat(c, strings.Repeat("x", 50), false),
					bdat(c, strings.Repeat("x", 100), false),
				}
			},
			want: []string{
				"250 2.0.0 50 octets received",
				"552 5.3.4 Message exceeded max message size of 100 bytes",
			},
			logged: 1,
		},
		{
			name: "BDAT chunks after a handler that failed",
			handler: func(ctx context.Context, _ smtpd.Peer, _ *smtpd.Envelope) (context.Context, error) {
				return ctx, errors.New(internal)
			},
			// The handler sends its result before the drain reads the first
			// chunk out of the pipe, so the session has the result by the end
			// of that chunk, and every chunk gets the same answer.
			run: func(c *rawClient) []string {
				return []string{
					bdat(c, "Subject: one\r\n", false),
					bdat(c, "\r\n", false),
					bdat(c, "A body.\r\n", false),
					bdat(c, "The end.\r\n", true),
				}
			},
			want: []string{
				"451 4.3.0 Requested action aborted: local error in processing",
				"451 4.3.0 Requested action aborted: local error in processing",
				"451 4.3.0 Requested action aborted: local error in processing",
				"451 4.3.0 Requested action aborted: local error in processing",
			},
			logged: 1,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var out syncBuffer
			srv := runserver(t, &smtpd.Server{
				Logger:         slog.New(slog.NewTextHandler(&out, nil)),
				MaxMessageSize: 100,
				Handler:        tc.handler,
			})

			c := dialRaw(t, srv.Addr)
			c.send("EHLO client.example")
			c.send("MAIL FROM:<sender@example.org>")
			c.send("RCPT TO:<recipient@example.net>")

			if got := tc.run(c); !slices.Equal(got, tc.want) {
				t.Errorf("replies = %q, want %q", got, tc.want)
			}

			// The session writes its log lines before its replies, so the log
			// is whole once the client has read the last reply.
			logged := strings.Count(out.String(), "a hook failed with an error that is not an smtpd.Error")
			if logged != tc.logged {
				t.Errorf("the log holds %d errors of the handler, want %d:\n%s", logged, tc.logged, out.String())
			}
		})
	}
}

// TestDataTimeoutIsNotAHandlerError drives a DATA message that stops in the
// middle, to a handler that reads it and returns the timeout that the read
// gave. The timeout is the session's own, so the log holds no error of the
// handler. A body that read the connection again after the timeout would
// give a second error that is not the one that the handler returned.
func TestDataTimeoutIsNotAHandlerError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		handler smtpd.Handler
	}{
		{
			name: "a handler that returns the error of its read",
			handler: func(ctx context.Context, _ smtpd.Peer, env *smtpd.Envelope) (context.Context, error) {
				_, err := io.ReadAll(env.Data)
				return ctx, err
			},
		},
		{
			// The body gives the same error on every read after the first
			// failure, so the handler returns the error that the session has.
			name: "a handler that reads again after the error and returns the first one",
			handler: func(ctx context.Context, _ smtpd.Peer, env *smtpd.Envelope) (context.Context, error) {
				_, err := io.ReadAll(env.Data)
				_, _ = env.Data.Read(make([]byte, 1))
				return ctx, err
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var out syncBuffer
			disconnected := make(chan struct{})
			srv := runserver(t, &smtpd.Server{
				Logger:      slog.New(slog.NewTextHandler(&out, nil)),
				DataTimeout: 200 * time.Millisecond,
				Handler:     tc.handler,
			}, smtpd.Middleware{
				Disconnect: func(_ context.Context, _ smtpd.Peer, _ error) {
					close(disconnected)
				},
			})

			c := dialRaw(t, srv.Addr)
			c.send("EHLO client.example")
			c.send("MAIL FROM:<sender@example.org>")
			c.send("RCPT TO:<recipient@example.net>")
			if reply := c.send("DATA"); !strings.HasPrefix(reply, "354") {
				t.Fatalf("DATA reply = %q, want 354", reply)
			}
			c.write([]byte("Subject: one\r\n"))

			select {
			case <-disconnected:
			case <-time.After(5 * time.Second):
				t.Fatal("the session did not end after the timeout")
			}

			if strings.Contains(out.String(), "a hook failed with an error that is not an smtpd.Error") {
				t.Errorf("the log holds the timeout as an error of the handler:\n%s", out.String())
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
