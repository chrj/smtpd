package smtpd_test

import (
	"context"
	"testing"

	"github.com/chrj/smtpd/v2"
)

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
