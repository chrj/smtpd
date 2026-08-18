package smtpd_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/chrj/smtpd/v2"
)

// TestEnhancedStatusCodesAdvertised proves that the server offers the
// extension of RFC 2034 in the reply to EHLO. A client reads the status
// codes of the session only after it sees this keyword.
func TestEnhancedStatusCodesAdvertised(t *testing.T) {
	t.Parallel()

	srv := runserver(t, &smtpd.Server{Logger: testLogger(t)})
	c := dialRaw(t, srv.Addr)

	lines := c.replyLines("EHLO localhost")

	found := false
	for _, line := range lines {
		if strings.TrimSpace(line[4:]) == "ENHANCEDSTATUSCODES" {
			found = true
		}
	}
	if !found {
		t.Errorf("EHLO reply %q, want a line with ENHANCEDSTATUSCODES", lines)
	}
}

// TestEnhancedStatusCodeOnReply drives a session to one point and reads the
// full text of the last reply line, so that the code, the status code and
// the message are all part of the assertion.
func TestEnhancedStatusCodeOnReply(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		commands []string
		want     string
	}{
		{
			name:     "accepted sender",
			commands: []string{"EHLO localhost", "MAIL FROM:<sender@example.org>"},
			want:     "250 2.1.0 Go ahead",
		},
		{
			name: "accepted recipient",
			commands: []string{
				"EHLO localhost",
				"MAIL FROM:<sender@example.org>",
				"RCPT TO:<recipient@example.net>",
			},
			want: "250 2.1.5 Go ahead",
		},
		{
			name:     "reset transaction",
			commands: []string{"EHLO localhost", "RSET"},
			want:     "250 2.0.0 Go ahead",
		},
		{
			name:     "no operation",
			commands: []string{"EHLO localhost", "NOOP"},
			want:     "250 2.0.0 Go ahead",
		},
		{
			name:     "quit",
			commands: []string{"EHLO localhost", "QUIT"},
			want:     "221 2.0.0 OK, bye",
		},
		{
			name:     "unknown command",
			commands: []string{"EHLO localhost", "FROBNICATE"},
			want:     "500 5.5.1 Unsupported command.",
		},
		{
			name:     "recipient before sender",
			commands: []string{"EHLO localhost", "RCPT TO:<recipient@example.net>"},
			want:     "503 5.5.1 Missing MAIL FROM command.",
		},
		{
			name:     "second sender",
			commands: []string{"EHLO localhost", "MAIL FROM:<a@example.org>", "MAIL FROM:<b@example.org>"},
			want:     "503 5.5.1 Duplicate MAIL",
		},
		{
			name:     "malformed sender",
			commands: []string{"EHLO localhost", "MAIL FROM:<not an address>"},
			want:     "501 5.1.7 Malformed e-mail address",
		},
		{
			name: "malformed recipient",
			commands: []string{
				"EHLO localhost",
				"MAIL FROM:<sender@example.org>",
				"RCPT TO:<not an address>",
			},
			want: "501 5.1.3 Malformed e-mail address",
		},
		{
			name:     "data before recipient",
			commands: []string{"EHLO localhost", "MAIL FROM:<sender@example.org>", "DATA"},
			want:     "503 5.5.1 Missing RCPT TO command.",
		},
		{
			name:     "declared size over the limit",
			commands: []string{"EHLO localhost", "MAIL FROM:<sender@example.org> SIZE=99999999"},
			want:     "552 5.3.4 Message size exceeds fixed maximum of 10240000 bytes",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			srv := runserver(t, &smtpd.Server{Logger: testLogger(t)})
			c := dialRaw(t, srv.Addr)

			got := ""
			for _, command := range test.commands {
				got = c.send("%s", command)
			}

			if got != test.want {
				t.Errorf("got %q, want %q", got, test.want)
			}
		})
	}
}

// TestNoEnhancedStatusCodeAfterHELO proves that a client that sent HELO gets
// the replies of RFC 5321. RFC 2034 puts the status codes behind an
// extension, and a HELO client never saw the server offer it.
func TestNoEnhancedStatusCodeAfterHELO(t *testing.T) {
	t.Parallel()

	srv := runserver(t, &smtpd.Server{Logger: testLogger(t)})
	c := dialRaw(t, srv.Addr)

	if got, want := c.send("HELO localhost"), "250 Go ahead"; got != want {
		t.Errorf("HELO: got %q, want %q", got, want)
	}

	if got, want := c.send("MAIL FROM:<sender@example.org>"), "250 Go ahead"; got != want {
		t.Errorf("MAIL FROM: got %q, want %q", got, want)
	}

	if got, want := c.send("FROBNICATE"), "500 Unsupported command."; got != want {
		t.Errorf("unknown command: got %q, want %q", got, want)
	}
}

// TestGreetingCarriesNoEnhancedStatusCode proves that the banner stays as it
// was. RFC 2034 takes the greeting out of the extension, and the client has
// sent no command at that point.
func TestGreetingCarriesNoEnhancedStatusCode(t *testing.T) {
	t.Parallel()

	srv := runserver(t, &smtpd.Server{
		Hostname: "mx.example.com",
		Logger:   testLogger(t),
	})
	c := dialRaw(t, srv.Addr)

	if got, want := c.banner, "220 mx.example.com ESMTP ready."; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

// TestEHLOReplyCarriesNoEnhancedStatusCode proves that the reply to EHLO
// keeps only the hostname and the extension keywords. A status code on those
// lines makes the client read a keyword that the server does not have.
func TestEHLOReplyCarriesNoEnhancedStatusCode(t *testing.T) {
	t.Parallel()

	srv := runserver(t, &smtpd.Server{
		Hostname: "mx.example.com",
		Logger:   testLogger(t),
	})
	c := dialRaw(t, srv.Addr)

	lines := c.replyLines("EHLO localhost")

	want := []string{
		"250-mx.example.com",
		"250-SIZE 10240000",
		"250-8BITMIME",
		"250-PIPELINING",
		"250 ENHANCEDSTATUSCODES",
	}

	if len(lines) != len(want) {
		t.Fatalf("got %q, want %q", lines, want)
	}
	for i := range want {
		if lines[i] != want[i] {
			t.Errorf("line %d: got %q, want %q", i, lines[i], want[i])
		}
	}
}

// TestDataContinuationCarriesNoEnhancedStatusCode proves that the 354 reply
// stays as it was. RFC 3463 gives no status class for a 3yz reply, because
// the command is not finished.
func TestDataContinuationCarriesNoEnhancedStatusCode(t *testing.T) {
	t.Parallel()

	srv := runserver(t, &smtpd.Server{Logger: testLogger(t)})
	c := dialRaw(t, srv.Addr)

	c.send("EHLO localhost")
	c.send("MAIL FROM:<sender@example.org>")
	c.send("RCPT TO:<recipient@example.net>")

	got := c.send("DATA")
	want := "354 Go ahead. End your data with <CR><LF>.<CR><LF>"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

// TestMiddlewareErrorCarriesEnhancedStatusCode proves that a status code set
// on an smtpd.Error reaches the client.
func TestMiddlewareErrorCarriesEnhancedStatusCode(t *testing.T) {
	t.Parallel()

	deny := smtpd.Middleware{
		CheckRecipient: func(ctx context.Context, _ smtpd.Peer, _ string) (context.Context, error) {
			return ctx, smtpd.Error{
				Code:     550,
				Enhanced: smtpd.EnhancedCode{5, 7, 1},
				Message:  "Relay access denied",
			}
		},
	}

	srv := runserver(t, &smtpd.Server{Logger: testLogger(t)}, deny)
	c := dialRaw(t, srv.Addr)

	c.send("EHLO localhost")
	c.send("MAIL FROM:<sender@example.org>")

	got := c.send("RCPT TO:<recipient@example.net>")
	want := "550 5.7.1 Relay access denied"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

// TestMiddlewareErrorTakesDefaultEnhancedStatusCode proves that an error
// with no status code still gets a valid one, from the class of the reply
// code. RFC 3463 section 3.1 gives "x.0.0" for a reply with no more precise
// reason.
func TestMiddlewareErrorTakesDefaultEnhancedStatusCode(t *testing.T) {
	t.Parallel()

	srv := runserver(t, &smtpd.Server{Logger: testLogger(t)}, rejectSender())
	c := dialRaw(t, srv.Addr)

	c.send("EHLO localhost")

	got := c.send("MAIL FROM:<sender@example.org>")
	want := "552 5.0.0 Denied"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

// TestPlainErrorTakesEnhancedStatusCode proves that an error which is not an
// smtpd.Error also reaches the client with a status code. The server reports
// those as 502, which means that the command is not implemented.
func TestPlainErrorTakesEnhancedStatusCode(t *testing.T) {
	t.Parallel()

	srv := runserver(t, &smtpd.Server{Logger: testLogger(t)}, smtpd.Middleware{
		CheckSender: func(ctx context.Context, _ smtpd.Peer, _ string) (context.Context, error) {
			return ctx, errors.New("Denied")
		},
	})
	c := dialRaw(t, srv.Addr)

	c.send("EHLO localhost")

	got := c.send("MAIL FROM:<sender@example.org>")
	want := "502 5.5.1 Denied"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

// TestEnhancedCodeString proves the text form of the status code, and that
// the zero value produces no text.
func TestEnhancedCodeString(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		code smtpd.EnhancedCode
		want string
	}{
		{"success", smtpd.EnhancedCode{2, 1, 5}, "2.1.5"},
		{"temporary fault", smtpd.EnhancedCode{4, 7, 1}, "4.7.1"},
		{"permanent fault", smtpd.EnhancedCode{5, 7, 1}, "5.7.1"},
		{"two-digit detail", smtpd.EnhancedCode{5, 7, 23}, "5.7.23"},
		{"zero value", smtpd.EnhancedCode{}, ""},
		{"class that RFC 3463 does not define", smtpd.EnhancedCode{3, 0, 0}, ""},
		{"negative part", smtpd.EnhancedCode{5, -1, 0}, ""},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			if got := test.code.String(); got != test.want {
				t.Errorf("got %q, want %q", got, test.want)
			}
		})
	}
}

// TestErrorString proves that the text of an smtpd.Error names the status
// code that the caller set, and leaves out one that the caller did not set.
func TestErrorString(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		err  smtpd.Error
		want string
	}{
		{
			name: "with a status code",
			err: smtpd.Error{
				Code:     550,
				Enhanced: smtpd.EnhancedCode{5, 7, 1},
				Message:  "Relay access denied",
			},
			want: "550 5.7.1 Relay access denied",
		},
		{
			name: "without a status code",
			err:  smtpd.Error{Code: 550, Message: "Relay access denied"},
			want: "550 Relay access denied",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			if got := test.err.Error(); got != test.want {
				t.Errorf("got %q, want %q", got, test.want)
			}
		})
	}
}
