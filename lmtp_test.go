package smtpd_test

import (
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
