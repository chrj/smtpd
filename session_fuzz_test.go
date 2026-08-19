package smtpd

import (
	"bytes"
	"context"
	"io"
	"net"
	"regexp"
	"strings"
	"testing"
	"time"
)

// scriptConn is a net.Conn that reads a session written in advance and keeps
// what the server writes. The deadlines do nothing, so a fuzz target runs at
// the speed of memory.
type scriptConn struct {
	in  *bytes.Reader
	out bytes.Buffer
}

func (c *scriptConn) Read(p []byte) (int, error)  { return c.in.Read(p) }
func (c *scriptConn) Write(p []byte) (int, error) { return c.out.Write(p) }
func (c *scriptConn) Close() error                { return nil }

func (c *scriptConn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 25}
}

func (c *scriptConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 12345}
}

func (c *scriptConn) SetDeadline(time.Time) error      { return nil }
func (c *scriptConn) SetReadDeadline(time.Time) error  { return nil }
func (c *scriptConn) SetWriteDeadline(time.Time) error { return nil }

var _ net.Conn = (*scriptConn)(nil)

// replyLine is the shape of every line that an SMTP server writes. It carries
// three digits, then a space for the last line of a reply, or a hyphen for a
// line that continues. A line without that shape means the server let
// something from the client into a reply.
var replyLine = regexp.MustCompile(`^[2-5][0-9][0-9][ -]`)

// FuzzSession runs a whole session against a script of bytes. It holds three
// properties:
//
//   - The session never panics.
//   - The session always ends.
//   - Every line that the server writes is a reply.
//
// The last property catches a reply that a client splits in two. A client
// does that with a line break in a value that reaches a message.
//
// STARTTLS is outside the target. The server has no certificate here, so it
// answers 502 and stays in plain text.
func FuzzSession(f *testing.F) {
	f.Add("EHLO relay.example.org\r\nMAIL FROM:<a@example.org>\r\nRCPT TO:<b@example.net>\r\nDATA\r\nhello\r\n.\r\nQUIT\r\n", uint8(0))
	f.Add("HELO relay.example.org\r\nMAIL FROM:<>\r\nRCPT TO:<b@example.net>\r\nDATA\r\n.\r\nQUIT\r\n", uint8(0))
	f.Add("XCLIENT ADDR=192.0.2.2 PORT=2525 LOGIN=user\r\nEHLO x\r\nQUIT\r\n", uint8(1))
	f.Add("PROXY TCP4 192.0.2.2 192.0.2.1 2525 25\r\nEHLO x\r\nQUIT\r\n", uint8(2))
	f.Add("EHLO x\r\nAUTH PLAIN AGZvbwBiYXI=\r\nQUIT\r\n", uint8(4))
	f.Add("EHLO x\r\nAUTH LOGIN\r\ndXNlcg==\r\ncGFzcw==\r\nQUIT\r\n", uint8(4))
	f.Add("MAIL FROM:<\r\nRCPT TO:>>>\r\nDATA\r\n", uint8(7))
	f.Add("MAIL FROM:<\" \"@0> SIZE=1 SIZE=2\r\n", uint8(7))
	f.Add("EHLO x\r\nMAIL FROM:<a@example.org> RET=HDRS ENVID=QQ+40314159\r\nRCPT TO:<b@example.net> NOTIFY=SUCCESS,DELAY ORCPT=rfc822;b+40example.net\r\nDATA\r\n.\r\nQUIT\r\n", uint8(8))
	f.Add("EHLO x\r\nMAIL FROM:<a@example.org> ENVID=a+0D+0A\r\nRCPT TO:<b@example.net> NOTIFY=NEVER,SUCCESS\r\n", uint8(8))

	f.Fuzz(func(t *testing.T, script string, options uint8) {
		srv := &Server{
			EnableXCLIENT:       options&1 != 0,
			EnableProxyProtocol: options&2 != 0,
			AllowInsecureAuth:   options&4 != 0,
			EnableDSN:           options&8 != 0,

			// Small enough that a short script reaches the limit and the
			// drain that follows it.
			MaxMessageSize: 4096,
			MaxRecipients:  4,

			Handler: func(ctx context.Context, _ Peer, env *Envelope) (context.Context, error) {
				_, _ = io.Copy(io.Discard, env.Data)
				return ctx, nil
			},
		}

		srv.Use(Middleware{
			Authenticate: func(ctx context.Context, _ Peer, _, _ string) (context.Context, error) {
				return ctx, nil
			},
		})

		if err := srv.configureDefaults(); err != nil {
			t.Fatalf("configureDefaults: %v", err)
		}

		conn := &scriptConn{in: bytes.NewReader([]byte(script))}
		ctx, session := srv.newSession(context.Background(), conn)

		done := make(chan struct{})
		go func() {
			defer close(done)
			session.serve(ctx)
		}()

		select {
		case <-done:
		case <-time.After(30 * time.Second):
			t.Fatalf("the session did not end for the script %q", script)
		}

		replyLines(t, conn.out.String())
	})
}

// runScript drives one session over script and returns the session and every
// byte that the server wrote. It fails the test if the session does not end,
// which is how a target reports a loop that never leaves.
func runScript(t *testing.T, srv *Server, script string) (*session, string) {
	t.Helper()

	if err := srv.configureDefaults(); err != nil {
		t.Fatalf("configureDefaults: %v", err)
	}

	conn := &scriptConn{in: bytes.NewReader([]byte(script))}
	ctx, session := srv.newSession(context.Background(), conn)

	done := make(chan struct{})
	go func() {
		defer close(done)
		session.serve(ctx)
	}()

	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatalf("the session did not end for the script %q", script)
	}

	return session, conn.out.String()
}

// replyLines cuts what the server wrote into lines and holds the shape of
// each one. A line that carries a control character means that the server let
// something from the client past the end of a reply.
func replyLines(t *testing.T, written string) []string {
	t.Helper()

	var lines []string
	for line := range strings.SplitSeq(strings.TrimSuffix(written, "\r\n"), "\r\n") {
		if line == "" {
			continue
		}
		if !replyLine.MatchString(line) {
			t.Fatalf("the server wrote %q, which is not a reply\nwritten: %q", line, written)
		}
		if strings.ContainsAny(line, "\r\n") {
			t.Fatalf("the server wrote %q, which carries a line break\nwritten: %q", line, written)
		}
		lines = append(lines, line)
	}
	return lines
}

// FuzzReplyText puts the message of a middleware refusal on the wire. It
// holds one property: the message stays inside its reply.
//
// A middleware writes what it knows into the message, and some of that comes
// from the client. The user name of an AUTH command is one example: the
// session decodes it from base64, so it carries any byte at all. A message
// with a line break in it would end the reply and start a line of the
// client's choosing, which the client uses to answer a command that the
// server never ran.
//
// The script uses HELO, so the count of the lines does not move with the list
// of extensions that EHLO reports.
func FuzzReplyText(f *testing.F) {
	f.Add("Denied")
	f.Add("no such user\r\n250 injected")
	f.Add("no such user\n250 injected")
	f.Add("no such user\rmore")
	f.Add("")
	f.Add("\x00\x07denied")
	f.Add(strings.Repeat("x", 600))

	f.Fuzz(func(t *testing.T, message string) {
		srv := &Server{}
		srv.Use(Middleware{
			CheckSender: func(ctx context.Context, _ Peer, _ string) (context.Context, error) {
				return ctx, Error{Code: 550, Message: message}
			},
		})

		_, written := runScript(t, srv,
			"HELO relay.example.org\r\nMAIL FROM:<a@example.org>\r\nQUIT\r\n")

		// The greeting, the reply to HELO, the refusal of MAIL FROM and the
		// reply to QUIT. One line each.
		if got := replyLines(t, written); len(got) != 4 {
			t.Fatalf("the server wrote %d lines for the message %q, want 4\nwritten: %q",
				len(got), message, written)
		}
	})
}

// FuzzXCLIENT runs the XCLIENT command of Postfix over a fuzzed argument. It
// holds two properties:
//
//   - The address of the peer stays a TCP address.
//   - Every line that the server writes is a reply.
//
// The first property is what handleXCLIENT and handlePROXY both read. A peer
// with an address of another type, or with none, makes the next command that
// reads it fail.
func FuzzXCLIENT(f *testing.F) {
	f.Add("ADDR=192.0.2.2 PORT=2525 LOGIN=user PROTO=ESMTP")
	f.Add("ADDR=[UNAVAILABLE] PORT=[TEMPUNAVAIL]")
	f.Add("HELO=+2Brelay.example.org NAME=proxy.example.net")
	f.Add("LOGIN=user+0D+0A250+20injected")
	f.Add("ADDR=2001:db8::1 PORT=65535")
	f.Add("PORT=99999999")
	f.Add("ADDR=")
	f.Add("=")
	f.Add("")

	f.Fuzz(func(t *testing.T, arg string) {
		srv := &Server{EnableXCLIENT: true}

		session, written := runScript(t, srv,
			"XCLIENT "+arg+"\r\nEHLO relay.example.org\r\nQUIT\r\n")

		if session.peer.Addr == nil {
			t.Fatalf("the peer lost its address for the argument %q", arg)
		}
		if _, ok := session.peer.Addr.(*net.TCPAddr); !ok {
			t.Fatalf("the peer holds a %T for the argument %q, want a *net.TCPAddr", session.peer.Addr, arg)
		}

		replyLines(t, written)
	})
}

// FuzzAuthExchange runs the AUTH command over a fuzzed argument, and answers
// every continuation with a fuzzed line. It holds one property: the server
// reports success only after it asked the authenticator.
//
// A 235 reply without that call is an authentication bypass. The two
// mechanisms read a different number of lines, and both of them decode base64
// from the client, so the paths that reach the reply are many.
func FuzzAuthExchange(f *testing.F) {
	f.Add("PLAIN AGZvbwBiYXI=", "")
	f.Add("PLAIN", "AGZvbwBiYXI=")
	f.Add("LOGIN", "dXNlcg==")
	f.Add("LOGIN dXNlcg==", "cGFzcw==")
	f.Add("PLAIN =", "")
	f.Add("PLAIN *", "*")
	f.Add("CRAM-MD5", "")
	f.Add("", "")

	f.Fuzz(func(t *testing.T, arg, response string) {
		calls := 0

		srv := &Server{AllowInsecureAuth: true}
		srv.Use(Middleware{
			Authenticate: func(ctx context.Context, _ Peer, _, _ string) (context.Context, error) {
				calls++
				return ctx, nil
			},
		})

		// Two responses, because AUTH LOGIN asks twice.
		_, written := runScript(t, srv,
			"EHLO relay.example.org\r\nAUTH "+arg+"\r\n"+response+"\r\n"+response+"\r\nQUIT\r\n")

		lines := replyLines(t, written)

		for _, line := range lines {
			if strings.HasPrefix(line, "235 ") && calls == 0 {
				t.Fatalf("the server wrote %q without asking the authenticator\nwritten: %q", line, written)
			}
		}
	})
}
