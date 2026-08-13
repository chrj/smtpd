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

	f.Fuzz(func(t *testing.T, script string, options uint8) {
		srv := &Server{
			EnableXCLIENT:       options&1 != 0,
			EnableProxyProtocol: options&2 != 0,
			AllowInsecureAuth:   options&4 != 0,

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

		written := conn.out.String()
		for line := range strings.SplitSeq(strings.TrimSuffix(written, "\r\n"), "\r\n") {
			if line == "" {
				continue
			}
			if !replyLine.MatchString(line) {
				t.Fatalf("the server wrote %q, which is not a reply\nscript: %q\nwritten: %q", line, script, written)
			}
		}
	})
}
