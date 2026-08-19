package smtpd_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/chrj/smtpd/v2"
)

// bdat writes one BDAT command with its chunk in a single write, in the way
// that a client sends them, and returns the reply.
//
// The chunk follows the command line on the same stream with nothing between
// them, so this is also the test that the server reads its command lines
// without taking the octets of the chunk with them.
func bdat(t *testing.T, c *rawClient, payload string, last bool) string {
	t.Helper()

	command := fmt.Sprintf("BDAT %d", len(payload))
	if last {
		command += " LAST"
	}

	c.write([]byte(command + "\r\n" + payload))
	return c.line()
}

// openTransaction greets the server and sends MAIL FROM and RCPT TO, so that
// the next command is a BDAT that the server takes.
func openTransaction(t *testing.T, c *rawClient, mail string) {
	t.Helper()

	if reply := c.send("EHLO localhost"); !strings.HasPrefix(reply, "250") {
		t.Fatalf("EHLO reply = %q, want 250", reply)
	}
	if reply := c.send("%s", mail); !strings.HasPrefix(reply, "250") {
		t.Fatalf("MAIL reply = %q, want 250", reply)
	}
	if reply := c.send("RCPT TO:<recipient@example.net>"); !strings.HasPrefix(reply, "250") {
		t.Fatalf("RCPT reply = %q, want 250", reply)
	}
}

// TestChunkingOffered covers the EHLO keywords of RFC 3030.
func TestChunkingOffered(t *testing.T) {
	t.Parallel()

	srv := runserver(t, &smtpd.Server{Logger: testLogger(t)})

	c := srv.Dial()
	if err := c.Hello("localhost"); err != nil {
		t.Fatalf("EHLO failed: %v", err)
	}

	for _, keyword := range []string{"CHUNKING", "BINARYMIME"} {
		if ok, _ := c.Extension(keyword); !ok {
			t.Errorf("the server does not offer %s", keyword)
		}
	}

	if err := c.Quit(); err != nil {
		t.Errorf("QUIT failed: %v", err)
	}
}

// TestBDATDelivers drives whole messages through BDAT and reads them back off
// the envelope.
func TestBDATDelivers(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mail   string
		chunks []string
		want   message
	}{
		{
			name:   "one chunk",
			mail:   "MAIL FROM:<sender@example.org>",
			chunks: []string{"Subject: one\r\n\r\nA short body.\r\n"},
			want:   message{body: "Subject: one\r\n\r\nA short body.\r\n"},
		},
		{
			name:   "three chunks in order",
			mail:   "MAIL FROM:<sender@example.org>",
			chunks: []string{"Subject: three\r\n", "\r\nfirst half ", "second half\r\n"},
			want:   message{body: "Subject: three\r\n\r\nfirst half second half\r\n"},
		},
		{
			name:   "an empty last chunk ends the message",
			mail:   "MAIL FROM:<sender@example.org>",
			chunks: []string{"Subject: empty end\r\n\r\nbody\r\n", ""},
			want:   message{body: "Subject: empty end\r\n\r\nbody\r\n"},
		},
		{
			name:   "an empty message",
			mail:   "MAIL FROM:<sender@example.org>",
			chunks: []string{""},
			want:   message{body: ""},
		},
		{
			// A dot on a line of its own ends a DATA message. BDAT counts
			// octets, so the body carries it like any other content.
			name:   "a line with one dot on it",
			mail:   "MAIL FROM:<sender@example.org>",
			chunks: []string{"Subject: dot\r\n\r\n.\r\nstill the body\r\n"},
			want:   message{body: "Subject: dot\r\n\r\n.\r\nstill the body\r\n"},
		},
		{
			name:   "octets that carry no line structure",
			mail:   "MAIL FROM:<sender@example.org> BODY=BINARYMIME",
			chunks: []string{"\x00\x01\x02\r\n\xff\xfe no line break at the end"},
			want: message{
				bodyType: smtpd.BodyBinaryMIME,
				body:     "\x00\x01\x02\r\n\xff\xfe no line break at the end",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			got := make(chan message, 1)
			srv := runserver(t, &smtpd.Server{
				Logger:  testLogger(t),
				Handler: captureMessage(got),
			})

			c := dialRaw(t, srv.Addr)
			openTransaction(t, c, test.mail)

			for i, chunk := range test.chunks {
				last := i == len(test.chunks)-1

				reply := bdat(t, c, chunk, last)
				if !strings.HasPrefix(reply, "250") {
					t.Fatalf("chunk %d: reply = %q, want 250", i, reply)
				}
			}

			msg := <-got
			if msg.readErr != nil {
				t.Fatalf("the handler read the body with the error %v", msg.readErr)
			}
			if msg.body != test.want.body {
				t.Errorf("body = %q, want %q", msg.body, test.want.body)
			}
			if msg.bodyType != test.want.bodyType {
				t.Errorf("body type = %q, want %q", msg.bodyType, test.want.bodyType)
			}
			if msg.sender != "sender@example.org" {
				t.Errorf("sender = %q, want %q", msg.sender, "sender@example.org")
			}

			// The transaction is over, so the next one starts from MAIL FROM.
			if reply := c.send("MAIL FROM:<second@example.org>"); !strings.HasPrefix(reply, "250") {
				t.Errorf("MAIL FROM after the message = %q, want 250", reply)
			}
		})
	}
}

// TestBDATKeepsTheStreamInSync covers the rule of RFC 3030 that a server which
// refuses a chunk still takes its octets off the wire. A chunk that stays
// there is read as commands.
func TestBDATKeepsTheStreamInSync(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		// setup runs before the chunk that the server refuses.
		setup   func(t *testing.T, c *rawClient)
		payload string
		want    string
	}{
		{
			name:    "before MAIL FROM",
			setup:   func(t *testing.T, c *rawClient) { c.send("EHLO localhost") },
			payload: "NOOP\r\nNOOP\r\n",
			want:    "503",
		},
		{
			name: "before RCPT TO",
			setup: func(t *testing.T, c *rawClient) {
				c.send("EHLO localhost")
				c.send("MAIL FROM:<sender@example.org>")
			},
			payload: "RSET\r\n",
			want:    "503",
		},
		{
			name: "a message that is too large",
			setup: func(t *testing.T, c *rawClient) {
				openTransaction(t, c, "MAIL FROM:<sender@example.org>")
			},
			payload: strings.Repeat("x", 2048),
			want:    "552",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			srv := runserver(t, &smtpd.Server{
				Logger:         testLogger(t),
				MaxMessageSize: 1024,
			})

			c := dialRaw(t, srv.Addr)
			test.setup(t, c)

			if reply := bdat(t, c, test.payload, false); !strings.HasPrefix(reply, test.want) {
				t.Fatalf("reply = %q, want %s", reply, test.want)
			}

			// The octets of the chunk are gone from the stream, so the
			// server reads the next line as a command.
			if reply := c.send("NOOP"); !strings.HasPrefix(reply, "250") {
				t.Errorf("NOOP after the refusal = %q, want 250", reply)
			}
		})
	}
}

// TestBDATRefusesEveryChunkAfterAFailure covers the rule of RFC 3030 that the
// chunks a client already sent through a pipeline get an answer of their own.
// RSET starts a transaction that works again.
func TestBDATRefusesEveryChunkAfterAFailure(t *testing.T) {
	t.Parallel()

	got := make(chan message, 1)
	srv := runserver(t, &smtpd.Server{
		Logger:         testLogger(t),
		MaxMessageSize: 32,
		Handler:        captureMessage(got),
	})

	c := dialRaw(t, srv.Addr)
	openTransaction(t, c, "MAIL FROM:<sender@example.org>")

	if reply := bdat(t, c, strings.Repeat("x", 64), false); !strings.HasPrefix(reply, "552") {
		t.Fatalf("the chunk that is too large = %q, want 552", reply)
	}

	// A chunk that would fit on its own still gets the answer of the
	// transaction that failed.
	if reply := bdat(t, c, "small", true); !strings.HasPrefix(reply, "552") {
		t.Errorf("the chunk after the failure = %q, want 552", reply)
	}

	if reply := c.send("RSET"); !strings.HasPrefix(reply, "250") {
		t.Fatalf("RSET = %q, want 250", reply)
	}

	openTransaction(t, c, "MAIL FROM:<sender@example.org>")
	if reply := bdat(t, c, "short body", true); !strings.HasPrefix(reply, "250") {
		t.Fatalf("the message after RSET = %q, want 250", reply)
	}

	if msg := <-got; msg.body != "short body" {
		t.Errorf("body = %q, want %q", msg.body, "short body")
	}
}

// TestBDATAndDATADoNotMix covers the commands that RFC 3030 keeps apart.
func TestBDATAndDATADoNotMix(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		mail string
		bdat bool
		want string
	}{
		{
			name: "DATA after BDAT",
			mail: "MAIL FROM:<sender@example.org>",
			bdat: true,
			want: "503",
		},
		{
			name: "DATA for a BINARYMIME message",
			mail: "MAIL FROM:<sender@example.org> BODY=BINARYMIME",
			want: "503",
		},
		{
			name: "DATA for a message of text",
			mail: "MAIL FROM:<sender@example.org> BODY=8BITMIME",
			want: "354",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			srv := runserver(t, &smtpd.Server{Logger: testLogger(t)})

			c := dialRaw(t, srv.Addr)
			openTransaction(t, c, test.mail)

			if test.bdat {
				if reply := bdat(t, c, "part of a message\r\n", false); !strings.HasPrefix(reply, "250") {
					t.Fatalf("BDAT = %q, want 250", reply)
				}
			}

			if reply := c.send("DATA"); !strings.HasPrefix(reply, test.want) {
				t.Errorf("DATA = %q, want %s", reply, test.want)
			}
		})
	}
}

// TestBDATStopsTheHandlerOnRSET covers a transfer that ends before the last
// chunk. The handler must read an error in the place of the rest of the
// message, so that half a message never looks whole to it.
func TestBDATStopsTheHandlerOnRSET(t *testing.T) {
	t.Parallel()

	got := make(chan message, 1)
	srv := runserver(t, &smtpd.Server{
		Logger:  testLogger(t),
		Handler: captureMessage(got),
	})

	c := dialRaw(t, srv.Addr)
	openTransaction(t, c, "MAIL FROM:<sender@example.org>")

	if reply := bdat(t, c, "Subject: half a message\r\n", false); !strings.HasPrefix(reply, "250") {
		t.Fatalf("BDAT = %q, want 250", reply)
	}

	if reply := c.send("RSET"); !strings.HasPrefix(reply, "250") {
		t.Fatalf("RSET = %q, want 250", reply)
	}

	msg := <-got
	if msg.readErr == nil {
		t.Fatalf("the handler read the body without an error, and it got %q", msg.body)
	}

	// The session carries on.
	openTransaction(t, c, "MAIL FROM:<second@example.org>")
	if reply := bdat(t, c, "a whole message", true); !strings.HasPrefix(reply, "250") {
		t.Errorf("the message after RSET = %q, want 250", reply)
	}
}

// TestBDATReportsTheHandlerError covers a handler that refuses the message.
// The client hears about it at the last chunk.
func TestBDATReportsTheHandlerError(t *testing.T) {
	t.Parallel()

	srv := runserver(t, &smtpd.Server{
		Logger: testLogger(t),
		Handler: func(ctx context.Context, _ smtpd.Peer, env *smtpd.Envelope) (context.Context, error) {
			_ = env.Data.Close()
			return ctx, smtpd.Error{Code: 554, Enhanced: smtpd.EnhancedCode{5, 7, 1}, Message: "Not today"}
		},
	})

	c := dialRaw(t, srv.Addr)
	openTransaction(t, c, "MAIL FROM:<sender@example.org>")

	if reply := bdat(t, c, "a whole message", true); reply != "554 5.7.1 Not today" {
		t.Errorf("BDAT LAST = %q, want %q", reply, "554 5.7.1 Not today")
	}

	// The transaction is over, so the next one starts from MAIL FROM.
	if reply := c.send("MAIL FROM:<second@example.org>"); !strings.HasPrefix(reply, "250") {
		t.Errorf("MAIL FROM after the refusal = %q, want 250", reply)
	}
}

// TestBDATSyntaxErrorEndsTheSession covers a command whose chunk size cannot
// be read. Nothing says where the chunk ends, so the session cannot go on.
func TestBDATSyntaxErrorEndsTheSession(t *testing.T) {
	t.Parallel()

	srv := runserver(t, &smtpd.Server{Logger: testLogger(t)})

	c := dialRaw(t, srv.Addr)
	openTransaction(t, c, "MAIL FROM:<sender@example.org>")

	if reply := c.send("BDAT plenty"); !strings.HasPrefix(reply, "501") {
		t.Fatalf("BDAT with a bad size = %q, want 501", reply)
	}

	if _, err := c.conn.Write([]byte("NOOP\r\n")); err == nil {
		if _, err := c.br.ReadString('\n'); err == nil {
			t.Error("the session stayed open after a BDAT that could not be read")
		}
	}
}

// TestRCPTAfterBDAT covers a recipient that arrives after the message started.
// The handler reads the envelope while the chunks arrive, so the list of
// recipients is closed by then.
func TestRCPTAfterBDAT(t *testing.T) {
	t.Parallel()

	srv := runserver(t, &smtpd.Server{Logger: testLogger(t)})

	c := dialRaw(t, srv.Addr)
	openTransaction(t, c, "MAIL FROM:<sender@example.org>")

	if reply := bdat(t, c, "part of a message\r\n", false); !strings.HasPrefix(reply, "250") {
		t.Fatalf("BDAT = %q, want 250", reply)
	}

	if reply := c.send("RCPT TO:<late@example.net>"); !strings.HasPrefix(reply, "503") {
		t.Errorf("RCPT TO after BDAT = %q, want 503", reply)
	}
}

// TestBDATHandlerPanicClosesTheSession covers a handler that panics while a
// chunked message arrives. The handler runs on a goroutine of its own, so its
// panic reaches the session as a value and not through recover. The client
// must see the same 421 as for a panic in a DATA handler, and the Disconnect
// hooks must read the PanicError.
func TestBDATHandlerPanicClosesTheSession(t *testing.T) {
	t.Parallel()

	var rec disconnectRecord
	boom := panicOnce("boom in a chunk")

	srv := runserver(t, &smtpd.Server{
		Logger: testLogger(t),
		Handler: func(ctx context.Context, _ smtpd.Peer, env *smtpd.Envelope) (context.Context, error) {
			_, _ = io.ReadAll(env.Data)
			boom()
			return ctx, nil
		},
	}, disconnectCounter(&rec))

	c := dialRaw(t, srv.Addr)
	openTransaction(t, c, "MAIL FROM:<sender@example.org>")

	if reply := bdat(t, c, "a whole message", true); !strings.HasPrefix(reply, "421") {
		t.Fatalf("BDAT LAST = %q, want 421", reply)
	}

	count, lastErr := waitDisconnect(&rec, time.Second)
	if count != 1 {
		t.Fatalf("Disconnect ran %d times, want 1", count)
	}

	var panicErr smtpd.PanicError
	if !errors.As(lastErr, &panicErr) {
		t.Fatalf("the Disconnect hook read %v, want a smtpd.PanicError", lastErr)
	}
	if panicErr.Value != "boom in a chunk" {
		t.Errorf("the panic value is %v, want %q", panicErr.Value, "boom in a chunk")
	}

	// The stack must reach the frame that panicked, and not only the frame
	// that recovered, or it gives an operator nothing to debug with.
	if !strings.Contains(string(panicErr.Stack), "TestBDATHandlerPanicClosesTheSession") {
		t.Errorf("the stack does not reach the handler that panicked:\n%s", panicErr.Stack)
	}
}

// TestBDATLeavesNoGoroutine covers the goroutine that runs the handler of a
// chunked message. A session that ends in the middle of a transfer must not
// leave it behind.
func TestBDATLeavesNoGoroutine(t *testing.T) {
	t.Parallel()

	// The handler blocks on a body that never ends, which is the goroutine
	// that a session must stop before it goes away.
	srv := runserver(t, &smtpd.Server{
		Logger: testLogger(t),
		Handler: func(ctx context.Context, _ smtpd.Peer, env *smtpd.Envelope) (context.Context, error) {
			_, _ = io.ReadAll(env.Data)
			return ctx, nil
		},
	})

	before := runtime.NumGoroutine()

	for range 20 {
		c := dialRaw(t, srv.Addr)
		openTransaction(t, c, "MAIL FROM:<sender@example.org>")

		if reply := bdat(t, c, "half of a message\r\n", false); !strings.HasPrefix(reply, "250") {
			t.Fatalf("BDAT = %q, want 250", reply)
		}

		// The client goes away in the middle of the message.
		_ = c.conn.Close()
	}

	// The sessions end on their own, so give them a moment to.
	deadline := time.Now().Add(2 * time.Second)
	for runtime.NumGoroutine() > before+5 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}

	if after := runtime.NumGoroutine(); after > before+5 {
		t.Errorf("the server holds %d goroutines, and it held %d before the 20 sessions", after, before)
	}
}

// TestBDATSyntaxErrorKeepsTheSession covers a BDAT command whose length reads
// but whose rest does not. The server can still take the chunk off the wire,
// so the session goes on.
func TestBDATSyntaxErrorKeepsTheSession(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		command string
	}{
		{name: "a mark of another kind", command: "BDAT 5 FIRST"},
		{name: "three arguments", command: "BDAT 5 LAST LAST"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			srv := runserver(t, &smtpd.Server{Logger: testLogger(t)})

			c := dialRaw(t, srv.Addr)
			openTransaction(t, c, "MAIL FROM:<sender@example.org>")

			c.write([]byte(test.command + "\r\nhello"))
			if reply := c.line(); !strings.HasPrefix(reply, "501") {
				t.Fatalf("%s = %q, want 501", test.command, reply)
			}

			// The five octets of the chunk are gone from the stream, so the
			// server reads the next line as a command.
			if reply := c.send("NOOP"); !strings.HasPrefix(reply, "250") {
				t.Errorf("NOOP after the refusal = %q, want 250", reply)
			}
		})
	}
}

// TestBDATPanicReachesTheHookAfterRSET covers a handler that panics while the
// session reads the next command. RSET drops the transfer, and the panic must
// not go with it: it ends the session and reaches the Disconnect hooks.
func TestBDATPanicReachesTheHookAfterRSET(t *testing.T) {
	t.Parallel()

	var rec disconnectRecord

	// release holds the handler until the client has the reply to its chunk,
	// so the panic lands on the command that follows and not on the chunk.
	release := make(chan struct{})
	boom := panicOnce("boom after the chunk")

	srv := runserver(t, &smtpd.Server{
		Logger: testLogger(t),
		Handler: func(ctx context.Context, _ smtpd.Peer, env *smtpd.Envelope) (context.Context, error) {
			buf := make([]byte, 4)
			if _, err := io.ReadFull(env.Data, buf); err != nil {
				return ctx, err
			}

			<-release
			boom()

			return ctx, nil
		},
	}, disconnectCounter(&rec))

	c := dialRaw(t, srv.Addr)
	openTransaction(t, c, "MAIL FROM:<sender@example.org>")

	if reply := bdat(t, c, "half", false); !strings.HasPrefix(reply, "250") {
		t.Fatalf("BDAT = %q, want 250", reply)
	}

	close(release)

	// The panic answers the command that follows, whichever one it is.
	if reply := c.send("RSET"); !strings.HasPrefix(reply, "421") {
		t.Fatalf("RSET = %q, want 421", reply)
	}

	count, lastErr := waitDisconnect(&rec, 2*time.Second)
	if count != 1 {
		t.Fatalf("Disconnect ran %d times, want 1", count)
	}

	var panicErr smtpd.PanicError
	if !errors.As(lastErr, &panicErr) {
		t.Fatalf("the Disconnect hook read %v, want a smtpd.PanicError", lastErr)
	}
	if panicErr.Value != "boom after the chunk" {
		t.Errorf("the panic value is %v, want %q", panicErr.Value, "boom after the chunk")
	}
}

// TestBDATRefusedFirstChunkClosesTheTransaction covers a transaction whose
// first chunk the server refused. The transaction saw a BDAT command, so it
// takes no recipient and no DATA after that.
func TestBDATRefusedFirstChunkClosesTheTransaction(t *testing.T) {
	t.Parallel()

	srv := runserver(t, &smtpd.Server{
		Logger:         testLogger(t),
		MaxMessageSize: 32,
	})

	c := dialRaw(t, srv.Addr)
	openTransaction(t, c, "MAIL FROM:<sender@example.org>")

	if reply := bdat(t, c, strings.Repeat("x", 64), false); !strings.HasPrefix(reply, "552") {
		t.Fatalf("the chunk that is too large = %q, want 552", reply)
	}

	if reply := c.send("RCPT TO:<late@example.net>"); !strings.HasPrefix(reply, "503") {
		t.Errorf("RCPT TO after the refused chunk = %q, want 503", reply)
	}

	if reply := c.send("DATA"); !strings.HasPrefix(reply, "503") {
		t.Errorf("DATA after the refused chunk = %q, want 503", reply)
	}
}

// TestBDATPanicSkipsTheResetHook covers the order of the hooks when a handler
// panics on its way out of a transfer that RSET ended. The Disconnect hooks
// run last, so a Reset hook must not run after them.
//
// The handler waits for the end of the body, which is what RSET gives it, and
// panics there. The session is inside its own reset at that moment, which is
// the order that this test holds.
func TestBDATPanicSkipsTheResetHook(t *testing.T) {
	t.Parallel()

	var resets resetRecord
	var rec disconnectRecord

	boom := panicOnce("boom on the way out")

	srv := runserver(t, &smtpd.Server{
		Logger: testLogger(t),
		Handler: func(ctx context.Context, _ smtpd.Peer, env *smtpd.Envelope) (context.Context, error) {
			if _, err := io.ReadAll(env.Data); err != nil {
				boom()
			}
			return ctx, nil
		},
	}, resetCounter(&resets), disconnectCounter(&rec))

	c := dialRaw(t, srv.Addr)
	openTransaction(t, c, "MAIL FROM:<sender@example.org>")

	if reply := bdat(t, c, "half", false); !strings.HasPrefix(reply, "250") {
		t.Fatalf("BDAT = %q, want 250", reply)
	}

	if reply := c.send("RSET"); !strings.HasPrefix(reply, "421") {
		t.Fatalf("RSET = %q, want 421", reply)
	}

	if count, _ := waitDisconnect(&rec, 2*time.Second); count != 1 {
		t.Fatalf("Disconnect ran %d times, want 1", count)
	}

	if got := resets.Count(); got != 0 {
		t.Errorf("the Reset hook ran %d times after the panic, want 0", got)
	}
}

// TestBDATHandlerContextReachesLaterCommands covers the contract of Handler:
// the context that it gives back holds for the commands that follow. A
// handler of a chunked message can end before the last chunk, and the
// commands after it must run in its context.
func TestBDATHandlerContextReachesLaterCommands(t *testing.T) {
	t.Parallel()

	type ctxKey struct{}

	finished := make(chan struct{})
	seen := make(chan bool, 1)

	srv := runserver(t, &smtpd.Server{
		Logger: testLogger(t),
		Handler: func(ctx context.Context, _ smtpd.Peer, env *smtpd.Envelope) (context.Context, error) {
			// End before the last chunk, with a context of its own.
			buf := make([]byte, 4)
			if _, err := io.ReadFull(env.Data, buf); err != nil {
				return ctx, err
			}

			defer close(finished)
			return context.WithValue(ctx, ctxKey{}, "from the handler"), nil
		},
	}, smtpd.Middleware{
		Reset: func(ctx context.Context, _ smtpd.Peer) context.Context {
			seen <- ctx.Value(ctxKey{}) == "from the handler"
			return ctx
		},
	})

	c := dialRaw(t, srv.Addr)
	openTransaction(t, c, "MAIL FROM:<sender@example.org>")

	if reply := bdat(t, c, "half", false); !strings.HasPrefix(reply, "250") {
		t.Fatalf("BDAT = %q, want 250", reply)
	}

	<-finished

	if reply := c.send("RSET"); !strings.HasPrefix(reply, "250") {
		t.Fatalf("RSET = %q, want 250", reply)
	}

	if !<-seen {
		t.Error("the Reset hook ran without the context of the handler")
	}
}
