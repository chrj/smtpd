package smtpd_test

import (
	"errors"
	"io"
	"net/smtp"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/chrj/smtpd/v2"
	"github.com/chrj/smtpd/v2/smtptest"
)

// TestDATAEndsAtCRLFDotCRLFAlone verifies that a DATA message ends at
// <CRLF>.<CRLF> and at no other sequence. RFC 5321 section 4.1.1.4 gives that
// one sequence, and it names <LF>.<LF> as one that the server must not take.
//
// A server that ends the message early reads the rest of it as commands. A
// client behind a relay then writes a transaction of its own into the session
// of that relay. The relay never saw the sender of that transaction.
//
// Each case puts one sequence inside a message, and a transaction after it.
// The server must deliver one message, and the transaction must arrive as
// text in the body.
func TestDATAEndsAtCRLFDotCRLFAlone(t *testing.T) {
	t.Parallel()

	// The transaction that follows the sequence, as the client writes it and
	// as the handler reads it when it is text of the body.
	const (
		transaction     = "MAIL FROM:<smuggled@example.org>\r\nRCPT TO:<recipient@example.net>\r\nDATA\r\nsecond"
		transactionText = "MAIL FROM:<smuggled@example.org>\nRCPT TO:<recipient@example.net>\nDATA\nsecond\n"
	)

	tests := []struct {
		name string

		// sequence stands inside the message, where a client puts it to end
		// the message early.
		sequence string

		// want is the body that the handler reads.
		want string
	}{
		{
			name:     "LF dot LF",
			sequence: "\n.\n",
			want:     "Subject: outer\n\nfirst\n.\n" + transactionText,
		},
		{
			name:     "LF dot CRLF",
			sequence: "\n.\r\n",
			want:     "Subject: outer\n\nfirst\n.\n" + transactionText,
		},
		{
			// The dot stands first on a line, so it is the escape of RFC 5321
			// section 4.5.2, and the server takes it off.
			name:     "CRLF dot LF",
			sequence: "\r\n.\n",
			want:     "Subject: outer\n\nfirst\n\n" + transactionText,
		},
		{
			name:     "CR dot CR",
			sequence: "\r.\r",
			want:     "Subject: outer\n\nfirst\r.\r" + transactionText,
		},
		{
			name:     "CRLF dot CR",
			sequence: "\r\n.\r",
			want:     "Subject: outer\n\nfirst\n\r" + transactionText,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			rec := &smtptest.Recorder{}
			ts := runserver(t, &smtpd.Server{Logger: testLogger(t), Handler: rec.Handler})

			c := dialRaw(t, ts.Addr)
			c.send("EHLO relay.example")
			c.send("MAIL FROM:<outer@example.org>")
			c.send("RCPT TO:<recipient@example.net>")
			if reply := c.send("DATA"); !strings.HasPrefix(reply, "354") {
				t.Fatalf("DATA = %q, want 354", reply)
			}

			// The message ends with a dot, and send adds the <CRLF> after it.
			message := "Subject: outer\r\n\r\nfirst" + tt.sequence + transaction + "\r\n."
			if reply := c.send("%s", message); !strings.HasPrefix(reply, "250") {
				t.Fatalf("end of message = %q, want 250", reply)
			}

			// A server that ran the transaction wrote the replies to it first,
			// and the client reads one of those in the place of the 221.
			if reply := c.send("QUIT"); !strings.HasPrefix(reply, "221") {
				t.Fatalf("QUIT = %q, want 221: the server read commands out of the message", reply)
			}

			messages := rec.Messages()
			if len(messages) != 1 {
				t.Fatalf("the server delivered %d messages, want 1", len(messages))
			}
			if got := messages[0].Sender; got != "outer@example.org" {
				t.Errorf("Sender = %q, want %q", got, "outer@example.org")
			}
			if got := string(messages[0].Data); got != tt.want {
				t.Errorf("body = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestDATAThatEndsWithBareLFGetsNoReply verifies what a client sees that ends
// its message with <LF>.<LF>. The server reads no end there, so it waits for
// one until Server.DataTimeout and then closes the connection. The handler
// reads an error in the place of the end, and the server delivers no message.
func TestDATAThatEndsWithBareLFGetsNoReply(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		rec := &smtptest.Recorder{}
		l := runpipeserver(t, &smtpd.Server{
			DataTimeout: 30 * time.Second,
			Logger:      testLogger(t),
			Handler:     rec.Handler,
		})
		defer func() { _ = l.Close() }()

		conn := l.dial(t)
		defer func() { _ = conn.Close() }()

		c, err := smtp.NewClient(conn, "localhost")
		if err != nil {
			t.Fatalf("NewClient failed: %v", err)
		}
		if err := c.Mail("sender@example.org"); err != nil {
			t.Fatalf("MAIL failed: %v", err)
		}
		if err := c.Rcpt("recipient@example.net"); err != nil {
			t.Fatalf("RCPT failed: %v", err)
		}
		if err := smtptest.Cmd(c.Text, 354, "DATA"); err != nil {
			t.Fatalf("DATA failed: %v", err)
		}

		start := time.Now()

		// Every line break of this message is a bare LF, and so is its end.
		if _, err := io.WriteString(conn, "body\n.\n"); err != nil {
			t.Fatalf("write failed: %v", err)
		}

		if _, _, err := c.Text.ReadResponse(250); !errors.Is(err, io.EOF) {
			t.Fatalf("read after the message = %v, want %v: the server must close without a reply", err, io.EOF)
		}
		if got := time.Since(start); got != 30*time.Second {
			t.Errorf("the server closed after %v, want 30s", got)
		}
		if got := len(rec.Messages()); got != 0 {
			t.Errorf("the server delivered %d messages, want 0", got)
		}
	})
}
