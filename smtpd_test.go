package smtpd_test

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/smtp"
	"net/textproto"
	"strings"
	"testing"
	"time"

	"github.com/chrj/smtpd/v2"
)

func TestSMTP(t *testing.T) {
	t.Parallel()

	addr, closer := runserver(t, &smtpd.Server{
		Logger: testLogger(t),
	})
	defer closer()

	c, err := smtp.Dial(addr)
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}

	if err := cmd(c.Text, 250, "HELO localhost"); err != nil {
		t.Fatalf("HELO failed: %v", err)
	}

	if supported, _ := c.Extension("AUTH"); supported {
		t.Fatal("AUTH supported before TLS")
	}

	if supported, _ := c.Extension("8BITMIME"); !supported {
		t.Fatal("8BITMIME not supported")
	}

	if supported, _ := c.Extension("STARTTLS"); supported {
		t.Fatal("STARTTLS supported")
	}

	if err := c.Mail("sender@example.org"); err != nil {
		t.Fatalf("Mail failed: %v", err)
	}

	if err := c.Rcpt("recipient@example.net"); err != nil {
		t.Fatalf("Rcpt failed: %v", err)
	}

	if err := c.Rcpt("recipient2@example.net"); err != nil {
		t.Fatalf("Rcpt2 failed: %v", err)
	}

	wc, err := c.Data()
	if err != nil {
		t.Fatalf("Data failed: %v", err)
	}

	_, err = fmt.Fprintf(wc, "This is the email body")
	if err != nil {
		t.Fatalf("Data body failed: %v", err)
	}

	err = wc.Close()
	if err != nil {
		t.Fatalf("Data close failed: %v", err)
	}

	if err := c.Reset(); err != nil {
		t.Fatalf("Reset failed: %v", err)
	}

	if err := c.Verify("foobar@example.net"); err == nil {
		t.Fatal("Unexpected support for VRFY")
	}

	if err := cmd(c.Text, 250, "NOOP"); err != nil {
		t.Fatalf("NOOP failed: %v", err)
	}

	if err := c.Quit(); err != nil {
		t.Fatalf("Quit failed: %v", err)
	}
}

func TestListenAndServe(t *testing.T) {
	t.Parallel()

	addr, closer := runserver(t, &smtpd.Server{})
	closer()

	server := &smtpd.Server{
		Logger: testLogger(t),
	}

	go func() {
		_ = server.ListenAndServe(addr)
	}()

	time.Sleep(100 * time.Millisecond)

	c, err := smtp.Dial(addr)
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}

	if err := c.Quit(); err != nil {
		t.Fatalf("Quit failed: %v", err)
	}

}

func TestSTARTTLS(t *testing.T) {
	t.Parallel()

	addr, closer := runsslserver(t, &smtpd.Server{
		Logger: testLogger(t),
	}, acceptAuth())

	defer closer()

	c, err := smtp.Dial(addr)
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}

	if supported, _ := c.Extension("AUTH"); supported {
		t.Fatal("AUTH supported before TLS")
	}

	if err := c.StartTLS(&tls.Config{InsecureSkipVerify: true}); err != nil {
		t.Fatalf("STARTTLS failed: %v", err)
	}

	if err := c.StartTLS(&tls.Config{InsecureSkipVerify: true}); err == nil {
		t.Fatal("STARTTLS worked twice")
	}

	if supported, _ := c.Extension("AUTH"); !supported {
		t.Fatal("AUTH not supported after TLS")
	}

	if _, mechs := c.Extension("AUTH"); !strings.Contains(mechs, "PLAIN") {
		t.Fatal("PLAIN AUTH not supported after TLS")
	}

	if _, mechs := c.Extension("AUTH"); !strings.Contains(mechs, "LOGIN") {
		t.Fatal("LOGIN AUTH not supported after TLS")
	}

	if err := c.Auth(smtp.PlainAuth("foo", "foo", "bar", "127.0.0.1")); err != nil {
		t.Fatalf("Auth failed: %v", err)
	}

	if err := c.Mail("sender@example.org"); err != nil {
		t.Fatalf("Mail failed: %v", err)
	}

	if err := c.Rcpt("recipient@example.net"); err != nil {
		t.Fatalf("Rcpt failed: %v", err)
	}

	if err := c.Rcpt("recipient2@example.net"); err != nil {
		t.Fatalf("Rcpt2 failed: %v", err)
	}

	wc, err := c.Data()
	if err != nil {
		t.Fatalf("Data failed: %v", err)
	}

	_, err = fmt.Fprintf(wc, "This is the email body")
	if err != nil {
		t.Fatalf("Data body failed: %v", err)
	}

	err = wc.Close()
	if err != nil {
		t.Fatalf("Data close failed: %v", err)
	}

	if err := c.Quit(); err != nil {
		t.Fatalf("Quit failed: %v", err)
	}
}

func TestConnectionCheck(t *testing.T) {
	t.Parallel()

	addr, closer := runserver(t, &smtpd.Server{
		Logger: testLogger(t),
	}, rejectConnSMTPErr())

	defer closer()

	if _, err := smtp.Dial(addr); err == nil {
		t.Fatal("Dial succeeded despite ConnectionCheck")
	}

}

func TestConnectionCheckSimpleError(t *testing.T) {
	t.Parallel()

	addr, closer := runserver(t, &smtpd.Server{
		Logger: testLogger(t),
	}, rejectConnPlainErr())

	defer closer()

	if _, err := smtp.Dial(addr); err == nil {
		t.Fatal("Dial succeeded despite ConnectionCheck")
	}

}

func TestHELOCheck(t *testing.T) {
	t.Parallel()

	addr, closer := runserver(t, &smtpd.Server{
		Logger: testLogger(t),
	}, heloAssert(t))

	defer closer()

	c, err := smtp.Dial(addr)
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}

	if err := c.Hello("foobar.local"); err == nil {
		t.Fatal("Unexpected HELO success")
	}

}

func TestSenderCheck(t *testing.T) {
	t.Parallel()

	addr, closer := runserver(t, &smtpd.Server{
		Logger: testLogger(t),
	}, rejectSender())

	defer closer()

	c, err := smtp.Dial(addr)
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}

	if err := c.Mail("sender@example.org"); err == nil {
		t.Fatal("Unexpected MAIL success")
	}

}

func TestRecipientCheck(t *testing.T) {
	t.Parallel()

	addr, closer := runserver(t, &smtpd.Server{
		Logger: testLogger(t),
	}, rejectRecipient())

	defer closer()

	c, err := smtp.Dial(addr)
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}

	if err := c.Mail("sender@example.org"); err != nil {
		t.Fatalf("Mail failed: %v", err)
	}

	if err := c.Rcpt("recipient@example.net"); err == nil {
		t.Fatal("Unexpected RCPT success")
	}

}

func TestMAILFromWithESMTPParams(t *testing.T) {
	t.Parallel()

	addr, closer := runserver(t, &smtpd.Server{Logger: testLogger(t)})
	defer closer()

	c, err := smtp.Dial(addr)
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}

	if err := cmd(c.Text, 250, "EHLO localhost"); err != nil {
		t.Fatalf("EHLO failed: %v", err)
	}
	if err := cmd(c.Text, 250, "MAIL FROM:<sender@example.org> SIZE=123 BODY=8BITMIME AUTH=<>"); err != nil {
		t.Fatalf("MAIL with ESMTP params failed: %v", err)
	}
	if err := c.Quit(); err != nil {
		t.Fatalf("Quit failed: %v", err)
	}
}

func TestMAILFromRejectsOversizeDeclaration(t *testing.T) {
	t.Parallel()

	addr, closer := runserver(t, &smtpd.Server{
		Logger:         testLogger(t),
		MaxMessageSize: 32,
	})
	defer closer()

	c, err := smtp.Dial(addr)
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}

	if err := cmd(c.Text, 250, "EHLO localhost"); err != nil {
		t.Fatalf("EHLO failed: %v", err)
	}
	if err := cmd(c.Text, 552, "MAIL FROM:<sender@example.org> SIZE=33"); err != nil {
		t.Fatalf("MAIL with oversize SIZE didn't 552: %v", err)
	}
	_ = c.Quit()
}

func TestMAILFromRejectsUnknownESMTPParam(t *testing.T) {
	t.Parallel()

	addr, closer := runserver(t, &smtpd.Server{Logger: testLogger(t)})
	defer closer()

	c, err := smtp.Dial(addr)
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}

	if err := cmd(c.Text, 250, "EHLO localhost"); err != nil {
		t.Fatalf("EHLO failed: %v", err)
	}
	if err := cmd(c.Text, 555, "MAIL FROM:<sender@example.org> FROB=1"); err != nil {
		t.Fatalf("MAIL with unknown param didn't 555: %v", err)
	}
	_ = c.Quit()
}

func TestMAILFromRejectsParamsWithoutEHLO(t *testing.T) {
	t.Parallel()

	addr, closer := runserver(t, &smtpd.Server{Logger: testLogger(t)})
	defer closer()

	c, err := smtp.Dial(addr)
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}

	if err := cmd(c.Text, 250, "HELO localhost"); err != nil {
		t.Fatalf("HELO failed: %v", err)
	}
	if err := cmd(c.Text, 555, "MAIL FROM:<sender@example.org> SIZE=1"); err != nil {
		t.Fatalf("MAIL with params after HELO didn't 555: %v", err)
	}
	_ = c.Quit()
}

// senderInRecipient returns a Middleware whose CheckRecipient verifies that
// SenderFromContext returns the MAIL FROM address, and that it is cleared
// after RSET. The recorded "want" values are read through the returned
// pointer so individual subtests can mutate them.
type senderInRecipientWants struct {
	wantSender     string
	wantSenderSeen bool
}

func senderInRecipient(t *testing.T, want *senderInRecipientWants) smtpd.Middleware {
	return smtpd.Middleware{
		CheckRecipient: func(ctx context.Context, _ smtpd.Peer, _ string) (context.Context, error) {
			t.Helper()
			got, ok := smtpd.SenderFromContext(ctx)
			if ok != want.wantSenderSeen {
				t.Errorf("SenderFromContext ok = %v, want %v", ok, want.wantSenderSeen)
			}
			if got != want.wantSender {
				t.Errorf("SenderFromContext = %q, want %q", got, want.wantSender)
			}
			return ctx, nil
		},
	}
}

// resetCounter returns a Middleware whose Reset hook bumps n on each call.
func resetCounter(n *int) smtpd.Middleware {
	return smtpd.Middleware{
		Reset: func(ctx context.Context, _ smtpd.Peer) context.Context {
			*n++
			return ctx
		},
	}
}

// disconnectCounter returns a Middleware whose Disconnect hook bumps n on
// each call. The err argument is recorded into lastErr if non-nil is
// observed, so tests that care can assert on the cause; nil-err calls
// leave lastErr untouched.
func disconnectCounter(n *int, lastErr *error) smtpd.Middleware {
	return smtpd.Middleware{
		Disconnect: func(_ context.Context, _ smtpd.Peer, err error) {
			*n++
			if err != nil && lastErr != nil {
				*lastErr = err
			}
		},
	}
}

func TestResetHook(t *testing.T) {
	t.Parallel()

	var count int
	addr, closer := runserver(t, &smtpd.Server{Logger: testLogger(t)}, resetCounter(&count))
	defer closer()

	c, err := smtp.Dial(addr)
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}
	// Explicit RSET.
	if err := c.Reset(); err != nil {
		t.Fatalf("Reset failed: %v", err)
	}
	// Transaction that ends in DATA - implicit reset after delivery.
	if err := c.Mail("a@example.org"); err != nil {
		t.Fatal(err)
	}
	if err := c.Rcpt("b@example.net"); err != nil {
		t.Fatal(err)
	}
	w, err := c.Data()
	if err != nil {
		t.Fatal(err)
	}
	_, _ = w.Write([]byte("hello\r\n"))
	_ = w.Close()
	_ = c.Quit()

	// Expect at least one reset from RSET plus one implicit after DATA.
	// HELO/EHLO also fire reset, so exact count is noisy - just require >=2.
	if count < 2 {
		t.Fatalf("expected >= 2 Reset calls, got %d", count)
	}
}

func TestDisconnectHook(t *testing.T) {
	t.Parallel()

	var count int
	var lastErr error
	addr, closer := runserver(t, &smtpd.Server{Logger: testLogger(t)}, disconnectCounter(&count, &lastErr))
	defer closer()

	c, err := smtp.Dial(addr)
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}
	_ = c.Quit()

	// Give the server goroutine a moment to run its deferred close.
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) && count == 0 {
		time.Sleep(5 * time.Millisecond)
	}
	if count != 1 {
		t.Fatalf("expected exactly 1 Disconnect call, got %d", count)
	}
	if lastErr != nil {
		t.Fatalf("expected nil Disconnect err on clean QUIT, got %v", lastErr)
	}
}

// TestDisconnectHookAbruptClose verifies the hook still fires when the client
// drops the TCP connection without sending QUIT. The server's session.serve
// loop defers close regardless of how the scanner exits. A cooperative FIN
// from the client reaches the server as EOF, so err should be nil.
func TestDisconnectHookAbruptClose(t *testing.T) {
	t.Parallel()

	var count int
	var lastErr error
	addr, closer := runserver(t, &smtpd.Server{Logger: testLogger(t)}, disconnectCounter(&count, &lastErr))
	defer closer()

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}
	// Read the 220 banner so we know the session is established, then slam
	// the connection shut without any SMTP exchange.
	buf := make([]byte, 256)
	_ = conn.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := conn.Read(buf); err != nil {
		t.Fatalf("reading banner failed: %v", err)
	}
	_ = conn.Close()

	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) && count == 0 {
		time.Sleep(5 * time.Millisecond)
	}
	if count != 1 {
		t.Fatalf("expected exactly 1 Disconnect call, got %d", count)
	}
	if lastErr != nil {
		t.Fatalf("expected nil Disconnect err on cooperative close, got %v", lastErr)
	}
}

// TestDisconnectHookImplicitTLSHandshakeFail dials a tls.NewListener-wrapped
// server with plain TCP so the forced handshake in newSession fails. The
// session must close and Disconnect must fire with a non-nil err describing
// the handshake failure.
func TestDisconnectHookImplicitTLSHandshakeFail(t *testing.T) {
	var count int
	var lastErr error
	addr, closer := runImplicitTLSServer(t, &smtpd.Server{Logger: testLogger(t)}, disconnectCounter(&count, &lastErr))
	defer closer()

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}
	// Send bytes that are not a TLS ClientHello. The server's HandshakeContext
	// reads them, fails, and we bail out of newSession with closeErr set.
	_, _ = conn.Write([]byte("HELO not-a-client-hello\r\n"))
	_ = conn.Close()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && count == 0 {
		time.Sleep(5 * time.Millisecond)
	}
	if count != 1 {
		t.Fatalf("expected exactly 1 Disconnect call, got %d", count)
	}
	if lastErr == nil {
		t.Fatal("expected non-nil Disconnect err for failed implicit-TLS handshake")
	}
}

// TestDisconnectHookSTARTTLSHandshakeFail dials a STARTTLS-capable server,
// asks for STARTTLS, and then sends non-TLS bytes. The server's
// HandshakeContext must fail, close the session, and fire Disconnect with
// the handshake error.
func TestDisconnectHookSTARTTLSHandshakeFail(t *testing.T) {
	var count int
	var lastErr error
	addr, closer := runsslserver(t, &smtpd.Server{Logger: testLogger(t)}, disconnectCounter(&count, &lastErr))
	defer closer()

	c, err := smtp.Dial(addr)
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}
	if err := c.Hello("localhost"); err != nil {
		t.Fatalf("HELO failed: %v", err)
	}
	// Ask for STARTTLS and get the 220 go-ahead.
	if err := cmd(c.Text, 220, "STARTTLS"); err != nil {
		t.Fatalf("STARTTLS failed: %v", err)
	}
	// Send garbage where a TLS ClientHello is expected.
	_, _ = c.Text.W.WriteString("foobar\r\n")
	_ = c.Text.W.Flush()
	_ = c.Close()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && count == 0 {
		time.Sleep(5 * time.Millisecond)
	}
	if count != 1 {
		t.Fatalf("expected exactly 1 Disconnect call, got %d", count)
	}
	if lastErr == nil {
		t.Fatal("expected non-nil Disconnect err for failed STARTTLS handshake")
	}
}

// TestDisconnectHookDataInterrupted dials a server, starts a DATA transfer,
// and slams the connection shut before sending the terminating "\r\n.\r\n".
// The server's DATA reader should surface ErrUnexpectedEOF, which must
// propagate to Disconnect.
func TestDisconnectHookDataInterrupted(t *testing.T) {
	var count int
	var lastErr error
	readErr := make(chan error, 1)
	addr, closer := runserver(t,
		&smtpd.Server{Logger: testLogger(t)},
		smtpd.Middleware{Handler: interruptServe(readErr)},
		disconnectCounter(&count, &lastErr),
	)
	defer closer()

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}
	tp := textproto.NewConn(conn)
	if _, _, err := tp.ReadResponse(220); err != nil {
		t.Fatalf("banner: %v", err)
	}
	if err := cmd(tp, 250, "HELO localhost"); err != nil {
		t.Fatalf("HELO: %v", err)
	}
	if err := cmd(tp, 250, "MAIL FROM:<a@example.org>"); err != nil {
		t.Fatalf("MAIL: %v", err)
	}
	if err := cmd(tp, 250, "RCPT TO:<b@example.net>"); err != nil {
		t.Fatalf("RCPT: %v", err)
	}
	if err := cmd(tp, 354, "DATA"); err != nil {
		t.Fatalf("DATA: %v", err)
	}
	// Partial body, then close without the terminating ".\r\n".
	_, _ = conn.Write([]byte("Subject: hi\r\nhalf"))
	_ = conn.Close()

	// Wait for the handler's ReadAll to surface an error.
	select {
	case err := <-readErr:
		if err == nil {
			t.Fatal("expected non-nil ReadAll error after interrupted DATA")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("handler didn't return")
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && count == 0 {
		time.Sleep(5 * time.Millisecond)
	}
	if count != 1 {
		t.Fatalf("expected exactly 1 Disconnect call, got %d", count)
	}
	if lastErr == nil {
		t.Fatal("expected non-nil Disconnect err for interrupted DATA")
	}
}

func TestSenderInContext(t *testing.T) {
	t.Parallel()

	wants := &senderInRecipientWants{wantSender: "sender@example.org", wantSenderSeen: true}
	addr, closer := runserver(t, &smtpd.Server{Logger: testLogger(t)}, senderInRecipient(t, wants))
	defer closer()

	c, err := smtp.Dial(addr)
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}
	if err := c.Mail("sender@example.org"); err != nil {
		t.Fatalf("Mail failed: %v", err)
	}
	if err := c.Rcpt("a@example.net"); err != nil {
		t.Fatalf("Rcpt failed: %v", err)
	}

	// RSET clears the sender; next RCPT should see no sender. But RCPT
	// without prior MAIL is rejected at the protocol level, so instead issue
	// another MAIL FROM after RSET to confirm the sender is restored fresh.
	if err := c.Reset(); err != nil {
		t.Fatalf("Reset failed: %v", err)
	}
	wants.wantSender = "other@example.org"
	if err := c.Mail("other@example.org"); err != nil {
		t.Fatalf("Mail failed: %v", err)
	}
	if err := c.Rcpt("b@example.net"); err != nil {
		t.Fatalf("Rcpt failed: %v", err)
	}
	_ = c.Quit()
}

func TestMaxConnections(t *testing.T) {
	t.Parallel()

	addr, closer := runserver(t, &smtpd.Server{
		MaxConnections: 1,
		Logger:         testLogger(t),
	})

	defer closer()

	c1, err := smtp.Dial(addr)
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}

	_, err = smtp.Dial(addr)
	if err == nil {
		t.Fatal("Dial succeeded despite MaxConnections = 1")
	}

	_ = c1.Close()
}

func TestNoMaxConnections(t *testing.T) {
	t.Parallel()

	addr, closer := runserver(t, &smtpd.Server{
		MaxConnections: -1,
		Logger:         testLogger(t),
	})

	defer closer()

	c1, err := smtp.Dial(addr)
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}

	_ = c1.Close()
}

func TestMaxRecipients(t *testing.T) {
	t.Parallel()

	addr, closer := runserver(t, &smtpd.Server{
		MaxRecipients: 1,
		Logger:        testLogger(t),
	})

	defer closer()

	c, err := smtp.Dial(addr)
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}

	if err := c.Mail("sender@example.org"); err != nil {
		t.Fatalf("MAIL failed: %v", err)
	}

	if err := c.Rcpt("recipient@example.net"); err != nil {
		t.Fatalf("RCPT failed: %v", err)
	}

	if err := c.Rcpt("recipient@example.net"); err == nil {
		t.Fatal("RCPT succeeded despite MaxRecipients = 1")
	}

	if err := c.Quit(); err != nil {
		t.Fatalf("QUIT failed: %v", err)
	}

}

func TestInterruptedDATA(t *testing.T) {
	t.Parallel()

	// With streaming DATA, the handler is invoked as soon as the dot-stream
	// starts, but reading to EOF on an interrupted connection must fail -
	// otherwise the server would commit partial messages.
	readErr := make(chan error, 1)
	addr, closer := runserver(t, &smtpd.Server{
		Logger:  testLogger(t),
		Handler: interruptServe(readErr),
	})

	defer closer()

	c, err := smtp.Dial(addr)
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}

	if err := c.Mail("sender@example.org"); err != nil {
		t.Fatalf("MAIL failed: %v", err)
	}

	if err := c.Rcpt("recipient@example.net"); err != nil {
		t.Fatalf("RCPT failed: %v", err)
	}

	wc, err := c.Data()
	if err != nil {
		t.Fatalf("Data failed: %v", err)
	}

	_, err = fmt.Fprintf(wc, "This is the email body")
	if err != nil {
		t.Fatalf("Data body failed: %v", err)
	}

	_ = c.Close()

	select {
	case err := <-readErr:
		if err == nil {
			t.Fatal("Accepted DATA despite disconnection")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Handler never observed interrupted DATA")
	}
}

func TestTimeoutClose(t *testing.T) {
	t.Parallel()

	addr, closer := runserver(t, &smtpd.Server{
		MaxConnections: 1,
		ReadTimeout:    time.Second,
		WriteTimeout:   time.Second,
		Logger:         testLogger(t),
	})

	defer closer()

	c1, err := smtp.Dial(addr)
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}

	time.Sleep(time.Second * 2)

	c2, err := smtp.Dial(addr)
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}

	if err := c1.Mail("sender@example.org"); err == nil {
		t.Fatal("MAIL succeeded despite being timed out.")
	}

	if err := c2.Mail("sender@example.org"); err != nil {
		t.Fatalf("MAIL failed: %v", err)
	}

	if err := c2.Quit(); err != nil {
		t.Fatalf("Quit failed: %v", err)
	}

	_ = c2.Close()
}

func TestTLSTimeout(t *testing.T) {
	t.Parallel()

	addr, closer := runsslserver(t, &smtpd.Server{
		ReadTimeout:  time.Second * 2,
		WriteTimeout: time.Second * 2,
		Logger:       testLogger(t),
	})

	defer closer()

	c, err := smtp.Dial(addr)
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}

	if err := c.StartTLS(&tls.Config{InsecureSkipVerify: true}); err != nil {
		t.Fatalf("STARTTLS failed: %v", err)
	}

	time.Sleep(time.Second)

	if err := c.Mail("sender@example.org"); err != nil {
		t.Fatalf("MAIL failed: %v", err)
	}

	time.Sleep(time.Second)

	if err := c.Rcpt("recipient@example.net"); err != nil {
		t.Fatalf("RCPT failed: %v", err)
	}

	time.Sleep(time.Second)

	if err := c.Rcpt("recipient@example.net"); err != nil {
		t.Fatalf("RCPT failed: %v", err)
	}

	time.Sleep(time.Second)

	if err := c.Quit(); err != nil {
		t.Fatalf("Quit failed: %v", err)
	}

}

func TestLongLine(t *testing.T) {
	t.Parallel()

	addr, closer := runserver(t, &smtpd.Server{
		Logger: testLogger(t),
	})

	defer closer()

	c, err := smtp.Dial(addr)
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}

	if err := c.Mail(fmt.Sprintf("%s@example.org", strings.Repeat("x", 65*1024))); err == nil {
		t.Fatalf("MAIL failed: %v", err)
	}

	// The server closes the connection after "500 Line too long",
	// so subsequent commands are expected to fail.
	if err := c.Quit(); err == nil {
		t.Fatalf("expected Quit to fail after too-long line")
	}

}

// TestEnvelopeReceived covered Envelope.AddReceivedLine, which was removed
// as part of the streaming-Data migration. A replacement will be designed
// along with the redesigned helper (see v2_proposal.md §Envelope.AddReceivedLine).

func TestTLSListener(t *testing.T) {
	t.Parallel()

	cfg := &tls.Config{
		Certificates: []tls.Certificate{localhostTLSCert(t)},
	}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
	if err != nil {
		t.Fatalf("tls.Listen failed: %v", err)
	}
	defer func() { _ = ln.Close() }()

	addr := ln.Addr().String()

	server := &smtpd.Server{
		Logger: testLogger(t),
	}
	server.Use(tlsAuthAssert(t))

	go func() {
		_ = server.Serve(ln)
	}()

	conn, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatalf("couldn't connect to tls socket: %v", err)
	}

	c, err := smtp.NewClient(conn, "localhost")
	if err != nil {
		t.Fatalf("couldn't create client: %v", err)
	}

	if err := c.Hello("localhost"); err != nil {
		t.Fatalf("HELO failed: %v", err)
	}

	if err := cmd(c.Text, 334, "AUTH PLAIN"); err != nil {
		t.Fatalf("AUTH didn't work: %v", err)
	}

	if err := cmd(c.Text, 235, "Zm9vAGJhcgBxdXV4"); err != nil {
		t.Fatalf("AUTH didn't work: %v", err)
	}

	if err := c.Quit(); err != nil {
		t.Fatalf("Quit failed: %v", err)
	}

}

func TestShutdown(t *testing.T) {
	t.Parallel()

	fmt.Println("Starting test")
	server := &smtpd.Server{
		Logger: testLogger(t),
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}

	srvres := make(chan error)
	go func() {
		t.Log("Starting server")
		srvres <- server.Serve(ln)
	}()

	// Connect a client
	c, err := smtp.Dial(ln.Addr().String())
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}

	if err := c.Hello("localhost"); err != nil {
		t.Fatalf("HELO failed: %v", err)
	}

	// While the client connection is open, shut down the server in a
	// goroutine - Shutdown blocks until active sessions drain.
	shutres := make(chan error)
	go func() {
		t.Log("Calling Shutdown")
		shutres <- server.Shutdown(context.Background())
	}()

	// Give Shutdown a moment to close the listener.
	time.Sleep(250 * time.Millisecond)

	// Verify that Shutdown() worked by attempting to connect another client
	_, err = smtp.Dial(ln.Addr().String())
	if err == nil {
		t.Fatalf("Dial did not fail as expected")
	}
	if _, typok := err.(*net.OpError); !typok {
		t.Fatalf("Dial did not return net.OpError as expected: %v (%T)", err, err)
	}

	// Shutdown should not have returned yet due to open client conn
	select {
	case shuterr := <-shutres:
		t.Fatalf("Shutdown returned early w/ error: %v", shuterr)
	default:
	}

	// Now close the client
	t.Log("Closing client connection")
	if err := c.Quit(); err != nil {
		t.Fatalf("QUIT failed: %v", err)
	}
	_ = c.Close()

	// Wait for Shutdown to return
	t.Log("Waiting for Shutdown to return")
	select {
	case shuterr := <-shutres:
		if shuterr != nil {
			t.Fatalf("Shutdown returned error: %v", shuterr)
		}
	case <-time.After(15 * time.Second):
		t.Fatalf("Timed out waiting for Shutdown to return")
	}

	// Wait for Serve() to return
	t.Log("Waiting for Serve() to return")
	select {
	case srverr := <-srvres:
		if srverr != smtpd.ErrServerClosed {
			t.Fatalf("Serve() returned error: %v", srverr)
		}
	case <-time.After(15 * time.Second):
		t.Fatalf("Timed out waiting for Serve() to return")
	}
}

func TestServeFailsIfShutdown(t *testing.T) {
	t.Parallel()

	server := &smtpd.Server{}
	if err := server.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown() failed: %v", err)
	}
	if err := server.Serve(nil); err != smtpd.ErrServerClosed {
		t.Fatalf("Serve() did not return ErrServerClosed: %v", err)
	}
}
