package smtpd_test

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/smtp"
	"strings"
	"testing"
	"time"

	"github.com/chrj/smtpd/v2/pkg/smtpd"
)

func TestSMTP(t *testing.T) {

	addr, closer := runserver(t, &smtpd.Server{
		Logger: testLogger(t),
	})
	defer closer()

	c, err := smtp.Dial(addr)
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}

	if err := c.Hello("localhost"); err != nil {
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

	addr, closer := runsslserver(t, &smtpd.Server{
		ForceTLS: true,
		Logger:   testLogger(t),
	}, acceptAuth{})

	defer closer()

	c, err := smtp.Dial(addr)
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}

	if supported, _ := c.Extension("AUTH"); supported {
		t.Fatal("AUTH supported before TLS")
	}

	if err := c.Mail("sender@example.org"); err == nil {
		t.Fatal("Mail workded before TLS with ForceTLS")
	}

	if err := cmd(c.Text, 220, "STARTTLS"); err != nil {
		t.Fatalf("STARTTLS failed: %v", err)
	}

	if err := cmd(c.Text, 250, "foobar"); err == nil {
		t.Fatal("STARTTLS didn't fail with invalid handshake")
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

func TestAuthRejection(t *testing.T) {

	addr, closer := runsslserver(t, &smtpd.Server{
		ForceTLS: true,
		Logger:   testLogger(t),
	}, rejectAuth{})

	defer closer()

	c, err := smtp.Dial(addr)
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}

	if err := c.StartTLS(&tls.Config{InsecureSkipVerify: true}); err != nil {
		t.Fatalf("STARTTLS failed: %v", err)
	}

	if err := c.Auth(smtp.PlainAuth("foo", "foo", "bar", "127.0.0.1")); err == nil {
		t.Fatal("Auth worked despite rejection")
	}

}

func TestAuthNotSupported(t *testing.T) {

	addr, closer := runsslserver(t, &smtpd.Server{
		ForceTLS: true,
		Logger:   testLogger(t),
	})

	defer closer()

	c, err := smtp.Dial(addr)
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}

	if err := c.StartTLS(&tls.Config{InsecureSkipVerify: true}); err != nil {
		t.Fatalf("STARTTLS failed: %v", err)
	}

	if err := c.Auth(smtp.PlainAuth("foo", "foo", "bar", "127.0.0.1")); err == nil {
		t.Fatal("Auth worked despite no authenticator")
	}

}

func TestAuthBypass(t *testing.T) {

	addr, closer := runsslserver(t, &smtpd.Server{
		ForceTLS: true,
		Logger:   testLogger(t),
	}, rejectAuth{})

	defer closer()

	c, err := smtp.Dial(addr)
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}

	if err := c.StartTLS(&tls.Config{InsecureSkipVerify: true}); err != nil {
		t.Fatalf("STARTTLS failed: %v", err)
	}

	if err := c.Mail("sender@example.org"); err == nil {
		t.Fatal("Unexpected MAIL success")
	}

}

func TestAuthRequiredByDefault(t *testing.T) {

	addr, closer := runsslserver(t, &smtpd.Server{
		ForceTLS: true,
		Logger:   testLogger(t),
	}, rejectAuth{})

	defer closer()

	c, err := smtp.Dial(addr)
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}

	if err := c.StartTLS(&tls.Config{InsecureSkipVerify: true}); err != nil {
		t.Fatalf("STARTTLS failed: %v", err)
	}

	if err := c.Mail("sender@example.org"); err == nil {
		t.Fatal("Unexpected MAIL success")
	}

}

func TestAuthOptional(t *testing.T) {

	addr, closer := runsslserver(t, &smtpd.Server{
		AuthOptional: true,
		ForceTLS:     true,
		Logger:       testLogger(t),
	}, rejectAuth{})

	defer closer()

	c, err := smtp.Dial(addr)
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}

	if err := c.StartTLS(&tls.Config{InsecureSkipVerify: true}); err != nil {
		t.Fatalf("STARTTLS failed: %v", err)
	}

	if err := c.Mail("sender@example.org"); err != nil {
		t.Fatalf("Unexpected MAIL failure: %v", err)
	}

	if err := c.Quit(); err != nil {
		t.Fatalf("Quit failed: %v", err)
	}

}

func TestConnectionCheck(t *testing.T) {

	addr, closer := runserver(t, &smtpd.Server{
		Logger: testLogger(t),
	}, rejectConnSMTPErr{})

	defer closer()

	if _, err := smtp.Dial(addr); err == nil {
		t.Fatal("Dial succeeded despite ConnectionCheck")
	}

}

func TestConnectionCheckSimpleError(t *testing.T) {

	addr, closer := runserver(t, &smtpd.Server{
		Logger: testLogger(t),
	}, rejectConnPlainErr{})

	defer closer()

	if _, err := smtp.Dial(addr); err == nil {
		t.Fatal("Dial succeeded despite ConnectionCheck")
	}

}

func TestHELOCheck(t *testing.T) {

	addr, closer := runserver(t, &smtpd.Server{
		Logger: testLogger(t),
	}, heloAssert{t})

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

	addr, closer := runserver(t, &smtpd.Server{
		Logger: testLogger(t),
	}, rejectSender{})

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

	addr, closer := runserver(t, &smtpd.Server{
		Logger: testLogger(t),
	}, rejectRecipient{})

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

func TestMaxMessageSize(t *testing.T) {

	addr, closer := runserver(t, &smtpd.Server{
		MaxMessageSize: 5,
		Logger:         testLogger(t),
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

	err = wc.Close()
	if err == nil {
		t.Fatal("Allowed message larger than 5 bytes to pass.")
	}

	if err := c.Quit(); err != nil {
		t.Fatalf("QUIT failed: %v", err)
	}

}

func TestHandler(t *testing.T) {

	addr, closer := runserver(t, &smtpd.Server{
		Logger: testLogger(t),
	}, serveAssert{t})

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

	err = wc.Close()
	if err != nil {
		t.Fatalf("Data close failed: %v", err)
	}

	if err := c.Quit(); err != nil {
		t.Fatalf("QUIT failed: %v", err)
	}

}

func TestRejectHandler(t *testing.T) {

	addr, closer := runserver(t, &smtpd.Server{
		Logger: testLogger(t),
	}, rejectServe{})

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

	err = wc.Close()
	if err == nil {
		t.Fatal("Unexpected accept of data")
	}

	if err := c.Quit(); err != nil {
		t.Fatalf("QUIT failed: %v", err)
	}

}

func TestMaxConnections(t *testing.T) {

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

func TestInvalidHelo(t *testing.T) {

	addr, closer := runserver(t, &smtpd.Server{
		Logger: testLogger(t),
	})

	defer closer()

	c, err := smtp.Dial(addr)
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}

	if err := c.Hello(""); err == nil {
		t.Fatal("Unexpected HELO success")
	}

}

func TestInvalidSender(t *testing.T) {

	addr, closer := runserver(t, &smtpd.Server{
		Logger: testLogger(t),
	})

	defer closer()

	c, err := smtp.Dial(addr)
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}

	if err := c.Mail("invalid@@example.org"); err == nil {
		t.Fatal("Unexpected MAIL success")
	}

}

func TestInvalidRecipient(t *testing.T) {

	addr, closer := runserver(t, &smtpd.Server{
		Logger: testLogger(t),
	})

	defer closer()

	c, err := smtp.Dial(addr)
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}

	if err := c.Mail("sender@example.org"); err != nil {
		t.Fatalf("Mail failed: %v", err)
	}

	if err := c.Rcpt("invalid@@example.org"); err == nil {
		t.Fatal("Unexpected RCPT success")
	}

}

func TestRCPTbeforeMAIL(t *testing.T) {

	addr, closer := runserver(t, &smtpd.Server{
		Logger: testLogger(t),
	})

	defer closer()

	c, err := smtp.Dial(addr)
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}

	if err := c.Rcpt("recipient@example.net"); err == nil {
		t.Fatal("Unexpected RCPT success")
	}

}

func TestDATAbeforeRCPT(t *testing.T) {

	addr, closer := runserver(t, &smtpd.Server{
		Logger: testLogger(t),
	})

	defer closer()

	c, err := smtp.Dial(addr)
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}

	if err := c.Mail("sender@example.org"); err != nil {
		t.Fatalf("MAIL failed: %v", err)
	}

	if _, err := c.Data(); err == nil {
		t.Fatal("Data accepted despite no recipients")
	}

	if err := c.Quit(); err != nil {
		t.Fatalf("QUIT failed: %v", err)
	}

}

func TestInterruptedDATA(t *testing.T) {

	// With streaming DATA, the handler is invoked as soon as the dot-stream
	// starts, but reading to EOF on an interrupted connection must fail —
	// otherwise the server would commit partial messages.
	readErr := make(chan error, 1)
	addr, closer := runserver(t, &smtpd.Server{
		Logger: testLogger(t),
	}, interruptServe{readErr: readErr})

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

	if err := c.Quit(); err != nil {
		t.Fatalf("Quit failed: %v", err)
	}

}

func TestXCLIENT(t *testing.T) {

	addr, closer := runserver(t, &smtpd.Server{
		EnableXCLIENT: true,
		Logger:        testLogger(t),
	}, xclientAssert{t})

	defer closer()

	c, err := smtp.Dial(addr)
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}

	if supported, _ := c.Extension("XCLIENT"); !supported {
		t.Fatal("XCLIENT not supported")
	}

	err = cmd(c.Text, 220, "XCLIENT NAME=ignored ADDR=42.42.42.42 PORT=4242 PROTO=SMTP HELO=new.example.net LOGIN=newusername")
	if err != nil {
		t.Fatalf("XCLIENT failed: %v", err)
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

// TestEnvelopeReceived covered Envelope.AddReceivedLine, which was removed
// as part of the streaming-Data migration. A replacement will be designed
// along with the redesigned helper (see v2_proposal.md §Envelope.AddReceivedLine).

func TestHELO(t *testing.T) {

	addr, closer := runserver(t, &smtpd.Server{
		Logger: testLogger(t),
	})

	defer closer()

	c, err := smtp.Dial(addr)
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}

	if err := cmd(c.Text, 502, "MAIL FROM:<test@example.org>"); err != nil {
		t.Fatalf("MAIL before HELO didn't fail: %v", err)
	}

	if err := cmd(c.Text, 250, "HELO localhost"); err != nil {
		t.Fatalf("HELO failed: %v", err)
	}

	if err := cmd(c.Text, 250, "MAIL FROM:<test@example.org>"); err != nil {
		t.Fatalf("MAIL after HELO failed: %v", err)
	}

	if err := cmd(c.Text, 250, "HELO localhost"); err != nil {
		t.Fatalf("double HELO failed: %v", err)
	}

	if err := c.Quit(); err != nil {
		t.Fatalf("Quit failed: %v", err)
	}

}

func TestLOGINAuth(t *testing.T) {

	addr, closer := runsslserver(t, &smtpd.Server{
		Logger: testLogger(t),
	}, acceptAuth{})

	defer closer()

	c, err := smtp.Dial(addr)
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}

	if err := c.StartTLS(&tls.Config{InsecureSkipVerify: true}); err != nil {
		t.Fatalf("STARTTLS failed: %v", err)
	}

	if err := cmd(c.Text, 334, "AUTH LOGIN"); err != nil {
		t.Fatalf("AUTH didn't work: %v", err)
	}

	if err := cmd(c.Text, 502, "foo"); err != nil {
		t.Fatalf("AUTH didn't fail: %v", err)
	}

	if err := cmd(c.Text, 334, "AUTH LOGIN"); err != nil {
		t.Fatalf("AUTH didn't work: %v", err)
	}

	if err := cmd(c.Text, 334, "Zm9v"); err != nil {
		t.Fatalf("AUTH didn't work: %v", err)
	}

	if err := cmd(c.Text, 502, "foo"); err != nil {
		t.Fatalf("AUTH didn't fail: %v", err)
	}

	if err := cmd(c.Text, 334, "AUTH LOGIN"); err != nil {
		t.Fatalf("AUTH didn't work: %v", err)
	}

	if err := cmd(c.Text, 334, "Zm9v"); err != nil {
		t.Fatalf("AUTH didn't work: %v", err)
	}

	if err := cmd(c.Text, 235, "Zm9v"); err != nil {
		t.Fatalf("AUTH didn't work: %v", err)
	}

	if err := c.Quit(); err != nil {
		t.Fatalf("Quit failed: %v", err)
	}

}

func TestNullSender(t *testing.T) {

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

	if err := cmd(c.Text, 250, "MAIL FROM:<>"); err != nil {
		t.Fatalf("MAIL with null sender failed: %v", err)
	}

	if err := c.Quit(); err != nil {
		t.Fatalf("Quit failed: %v", err)
	}

}

func TestNoBracketsSender(t *testing.T) {

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

	if err := cmd(c.Text, 250, "MAIL FROM:test@example.org"); err != nil {
		t.Fatalf("MAIL without brackets failed: %v", err)
	}

	if err := c.Quit(); err != nil {
		t.Fatalf("Quit failed: %v", err)
	}

}

func TestErrors(t *testing.T) {

	cert := localhostTLSCert(t)

	server := &smtpd.Server{
		Logger: testLogger(t),
	}

	addr, closer := runserver(t, server, acceptAuth{})

	defer closer()

	c, err := smtp.Dial(addr)
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}

	if err := cmd(c.Text, 502, "AUTH PLAIN foobar"); err != nil {
		t.Fatalf("AUTH didn't fail: %v", err)
	}

	if err := c.Hello("localhost"); err != nil {
		t.Fatalf("HELO failed: %v", err)
	}

	if err := cmd(c.Text, 502, "AUTH PLAIN foobar"); err != nil {
		t.Fatalf("AUTH didn't fail: %v", err)
	}

	if err := c.Mail("sender@example.org"); err == nil {
		t.Fatalf("MAIL didn't fail")
	}

	if err := cmd(c.Text, 502, "STARTTLS"); err != nil {
		t.Fatalf("STARTTLS didn't fail: %v", err)
	}

	server.TLSConfig = &tls.Config{
		Certificates: []tls.Certificate{cert},
	}

	if err := c.StartTLS(&tls.Config{InsecureSkipVerify: true}); err != nil {
		t.Fatalf("STARTTLS failed: %v", err)
	}

	if err := cmd(c.Text, 502, "AUTH UNKNOWN"); err != nil {
		t.Fatalf("AUTH didn't fail: %v", err)
	}

	if err := cmd(c.Text, 502, "AUTH PLAIN foobar"); err != nil {
		t.Fatalf("AUTH didn't fail: %v", err)
	}

	if err := cmd(c.Text, 502, "AUTH PLAIN Zm9vAGJhcg=="); err != nil {
		t.Fatalf("AUTH didn't fail: %v", err)
	}

	if err := cmd(c.Text, 334, "AUTH PLAIN"); err != nil {
		t.Fatalf("AUTH didn't work: %v", err)
	}

	if err := cmd(c.Text, 235, "Zm9vAGJhcgBxdXV4"); err != nil {
		t.Fatalf("AUTH didn't work: %v", err)
	}

	if err := c.Mail("sender@example.org"); err != nil {
		t.Fatalf("MAIL failed: %v", err)
	}

	if err := c.Mail("sender@example.org"); err == nil {
		t.Fatalf("Duplicate MAIL didn't fail")
	}

	if err := c.Quit(); err != nil {
		t.Fatalf("Quit failed: %v", err)
	}

}

func TestMailformedMAILFROM(t *testing.T) {

	addr, closer := runserver(t, &smtpd.Server{
		Logger: testLogger(t),
	}, strictSender{})

	defer closer()

	c, err := smtp.Dial(addr)
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}

	if err := c.Hello("localhost"); err != nil {
		t.Fatalf("HELO failed: %v", err)
	}

	if err := cmd(c.Text, 250, "MAIL FROM: <test@example.org>"); err != nil {
		t.Fatalf("MAIL FROM failed with extra whitespace: %v", err)
	}

	if err := c.Quit(); err != nil {
		t.Fatalf("Quit failed: %v", err)
	}
}

func TestTLSListener(t *testing.T) {

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
	server.Handler(tlsAuthAssert{t})

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
	// goroutine — Shutdown blocks until active sessions drain.
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
	server := &smtpd.Server{}
	if err := server.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown() failed: %v", err)
	}
	if err := server.Serve(nil); err != smtpd.ErrServerClosed {
		t.Fatalf("Serve() did not return ErrServerClosed: %v", err)
	}
}
