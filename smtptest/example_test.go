package smtptest_test

import (
	"fmt"
	"log"
	"net/smtp"

	"github.com/chrj/smtpd/v2/smtptest"
)

// ExampleServer sends a message to a test server over STARTTLS and reads back
// what arrived. Replace the net/smtp calls with the client under test.
func ExampleServer() {
	rec := &smtptest.Recorder{}
	srv := smtptest.NewSTARTTLSServer(rec.Handler)
	defer srv.Close()

	c, err := smtp.Dial(srv.Addr)
	if err != nil {
		log.Fatalf("dial %s: %v", srv.Addr, err)
	}
	if err := c.StartTLS(srv.ClientTLSConfig()); err != nil {
		log.Fatalf("STARTTLS: %v", err)
	}

	if err := c.Mail("sender@example.org"); err != nil {
		log.Fatalf("MAIL FROM: %v", err)
	}
	if err := c.Rcpt("recipient@example.net"); err != nil {
		log.Fatalf("RCPT TO: %v", err)
	}

	w, err := c.Data()
	if err != nil {
		log.Fatalf("DATA: %v", err)
	}
	if _, err := fmt.Fprint(w, "Subject: hello\r\n\r\nThis is the email body\r\n"); err != nil {
		log.Fatalf("write the body: %v", err)
	}
	if err := w.Close(); err != nil {
		log.Fatalf("close the body: %v", err)
	}
	if err := c.Quit(); err != nil {
		log.Fatalf("QUIT: %v", err)
	}

	message := rec.Messages()[0]
	fmt.Println(message.Sender)
	fmt.Println(message.Recipients)
	fmt.Println(message.Peer.TLS != nil)

	// Output:
	// sender@example.org
	// [recipient@example.net]
	// true
}
