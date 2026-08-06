package smtptest_test

import (
	"fmt"
	"log"

	"github.com/chrj/smtpd/v2/smtptest"
)

// ExampleServer sends a message to a test server over STARTTLS and reads back
// what arrived. Dial gives a net/smtp client that already sent STARTTLS. A
// client of your own connects to srv.Addr and trusts srv.ClientTLSConfig().
func ExampleServer() {
	rec := &smtptest.Recorder{}
	srv := smtptest.NewSTARTTLSServer(rec.Handler)
	defer srv.Close()

	c := srv.Dial()

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
