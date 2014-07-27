package smtpd_test

import (
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/smtp"
	"net/textproto"
	"strings"
	"testing"
	"time"

	"bitbucket.org/chrj/smtpd"
)

var localhostCert = []byte(`-----BEGIN CERTIFICATE-----
MIIBkzCCAT+gAwIBAgIQf4LO8+QzcbXRHJUo6MvX7zALBgkqhkiG9w0BAQswEjEQ
MA4GA1UEChMHQWNtZSBDbzAeFw03MDAxMDEwMDAwMDBaFw04MTA1MjkxNjAwMDBa
MBIxEDAOBgNVBAoTB0FjbWUgQ28wXDANBgkqhkiG9w0BAQEFAANLADBIAkEAx2Uj
2nl0ESnMMrdUOwQnpnIPQzQBX9MIYT87VxhHzImOukWcq5DrmN1ZB//diyrgiCLv
D0udX3YXNHMn1Ki8awIDAQABo3MwcTAOBgNVHQ8BAf8EBAMCAKQwEwYDVR0lBAww
CgYIKwYBBQUHAwEwDwYDVR0TAQH/BAUwAwEB/zA5BgNVHREEMjAwggtleGFtcGxl
LmNvbYIJbG9jYWxob3N0hwR/AAABhxAAAAAAAAAAAAAAAAAAAAABMAsGCSqGSIb3
DQEBCwNBAGcaB2Il0TIXFcJOdOLGPa6F8qZH1ZHBtVlCBnaJn4vZJGzID+V36Gn0
hA1AYfGAaF0c43oQofvv+XqQlTe4a+M=
-----END CERTIFICATE-----`)

var localhostKey = []byte(`-----BEGIN RSA PRIVATE KEY-----
MIIBPAIBAAJBAMdlI9p5dBEpzDK3VDsEJ6ZyD0M0AV/TCGE/O1cYR8yJjrpFnKuQ
65jdWQf/3Ysq4Igi7w9LnV92FzRzJ9SovGsCAwEAAQJAVaFw2VWJbAmIQUuMJ+Ar
6wZW2aSO5okpsyHFqSyrQQIcAj/QOq8P83F8J10IreFWNlBlywJU9c7IlJtn/lqq
AQIhAOxHXOxrKPxqTIdIcNnWye/HRQ+5VD54QQr1+M77+bEBAiEA2AmsNNqj2fKj
j2xk+4vnBSY0vrb4q/O3WZ46oorawWsCIQDWdpfzx/i11E6OZMR6FinJSNh4w0Gi
SkjPiCBE0BX+AQIhAI/TiLk7YmBkQG3ovSYW0vvDntPlXpKj08ovJFw4U0D3AiEA
lGjGna4oaauI0CWI6pG0wg4zklTnrDWK7w9h/S/T4e0=
-----END RSA PRIVATE KEY-----`)

func cmd(c *textproto.Conn, expectedCode int, format string, args ...interface{}) error {
	id, err := c.Cmd(format, args...)
	if err != nil {
		return err
	}

	c.StartResponse(id)
	_, _, err = c.ReadResponse(expectedCode)
	c.EndResponse(id)

	return err
}

func runserver(t *testing.T, server *smtpd.Server) (addr string, closer func()) {

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}

	go func() {
		server.Serve(ln)
	}()

	done := make(chan bool)

	go func() {
		<-done
		ln.Close()
	}()

	return ln.Addr().String(), func() {
		done <- true
	}

}

func runsslserver(t *testing.T, server *smtpd.Server) (addr string, closer func()) {

	cert, err := tls.X509KeyPair(localhostCert, localhostKey)
	if err != nil {
		t.Fatalf("Cert load failed: %v", err)
	}

	server.TLSConfig = &tls.Config{
		Certificates: []tls.Certificate{cert},
	}

	return runserver(t, server)

}

func TestSMTP(t *testing.T) {

	addr, closer := runserver(t, &smtpd.Server{})
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

	server := &smtpd.Server{}

	go func() {
		server.ListenAndServe(addr)
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
		Authenticator: func(peer smtpd.Peer, username, password string) error { return nil },
		ForceTLS:      true,
	})

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
		Authenticator: func(peer smtpd.Peer, username, password string) error {
			return smtpd.Error{Code: 550, Message: "Denied"}
		},
		ForceTLS: true,
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
		t.Fatal("Auth worked despite rejection")
	}

}

func TestAuthNotSupported(t *testing.T) {

	addr, closer := runsslserver(t, &smtpd.Server{
		ForceTLS: true,
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

func TestConnectionCheck(t *testing.T) {

	addr, closer := runserver(t, &smtpd.Server{
		ConnectionChecker: func(peer smtpd.Peer) error {
			return smtpd.Error{Code: 552, Message: "Denied"}
		},
	})

	defer closer()

	if _, err := smtp.Dial(addr); err == nil {
		t.Fatal("Dial succeeded despite ConnectionCheck")
	}

}

func TestConnectionCheckSimpleError(t *testing.T) {

	addr, closer := runserver(t, &smtpd.Server{
		ConnectionChecker: func(peer smtpd.Peer) error {
			return errors.New("Denied")
		},
	})

	defer closer()

	if _, err := smtp.Dial(addr); err == nil {
		t.Fatal("Dial succeeded despite ConnectionCheck")
	}

}

func TestHELOCheck(t *testing.T) {

	addr, closer := runserver(t, &smtpd.Server{
		HeloChecker: func(peer smtpd.Peer, name string) error {
			if name != "foobar.local" {
				t.Fatal("Wrong HELO name")
			}
			return smtpd.Error{Code: 552, Message: "Denied"}
		},
	})

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
		SenderChecker: func(peer smtpd.Peer, addr string) error {
			return smtpd.Error{Code: 552, Message: "Denied"}
		},
	})

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
		RecipientChecker: func(peer smtpd.Peer, addr string) error {
			return smtpd.Error{Code: 552, Message: "Denied"}
		},
	})

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
		Handler: func(peer smtpd.Peer, env smtpd.Envelope) error {
			if env.Sender != "sender@example.org" {
				t.Fatalf("Unknown sender: %v", env.Sender)
			}
			if len(env.Recipients) != 1 {
				t.Fatalf("Too many recipients: %d", len(env.Recipients))
			}
			if env.Recipients[0] != "recipient@example.net" {
				t.Fatalf("Unknown recipient: %v", env.Recipients[0])
			}
			if string(env.Data) != "This is the email body\n" {
				t.Fatalf("Wrong message body: %v", string(env.Data))
			}
			return nil
		},
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
	if err != nil {
		t.Fatalf("Data close failed: %v", err)
	}

	if err := c.Quit(); err != nil {
		t.Fatalf("QUIT failed: %v", err)
	}

}

func TestRejectHandler(t *testing.T) {

	addr, closer := runserver(t, &smtpd.Server{
		Handler: func(peer smtpd.Peer, env smtpd.Envelope) error {
			return smtpd.Error{Code: 550, Message: "Rejected"}
		},
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
		t.Fatal("Unexpected accept of data")
	}

	if err := c.Quit(); err != nil {
		t.Fatalf("QUIT failed: %v", err)
	}

}

func TestMaxConnections(t *testing.T) {

	addr, closer := runserver(t, &smtpd.Server{
		MaxConnections: 1,
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

	c1.Close()
}

func TestNoMaxConnections(t *testing.T) {

	addr, closer := runserver(t, &smtpd.Server{
		MaxConnections: -1,
	})

	defer closer()

	c1, err := smtp.Dial(addr)
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}

	c1.Close()
}

func TestMaxRecipients(t *testing.T) {

	addr, closer := runserver(t, &smtpd.Server{
		MaxRecipients: 1,
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

	addr, closer := runserver(t, &smtpd.Server{})

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

	addr, closer := runserver(t, &smtpd.Server{})

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

	addr, closer := runserver(t, &smtpd.Server{})

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

	addr, closer := runserver(t, &smtpd.Server{})

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

	addr, closer := runserver(t, &smtpd.Server{})

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

	addr, closer := runserver(t, &smtpd.Server{
		Handler: func(peer smtpd.Peer, env smtpd.Envelope) error {
			t.Fatal("Accepted DATA despite disconnection")
			return nil
		},
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

	c.Close()

}

func TestTimeoutClose(t *testing.T) {

	addr, closer := runserver(t, &smtpd.Server{
		MaxConnections: 1,
		ReadTimeout:    time.Second,
		WriteTimeout:   time.Second,
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

	c2.Close()
}

func TestTLSTimeout(t *testing.T) {

	addr, closer := runsslserver(t, &smtpd.Server{
		ReadTimeout:  time.Second * 2,
		WriteTimeout: time.Second * 2,
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

	addr, closer := runserver(t, &smtpd.Server{})

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
		SenderChecker: func(peer smtpd.Peer, addr string) error {
			if peer.HeloName != "new.example.net" {
				t.Fatalf("Didn't override HELO name: %v", peer.HeloName)
			}
			if peer.Addr.String() != "42.42.42.42:4242" {
				t.Fatalf("Didn't override IP/Port: %v", peer.Addr)
			}
			if peer.Username != "newusername" {
				t.Fatalf("Didn't override username: %v", peer.Username)
			}
			if peer.Protocol != smtpd.SMTP {
				t.Fatalf("Didn't override protocol: %v", peer.Protocol)
			}
			return nil
		},
	})

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

func TestEnvelopeReceived(t *testing.T) {

	addr, closer := runsslserver(t, &smtpd.Server{
		Hostname: "foobar.example.net",
		Handler: func(peer smtpd.Peer, env smtpd.Envelope) error {
			env.AddReceivedLine(peer)
			if !bytes.HasPrefix(env.Data, []byte("Received: from localhost [127.0.0.1] by foobar.example.net with ESMTP;")) {
				t.Fatal("Wrong received line.")
			}
			return nil
		},
		ForceTLS: true,
	})

	defer closer()

	c, err := smtp.Dial(addr)
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}

	if err := c.StartTLS(&tls.Config{InsecureSkipVerify: true}); err != nil {
		t.Fatalf("STARTTLS failed: %v", err)
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

func TestHELO(t *testing.T) {

	addr, closer := runserver(t, &smtpd.Server{})

	defer closer()

	c, err := smtp.Dial(addr)
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}

	if err := cmd(c.Text, 502, "MAIL FROM:<christian@technobabble.dk>"); err != nil {
		t.Fatalf("MAIL didn't fail: %v", err)
	}

	if err := cmd(c.Text, 250, "HELO localhost"); err != nil {
		t.Fatalf("HELO failed: %v", err)
	}

	if err := cmd(c.Text, 502, "MAIL FROM:christian@technobabble.dk"); err != nil {
		t.Fatalf("MAIL didn't fail: %v", err)
	}

	if err := cmd(c.Text, 250, "HELO localhost"); err != nil {
		t.Fatalf("HELO failed: %v", err)
	}

	if err := c.Quit(); err != nil {
		t.Fatalf("Quit failed: %v", err)
	}

}

func TestLOGINAuth(t *testing.T) {

	addr, closer := runsslserver(t, &smtpd.Server{
		Authenticator: func(peer smtpd.Peer, username, password string) error { return nil },
	})

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

func TestErrors(t *testing.T) {

	cert, err := tls.X509KeyPair(localhostCert, localhostKey)
	if err != nil {
		t.Fatalf("Cert load failed: %v", err)
	}

	server := &smtpd.Server{
		Authenticator: func(peer smtpd.Peer, username, password string) error { return nil },
	}

	addr, closer := runserver(t, server)

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

	if err := cmd(c.Text, 502, "MAIL FROM:christian@technobabble.dk"); err != nil {
		t.Fatalf("MAIL didn't fail: %v", err)
	}

	if err := c.Mail("sender@example.org"); err != nil {
		t.Fatalf("MAIL failed: %v", err)
	}

	if err := c.Mail("sender@example.org"); err == nil {
		t.Fatal("Duplicate MAIL didn't fail")
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

	if err := c.Quit(); err != nil {
		t.Fatalf("Quit failed: %v", err)
	}

}
