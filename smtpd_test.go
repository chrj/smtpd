package smtpd

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/smtp"
	"strings"
	"testing"
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

func TestSMTP(t *testing.T) {

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}

	defer ln.Close()

	server := &Server{}

	go func() {
		server.Serve(ln)
	}()

	c, err := smtp.Dial(ln.Addr().String())
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
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

	if err := c.Quit(); err != nil {
		t.Fatalf("Quit failed: %v", err)
	}
}

func TestSTARTTLS(t *testing.T) {

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}

	defer ln.Close()

	cert, err := tls.X509KeyPair(localhostCert, localhostKey)
	if err != nil {
		t.Fatalf("Cert load failed: %v", err)
	}

	server := &Server{
		Authenticator: func(peer Peer, username, password string) error { return nil },
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
		},
		ForceTLS: true,
	}

	go func() {
		server.Serve(ln)
	}()

	c, err := smtp.Dial(ln.Addr().String())
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}

	if supported, _ := c.Extension("AUTH"); supported {
		t.Fatal("AUTH supported before TLS")
	}

	if err := c.Mail("sender@example.org"); err == nil {
		t.Fatal("Mail workded before TLS with ForceTLS")
	}

	if err := c.StartTLS(&tls.Config{InsecureSkipVerify: true}); err != nil {
		t.Fatalf("STARTTLS failed: %v", err)
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
