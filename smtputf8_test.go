package smtpd_test

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/chrj/smtpd/v2"
	"github.com/chrj/smtpd/v2/smtptest"
)

// TestSMTPUTF8OfferedOnlyWhenEnabled covers the EHLO keyword of RFC 6531. A
// server that offers it says that it carries an address of Unicode onward, so
// the operator turns it on.
func TestSMTPUTF8OfferedOnlyWhenEnabled(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		enabled bool
	}{
		{name: "the extension is on", enabled: true},
		{name: "the extension is off", enabled: false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			srv := runserver(t, &smtpd.Server{
				Logger:         testLogger(t),
				EnableSMTPUTF8: test.enabled,
			})

			c := srv.Dial()
			if err := c.Hello("localhost"); err != nil {
				t.Fatalf("EHLO failed: %v", err)
			}

			if got, params := c.Extension("SMTPUTF8"); got != test.enabled {
				t.Errorf("the server offers SMTPUTF8 = %v, want %v", got, test.enabled)
			} else if params != "" {
				// RFC 6531 section 3.1 asks for the keyword alone.
				t.Errorf("the SMTPUTF8 keyword carries the parameters %q, want none", params)
			}

			// RFC 6531 section 3.1 asks for 8BITMIME next to the extension.
			if got, _ := c.Extension("8BITMIME"); !got {
				t.Error("the server does not offer 8BITMIME")
			}

			if err := c.Quit(); err != nil {
				t.Errorf("QUIT failed: %v", err)
			}
		})
	}
}

// TestSMTPUTF8ReachesTheHandler drives a whole transaction and reads the
// addresses of Unicode back from the envelope.
func TestSMTPUTF8ReachesTheHandler(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		mail  string
		rcpts []string
		want  message
	}{
		{
			name:  "a local part of Unicode",
			mail:  "MAIL FROM:<jörg@example.org> SMTPUTF8",
			rcpts: []string{"RCPT TO:<用户@example.net>"},
			want: message{
				sender:     "jörg@example.org",
				recipients: []string{"用户@example.net"},
				smtputf8:   true,
			},
		},
		{
			name:  "a domain of Unicode",
			mail:  "MAIL FROM:<sender@exämple.org> SMTPUTF8",
			rcpts: []string{"RCPT TO:<one@例子.广告>"},
			want: message{
				sender:     "sender@exämple.org",
				recipients: []string{"one@例子.广告"},
				smtputf8:   true,
			},
		},
		{
			name:  "the parameter in lower case next to BODY",
			mail:  "MAIL FROM:<jörg@example.org> smtputf8 BODY=8BITMIME",
			rcpts: []string{"RCPT TO:<one@example.net>"},
			want: message{
				sender:     "jörg@example.org",
				recipients: []string{"one@example.net"},
				bodyType:   smtpd.Body8BitMIME,
				smtputf8:   true,
			},
		},
		{
			name:  "the parameter on an address of US-ASCII",
			mail:  "MAIL FROM:<sender@example.org> SMTPUTF8",
			rcpts: []string{"RCPT TO:<one@example.net>"},
			want: message{
				sender:     "sender@example.org",
				recipients: []string{"one@example.net"},
				smtputf8:   true,
			},
		},
		{
			name:  "an address of US-ASCII without the parameter",
			mail:  "MAIL FROM:<sender@example.org>",
			rcpts: []string{"RCPT TO:<one@example.net>"},
			want: message{
				sender:     "sender@example.org",
				recipients: []string{"one@example.net"},
			},
		},
		{
			name:  "a null sender with the parameter",
			mail:  "MAIL FROM:<> SMTPUTF8",
			rcpts: []string{"RCPT TO:<用户@example.net>"},
			want: message{
				recipients: []string{"用户@example.net"},
				smtputf8:   true,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			got := make(chan message, 1)
			srv := runserver(t, &smtpd.Server{
				Logger:         testLogger(t),
				EnableSMTPUTF8: true,
				Handler:        captureMessage(got),
			})

			c := srv.Dial()
			if err := c.Hello("localhost"); err != nil {
				t.Fatalf("EHLO failed: %v", err)
			}

			if err := smtptest.Cmd(c.Text, 250, "%s", test.mail); err != nil {
				t.Fatalf("%s failed: %v", test.mail, err)
			}

			for _, rcpt := range test.rcpts {
				if err := smtptest.Cmd(c.Text, 250, "%s", rcpt); err != nil {
					t.Fatalf("%s failed: %v", rcpt, err)
				}
			}

			w, err := c.Data()
			if err != nil {
				t.Fatalf("DATA failed: %v", err)
			}
			if _, err := fmt.Fprint(w, "Subject: Grüße\r\n\r\nA short body.\r\n"); err != nil {
				t.Fatalf("write body failed: %v", err)
			}
			if err := w.Close(); err != nil {
				t.Fatalf("close body failed: %v", err)
			}

			// The DATA reader gives the body with the line breaks of the
			// host, in the way that the standard library reads a dot stream.
			want := test.want
			want.body = "Subject: Grüße\n\nA short body.\n"

			assertMessage(t, <-got, want)

			if err := c.Quit(); err != nil {
				t.Errorf("QUIT failed: %v", err)
			}
		})
	}
}

// TestNonASCIIAddressWithoutTheParameter covers RFC 6531 section 3.5. A
// server that offers the extension holds every other transaction to US-ASCII,
// and answers 550 for the sender and 553 for a recipient.
func TestNonASCIIAddressWithoutTheParameter(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		mail string
		rcpt string
		want int
	}{
		{
			name: "a sender of Unicode",
			mail: "MAIL FROM:<jörg@example.org>",
			want: 550,
		},
		{
			name: "a sender domain of Unicode",
			mail: "MAIL FROM:<sender@exämple.org>",
			want: 550,
		},
		{
			name: "a recipient of Unicode",
			mail: "MAIL FROM:<sender@example.org>",
			rcpt: "RCPT TO:<用户@example.net>",
			want: 553,
		},
		{
			name: "a recipient of Unicode after a sender of US-ASCII with the parameter",
			mail: "MAIL FROM:<sender@example.org> SMTPUTF8",
			rcpt: "RCPT TO:<用户@example.net>",
			want: 250,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			srv := runserver(t, &smtpd.Server{
				Logger:         testLogger(t),
				EnableSMTPUTF8: true,
			})

			c := srv.Dial()
			if err := c.Hello("localhost"); err != nil {
				t.Fatalf("EHLO failed: %v", err)
			}

			want := test.want
			if test.rcpt != "" {
				if err := smtptest.Cmd(c.Text, 250, "%s", test.mail); err != nil {
					t.Fatalf("%s failed: %v", test.mail, err)
				}
				if err := smtptest.Cmd(c.Text, want, "%s", test.rcpt); err != nil {
					t.Errorf("%s: %v", test.rcpt, err)
				}
			} else if err := smtptest.Cmd(c.Text, want, "%s", test.mail); err != nil {
				t.Errorf("%s: %v", test.mail, err)
			}

			// The session survives a refused address.
			if err := smtptest.Cmd(c.Text, 250, "NOOP"); err != nil {
				t.Errorf("NOOP after the reply: %v", err)
			}

			if err := c.Quit(); err != nil {
				t.Errorf("QUIT failed: %v", err)
			}
		})
	}
}

// TestNonASCIIAddressWithoutTheExtension covers a server that runs without
// Server.EnableSMTPUTF8. It offers the extension to no client, and reads an
// address as it did before the extension.
func TestNonASCIIAddressWithoutTheExtension(t *testing.T) {
	t.Parallel()

	got := make(chan message, 1)
	srv := runserver(t, &smtpd.Server{
		Logger:  testLogger(t),
		Handler: captureMessage(got),
	})

	c := srv.Dial()
	if err := c.Hello("localhost"); err != nil {
		t.Fatalf("EHLO failed: %v", err)
	}

	if err := smtptest.Cmd(c.Text, 250, "MAIL FROM:<jörg@example.org>"); err != nil {
		t.Fatalf("MAIL FROM failed: %v", err)
	}
	if err := smtptest.Cmd(c.Text, 250, "RCPT TO:<用户@example.net>"); err != nil {
		t.Fatalf("RCPT TO failed: %v", err)
	}

	w, err := c.Data()
	if err != nil {
		t.Fatalf("DATA failed: %v", err)
	}
	if _, err := fmt.Fprint(w, "body\r\n"); err != nil {
		t.Fatalf("write body failed: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close body failed: %v", err)
	}

	assertMessage(t, <-got, message{
		sender:     "jörg@example.org",
		recipients: []string{"用户@example.net"},
		body:       "body\n",
	})

	if err := c.Quit(); err != nil {
		t.Errorf("QUIT failed: %v", err)
	}
}

// TestSMTPUTF8ParameterRefused covers the replies to a parameter that the
// server cannot take.
func TestSMTPUTF8ParameterRefused(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		enabled  bool
		greeting string
		cmd      string
		want     int
	}{
		{
			name:     "the extension is off",
			greeting: "EHLO",
			cmd:      "MAIL FROM:<sender@example.org> SMTPUTF8",
			want:     555,
		},
		{
			name:     "the client greeted with HELO",
			enabled:  true,
			greeting: "HELO",
			cmd:      "MAIL FROM:<sender@example.org> SMTPUTF8",
			want:     555,
		},
		{
			name:     "the parameter carries a value",
			enabled:  true,
			greeting: "EHLO",
			cmd:      "MAIL FROM:<sender@example.org> SMTPUTF8=YES",
			want:     501,
		},
		{
			name:     "the address is not UTF-8",
			enabled:  true,
			greeting: "EHLO",
			cmd:      "MAIL FROM:<j\xf6rg@example.org> SMTPUTF8",
			want:     501,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			srv := runserver(t, &smtpd.Server{
				Logger:         testLogger(t),
				EnableSMTPUTF8: test.enabled,
			})

			c := srv.Dial()
			if err := smtptest.Cmd(c.Text, 250, "%s localhost", test.greeting); err != nil {
				t.Fatalf("%s failed: %v", test.greeting, err)
			}

			if err := smtptest.Cmd(c.Text, test.want, "%s", test.cmd); err != nil {
				t.Errorf("%s: %v", test.cmd, err)
			}

			// The session survives a refused parameter.
			if err := smtptest.Cmd(c.Text, 250, "NOOP"); err != nil {
				t.Errorf("NOOP after the reply: %v", err)
			}

			if err := c.Quit(); err != nil {
				t.Errorf("QUIT failed: %v", err)
			}
		})
	}
}

// TestSMTPUTF8RecipientNotUTF8 covers a RCPT TO command whose address carries
// a byte that is not UTF-8. RFC 6531 gives the address in that encoding, and
// a byte outside it is not a character at all.
func TestSMTPUTF8RecipientNotUTF8(t *testing.T) {
	t.Parallel()

	srv := runserver(t, &smtpd.Server{
		Logger:         testLogger(t),
		EnableSMTPUTF8: true,
	})

	c := srv.Dial()
	if err := c.Hello("localhost"); err != nil {
		t.Fatalf("EHLO failed: %v", err)
	}

	if err := smtptest.Cmd(c.Text, 250, "MAIL FROM:<sender@example.org> SMTPUTF8"); err != nil {
		t.Fatalf("MAIL FROM failed: %v", err)
	}

	cmd := "RCPT TO:<one@ex\xe4mple.net>"
	if err := smtptest.Cmd(c.Text, 501, "%s", cmd); err != nil {
		t.Errorf("%s: %v", cmd, err)
	}

	if err := c.Quit(); err != nil {
		t.Errorf("QUIT failed: %v", err)
	}
}

// TestSMTPUTF8EndsWithTheTransaction covers the second transaction of a
// connection. The parameter belongs to one MAIL FROM command, so a
// transaction that follows it starts without it.
func TestSMTPUTF8EndsWithTheTransaction(t *testing.T) {
	t.Parallel()

	srv := runserver(t, &smtpd.Server{
		Logger:         testLogger(t),
		EnableSMTPUTF8: true,
	})

	c := srv.Dial()
	if err := c.Hello("localhost"); err != nil {
		t.Fatalf("EHLO failed: %v", err)
	}

	if err := smtptest.Cmd(c.Text, 250, "MAIL FROM:<jörg@example.org> SMTPUTF8"); err != nil {
		t.Fatalf("MAIL FROM failed: %v", err)
	}
	if err := smtptest.Cmd(c.Text, 250, "RCPT TO:<用户@example.net>"); err != nil {
		t.Fatalf("RCPT TO failed: %v", err)
	}
	if err := smtptest.Cmd(c.Text, 250, "RSET"); err != nil {
		t.Fatalf("RSET failed: %v", err)
	}

	if err := smtptest.Cmd(c.Text, 550, "MAIL FROM:<jörg@example.org>"); err != nil {
		t.Errorf("the sender of the second transaction: %v", err)
	}
	if err := smtptest.Cmd(c.Text, 250, "MAIL FROM:<sender@example.org>"); err != nil {
		t.Fatalf("MAIL FROM failed: %v", err)
	}
	if err := smtptest.Cmd(c.Text, 553, "RCPT TO:<用户@example.net>"); err != nil {
		t.Errorf("the recipient of the second transaction: %v", err)
	}

	if err := c.Quit(); err != nil {
		t.Errorf("QUIT failed: %v", err)
	}
}

// TestSMTPUTF8ORcpt covers the "utf-8" address type of RFC 6533. A server
// that offers both SMTPUTF8 and DSN takes it, with the bytes as they came.
func TestSMTPUTF8ORcpt(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		mail string
		rcpt string
		want *smtpd.DSN
	}{
		{
			name: "the address as it came",
			mail: "MAIL FROM:<sender@example.org> SMTPUTF8",
			rcpt: "RCPT TO:<用户@example.net> ORCPT=utf-8;用户@example.net",
			want: &smtpd.DSN{
				Recipients: []smtpd.RecipientDSN{{
					OriginalType:      "utf-8",
					OriginalRecipient: "用户@example.net",
				}},
			},
		},
		{
			name: "the address in the escape of RFC 6533",
			mail: "MAIL FROM:<sender@example.org>",
			rcpt: `RCPT TO:<one@example.net> ORCPT=utf-8;j\x{00F6}rg@example.net`,
			want: &smtpd.DSN{
				Recipients: []smtpd.RecipientDSN{{
					OriginalType:      "utf-8",
					OriginalRecipient: "jörg@example.net",
				}},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			got := make(chan *smtpd.DSN, 1)
			srv := runserver(t, &smtpd.Server{
				Logger:         testLogger(t),
				EnableSMTPUTF8: true,
				EnableDSN:      true,
				Handler:        dsnCapture(got),
			})

			c := srv.Dial()
			if err := c.Hello("localhost"); err != nil {
				t.Fatalf("EHLO failed: %v", err)
			}

			if err := smtptest.Cmd(c.Text, 250, "%s", test.mail); err != nil {
				t.Fatalf("%s failed: %v", test.mail, err)
			}
			if err := smtptest.Cmd(c.Text, 250, "%s", test.rcpt); err != nil {
				t.Fatalf("%s failed: %v", test.rcpt, err)
			}

			w, err := c.Data()
			if err != nil {
				t.Fatalf("DATA failed: %v", err)
			}
			if _, err := fmt.Fprint(w, "body\r\n"); err != nil {
				t.Fatalf("write body failed: %v", err)
			}
			if err := w.Close(); err != nil {
				t.Fatalf("close body failed: %v", err)
			}

			if dsn := <-got; !reflect.DeepEqual(dsn, test.want) {
				t.Errorf("env.DSN = %+v, want %+v", dsn, test.want)
			}

			if err := c.Quit(); err != nil {
				t.Errorf("QUIT failed: %v", err)
			}
		})
	}
}

// TestORcptUTF8WithoutTheExtension covers a server that offers DSN alone. It
// reads an ORCPT parameter of the "utf-8" address type as the xtext of RFC
// 3461, in the way that it did before RFC 6533, so the escape reaches the
// handler as it came.
func TestORcptUTF8WithoutTheExtension(t *testing.T) {
	t.Parallel()

	got := make(chan *smtpd.DSN, 1)
	srv := runserver(t, &smtpd.Server{
		Logger:    testLogger(t),
		EnableDSN: true,
		Handler:   dsnCapture(got),
	})

	c := srv.Dial()
	if err := c.Hello("localhost"); err != nil {
		t.Fatalf("EHLO failed: %v", err)
	}

	if err := smtptest.Cmd(c.Text, 250, "MAIL FROM:<sender@example.org>"); err != nil {
		t.Fatalf("MAIL FROM failed: %v", err)
	}

	rcpt := `RCPT TO:<one@example.net> ORCPT=utf-8;j\x{00F6}rg@example.net`
	if err := smtptest.Cmd(c.Text, 250, "%s", rcpt); err != nil {
		t.Fatalf("%s failed: %v", rcpt, err)
	}

	w, err := c.Data()
	if err != nil {
		t.Fatalf("DATA failed: %v", err)
	}
	if _, err := fmt.Fprint(w, "body\r\n"); err != nil {
		t.Fatalf("write body failed: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close body failed: %v", err)
	}

	want := &smtpd.DSN{
		Recipients: []smtpd.RecipientDSN{{
			OriginalType:      "utf-8",
			OriginalRecipient: `j\x{00F6}rg@example.net`,
		}},
	}
	if dsn := <-got; !reflect.DeepEqual(dsn, want) {
		t.Errorf("env.DSN = %+v, want %+v", dsn, want)
	}

	if err := c.Quit(); err != nil {
		t.Errorf("QUIT failed: %v", err)
	}
}

// TestORcptUTF8WithoutTheParameter covers an ORCPT parameter of the "utf-8"
// address type whose address carries UTF-8 as it is. RFC 6533 section 3 asks
// the client for the escape where the transaction did not ask for SMTPUTF8.
func TestORcptUTF8WithoutTheParameter(t *testing.T) {
	t.Parallel()

	srv := runserver(t, &smtpd.Server{
		Logger:         testLogger(t),
		EnableSMTPUTF8: true,
		EnableDSN:      true,
	})

	c := srv.Dial()
	if err := c.Hello("localhost"); err != nil {
		t.Fatalf("EHLO failed: %v", err)
	}

	if err := smtptest.Cmd(c.Text, 250, "MAIL FROM:<sender@example.org>"); err != nil {
		t.Fatalf("MAIL FROM failed: %v", err)
	}

	cmd := "RCPT TO:<one@example.net> ORCPT=utf-8;用户@example.net"
	if err := smtptest.Cmd(c.Text, 501, "%s", cmd); err != nil {
		t.Errorf("%s: %v", cmd, err)
	}

	if err := c.Quit(); err != nil {
		t.Errorf("QUIT failed: %v", err)
	}
}
