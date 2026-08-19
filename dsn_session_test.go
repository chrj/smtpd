package smtpd_test

import (
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/chrj/smtpd/v2"
	"github.com/chrj/smtpd/v2/smtptest"
)

// TestDSNOfferedOnlyWhenEnabled covers the EHLO keyword of RFC 3461. A server
// that offers it tells the client that a notification follows the request, so
// the operator turns it on.
func TestDSNOfferedOnlyWhenEnabled(t *testing.T) {
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
				Logger:    testLogger(t),
				EnableDSN: test.enabled,
			})

			c := srv.Dial()
			if err := c.Hello("localhost"); err != nil {
				t.Fatalf("EHLO failed: %v", err)
			}

			if got, _ := c.Extension("DSN"); got != test.enabled {
				t.Errorf("the server offers DSN = %v, want %v", got, test.enabled)
			}

			if err := c.Quit(); err != nil {
				t.Errorf("QUIT failed: %v", err)
			}
		})
	}
}

// TestDSNParametersReachTheHandler drives a whole transaction and reads the
// parameters back from the envelope.
func TestDSNParametersReachTheHandler(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		mail  string
		rcpts []string
		want  *smtpd.DSN
	}{
		{
			name:  "no parameter at all",
			mail:  "MAIL FROM:<sender@example.org>",
			rcpts: []string{"RCPT TO:<one@example.net>"},
			want:  nil,
		},
		{
			name:  "RET and ENVID",
			mail:  "MAIL FROM:<sender@example.org> RET=HDRS ENVID=QQ+40314159",
			rcpts: []string{"RCPT TO:<one@example.net>"},
			want: &smtpd.DSN{
				Return:     smtpd.DSNReturnHeaders,
				EnvID:      "QQ@314159",
				Recipients: []smtpd.RecipientDSN{{}},
			},
		},
		{
			name: "NOTIFY and ORCPT on the second recipient of three",
			mail: "MAIL FROM:<sender@example.org>",
			rcpts: []string{
				"RCPT TO:<one@example.net>",
				"RCPT TO:<two@example.net> NOTIFY=SUCCESS,DELAY ORCPT=rfc822;old+40example.net",
				"RCPT TO:<three@example.net>",
			},
			want: &smtpd.DSN{
				Recipients: []smtpd.RecipientDSN{
					{},
					{
						Notify:            smtpd.DSNNotifySuccess | smtpd.DSNNotifyDelay,
						OriginalRecipient: "old@example.net",
						OriginalType:      "rfc822",
					},
					{},
				},
			},
		},
		{
			name: "NEVER on every recipient",
			mail: "MAIL FROM:<sender@example.org> RET=FULL",
			rcpts: []string{
				"RCPT TO:<one@example.net> NOTIFY=NEVER",
				"RCPT TO:<two@example.net> NOTIFY=never",
			},
			want: &smtpd.DSN{
				Return: smtpd.DSNReturnFull,
				Recipients: []smtpd.RecipientDSN{
					{Notify: smtpd.DSNNotifyNever},
					{Notify: smtpd.DSNNotifyNever},
				},
			},
		},
		{
			name:  "the DSN parameters next to SIZE and BODY",
			mail:  "MAIL FROM:<sender@example.org> SIZE=100 BODY=8BITMIME ENVID=QQ314159",
			rcpts: []string{"RCPT TO:<one@example.net> NOTIFY=FAILURE"},
			want: &smtpd.DSN{
				EnvID:      "QQ314159",
				Recipients: []smtpd.RecipientDSN{{Notify: smtpd.DSNNotifyFailure}},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
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
			if _, err := fmt.Fprint(w, "This is the email body\r\n"); err != nil {
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

// paramCase is one command that carries a DSN parameter, with the reply code
// that the server must answer. rcpt says that the command needs an open
// transaction before it.
type paramCase struct {
	name string
	cmd  string
	rcpt bool
}

// runParamCase greets the server, opens a transaction for a RCPT TO command,
// and reads the reply to the command of the test.
func runParamCase(t *testing.T, srv *smtptest.Server, test paramCase, greeting string, want int) {
	t.Helper()

	c := srv.Dial()

	if err := smtptest.Cmd(c.Text, 250, "%s localhost", greeting); err != nil {
		t.Fatalf("%s failed: %v", greeting, err)
	}

	if test.rcpt {
		if err := smtptest.Cmd(c.Text, 250, "MAIL FROM:<sender@example.org>"); err != nil {
			t.Fatalf("MAIL FROM failed: %v", err)
		}
	}

	if err := smtptest.Cmd(c.Text, want, "%s", test.cmd); err != nil {
		t.Errorf("%s: %v", test.cmd, err)
	}

	// The session survives a refused parameter.
	if err := smtptest.Cmd(c.Text, 250, "NOOP"); err != nil {
		t.Errorf("NOOP after the reply: %v", err)
	}

	if err := c.Quit(); err != nil {
		t.Errorf("QUIT failed: %v", err)
	}
}

// TestDSNParametersWithoutTheExtension covers a client that sends the
// parameters to a server that does not offer them. RFC 3461 section 4.4 gives
// 555 for that.
func TestDSNParametersWithoutTheExtension(t *testing.T) {
	t.Parallel()

	tests := []paramCase{
		{name: "RET", cmd: "MAIL FROM:<sender@example.org> RET=FULL"},
		{name: "ENVID", cmd: "MAIL FROM:<sender@example.org> ENVID=QQ314159"},
		{name: "NOTIFY", cmd: "RCPT TO:<one@example.net> NOTIFY=SUCCESS", rcpt: true},
		{name: "ORCPT", cmd: "RCPT TO:<one@example.net> ORCPT=rfc822;one@example.net", rcpt: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			srv := runserver(t, &smtpd.Server{Logger: testLogger(t)})
			runParamCase(t, srv, test, "EHLO", 555)
		})
	}
}

// TestDSNParametersAfterHELO covers a client that greets with HELO and then
// sends the parameters. The extension belongs to ESMTP, and a client that
// sends HELO never saw the server offer it.
func TestDSNParametersAfterHELO(t *testing.T) {
	t.Parallel()

	tests := []paramCase{
		{name: "on MAIL FROM", cmd: "MAIL FROM:<sender@example.org> RET=FULL"},
		{name: "on RCPT TO", cmd: "RCPT TO:<one@example.net> NOTIFY=SUCCESS", rcpt: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			srv := runserver(t, &smtpd.Server{
				Logger:    testLogger(t),
				EnableDSN: true,
			})
			runParamCase(t, srv, test, "HELO", 555)
		})
	}
}

// TestDSNInvalidParameters covers the values that RFC 3461 refuses. The
// server answers 501 and keeps the session open.
func TestDSNInvalidParameters(t *testing.T) {
	t.Parallel()

	tests := []paramCase{
		{name: "a RET value of another kind", cmd: "MAIL FROM:<sender@example.org> RET=HEADERS"},
		{name: "an ENVID that is not xtext", cmd: "MAIL FROM:<sender@example.org> ENVID=a+zz"},
		{name: "an ENVID with a line break in it", cmd: "MAIL FROM:<sender@example.org> ENVID=a+0D+0A"},
		{name: "an ENVID of 101 characters", cmd: "MAIL FROM:<sender@example.org> ENVID=" + strings.Repeat("a", 101)},
		{name: "a NOTIFY event of another kind", cmd: "RCPT TO:<one@example.net> NOTIFY=BOUNCE", rcpt: true},
		{name: "NEVER with another event", cmd: "RCPT TO:<one@example.net> NOTIFY=NEVER,SUCCESS", rcpt: true},
		{name: "an ORCPT with no address type", cmd: "RCPT TO:<one@example.net> ORCPT=one@example.net", rcpt: true},
		{name: "an ORCPT with a line break in it", cmd: "RCPT TO:<one@example.net> ORCPT=rfc822;a+0D+0A", rcpt: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			srv := runserver(t, &smtpd.Server{
				Logger:    testLogger(t),
				EnableDSN: true,
			})
			runParamCase(t, srv, test, "EHLO", 501)
		})
	}
}
