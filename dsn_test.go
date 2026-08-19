package smtpd

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
)

// TestParseDSNReturn covers the RET parameter of MAIL FROM.
func TestParseDSNReturn(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want DSNReturn
		ok   bool
	}{
		{name: "the whole message", in: "FULL", want: DSNReturnFull, ok: true},
		{name: "the headers only", in: "HDRS", want: DSNReturnHeaders, ok: true},
		{name: "lower case", in: "hdrs", want: DSNReturnHeaders, ok: true},
		{name: "mixed case", in: "Full", want: DSNReturnFull, ok: true},
		{name: "a value that RFC 3461 does not give", in: "HEADERS"},
		{name: "an empty value", in: ""},
		{name: "two values", in: "FULL,HDRS"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, ok := parseDSNReturn(test.in)
			if ok != test.ok {
				t.Fatalf("parseDSNReturn(%q) ok = %v, want %v", test.in, ok, test.ok)
			}
			if got != test.want {
				t.Errorf("parseDSNReturn(%q) = %q, want %q", test.in, got, test.want)
			}
		})
	}
}

// TestParseEnvID covers the ENVID parameter of MAIL FROM.
func TestParseEnvID(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
		ok   bool
	}{
		{name: "a plain identifier", in: "QQ314159", want: "QQ314159", ok: true},
		{name: "an at sign in xtext", in: "id+40example.org", want: "id@example.org", ok: true},
		{name: "a space in xtext", in: "two+20words", want: "two words", ok: true},
		{name: "the longest value", in: strings.Repeat("a", 100), want: strings.Repeat("a", 100), ok: true},
		{name: "one character too long", in: strings.Repeat("a", 101)},
		{name: "a bare equals sign", in: "a=b"},
		{name: "a bare space", in: "two words"},
		{name: "a plus with no digits", in: "user+tag"},
		{name: "a plus with one digit", in: "a+4"},
		{name: "a line break in xtext", in: "a+0D+0Ab"},
		{name: "a byte above ASCII in xtext", in: "a+FFb"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, ok := parseEnvID(test.in)
			if ok != test.ok {
				t.Fatalf("parseEnvID(%q) ok = %v, want %v", test.in, ok, test.ok)
			}
			if got != test.want {
				t.Errorf("parseEnvID(%q) = %q, want %q", test.in, got, test.want)
			}
		})
	}
}

// TestParseNotify covers the NOTIFY parameter of RCPT TO.
func TestParseNotify(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want DSNNotify
		ok   bool
	}{
		{name: "one event", in: "SUCCESS", want: DSNNotifySuccess, ok: true},
		{name: "two events", in: "SUCCESS,DELAY", want: DSNNotifySuccess | DSNNotifyDelay, ok: true},
		{name: "three events", in: "FAILURE,DELAY,SUCCESS", want: DSNNotifyFailure | DSNNotifyDelay | DSNNotifySuccess, ok: true},
		{name: "no event at all", in: "NEVER", want: DSNNotifyNever, ok: true},
		{name: "lower case", in: "failure", want: DSNNotifyFailure, ok: true},
		{name: "the same event twice", in: "DELAY,DELAY", want: DSNNotifyDelay, ok: true},
		{name: "NEVER with another event", in: "NEVER,SUCCESS"},
		{name: "another event with NEVER", in: "SUCCESS,NEVER"},
		{name: "an event that RFC 3461 does not give", in: "BOUNCE"},
		{name: "an empty value", in: ""},
		{name: "an empty element", in: "SUCCESS,"},
		{name: "a space between the events", in: "SUCCESS, DELAY"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, ok := parseNotify(test.in)
			if ok != test.ok {
				t.Fatalf("parseNotify(%q) ok = %v, want %v", test.in, ok, test.ok)
			}
			if got != test.want {
				t.Errorf("parseNotify(%q) = %q, want %q", test.in, got, test.want)
			}
		})
	}
}

// TestParseORcpt covers the ORCPT parameter of RCPT TO.
func TestParseORcpt(t *testing.T) {
	tests := []struct {
		name     string
		in       string
		wantType string
		wantAddr string
		ok       bool
	}{
		{
			name:     "an address type and an address",
			in:       "rfc822;user@example.org",
			wantType: "rfc822",
			wantAddr: "user@example.org",
			ok:       true,
		},
		{
			name:     "an at sign in xtext",
			in:       "rfc822;user+40example.org",
			wantType: "rfc822",
			wantAddr: "user@example.org",
			ok:       true,
		},
		{
			name:     "a semicolon in the address",
			in:       "rfc822;a+3Bb@example.org",
			wantType: "rfc822",
			wantAddr: "a;b@example.org",
			ok:       true,
		},
		{
			name:     "an address type of another kind",
			in:       "x-unix;/var/mail/user",
			wantType: "x-unix",
			wantAddr: "/var/mail/user",
			ok:       true,
		},
		{name: "no semicolon", in: "rfc822"},
		{name: "no address type", in: ";user@example.org"},
		{name: "no address", in: "rfc822;"},
		{name: "an address type that is not an atom", in: "rfc 822;user@example.org"},
		{name: "a line break in the address", in: "rfc822;user+0D+0A"},
		{name: "an empty value", in: ""},
		{name: "one character too long", in: "rfc822;" + strings.Repeat("a", 494)},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			addrType, addr, ok := parseORcpt(test.in)
			if ok != test.ok {
				t.Fatalf("parseORcpt(%q) ok = %v, want %v", test.in, ok, test.ok)
			}
			if addrType != test.wantType || addr != test.wantAddr {
				t.Errorf("parseORcpt(%q) = %q, %q, want %q, %q", test.in, addrType, addr, test.wantType, test.wantAddr)
			}
		})
	}
}

// TestDSNNotifyString covers the form that a relay writes into a NOTIFY
// parameter of its own.
func TestDSNNotifyString(t *testing.T) {
	tests := []struct {
		in   DSNNotify
		want string
	}{
		{in: 0, want: ""},
		{in: DSNNotifyNever, want: "NEVER"},
		{in: DSNNotifySuccess, want: "SUCCESS"},
		{in: DSNNotifyFailure, want: "FAILURE"},
		{in: DSNNotifyDelay, want: "DELAY"},
		{in: DSNNotifySuccess | DSNNotifyDelay, want: "SUCCESS,DELAY"},
		{in: DSNNotifySuccess | DSNNotifyFailure | DSNNotifyDelay, want: "SUCCESS,FAILURE,DELAY"},
	}

	for _, test := range tests {
		t.Run(test.want, func(t *testing.T) {
			if got := test.in.String(); got != test.want {
				t.Errorf("DSNNotify(%d).String() = %q, want %q", test.in, got, test.want)
			}
		})
	}
}

// TestRecordRecipientDSN covers the invariant that the handler reads: index i
// of DSN.Recipients describes address i of Recipients.
func TestRecordRecipientDSN(t *testing.T) {
	notify := RecipientDSN{Notify: DSNNotifySuccess}
	orcpt := RecipientDSN{OriginalRecipient: "user@example.org", OriginalType: "rfc822"}

	tests := []struct {
		name  string
		mail  *DSN
		rcpts []RecipientDSN
		want  *DSN
	}{
		{
			name:  "no parameter at all leaves the envelope alone",
			rcpts: []RecipientDSN{{}, {}},
		},
		{
			name:  "the first recipient carries one",
			rcpts: []RecipientDSN{notify, {}},
			want:  &DSN{Recipients: []RecipientDSN{notify, {}}},
		},
		{
			name:  "a later recipient carries one",
			rcpts: []RecipientDSN{{}, {}, orcpt},
			want:  &DSN{Recipients: []RecipientDSN{{}, {}, orcpt}},
		},
		{
			name:  "MAIL FROM carried one and no recipient does",
			mail:  &DSN{EnvID: "QQ314159"},
			rcpts: []RecipientDSN{{}, {}},
			want:  &DSN{EnvID: "QQ314159", Recipients: []RecipientDSN{{}, {}}},
		},
		{
			name:  "every recipient carries one",
			mail:  &DSN{Return: DSNReturnFull},
			rcpts: []RecipientDSN{notify, orcpt},
			want:  &DSN{Return: DSNReturnFull, Recipients: []RecipientDSN{notify, orcpt}},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			env := &Envelope{Sender: "sender@example.org", DSN: test.mail}

			for i, rcpt := range test.rcpts {
				env.Recipients = append(env.Recipients, fmt.Sprintf("r%d@example.net", i))
				env.recordRecipientDSN(rcpt)
			}

			if !reflect.DeepEqual(env.DSN, test.want) {
				t.Fatalf("env.DSN = %+v, want %+v", env.DSN, test.want)
			}

			if env.DSN != nil && len(env.DSN.Recipients) != len(env.Recipients) {
				t.Errorf("the envelope holds %d recipients and %d entries, want the same count",
					len(env.Recipients), len(env.DSN.Recipients))
			}
		})
	}
}
