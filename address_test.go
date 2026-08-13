package smtpd

import (
	"slices"
	"strings"
	"testing"
)

// TestParseAddress covers the forms of an address that reach MAIL FROM and
// RCPT TO. Each address that parses must come back in a form that goes on the
// wire again. A relay writes the value of Envelope.Sender and
// Envelope.Recipients into a command of its own.
func TestParseAddress(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		src     string
		want    string
		wantErr bool
	}{
		{name: "bare address", src: "user@example.org", want: "user@example.org"},
		{name: "angle brackets", src: "<user@example.org>", want: "user@example.org"},
		{name: "display name", src: `"User" <user@example.org>`, want: "user@example.org"},
		{name: "address literal", src: "<user@[192.0.2.1]>", want: "user@[192.0.2.1]"},
		{name: "dots in the local part", src: "<first.last@example.org>", want: "first.last@example.org"},
		{name: "utf-8 local part stays as it is", src: "<üser@example.org>", want: "üser@example.org"},
		{
			name: "a space in the local part keeps its quoting",
			src:  `<"a b"@example.org>`,
			want: `"a b"@example.org`,
		},
		{
			name: "an at sign in the local part keeps its quoting",
			src:  `<"@"@example.org>`,
			want: `"@"@example.org`,
		},
		{
			name: "a lone space is a local part of its own",
			src:  `<" "@example.org>`,
			want: `" "@example.org`,
		},
		{
			name: "a quote in the local part stays escaped",
			src:  `<"a\"b"@example.org>`,
			want: `"a\"b"@example.org`,
		},
		{
			name: "a backslash in the local part stays escaped",
			src:  `<"a\\b"@example.org>`,
			want: `"a\\b"@example.org`,
		},
		{name: "not an address", src: "not an address", wantErr: true},
		{name: "empty", src: "", wantErr: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			got, err := parseAddress(test.src)
			if test.wantErr {
				if err == nil {
					t.Fatalf("parseAddress(%q) = %q, want an error", test.src, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseAddress(%q): %v", test.src, err)
			}
			if got != test.want {
				t.Fatalf("parseAddress(%q) = %q, want %q", test.src, got, test.want)
			}

			again, err := parseAddress(got)
			if err != nil {
				t.Fatalf("parseAddress(%q) gave %q, which does not parse: %v", test.src, got, err)
			}
			if again != got {
				t.Fatalf("parseAddress(%q) = %q, which parses to %q", got, again, got)
			}
		})
	}
}

// FuzzParseAddress holds the two properties that a caller depends on. The
// address that comes back parses to itself, so a relay can write it into a
// command. It carries no line break, so it cannot add a command of its own to
// the session of that relay.
func FuzzParseAddress(f *testing.F) {
	f.Add("user@example.org")
	f.Add("<user@example.org>")
	f.Add(`"User" <user@example.org>`)
	f.Add(`<"a b"@example.org>`)
	f.Add(`<"@"@example.org>`)
	f.Add("<user@[192.0.2.1]>")
	f.Add("<üser@example.org>")

	f.Fuzz(func(t *testing.T, src string) {
		addr, err := parseAddress(src)
		if err != nil {
			return
		}

		if strings.ContainsAny(addr, "\r\n") {
			t.Fatalf("parseAddress(%q) = %q, which carries a line break", src, addr)
		}

		again, err := parseAddress(addr)
		if err != nil {
			t.Fatalf("parseAddress(%q) = %q, which does not parse: %v", src, addr, err)
		}
		if again != addr {
			t.Fatalf("parseAddress(%q) = %q, which parses to %q", src, addr, again)
		}
	})
}

// TestQuoteLocalPart covers the shapes that decide whether the local part
// needs quoting, without the address parser in front of it.
func TestQuoteLocalPart(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		addr string
		want string
	}{
		{name: "dot-atom stays as it is", addr: "user@example.org", want: "user@example.org"},
		{name: "every atext character", addr: "!#$%&'*+-/=?^_`{|}~@example.org", want: "!#$%&'*+-/=?^_`{|}~@example.org"},
		{name: "utf-8 stays as it is", addr: "üser@example.org", want: "üser@example.org"},
		{name: "a space is quoted", addr: "a b@example.org", want: `"a b"@example.org`},
		{name: "a leading dot is quoted", addr: ".user@example.org", want: `".user"@example.org`},
		{name: "a trailing dot is quoted", addr: "user.@example.org", want: `"user."@example.org`},
		{name: "two dots are quoted", addr: "a..b@example.org", want: `"a..b"@example.org`},
		{name: "an empty local part is quoted", addr: "@example.org", want: `""@example.org`},
		{name: "a quote is escaped", addr: `a"b@example.org`, want: `"a\"b"@example.org`},
		{name: "a backslash is escaped", addr: `a\b@example.org`, want: `"a\\b"@example.org`},
		{name: "the last at sign separates the parts", addr: "a@b@example.org", want: `"a@b"@example.org`},
		{name: "no at sign at all", addr: "example.org", want: "example.org"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			if got := quoteLocalPart(test.addr); got != test.want {
				t.Fatalf("quoteLocalPart(%q) = %q, want %q", test.addr, got, test.want)
			}
		})
	}
}

// TestParseAddressRejectsALineBreak makes sure the guard on the result holds,
// whatever the address parser accepts.
func TestParseAddressRejectsALineBreak(t *testing.T) {
	t.Parallel()

	for _, src := range []string{"<a\rb@example.org>", "<a\nb@example.org>", "<\"a\r\nb\"@example.org>"} {
		if got, err := parseAddress(src); err == nil {
			t.Errorf("parseAddress(%q) = %q, want an error", src, got)
		}
	}
}

// atextCharacters is the set that isAtext accepts beyond the letters, the
// digits and the bytes above ASCII. RFC 5321 calls it atext.
var atextCharacters = []byte("!#$%&'*+-/=?^_`{|}~")

// TestIsAtext pins the set of characters that need no quoting.
func TestIsAtext(t *testing.T) {
	t.Parallel()

	for c := range 128 {
		letter := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
		digit := c >= '0' && c <= '9'
		want := letter || digit || slices.Contains(atextCharacters, byte(c))

		if got := isAtext(byte(c)); got != want {
			t.Errorf("isAtext(%q) = %v, want %v", rune(c), got, want)
		}
	}

	// RFC 6531 adds every byte above ASCII, so a UTF-8 local part needs no
	// quoting.
	for c := 128; c < 256; c++ {
		if !isAtext(byte(c)) {
			t.Errorf("isAtext(%#x) = false, want true", c)
		}
	}
}
