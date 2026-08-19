package smtpd

import (
	"strings"
	"testing"
)

// FuzzDecodeXtext runs the xtext decoder over an XCLIENT attribute value. It
// holds three properties:
//
//   - The decoder never panics.
//   - The result is never longer than the value.
//   - A value without a plus sign comes back as it was.
//
// The second property bounds the memory that one command can take. The third
// keeps the decoder away from a value that carries no encoding, which is what
// a proxy that does not encode its values sends.
func FuzzDecodeXtext(f *testing.F) {
	f.Add("192.0.2.2")
	f.Add("user+2Bname")
	f.Add("+2B+2B+2B")
	f.Add("+")
	f.Add("++")
	f.Add("+2")
	f.Add("+zz")
	f.Add("+0D+0A250+20injected")
	f.Add("[UNAVAILABLE]")
	f.Add("")

	f.Fuzz(func(t *testing.T, value string) {
		got := decodeXtext(value)

		if len(got) > len(value) {
			t.Fatalf("decodeXtext(%q) gave %q, which is longer than the value", value, got)
		}

		if !strings.Contains(value, "+") && got != value {
			t.Fatalf("decodeXtext(%q) gave %q, and the value carries no plus sign", value, got)
		}
	})
}

// FuzzParseXtext runs the strict xtext reader over the value of a DSN
// parameter. It holds three properties:
//
//   - The reader never panics.
//   - The result is never longer than the value.
//   - The result carries printable US-ASCII only.
//
// The third property is the one that keeps the value inside its command. A
// relay writes an ENVID or an ORCPT that it took here into a command of its
// own, and a line break there would end that command.
func FuzzParseXtext(f *testing.F) {
	f.Add("QQ314159")
	f.Add("user+40example.org")
	f.Add("a+2Bb")
	f.Add("+")
	f.Add("++")
	f.Add("+2")
	f.Add("+zz")
	f.Add("a+0D+0A250+20injected")
	f.Add("a+FFb")
	f.Add("a=b")
	f.Add("")

	f.Fuzz(func(t *testing.T, value string) {
		got, ok := parseXtext(value)
		if !ok {
			if got != "" {
				t.Fatalf("parseXtext(%q) refused the value and gave %q, want an empty string", value, got)
			}
			return
		}

		if len(got) > len(value) {
			t.Fatalf("parseXtext(%q) gave %q, which is longer than the value", value, got)
		}

		for i := 0; i < len(got); i++ {
			if got[i] < ' ' || got[i] > '~' {
				t.Fatalf("parseXtext(%q) gave %q, which carries the byte %#x", value, got, got[i])
			}
		}
	})
}
