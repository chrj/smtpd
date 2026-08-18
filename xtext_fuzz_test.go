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
