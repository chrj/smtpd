package smtpd

import "testing"

// TestDecodeXtext covers the encoding that RFC 1891 defines and that XCLIENT
// uses for its attribute values.
func TestDecodeXtext(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "a value with nothing to decode",
			in:   "mail.example.com",
			want: "mail.example.com",
		},
		{
			name: "an at sign",
			in:   "user+40example.com",
			want: "user@example.com",
		},
		{
			name: "a plus sign",
			in:   "a+2Bb",
			want: "a+b",
		},
		{
			name: "an equals sign",
			in:   "a+3Db",
			want: "a=b",
		},
		{
			name: "a space",
			in:   "two+20words",
			want: "two words",
		},
		{
			name: "lower case digits",
			in:   "user+40example.com",
			want: "user@example.com",
		},
		{
			name: "lower case letters in the digits",
			in:   "a+2bb",
			want: "a+b",
		},
		{
			name: "more than one",
			in:   "a+2Bb+40c",
			want: "a+b@c",
		},
		{
			name: "at the start and at the end",
			in:   "+40middle+40",
			want: "@middle@",
		},
		{
			name: "a plus that no digits follow stands for itself",
			in:   "user+tag@example.com",
			want: "user+tag@example.com",
		},
		{
			name: "a plus at the end stands for itself",
			in:   "trailing+",
			want: "trailing+",
		},
		{
			name: "a plus with one digit stands for itself",
			in:   "short+4",
			want: "short+4",
		},
		{
			name: "a plus that one digit and one letter follow",
			in:   "mixed+4z",
			want: "mixed+4z",
		},
		{
			name: "an empty value",
			in:   "",
			want: "",
		},
		{
			name: "the mark for no information",
			in:   "[UNAVAILABLE]",
			want: "[UNAVAILABLE]",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := decodeXtext(test.in); got != test.want {
				t.Errorf("decodeXtext(%q) = %q, want %q", test.in, got, test.want)
			}
		})
	}
}

// TestIsUnavailable covers the values that say the proxy has no information.
func TestIsUnavailable(t *testing.T) {
	tests := []struct {
		in   string
		want bool
	}{
		{"[UNAVAILABLE]", true},
		{"[TEMPUNAVAIL]", true},
		{"[unavailable]", true},
		{"[TempUnavail]", true},
		{"UNAVAILABLE", false},
		{"[UNAVAILABLE", false},
		{"mail.example.com", false},
		{"", false},
	}

	for _, test := range tests {
		t.Run(test.in, func(t *testing.T) {
			if got := isUnavailable(test.in); got != test.want {
				t.Errorf("isUnavailable(%q) = %v, want %v", test.in, got, test.want)
			}
		})
	}
}

// TestParseXtext covers the strict reading of the encoding that RFC 3461
// section 4 defines and that the DSN parameters use.
func TestParseXtext(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
		ok   bool
	}{
		{name: "a value with nothing to decode", in: "QQ314159", want: "QQ314159", ok: true},
		{name: "an at sign", in: "user+40example.org", want: "user@example.org", ok: true},
		{name: "a plus sign", in: "a+2Bb", want: "a+b", ok: true},
		{name: "an equals sign", in: "a+3Db", want: "a=b", ok: true},
		{name: "a space", in: "two+20words", want: "two words", ok: true},
		{name: "lower case digits", in: "a+2bb", want: "a+b", ok: true},
		{name: "more than one", in: "a+2Bb+40c", want: "a+b@c", ok: true},
		{name: "at the start and at the end", in: "+40middle+40", want: "@middle@", ok: true},
		{name: "an empty value", in: "", want: "", ok: true},
		{name: "a plus that no digits follow", in: "user+tag"},
		{name: "a plus at the end", in: "trailing+"},
		{name: "a plus with one digit", in: "short+4"},
		{name: "a plus that one digit and one letter follow", in: "mixed+4z"},
		{name: "a bare equals sign", in: "a=b"},
		{name: "a bare space", in: "two words"},
		{name: "a tab", in: "two\twords"},
		{name: "a line break", in: "a\r\nb"},
		{name: "a byte above ASCII", in: "brugér"},
		{name: "a line break in the encoding", in: "a+0D+0A250+20injected"},
		{name: "a null byte in the encoding", in: "a+00b"},
		{name: "a byte above ASCII in the encoding", in: "a+FFb"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, ok := parseXtext(test.in)
			if ok != test.ok {
				t.Fatalf("parseXtext(%q) ok = %v, want %v", test.in, ok, test.ok)
			}
			if got != test.want {
				t.Errorf("parseXtext(%q) = %q, want %q", test.in, got, test.want)
			}
		})
	}
}
