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
