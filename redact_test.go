package smtpd

import "testing"

// TestRedactLine covers the shapes of AUTH that carry the credentials on the
// command line, and makes sure that every other command reaches the log as it
// was received.
func TestRedactLine(t *testing.T) {
	tests := []struct {
		name string
		line string
		want string
	}{
		{
			name: "AUTH PLAIN with credentials",
			line: "AUTH PLAIN AGh1bnRlcjJ1c2VyAHN1cDNyczNjcjN0",
			want: "AUTH PLAIN [redacted]",
		},
		{
			name: "AUTH LOGIN with a user name",
			line: "AUTH LOGIN dXNlcm5hbWU=",
			want: "AUTH LOGIN [redacted]",
		},
		{
			name: "lower case verb and mechanism",
			line: "auth plain AGZvbwBiYXI=",
			want: "auth plain [redacted]",
		},
		{
			name: "extra spaces around the credentials",
			line: "AUTH  PLAIN   AGZvbwBiYXI=",
			want: "AUTH PLAIN [redacted]",
		},
		{
			name: "AUTH PLAIN without credentials keeps the line",
			line: "AUTH PLAIN",
			want: "AUTH PLAIN",
		},
		{
			name: "AUTH alone keeps the line",
			line: "AUTH",
			want: "AUTH",
		},
		{
			name: "an unknown mechanism is redacted too",
			line: "AUTH CRAM-MD5 dGVzdA==",
			want: "AUTH CRAM-MD5 [redacted]",
		},
		{
			name: "MAIL FROM is not touched",
			line: "MAIL FROM:<sender@example.org>",
			want: "MAIL FROM:<sender@example.org>",
		},
		{
			name: "AUTHENTICATE is not AUTH",
			line: "AUTHENTICATE something",
			want: "AUTHENTICATE something",
		},
		{
			name: "an empty line stays empty",
			line: "",
			want: "",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := redactLine(test.line)
			if got != test.want {
				t.Errorf("redactLine(%q) = %q, want %q", test.line, got, test.want)
			}
		})
	}
}
