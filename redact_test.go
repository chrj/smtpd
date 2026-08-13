package smtpd

import (
	"slices"
	"testing"
)

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
			name: "tabs between the parts",
			line: "AUTH\tPLAIN\tAGZvbwBiYXI=",
			want: "AUTH PLAIN [redacted]",
		},
		{
			name: "more parts than the mechanism takes",
			line: "AUTH PLAIN AGZvbwBiYXI= extra",
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

// FuzzRedactLine holds redaction to the view of the command parser. The
// parser reads some lines as AUTH with a mechanism and one or more parts
// after it. Those parts are the credentials. The line that reaches the log
// must carry the mechanism and the mark, and nothing else.
//
// The test compares the parts that the parser reads, not substrings. A
// credential of one or two characters can also appear inside the name of the
// mechanism.
func FuzzRedactLine(f *testing.F) {
	f.Add("AUTH PLAIN AGZvbwBiYXI=")
	f.Add("AUTH\tPLAIN\tAGZvbwBiYXI=")
	f.Add("AUTH  LOGIN   dXNlcm5hbWU=")
	f.Add("auth plain AGZvbwBiYXI=")
	f.Add("AUTH PLAIN")
	f.Add("MAIL FROM:<sender@example.org>")

	f.Fuzz(func(t *testing.T, line string) {
		cmd, err := parseCommand(line)
		if err != nil || cmd.action != "AUTH" {
			return
		}

		args := cmd.args()
		if len(args) < 2 {
			// Nothing comes after the mechanism, so the line carries no
			// credentials. The other form of AUTH sends the credentials on
			// their own lines. The session never logs those lines.
			return
		}

		redactedLine := redactLine(line)

		out, err := parseCommand(redactedLine)
		if err != nil {
			t.Fatalf("redactLine(%q) = %q, which does not parse: %v", line, redactedLine, err)
		}

		want := []string{args[0], redacted}
		if got := out.args(); !slices.Equal(got, want) {
			t.Fatalf("redactLine(%q) = %q, with the parts %q, want %q", line, redactedLine, got, want)
		}
	})
}
