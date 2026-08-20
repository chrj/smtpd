package smtpd

import "testing"

// TestVerifyLine covers the text of a 250 reply to a VRFY command. RFC 5321
// section 3.5.1 gives the mailbox in angle brackets, with the name of the
// user before it.
func TestVerifyLine(t *testing.T) {
	tests := []struct {
		name     string
		fullName string
		mailbox  string
		want     string
	}{
		{
			name:    "a mailbox alone",
			mailbox: "user@example.org",
			want:    "<user@example.org>",
		},
		{
			name:     "a mailbox with the name of the user",
			fullName: "Jörg Smith",
			mailbox:  "jörg@example.org",
			want:     "Jörg Smith <jörg@example.org>",
		},
		{
			name:     "a name of spaces alone",
			fullName: "   ",
			mailbox:  "user@example.org",
			want:     "<user@example.org>",
		},
		{
			name:     "spaces around the name",
			fullName: "  Joe  ",
			mailbox:  "user@example.org",
			want:     "Joe <user@example.org>",
		},
		{
			name:     "a name that carries an address of its own",
			fullName: "Joe <other@example.net>",
			mailbox:  "user@example.org",
			want:     "Joe other@example.net <user@example.org>",
		},
		{
			name:    "a local part in quotes",
			mailbox: `"a b"@example.org`,
			want:    `<"a b"@example.org>`,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := verifyLine(test.fullName, test.mailbox); got != test.want {
				t.Errorf("verifyLine(%q, %q) = %q, want %q", test.fullName, test.mailbox, got, test.want)
			}
		})
	}
}
