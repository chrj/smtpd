package smtpd

import (
	"strings"
	"testing"
)

// FuzzParseCommand runs the command parser over a line of bytes. It holds
// the properties that the rest of the session depends on:
//
//   - The parser never panics.
//   - The verb is upper case and carries no space.
//   - The argument has no space at the front.
//
// A verb with a space in it reaches the switch in handle and matches
// nothing, so the session answers 500 to a command that it must run.
func FuzzParseCommand(f *testing.F) {
	f.Add("EHLO relay.example.org")
	f.Add("mail from:<a@example.org> SIZE=100 BODY=8BITMIME")
	f.Add("RCPT\tTO:<b@example.net>")
	f.Add("   MAIL   FROM:   <a@example.org>   ")
	f.Add("AUTH PLAIN AGZvbwBiYXI=")
	f.Add("XCLIENT ADDR=192.0.2.2 PORT=2525")
	f.Add("")
	f.Add("MAIL FROM:<")
	f.Add("MAIL FROM:<a@b>trailing")

	f.Fuzz(func(t *testing.T, line string) {
		cmd, err := parseCommand(line)
		if err != nil {
			t.Fatalf("parseCommand(%q) returned an error, which it never does: %v", line, err)
		}
		if cmd == nil {
			t.Fatalf("parseCommand(%q) returned no command", line)
		}

		if strings.ContainsAny(cmd.action, " \t") {
			t.Errorf("parseCommand(%q) gave the verb %q, which carries a space", line, cmd.action)
		}

		if cmd.action != strings.ToUpper(cmd.action) {
			t.Errorf("parseCommand(%q) gave the verb %q, which is not upper case", line, cmd.action)
		}

		if strings.HasPrefix(cmd.arg, " ") || strings.HasPrefix(cmd.arg, "\t") {
			t.Errorf("parseCommand(%q) gave the argument %q, which starts with a space", line, cmd.arg)
		}
	})
}

// FuzzPathArg runs the parser of a MAIL FROM and RCPT TO argument. It holds
// the properties that handleMAIL and handleRCPT depend on:
//
//   - The parser never panics.
//   - A path that starts with "<" also ends with ">".
//   - A path without those marks carries no space.
//   - Every parameter has an upper case name.
//   - No parameter carries a space in its name or its value.
//
// A path that keeps a space reaches parseAddress, and a parameter name in
// lower case misses the switch in validateMailParams. A parameter with an
// empty value is one that came without an "=" sign, which is how the
// SMTPUTF8 parameter of RFC 6531 arrives.
func FuzzPathArg(f *testing.F) {
	f.Add("MAIL", "FROM:<a@example.org>")
	f.Add("MAIL", "FROM:<a@example.org> SIZE=100")
	f.Add("MAIL", "from:a@example.org body=8bitmime")
	f.Add("RCPT", "TO:<b@example.net>")
	f.Add("RCPT", "TO:<b@example.net> NOTIFY=SUCCESS")
	f.Add("MAIL", "FROM:<>")
	f.Add("MAIL", "FROM:<a b@example.org> SIZE=1 SIZE=2")
	f.Add("MAIL", "FROM:")

	f.Fuzz(func(t *testing.T, keyword, arg string) {
		// The keyword comes from the caller, never from the client. A
		// fuzzed one only widens the shapes that reach parsePath.
		if keyword == "" {
			t.Skip("the callers pass FROM or TO")
		}

		cmd := &command{line: keyword + " " + arg, action: keyword, arg: arg}

		path, params, err := cmd.pathArg(keyword)
		if err != nil {
			return
		}

		if path == "" {
			t.Fatalf("pathArg(%q, %q) gave no error and an empty path", keyword, arg)
		}

		if strings.HasPrefix(path, "<") {
			if !strings.HasSuffix(path, ">") {
				t.Errorf("pathArg(%q, %q) gave the path %q, which opens with < and does not close", keyword, arg, path)
			}
		} else if strings.ContainsAny(path, " \t") {
			t.Errorf("pathArg(%q, %q) gave the path %q, which carries a space", keyword, arg, path)
		}

		for name, value := range params {
			if name == "" {
				t.Errorf("pathArg(%q, %q) gave a parameter with an empty name", keyword, arg)
			}
			if name != strings.ToUpper(name) {
				t.Errorf("pathArg(%q, %q) gave the parameter name %q, which is not upper case", keyword, arg, name)
			}
			if strings.ContainsAny(name+value, " \t") {
				t.Errorf("pathArg(%q, %q) gave the parameter %q=%q, which carries a space", keyword, arg, name, value)
			}
		}
	})
}
