package smtpd

import (
	"errors"
	"testing"
)

func TestParseCommand(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		line       string
		wantAction string
		wantArg    string
	}{
		{name: "single word", line: "DATA", wantAction: "DATA"},
		{name: "simple arg", line: "HELO hostname", wantAction: "HELO", wantArg: "hostname"},
		{name: "leading whitespace", line: "\t  EHLO example.net", wantAction: "EHLO", wantArg: "example.net"},
		{
			name:       "mail with esmtp params",
			line:       "MAIL FROM:<test@example.org> SIZE=123 BODY=8BITMIME",
			wantAction: "MAIL",
			wantArg:    "FROM:<test@example.org> SIZE=123 BODY=8BITMIME",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			cmd, err := parseCommand(tt.line)
			if err != nil {
				t.Fatalf("parseCommand returned error: %v", err)
			}
			if cmd.action != tt.wantAction {
				t.Fatalf("action = %q, want %q", cmd.action, tt.wantAction)
			}
			if cmd.arg != tt.wantArg {
				t.Fatalf("arg = %q, want %q", cmd.arg, tt.wantArg)
			}
		})
	}
}

func TestCommandPathArg(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		arg        string
		keyword    string
		wantPath   string
		wantParams map[string]string
	}{
		{
			name:     "mail with params",
			arg:      "FROM: <test@example.org> SIZE=123 BODY=8BITMIME AUTH=<>",
			keyword:  "FROM",
			wantPath: "<test@example.org>",
			wantParams: map[string]string{
				"SIZE": "123",
				"BODY": "8BITMIME",
				"AUTH": "<>",
			},
		},
		{
			name:       "null sender",
			arg:        "FROM: <>",
			keyword:    "FROM",
			wantPath:   "<>",
			wantParams: nil,
		},
		{
			name:       "bare path",
			arg:        "TO: recipient@example.net",
			keyword:    "TO",
			wantPath:   "recipient@example.net",
			wantParams: nil,
		},
		{
			name:     "a parameter without a value",
			arg:      "FROM: <test@example.org> SMTPUTF8 BODY=8BITMIME",
			keyword:  "FROM",
			wantPath: "<test@example.org>",
			wantParams: map[string]string{
				"SMTPUTF8": "",
				"BODY":     "8BITMIME",
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			cmd := &command{arg: tt.arg}
			path, params, err := cmd.pathArg(tt.keyword)
			if err != nil {
				t.Fatalf("pathArg returned error: %v", err)
			}
			if path != tt.wantPath {
				t.Fatalf("path = %q, want %q", path, tt.wantPath)
			}
			if len(params) != len(tt.wantParams) {
				t.Fatalf("len(params) = %d, want %d", len(params), len(tt.wantParams))
			}
			for name, want := range tt.wantParams {
				if got := params[name]; got != want {
					t.Fatalf("%s = %q, want %q", name, got, want)
				}
			}
		})
	}
}

func TestCommandPathArgRejectsInvalidInput(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		arg  string
	}{
		{name: "missing colon", arg: "FROM <test@example.org>"},
		{name: "missing path", arg: "FROM:"},
		{name: "unterminated path", arg: "FROM:<test@example.org"},
		{name: "empty parameter value", arg: "FROM:<test@example.org> SIZE="},
		{name: "duplicate parameter", arg: "FROM:<test@example.org> SIZE=1 SIZE=2"},
		{name: "missing keyword", arg: "TO:<test@example.org>"},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			cmd := &command{line: tt.arg, arg: tt.arg}
			_, _, err := cmd.pathArg("FROM")
			if err == nil {
				t.Fatal("expected pathArg to fail")
			}
			var syntaxErr SyntaxError
			if !errors.As(err, &syntaxErr) {
				t.Fatalf("error type = %T, want SyntaxError", err)
			}
			if syntaxErr.Line != tt.arg {
				t.Fatalf("syntaxErr.Line = %q, want %q", syntaxErr.Line, tt.arg)
			}
		})
	}
}

// TestCommandVrfyArg covers the argument of a VRFY command. RFC 6531 section
// 3.7.4.2 writes it as "VRFY" SP String [ SP "SMTPUTF8" ].
func TestCommandVrfyArg(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		arg       string
		extension bool
		wantName  string
		wantParam bool
	}{
		{
			name:     "a name alone",
			arg:      "Crispin",
			wantName: "Crispin",
		},
		{
			name:      "the parameter",
			arg:       "Crispin SMTPUTF8",
			extension: true,
			wantName:  "Crispin",
			wantParam: true,
		},
		{
			name:      "the parameter in lower case",
			arg:       "Crispin smtputf8",
			extension: true,
			wantName:  "Crispin",
			wantParam: true,
		},
		{
			name:      "a name that carries a space",
			arg:       "Sam Q. Smith SMTPUTF8",
			extension: true,
			wantName:  "Sam Q. Smith",
			wantParam: true,
		},
		{
			name:      "spaces around the parameter",
			arg:       "  Crispin   SMTPUTF8  ",
			extension: true,
			wantName:  "Crispin",
			wantParam: true,
		},
		{
			// The String of the command takes any form that the site knows,
			// so a user of that name is one of them.
			name:      "the parameter without a name",
			arg:       "SMTPUTF8",
			extension: true,
			wantName:  "SMTPUTF8",
		},
		{
			name:      "the parameter twice",
			arg:       "Crispin SMTPUTF8 SMTPUTF8",
			extension: true,
			wantName:  "Crispin SMTPUTF8",
			wantParam: true,
		},
		{
			// A server that does not offer the extension knows no such
			// parameter, so the word belongs to the name.
			name:     "the parameter without the extension",
			arg:      "Crispin SMTPUTF8",
			wantName: "Crispin SMTPUTF8",
		},
		{
			name:      "a word of another kind",
			arg:       "Crispin UTF8",
			extension: true,
			wantName:  "Crispin UTF8",
		},
		{
			name:      "no argument",
			arg:       "",
			extension: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			cmd := &command{action: "VRFY", arg: test.arg}
			name, param := cmd.vrfyArg(test.extension)
			if name != test.wantName || param != test.wantParam {
				t.Errorf("vrfyArg(%q, %v) = %q, %v, want %q, %v",
					test.arg, test.extension, name, param, test.wantName, test.wantParam)
			}
		})
	}
}

func TestCommandSingleArg(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		arg    string
		want   string
		wantOK bool
	}{
		{name: "one arg", arg: "example.net", want: "example.net", wantOK: true},
		{name: "no args", arg: "", wantOK: false},
		{name: "too many args", arg: "one two", wantOK: false},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			cmd := &command{arg: tt.arg}
			got, ok := cmd.singleArg()
			if ok != tt.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tt.wantOK)
			}
			if got != tt.want {
				t.Fatalf("got = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestBdatArg covers the arguments of the BDAT command of RFC 3030.
func TestBdatArg(t *testing.T) {
	tests := []struct {
		name      string
		arg       string
		wantSize  int64
		wantLast  bool
		wantSized bool
		wantErr   bool
	}{
		{name: "a chunk", arg: "1024", wantSize: 1024, wantSized: true},
		{name: "the last chunk", arg: "1024 LAST", wantSize: 1024, wantLast: true, wantSized: true},
		{name: "the mark in lower case", arg: "7 last", wantSize: 7, wantLast: true, wantSized: true},
		{name: "an empty last chunk", arg: "0 LAST", wantSize: 0, wantLast: true, wantSized: true},
		{name: "no argument", arg: "", wantErr: true},
		{name: "a size that is not a number", arg: "big", wantErr: true},
		{name: "a negative size", arg: "-1", wantErr: true},
		{name: "a size with a sign", arg: "+1", wantErr: true},
		{name: "a size that does not fit", arg: "99999999999999999999", wantErr: true},

		// The length reads in these two, so the server can still take the
		// chunk off the wire and keep the session.
		{name: "a mark of another kind", arg: "10 FIRST", wantSize: 10, wantSized: true, wantErr: true},
		{name: "three arguments", arg: "10 LAST LAST", wantSize: 10, wantSized: true, wantErr: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cmd := &command{action: "BDAT", arg: test.arg}

			size, last, sized, err := cmd.bdatArg()
			if (err != nil) != test.wantErr {
				t.Fatalf("bdatArg() error = %v, wantErr %v", err, test.wantErr)
			}
			if sized != test.wantSized {
				t.Errorf("bdatArg() sized = %v, want %v", sized, test.wantSized)
			}
			if size != test.wantSize || last != test.wantLast {
				t.Errorf("bdatArg() = %d, %v, want %d, %v", size, last, test.wantSize, test.wantLast)
			}
		})
	}
}
