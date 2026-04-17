package smtpd

import (
	"errors"
	"testing"
)

func TestParseCommand(t *testing.T) {
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
		t.Run(tt.name, func(t *testing.T) {
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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
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
	tests := []struct {
		name string
		arg  string
	}{
		{name: "missing colon", arg: "FROM <test@example.org>"},
		{name: "missing path", arg: "FROM:"},
		{name: "unterminated path", arg: "FROM:<test@example.org"},
		{name: "missing parameter value", arg: "FROM:<test@example.org> SIZE"},
		{name: "empty parameter value", arg: "FROM:<test@example.org> SIZE="},
		{name: "duplicate parameter", arg: "FROM:<test@example.org> SIZE=1 SIZE=2"},
		{name: "missing keyword", arg: "TO:<test@example.org>"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := &command{line: tt.arg, arg: tt.arg}
			_, _, err := cmd.pathArg("FROM")
			if err == nil {
				t.Fatal("expected pathArg to fail")
			}
			var syntaxErr ErrCommandSyntax
			if !errors.As(err, &syntaxErr) {
				t.Fatalf("error type = %T, want ErrCommandSyntax", err)
			}
			if syntaxErr.Line != tt.arg {
				t.Fatalf("syntaxErr.Line = %q, want %q", syntaxErr.Line, tt.arg)
			}
		})
	}
}

func TestCommandSingleArg(t *testing.T) {
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
		t.Run(tt.name, func(t *testing.T) {
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
