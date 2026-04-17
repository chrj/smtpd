package smtpd

import (
	"fmt"
	"strings"
)

type ErrCommandSyntax struct {
	Line    string
	Message string
}

func (e ErrCommandSyntax) Error() string {
	if e.Message == "" {
		return fmt.Sprintf("smtpd: command syntax error: %q", e.Line)
	}
	return fmt.Sprintf("smtpd: command syntax error: %s: %q", e.Message, e.Line)
}

type command struct {
	line   string
	action string
	arg    string
}

func parseCommand(line string) (*command, error) {
	cmd := &command{line: line}

	line = strings.TrimLeft(line, " \t")
	if line == "" {
		return cmd, nil
	}

	if i := strings.IndexAny(line, " \t"); i >= 0 {
		cmd.action = strings.ToUpper(line[:i])
		cmd.arg = strings.TrimLeft(line[i+1:], " \t")
		return cmd, nil
	}

	cmd.action = strings.ToUpper(line)
	return cmd, nil
}

func (cmd *command) args() []string {
	if cmd == nil || cmd.arg == "" {
		return nil
	}
	return strings.Fields(cmd.arg)
}

func (cmd *command) singleArg() (string, bool) {
	fields := cmd.args()
	if len(fields) != 1 {
		return "", false
	}
	return fields[0], true
}

func (cmd *command) pathArg(keyword string) (path string, params map[string]string, err error) {
	if cmd == nil {
		return "", nil, ErrCommandSyntax{Message: "nil command"}
	}

	arg := strings.TrimLeft(cmd.arg, " \t")
	if !strings.HasPrefix(strings.ToUpper(arg), keyword) {
		return "", nil, cmd.syntaxError(fmt.Sprintf("missing %s", keyword))
	}

	rest := strings.TrimLeft(arg[len(keyword):], " \t")
	if !strings.HasPrefix(rest, ":") {
		return "", nil, cmd.syntaxError("missing colon")
	}
	rest = strings.TrimLeft(rest[1:], " \t")
	if rest == "" {
		return "", nil, cmd.syntaxError("missing path")
	}

	path, rest, ok := cmd.parsePath(rest)
	if !ok {
		return "", nil, cmd.syntaxError("invalid path")
	}

	params, err = cmd.parseESMTPParams(rest)
	if err != nil {
		return "", nil, err
	}

	return path, params, nil
}

func (cmd *command) parsePath(src string) (path, rest string, ok bool) {
	if src == "" {
		return "", "", false
	}

	if src[0] == '<' {
		end := strings.IndexByte(src, '>')
		if end < 0 {
			return "", "", false
		}
		path = src[:end+1]
		rest = src[end+1:]
		if rest != "" && !cmd.isWhitespace(rest[0]) {
			return "", "", false
		}
		return path, rest, true
	}

	if i := strings.IndexAny(src, " \t"); i >= 0 {
		return src[:i], src[i:], true
	}

	return src, "", true
}

func (cmd *command) parseESMTPParams(src string) (map[string]string, error) {
	src = strings.TrimSpace(src)
	if src == "" {
		return nil, nil
	}

	params := make(map[string]string)
	for _, field := range strings.Fields(src) {
		name, value, hasValue := strings.Cut(field, "=")
		if name == "" {
			return nil, cmd.syntaxError("empty parameter")
		}
		name = strings.ToUpper(name)
		if _, dup := params[name]; dup {
			return nil, cmd.syntaxError("duplicate parameter")
		}
		if !hasValue || value == "" {
			return nil, cmd.syntaxError("missing parameter value")
		}
		params[name] = value
	}
	return params, nil
}

func (cmd *command) isWhitespace(b byte) bool {
	return b == ' ' || b == '\t'
}

func (cmd *command) syntaxError(message string) error {
	line := ""
	if cmd != nil {
		line = cmd.line
		if line == "" {
			line = cmd.arg
		}
	}
	return ErrCommandSyntax{Line: line, Message: message}
}
