package smtpd

import (
	"fmt"
	"strconv"
	"strings"
)

// SyntaxError describes a malformed SMTP command or parameter. It is
// returned by the internal command parser and surfaces to callers only
// through test assertions today; the session layer translates it into a
// 502 reply on the wire. Line is the raw command text that failed to
// parse (empty when the input was nil); Message is a short human-readable
// reason ("missing colon", "duplicate parameter", etc.).
type SyntaxError struct {
	Line    string
	Message string
}

func (e SyntaxError) Error() string {
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
		return "", nil, SyntaxError{Message: "nil command"}
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

// parseESMTPParams reads the parameters that follow the path of a MAIL FROM
// or RCPT TO command. RFC 5321 section 4.1.2 writes a parameter as a keyword
// with an optional value after an "=" sign.
//
// A keyword that came alone gets the empty string, in the way that the
// SMTPUTF8 parameter of RFC 6531 arrives. A keyword with an "=" and nothing
// after it is an error: the grammar asks for one character or more there.
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
		if hasValue && value == "" {
			return nil, cmd.syntaxError("empty parameter value")
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
	return SyntaxError{Line: line, Message: message}
}

// bdatArg reads the arguments of a BDAT command: the length of the chunk that
// follows the command line, and the mark that says it is the last one. RFC
// 3030 writes the command as "BDAT" SP chunk-size [ SP end-marker ].
//
// sized reports whether the length of the chunk is known. A command with a
// length that reads gets an answer and keeps the session, because the server
// can still take the chunk off the wire. A command without one ends the
// session: nothing says where the chunk stops.
func (cmd *command) bdatArg() (size int64, last, sized bool, err error) {
	if cmd == nil {
		return 0, false, false, SyntaxError{Message: "nil command"}
	}

	args := cmd.args()
	if len(args) < 1 {
		return 0, false, false, cmd.syntaxError("BDAT takes a chunk size and an optional LAST")
	}

	// The length is a count of octets, so a sign has no place in it.
	// ParseUint takes none, and 63 bits keep the value inside an int64.
	value, err := strconv.ParseUint(args[0], 10, 63)
	if err != nil {
		return 0, false, false, cmd.syntaxError("invalid chunk size")
	}
	size = int64(value)

	if len(args) > 2 {
		return size, false, true, cmd.syntaxError("BDAT takes a chunk size and an optional LAST")
	}

	if len(args) == 2 {
		if !strings.EqualFold(args[1], "LAST") {
			return size, false, true, cmd.syntaxError("invalid end marker")
		}
		last = true
	}

	return size, last, true, nil
}
