package smtpd

import (
	"context"
	"log/slog"
	"strings"
)

// redacted stands in the log for what the server keeps out of it: the
// credentials of an AUTH command, and a line that is no command of the server.
const redacted = "[redacted]"

// knownCommands holds the verbs that handle runs. A line with another verb is
// no command of the server, and it reaches the log as redacted.
//
// The set and the switch of handle are two lists, and
// TestKnownCommandsRunInTheSession holds that the server takes every verb of
// the set. A verb that the switch gains and the set lacks reaches the log as
// redacted, which hides a line and leaks nothing.
var knownCommands = map[string]bool{
	"PROXY": true, "HELO": true, "EHLO": true, "LHLO": true,
	"MAIL": true, "RCPT": true, "STARTTLS": true, "DATA": true,
	"BDAT": true, "RSET": true, "NOOP": true, "VRFY": true,
	"QUIT": true, "AUTH": true, "XCLIENT": true,
}

// authRefusedLines is the number of lines after a refused AUTH command that
// reach the log as redacted. PLAIN sends its credentials on one line after
// the 334, and LOGIN on two.
const authRefusedLines = 2

// logLine gives the form of a line that goes to the log. The lines right
// after an AUTH command that the server refused before its 334 are redacted
// whatever they read as, because a line of base64 can read as a command of
// the server. Every other line goes through redactLine.
func (s *session) logLine(line string) string {
	if s.redactNext > 0 {
		s.redactNext--
		return redacted
	}
	return redactLine(line)
}

// redactLine removes the credentials from a line before it goes to the log.
// The inline forms of AUTH carry them on the command line:
//
//	AUTH PLAIN <base64 of the user name and the password>
//	AUTH LOGIN <base64 of the user name>
//
// Everything after the mechanism is replaced. The verb and the mechanism stay,
// so an operator can still see that a client tried to authenticate.
//
// The other form of AUTH sends the credentials on their own lines, after a 334
// reply. The session reads those lines directly, and they never reach the log.
// A client whose AUTH the server refused before the 334 can still send them,
// and the session reads them as commands. A line whose verb the server does
// not know is therefore replaced as a whole. The verb is read as the command
// parser reads it.
//
// strings.Fields cuts the line into parts. It breaks on every kind of space,
// and the command parser breaks the verb on a space or a tab only. The parts
// here are therefore never fewer than the parts that the parser reads. A line
// that the parser takes as AUTH is always redacted. A line that it does not
// take as AUTH is redacted for nothing at worst.
func redactLine(line string) string {
	// The verb comes from the line as handle gets it. The command parser trims
	// spaces and tabs alone, so a line that starts with another kind of space
	// is no command of the server, and the trimmed form would hide that.
	cmd, err := parseCommand(line)

	line = strings.TrimSpace(line)
	if line == "" {
		return line
	}

	if err != nil || !knownCommands[cmd.action] {
		return redacted
	}

	// A line with credentials has three parts: the verb, the mechanism, and
	// the credentials. With fewer parts, the line carries no credentials.
	fields := strings.Fields(line)
	if len(fields) < 3 || !strings.EqualFold(fields[0], "AUTH") {
		return line
	}

	return fields[0] + " " + fields[1] + " " + redacted
}

// LoggerFromContext returns the logger associated with the context, tagged
// with the SMTP phase currently being executed.
// If no logger is found, it returns a default slog.DiscardHandler.
func LoggerFromContext(ctx context.Context) *slog.Logger {
	values := sessionValuesFrom(ctx)
	if values.phased != nil {
		return values.phased
	}
	return values.sessionLogger()
}

func contextWithLogger(ctx context.Context, logger *slog.Logger) context.Context {
	values := sessionValuesFrom(ctx)
	values.logger = logger
	return withSessionValues(ctx, values)
}

func (srv *Server) newLogger() *slog.Logger {
	if srv.Logger != nil {
		return srv.Logger
	}
	return slog.New(slog.DiscardHandler)
}

// phasedLoggerFromContext derives a logger tagged with phase from the session
// logger, and returns it along with a context carrying it. Deriving from the
// session logger rather than from the logger of the previous phase keeps a
// single phase attribute on the logger as the session moves between phases.
func phasedLoggerFromContext(ctx context.Context, phase string) (context.Context, *slog.Logger) {
	values := sessionValuesFrom(ctx)
	values.phased = values.sessionLogger().With("phase", phase)
	return withSessionValues(ctx, values), values.phased
}
