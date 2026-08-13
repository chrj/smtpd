package smtpd

import (
	"context"
	"log/slog"
	"strings"
)

// redacted replaces the credentials of an AUTH command in the log.
const redacted = "[redacted]"

// redactLine removes the credentials from a line before it goes to the log.
// The inline forms of AUTH carry them on the command line:
//
//	AUTH PLAIN <base64 of the user name and the password>
//	AUTH LOGIN <base64 of the user name>
//
// Everything after the mechanism is replaced. The verb and the mechanism stay,
// so an operator can still see that a client tried to authenticate. A line
// that is not an AUTH command is returned as it was received.
//
// The other form of AUTH sends the credentials on their own lines, after a 334
// reply. The session reads those lines directly, and they never reach the log.
//
// strings.Fields cuts the line into parts. It breaks on every kind of space,
// and the command parser breaks the verb on a space or a tab only. The parts
// here are therefore never fewer than the parts that the parser reads. A line
// that the parser takes as AUTH is always redacted. A line that it does not
// take as AUTH is redacted for nothing at worst.
func redactLine(line string) string {
	line = strings.TrimSpace(line)

	// A line with credentials has three parts: the verb, the mechanism, and
	// the credentials. With fewer parts, the line carries no credentials.
	fields := strings.Fields(line)
	if len(fields) < 3 || !strings.EqualFold(fields[0], "AUTH") {
		return line
	}

	return fields[0] + " " + fields[1] + " " + redacted
}

type contextKey string

const (
	// loggerKey holds the session logger, without a phase attribute.
	loggerKey contextKey = "smtpd-logger"

	// phasedLoggerKey holds the session logger tagged with the phase
	// currently being executed.
	phasedLoggerKey contextKey = "smtpd-phased-logger"
)

// LoggerFromContext returns the logger associated with the context, tagged
// with the SMTP phase currently being executed.
// If no logger is found, it returns a default slog.DiscardHandler.
func LoggerFromContext(ctx context.Context) *slog.Logger {
	if l, ok := ctx.Value(phasedLoggerKey).(*slog.Logger); ok {
		return l
	}
	return sessionLoggerFromContext(ctx)
}

// sessionLoggerFromContext returns the session logger without a phase
// attribute, so that each phase tags a fresh one.
func sessionLoggerFromContext(ctx context.Context) *slog.Logger {
	if l, ok := ctx.Value(loggerKey).(*slog.Logger); ok {
		return l
	}
	return slog.New(slog.DiscardHandler)
}

func contextWithLogger(ctx context.Context, logger *slog.Logger) context.Context {
	return context.WithValue(ctx, loggerKey, logger)
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
	logger := sessionLoggerFromContext(ctx).With("phase", phase)
	return context.WithValue(ctx, phasedLoggerKey, logger), logger
}
