package smtpd

import (
	"context"
	"log/slog"
)

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
