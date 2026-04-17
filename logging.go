package smtpd

import (
	"context"
	"log/slog"
)

type contextKey string

const loggerKey contextKey = "smtpd-logger"

// LoggerFromContext returns the logger associated with the context.
// If no logger is found, it returns a default slog.DiscardHandler.
func LoggerFromContext(ctx context.Context) *slog.Logger {
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

func phasedLoggerFromContext(ctx context.Context, phase string) (context.Context, *slog.Logger) {
	logger := LoggerFromContext(ctx)
	logger = logger.With("phase", phase)
	return contextWithLogger(ctx, logger), logger
}
