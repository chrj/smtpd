package smtpd

import (
	"context"
	"log/slog"
)

type contextKey string

// sessionKey is the key that a sessionContext answers to.
const sessionKey contextKey = "smtpd-session"

// sessionValues holds what a session puts on its context.
type sessionValues struct {
	// logger is the logger of the session, without a phase attribute.
	logger *slog.Logger

	// phased is the logger of the session with the attribute of the phase
	// that runs now. It is nil before the first phase.
	phased *slog.Logger

	// sender is the address of MAIL FROM, and hasSender says that the
	// transaction has one. The null sender is the empty string with
	// hasSender set.
	sender    string
	hasSender bool
}

// sessionLogger gives the logger of the session without a phase attribute, so
// that each phase tags a new one. Values without a logger give one that
// discards every record.
func (v sessionValues) sessionLogger() *slog.Logger {
	if v.logger != nil {
		return v.logger
	}
	return slog.New(slog.DiscardHandler)
}

// sessionContext is a context that carries the values of a session.
//
// A session sets a value for every command that it runs, and a client sends
// as many commands as it likes. One context.WithValue for each of them makes
// a context that grows with the session, and every lookup walks all of it.
// The values therefore stand together in one context, and withSessionValues
// puts a new one in the place of the one before it.
//
// A sessionContext does not change after withSessionValues made it. The
// handler of a BDAT message keeps the context that it started with, and the
// session runs the commands that follow on another goroutine. That handler
// reads the same logger and the same sender for as long as it runs.
type sessionContext struct {
	context.Context
	values sessionValues
}

// Value gives the sessionContext for sessionKey, and asks the parent for
// every other key.
func (c *sessionContext) Value(key any) any {
	if key == sessionKey {
		return c
	}
	return c.Context.Value(key)
}

// sessionValuesFrom gives the values of the session that ctx carries, and the
// zero value for a context without a session.
func sessionValuesFrom(ctx context.Context) sessionValues {
	if c, ok := ctx.Value(sessionKey).(*sessionContext); ok {
		return c.values
	}
	return sessionValues{}
}

// withSessionValues returns a context that carries values, and everything
// else that ctx carries.
//
// When ctx is a sessionContext, the new context takes its place on the same
// parent. The context of the session then stays as deep as it was.
//
// When a hook put a context of its own on top, the new context goes on top of
// that one. The value of the hook stays that way.
func withSessionValues(ctx context.Context, values sessionValues) context.Context {
	if top, ok := ctx.(*sessionContext); ok {
		ctx = top.Context
	}
	return &sessionContext{Context: ctx, values: values}
}

// SenderFromContext returns the MAIL FROM address for the current transaction.
// ok is true once MAIL FROM has been accepted, false before or after RSET.
// A null sender (MAIL FROM:<>) is reported as an empty string with ok=true.
//
// This is primarily useful for RecipientChecker implementations (e.g. greylisting)
// that need the sender alongside the recipient.
func SenderFromContext(ctx context.Context) (string, bool) {
	values := sessionValuesFrom(ctx)
	return values.sender, values.hasSender
}

// ContextWithSender returns ctx with addr installed as the current MAIL FROM
// sender. The server calls this after a successful CheckSender; it is exported
// so tests and custom integrations can prepare a context that SenderFromContext
// will read.
func ContextWithSender(ctx context.Context, addr string) context.Context {
	values := sessionValuesFrom(ctx)
	values.sender, values.hasSender = addr, true
	return withSessionValues(ctx, values)
}

func contextWithoutSender(ctx context.Context) context.Context {
	values := sessionValuesFrom(ctx)
	values.sender, values.hasSender = "", false
	return withSessionValues(ctx, values)
}
