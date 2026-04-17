package smtpd

import "context"

const senderKey contextKey = "smtpd-sender"

// SenderFromContext returns the MAIL FROM address for the current transaction.
// ok is true once MAIL FROM has been accepted, false before or after RSET.
// A null sender (MAIL FROM:<>) is reported as an empty string with ok=true.
//
// This is primarily useful for RecipientChecker implementations (e.g. greylisting)
// that need the sender alongside the recipient.
func SenderFromContext(ctx context.Context) (string, bool) {
	v, ok := ctx.Value(senderKey).(string)
	return v, ok
}

// ContextWithSender returns ctx with addr installed as the current MAIL FROM
// sender. The server calls this after a successful CheckSender; it is exported
// so tests and custom integrations can prepare a context that SenderFromContext
// will read.
func ContextWithSender(ctx context.Context, addr string) context.Context {
	return context.WithValue(ctx, senderKey, addr)
}

func contextWithoutSender(ctx context.Context) context.Context {
	return context.WithValue(ctx, senderKey, nil)
}
