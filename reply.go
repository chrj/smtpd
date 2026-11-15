package smtpd

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
)

// reply writes a single reply line with the generic status code for the
// class of code, such as "5.0.0" for a 550. Use replyEnhanced where a
// precise reason helps the client.
func (s *session) reply(ctx context.Context, code int, message string) context.Context {
	return s.replyEnhanced(ctx, code, defaultEnhancedCode(code), message)
}

// replyEnhanced writes a single reply line with the given status code. The
// zero value of enhanced leaves the status code out, which is what the
// greeting and the reply to HELO and EHLO need.
func (s *session) replyEnhanced(ctx context.Context, code int, enhanced EnhancedCode, message string) context.Context {
	// A closed session has no reader on the other end. The write would go
	// into a buffer that nothing flushes, and the reply that the client did
	// read was the last one.
	if s.closed {
		return ctx
	}

	status := s.status(enhanced)
	message = sanitizeReplyText(message)

	logger := LoggerFromContext(ctx)
	logger.DebugContext(ctx, "sending",
		slog.Int("code", code),
		slog.String("status", status),
		slog.String("message", message),
	)

	if status == "" {
		_, _ = fmt.Fprintf(s.writer, "%d %s\r\n", code, message)
		return s.flush(ctx)
	}

	_, _ = fmt.Fprintf(s.writer, "%d %s %s\r\n", code, status, message)
	return s.flush(ctx)
}

// replyMultiline writes first and rest as one reply, with the continuation
// mark on every line but the last. The lines carry no status code: this is
// the reply to EHLO, and RFC 2034 takes that reply out of the extension.
//
// The first line is a separate argument, so that a reply always has one.
func (s *session) replyMultiline(ctx context.Context, code int, first string, rest ...string) context.Context {
	if s.closed {
		return ctx
	}

	logger := LoggerFromContext(ctx)

	lines := append([]string{first}, rest...)
	for _, line := range lines[:len(lines)-1] {
		line = sanitizeReplyText(line)
		logger.DebugContext(ctx, "sending",
			slog.Int("code", code),
			slog.String("message", line),
		)
		_, _ = fmt.Fprintf(s.writer, "%d-%s\r\n", code, line)
	}

	return s.replyEnhanced(ctx, code, EnhancedCode{}, lines[len(lines)-1])
}

// sanitizeReplyText makes text safe to write inside a reply line. Every
// control character becomes a space.
//
// The message of a middleware refusal often carries something that the client
// sent. The user name of an AUTH command is one example: the session decodes
// it from base64, so it holds any byte at all. A line break inside a reply
// ends that reply and starts a line of the client's choosing. The client then
// reads an answer to a command that the server never ran.
//
// A byte at 0x80 and above stays as it is, so a message in UTF-8 arrives
// whole.
func sanitizeReplyText(text string) string {
	if !hasControl(text) {
		return text
	}

	out := []byte(text)
	for i, c := range out {
		if isControl(c) {
			out[i] = ' '
		}
	}
	return string(out)
}

// hasControl reports whether text carries a control character, so that a
// text without one goes on the wire as it is.
func hasControl(text string) bool {
	for i := 0; i < len(text); i++ {
		if isControl(text[i]) {
			return true
		}
	}
	return false
}

// isControl reports whether c is a control character. RFC 5321 gives the text
// of a reply as printable characters.
func isControl(c byte) bool {
	return c < 0x20 || c == 0x7f
}

// status gives the text of the status code to write with a reply. It is
// empty when the client did not send EHLO.
//
// RFC 2034 makes the status code part of an extension, and the server
// offers that extension in the reply to EHLO and to LHLO. A client that sent
// HELO never saw the offer, so it gets the replies that it expects from RFC
// 5321.
func (s *session) status(enhanced EnhancedCode) string {
	if !s.peer.Protocol.extended() {
		return ""
	}
	return enhanced.String()
}

// replyError answers a hook that returned an error, with the reply of
// hookReply. An error that is not an Error goes to the log first.
func (s *session) replyError(ctx context.Context, err error) context.Context {
	logHookError(ctx, err)
	return s.replyHook(ctx, hookReply(err))
}

// replyHook writes the reply that hookReply chose.
func (s *session) replyHook(ctx context.Context, reply Error) context.Context {
	return s.replyEnhanced(ctx, reply.Code, reply.enhanced(), reply.Message)
}

// errLocalProcessing is the reply to an error of a hook that is not an
// Error. RFC 5321 section 4.2.3 gives this text to 451.
var errLocalProcessing = Error{
	Code:     451,
	Enhanced: EnhancedCode{4, 3, 0},
	Message:  "Requested action aborted: local error in processing",
}

// hookReply gives the reply to an error that a hook returned. An Error is the
// reply that the hook chose. Any other error gets errLocalProcessing.
//
// The text of such an error comes from the site, such as the address of a
// database or the name of a file, and a client of any kind reads a reply. A
// 502 would say that the server does not carry the command, which section
// 3.5.3 calls a fault for a command that it does carry.
func hookReply(err error) Error {
	if smtpErr, ok := errors.AsType[Error](err); ok {
		return smtpErr
	}
	return errLocalProcessing
}

// logHookError writes an error that a hook returned to the log, unless it is
// an Error. The text of such an error reaches no client, so the log is the
// one place where an operator reads it.
//
// Call it once for each error. A reply that stands in the place of the one
// of the hook, such as the 421 at the limit of AUTH attempts, needs it as
// well. The error of the handler goes through logHandlerError instead.
func logHookError(ctx context.Context, err error) {
	if _, ok := errors.AsType[Error](err); ok {
		return
	}
	LoggerFromContext(ctx).ErrorContext(ctx, "a hook failed with an error that is not an smtpd.Error",
		slog.Any("err", err),
	)
}

// logHandlerError writes the error that the handler of a message gave back
// to the log, where the session reads it. The handler gives back one result,
// so its error goes to the log once. The reply to it does not log: a 552
// for a message that is too large can stand in its place, and a BDAT
// transfer answers every chunk after the failure with it.
//
// cause is the error that the body gave the handler, such as
// errMessageTooLarge, the error of a broken connection, or the cause of a
// transfer that ended early. A handler that returns it reports what the
// session already knows, and not a fault of its own, so it stays out of the
// log. A panic goes to the log through reportPanic.
func logHandlerError(ctx context.Context, err, cause error) {
	if err == nil || (cause != nil && errors.Is(err, cause)) {
		return
	}
	if _, ok := errors.AsType[PanicError](err); ok {
		return
	}
	logHookError(ctx, err)
}
