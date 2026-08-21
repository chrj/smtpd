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
// offers that extension in the reply to EHLO. A client that sent HELO never
// saw the offer, so it gets the replies that it expects from RFC 5321.
func (s *session) status(enhanced EnhancedCode) string {
	if s.peer.Protocol != ESMTP {
		return ""
	}
	return enhanced.String()
}

func (s *session) replyError(ctx context.Context, err error) context.Context {
	var smtpErr Error
	if errors.As(err, &smtpErr) {
		return s.replyEnhanced(ctx, smtpErr.Code, smtpErr.enhanced(), smtpErr.Message)
	}
	return s.replyEnhanced(ctx, 502, EnhancedCode{5, 5, 1}, err.Error())
}
