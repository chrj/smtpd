package smtpd

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"
)

// listError is an error of a type that == cannot compare, which a handler
// can return.
type listError []string

func (e listError) Error() string { return strings.Join(e, "; ") }

// TestOnlyCause covers the test that keeps an error of the body out of the
// log. An error that wraps the cause is the cause. An error that joins it with
// another one carries a fault of the handler.
func TestOnlyCause(t *testing.T) {
	t.Parallel()

	cause := errMessageTooLarge
	other := errors.New("the database is down")

	tests := []struct {
		name string
		err  error
		want bool
	}{
		{name: "the cause", err: cause, want: true},
		{name: "the cause wrapped", err: fmt.Errorf("read the message: %w", cause), want: true},
		{name: "the cause wrapped twice", err: fmt.Errorf("deliver: %w", fmt.Errorf("read: %w", cause)), want: true},
		{name: "the cause joined with itself", err: errors.Join(cause, fmt.Errorf("again: %w", cause)), want: true},
		{name: "the cause joined with another error", err: errors.Join(cause, other), want: false},
		{name: "the cause and another error in one fmt.Errorf", err: fmt.Errorf("%w and %w", cause, other), want: false},
		{name: "another error", err: other, want: false},
		{name: "an error that wraps nothing", err: fmt.Errorf("deliver: %v", cause), want: false},
		{name: "an error of a type that == cannot compare", err: listError{"one", "two"}, want: false},
		{name: "an error that wraps nil", err: fmt.Errorf("%w", nil), want: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if got := onlyCause(tc.err, cause); got != tc.want {
				t.Errorf("onlyCause(%q) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

// TestChunkResultLogsInTheContextOfTheHandler verifies that the error of the
// handler of a chunked message goes to the logger of the context that the
// handler gave back, and not to the one of the command that reads it.
//
// The session reads the result of the handler at the next command, so its own
// context names that command, such as NOOP. The context of the handler names
// BDAT, and it carries what the handler added, such as the ID of the message.
func TestChunkResultLogsInTheContextOfTheHandler(t *testing.T) {
	t.Parallel()

	var sessionLog, handlerLog bytes.Buffer
	sessionCtx := contextWithLogger(context.Background(), slog.New(slog.NewTextHandler(&sessionLog, nil)))
	handlerCtx := contextWithLogger(context.Background(), slog.New(slog.NewTextHandler(&handlerLog, nil)).With("message", "m-42"))

	tests := []struct {
		name string
		read func(ct *chunkTransfer) deliverResult
	}{
		{
			name: "poll",
			read: func(ct *chunkTransfer) deliverResult {
				result, ok := ct.poll(sessionCtx, nil)
				if !ok {
					t.Fatal("poll found no result, and the handler gave one")
				}
				return result
			},
		},
		{
			name: "wait",
			read: func(ct *chunkTransfer) deliverResult { return ct.wait(sessionCtx) },
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			sessionLog.Reset()
			handlerLog.Reset()

			ct := &chunkTransfer{done: make(chan deliverResult, 1)}
			ct.done <- deliverResult{ctx: handlerCtx, err: errors.New("the database is down")}
			tc.read(ct)

			if !strings.Contains(handlerLog.String(), "message=m-42") {
				t.Errorf("the logger of the handler holds %q, want the error with message=m-42", handlerLog.String())
			}
			if sessionLog.Len() != 0 {
				t.Errorf("the logger of the session holds %q, want nothing", sessionLog.String())
			}
		})
	}
}
