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

// holderError is an error of a type that reflect calls comparable, because
// its one field is an interface. == on two of them compares the values in
// that field, and it panics when they are of a type that == cannot compare.
type holderError struct{ inner error }

func (e holderError) Error() string { return "holder: " + e.inner.Error() }

// TestEveryBranch covers the walk that keeps an error of the body out of the
// log. An error that wraps the cause ends in the cause. An error that joins
// it with another one has a branch that ends elsewhere.
func TestEveryBranch(t *testing.T) {
	t.Parallel()

	cause := errMessageTooLarge
	other := errors.New("the database is down")
	isCause := func(e error) bool { return e == cause }

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
		{name: "nil", err: nil, want: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if got := everyBranch(tc.err, isCause); got != tc.want {
				t.Errorf("everyBranch(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

// TestLogHookError covers the errors of a hook that go to the log. An Error
// is a reply that the hook chose, also when it is wrapped. An error that
// joins an Error with one of another kind reports a fault, and it goes to
// the log, while hookReply still gives the Error.
func TestLogHookError(t *testing.T) {
	t.Parallel()

	reply := Error{Code: 550, Enhanced: EnhancedCode{5, 7, 1}, Message: "Sender refused"}
	other := errors.New("the database is down")

	tests := []struct {
		name   string
		err    error
		logged bool
	}{
		{name: "an Error", err: reply, logged: false},
		{name: "an Error wrapped", err: fmt.Errorf("check the sender: %w", reply), logged: false},
		{name: "two Errors joined", err: errors.Join(reply, Error{Code: 451}), logged: false},
		{name: "an Error joined with another error", err: errors.Join(reply, other), logged: true},
		{name: "another error", err: other, logged: true},
		{name: "nil", err: nil, logged: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var out bytes.Buffer
			ctx := contextWithLogger(context.Background(), slog.New(slog.NewTextHandler(&out, nil)))
			logHookError(ctx, tc.err)

			if got := out.Len() != 0; got != tc.logged {
				t.Errorf("logHookError(%v) logged = %v, want %v:\n%s", tc.err, got, tc.logged, out.String())
			}
		})
	}
}

// TestLogHandlerError covers the errors of a handler that go to the log. An
// error that the body gave the handler, and a reply that the handler chose,
// are not faults of the handler. Every other branch is one.
func TestLogHandlerError(t *testing.T) {
	t.Parallel()

	tooLarge := Error{Code: 552, Enhanced: EnhancedCode{5, 3, 4}, Message: "Message exceeded max message size of 100 bytes"}
	other := errors.New("the database is down")

	tests := []struct {
		name   string
		err    error
		cause  error
		logged bool
	}{
		{name: "the cause", err: errMessageTooLarge, cause: errMessageTooLarge, logged: false},
		{name: "the cause wrapped", err: fmt.Errorf("read: %w", errMessageTooLarge), cause: errMessageTooLarge, logged: false},
		{name: "the cause joined with another error", err: errors.Join(errMessageTooLarge, other), cause: errMessageTooLarge, logged: true},
		{name: "the cause joined with an Error", err: errors.Join(errMessageTooLarge, Error{Code: 451}), cause: errMessageTooLarge, logged: false},
		{name: "a cause that is an Error", err: tooLarge, cause: tooLarge, logged: false},
		{name: "a cause that is an Error joined with another error", err: errors.Join(tooLarge, other), cause: tooLarge, logged: true},
		{name: "another error and no cause", err: other, cause: nil, logged: true},
		{name: "an error that wraps nil and no cause", err: fmt.Errorf("%w", nil), cause: nil, logged: true},
		{name: "a panic", err: PanicError{Value: "boom"}, cause: nil, logged: false},
		{name: "nil", err: nil, cause: nil, logged: false},

		// A connection can give an error of a type that == cannot compare.
		// The comparison must not panic, and the cause then matches nothing,
		// as errors.Is matches nothing for such a target.
		{name: "a cause that == cannot compare", err: listError{"read", "failed"}, cause: listError{"read", "failed"}, logged: true},
		{name: "a cause that == cannot compare, wrapped", err: fmt.Errorf("read: %w", listError{"read", "failed"}), cause: listError{"read", "failed"}, logged: true},
		{name: "a cause of a comparable type that holds one that == cannot compare", err: holderError{listError{"read"}}, cause: holderError{listError{"read"}}, logged: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var out bytes.Buffer
			ctx := contextWithLogger(context.Background(), slog.New(slog.NewTextHandler(&out, nil)))
			logHandlerError(ctx, tc.err, tc.cause)

			if got := out.Len() != 0; got != tc.logged {
				t.Errorf("logHandlerError(%v, %v) logged = %v, want %v:\n%s", tc.err, tc.cause, got, tc.logged, out.String())
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
