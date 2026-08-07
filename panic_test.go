package smtpd_test

import (
	"context"
	"errors"
	"net/smtp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/chrj/smtpd/v2"
)

// panicOnce returns a function that panics the first time it runs, and does
// nothing on every call after that. A hook that panics on every call would
// also panic on the connection that tests whether the server survived.
func panicOnce(value any) func() {
	var mu sync.Mutex
	var done bool

	return func() {
		mu.Lock()
		defer mu.Unlock()
		if done {
			return
		}
		done = true
		panic(value)
	}
}

// sendMessage runs a full transaction against addr and returns the first
// error the client sees.
func sendMessage(t *testing.T, addr string) error {
	t.Helper()

	c, err := smtp.Dial(addr)
	if err != nil {
		return err
	}
	defer func() { _ = c.Close() }()

	if err := c.Mail("sender@example.org"); err != nil {
		return err
	}
	if err := c.Rcpt("recipient@example.net"); err != nil {
		return err
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	if _, err := w.Write([]byte("This is the email body\n")); err != nil {
		return err
	}
	return w.Close()
}

// TestHandlerPanicKeepsServerAlive verifies that a panic in Server.Handler is
// contained: the client that triggered it gets a 421, and a later transaction
// completes. Before the recovery, the panic unwound out of the goroutine of
// the session and took the whole process down with it.
func TestHandlerPanicKeepsServerAlive(t *testing.T) {
	t.Parallel()

	boom := panicOnce("boom")
	srv := runserver(t, &smtpd.Server{
		Logger: testLogger(t),
		Handler: func(ctx context.Context, _ smtpd.Peer, _ *smtpd.Envelope) (context.Context, error) {
			boom()
			return ctx, nil
		},
	})

	err := sendMessage(t, srv.Addr)
	if err == nil {
		t.Fatal("expected an error from the transaction that panicked")
	}
	if !strings.Contains(err.Error(), "421") {
		t.Fatalf("expected a 421 reply, got %v", err)
	}

	if err := sendMessage(t, srv.Addr); err != nil {
		t.Fatalf("expected the second transaction to succeed, got %v", err)
	}
}

// TestMiddlewarePanicKeepsServerAlive verifies the same containment for a
// panic in each middleware phase hook.
func TestMiddlewarePanicKeepsServerAlive(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		mw   func(boom func()) smtpd.Middleware
	}{
		{
			name: "CheckConnection",
			mw: func(boom func()) smtpd.Middleware {
				return smtpd.Middleware{
					CheckConnection: func(ctx context.Context, _ smtpd.Peer) (context.Context, error) {
						boom()
						return ctx, nil
					},
				}
			},
		},
		{
			name: "CheckHelo",
			mw: func(boom func()) smtpd.Middleware {
				return smtpd.Middleware{
					CheckHelo: func(ctx context.Context, _ smtpd.Peer, _ string) (context.Context, error) {
						boom()
						return ctx, nil
					},
				}
			},
		},
		{
			name: "CheckSender",
			mw: func(boom func()) smtpd.Middleware {
				return smtpd.Middleware{
					CheckSender: func(ctx context.Context, _ smtpd.Peer, _ string) (context.Context, error) {
						boom()
						return ctx, nil
					},
				}
			},
		},
		{
			name: "CheckRecipient",
			mw: func(boom func()) smtpd.Middleware {
				return smtpd.Middleware{
					CheckRecipient: func(ctx context.Context, _ smtpd.Peer, _ string) (context.Context, error) {
						boom()
						return ctx, nil
					},
				}
			},
		},
		{
			name: "Handler",
			mw: func(boom func()) smtpd.Middleware {
				return smtpd.Middleware{
					Handler: func(ctx context.Context, _ smtpd.Peer, _ *smtpd.Envelope) (context.Context, error) {
						boom()
						return ctx, nil
					},
				}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			srv := runserver(t, &smtpd.Server{Logger: testLogger(t)}, test.mw(panicOnce("boom")))

			if err := sendMessage(t, srv.Addr); err == nil {
				t.Fatal("expected an error from the transaction that panicked")
			}

			// The hook no longer panics, so a later transaction proves the
			// server kept running.
			if err := sendMessage(t, srv.Addr); err != nil {
				t.Fatalf("expected the second transaction to succeed, got %v", err)
			}
		})
	}
}

// TestPanicReachesDisconnectHook verifies that the panic surfaces to the
// Disconnect hook as a smtpd.PanicError carrying the value passed to panic.
func TestPanicReachesDisconnectHook(t *testing.T) {
	t.Parallel()

	var rec disconnectRecord
	boom := panicOnce("boom")
	srv := runserver(t, &smtpd.Server{
		Logger: testLogger(t),
		Handler: func(ctx context.Context, _ smtpd.Peer, _ *smtpd.Envelope) (context.Context, error) {
			boom()
			return ctx, nil
		},
	}, disconnectCounter(&rec))

	_ = sendMessage(t, srv.Addr)

	count, lastErr := waitDisconnect(&rec, time.Second)
	if count != 1 {
		t.Fatalf("expected exactly 1 Disconnect call, got %d", count)
	}

	var panicErr smtpd.PanicError
	if !errors.As(lastErr, &panicErr) {
		t.Fatalf("expected a smtpd.PanicError, got %v", lastErr)
	}
	if panicErr.Value != "boom" {
		t.Fatalf("expected the panic value %q, got %v", "boom", panicErr.Value)
	}
	// The stack must reach the frame that panicked, not only the frame that
	// recovered, or it gives an operator nothing to debug with.
	if !strings.Contains(string(panicErr.Stack), "TestPanicReachesDisconnectHook") {
		t.Fatalf("expected the stack to reach the handler that panicked, got:\n%s", panicErr.Stack)
	}
}

// TestDisconnectHookPanicKeepsServerAlive verifies that a panic in a
// Disconnect hook is contained too. That hook runs from the deferred close of
// the session, which is outside the recovery around the body of the session.
func TestDisconnectHookPanicKeepsServerAlive(t *testing.T) {
	t.Parallel()

	boom := panicOnce("boom")
	srv := runserver(t, &smtpd.Server{Logger: testLogger(t)}, smtpd.Middleware{
		Disconnect: func(_ context.Context, _ smtpd.Peer, _ error) {
			boom()
		},
	})

	c, err := smtp.Dial(srv.Addr)
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}
	_ = c.Quit()

	// The panicking hook ran on that session. The process is still alive, so
	// a later transaction completes.
	if err := sendMessage(t, srv.Addr); err != nil {
		t.Fatalf("expected a later transaction to succeed, got %v", err)
	}
}
