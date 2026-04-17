package middleware

import (
	"context"
	"errors"
	"testing"

	"github.com/chrj/smtpd/v2"
)

func TestAuthenticator(t *testing.T) {
	var gotUser, gotPass string
	m := Authenticator(func(_ context.Context, _ smtpd.Peer, user, pass string) error {
		gotUser, gotPass = user, pass
		return nil
	})

	if m.Authenticate == nil {
		t.Fatal("Authenticator did not set the Authenticate hook")
	}

	ctx, err := m.Authenticate(context.Background(), smtpd.Peer{}, "alice", "hunter2")
	if err != nil {
		t.Fatalf("Authenticate returned %v", err)
	}
	if ctx == nil {
		t.Fatal("Authenticate returned nil context")
	}
	if gotUser != "alice" || gotPass != "hunter2" {
		t.Fatalf("AuthFunc got %q/%q, want alice/hunter2", gotUser, gotPass)
	}
}

func TestAuthenticatorRejects(t *testing.T) {
	want := smtpd.Error{Code: 535, Message: "nope"}
	m := Authenticator(func(_ context.Context, _ smtpd.Peer, _, _ string) error {
		return want
	})

	_, err := m.Authenticate(context.Background(), smtpd.Peer{}, "a", "b")
	var got smtpd.Error
	if !errors.As(err, &got) || got != want {
		t.Fatalf("Authenticate err = %v, want %v", err, want)
	}
}

func TestRequireAuthDefault(t *testing.T) {
	m := RequireAuth()

	if m.CheckSender == nil {
		t.Fatal("RequireAuth did not wire CheckSender (default is MAIL FROM)")
	}
	if m.CheckRecipient != nil || m.Handler != nil {
		t.Fatal("RequireAuth should only touch the CheckSender hook")
	}

	// Unauthenticated: rejected with 530.
	_, err := m.CheckSender(context.Background(), smtpd.Peer{}, "sender@example.com")
	assertAuthRequired(t, err)

	// Authenticated: accepted.
	_, err = m.CheckSender(context.Background(), smtpd.Peer{Username: "alice"}, "sender@example.com")
	if err != nil {
		t.Fatalf("authenticated CheckSender returned %v", err)
	}
}

func TestRequireAuthAtRcpt(t *testing.T) {
	m := RequireAuthAt(AuthAtRcpt)

	if m.CheckRecipient == nil {
		t.Fatal("RequireAuthAt(AuthAtRcpt) did not wire CheckRecipient")
	}
	if m.CheckSender != nil || m.Handler != nil {
		t.Fatal("RequireAuthAt(AuthAtRcpt) should only touch CheckRecipient")
	}

	_, err := m.CheckRecipient(context.Background(), smtpd.Peer{}, "rcpt@example.com")
	assertAuthRequired(t, err)

	_, err = m.CheckRecipient(context.Background(), smtpd.Peer{Username: "alice"}, "rcpt@example.com")
	if err != nil {
		t.Fatalf("authenticated CheckRecipient returned %v", err)
	}
}

func TestRequireAuthAtData(t *testing.T) {
	m := RequireAuthAt(AuthAtData)

	if m.Handler == nil {
		t.Fatal("RequireAuthAt(AuthAtData) did not wire Handler")
	}
	if m.CheckSender != nil || m.CheckRecipient != nil {
		t.Fatal("RequireAuthAt(AuthAtData) should only touch Handler")
	}

	_, err := m.Handler(context.Background(), smtpd.Peer{}, &smtpd.Envelope{})
	assertAuthRequired(t, err)

	_, err = m.Handler(context.Background(), smtpd.Peer{Username: "alice"}, &smtpd.Envelope{})
	if err != nil {
		t.Fatalf("authenticated Handler returned %v", err)
	}
}

func TestRequireAuthAtUnknownPhase(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("RequireAuthAt with unknown phase did not panic")
		}
	}()
	RequireAuthAt(AuthPhase(99))
}

func assertAuthRequired(t *testing.T, err error) {
	t.Helper()
	var e smtpd.Error
	if !errors.As(err, &e) {
		t.Fatalf("expected smtpd.Error, got %T: %v", err, err)
	}
	if e.Code != 530 {
		t.Fatalf("expected 530, got %d (%q)", e.Code, e.Message)
	}
}
