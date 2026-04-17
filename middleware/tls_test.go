package middleware

import (
	"context"
	"crypto/tls"
	"errors"
	"testing"

	"github.com/chrj/smtpd/v2"
)

func TestRequireTLSDefault(t *testing.T) {
	m := RequireTLS()

	if m.CheckSender == nil {
		t.Fatal("RequireTLS did not wire CheckSender (default is MAIL FROM)")
	}
	if m.CheckRecipient != nil || m.Handler != nil {
		t.Fatal("RequireTLS should only touch the CheckSender hook")
	}

	// Plain session: rejected with 530.
	_, err := m.CheckSender(context.Background(), smtpd.Peer{}, "sender@example.com")
	assertTLSRequired(t, err)

	// TLS session: accepted.
	_, err = m.CheckSender(context.Background(), smtpd.Peer{TLS: &tls.ConnectionState{}}, "sender@example.com")
	if err != nil {
		t.Fatalf("TLS CheckSender returned %v", err)
	}
}

func TestRequireTLSAtRcpt(t *testing.T) {
	m := RequireTLSAt(TLSAtRcpt)

	if m.CheckRecipient == nil {
		t.Fatal("RequireTLSAt(TLSAtRcpt) did not wire CheckRecipient")
	}
	if m.CheckSender != nil || m.Handler != nil {
		t.Fatal("RequireTLSAt(TLSAtRcpt) should only touch CheckRecipient")
	}

	_, err := m.CheckRecipient(context.Background(), smtpd.Peer{}, "rcpt@example.com")
	assertTLSRequired(t, err)

	_, err = m.CheckRecipient(context.Background(), smtpd.Peer{TLS: &tls.ConnectionState{}}, "rcpt@example.com")
	if err != nil {
		t.Fatalf("TLS CheckRecipient returned %v", err)
	}
}

func TestRequireTLSAtData(t *testing.T) {
	m := RequireTLSAt(TLSAtData)

	if m.Handler == nil {
		t.Fatal("RequireTLSAt(TLSAtData) did not wire Handler")
	}
	if m.CheckSender != nil || m.CheckRecipient != nil {
		t.Fatal("RequireTLSAt(TLSAtData) should only touch Handler")
	}

	_, err := m.Handler(context.Background(), smtpd.Peer{}, &smtpd.Envelope{})
	assertTLSRequired(t, err)

	_, err = m.Handler(context.Background(), smtpd.Peer{TLS: &tls.ConnectionState{}}, &smtpd.Envelope{})
	if err != nil {
		t.Fatalf("TLS Handler returned %v", err)
	}
}

func TestRequireTLSAtUnknownPhase(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("RequireTLSAt with unknown phase did not panic")
		}
	}()
	RequireTLSAt(TLSPhase(99))
}

func assertTLSRequired(t *testing.T, err error) {
	t.Helper()
	var e smtpd.Error
	if !errors.As(err, &e) {
		t.Fatalf("expected smtpd.Error, got %T: %v", err, err)
	}
	if e.Code != 530 {
		t.Fatalf("expected 530, got %d (%q)", e.Code, e.Message)
	}
}
