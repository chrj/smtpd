package middleware

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"

	"github.com/chrj/smtpd/v2/pkg/smtpd"
)

type mockHandler struct{}

func (h *mockHandler) ServeSMTP(ctx context.Context, peer smtpd.Peer, env smtpd.Envelope) error {
	return nil
}

type mockResolver struct {
	blockedHosts map[string]bool
	txtRecords   map[string][]string
}

func (r *mockResolver) LookupHost(ctx context.Context, host string) ([]string, error) {
	if r.blockedHosts[host] {
		return []string{"127.0.0.2"}, nil
	}
	return nil, errors.New("not found")
}

func (r *mockResolver) LookupTXT(ctx context.Context, name string) ([]string, error) {
	if txt, ok := r.txtRecords[name]; ok {
		return txt, nil
	}
	return nil, errors.New("not found")
}

func TestRBL(t *testing.T) {
	resolver := &mockResolver{
		blockedHosts: map[string]bool{
			"4.3.2.1.bl.example.com": true,
			"1.1.1.1.bl.example.com": true,
		},
		txtRecords: map[string][]string{
			"1.1.1.1.bl.example.com": {"reason: spammer"},
		},
	}

	middleware := RBLWithResolver(resolver, "bl.example.com")
	handler := middleware(&mockHandler{})
	cc := handler.(smtpd.ConnectionChecker)

	tests := []struct {
		ip             string
		blocked        bool
		messageContain string
	}{
		{"1.2.3.4", true, "IP 1.2.3.4 listed in bl.example.com"},
		{"5.6.7.8", false, ""},
		{"1.1.1.1", true, "IP 1.1.1.1 listed in bl.example.com: reason: spammer"},
	}

	for _, tt := range tests {
		peer := smtpd.Peer{
			Addr: &net.TCPAddr{IP: net.ParseIP(tt.ip)},
		}
		_, err := cc.CheckConnection(context.Background(), peer)
		if tt.blocked && err == nil {
			t.Errorf("expected IP %s to be blocked", tt.ip)
		}
		if !tt.blocked && err != nil {
			t.Errorf("expected IP %s not to be blocked, got err: %v", tt.ip, err)
		}
		if tt.blocked && err != nil && !strings.Contains(err.Error(), tt.messageContain) {
			t.Errorf("expected message to contain %q, got %q", tt.messageContain, err.Error())
		}
	}
}

func TestRBLOptions(t *testing.T) {
	resolver := &mockResolver{
		blockedHosts: map[string]bool{
			"4.3.2.1.bl.example.com": true,
		},
	}
	peer := smtpd.Peer{
		Addr: &net.TCPAddr{IP: net.ParseIP("1.2.3.4")},
	}

	m := RBL([]string{"bl.example.com"}, WithRBLStage(OnHelo), WithRBLResolver(resolver))
	h := m(&mockHandler{})

	// Should NOT block on connection
	if _, err := h.(smtpd.ConnectionChecker).CheckConnection(context.Background(), peer); err != nil {
		t.Fatalf("expected no block on connection, got %v", err)
	}
	// SHOULD block on HELO
	if _, err := h.(smtpd.HeloChecker).CheckHelo(context.Background(), peer, "localhost"); err == nil {
		t.Fatal("expected block on HELO")
	}
}

func TestRBLStages(t *testing.T) {
	resolver := &mockResolver{
		blockedHosts: map[string]bool{
			"4.3.2.1.bl.example.com": true,
		},
	}
	peer := smtpd.Peer{
		Addr: &net.TCPAddr{IP: net.ParseIP("1.2.3.4")},
	}

	t.Run("OnHelo", func(t *testing.T) {
		m := RBLWithStage(OnHelo, "bl.example.com")
		h := m(&mockHandler{})
		rblObj := h.(*rbl)
		rblObj.resolver = resolver

		// Should NOT block on connection
		if _, err := h.(smtpd.ConnectionChecker).CheckConnection(context.Background(), peer); err != nil {
			t.Fatalf("expected no block on connection, got %v", err)
		}
		// SHOULD block on HELO
		if _, err := h.(smtpd.HeloChecker).CheckHelo(context.Background(), peer, "localhost"); err == nil {
			t.Fatal("expected block on HELO")
		}
	})

	t.Run("OnMailFrom", func(t *testing.T) {
		m := RBLWithStage(OnMailFrom, "bl.example.com")
		h := m(&mockHandler{})
		rblObj := h.(*rbl)
		rblObj.resolver = resolver

		// SHOULD block on MAIL FROM
		if _, err := h.(smtpd.SenderChecker).CheckSender(context.Background(), peer, "test@example.com"); err == nil {
			t.Fatal("expected block on MAIL FROM")
		}
	})

	t.Run("OnRcptTo", func(t *testing.T) {
		m := RBLWithStage(OnRcptTo, "bl.example.com")
		h := m(&mockHandler{})
		rblObj := h.(*rbl)
		rblObj.resolver = resolver

		// SHOULD block on RCPT TO
		if _, err := h.(smtpd.RecipientChecker).CheckRecipient(context.Background(), peer, "test@example.com"); err == nil {
			t.Fatal("expected block on RCPT TO")
		}
	})

	t.Run("OnData", func(t *testing.T) {
		m := RBLWithStage(OnData, "bl.example.com")
		h := m(&mockHandler{})
		rblObj := h.(*rbl)
		rblObj.resolver = resolver

		// SHOULD block on ServeSMTP (DATA)
		if err := h.ServeSMTP(context.Background(), peer, smtpd.Envelope{}); err == nil {
			t.Fatal("expected block on DATA")
		}
	})
}

func TestReverseIP(t *testing.T) {
	tests := []struct {
		ip       string
		expected string
	}{
		{"1.2.3.4", "4.3.2.1"},
		{"127.0.0.1", "1.0.0.127"},
		{"::1", "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0"},
	}

	for _, tt := range tests {
		ip := net.ParseIP(tt.ip)
		var reversedIP string
		if ip4 := ip.To4(); ip4 != nil {
			reversedIP = fmt.Sprintf("%d.%d.%d.%d", ip4[3], ip4[2], ip4[1], ip4[0])
		} else {
			var sb strings.Builder
			for i := len(ip) - 1; i >= 0; i-- {
				fmt.Fprintf(&sb, "%x.%x.", ip[i]&0xf, ip[i]>>4)
			}
			reversedIP = strings.TrimSuffix(sb.String(), ".")
		}

		if reversedIP != tt.expected {
			t.Errorf("expected %s, got %s", tt.expected, reversedIP)
		}
	}
}
