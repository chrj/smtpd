package middleware

import (
	"context"
	"net"
	"testing"

	"blitiri.com.ar/go/spf"
	"github.com/chrj/smtpd/v2/pkg/smtpd"
)

var _ spf.DNSResolver = &mockSPFResolver{}

type mockSPFResolver struct {
	results map[string][]string
}

func (r *mockSPFResolver) LookupTXT(ctx context.Context, domain string) ([]string, error) {
	if res, ok := r.results[domain]; ok {
		return res, nil
	}
	return nil, nil
}
func (r *mockSPFResolver) LookupIPAddr(context.Context, string) ([]net.IPAddr, error) {
	return nil, nil
}
func (r *mockSPFResolver) LookupMX(context.Context, string) ([]*net.MX, error)  { return nil, nil }
func (r *mockSPFResolver) LookupNS(context.Context, string) ([]*net.NS, error)  { return nil, nil }
func (r *mockSPFResolver) LookupAddr(context.Context, string) ([]string, error) { return nil, nil }

func TestSPFChecks(t *testing.T) {
	resolver := &mockSPFResolver{
		results: map[string][]string{
			"pass.com": {"v=spf1 ip4:1.2.3.4 -all"},
			"fail.com": {"v=spf1 ip4:5.6.7.8 -all"},
		},
	}
	peer := smtpd.Peer{Addr: &net.TCPAddr{IP: net.ParseIP("1.2.3.4")}}
	s := SPF(WithSPFResolver(resolver))

	// MailFrom: pass / fail
	if err := s.SenderCheck(context.Background(), peer, "test@pass.com"); err != nil {
		t.Errorf("MailFrom pass: %v", err)
	}
	if err := s.SenderCheck(context.Background(), peer, "test@fail.com"); err == nil {
		t.Error("MailFrom fail: expected error")
	} else if smtpdErr, ok := err.(smtpd.Error); !ok || smtpdErr.Code != 550 {
		t.Errorf("expected 550, got %v", err)
	}

	// Helo (uses peer.HeloName)
	heloPeer := peer
	heloPeer.HeloName = "pass.com"
	if err := s.HeloCheck(context.Background(), heloPeer); err != nil {
		t.Errorf("Helo pass: %v", err)
	}
	heloPeer.HeloName = "fail.com"
	if err := s.HeloCheck(context.Background(), heloPeer); err == nil {
		t.Error("Helo fail: expected error")
	}

	// Data (uses env.Sender)
	if err := s.DataCheck(context.Background(), peer, &smtpd.Envelope{Sender: "test@pass.com"}); err != nil {
		t.Errorf("Data pass: %v", err)
	}
	if err := s.DataCheck(context.Background(), peer, &smtpd.Envelope{Sender: "test@fail.com"}); err == nil {
		t.Error("Data fail: expected error")
	}
}

// TestSPFAtStages confirms the Check* adapters wire the matching method into
// the matching checker interface, and only that one.
func TestSPFAtStages(t *testing.T) {
	resolver := &mockSPFResolver{
		results: map[string][]string{"fail.com": {"v=spf1 ip4:5.6.7.8 -all"}},
	}
	peer := smtpd.Peer{
		Addr:     &net.TCPAddr{IP: net.ParseIP("1.2.3.4")},
		HeloName: "fail.com",
	}
	s := SPF(WithSPFResolver(resolver))

	base := smtpd.HandlerFunc(func(context.Context, smtpd.Peer, *smtpd.Envelope) error { return nil })
	layer := CheckHelo(s.HeloCheck)(base)
	if _, ok := layer.(smtpd.SenderChecker); ok {
		t.Fatal("CheckHelo layer should not satisfy SenderChecker")
	}
	hc, ok := layer.(smtpd.HeloChecker)
	if !ok {
		t.Fatal("CheckHelo layer should satisfy HeloChecker")
	}
	if _, err := hc.CheckHelo(context.Background(), peer, "fail.com"); err == nil {
		t.Error("expected SPF block at HELO")
	}
}
