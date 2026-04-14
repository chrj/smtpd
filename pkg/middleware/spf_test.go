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

func (r *mockSPFResolver) LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error) {
	return nil, nil
}

func (r *mockSPFResolver) LookupMX(ctx context.Context, name string) ([]*net.MX, error) {
	return nil, nil
}

func (r *mockSPFResolver) LookupNS(ctx context.Context, name string) ([]*net.NS, error) {
	return nil, nil
}

func (r *mockSPFResolver) LookupAddr(ctx context.Context, addr string) ([]string, error) {
	return nil, nil
}

func TestSPF(t *testing.T) {
	resolver := &mockSPFResolver{
		results: map[string][]string{
			"pass.com": {"v=spf1 ip4:1.2.3.4 -all"},
			"fail.com": {"v=spf1 ip4:5.6.7.8 -all"},
		},
	}

	peer := smtpd.Peer{
		Addr: &net.TCPAddr{IP: net.ParseIP("1.2.3.4")},
	}

	next := smtpd.HandlerFunc(func(ctx context.Context, peer smtpd.Peer, env smtpd.Envelope) error {
		return nil
	})

	// Test OnMailFrom - Pass
	mw := SPFWithResolver(resolver)(next).(*spfMiddleware)
	if _, err := mw.CheckSender(context.Background(), peer, "test@pass.com"); err != nil {
		t.Errorf("Expected pass, got error: %v", err)
	}

	// Test OnMailFrom - Fail
	if _, err := mw.CheckSender(context.Background(), peer, "test@fail.com"); err == nil {
		t.Error("Expected fail, got no error")
	} else if smtpdErr, ok := err.(smtpd.Error); !ok || smtpdErr.Code != 550 {
		t.Errorf("Expected 550 error, got %v", err)
	}

	// Test OnHelo - Pass
	mwHelo := SPFWithStage(OnHelo)(next).(*spfMiddleware)
	mwHelo.resolver = resolver
	if _, err := mwHelo.CheckHelo(context.Background(), peer, "pass.com"); err != nil {
		t.Errorf("Expected pass, got error: %v", err)
	}

	// Test OnHelo - Fail
	if _, err := mwHelo.CheckHelo(context.Background(), peer, "fail.com"); err == nil {
		t.Error("Expected fail, got no error")
	}

	// Test OnData - Pass
	mwData := SPFWithStage(OnData)(next).(*spfMiddleware)
	mwData.resolver = resolver
	env := smtpd.Envelope{Sender: "test@pass.com"}
	if err := mwData.ServeSMTP(context.Background(), peer, env); err != nil {
		t.Errorf("Expected pass, got error: %v", err)
	}

	// Test OnData - Fail
	envFail := smtpd.Envelope{Sender: "test@fail.com"}
	if err := mwData.ServeSMTP(context.Background(), peer, envFail); err == nil {
		t.Error("Expected fail, got no error")
	}
}

func TestSPFOptions(t *testing.T) {
	resolver := &mockSPFResolver{
		results: map[string][]string{
			"fail.com": {"v=spf1 ip4:5.6.7.8 -all"},
		},
	}

	peer := smtpd.Peer{
		Addr: &net.TCPAddr{IP: net.ParseIP("1.2.3.4")},
	}

	next := smtpd.HandlerFunc(func(ctx context.Context, peer smtpd.Peer, env smtpd.Envelope) error {
		return nil
	})

	m := SPF(WithSPFStage(OnHelo), WithSPFResolver(resolver))
	h := m(next)

	// Should NOT block on MAIL FROM (since stage is OnHelo)
	if _, err := h.(smtpd.SenderChecker).CheckSender(context.Background(), peer, "test@fail.com"); err != nil {
		t.Errorf("Expected no block on MAIL FROM, got error: %v", err)
	}

	// SHOULD block on HELO
	if _, err := h.(smtpd.HeloChecker).CheckHelo(context.Background(), peer, "fail.com"); err == nil {
		t.Error("Expected block on HELO")
	}
}
