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
	peer := smtpd.Peer{Addr: &net.TCPAddr{IP: net.ParseIP("1.2.3.4")}}

	// Default: OnMailFrom
	mw := SPF(WithSPFResolver(resolver))
	if _, err := mw.CheckSender(context.Background(), peer, "test@pass.com"); err != nil {
		t.Errorf("Expected pass, got error: %v", err)
	}
	if _, err := mw.CheckSender(context.Background(), peer, "test@fail.com"); err == nil {
		t.Error("Expected fail, got no error")
	} else if smtpdErr, ok := err.(smtpd.Error); !ok || smtpdErr.Code != 550 {
		t.Errorf("Expected 550 error, got %v", err)
	}

	// OnHelo
	mwHelo := SPF(WithSPFStage(OnHelo), WithSPFResolver(resolver))
	if _, err := mwHelo.CheckHelo(context.Background(), peer, "pass.com"); err != nil {
		t.Errorf("Expected pass, got error: %v", err)
	}
	if _, err := mwHelo.CheckHelo(context.Background(), peer, "fail.com"); err == nil {
		t.Error("Expected fail, got no error")
	}

	// OnData — check runs inside Wrap'd ServeSMTP
	mwData := SPF(WithSPFStage(OnData), WithSPFResolver(resolver))
	base := smtpd.HandlerFunc(func(context.Context, smtpd.Peer, *smtpd.Envelope) error { return nil })
	hData := mwData.Wrap(base)
	if err := hData.ServeSMTP(context.Background(), peer, &smtpd.Envelope{Sender: "test@pass.com"}); err != nil {
		t.Errorf("Expected pass, got error: %v", err)
	}
	if err := hData.ServeSMTP(context.Background(), peer, &smtpd.Envelope{Sender: "test@fail.com"}); err == nil {
		t.Error("Expected fail, got no error")
	}
}

func TestSPFOptions(t *testing.T) {
	resolver := &mockSPFResolver{
		results: map[string][]string{
			"fail.com": {"v=spf1 ip4:5.6.7.8 -all"},
		},
	}
	peer := smtpd.Peer{Addr: &net.TCPAddr{IP: net.ParseIP("1.2.3.4")}}

	mw := SPF(WithSPFStage(OnHelo), WithSPFResolver(resolver))

	// Should NOT block on MAIL FROM (stage is OnHelo)
	if _, err := mw.CheckSender(context.Background(), peer, "test@fail.com"); err != nil {
		t.Errorf("Expected no block on MAIL FROM, got error: %v", err)
	}
	// SHOULD block on HELO
	if _, err := mw.CheckHelo(context.Background(), peer, "fail.com"); err == nil {
		t.Error("Expected block on HELO")
	}
}
