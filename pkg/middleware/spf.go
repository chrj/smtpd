package middleware

import (
	"context"
	"log/slog"
	"net"

	"blitiri.com.ar/go/spf"
	"github.com/chrj/smtpd/v2/pkg/smtpd"
)

// SPFChecker performs Sender Policy Framework checks. The same checker can be
// used at HELO, MAIL FROM, or DATA — pick the phase by lifting the matching
// method through a Check* adapter:
//
//	s := middleware.SPF()
//	srv.Handler = middleware.Chain(base,
//	    middleware.CheckHelo(s.Helo),         // PeerCheck
//	    middleware.CheckSender(s.MailFrom),   // AddrCheck
//	    middleware.CheckData(s.Data),         // DataCheck
//	)
type SPFChecker struct {
	resolver spf.DNSResolver
}

type SPFOption func(*SPFChecker)

// WithSPFResolver sets a custom DNS resolver for the SPF check.
func WithSPFResolver(resolver spf.DNSResolver) SPFOption {
	return func(s *SPFChecker) { s.resolver = resolver }
}

// SPF constructs an SPF checker.
func SPF(opts ...SPFOption) *SPFChecker {
	s := &SPFChecker{}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// Helo is a PeerCheck. It checks SPF using peer.HeloName as the identity and
// no sender — useful for early rejection at HELO/EHLO.
func (s *SPFChecker) Helo(ctx context.Context, peer smtpd.Peer) error {
	return s.check(ctx, peer, peer.HeloName, "")
}

// MailFrom is an AddrCheck. It checks SPF using peer.HeloName and the sender
// from MAIL FROM.
func (s *SPFChecker) MailFrom(ctx context.Context, peer smtpd.Peer, addr string) error {
	return s.check(ctx, peer, peer.HeloName, addr)
}

// Data is a DataCheck. It checks SPF using peer.HeloName and env.Sender after
// DATA — useful when MAIL FROM rejection isn't acceptable but you still want
// to drop the message before delivery.
func (s *SPFChecker) Data(ctx context.Context, peer smtpd.Peer, env *smtpd.Envelope) error {
	return s.check(ctx, peer, peer.HeloName, env.Sender)
}

func (s *SPFChecker) check(ctx context.Context, peer smtpd.Peer, helo, sender string) error {
	logger := smtpd.LoggerFromContext(ctx)

	tcpAddr, ok := peer.Addr.(*net.TCPAddr)
	if !ok {
		return nil
	}
	ip := tcpAddr.IP

	opts := []spf.Option{spf.WithContext(ctx)}
	if s.resolver != nil {
		opts = append(opts, spf.WithResolver(s.resolver))
	}

	result, _ := spf.CheckHostWithSender(ip, helo, sender, opts...)

	switch result {
	case spf.Fail:
		logger.WarnContext(ctx, "SPF check failed",
			slog.String("sender", sender), slog.String("helo", helo))
		return smtpd.Error{Code: 550, Message: "SPF check failed"}
	case spf.TempError:
		return smtpd.Error{Code: 451, Message: "SPF check temporary error"}
	case spf.PermError:
		return smtpd.Error{Code: 550, Message: "SPF check permanent error"}
	}
	return nil
}

// Compile-time interface assertions.
var (
	_ PeerCheck = (*SPFChecker)(nil).Helo
	_ AddrCheck = (*SPFChecker)(nil).MailFrom
	_ DataCheck = (*SPFChecker)(nil).Data
)
