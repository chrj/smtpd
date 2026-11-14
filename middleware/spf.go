package middleware

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"unicode/utf8"

	"blitiri.com.ar/go/spf"
	"github.com/chrj/smtpd/v2"
	"golang.org/x/net/idna"
)

// SPFChecker performs Sender Policy Framework checks. The same checker can be
// used at HELO, MAIL FROM, or DATA - pick the phase by lifting the matching
// method through a Check* adapter:
//
//	s := middleware.SPF()
//	srv.Handler = smtpd.Chain(base).
//	    Use(middleware.CheckHelo(s.HeloCheck)).       // PeerCheck
//	    Use(middleware.CheckSender(s.SenderCheck)).   // AddrCheck
//	    Use(middleware.CheckData(s.DataCheck)).       // DataCheck
//	    Handler()
type SPFChecker struct {
	resolver spf.DNSResolver
}

// SPFOption configures an SPFChecker at construction time. Pass options
// to SPF.
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

// HeloCheck is a PeerCheck. It checks SPF using peer.HeloName as the identity
// and no sender - useful for early rejection at HELO/EHLO.
func (s *SPFChecker) HeloCheck(ctx context.Context, peer smtpd.Peer) error {
	return s.check(ctx, peer, peer.HeloName, "")
}

// SenderCheck is an AddrCheck. It checks SPF using peer.HeloName and the
// sender from MAIL FROM.
func (s *SPFChecker) SenderCheck(ctx context.Context, peer smtpd.Peer, addr string) error {
	return s.check(ctx, peer, peer.HeloName, addr)
}

// DataCheck is a DataCheck. It checks SPF using peer.HeloName and env.Sender
// after DATA - useful when MAIL FROM rejection isn't acceptable but you still
// want to drop the message before delivery.
func (s *SPFChecker) DataCheck(ctx context.Context, peer smtpd.Peer, env *smtpd.Envelope) error {
	return s.check(ctx, peer, peer.HeloName, env.Sender)
}

func (s *SPFChecker) check(ctx context.Context, peer smtpd.Peer, helo, sender string) error {
	logger := smtpd.LoggerFromContext(ctx)

	tcpAddr, ok := peer.Addr.(*net.TCPAddr)
	if !ok {
		return nil
	}
	ip := tcpAddr.IP

	// RFC 7208 section 4.3 gives none for a domain that is not well formed,
	// and a domain without an A-label form is one.
	checkSender, err := spfSender(sender)
	if err != nil {
		logger.InfoContext(ctx, "SPF check gave none, because the domain of the sender has no A-label form",
			slog.String("sender", sender), slog.String("error", err.Error()))
		return nil
	}

	// The library reads the HELO name for the %{h} macro, and as the domain
	// to check when the sender is empty. A name without an A-label form goes
	// to the library as it came, and the DNS holds no name of that form.
	//
	// Such a name does not end the check as a sender does. The check of a
	// sender reads the HELO name too, and a client would otherwise send a
	// name of that kind to get past the policy of its sender.
	if ascii, err := asciiDomain(helo); err != nil {
		logger.DebugContext(ctx, "the HELO name has no A-label form, and the SPF check reads it as it came",
			slog.String("helo", helo), slog.String("error", err.Error()))
	} else {
		helo = ascii
	}

	opts := []spf.Option{spf.WithContext(ctx)}
	if s.resolver != nil {
		opts = append(opts, spf.WithResolver(s.resolver))
	}

	result, _ := spf.CheckHostWithSender(ip, helo, checkSender, opts...)

	switch result {
	case spf.Fail:
		logger.WarnContext(ctx, "SPF check failed",
			slog.String("sender", sender), slog.String("helo", helo))
		return smtpd.Error{Code: 550, Enhanced: smtpd.EnhancedCode{5, 7, 23}, Message: "SPF check failed"}
	case spf.TempError:
		return smtpd.Error{Code: 451, Enhanced: smtpd.EnhancedCode{4, 7, 24}, Message: "SPF check temporary error"}
	case spf.PermError:
		return smtpd.Error{Code: 550, Enhanced: smtpd.EnhancedCode{5, 7, 24}, Message: "SPF check permanent error"}
	}
	return nil
}

// spfSender gives the sender in the form that the SPF library reads.
//
// The library takes the domain after the first "@" of the sender, and the
// local part before it for the %{l} macro. RFC 5321 lets a quoted local part
// carry an "@" of its own, as in `"x@attacker.example"@victim.example`. The
// library would then check a name that does not exist, get none, and let a
// sender of every domain past the policy of that domain.
//
// The domain therefore comes from the last "@", in the A-label form. An "@"
// in the local part becomes "%40", so that %{l} names no other user of the
// domain.
func spfSender(sender string) (string, error) {
	at := strings.LastIndexByte(sender, '@')
	if at < 0 {
		return sender, nil
	}

	domain, err := asciiDomain(sender[at+1:])
	if err != nil {
		return "", err
	}

	local := strings.ReplaceAll(sender[:at], "@", "%40")
	return local + "@" + domain, nil
}

// asciiDomain gives a domain in the A-label form, which RFC 6531 section 3.2
// asks for before a lookup in the DNS. idna.Lookup maps the domain as a
// lookup does, such as to lower case, and it refuses a domain without an
// A-label form.
//
// A domain in US-ASCII stays as it came. The rules of idna.Lookup refuse
// names that the DNS holds, such as one with an underscore.
func asciiDomain(domain string) (string, error) {
	for i := 0; i < len(domain); i++ {
		if domain[i] < utf8.RuneSelf {
			continue
		}

		ascii, err := idna.Lookup.ToASCII(domain)
		if err != nil {
			return "", fmt.Errorf("the domain %q has no A-label form: %w", domain, err)
		}
		return ascii, nil
	}

	return domain, nil
}

// Compile-time interface assertions.
var (
	_ PeerCheck = (*SPFChecker)(nil).HeloCheck
	_ AddrCheck = (*SPFChecker)(nil).SenderCheck
	_ DataCheck = (*SPFChecker)(nil).DataCheck
)
