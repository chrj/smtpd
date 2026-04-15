package middleware

import (
	"context"
	"log/slog"
	"net"

	"blitiri.com.ar/go/spf"
	"github.com/chrj/smtpd/v2/pkg/smtpd"
)

// SPFMiddleware performs an SPF check at a configurable SMTP phase.
//
// SPFMiddleware is a smtpd.Middleware: pass it to smtpd.Chain.
type SPFMiddleware struct {
	resolver spf.DNSResolver
	stage    Stage
}

var (
	_ smtpd.Middleware       = (*SPFMiddleware)(nil)
	_ smtpd.HeloChecker      = (*SPFMiddleware)(nil)
	_ smtpd.SenderChecker    = (*SPFMiddleware)(nil)
	_ smtpd.RecipientChecker = (*SPFMiddleware)(nil)
)

type SPFOption func(*SPFMiddleware)

// WithSPFStage sets the stage at which the SPF check is performed.
func WithSPFStage(stage Stage) SPFOption {
	return func(s *SPFMiddleware) { s.stage = stage }
}

// WithSPFResolver sets a custom DNS resolver for the SPF check.
func WithSPFResolver(resolver spf.DNSResolver) SPFOption {
	return func(s *SPFMiddleware) { s.resolver = resolver }
}

// SPF returns a middleware that performs an SPF check. By default, the check
// runs at the MAIL FROM stage.
func SPF(opts ...SPFOption) *SPFMiddleware {
	s := &SPFMiddleware{stage: OnMailFrom}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

func (s *SPFMiddleware) Wrap(next smtpd.Handler) smtpd.Handler {
	if s.stage != OnData {
		return next
	}
	return &spfOnData{SPFMiddleware: s, next: next}
}

type spfOnData struct {
	*SPFMiddleware
	next smtpd.Handler
}

func (h *spfOnData) ServeSMTP(ctx context.Context, peer smtpd.Peer, env *smtpd.Envelope) error {
	if err := h.check(ctx, peer, peer.HeloName, env.Sender); err != nil {
		return err
	}
	return h.next.ServeSMTP(ctx, peer, env)
}

func (s *SPFMiddleware) check(ctx context.Context, peer smtpd.Peer, helo string, sender string) error {
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

func (s *SPFMiddleware) CheckHelo(ctx context.Context, peer smtpd.Peer, name string) (context.Context, error) {
	if s.stage == OnHelo {
		return ctx, s.check(ctx, peer, name, "")
	}
	return ctx, nil
}

func (s *SPFMiddleware) CheckSender(ctx context.Context, peer smtpd.Peer, addr string) (context.Context, error) {
	if s.stage == OnMailFrom {
		return ctx, s.check(ctx, peer, peer.HeloName, addr)
	}
	return ctx, nil
}

func (s *SPFMiddleware) CheckRecipient(ctx context.Context, peer smtpd.Peer, addr string) (context.Context, error) {
	// SPF at RCPT TO has no new input over MAIL FROM; intentionally no-op.
	return ctx, nil
}
