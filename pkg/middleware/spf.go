package middleware

import (
	"context"
	"log/slog"
	"net"

	"blitiri.com.ar/go/spf"
	"github.com/chrj/smtpd/v2/pkg/smtpd"
)

type spfMiddleware struct {
	resolver spf.DNSResolver
	stage    Stage
	next     smtpd.Handler
}

var (
	_ smtpd.Handler           = (*spfMiddleware)(nil)
	_ smtpd.ConnectionChecker = (*spfMiddleware)(nil)
	_ smtpd.HeloChecker       = (*spfMiddleware)(nil)
	_ smtpd.SenderChecker     = (*spfMiddleware)(nil)
	_ smtpd.RecipientChecker  = (*spfMiddleware)(nil)
)

type SPFOption func(*spfMiddleware)

// WithSPFStage sets the stage at which the SPF check is performed.
func WithSPFStage(stage Stage) SPFOption {
	return func(s *spfMiddleware) {
		s.stage = stage
	}
}

// WithSPFResolver sets a custom DNS resolver for the SPF check.
func WithSPFResolver(resolver spf.DNSResolver) SPFOption {
	return func(s *spfMiddleware) {
		s.resolver = resolver
	}
}

// SPF performs an SPF check on the remote IP and sender address.
// By default, the check is performed at the MAIL FROM stage.
func SPF(opts ...SPFOption) smtpd.Middleware {
	return func(next smtpd.Handler) smtpd.Handler {
		s := &spfMiddleware{
			stage: OnMailFrom,
			next:  next,
		}

		for _, opt := range opts {
			opt(s)
		}

		return s
	}
}

// SPFWithStage is a legacy helper. Use SPF with WithSPFStage instead.
func SPFWithStage(stage Stage) smtpd.Middleware {
	return SPF(WithSPFStage(stage))
}

// SPFWithResolver is a legacy helper. Use SPF with WithSPFResolver instead.
func SPFWithResolver(resolver spf.DNSResolver) smtpd.Middleware {
	return SPF(WithSPFResolver(resolver))
}

func (s *spfMiddleware) check(ctx context.Context, peer smtpd.Peer, helo string, sender string) error {
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
		logger.WarnContext(ctx, "SPF check failed", slog.String("sender", sender), slog.String("helo", helo))
		return smtpd.Error{Code: 550, Message: "SPF check failed"}
	case spf.TempError:
		return smtpd.Error{Code: 451, Message: "SPF check temporary error"}
	case spf.PermError:
		return smtpd.Error{Code: 550, Message: "SPF check permanent error"}
	}

	return nil
}

func (s *spfMiddleware) ServeSMTP(ctx context.Context, peer smtpd.Peer, env smtpd.Envelope) error {
	if s.stage == OnData {
		if err := s.check(ctx, peer, peer.HeloName, env.Sender); err != nil {
			return err
		}
	}
	return s.next.ServeSMTP(ctx, peer, env)
}

func (s *spfMiddleware) CheckConnection(ctx context.Context, peer smtpd.Peer) (context.Context, error) {
	// SPF requires a domain (HELO or MAIL FROM), so it can't be performed at connection time.
	return ctx, nil
}

func (s *spfMiddleware) CheckHelo(ctx context.Context, peer smtpd.Peer, name string) (context.Context, error) {
	if s.stage == OnHelo {
		return ctx, s.check(ctx, peer, name, "")
	}
	return ctx, nil
}

func (s *spfMiddleware) CheckSender(ctx context.Context, peer smtpd.Peer, addr string) (context.Context, error) {
	if s.stage == OnMailFrom {
		return ctx, s.check(ctx, peer, peer.HeloName, addr)
	}
	return ctx, nil
}

func (s *spfMiddleware) CheckRecipient(ctx context.Context, peer smtpd.Peer, addr string) (context.Context, error) {
	if s.stage == OnRcptTo {
		// We don't have the sender address here, so we can't perform an SPF check.
		return ctx, nil
	}
	return ctx, nil
}
