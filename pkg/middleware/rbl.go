package middleware

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"strings"

	"github.com/chrj/smtpd/v2/pkg/smtpd"
)

type DNSResolver interface {
	LookupHost(ctx context.Context, host string) (addrs []string, err error)
	LookupTXT(ctx context.Context, name string) ([]string, error)
}

type rbl struct {
	lists    []string
	resolver DNSResolver
	stage    Stage
	next     smtpd.Handler
}

var (
	_ smtpd.Handler           = (*rbl)(nil)
	_ smtpd.ConnectionChecker = (*rbl)(nil)
	_ smtpd.HeloChecker       = (*rbl)(nil)
	_ smtpd.SenderChecker     = (*rbl)(nil)
	_ smtpd.RecipientChecker  = (*rbl)(nil)
)

type RBLOption func(*rbl)

// WithRBLStage sets the stage at which the RBL check is performed.
func WithRBLStage(stage Stage) RBLOption {
	return func(r *rbl) {
		r.stage = stage
	}
}

// WithRBLResolver sets a custom DNS resolver for the RBL check.
func WithRBLResolver(resolver DNSResolver) RBLOption {
	return func(r *rbl) {
		r.resolver = resolver
	}
}

// RBL checks the remote IP against one or more Real-time Blackhole Lists.
// By default, the check is performed at the connection stage.
func RBL(lists []string, opts ...RBLOption) smtpd.Middleware {
	return func(next smtpd.Handler) smtpd.Handler {
		r := &rbl{
			lists:    lists,
			resolver: net.DefaultResolver,
			stage:    OnConnect,
			next:     next,
		}

		for _, opt := range opts {
			opt(r)
		}

		return r
	}
}

// RBLWithStage is a legacy helper. Use RBL with WithRBLStage instead.
func RBLWithStage(stage Stage, lists ...string) smtpd.Middleware {
	return RBL(lists, WithRBLStage(stage))
}

// RBLWithResolver is a legacy helper. Use RBL with WithRBLResolver instead.
func RBLWithResolver(resolver DNSResolver, lists ...string) smtpd.Middleware {
	return RBL(lists, WithRBLResolver(resolver))
}

func (r *rbl) check(ctx context.Context, peer smtpd.Peer) error {
	logger := smtpd.LoggerFromContext(ctx)

	tcpAddr, ok := peer.Addr.(*net.TCPAddr)
	if !ok {
		return nil
	}

	ip := tcpAddr.IP
	var reversedIP string
	if ip4 := ip.To4(); ip4 != nil {
		reversedIP = fmt.Sprintf("%d.%d.%d.%d", ip4[3], ip4[2], ip4[1], ip4[0])
	} else {
		// IPv6 RBL lookup (RFC 5782)
		var sb strings.Builder
		for i := len(ip) - 1; i >= 0; i-- {
			fmt.Fprintf(&sb, "%x.%x.", ip[i]&0xf, ip[i]>>4)
		}
		reversedIP = strings.TrimSuffix(sb.String(), ".")
	}

	for _, list := range r.lists {
		query := fmt.Sprintf("%s.%s", reversedIP, list)
		_, err := r.resolver.LookupHost(ctx, query)
		if err == nil {
			msg := fmt.Sprintf("IP %s listed in %s", ip, list)

			// Try to fetch a reason from a TXT record (RFC 5782)
			txt, err := r.resolver.LookupTXT(ctx, query)
			if err == nil && len(txt) > 0 {
				msg = fmt.Sprintf("%s: %s", msg, strings.Join(txt, " "))
			}

			logger.WarnContext(ctx, "IP listed in RBL",
				slog.String("ip", ip.String()),
				slog.String("list", list),
				slog.String("msg", msg),
			)

			return smtpd.Error{Code: 554, Message: msg}
		}
	}

	return nil
}

func (r *rbl) ServeSMTP(ctx context.Context, peer smtpd.Peer, env *smtpd.Envelope) error {
	if r.stage == OnData {
		if err := r.check(ctx, peer); err != nil {
			return err
		}
	}
	return r.next.ServeSMTP(ctx, peer, env)
}

func (r *rbl) CheckConnection(ctx context.Context, peer smtpd.Peer) (context.Context, error) {
	if r.stage == OnConnect {
		return ctx, r.check(ctx, peer)
	}
	return ctx, nil
}

func (r *rbl) CheckHelo(ctx context.Context, peer smtpd.Peer, name string) (context.Context, error) {
	if r.stage == OnHelo {
		return ctx, r.check(ctx, peer)
	}
	return ctx, nil
}

func (r *rbl) CheckSender(ctx context.Context, peer smtpd.Peer, addr string) (context.Context, error) {
	if r.stage == OnMailFrom {
		return ctx, r.check(ctx, peer)
	}
	return ctx, nil
}

func (r *rbl) CheckRecipient(ctx context.Context, peer smtpd.Peer, addr string) (context.Context, error) {
	if r.stage == OnRcptTo {
		return ctx, r.check(ctx, peer)
	}
	return ctx, nil
}
