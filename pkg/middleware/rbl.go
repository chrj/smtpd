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

// RBLMiddleware checks the remote IP against one or more Real-time Blackhole
// Lists at a configurable SMTP phase.
//
// RBLMiddleware is a smtpd.Middleware: pass it to smtpd.Chain.
type RBLMiddleware struct {
	lists    []string
	resolver DNSResolver
	stage    Stage
}

var (
	_ smtpd.Middleware        = (*RBLMiddleware)(nil)
	_ smtpd.ConnectionChecker = (*RBLMiddleware)(nil)
	_ smtpd.HeloChecker       = (*RBLMiddleware)(nil)
	_ smtpd.SenderChecker     = (*RBLMiddleware)(nil)
	_ smtpd.RecipientChecker  = (*RBLMiddleware)(nil)
)

type RBLOption func(*RBLMiddleware)

// WithRBLStage sets the stage at which the RBL check is performed.
func WithRBLStage(stage Stage) RBLOption {
	return func(r *RBLMiddleware) { r.stage = stage }
}

// WithRBLResolver sets a custom DNS resolver for the RBL check.
func WithRBLResolver(resolver DNSResolver) RBLOption {
	return func(r *RBLMiddleware) { r.resolver = resolver }
}

// RBL returns a middleware that rejects peers listed on any of the provided
// DNSBLs. By default, the check runs at the connection stage.
func RBL(lists []string, opts ...RBLOption) *RBLMiddleware {
	r := &RBLMiddleware{
		lists:    lists,
		resolver: net.DefaultResolver,
		stage:    OnConnect,
	}
	for _, opt := range opts {
		opt(r)
	}
	return r
}

func (r *RBLMiddleware) Wrap(next smtpd.Handler) smtpd.Handler {
	if r.stage != OnData {
		return next
	}
	return &rblOnData{RBLMiddleware: r, next: next}
}

type rblOnData struct {
	*RBLMiddleware
	next smtpd.Handler
}

func (h *rblOnData) ServeSMTP(ctx context.Context, peer smtpd.Peer, env *smtpd.Envelope) error {
	if err := h.check(ctx, peer); err != nil {
		return err
	}
	return h.next.ServeSMTP(ctx, peer, env)
}

func (r *RBLMiddleware) check(ctx context.Context, peer smtpd.Peer) error {
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
			if txt, err := r.resolver.LookupTXT(ctx, query); err == nil && len(txt) > 0 {
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

func (r *RBLMiddleware) CheckConnection(ctx context.Context, peer smtpd.Peer) (context.Context, error) {
	if r.stage == OnConnect {
		return ctx, r.check(ctx, peer)
	}
	return ctx, nil
}

func (r *RBLMiddleware) CheckHelo(ctx context.Context, peer smtpd.Peer, name string) (context.Context, error) {
	if r.stage == OnHelo {
		return ctx, r.check(ctx, peer)
	}
	return ctx, nil
}

func (r *RBLMiddleware) CheckSender(ctx context.Context, peer smtpd.Peer, addr string) (context.Context, error) {
	if r.stage == OnMailFrom {
		return ctx, r.check(ctx, peer)
	}
	return ctx, nil
}

func (r *RBLMiddleware) CheckRecipient(ctx context.Context, peer smtpd.Peer, addr string) (context.Context, error) {
	if r.stage == OnRcptTo {
		return ctx, r.check(ctx, peer)
	}
	return ctx, nil
}
