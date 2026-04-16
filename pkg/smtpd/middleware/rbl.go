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

// RBLChecker performs lookups against one or more Real-time Blackhole Lists.
// Use Check as a PeerCheck and apply it at any phase via Check*:
//
//	rbl := middleware.RBL([]string{"bl.example.com"})
//	srv.Handler = middleware.For(base).
//	    With(middleware.CheckConnection(rbl.Check)).
//	    Handler()
type RBLChecker struct {
	lists    []string
	resolver DNSResolver
}

type RBLOption func(*RBLChecker)

// WithRBLResolver sets a custom DNS resolver for the RBL check.
func WithRBLResolver(resolver DNSResolver) RBLOption {
	return func(r *RBLChecker) { r.resolver = resolver }
}

// RBL constructs a checker against the given DNSBLs.
func RBL(lists []string, opts ...RBLOption) *RBLChecker {
	r := &RBLChecker{
		lists:    lists,
		resolver: net.DefaultResolver,
	}
	for _, opt := range opts {
		opt(r)
	}
	return r
}

// Check is a PeerCheck. It returns a 554 error when the peer's IP is listed.
func (r *RBLChecker) Check(ctx context.Context, peer smtpd.Peer) error {
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

// Compile-time check that Check satisfies PeerCheck.
var _ PeerCheck = (*RBLChecker)(nil).Check
