package middleware

import (
	"context"
	"fmt"

	"github.com/chrj/smtpd/v2"
)

// TLSPhase names the SMTP stage at which RequireTLSAt enforces that the
// session has negotiated TLS.
type TLSPhase int

const (
	// TLSAtMailFrom enforces TLS at MAIL FROM. This matches the typical
	// "must STARTTLS before sending mail" policy.
	TLSAtMailFrom TLSPhase = iota
	// TLSAtRcpt enforces TLS at each RCPT TO.
	TLSAtRcpt
	// TLSAtData enforces TLS after the DATA payload has been received.
	TLSAtData
)

// RequireTLS returns a Middleware that rejects MAIL FROM with 530 when the
// session is not running over TLS. Use RequireTLSAt for a different stage.
func RequireTLS() smtpd.Middleware { return RequireTLSAt(TLSAtMailFrom) }

// RequireTLSAt returns a Middleware that rejects the chosen phase with 530
// when peer.TLS is nil. Non-TLS sessions stay connected; they just cannot
// progress past the enforced phase.
func RequireTLSAt(phase TLSPhase) smtpd.Middleware {
	switch phase {
	case TLSAtMailFrom:
		return smtpd.Middleware{
			CheckSender: func(ctx context.Context, peer smtpd.Peer, _ string) (context.Context, error) {
				return ctx, requireTLS(peer)
			},
		}
	case TLSAtRcpt:
		return smtpd.Middleware{
			CheckRecipient: func(ctx context.Context, peer smtpd.Peer, _ string) (context.Context, error) {
				return ctx, requireTLS(peer)
			},
		}
	case TLSAtData:
		return smtpd.Middleware{
			Handler: func(ctx context.Context, peer smtpd.Peer, _ *smtpd.Envelope) (context.Context, error) {
				return ctx, requireTLS(peer)
			},
		}
	}
	panic(fmt.Sprintf("middleware: unknown TLSPhase %d", phase))
}

func requireTLS(peer smtpd.Peer) error {
	if peer.TLS == nil {
		return smtpd.Error{Code: 530, Message: "Must issue STARTTLS first"}
	}
	return nil
}
