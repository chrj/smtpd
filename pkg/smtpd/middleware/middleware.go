// Package middleware provides reusable smtpd middleware and stage adapters
// for composing SMTP-phase checks.
//
// Checks come in three signatures depending on what input they need:
//
//	PeerCheck — peer only (Connect, Helo)
//	AddrCheck — peer + an SMTP address (MailFrom, RcptTo)
//	DataCheck — peer + the completed Envelope (after DATA)
//
// Each signature is lifted into an smtpd.Middleware by the matching Check*
// function. The returned Middleware sets only the field for the SMTP phase
// it targets; pass the result to Server.Use to install it.
package middleware

import (
	"context"

	"github.com/chrj/smtpd/v2/pkg/smtpd"
)

// PeerCheck inspects only the peer. Use with CheckConnection or CheckHelo.
type PeerCheck func(ctx context.Context, peer smtpd.Peer) error

// AddrCheck inspects the peer and an SMTP address. Use with CheckSender or CheckRecipient.
type AddrCheck func(ctx context.Context, peer smtpd.Peer, addr string) error

// DataCheck inspects the peer and the completed envelope. Use with CheckData.
type DataCheck func(ctx context.Context, peer smtpd.Peer, env *smtpd.Envelope) error

// CheckConnection returns a Middleware that runs c when a new connection is
// accepted.
func CheckConnection(c PeerCheck) smtpd.Middleware {
	return smtpd.Middleware{
		CheckConnection: func(ctx context.Context, peer smtpd.Peer) (context.Context, error) {
			return ctx, c(ctx, peer)
		},
	}
}

// CheckHelo returns a Middleware that runs c after HELO/EHLO. peer.HeloName
// is populated.
func CheckHelo(c PeerCheck) smtpd.Middleware {
	return smtpd.Middleware{
		CheckHelo: func(ctx context.Context, peer smtpd.Peer, _ string) (context.Context, error) {
			return ctx, c(ctx, peer)
		},
	}
}

// CheckSender returns a Middleware that runs c after MAIL FROM. addr is the
// sender.
func CheckSender(c AddrCheck) smtpd.Middleware {
	return smtpd.Middleware{
		CheckSender: func(ctx context.Context, peer smtpd.Peer, addr string) (context.Context, error) {
			return ctx, c(ctx, peer, addr)
		},
	}
}

// CheckRecipient returns a Middleware that runs c after each RCPT TO. addr is
// the recipient.
func CheckRecipient(c AddrCheck) smtpd.Middleware {
	return smtpd.Middleware{
		CheckRecipient: func(ctx context.Context, peer smtpd.Peer, addr string) (context.Context, error) {
			return ctx, c(ctx, peer, addr)
		},
	}
}

// CheckData returns a Middleware that runs c after the DATA payload has been
// received, as a pre-deliver stage. Returning an error rejects the message
// and prevents Server.Handler (and any later middleware Handlers) from running.
func CheckData(c DataCheck) smtpd.Middleware {
	return smtpd.Middleware{
		Handler: func(ctx context.Context, peer smtpd.Peer, env *smtpd.Envelope) (context.Context, error) {
			return ctx, c(ctx, peer, env)
		},
	}
}
