package middleware

import (
	"context"
	"fmt"

	"github.com/chrj/smtpd/v2"
)

// AuthFunc validates a username/password pair submitted during the AUTH
// phase. It returns nil to accept the credentials or a non-nil error to
// reject them; return an smtpd.Error to control the reply code.
type AuthFunc func(ctx context.Context, peer smtpd.Peer, user, pass string) error

// Authenticator returns a Middleware that delegates AUTH credential
// validation to fn. The SMTP layer handles PLAIN/LOGIN framing; fn only
// sees the decoded (user, pass) pair. On success peer.Username is set for
// every subsequent hook on the same connection.
//
// Authenticator does not enforce authentication on its own: unauthenticated
// clients can still issue MAIL FROM unless you also install RequireAuth
// (or RequireAuthAt for a different SMTP stage).
//
//	srv.Use(middleware.Authenticator(myAuthFn))
//	srv.Use(middleware.RequireAuth()) // enforce at MAIL FROM
func Authenticator(fn AuthFunc) smtpd.Middleware {
	return smtpd.Middleware{
		Authenticate: func(ctx context.Context, peer smtpd.Peer, user, pass string) (context.Context, error) {
			return ctx, fn(ctx, peer, user, pass)
		},
	}
}

// AuthPhase names the SMTP stage at which RequireAuthAt enforces
// authentication.
type AuthPhase int

const (
	// AuthAtMailFrom enforces authentication at MAIL FROM. This matches the
	// behavior most SMTP submission services expect.
	AuthAtMailFrom AuthPhase = iota
	// AuthAtRcpt enforces authentication at each RCPT TO. Use when a single
	// connection may carry both anonymous and authenticated transactions
	// distinguished by recipient.
	AuthAtRcpt
	// AuthAtData enforces authentication after the DATA payload has been
	// received. Use when earlier rejection isn't acceptable but delivery
	// still requires auth.
	AuthAtData
)

// RequireAuth returns a Middleware that rejects MAIL FROM with 530 when
// peer.Username is empty. It is the common case; for other stages use
// RequireAuthAt.
func RequireAuth() smtpd.Middleware { return RequireAuthAt(AuthAtMailFrom) }

// RequireAuthAt returns a Middleware that rejects the chosen phase with
// 530 when peer.Username is empty. Pair it with Authenticator so there is
// something populating peer.Username.
func RequireAuthAt(phase AuthPhase) smtpd.Middleware {
	switch phase {
	case AuthAtMailFrom:
		return smtpd.Middleware{
			CheckSender: func(ctx context.Context, peer smtpd.Peer, _ string) (context.Context, error) {
				return ctx, requireAuth(peer)
			},
		}
	case AuthAtRcpt:
		return smtpd.Middleware{
			CheckRecipient: func(ctx context.Context, peer smtpd.Peer, _ string) (context.Context, error) {
				return ctx, requireAuth(peer)
			},
		}
	case AuthAtData:
		return smtpd.Middleware{
			Handler: func(ctx context.Context, peer smtpd.Peer, _ *smtpd.Envelope) (context.Context, error) {
				return ctx, requireAuth(peer)
			},
		}
	}
	panic(fmt.Sprintf("middleware: unknown AuthPhase %d", phase))
}

func requireAuth(peer smtpd.Peer) error {
	if peer.Username == "" {
		return smtpd.Error{Code: 530, Message: "Authentication required"}
	}
	return nil
}
