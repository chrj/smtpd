// Package middleware provides reusable smtpd.Middleware implementations and
// stage adapters for composing SMTP-phase checks.
//
// Checks come in three signatures depending on what input they need:
//
//	PeerCheck — peer only (Connect, Helo)
//	AddrCheck — peer + an SMTP address (MailFrom, RcptTo)
//	DataCheck — peer + the completed Envelope (after DATA)
//
// The Check* functions lift each signature into a smtpd.Middleware, decoupling
// "what to check" (RBL/SPF/rate-limit) from "when to check" (the stage).
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

// CheckConnection runs c when a new connection is accepted.
func CheckConnection(c PeerCheck) smtpd.Middleware { return connectCheck{c} }

// CheckHelo runs c after HELO/EHLO. peer.HeloName is populated.
func CheckHelo(c PeerCheck) smtpd.Middleware { return heloCheck{c} }

// CheckSender runs c after MAIL FROM. addr is the sender.
func CheckSender(c AddrCheck) smtpd.Middleware { return senderCheck{c} }

// CheckRecipient runs c after each RCPT TO. addr is the recipient.
func CheckRecipient(c AddrCheck) smtpd.Middleware { return recipientCheck{c} }

// CheckData runs c after the DATA payload has been received, before the base
// handler. Returning an error rejects the message with the appropriate code.
func CheckData(c DataCheck) smtpd.Middleware { return dataCheck{c} }

// --- adapters ---

type connectCheck struct{ c PeerCheck }

func (a connectCheck) Wrap(next smtpd.Handler) smtpd.Handler { return next }
func (a connectCheck) CheckConnection(ctx context.Context, peer smtpd.Peer) (context.Context, error) {
	return ctx, a.c(ctx, peer)
}

type heloCheck struct{ c PeerCheck }

func (a heloCheck) Wrap(next smtpd.Handler) smtpd.Handler { return next }
func (a heloCheck) CheckHelo(ctx context.Context, peer smtpd.Peer, _ string) (context.Context, error) {
	return ctx, a.c(ctx, peer)
}

type senderCheck struct{ c AddrCheck }

func (a senderCheck) Wrap(next smtpd.Handler) smtpd.Handler { return next }
func (a senderCheck) CheckSender(ctx context.Context, peer smtpd.Peer, addr string) (context.Context, error) {
	return ctx, a.c(ctx, peer, addr)
}

type recipientCheck struct{ c AddrCheck }

func (a recipientCheck) Wrap(next smtpd.Handler) smtpd.Handler { return next }
func (a recipientCheck) CheckRecipient(ctx context.Context, peer smtpd.Peer, addr string) (context.Context, error) {
	return ctx, a.c(ctx, peer, addr)
}

type dataCheck struct{ c DataCheck }

func (a dataCheck) Wrap(next smtpd.Handler) smtpd.Handler {
	return dataCheckHandler{c: a.c, next: next}
}

type dataCheckHandler struct {
	c    DataCheck
	next smtpd.Handler
}

func (h dataCheckHandler) ServeSMTP(ctx context.Context, peer smtpd.Peer, env *smtpd.Envelope) error {
	if err := h.c(ctx, peer, env); err != nil {
		return err
	}
	return h.next.ServeSMTP(ctx, peer, env)
}

// Compile-time interface assertions.
var (
	_ smtpd.Middleware        = connectCheck{}
	_ smtpd.ConnectionChecker = connectCheck{}
	_ smtpd.Middleware        = heloCheck{}
	_ smtpd.HeloChecker       = heloCheck{}
	_ smtpd.Middleware        = senderCheck{}
	_ smtpd.SenderChecker     = senderCheck{}
	_ smtpd.Middleware        = recipientCheck{}
	_ smtpd.RecipientChecker  = recipientCheck{}
	_ smtpd.Middleware        = dataCheck{}
)
