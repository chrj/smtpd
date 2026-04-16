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
// function. The Middleware wraps the next Handler in a layer that advertises
// the appropriate phase checker interface (ConnectionChecker, HeloChecker,
// SenderChecker, RecipientChecker) or, for CheckData, performs the check
// inline inside ServeSMTP. Pass the result to Chain.With.
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
// accepted. ServeSMTP passes through unchanged.
func CheckConnection(c PeerCheck) smtpd.Middleware {
	return func(next smtpd.Handler) smtpd.Handler {
		return &connCheckLayer{c: c, next: next}
	}
}

// CheckHelo returns a Middleware that runs c after HELO/EHLO. peer.HeloName is
// populated. ServeSMTP passes through unchanged.
func CheckHelo(c PeerCheck) smtpd.Middleware {
	return func(next smtpd.Handler) smtpd.Handler {
		return &heloCheckLayer{c: c, next: next}
	}
}

// CheckSender returns a Middleware that runs c after MAIL FROM. addr is the
// sender. ServeSMTP passes through unchanged.
func CheckSender(c AddrCheck) smtpd.Middleware {
	return func(next smtpd.Handler) smtpd.Handler {
		return &senderCheckLayer{c: c, next: next}
	}
}

// CheckRecipient returns a Middleware that runs c after each RCPT TO. addr is
// the recipient. ServeSMTP passes through unchanged.
func CheckRecipient(c AddrCheck) smtpd.Middleware {
	return func(next smtpd.Handler) smtpd.Handler {
		return &recipientCheckLayer{c: c, next: next}
	}
}

// CheckData returns a Middleware that runs c after the DATA payload has been
// received, before the next Handler. Returning an error rejects the message.
func CheckData(c DataCheck) smtpd.Middleware {
	return func(next smtpd.Handler) smtpd.Handler {
		return &dataCheckLayer{c: c, next: next}
	}
}

// --- layers ---

type connCheckLayer struct {
	c    PeerCheck
	next smtpd.Handler
}

func (l *connCheckLayer) ServeSMTP(ctx context.Context, peer smtpd.Peer, env *smtpd.Envelope) error {
	return l.next.ServeSMTP(ctx, peer, env)
}

func (l *connCheckLayer) CheckConnection(ctx context.Context, peer smtpd.Peer) (context.Context, error) {
	return ctx, l.c(ctx, peer)
}

type heloCheckLayer struct {
	c    PeerCheck
	next smtpd.Handler
}

func (l *heloCheckLayer) ServeSMTP(ctx context.Context, peer smtpd.Peer, env *smtpd.Envelope) error {
	return l.next.ServeSMTP(ctx, peer, env)
}

func (l *heloCheckLayer) CheckHelo(ctx context.Context, peer smtpd.Peer, _ string) (context.Context, error) {
	return ctx, l.c(ctx, peer)
}

type senderCheckLayer struct {
	c    AddrCheck
	next smtpd.Handler
}

func (l *senderCheckLayer) ServeSMTP(ctx context.Context, peer smtpd.Peer, env *smtpd.Envelope) error {
	return l.next.ServeSMTP(ctx, peer, env)
}

func (l *senderCheckLayer) CheckSender(ctx context.Context, peer smtpd.Peer, addr string) (context.Context, error) {
	return ctx, l.c(ctx, peer, addr)
}

type recipientCheckLayer struct {
	c    AddrCheck
	next smtpd.Handler
}

func (l *recipientCheckLayer) ServeSMTP(ctx context.Context, peer smtpd.Peer, env *smtpd.Envelope) error {
	return l.next.ServeSMTP(ctx, peer, env)
}

func (l *recipientCheckLayer) CheckRecipient(ctx context.Context, peer smtpd.Peer, addr string) (context.Context, error) {
	return ctx, l.c(ctx, peer, addr)
}

type dataCheckLayer struct {
	c    DataCheck
	next smtpd.Handler
}

func (l *dataCheckLayer) ServeSMTP(ctx context.Context, peer smtpd.Peer, env *smtpd.Envelope) error {
	if err := l.c(ctx, peer, env); err != nil {
		return err
	}
	return l.next.ServeSMTP(ctx, peer, env)
}

// Compile-time interface assertions.
var (
	_ smtpd.Handler          = (*connCheckLayer)(nil)
	_ smtpd.ConnectionChecker = (*connCheckLayer)(nil)
	_ smtpd.Handler          = (*heloCheckLayer)(nil)
	_ smtpd.HeloChecker      = (*heloCheckLayer)(nil)
	_ smtpd.Handler          = (*senderCheckLayer)(nil)
	_ smtpd.SenderChecker    = (*senderCheckLayer)(nil)
	_ smtpd.Handler          = (*recipientCheckLayer)(nil)
	_ smtpd.RecipientChecker = (*recipientCheckLayer)(nil)
	_ smtpd.Handler          = (*dataCheckLayer)(nil)
)
