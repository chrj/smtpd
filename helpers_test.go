package smtpd_test

import (
	"context"
	"io"
	"log/slog"
	"testing"

	"github.com/chrj/smtpd"
)

// testLogger returns a discard logger so tests don't spam stdout.
// Flip to t.Log / os.Stdout during debugging.
func testLogger(_ *testing.T) *slog.Logger {
	return slog.New(slog.DiscardHandler)
}

// testHandler is a test shim that satisfies Handler plus the optional
// ConnectionChecker/HeloChecker/SenderChecker/RecipientChecker interfaces.
// Any nil func is a no-op; the shim deliberately does NOT implement
// Authenticator so tests that don't set an auth func don't get AUTH
// advertised in EHLO. Use testAuthHandler for auth-enabled tests.
type testHandler struct {
	serve     func(peer smtpd.Peer, env smtpd.Envelope) error
	conn      func(peer smtpd.Peer) error
	helo      func(peer smtpd.Peer, name string) error
	sender    func(peer smtpd.Peer, addr string) error
	recipient func(peer smtpd.Peer, addr string) error
}

func (h *testHandler) ServeSMTP(_ context.Context, peer smtpd.Peer, env smtpd.Envelope) error {
	defer func() { _ = env.Data.Close() }()
	if h.serve != nil {
		return h.serve(peer, env)
	}
	_, _ = io.Copy(io.Discard, env.Data)
	return nil
}

func (h *testHandler) CheckConnection(ctx context.Context, peer smtpd.Peer) (context.Context, error) {
	if h.conn == nil {
		return ctx, nil
	}
	return ctx, h.conn(peer)
}

func (h *testHandler) CheckHelo(ctx context.Context, peer smtpd.Peer, name string) (context.Context, error) {
	if h.helo == nil {
		return ctx, nil
	}
	return ctx, h.helo(peer, name)
}

func (h *testHandler) CheckSender(ctx context.Context, peer smtpd.Peer, addr string) (context.Context, error) {
	if h.sender == nil {
		return ctx, nil
	}
	return ctx, h.sender(peer, addr)
}

func (h *testHandler) CheckRecipient(ctx context.Context, peer smtpd.Peer, addr string) (context.Context, error) {
	if h.recipient == nil {
		return ctx, nil
	}
	return ctx, h.recipient(peer, addr)
}

// testAuthHandler extends testHandler with Authenticator. Use this only
// when the test actually exercises AUTH (so EHLO capability advertising
// stays accurate for non-auth tests).
type testAuthHandler struct {
	testHandler
	auth func(peer smtpd.Peer, user, pass string) error
}

func (h *testAuthHandler) Authenticate(ctx context.Context, peer smtpd.Peer, user, pass string) (context.Context, error) {
	if h.auth == nil {
		return ctx, nil
	}
	return ctx, h.auth(peer, user, pass)
}

// install registers h on srv. Returns srv for chaining convenience.
func install(srv *smtpd.Server, h smtpd.Handler) *smtpd.Server {
	srv.Handler(h)
	return srv
}
