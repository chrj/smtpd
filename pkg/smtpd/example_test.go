package smtpd_test

import (
	"context"
	"errors"
	"io"
	"net/smtp"
	"strings"

	"github.com/chrj/smtpd/v2/pkg/smtpd"
)

// relayHandler forwards accepted mail upstream via Gmail SMTP.
func relayHandler() smtpd.Handler {
	return func(ctx context.Context, _ smtpd.Peer, env *smtpd.Envelope) (context.Context, error) {
		defer func() { _ = env.Data.Close() }()
		body, err := io.ReadAll(env.Data)
		if err != nil {
			return ctx, err
		}
		return ctx, smtp.SendMail(
			"smtp.gmail.com:587",
			smtp.PlainAuth("", "username@gmail.com", "password", "smtp.gmail.com"),
			env.Sender,
			env.Recipients,
			body,
		)
	}
}

// restrictHelo rejects HELOs from peers whose IP doesn't match a whitelist.
func restrictHelo() smtpd.Middleware {
	return smtpd.Middleware{
		CheckHelo: func(ctx context.Context, peer smtpd.Peer, _ string) (context.Context, error) {
			if !strings.HasPrefix(peer.Addr.String(), "42.42.42.42:") {
				return ctx, errors.New("Denied")
			}
			return ctx, nil
		},
	}
}

func ExampleServer() {
	// No-op server. Accepts and discards.
	server := &smtpd.Server{}
	_ = server.ListenAndServe("127.0.0.1:10025")

	// Relay server. Accepts only from a single IP and forwards via Gmail SMTP.
	relay := &smtpd.Server{Handler: relayHandler()}
	relay.Use(restrictHelo())
	_ = relay.ListenAndServe("127.0.0.1:10025")
}

func ExampleServer_Use() {
	// Compose a terminal Handler with per-phase middleware. Check* adapters
	// from the middleware package lift plain check functions into
	// smtpd.Middleware values bound to a specific SMTP phase. Middlewares
	// run in Use order; the first non-nil error short-circuits that phase.
	//
	//   spf := middleware.SPF()
	//   rbl := middleware.RBL([]string{"bl.example.com"})
	//   srv.Use(middleware.CheckConnection(middleware.IPAddressRateLimit(1, 10)))
	//   srv.Use(middleware.CheckConnection(rbl.ConnectionCheck))
	//   srv.Use(middleware.CheckHelo(spf.HeloCheck))
	//   srv.Use(middleware.CheckSender(spf.SenderCheck))
	srv := &smtpd.Server{Handler: relayHandler()}
	_ = srv.ListenAndServe("127.0.0.1:10025")
}
