package smtpd_test

import (
	"context"
	"errors"
	"io"
	"net/smtp"
	"strings"

	"github.com/chrj/smtpd/v2/pkg/smtpd"
	"github.com/chrj/smtpd/v2/pkg/smtpd/middleware"
)

type relayHandler struct{}

func (relayHandler) ServeSMTP(_ context.Context, _ smtpd.Peer, env *smtpd.Envelope) error {
	defer func() { _ = env.Data.Close() }()
	body, err := io.ReadAll(env.Data)
	if err != nil {
		return err
	}
	return smtp.SendMail(
		"smtp.gmail.com:587",
		smtp.PlainAuth("", "username@gmail.com", "password", "smtp.gmail.com"),
		env.Sender,
		env.Recipients,
		body,
	)
}

func (relayHandler) CheckHelo(ctx context.Context, peer smtpd.Peer, _ string) (context.Context, error) {
	if !strings.HasPrefix(peer.Addr.String(), "42.42.42.42:") {
		return ctx, errors.New("Denied")
	}
	return ctx, nil
}

func ExampleServer() {
	// No-op server. Accepts and discards.
	server := &smtpd.Server{}
	_ = server.ListenAndServe("127.0.0.1:10025")

	// Relay server. Accepts only from a single IP and forwards via Gmail SMTP.
	relay := &smtpd.Server{
		Handler: relayHandler{},
	}
	_ = relay.ListenAndServe("127.0.0.1:10025")
}

func ExampleChain() {
	// Compose a base Handler with middleware. Each check builder produces a
	// plain function; Check* adapters lift it into a smtpd.Middleware bound
	// to a specific SMTP phase. Leftmost runs outermost.
	//
	//   spf := middleware.SPF()
	//   rbl := middleware.RBL([]string{"bl.example.com"})
	//   srv.Handler = middleware.Chain(
	//       relayHandler{},
	//       middleware.CheckConnection(middleware.IPAddressRateLimit(1, 10)),
	//       middleware.CheckConnection(rbl.Check),
	//       middleware.CheckHelo(spf.Helo),
	//       middleware.CheckSender(spf.MailFrom),
	//   )
	srv := &smtpd.Server{
		Handler: middleware.Chain(relayHandler{}),
	}
	_ = srv.ListenAndServe("127.0.0.1:10025")
}
