// Command gmail-relay is an SMTP relay that accepts mail on a local port,
// runs per-IP rate limiting, SPF and RBL checks, and forwards accepted
// messages to Gmail over SMTP submission.
package main

import (
	"context"
	"crypto/tls"
	"flag"
	"io"
	"log/slog"
	"net/smtp"
	"os"
	"strings"

	"github.com/chrj/smtpd/v2/pkg/smtpd"
	"github.com/chrj/smtpd/v2/pkg/smtpd/middleware"
)

var (
	listenAddr = flag.String("listen", "127.0.0.1:10025", "Address to listen for incoming SMTP on")
	welcomeMsg = flag.String("welcome", "gmail-relay ESMTP ready.", "Welcome message for SMTP session")
	gmailUser  = flag.String("user", "", "Gmail account (e.g. you@gmail.com)")
	gmailPass  = flag.String("pass", "", "Gmail app password")
	rblLists   = flag.String("rbl", "zen.spamhaus.org,bl.spamcop.net", "Comma-separated DNSBL zones")
	rps        = flag.Float64("rps", 1, "Per-IP connection rate (tokens/second)")
	burst      = flag.Int("burst", 5, "Per-IP burst size")
)

const (
	gmailHost = "smtp.gmail.com"
	gmailAddr = "smtp.gmail.com:587"
)

// forwardToGmail streams env.Data straight into the upstream DATA writer
// without buffering the message body, by driving an smtp.Client directly
// rather than going through smtp.SendMail.
func forwardToGmail(user, pass string) smtpd.Handler {
	auth := smtp.PlainAuth("", user, pass, gmailHost)
	return func(ctx context.Context, _ smtpd.Peer, env *smtpd.Envelope) (context.Context, error) {
		defer func() { _ = env.Data.Close() }()

		relayErr := func(err error) error {
			smtpd.LoggerFromContext(ctx).Error("relay failed", slog.Any("err", err))
			return smtpd.Error{Code: 451, Message: "upstream delivery failed"}
		}

		c, err := smtp.Dial(gmailAddr)
		if err != nil {
			return ctx, relayErr(err)
		}
		defer func() { _ = c.Close() }()

		if err := c.Hello("localhost"); err != nil {
			return ctx, relayErr(err)
		}
		if err := c.StartTLS(&tls.Config{ServerName: gmailHost}); err != nil {
			return ctx, relayErr(err)
		}
		if err := c.Auth(auth); err != nil {
			return ctx, relayErr(err)
		}
		if err := c.Mail(env.Sender); err != nil {
			return ctx, relayErr(err)
		}
		for _, rcpt := range env.Recipients {
			if err := c.Rcpt(rcpt); err != nil {
				return ctx, relayErr(err)
			}
		}

		w, err := c.Data()
		if err != nil {
			return ctx, relayErr(err)
		}
		if _, err := io.Copy(w, env.Data); err != nil {
			_ = w.Close()
			return ctx, relayErr(err)
		}
		if err := w.Close(); err != nil {
			return ctx, relayErr(err)
		}
		if err := c.Quit(); err != nil {
			return ctx, relayErr(err)
		}
		return ctx, nil
	}
}

func main() {
	flag.Parse()

	if *gmailUser == "" || *gmailPass == "" {
		slog.Error("both -user and -pass are required")
		os.Exit(2)
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))

	lists := strings.Split(*rblLists, ",")
	for i := range lists {
		lists[i] = strings.TrimSpace(lists[i])
	}
	rbl := middleware.RBL(lists)
	spf := middleware.SPF()

	srv := &smtpd.Server{
		WelcomeMessage: *welcomeMsg,
		Logger:         logger,
		Handler:        forwardToGmail(*gmailUser, *gmailPass),
	}

	srv.Use(middleware.CheckConnection(middleware.IPAddressRateLimit(*rps, *burst)))
	srv.Use(middleware.CheckConnection(rbl.ConnectionCheck))
	srv.Use(middleware.CheckHelo(spf.HeloCheck))
	srv.Use(middleware.CheckSender(spf.SenderCheck))

	logger.Info("listening", slog.String("addr", *listenAddr))
	if err := srv.ListenAndServe(*listenAddr); err != nil {
		logger.Error("server stopped", slog.Any("err", err))
		os.Exit(1)
	}
}
