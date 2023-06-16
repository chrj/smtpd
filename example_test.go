package smtpd_test

import (
	"errors"
	"fmt"
	"log"
	"net/smtp"
	"strings"

	"github.com/chrj/smtpd"
)

func ExampleServer() {
	var server *smtpd.Server

	// No-op server. Accepts and discards
	server = &smtpd.Server{}
	server.ListenAndServe("127.0.0.1:10025")

	// Relay server. Accepts only from single IP address and forwards using the Gmail smtp
	server = &smtpd.Server{

		HeloChecker: func(peer *smtpd.Peer, name string) error {
			if !strings.HasPrefix(peer.Addr.String(), "42.42.42.42:") {
				return errors.New("denied")
			}
			return nil
		},

		RecipientChecker: func(peer *smtpd.Peer, addr string) error {
			peer.IncrInt("recipientsQueued", 1)
			if strings.HasPrefix("scubad1ver", addr) {
				// it is bad idea ;-)
				peer.SetString("never_send_to_scuba", addr)
			}
			return nil
		},

		Handler: func(peer *smtpd.Peer, env smtpd.Envelope) error {
			numberOfRecepients, ok := peer.Meta["recipientsQueued"]
			if ok {
				log.Printf("Sending email for %v recipients...", numberOfRecepients)
			}
			never, ok := peer.Meta["never_send_to_scuba"]
			if ok {
				return smtpd.Error{
					Code:    521,
					Message: fmt.Sprintf("Sending messages to %s is a bad idea", never),
				}
			}

			return smtp.SendMail(
				"smtp.gmail.com:587",
				smtp.PlainAuth(
					"",
					"username@gmail.com",
					"password",
					"smtp.gmail.com",
				),
				env.Sender,
				env.Recipients,
				env.Data,
			)

		},
	}

	server.ListenAndServe("127.0.0.1:10025")
}
