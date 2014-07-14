package smtpd

import (
	"bitbucket.org/chrj/smtpd"
	"errors"
	"net"
	"net/smtp"
	"strings"
)

func ExampleServer() {

	// No-op server. Accepts and discards
	server := &smtpd.Server{}
	server.serve()

	// Relay server. Accepts only from single IP address and forwards using the Gmail smtp
	server := &smtpd.Server{

		Addr: "0.0.0.0:10025",

		HeloChecker: func(peer smtpd.Peer) error {
			if !strings.HasPrefix(peer.Addr.String(), "42.42.42.42:") {
				return errors.New("Denied")
			}
			return nil
		},

		Handler: func(peer smtpd.Peer, env smtpd.Envelope) error {
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

	server.serve()

}
