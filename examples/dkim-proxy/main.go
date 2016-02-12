// Command dkim-proxy implements a simple SMTP proxy that DKIM signs incoming e-mail and relays to another SMTP server for delivery
package main

import (
	"bytes"
	"flag"
	"io/ioutil"
	"log"
	"net/smtp"

	"bitbucket.org/chrj/smtpd"
	"github.com/eaigner/dkim"
)

var (
	welcomeMsg  = flag.String("welcome", "DKIM-proxy ESMTP ready.", "Welcome message for SMTP session")
	inAddr      = flag.String("inaddr", "localhost:10025", "Address to listen for incoming SMTP on")
	outAddr     = flag.String("outaddr", "localhost:25", "Address to deliver outgoing SMTP on")
	privKeyFile = flag.String("key", "", "Private key file.")
	dkimS       = flag.String("s", "default", "DKIM selector")
	dkimD       = flag.String("d", "", "DKIM domain")

	dkimConf dkim.Conf
	privKey  []byte
)

func handler(peer smtpd.Peer, env smtpd.Envelope) error {

	d, err := dkim.New(dkimConf, privKey)
	if err != nil {
		log.Printf("DKIM error: %v", err)
		return smtpd.Error{450, "Internal server error"}
	}

	// The dkim package expects \r\n newlines, so replace to that
	data, err := d.Sign(bytes.Replace(env.Data, []byte("\n"), []byte("\r\n"), -1))
	if err != nil {
		log.Printf("DKIM signing error: %v", err)
		return smtpd.Error{450, "Internal server error"}
	}

	return smtp.SendMail(
		*outAddr,
		nil,
		env.Sender,
		env.Recipients,
		data,
	)

}

func main() {

	flag.Parse()

	var err error

	dkimConf, err = dkim.NewConf(*dkimD, *dkimS)
	if err != nil {
		log.Fatalf("DKIM configuration error: %v", err)
	}

	privKey, err = ioutil.ReadFile(*privKeyFile)
	if err != nil {
		log.Fatalf("Couldn't read private key: %v", err)
	}

	_, err = dkim.New(dkimConf, privKey)
	if err != nil {
		log.Fatalf("DKIM error: %v", err)
	}

	server := &smtpd.Server{
		WelcomeMessage: *welcomeMsg,
		Handler:        handler,
	}

	server.ListenAndServe(*inAddr)

}
