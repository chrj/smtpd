// Command dkim-proxy implements a simple SMTP proxy that DKIM signs incoming e-mail and relays to another SMTP server for delivery
package main

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"io/ioutil"
	"log"
	"net/smtp"

	"github.com/chrj/smtpd"
	"github.com/emersion/go-msgauth/dkim"
)

var (
	welcomeMsg  = flag.String("welcome", "DKIM-proxy ESMTP ready.", "Welcome message for SMTP session")
	inAddr      = flag.String("inaddr", "localhost:10025", "Address to listen for incoming SMTP on")
	outAddr     = flag.String("outaddr", "localhost:25", "Address to deliver outgoing SMTP on")
	privKeyFile = flag.String("key", "", "PEM encoded RSA private key file.")
	dkimS       = flag.String("s", "default", "DKIM selector")
	dkimD       = flag.String("d", "", "DKIM domain")

	dkimOptions *dkim.SignOptions
)

func handler(peer smtpd.Peer, env smtpd.Envelope) error {

	out := bytes.NewBuffer(nil)
	in := bytes.NewBuffer(bytes.Replace(env.Data, []byte("\n"), []byte("\r\n"), -1))
	// The dkim package expects \r\n newlines, so replace to that
	err := dkim.Sign(out, in, dkimOptions)
	if err != nil {
		log.Printf("DKIM signing error: %v", err)
		return smtpd.Error{Code: 450, Message: "Internal server error"}
	}

	return smtp.SendMail(
		*outAddr,
		nil,
		env.Sender,
		env.Recipients,
		out.Bytes(),
	)

}

func getSigner() crypto.Signer {
	privKey, err := ioutil.ReadFile(*privKeyFile)
	if err != nil {
		log.Fatalf("Couldn't read private key: %v", err)
	}
	pemBlock, _ := pem.Decode(privKey)
	if pemBlock == nil {
		log.Fatalf("Couldn't decode private key: %v", err)
	}
	rsa, err := x509.ParsePKCS1PrivateKey(pemBlock.Bytes)
	if err != nil {
		log.Fatalf("Couldn't parse as RSA private key: %v", err)
	}
	return rsa
}

func main() {

	flag.Parse()

	dkimOptions = &dkim.SignOptions{
		Domain:   *dkimD,
		Selector: *dkimS,
		Signer:   getSigner(),
	}

	server := &smtpd.Server{
		WelcomeMessage: *welcomeMsg,
		Handler:        handler,
	}

	server.ListenAndServe(*inAddr)

}
