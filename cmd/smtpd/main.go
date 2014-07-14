package main

import (
	"bitbucket.org/chrj/smtpd"
	"crypto/tls"
	"flag"
	"log"
)

func authenticate(peer smtpd.Peer, username, password string) error {
	log.Printf("Auth: %s / %s", username, password)
	return nil
}

func dumpMessage(peer smtpd.Peer, env smtpd.Envelope) error {
	log.Printf("New mail from: %s", env.Sender)
	return nil
}

var tlsCert = flag.String("tlscert", "", "TLS: Certificate file")
var tlsKey = flag.String("tlskey", "", "TLS: Private key")

func main() {

	flag.Parse()

	var tlsConfig *tls.Config

	if *tlsCert != "" {
		cert, err := tls.LoadX509KeyPair(*tlsCert, *tlsKey)
		if err != nil {
			log.Fatal("certificate error:", err)
		}
		tlsConfig = &tls.Config{
			Certificates: []tls.Certificate{cert},
		}
	}

	server := &smtpd.Server{
		Handler:        dumpMessage,
		Authenticator:  authenticate,
		TLSConfig:      tlsConfig,
		ForceTLS:       true,
	}

	server.ListenAndServe()

	return

}
