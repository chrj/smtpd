package main

import (
	"bitbucket.org/chrj/smtpd"
	"crypto/tls"
	"flag"
	"log"
)

func dumpMessage(peer smtpd.Peer, env smtpd.Envelope) error {
	log.Printf("New mail from: %s", env.MailFrom)
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
		Addr:           "127.0.0.1:10025",
		WelcomeMessage: "localhost ESMTP ready.",
		Handler:        dumpMessage,
		TLSConfig:      tlsConfig,
		ForceTLS:       true,
	}

	server.ListenAndServe()

	return

}
