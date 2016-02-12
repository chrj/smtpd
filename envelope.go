package smtpd

import (
	"crypto/tls"
	"fmt"
	"strings"
	"time"
)

// Envelope holds a message
type Envelope struct {
	Sender     string
	Recipients []string
	Data       []byte
}

// AddReceivedLine prepends a Received header to the Data
func (env *Envelope) AddReceivedLine(peer Peer) {

	tlsDetails := ""

	tlsVersions := map[uint16]string{
		tls.VersionSSL30: "SSL3.0",
		tls.VersionTLS10: "TLS1.0",
		tls.VersionTLS11: "TLS1.1",
		tls.VersionTLS12: "TLS1.2",
	}

	if peer.TLS != nil {
		tlsDetails = fmt.Sprintf(
			"\r\n\t(version=%s cipher=0x%x);",
			tlsVersions[peer.TLS.Version],
			peer.TLS.CipherSuite,
		)
	}

	line := wrap([]byte(fmt.Sprintf(
		"Received: from %s [%s] by %s with %s;%s\r\n\t%s\r\n",
		peer.HeloName,
		strings.Split(peer.Addr.String(), ":")[0],
		peer.ServerName,
		peer.Protocol,
		tlsDetails,
		time.Now().Format("Mon Jan 2 15:04:05 -0700 2006"),
	)))

	env.Data = append(env.Data, line...)

	// Move the new Received line up front

	copy(env.Data[len(line):], env.Data[0:len(env.Data)-len(line)])
	copy(env.Data, line)

}
