package smtptest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"sync"
	"time"
)

// localhostCert returns the certificate that a TLS server presents when the
// test supplies none. It is valid for "localhost", 127.0.0.1 and ::1, and it
// signs itself, so a client trusts the server when it holds this one
// certificate.
//
// The certificate is generated once for each test binary. Every server in
// the binary shares it, so the test pays the cost of the key generation one
// time.
var localhostCert = sync.OnceValue(newLocalhostCert)

// newLocalhostCert creates a self-signed certificate for the loopback
// interface. It is valid from one hour in the past until 24 hours in the
// future.
func newLocalhostCert() tls.Certificate {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(fmt.Sprintf("smtptest: generate the key of the test certificate: %v", err))
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		panic(fmt.Sprintf("smtptest: generate the serial number of the test certificate: %v", err))
	}

	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{Organization: []string{"smtptest"}, CommonName: "localhost"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		panic(fmt.Sprintf("smtptest: create the test certificate: %v", err))
	}

	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		panic(fmt.Sprintf("smtptest: parse the test certificate: %v", err))
	}

	return tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  key,
		Leaf:        leaf,
	}
}
