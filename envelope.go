package smtpd

import "io"

// Envelope holds a message. Data is a streaming body that the handler
// must fully read and Close. The server drains and closes it on return
// from the handler regardless, to keep the SMTP protocol in sync.
type Envelope struct {
	Sender     string
	Recipients []string
	Data       io.ReadCloser

	// DSN holds the delivery status notification parameters of RFC 3461
	// that came with the transaction. It is nil when the server runs
	// without Server.EnableDSN, and nil when the client sent none of the
	// parameters.
	DSN *DSN
}
