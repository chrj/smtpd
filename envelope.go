package smtpd

import "io"

// Envelope holds a message. Data is a streaming body that the handler
// must fully read and Close. The server drains and closes it on return
// from the handler regardless, to keep the SMTP protocol in sync.
type Envelope struct {
	Sender     string
	Recipients []string
	Data       io.ReadCloser
}
