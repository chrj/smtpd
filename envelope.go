package smtpd

import "io"

// BodyType is the value of the BODY parameter of MAIL FROM. RFC 1652 gives
// the first two values, and RFC 3030 adds the third.
type BodyType string

const (
	// Body7Bit is a message of 7-bit text, which is what a client that sends
	// no BODY parameter means.
	Body7Bit BodyType = "7BIT"

	// Body8BitMIME is a message of 8-bit text with lines.
	Body8BitMIME BodyType = "8BITMIME"

	// BodyBinaryMIME is a message of octets without a line structure. RFC
	// 3030 gives it to BDAT alone: the server answers 503 to a DATA command
	// for such a message, because the dot that ends a DATA message has no
	// meaning in binary content.
	BodyBinaryMIME BodyType = "BINARYMIME"
)

// Envelope holds a message. Data is a streaming body that the handler
// must fully read and Close. The server drains and closes it on return
// from the handler regardless, to keep the SMTP protocol in sync.
//
// A message that arrives in BDAT chunks gives Data the chunks as they come,
// so a handler that reads it to the end waits for the last chunk. Close on
// such a body does nothing: the session owns the stream, because it still has
// to read the rest of the message off the wire.
type Envelope struct {
	Sender     string
	Recipients []string
	Data       io.ReadCloser

	// BodyType is the value of the BODY parameter of MAIL FROM. The empty
	// string means that the client sent no BODY parameter, which RFC 1652
	// reads as a message of 7-bit text.
	//
	// A message of BodyBinaryMIME arrives through BDAT, and Data gives its
	// octets as they came. Such a message carries no line structure, so a
	// handler that writes it on must keep it whole.
	BodyType BodyType

	// SMTPUTF8 says that the client sent the SMTPUTF8 parameter of RFC 6531
	// with MAIL FROM. Such a transaction takes an address of Unicode in
	// UTF-8 in Sender and Recipients, and the message carries headers in
	// UTF-8 as well.
	//
	// A server without Server.EnableSMTPUTF8 offers the extension to no
	// client, so the parameter never arrives and the field is always false
	// there. Such a server reads an address as it did before the extension,
	// which leaves a value of Unicode possible in Sender and Recipients.
	//
	// A handler that hands the message to another server must send the
	// parameter on, and must find a server that offers the extension. A
	// server without it takes none of these addresses.
	SMTPUTF8 bool

	// DSN holds the delivery status notification parameters of RFC 3461
	// that came with the transaction. It is nil when the server runs
	// without Server.EnableDSN, and nil when the client sent none of the
	// parameters.
	DSN *DSN

	// recipientErrs holds the answer that each recipient of an LMTP delivery
	// gets, as RejectRecipient recorded it. Index i belongs to address i of
	// Recipients, and nil there gives that recipient the reply of the
	// message.
	recipientErrs []error
}
