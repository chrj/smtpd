package smtpd

import "unicode/utf8"

// errSenderNonASCII answers a MAIL FROM command that carries an address of
// Unicode without the SMTPUTF8 parameter. RFC 6531 section 3.5 gives 550 for
// the sender, and the status code 5.6.7 with it.
var errSenderNonASCII = Error{Code: 550, Enhanced: EnhancedCode{5, 6, 7}, Message: "Non-ASCII sender address needs the SMTPUTF8 parameter"}

// errRecipientNonASCII answers a RCPT TO command that carries an address of
// Unicode in a transaction that did not ask for SMTPUTF8. RFC 6531 section
// 3.5 gives 553 for a recipient.
var errRecipientNonASCII = Error{Code: 553, Enhanced: EnhancedCode{5, 6, 7}, Message: "Non-ASCII recipient address needs the SMTPUTF8 parameter"}

// needsSMTPUTF8 reports whether addr carries Unicode that RFC 6531 gives to a
// transaction with the SMTPUTF8 parameter alone.
//
// A server that runs without Server.EnableSMTPUTF8 offers the extension to no
// client, and takes an address as it came.
func (s *session) needsSMTPUTF8(addr string) bool {
	return s.server.EnableSMTPUTF8 && !isASCII(addr)
}

// checkSenderCharset reads the character set of the address of a MAIL FROM
// command. RFC 6531 section 3.5 answers 550 to an address of Unicode that
// came without the SMTPUTF8 parameter, and RFC 6531 gives the address in
// UTF-8, so a byte outside that encoding is a malformed address.
func (s *session) checkSenderCharset(addr string, smtputf8 bool) error {
	if !s.needsSMTPUTF8(addr) {
		return nil
	}
	if !smtputf8 {
		return errSenderNonASCII
	}
	if !utf8.ValidString(addr) {
		return errSenderMalformed
	}
	return nil
}

// checkRecipientCharset reads the character set of the address of a RCPT TO
// command. RFC 6531 section 3.5 answers 553 for a recipient, where it answers
// 550 for the sender.
func (s *session) checkRecipientCharset(addr string) error {
	if !s.needsSMTPUTF8(addr) {
		return nil
	}
	if !s.envelope.SMTPUTF8 {
		return errRecipientNonASCII
	}
	if !utf8.ValidString(addr) {
		return errRecipientMalformed
	}
	return nil
}
