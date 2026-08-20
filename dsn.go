package smtpd

import "strings"

// DSN holds the delivery status notification parameters of RFC 3461. The
// client sends them to say what a notification carries back, and for which
// recipients.
//
// The server reads the parameters and puts them on the envelope. It writes
// no notification of its own, because only the handler knows what became of
// the message.
//
// Envelope.DSN is nil unless the server runs with Server.EnableDSN and the
// client sent at least one of the parameters.
type DSN struct {
	// Return is the RET parameter of MAIL FROM. It says how much of the
	// message a notification carries back. The empty string means that the
	// client sent no RET parameter.
	Return DSNReturn

	// EnvID is the ENVID parameter of MAIL FROM, decoded from xtext. The
	// client puts an identifier of its own there, and a notification carries
	// that identifier back. The empty string means that the client sent no
	// ENVID parameter.
	EnvID string

	// Recipients holds one entry for each address in Envelope.Recipients, at
	// the same index. A recipient that came with no parameter of its own has
	// the zero value there.
	Recipients []RecipientDSN
}

// DSNReturn is the value of the RET parameter of MAIL FROM.
type DSNReturn string

const (
	// DSNReturnFull asks for the whole message in a notification.
	DSNReturnFull DSNReturn = "FULL"

	// DSNReturnHeaders asks for the headers of the message only.
	DSNReturnHeaders DSNReturn = "HDRS"
)

// RecipientDSN holds the delivery status notification parameters of one
// RCPT TO command.
type RecipientDSN struct {
	// Notify is the NOTIFY parameter. The zero value means that the client
	// sent none, and the default of RFC 3461 section 4.1 applies.
	Notify DSNNotify

	// OriginalRecipient is the address of the ORCPT parameter, decoded from
	// xtext. A server with Server.EnableSMTPUTF8 reads the encoding of RFC
	// 6533 instead where OriginalType is "utf-8".
	//
	// It holds the recipient as the first sender wrote it, which a forward or
	// an alias along the way can have changed since.
	//
	// RFC 3461 lets the address be empty, so OriginalType is the field that
	// tells you whether the client sent an ORCPT parameter.
	OriginalRecipient string

	// OriginalType is the address type of the ORCPT parameter, such as
	// "rfc822". The empty string means that the client sent no ORCPT
	// parameter.
	OriginalType string
}

// DSNNotify is the set of events that the client asks for a notification
// about. It is the value of the NOTIFY parameter of RCPT TO, where the
// events stand in a list, such as "SUCCESS,DELAY".
type DSNNotify uint8

const (
	// DSNNotifyNever asks for no notification at all. RFC 3461 gives this
	// value alone, so it never comes together with one of the other three.
	DSNNotifyNever DSNNotify = 1 << iota

	// DSNNotifySuccess asks for a notification on a delivery that succeeds.
	DSNNotifySuccess

	// DSNNotifyFailure asks for a notification on a delivery that fails.
	DSNNotifyFailure

	// DSNNotifyDelay asks for a notification on a delivery that is late.
	DSNNotifyDelay
)

// String writes the events in the form that the NOTIFY parameter takes, such
// as "SUCCESS,DELAY". The zero value gives an empty string, which is what a
// relay writes when it passes the recipient on without a NOTIFY parameter.
func (n DSNNotify) String() string {
	if n&DSNNotifyNever != 0 {
		return "NEVER"
	}

	var events []string
	if n&DSNNotifySuccess != 0 {
		events = append(events, "SUCCESS")
	}
	if n&DSNNotifyFailure != 0 {
		events = append(events, "FAILURE")
	}
	if n&DSNNotifyDelay != 0 {
		events = append(events, "DELAY")
	}

	return strings.Join(events, ",")
}

const (
	// maxEnvIDLength is the length that RFC 3461 section 4.4 gives for the
	// value of the ENVID parameter.
	maxEnvIDLength = 100

	// maxORcptLength is the length that RFC 3461 section 4.2 gives for the
	// value of the ORCPT parameter.
	maxORcptLength = 500

	// utf8AddrType is the address type that RFC 6533 section 3 gives to an
	// ORCPT parameter that carries an address of Unicode.
	utf8AddrType = "utf-8"
)

// parseDSNReturn reads the RET parameter of MAIL FROM. RFC 3461 section 4.3
// gives two values for it, and a client writes either one in any case.
func parseDSNReturn(value string) (DSNReturn, bool) {
	switch strings.ToUpper(value) {
	case string(DSNReturnFull):
		return DSNReturnFull, true
	case string(DSNReturnHeaders):
		return DSNReturnHeaders, true
	}
	return "", false
}

// parseEnvID reads the ENVID parameter of MAIL FROM. The value is xtext, and
// RFC 3461 section 4.4 holds it to 100 characters.
func parseEnvID(value string) (string, bool) {
	if len(value) > maxEnvIDLength {
		return "", false
	}
	return parseXtext(value)
}

// parseNotify reads the NOTIFY parameter of RCPT TO. RFC 3461 section 4.1
// writes the events in a list with a comma between them, in any case. NEVER
// stands alone, and a list that carries it with another event is an error.
func parseNotify(value string) (DSNNotify, bool) {
	var notify DSNNotify

	for element := range strings.SplitSeq(value, ",") {
		switch strings.ToUpper(element) {
		case "NEVER":
			notify |= DSNNotifyNever
		case "SUCCESS":
			notify |= DSNNotifySuccess
		case "FAILURE":
			notify |= DSNNotifyFailure
		case "DELAY":
			notify |= DSNNotifyDelay
		default:
			return 0, false
		}
	}

	if notify&DSNNotifyNever != 0 && notify != DSNNotifyNever {
		return 0, false
	}

	return notify, true
}

// parseORcpt reads the ORCPT parameter of RCPT TO. RFC 3461 section 4.2
// writes it as an address type, a semicolon and the address in xtext, and
// holds the value to 500 characters.
//
// The "utf-8" address type of RFC 6533 carries an address of Unicode, and it
// takes an encoding of its own where "\x{HEX}" holds a code point. RFC 6531
// section 3.2 asks for this address type from a server that offers both
// extensions, so two flags say how to read it:
//
//   - utf8Type says that the server offers SMTPUTF8 and reads the address
//     type. A server without the extension takes the value as ordinary
//     xtext, in the way that it did before RFC 6533.
//   - raw says that the transaction carries the SMTPUTF8 parameter, which
//     lets the address hold UTF-8 as it is. RFC 6533 section 3 asks every
//     other client for the escape.
//
// The address is empty when the client writes an address type and a
// semicolon alone. RFC 3461 gives xtext as a string of no length or more,
// which makes that value a good one.
func parseORcpt(value string, utf8Type, raw bool) (addrType, addr string, ok bool) {
	if len(value) > maxORcptLength {
		return "", "", false
	}

	addrType, encoded, found := strings.Cut(value, ";")
	if !found || !isAtom(addrType) {
		return "", "", false
	}

	if utf8Type && strings.EqualFold(addrType, utf8AddrType) {
		addr, ok = parseUnitext(encoded, raw)
	} else {
		addr, ok = parseXtext(encoded)
	}
	if !ok {
		return "", "", false
	}

	return addrType, addr, true
}

// isAtom reports whether s is an atom, the form that RFC 3461 gives for the
// address type of an ORCPT parameter.
func isAtom(s string) bool {
	if s == "" {
		return false
	}

	for i := 0; i < len(s); i++ {
		if !isAtext(s[i]) {
			return false
		}
	}

	return true
}

// recordRecipientDSN keeps the parameters of the recipient that RCPT TO added
// last. The caller appends the address to Recipients first.
//
// The two slices carry the same length, so index i of DSN.Recipients always
// describes address i of Recipients. A recipient that came with no parameter
// of its own gets the zero value, and the first recipient that carries one
// brings the DSN into being.
func (e *Envelope) recordRecipientDSN(r RecipientDSN) {
	if e.DSN == nil {
		if r == (RecipientDSN{}) {
			return
		}
		e.DSN = &DSN{}
	}

	for len(e.DSN.Recipients) < len(e.Recipients)-1 {
		e.DSN.Recipients = append(e.DSN.Recipients, RecipientDSN{})
	}

	e.DSN.Recipients = append(e.DSN.Recipients, r)
}
