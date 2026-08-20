package smtpd

import "strings"

// Verification is what a Verify hook found for the name that a VRFY command
// carried. RFC 5321 section 3.5.1 gives the command a user name, a mailbox,
// or a string of another kind that the site knows.
//
// The zero value says that the hook verified nothing, and the client gets the
// 252 reply of RFC 5321 section 7.3. A hook that knows the name to be wrong
// returns an Error instead, such as 550 for a user that the server does not
// carry.
type Verification struct {
	// Mailbox is the address of the user, in the form that Envelope.Sender
	// takes: "user@example.org", without the angle brackets. The server
	// writes it inside them, which RFC 5321 section 3.5.2 asks for.
	//
	// The address needs a domain, because the client writes it into a RCPT
	// TO command of its own. A mailbox that is not an address gets the 252
	// reply, and the server writes the fault to the log.
	Mailbox string

	// FullName is the name of the user, such as "Jörg Smith". RFC 5321
	// section 3.5.1 writes it before the mailbox, and it is optional.
	//
	// The server takes the angle brackets out of it, so that the reply
	// carries one address alone.
	FullName string
}

// cannotVerify is the reply to a name that the server did not verify. RFC
// 5321 section 7.3 asks for 252 there, and for that code alone: a server that
// answers 250 says that it verified the name, and one that answers 550 says
// that the name is wrong.
const cannotVerify = "Cannot VRFY user, but will accept message and attempt delivery"

// cannotShowMailbox is the reply to a mailbox of Unicode. RFC 5321 holds a
// reply to US-ASCII, and RFC 6531 section 3.7.4.2 gives UTF-8 to a client that
// asked for it with the SMTPUTF8 parameter of a VRFY command. This server
// offers neither, so it cannot write such a mailbox at all.
//
// The same section gives 252 or 550 for that, with the status code X.6.8.
const cannotShowMailbox = "Cannot show the mailbox of the user without a reply in UTF-8"

// verifyLine writes the text of a 250 reply to a VRFY command. RFC 5321
// section 3.5.1 gives two forms for it:
//
//	User Name <local-part@domain>
//	<local-part@domain>
//
// mailbox comes from parseAddress, so it is an address that the client can
// write into a RCPT TO command.
func verifyLine(fullName, mailbox string) string {
	name := strings.TrimSpace(stripBrackets(fullName))
	if name == "" {
		return "<" + mailbox + ">"
	}
	return name + " <" + mailbox + ">"
}

// stripBrackets takes the angle brackets out of a name. The name of a user
// comes from a directory of the site, where anything can stand, and a reply
// that carries a second pair of brackets gives the client a second address.
func stripBrackets(name string) string {
	if !strings.ContainsAny(name, "<>") {
		return name
	}
	return strings.NewReplacer("<", "", ">", "").Replace(name)
}
