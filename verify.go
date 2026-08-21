package smtpd

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"unicode/utf8"
)

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

// cannotShowMailbox is the reply to a mailbox of Unicode that the client
// cannot read. RFC 5321 holds a reply to US-ASCII, and RFC 6531 section
// 3.7.4.2 gives UTF-8 to a client that asked for it with the SMTPUTF8
// parameter of the VRFY command.
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

// handleVRFY answers the VRFY command of RFC 5321 section 4.1.1.6. The
// command asks the server to confirm that a name stands for a user, and the
// Verify hooks of the middleware look it up.
//
// The command carries no transaction, so it needs no HELO and no MAIL FROM
// before it. RFC 5321 section 4.1.4 lets a client send it at any time.
func (s *session) handleVRFY(ctx context.Context, cmd *command) context.Context {
	ctx, logger := phasedLoggerFromContext(ctx, "vrfy")

	// RFC 5321 section 3.5.1 leaves the form of the name to the site, so the
	// argument goes to the hooks as it came. A name that carries a space
	// reaches them whole.
	//
	// smtputf8 says that the client sent the SMTPUTF8 parameter of RFC 6531
	// section 3.7.4.2, which lets the reply to this one command carry UTF-8.
	name, smtputf8, err := cmd.vrfyArg(s.server.EnableSMTPUTF8)
	if err != nil {
		return s.replyEnhanced(ctx, 501, EnhancedCode{5, 5, 4}, "The SMTPUTF8 parameter takes no value")
	}
	if name == "" {
		return s.replyEnhanced(ctx, 501, EnhancedCode{5, 5, 4}, "Missing parameter")
	}

	ctx, verified, err := s.server.verify(ctx, s.peer, name)
	if err != nil {
		var smtpErr Error
		if errors.As(err, &smtpErr) {
			return s.replyError(ctx, err)
		}

		// A lookup that failed is not a command that the server does not
		// carry, and replyError answers 502 to an error of another kind. RFC
		// 5321 section 3.5.3 reads a 500 and a 502 as the answer of a server
		// without VRFY, so a fault of the directory takes a 451 instead.
		//
		// The text of the error stays in the log. It comes from the site, and
		// a client of any kind reads a reply.
		logger.ErrorContext(ctx, "the Verify hook failed",
			slog.String("name", name),
			slog.Any("err", err),
		)
		return s.replyEnhanced(ctx, 451, EnhancedCode{4, 3, 0}, "Cannot verify the user right now")
	}

	if verified.Mailbox == "" {
		return s.reply(ctx, 252, cannotVerify)
	}

	// The client writes the mailbox of the reply into a RCPT TO command of
	// its own, so a value that is not an address never goes on the wire. RFC
	// 5321 section 7.3 asks the server to answer 252 where it cannot say
	// that it verified the name.
	mailbox, err := parseAddress(verified.Mailbox)
	if err != nil {
		logger.ErrorContext(ctx, "the Verify hook gave a mailbox that is not an address",
			slog.String("name", name),
			slog.String("mailbox", verified.Mailbox),
			slog.Any("err", err),
		)
		return s.reply(ctx, 252, cannotVerify)
	}

	// RFC 6531 widens the reply to UTF-8, and to nothing else. A byte outside
	// that encoding is not a character at all, and it reaches a client that
	// reads the reply as UTF-8.
	if !utf8.ValidString(mailbox) {
		logger.ErrorContext(ctx, "the Verify hook gave a mailbox that is not UTF-8",
			slog.String("name", name),
			slog.String("mailbox", verified.Mailbox),
		)
		return s.reply(ctx, 252, cannotVerify)
	}

	fullName := verified.FullName

	// RFC 5321 holds the text of a reply to US-ASCII, and RFC 6531 section
	// 3.7.4.2 widens it for the client that asked with the SMTPUTF8 parameter
	// of this command. A client without it reads a reply that it cannot,
	// which the same section keeps it away from.
	//
	// The name of the user is the part that RFC 5321 section 3.5.1 leaves
	// out, so a name of Unicode goes and the mailbox stays. A mailbox of
	// Unicode leaves nothing to write, and RFC 6531 gives 252 for it.
	if !smtputf8 {
		if !isASCII(mailbox) {
			return s.replyEnhanced(ctx, 252, EnhancedCode{2, 6, 8}, cannotShowMailbox)
		}
		if !isASCII(fullName) {
			fullName = ""
		}
	} else if !utf8.ValidString(fullName) {
		// The name of the user is the part that the reply can leave out, so a
		// name that is not UTF-8 goes and the mailbox stays.
		logger.ErrorContext(ctx, "the Verify hook gave a name that is not UTF-8",
			slog.String("name", name),
			slog.String("full_name", fullName),
		)
		fullName = ""
	}

	return s.replyEnhanced(ctx, 250, EnhancedCode{2, 1, 5}, verifyLine(fullName, mailbox))
}
