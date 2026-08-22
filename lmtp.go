package smtpd

import (
	"context"
	"fmt"
)

// handleLHLO runs the LHLO command of RFC 2033 section 4.1. It is the
// greeting of LMTP, in the place of HELO and of EHLO, and it carries the
// semantics of EHLO: the reply lists the extensions that the server offers.
func (s *session) handleLHLO(ctx context.Context, cmd *command) context.Context {
	ctx, _ = phasedLoggerFromContext(ctx, "lhlo")
	return s.greetExtended(ctx, cmd, LMTP)
}

// replyWrongGreeting answers the greeting of the other protocol. RFC 2033
// section 4.1 asks an LMTP server for a reply that is not a completion to
// HELO and to EHLO, and an SMTP server knows no LHLO.
//
// The message names the greeting to send, because a client that sends the
// wrong one reaches a server of the other protocol.
func (s *session) replyWrongGreeting(ctx context.Context) context.Context {
	if s.server.LMTP {
		return s.replyEnhanced(ctx, 500, EnhancedCode{5, 5, 1}, "This server speaks LMTP. Send LHLO.")
	}
	return s.replyEnhanced(ctx, 500, EnhancedCode{5, 5, 1}, "This server speaks SMTP. Send EHLO.")
}

// RejectRecipient records the answer that one recipient of an LMTP delivery
// gets. i is the index of the recipient in Recipients.
//
// LMTP writes one reply for every recipient of a message, in the order that
// RCPT TO added them (RFC 2033 section 4.2), so a handler can take a message
// for some of the recipients and refuse it for the rest. A recipient that
// carries no error of its own gets the reply of the message: the error that
// the handler returned, or 250 where it returned none.
//
// err takes the form of the error of a Handler: an Error goes on the wire
// with its code and its message, and every other error becomes a 502. An err
// of nil gives the recipient the reply of the message again.
//
// Call it from a Handler, and before that handler returns. The session writes
// the replies as soon as the last handler of the message ends.
//
// A session of SMTP takes as many recipients as an LMTP one, and it writes
// one reply for all of them: that reply answers for the message, and it reads
// none of these errors. A handler tells the two apart by Peer.Protocol.
//
// It returns an error for an index that no recipient carries, and records
// nothing.
func (e *Envelope) RejectRecipient(i int, err error) error {
	if i < 0 || i >= len(e.Recipients) {
		return fmt.Errorf("smtpd: no recipient at index %d, the envelope carries %d", i, len(e.Recipients))
	}

	for len(e.recipientErrs) < len(e.Recipients) {
		e.recipientErrs = append(e.recipientErrs, nil)
	}

	e.recipientErrs[i] = err
	return nil
}

// recipientErr gives the answer that a handler recorded for recipient i, and
// nil where it recorded none.
func (e *Envelope) recipientErr(i int) error {
	if i >= len(e.recipientErrs) {
		return nil
	}
	return e.recipientErrs[i]
}

// perRecipient reports whether the answer to the end of a message goes to
// every recipient: a server of LMTP with a transaction that has recipients.
func (s *session) perRecipient() bool {
	return s.server.LMTP && s.envelope != nil && len(s.envelope.Recipients) > 0
}

// replyDelivery answers the end of a message that the server took. message is
// the text of the reply for a recipient that it holds the message for.
//
// SMTP takes one reply for the whole message. LMTP takes one for every
// recipient, and a recipient that the handler refused with RejectRecipient
// gets that answer in the place of this one.
func (s *session) replyDelivery(ctx context.Context, message string) context.Context {
	if !s.perRecipient() {
		return s.reply(ctx, 250, message)
	}

	for i := range s.envelope.Recipients {
		if err := s.envelope.recipientErr(i); err != nil {
			ctx = s.replyError(ctx, err)
			continue
		}
		ctx = s.reply(ctx, 250, message)
	}

	return ctx
}

// replyDeliveryError answers the end of a message that the server did not
// take. In LMTP every recipient gets the same answer, because the message
// failed for all of them.
func (s *session) replyDeliveryError(ctx context.Context, err error) context.Context {
	if !s.perRecipient() {
		return s.replyError(ctx, err)
	}

	for range s.envelope.Recipients {
		ctx = s.replyError(ctx, err)
	}

	return ctx
}
