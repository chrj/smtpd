package smtpd

import "context"

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
