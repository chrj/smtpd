package smtpd

import (
	"context"
	"fmt"
)

func (s *session) handle(ctx context.Context, line string) context.Context {
	// The handler of a chunked message runs while the session reads the next
	// command. A panic in it ends the session, whatever that command is.
	if s.chunk.started() {
		if result, ok := s.chunk.poll(); ok {
			var done bool
			if ctx, done = s.reportChunkPanic(ctx, &result); done {
				return ctx
			}

			// A handler that ended gives back a context, and the commands
			// after it run in that one.
			if result.ctx != nil {
				ctx = result.ctx
			}
		}
	}

	cmd, err := parseCommand(line)
	if err != nil {
		return s.replyEnhanced(ctx, 500, EnhancedCode{5, 5, 2}, "Invalid syntax.")
	}

	// Commands are dispatched to the appropriate handler functions.
	// If a network error occurs during handling, the handler should
	// just return and let the error be handled on the next read.

	switch cmd.action {

	case "PROXY":
		return s.handlePROXY(ctx, cmd)

	case "HELO":
		return s.handleHELO(ctx, cmd)

	case "EHLO":
		return s.handleEHLO(ctx, cmd)

	case "MAIL":
		return s.handleMAIL(ctx, cmd)

	case "RCPT":
		return s.handleRCPT(ctx, cmd)

	case "STARTTLS":
		return s.handleSTARTTLS(ctx, cmd)

	case "DATA":
		return s.handleDATA(ctx, cmd)

	case "BDAT":
		return s.handleBDAT(ctx, cmd)

	case "RSET":
		return s.handleRSET(ctx, cmd)

	case "NOOP":
		return s.handleNOOP(ctx, cmd)

	case "VRFY":
		return s.handleVRFY(ctx, cmd)

	case "QUIT":
		return s.handleQUIT(ctx, cmd)

	case "AUTH":
		return s.handleAUTH(ctx, cmd)

	case "XCLIENT":
		return s.handleXCLIENT(ctx, cmd)

	}

	return s.replyEnhanced(ctx, 500, EnhancedCode{5, 5, 1}, "Unsupported command.")

}

func (s *session) handleHELO(ctx context.Context, cmd *command) context.Context {
	ctx, _ = phasedLoggerFromContext(ctx, "helo")

	name, ok := cmd.singleArg()
	if !ok {
		return s.reply(ctx, 501, "Missing parameter")
	}

	if s.peer.HeloName != "" {
		// Reset envelope in case of duplicate HELO
		ctx = s.reset(ctx)
	}

	var err error
	ctx, err = s.server.checkHelo(ctx, s.peer, name)
	if err != nil {
		return s.replyError(ctx, err)
	}

	s.peer.HeloName = name
	s.peer.Protocol = SMTP
	return s.reply(ctx, 250, "Go ahead")

}

func (s *session) handleEHLO(ctx context.Context, cmd *command) context.Context {
	ctx, _ = phasedLoggerFromContext(ctx, "ehlo")

	name, ok := cmd.singleArg()
	if !ok {
		return s.reply(ctx, 501, "Missing parameter")
	}

	if s.peer.HeloName != "" {
		// Reset envelope in case of duplicate EHLO
		ctx = s.reset(ctx)
	}

	var err error
	ctx, err = s.server.checkHelo(ctx, s.peer, name)
	if err != nil {
		return s.replyError(ctx, err)
	}

	s.peer.HeloName = name
	s.peer.Protocol = ESMTP

	return s.replyMultiline(ctx, 250, s.server.Hostname, s.extensions()...)

}

func (s *session) extensions() []string {

	extensions := []string{
		fmt.Sprintf("SIZE %d", s.server.MaxMessageSize),
		"8BITMIME",
		"BINARYMIME",
		"CHUNKING",
		"PIPELINING",
		"ENHANCEDSTATUSCODES",
	}

	if s.server.EnableDSN {
		extensions = append(extensions, "DSN")
	}

	// RFC 6531 section 3.1 asks for the keyword alone, without a parameter of
	// its own, and for 8BITMIME next to it. The list above carries 8BITMIME
	// for every client.
	if s.server.EnableSMTPUTF8 {
		extensions = append(extensions, "SMTPUTF8")
	}

	if s.server.EnableXCLIENT {
		extensions = append(extensions, "XCLIENT")
	}

	if s.server.TLSConfig != nil && !s.tls {
		extensions = append(extensions, "STARTTLS")
	}

	if s.server.hasAuthenticator() && (s.tls || s.server.AllowInsecureAuth) {
		extensions = append(extensions, "AUTH PLAIN LOGIN")
	}

	return extensions

}

func (s *session) handleRSET(ctx context.Context, cmd *command) context.Context {
	ctx, _ = phasedLoggerFromContext(ctx, "rset")
	ctx = s.reset(ctx)
	return s.reply(ctx, 250, "Go ahead")
}

func (s *session) handleNOOP(ctx context.Context, cmd *command) context.Context {
	ctx, _ = phasedLoggerFromContext(ctx, "noop")
	return s.reply(ctx, 250, "Go ahead")
}

func (s *session) handleQUIT(ctx context.Context, cmd *command) context.Context {
	ctx, _ = phasedLoggerFromContext(ctx, "quit")
	ctx = s.replyEnhanced(ctx, 221, EnhancedCode{2, 0, 0}, "OK, bye")
	return s.close(ctx)
}
