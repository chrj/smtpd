package smtpd

import (
	"context"
	"fmt"
	"strconv"
	"strings"
)

// errMailParams answers a MAIL FROM parameter that the server does not know.
// RFC 3461 section 4.4 asks for 555 to the DSN parameters of a server that
// does not offer the extension, and RFC 5321 gives the same code for any
// other parameter.
var errMailParams = Error{Code: 555, Enhanced: EnhancedCode{5, 5, 4}, Message: "MAIL FROM parameters not recognized or not implemented"}

// errRcptParams answers a RCPT TO parameter that the server does not know.
var errRcptParams = Error{Code: 555, Enhanced: EnhancedCode{5, 5, 4}, Message: "RCPT TO parameters not recognized or not implemented"}

// mailParams holds what the parameters of a MAIL FROM command say about the
// message that follows.
type mailParams struct {
	body     BodyType
	smtputf8 bool
	dsn      *DSN
}

// parseMailParams reads the parameters of a MAIL FROM command.
func (s *session) parseMailParams(params map[string]string) (mailParams, error) {
	var out mailParams

	if len(params) == 0 {
		return out, nil
	}
	if s.peer.Protocol != ESMTP {
		return mailParams{}, errMailParams
	}

	for name, value := range params {
		switch name {
		case "SIZE":
			size, err := strconv.ParseInt(value, 10, 64)
			if err != nil || size < 0 {
				return mailParams{}, Error{Code: 501, Enhanced: EnhancedCode{5, 5, 4}, Message: "Invalid SIZE parameter"}
			}
			if size > int64(s.server.MaxMessageSize) {
				return mailParams{}, Error{
					Code:     552,
					Enhanced: EnhancedCode{5, 3, 4},
					Message:  fmt.Sprintf("Message size exceeds fixed maximum of %d bytes", s.server.MaxMessageSize),
				}
			}
		case "BODY":
			switch body := BodyType(strings.ToUpper(value)); body {
			case Body7Bit, Body8BitMIME, BodyBinaryMIME:
				out.body = body
			default:
				return mailParams{}, Error{Code: 501, Enhanced: EnhancedCode{5, 5, 4}, Message: "Invalid BODY parameter"}
			}
		case "AUTH":
			// AUTH=<> and xtext-style identities are accepted as opaque
			// values. RFC 4954 section 5 writes the keyword with a value, so
			// one that came alone is an error.
			if value == "" {
				return mailParams{}, Error{Code: 501, Enhanced: EnhancedCode{5, 5, 4}, Message: "Missing AUTH parameter value"}
			}
		case "SMTPUTF8":
			if !s.server.EnableSMTPUTF8 {
				return mailParams{}, errMailParams
			}
			// RFC 6531 section 3.1 gives the parameter no value at all.
			if value != "" {
				return mailParams{}, Error{Code: 501, Enhanced: EnhancedCode{5, 5, 4}, Message: "The SMTPUTF8 parameter takes no value"}
			}
			out.smtputf8 = true
		case "RET":
			if !s.server.EnableDSN {
				return mailParams{}, errMailParams
			}
			ret, ok := parseDSNReturn(value)
			if !ok {
				return mailParams{}, Error{Code: 501, Enhanced: EnhancedCode{5, 5, 4}, Message: "Invalid RET parameter"}
			}
			if out.dsn == nil {
				out.dsn = &DSN{}
			}
			out.dsn.Return = ret
		case "ENVID":
			if !s.server.EnableDSN {
				return mailParams{}, errMailParams
			}
			// RFC 3461 section 4.4 writes the keyword with a value, so one
			// that came alone is an error.
			if value == "" {
				return mailParams{}, Error{Code: 501, Enhanced: EnhancedCode{5, 5, 4}, Message: "Missing ENVID parameter value"}
			}
			envID, ok := parseEnvID(value)
			if !ok {
				return mailParams{}, Error{Code: 501, Enhanced: EnhancedCode{5, 5, 4}, Message: "Invalid ENVID parameter"}
			}
			if out.dsn == nil {
				out.dsn = &DSN{}
			}
			out.dsn.EnvID = envID
		default:
			return mailParams{}, errMailParams
		}
	}

	return out, nil
}

// parseRcptParams reads the parameters of a RCPT TO command. It returns the
// delivery status notification parameters of RFC 3461, and the zero value
// when the client sent none of them.
//
// smtputf8 says that the transaction carries the SMTPUTF8 parameter, which
// lets an ORCPT parameter of the "utf-8" address type hold UTF-8 as it is.
// The server reads that address type where it offers the extension, and takes
// the value as ordinary xtext without it.
func (s *session) parseRcptParams(params map[string]string, smtputf8 bool) (RecipientDSN, error) {
	var rcpt RecipientDSN

	if len(params) == 0 {
		return rcpt, nil
	}
	if s.peer.Protocol != ESMTP || !s.server.EnableDSN {
		return RecipientDSN{}, errRcptParams
	}

	for name, value := range params {
		switch name {
		case "NOTIFY":
			notify, ok := parseNotify(value)
			if !ok {
				return RecipientDSN{}, Error{Code: 501, Enhanced: EnhancedCode{5, 5, 4}, Message: "Invalid NOTIFY parameter"}
			}
			rcpt.Notify = notify
		case "ORCPT":
			addrType, addr, ok := parseORcpt(value, s.server.EnableSMTPUTF8, smtputf8)
			if !ok {
				return RecipientDSN{}, Error{Code: 501, Enhanced: EnhancedCode{5, 5, 4}, Message: "Invalid ORCPT parameter"}
			}
			rcpt.OriginalType = addrType
			rcpt.OriginalRecipient = addr
		default:
			return RecipientDSN{}, errRcptParams
		}
	}

	return rcpt, nil
}

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

func (s *session) handleMAIL(ctx context.Context, cmd *command) context.Context {
	ctx, _ = phasedLoggerFromContext(ctx, "mail")

	addrSpec, params, err := cmd.pathArg("FROM")
	if err != nil {
		return s.replyEnhanced(ctx, 501, EnhancedCode{5, 5, 4}, "Invalid syntax.")
	}

	if s.peer.HeloName == "" {
		return s.replyEnhanced(ctx, 503, EnhancedCode{5, 5, 1}, "Please introduce yourself first.")
	}

	if s.envelope != nil {
		return s.replyEnhanced(ctx, 503, EnhancedCode{5, 5, 1}, "Duplicate MAIL")
	}

	addr := "" // null sender

	// We must accept a null sender as per rfc5321 section-6.1.
	if addrSpec != "<>" {
		addr, err = parseAddress(addrSpec)

		if err != nil {
			return s.replyError(ctx, errSenderMalformed)
		}
	}

	mail, err := s.parseMailParams(params)
	if err != nil {
		return s.replyError(ctx, err)
	}

	if err := s.checkSenderCharset(addr, mail.smtputf8); err != nil {
		return s.replyError(ctx, err)
	}

	ctx, err = s.server.checkSender(ctx, s.peer, addr)
	if err != nil {
		return s.replyError(ctx, err)
	}

	ctx = ContextWithSender(ctx, addr)

	s.envelope = &Envelope{
		Sender:   addr,
		BodyType: mail.body,
		SMTPUTF8: mail.smtputf8,
		DSN:      mail.dsn,
	}

	return s.replyEnhanced(ctx, 250, EnhancedCode{2, 1, 0}, "Go ahead")

}

func (s *session) handleRCPT(ctx context.Context, cmd *command) context.Context {
	ctx, _ = phasedLoggerFromContext(ctx, "rcpt")

	addrSpec, params, err := cmd.pathArg("TO")
	if err != nil {
		return s.replyEnhanced(ctx, 501, EnhancedCode{5, 5, 4}, "Invalid syntax.")
	}

	if s.envelope == nil {
		return s.replyEnhanced(ctx, 503, EnhancedCode{5, 5, 1}, "Missing MAIL FROM command.")
	}

	// A transaction that saw a BDAT command takes no more recipients, whether
	// the server took that chunk or not. It also keeps the session away from
	// an envelope that the handler of a chunked message can write to.
	if s.chunk != nil {
		return s.replyEnhanced(ctx, 503, EnhancedCode{5, 5, 1}, "Cannot add a recipient after BDAT")
	}

	if len(s.envelope.Recipients) >= s.server.MaxRecipients {
		return s.replyEnhanced(ctx, 452, EnhancedCode{4, 5, 3}, "Too many recipients")
	}

	rcptDSN, err := s.parseRcptParams(params, s.envelope.SMTPUTF8)
	if err != nil {
		return s.replyError(ctx, err)
	}

	addr, err := parseAddress(addrSpec)

	if err != nil {
		return s.replyError(ctx, errRecipientMalformed)
	}

	if err := s.checkRecipientCharset(addr); err != nil {
		return s.replyError(ctx, err)
	}

	ctx, err = s.server.checkRecipient(ctx, s.peer, addr)
	if err != nil {
		return s.replyError(ctx, err)
	}

	s.envelope.Recipients = append(s.envelope.Recipients, addr)
	s.envelope.recordRecipientDSN(rcptDSN)

	return s.replyEnhanced(ctx, 250, EnhancedCode{2, 1, 5}, "Go ahead")

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
