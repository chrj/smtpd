package smtpd

import "context"

// errRcptParams answers a RCPT TO parameter that the server does not know.
var errRcptParams = Error{Code: 555, Enhanced: EnhancedCode{5, 5, 4}, Message: "RCPT TO parameters not recognized or not implemented"}

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
	if !s.peer.Protocol.extended() || !s.server.EnableDSN {
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
