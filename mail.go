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
	if !s.peer.Protocol.extended() {
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
