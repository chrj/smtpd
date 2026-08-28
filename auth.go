package smtpd

import (
	"bytes"
	"context"
	"encoding/base64"
	"log/slog"
	"strings"
)

func (s *session) handleAUTH(ctx context.Context, cmd *command) context.Context {
	ctx, logger := phasedLoggerFromContext(ctx, "auth")

	args := cmd.args()
	if len(args) < 1 || len(args) > 2 {
		return s.replyEnhanced(ctx, 501, EnhancedCode{5, 5, 4}, "Invalid syntax.")
	}

	if !s.server.hasAuthenticator() {
		return s.replyEnhanced(ctx, 502, EnhancedCode{5, 5, 1}, "AUTH not supported.")
	}

	if s.peer.HeloName == "" {
		return s.replyEnhanced(ctx, 503, EnhancedCode{5, 5, 1}, "Please introduce yourself first.")
	}

	if !s.tls && !s.server.AllowInsecureAuth {
		if s.server.TLSConfig == nil {
			return s.replyEnhanced(ctx, 502, EnhancedCode{5, 5, 1}, "Cannot AUTH in plain text mode and STARTTLS is not available.")
		}
		return s.replyEnhanced(ctx, 530, EnhancedCode{5, 7, 0}, "Cannot AUTH in plain text mode. Use STARTTLS.")
	}

	mechanism := strings.ToUpper(args[0])

	username := ""
	password := ""

	switch mechanism {

	case "PLAIN":

		auth := ""

		if len(args) < 2 {
			ctx = s.reply(ctx, 334, "Give me your credentials")
			line, err := s.readLine()
			if err != nil {
				return ctx
			}
			auth = line
		} else {
			auth = args[1]
		}

		data, err := base64.StdEncoding.DecodeString(auth)

		if err != nil {
			return s.replyEnhanced(ctx, 501, EnhancedCode{5, 5, 2}, "Couldn't decode your credentials")
		}

		parts := bytes.Split(data, []byte{0})

		if len(parts) != 3 {
			return s.replyEnhanced(ctx, 501, EnhancedCode{5, 5, 2}, "Couldn't decode your credentials")
		}

		username = string(parts[1])
		password = string(parts[2])

	case "LOGIN":

		encodedUsername := ""

		if len(args) < 2 {
			ctx = s.reply(ctx, 334, "VXNlcm5hbWU6")
			line, err := s.readLine()
			if err != nil {
				return ctx
			}
			encodedUsername = line
		} else {
			encodedUsername = args[1]
		}

		byteUsername, err := base64.StdEncoding.DecodeString(encodedUsername)

		if err != nil {
			return s.replyEnhanced(ctx, 501, EnhancedCode{5, 5, 2}, "Couldn't decode your credentials")
		}

		ctx = s.reply(ctx, 334, "UGFzc3dvcmQ6")

		encodedPassword, err := s.readLine()
		if err != nil {
			return ctx
		}

		bytePassword, err := base64.StdEncoding.DecodeString(encodedPassword)

		if err != nil {
			return s.replyEnhanced(ctx, 501, EnhancedCode{5, 5, 2}, "Couldn't decode your credentials")
		}

		username = string(byteUsername)
		password = string(bytePassword)

	default:

		logger.WarnContext(ctx, "unknown authentication mechanism", slog.String("mechanism", mechanism))
		return s.replyEnhanced(ctx, 504, EnhancedCode{5, 5, 4}, "Unknown authentication mechanism")

	}

	var err error
	ctx, err = s.server.authenticate(ctx, s.peer, username, password)
	if err != nil {
		s.authFailures++
		if s.server.tooManyAuthFailures(s.authFailures) {
			// The attempt that reaches the limit takes this reply in the
			// place of the refusal, so that the client reads one answer to
			// its command and learns why the connection ends.
			logger.WarnContext(ctx, "closing the session after too many failed authentication attempts",
				slog.Int("attempts", s.authFailures),
			)
			ctx = s.replyEnhanced(ctx, 421, EnhancedCode{4, 7, 0}, "Too many failed authentication attempts")
			return s.close(ctx)
		}
		return s.replyError(ctx, err)
	}

	s.authFailures = 0
	s.peer.Username = username

	return s.replyEnhanced(ctx, 235, EnhancedCode{2, 7, 0}, "OK, you are now authenticated")

}
