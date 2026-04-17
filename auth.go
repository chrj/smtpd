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
		return s.reply(ctx, 502, "Invalid syntax.")
	}

	if !s.server.hasAuthenticator() {
		return s.reply(ctx, 502, "AUTH not supported.")
	}

	if s.peer.HeloName == "" {
		return s.reply(ctx, 502, "Please introduce yourself first.")
	}

	if !s.tls {
		return s.reply(ctx, 502, "Cannot AUTH in plain text mode. Use STARTTLS.")
	}

	mechanism := strings.ToUpper(args[0])

	username := ""
	password := ""

	switch mechanism {

	case "PLAIN":

		logger = logger.With("mechanism", "PLAIN")

		auth := ""

		if len(args) < 2 {
			ctx = s.reply(ctx, 334, "Give me your credentials")
			if !s.scanner.Scan() {
				return ctx
			}
			auth = s.scanner.Text()
		} else {
			auth = args[1]
		}

		data, err := base64.StdEncoding.DecodeString(auth)

		if err != nil {
			return s.reply(ctx, 502, "Couldn't decode your credentials")
		}

		parts := bytes.Split(data, []byte{0})

		if len(parts) != 3 {
			return s.reply(ctx, 502, "Couldn't decode your credentials")
		}

		username = string(parts[1])
		password = string(parts[2])

	case "LOGIN":

		logger = logger.With("mechanism", "LOGIN")

		encodedUsername := ""

		if len(args) < 2 {
			ctx = s.reply(ctx, 334, "VXNlcm5hbWU6")
			if !s.scanner.Scan() {
				return ctx
			}
			encodedUsername = s.scanner.Text()
		} else {
			encodedUsername = args[1]
		}

		byteUsername, err := base64.StdEncoding.DecodeString(encodedUsername)

		if err != nil {
			return s.reply(ctx, 502, "Couldn't decode your credentials")
		}

		ctx = s.reply(ctx, 334, "UGFzc3dvcmQ6")

		if !s.scanner.Scan() {
			return ctx
		}

		bytePassword, err := base64.StdEncoding.DecodeString(s.scanner.Text())

		if err != nil {
			return s.reply(ctx, 502, "Couldn't decode your credentials")
		}

		username = string(byteUsername)
		password = string(bytePassword)

	default:

		logger.WarnContext(ctx, "unknown authentication mechanism", slog.String("mechanism", mechanism))
		return s.reply(ctx, 502, "Unknown authentication mechanism")

	}

	var err error
	ctx, err = s.server.authenticate(ctx, s.peer, username, password)
	if err != nil {
		return s.replyError(ctx, err)
	}

	s.peer.Username = username

	return s.reply(ctx, 235, "OK, you are now authenticated")

}
