package smtpd

import (
	"bytes"
	"context"
	"encoding/base64"
	"log/slog"
	"strings"
)

func (s *session) handleAUTH(ctx context.Context, cmd command) context.Context {
	if len(cmd.fields) < 2 {
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

	mechanism := strings.ToUpper(cmd.fields[1])

	username := ""
	password := ""

	switch mechanism {

	case "PLAIN":

		auth := ""

		if len(cmd.fields) < 3 {
			ctx = s.reply(ctx, 334, "Give me your credentials")
			if !s.scanner.Scan() {
				return ctx
			}
			auth = s.scanner.Text()
		} else {
			auth = cmd.fields[2]
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

		encodedUsername := ""

		if len(cmd.fields) < 3 {
			ctx = s.reply(ctx, 334, "VXNlcm5hbWU6")
			if !s.scanner.Scan() {
				return ctx
			}
			encodedUsername = s.scanner.Text()
		} else {
			encodedUsername = cmd.fields[2]
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

		s.log.WarnContext(ctx, "unknown authentication mechanism", slog.String("mechanism", mechanism))
		return s.reply(ctx, 502, "Unknown authentication mechanism")

	}

	var err error
	ctx, err = s.server.authenticate(ctx, s.peer, username, password)
	if err != nil {
		return s.replyError(ctx, err)
	}

	s.peer.Username = username
	_ = password

	return s.reply(ctx, 235, "OK, you are now authenticated")

}
