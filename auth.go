package smtpd

import (
	"bytes"
	"context"
	"encoding/base64"
	"log/slog"
	"strings"
)

func (session *session) handleAUTH(ctx context.Context, cmd command) context.Context {
	if len(cmd.fields) < 2 {
		return session.reply(ctx, 502, "Invalid syntax.")
	}

	if len(session.server.authenticators) == 0 {
		return session.reply(ctx, 502, "AUTH not supported.")
	}

	if session.peer.HeloName == "" {
		return session.reply(ctx, 502, "Please introduce yourself first.")
	}

	if !session.tls {
		return session.reply(ctx, 502, "Cannot AUTH in plain text mode. Use STARTTLS.")
	}

	mechanism := strings.ToUpper(cmd.fields[1])

	username := ""
	password := ""

	switch mechanism {

	case "PLAIN":

		auth := ""

		if len(cmd.fields) < 3 {
			ctx = session.reply(ctx, 334, "Give me your credentials")
			if !session.scanner.Scan() {
				return ctx
			}
			auth = session.scanner.Text()
		} else {
			auth = cmd.fields[2]
		}

		data, err := base64.StdEncoding.DecodeString(auth)

		if err != nil {
			return session.reply(ctx, 502, "Couldn't decode your credentials")
		}

		parts := bytes.Split(data, []byte{0})

		if len(parts) != 3 {
			return session.reply(ctx, 502, "Couldn't decode your credentials")
		}

		username = string(parts[1])
		password = string(parts[2])

	case "LOGIN":

		encodedUsername := ""

		if len(cmd.fields) < 3 {
			ctx = session.reply(ctx, 334, "VXNlcm5hbWU6")
			if !session.scanner.Scan() {
				return ctx
			}
			encodedUsername = session.scanner.Text()
		} else {
			encodedUsername = cmd.fields[2]
		}

		byteUsername, err := base64.StdEncoding.DecodeString(encodedUsername)

		if err != nil {
			return session.reply(ctx, 502, "Couldn't decode your credentials")
		}

		ctx = session.reply(ctx, 334, "UGFzc3dvcmQ6")

		if !session.scanner.Scan() {
			return ctx
		}

		bytePassword, err := base64.StdEncoding.DecodeString(session.scanner.Text())

		if err != nil {
			return session.reply(ctx, 502, "Couldn't decode your credentials")
		}

		username = string(byteUsername)
		password = string(bytePassword)

	default:

		session.log.WarnContext(ctx, "unknown authentication mechanism", slog.String("mechanism", mechanism))
		return session.reply(ctx, 502, "Unknown authentication mechanism")

	}

	var err error
	ctx, err = session.server.authenticate(ctx, session.peer, username, password)
	if err != nil {
		return session.error(ctx, err)
	}

	session.peer.Username = username
	_ = password

	return session.reply(ctx, 235, "OK, you are now authenticated")

}
