package smtptest

import (
	"fmt"
	"io"
	"net/smtp"
	"net/textproto"
)

// Send runs one transaction on c: MAIL FROM, RCPT TO, DATA and QUIT. It
// returns the first error, so a test can read the reply code of the server
// with errors.As and a *textproto.Error.
//
// Send does not close c. A test that stops at a rejected reply can read more
// from the client.
func Send(c *smtp.Client, from string, to []string, body string) error {
	if err := c.Mail(from); err != nil {
		return fmt.Errorf("MAIL FROM <%s>: %w", from, err)
	}

	for _, recipient := range to {
		if err := c.Rcpt(recipient); err != nil {
			return fmt.Errorf("RCPT TO <%s>: %w", recipient, err)
		}
	}

	w, err := c.Data()
	if err != nil {
		return fmt.Errorf("DATA: %w", err)
	}

	if _, err := io.WriteString(w, body); err != nil {
		return fmt.Errorf("write the body: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("close the body: %w", err)
	}

	return c.Quit()
}

// Cmd sends one raw command and reads the reply. It returns an error when the
// reply code is not wantCode.
//
// Use it for a command that net/smtp does not send, such as XCLIENT, or for
// bad syntax. The Text field of a client gives the connection:
//
//	err := smtptest.Cmd(c.Text, 502, "XCLIENT NAME=ignored")
func Cmd(c *textproto.Conn, wantCode int, format string, args ...any) error {
	id, err := c.Cmd(format, args...)
	if err != nil {
		return fmt.Errorf("send %q: %w", fmt.Sprintf(format, args...), err)
	}

	c.StartResponse(id)
	defer c.EndResponse(id)

	_, _, err = c.ReadResponse(wantCode)
	return err
}
