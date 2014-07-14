package smtpd

import (
	"fmt"
	"strings"
)

type MailAddress string

func parseMailAddress(src string) (MailAddress, error) {
	if src[0] != '<' || src[len(src)-1] != '>' || strings.Count(src, "@") != 1 {
		return MailAddress(""), fmt.Errorf("Ill-formatted e-mail address: %s", src)
	}
	return MailAddress(src[1 : len(src)-1]), nil
}
