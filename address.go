package smtpd

import (
	"fmt"
	"net/mail"
	"strings"
)

func parseAddress(src string) (string, error) {
	// While a RFC5321 mailbox specification is not the same as an RFC5322
	// email address specification, it is better to accept that format and
	// parse it down to the actual address, as there are a lot of badly
	// behaving MTAs and MUAs that do it wrongly. It therefore makes sense
	// to rely on Go's built-in address parser. This does have the benefit
	// of allowing "email@example.com" as input as thats commonly used,
	// though not RFC compliant.
	addr, err := mail.ParseAddress(src)
	if err != nil {
		return "", fmt.Errorf("malformed e-mail address: %s", src)
	}

	address := quoteLocalPart(addr.Address)

	// A line break lets the client write a command of its own into the
	// session of a relay that sends this address on.
	if strings.ContainsAny(address, "\r\n") {
		return "", fmt.Errorf("e-mail address carries a line break: %q", src)
	}

	return address, nil
}

// quoteLocalPart puts the quoting back on a local part that needs it. The
// address parser takes the quoting off, so `"a b"@example.org` comes back as
// `a b@example.org`. That value is not an address any more. It does not
// parse, and a relay that writes it into a MAIL FROM command sends a command
// that the next server cannot read.
//
// An address that needs no quoting stays as it is.
func quoteLocalPart(addr string) string {
	// The local part is what stands before the last at sign. Quoting can
	// carry an at sign of its own.
	at := strings.LastIndexByte(addr, '@')
	if at < 0 {
		return addr
	}

	local, domain := addr[:at], addr[at+1:]
	if isDotAtom(local) {
		return addr
	}

	var out strings.Builder
	out.Grow(len(addr) + 4)

	out.WriteByte('"')
	for i := 0; i < len(local); i++ {
		if local[i] == '"' || local[i] == '\\' {
			out.WriteByte('\\')
		}
		out.WriteByte(local[i])
	}
	out.WriteString(`"@`)
	out.WriteString(domain)

	return out.String()
}

// isDotAtom reports whether local is a dot-atom, the form of a local part
// that needs no quoting. RFC 5321 writes it as one or more atoms of atext
// with a single dot between them.
func isDotAtom(local string) bool {
	if local == "" {
		return false
	}

	for atom := range strings.SplitSeq(local, ".") {
		if atom == "" {
			return false
		}
		for i := 0; i < len(atom); i++ {
			if !isAtext(atom[i]) {
				return false
			}
		}
	}

	return true
}

// isAtext reports whether c is an atext character. RFC 5321 gives the
// letters, the digits and a set of signs. RFC 6531 adds every byte above
// ASCII, so that a UTF-8 local part stays as it is.
func isAtext(c byte) bool {
	switch {
	case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		return true
	case c >= 0x80:
		return true
	}
	return strings.IndexByte("!#$%&'*+-/=?^_`{|}~", c) >= 0
}
