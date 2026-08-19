package smtpd

import "strings"

// decodeXtext decodes the xtext encoding of RFC 1891, which the XCLIENT
// specification asks for on every attribute value. A "+" starts a byte
// written as two hexadecimal digits, and every other character stands for
// itself.
//
// A "+" that two hexadecimal digits do not follow stands for itself as well.
// The specification does not allow that, but a proxy that sends a value
// without encoding it is common, and a plus sign in an address is ordinary.
// Reading such a value as it came keeps the rest of the command, where
// refusing it would drop the address of the client with it.
func decodeXtext(value string) string {
	if !strings.Contains(value, "+") {
		return value
	}

	var out strings.Builder
	out.Grow(len(value))

	for i := 0; i < len(value); i++ {
		if value[i] != '+' || i+2 >= len(value) {
			out.WriteByte(value[i])
			continue
		}

		hi, hiOK := hexDigit(value[i+1])
		lo, loOK := hexDigit(value[i+2])
		if !hiOK || !loOK {
			out.WriteByte(value[i])
			continue
		}

		out.WriteByte(hi<<4 | lo)
		i += 2
	}

	return out.String()
}

// hexDigit returns the value of one hexadecimal digit. RFC 1891 writes the
// digits in upper case, and lower case is taken as well.
func hexDigit(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	}
	return 0, false
}

// isUnavailable reports whether an XCLIENT value says that the proxy has no
// information for that attribute. Postfix sends these two marks, and the
// attribute they carry has to stay as it was.
func isUnavailable(value string) bool {
	return strings.EqualFold(value, "[UNAVAILABLE]") ||
		strings.EqualFold(value, "[TEMPUNAVAIL]")
}

// parseXtext decodes the xtext of RFC 3461 section 4 and reports whether the
// value keeps to it. A "+" starts a byte written as two hexadecimal digits,
// and every other character stands for itself. The characters that stand for
// themselves run from "!" (33) to "~" (126), and they leave out "+" and "=".
//
// The decoded value carries printable US-ASCII only. A byte outside that
// range ends a MAIL or RCPT command that a relay writes the value into, and
// the next line comes from the client. RFC 3461 asks the server to answer
// 501 to such a value.
//
// The DSN parameters take this strict reading of xtext, where XCLIENT takes
// the lenient one in decodeXtext. A DSN parameter comes from a mail client,
// which follows the specification, and the value travels on to the next
// server.
//
// RFC 3461 writes the two digits in upper case. A lower case digit is read
// as well, because it stands for the same byte and no other value can be
// meant by it.
func parseXtext(value string) (string, bool) {
	var out strings.Builder
	out.Grow(len(value))

	for i := 0; i < len(value); i++ {
		c := value[i]

		if c != '+' {
			if c < '!' || c > '~' || c == '=' {
				return "", false
			}
			out.WriteByte(c)
			continue
		}

		if i+2 >= len(value) {
			return "", false
		}

		hi, hiOK := hexDigit(value[i+1])
		lo, loOK := hexDigit(value[i+2])
		if !hiOK || !loOK {
			return "", false
		}

		b := hi<<4 | lo
		if b < ' ' || b > '~' {
			return "", false
		}

		out.WriteByte(b)
		i += 2
	}

	return out.String(), true
}
