package smtpd

import (
	"strings"
	"unicode/utf8"
)

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
	return equalASCIIFold(value, "[UNAVAILABLE]") ||
		equalASCIIFold(value, "[TEMPUNAVAIL]")
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

// parseUnitext decodes the unitext encoding that RFC 6533 section 3 gives to
// the "utf-8" address type of an ORCPT parameter, and reports whether the
// value keeps to it. A "\x{HEX}" holds one code point in two to six
// hexadecimal digits, and every other character stands for itself.
//
// The characters that stand for themselves are the printable US-ASCII ones
// without the space, "\", "+" and "=", which the encoding writes as code
// points. raw says whether a byte above US-ASCII stands for itself as well:
// RFC 6533 gives that form to a server that offers SMTPUTF8, and asks a
// client that talks to any other server for the escape.
//
// The value decodes to no control character of US-ASCII, in the way that
// parseXtext reads the xtext of RFC 3461. Such a character ends a MAIL or
// RCPT command that a relay writes the address into, and the next line then
// comes from the client. RFC 6533 keeps CR and LF out of the escape for that
// reason, and this reading keeps the rest of them out too.
//
// A code point above US-ASCII stands, and the C1 range from U+0080 to U+009F
// with it. RFC 6533 gives that range to both forms of the encoding, and the
// UTF-8 of such a code point carries no CR and no LF, so it stays inside its
// command line.
func parseUnitext(value string, raw bool) (string, bool) {
	var out strings.Builder
	out.Grow(len(value))

	for i := 0; i < len(value); i++ {
		c := value[i]

		if c >= 0x80 {
			if !raw {
				return "", false
			}
			out.WriteByte(c)
			continue
		}

		if c == '\\' {
			r, width, ok := parseEmbeddedUnicodeChar(value[i:])
			if !ok {
				return "", false
			}
			out.WriteRune(r)
			i += width - 1
			continue
		}

		// QCHAR is the printable US-ASCII without the space, "\", "+" and
		// "=". The three signs carry a meaning of their own in the ORCPT
		// parameter and in the encoding.
		if c <= ' ' || c == 0x7f || c == '+' || c == '=' {
			return "", false
		}

		out.WriteByte(c)
	}

	decoded := out.String()

	// A raw value carries the bytes as they came, and they have to form
	// UTF-8. RFC 6531 gives an address in that encoding, and a byte outside
	// it is not a character at all.
	if raw && !utf8.ValidString(decoded) {
		return "", false
	}

	return decoded, true
}

// parseEmbeddedUnicodeChar reads one "\x{HEX}" escape of RFC 6533 from the
// start of src and gives the code point and the length of the escape.
//
// The digits run from two to six, and they hold a code point that a
// character stands for: a surrogate half or a value above the last code
// point is not one. A control character of US-ASCII is refused as well, so
// that the decoded address stays on one line.
func parseEmbeddedUnicodeChar(src string) (r rune, width int, ok bool) {
	if !strings.HasPrefix(src, `\x{`) {
		return 0, 0, false
	}

	end := strings.IndexByte(src, '}')
	if end < 0 {
		return 0, 0, false
	}

	digits := src[len(`\x{`):end]
	if len(digits) < 2 || len(digits) > 6 {
		return 0, 0, false
	}

	var value rune
	for i := 0; i < len(digits); i++ {
		d, dOK := hexDigit(digits[i])
		if !dOK {
			return 0, 0, false
		}
		value = value<<4 | rune(d)
	}

	if !utf8.ValidRune(value) || value < ' ' || value == 0x7f {
		return 0, 0, false
	}

	return value, end + 1, true
}
