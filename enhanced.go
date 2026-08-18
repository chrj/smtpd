package smtpd

import "strconv"

// EnhancedCode is the mail system status code of RFC 3463. It holds the
// class, the subject and the detail of a reply, in that order, and the
// server writes it after the reply code as "class.subject.detail".
//
// RFC 3463 gives three classes: 2 for success, 4 for a temporary fault and
// 5 for a permanent one. The zero value means that the reply carries no
// status code.
//
// Set it on an Error to give a middleware rejection a precise reason:
//
//	smtpd.Error{
//	    Code:     550,
//	    Enhanced: smtpd.EnhancedCode{5, 7, 1},
//	    Message:  "Relay access denied",
//	}
//
// An Error with the zero value gets a code from the class of Code, so a
// middleware that sets no status code still produces a valid reply.
type EnhancedCode [3]int

// String writes the code in the form that RFC 3463 gives, for example
// "5.7.1". The zero value returns an empty string.
func (c EnhancedCode) String() string {
	if !c.valid() {
		return ""
	}
	return strconv.Itoa(c[0]) + "." + strconv.Itoa(c[1]) + "." + strconv.Itoa(c[2])
}

// valid reports whether the code has a class that RFC 3463 defines. The
// zero value is not valid, which is what makes it mean "no status code".
func (c EnhancedCode) valid() bool {
	switch c[0] {
	case 2, 4, 5:
		return c[1] >= 0 && c[2] >= 0
	}
	return false
}

// defaultEnhancedCode gives the generic status code for an SMTP reply code.
// RFC 3463 section 3.1 defines "x.0.0" as the code for a reply with no more
// precise reason.
//
// A reply of class 1 or 3 gets no status code. RFC 3463 defines the classes
// 2, 4 and 5 only, and a 354 or a 334 reply is part of a command that is
// still in progress.
func defaultEnhancedCode(code int) EnhancedCode {
	switch code / 100 {
	case 2:
		return EnhancedCode{2, 0, 0}
	case 4:
		return EnhancedCode{4, 0, 0}
	case 5:
		return EnhancedCode{5, 0, 0}
	}
	return EnhancedCode{}
}
