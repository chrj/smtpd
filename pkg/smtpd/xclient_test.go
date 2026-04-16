package smtpd_test

import (
	"net/smtp"
	"testing"

	"github.com/chrj/smtpd/v2/pkg/smtpd"
)

func TestXCLIENTNoArgs(t *testing.T) {
	addr, closer := runserver(t, &smtpd.Server{
		EnableXCLIENT: true,
		Logger:        testLogger(t),
	})
	defer closer()

	c, err := smtp.Dial(addr)
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}
	if err := cmd(c.Text, 502, "XCLIENT"); err != nil {
		t.Fatalf("XCLIENT with no args didn't 502: %v", err)
	}
}

func TestXCLIENTDisabled(t *testing.T) {
	addr, closer := runserver(t, &smtpd.Server{Logger: testLogger(t)})
	defer closer()

	c, err := smtp.Dial(addr)
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}
	if err := cmd(c.Text, 550, "XCLIENT NAME=ignored"); err != nil {
		t.Fatalf("XCLIENT with extension disabled didn't 550: %v", err)
	}
}

func TestXCLIENTMalformedItem(t *testing.T) {
	addr, closer := runserver(t, &smtpd.Server{
		EnableXCLIENT: true,
		Logger:        testLogger(t),
	})
	defer closer()

	c, err := smtp.Dial(addr)
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}
	if err := cmd(c.Text, 502, "XCLIENT NAMEwithoutequals"); err != nil {
		t.Fatalf("XCLIENT with malformed item didn't 502: %v", err)
	}
}

func TestXCLIENTBadPort(t *testing.T) {
	addr, closer := runserver(t, &smtpd.Server{
		EnableXCLIENT: true,
		Logger:        testLogger(t),
	})
	defer closer()

	c, err := smtp.Dial(addr)
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}
	if err := cmd(c.Text, 502, "XCLIENT PORT=notanumber"); err != nil {
		t.Fatalf("XCLIENT with bad port didn't 502: %v", err)
	}
}

func TestXCLIENTUnknownAttribute(t *testing.T) {
	addr, closer := runserver(t, &smtpd.Server{
		EnableXCLIENT: true,
		Logger:        testLogger(t),
	})
	defer closer()

	c, err := smtp.Dial(addr)
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}
	if err := cmd(c.Text, 502, "XCLIENT BOGUS=value"); err != nil {
		t.Fatalf("XCLIENT with unknown attribute didn't 502: %v", err)
	}
}

func TestXCLIENTProtoESMTP(t *testing.T) {
	cap := &capturedAddr{}
	addr, closer := runserver(t, &smtpd.Server{
		EnableXCLIENT: true,
		Logger:        testLogger(t),
	}, capturePeerAddr(cap))
	defer closer()

	c, err := smtp.Dial(addr)
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}
	// Valid XCLIENT with PROTO=ESMTP and an ADDR/PORT that can be captured.
	if err := cmd(c.Text, 220, "XCLIENT ADDR=9.9.9.9 PORT=999 PROTO=ESMTP"); err != nil {
		t.Fatalf("XCLIENT failed: %v", err)
	}
	if err := c.Hello("localhost"); err != nil {
		t.Fatalf("HELO failed: %v", err)
	}
	if err := c.Mail("sender@example.org"); err != nil {
		t.Fatalf("MAIL failed: %v", err)
	}
	if cap.got == nil || cap.got.String() != "9.9.9.9:999" {
		t.Fatalf("peer.Addr after XCLIENT = %v, want 9.9.9.9:999", cap.got)
	}
	_ = c.Quit()
}
