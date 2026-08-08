package smtpd_test

import (
	"context"
	"strings"
	"testing"

	"github.com/chrj/smtpd/v2"
	"github.com/chrj/smtpd/v2/smtptest"
)

func TestXCLIENTNoArgs(t *testing.T) {
	t.Parallel()

	srv := runserver(t, &smtpd.Server{
		EnableXCLIENT: true,
		Logger:        testLogger(t),
	})

	c := srv.Dial()
	if err := smtptest.Cmd(c.Text, 502, "XCLIENT"); err != nil {
		t.Fatalf("XCLIENT with no args didn't 502: %v", err)
	}
}

func TestXCLIENTDisabled(t *testing.T) {
	t.Parallel()

	srv := runserver(t, &smtpd.Server{Logger: testLogger(t)})

	c := srv.Dial()
	if err := smtptest.Cmd(c.Text, 550, "XCLIENT NAME=ignored"); err != nil {
		t.Fatalf("XCLIENT with extension disabled didn't 550: %v", err)
	}
}

func TestXCLIENTMalformedItem(t *testing.T) {
	t.Parallel()

	srv := runserver(t, &smtpd.Server{
		EnableXCLIENT: true,
		Logger:        testLogger(t),
	})

	c := srv.Dial()
	if err := smtptest.Cmd(c.Text, 502, "XCLIENT NAMEwithoutequals"); err != nil {
		t.Fatalf("XCLIENT with malformed item didn't 502: %v", err)
	}
}

func TestXCLIENTBadPort(t *testing.T) {
	t.Parallel()

	srv := runserver(t, &smtpd.Server{
		EnableXCLIENT: true,
		Logger:        testLogger(t),
	})

	c := srv.Dial()
	if err := smtptest.Cmd(c.Text, 502, "XCLIENT PORT=notanumber"); err != nil {
		t.Fatalf("XCLIENT with bad port didn't 502: %v", err)
	}
}

func TestXCLIENTUnknownAttribute(t *testing.T) {
	t.Parallel()

	srv := runserver(t, &smtpd.Server{
		EnableXCLIENT: true,
		Logger:        testLogger(t),
	})

	c := srv.Dial()
	if err := smtptest.Cmd(c.Text, 502, "XCLIENT BOGUS=value"); err != nil {
		t.Fatalf("XCLIENT with unknown attribute didn't 502: %v", err)
	}
}

func TestXCLIENTProtoESMTP(t *testing.T) {
	t.Parallel()

	cap := &capturedAddr{}
	srv := runserver(t, &smtpd.Server{
		EnableXCLIENT: true,
		Logger:        testLogger(t),
	}, capturePeerAddr(cap))

	c := srv.Dial()
	// Valid XCLIENT with PROTO=ESMTP and an ADDR/PORT that can be captured.
	if err := smtptest.Cmd(c.Text, 220, "XCLIENT ADDR=9.9.9.9 PORT=999 PROTO=ESMTP"); err != nil {
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

// capturedPeer holds the Peer recorded by capturePeer.
type capturedPeer struct{ got smtpd.Peer }

// capturePeer returns a Middleware whose CheckSender stores the first Peer it
// sees into state.got.
func capturePeer(state *capturedPeer) smtpd.Middleware {
	return smtpd.Middleware{
		CheckSender: func(ctx context.Context, peer smtpd.Peer, _ string) (context.Context, error) {
			if state.got.Addr == nil {
				state.got = peer
			}
			return ctx, nil
		},
	}
}

// TestXCLIENTValueWithEquals verifies that only the first equals sign splits
// an item. A value that carries one of its own, such as the padding of base64,
// belongs to the value.
func TestXCLIENTValueWithEquals(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		command string
		field   func(smtpd.Peer) string
		want    string
	}{
		{
			name:    "padding of base64 in LOGIN",
			command: "XCLIENT LOGIN=dXNlcg==",
			field:   func(p smtpd.Peer) string { return p.Username },
			want:    "dXNlcg==",
		},
		{
			name:    "equals inside HELO",
			command: "XCLIENT HELO=a=b",
			field:   func(p smtpd.Peer) string { return p.HeloName },
			want:    "a=b",
		},
		{
			name:    "an item with equals beside others",
			command: "XCLIENT ADDR=9.9.9.9 LOGIN=dXNlcg== HELO=a=b",
			field:   func(p smtpd.Peer) string { return p.Username },
			want:    "dXNlcg==",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			cap := &capturedPeer{}
			srv := runserver(t, &smtpd.Server{
				EnableXCLIENT: true,
				Logger:        testLogger(t),
			}, capturePeer(cap))

			// A raw client, because XCLIENT gives the name of the greeting
			// here. A client library sends its own greeting for MAIL FROM,
			// which would write over that name after XCLIENT set it.
			c := dialRaw(t, srv.Addr)
			c.send("EHLO client.example")
			if reply := c.send("%s", test.command); !strings.HasPrefix(reply, "220") {
				t.Fatalf("%q was not accepted: %s", test.command, reply)
			}
			if reply := c.send("MAIL FROM:<sender@example.org>"); !strings.HasPrefix(reply, "250") {
				t.Fatalf("MAIL FROM = %q, want 250", reply)
			}

			if got := test.field(cap.got); got != test.want {
				t.Errorf("got %q, want %q", got, test.want)
			}
		})
	}
}

// TestXCLIENTValueIsEmpty verifies that an item with nothing after the equals
// sign is accepted and changes nothing.
func TestXCLIENTValueIsEmpty(t *testing.T) {
	t.Parallel()

	srv := runserver(t, &smtpd.Server{
		EnableXCLIENT: true,
		Logger:        testLogger(t),
	})

	c := srv.Dial()
	if err := smtptest.Cmd(c.Text, 220, "XCLIENT LOGIN="); err != nil {
		t.Fatalf("XCLIENT with an empty value was not accepted: %v", err)
	}
	_ = c.Quit()
}

// TestXCLIENTDecodesXtext verifies that an attribute value arrives decoded.
// RFC 1891 xtext is what the XCLIENT specification of Postfix asks for.
func TestXCLIENTDecodesXtext(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		command string
		field   func(smtpd.Peer) string
		want    string
	}{
		{
			name:    "an at sign in LOGIN",
			command: "XCLIENT LOGIN=user+40example.com",
			field:   func(p smtpd.Peer) string { return p.Username },
			want:    "user@example.com",
		},
		{
			name:    "a plus sign in HELO",
			command: "XCLIENT HELO=a+2Bb",
			field:   func(p smtpd.Peer) string { return p.HeloName },
			want:    "a+b",
		},
		{
			name:    "a plus that no digits follow stays as it is",
			command: "XCLIENT LOGIN=user+tag@example.com",
			field:   func(p smtpd.Peer) string { return p.Username },
			want:    "user+tag@example.com",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			cap := &capturedPeer{}
			srv := runserver(t, &smtpd.Server{
				EnableXCLIENT: true,
				Logger:        testLogger(t),
			}, capturePeer(cap))

			c := dialRaw(t, srv.Addr)
			c.send("EHLO client.example")
			if reply := c.send("%s", test.command); !strings.HasPrefix(reply, "220") {
				t.Fatalf("%q was not accepted: %s", test.command, reply)
			}
			if reply := c.send("MAIL FROM:<sender@example.org>"); !strings.HasPrefix(reply, "250") {
				t.Fatalf("MAIL FROM = %q, want 250", reply)
			}

			if got := test.field(cap.got); got != test.want {
				t.Errorf("got %q, want %q", got, test.want)
			}
		})
	}
}

// TestXCLIENTUnavailable verifies that a value which says the proxy has no
// information leaves the attribute as it was, and does not fail the command.
func TestXCLIENTUnavailable(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		command string
	}{
		{name: "HELO", command: "XCLIENT HELO=[UNAVAILABLE]"},
		{name: "LOGIN", command: "XCLIENT LOGIN=[UNAVAILABLE]"},
		{name: "ADDR", command: "XCLIENT ADDR=[UNAVAILABLE]"},
		{name: "PORT", command: "XCLIENT PORT=[UNAVAILABLE]"},
		{name: "NAME", command: "XCLIENT NAME=[TEMPUNAVAIL]"},
		{name: "beside an attribute that has a value", command: "XCLIENT PORT=[UNAVAILABLE] ADDR=9.9.9.9"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			cap := &capturedPeer{}
			srv := runserver(t, &smtpd.Server{
				EnableXCLIENT: true,
				Logger:        testLogger(t),
			}, capturePeer(cap))

			c := dialRaw(t, srv.Addr)
			c.send("EHLO client.example")
			if reply := c.send("%s", test.command); !strings.HasPrefix(reply, "220") {
				t.Fatalf("%q was not accepted: %s", test.command, reply)
			}
			if reply := c.send("MAIL FROM:<sender@example.org>"); !strings.HasPrefix(reply, "250") {
				t.Fatalf("MAIL FROM = %q, want 250", reply)
			}

			// Nothing takes the mark itself as a name or a user.
			if strings.Contains(cap.got.HeloName, "UNAVAIL") {
				t.Errorf("HeloName = %q, want the greeting to stand", cap.got.HeloName)
			}
			if strings.Contains(cap.got.Username, "UNAVAIL") {
				t.Errorf("Username = %q, want it empty", cap.got.Username)
			}
		})
	}
}

// TestXCLIENTUnavailableAddressKeepsThePeer verifies that the address of the
// connection stands when the proxy reports no address.
func TestXCLIENTUnavailableAddressKeepsThePeer(t *testing.T) {
	t.Parallel()

	cap := &capturedPeer{}
	srv := runserver(t, &smtpd.Server{
		EnableXCLIENT: true,
		Logger:        testLogger(t),
	}, capturePeer(cap))

	c := dialRaw(t, srv.Addr)
	c.send("EHLO client.example")
	if reply := c.send("XCLIENT ADDR=[UNAVAILABLE] PORT=[UNAVAILABLE]"); !strings.HasPrefix(reply, "220") {
		t.Fatalf("XCLIENT was not accepted: %s", reply)
	}
	c.send("MAIL FROM:<sender@example.org>")

	if cap.got.Addr == nil {
		t.Fatal("expected the address of the connection to stand")
	}
	if !strings.HasPrefix(cap.got.Addr.String(), "127.0.0.1:") {
		t.Errorf("Addr = %v, want the address of the connection", cap.got.Addr)
	}
}
