package smtpd_test

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

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
	if err := smtptest.Cmd(c.Text, 501, "XCLIENT"); err != nil {
		t.Fatalf("XCLIENT with no args didn't 501: %v", err)
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
	if err := smtptest.Cmd(c.Text, 501, "XCLIENT NAMEwithoutequals"); err != nil {
		t.Fatalf("XCLIENT with malformed item didn't 501: %v", err)
	}
}

func TestXCLIENTBadPort(t *testing.T) {
	t.Parallel()

	srv := runserver(t, &smtpd.Server{
		EnableXCLIENT: true,
		Logger:        testLogger(t),
	})

	c := srv.Dial()
	if err := smtptest.Cmd(c.Text, 501, "XCLIENT PORT=notanumber"); err != nil {
		t.Fatalf("XCLIENT with bad port didn't 501: %v", err)
	}
}

func TestXCLIENTUnknownAttribute(t *testing.T) {
	t.Parallel()

	srv := runserver(t, &smtpd.Server{
		EnableXCLIENT: true,
		Logger:        testLogger(t),
	})

	c := srv.Dial()
	if err := smtptest.Cmd(c.Text, 501, "XCLIENT BOGUS=value"); err != nil {
		t.Fatalf("XCLIENT with unknown attribute didn't 501: %v", err)
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

// TestXCLIENTFromAnUntrustedAddress verifies that an XCLIENT command from an
// address outside Server.TrustedProxies is refused. The command writes
// Peer.Addr, Peer.HeloName, Peer.Username and Peer.Protocol.
//
// The session goes on, because a server that takes XCLIENT sends its greeting
// as any other server does, and the client has an ordinary session to run.
func TestXCLIENTFromAnUntrustedAddress(t *testing.T) {
	t.Parallel()

	cap := &capturedPeer{}
	srv := runserver(t, &smtpd.Server{
		EnableXCLIENT:  true,
		TrustedProxies: []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")},
		Logger:         testLogger(t),
	}, capturePeer(cap))

	c := srv.Dial()

	if err := smtptest.Cmd(c.Text, 550, "XCLIENT ADDR=9.9.9.9 PORT=999 LOGIN=someone"); err != nil {
		t.Fatalf("the XCLIENT command from an untrusted address did not get 550: %v", err)
	}

	if err := c.Mail("sender@example.org"); err != nil {
		t.Fatalf("MAIL FROM after the refusal failed: %v", err)
	}

	if cap.got.Username == "someone" {
		t.Error("the refused command wrote Peer.Username")
	}
	if host, _, _ := net.SplitHostPort(cap.got.Addr.String()); host == "9.9.9.9" {
		t.Fatalf("Peer.Addr = %v, want the address of the connection", cap.got.Addr)
	}
	_ = c.Quit()
}

// TestXCLIENTAfterPROXYReadsTheConnection verifies that the trust of an
// XCLIENT command is read from the address of the connection, and never from
// Peer.Addr.
//
// A PROXY header writes Peer.Addr before any XCLIENT command arrives. A client
// that named a trusted address in the header would otherwise authorize itself
// for the command that follows it.
func TestXCLIENTAfterPROXYReadsTheConnection(t *testing.T) {
	t.Parallel()

	cap := &capturedPeer{}
	srv := runserver(t, &smtpd.Server{
		EnableXCLIENT:       true,
		EnableProxyProtocol: true,
		// The loopback address of the connection is left out, and the address
		// that the PROXY command below names is in.
		TrustedProxies: []netip.Prefix{netip.MustParsePrefix("42.42.42.42/32")},
		Logger:         testLogger(t),
	}, capturePeer(cap))

	tp, conn := dialRawProxy(t, srv.Addr)
	defer func() { _ = conn.Close() }()

	// The PROXY command is refused for the same reason, so the client never
	// reaches the state it was after.
	if err := smtptest.Cmd(tp, 550, "PROXY TCP4 42.42.42.42 5.6.7.8 4242 25"); err != nil {
		t.Fatalf("the PROXY command from an untrusted address did not get 550: %v", err)
	}

	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if err := smtptest.Cmd(tp, 250, "XCLIENT ADDR=9.9.9.9"); err == nil {
		t.Fatal("the session took an XCLIENT command after the refusal")
	}

	if cap.got.Addr != nil {
		t.Fatalf("a hook saw Peer.Addr = %v, want no hook to run", cap.got.Addr)
	}
}

// TestXCLIENTFromATrustedAddress verifies that the command still works for an
// address that the list names.
func TestXCLIENTFromATrustedAddress(t *testing.T) {
	t.Parallel()

	cap := &capturedPeer{}
	srv := runserver(t, &smtpd.Server{
		EnableXCLIENT: true,
		TrustedProxies: []netip.Prefix{
			netip.MustParsePrefix("127.0.0.0/8"),
			netip.MustParsePrefix("::1/128"),
		},
		Logger: testLogger(t),
	}, capturePeer(cap))

	c := srv.Dial()

	if err := smtptest.Cmd(c.Text, 220, "XCLIENT ADDR=9.9.9.9 PORT=999"); err != nil {
		t.Fatalf("the XCLIENT command from a trusted address failed: %v", err)
	}
	if err := smtptest.Cmd(c.Text, 250, "EHLO client.example"); err != nil {
		t.Fatalf("EHLO failed: %v", err)
	}
	if err := smtptest.Cmd(c.Text, 250, "MAIL FROM:<sender@example.org>"); err != nil {
		t.Fatalf("MAIL FROM failed: %v", err)
	}

	if got := cap.got.Addr.String(); got != "9.9.9.9:999" {
		t.Fatalf("Peer.Addr = %v, want 9.9.9.9:999", got)
	}
}
