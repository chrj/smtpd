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

// TestXCLIENTAfterAnAcceptedPROXYHeader verifies that a session which took a
// PROXY header refuses an XCLIENT command.
//
// A proxy writes its header and then passes on what the client sends, so
// every octet after the header comes from the client behind the proxy. The
// address of the connection stays that of the proxy, and it therefore says
// nothing about who sent the command.
func TestXCLIENTAfterAnAcceptedPROXYHeader(t *testing.T) {
	t.Parallel()

	cap := &capturedPeer{}
	srv := runserver(t, &smtpd.Server{
		EnableXCLIENT:       true,
		EnableProxyProtocol: true,
		Logger:              testLogger(t),
	}, capturePeer(cap))

	tp, conn := dialRawProxy(t, srv.Addr)
	defer func() { _ = conn.Close() }()

	// The loopback address of the connection is trusted, so the header is
	// taken and the greeting follows it.
	if err := smtptest.Cmd(tp, 220, "PROXY TCP4 42.42.42.42 5.6.7.8 4242 25"); err != nil {
		t.Fatalf("the PROXY command was not accepted: %v", err)
	}

	// The client behind the proxy sends this one.
	if err := smtptest.Cmd(tp, 550, "XCLIENT ADDR=9.9.9.9 LOGIN=someone"); err != nil {
		t.Fatalf("the XCLIENT command after a PROXY header did not get 550: %v", err)
	}

	if err := smtptest.Cmd(tp, 250, "EHLO client.example"); err != nil {
		t.Fatalf("EHLO failed: %v", err)
	}
	if err := smtptest.Cmd(tp, 250, "MAIL FROM:<sender@example.org>"); err != nil {
		t.Fatalf("MAIL FROM failed: %v", err)
	}

	// The address of the header stands, and the one of the command does not.
	if host, _, _ := net.SplitHostPort(cap.got.Addr.String()); host != "42.42.42.42" {
		t.Fatalf("Peer.Addr = %v, want the address of the PROXY header", cap.got.Addr)
	}
	if cap.got.Username == "someone" {
		t.Error("the refused command wrote Peer.Username")
	}
}

// TestXCLIENTReadsTheAddress verifies the forms that the ADDR attribute takes.
// The XCLIENT specification writes an IPv4 address as it is, and an IPv6
// address after the prefix "IPV6:". The prefix comes in either case.
//
// An IPv6 address without the prefix is read as well. The specification does
// not give that form, but the value says one thing alone, and a proxy that
// sends it has a session that works.
func TestXCLIENTReadsTheAddress(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		command string
		want    string
	}{
		{
			name:    "an IPv4 address",
			command: "XCLIENT ADDR=192.0.2.7 PORT=4242",
			want:    "192.0.2.7:4242",
		},
		{
			name:    "an IPv6 address after the prefix",
			command: "XCLIENT ADDR=IPV6:2001:db8::7 PORT=4242",
			want:    "[2001:db8::7]:4242",
		},
		{
			name:    "the prefix in lower case",
			command: "XCLIENT ADDR=ipv6:2001:db8::7 PORT=4242",
			want:    "[2001:db8::7]:4242",
		},
		{
			name:    "the prefix in mixed case",
			command: "XCLIENT ADDR=IPv6:2001:db8::7 PORT=4242",
			want:    "[2001:db8::7]:4242",
		},
		{
			name:    "an IPv6 address without the prefix",
			command: "XCLIENT ADDR=2001:db8::7 PORT=4242",
			want:    "[2001:db8::7]:4242",
		},
		{
			// The proxy has no protocol to give, and the one of the session
			// stays.
			name:    "a protocol that the proxy does not know",
			command: "XCLIENT ADDR=192.0.2.7 PORT=4242 PROTO=[UNAVAILABLE]",
			want:    "192.0.2.7:4242",
		},
		{
			name:    "a protocol in lower case",
			command: "XCLIENT ADDR=192.0.2.7 PORT=4242 PROTO=esmtp",
			want:    "192.0.2.7:4242",
		},
		{
			name:    "two spaces between two attributes",
			command: "XCLIENT ADDR=192.0.2.7  PORT=4242",
			want:    "192.0.2.7:4242",
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
				t.Fatalf("%q = %q, want 220", test.command, reply)
			}
			if reply := c.send("MAIL FROM:<sender@example.org>"); !strings.HasPrefix(reply, "250") {
				t.Fatalf("MAIL FROM = %q, want 250", reply)
			}

			if got := cap.got.Addr.String(); got != test.want {
				t.Errorf("Peer.Addr = %q, want %q", got, test.want)
			}
		})
	}
}

// TestXCLIENTRefusesAValueThatDoesNotRead verifies that the server answers
// 501 to a command with a value that it cannot read, and that no attribute of
// such a command reaches the peer.
//
// A value that the server drops leaves the attribute as it was. For ADDR that
// is the address of the proxy, so the RBL check, the SPF check, the greylist
// and the rate limits all read the proxy in the place of the client.
//
// A control character has no place in a value. A handler writes
// Peer.HeloName and Peer.Username into a Received header and into the log,
// and a line break there starts a line that the client chose.
//
// One space separates two attributes, and no other character does. A proxy
// that passes a HELO name on without encoding it keeps a tab or a no-break
// space inside the value. A server that broke on that character would read an
// attribute that the client wrote, such as LOGIN.
func TestXCLIENTRefusesAValueThatDoesNotRead(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		command string
	}{
		{
			name:    "a word in ADDR",
			command: "XCLIENT HELO=spoofed.example LOGIN=admin ADDR=not-an-address",
		},
		{
			name:    "no value in ADDR",
			command: "XCLIENT HELO=spoofed.example LOGIN=admin ADDR=",
		},
		{
			name:    "an IPv4 address after the IPv6 prefix",
			command: "XCLIENT HELO=spoofed.example LOGIN=admin ADDR=IPV6:192.0.2.7",
		},
		{
			name:    "the IPv6 prefix alone",
			command: "XCLIENT HELO=spoofed.example LOGIN=admin ADDR=IPV6:",
		},
		{
			name:    "an address in brackets",
			command: "XCLIENT HELO=spoofed.example LOGIN=admin ADDR=[192.0.2.7]",
		},
		{
			name:    "an address with a port",
			command: "XCLIENT HELO=spoofed.example LOGIN=admin ADDR=192.0.2.7:25",
		},
		{
			name:    "an address with a zone",
			command: "XCLIENT HELO=spoofed.example LOGIN=admin ADDR=IPV6:fe80::7%eth0",
		},
		{
			name:    "a line break in HELO",
			command: "XCLIENT ADDR=192.0.2.7 LOGIN=admin HELO=a+0D+0AReceived:+20forged",
		},
		{
			name:    "a line break in LOGIN",
			command: "XCLIENT ADDR=192.0.2.7 HELO=spoofed.example LOGIN=admin+0D+0Ax",
		},
		{
			name:    "a NUL in LOGIN",
			command: "XCLIENT ADDR=192.0.2.7 HELO=spoofed.example LOGIN=admin+00",
		},
		{
			name:    "an escape character in NAME",
			command: "XCLIENT ADDR=192.0.2.7 HELO=spoofed.example LOGIN=admin NAME=a+1Bb",
		},
		{
			name:    "a DEL in HELO",
			command: "XCLIENT ADDR=192.0.2.7 LOGIN=admin HELO=a+7Fb",
		},
		{
			name:    "a control character that is not encoded",
			command: "XCLIENT ADDR=192.0.2.7 LOGIN=admin HELO=a\x1bb",
		},
		{
			name:    "a protocol that the specification does not have",
			command: "XCLIENT ADDR=192.0.2.7 HELO=spoofed.example LOGIN=admin PROTO=HTTP",
		},
		{
			name:    "a tab between two attributes",
			command: "XCLIENT ADDR=192.0.2.7 HELO=spoofed.example\tLOGIN=admin",
		},
		{
			name:    "a vertical tab after a value",
			command: "XCLIENT HELO=spoofed.example LOGIN=admin\v ADDR=192.0.2.7",
		},
		{
			name:    "a form feed between two attributes",
			command: "XCLIENT ADDR=192.0.2.7 HELO=spoofed.example\fLOGIN=admin",
		},
		{
			name:    "a CR between two attributes",
			command: "XCLIENT ADDR=192.0.2.7 HELO=spoofed.example\rLOGIN=admin",
		},
		{
			name:    "a no-break space between two attributes",
			command: "XCLIENT ADDR=192.0.2.7 HELO=spoofed.example LOGIN=admin",
		},
		{
			name:    "a line separator between two attributes",
			command: "XCLIENT ADDR=192.0.2.7 HELO=spoofed.example LOGIN=admin",
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
			if reply := c.send("%s", test.command); !strings.HasPrefix(reply, "501") {
				t.Fatalf("%q = %q, want 501", test.command, reply)
			}
			if reply := c.send("MAIL FROM:<sender@example.org>"); !strings.HasPrefix(reply, "250") {
				t.Fatalf("MAIL FROM = %q, want 250", reply)
			}

			// The peer is the one of the connection and of the greeting.
			if host, _, _ := net.SplitHostPort(cap.got.Addr.String()); host != "127.0.0.1" {
				t.Errorf("Peer.Addr = %v, want the address of the connection", cap.got.Addr)
			}
			if got := cap.got.HeloName; got != "client.example" {
				t.Errorf("Peer.HeloName = %q, want %q", got, "client.example")
			}
			if got := cap.got.Username; got != "" {
				t.Errorf("Peer.Username = %q, want it empty", got)
			}
		})
	}
}

// TestXCLIENTInsideATransaction verifies that the server answers 503 to an
// XCLIENT command between MAIL FROM and the end of the message. The XCLIENT
// specification gives that reply for a mail transaction in progress.
//
// A command that the server took there changed the client of a transaction
// whose sender the hooks already checked for another client.
func TestXCLIENTInsideATransaction(t *testing.T) {
	t.Parallel()

	const (
		command = "XCLIENT ADDR=192.0.2.7 LOGIN=admin"
		refusal = "503 5.5.1 XCLIENT is not accepted inside a mail transaction"
	)

	t.Run("a message through DATA", func(t *testing.T) {
		t.Parallel()

		rec := &smtptest.Recorder{}
		srv := runserver(t, &smtpd.Server{
			EnableXCLIENT: true,
			Logger:        testLogger(t),
			Handler:       rec.Handler,
		})

		c := dialRaw(t, srv.Addr)
		c.send("EHLO client.example")

		c.send("MAIL FROM:<sender@example.org>")
		if reply := c.send(command); reply != refusal {
			t.Fatalf("XCLIENT after MAIL FROM = %q, want %q", reply, refusal)
		}

		c.send("RCPT TO:<recipient@example.net>")
		if reply := c.send(command); reply != refusal {
			t.Fatalf("XCLIENT after RCPT TO = %q, want %q", reply, refusal)
		}

		// The transaction goes on as it was.
		c.send("DATA")
		if reply := c.send("body\r\n."); !strings.HasPrefix(reply, "250") {
			t.Fatalf("end of message = %q, want 250", reply)
		}

		messages := rec.Messages()
		if len(messages) != 1 {
			t.Fatalf("the server delivered %d messages, want 1", len(messages))
		}
		peer := messages[0].Peer
		if host, _, _ := net.SplitHostPort(peer.Addr.String()); host != "127.0.0.1" {
			t.Errorf("Peer.Addr = %v, want the address of the connection", peer.Addr)
		}
		if got := peer.Username; got != "" {
			t.Errorf("Peer.Username = %q, want it empty", got)
		}

		// The message ended the transaction, so the server takes the command.
		if reply := c.send(command); !strings.HasPrefix(reply, "220") {
			t.Fatalf("XCLIENT after the message = %q, want 220", reply)
		}
	})

	t.Run("a message through BDAT", func(t *testing.T) {
		t.Parallel()

		srv := runserver(t, &smtpd.Server{
			EnableXCLIENT: true,
			Logger:        testLogger(t),
		})

		c := dialRaw(t, srv.Addr)
		openTransaction(t, c, "MAIL FROM:<sender@example.org>")

		if reply := bdat(t, c, "half", false); !strings.HasPrefix(reply, "250") {
			t.Fatalf("BDAT = %q, want 250", reply)
		}
		if reply := c.send(command); reply != refusal {
			t.Fatalf("XCLIENT between two chunks = %q, want %q", reply, refusal)
		}
		if reply := bdat(t, c, "", true); !strings.HasPrefix(reply, "250") {
			t.Fatalf("BDAT LAST = %q, want 250", reply)
		}
	})

	t.Run("after RSET", func(t *testing.T) {
		t.Parallel()

		srv := runserver(t, &smtpd.Server{
			EnableXCLIENT: true,
			Logger:        testLogger(t),
		})

		c := dialRaw(t, srv.Addr)
		c.send("EHLO client.example")
		c.send("MAIL FROM:<sender@example.org>")
		c.send("RSET")

		if reply := c.send(command); !strings.HasPrefix(reply, "220") {
			t.Fatalf("XCLIENT after RSET = %q, want 220", reply)
		}
	})
}
