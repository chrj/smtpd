package smtpd_test

import (
	"context"
	"net"
	"net/smtp"
	"net/textproto"
	"testing"

	"github.com/chrj/smtpd/v2/pkg/smtpd"
)

// capturePeerAddr records the peer's Addr the first time CheckSender runs.
type capturePeerAddr struct{ got net.Addr }

func (capturePeerAddr) ServeSMTP(context.Context, smtpd.Peer, *smtpd.Envelope) error { return nil }
func (c *capturePeerAddr) CheckSender(ctx context.Context, peer smtpd.Peer, _ string) (context.Context, error) {
	if c.got == nil {
		c.got = peer.Addr
	}
	return ctx, nil
}

// dialRawProxy opens a raw TCP connection without reading a banner — necessary
// because when EnableProxyProtocol is set, the server withholds the banner
// until PROXY is received.
func dialRawProxy(t *testing.T, addr string) (*textproto.Conn, net.Conn) {
	t.Helper()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}
	return textproto.NewConn(conn), conn
}

func TestPROXYDisabled(t *testing.T) {
	addr, closer := runserver(t, &smtpd.Server{Logger: testLogger(t)})
	defer closer()

	c, err := smtp.Dial(addr)
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}
	if err := cmd(c.Text, 550, "PROXY TCP4 1.2.3.4 5.6.7.8 12345 25"); err != nil {
		t.Fatalf("PROXY with protocol disabled didn't 550: %v", err)
	}
}

func TestPROXYTooFewFields(t *testing.T) {
	addr, closer := runserver(t, &smtpd.Server{
		EnableProxyProtocol: true,
		Logger:              testLogger(t),
	})
	defer closer()

	tp, raw := dialRawProxy(t, addr)
	defer func() { _ = raw.Close() }()
	if err := cmd(tp, 502, "PROXY TCP4 1.2.3.4 5.6.7.8 12345"); err != nil {
		t.Fatalf("PROXY with too few fields didn't 502: %v", err)
	}
}

func TestPROXYBadPort(t *testing.T) {
	addr, closer := runserver(t, &smtpd.Server{
		EnableProxyProtocol: true,
		Logger:              testLogger(t),
	})
	defer closer()

	tp, raw := dialRawProxy(t, addr)
	defer func() { _ = raw.Close() }()
	if err := cmd(tp, 502, "PROXY TCP4 1.2.3.4 5.6.7.8 notanumber 25"); err != nil {
		t.Fatalf("PROXY with bad port didn't 502: %v", err)
	}
}

func TestPROXYOverridesPeerAddr(t *testing.T) {
	cap := &capturePeerAddr{}
	addr, closer := runserver(t, &smtpd.Server{
		EnableProxyProtocol: true,
		Logger:              testLogger(t),
	}, cap)
	defer closer()

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}
	defer func() { _ = conn.Close() }()

	tp := textproto.NewConn(conn)
	if err := cmd(tp, 220, "PROXY TCP4 42.42.42.42 5.6.7.8 4242 25"); err != nil {
		t.Fatalf("PROXY failed: %v", err)
	}

	// Hand the live connection over to net/smtp, using a bufio.Reader so
	// NewClient re-reads the 220 we just saw? No — NewClient expects the
	// banner, so continue with raw textproto commands instead.
	if err := cmd(tp, 250, "HELO localhost"); err != nil {
		t.Fatalf("HELO failed: %v", err)
	}
	if err := cmd(tp, 250, "MAIL FROM:<sender@example.org>"); err != nil {
		t.Fatalf("MAIL failed: %v", err)
	}
	if cap.got == nil {
		t.Fatal("CheckSender never saw peer.Addr")
	}
	if cap.got.String() != "42.42.42.42:4242" {
		t.Fatalf("peer.Addr after PROXY = %s, want 42.42.42.42:4242", cap.got)
	}
	_ = cmd(tp, 221, "QUIT")
}
