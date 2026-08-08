package smtpd_test

import (
	"context"
	"net"
	"net/textproto"
	"testing"

	"github.com/chrj/smtpd/v2"
	"github.com/chrj/smtpd/v2/smtptest"
)

// capturedAddr holds the peer.Addr value recorded by capturePeerAddr.
type capturedAddr struct{ got net.Addr }

// capturePeerAddr returns a Middleware whose CheckSender stores the first
// peer.Addr it sees into state.got.
func capturePeerAddr(state *capturedAddr) smtpd.Middleware {
	return smtpd.Middleware{
		CheckSender: func(ctx context.Context, peer smtpd.Peer, _ string) (context.Context, error) {
			if state.got == nil {
				state.got = peer.Addr
			}
			return ctx, nil
		},
	}
}

// dialRawProxy opens a raw TCP connection without reading a banner - necessary
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
	t.Parallel()

	srv := runserver(t, &smtpd.Server{Logger: testLogger(t)})

	c := srv.Dial()
	if err := smtptest.Cmd(c.Text, 550, "PROXY TCP4 1.2.3.4 5.6.7.8 12345 25"); err != nil {
		t.Fatalf("PROXY with protocol disabled didn't 550: %v", err)
	}
}

func TestPROXYTooFewFields(t *testing.T) {
	t.Parallel()

	srv := runserver(t, &smtpd.Server{
		EnableProxyProtocol: true,
		Logger:              testLogger(t),
	})

	tp, raw := dialRawProxy(t, srv.Addr)
	defer func() { _ = raw.Close() }()
	if err := smtptest.Cmd(tp, 501, "PROXY TCP4 1.2.3.4 5.6.7.8 12345"); err != nil {
		t.Fatalf("PROXY with too few fields didn't 501: %v", err)
	}
}

func TestPROXYBadPort(t *testing.T) {
	t.Parallel()

	srv := runserver(t, &smtpd.Server{
		EnableProxyProtocol: true,
		Logger:              testLogger(t),
	})

	tp, raw := dialRawProxy(t, srv.Addr)
	defer func() { _ = raw.Close() }()
	if err := smtptest.Cmd(tp, 501, "PROXY TCP4 1.2.3.4 5.6.7.8 notanumber 25"); err != nil {
		t.Fatalf("PROXY with bad port didn't 501: %v", err)
	}
}

func TestPROXYOverridesPeerAddr(t *testing.T) {
	t.Parallel()

	cap := &capturedAddr{}
	srv := runserver(t, &smtpd.Server{
		EnableProxyProtocol: true,
		Logger:              testLogger(t),
	}, capturePeerAddr(cap))

	conn, err := net.Dial("tcp", srv.Addr)
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}
	defer func() { _ = conn.Close() }()

	tp := textproto.NewConn(conn)
	if err := smtptest.Cmd(tp, 220, "PROXY TCP4 42.42.42.42 5.6.7.8 4242 25"); err != nil {
		t.Fatalf("PROXY failed: %v", err)
	}

	// Hand the live connection over to net/smtp, using a bufio.Reader so
	// NewClient re-reads the 220 we just saw? No - NewClient expects the
	// banner, so continue with raw textproto commands instead.
	if err := smtptest.Cmd(tp, 250, "HELO localhost"); err != nil {
		t.Fatalf("HELO failed: %v", err)
	}
	if err := smtptest.Cmd(tp, 250, "MAIL FROM:<sender@example.org>"); err != nil {
		t.Fatalf("MAIL failed: %v", err)
	}
	if cap.got == nil {
		t.Fatal("CheckSender never saw peer.Addr")
	}
	if cap.got.String() != "42.42.42.42:4242" {
		t.Fatalf("peer.Addr after PROXY = %s, want 42.42.42.42:4242", cap.got)
	}
	_ = smtptest.Cmd(tp, 221, "QUIT")
}
