package smtpd_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/textproto"
	"testing"
	"testing/synctest"
	"time"

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

// proxyV2Header builds a header of the PROXY protocol version 2. command is
// the low half of the version octet, and famProto carries the address family
// and the transport protocol.
func proxyV2Header(command, famProto byte, block []byte) []byte {
	header := []byte{0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A}
	header = append(header, 0x20|command, famProto, 0, 0)
	binary.BigEndian.PutUint16(header[14:16], uint16(len(block)))
	return append(header, block...)
}

// proxyV2Addrs builds the address block of the IPv4 or the IPv6 family: the
// two addresses first, and the two ports after them.
func proxyV2Addrs(src, dst string, srcPort, dstPort uint16) []byte {
	srcIP, dstIP := net.ParseIP(src), net.ParseIP(dst)
	if v4 := srcIP.To4(); v4 != nil {
		srcIP, dstIP = v4, dstIP.To4()
	}

	block := append(append([]byte{}, srcIP...), dstIP...)
	block = binary.BigEndian.AppendUint16(block, srcPort)
	return binary.BigEndian.AppendUint16(block, dstPort)
}

// proxyV2Unix builds the address block of the UNIX family: two paths of 108
// octets each, with NUL after the path.
func proxyV2Unix(src, dst string) []byte {
	block := make([]byte, 216)
	copy(block[:108], src)
	copy(block[108:], dst)
	return block
}

// proxyV2Dial opens a connection, writes a header of version 2, and reads the
// greeting that follows it.
func proxyV2Dial(t *testing.T, addr string, header []byte) (*textproto.Conn, net.Conn) {
	t.Helper()

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	if _, err := conn.Write(header); err != nil {
		t.Fatalf("the header could not be written: %v", err)
	}

	tp := textproto.NewConn(conn)
	if _, _, err := tp.ReadResponse(220); err != nil {
		t.Fatalf("the greeting after the header failed: %v", err)
	}

	return tp, conn
}

// proxyV2Sender opens a transaction, so that the CheckSender hook reads the
// address of the peer.
func proxyV2Sender(t *testing.T, tp *textproto.Conn) {
	t.Helper()

	if err := smtptest.Cmd(tp, 250, "HELO localhost"); err != nil {
		t.Fatalf("HELO failed: %v", err)
	}
	if err := smtptest.Cmd(tp, 250, "MAIL FROM:<sender@example.org>"); err != nil {
		t.Fatalf("MAIL failed: %v", err)
	}
}

// TestPROXYV2OverridesPeerAddr covers the address that a header of version 2
// puts on the peer.
func TestPROXYV2OverridesPeerAddr(t *testing.T) {
	t.Parallel()

	// A value of the protocol that a proxy writes after the addresses. The
	// server reads the addresses and leaves this one where it is.
	tlv := []byte{0x02, 0x00, 0x02, 0x41, 0x42}

	tests := []struct {
		name   string
		header []byte
		want   string
	}{
		{
			name:   "IPv4",
			header: proxyV2Header(0x1, 0x11, proxyV2Addrs("42.42.42.42", "5.6.7.8", 4242, 25)),
			want:   "42.42.42.42:4242",
		},
		{
			name:   "IPv6",
			header: proxyV2Header(0x1, 0x21, proxyV2Addrs("2001:db8::1", "2001:db8::2", 4242, 25)),
			want:   "[2001:db8::1]:4242",
		},
		{
			name:   "IPv4 with a value after the addresses",
			header: proxyV2Header(0x1, 0x11, append(proxyV2Addrs("42.42.42.42", "5.6.7.8", 4242, 25), tlv...)),
			want:   "42.42.42.42:4242",
		},
		{
			name:   "a unix socket",
			header: proxyV2Header(0x1, 0x31, proxyV2Unix("/var/run/haproxy.sock", "/var/run/smtpd.sock")),
			want:   "/var/run/haproxy.sock",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			addr := &capturedAddr{}
			srv := runserver(t, &smtpd.Server{
				EnableProxyProtocol: true,
				Logger:              testLogger(t),
			}, capturePeerAddr(addr))

			tp, _ := proxyV2Dial(t, srv.Addr, tc.header)
			proxyV2Sender(t, tp)

			if addr.got == nil {
				t.Fatal("CheckSender never saw peer.Addr")
			}
			if addr.got.String() != tc.want {
				t.Errorf("peer.Addr = %s, want %s", addr.got, tc.want)
			}

			_ = smtptest.Cmd(tp, 221, "QUIT")
		})
	}
}

// TestPROXYV2KeepsTheConnectionAddress covers the headers that carry no
// address of a client: the addresses of the connection stay on the peer.
func TestPROXYV2KeepsTheConnectionAddress(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		header []byte
	}{
		{
			name: "a connection of the proxy itself",
			// The LOCAL command comes with an address block that the server
			// reads no address out of.
			header: proxyV2Header(0x0, 0x11, proxyV2Addrs("42.42.42.42", "5.6.7.8", 4242, 25)),
		},
		{
			name:   "an unspecified address family",
			header: proxyV2Header(0x1, 0x00, nil),
		},
		{
			name:   "an unspecified transport protocol",
			header: proxyV2Header(0x1, 0x10, nil),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			addr := &capturedAddr{}
			srv := runserver(t, &smtpd.Server{
				EnableProxyProtocol: true,
				Logger:              testLogger(t),
			}, capturePeerAddr(addr))

			tp, conn := proxyV2Dial(t, srv.Addr, tc.header)
			proxyV2Sender(t, tp)

			if addr.got == nil {
				t.Fatal("CheckSender never saw peer.Addr")
			}
			if addr.got.String() != conn.LocalAddr().String() {
				t.Errorf("peer.Addr = %s, want the address of the connection %s", addr.got, conn.LocalAddr())
			}

			_ = smtptest.Cmd(tp, 221, "QUIT")
		})
	}
}

// TestPROXYV2Refused covers a header that the server cannot read. The session
// ends without a greeting, and the Disconnect hooks read a ProxyError.
func TestPROXYV2Refused(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		header []byte
	}{
		{
			name:   "a signature that does not read",
			header: append([]byte{0x0D}, bytes.Repeat([]byte{0x2A}, 31)...),
		},
		{
			name:   "a version that is not 2",
			header: append(append([]byte{}, proxyV2Header(0x1, 0x11, nil)[:12]...), 0x11, 0x11, 0x00, 0x00),
		},
		{
			name:   "a command that is neither LOCAL nor PROXY",
			header: proxyV2Header(0xF, 0x11, proxyV2Addrs("42.42.42.42", "5.6.7.8", 4242, 25)),
		},
		{
			name:   "a transport protocol of datagrams",
			header: proxyV2Header(0x1, 0x12, proxyV2Addrs("42.42.42.42", "5.6.7.8", 4242, 25)),
		},
		{
			name:   "an address block that is too short",
			header: proxyV2Header(0x1, 0x11, []byte{1, 2, 3, 4}),
		},
		{
			// The protocol says nothing here, and the family carries a value
			// that no version of the protocol has.
			name:   "an address family that is not one of the four",
			header: proxyV2Header(0x1, 0xF0, nil),
		},
		{
			// The family says nothing here, and the protocol carries a value
			// that no version of the protocol has.
			name:   "a transport protocol that is not one of the three",
			header: proxyV2Header(0x1, 0x0F, nil),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			record := &disconnectRecord{}
			srv := runserver(t, &smtpd.Server{
				EnableProxyProtocol: true,
				Logger:              testLogger(t),
			}, disconnectCounter(record))

			conn, err := net.Dial("tcp", srv.Addr)
			if err != nil {
				t.Fatalf("Dial failed: %v", err)
			}
			defer func() { _ = conn.Close() }()

			if _, err := conn.Write(tc.header); err != nil {
				t.Fatalf("the header could not be written: %v", err)
			}

			_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
			if line, err := textproto.NewConn(conn).ReadLine(); err == nil {
				t.Fatalf("the server answered %q, want a session that ends", line)
			}

			count, lastErr := waitDisconnect(record, 3*time.Second)
			if count != 1 {
				t.Fatalf("the Disconnect hook ran %d times, want 1", count)
			}

			var proxyErr smtpd.ProxyError
			if !errors.As(lastErr, &proxyErr) {
				t.Fatalf("the Disconnect hook read %v, want a ProxyError", lastErr)
			}
			if proxyErr.Reason == "" {
				t.Error("the ProxyError carries no reason")
			}
		})
	}
}

// TestPROXYV1SplitHeader covers a header of version 1 that arrives in pieces.
// The server reads the first octet of the stream to tell the two versions
// apart, and that read must take no more of the header than the one octet.
func TestPROXYV1SplitHeader(t *testing.T) {
	t.Parallel()

	addr := &capturedAddr{}
	srv := runserver(t, &smtpd.Server{
		EnableProxyProtocol: true,
		Logger:              testLogger(t),
	}, capturePeerAddr(addr))

	conn, err := net.Dial("tcp", srv.Addr)
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}
	defer func() { _ = conn.Close() }()

	for _, part := range []string{"P", "ROXY TCP4 42.42.42.42 5.6", ".7.8 4242 25\r\n"} {
		if _, err := conn.Write([]byte(part)); err != nil {
			t.Fatalf("the header could not be written: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}

	tp := textproto.NewConn(conn)
	if _, _, err := tp.ReadResponse(220); err != nil {
		t.Fatalf("the greeting after the header failed: %v", err)
	}

	proxyV2Sender(t, tp)

	if addr.got == nil {
		t.Fatal("CheckSender never saw peer.Addr")
	}
	if addr.got.String() != "42.42.42.42:4242" {
		t.Errorf("peer.Addr = %s, want 42.42.42.42:4242", addr.got)
	}

	_ = smtptest.Cmd(tp, 221, "QUIT")
}

// TestPROXYV2Truncated covers a header of version 2 that stops in the middle.
// The first octet says that a header of that version follows, so what comes
// after it is a header that the server could not read, and the ProxyError
// carries the error of the read.
func TestPROXYV2Truncated(t *testing.T) {
	t.Parallel()

	// A whole header of the IPv4 family: 16 octets, and 12 after them.
	whole := proxyV2Header(0x1, 0x11, proxyV2Addrs("42.42.42.42", "5.6.7.8", 4242, 25))

	tests := []struct {
		name   string
		header []byte
	}{
		{
			name:   "inside the first 16 octets",
			header: whole[:8],
		},
		{
			name:   "inside the address block",
			header: whole[:20],
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			record := &disconnectRecord{}
			srv := runserver(t, &smtpd.Server{
				EnableProxyProtocol: true,
				Logger:              testLogger(t),
			}, disconnectCounter(record))

			conn, err := net.Dial("tcp", srv.Addr)
			if err != nil {
				t.Fatalf("Dial failed: %v", err)
			}
			defer func() { _ = conn.Close() }()

			if _, err := conn.Write(tc.header); err != nil {
				t.Fatalf("the header could not be written: %v", err)
			}

			// The end of the stream is what tells the server that no more of
			// the header follows.
			if err := conn.(*net.TCPConn).CloseWrite(); err != nil {
				t.Fatalf("the write side could not be closed: %v", err)
			}

			count, lastErr := waitDisconnect(record, 3*time.Second)
			if count != 1 {
				t.Fatalf("the Disconnect hook ran %d times, want 1", count)
			}

			var proxyErr smtpd.ProxyError
			if !errors.As(lastErr, &proxyErr) {
				t.Fatalf("the Disconnect hook read %v, want a ProxyError", lastErr)
			}
			if !errors.Is(lastErr, io.ErrUnexpectedEOF) {
				t.Errorf("the ProxyError carries %v, want the error of the read", proxyErr.Err)
			}
		})
	}
}

// TestPROXYIdleConnectionTimesOut covers a connection that sends no header at
// all. The server holds the greeting back until one arrives, and the read of
// it takes ReadTimeout, so the session ends and gives its slot in
// MaxConnections back.
func TestPROXYIdleConnectionTimesOut(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		l := runpipeserver(t, &smtpd.Server{
			EnableProxyProtocol: true,
			MaxConnections:      1,
			ReadTimeout:         time.Second,
			WriteTimeout:        time.Second,
			Logger:              testLogger(t),
		})
		defer func() { _ = l.Close() }()

		idle := l.dial(t)

		// The connection sends nothing, so the read of the header runs into
		// the deadline.
		time.Sleep(2 * time.Second)
		synctest.Wait()

		if _, err := idle.Read(make([]byte, 1)); err == nil {
			t.Fatal("the idle connection is open, want a session that ended")
		}

		// The session gave its slot back, so the connection that follows
		// takes one and runs. The header is of version 2, because a header of
		// version 1 needs an address of TCP and this listener has none.
		conn := l.dial(t)
		header := proxyV2Header(0x1, 0x11, proxyV2Addrs("42.42.42.42", "5.6.7.8", 4242, 25))
		if _, err := conn.Write(header); err != nil {
			t.Fatalf("the header could not be written: %v", err)
		}

		tp := textproto.NewConn(conn)
		if _, _, err := tp.ReadResponse(220); err != nil {
			t.Fatalf("the greeting after the header failed: %v", err)
		}

		_ = smtptest.Cmd(tp, 221, "QUIT")
	})
}

// TestPROXYOnlyAsTheFirstLine covers a PROXY command that comes after the
// header of the proxy. The proxy writes its header before it passes on
// anything of the client, so a second one comes from the client behind it,
// and the address of that client stays where it is.
func TestPROXYOnlyAsTheFirstLine(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		// between are the commands that the client sends after the header of
		// the proxy and before the PROXY command of its own.
		between []string
	}{
		{
			name: "right after the header",
		},
		{
			name:    "after a greeting",
			between: []string{"HELO localhost"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			addr := &capturedAddr{}
			srv := runserver(t, &smtpd.Server{
				EnableProxyProtocol: true,
				Logger:              testLogger(t),
			}, capturePeerAddr(addr))

			conn, err := net.Dial("tcp", srv.Addr)
			if err != nil {
				t.Fatalf("Dial failed: %v", err)
			}
			defer func() { _ = conn.Close() }()

			tp := textproto.NewConn(conn)
			if err := smtptest.Cmd(tp, 220, "PROXY TCP4 42.42.42.42 5.6.7.8 4242 25"); err != nil {
				t.Fatalf("the header of the proxy failed: %v", err)
			}

			for _, command := range tc.between {
				if err := smtptest.Cmd(tp, 250, "%s", command); err != nil {
					t.Fatalf("%s failed: %v", command, err)
				}
			}

			if err := smtptest.Cmd(tp, 503, "PROXY TCP4 9.9.9.9 5.6.7.8 9999 25"); err != nil {
				t.Fatalf("the second PROXY didn't 503: %v", err)
			}

			// The session goes on with the address of the header, and the
			// hooks read that one.
			if err := smtptest.Cmd(tp, 250, "HELO localhost"); err != nil {
				t.Fatalf("HELO failed: %v", err)
			}
			if err := smtptest.Cmd(tp, 250, "MAIL FROM:<sender@example.org>"); err != nil {
				t.Fatalf("MAIL failed: %v", err)
			}

			if addr.got == nil {
				t.Fatal("CheckSender never saw peer.Addr")
			}
			if addr.got.String() != "42.42.42.42:4242" {
				t.Errorf("peer.Addr = %s, want the address of the header 42.42.42.42:4242", addr.got)
			}

			_ = smtptest.Cmd(tp, 221, "QUIT")
		})
	}
}

// TestPROXYV2ClosesTheFirstLine covers a PROXY command that follows a header
// of version 2. The header is the first line of the session, so the command
// after it comes from the client behind the proxy.
func TestPROXYV2ClosesTheFirstLine(t *testing.T) {
	t.Parallel()

	addr := &capturedAddr{}
	srv := runserver(t, &smtpd.Server{
		EnableProxyProtocol: true,
		Logger:              testLogger(t),
	}, capturePeerAddr(addr))

	header := proxyV2Header(0x1, 0x11, proxyV2Addrs("42.42.42.42", "5.6.7.8", 4242, 25))
	tp, _ := proxyV2Dial(t, srv.Addr, header)

	if err := smtptest.Cmd(tp, 503, "PROXY TCP4 9.9.9.9 5.6.7.8 9999 25"); err != nil {
		t.Fatalf("the PROXY command after the header didn't 503: %v", err)
	}

	proxyV2Sender(t, tp)

	if addr.got == nil {
		t.Fatal("CheckSender never saw peer.Addr")
	}
	if addr.got.String() != "42.42.42.42:4242" {
		t.Errorf("peer.Addr = %s, want the address of the header 42.42.42.42:4242", addr.got)
	}

	_ = smtptest.Cmd(tp, 221, "QUIT")
}
