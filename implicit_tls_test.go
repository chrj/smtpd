package smtpd_test

import (
	"context"
	"errors"
	"io"
	"os"
	"testing"
	"testing/synctest"
	"time"

	"github.com/chrj/smtpd/v2"
)

// greeting is what a server of these tests writes first. newTestServer gives
// the server no Hostname, so it takes the default one.
const greeting = "220 localhost.localdomain ESMTP ready."

// TestImplicitTLSIdleClientHoldsNoOtherConnection verifies that a client which
// opens a connection and never starts the TLS handshake does not keep the
// server from the client behind it. The handshake waits for the client, so it
// must not run where the server accepts its connections.
func TestImplicitTLSIdleClientHoldsNoOtherConnection(t *testing.T) {
	t.Parallel()

	ts := runImplicitTLSServer(t, &smtpd.Server{Logger: testLogger(t)})

	// The idle connection comes first, so the server accepts it first.
	dialIdle(t, ts.Addr)

	c, err := dialRawTLS(t, ts)
	if err != nil {
		t.Fatalf("the TLS handshake behind an idle connection failed: %v", err)
	}
	if got := c.line(); got != greeting {
		t.Fatalf("greeting = %q, want %q", got, greeting)
	}
}

// TestImplicitTLSHandshakeEndsAtReadTimeout verifies that ReadTimeout bounds
// the TLS handshake. A client that never starts it loses the connection, and
// the Disconnect hooks read the deadline as the cause.
func TestImplicitTLSHandshakeEndsAtReadTimeout(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		var rec disconnectRecord

		server := &smtpd.Server{
			ReadTimeout:  time.Second,
			WriteTimeout: time.Second,
			Logger:       testLogger(t),
		}
		server.Use(disconnectCounter(&rec))

		l := runpipeTLSServer(t, server)
		defer func() { _ = l.Close() }()

		// The close also releases a server that still waits for the handshake,
		// so that a failure of this test ends the bubble.
		idle := l.dial(t)
		defer func() { _ = idle.Close() }()

		time.Sleep(2 * time.Second)
		synctest.Wait()

		count, lastErr := rec.Snapshot()
		if count != 1 {
			t.Fatalf("Disconnect ran %d times after ReadTimeout, want 1", count)
		}
		if !errors.Is(lastErr, os.ErrDeadlineExceeded) {
			t.Fatalf("Disconnect err = %v, want %v", lastErr, os.ErrDeadlineExceeded)
		}

		if _, err := idle.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
			t.Fatalf("read on the idle connection = %v, want %v from a closed connection", err, io.EOF)
		}
	})
}

// TestImplicitTLSOverTheLimitClosesWithoutAReply verifies that a connection
// over MaxConnections on a TLS listener closes at once. A reply needs the
// handshake first, and the handshake waits for the client, so a server that
// replies there holds a connection for every client that sends nothing.
func TestImplicitTLSOverTheLimitClosesWithoutAReply(t *testing.T) {
	t.Parallel()

	ts := runImplicitTLSServer(t, &smtpd.Server{
		MaxConnections: 1,
		Logger:         testLogger(t),
	})

	// The first client takes the one slot and keeps it.
	first, err := dialRawTLS(t, ts)
	if err != nil {
		t.Fatalf("the TLS handshake of the first client failed: %v", err)
	}
	if got := first.line(); got != greeting {
		t.Fatalf("greeting = %q, want %q", got, greeting)
	}

	// A client over the limit that sends nothing.
	idle := dialIdle(t, ts.Addr)
	_ = idle.SetReadDeadline(time.Now().Add(3 * time.Second))
	if n, err := idle.Read(make([]byte, 1)); n != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("read on the idle connection over the limit = (%d, %v), want (0, %v) from a closed connection", n, err, io.EOF)
	}

	// A client over the limit that starts the handshake.
	if _, err := dialRawTLS(t, ts); err == nil {
		t.Fatal("the TLS handshake of a client over the limit succeeded, want a closed connection")
	}

	// The session that holds the slot goes on.
	if got, want := first.send("NOOP"), "250 Go ahead"; got != want {
		t.Fatalf("NOOP on the first session = %q, want %q", got, want)
	}
}

// TestShutdownEndsASessionInTheTLSHandshake verifies that Shutdown does not
// wait for a client that never starts the TLS handshake. Shutdown cancels the
// context of every session, and the handshake reads that context.
func TestShutdownEndsASessionInTheTLSHandshake(t *testing.T) {
	t.Parallel()

	var rec disconnectRecord
	ts := runImplicitTLSServer(t, &smtpd.Server{Logger: testLogger(t)}, disconnectCounter(&rec))

	dialIdle(t, ts.Addr)

	// A whole session behind the idle connection. The server takes its
	// connections in order, so the session of the idle one is there when this
	// one ran.
	c, err := dialRawTLS(t, ts)
	if err != nil {
		t.Fatalf("the TLS handshake behind an idle connection failed: %v", err)
	}
	if got := c.line(); got != greeting {
		t.Fatalf("greeting = %q, want %q", got, greeting)
	}
	if got, want := c.send("QUIT"), "221 OK, bye"; got != want {
		t.Fatalf("QUIT = %q, want %q", got, want)
	}

	// ReadTimeout is 60 seconds here, so a Shutdown that returns inside its
	// own deadline ended the handshake and did not wait for it.
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	if err := ts.Config.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown() = %v, want nil", err)
	}

	count, lastErr := rec.Snapshot()
	if count != 2 {
		t.Fatalf("Disconnect ran %d times, want 2: the session that quit and the one in the handshake", count)
	}
	if !errors.Is(lastErr, context.Canceled) {
		t.Fatalf("Disconnect err of the session in the handshake = %v, want %v", lastErr, context.Canceled)
	}
}

// TestImplicitTLSStateReachesCheckConnection verifies that the handshake is
// over before the CheckConnection hooks run, so that they read Peer.TLS. A
// server with the PROXY protocol reads the header through the TLS connection,
// so the handshake comes before the header as well.
func TestImplicitTLSStateReachesCheckConnection(t *testing.T) {
	t.Parallel()

	type seen struct {
		tls  bool
		addr string
	}

	tests := []struct {
		name string
		// header is the PROXY header that the client writes before it reads
		// the greeting. It is empty for a server without the PROXY protocol.
		header string
		// wantAddr is the address that the header puts on the peer.
		wantAddr string
	}{
		{
			name: "the greeting comes first",
		},
		{
			name:     "a PROXY header comes first",
			header:   "PROXY TCP4 42.42.42.42 5.6.7.8 4242 25",
			wantAddr: "42.42.42.42:4242",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			// The hook runs one time for a connection, and the buffer lets it
			// return before the test reads the value.
			got := make(chan seen, 1)

			ts := runImplicitTLSServer(t, &smtpd.Server{
				EnableProxyProtocol: test.header != "",
				Logger:              testLogger(t),
			}, smtpd.Middleware{
				CheckConnection: func(ctx context.Context, peer smtpd.Peer) (context.Context, error) {
					got <- seen{tls: peer.TLS != nil, addr: peer.Addr.String()}
					return ctx, nil
				},
			})

			c, err := dialRawTLS(t, ts)
			if err != nil {
				t.Fatalf("the TLS handshake failed: %v", err)
			}

			var reply string
			if test.header != "" {
				reply = c.send("%s", test.header)
			} else {
				reply = c.line()
			}
			if reply != greeting {
				t.Fatalf("greeting = %q, want %q", reply, greeting)
			}

			// The greeting follows the hooks, so the value is there.
			hook := <-got
			if !hook.tls {
				t.Error("CheckConnection read a nil Peer.TLS, want the state of the TLS connection")
			}
			if test.wantAddr != "" && hook.addr != test.wantAddr {
				t.Errorf("CheckConnection read the address %q, want %q", hook.addr, test.wantAddr)
			}
		})
	}
}
