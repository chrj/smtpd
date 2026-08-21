package smtptest

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/chrj/smtpd/v2"
)

// TestDialGivesUpOnASilentServer covers a server that takes the connection and
// answers nothing. Dial gives up on its deadline, where it waited for the
// greeting until the whole test run timed out.
func TestDialGivesUpOnASilentServer(t *testing.T) {
	// A test cannot wait for the deadline of the package.
	old := handshakeTimeout
	handshakeTimeout = 100 * time.Millisecond
	t.Cleanup(func() { handshakeTimeout = old })

	// The hook holds the session, so the client sees no greeting. The
	// cleanups run in the order that a session needs: the hook returns, and
	// Close then finds nothing to wait for.
	release := make(chan struct{})

	srv := NewUnstartedServer(nil)
	srv.Config.Use(smtpd.Middleware{
		CheckConnection: func(ctx context.Context, _ smtpd.Peer) (context.Context, error) {
			<-release
			return ctx, nil
		},
	})

	srv.Start()
	t.Cleanup(srv.Close)
	t.Cleanup(func() { close(release) })

	start := time.Now()
	value := dialValue(t, srv)

	if value == nil {
		t.Fatal("Dial read a greeting from a server that sent none")
	}
	if got := time.Since(start); got > 5*time.Second {
		t.Errorf("Dial gave up after %s, want the deadline of %s", got, handshakeTimeout)
	}

	if text, ok := value.(string); !ok || !strings.Contains(text, "greeting") {
		t.Errorf("Dial panicked with %v, want the greeting that it waited for", value)
	}
}

// dialValue returns the panic value of Dial, or nil when Dial did not panic.
// A client that Dial returned is closed again.
func dialValue(t *testing.T, srv *Server) (value any) {
	t.Helper()

	defer func() { value = recover() }()

	c := srv.Dial()
	_ = c.Close()
	return nil
}
