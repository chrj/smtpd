package middleware

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/chrj/smtpd/v2"
)

// errWrongPassword stands for the refusal of a credential check.
var errWrongPassword = smtpd.Error{Code: 535, Message: "Denied"}

// authFor returns an AuthFunc that takes the one password and counts the
// calls that reached it.
func authFor(good string, calls *int) AuthFunc {
	return func(_ context.Context, _ smtpd.Peer, _, pass string) error {
		*calls++
		if pass != good {
			return errWrongPassword
		}
		return nil
	}
}

func tcpPeer(ip string) smtpd.Peer {
	return smtpd.Peer{Addr: &net.TCPAddr{IP: net.ParseIP(ip)}}
}

// TestAuthRateLimitStopsTheGuesses verifies that an address runs out of
// tokens, and that the check underneath stops running for it.
func TestAuthRateLimitStopsTheGuesses(t *testing.T) {
	t.Parallel()

	var calls int
	fn := AuthRateLimit(authFor("right", &calls), 0.001, 2)
	peer := tcpPeer("10.0.0.1")

	for i := range 2 {
		if err := fn(context.Background(), peer, "user", "wrong"); !errors.Is(err, errWrongPassword) {
			t.Fatalf("attempt %d = %v, want the refusal of the check", i+1, err)
		}
	}

	err := fn(context.Background(), peer, "user", "wrong")
	var smtpErr smtpd.Error
	if !errors.As(err, &smtpErr) || smtpErr.Code != 454 {
		t.Fatalf("the attempt past the burst = %v, want a 454", err)
	}

	if calls != 2 {
		t.Fatalf("the check ran %d times, want 2", calls)
	}
}

// TestAuthRateLimitHoldsOneAddress verifies that the bucket belongs to the
// address, so one client never spends the tokens of another.
func TestAuthRateLimitHoldsOneAddress(t *testing.T) {
	t.Parallel()

	var calls int
	fn := AuthRateLimit(authFor("right", &calls), 0.001, 1)

	if err := fn(context.Background(), tcpPeer("10.0.0.1"), "user", "wrong"); !errors.Is(err, errWrongPassword) {
		t.Fatalf("the first address = %v, want the refusal of the check", err)
	}
	if err := fn(context.Background(), tcpPeer("10.0.0.1"), "user", "wrong"); errors.Is(err, errWrongPassword) {
		t.Fatal("the first address kept its tokens past the burst")
	}

	if err := fn(context.Background(), tcpPeer("10.0.0.2"), "user", "wrong"); !errors.Is(err, errWrongPassword) {
		t.Fatalf("the second address = %v, want the refusal of the check", err)
	}
}

// TestAuthRateLimitPassesSuccess verifies that a successful attempt takes no
// token. A client that knows its password is never limited, however often it
// authenticates.
func TestAuthRateLimitPassesSuccess(t *testing.T) {
	t.Parallel()

	var calls int
	fn := AuthRateLimit(authFor("right", &calls), 0.001, 2)
	peer := tcpPeer("10.0.0.1")

	for i := range 20 {
		if err := fn(context.Background(), peer, "user", "right"); err != nil {
			t.Fatalf("attempt %d with the good password = %v, want no error", i+1, err)
		}
	}

	if calls != 20 {
		t.Fatalf("the check ran %d times, want 20", calls)
	}
}

// TestAuthRateLimitKeepsFailuresAfterSuccess verifies that a successful
// attempt does not give back the tokens that earlier failures took. A client
// that holds one good credential would otherwise clear the count and go on
// guessing the rest.
func TestAuthRateLimitKeepsFailuresAfterSuccess(t *testing.T) {
	t.Parallel()

	var calls int
	fn := AuthRateLimit(authFor("right", &calls), 0.001, 3)
	peer := tcpPeer("10.0.0.1")

	// Two of the three tokens go to failures.
	for i := range 2 {
		if err := fn(context.Background(), peer, "user", "wrong"); !errors.Is(err, errWrongPassword) {
			t.Fatalf("attempt %d = %v, want the refusal of the check", i+1, err)
		}
	}

	// The third token is still there, so the good password gets through.
	if err := fn(context.Background(), peer, "user", "right"); err != nil {
		t.Fatalf("the good password = %v, want no error", err)
	}

	// A success that gave the bucket back would leave three tokens here. It
	// gave none back, so this failure takes the last one.
	if err := fn(context.Background(), peer, "user", "wrong"); !errors.Is(err, errWrongPassword) {
		t.Fatalf("the failure after the success = %v, want the refusal of the check", err)
	}

	err := fn(context.Background(), peer, "user", "wrong")
	var smtpErr smtpd.Error
	if !errors.As(err, &smtpErr) || smtpErr.Code != 454 {
		t.Fatalf("the attempt past the burst = %v, want a 454", err)
	}
}

// TestAuthRateLimitPassesNonTCP verifies that a peer without an IP is never
// limited, in the way that the other checks of this package read one.
func TestAuthRateLimitPassesNonTCP(t *testing.T) {
	t.Parallel()

	var calls int
	fn := AuthRateLimit(authFor("right", &calls), 0.001, 1)
	peer := smtpd.Peer{Addr: &net.UnixAddr{Name: "/tmp/smtpd.sock", Net: "unix"}}

	for i := range 5 {
		if err := fn(context.Background(), peer, "user", "wrong"); !errors.Is(err, errWrongPassword) {
			t.Fatalf("attempt %d = %v, want the refusal of the check", i+1, err)
		}
	}

	if calls != 5 {
		t.Fatalf("the check ran %d times, want 5", calls)
	}
}

// TestAuthRateLimitAdmitsOneAtATime fires many attempts at one address while
// the check underneath is held up. A bucket of one token must let one of them
// through: the check runs between the read of the bucket and the taking of
// the token, so attempts that overlap must not each read the same token.
func TestAuthRateLimitAdmitsOneAtATime(t *testing.T) {
	t.Parallel()

	const attempts = 50

	var (
		reached atomic.Int64
		entered = make(chan struct{}, attempts)
		release = make(chan struct{})
	)

	// The check holds every caller until the test releases them, so that all
	// the attempts that got in are inside it at the same time.
	fn := func(_ context.Context, _ smtpd.Peer, _, _ string) error {
		reached.Add(1)
		entered <- struct{}{}
		<-release
		return errWrongPassword
	}

	limited := AuthRateLimit(fn, 0.001, 1)
	peer := tcpPeer("10.0.0.1")

	var wg sync.WaitGroup
	for range attempts {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = limited(context.Background(), peer, "user", "wrong")
		}()
	}

	// Wait for the one attempt that the burst allows, then let the rest run
	// into the limit before the check returns.
	<-entered
	time.Sleep(100 * time.Millisecond)
	close(release)
	wg.Wait()

	if got := reached.Load(); got != 1 {
		t.Fatalf("the check ran %d times, want 1: a bucket of one token let %d guesses through", got, got)
	}
}
