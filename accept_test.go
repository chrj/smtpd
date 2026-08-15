package smtpd_test

import (
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/chrj/smtpd/v2"
)

// acceptTimeoutErr is a net.Error that reports a timeout, which is what Serve
// waits out before it calls Accept again.
type acceptTimeoutErr struct{}

func (acceptTimeoutErr) Error() string   { return "accept: temporary failure" }
func (acceptTimeoutErr) Timeout() bool   { return true }
func (acceptTimeoutErr) Temporary() bool { return true }

// flakyListener fails the first failures calls to Accept with a timeout, then
// blocks until Close.
type flakyListener struct {
	remaining atomic.Int32
	accepts   atomic.Int32
	closed    chan struct{}
	once      sync.Once
}

func newFlakyListener(failures int32) *flakyListener {
	l := &flakyListener{closed: make(chan struct{})}
	l.remaining.Store(failures)

	return l
}

func (l *flakyListener) Accept() (net.Conn, error) {
	l.accepts.Add(1)
	if l.remaining.Add(-1) >= 0 {
		return nil, acceptTimeoutErr{}
	}

	<-l.closed
	return nil, net.ErrClosed
}

func (l *flakyListener) Close() error {
	l.once.Do(func() { close(l.closed) })
	return nil
}

func (l *flakyListener) Addr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 25}
}

// TestAcceptRetryBackoff verifies that a timeout from Accept does not stop the
// server. Serve waits one second and accepts again.
//
// The test sleeps in its own goroutine, and not in synctest.Wait. Wait returns
// as soon as the other goroutines block, and it does not move the clock, so
// the server would stay in its first backoff.
func TestAcceptRetryBackoff(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		const failures = 3

		l := newFlakyListener(failures)
		srv := &smtpd.Server{Logger: testLogger(t)}

		served := make(chan error, 1)
		go func() { served <- srv.Serve(l) }()

		// The backoff is one second, so the server calls Accept at 0s, 1s and
		// 2s. The call at 3s is still in the future.
		time.Sleep(2*time.Second + 500*time.Millisecond)
		synctest.Wait()

		if got, want := l.accepts.Load(), int32(3); got != want {
			t.Errorf("Accept calls after 2.5s = %d, want %d", got, want)
		}

		// The last failure is spent, so the call at 3s blocks until Close.
		time.Sleep(time.Second)
		synctest.Wait()

		if got, want := l.accepts.Load(), int32(failures+1); got != want {
			t.Errorf("Accept calls after 3.5s = %d, want %d", got, want)
		}

		_ = l.Close()

		if err := <-served; err == nil {
			t.Error("Serve returned nil, want the error of the listener")
		}
	})
}
