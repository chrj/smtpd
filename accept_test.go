package smtpd_test

import (
	"errors"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
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

// flakyListener fails the first failures calls to Accept with err, then
// blocks until Close.
type flakyListener struct {
	err       error
	remaining atomic.Int32
	accepts   atomic.Int32
	closed    chan struct{}
	once      sync.Once
}

func newFlakyListener(failures int32, err error) *flakyListener {
	l := &flakyListener{err: err, closed: make(chan struct{})}
	l.remaining.Store(failures)

	return l
}

func (l *flakyListener) Accept() (net.Conn, error) {
	l.accepts.Add(1)
	if l.remaining.Add(-1) >= 0 {
		return nil, l.err
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

// acceptErrno is the error that a TCP listener gives for an errno of
// accept(2), such as EMFILE when the process holds its limit of open files.
func acceptErrno(errno syscall.Errno) error {
	return &net.OpError{Op: "accept", Net: "tcp", Err: os.NewSyscallError("accept", errno)}
}

// TestAcceptRetryBackoff verifies that an error from Accept that passes does
// not stop the server. Serve waits 5ms, then twice as long after each failure
// up to one second, and accepts again.
//
// The test sleeps in its own goroutine, and not in synctest.Wait. Wait returns
// as soon as the other goroutines block, and it does not move the clock, so
// the server would stay in its first backoff.
func TestAcceptRetryBackoff(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		err  error
	}{
		{name: "a timeout", err: acceptTimeoutErr{}},
		{name: "EMFILE", err: acceptErrno(syscall.EMFILE)},
		{name: "ENFILE", err: acceptErrno(syscall.ENFILE)},
		{name: "ENOBUFS", err: acceptErrno(syscall.ENOBUFS)},
		{name: "ENOMEM", err: acceptErrno(syscall.ENOMEM)},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			synctest.Test(t, func(t *testing.T) {
				// The pauses are 5, 10, 20, 40, 80, 160, 320 and 640ms, and
				// then one second each, so the calls to Accept come at these
				// times. Every call but the last one fails.
				ms := time.Millisecond
				calls := []time.Duration{
					0, 5 * ms, 15 * ms, 35 * ms, 75 * ms, 155 * ms,
					315 * ms, 635 * ms, 1275 * ms, 2275 * ms, 3275 * ms,
				}

				l := newFlakyListener(int32(len(calls)-1), tc.err)
				srv := &smtpd.Server{Logger: testLogger(t)}

				served := make(chan error, 1)
				go func() { served <- srv.Serve(l) }()

				// stop closes the listener and waits for Serve. A test that
				// fails ends early, and Serve must still return before the
				// bubble ends.
				stop := sync.OnceValue(func() error {
					_ = l.Close()
					return <-served
				})
				defer func() { _ = stop() }()

				// Halfway between two calls, the count holds the calls so far.
				start := time.Now()
				for i := range calls[1:] {
					time.Sleep(time.Until(start.Add(calls[i] + (calls[i+1]-calls[i])/2)))
					synctest.Wait()

					if got, want := l.accepts.Load(), int32(i+1); got != want {
						t.Fatalf("Accept calls after %v = %d, want %d", time.Since(start), got, want)
					}
				}

				// The last failure is spent, so the last call blocks until Close.
				time.Sleep(time.Until(start.Add(calls[len(calls)-1] + time.Second)))
				synctest.Wait()

				if got, want := l.accepts.Load(), int32(len(calls)); got != want {
					t.Errorf("Accept calls at the end = %d, want %d", got, want)
				}

				if err := stop(); !errors.Is(err, net.ErrClosed) {
					t.Errorf("Serve = %v, want %v", err, net.ErrClosed)
				}
			})
		})
	}
}

// scriptedListener answers each call to Accept from a script: an error, or a
// connection where the script holds nil. Past the end of the script, Accept
// blocks until Close.
type scriptedListener struct {
	script  []error
	accepts atomic.Int32
	closed  chan struct{}
	once    sync.Once
}

func (l *scriptedListener) Accept() (net.Conn, error) {
	n := int(l.accepts.Add(1))
	if n > len(l.script) {
		<-l.closed
		return nil, net.ErrClosed
	}
	if err := l.script[n-1]; err != nil {
		return nil, err
	}

	// The client closes its end at once, so the session ends at its first
	// write.
	server, client := net.Pipe()
	_ = client.Close()
	return server, nil
}

func (l *scriptedListener) Close() error {
	l.once.Do(func() { close(l.closed) })
	return nil
}

func (l *scriptedListener) Addr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 25}
}

// TestAcceptPauseStartsOverAfterAConnection verifies that a call to Accept
// that works sets the pause back to its start. A server that kept the pause of
// an earlier run of errors would wait up to one second at the next one.
func TestAcceptPauseStartsOverAfterAConnection(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		emfile := acceptErrno(syscall.EMFILE)

		// The calls come at 0, 5, 15 and 35ms, and the one at 35ms gives a
		// connection. The next error then waits 5ms again, so the last call
		// comes at 40ms. With the pause of the run before, it would come at
		// 75ms.
		l := &scriptedListener{
			script: []error{emfile, emfile, emfile, nil, emfile},
			closed: make(chan struct{}),
		}
		srv := &smtpd.Server{Logger: testLogger(t)}

		served := make(chan error, 1)
		go func() { served <- srv.Serve(l) }()

		stop := sync.OnceValue(func() error {
			_ = l.Close()
			return <-served
		})
		defer func() { _ = stop() }()

		start := time.Now()
		time.Sleep(time.Until(start.Add(38 * time.Millisecond)))
		synctest.Wait()
		if got, want := l.accepts.Load(), int32(5); got != want {
			t.Fatalf("Accept calls after 38ms = %d, want %d", got, want)
		}

		time.Sleep(time.Until(start.Add(42 * time.Millisecond)))
		synctest.Wait()
		if got, want := l.accepts.Load(), int32(6); got != want {
			t.Fatalf("Accept calls after 42ms = %d, want %d", got, want)
		}

		if err := stop(); !errors.Is(err, net.ErrClosed) {
			t.Errorf("Serve = %v, want %v", err, net.ErrClosed)
		}
	})
}

// TestAcceptReturnsAnotherError verifies that an error from Accept that does
// not pass stops Serve, which returns it. A listener that gives EBADF, or an
// error of its own, gives it again on every call.
func TestAcceptReturnsAnotherError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		err  error
	}{
		{name: "EBADF", err: acceptErrno(syscall.EBADF)},
		{name: "an error of the listener", err: errors.New("the listener broke")},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			synctest.Test(t, func(t *testing.T) {
				l := newFlakyListener(1, tc.err)
				srv := &smtpd.Server{Logger: testLogger(t)}

				if err := srv.Serve(l); !errors.Is(err, tc.err) {
					t.Errorf("Serve = %v, want %v", err, tc.err)
				}
				if got := l.accepts.Load(); got != 1 {
					t.Errorf("Accept calls = %d, want 1", got)
				}
			})
		})
	}
}
