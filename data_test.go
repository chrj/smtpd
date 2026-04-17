package smtpd

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"
)

// failingReader returns data, then a non-EOF error on the next Read.
type failingReader struct {
	data []byte
	err  error
	done bool
}

func (f *failingReader) Read(p []byte) (int, error) {
	if f.done {
		return 0, f.err
	}
	f.done = true
	n := copy(p, f.data)
	if n < len(f.data) {
		f.data = f.data[n:]
		f.done = false
		return n, nil
	}
	return n, nil
}

func TestDataReaderUnderLimit(t *testing.T) {
	d := &dataReader{r: strings.NewReader("hello world"), max: 1024}
	got, err := io.ReadAll(d)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if string(got) != "hello world" {
		t.Fatalf("body = %q, want %q", got, "hello world")
	}
	if d.tooBig {
		t.Fatal("tooBig set for under-limit body")
	}
	if err := d.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

func TestDataReaderAtLimit(t *testing.T) {
	body := strings.Repeat("a", 10)
	d := &dataReader{r: strings.NewReader(body), max: 10}
	got, err := io.ReadAll(d)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if string(got) != body {
		t.Fatalf("body = %q, want %q", got, body)
	}
	if d.tooBig {
		t.Fatal("tooBig set at exactly max")
	}
}

func TestDataReaderOverLimitTruncates(t *testing.T) {
	body := strings.Repeat("a", 20)
	d := &dataReader{r: strings.NewReader(body), max: 10}

	buf := make([]byte, 32)
	n, err := d.Read(buf)
	if !errors.Is(err, errMessageTooLarge) {
		t.Fatalf("Read err = %v, want errMessageTooLarge", err)
	}
	if n != 10 {
		t.Fatalf("Read returned %d bytes, want 10 (truncated to max)", n)
	}
	if !d.tooBig {
		t.Fatal("tooBig not set after overflow")
	}

	// Subsequent Read keeps returning errMessageTooLarge.
	n2, err2 := d.Read(buf)
	if n2 != 0 || !errors.Is(err2, errMessageTooLarge) {
		t.Fatalf("post-overflow Read = (%d, %v), want (0, errMessageTooLarge)", n2, err2)
	}
}

func TestDataReaderCloseDrainsOversize(t *testing.T) {
	// Handler reads just 5 bytes then bails; Close must keep draining so
	// we detect the oversize condition and re-sync the stream.
	body := strings.Repeat("a", 50)
	d := &dataReader{r: strings.NewReader(body), max: 10}

	buf := make([]byte, 5)
	if _, err := d.Read(buf); err != nil {
		t.Fatalf("initial Read: %v", err)
	}
	if d.tooBig {
		t.Fatal("tooBig set prematurely")
	}

	if err := d.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if !d.tooBig {
		t.Fatal("Close didn't detect oversize after drain")
	}
}

func TestDataReaderDoubleClose(t *testing.T) {
	d := &dataReader{r: strings.NewReader("x"), max: 10}
	if err := d.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := d.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	// Read after Close returns EOF.
	n, err := d.Read(make([]byte, 8))
	if n != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("Read after Close = (%d, %v), want (0, EOF)", n, err)
	}
}

func TestDataReaderPropagatesUnderlyingError(t *testing.T) {
	boom := errors.New("boom")
	d := &dataReader{
		r:   &failingReader{data: []byte("hi"), err: boom},
		max: 1024,
	}
	buf := make([]byte, 16)
	// First Read returns "hi", nil.
	if _, err := d.Read(buf); err != nil {
		t.Fatalf("first Read: %v", err)
	}
	// Second Read surfaces boom and stashes it in readErr.
	_, err := d.Read(buf)
	if !errors.Is(err, boom) {
		t.Fatalf("Read err = %v, want boom", err)
	}
	if !errors.Is(d.readErr, boom) {
		t.Fatalf("readErr = %v, want boom", d.readErr)
	}
}

func TestDataReaderCloseSurfacesReadError(t *testing.T) {
	boom := errors.New("network gone")
	d := &dataReader{
		r:   &failingReader{data: []byte("abc"), err: boom},
		max: 1024,
	}
	err := d.Close()
	if !errors.Is(err, boom) {
		t.Fatalf("Close err = %v, want boom", err)
	}
	if !errors.Is(d.readErr, boom) {
		t.Fatalf("readErr = %v, want boom", d.readErr)
	}
}

func TestDataReaderOverflowWithinSingleRead(t *testing.T) {
	// Single Read that returns more than `max` in one call. Verify that
	// the returned count is clamped to max (caller never sees past max).
	body := bytes.Repeat([]byte("x"), 100)
	d := &dataReader{r: bytes.NewReader(body), max: 8}
	buf := make([]byte, 64)
	n, err := d.Read(buf)
	if !errors.Is(err, errMessageTooLarge) {
		t.Fatalf("err = %v, want errMessageTooLarge", err)
	}
	if n != 8 {
		t.Fatalf("n = %d, want 8", n)
	}
	if d.n != 8 {
		t.Fatalf("d.n = %d, want 8", d.n)
	}
}

// dataHandler lets handleDATA tests observe the delivered envelope and
// optionally inject a handler error.
type dataHandler struct {
	got    []byte
	gotErr error
	ret    error
	drain  bool // if true, read env.Data fully
}

func (h *dataHandler) handler() Handler {
	return func(ctx context.Context, _ Peer, env *Envelope) (context.Context, error) {
		if h.drain {
			h.got, h.gotErr = io.ReadAll(env.Data)
		}
		_ = env.Data.Close()
		return ctx, h.ret
	}
}

// runDATA wires handleDATA to an in-memory duplex pipe and returns the SMTP
// reply codes the server wrote, in order. The caller supplies the envelope
// state and the raw DATA payload (must end with <CRLF>.<CRLF>).
func runDATA(t *testing.T, srv *Server, env *Envelope, payload string) []int {
	t.Helper()

	clientRead, clientWrite := io.Pipe()
	serverWrite := &bytes.Buffer{} // replies - safe without locking; single writer, read after join.

	reader := bufio.NewReader(clientRead)
	s := &session{
		server:   srv,
		conn:     fakeConn{},
		reader:   reader,
		writer:   bufio.NewWriter(serverWrite),
		scanner:  bufio.NewScanner(reader),
		envelope: env,
		peer:     Peer{ServerName: "localhost"},
		log:      slog.New(slog.DiscardHandler),
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		s.handleDATA(context.Background(), &command{})
		_ = s.writer.Flush()
	}()

	if payload != "" {
		if _, err := io.WriteString(clientWrite, payload); err != nil {
			t.Fatalf("write payload: %v", err)
		}
	}
	_ = clientWrite.Close()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("handleDATA didn't return")
	}

	return parseReplyCodes(t, serverWrite.Bytes())
}

func parseReplyCodes(t *testing.T, buf []byte) []int {
	t.Helper()
	var codes []int
	br := bufio.NewReader(bytes.NewReader(buf))
	for {
		line, err := br.ReadString('\n')
		if len(line) >= 3 {
			code := 0
			ok := true
			for i := 0; i < 3; i++ {
				if line[i] < '0' || line[i] > '9' {
					ok = false
					break
				}
				code = code*10 + int(line[i]-'0')
			}
			if ok {
				codes = append(codes, code)
			}
		}
		if err != nil {
			return codes
		}
	}
}

// fakeConn is the minimum net.Conn surface handleDATA touches - only
// SetDeadline is actually called, and it's a no-op here.
type fakeConn struct{}

func (fakeConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (fakeConn) Write(p []byte) (int, error)      { return len(p), nil }
func (fakeConn) Close() error                     { return nil }
func (fakeConn) LocalAddr() net.Addr              { return &net.TCPAddr{IP: net.IPv4zero} }
func (fakeConn) RemoteAddr() net.Addr             { return &net.TCPAddr{IP: net.IPv4zero} }
func (fakeConn) SetDeadline(time.Time) error      { return nil }
func (fakeConn) SetReadDeadline(time.Time) error  { return nil }
func (fakeConn) SetWriteDeadline(time.Time) error { return nil }

var _ net.Conn = fakeConn{}

func TestHandleDATAMissingRCPT(t *testing.T) {
	srv := &Server{MaxMessageSize: 1024}
	codes := runDATA(t, srv, nil, "")
	if len(codes) != 1 || codes[0] != 502 {
		t.Fatalf("codes = %v, want [502]", codes)
	}
}

func TestHandleDATASuccess(t *testing.T) {
	handler := &dataHandler{drain: true}
	srv := &Server{MaxMessageSize: 1024, Handler: handler.handler()}
	env := &Envelope{Sender: "s@example.org", Recipients: []string{"r@example.net"}}

	codes := runDATA(t, srv, env, "hello world\r\n.\r\n")

	if len(codes) != 2 || codes[0] != 354 || codes[1] != 250 {
		t.Fatalf("codes = %v, want [354 250]", codes)
	}
	if string(handler.got) != "hello world\n" {
		t.Fatalf("handler body = %q, want %q", handler.got, "hello world\n")
	}
}

func TestHandleDATAOversize(t *testing.T) {
	handler := &dataHandler{drain: true}
	srv := &Server{MaxMessageSize: 5, Handler: handler.handler()}
	env := &Envelope{Recipients: []string{"r@example.net"}}

	codes := runDATA(t, srv, env, "this body is definitely bigger than five bytes\r\n.\r\n")

	if len(codes) != 2 || codes[0] != 354 || codes[1] != 552 {
		t.Fatalf("codes = %v, want [354 552]", codes)
	}
}

func TestHandleDATAHandlerError(t *testing.T) {
	handler := &dataHandler{drain: true, ret: Error{Code: 554, Message: "nope"}}
	srv := &Server{MaxMessageSize: 1024, Handler: handler.handler()}
	env := &Envelope{Recipients: []string{"r@example.net"}}

	codes := runDATA(t, srv, env, "body\r\n.\r\n")

	if len(codes) != 2 || codes[0] != 354 || codes[1] != 554 {
		t.Fatalf("codes = %v, want [354 554]", codes)
	}
}
