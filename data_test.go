package smtpd

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
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
	t.Parallel()

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
	t.Parallel()

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
	t.Parallel()

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
	t.Parallel()

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
	t.Parallel()

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
	t.Parallel()

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
	t.Parallel()

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
	t.Parallel()

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
		envelope: env,
		peer:     Peer{ServerName: "localhost"},
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
			for i := range 3 {
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
	t.Parallel()

	srv := &Server{MaxMessageSize: 1024}
	codes := runDATA(t, srv, nil, "")
	if len(codes) != 1 || codes[0] != 503 {
		t.Fatalf("codes = %v, want [503]", codes)
	}
}

func TestHandleDATASuccess(t *testing.T) {
	t.Parallel()

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
	t.Parallel()

	handler := &dataHandler{drain: true}
	srv := &Server{MaxMessageSize: 5, Handler: handler.handler()}
	env := &Envelope{Recipients: []string{"r@example.net"}}

	codes := runDATA(t, srv, env, "this body is definitely bigger than five bytes\r\n.\r\n")

	if len(codes) != 2 || codes[0] != 354 || codes[1] != 552 {
		t.Fatalf("codes = %v, want [354 552]", codes)
	}
}

func TestHandleDATAHandlerError(t *testing.T) {
	t.Parallel()

	handler := &dataHandler{drain: true, ret: Error{Code: 554, Message: "nope"}}
	srv := &Server{MaxMessageSize: 1024, Handler: handler.handler()}
	env := &Envelope{Recipients: []string{"r@example.net"}}

	codes := runDATA(t, srv, env, "body\r\n.\r\n")

	if len(codes) != 2 || codes[0] != 354 || codes[1] != 554 {
		t.Fatalf("codes = %v, want [354 554]", codes)
	}
}

// readDot reads the message at the start of stream through a dotReader, in
// reads of size octets. It gives the body, the part of the stream that the
// reader left, and the error that stopped the read. The error is nil for a
// message that came to its end.
func readDot(t *testing.T, stream []byte, size int) (body, rest []byte, err error) {
	t.Helper()

	br := bufio.NewReader(bytes.NewReader(stream))
	d := &dotReader{r: br}

	var got bytes.Buffer
	buf := make([]byte, size)
	for err == nil {
		var n int
		n, err = d.Read(buf)
		if n < 0 || n > len(buf) {
			t.Fatalf("Read gave n = %d for a buffer of %d", n, len(buf))
		}
		got.Write(buf[:n])
	}
	if errors.Is(err, io.EOF) {
		err = nil
	}

	rest, restErr := io.ReadAll(br)
	if restErr != nil {
		t.Fatalf("read the rest of the stream: %v", restErr)
	}

	return got.Bytes(), rest, err
}

// TestDotReader holds the framing of a DATA message: where the message ends,
// which dots go, and which octets stand for a line break.
func TestDotReader(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		stream string

		wantBody string
		wantRest string
		wantErr  error
	}{
		{
			name:     "one line",
			stream:   "hello\r\n.\r\n",
			wantBody: "hello\n",
		},
		{
			name:   "no line at all",
			stream: ".\r\n",
		},
		{
			name:     "the octets after the end stay on the stream",
			stream:   "a\r\n.\r\nQUIT\r\n",
			wantBody: "a\n",
			wantRest: "QUIT\r\n",
		},
		{
			name:     "a line that begins with a dot loses it",
			stream:   "..a\r\n.\r\n",
			wantBody: ".a\n",
		},
		{
			name:     "a line of two dots gives one",
			stream:   "..\r\n.\r\n",
			wantBody: ".\n",
		},
		{
			name:     "a dot inside a line stays",
			stream:   "a.b\r\n.\r\n",
			wantBody: "a.b\n",
		},
		{
			name:     "LF dot LF does not end the message",
			stream:   "a\n.\nb\r\n.\r\n",
			wantBody: "a\n.\nb\n",
		},
		{
			name:     "LF dot CRLF does not end the message",
			stream:   "a\n.\r\nb\r\n.\r\n",
			wantBody: "a\n.\nb\n",
		},
		{
			name:     "CRLF dot LF does not end the message, and the dot is an escape",
			stream:   "a\r\n.\nb\r\n.\r\n",
			wantBody: "a\n\nb\n",
		},
		{
			name:     "CR dot CR does not end the message",
			stream:   "a\r.\rb\r\n.\r\n",
			wantBody: "a\r.\rb\n",
		},
		{
			name:     "CRLF dot CR does not end the message, and the dot is an escape",
			stream:   "a\r\n.\rb\r\n.\r\n",
			wantBody: "a\n\rb\n",
		},
		{
			name:     "no line begins after a bare LF, so two dots stay",
			stream:   "a\n..b\r\n.\r\n",
			wantBody: "a\n..b\n",
		},
		{
			name:     "a CR before a line break stands alone",
			stream:   "a\r\r\n.\r\n",
			wantBody: "a\r\n",
		},
		{
			name:     "a CR after a dot at the start of a line stands alone",
			stream:   ".\r\r\n.\r\n",
			wantBody: "\r\n",
		},
		{
			name:     "a stream that stops after a line",
			stream:   "a\r\n",
			wantBody: "a\n",
			wantErr:  io.ErrUnexpectedEOF,
		},
		{
			name:     "a stream that stops inside the end of the message",
			stream:   "a\r\n.\r",
			wantBody: "a\n",
			wantErr:  io.ErrUnexpectedEOF,
		},
		{
			name:     "a stream that ends with LF dot LF",
			stream:   "a\n.\n",
			wantBody: "a\n.\n",
			wantErr:  io.ErrUnexpectedEOF,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// The size of a read decides where it falls in a sequence, and
			// the body must come out the same for each one.
			for _, size := range []int{1, 2, 64} {
				body, rest, err := readDot(t, []byte(tt.stream), size)

				if !errors.Is(err, tt.wantErr) {
					t.Errorf("reads of %d: err = %v, want %v", size, err, tt.wantErr)
				}
				if string(body) != tt.wantBody {
					t.Errorf("reads of %d: body = %q, want %q", size, body, tt.wantBody)
				}
				if string(rest) != tt.wantRest {
					t.Errorf("reads of %d: rest = %q, want %q", size, rest, tt.wantRest)
				}
			}
		})
	}
}

// decodeLines takes the framing off the lines of a DATA message in the plain
// way. It cuts them at each <CRLF>, takes one dot off the start of a line,
// and puts "\n" after the line. FuzzDotReader compares the reader with it.
func decodeLines(lines []byte) []byte {
	if len(lines) == 0 {
		return nil
	}

	var out []byte
	for line := range bytes.SplitSeq(bytes.TrimSuffix(lines, []byte("\r\n")), []byte("\r\n")) {
		line = bytes.TrimPrefix(line, []byte("."))
		out = append(out, line...)
		out = append(out, '\n')
	}
	return out
}

// FuzzDotReader holds the end of a DATA message in place:
//
//   - The message ends at the first <CRLF>.<CRLF> of the stream, and at no
//     other point. A stream that begins with .<CRLF> is such an end as well,
//     because the DATA command line stands before it.
//   - The reader leaves the octets after the end on the stream, where the
//     session reads them as commands.
//   - A stream without such an end never looks like a whole message.
func FuzzDotReader(f *testing.F) {
	f.Add([]byte("hello\r\n.\r\n"), uint8(64))
	f.Add([]byte(".\r\n"), uint8(0))
	f.Add([]byte("..a\r\n.\r\nQUIT\r\n"), uint8(1))
	f.Add([]byte("a\n.\nMAIL FROM:<a@example.org>\r\n.\r\n"), uint8(3))
	f.Add([]byte("a\n.\r\nMAIL FROM:<a@example.org>\r\n.\r\n"), uint8(3))
	f.Add([]byte("a\r\n.\nMAIL FROM:<a@example.org>\r\n.\r\n"), uint8(3))
	f.Add([]byte("a\r.\rb\r\r\n.\r\r\n.\r\n"), uint8(2))
	f.Add([]byte("a\r\n.\r"), uint8(7))

	f.Fuzz(func(t *testing.T, stream []byte, readSize uint8) {
		body, rest, err := readDot(t, stream, int(readSize)%64+1)

		// The DATA command line ends with a line break, so the first octet
		// of the stream is the first one of a line.
		end := bytes.Index(append([]byte("\r\n"), stream...), []byte("\r\n.\r\n"))

		if end < 0 {
			if !errors.Is(err, io.ErrUnexpectedEOF) {
				t.Fatalf("err = %v for a stream without an end, want %v", err, io.ErrUnexpectedEOF)
			}
			if len(rest) != 0 {
				t.Fatalf("the reader left %q of a stream without an end", rest)
			}
			return
		}

		if err != nil {
			t.Fatalf("err = %v for a stream that ends at octet %d", err, end)
		}

		// The line break in front moves each index by two, so end is the
		// place of the dot in stream. The lines stand before it, and the
		// session reads what stands after the dot and its line break.
		lines, after := stream[:end], stream[end+len(".\r\n"):]

		if !bytes.Equal(rest, after) {
			t.Fatalf("the reader left %q on the stream, want %q", rest, after)
		}
		if want := decodeLines(lines); !bytes.Equal(body, want) {
			t.Fatalf("body = %q, want %q", body, want)
		}
	})
}

// chunkReader hands out the body in the sizes it is given, so a fuzz target
// decides where the reads of dataReader fall.
type chunkReader struct {
	data   []byte
	chunks []byte

	pos  int
	next int
}

func (r *chunkReader) Read(p []byte) (int, error) {
	if r.pos >= len(r.data) {
		return 0, io.EOF
	}

	want := len(p)
	if len(r.chunks) > 0 {
		size := int(r.chunks[r.next%len(r.chunks)]) + 1
		r.next++
		want = min(want, size)
	}

	n := copy(p[:want], r.data[r.pos:])
	r.pos += n
	return n, nil
}

// FuzzDataReader holds the accounting of the DATA body:
//
//   - The handler never sees more than the limit.
//   - What the handler sees is the start of the message.
//   - The marks that handleDATA reads afterwards say what happened.
//
// The limit is at least one byte, as configureDefaults gives the server.
func FuzzDataReader(f *testing.F) {
	f.Add([]byte("hello world"), []byte{4}, uint16(1024), uint16(512))
	f.Add([]byte("hello world"), []byte{1}, uint16(5), uint16(1))
	f.Add(bytes.Repeat([]byte("a"), 300), []byte{7, 1, 64}, uint16(100), uint16(16))

	f.Fuzz(func(t *testing.T, body, chunks []byte, limit, readSize uint16) {
		max := int(limit)%4096 + 1
		buf := make([]byte, int(readSize)%64+1)

		d := &dataReader{r: &chunkReader{data: body, chunks: chunks}, max: max}

		var got bytes.Buffer
		for {
			n, err := d.Read(buf)
			if n < 0 || n > len(buf) {
				t.Fatalf("Read gave n = %d for a buffer of %d", n, len(buf))
			}
			got.Write(buf[:n])
			if err != nil {
				if !errors.Is(err, io.EOF) && !errors.Is(err, errMessageTooLarge) {
					t.Fatalf("Read: %v", err)
				}
				break
			}
		}

		if got.Len() > max {
			t.Fatalf("the handler saw %d bytes, over the limit of %d", got.Len(), max)
		}
		if !bytes.HasPrefix(body, got.Bytes()) {
			t.Fatalf("the handler saw %q, which is not the start of the body %q", got.Bytes(), body)
		}

		if err := d.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}

		if want := len(body) > max; d.tooBig != want {
			t.Fatalf("tooBig = %v for a body of %d and a limit of %d, want %v", d.tooBig, len(body), max, want)
		}
		if d.abandoned && len(body) <= 2*max {
			t.Fatalf("gave up on a body of %d bytes with a limit of %d, which ends inside the budget", len(body), max)
		}
	})
}
