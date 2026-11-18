package smtpd

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"math"
	"slices"
	"strings"
	"testing"
	"time"
)

// endlessReader never reaches the end of the message. It stands for a client
// that keeps sending after the server rejected the size.
type endlessReader struct{}

func (endlessReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 'a'
	}
	return len(p), nil
}

// TestDataReaderCloseStopsAtTheDrainLimit verifies that Close gives up on a
// message that does not end inside the budget, instead of reading whatever
// the client sends.
func TestDataReaderCloseStopsAtTheDrainLimit(t *testing.T) {
	t.Parallel()

	d := &dataReader{r: endlessReader{}, max: 10}

	if err := d.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if !d.tooBig {
		t.Error("expected tooBig after the drain")
	}
	if !d.abandoned {
		t.Error("expected abandoned when the message does not end in the budget")
	}
	if d.n > 20 {
		t.Errorf("read %d bytes, want at most twice the limit = 20", d.n)
	}
}

// TestDataReaderCloseFinishesInsideTheBudget verifies that a message which
// ends inside the budget is drained to the end, so the session can go on.
func TestDataReaderCloseFinishesInsideTheBudget(t *testing.T) {
	t.Parallel()

	// 15 bytes: over the limit of 10, inside twice the limit.
	d := &dataReader{r: strings.NewReader(strings.Repeat("a", 15)), max: 10}

	if err := d.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if !d.tooBig {
		t.Error("expected tooBig after the drain")
	}
	if d.abandoned {
		t.Error("did not expect abandoned for a message that ends in the budget")
	}
	if d.n != 15 {
		t.Errorf("read %d bytes, want the whole 15", d.n)
	}
}

// runDATAFrom wires handleDATA to r and returns the reply codes, and whether
// the session was closed.
func runDATAFrom(t *testing.T, srv *Server, env *Envelope, r io.Reader) ([]int, bool) {
	t.Helper()

	serverWrite := &bytes.Buffer{}
	reader := bufio.NewReader(r)
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

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("handleDATA did not return: the drain is not bounded")
	}

	return parseReplyCodes(t, serverWrite.Bytes()), s.closed
}

// TestHandleDATAOversizeClosesWhenTheClientKeepsSending verifies that a client
// which keeps sending after the size limit gets a 552 and loses the
// connection. Leaving the rest of the message on the wire is not an option:
// the session would read the body of the message as SMTP commands.
func TestHandleDATAOversizeClosesWhenTheClientKeepsSending(t *testing.T) {
	t.Parallel()

	handler := &dataHandler{drain: true}
	srv := &Server{MaxMessageSize: 64, Handler: handler.handler()}
	env := &Envelope{Recipients: []string{"r@example.net"}}

	codes, closed := runDATAFrom(t, srv, env, endlessReader{})

	if len(codes) != 2 || codes[0] != 354 || codes[1] != 552 {
		t.Fatalf("codes = %v, want [354 552]", codes)
	}
	if !closed {
		t.Error("expected the session to be closed")
	}
}

// TestHandleDATAOversizeKeepsTheSessionWhenTheMessageEnds verifies that a
// message which is over the limit but ends inside the budget still gets a 552
// and leaves the session open, as it did before.
func TestHandleDATAOversizeKeepsTheSessionWhenTheMessageEnds(t *testing.T) {
	t.Parallel()

	handler := &dataHandler{drain: true}
	srv := &Server{MaxMessageSize: 5, Handler: handler.handler()}
	env := &Envelope{Recipients: []string{"r@example.net"}}

	body := strings.Repeat("a", 20) + "\r\n.\r\n"
	codes, closed := runDATAFrom(t, srv, env, strings.NewReader(body))

	if len(codes) != 2 || codes[0] != 354 || codes[1] != 552 {
		t.Fatalf("codes = %v, want [354 552]", codes)
	}
	if closed {
		t.Error("did not expect the session to be closed for a message that ends")
	}
}

// errBlip is a read error that passes: the next read of the connection works.
var errBlip = errors.New("the connection failed once")

// blipConn is a scriptConn that fails one read at the offset at, and reads
// on after it.
type blipConn struct {
	scriptConn
	at      int
	read    int
	blipped bool
}

func (c *blipConn) Read(p []byte) (int, error) {
	if !c.blipped && c.read == c.at {
		c.blipped = true
		return 0, errBlip
	}
	if !c.blipped && c.read+len(p) > c.at {
		p = p[:c.at-c.read]
	}
	n, err := c.in.Read(p)
	c.read += n
	return n, err
}

// TestHandleDATAReadErrorEndsTheSession drives a DATA message whose read
// fails once in the middle of the body, and then works again. The session
// cannot know how much of the message is still on the wire, so it must take
// no line after the error as a command, and it closes without a reply. The rest of the body carries a RCPT
// TO line, and a session that read on would run it.
//
// The error can come while the handler reads, or while the session drains a
// message that is too large. A 552 there would reset the transaction and go
// on, so the read error decides first.
func TestHandleDATAReadErrorEndsTheSession(t *testing.T) {
	t.Parallel()

	head := "EHLO client.example\r\n" +
		"MAIL FROM:<sender@example.org>\r\n" +
		"RCPT TO:<recipient@example.net>\r\n" +
		"DATA\r\n" +
		"Subject: one\r\n"
	rest := "RCPT TO:<smuggled@example.net>\r\n" +
		"\r\n" +
		"A body.\r\n" +
		".\r\n" +
		"QUIT\r\n"

	readAll := func(ctx context.Context, _ Peer, env *Envelope) (context.Context, error) {
		_, err := io.ReadAll(env.Data)
		return ctx, err
	}

	tests := []struct {
		name    string
		max     int
		head    string
		handler Handler
	}{
		{
			name:    "while the handler reads",
			head:    head,
			handler: readAll,
		},
		{
			// The handler returns without reading. The drain reads past the
			// limit, and then it meets the error.
			name: "while the session drains a message that is too large",
			max:  40,
			head: head + strings.Repeat("x", 60) + "\r\n",
			handler: func(ctx context.Context, _ Peer, _ *Envelope) (context.Context, error) {
				return ctx, nil
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var recipients []string
			srv := &Server{
				MaxMessageSize: tc.max,
				Handler:        tc.handler,
			}
			srv.Use(Middleware{
				CheckRecipient: func(ctx context.Context, _ Peer, addr string) (context.Context, error) {
					recipients = append(recipients, addr)
					return ctx, nil
				},
			})
			if err := srv.configureDefaults(); err != nil {
				t.Fatalf("configureDefaults: %v", err)
			}

			conn := &blipConn{scriptConn: scriptConn{in: bytes.NewReader([]byte(tc.head + rest))}, at: len(tc.head)}
			ctx, session := srv.newSession(context.Background(), conn)

			done := make(chan struct{})
			go func() {
				defer close(done)
				session.serve(ctx)
			}()
			select {
			case <-done:
			case <-time.After(10 * time.Second):
				t.Fatal("the session did not end")
			}

			if want := []string{"recipient@example.net"}; !slices.Equal(recipients, want) {
				t.Errorf("CheckRecipient saw %q, want %q: the session read the body as commands", recipients, want)
			}

			// The session closes without a reply, as it does for a message
			// that times out. Nothing follows the 354.
			written := conn.out.String()
			if _, after, ok := strings.Cut(written, "354 "); !ok || strings.Count(after, "\r\n") != 1 {
				t.Errorf("the session wrote %q, want nothing after the 354", written)
			}
		})
	}
}

// blipReader gives its bytes and errBlip in one read, as a reader can when
// the connection fails in the middle of a read.
type blipReader struct {
	data []byte
	done bool
}

func (r *blipReader) Read(p []byte) (int, error) {
	if r.done {
		return 0, io.EOF
	}
	r.done = true
	return copy(p, r.data), errBlip
}

// TestDataReaderKeepsAReadErrorPastTheLimit covers a read that crosses the
// size limit and fails in the same call. The body gives the handler the error
// for the size, and it keeps the read error as well, so that the session
// still ends. Close then reads no more.
func TestDataReaderKeepsAReadErrorPastTheLimit(t *testing.T) {
	t.Parallel()

	d := &dataReader{r: &blipReader{data: bytes.Repeat([]byte("x"), 60)}, max: 40}

	n, err := d.Read(make([]byte, 100))
	if n != 40 || !errors.Is(err, errMessageTooLarge) {
		t.Fatalf("Read = %d, %v, want 40, %v", n, err, errMessageTooLarge)
	}
	if !errors.Is(d.readErr, errBlip) {
		t.Errorf("readErr = %v, want %v", d.readErr, errBlip)
	}
	if err := d.Close(); !errors.Is(err, errBlip) {
		t.Errorf("Close = %v, want %v", err, errBlip)
	}
}

// TestDataReaderCloseDrainsAtTheLargestMessageSize verifies that a
// MaxMessageSize of math.MaxInt still drains a message to its end. Twice
// that size wrapped to a negative limit, so Close read none of the rest, and
// the session read the lines of the message that the handler left as
// commands.
func TestDataReaderCloseDrainsAtTheLargestMessageSize(t *testing.T) {
	t.Parallel()

	r := bufio.NewReader(strings.NewReader("Subject: one\r\n\r\nRCPT TO:<smuggled@example.net>\r\n.\r\nQUIT\r\n"))
	d := &dataReader{r: &dotReader{r: r}, max: math.MaxInt}

	if err := d.Close(); err != nil {
		t.Fatalf("Close = %v, want nil", err)
	}

	rest, _ := io.ReadAll(r)
	if got, want := string(rest), "QUIT\r\n"; got != want {
		t.Errorf("after Close the stream holds %q, want %q", got, want)
	}
}

// TestDiscardChunkAtTheLargestMessageSize verifies that a MaxMessageSize of
// math.MaxInt takes a refused chunk off the wire. Twice that size wrapped to
// a negative number, and no chunk fit below it.
func TestDiscardChunkAtTheLargestMessageSize(t *testing.T) {
	t.Parallel()

	s := &session{
		server: &Server{MaxMessageSize: math.MaxInt},
		reader: bufio.NewReader(strings.NewReader("x")),
	}

	read, err := s.discardChunk(1)
	if !read || err != nil {
		t.Errorf("discardChunk(1) = %v, %v, want true, nil", read, err)
	}
}

// TestDrainLimit covers the number of octets that the server reads of input
// that it does not take: twice MaxMessageSize, and never past the largest
// int.
func TestDrainLimit(t *testing.T) {
	t.Parallel()

	tests := []struct {
		max  int
		want int
	}{
		{max: 10, want: 20},
		{max: math.MaxInt / 2, want: math.MaxInt - 1},
		{max: math.MaxInt/2 + 1, want: math.MaxInt},
		{max: math.MaxInt, want: math.MaxInt},
	}

	for _, tc := range tests {
		if got := drainLimit(tc.max); got != tc.want {
			t.Errorf("drainLimit(%d) = %d, want %d", tc.max, got, tc.want)
		}
	}
}
