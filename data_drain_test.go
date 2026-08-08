package smtpd

import (
	"bufio"
	"bytes"
	"context"
	"io"
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
		scanner:  bufio.NewScanner(reader),
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
