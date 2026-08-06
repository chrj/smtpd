package smtptest_test

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/chrj/smtpd/v2"
	"github.com/chrj/smtpd/v2/smtptest"
)

// errReader fails on the first read. It stands for a client that broke the
// connection in the middle of DATA.
type errReader struct{ err error }

func (r errReader) Read([]byte) (int, error) { return 0, r.err }
func (r errReader) Close() error             { return nil }

func TestRecorderHandler(t *testing.T) {
	rec := &smtptest.Recorder{}

	recipients := []string{"one@example.net", "two@example.net"}
	env := &smtpd.Envelope{
		Sender:     "sender@example.org",
		Recipients: recipients,
		Data:       io.NopCloser(strings.NewReader("the body")),
	}
	peer := smtpd.Peer{HeloName: "client.example.org", Username: "joe"}

	if _, err := rec.Handler(context.Background(), peer, env); err != nil {
		t.Fatalf("Handler: %v", err)
	}

	messages := rec.Messages()
	if len(messages) != 1 {
		t.Fatalf("recorded %d messages, want 1", len(messages))
	}

	got := messages[0]
	if got.Sender != "sender@example.org" {
		t.Errorf("Sender: got %q, want %q", got.Sender, "sender@example.org")
	}
	if string(got.Data) != "the body" {
		t.Errorf("Data: got %q, want %q", string(got.Data), "the body")
	}
	if got.Peer.Username != "joe" {
		t.Errorf("Username: got %q, want %q", got.Peer.Username, "joe")
	}

	// The handler that runs after the Recorder reads the same bytes.
	rest, err := io.ReadAll(env.Data)
	if err != nil {
		t.Fatalf("read the restored body: %v", err)
	}
	if string(rest) != "the body" {
		t.Errorf("restored body: got %q, want %q", string(rest), "the body")
	}

	// A later change of the envelope does not reach the record.
	recipients[0] = "changed@example.net"
	if got.Recipients[0] != "one@example.net" {
		t.Errorf("Recipients[0]: got %q, want %q", got.Recipients[0], "one@example.net")
	}
}

func TestRecorderHandlerReadError(t *testing.T) {
	rec := &smtptest.Recorder{}
	want := errors.New("connection reset")

	env := &smtpd.Envelope{
		Sender: "sender@example.org",
		Data:   errReader{err: want},
	}

	_, err := rec.Handler(context.Background(), smtpd.Peer{}, env)
	if !errors.Is(err, want) {
		t.Errorf("Handler error: got %v, want %v", err, want)
	}
	if got := rec.Messages(); len(got) != 0 {
		t.Errorf("recorded %d messages after a read error, want 0", len(got))
	}
}

func TestRecorderReset(t *testing.T) {
	rec := &smtptest.Recorder{}
	env := &smtpd.Envelope{Data: io.NopCloser(strings.NewReader(""))}

	if _, err := rec.Handler(context.Background(), smtpd.Peer{}, env); err != nil {
		t.Fatalf("Handler: %v", err)
	}
	if got := len(rec.Messages()); got != 1 {
		t.Fatalf("recorded %d messages, want 1", got)
	}

	rec.Reset()

	if got := len(rec.Messages()); got != 0 {
		t.Errorf("recorded %d messages after Reset, want 0", got)
	}
}

// TestRecorderAsMiddleware makes sure that a delivery handler after the
// Recorder reads the full message body.
func TestRecorderAsMiddleware(t *testing.T) {
	rec := &smtptest.Recorder{}
	delivered := make(chan string, 1)

	srv := smtptest.NewUnstartedServer(
		func(ctx context.Context, _ smtpd.Peer, env *smtpd.Envelope) (context.Context, error) {
			data, err := io.ReadAll(env.Data)
			if err != nil {
				return ctx, err
			}
			delivered <- string(data)
			return ctx, env.Data.Close()
		},
	)
	srv.Config.Use(smtpd.Middleware{Handler: rec.Handler})
	srv.Start()
	defer srv.Close()

	deliver(t, srv.Dial())

	want := "Subject: test\n\nThis is the email body\n"
	if got := <-delivered; got != want {
		t.Errorf("body at the delivery handler: got %q, want %q", got, want)
	}
	if got := rec.Messages(); len(got) != 1 || string(got[0].Data) != want {
		t.Errorf("recorded messages: got %d, want 1 with the same body", len(got))
	}
}
