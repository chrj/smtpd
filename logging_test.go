package smtpd_test

import (
	"context"
	"log/slog"
	"sync"
	"testing"

	"github.com/chrj/smtpd/v2"
	"github.com/chrj/smtpd/v2/smtptest"
)

// capturedRecord is a flattened log record: the message plus every attribute,
// including the ones accumulated through Logger.With.
type capturedRecord struct {
	message string
	attrs   []slog.Attr
}

// values returns every value logged under key, in the order they were added.
func (r capturedRecord) values(key string) []string {
	var values []string
	for _, a := range r.attrs {
		if a.Key == key {
			values = append(values, a.Value.String())
		}
	}
	return values
}

// recorder collects log records emitted through the handlers derived from it.
type recorder struct {
	mu      sync.Mutex
	records []capturedRecord
}

func (r *recorder) handler() slog.Handler {
	return &recordingHandler{recorder: r}
}

// find returns the first record logged with the given message.
func (r *recorder) find(message string) (capturedRecord, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()

	for _, rec := range r.records {
		if rec.message == message {
			return rec, true
		}
	}
	return capturedRecord{}, false
}

type recordingHandler struct {
	recorder *recorder
	attrs    []slog.Attr
}

func (h *recordingHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h *recordingHandler) Handle(_ context.Context, rec slog.Record) error {
	attrs := make([]slog.Attr, 0, len(h.attrs)+rec.NumAttrs())
	attrs = append(attrs, h.attrs...)
	rec.Attrs(func(a slog.Attr) bool {
		attrs = append(attrs, a)
		return true
	})

	h.recorder.mu.Lock()
	defer h.recorder.mu.Unlock()

	h.recorder.records = append(h.recorder.records, capturedRecord{message: rec.Message, attrs: attrs})
	return nil
}

func (h *recordingHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	merged := make([]slog.Attr, 0, len(h.attrs)+len(attrs))
	merged = append(merged, h.attrs...)
	merged = append(merged, attrs...)
	return &recordingHandler{recorder: h.recorder, attrs: merged}
}

func (h *recordingHandler) WithGroup(string) slog.Handler { return h }

// logHandler returns a Handler that logs the given message with the logger
// carried by the session context, so the test can inspect its attributes.
func logHandler(message string) smtpd.Handler {
	return func(ctx context.Context, _ smtpd.Peer, env *smtpd.Envelope) (context.Context, error) {
		defer func() { _ = env.Data.Close() }()
		smtpd.LoggerFromContext(ctx).InfoContext(ctx, message)
		return ctx, nil
	}
}

// TestPhaseLoggingReplacesPhase verifies that walking through the SMTP phases
// of a single session leaves exactly one phase attribute on the logger, naming
// the phase currently being executed.
func TestPhaseLoggingReplacesPhase(t *testing.T) {
	rec := &recorder{}

	srv := runsslserver(t, &smtpd.Server{
		Logger:  slog.New(rec.handler()),
		Handler: logHandler("delivered"),
	})

	err := smtptest.Send(srv.Dial(),
		"sender@example.org",
		[]string{"recipient@example.net"},
		"This is the email body\n",
	)
	if err != nil {
		t.Fatalf("send the message: %v", err)
	}

	delivered, ok := rec.find("delivered")
	if !ok {
		t.Fatal("handler log record not captured")
	}

	if got, want := delivered.values("phase"), []string{"data"}; !equal(got, want) {
		t.Errorf("phase attributes = %v, want %v", got, want)
	}
	if got, want := len(delivered.values("peer")), 1; got != want {
		t.Errorf("peer attribute count = %d, want %d", got, want)
	}
}

func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
