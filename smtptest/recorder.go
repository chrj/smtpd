package smtptest

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"slices"
	"sync"

	"github.com/chrj/smtpd/v2"
)

// Message is one message that a Recorder captured.
type Message struct {
	Sender     string
	Recipients []string
	Data       []byte

	// Peer is the state of the client at the moment of delivery. It carries
	// the HELO name, the user name after AUTH, and the TLS state.
	Peer smtpd.Peer
}

// Recorder is an smtpd.Handler that keeps the messages that it receives, so
// a test can read back what the client sent. The zero value is ready to use,
// and it is safe for concurrent sessions.
//
// Pass Recorder.Handler to one of the New functions of this package:
//
//	rec := &smtptest.Recorder{}
//	srv := smtptest.NewSTARTTLSServer(rec.Handler)
//	defer srv.Close()
type Recorder struct {
	mu       sync.Mutex
	messages []Message
}

// Handler records the envelope and accepts the message. It reads the body
// into memory and then replaces env.Data with an equal stream. A middleware
// stage or a delivery handler that runs after it reads the same bytes.
func (r *Recorder) Handler(ctx context.Context, peer smtpd.Peer, env *smtpd.Envelope) (context.Context, error) {
	data, err := io.ReadAll(env.Data)
	if err != nil {
		return ctx, fmt.Errorf("smtptest: read the message from %v: %w", peer.Addr, err)
	}

	if err := env.Data.Close(); err != nil {
		return ctx, fmt.Errorf("smtptest: close the message from %v: %w", peer.Addr, err)
	}

	env.Data = io.NopCloser(bytes.NewReader(data))

	r.mu.Lock()
	defer r.mu.Unlock()

	r.messages = append(r.messages, Message{
		Sender:     env.Sender,
		Recipients: slices.Clone(env.Recipients),
		Data:       data,
		Peer:       peer,
	})

	return ctx, nil
}

// Messages returns a copy of the messages in the order of delivery.
func (r *Recorder) Messages() []Message {
	r.mu.Lock()
	defer r.mu.Unlock()

	return slices.Clone(r.messages)
}

// Reset removes every message that the Recorder holds.
func (r *Recorder) Reset() {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.messages = nil
}
