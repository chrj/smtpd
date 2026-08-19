package smtpd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"runtime/debug"
	"time"
)

// errChunkAborted is what the handler reads in the place of the rest of the
// message when a transfer ends before BDAT LAST. RSET does that, and so does
// a connection that closes in the middle of a message.
var errChunkAborted = errors.New("smtpd: the chunked transfer ended before the last chunk")

// deliverResult carries what the handler of a chunked message gave back. The
// context replaces the one of the session, in the same way as it does for a
// message that arrives through DATA.
type deliverResult struct {
	ctx context.Context
	err error
}

// chunkTransfer holds the state of one BDAT transfer.
//
// The handler runs on a goroutine of its own and reads the chunks through a
// pipe as they arrive, so a message that arrives in chunks streams in the
// same way as a message that arrives through DATA. The session writes each
// chunk into the pipe and closes it at BDAT LAST.
//
// The transfer exists from the first BDAT command of a transaction. The
// goroutine starts with the first chunk that the server takes, so a chunk
// that the server refuses starts nothing.
type chunkTransfer struct {
	pw     *io.PipeWriter
	done   chan deliverResult
	exited chan struct{}

	// received counts the octets of the message so far.
	received int64

	// buf carries the octets from the connection into the pipe. It stays
	// with the transfer, so that a message of many chunks takes one buffer
	// and not one for every chunk.
	buf []byte

	// failure is the answer that every chunk after a refusal gets. RFC 3030
	// asks the server to take the chunks that the client already sent and to
	// answer each one of them.
	failure error

	// result holds what the handler gave back, once it arrived. The handler
	// can return before the last chunk, and the client hears about it at the
	// next command.
	result *deliverResult
}

// copyBuf gives the buffer that carries the octets of a chunk into the pipe.
func (t *chunkTransfer) copyBuf() []byte {
	if t.buf == nil {
		t.buf = make([]byte, 32*1024)
	}
	return t.buf
}

// started reports whether the handler is running.
func (t *chunkTransfer) started() bool {
	return t != nil && t.pw != nil
}

// poll asks for the result of the handler without waiting for it.
func (t *chunkTransfer) poll() (deliverResult, bool) {
	if t.result != nil {
		return *t.result, true
	}

	select {
	case result := <-t.done:
		t.result = &result
		return result, true
	default:
		return deliverResult{}, false
	}
}

// wait asks for the result of the handler and waits for it. The caller closes
// the write end of the pipe first, which is what makes the handler read the
// end of the message.
func (t *chunkTransfer) wait() deliverResult {
	if t.result != nil {
		return *t.result
	}

	result := <-t.done
	t.result = &result
	return result
}

// chunkBody hands the chunks of a message to the handler. Close does
// nothing: the session owns the pipe, and it closes the write end at the last
// chunk. A handler that closes the body early would otherwise take the rest
// of the message away from the session, which still has to read it off the
// wire.
type chunkBody struct {
	r *io.PipeReader
}

func (c *chunkBody) Read(p []byte) (int, error) { return c.r.Read(p) }
func (c *chunkBody) Close() error               { return nil }

// startChunk puts the handler on a goroutine of its own and gives it the read
// end of the pipe as the body of the message.
//
// The goroutine always ends: the drain that follows the handler reads until
// the session closes the write end of the pipe, which finishChunk and
// stopChunk both do.
func (s *session) startChunk(ctx context.Context) {
	pr, pw := io.Pipe()

	t := s.chunk
	t.pw = pw
	t.done = make(chan deliverResult, 1)
	t.exited = make(chan struct{})

	s.envelope.Data = &chunkBody{r: pr}

	// The peer of the session is a snapshot, because a command that arrives
	// while the handler runs can write to the one of the session.
	peer := s.peer
	env := s.envelope

	go func() {
		defer close(t.exited)

		defer func() {
			if v := recover(); v != nil {
				// The session turns this into the 421 that a panic in a DATA
				// handler gives, and into the error that the Disconnect
				// hooks read.
				t.done <- deliverResult{ctx: ctx, err: PanicError{Value: v, Stack: debug.Stack()}}
			}

			// Read what the handler left, so that the session can write the
			// chunks that follow. The server drains the body of a DATA
			// message in the same way.
			_, _ = io.Copy(io.Discard, pr)
			_ = pr.Close()
		}()

		dctx, err := s.server.deliver(ctx, peer, env)
		t.done <- deliverResult{ctx: dctx, err: err}
	}()
}

// finishChunk closes the message at BDAT LAST and waits for the handler. It
// gives the context of the handler, the length of the message and the error
// that the handler gave back.
func (s *session) finishChunk(ctx context.Context) (context.Context, int64, error) {
	t := s.chunk
	s.chunk = nil

	_ = t.pw.Close()
	result := t.wait()
	<-t.exited

	if result.ctx != nil {
		ctx = result.ctx
	}

	return ctx, t.received, result.err
}

// end stops the handler and gives back what it left. The handler reads cause
// in the place of the rest of the message, so a message that is not whole
// never looks complete to it.
//
// The goroutine writes one result before it ends, so a handler that returned
// after the last poll is still here to answer for. A panic that nothing reads
// would leave no trace at all.
func (t *chunkTransfer) end(cause error) *deliverResult {
	if !t.started() {
		return nil
	}

	_ = t.pw.CloseWithError(cause)
	<-t.exited
	t.pw = nil

	if result, ok := t.poll(); ok {
		return &result
	}

	return nil
}

// abort ends the handler of a transfer that will not finish and keeps the
// cause on the transfer, so that every chunk that follows gets the same
// answer.
func (t *chunkTransfer) abort(cause error) *deliverResult {
	t.failure = cause
	return t.end(cause)
}

// stopChunk ends a transfer that did not reach BDAT LAST and drops it.
//
// It waits for the goroutine of the handler, so that no handler of a message
// that the client gave up on runs into the session that follows.
func (s *session) stopChunk(cause error) *deliverResult {
	t := s.chunk
	s.chunk = nil

	if t == nil {
		return nil
	}

	return t.end(cause)
}

// handleBDAT runs the BDAT command of RFC 3030. The octets of the chunk
// follow the command line on the same stream, so every path here takes the
// whole chunk off the wire before it writes a reply. A reply that leaves the
// octets there makes the server read the message as commands.
func (s *session) handleBDAT(ctx context.Context, cmd *command) context.Context {
	ctx, _ = phasedLoggerFromContext(ctx, "bdat")

	size, last, sized, err := cmd.bdatArg()
	if err != nil && !sized {
		// The length of the chunk is the only thing that says where it ends.
		// Without it, nothing that follows can be read as a command.
		ctx = s.replyEnhanced(ctx, 501, EnhancedCode{5, 5, 4}, "Invalid BDAT syntax.")
		return s.close(ctx)
	}

	// A chunk arrives at the speed of a message, not of a command.
	_ = s.conn.SetDeadline(time.Now().Add(s.server.DataTimeout))

	if err != nil {
		// The length reads, so the chunk comes off the wire and the session
		// goes on. The transaction does not: a command that the server
		// cannot read leaves the message in a state it cannot trust.
		return s.refuseChunk(ctx, size, false, Error{
			Code:     501,
			Enhanced: EnhancedCode{5, 5, 4},
			Message:  "Invalid BDAT syntax.",
		})
	}

	if s.envelope == nil || len(s.envelope.Recipients) == 0 {
		return s.refuseChunk(ctx, size, last, Error{
			Code:     503,
			Enhanced: EnhancedCode{5, 5, 1},
			Message:  "Missing RCPT TO command.",
		})
	}

	if s.chunk == nil {
		s.chunk = &chunkTransfer{}
	}

	if refusal := s.chunkRefusal(size); refusal != nil {
		return s.refuseChunk(ctx, size, last, refusal)
	}

	if !s.chunk.started() {
		s.startChunk(ctx)
	}

	n, err := io.CopyBuffer(s.chunk.pw, io.LimitReader(s.reader, size), s.chunk.copyBuf())
	if err == nil && n != size {
		// A reader that stops early gives no error of its own, and a chunk
		// that is not whole is not a chunk.
		err = io.ErrUnexpectedEOF
	}
	if err != nil {
		// The session cannot know how much of the chunk it read, so the line
		// that follows is not a command.
		s.setErr(err)
		s.stopChunk(err)
		ctx = s.replyEnhanced(ctx, 451, EnhancedCode{4, 3, 0}, "The chunk could not be read")
		return s.close(ctx)
	}

	s.chunk.received += size

	if !last {
		// A handler that returned before the last chunk has an answer that
		// the client needs now. The chunks that follow get the same one.
		if result, ok := s.chunk.poll(); ok && result.err != nil {
			if result.ctx != nil {
				ctx = result.ctx
			}
			s.chunk.failure = result.err
			return s.replyChunkError(ctx, result.err)
		}

		return s.reply(ctx, 250, fmt.Sprintf("%d octets received", size))
	}

	ctx, received, err := s.finishChunk(ctx)
	if err != nil {
		ctx = s.replyChunkError(ctx, err)
		if s.closed {
			// A panic in the handler ended the session, and there is no
			// transaction left to reset.
			return ctx
		}
		return s.reset(ctx)
	}

	return s.reset(s.reply(ctx, 250, fmt.Sprintf("Message OK, %d octets received", received)))
}

// chunkRefusal gives the answer for a chunk that the server does not take, or
// nil for a chunk that it takes.
func (s *session) chunkRefusal(size int64) error {
	if s.chunk.failure != nil {
		return s.chunk.failure
	}

	if size > int64(s.server.MaxMessageSize)-s.chunk.received {
		return Error{
			Code:     552,
			Enhanced: EnhancedCode{5, 3, 4},
			Message:  fmt.Sprintf("Message exceeded max message size of %d bytes", s.server.MaxMessageSize),
		}
	}

	return nil
}

// refuseChunk takes the octets of a chunk off the wire and answers the
// command with refusal.
func (s *session) refuseChunk(ctx context.Context, size int64, last bool, refusal error) context.Context {
	if s.chunk != nil {
		if ctx, done := s.reportChunkPanic(ctx, s.chunk.abort(refusal)); done {
			return ctx
		}
	}

	read, err := s.discardChunk(size)
	if err != nil {
		// The connection is gone, and the read loop sees the same error.
		s.setErr(err)
		return ctx
	}

	ctx = s.replyError(ctx, refusal)

	if !read {
		return s.close(ctx)
	}

	if last {
		return s.reset(ctx)
	}

	return ctx
}

// discardChunk reads the octets of a chunk that the server does not take, and
// throws them away.
//
// read is false for a chunk that is longer than twice the largest message
// that the server takes. Reading that costs without bound, so the caller
// closes the session in the place of reading it.
func (s *session) discardChunk(size int64) (read bool, err error) {
	if size > int64(s.server.MaxMessageSize)*2 {
		return false, nil
	}

	if _, err := io.CopyN(io.Discard, s.reader, size); err != nil {
		return false, err
	}

	return true, nil
}

// reportChunkPanic answers a handler that ended in a panic while the session
// was busy with something else. The panic goes to the log and to the
// Disconnect hooks, and to the client as the 421 that a panic in a DATA
// handler also gives. done says that the session is over.
//
// An error that is not a panic goes no further here. A message that the
// client gave up on has nobody left to answer to.
func (s *session) reportChunkPanic(ctx context.Context, result *deliverResult) (context.Context, bool) {
	if result == nil {
		return ctx, false
	}

	var panicErr PanicError
	if !errors.As(result.err, &panicErr) {
		return ctx, false
	}

	ctx = s.reportPanic(ctx, panicErr)
	return s.close(ctx), true
}

// replyChunkError answers a handler that ended with an error. A panic ends the
// session, in the same way as a panic in the handler of a DATA message.
func (s *session) replyChunkError(ctx context.Context, err error) context.Context {
	var panicErr PanicError
	if errors.As(err, &panicErr) {
		ctx = s.reportPanic(ctx, panicErr)
		return s.close(ctx)
	}

	return s.replyError(ctx, err)
}
