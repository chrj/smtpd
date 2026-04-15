# V2 API Review Notes

## Proposal vs Implementation Divergences

### 1. Peer placement

Proposal embeds `Peer` in `Envelope` and removes it from checker/handler signatures.
Implementation keeps `Peer` as a separate argument everywhere, and `Envelope` has no `Peer` field.

The implementation's approach is arguably better -- `Peer` is connection-scoped state that gets
progressively populated, while `Envelope` is per-message. Embedding mutable connection state in a
per-message value struct is misleading. But the proposal and code need to agree.

### 2. Checkers return `(context.Context, error)` -- good divergence

The proposal has checkers returning just `error`. The implementation returns `(context.Context, error)`,
which is critical for middleware that needs to thread values through the context (e.g., storing auth
tokens, trace IDs). Without it, `ConnectionChecker` couldn't inject per-connection values. Keep this.

### 3. No `Chain`/`Pipeline` -- replaced by `Server.Handler()` + `Server.Use()`

The proposal's `Chain()` returning a `*Pipeline` with pre-resolved checker slices doesn't exist.
Instead `smtpd.go` has `Handler()` and `Use()` methods with `checkHandlerCapabilities()` doing
runtime type-assertion on every `Use()` call.

Bug: it appends checkers cumulatively. Middlewares like `rbl` implement all checker interfaces (even
when they're no-ops for the current stage), so every such middleware gets added to every checker list.
At runtime, `if r.stage == OnConnect` inside each method is the only guard. This works but is wasteful.

The `Pipeline` design from the proposal is cleaner -- it resolves once at build time.

### 4. `Error.Error()` drops the code -- FIXED

Now uses `fmt.Sprintf("%d %s", e.Code, e.Message)`, matching v1 behavior.

---

## Unnecessary Public API Surface

1. **`LoggerFromContext`** (`logging.go`) -- Exporting this couples middleware to an internal logging
   convention. If kept, document that it's part of the contract.

2. **`middleware.Stage` type** (`middleware.go`) -- Only used internally by middleware to decide which
   checker method to activate. Probably shouldn't be public.

3. **`Server.Handler()` and `Server.Use()` as methods** -- Mutate `Server` and panic if called in
   wrong order. The proposal's approach of `Server.Handler` as a plain field with `Chain()` for
   composition is more idiomatic Go.

---

## Potential Bugs

1. **`session.close` has a 200ms sleep** (`session.go:197`) -- FIXED. Sleep removed; the buffered
   writer flush before `conn.Close()` is sufficient to drain the final reply.

2. **`session.serve` scanner error handling** (`session.go:93`) -- FIXED. On `bufio.ErrTooLong`
   the server now sends `500 Line too long` and closes the connection instead of trying to advance
   past the offending line, which could block until `ReadTimeout` on a dead peer.

3. **PROXY/XCLIENT mutate `Peer.Addr` in-place** (`proxy.go:38-43`, `xclient.go:78-101`) -- FIXED.
   Both handlers now allocate a fresh `*net.TCPAddr` and assign it to `session.peer.Addr` instead
   of mutating the one returned by `conn.RemoteAddr()`.

4. **`deliver` is nil-safe but `Use` panics** -- `deliver` silently succeeds with no handler, but
   `Use` panics if no handler is set. The no-op discard server works because `deliver` checks
   `srv.handler != nil`, but you can't add middleware to it.

---

## Gaps

1. **No `RSET` hook.** Middleware tracking per-transaction state in context never gets notified that
   the transaction was abandoned.

2. **No `DATA` phase checker.** RBL/SPF work around this by checking in `ServeSMTP`, but by then the
   server has already sent `354` and the client has transmitted the entire body. An early-reject-
   before-DATA checker would save bandwidth.

3. **No multi-line SMTP response support.** `session.reply` only sends single-line responses. Some
   contexts need multi-line replies.

4. **No `VRFY`/`EXPN` support.**

5. **No way to add custom EHLO extensions.** `session.extensions()` is hardcoded. A handler
   implementing CHUNKING, DSN, or custom extensions can't advertise them.

6. **`Envelope.Data` is `io.ReadCloser` but proposal says `io.Reader`.** Implementation correctly
   uses `ReadCloser`, but diverges from proposal. `handleDATA` always drains+closes after `deliver`
   returns, making the handler's Close optional but not documenting this clearly.

7. **No per-recipient delivery feedback.** `ServeSMTP` returns a single `error` for the whole
   message. SMTP supports per-recipient DSNs, but the API collapses everything into one error.

---

## Hard-to-Implement Use Cases

### 1. LMTP (Local Mail Transfer Protocol)
RFC 2033 requires per-recipient responses after DATA. The current `ServeSMTP` returns one `error`,
so there's no way to report different status codes per recipient.

### 2. Milter/Content Filter with Modification
A milter needs to modify headers, body, or recipient list after seeing DATA but before final
delivery. The streaming `io.ReadCloser` model means data flows one way. Middleware can buffer and
replace `env.Data`, but can't modify `Recipients` or `Sender` because `Envelope` is passed by value.

### 3. Greylisting
Greylisting needs to temporarily reject (`450`) at RCPT TO time based on (sender, recipient, IP).
`RecipientChecker` receives `peer` and `addr` but doesn't know the sender. You'd have to stash the
sender in context during `CheckSender`, which is clumsy.

### 4. SMTP Relay with Connection Pooling
A relay maintaining persistent downstream connections needs connection lifecycle hooks across
multiple MAIL/DATA transactions per connection. There's no `OnDisconnect` or session-end callback.

### 5. DKIM/ARC Verification Middleware
Verification needs to see raw message body as bytes, defeating streaming. More critically, it needs
to pass results to downstream handlers. With `Envelope` passed by value, it has to use context,
making verification results invisible in the type system.

### 6. SIZE Extension with Deferred Checking
RFC 1870 allows clients to declare message size in MAIL FROM. `SenderChecker` receives only
`(ctx, peer, addr string)` -- MAIL FROM parameters are parsed but not forwarded to checkers.

### 7. Custom AUTH Mechanisms (XOAUTH2, CRAM-MD5)
AUTH handling is hardcoded to PLAIN and LOGIN. CRAM-MD5 requires server-generated challenges, and
XOAUTH2 has a different token format. Neither fits `Authenticate(ctx, peer, username, password)`.

---

## Recommendations

1. **Reconcile proposal and implementation** -- especially Peer placement and checker return types.
2. **Implement `Chain`/`Pipeline`** from the proposal -- current `Handler()`/`Use()` has the checker
   accumulation bug and is less idiomatic.
3. **Add MAIL FROM parameters to `SenderChecker`** (or a new struct) for SIZE and other extensions.
4. **Add context key or parameter** giving `RecipientChecker` access to the sender for greylisting.
5. **Consider a session lifecycle hook** (`OnDisconnect`/`SessionEnd`) for relay pooling and cleanup.
6. **Remove the 200ms sleep** in `session.close`.
7. **Fix `Error.Error()`** to include the status code.
8. **Fix in-place mutation** of `*net.TCPAddr` in PROXY/XCLIENT handlers.
