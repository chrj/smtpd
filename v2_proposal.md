# smtpd v2 API Proposal

## Goals

1. **Context support** -- per-connection `context.Context` threaded through every callback and handler.
2. **Streaming data** -- `Envelope.Data` as `io.Reader` instead of `[]byte`.
3. **Handler/middleware architecture** -- composable, inspired by `net/http`.
4. **Structured logging** -- `*slog.Logger` replaces `*log.Logger`.
5. **Idiomatic shutdown** -- `Shutdown(ctx)` follows `net/http.Server`.
6. **Cleaner envelope** -- `Peer` embedded in `Envelope`, not a separate argument.

Non-goals: changing the wire protocol, adding new SMTP extensions, or introducing dependency injection frameworks. The library should remain a single package with zero non-stdlib dependencies.

---

## Core Types

### Handler

Follows the `net/http.Handler` pattern exactly: an interface with a single method, plus a func adapter.

```go
// Handler processes a received message.
type Handler interface {
    ServeSMTP(ctx context.Context, env Envelope) error
}

// HandlerFunc adapts a plain function to the Handler interface.
type HandlerFunc func(ctx context.Context, env Envelope) error

func (f HandlerFunc) ServeSMTP(ctx context.Context, env Envelope) error {
    return f(ctx, env)
}
```

### Envelope

```go
// Envelope carries everything about a single message transaction.
type Envelope struct {
    Peer       Peer
    Sender     string
    Recipients []string
    Data       io.Reader // only valid during ServeSMTP; read once
}
```

`Data` is an `io.Reader` backed by the connection. Callers that need `[]byte` opt in with `io.ReadAll`. Callers that forward (relay, pipe to command) can stream without buffering.

### Peer

```go
// Peer describes the remote client. Fields are populated progressively
// as the SMTP session advances (HeloName after HELO, Username after AUTH, etc.).
type Peer struct {
    HeloName   string
    Username   string
    Password   string
    Protocol   Protocol
    ServerName string
    Addr       net.Addr
    TLS        *tls.ConnectionState
}
```

Unchanged from v1 except `Password` is removed (see [Open Questions](#open-questions)).

### Error

```go
// Error represents an SMTP protocol error with a status code.
type Error struct {
    Code    int
    Message string
}

func (e Error) Error() string { return fmt.Sprintf("%d %s", e.Code, e.Message) }
```

Unchanged from v1.

---

## Middleware

```go
// Middleware wraps a Handler. Applied first-in, outermost.
type Middleware func(Handler) Handler

// Chain applies middleware to a handler. The first middleware in the
// list is the outermost (runs first on the way in, last on the way out).
func Chain(h Handler, mw ...Middleware) Handler
```

### Example middleware

```go
// Logging logs every message transaction.
func Logging(logger *slog.Logger) Middleware {
    return func(next Handler) Handler {
        return HandlerFunc(func(ctx context.Context, env Envelope) error {
            start := time.Now()
            err := next.ServeSMTP(ctx, env)
            logger.InfoContext(ctx, "message handled",
                "sender", env.Sender,
                "recipients", len(env.Recipients),
                "peer", env.Peer.Addr,
                "duration", time.Since(start),
                "error", err,
            )
            return err
        })
    }
}

// MaxSize wraps the data reader with a limit.
func MaxSize(n int64) Middleware {
    return func(next Handler) Handler {
        return HandlerFunc(func(ctx context.Context, env Envelope) error {
            env.Data = io.LimitReader(env.Data, n)
            return next.ServeSMTP(ctx, env)
        })
    }
}

// RequireTLS rejects messages from unencrypted connections.
func RequireTLS() Middleware {
    return func(next Handler) Handler {
        return HandlerFunc(func(ctx context.Context, env Envelope) error {
            if env.Peer.TLS == nil {
                return Error{Code: 530, Message: "Must issue STARTTLS first"}
            }
            return next.ServeSMTP(ctx, env)
        })
    }
}
```

### Composition

```go
srv := &smtpd.Server{
    Handler: smtpd.Chain(
        deliveryHandler,
        smtpd.Logging(slog.Default()),
        smtpd.MaxSize(25<<20),
        smtpd.RequireTLS(),
    ),
}
```

---

## Server

```go
type Server struct {
    // Identity
    Hostname       string        // default: "localhost.localdomain"
    WelcomeMessage string        // default: "{Hostname} ESMTP ready."

    // Timeouts
    ReadTimeout  time.Duration   // per-read; default 60s
    WriteTimeout time.Duration   // per-write; default 60s
    DataTimeout  time.Duration   // DATA command; default 5m

    // Limits
    MaxConnections int           // default 100; -1 unlimited
    MaxMessageSize int           // default 10MB; enforced at protocol level
    MaxRecipients  int           // default 100

    // Handler
    Handler Handler              // nil = accept and discard

    // Checkers -- context is derived from the connection's base context.
    ConnectionChecker func(ctx context.Context, peer Peer) error
    HeloChecker       func(ctx context.Context, peer Peer, name string) error
    SenderChecker     func(ctx context.Context, peer Peer, addr string) error
    RecipientChecker  func(ctx context.Context, peer Peer, addr string) error

    // Authentication
    Authenticator func(ctx context.Context, peer Peer, username, password string) error
    AuthOptional  bool

    // Extensions
    EnableXCLIENT       bool
    EnableProxyProtocol bool

    // TLS
    TLSConfig *tls.Config
    ForceTLS  bool

    // Logging
    Logger *slog.Logger          // nil = silent

    // BaseContext optionally specifies a function that returns the base
    // context for incoming connections. If nil, context.Background() is used.
    // The listener address is provided as an argument.
    BaseContext func(net.Listener) context.Context

    // ConnContext optionally specifies a function that modifies the context
    // used for a new connection. The provided ctx is derived from BaseContext
    // and has a per-connection cancel. Use this to attach connection-scoped
    // values (tracing IDs, rate-limiter tokens, etc.).
    ConnContext func(ctx context.Context, conn net.Conn) context.Context
}
```

### Lifecycle

```go
func (srv *Server) ListenAndServe(addr string) error
func (srv *Server) Serve(l net.Listener) error
func (srv *Server) Shutdown(ctx context.Context) error
func (srv *Server) Address() net.Addr
```

`Shutdown` replaces the v1 `Shutdown(wait bool)` / `Wait()` pair. The context deadline controls the drain period, consistent with `net/http.Server.Shutdown`.

```go
ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
defer cancel()
if err := srv.Shutdown(ctx); err != nil {
    // connections did not drain in time
}
```

---

## Context Flow

Each accepted connection gets its own `context.Context` derived from `BaseContext` (or `context.Background()`), optionally modified by `ConnContext`. This context is:

- Cancelled when the connection closes (for any reason).
- Passed to every checker and to `Handler.ServeSMTP`.
- Usable with `context.WithValue` for request-scoped data (trace IDs, auth tokens).

### Context helpers

```go
// PeerFromContext returns the Peer associated with the current connection.
// The server stores it automatically; middleware and handlers can retrieve
// it without threading Peer through custom types.
func PeerFromContext(ctx context.Context) (Peer, bool)
```

---

## Streaming Data

`Envelope.Data` is an `io.Reader` valid only for the duration of the `ServeSMTP` call. The server enforces `MaxMessageSize` at the protocol level before the reader is exposed to the handler.

### Relay (zero-copy)

```go
smtpd.HandlerFunc(func(ctx context.Context, env smtpd.Envelope) error {
    return relay.Send(ctx, env.Sender, env.Recipients, env.Data)
})
```

### DKIM signing (needs bytes)

```go
smtpd.HandlerFunc(func(ctx context.Context, env smtpd.Envelope) error {
    data, err := io.ReadAll(env.Data)
    if err != nil {
        return err
    }
    signed, err := dkim.Sign(data, selector, privateKey)
    if err != nil {
        return err
    }
    return relay.Send(ctx, env.Sender, env.Recipients, bytes.NewReader(signed))
})
```

### Writing to disk (streaming)

```go
smtpd.HandlerFunc(func(ctx context.Context, env smtpd.Envelope) error {
    f, err := os.CreateTemp("/var/spool/mail", "msg-*")
    if err != nil {
        return err
    }
    defer f.Close()
    _, err = io.Copy(f, env.Data)
    return err
})
```

---

## Structured Logging

Replace `ProtocolLogger *log.Logger` with `Logger *slog.Logger`.

The server emits structured log records at well-defined points:

| Level | Event | Attributes |
|-------|-------|------------|
| Debug | connection accepted | `remote_addr`, `conn_id` |
| Debug | command received | `cmd`, `args`, `conn_id` |
| Debug | response sent | `code`, `msg`, `conn_id` |
| Info  | STARTTLS upgraded | `remote_addr`, `tls_version`, `cipher`, `conn_id` |
| Info  | AUTH success | `remote_addr`, `username`, `conn_id` |
| Info  | message received | `sender`, `recipients`, `size`, `conn_id`, `duration` |
| Warn  | AUTH failure | `remote_addr`, `username`, `conn_id` |
| Warn  | checker rejected | `checker`, `remote_addr`, `error`, `conn_id` |
| Error | connection error | `remote_addr`, `error`, `conn_id` |

Every log record includes a `conn_id` attribute for correlating events within a single connection. The server generates this automatically and also stores it in the connection context.

```go
srv := &smtpd.Server{
    Logger: slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
        Level: slog.LevelDebug,
    })),
}
```

Passing `nil` silences all server-internal logging (the default, same as v1).

---

## Envelope.AddReceivedLine

```go
// AddReceivedLine reads all data from the envelope's reader, prepends
// an RFC 5321 Received header, and replaces Data with a new reader
// over the combined result. Call this before passing the envelope to
// the next handler.
func (env *Envelope) AddReceivedLine() error
```

In v1 this was `AddReceivedLine(peer Peer)` -- the peer argument is gone because `Peer` is now embedded in the envelope. The method now consumes the `io.Reader` and replaces it, so it should be used as middleware or called early in the handler.

As a middleware:

```go
func AddReceived() smtpd.Middleware {
    return func(next smtpd.Handler) smtpd.Handler {
        return smtpd.HandlerFunc(func(ctx context.Context, env smtpd.Envelope) error {
            if err := env.AddReceivedLine(); err != nil {
                return err
            }
            return next.ServeSMTP(ctx, env)
        })
    }
}
```

---

## Breaking Changes Summary

| v1 | v2 | Migration |
|----|-----|-----------|
| `Handler func(Peer, Envelope) error` | `Handler interface { ServeSMTP(context.Context, Envelope) error }` | Wrap with `HandlerFunc` adapter |
| `Envelope.Data []byte` | `Envelope.Data io.Reader` | Add `io.ReadAll(env.Data)` where needed |
| `Peer` as separate handler arg | `env.Peer` | Access via envelope |
| Checkers: `func(Peer, ...) error` | `func(context.Context, Peer, ...) error` | Add `ctx` first param |
| `Shutdown(wait bool)` + `Wait()` | `Shutdown(ctx context.Context) error` | Use context with timeout |
| `ProtocolLogger *log.Logger` | `Logger *slog.Logger` | Switch to `slog` |
| `Peer.Password` exposed | Removed | See open questions |
| `AddReceivedLine(peer)` | `AddReceivedLine() error` | Peer now in envelope; returns error |

---

## What Stays the Same

- Package name: `smtpd`
- Struct literal construction: `&smtpd.Server{...}` -- no functional options, no builder
- `ListenAndServe` / `Serve` surface
- `Error{Code, Message}` for SMTP protocol errors
- `Peer` struct (minus `Password`)
- `Protocol` type (`SMTP` / `ESMTP`)
- All configuration fields on `Server` (timeouts, limits, TLS, extensions)
- Zero external dependencies

---

## New Additions

### BaseContext / ConnContext

Borrowed from `net/http.Server`. These let callers inject values into the connection-scoped context without forking the library.

```go
srv := &smtpd.Server{
    BaseContext: func(l net.Listener) context.Context {
        return context.WithValue(context.Background(), serverKey, "prod-mx-01")
    },
    ConnContext: func(ctx context.Context, c net.Conn) context.Context {
        return context.WithValue(ctx, traceKey, generateTraceID())
    },
}
```

### Built-in Middleware

The package ships a small set of middleware for common patterns:

- `smtpd.Logging(logger)` -- log every transaction
- `smtpd.MaxSize(n)` -- limit data reader
- `smtpd.RequireTLS()` -- reject plaintext connections

Users compose their own for anything domain-specific.

---

## Example: DKIM Proxy (v2)

```go
func main() {
    logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

    handler := smtpd.Chain(
        smtpd.HandlerFunc(func(ctx context.Context, env smtpd.Envelope) error {
            data, err := io.ReadAll(env.Data)
            if err != nil {
                return err
            }
            signed, err := dkim.Sign(data, selector, privateKey)
            if err != nil {
                return err
            }
            return smtp.SendMail(relay, auth, env.Sender, env.Recipients, signed)
        }),
        smtpd.Logging(logger),
    )

    srv := &smtpd.Server{
        Hostname:  "mx.example.com",
        Handler:   handler,
        TLSConfig: tlsConfig,
        ForceTLS:  true,
        Logger:    logger,
    }

    go func() {
        sig := make(chan os.Signal, 1)
        signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
        <-sig
        ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
        defer cancel()
        srv.Shutdown(ctx)
    }()

    if err := srv.ListenAndServe(":465"); err != nil && err != smtpd.ErrServerClosed {
        logger.Error("server failed", "error", err)
        os.Exit(1)
    }
}
```

---

## Open Questions

1. **Remove `Peer.Password`?** -- Exposing the raw password in a struct that gets passed to middleware and logged is a security smell. The `Authenticator` callback already receives it. Consider removing it from `Peer` entirely and letting `Authenticator` store whatever it needs in the context via `ConnContext` or a context value.

2. **Checker composition** -- Should checkers also become interfaces with middleware support, or are plain functions sufficient? Plain functions keep the API small; interface checkers would enable chaining (e.g., rate limit *then* SPF check). Leaning toward plain functions -- composition at that level is rare enough to handle in userland.

3. **Multiple AUTH mechanisms** -- v1 supports PLAIN and LOGIN. Should v2 expose a pluggable `AuthMechanism` interface for CRAM-MD5, XOAUTH2, etc.? This adds complexity but covers real-world needs for OAuth-based auth.

4. **`io.Reader` lifetime** -- If the handler spawns a goroutine and returns, the reader becomes invalid. Should the server document this, or enforce it with a wrapper that errors after `ServeSMTP` returns? Suggesting an explicit `io.Reader` wrapper that returns `ErrBodyClosed` after the handler returns, similar to `http.Request.Body` semantics.

5. **SMTP pipelining improvements** -- v1 advertises PIPELINING. Should v2 offer any API surface for handlers to be aware of pipelined commands, or keep it transparent?

6. **Metrics hook** -- Should the server expose a metrics callback or interface for Prometheus/OpenTelemetry integration, or leave this entirely to middleware? Middleware can cover it, but a `ConnState` callback (like `net/http.Server.ConnState`) could be useful for connection-level metrics that middleware can't observe.

---

## Appendix A: Unified Handler with Pre-resolved Checker Chains

An alternative to keeping checkers as flat function fields on `Server`: make them optional interfaces that any `Handler` in the middleware chain can implement. `Chain` walks the handler list once at build time, extracts participants per checker interface, and pre-builds a dedicated chain for each. No runtime type switches, no propagation wrappers, and every `next` in a checker chain is guaranteed to implement that interface.

### Interfaces

```go
// Handler is the only required interface. Everything else is opt-in.
type Handler interface {
    ServeSMTP(ctx context.Context, env Envelope) error
}

type HandlerFunc func(ctx context.Context, env Envelope) error

func (f HandlerFunc) ServeSMTP(ctx context.Context, env Envelope) error {
    return f(ctx, env)
}

// Optional interfaces. A Handler (or middleware) implements these to
// participate in the corresponding SMTP phase. Chain resolves them
// at build time -- the server never does type switches at runtime.

type ConnectionChecker interface {
    CheckConnection(ctx context.Context, peer Peer) error
}

type HeloChecker interface {
    CheckHelo(ctx context.Context, peer Peer, name string) error
}

type SenderChecker interface {
    CheckSender(ctx context.Context, peer Peer, addr string) error
}

type RecipientChecker interface {
    CheckRecipient(ctx context.Context, peer Peer, addr string) error
}

type Authenticator interface {
    Authenticate(ctx context.Context, peer Peer, username, password string) error
}
```

### The pipeline type

`Chain` returns a `*Pipeline` -- a concrete type that pre-resolves every optional interface into a flat call list. The server only ever interacts with the pipeline, never with raw type switches.

```go
// Pipeline is the resolved result of Chain. It implements Handler and
// every optional checker interface. The server calls these directly.
type Pipeline struct {
    handler            Handler              // the composed ServeSMTP chain
    connectionCheckers []ConnectionChecker  // only handlers that implement it
    heloCheckers       []HeloChecker
    senderCheckers     []SenderChecker
    recipientCheckers  []RecipientChecker
    authenticators     []Authenticator
}

func (p *Pipeline) ServeSMTP(ctx context.Context, env Envelope) error {
    return p.handler.ServeSMTP(ctx, env)
}

func (p *Pipeline) CheckConnection(ctx context.Context, peer Peer) error {
    for _, c := range p.connectionCheckers {
        if err := c.CheckConnection(ctx, peer); err != nil {
            return err
        }
    }
    return nil
}

func (p *Pipeline) CheckHelo(ctx context.Context, peer Peer, name string) error {
    for _, c := range p.heloCheckers {
        if err := c.CheckHelo(ctx, peer, name); err != nil {
            return err
        }
    }
    return nil
}

func (p *Pipeline) CheckSender(ctx context.Context, peer Peer, addr string) error {
    for _, c := range p.senderCheckers {
        if err := c.CheckSender(ctx, peer, addr); err != nil {
            return err
        }
    }
    return nil
}

func (p *Pipeline) CheckRecipient(ctx context.Context, peer Peer, addr string) error {
    for _, c := range p.recipientCheckers {
        if err := c.CheckRecipient(ctx, peer, addr); err != nil {
            return err
        }
    }
    return nil
}

func (p *Pipeline) Authenticate(ctx context.Context, peer Peer, username, password string) error {
    for _, a := range p.authenticators {
        if err := a.Authenticate(ctx, peer, username, password); err != nil {
            return err
        }
    }
    return nil
}
```

### Chain builds the pipeline

`Chain` takes the inner handler and middleware, composes `ServeSMTP` the usual way, then does a single pass to extract checker participants. Order is outermost-first (middleware applied last runs first).

```go
// Chain composes middleware around a handler and pre-resolves all
// optional checker interfaces into flat call lists.
func Chain(h Handler, mw ...Middleware) *Pipeline {
    // Collect all participants: inner handler + each middleware wrapper.
    // We need the unwrapped middleware values, not the composed result,
    // because composition hides interfaces behind the wrapper.
    participants := make([]Handler, 0, len(mw)+1)

    // Apply middleware to build the ServeSMTP chain as usual.
    for _, m := range mw {
        wrapped := m(h)
        participants = append(participants, wrapped)
        h = wrapped
    }
    // The inner handler is last in checker order (outermost runs first).
    participants = append(participants, h)
    // But wait -- h is now the fully wrapped handler. The inner handler
    // is the original one passed to Chain. We need it unwrapped.
    // Let's restructure:

    // Actually, simpler: middleware functions return a Handler value.
    // That returned value is what might implement checker interfaces.
    // We collect those values in application order (outermost first).

    p := &Pipeline{handler: h}

    // Walk participants outermost-first and pick up checker implementations.
    for _, part := range participants {
        if cc, ok := part.(ConnectionChecker); ok {
            p.connectionCheckers = append(p.connectionCheckers, cc)
        }
        if hc, ok := part.(HeloChecker); ok {
            p.heloCheckers = append(p.heloCheckers, hc)
        }
        if sc, ok := part.(SenderChecker); ok {
            p.senderCheckers = append(p.senderCheckers, sc)
        }
        if rc, ok := part.(RecipientChecker); ok {
            p.recipientCheckers = append(p.recipientCheckers, rc)
        }
        if a, ok := part.(Authenticator); ok {
            p.authenticators = append(p.authenticators, a)
        }
    }

    return p
}
```

This is a cleaner version. Let's make it precise:

```go
func Chain(inner Handler, mw ...Middleware) *Pipeline {
    // Collect every handler value in the stack. The inner handler
    // and each middleware wrapper are all candidates for checkers.
    all := make([]Handler, 0, len(mw)+1)

    // Apply middleware innermost-first: mw[0] is outermost.
    // We iterate in reverse so mw[0] wraps everything else.
    h := inner
    wrappers := make([]Handler, len(mw))
    for i := len(mw) - 1; i >= 0; i-- {
        h = mw[i](h)
        wrappers[i] = h // wrappers[0] is the outermost
    }

    // Order: outermost middleware first, inner handler last.
    all = append(all, wrappers...)
    all = append(all, inner)

    // Build the pipeline.
    p := &Pipeline{handler: h} // h is the fully composed ServeSMTP chain

    for _, part := range all {
        if cc, ok := part.(ConnectionChecker); ok {
            p.connectionCheckers = append(p.connectionCheckers, cc)
        }
        if hc, ok := part.(HeloChecker); ok {
            p.heloCheckers = append(p.heloCheckers, hc)
        }
        if sc, ok := part.(SenderChecker); ok {
            p.senderCheckers = append(p.senderCheckers, sc)
        }
        if rc, ok := part.(RecipientChecker); ok {
            p.recipientCheckers = append(p.recipientCheckers, rc)
        }
        if a, ok := part.(Authenticator); ok {
            p.authenticators = append(p.authenticators, a)
        }
    }

    return p
}
```

### Server changes

The `Server` struct drops all checker fields. It only has `Handler`:

```go
type Server struct {
    Hostname       string
    WelcomeMessage string

    ReadTimeout  time.Duration
    WriteTimeout time.Duration
    DataTimeout  time.Duration

    MaxConnections int
    MaxMessageSize int
    MaxRecipients  int

    Handler Handler  // use Chain() to get a *Pipeline with checker support

    AuthOptional bool

    EnableXCLIENT       bool
    EnableProxyProtocol bool

    TLSConfig *tls.Config
    ForceTLS  bool

    Logger *slog.Logger

    BaseContext func(net.Listener) context.Context
    ConnContext func(ctx context.Context, conn net.Conn) context.Context
}
```

Internally, the server checks once whether `Handler` implements the optional interfaces:

```go
// In Serve(), resolved once:
cc, hasCC := srv.Handler.(ConnectionChecker)
hc, hasHC := srv.Handler.(HeloChecker)
sc, hasSC := srv.Handler.(SenderChecker)
rc, hasRC := srv.Handler.(RecipientChecker)
au, hasAU := srv.Handler.(Authenticator)

// On new connection:
if hasCC {
    if err := cc.CheckConnection(ctx, peer); err != nil { /* reject */ }
}
```

When `Handler` is a `*Pipeline` (returned by `Chain`), it always satisfies every optional interface -- the pipeline methods just iterate their pre-built slices, which may be empty (no-op).

When `Handler` is a plain `HandlerFunc`, none of the optional interfaces are satisfied, so all phases are no-ops. Simple and predictable.

### What this eliminates

Compared to the runtime propagation approach:

- **No `Propagate` wrapper.** Middleware that doesn't care about checkers doesn't need to forward anything. `Chain` extracts interfaces from each layer independently.
- **No manual `next.(SenderChecker)` calls.** Middleware that implements `CheckSender` doesn't need to know whether the next handler also does. `Chain` already collected both into the flat list.
- **No outermost-wins ambiguity.** Every participant runs, in order. If `RateLimit` and `IPBlocklist` both implement `ConnectionChecker`, both run.
- **No runtime type switches** on the hot path. Everything is resolved once at build time.

### Writing a handler with checkers

A handler implements the interfaces it cares about. It never thinks about `next`:

```go
type Mailbox struct {
    Domain   string
    UserDB   UserLookup
    SpoolDir string
}

func (m *Mailbox) CheckRecipient(ctx context.Context, peer smtpd.Peer, addr string) error {
    local, domain, _ := strings.Cut(addr, "@")
    if domain != m.Domain {
        return smtpd.Error{Code: 550, Message: "No such domain"}
    }
    if !m.UserDB.Exists(local) {
        return smtpd.Error{Code: 550, Message: "No such user"}
    }
    return nil
}

func (m *Mailbox) ServeSMTP(ctx context.Context, env smtpd.Envelope) error {
    for _, rcpt := range env.Recipients {
        local, _, _ := strings.Cut(rcpt, "@")
        if err := m.deliver(local, env.Data); err != nil {
            return err
        }
    }
    return nil
}
```

### Writing middleware with checkers

Middleware returns a struct that implements `Handler` and whatever optional interfaces it participates in. No delegation boilerplate:

```go
type rateLimiter struct {
    limiter *rate.Limiter
    next    smtpd.Handler
}

func RateLimit(rps float64, burst int) smtpd.Middleware {
    lim := rate.NewLimiter(rate.Limit(rps), burst)
    return func(next smtpd.Handler) smtpd.Handler {
        return &rateLimiter{limiter: lim, next: next}
    }
}

// CheckConnection -- no need to call next. The pipeline runs all
// ConnectionCheckers in the chain automatically.
func (r *rateLimiter) CheckConnection(ctx context.Context, peer smtpd.Peer) error {
    if !r.limiter.Allow() {
        return smtpd.Error{Code: 421, Message: "Too many connections, try again later"}
    }
    return nil
}

func (r *rateLimiter) ServeSMTP(ctx context.Context, env smtpd.Envelope) error {
    return r.next.ServeSMTP(ctx, env)
}
```

Compare this to the previous version which required:
```go
// OLD: had to manually chain to inner handler's checker
if cc, ok := r.next.(smtpd.ConnectionChecker); ok {
    return cc.CheckConnection(ctx, peer)
}
```

That's gone. The middleware only contains its own logic.

### SPF sender check

```go
type spfChecker struct {
    next smtpd.Handler
}

func SPF() smtpd.Middleware {
    return func(next smtpd.Handler) smtpd.Handler {
        return &spfChecker{next: next}
    }
}

func (s *spfChecker) CheckSender(ctx context.Context, peer smtpd.Peer, addr string) error {
    result := spf.Check(peer.Addr, addr)
    if result == spf.Fail {
        return smtpd.Error{Code: 550, Message: "SPF check failed"}
    }
    return nil
}

func (s *spfChecker) ServeSMTP(ctx context.Context, env smtpd.Envelope) error {
    return s.next.ServeSMTP(ctx, env)
}
```

### LDAP auth

```go
type ldapAuth struct {
    pool *ldap.ConnPool
    next smtpd.Handler
}

func LDAPAuthenticate(pool *ldap.ConnPool) smtpd.Middleware {
    return func(next smtpd.Handler) smtpd.Handler {
        return &ldapAuth{pool: pool, next: next}
    }
}

func (a *ldapAuth) Authenticate(ctx context.Context, peer smtpd.Peer, user, pass string) error {
    conn, err := a.pool.Get(ctx)
    if err != nil {
        return smtpd.Error{Code: 454, Message: "Temporary auth failure"}
    }
    defer conn.Close()
    if err := conn.Bind(user, pass); err != nil {
        return smtpd.Error{Code: 535, Message: "Authentication failed"}
    }
    return nil
}

func (a *ldapAuth) ServeSMTP(ctx context.Context, env smtpd.Envelope) error {
    return a.next.ServeSMTP(ctx, env)
}
```

### Full composition

```go
srv := &smtpd.Server{
    Hostname:  "mx.example.com",
    TLSConfig: tlsConfig,
    ForceTLS:  true,
    Logger:    slog.Default(),
    Handler: smtpd.Chain(
        &Mailbox{Domain: "example.com", UserDB: db, SpoolDir: "/var/spool/mail"},
        smtpd.Logging(slog.Default()),     // no checkers, skipped in all checker chains
        SPF(),                              // participates in SenderChecker chain
        LDAPAuthenticate(ldapPool),         // participates in Authenticator chain
        RateLimit(10, 50),                  // participates in ConnectionChecker chain
    ),
}
```

At build time, `Chain` resolves:

| Checker chain | Participants (outermost first) |
|---|---|
| `connectionCheckers` | `RateLimit` |
| `heloCheckers` | *(empty)* |
| `senderCheckers` | `SPF` |
| `recipientCheckers` | `Mailbox` |
| `authenticators` | `LDAPAuthenticate` |

When the server receives `RCPT TO`, it calls `pipeline.CheckRecipient(ctx, peer, addr)`, which calls `Mailbox.CheckRecipient` -- the only participant. If there were two `RecipientChecker` implementations in the chain, both would run in order. No type switches, no delegation, no forgotten `next` calls.

### Multiple checkers of the same type

Because the pipeline runs all participants, stacking is natural:

```go
smtpd.Chain(
    &Mailbox{Domain: "example.com", UserDB: db, SpoolDir: "/var/spool/mail"},
    IPBlocklist(blockedRanges),   // implements ConnectionChecker
    RateLimit(10, 50),            // also implements ConnectionChecker
)
```

On new connection: `RateLimit.CheckConnection` runs first (outermost), then `IPBlocklist.CheckConnection`. If either returns an error, the connection is rejected. Neither knows about the other.

### Trade-offs

**Advantages over the propagation approach:**

- **No magic wrappers.** `Chain` does a simple, visible pass. There's no `Propagate` type that silently re-implements every interface.
- **Middleware is simpler to write.** Implement your checker method, return nil or an error. Never think about `next` for checkers.
- **All participants run.** Two `ConnectionChecker` middleware both fire, in order. No silent shadowing.
- **Build-time resolution.** The server does zero type switches per connection. The pipeline is a concrete struct with pre-built slices.
- **Easy to debug.** Inspect `pipeline.connectionCheckers` to see exactly what runs and in what order.

**Disadvantages:**

- **No short-circuit delegation.** A middleware can't say "run my check, then also run the next checker in this specific chain." It either participates (returns nil to continue, error to reject) or it doesn't. This is usually what you want, but prevents patterns like "override the inner check only if my check passes."
- **`Pipeline` is a concrete type, not an interface.** `Chain` returns `*Pipeline`, not `Handler`. The server still accepts any `Handler`, but only `*Pipeline` gets checker support. Users who don't call `Chain` get no checkers (clear and predictable, but worth documenting).
- **`HandlerFunc` still can't carry checkers.** For a simple function + checkers, you need a struct. This is inherent to the interface approach.
- **All-or-nothing per phase.** If you want a checker to run for some recipients but not others, that logic goes inside the checker itself -- the pipeline always calls every participant.

### Optional ServeSMTP for pure checker middleware

Every middleware example in this appendix that only participates in a checker phase still has to implement `ServeSMTP` with identical boilerplate:

```go
func (s *spfChecker) ServeSMTP(ctx context.Context, env smtpd.Envelope) error {
    return s.next.ServeSMTP(ctx, env)
}
```

This is dead weight. An SPF checker doesn't touch the message -- it only cares about `CheckSender`. It shouldn't need a `next` field, shouldn't need to implement `Handler`, and shouldn't be in the `ServeSMTP` call chain at all.

#### The idea

`Chain` accepts both `Middleware` (participates in `ServeSMTP` chain) and plain values that only implement checker interfaces (do not). A pure checker value gets scanned for interfaces but is never inserted into the `ServeSMTP` chain.

The simplest way to express this: change `Chain` to accept `any`:

```go
func Chain(inner Handler, steps ...any) *Pipeline
```

`Chain` type-switches each step:

```go
func Chain(inner Handler, steps ...any) *Pipeline {
    h := inner
    p := &Pipeline{}

    // Collect all handler values for checker scanning.
    all := make([]any, 0, len(steps)+1)

    for i := len(steps) - 1; i >= 0; i-- {
        switch step := steps[i].(type) {
        case Middleware:
            // Participates in ServeSMTP chain.
            h = step(h)
            all = append(all, h)
        default:
            // Pure checker -- not in ServeSMTP chain.
            // Scanned for interfaces only.
            all = append(all, step)
        }
    }

    all = append(all, inner)
    p.handler = h

    // Extract checker participants.
    for _, part := range all {
        if cc, ok := part.(ConnectionChecker); ok {
            p.connectionCheckers = append(p.connectionCheckers, cc)
        }
        if hc, ok := part.(HeloChecker); ok {
            p.heloCheckers = append(p.heloCheckers, hc)
        }
        if sc, ok := part.(SenderChecker); ok {
            p.senderCheckers = append(p.senderCheckers, sc)
        }
        if rc, ok := part.(RecipientChecker); ok {
            p.recipientCheckers = append(p.recipientCheckers, rc)
        }
        if a, ok := part.(Authenticator); ok {
            p.authenticators = append(p.authenticators, a)
        }
    }

    return p
}
```

#### What this enables

Pure checkers become trivial structs with no handler boilerplate and no `next` field:

```go
// Before: middleware, must implement Handler, must store and call next
type spfChecker struct {
    next smtpd.Handler
}

func SPF() smtpd.Middleware {
    return func(next smtpd.Handler) smtpd.Handler {
        return &spfChecker{next: next}
    }
}

func (s *spfChecker) CheckSender(ctx context.Context, peer smtpd.Peer, addr string) error {
    result := spf.Check(peer.Addr, addr)
    if result == spf.Fail {
        return smtpd.Error{Code: 550, Message: "SPF check failed"}
    }
    return nil
}

func (s *spfChecker) ServeSMTP(ctx context.Context, env smtpd.Envelope) error {
    return s.next.ServeSMTP(ctx, env)
}

// After: pure checker, no Handler, no next
type spfChecker struct{}

func (s spfChecker) CheckSender(ctx context.Context, peer smtpd.Peer, addr string) error {
    result := spf.Check(peer.Addr, addr)
    if result == spf.Fail {
        return smtpd.Error{Code: 550, Message: "SPF check failed"}
    }
    return nil
}
```

Same for LDAP auth:

```go
// Before
type ldapAuth struct {
    pool *ldap.ConnPool
    next smtpd.Handler
}

func LDAPAuthenticate(pool *ldap.ConnPool) smtpd.Middleware {
    return func(next smtpd.Handler) smtpd.Handler {
        return &ldapAuth{pool: pool, next: next}
    }
}

func (a *ldapAuth) Authenticate(ctx context.Context, peer smtpd.Peer, user, pass string) error { /* ... */ }
func (a *ldapAuth) ServeSMTP(ctx context.Context, env smtpd.Envelope) error {
    return a.next.ServeSMTP(ctx, env)
}

// After
type ldapAuth struct {
    pool *ldap.ConnPool
}

func (a *ldapAuth) Authenticate(ctx context.Context, peer smtpd.Peer, user, pass string) error { /* ... */ }
```

Composition reads cleanly -- `Middleware` and plain checkers are intermixed in the same `Chain` call, and the distinction is obvious from the types:

```go
srv := &smtpd.Server{
    Handler: smtpd.Chain(
        &Mailbox{Domain: "example.com", UserDB: db, SpoolDir: "/var/spool/mail"},
        smtpd.Logging(slog.Default()),     // Middleware: wraps ServeSMTP
        spfChecker{},                       // pure SenderChecker: not in ServeSMTP chain
        &ldapAuth{pool: ldapPool},          // pure Authenticator: not in ServeSMTP chain
        RateLimit(10, 50),                  // Middleware: wraps ServeSMTP AND ConnectionChecker
    ),
}
```

Note that `RateLimit` remains a `Middleware` -- it wraps `ServeSMTP` (maybe to add timing metadata to the context) *and* implements `ConnectionChecker`. The two concepts coexist naturally.

#### Arguments for

- **Less boilerplate.** The passthrough `ServeSMTP` and stored `next` field are the most common complaint about middleware-style APIs. Pure checkers eliminate both entirely.
- **Clearer intent.** Looking at a type, if it has no `ServeSMTP` method, it obviously doesn't participate in message handling. If it does, it does. No ambiguity about whether a `ServeSMTP` is "real" or just delegation.
- **Shorter ServeSMTP chain.** Five middleware where three are pure checkers means only two actual `ServeSMTP` calls instead of five. Less indirection at runtime.
- **Pure checkers don't need `next`.** They are stateless with respect to the handler chain. This makes them simpler to test (no mock handler needed) and safer to share across pipelines.

#### Arguments against

- **`Chain` accepts `any`.** This is the big one. The Go community has strong opinions about `any` in public APIs -- it pushes type errors from compile time to runtime. A step that is neither a `Middleware` nor a known checker interface is a silent no-op (or a panic, depending on how strict `Chain` is). Compare this to the current signature where every step is statically typed as `Middleware`.
- **Two mental models.** Middleware has `next` and wraps `ServeSMTP`. Pure checkers have neither. When someone needs to add `ServeSMTP` behavior to what was a pure checker (e.g., "also log the message body size"), they have to restructure from a plain struct to a `Middleware` function returning a struct with a `next` field. The refactor isn't hard but it's a conceptual gear shift.
- **Ordering ambiguity.** A `Middleware` step gets a position in the `ServeSMTP` chain. A pure checker step gets a position in its checker chain. But what about a step that is *both* a `Middleware` and a checker? It appears once in `steps`, but its checker and `ServeSMTP` positions are both derived from that one position. This is fine and consistent, but worth being explicit about in documentation.
- **Discoverability.** A value that implements no recognized interface at all is silently ignored by `Chain`. This could mask bugs (typo in method name, wrong receiver type). Mitigation: `Chain` could panic if a step is neither `Middleware` nor any checker interface, catching misconfiguration at startup.

#### Mitigation: validate at build time

`Chain` can reject steps that contribute nothing:

```go
for i := len(steps) - 1; i >= 0; i-- {
    switch step := steps[i].(type) {
    case Middleware:
        h = step(h)
        all = append(all, h)
    default:
        if !implementsAnyChecker(step) {
            panic(fmt.Sprintf("smtpd.Chain: step %d (%T) is not a Middleware and implements no checker interface", i, step))
        }
        all = append(all, step)
    }
}
```

This catches misuse at startup, which is the same time you'd catch a nil handler or other configuration errors. It doesn't replace compile-time safety, but it's a practical middle ground.

#### Alternative: typed step union instead of `any`

If `any` is too loose, define a marker interface:

```go
// Step is something that can participate in a Chain.
// Either a Middleware (wraps ServeSMTP) or a value that implements
// at least one checker interface.
type Step interface {
    smtpdStep() // unexported marker -- only this package can satisfy it
}

// Make Middleware satisfy Step.
// Make each checker interface embed Step (or provide a helper).
```

This keeps `Chain` type-safe:

```go
func Chain(inner Handler, steps ...Step) *Pipeline
```

But it requires every checker struct to embed a marker or call a registration function, which adds its own boilerplate. It also prevents third-party types from being passed directly. On balance, the `any` + runtime validation approach is likely simpler and more practical -- the marker interface trades one kind of boilerplate for another.

**Hybrid option:** the server can still accept checker function fields as a convenience for simple cases. If `Handler` is a `*Pipeline`, use its resolved chains. Otherwise, fall back to the function fields:

```go
// Simple -- function fields, no Chain:
srv := &smtpd.Server{
    Handler:          smtpd.HandlerFunc(deliver),
    RecipientChecker: func(ctx context.Context, peer smtpd.Peer, addr string) error {
        if !validDomain(addr) {
            return smtpd.Error{Code: 550, Message: "Invalid domain"}
        }
        return nil
    },
}

// Advanced -- everything through Chain:
srv := &smtpd.Server{
    Handler: smtpd.Chain(mailbox, SPF(), RateLimit(10, 50)),
}
```
