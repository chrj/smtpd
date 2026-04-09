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

## Appendix A: Unified Handler with Optional Interfaces

An alternative to keeping checkers as flat function fields on `Server`: make them optional interfaces that any `Handler` in the middleware chain can implement. The server walks the chain with type switches to discover which handlers participate in each SMTP phase.

This unifies the extension model -- everything is a `Handler`, and some handlers also have opinions about connections, senders, recipients, or authentication.

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

// Optional interfaces. The server type-switches on the resolved handler
// (after middleware wrapping) at each SMTP phase.

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

### Server changes

The `Server` struct no longer has checker fields. It only has `Handler`:

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

    Handler Handler

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

Internally, at each SMTP phase the server does:

```go
// On new connection:
if cc, ok := srv.Handler.(ConnectionChecker); ok {
    if err := cc.CheckConnection(ctx, peer); err != nil {
        // reject
    }
}

// On HELO/EHLO:
if hc, ok := srv.Handler.(HeloChecker); ok {
    if err := hc.CheckHelo(ctx, peer, name); err != nil {
        // reject
    }
}

// On AUTH:
if auth, ok := srv.Handler.(Authenticator); ok {
    if err := auth.Authenticate(ctx, peer, user, pass); err != nil {
        // reject
    }
}
// (and so on for SenderChecker, RecipientChecker)
```

If the handler doesn't implement an optional interface, that phase is a no-op (accept).

### Propagating interfaces through middleware

The key challenge: middleware wraps a `Handler`, but the wrapper must propagate the inner handler's optional interfaces or they become invisible to the type switch.

A simple approach -- middleware that doesn't care about a phase delegates to the inner handler:

```go
// Middleware is still the same type.
type Middleware func(Handler) Handler

// propagate is a helper that wraps an outer handler but forwards
// optional interface checks to an inner handler.
type propagate struct {
    Handler                    // the outer (wrapped) handler
    inner   Handler            // the original handler, checked for optional interfaces
}

func (p propagate) CheckConnection(ctx context.Context, peer Peer) error {
    if cc, ok := p.inner.(ConnectionChecker); ok {
        return cc.CheckConnection(ctx, peer)
    }
    return nil
}

func (p propagate) CheckHelo(ctx context.Context, peer Peer, name string) error {
    if hc, ok := p.inner.(HeloChecker); ok {
        return hc.CheckHelo(ctx, peer, name)
    }
    return nil
}

func (p propagate) CheckSender(ctx context.Context, peer Peer, addr string) error {
    if sc, ok := p.inner.(SenderChecker); ok {
        return sc.CheckSender(ctx, peer, addr)
    }
    return nil
}

func (p propagate) CheckRecipient(ctx context.Context, peer Peer, addr string) error {
    if rc, ok := p.inner.(RecipientChecker); ok {
        return rc.CheckRecipient(ctx, peer, addr)
    }
    return nil
}

func (p propagate) Authenticate(ctx context.Context, peer Peer, username, password string) error {
    if a, ok := p.inner.(Authenticator); ok {
        return a.Authenticate(ctx, peer, username, password)
    }
    return nil
}

// Propagate wraps outer so that optional interfaces from inner show
// through. Use this in middleware that doesn't participate in checkers.
func Propagate(outer, inner Handler) Handler {
    return propagate{Handler: outer, inner: inner}
}
```

The `Chain` function uses `Propagate` automatically:

```go
func Chain(h Handler, mw ...Middleware) Handler {
    for _, m := range mw {
        inner := h
        h = m(h)
        // If the middleware wrapper doesn't implement an optional
        // interface but the inner handler does, propagate it.
        h = Propagate(h, inner)
    }
    return h
}
```

This means middleware that is unaware of checkers (like `Logging`) still lets the inner handler's `CheckConnection` etc. be discovered by the server.

### Writing a handler that checks everything

A handler that cares about the full SMTP lifecycle implements the interfaces it needs:

```go
// Mailbox is a handler that validates recipients against a local user database
// and delivers to Maildir.
type Mailbox struct {
    Domain  string
    UserDB  UserLookup
    SpoolDir string
}

func (m *Mailbox) CheckRecipient(ctx context.Context, peer Peer, addr string) error {
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

No need to wire up a separate `RecipientChecker` function field -- the handler carries its own validation.

### Writing middleware that participates in a checker

Middleware can also implement optional interfaces. For example, a rate limiter that rejects connections:

```go
type RateLimiter struct {
    limiter *rate.Limiter
    next    smtpd.Handler
}

func RateLimit(rps float64, burst int) smtpd.Middleware {
    lim := rate.NewLimiter(rate.Limit(rps), burst)
    return func(next smtpd.Handler) smtpd.Handler {
        return &RateLimiter{limiter: lim, next: next}
    }
}

func (r *RateLimiter) CheckConnection(ctx context.Context, peer smtpd.Peer) error {
    if !r.limiter.Allow() {
        return smtpd.Error{Code: 421, Message: "Too many connections, try again later"}
    }
    // Also call inner handler's CheckConnection if it has one.
    if cc, ok := r.next.(smtpd.ConnectionChecker); ok {
        return cc.CheckConnection(ctx, peer)
    }
    return nil
}

func (r *RateLimiter) ServeSMTP(ctx context.Context, env smtpd.Envelope) error {
    return r.next.ServeSMTP(ctx, env)
}
```

Because `RateLimiter` implements `ConnectionChecker` itself, `Chain` sees it directly -- no propagation needed for that interface. Other interfaces still propagate from the inner handler.

### Writing middleware that overrides a checker

An SPF middleware can replace the inner handler's `SenderChecker` entirely:

```go
type SPFChecker struct {
    next smtpd.Handler
}

func SPF() smtpd.Middleware {
    return func(next smtpd.Handler) smtpd.Handler {
        return &SPFChecker{next: next}
    }
}

func (s *SPFChecker) CheckSender(ctx context.Context, peer smtpd.Peer, addr string) error {
    result := spf.Check(peer.Addr, addr)
    if result == spf.Fail {
        return smtpd.Error{Code: 550, Message: "SPF check failed"}
    }
    // Optionally chain to inner:
    if sc, ok := s.next.(smtpd.SenderChecker); ok {
        return sc.CheckSender(ctx, peer, addr)
    }
    return nil
}

func (s *SPFChecker) ServeSMTP(ctx context.Context, env smtpd.Envelope) error {
    return s.next.ServeSMTP(ctx, env)
}
```

Because `SPFChecker` implements `SenderChecker`, `Propagate` won't override it -- the outermost implementation wins.

### LDAP auth middleware

```go
type LDAPAuth struct {
    pool *ldap.ConnPool
    next smtpd.Handler
}

func LDAPAuthenticate(pool *ldap.ConnPool) smtpd.Middleware {
    return func(next smtpd.Handler) smtpd.Handler {
        return &LDAPAuth{pool: pool, next: next}
    }
}

func (a *LDAPAuth) Authenticate(ctx context.Context, peer smtpd.Peer, user, pass string) error {
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

func (a *LDAPAuth) ServeSMTP(ctx context.Context, env smtpd.Envelope) error {
    return a.next.ServeSMTP(ctx, env)
}
```

### Full composition example

```go
srv := &smtpd.Server{
    Hostname:  "mx.example.com",
    TLSConfig: tlsConfig,
    ForceTLS:  true,
    Logger:    slog.Default(),
    Handler: smtpd.Chain(
        &Mailbox{Domain: "example.com", UserDB: db, SpoolDir: "/var/spool/mail"},
        smtpd.Logging(slog.Default()),      // just logs, propagates all checkers from Mailbox
        SPF(),                               // adds SenderChecker, propagates others
        LDAPAuthenticate(ldapPool),          // adds Authenticator, propagates others
        RateLimit(10, 50),                   // adds ConnectionChecker, propagates others
    ),
}
```

The server sees a single `Handler` that also satisfies `ConnectionChecker` (from `RateLimit`), `SenderChecker` (from `SPF`), `RecipientChecker` (from `Mailbox`, propagated through), and `Authenticator` (from `LDAPAuth`). No function fields to wire up.

### Trade-offs

**Advantages:**

- Single extension point -- everything is a `Handler`, composed with `Chain`.
- Checkers travel with the handler they belong to. A `Mailbox` handler that validates recipients carries its own `CheckRecipient` -- no separate wiring.
- Middleware can participate in any SMTP phase, not just `ServeSMTP`. This enables rate limiters, SPF checks, auth backends, etc. as composable middleware.
- The `Server` struct shrinks. No checker fields, no `Authenticator` field.
- Adding a new optional interface in the future is backwards-compatible -- existing handlers that don't implement it are unaffected.

**Disadvantages:**

- `Propagate` is implicit magic. When `Chain` auto-propagates, it's not obvious which handler in the stack is actually handling `CheckRecipient`. Debugging requires understanding the propagation rules.
- Middleware that participates in a checker *and* wants to chain to the inner handler's checker must do so explicitly (calling `s.next.(SenderChecker)` etc.). Forgetting this silently drops the inner check.
- Type switches on the outermost handler only find one implementation per interface. If two middleware in the chain both implement `ConnectionChecker`, only the outermost one is visible -- it must explicitly delegate to the inner one. This is the same as `net/http` response writer interfaces (`http.Flusher`, `http.Hijacker`), but it's a known source of subtle bugs there too.
- Plain function handlers (`HandlerFunc`) can never implement optional interfaces. Users who want a simple function *and* a checker must either use a struct or use the function fields on `Server` (which this design removes).

**Hybrid option:** keep the function fields on `Server` as a fallback. The server checks the handler's optional interfaces first, and only falls back to the function fields if the interface isn't satisfied. This gives simple setups an easy path while enabling the full middleware model for complex ones:

```go
// Simple -- function fields, no middleware:
srv := &smtpd.Server{
    Handler:          smtpd.HandlerFunc(deliver),
    RecipientChecker: func(ctx context.Context, peer smtpd.Peer, addr string) error {
        if !validDomain(addr) {
            return smtpd.Error{Code: 550, Message: "Invalid domain"}
        }
        return nil
    },
}

// Advanced -- everything in the handler chain:
srv := &smtpd.Server{
    Handler: smtpd.Chain(mailbox, SPF(), RateLimit(10, 50)),
}
```
