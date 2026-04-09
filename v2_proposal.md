# smtpd v2 API Proposal

## Goals

1. **Context support** -- per-connection `context.Context` threaded through every callback and handler.
2. **Streaming data** -- `Envelope.Data` as `io.Reader` instead of `[]byte`.
3. **Handler/middleware architecture** -- composable, inspired by `net/http`. Handlers and middleware can participate in any SMTP phase (connection, HELO, sender, recipient, auth, message delivery) through optional interfaces, resolved at build time into a `Pipeline`.
4. **Structured logging** -- `*slog.Logger` replaces `*log.Logger`.
5. **Idiomatic shutdown** -- `Shutdown(ctx)` follows `net/http.Server`.
6. **Cleaner envelope** -- `Peer` embedded in `Envelope`, not a separate argument.

Non-goals: changing the wire protocol, adding new SMTP extensions, or introducing dependency injection frameworks. The library should remain a single package with zero non-stdlib dependencies.

---

## Core Types

### Handler

Follows the `net/http.Handler` pattern: an interface with a single method, plus a func adapter. `ServeSMTP` is the only required method -- all other SMTP phases are opt-in through separate interfaces.

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

### Optional Checker Interfaces

A `Handler` (or the struct returned by a middleware) can implement any combination of these interfaces to participate in earlier SMTP phases. `Chain` resolves them at build time -- the server never does type switches at runtime.

```go
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

These are not part of `Handler` -- they are independent interfaces. A type can implement `Handler` alone, `Handler` plus one or more checkers, or (in the future, if needed) just checkers. But `Handler` is always required to participate in the `ServeSMTP` chain.

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
    Protocol   Protocol
    ServerName string
    Addr       net.Addr
    TLS        *tls.ConnectionState
}
```

Changed from v1: `Password` is removed. The `Authenticator` interface receives the password directly; there is no reason to carry it on a struct that gets passed to every middleware and handler. If authentication state needs to flow downstream, the `Authenticator` implementation can store it in the context.

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

## Middleware and Chain

```go
// Middleware wraps a Handler.
type Middleware func(Handler) Handler
```

### Pipeline

`Chain` returns a `*Pipeline` -- a concrete type that composes the `ServeSMTP` chain and pre-resolves every optional checker interface into flat call lists. The server interacts with the pipeline directly; no runtime type switches on the hot path.

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

### Chain

`Chain` takes the inner handler and middleware, composes `ServeSMTP` the usual way, then does a single pass to extract checker participants. Order is outermost-first (the last middleware in the list runs first).

```go
func Chain(inner Handler, mw ...Middleware) *Pipeline {
    // Apply middleware innermost-first: mw[0] is outermost.
    // We iterate in reverse so mw[0] wraps everything else.
    h := inner
    wrappers := make([]Handler, len(mw))
    for i := len(mw) - 1; i >= 0; i-- {
        h = mw[i](h)
        wrappers[i] = h // wrappers[0] is the outermost
    }

    // Collect all handler values for checker scanning.
    // Order: outermost middleware first, inner handler last.
    all := make([]Handler, 0, len(mw)+1)
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

### How checkers are resolved

Given this composition:

```go
smtpd.Chain(
    &Mailbox{...},                     // implements RecipientChecker + Handler
    smtpd.Logging(slog.Default()),     // implements Handler only
    SPF(),                             // implements SenderChecker + Handler
    LDAPAuthenticate(ldapPool),        // implements Authenticator + Handler
    RateLimit(10, 50),                 // implements ConnectionChecker + Handler
)
```

`Chain` resolves at build time:

| Checker chain | Participants (outermost first) |
|---|---|
| `connectionCheckers` | `RateLimit` |
| `heloCheckers` | *(empty -- no-op)* |
| `senderCheckers` | `SPF` |
| `recipientCheckers` | `Mailbox` |
| `authenticators` | `LDAPAuthenticate` |

When the server receives `RCPT TO`, it calls `pipeline.CheckRecipient(ctx, peer, addr)`, which calls `Mailbox.CheckRecipient` -- the only participant. No type switches, no delegation, no forgotten `next` calls.

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

### Example middleware

```go
// Logging logs every message transaction. Pure ServeSMTP middleware --
// implements no checker interfaces, so it is invisible to checker chains.
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

    // Handler -- use Chain() to get a *Pipeline with checker support.
    // A plain Handler (e.g. HandlerFunc) works too, but with no checkers.
    // nil = accept and discard.
    Handler Handler

    AuthOptional bool

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
    BaseContext func(net.Listener) context.Context

    // ConnContext optionally specifies a function that modifies the context
    // used for a new connection. The provided ctx is derived from BaseContext
    // and has a per-connection cancel.
    ConnContext func(ctx context.Context, conn net.Conn) context.Context
}
```

Internally, the server checks once (in `Serve`) whether `Handler` implements the optional interfaces:

```go
cc, hasCC := srv.Handler.(ConnectionChecker)
hc, hasHC := srv.Handler.(HeloChecker)
sc, hasSC := srv.Handler.(SenderChecker)
rc, hasRC := srv.Handler.(RecipientChecker)
au, hasAU := srv.Handler.(Authenticator)
```

When `Handler` is a `*Pipeline` (returned by `Chain`), it always satisfies every optional interface -- the pipeline methods iterate their pre-built slices, which may be empty (no-op). When `Handler` is a plain `HandlerFunc`, none of the optional interfaces are satisfied, so all checker phases are no-ops.

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

## Writing Handlers and Middleware

### A handler with checkers

A handler implements the optional interfaces it cares about. It never thinks about `next` for checkers -- the pipeline calls every participant in order.

```go
// Mailbox validates recipients against a local user database
// and delivers to Maildir.
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

No need to wire up a separate checker function -- the handler carries its own recipient validation.

### Middleware with checkers

Middleware returns a struct that implements `Handler` and whatever optional interfaces it participates in. No delegation boilerplate for checkers:

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

### LDAP authentication

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

---

## Example: Full Composition

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

The server sees a single `*Pipeline` that satisfies `Handler`, `ConnectionChecker`, `SenderChecker`, `RecipientChecker`, and `Authenticator`. Each checker chain runs only its participants, in outermost-first order.

## Example: DKIM Proxy

```go
func main() {
    logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

    srv := &smtpd.Server{
        Hostname:  "mx.example.com",
        TLSConfig: tlsConfig,
        ForceTLS:  true,
        Logger:    logger,
        Handler: smtpd.Chain(
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
        ),
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

## Breaking Changes Summary

| v1 | v2 | Migration |
|----|-----|-----------|
| `Handler func(Peer, Envelope) error` | `Handler interface { ServeSMTP(context.Context, Envelope) error }` | Wrap with `HandlerFunc` adapter |
| `Envelope.Data []byte` | `Envelope.Data io.Reader` | Add `io.ReadAll(env.Data)` where needed |
| `Peer` as separate handler arg | `env.Peer` | Access via envelope |
| `Peer.Password` field | Removed | Use context in `Authenticator` to pass auth state downstream |
| Checker func fields on `Server` | Optional interfaces on `Handler` | Implement interface on handler struct, use `Chain` |
| `Shutdown(wait bool)` + `Wait()` | `Shutdown(ctx context.Context) error` | Use context with timeout |
| `ProtocolLogger *log.Logger` | `Logger *slog.Logger` | Switch to `slog` |
| `AddReceivedLine(peer)` | `AddReceivedLine() error` | Peer now in envelope; returns error |

---

## What Stays the Same

- Package name: `smtpd`
- Struct literal construction: `&smtpd.Server{...}` -- no functional options, no builder
- `ListenAndServe` / `Serve` surface
- `Error{Code, Message}` for SMTP protocol errors
- `Peer` struct (minus `Password`)
- `Protocol` type (`SMTP` / `ESMTP`)
- Configuration fields on `Server` (timeouts, limits, TLS, extensions)
- Zero external dependencies

---

## Testing

The v2 API is designed so that handlers, checkers, and middleware can be tested as plain Go values without starting a server or opening a TCP connection.

### Unit testing a handler

`ServeSMTP` takes a `context.Context` and an `Envelope` -- both trivial to construct:

```go
func TestMailbox_ServeSMTP(t *testing.T) {
    mb := &Mailbox{Domain: "example.com", UserDB: memDB, SpoolDir: t.TempDir()}

    env := smtpd.Envelope{
        Peer:       smtpd.Peer{Addr: &net.TCPAddr{IP: net.ParseIP("127.0.0.1")}},
        Sender:     "alice@other.com",
        Recipients: []string{"bob@example.com"},
        Data:       strings.NewReader("Subject: hi\r\n\r\nHello.\r\n"),
    }

    if err := mb.ServeSMTP(context.Background(), env); err != nil {
        t.Fatal(err)
    }

    // assert file was written to spool...
}
```

No test server, no `net.Pipe`, no SMTP client library. The `io.Reader` for `Data` is a `strings.NewReader`.

### Unit testing a checker

Checkers are just methods on the same struct. Test them directly:

```go
func TestMailbox_CheckRecipient(t *testing.T) {
    mb := &Mailbox{Domain: "example.com", UserDB: memDB}
    peer := smtpd.Peer{Addr: &net.TCPAddr{IP: net.ParseIP("127.0.0.1")}}

    // Valid recipient.
    if err := mb.CheckRecipient(context.Background(), peer, "bob@example.com"); err != nil {
        t.Fatalf("unexpected error: %v", err)
    }

    // Wrong domain.
    err := mb.CheckRecipient(context.Background(), peer, "bob@other.com")
    var smtpErr smtpd.Error
    if !errors.As(err, &smtpErr) || smtpErr.Code != 550 {
        t.Fatalf("expected 550, got %v", err)
    }

    // Unknown user.
    err = mb.CheckRecipient(context.Background(), peer, "nobody@example.com")
    if !errors.As(err, &smtpErr) || smtpErr.Code != 550 {
        t.Fatalf("expected 550, got %v", err)
    }
}
```

### Unit testing middleware

Middleware wraps a `Handler`, so tests supply a stub inner handler:

```go
func TestRateLimit_CheckConnection(t *testing.T) {
    // 1 request/sec, burst of 1.
    mw := RateLimit(1, 1)
    inner := smtpd.HandlerFunc(func(ctx context.Context, env smtpd.Envelope) error {
        return nil
    })
    h := mw(inner)

    peer := smtpd.Peer{Addr: &net.TCPAddr{IP: net.ParseIP("10.0.0.1")}}
    cc := h.(smtpd.ConnectionChecker)

    // First call succeeds.
    if err := cc.CheckConnection(context.Background(), peer); err != nil {
        t.Fatalf("unexpected error: %v", err)
    }

    // Second call (immediate) should be rate-limited.
    err := cc.CheckConnection(context.Background(), peer)
    var smtpErr smtpd.Error
    if !errors.As(err, &smtpErr) || smtpErr.Code != 421 {
        t.Fatalf("expected 421, got %v", err)
    }
}
```

### Testing a composed pipeline

`Chain` returns a `*Pipeline` whose checker slices can be exercised directly:

```go
func TestPipeline_Integration(t *testing.T) {
    mb := &Mailbox{Domain: "example.com", UserDB: memDB, SpoolDir: t.TempDir()}

    p := smtpd.Chain(
        mb,
        SPF(),
        RateLimit(100, 100),
    )

    peer := smtpd.Peer{Addr: &net.TCPAddr{IP: net.ParseIP("10.0.0.1")}}

    // Walk through the SMTP phases in order.
    if err := p.CheckConnection(context.Background(), peer); err != nil {
        t.Fatalf("CheckConnection: %v", err)
    }
    if err := p.CheckSender(context.Background(), peer, "alice@other.com"); err != nil {
        t.Fatalf("CheckSender: %v", err)
    }
    if err := p.CheckRecipient(context.Background(), peer, "bob@example.com"); err != nil {
        t.Fatalf("CheckRecipient: %v", err)
    }

    env := smtpd.Envelope{
        Peer:       peer,
        Sender:     "alice@other.com",
        Recipients: []string{"bob@example.com"},
        Data:       strings.NewReader("Subject: test\r\n\r\nBody.\r\n"),
    }
    if err := p.ServeSMTP(context.Background(), env); err != nil {
        t.Fatalf("ServeSMTP: %v", err)
    }
}
```

This exercises the full checker pipeline and delivery path without any network I/O.

### Integration testing with a real server

For tests that need to exercise the SMTP wire protocol (TLS negotiation, pipelining, AUTH handshake, etc.), start a server on a random port and talk to it with `net/smtp` or `net/textproto`:

```go
func TestServer_SMTP(t *testing.T) {
    var got smtpd.Envelope
    srv := &smtpd.Server{
        Handler: smtpd.Chain(
            smtpd.HandlerFunc(func(ctx context.Context, env smtpd.Envelope) error {
                data, _ := io.ReadAll(env.Data)
                got = env
                got.Data = bytes.NewReader(data) // capture for assertion
                return nil
            }),
        ),
    }

    ln, err := net.Listen("tcp", "127.0.0.1:0")
    if err != nil {
        t.Fatal(err)
    }

    go srv.Serve(ln)
    defer srv.Shutdown(context.Background())

    // Use stdlib SMTP client.
    c, err := smtp.Dial(ln.Addr().String())
    if err != nil {
        t.Fatal(err)
    }
    defer c.Close()

    c.Mail("sender@example.com")
    c.Rcpt("rcpt@example.com")
    w, _ := c.Data()
    w.Write([]byte("Subject: test\r\n\r\nHello.\r\n"))
    w.Close()
    c.Quit()

    if got.Sender != "sender@example.com" {
        t.Fatalf("sender = %q", got.Sender)
    }
}
```

### Should `smtpd` ship test helpers?

The types are already simple enough that most tests don't need helpers -- `Peer`, `Envelope`, and `context.Background()` are all plain values. But there are a few things the package could provide in a `smtpdtest` sub-package:

```go
package smtpdtest

// NewEnvelope builds an Envelope with sensible defaults for testing.
// Fields can be overridden after construction.
func NewEnvelope(from string, to []string, body string) smtpd.Envelope

// NewPeer builds a Peer with a loopback address and optional overrides.
func NewPeer(opts ...PeerOption) smtpd.Peer

type PeerOption func(*smtpd.Peer)
func WithAddr(addr net.Addr) PeerOption
func WithTLS(state *tls.ConnectionState) PeerOption
func WithUsername(u string) PeerOption

// Server starts a test server on a random port and returns its address
// and a cleanup function. The server is configured with the given handler.
func Server(t testing.TB, handler smtpd.Handler) (addr string, cleanup func())
```

**Arguments for shipping `smtpdtest`:**

- `NewEnvelope` avoids repeating the `strings.NewReader` / `Peer` / `Recipients` boilerplate in every test.
- `Server` helper eliminates the `net.Listen` + `go srv.Serve` + `defer srv.Shutdown` ceremony for integration tests.
- A dedicated sub-package keeps test-only code out of the main API surface.

**Arguments against:**

- The construction boilerplate is ~5 lines. A helper saves little and adds API surface to maintain.
- `PeerOption` functional options are more machinery than the struct they configure. Users can just write `smtpd.Peer{Addr: ...}` directly.
- A `Server` helper is only valuable if it does something beyond the three-line `Listen`/`Serve`/`Shutdown` pattern.

**Recommendation:** ship `smtpdtest.Server` (it handles the `t.Cleanup` registration and avoids the goroutine boilerplate) and `smtpdtest.NewEnvelope` (it sets the `Peer` and wraps the body in a `Reader`). Skip `NewPeer` with functional options -- `smtpd.Peer{}` is a plain struct literal, options add nothing.

---

## Design Trade-offs

**Advantages:**

- **Single extension point.** Everything is a `Handler`, composed with `Chain`. No separate function fields to wire up.
- **Checkers travel with the handler they belong to.** A `Mailbox` that validates recipients carries its own `CheckRecipient` -- no separate wiring on `Server`.
- **Build-time resolution.** `Chain` does a single pass and builds flat slices per checker. Zero runtime type switches per connection.
- **All participants run.** Two `ConnectionChecker` middleware both fire, in order. No silent shadowing, no forgotten `next` delegation.
- **Easy to debug.** Inspect `pipeline.connectionCheckers` to see exactly what runs and in what order.
- **Middleware is simpler to write.** Implement your checker method, return nil or an error. Never think about `next` for checkers.

**Disadvantages:**

- **No short-circuit delegation.** A checker can accept (return nil) or reject (return error). It can't say "skip the remaining checkers." This is usually what you want, but prevents patterns like "override the inner check only if my check passes."
- **`Pipeline` is a concrete type.** `Chain` returns `*Pipeline`, not `Handler`. The server accepts any `Handler`, but only `*Pipeline` gets checker support. A plain `HandlerFunc` has no checkers (clear and predictable, but worth documenting).
- **`HandlerFunc` can't carry checkers.** For a function + checkers, you need a struct. This is inherent to the interface approach.
- **All-or-nothing per phase.** If you want a checker to run for some recipients but not others, that logic goes inside the checker itself -- the pipeline always calls every participant.

---

## Pipelining

RFC 2920 allows clients to send multiple commands without waiting for individual responses. The server must process them in order and respond in order. v1 advertises `PIPELINING` in EHLO and handles it transparently -- the TCP read buffer naturally accumulates pipelined commands, and the server's read loop processes them sequentially. Handlers never know the difference.

The question is whether v2 should expose pipelining state to handlers, and if so, what the API would look like. There are two distinct problems this could solve.

### Problem 1: Batch recipient validation

The most concrete use case. When a client pipelines:

```
MAIL FROM:<alice@example.com>
RCPT TO:<bob@example.com>
RCPT TO:<carol@example.com>
RCPT TO:<dave@example.com>
DATA
```

The current design calls `CheckRecipient` three times, sequentially. If `CheckRecipient` hits a database, that's three round trips when a single `WHERE addr IN (...)` query would do.

#### Option A: BatchRecipientChecker interface

Add an optional interface that receives all pipelined recipients at once:

```go
type BatchRecipientChecker interface {
    CheckRecipients(ctx context.Context, peer Peer, addrs []string) (rejected map[string]error, err error)
}
```

The server collects pipelined `RCPT TO` commands, and if the handler implements `BatchRecipientChecker`, calls it once with the full batch instead of calling `CheckRecipient` per address. The `rejected` map contains per-address errors (sent as individual SMTP responses); `err` is a fatal error that rejects the entire transaction.

```go
func (m *Mailbox) CheckRecipients(ctx context.Context, peer smtpd.Peer, addrs []string) (map[string]error, error) {
    valid, err := m.UserDB.LookupBatch(addrs)
    if err != nil {
        return nil, smtpd.Error{Code: 451, Message: "Temporary failure"}
    }
    rejected := make(map[string]error)
    for _, addr := range addrs {
        if !valid[addr] {
            rejected[addr] = smtpd.Error{Code: 550, Message: "No such user"}
        }
    }
    return rejected, nil
}
```

The pipeline resolves this the same way as other optional interfaces -- `Chain` extracts `BatchRecipientChecker` participants at build time. When the handler implements both `RecipientChecker` and `BatchRecipientChecker`, the server prefers the batch version for pipelined commands and falls back to per-recipient for non-pipelined ones.

**Trade-off:** This adds a second interface for the same SMTP phase. Two code paths (batch vs. sequential) for recipient validation means two paths to test and two paths to get wrong. The return type (`map[string]error`) is also more complex than a simple `error`.

#### Option B: Accumulate-then-flush via the existing interface

Keep `RecipientChecker` as-is but let the server accumulate pipelined `RCPT TO` commands and call `CheckRecipient` for each one in a tight loop (which it already does). The handler batches internally using a per-connection cache stored in the context:

```go
type recipientCache struct {
    mu     sync.Mutex
    lookup func([]string) (map[string]bool, error)
    valid  map[string]bool
}

func (m *Mailbox) CheckRecipient(ctx context.Context, peer smtpd.Peer, addr string) error {
    cache := recipientCacheFromContext(ctx)
    cache.mu.Lock()
    defer cache.mu.Unlock()

    if cache.valid == nil {
        // First call -- could pre-fetch if we had the full list.
        // Without it, we query one at a time.
    }

    if !cache.valid[addr] {
        return smtpd.Error{Code: 550, Message: "No such user"}
    }
    return nil
}
```

**Trade-off:** This works but is awkward. The handler doesn't know which recipients are coming, so it can't pre-fetch. It ends up doing per-address lookups anyway, just with caching. The context-based cache also adds boilerplate that should be the library's job.

#### Option C: Do nothing

The server already processes pipelined commands in order. The per-recipient overhead is one function call and one DB query. For most backends (in-memory maps, Redis, SQL with connection pooling) this is fast enough. If a handler needs batching, it can implement it internally using `ServeSMTP`, which already receives the full `Envelope` with all accepted recipients.

**Trade-off:** Simplest API, but makes it impossible to reject individual recipients efficiently in the batch case. The handler has to accept all recipients first, then decide during `ServeSMTP` -- by which point the client has already sent the DATA payload.

#### Recommendation

Option A (`BatchRecipientChecker`) is the only one that solves the actual problem -- rejecting individual recipients efficiently during pipelined RCPT TO. But it's only worth adding if there's real demand. It could be deferred to a v2.1 without breaking compatibility, since it's a new optional interface.

### Problem 2: Pipeline-aware responses

Some servers want to know whether a command was pipelined to adjust response behavior. For example, a server might want to add a short delay after each non-pipelined `RCPT TO` (tarpitting spammers) but skip the delay for pipelined commands (legitimate clients).

#### Option: Expose pipeline state on context

The server could store a boolean on the connection context indicating whether the current command arrived as part of a pipeline batch:

```go
// Pipelined reports whether the current command was received as part
// of a pipelined batch (i.e., more commands were buffered behind it).
func Pipelined(ctx context.Context) bool
```

The server sets this by peeking at the read buffer after parsing each command -- if there's more data buffered, the command was pipelined.

```go
func (m *tarpitter) CheckRecipient(ctx context.Context, peer smtpd.Peer, addr string) error {
    if !smtpd.Pipelined(ctx) {
        // Non-pipelined: might be a spammer probing one address at a time.
        time.Sleep(2 * time.Second)
    }
    return m.inner.CheckRecipient(ctx, peer, addr)
}
```

**Trade-off:** Cheap to implement (one `bufio.Reader.Buffered() > 0` check), but it's a leaky abstraction -- whether something is "pipelined" depends on TCP buffering and timing, not strictly on client intent. A fast client on a local network might have its commands buffered even without explicit pipelining. In practice this heuristic works well enough (Postfix uses the same approach for `reject_unauth_pipelining`), but it's worth documenting the caveat.

### Summary

| Problem | API change | Complexity | Recommendation |
|---|---|---|---|
| Batch recipient validation | `BatchRecipientChecker` interface | Medium -- new interface, two code paths | Defer to v2.1; solvable without API change for most backends |
| Pipeline-aware responses | `Pipelined(ctx) bool` context helper | Low -- one buffer peek | Include if there's demand; trivial to add later |

Neither requires changes to the core `Handler`/`Middleware`/`Pipeline` architecture. Both are additive optional interfaces or context helpers that can be introduced without breaking existing code.

---

## Open Questions

1. **Multiple AUTH mechanisms** -- v1 supports PLAIN and LOGIN. Should v2 expose a pluggable `AuthMechanism` interface for CRAM-MD5, XOAUTH2, etc.? This adds complexity but covers real-world needs for OAuth-based auth.

2. **`io.Reader` lifetime** -- If the handler spawns a goroutine and returns, the reader becomes invalid. Should the server document this, or enforce it with a wrapper that errors after `ServeSMTP` returns? Suggesting an explicit `io.Reader` wrapper that returns `ErrBodyClosed` after the handler returns, similar to `http.Request.Body` semantics.

3. **Metrics hook** -- Should the server expose a `ConnState` callback (like `net/http.Server.ConnState`) for connection-level metrics, or leave this to middleware? Middleware can observe `ServeSMTP` but not lower-level connection events (accept, TLS upgrade, close).
