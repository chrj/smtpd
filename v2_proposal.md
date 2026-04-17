# smtpd v2 API

## Goals

1. **Context support** -- per-connection `context.Context` threaded through every callback and handler. Checkers return `(context.Context, error)` so middleware can inject values (auth tokens, trace IDs) into the context for downstream use.
2. **Streaming data** -- `Envelope.Data` as `io.ReadCloser` instead of `[]byte`.
3. **Handler/middleware architecture** -- composable, inspired by `net/http`. Handlers and middleware can participate in any SMTP phase (connection, HELO, sender, recipient, auth, message delivery) through optional interfaces. The server discovers checker implementations via type assertions when `Handler()` and `Use()` are called.
4. **Structured logging** -- `*slog.Logger` replaces `*log.Logger`. The server stores a per-connection logger in the context, retrievable via `LoggerFromContext`.
5. **Idiomatic shutdown** -- `Shutdown(ctx)` follows `net/http.Server`.

Non-goals: changing the wire protocol, adding new SMTP extensions, or introducing dependency injection frameworks.

---

## Core Types

### Handler

Follows the `net/http.Handler` pattern: an interface with a single method, plus a func adapter. `ServeSMTP` is the only required method -- all other SMTP phases are opt-in through separate interfaces.

```go
// Handler processes a received message.
type Handler interface {
    ServeSMTP(ctx context.Context, peer Peer, env Envelope) error
}

// HandlerFunc adapts a plain function to the Handler interface.
type HandlerFunc func(ctx context.Context, peer Peer, env Envelope) error

func (f HandlerFunc) ServeSMTP(ctx context.Context, peer Peer, env Envelope) error {
    return f(ctx, peer, env)
}
```

### Optional Checker Interfaces

A `Handler` (or the struct returned by a middleware) can implement any combination of these interfaces to participate in earlier SMTP phases. The server discovers them via type assertion when `Handler()` or `Use()` is called and collects them into per-phase checker lists.

All checkers return `(context.Context, error)` so they can thread values through the context. The updated context is propagated to subsequent checkers and ultimately to `ServeSMTP`.

```go
type ConnectionChecker interface {
    CheckConnection(ctx context.Context, peer Peer) (context.Context, error)
}

type HeloChecker interface {
    CheckHelo(ctx context.Context, peer Peer, name string) (context.Context, error)
}

type SenderChecker interface {
    CheckSender(ctx context.Context, peer Peer, addr string) (context.Context, error)
}

type RecipientChecker interface {
    CheckRecipient(ctx context.Context, peer Peer, addr string) (context.Context, error)
}

type Authenticator interface {
    Authenticate(ctx context.Context, peer Peer, username, password string) (context.Context, error)
}
```

These are not part of `Handler` -- they are independent interfaces. A type can implement `Handler` alone, `Handler` plus one or more checkers, or (in the future, if needed) just checkers. But `Handler` is always required to participate in the `ServeSMTP` chain.

### Envelope

```go
// Envelope holds a message. Data is a streaming body that the handler
// must fully read and Close. The server drains and closes it on return
// from the handler regardless, to keep the SMTP protocol in sync.
type Envelope struct {
    Sender     string
    Recipients []string
    Data       io.ReadCloser
}
```

`Peer` is passed as a separate argument to `ServeSMTP`, not embedded in `Envelope`. This reflects that `Peer` is connection-scoped state (progressively populated across HELO, AUTH, STARTTLS) while `Envelope` is per-message transaction state.

`Data` is an `io.ReadCloser` backed by the connection. The server wraps the SMTP dot-stream in a `dataReader` that enforces `MaxMessageSize` and handles protocol re-sync. The server always drains and closes the reader after `ServeSMTP` returns, so the handler need not close it -- but may do so to release resources early. Callers that need `[]byte` opt in with `io.ReadAll`. Callers that forward (relay, pipe to command) can stream without buffering.

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

The `Error()` method includes the SMTP status code for debugging and logging. When an `Error` is returned from a checker or handler, the server inspects the `Code` field to format the SMTP wire response. Non-`Error` errors produce a `502` response.

---

## Middleware and Composition

```go
// Middleware wraps a Handler.
type Middleware func(next Handler) Handler
```

### Server.Handler() and Server.Use()

The server provides two methods for composing the handler chain:

```go
// Handler sets the inner handler. Must be called before Use().
func (srv *Server) Handler(h Handler)

// Use wraps the current handler with a middleware. The server re-scans
// the resulting handler for optional checker interfaces after each call.
func (srv *Server) Use(m Middleware)
```

`Handler()` sets the innermost handler. `Use()` wraps it with middleware (outermost applied last). After each call, the server type-asserts the resulting handler to discover which optional checker interfaces it implements, and appends participants to per-phase checker lists.

At runtime, when the server receives (e.g.) `RCPT TO`, it iterates the `recipientCheckers` list and calls each participant's `CheckRecipient` in order. If any returns an error, the command is rejected. The updated context is threaded through.

```go
func (srv *Server) checkRecipient(ctx context.Context, peer Peer, addr string) (context.Context, error) {
    var err error
    for _, c := range srv.recipientCheckers {
        ctx, err = c.CheckRecipient(ctx, peer, addr)
        if err != nil {
            return ctx, err
        }
    }
    return ctx, nil
}
```

### Example middleware

```go
// Logging logs every message transaction. Pure ServeSMTP middleware --
// implements no checker interfaces, so it is invisible to checker chains.
func Logging(logger *slog.Logger) Middleware {
    return func(next Handler) Handler {
        return HandlerFunc(func(ctx context.Context, peer Peer, env Envelope) error {
            start := time.Now()
            err := next.ServeSMTP(ctx, peer, env)
            logger.InfoContext(ctx, "message handled",
                "sender", env.Sender,
                "recipients", len(env.Recipients),
                "peer", peer.Addr,
                "duration", time.Since(start),
                "error", err,
            )
            return err
        })
    }
}

// RequireTLS rejects messages from unencrypted connections.
func RequireTLS() Middleware {
    return func(next Handler) Handler {
        return HandlerFunc(func(ctx context.Context, peer Peer, env Envelope) error {
            if peer.TLS == nil {
                return Error{Code: 530, Message: "Must issue STARTTLS first"}
            }
            return next.ServeSMTP(ctx, peer, env)
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

    // Extensions
    EnableXCLIENT       bool
    EnableProxyProtocol bool

    // TLS
    TLSConfig *tls.Config

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

The handler is set via `srv.Handler(h)` and middleware applied via `srv.Use(m)`. The server keeps the composed handler and per-phase checker lists as private fields. A nil handler (no `Handler()` call) results in a no-op server that accepts and discards messages.

### Lifecycle

```go
func (srv *Server) ListenAndServe(addr string) error
func (srv *Server) Serve(l net.Listener) error
func (srv *Server) Shutdown(ctx context.Context) error
func (srv *Server) Address() net.Addr
```

`Shutdown` replaces the v1 `Shutdown(wait bool)` / `Wait()` pair. It stops accepting new connections, cancels every live session's context, and waits for in-flight sessions to finish. If the context deadline expires before sessions exit, it force-closes all live connections and returns `ctx.Err()`.

```go
ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
defer cancel()
if err := srv.Shutdown(ctx); err != nil {
    // connections did not drain in time
}
```

### Connection limiting

`MaxConnections` is enforced via a buffered channel semaphore. When all slots are taken, new connections are immediately rejected with `421 Too busy. Try again later.` and closed.

---

## Context Flow

Each accepted connection gets its own `context.Context` derived from `BaseContext` (or `context.Background()`), optionally modified by `ConnContext`. This context is:

- Cancelled when the connection closes (for any reason) or when `Shutdown` is called.
- Passed to every checker and to `Handler.ServeSMTP`.
- Usable with `context.WithValue` for request-scoped data (trace IDs, auth tokens).
- Carries a per-connection `*slog.Logger` with the remote address pre-attached.

### Context helpers

```go
// LoggerFromContext returns the logger associated with the context.
// If no logger is found, it returns a logger with slog.DiscardHandler.
func LoggerFromContext(ctx context.Context) *slog.Logger
```

---

## Streaming Data

`Envelope.Data` is an `io.ReadCloser` valid only for the duration of the `ServeSMTP` call. The server enforces `MaxMessageSize` at the protocol level via a `dataReader` wrapper. If the message exceeds the limit, the reader returns `errMessageTooLarge` and the server responds with `552`. The server always drains and closes the reader after the handler returns, keeping the SMTP protocol stream in sync.

### Relay (zero-copy)

```go
smtpd.HandlerFunc(func(ctx context.Context, peer smtpd.Peer, env smtpd.Envelope) error {
    return relay.Send(ctx, env.Sender, env.Recipients, env.Data)
})
```

### DKIM signing (needs bytes)

```go
smtpd.HandlerFunc(func(ctx context.Context, peer smtpd.Peer, env smtpd.Envelope) error {
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
smtpd.HandlerFunc(func(ctx context.Context, peer smtpd.Peer, env smtpd.Envelope) error {
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

The server creates a per-connection logger with `slog.String("peer", remoteAddr)` pre-attached and stores it in the context. Middleware can retrieve it via `LoggerFromContext(ctx)`.

The server emits structured log records at well-defined points:

| Level | Event | Attributes |
|-------|-------|------------|
| Debug | command received | `line`, `peer` |
| Debug | response sent | `code`, `message`, `peer` |
| Warn  | AUTH mechanism unknown | `mechanism`, `peer` |
| Error | TLS handshake failed | `err`, `peer` |

```go
srv := &smtpd.Server{
    Logger: slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
        Level: slog.LevelDebug,
    })),
}
```

Passing `nil` silences all server-internal logging (the default, same as v1).

---

## Writing Handlers and Middleware

### A handler with checkers

A handler implements the optional interfaces it cares about. The server calls every registered checker in order for each phase.

```go
// Mailbox validates recipients against a local user database
// and delivers to Maildir.
type Mailbox struct {
    Domain   string
    UserDB   UserLookup
    SpoolDir string
}

func (m *Mailbox) CheckRecipient(ctx context.Context, peer smtpd.Peer, addr string) (context.Context, error) {
    local, domain, _ := strings.Cut(addr, "@")
    if domain != m.Domain {
        return ctx, smtpd.Error{Code: 550, Message: "No such domain"}
    }
    if !m.UserDB.Exists(local) {
        return ctx, smtpd.Error{Code: 550, Message: "No such user"}
    }
    return ctx, nil
}

func (m *Mailbox) ServeSMTP(ctx context.Context, peer smtpd.Peer, env smtpd.Envelope) error {
    defer env.Data.Close()
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

Middleware returns a struct that implements `Handler` and whatever optional interfaces it participates in:

```go
type rateLimiter struct {
    limiters *keyrate.Limiters[string]
    next     smtpd.Handler
}

func IPAddressRateLimit(rps float64, burst int) smtpd.Middleware {
    lims := keyrate.New[string](rate.Limit(rps), burst, keyrate.WithAutoEvict())
    return func(next smtpd.Handler) smtpd.Handler {
        return &rateLimiter{limiters: lims, next: next}
    }
}

func (r *rateLimiter) CheckConnection(ctx context.Context, peer smtpd.Peer) (context.Context, error) {
    tcpAddr, ok := peer.Addr.(*net.TCPAddr)
    if !ok {
        return ctx, nil
    }
    if !r.limiters.Allow(tcpAddr.IP.String()) {
        return ctx, smtpd.Error{Code: 450, Message: "rate-limited, try again later"}
    }
    return ctx, nil
}

func (r *rateLimiter) ServeSMTP(ctx context.Context, peer smtpd.Peer, env smtpd.Envelope) error {
    return r.next.ServeSMTP(ctx, peer, env)
}
```

### SPF sender check

```go
type spfMiddleware struct {
    resolver spf.DNSResolver
    stage    Stage
    next     smtpd.Handler
}

func SPF(opts ...SPFOption) smtpd.Middleware {
    return func(next smtpd.Handler) smtpd.Handler {
        s := &spfMiddleware{stage: OnMailFrom, next: next}
        for _, opt := range opts {
            opt(s)
        }
        return s
    }
}

func (s *spfMiddleware) CheckSender(ctx context.Context, peer smtpd.Peer, addr string) (context.Context, error) {
    if s.stage == OnMailFrom {
        return ctx, s.check(ctx, peer, peer.HeloName, addr)
    }
    return ctx, nil
}

func (s *spfMiddleware) ServeSMTP(ctx context.Context, peer smtpd.Peer, env smtpd.Envelope) error {
    if s.stage == OnData {
        if err := s.check(ctx, peer, peer.HeloName, env.Sender); err != nil {
            return err
        }
    }
    return s.next.ServeSMTP(ctx, peer, env)
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

func (a *ldapAuth) Authenticate(ctx context.Context, peer smtpd.Peer, user, pass string) (context.Context, error) {
    conn, err := a.pool.Get(ctx)
    if err != nil {
        return ctx, smtpd.Error{Code: 454, Message: "Temporary auth failure"}
    }
    defer conn.Close()
    if err := conn.Bind(user, pass); err != nil {
        return ctx, smtpd.Error{Code: 535, Message: "Authentication failed"}
    }
    return ctx, nil
}

func (a *ldapAuth) ServeSMTP(ctx context.Context, peer smtpd.Peer, env smtpd.Envelope) error {
    return a.next.ServeSMTP(ctx, peer, env)
}
```

---

## Example: Full Composition

```go
srv := &smtpd.Server{
    Hostname:  "mx.example.com",
    TLSConfig: tlsConfig,
    Logger:    slog.Default(),
}

srv.Handler(&Mailbox{Domain: "example.com", UserDB: db, SpoolDir: "/var/spool/mail"})
srv.Use(Logging(slog.Default()))            // no checkers, skipped in all checker chains
srv.Use(middleware.RequireTLS())            // reject MAIL FROM until STARTTLS succeeds
srv.Use(SPF())                              // participates in SenderChecker chain
srv.Use(LDAPAuthenticate(ldapPool))         // participates in Authenticator chain
srv.Use(IPAddressRateLimit(10, 50))         // participates in ConnectionChecker chain
```

The server discovers checker interfaces via type assertion on each `Use()` call and builds per-phase checker lists. `Handler()` must be called before `Use()`.

## Example: DKIM Proxy

```go
func main() {
    logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

    srv := &smtpd.Server{
        Hostname:  "mx.example.com",
        TLSConfig: tlsConfig,
        Logger:    logger,
    }
    srv.Use(middleware.RequireTLS())

    srv.Handler(smtpd.HandlerFunc(func(ctx context.Context, peer smtpd.Peer, env smtpd.Envelope) error {
        defer env.Data.Close()
        data, err := io.ReadAll(env.Data)
        if err != nil {
            return err
        }
        signed, err := dkim.Sign(data, selector, privateKey)
        if err != nil {
            return err
        }
        return smtp.SendMail(relay, auth, env.Sender, env.Recipients, signed)
    }))
    srv.Use(Logging(logger))

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
| `Handler func(Peer, Envelope) error` | `Handler interface { ServeSMTP(context.Context, Peer, Envelope) error }` | Wrap with `HandlerFunc` adapter |
| `Envelope.Data []byte` | `Envelope.Data io.ReadCloser` | Add `io.ReadAll(env.Data)` where needed |
| `Peer.Password` field | Removed | Use context in `Authenticator` to pass auth state downstream |
| Checker func fields on `Server` | Optional interfaces on `Handler` | Implement interface on handler struct, register via `Handler()`/`Use()` |
| `Shutdown(wait bool)` + `Wait()` | `Shutdown(ctx context.Context) error` | Use context with timeout |
| `ProtocolLogger *log.Logger` | `Logger *slog.Logger` | Switch to `slog` |

---

## What Stays the Same

- Package name: `smtpd`
- Struct literal construction: `&smtpd.Server{...}` -- no functional options, no builder
- `ListenAndServe` / `Serve` surface
- `Error{Code, Message}` for SMTP protocol errors
- `Peer` struct (minus `Password`), passed as a separate argument
- `Protocol` type (`SMTP` / `ESMTP`)
- Configuration fields on `Server` (timeouts, limits, TLS, extensions)

---

## Testing

The v2 API is designed so that handlers, checkers, and middleware can be tested as plain Go values without starting a server or opening a TCP connection.

### Unit testing a handler

`ServeSMTP` takes a `context.Context`, `Peer`, and `Envelope` -- all trivial to construct:

```go
func TestMailbox_ServeSMTP(t *testing.T) {
    mb := &Mailbox{Domain: "example.com", UserDB: memDB, SpoolDir: t.TempDir()}

    peer := smtpd.Peer{Addr: &net.TCPAddr{IP: net.ParseIP("127.0.0.1")}}
    env := smtpd.Envelope{
        Sender:     "alice@other.com",
        Recipients: []string{"bob@example.com"},
        Data:       io.NopCloser(strings.NewReader("Subject: hi\r\n\r\nHello.\r\n")),
    }

    if err := mb.ServeSMTP(context.Background(), peer, env); err != nil {
        t.Fatal(err)
    }

    // assert file was written to spool...
}
```

No test server, no `net.Pipe`, no SMTP client library.

### Unit testing a checker

Checkers are just methods on the same struct. Test them directly:

```go
func TestMailbox_CheckRecipient(t *testing.T) {
    mb := &Mailbox{Domain: "example.com", UserDB: memDB}
    peer := smtpd.Peer{Addr: &net.TCPAddr{IP: net.ParseIP("127.0.0.1")}}

    // Valid recipient.
    _, err := mb.CheckRecipient(context.Background(), peer, "bob@example.com")
    if err != nil {
        t.Fatalf("unexpected error: %v", err)
    }

    // Wrong domain.
    _, err = mb.CheckRecipient(context.Background(), peer, "bob@other.com")
    var smtpErr smtpd.Error
    if !errors.As(err, &smtpErr) || smtpErr.Code != 550 {
        t.Fatalf("expected 550, got %v", err)
    }

    // Unknown user.
    _, err = mb.CheckRecipient(context.Background(), peer, "nobody@example.com")
    if !errors.As(err, &smtpErr) || smtpErr.Code != 550 {
        t.Fatalf("expected 550, got %v", err)
    }
}
```

### Unit testing middleware

Middleware wraps a `Handler`, so tests supply a stub inner handler:

```go
func TestRateLimit_CheckConnection(t *testing.T) {
    mw := IPAddressRateLimit(1, 1)
    inner := smtpd.HandlerFunc(func(ctx context.Context, peer smtpd.Peer, env smtpd.Envelope) error {
        return nil
    })
    h := mw(inner)

    peer := smtpd.Peer{Addr: &net.TCPAddr{IP: net.ParseIP("10.0.0.1")}}
    cc := h.(smtpd.ConnectionChecker)

    // First call succeeds.
    _, err := cc.CheckConnection(context.Background(), peer)
    if err != nil {
        t.Fatalf("unexpected error: %v", err)
    }

    // Second call (immediate) should be rate-limited.
    _, err = cc.CheckConnection(context.Background(), peer)
    var smtpErr smtpd.Error
    if !errors.As(err, &smtpErr) || smtpErr.Code != 450 {
        t.Fatalf("expected 450, got %v", err)
    }
}
```

### Integration testing with a real server

For tests that need to exercise the SMTP wire protocol (TLS negotiation, pipelining, AUTH handshake, etc.), start a server on a random port and talk to it with `net/smtp` or `net/textproto`:

```go
func TestServer_SMTP(t *testing.T) {
    var gotEnv smtpd.Envelope
    var gotPeer smtpd.Peer

    srv := &smtpd.Server{}
    srv.Handler(smtpd.HandlerFunc(func(ctx context.Context, peer smtpd.Peer, env smtpd.Envelope) error {
        defer env.Data.Close()
        data, _ := io.ReadAll(env.Data)
        gotPeer = peer
        gotEnv = env
        gotEnv.Data = io.NopCloser(bytes.NewReader(data)) // capture for assertion
        return nil
    }))

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

    if gotEnv.Sender != "sender@example.com" {
        t.Fatalf("sender = %q", gotEnv.Sender)
    }
}
```

---

## Design Trade-offs

**Advantages:**

- **Single extension point.** Everything is a `Handler`, composed with `Use()`. No separate function fields to wire up.
- **Checkers travel with the handler they belong to.** A `Mailbox` that validates recipients carries its own `CheckRecipient` -- no separate wiring on `Server`.
- **Context threading.** Checkers return `(context.Context, error)`, enabling middleware to inject per-connection or per-transaction values.
- **All participants run.** Two `ConnectionChecker` middleware both fire, in order. No silent shadowing.
- **Middleware is simpler to write.** Implement your checker method, return ctx and nil or an error.

**Disadvantages:**

- **No short-circuit delegation.** A checker can accept (return nil) or reject (return error). It can't say "skip the remaining checkers."
- **`HandlerFunc` can't carry checkers.** For a function + checkers, you need a struct. This is inherent to the interface approach.
- **All-or-nothing per phase.** If you want a checker to run for some recipients but not others, that logic goes inside the checker itself.
- **Checker discovery on each `Use()`.** Middleware that implements all checker interfaces (for stage-based dispatch) gets added to every checker list, with runtime stage guards as the only filter. This is correct but means the server iterates no-op checkers.

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

**Trade-off:** This adds a second interface for the same SMTP phase. Two code paths (batch vs. sequential) for recipient validation means two paths to test and two paths to get wrong. The return type (`map[string]error`) is also more complex than a simple `error`.

#### Option B: Do nothing

The server already processes pipelined commands in order. The per-recipient overhead is one function call and one DB query. For most backends (in-memory maps, Redis, SQL with connection pooling) this is fast enough. If a handler needs batching, it can implement it internally using `ServeSMTP`, which already receives the full `Envelope` with all accepted recipients.

**Trade-off:** Simplest API, but makes it impossible to reject individual recipients efficiently in the batch case.

#### Recommendation

Option A (`BatchRecipientChecker`) is the only one that solves the actual problem -- rejecting individual recipients efficiently during pipelined RCPT TO. But it's only worth adding if there's real demand. It could be deferred without breaking compatibility, since it's a new optional interface.

### Problem 2: Pipeline-aware responses

Some servers want to know whether a command was pipelined to adjust response behavior (e.g., tarpitting non-pipelined RCPT TO). The server could expose `Pipelined(ctx) bool` by peeking at the read buffer.

**Trade-off:** Cheap to implement (one `bufio.Reader.Buffered() > 0` check), but it's a leaky abstraction. In practice the heuristic works well enough (Postfix uses the same approach), but it's worth documenting the caveat. Trivial to add later.

---

## Open Questions

1. **Multiple AUTH mechanisms** -- v1 supports PLAIN and LOGIN (hardcoded). Should v2 expose a pluggable `AuthMechanism` interface for CRAM-MD5, XOAUTH2, etc.? This adds complexity but covers real-world needs for OAuth-based auth.

2. **`io.ReadCloser` lifetime** -- If the handler spawns a goroutine and returns, the reader becomes invalid. Should the server enforce this with a wrapper that errors after `ServeSMTP` returns, similar to `http.Request.Body` semantics?

3. **Metrics hook** -- Should the server expose a `ConnState` callback (like `net/http.Server.ConnState`) for connection-level metrics, or leave this to middleware? Middleware can observe `ServeSMTP` but not lower-level connection events (accept, TLS upgrade, close).
