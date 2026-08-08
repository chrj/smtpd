# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- `middleware.Greylist` no longer reads the whole map on every `RCPT TO`. The
  sweep for expired entries ran on each check, under the lock, so each check
  cost as much as the map was large. At 20000 entries a check took 271µs. It
  now takes 156ns, and the cost no longer grows with the map.

  The sweep runs once a minute, and as soon as the map reaches the cap.
  Whether a triple is past the TTL is read at the check itself, so the answer
  does not depend on when the sweep runs.

### Security

- `middleware.Greylist` holds at most 100000 triples and drops the oldest at
  that point. The map had no bound, so a client that sent many different
  triples made the server hold all of them until the 24 hour TTL removed them.
  `WithGreylistMaxEntries` sets another cap.

- The credentials of an `AUTH` command no longer go to the log. At the `DEBUG`
  level the server writes every line it receives, and the inline forms of
  `AUTH` carry the credentials on that line:

  ```
  line="AUTH PLAIN AGh1bnRlcjJ1c2VyAHN1cDNyczNjcjN0"
  ```

  Base64 is not protection, so anybody who read the log had the password. The
  server now keeps the verb and the mechanism, and replaces the rest with
  `[redacted]`.

  Read your logs if you run with `DEBUG` and accept `AUTH`. Passwords in them
  must be changed.

### Added

- `PanicError` records a panic from a `Handler` or a middleware hook. `Value`
  holds the value given to `panic`, and `Stack` holds the stack trace. The
  `Disconnect` hooks receive it through their `err` argument.

### Changed

- A panic in a `Handler` or a middleware hook no longer stops the process. The
  server writes the panic and the stack trace to the log at the `ERROR` level,
  replies `421`, and closes that connection. Other sessions continue. A panic
  in a `Disconnect` hook is contained the same way.

  A server that must stop on a panic has to do the check in its own handler.

- A panic in `BaseContext` stops `Serve` with a `PanicError`, instead of
  stopping the process. The hook runs once, before the accept loop.

- A panic in `ConnContext` drops that connection only. The server writes the
  panic to the log and keeps accepting. A `ConnContext` that returns a nil
  context still stops `Serve`, because that fault repeats on every connection.

## [2.2.0] - 2026-08-06

### Added

- `github.com/chrj/smtpd/v2/smtptest`: test servers that run on the loopback
  interface, for end-to-end tests of an SMTP client. The package follows
  `net/http/httptest`.
  - `NewServer`, `NewSTARTTLSServer` and `NewTLSServer` cover the three
    transports. `NewUnstartedServer` gives a server that a test configures
    first.
  - `Recorder` is an `smtpd.Handler` that keeps the messages that the client
    sent. It restores `env.Data`, so it also works as a middleware stage in
    front of a delivery handler.
  - `Server.Dial` returns a `*smtp.Client` that already completed the
    handshake of the transport. `Addr`, `Host` and `Port` give the address in
    the three forms that a client needs.
  - `ClientTLSConfig`, `Certificate`, `CertPEM` and `KeyPEM` pass the
    certificate of the server to the client under test.
  - `Send` runs one transaction and returns the reply of the server. `Cmd`
    sends one raw command, such as XCLIENT or PROXY. Both take an
    `*smtp.Client`, so a test of an SMTP server of your own can use them
    against a server that the package did not start.

## [2.1.2] - 2026-07-25

A test for `AllowInsecureAuth` on a connection without TLS. The library did
not change.

## [2.1.1] - 2026-07-25

### Fixed

- `LoggerFromContext` added one phase attribute for every phase that a
  session passed. A log record from a handler carried the whole list. Each
  phase now tags a fresh logger, so a record names only the phase that
  produced it.

## [2.1.0] - 2026-07-25

### Added

- `Server.AllowInsecureAuth` permits AUTH on a connection that did not
  negotiate TLS. It is false by default, because PLAIN and LOGIN both send
  the password in the clear. Set it only when the transport is trusted by
  other means, such as a listener on the loopback interface. Fixes #19.

## [2.0.0] - 2026-07-05

Ground-up rewrite of the v1 API. The SMTP wire behavior is unchanged; the Go
programming model is new. Import as `github.com/chrj/smtpd/v2`. See the
[migration guide](README.md#migration-guide---v1--v2) for a field-by-field
walkthrough.

### Added

- `context.Context` threaded through every hook and handler, cancelled when the
  connection closes or `Shutdown` is called.
- Composable `Middleware` value with optional per-phase hook fields
  (`CheckConnection`, `CheckHelo`, `CheckSender`, `CheckRecipient`,
  `Authenticate`, `Handler`, `Reset`, `Disconnect`), registered via `Server.Use`.
- Streaming `Envelope.Data` as an `io.ReadCloser` — no forced buffering.
- Structured logging via `*slog.Logger` on `Server.Logger`, with a
  per-connection logger exposed through `LoggerFromContext`.
- `SenderFromContext` for retrieving the current MAIL FROM in later stages.
- Context-aware `Shutdown(ctx)` that drains in-flight sessions.
- `Reset` and `Disconnect` middleware hooks.
- Ready-made middleware in `github.com/chrj/smtpd/v2/middleware`: SPF, RBL,
  greylisting, per-IP rate limiting, `RequireAuth`/`RequireAuthAt`, `RequireTLS`,
  and lifting adapters (`CheckConnection`, `CheckSender`, `CheckData`, ...).

### Changed

- `Handler` is now `func(ctx, peer, *Envelope) (ctx, error)` — context-aware,
  takes an `*Envelope` so it can replace `Data`, and returns the context back.
- The `Server` checker fields (`ConnectionChecker`, `HeloChecker`,
  `SenderChecker`, `RecipientChecker`, `Authenticator`) are replaced by
  middleware registered with `Server.Use`.
- `AuthOptional` is replaced by opt-in `middleware.RequireAuth` /
  `middleware.RequireAuthAt`; registering an authenticator no longer implicitly
  enforces AUTH.
- `ForceTLS` is replaced by `middleware.RequireTLS`.
- `ProtocolLogger` (`*log.Logger`) is replaced by `Logger` (`*slog.Logger`).
- `Shutdown(wait bool)` + `Wait()` are replaced by `Shutdown(ctx)`.
- `smtpd.Error` renders as `"{Code} {Message}"` and works with
  `errors.Is`/`errors.As`.
- A failed STARTTLS handshake now closes the connection (v1 continued in
  cleartext); the failure is reported through the `Disconnect` hook's `err`.

### Removed

- `Envelope.AddReceivedLine` — inject the `Received:` line from a middleware
  `Handler` and replace `env.Data` instead.
- `Peer.Password` — the password is still passed to the `Authenticate` hook but
  is no longer stored on `Peer`.

[Unreleased]: https://github.com/chrj/smtpd/compare/v2.2.0...main
[2.2.0]: https://github.com/chrj/smtpd/releases/tag/v2.2.0
[2.1.2]: https://github.com/chrj/smtpd/releases/tag/v2.1.2
[2.1.1]: https://github.com/chrj/smtpd/releases/tag/v2.1.1
[2.1.0]: https://github.com/chrj/smtpd/releases/tag/v2.1.0
[2.0.0]: https://github.com/chrj/smtpd/releases/tag/v2.0.0
