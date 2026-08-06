# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
