# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

[2.0.0]: https://github.com/chrj/smtpd/releases/tag/v2.0.0
