# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- `middleware.Greylist` holds the three parts of a triple apart. The key put
  the address of the client, the sender and the recipient in one string with a
  `|` between them, and RFC 5321 gives `|` to the local part of an address, so
  two triples could meet on one entry:

  ```
  sender "a|b@example.org" with recipient "c@example.net"
  sender "a"               with recipient "b@example.org|c@example.net"
  ```

  The second of them read the entry of the first, and it passed a delay that
  it never waited.

- One `AUTH` command can succeed in a session, and every `AUTH` command after
  it gets a `503` reply. RFC 4954 section 4 asks for that. The server took
  every one of them, so a client could take a second identity on a session
  whose earlier commands ran under the first.

  A refused `AUTH` closes no door, and a successful `STARTTLS` opens the
  session to a new one: the handshake drops what the client sent in plain
  text.

  **This changes behavior.** A client that sends `AUTH` twice gets a `503` for
  the second one, where the server authenticated it again before.

### Security

- `Server.MaxAuthAttempts` closes a connection whose `AUTH` commands keep
  failing. RFC 4954 section 6 asks for such a limit: `PLAIN` and `LOGIN` both
  carry a password, and one connection took as many guesses as the client
  cared to send.

  Only a refusal from the `Authenticate` hooks counts, and a successful `AUTH`
  sets the count back to zero.

  **This changes behavior.** The default is 5, so a client that fails five
  times now gets a `421` reply and a closed connection, where it could go on
  before. Set the field to `-1` for the behavior of earlier versions.

### Added

- `middleware.AuthRateLimit` limits the failed authentication attempts of one
  address, across the connections of that address. `Server.MaxAuthAttempts`
  bounds a single connection, which a client that opens a new one for every
  guess would otherwise get around.

  A failed attempt takes a token, and a successful one takes none, so a client
  that always sends the right password never spends the bucket of its address.
  An address with no tokens left gets a `454` reply.

### Fixed

- `Server.Shutdown` closes the connection that the listener gave, and not the
  one that the session holds. `STARTTLS` puts a TLS connection in the place of
  that one, on the goroutine of the session. `Shutdown` read the same field
  from the goroutine of its caller, and nothing ordered the two.

  The TLS connection reads and writes through the connection of the listener,
  so a close of that connection ends an upgraded session as well.

## [2.4.0] - 2026-08-22

### Security

- The `PROXY` command comes first in a session, before every other command,
  and a later one gets a `503` reply. A proxy writes its header before it
  passes on anything of the client, so a `PROXY` command that comes after a
  command comes from the client behind the proxy.

  The server took every `PROXY` command before, and each one wrote `Peer.Addr`
  and ran the `CheckConnection` hooks again. A client behind the proxy could
  therefore take the address of another one, and the greylist, the RBL check
  and the rate limit all read that address.

  **This changes behavior.** A client that sends `PROXY` twice gets a `503`
  for the second one, where it got a greeting before.

### Fixed

- The read of a PROXY protocol header takes `Server.ReadTimeout`. A server
  with `Server.EnableProxyProtocol` holds the greeting back until the header
  arrives, and no deadline stood on that read before. A connection that sent
  nothing therefore held a goroutine of the server for as long as it stayed
  open.

- The readers of an SMTP keyword take the letters of US-ASCII, where they took
  `strings.EqualFold` before. That function folds the case of Unicode, and two
  runes fold to a letter of US-ASCII: U+017F to `s` and U+212A to `k`.

  `BDAT 10 LAſT` therefore ended a message, where `LAſT` is not the marker of
  RFC 3030. The two other readers, the `utf-8` address type of an `ORCPT`
  parameter and the marks of an `XCLIENT` attribute, carry no letter that a
  rune of Unicode folds to today, and they take the same reader now.

- A control character in the message of a reply becomes a space. A middleware
  writes what it knows into the message of a refusal, and some of that comes
  from the client. The user name of an `AUTH` command is one example: the
  session decodes it from base64, so it holds any byte at all.

  A line break inside a reply ended that reply and started a line of the
  client's choosing. The client then read an answer to a command that the
  server never ran.

  A byte at 0x80 and above stays as it is, so a message in UTF-8 arrives
  whole.

### Added

- `Server.EnableProxyProtocol` takes a header of version 2 of the PROXY
  protocol, next to the version 1 that it took before. Version 2 is binary,
  and the first octet of the stream tells the two versions apart.

  The address of the client goes on `Peer.Addr`: a `*net.TCPAddr` for the IPv4
  and the IPv6 families, and a `*net.UnixAddr` for a unix socket. A header of
  the `LOCAL` command, of the unspecified address family, or of the
  unspecified transport protocol carries no address of a client, and the
  addresses of the connection stay.

  A header of version 2 is the first line of the session in the same way as a
  header of version 1, so a `PROXY` command after one gets a `503` reply.

  A header that the server cannot read ends the session without a reply, which
  the specification asks for, and the `Disconnect` hooks read a `ProxyError`
  with the reason. A header that stops in the middle gives the same error, and
  `ProxyError.Err` carries the error of the read. The values that a proxy
  writes after the addresses come off the stream with the rest of the header,
  and the server looks at none of them.

- `Server.LMTP` serves the Local Mail Transfer Protocol of RFC 2033 in the
  place of SMTP. Such a server takes `LHLO` as the greeting and answers `500`
  to `HELO` and to `EHLO`, and `Peer.Protocol` holds `LMTP`.

  `LHLO` carries the semantics of `EHLO`, so the reply lists the extensions of
  the server, and the replies of the session carry a status code.

  The server writes one reply for every recipient of a message, in the order
  that `RCPT TO` added them, which RFC 2033 section 4.2 asks for. The last
  chunk of a `BDAT` transfer ends a message in the same way, so it takes the
  same replies.

  `Envelope.RejectRecipient` records the answer of one recipient, by the index
  of that recipient in `Envelope.Recipients`. A handler that takes the message
  for some of the recipients calls it for each of the rest. A recipient
  without an error of its own gets the reply of the message.

- The server answers the `VRFY` command of RFC 5321. A `Verify` hook in the
  middleware looks the name up and gives back a `Verification` with the
  mailbox of the user, which the client reads in a `250` reply.

  A hook that knows the name to be wrong returns an `Error`, such as `550` for
  a user that the server does not carry, or `553` for a name that more than
  one user answers to. The hooks run in `Use` order, and the first one that
  finds a mailbox or returns an error ends the phase.

  A server without a `Verify` hook answers `252`, which RFC 5321 section 7.3
  asks for. The server answered `500` before, and section 3.5.3 counts that
  answer as a fault: a `500` or a `502` says that the command is not
  implemented. A hook that fails gets a `451` for the same reason, and the
  error goes to the log.

  A server with `Server.EnableSMTPUTF8` takes the `SMTPUTF8` parameter of RFC
  6531 section 3.7.4.2 on the command, and the reply to that one command can
  then carry a mailbox of Unicode. The parameter takes no value, and a value
  on it gets a `501` reply. Without the parameter the reply keeps to US-ASCII:
  a `FullName` of Unicode goes and the mailbox stays, and a `Mailbox` of
  Unicode gets `252 2.6.8`.

- `Server.EnableSMTPUTF8` offers the `SMTPUTF8` extension of RFC 6531 and takes
  its parameter on `MAIL FROM`. Such a transaction carries an address of
  Unicode in UTF-8, in the local part and in the domain, and
  `Envelope.SMTPUTF8` tells the handler that it did.

  The extension is off by default, in the same way as `DSN`. A server that
  offers it says that it carries such a message onward, and the next server on
  the way has to offer the extension as well.

  A server that offers it holds every other transaction to US-ASCII: a
  non-ASCII sender without the parameter gets `550 5.6.7`, and a recipient gets
  `553 5.6.7`. Without `EnableSMTPUTF8`, the server answers `555` to the
  parameter and reads an address as it did before.

  A server with `EnableSMTPUTF8` reads an `ORCPT` parameter of the `utf-8`
  address type with the encoding of RFC 6533, where `\x{HEX}` holds one code
  point. RFC 6531 asks for that address type from a server that offers `DSN`
  next to `SMTPUTF8`. A transaction with the parameter takes the bytes of the
  address as they came, and every other one needs the escape.

  A server without `EnableSMTPUTF8` reads that value as ordinary xtext, in the
  way that it did before.

- The server offers `CHUNKING` and takes a message in chunks with the `BDAT`
  command of RFC 3030. There is nothing to turn on, in the same way as for
  `PIPELINING` and `8BITMIME`.

  `Envelope.Data` streams the chunks as they arrive: the handler starts with
  the first chunk and reads the message through the rest of the transfer, so a
  chunked message is never held in memory as a whole. The server runs the
  handler on a goroutine of its own and waits for it at `BDAT LAST`.

  A transfer that ends before the last chunk gives the handler an error in the
  place of the rest of the message, so half a message never looks whole to it.
  `RSET` does that, and so does a connection that closes in the middle.

  A chunk that the server refuses still comes off the wire, which is what
  RFC 3030 asks for: a chunk that stays there is read as commands.

- The server offers `BINARYMIME` and takes `BODY=BINARYMIME` on `MAIL FROM`.
  Such a message needs `BDAT`, so `DATA` answers `503` for one.

- `Envelope.BodyType` holds the `BODY` parameter of `MAIL FROM`, as one of the
  new `Body7Bit`, `Body8BitMIME` and `BodyBinaryMIME` values. It is empty when
  the client sent no such parameter.

- The server offers the `DSN` extension of RFC 3461 when `Server.EnableDSN` is
  set. It reads `RET` and `ENVID` on `MAIL FROM`, and `NOTIFY` and `ORCPT` on
  `RCPT TO`, and puts them on the new `Envelope.DSN` field.

  `DSN.Recipients` holds one entry for each address in `Envelope.Recipients`,
  at the same index, so a handler reads the parameters of one recipient
  together with the address.

  The server writes no notification of its own. It carries the request to the
  handler, which knows what became of the message.

  The extension is off by default. A server that offers it tells the client
  that a notification follows the request, and only the handler can write one.
  Without it, the server answers `555` to each of the four parameters, as it
  did before.

- The server offers `ENHANCEDSTATUSCODES` and writes the status code of
  RFC 3463 after the reply code, for example `250 2.1.5 Go ahead` and
  `550 5.7.1 Relay access denied`.

- `EnhancedCode` holds such a status code, and the new `Enhanced` field of
  `Error` carries it from a middleware to the client. The field is optional.
  An error that leaves it out takes the generic code for the class of `Code`,
  which RFC 3463 section 3.1 writes as `x.0.0`.

- The middleware in `middleware` sets a status code for each of its refusals.
  The SPF checker uses the codes of RFC 7372: `5.7.23` for a check that
  fails, and `5.7.24` for an error in the check.

### Changed

- `smtptest.Server.Dial` gives up after ten seconds on the part of a session
  that comes before the test: the connection, the greeting, and the TLS
  handshake of a transport that needs one. It waited for the greeting with no
  deadline before.

  A server that takes a connection and answers nothing held the client for as
  long as the test run, and the run then failed on its own timeout, with no
  line to name the cause. A listener that nobody accepts on does that, because
  the connection reaches the queue of the listener and waits there.

  The deadline comes off once the handshake is over, so a test that drives a
  slow session keeps its own pace.

- The parser of a `MAIL FROM` and `RCPT TO` command takes a parameter keyword
  that comes without a value, which is the form of the `SMTPUTF8` parameter.
  RFC 5321 section 4.1.2 writes the value as an optional part.

  A keyword with an `=` sign and nothing after it is still an error. A known
  keyword that needs a value and comes without one gets a `501` reply from the
  parameter reader, where the command parser refused it before. Both replies
  carry the same code.

- The session reads its command lines from the reader of the connection, where
  it read them through a `bufio.Scanner` before. A read that fails once fails
  from then on, in the way that a scanner stops for good. A scanner reads ahead, and the
  octets of a `BDAT` chunk follow the command line on the same stream.

  A message that a client sends in the same write as its `DATA` command now
  arrives whole. The scanner took those octets into a buffer of its own, where
  the reader of the body could not reach them. RFC 2920 tells a client to wait
  for the `354` reply, so this reached only a client that does not.

- A client that sends `EHLO` gets a status code on every reply after that
  command. A test that asserts on the text of a reply must expect it.

  Three replies stay as they were, because RFC 2034 takes them out of the
  extension: the greeting, the reply to `HELO` and the reply to `EHLO`. A
  client that sends `HELO` sees no change at all, because it never saw the
  server offer the extension.

  The `354` of `DATA` and the `334` of `AUTH` also stay as they were.
  RFC 3463 defines no status class for those replies.

## [2.3.1] - 2026-08-16

### Fixed

- The credentials of an `AUTH` command stay out of the log when the client
  writes the command with tabs between the parts. The server reads
  `AUTH<TAB>PLAIN<TAB><credentials>` as a command, and the log carried that
  line in full at the `DEBUG` level.

- An address with a quoted local part keeps its quoting. Before,
  `MAIL FROM:<" "@example.org>` put ` @example.org` into `Envelope.Sender`.
  That value is not an address any more. A relay that sends it on writes a
  command that the next server cannot read.

- An address that carries a line break gets a `501` reply. Such an address
  lets the client add a command of its own to the session of a relay.

## [2.3.0] - 2026-08-08

### Added

- `PanicError` records a panic from a `Handler` or a middleware hook. `Value`
  holds the value given to `panic`, and `Stack` holds the stack trace. The
  `Disconnect` hooks receive it through their `err` argument.

### Changed

- The server answers with the reply code that RFC 5321 gives for each fault.
  It used `502`, which means that the command is not implemented, for a
  command that came in the wrong order and for one with a bad argument.

  | The client does this | Before | Now |
  | --- | --- | --- |
  | Sends a command this server does not know | `502` | `500` |
  | Sends a line that is not a command | `502` | `500` |
  | Leaves out the name on `HELO` or `EHLO` | `502` | `501` |
  | Writes `MAIL FROM` or `RCPT TO` wrongly | `502` | `501` |
  | Gives an address that does not parse | `502` | `501` |
  | Writes `XCLIENT` or `PROXY` wrongly | `502` | `501` |
  | Sends `AUTH` with no mechanism | `502` | `501` |
  | Sends credentials that do not decode | `502` | `501` |
  | Sends `MAIL FROM` before a greeting | `502` | `503` |
  | Sends `MAIL FROM` twice | `502` | `503` |
  | Sends `RCPT TO` before `MAIL FROM` | `502` | `503` |
  | Sends `DATA` before `RCPT TO` | `502` | `503` |
  | Sends `AUTH` before a greeting | `502` | `503` |
  | Sends `STARTTLS` inside TLS | `502` | `503` |
  | Asks for a mechanism this server does not have | `502` | `504` |
  | Sends `AUTH` in plain text where STARTTLS is offered | `502` | `530` |

  `502` stays where the command really is not implemented: `AUTH` with no
  authenticator, `STARTTLS` with no TLS, `AUTH` in plain text where STARTTLS
  is not offered, and `XCLIENT` or `PROXY` on a connection that is not TCP.

  A client that reads the first digit only sees no change. One that matches
  the whole code has to be read again.

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

### Fixed

- `XCLIENT` decodes its attribute values. The XCLIENT specification writes
  them in the xtext encoding of RFC 1891, where `+` starts a byte written as
  two hexadecimal digits. The server read them as they came, so
  `LOGIN=user+40example.com` gave the user name `user+40example.com` instead
  of `user@example.com`. A `+` that two such digits do not follow stands for
  itself, so a value that the proxy sent without encoding still arrives whole.

- `XCLIENT` reads `[UNAVAILABLE]` and `[TEMPUNAVAIL]` as the marks for an
  attribute the proxy has no information for, and leaves that attribute as it
  was. `HELO` and `LOGIN` took the mark itself as the name and the user
  before, and `PORT=[UNAVAILABLE]` failed the whole command with `502`, which
  dropped the address of the client along with it.

- `XCLIENT` accepts a value that carries an equals sign, such as the padding
  of base64 in `LOGIN=dXNlcg==`. Every equals sign split the item before, so
  the server answered `502` and the proxy lost the attributes it sent.

- The server no longer reads a message without bound after it rejected the
  size. It read to the end of the message to keep the SMTP stream in step,
  which let a client hold the session for as long as `DataTimeout` allows. It
  now stops at twice `MaxMessageSize`.

  A message that ends inside that gets a `552` and the session goes on, as
  before. A client that is still sending gets a `552` and loses the
  connection, because the rest of the message would otherwise be read as SMTP
  commands.

- `middleware.Greylist` no longer reads the whole map on every `RCPT TO`. The
  sweep for expired entries ran on each check, under the lock, so each check
  cost as much as the map was large. At 20000 entries a check took 271µs. It
  now takes 156ns, and the cost no longer grows with the map.

  The sweep runs once a minute, and as soon as the map reaches the cap.
  Whether a triple is past the TTL is read at the check itself, so the answer
  does not depend on when the sweep runs.

### Security

- A successful `STARTTLS` now clears `Peer.HeloName`, `Peer.Protocol` and
  `Peer.Username`. The server kept the name from the greeting before the
  handshake, which goes over the wire in plain text where anybody on the path
  can change it. RFC 3207 says the server must drop what it learned there, and
  names the argument of `EHLO`.

  A handler or a middleware could therefore read a `HeloName` that an attacker
  in the middle chose.

  **This changes behavior.** The client must send `EHLO` or `HELO` again after
  `STARTTLS`. Without it, `MAIL FROM` is answered with `503`. Client libraries
  already do this: `StartTLS` in `net/smtp` sends `EHLO` again as part of the
  call. A client of your own that skips it stops working.

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

[Unreleased]: https://github.com/chrj/smtpd/compare/v2.4.0...main
[2.4.0]: https://github.com/chrj/smtpd/releases/tag/v2.4.0
[2.3.1]: https://github.com/chrj/smtpd/releases/tag/v2.3.1
[2.3.0]: https://github.com/chrj/smtpd/releases/tag/v2.3.0
[2.2.0]: https://github.com/chrj/smtpd/releases/tag/v2.2.0
[2.1.2]: https://github.com/chrj/smtpd/releases/tag/v2.1.2
[2.1.1]: https://github.com/chrj/smtpd/releases/tag/v2.1.1
[2.1.0]: https://github.com/chrj/smtpd/releases/tag/v2.1.0
[2.0.0]: https://github.com/chrj/smtpd/releases/tag/v2.0.0
