# smtpd gmail-relay

A minimal SMTP relay built on `github.com/chrj/smtpd/v2` that forwards
accepted messages to Gmail. Inbound traffic is filtered with three
middlewares before the relay handler runs:

- **Per-IP rate limit** — token-bucket throttle on `CheckConnection`.
- **RBL lookup** — reject peers listed in one or more DNSBL zones.
- **SPF check** — evaluate the sending IP against the HELO identity
  (`HeloCheck`) and against `MAIL FROM` (`SenderCheck`).

## Build

```sh
go build -o gmail-relay .
```

## Run

Gmail submission requires an [app password][app-pass] — ordinary account
passwords will not authenticate. Export it or pass it via `-pass`.

```sh
./gmail-relay \
  -listen 127.0.0.1:10025 \
  -user you@gmail.com \
  -pass "xxxx xxxx xxxx xxxx" \
  -rbl zen.spamhaus.org,bl.spamcop.net \
  -rps 1 -burst 5
```

Point a client at `127.0.0.1:10025` and any accepted message is relayed
through `smtp.gmail.com:587`.

[app-pass]: https://support.google.com/accounts/answer/185833
