module github.com/chrj/smtpd/v2/_examples/gmail-relay

go 1.26.1

require github.com/chrj/smtpd/v2 v2.0.0

require (
	blitiri.com.ar/go/spf v1.5.1 // indirect
	github.com/chrj/keyrate v0.2.2 // indirect
	golang.org/x/time v0.15.0 // indirect
)

replace github.com/chrj/smtpd/v2 => ../..
