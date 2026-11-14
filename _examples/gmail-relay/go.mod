module github.com/chrj/smtpd/v2/_examples/gmail-relay

go 1.26.1

require github.com/chrj/smtpd/v2 v2.0.0

require (
	blitiri.com.ar/go/spf v1.6.0 // indirect
	github.com/chrj/keyrate v0.2.6 // indirect
	golang.org/x/net v0.62.0 // indirect
	golang.org/x/text v0.43.0 // indirect
	golang.org/x/time v0.16.0 // indirect
)

replace github.com/chrj/smtpd/v2 => ../..
