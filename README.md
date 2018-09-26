Go smtpd [![GoDoc](https://godoc.org/github.com/chrj/smtpd?status.png)](https://godoc.org/github.com/chrj/smtpd) [![Go Report Card](https://goreportcard.com/badge/github.com/chrj/smtpd)](https://goreportcard.com/report/github.com/chrj/smtpd)
========

Package smtpd implements an SMTP server in golang.

Features
--------

* STARTTLS (using `crypto/tls`)
* Authentication (PLAIN/LOGIN, only after STARTTLS)
* [XCLIENT](http://www.postfix.org/XCLIENT_README.html) and [PROXY protocol](https://www.haproxy.org/download/1.8/doc/proxy-protocol.txt) (for running behind a proxy)
* Connection, HELO, sender and recipient checks for rejecting e-mails using callbacks
* Configurable limits for: connection count, message size and recipient count
* Hands incoming e-mail off to a configured callback function

Version numbers
---------------

The package is tagged with semantic version numbers, making it suitable for use in a [Go Module](https://github.com/golang/go/wiki/Modules). 

Feedback
--------

If you end up using this package or have any feedback, I'd very much like to hear about it. You can reach me by [email](mailto:christian@technobabble.dk).
