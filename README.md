Go smtpd [![GoDoc](https://godoc.org/bitbucket.org/chrj/smtpd?status.png)](https://godoc.org/bitbucket.org/chrj/smtpd)
========

Package smtpd implements an SMTP server in golang.

Features
--------

* STARTTLS (using `crypto/tls`)
* Authentication (PLAIN/LOGIN, only after STARTTLS)
* XCLIENT (for running behind a proxy)
* Connection, HELO, sender and recipient checks for rejecting e-mails using callbacks
* Configurable limits for: connection count, message size and recipient count
* Hands incoming e-mail off to a configured callback function

Feedback
--------

If you end up using this package or have any feedback, I'd very much like to hear about it. You can reach me by [email](mailto:christian@technobabble.dk).
