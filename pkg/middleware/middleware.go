package middleware

// Stage defines when a middleware check should be performed.
type Stage int

const (
	// OnConnect performs the check when the client connects.
	OnConnect Stage = iota
	// OnHelo performs the check after the HELO or EHLO command.
	OnHelo
	// OnMailFrom performs the check after the MAIL FROM command.
	OnMailFrom
	// OnRcptTo performs the check after each RCPT TO command.
	OnRcptTo
	// OnData performs the check after the DATA command is completed.
	OnData
)
