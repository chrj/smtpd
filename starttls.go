package smtpd

import (
	"bufio"
	"context"
	"crypto/tls"
	"log/slog"
	"time"
)

func (s *session) handleSTARTTLS(ctx context.Context, cmd *command) context.Context {
	ctx, logger := phasedLoggerFromContext(ctx, "starttls")

	if s.tls {
		return s.replyEnhanced(ctx, 503, EnhancedCode{5, 5, 1}, "Already running in TLS")
	}

	if s.server.TLSConfig == nil {
		return s.replyEnhanced(ctx, 502, EnhancedCode{5, 5, 1}, "TLS not supported")
	}

	tlsConn := tls.Server(s.conn, s.server.TLSConfig)
	ctx = s.reply(ctx, 220, "Go ahead")

	if err := tlsConn.HandshakeContext(ctx); err != nil {
		logger.ErrorContext(ctx, "tls handshake failed", slog.Any("err", err))
		s.setErr(err)
		// Best-effort 550 over the still-plain conn in case the client
		// hasn't sent ClientHello yet; then close - continuing from a
		// half-failed handshake leaves the byte stream unintelligible.
		ctx = s.replyEnhanced(ctx, 550, EnhancedCode{5, 7, 0}, "Handshake error")
		return s.close(ctx)
	}

	// Everything the client sent before the handshake went over the wire in
	// plain text, where anybody on the path could change it. RFC 3207 gives
	// the argument of EHLO as the example of what the server must drop.
	//
	// Clearing the name from the greeting is also what makes a new EHLO or
	// HELO necessary: MAIL FROM asks for it, and turns the client away
	// without one.
	s.peer.HeloName = ""
	s.peer.Protocol = ""
	s.peer.Username = ""

	ctx = s.reset(ctx)

	// Reset deadlines on the underlying connection before I replace it
	// with a TLS connection
	_ = s.conn.SetDeadline(time.Time{})

	// Replace connection with a TLS connection
	s.conn = tlsConn
	s.reader = bufio.NewReader(tlsConn)
	s.writer = bufio.NewWriter(tlsConn)
	s.tls = true

	// Save connection state on peer
	state := tlsConn.ConnectionState()
	s.peer.TLS = &state

	// Flush the connection to set new timeout deadlines
	return s.flush(ctx)

}
