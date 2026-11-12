package smtpd

import (
	"context"
	"io"
	"log/slog"
	"reflect"
	"strings"
	"testing"
)

// contextDepth counts the contexts between ctx and its root.
//
// A context that derives from another one holds that one in an embedded field
// with the name Context. The contexts of the standard library do that, and so
// does the context of a session. TestContextDepth holds that reading in
// place, so that a change of the layout does not make the count too low.
func contextDepth(ctx context.Context) int {
	depth := 0

	for {
		v := reflect.ValueOf(ctx)
		if v.Kind() == reflect.Pointer {
			v = v.Elem()
		}
		if v.Kind() != reflect.Struct {
			return depth
		}

		field := v.FieldByName("Context")
		if !field.IsValid() || !field.CanInterface() {
			return depth
		}

		parent, ok := field.Interface().(context.Context)
		if !ok {
			return depth
		}

		ctx = parent
		depth++
	}
}

func TestContextDepth(t *testing.T) {
	t.Parallel()

	type key struct{}

	root := context.Background()
	value := context.WithValue(root, key{}, "a")
	canceled, cancel := context.WithCancel(value)
	defer cancel()

	tests := []struct {
		name string
		ctx  context.Context
		want int
	}{
		{name: "the root", ctx: root, want: 0},
		{name: "one value", ctx: value, want: 1},
		{name: "a value and a cancel", ctx: canceled, want: 2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := contextDepth(tt.ctx); got != tt.want {
				t.Errorf("contextDepth() = %d, want %d", got, tt.want)
			}
		})
	}
}

// sessionContextDepth runs one session over script and gives the depth of the
// context that the session ends with. The Disconnect hook reads that context.
//
// The hooks add no value of their own, so the depth is the one that the
// session itself builds.
func sessionContextDepth(t *testing.T, script string) int {
	t.Helper()

	var final context.Context

	srv := &Server{
		AllowInsecureAuth: true,

		// A session that closes at the fifth failed AUTH runs no more
		// commands, and the test needs all of them.
		MaxAuthAttempts: -1,

		Handler: func(ctx context.Context, _ Peer, env *Envelope) (context.Context, error) {
			_, _ = io.Copy(io.Discard, env.Data)
			return ctx, nil
		},
	}

	srv.Use(Middleware{
		Authenticate: func(ctx context.Context, _ Peer, _, _ string) (context.Context, error) {
			return ctx, Error{Code: 535, Message: "Authentication credentials invalid"}
		},
		CheckRecipient: func(ctx context.Context, _ Peer, addr string) (context.Context, error) {
			if addr == "refused@example.net" {
				return ctx, Error{Code: 550, Message: "No such user here"}
			}
			return ctx, nil
		},
		Verify: func(ctx context.Context, _ Peer, _ string) (context.Context, Verification, error) {
			return ctx, Verification{}, nil
		},
		Disconnect: func(ctx context.Context, _ Peer, _ error) {
			final = ctx
		},
	})

	runScript(t, srv, script)

	if final == nil {
		t.Fatal("the Disconnect hook did not run")
	}
	return contextDepth(final)
}

// TestSessionContextDoesNotGrow verifies that the context of a session is as
// deep after many commands as after one. A session takes as many commands as
// the client sends, and every lookup walks the context, so a context that
// grows with each command costs the server memory and time without a bound.
func TestSessionContextDoesNotGrow(t *testing.T) {
	t.Parallel()

	const (
		greeting = "EHLO client.example\r\n"
		mail     = "MAIL FROM:<sender@example.org>\r\n"
		rcpt     = "RCPT TO:<recipient@example.net>\r\n"
	)

	tests := []struct {
		name string

		// opening is sent one time, and command after it as often as the
		// test says.
		opening string
		command string
	}{
		{name: "NOOP", opening: greeting, command: "NOOP\r\n"},
		{name: "RSET", opening: greeting, command: "RSET\r\n"},
		{name: "a new greeting", opening: greeting, command: greeting},
		{name: "VRFY", opening: greeting, command: "VRFY user\r\n"},
		{name: "a refused STARTTLS", opening: greeting, command: "STARTTLS\r\n"},
		{name: "a refused XCLIENT", opening: greeting, command: "XCLIENT NAME=client.example\r\n"},
		{name: "a refused AUTH", opening: greeting, command: "AUTH PLAIN AHVzZXIAd3Jvbmc=\r\n"},
		{name: "a recipient that does not read", opening: greeting + mail, command: "RCPT TO:<not an address>\r\n"},
		{name: "a recipient that a hook refuses", opening: greeting + mail, command: "RCPT TO:<refused@example.net>\r\n"},
		{name: "a transaction that RSET ends", opening: greeting, command: mail + rcpt + "RSET\r\n"},
		{name: "a message through DATA", opening: greeting, command: mail + rcpt + "DATA\r\nbody\r\n.\r\n"},
		{name: "a message through BDAT", opening: greeting, command: mail + rcpt + "BDAT 4 LAST\r\nbody"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			once := sessionContextDepth(t, tt.opening+tt.command)
			many := sessionContextDepth(t, tt.opening+strings.Repeat(tt.command, 100))

			if many != once {
				t.Errorf("the context is %d deep after 100 repetitions, want %d as after one", many, once)
			}
		})
	}
}

func TestSenderFromContext(t *testing.T) {
	t.Parallel()

	type hookKey struct{}

	root := context.Background()

	tests := []struct {
		name       string
		ctx        context.Context
		wantSender string
		wantOK     bool
	}{
		{
			name: "a context without a sender",
			ctx:  root,
		},
		{
			name:       "a sender",
			ctx:        ContextWithSender(root, "sender@example.org"),
			wantSender: "sender@example.org",
			wantOK:     true,
		},
		{
			name:   "the null sender",
			ctx:    ContextWithSender(root, ""),
			wantOK: true,
		},
		{
			name: "a sender that the session cleared",
			ctx:  contextWithoutSender(ContextWithSender(root, "sender@example.org")),
		},
		{
			name:       "a sender below a value of a hook",
			ctx:        context.WithValue(ContextWithSender(root, "sender@example.org"), hookKey{}, "from a hook"),
			wantSender: "sender@example.org",
			wantOK:     true,
		},
		{
			name:       "a second sender",
			ctx:        ContextWithSender(ContextWithSender(root, "first@example.org"), "second@example.org"),
			wantSender: "second@example.org",
			wantOK:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			sender, ok := SenderFromContext(tt.ctx)
			if sender != tt.wantSender || ok != tt.wantOK {
				t.Errorf("SenderFromContext() = (%q, %v), want (%q, %v)", sender, ok, tt.wantSender, tt.wantOK)
			}
		})
	}
}

// TestSessionContextKeepsTheValueOfAHook verifies that a value which a hook
// put on the context is still there after the session sets values of its own.
func TestSessionContextKeepsTheValueOfAHook(t *testing.T) {
	t.Parallel()

	type hookKey struct{}

	ctx := ContextWithSender(context.Background(), "sender@example.org")
	ctx = context.WithValue(ctx, hookKey{}, "from a hook")
	ctx, _ = phasedLoggerFromContext(ctx, "rcpt")

	if got := ctx.Value(hookKey{}); got != "from a hook" {
		t.Errorf("the value of the hook after a new phase = %v, want %q", got, "from a hook")
	}
	if sender, ok := SenderFromContext(ctx); sender != "sender@example.org" || !ok {
		t.Errorf("SenderFromContext() after a new phase = (%q, %v), want (%q, true)", sender, ok, "sender@example.org")
	}

	ctx = contextWithoutSender(ctx)

	if got := ctx.Value(hookKey{}); got != "from a hook" {
		t.Errorf("the value of the hook after the sender was cleared = %v, want %q", got, "from a hook")
	}
}

// TestSessionContextLeavesAnEarlierContextAsItWas verifies that a context
// keeps its logger and its sender while the session goes on. The handler of a
// BDAT message holds the context that it started with, and the session runs
// the commands that follow on another goroutine.
func TestSessionContextLeavesAnEarlierContextAsItWas(t *testing.T) {
	t.Parallel()

	root := contextWithLogger(context.Background(), slog.New(slog.DiscardHandler))
	earlier, earlierLogger := phasedLoggerFromContext(ContextWithSender(root, "sender@example.org"), "bdat")

	// The session goes on with a command and then ends the transaction.
	later, _ := phasedLoggerFromContext(earlier, "noop")
	_ = contextWithoutSender(later)

	if LoggerFromContext(earlier) != earlierLogger {
		t.Error("the earlier context gives another logger after a later command")
	}
	if sender, ok := SenderFromContext(earlier); sender != "sender@example.org" || !ok {
		t.Errorf("SenderFromContext() of the earlier context = (%q, %v), want (%q, true)", sender, ok, "sender@example.org")
	}
}
