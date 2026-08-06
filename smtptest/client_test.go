package smtptest_test

import (
	"context"
	"errors"
	"net/textproto"
	"testing"

	"github.com/chrj/smtpd/v2"
	"github.com/chrj/smtpd/v2/smtptest"
)

// TestSendRejected makes sure that Send gives back the reply of the server,
// so a test can read the code of a rejection.
func TestSendRejected(t *testing.T) {
	srv := smtptest.NewUnstartedServer(nil)
	srv.Config.Use(smtpd.Middleware{
		CheckRecipient: func(ctx context.Context, _ smtpd.Peer, _ string) (context.Context, error) {
			return ctx, smtpd.Error{Code: 550, Message: "No such user"}
		},
	})
	srv.Start()
	defer srv.Close()

	c := srv.Dial()
	defer func() { _ = c.Close() }()

	err := smtptest.Send(c, testSender, []string{testRecipient}, testBody)
	if err == nil {
		t.Fatal("Send accepted a message that the server rejected")
	}

	var reply *textproto.Error
	if !errors.As(err, &reply) {
		t.Fatalf("Send error: got %v, want a *textproto.Error", err)
	}
	if reply.Code != 550 {
		t.Errorf("reply code: got %d, want 550", reply.Code)
	}
}

func TestCmd(t *testing.T) {
	srv := smtptest.NewServer(nil)
	defer srv.Close()

	c := srv.Dial()
	defer func() { _ = c.Close() }()

	// EnableXCLIENT is false by default, so the server answers 550.
	if err := smtptest.Cmd(c.Text, 550, "XCLIENT NAME=ignored"); err != nil {
		t.Errorf("Cmd with the expected code: %v", err)
	}

	err := smtptest.Cmd(c.Text, 250, "XCLIENT NAME=ignored")
	if err == nil {
		t.Fatal("Cmd accepted a reply code that it did not expect")
	}

	var reply *textproto.Error
	if !errors.As(err, &reply) {
		t.Fatalf("Cmd error: got %v, want a *textproto.Error", err)
	}
	if reply.Code != 550 {
		t.Errorf("reply code: got %d, want 550", reply.Code)
	}
}
