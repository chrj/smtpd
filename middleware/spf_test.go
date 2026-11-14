package middleware

import (
	"context"
	"net"
	"strings"
	"testing"
	"unicode/utf8"

	"blitiri.com.ar/go/spf"
	"github.com/chrj/smtpd/v2"
)

var _ spf.DNSResolver = &mockSPFResolver{}

type mockSPFResolver struct {
	results map[string][]string
}

func (r *mockSPFResolver) LookupTXT(ctx context.Context, domain string) ([]string, error) {
	if res, ok := r.results[domain]; ok {
		return res, nil
	}
	return nil, nil
}
func (r *mockSPFResolver) LookupIPAddr(context.Context, string) ([]net.IPAddr, error) {
	return nil, nil
}
func (r *mockSPFResolver) LookupMX(context.Context, string) ([]*net.MX, error)  { return nil, nil }
func (r *mockSPFResolver) LookupNS(context.Context, string) ([]*net.NS, error)  { return nil, nil }
func (r *mockSPFResolver) LookupAddr(context.Context, string) ([]string, error) { return nil, nil }

func TestSPFChecks(t *testing.T) {
	t.Parallel()

	resolver := &mockSPFResolver{
		results: map[string][]string{
			"pass.com": {"v=spf1 ip4:1.2.3.4 -all"},
			"fail.com": {"v=spf1 ip4:5.6.7.8 -all"},
		},
	}
	peer := smtpd.Peer{Addr: &net.TCPAddr{IP: net.ParseIP("1.2.3.4")}}
	s := SPF(WithSPFResolver(resolver))

	// MailFrom: pass / fail
	if err := s.SenderCheck(context.Background(), peer, "test@pass.com"); err != nil {
		t.Errorf("MailFrom pass: %v", err)
	}
	if err := s.SenderCheck(context.Background(), peer, "test@fail.com"); err == nil {
		t.Error("MailFrom fail: expected error")
	} else if smtpdErr, ok := err.(smtpd.Error); !ok || smtpdErr.Code != 550 {
		t.Errorf("expected 550, got %v", err)
	}

	// Helo (uses peer.HeloName)
	heloPeer := peer
	heloPeer.HeloName = "pass.com"
	if err := s.HeloCheck(context.Background(), heloPeer); err != nil {
		t.Errorf("Helo pass: %v", err)
	}
	heloPeer.HeloName = "fail.com"
	if err := s.HeloCheck(context.Background(), heloPeer); err == nil {
		t.Error("Helo fail: expected error")
	}

	// Data (uses env.Sender)
	if err := s.DataCheck(context.Background(), peer, &smtpd.Envelope{Sender: "test@pass.com"}); err != nil {
		t.Errorf("Data pass: %v", err)
	}
	if err := s.DataCheck(context.Background(), peer, &smtpd.Envelope{Sender: "test@fail.com"}); err == nil {
		t.Error("Data fail: expected error")
	}
}

// TestSPFChecksTheDomainOfTheSender verifies that the check reads the policy
// of the domain after the last "@" of the sender, in the A-label form.
//
// RFC 5321 lets a quoted local part carry an "@" of its own. A check of the
// name after the first "@" finds no policy, and the result none lets a sender
// of every domain past the policy of that domain. A domain of Unicode has no
// policy in the DNS in that form, which gives the same result.
func TestSPFChecksTheDomainOfTheSender(t *testing.T) {
	t.Parallel()

	resolver := &mockSPFResolver{
		results: map[string][]string{
			"victim.example":        {"v=spf1 ip4:5.6.7.8 -all"},
			"xn--bcher-kva.example": {"v=spf1 ip4:5.6.7.8 -all"},
		},
	}
	peer := smtpd.Peer{Addr: &net.TCPAddr{IP: net.ParseIP("1.2.3.4")}}
	s := SPF(WithSPFResolver(resolver))

	tests := []struct {
		name   string
		sender string
	}{
		{
			name:   "an @ in a quoted local part",
			sender: `"x@attacker.example"@victim.example`,
		},
		{
			name:   "two @ in a quoted local part",
			sender: `"a@b@attacker.example"@victim.example`,
		},
		{
			name:   "a domain of Unicode",
			sender: "user@bücher.example",
		},
		{
			name:   "a domain of Unicode in upper case",
			sender: "user@BÜCHER.example",
		},
	}

	want := smtpd.Error{Code: 550, Enhanced: smtpd.EnhancedCode{5, 7, 23}, Message: "SPF check failed"}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if err := s.SenderCheck(context.Background(), peer, tc.sender); err != want {
				t.Errorf("SenderCheck(%q) = %v, want %v", tc.sender, err, want)
			}
			if err := s.DataCheck(context.Background(), peer, &smtpd.Envelope{Sender: tc.sender}); err != want {
				t.Errorf("DataCheck(%q) = %v, want %v", tc.sender, err, want)
			}
		})
	}
}

// TestSPFChecksBothSpellingsOfADomain verifies that the A-label spelling and
// the Unicode spelling of a domain reach the same policy.
//
// The DNS holds labels that the rules of IDNA refuse, such as one with an
// underscore. A check that gave none for such a domain in the Unicode
// spelling would let a sender past a policy that the A-label spelling meets.
func TestSPFChecksBothSpellingsOfADomain(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		unicode string
		alabel  string
	}{
		{
			name:    "an underscore in a label of US-ASCII",
			unicode: "bücher.mail_relay.example",
			alabel:  "xn--bcher-kva.mail_relay.example",
		},
		{
			name:    "an underscore in a label of Unicode",
			unicode: "bücher_relay.example",
			alabel:  "xn--bcher_relay-thb.example",
		},
		{
			name:    "a hyphen at the start of a label of Unicode",
			unicode: "-bücher.example",
			alabel:  "xn---bcher-4ya.example",
		},
		{
			name:    "two hyphens in a label of US-ASCII",
			unicode: "ab--cd.bücher.example",
			alabel:  "ab--cd.xn--bcher-kva.example",
		},
		{
			name:    "a label of US-ASCII that is no A-label",
			unicode: "xn--zz.bücher.example",
			alabel:  "xn--zz.xn--bcher-kva.example",
		},
		{
			name:    "a label of US-ASCII beside a label of right-to-left text",
			unicode: "1abc.שלום.example",
			alabel:  "1abc.xn--9dbne9b.example",
		},
		{
			name:    "an ideographic full stop before a label of US-ASCII",
			unicode: "bücher\u3002xn--zz.example",
			alabel:  "xn--bcher-kva.xn--zz.example",
		},
		{
			name:    "a fullwidth full stop before a label of US-ASCII",
			unicode: "bücher\uFF0Exn--zz.example",
			alabel:  "xn--bcher-kva.xn--zz.example",
		},
		{
			name:    "a halfwidth ideographic full stop before a label of US-ASCII",
			unicode: "bücher\uFF61xn--zz.example",
			alabel:  "xn--bcher-kva.xn--zz.example",
		},
	}

	want := smtpd.Error{Code: 550, Enhanced: smtpd.EnhancedCode{5, 7, 23}, Message: "SPF check failed"}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			resolver := &mockSPFResolver{
				results: map[string][]string{tc.alabel: {"v=spf1 ip4:5.6.7.8 -all"}},
			}
			peer := smtpd.Peer{Addr: &net.TCPAddr{IP: net.ParseIP("1.2.3.4")}}
			s := SPF(WithSPFResolver(resolver))

			for _, domain := range []string{tc.alabel, tc.unicode} {
				sender := "user@" + domain
				if err := s.SenderCheck(context.Background(), peer, sender); err != want {
					t.Errorf("SenderCheck(%q) = %v, want %v", sender, err, want)
				}
			}
		})
	}
}

// TestSPFLabelSeparatorsAreComplete verifies that spfLabelSeparators replaces
// every character that spfIDNA maps to a text with a full stop. A character
// that it missed would split a label inside spfIDNA, and a label in US-ASCII
// after it would reach the rules of IDNA. A new version of the tables of
// IDNA can add such a character.
func TestSPFLabelSeparatorsAreComplete(t *testing.T) {
	t.Parallel()

	for r := rune(utf8.RuneSelf); r <= utf8.MaxRune; r++ {
		if !utf8.ValidRune(r) {
			continue
		}

		// The error says whether the label is valid, and the mapping is
		// what this test reads.
		mapped, _ := spfIDNA.ToUnicode("a" + string(r) + "b")
		if !strings.Contains(mapped, ".") {
			continue
		}
		if !strings.Contains(spfLabelSeparators.Replace(string(r)), ".") {
			t.Errorf("spfIDNA maps U+%04X to %q, and spfLabelSeparators does not replace it", r, mapped)
		}
	}
}

// TestSPFSender covers the sender that the SPF library gets. The library
// takes the domain and the %{l} macro from the first "@", so no "@" stays in
// the local part.
func TestSPFSender(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		sender string
		want   string
	}{
		{
			name:   "the null sender",
			sender: "",
			want:   "",
		},
		{
			name:   "an address in US-ASCII",
			sender: "user@example.org",
			want:   "user@example.org",
		},
		{
			name:   "a domain in US-ASCII keeps its case",
			sender: "user@Example.ORG",
			want:   "user@Example.ORG",
		},
		{
			name:   "a domain in US-ASCII with an underscore",
			sender: "user@mail_relay.example.org",
			want:   "user@mail_relay.example.org",
		},
		{
			name:   "an @ in a quoted local part",
			sender: `"x@attacker.example"@victim.example`,
			want:   `"x%40attacker.example"@victim.example`,
		},
		{
			name:   "two @ in a quoted local part",
			sender: `"a@b@attacker.example"@victim.example`,
			want:   `"a%40b%40attacker.example"@victim.example`,
		},
		{
			// The library has no way to carry an "@" in the local part, so
			// this sender and the one of "an @ in a quoted local part" read
			// as one in %{l} and %{s}.
			name:   "a %40 in a quoted local part",
			sender: `"x%40attacker.example"@victim.example`,
			want:   `"x%40attacker.example"@victim.example`,
		},
		{
			name:   "a domain of Unicode",
			sender: "user@bücher.example",
			want:   "user@xn--bcher-kva.example",
		},
		{
			name:   "a domain of Unicode in upper case",
			sender: "user@BÜCHER.example",
			want:   "user@xn--bcher-kva.example",
		},
		{
			name:   "a local part of Unicode",
			sender: "jörg@example.org",
			want:   "jörg@example.org",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := spfSender(tc.sender)
			if err != nil {
				t.Fatalf("spfSender(%q) failed: %v", tc.sender, err)
			}
			if got != tc.want {
				t.Errorf("spfSender(%q) = %q, want %q", tc.sender, got, tc.want)
			}
		})
	}
}

// TestSPFSenderWithoutAnALabel covers a domain of Unicode that has no A-label
// form. RFC 7208 section 4.3 gives none for a domain that is not well formed.
func TestSPFSenderWithoutAnALabel(t *testing.T) {
	t.Parallel()

	const sender = "user@a\uFFFDb.example"

	if got, err := spfSender(sender); err == nil {
		t.Fatalf("spfSender(%q) = %q, want an error", sender, got)
	}

	// The policy of every domain would refuse the address of the peer, so
	// only a check that stops short of the DNS lets the sender pass.
	resolver := &mockSPFResolver{
		results: map[string][]string{
			"a\uFFFDb.example": {"v=spf1 -all"},
		},
	}
	peer := smtpd.Peer{Addr: &net.TCPAddr{IP: net.ParseIP("1.2.3.4")}}
	s := SPF(WithSPFResolver(resolver))

	if err := s.SenderCheck(context.Background(), peer, sender); err != nil {
		t.Errorf("SenderCheck(%q) = %v, want none and no error", sender, err)
	}
}

// TestSPFChecksAHeloNameOfUnicode verifies that the check of the HELO name
// reads the policy of the name in the A-label form.
func TestSPFChecksAHeloNameOfUnicode(t *testing.T) {
	t.Parallel()

	resolver := &mockSPFResolver{
		results: map[string][]string{
			"xn--bcher-kva.example": {"v=spf1 ip4:5.6.7.8 -all"},
		},
	}
	peer := smtpd.Peer{
		Addr:     &net.TCPAddr{IP: net.ParseIP("1.2.3.4")},
		HeloName: "bücher.example",
	}
	s := SPF(WithSPFResolver(resolver))

	want := smtpd.Error{Code: 550, Enhanced: smtpd.EnhancedCode{5, 7, 23}, Message: "SPF check failed"}
	if err := s.HeloCheck(context.Background(), peer); err != want {
		t.Errorf("HeloCheck(%q) = %v, want %v", peer.HeloName, err, want)
	}
}

// TestSPFHeloNameWithoutAnALabel verifies that a HELO name without an A-label
// form does not end the check of the sender. A client would otherwise send
// such a name to get past the policy of its sender.
func TestSPFHeloNameWithoutAnALabel(t *testing.T) {
	t.Parallel()

	resolver := &mockSPFResolver{
		results: map[string][]string{
			"victim.example": {"v=spf1 ip4:5.6.7.8 -all"},
		},
	}
	peer := smtpd.Peer{
		Addr:     &net.TCPAddr{IP: net.ParseIP("1.2.3.4")},
		HeloName: "a\uFFFDb.example",
	}
	s := SPF(WithSPFResolver(resolver))

	want := smtpd.Error{Code: 550, Enhanced: smtpd.EnhancedCode{5, 7, 23}, Message: "SPF check failed"}
	if err := s.SenderCheck(context.Background(), peer, "user@victim.example"); err != want {
		t.Errorf("SenderCheck after HELO %q = %v, want %v", peer.HeloName, err, want)
	}
}

// TestSPFAtStages confirms the Check* adapters wire the matching method into
// the matching checker interface, and only that one.
func TestSPFAtStages(t *testing.T) {
	t.Parallel()

	resolver := &mockSPFResolver{
		results: map[string][]string{"fail.com": {"v=spf1 ip4:5.6.7.8 -all"}},
	}
	peer := smtpd.Peer{
		Addr:     &net.TCPAddr{IP: net.ParseIP("1.2.3.4")},
		HeloName: "fail.com",
	}
	s := SPF(WithSPFResolver(resolver))

	mw := CheckHelo(s.HeloCheck)
	if mw.CheckSender != nil {
		t.Fatal("CheckHelo middleware should not contribute to CheckSender")
	}
	if mw.CheckHelo == nil {
		t.Fatal("CheckHelo middleware should contribute to CheckHelo")
	}
	if _, err := mw.CheckHelo(context.Background(), peer, "fail.com"); err == nil {
		t.Error("expected SPF block at HELO")
	}
}
