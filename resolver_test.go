package main

import (
	"io"
	"log/slog"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func query(t *testing.T, name string, qtype dnsmessage.Type, id uint16) []byte {
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: id, RecursionDesired: true})

	if err := b.StartQuestions(); err != nil {
		t.Fatal(err)
	}

	q := dnsmessage.Question{Name: dnsmessage.MustNewName(name), Type: qtype, Class: dnsmessage.ClassINET}

	if err := b.Question(q); err != nil {
		t.Fatal(err)
	}

	msg, err := b.Finish()

	if err != nil {
		t.Fatal(err)
	}

	return msg
}

func TestAAAAQueryIsBlockedLocally(t *testing.T) {
	q := query(t, "example.com.", dnsmessage.TypeAAAA, 0x1234)

	// upstream is unreachable on purpose: an AAAA query must be answered
	// locally without forwarding.
	resp := resolveIPv4Only(discardLogger(), q, "203.0.113.1:53")

	var p dnsmessage.Parser

	h, err := p.Start(resp)

	if err != nil {
		t.Fatalf("parse response: %v", err)
	}

	if !h.Response {
		t.Error("expected Response bit set")
	}

	if h.ID != 0x1234 {
		t.Errorf("ID = %#x, want 0x1234", h.ID)
	}

	if h.RCode != dnsmessage.RCodeSuccess {
		t.Errorf("RCode = %v, want success (NODATA)", h.RCode)
	}

	qs, err := p.AllQuestions()

	if err != nil || len(qs) != 1 || qs[0].Type != dnsmessage.TypeAAAA {
		t.Errorf("questions = %v (err %v), want one AAAA question echoed", qs, err)
	}

	if err := p.SkipAllQuestions(); err != nil {
		t.Fatal(err)
	}

	ans, err := p.AllAnswers()

	if err != nil && err != dnsmessage.ErrSectionDone {
		t.Fatalf("answers: %v", err)
	}

	if len(ans) != 0 {
		t.Errorf("answers = %d, want 0 (NODATA)", len(ans))
	}
}

func TestParseUpstreamDNS(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want string
	}{
		{"", ""},
		{"1.1.1.1", "1.1.1.1:53"},
		{"1.1.1.1:5353", "1.1.1.1:5353"},
		{"2001:4860:4860::8888", "[2001:4860:4860::8888]:53"},
		{"[2001:4860:4860::8888]:5353", "[2001:4860:4860::8888]:5353"},
	} {
		if got := parseUpstreamDNS(tc.in); got != tc.want {
			t.Errorf("parseUpstreamDNS(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestParseUpstreamDNSInvalid(t *testing.T) {
	err := Try(func() { parseUpstreamDNS("not-an-ip") })

	if err == nil {
		t.Error("expected error for invalid -D address")
	}
}
