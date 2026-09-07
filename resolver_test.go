package main

import (
	"io"
	"log/slog"
	"net"
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

// aResponse answers query with the given A records; truncated sets the TC bit.
func aResponse(t *testing.T, query []byte, truncated bool, ips ...string) []byte {
	t.Helper()

	var p dnsmessage.Parser

	h, err := p.Start(query)

	if err != nil {
		t.Fatal(err)
	}

	q, err := p.Question()

	if err != nil {
		t.Fatal(err)
	}

	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: h.ID, Response: true, Truncated: truncated})

	if err := b.StartQuestions(); err != nil {
		t.Fatal(err)
	}

	if err := b.Question(q); err != nil {
		t.Fatal(err)
	}

	if err := b.StartAnswers(); err != nil {
		t.Fatal(err)
	}

	for _, s := range ips {
		var r dnsmessage.AResource
		copy(r.A[:], net.ParseIP(s).To4())

		hdr := dnsmessage.ResourceHeader{Name: q.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 60}

		if err := b.AResource(hdr, r); err != nil {
			t.Fatal(err)
		}
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
	resp := resolveDNS(discardLogger(), q, newDNSUpstreams([]string{"203.0.113.1:53"}), &dnsPolicy{})

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
		{"1.1.1.1", "1.1.1.1:53"},
		{"1.1.1.1:5353", "1.1.1.1:5353"},
		{"2001:4860:4860::8888", "[2001:4860:4860::8888]:53"},
		{"[2001:4860:4860::8888]:5353", "[2001:4860:4860::8888]:5353"},
	} {
		if got := parseUpstreamDNS(tc.in); got != tc.want {
			t.Errorf("parseUpstreamDNS(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}

	for _, in := range []string{"", "not-an-ip"} {
		if err := Try(func() { parseUpstreamDNS(in) }); err == nil {
			t.Errorf("parseUpstreamDNS(%q) accepted", in)
		}
	}
}

func TestIsTruncated(t *testing.T) {
	q := query(t, "example.com.", dnsmessage.TypeA, 1)

	if isTruncated(aResponse(t, q, false, "192.0.2.1")) {
		t.Error("complete answer reported as truncated")
	}

	if !isTruncated(aResponse(t, q, true)) {
		t.Error("TC answer not reported as truncated")
	}

	if isTruncated([]byte{1, 2, 3}) {
		t.Error("garbage reported as truncated")
	}
}
