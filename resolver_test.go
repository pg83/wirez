package main

import (
	"bytes"
	"encoding/binary"
	"io"
	"log/slog"
	"net"
	"strconv"
	"testing"
	"time"

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

// fakeUpstream is a DNS server on loopback that answers UDP queries with
// udpReply and TCP queries with tcpReply (nil: no TCP listener at all).
func fakeUpstream(t *testing.T, udpReply, tcpReply []byte) string {
	t.Helper()

	udpConn, err := net.ListenPacket("udp", "127.0.0.1:0")

	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { udpConn.Close() })

	go func() {
		buf := make([]byte, dnsBufferSize)

		for {
			_, addr, err := udpConn.ReadFrom(buf)

			if err != nil {
				return
			}

			udpConn.WriteTo(udpReply, addr)
		}
	}()

	addr := udpConn.LocalAddr().String()

	if tcpReply == nil {
		return addr
	}

	port := udpConn.LocalAddr().(*net.UDPAddr).Port
	ln, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))

	if err != nil {
		t.Skipf("tcp port %d is busy: %v", port, err)
	}

	t.Cleanup(func() { ln.Close() })

	go func() {
		for {
			c, err := ln.Accept()

			if err != nil {
				return
			}

			go func() {
				defer c.Close()

				var length [2]byte

				if _, err := io.ReadFull(c, length[:]); err != nil {
					return
				}

				q := make([]byte, binary.BigEndian.Uint16(length[:]))

				if _, err := io.ReadFull(c, q); err != nil {
					return
				}

				out := make([]byte, 2+len(tcpReply))
				binary.BigEndian.PutUint16(out, uint16(len(tcpReply)))
				copy(out[2:], tcpReply)
				c.Write(out)
			}()
		}
	}()

	return addr
}

func TestAAAAQueryIsBlockedLocally(t *testing.T) {
	q := query(t, "example.com.", dnsmessage.TypeAAAA, 0x1234)

	// upstream is unreachable on purpose: an AAAA query must be answered
	// locally without forwarding.
	resp := resolveDNS(discardLogger(), q, "203.0.113.1:53", &dnsPolicy{})

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

func TestForwardDNSKeepsCompleteUDPAnswer(t *testing.T) {
	q := query(t, "example.com.", dnsmessage.TypeA, 7)
	full := aResponse(t, q, false, "192.0.2.1")
	upstream := fakeUpstream(t, full, nil)

	var got []byte

	err := Try(func() { got = forwardDNS(q, upstream) })

	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(got, full) {
		t.Errorf("forwardDNS returned %x, want the UDP answer %x", got, full)
	}
}

func TestForwardDNSFallsBackToTCPWhenTruncated(t *testing.T) {
	q := query(t, "example.com.", dnsmessage.TypeA, 7)
	truncated := aResponse(t, q, true)
	full := aResponse(t, q, false, "192.0.2.1", "192.0.2.2")
	upstream := fakeUpstream(t, truncated, full)

	var got []byte

	err := Try(func() { got = forwardDNS(q, upstream) })

	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(got, full) {
		t.Errorf("forwardDNS returned %x, want the TCP answer %x", got, full)
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

func TestServeDNSStopsWhenClosed(t *testing.T) {
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")

	if err != nil {
		t.Fatal(err)
	}

	done := make(chan struct{})

	go func() {
		serveDNS(discardLogger(), conn, "203.0.113.1:53", &dnsPolicy{})
		close(done)
	}()

	conn.Close()

	select {
	case <-done:
	case <-time.After(testTimeout):
		t.Fatal("serveDNS did not return after the listener was closed")
	}
}

func TestServeDNSAnswersQueries(t *testing.T) {
	q := query(t, "example.com.", dnsmessage.TypeA, 9)
	full := aResponse(t, q, false, "192.0.2.1")
	upstream := fakeUpstream(t, full, nil)

	listener, err := net.ListenPacket("udp", "127.0.0.1:0")

	if err != nil {
		t.Fatal(err)
	}

	defer listener.Close()

	go serveDNS(discardLogger(), listener, upstream, &dnsPolicy{})

	client, err := net.Dial("udp", listener.LocalAddr().String())

	if err != nil {
		t.Fatal(err)
	}

	defer client.Close()
	client.SetDeadline(time.Now().Add(testTimeout))

	if _, err := client.Write(q); err != nil {
		t.Fatal(err)
	}

	buf := make([]byte, dnsBufferSize)
	n, err := client.Read(buf)

	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(buf[:n], full) {
		t.Errorf("resolver answered %x, want %x", buf[:n], full)
	}
}
