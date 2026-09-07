package main

import (
	"context"
	"net"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

func nat64Prefix(t *testing.T) *net.IPNet {
	t.Helper()

	return parseNAT64("64:ff9b::/96")
}

func TestNAT64MapUnmap(t *testing.T) {
	prefix := nat64Prefix(t)

	for _, tc := range []struct {
		in     string
		mapped string
	}{
		{"5.255.240.6:443", "[64:ff9b::5ff:f006]:443"},
		{"[2a02:6b8::1]:80", "[2a02:6b8::1]:80"},
		// an IPv4-mapped address is still IPv4 for the host, so it goes through NAT64 too
		{"[::ffff:1.2.3.4]:80", "[64:ff9b::102:304]:80"},
	} {
		if got := nat64Map(prefix, tc.in); got != tc.mapped {
			t.Errorf("nat64Map(%q) = %q, want %q", tc.in, got, tc.mapped)
		}
	}

	if got := nat64Unmap(prefix, "[64:ff9b::5ff:f006]:443"); got != "5.255.240.6:443" {
		t.Errorf("nat64Unmap = %q, want 5.255.240.6:443", got)
	}

	if got := nat64Unmap(prefix, "[2a02:6b8::1]:80"); got != "[2a02:6b8::1]:80" {
		t.Errorf("nat64Unmap left = %q", got)
	}

	if got := nat64Unmap(nil, "[64:ff9b::5ff:f006]:443"); got != "[64:ff9b::5ff:f006]:443" {
		t.Errorf("nat64Unmap(nil) = %q, want passthrough", got)
	}
}

func TestParseNAT64Invalid(t *testing.T) {
	for _, in := range []string{"64:ff9b::/64", "10.0.0.0/8", "garbage"} {
		if err := Try(func() { parseNAT64(in) }); err == nil {
			t.Errorf("parseNAT64(%q): expected error", in)
		}
	}

	if parseNAT64("") != nil {
		t.Error("parseNAT64(\"\") must be nil")
	}
}

type recordingConnector struct {
	name   string
	dialed *string
	last   *string
}

func (c *recordingConnector) DialContext(_ context.Context, _, address string) (net.Conn, error) {
	*c.dialed = c.name
	*c.last = address

	return nil, nil
}

func TestDialOrderMappingBeforeBypass(t *testing.T) {
	var dialed, last string

	direct := &recordingConnector{"direct", &dialed, &last}
	socks := &recordingConnector{"socks", &dialed, &last}
	nat := parseAddressMapper([]string{"37933:127.0.0.1:37933/tcp"})
	bypass := parseBypassNets([]string{"10.0.0.0/8", "5.255.192.0/18"})
	c := NewLocalForwardingConnector(direct, socks, nat, bypass, nat64Prefix(t))

	for _, tc := range []struct {
		address string
		via     string
		target  string
	}{
		// -L wins over -B even though 10.1.1.2 is inside a bypass network
		{"10.1.1.2:37933", "direct", "127.0.0.1:37933"},
		// bypassed IPv4 is dialed through NAT64
		{"10.1.1.2:80", "direct", "[64:ff9b::a01:102]:80"},
		// DNS64-synthesized address is unmapped and then follows the IPv4 rules
		{"[64:ff9b::5ff:f006]:443", "direct", "[64:ff9b::5ff:f006]:443"},
		{"[64:ff9b::a04f:680a]:443", "socks", "160.79.104.10:443"},
		{"[2607:6bc0::10]:443", "socks", "[2607:6bc0::10]:443"},
	} {
		_, _ = c.DialContext(context.Background(), "tcp", tc.address)

		if dialed != tc.via || last != tc.target {
			t.Errorf("dial %q: via %s to %q, want via %s to %q", tc.address, dialed, last, tc.via, tc.target)
		}
	}
}

func aaaaResponse(t *testing.T, name string, ips ...string) []byte {
	t.Helper()

	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 1, Response: true})
	n := dnsmessage.MustNewName(name)

	if err := b.StartQuestions(); err != nil {
		t.Fatal(err)
	}

	if err := b.Question(dnsmessage.Question{Name: n, Type: dnsmessage.TypeAAAA, Class: dnsmessage.ClassINET}); err != nil {
		t.Fatal(err)
	}

	if err := b.StartAnswers(); err != nil {
		t.Fatal(err)
	}

	for _, s := range ips {
		var r dnsmessage.AAAAResource
		copy(r.AAAA[:], net.ParseIP(s).To16())

		hdr := dnsmessage.ResourceHeader{Name: n, Type: dnsmessage.TypeAAAA, Class: dnsmessage.ClassINET, TTL: 60}

		if err := b.AAAAResource(hdr, r); err != nil {
			t.Fatal(err)
		}
	}

	msg, err := b.Finish()

	if err != nil {
		t.Fatal(err)
	}

	return msg
}

func TestDNSPolicyAllowsAAAA(t *testing.T) {
	allow := parseBypassNets([]string{"2a02:6b8::/32", "5.255.192.0/18"})
	policy := &dnsPolicy{ipv6: true, allow: allow, nat64: nat64Prefix(t)}

	for _, tc := range []struct {
		ips  []string
		want bool
	}{
		{[]string{"2a02:6b8::1"}, true},
		{[]string{"2607:6bc0::10"}, false},
		{[]string{"64:ff9b::5ff:f006"}, true},
		{[]string{"64:ff9b::a04f:680a"}, false},
		{[]string{"2607:6bc0::10", "2a02:6b8::1"}, true},
		{nil, false},
	} {
		if got := policy.allowsAAAA(aaaaResponse(t, "example.com.", tc.ips...)); got != tc.want {
			t.Errorf("allowsAAAA(%v) = %v, want %v", tc.ips, got, tc.want)
		}
	}

	off := &dnsPolicy{allow: allow}

	if off.allowsAAAA(aaaaResponse(t, "example.com.", "2a02:6b8::1")) {
		t.Error("allowsAAAA must be false without -6")
	}
}
