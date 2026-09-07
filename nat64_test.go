package main

import (
	"context"
	"net"
	"testing"
)

// The NAT64 leg of the routing decision needs an IPv6-only host with a NAT64
// gateway to be observed end to end, so it is checked here on the pure
// decision instead.

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

func TestBypassedIPv4IsDialedThroughNAT64(t *testing.T) {
	var dialed, last string

	direct := &recordingConnector{"direct", &dialed, &last}
	socks := &recordingConnector{"socks", &dialed, &last}
	nat := parseAddressMapper([]string{"37933:127.0.0.1:37933/tcp"})
	bypass := parseBypassNets([]string{"10.0.0.0/8", "5.255.192.0/18"})
	c := NewLocalForwardingConnector(direct, socks, nat, bypass, nil, nat64Prefix(t))

	for _, tc := range []struct {
		address string
		via     string
		target  string
	}{
		// bypassed IPv4 is dialed through NAT64
		{"10.2.0.1:80", "direct", "[64:ff9b::a02:1]:80"},
		// a synthesized address that unmaps into a bypass network goes direct, still through NAT64
		{"[64:ff9b::5ff:f006]:443", "direct", "[64:ff9b::5ff:f006]:443"},
		// one that does not is handed to the proxy as plain IPv4
		{"[64:ff9b::a04f:680a]:443", "socks", "160.79.104.10:443"},
		// -L rewrites are not run through NAT64
		{"10.2.0.1:37933", "direct", "127.0.0.1:37933"},
	} {
		_, _ = c.DialContext(context.Background(), "tcp", tc.address)

		if dialed != tc.via || last != tc.target {
			t.Errorf("dial %q: via %s to %q, want via %s to %q", tc.address, dialed, last, tc.via, tc.target)
		}
	}
}
