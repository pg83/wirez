package main

import (
	"net"
	"strconv"
	"testing"
)

// dstAddress mirrors how network_stack.go builds the destination address
// from a gVisor endpoint id.
func dstAddress(host string, port uint16) string {
	return net.JoinHostPort(host, strconv.Itoa(int(port)))
}

func TestIPv6DestinationAddressIsValid(t *testing.T) {
	for _, tc := range []struct {
		host string
		port uint16
		want string
	}{
		{"1.2.3.4", 443, "1.2.3.4:443"},
		{"2606:4700:4700::1111", 443, "[2606:4700:4700::1111]:443"},
		{"::1", 53, "[::1]:53"},
	} {
		got := dstAddress(tc.host, tc.port)

		if got != tc.want {
			t.Errorf("dstAddress(%q,%d) = %q, want %q", tc.host, tc.port, got, tc.want)
		}

		if _, _, err := net.SplitHostPort(got); err != nil {
			t.Errorf("dstAddress(%q,%d) = %q is not a valid host:port: %v", tc.host, tc.port, got, err)
		}
	}
}

func TestIPv6BypassMatch(t *testing.T) {
	bypass := parseBypassNets([]string{"fd00::/8", "2606:4700::/32", "10.0.0.0/8"})
	c := &localForwardingConnector{bypass: bypass}

	for _, tc := range []struct {
		address string
		want    bool
	}{
		{dstAddress("2606:4700:4700::1111", 443), true},
		{dstAddress("fd00::1", 53), true},
		{dstAddress("2001:db8::1", 443), false},
		{dstAddress("10.1.2.3", 80), true},
		{dstAddress("8.8.8.8", 53), false},
	} {
		if got := c.matchBypass(tc.address); got != tc.want {
			t.Errorf("matchBypass(%q) = %v, want %v", tc.address, got, tc.want)
		}
	}
}

func TestIPv6AddressMapping(t *testing.T) {
	m := parseAddressMapper([]string{
		"[2606:4700::1]:443:[fd00::2]:8443/tcp",
		"53:[::1]:5353/udp",
	})

	// full IPv6 destination -> rewritten target
	if got, ok := m.MapAddress("tcp", dstAddress("2606:4700::1", 443)); !ok || got != "[fd00::2]:8443" {
		t.Errorf("full IPv6 map = %q, ok=%v; want %q", got, ok, "[fd00::2]:8443")
	}

	// port-only rule applies to any IPv6 destination on that udp port
	if got, ok := m.MapAddress("udp", dstAddress("2606:4700:4700::1111", 53)); !ok || got != "[::1]:5353" {
		t.Errorf("port-only IPv6 map = %q, ok=%v; want %q", got, ok, "[::1]:5353")
	}
}
