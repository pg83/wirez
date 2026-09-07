package main

import (
	"context"
	"testing"
)

func TestParseProxyURL(t *testing.T) {
	for _, tc := range []struct {
		in     string
		scheme string
		addr   string
		user   string
	}{
		{"127.0.0.1:1080", "socks5", "127.0.0.1:1080", ""},
		{"socks5://u:p@[::1]:1080", "socks5", "[::1]:1080", "u"},
		{"socks5h://proxy.example:1080", "socks5", "proxy.example:1080", ""},
		{"http://u:p@proxy.example:3128", "http", "proxy.example:3128", "u"},
	} {
		p := parseProxyURL(tc.in)

		if p.Scheme != tc.scheme || p.Address != tc.addr || p.Auth.Username() != tc.user {
			t.Errorf("parseProxyURL(%q) = %+v", tc.in, p)
		}
	}

	for _, in := range []string{"https://proxy.example:443", "ftp://x:1", "socks5://noport"} {
		if err := Try(func() { parseProxyURL(in) }); err == nil {
			t.Errorf("parseProxyURL(%q) accepted", in)
		}
	}
}

func TestProxyChainWithHTTPHopHasNoUDP(t *testing.T) {
	proxies := parseProxyURLs([]string{"socks5://127.0.0.1:1080", "http://127.0.0.1:3128"})
	_, udpConn := buildProxyChain(discardLogger(), proxies)

	if _, err := udpConn.DialContext(context.Background(), "udp", "192.0.2.1:53"); err == nil {
		t.Error("udp through an HTTP hop did not fail")
	}

	proxies = parseProxyURLs([]string{"127.0.0.1:1080", "socks5h://127.0.0.1:1081"})
	_, udpConn = buildProxyChain(discardLogger(), proxies)

	if _, ok := udpConn.(*socks5UDPConnector); !ok {
		t.Errorf("udp connector for a SOCKS-only chain is %T", udpConn)
	}
}
