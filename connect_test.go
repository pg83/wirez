package main

import (
	"bytes"
	"context"
	"testing"
)

func TestSOCKS5AddrRoundTrip(t *testing.T) {
	for _, tc := range []struct {
		host string
		port uint16
	}{
		{"1.2.3.4", 80},
		{"2001:db8::1", 443},
		{"example.com", 8080},
	} {
		b := socks5AppendAddr(nil, tc.host, tc.port)
		host, port, err := socks5ReadAddr(bytes.NewReader(b))

		if err != nil || host != tc.host || port != tc.port {
			t.Errorf("round trip of %s:%d = %s:%d, %v", tc.host, tc.port, host, port, err)
		}
	}

	if _, _, err := socks5ReadAddr(bytes.NewReader([]byte{0x09})); err == nil {
		t.Error("bad address type accepted")
	}
}

func TestSOCKS5UDPDatagramRoundTrip(t *testing.T) {
	d := socks5UDPDatagram("192.0.2.1", 53, []byte("payload"))
	host, port, payload, err := socks5ParseUDPDatagram(d)

	if err != nil || host != "192.0.2.1" || port != 53 || string(payload) != "payload" {
		t.Errorf("parse = %s:%d %q, %v", host, port, payload, err)
	}

	if _, _, _, err := socks5ParseUDPDatagram([]byte{0, 0, 1, 1, 1, 2, 3, 4, 0, 53}); err == nil {
		t.Error("fragmented datagram accepted")
	}
}

func TestSOCKS5ReplyError(t *testing.T) {
	if got := socks5ReplyError(0x05).Error(); got != "socks5: connection refused" {
		t.Errorf("reply 5 = %q", got)
	}

	if got := socks5ReplyError(0x42).Error(); got != "socks5: reply code 66" {
		t.Errorf("unknown reply = %q", got)
	}
}

func TestUDPFlowKey(t *testing.T) {
	for _, tc := range []struct {
		host string
		port uint16
		want string
	}{
		{"192.0.2.1", 53, "192.0.2.1:53"},
		{"::ffff:192.0.2.1", 53, "192.0.2.1:53"},
		{"2001:DB8::1", 53, "[2001:db8::1]:53"},
	} {
		if got := udpFlowKey(tc.host, tc.port); got != tc.want {
			t.Errorf("udpFlowKey(%q, %d) = %q, want %q", tc.host, tc.port, got, tc.want)
		}
	}
}

func TestUDPDialNeedsASource(t *testing.T) {
	connector := NewSOCKS5UDPConnector(discardLogger(), NewDirectConnector(), NewDirectConnector(), parseProxyURL("127.0.0.1:1"))

	if _, err := connector.DialContext(context.Background(), "udp", "192.0.2.1:53"); err == nil {
		t.Error("udp dial without a source endpoint succeeded")
	}
}
