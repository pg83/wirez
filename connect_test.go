package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

func dialContext(t *testing.T) context.Context {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	t.Cleanup(cancel)

	return ctx
}

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

func TestSOCKS5ConnHalfClose(t *testing.T) {
	dst := eofEchoServer(t)
	proxy := newSocks5TestServer(t, socks5TestConfig{})
	connector := NewSOCKS5Connector(NewDirectConnector(), parseProxyURL(proxy.Addr()))

	conn, err := connector.DialContext(dialContext(t), "tcp", dst)

	if err != nil {
		t.Fatal(err)
	}

	defer conn.Close()
	conn.SetDeadline(time.Now().Add(testTimeout))

	if _, err := conn.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}

	if err := closeWrite(conn); err != nil {
		t.Fatalf("CloseWrite: %v", err)
	}

	got, err := io.ReadAll(conn)

	if err != nil || string(got) != "echo:hello" {
		t.Fatalf("read %q, %v; want \"echo:hello\" and EOF", got, err)
	}

	if connects := proxy.Connects(); len(connects) != 1 || connects[0] != dst {
		t.Errorf("proxy saw CONNECT %v, want [%s]", connects, dst)
	}
}

// A proxy may deliver the destination's first bytes in the same segment as
// its CONNECT reply; they must reach the application.
func TestSOCKS5KeepsBytesAfterReply(t *testing.T) {
	dst := eofEchoServer(t)
	proxy := newSocks5TestServer(t, socks5TestConfig{banner: []byte("SSH-2.0-banner\r\n")})
	connector := NewSOCKS5Connector(NewDirectConnector(), parseProxyURL(proxy.Addr()))

	conn, err := connector.DialContext(dialContext(t), "tcp", dst)

	if err != nil {
		t.Fatal(err)
	}

	defer conn.Close()
	conn.SetDeadline(time.Now().Add(testTimeout))

	buf := make([]byte, len(proxy.banner))

	if _, err := io.ReadFull(conn, buf); err != nil || !bytes.Equal(buf, proxy.banner) {
		t.Fatalf("read %q, %v; want the banner", buf, err)
	}
}

func TestSOCKS5Auth(t *testing.T) {
	dst := eofEchoServer(t)
	proxy := newSocks5TestServer(t, socks5TestConfig{user: "alice", pass: "s3cret"})

	good := NewSOCKS5Connector(NewDirectConnector(), parseProxyURL("socks5://alice:s3cret@"+proxy.Addr()))
	conn, err := good.DialContext(dialContext(t), "tcp", dst)

	if err != nil {
		t.Fatalf("authenticated dial: %v", err)
	}

	conn.Close()

	bad := NewSOCKS5Connector(NewDirectConnector(), parseProxyURL("socks5://alice:wrong@"+proxy.Addr()))

	if conn, err := bad.DialContext(dialContext(t), "tcp", dst); err == nil {
		conn.Close()
		t.Fatal("dial with a wrong password succeeded")
	}

	anonymous := NewSOCKS5Connector(NewDirectConnector(), parseProxyURL(proxy.Addr()))

	if conn, err := anonymous.DialContext(dialContext(t), "tcp", dst); err == nil {
		conn.Close()
		t.Fatal("dial without credentials succeeded")
	}
}

func TestSOCKS5ConnectRefused(t *testing.T) {
	proxy := newSocks5TestServer(t, socks5TestConfig{})
	connector := NewSOCKS5Connector(NewDirectConnector(), parseProxyURL(proxy.Addr()))

	// nothing listens on the destination: the proxy must report a failure
	ln, err := net.Listen("tcp", "127.0.0.1:0")

	if err != nil {
		t.Fatal(err)
	}

	unused := ln.Addr().String()
	ln.Close()

	if conn, err := connector.DialContext(dialContext(t), "tcp", unused); err == nil {
		conn.Close()
		t.Fatal("dial to a closed port succeeded")
	}
}

func exchange(t *testing.T, conn net.Conn, msg string) string {
	t.Helper()

	conn.SetDeadline(time.Now().Add(testTimeout))

	if _, err := conn.Write([]byte(msg)); err != nil {
		t.Fatal(err)
	}

	buf := make([]byte, 1024)
	n, err := conn.Read(buf)

	if err != nil {
		t.Fatalf("read after sending %q: %v", msg, err)
	}

	return string(buf[:n])
}

// Flows from one source share an association; each still only sees replies
// to its own destination.
func TestSOCKS5UDPSharedAssociation(t *testing.T) {
	echo1 := udpEchoServer(t)
	echo2 := udpEchoServer(t)
	proxy := newSocks5TestServer(t, socks5TestConfig{})
	direct := NewDirectConnector()
	connector := NewSOCKS5UDPConnector(discardLogger(), direct, direct, parseProxyURL(proxy.Addr()))
	ctx := withUDPSource(dialContext(t), "10.1.1.5:40000")

	flow1, err := connector.DialContext(ctx, "udp", echo1)

	if err != nil {
		t.Fatal(err)
	}

	flow2, err := connector.DialContext(ctx, "udp", echo2)

	if err != nil {
		t.Fatal(err)
	}

	if got := exchange(t, flow1, "one"); got != "one" {
		t.Errorf("flow1 got %q", got)
	}

	if got := exchange(t, flow2, "two"); got != "two" {
		t.Errorf("flow2 got %q", got)
	}

	if n := proxy.Associations(); n != 1 {
		t.Errorf("associations = %d, want 1 for one source", n)
	}

	// closing one flow leaves the association to the other
	flow1.Close()

	if got := exchange(t, flow2, "still"); got != "still" {
		t.Errorf("flow2 after flow1 closed got %q", got)
	}

	// a different source gets its own association
	other, err := connector.DialContext(withUDPSource(dialContext(t), "10.1.1.5:40001"), "udp", echo1)

	if err != nil {
		t.Fatal(err)
	}

	defer other.Close()

	if got := exchange(t, other, "other"); got != "other" {
		t.Errorf("other source got %q", got)
	}

	if n := proxy.Associations(); n != 2 {
		t.Errorf("associations = %d, want 2 for two sources", n)
	}

	// the last flow closing ends the association; the source can come back
	flow2.Close()

	again, err := connector.DialContext(ctx, "udp", echo2)

	if err != nil {
		t.Fatal(err)
	}

	defer again.Close()

	if got := exchange(t, again, "again"); got != "again" {
		t.Errorf("reopened source got %q", got)
	}

	if n := proxy.Associations(); n != 3 {
		t.Errorf("associations = %d, want 3 after the source came back", n)
	}
}

// Without a source in the context every flow gets its own association.
func TestSOCKS5UDPDedicatedAssociation(t *testing.T) {
	echo := udpEchoServer(t)
	proxy := newSocks5TestServer(t, socks5TestConfig{})
	direct := NewDirectConnector()
	connector := NewSOCKS5UDPConnector(discardLogger(), direct, direct, parseProxyURL(proxy.Addr()))

	for i, msg := range []string{"a", "b"} {
		conn, err := connector.DialContext(dialContext(t), "udp", echo)

		if err != nil {
			t.Fatal(err)
		}

		if got := exchange(t, conn, msg); got != msg {
			t.Errorf("flow %d got %q", i, got)
		}

		conn.Close()
	}

	if n := proxy.Associations(); n != 2 {
		t.Errorf("associations = %d, want 2", n)
	}
}

func TestUDPFlowReadDeadline(t *testing.T) {
	proxy := newSocks5TestServer(t, socks5TestConfig{})
	direct := NewDirectConnector()
	connector := NewSOCKS5UDPConnector(discardLogger(), direct, direct, parseProxyURL(proxy.Addr()))

	flow, err := connector.DialContext(withUDPSource(dialContext(t), "10.1.1.5:1"), "udp", "192.0.2.1:9")

	if err != nil {
		t.Fatal(err)
	}

	defer flow.Close()

	flow.SetDeadline(time.Now().Add(50 * time.Millisecond))
	_, err = flow.Read(make([]byte, 16))

	var terr timeoutError

	if !errors.As(err, &terr) || !terr.Timeout() {
		t.Errorf("Read past the deadline = %v, want a timeout", err)
	}
}
