package main

import (
	"bytes"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// httpTestConfig tunes an httpTestProxy; it is fixed at construction.
type httpTestConfig struct {
	auth   string // expected Proxy-Authorization value when set
	banner []byte // sent in the same write as the response
}

// httpTestProxy is an HTTP CONNECT proxy for tests. Like socks5TestServer it
// can require credentials and put the destination's first bytes into the same
// write as its response.
type httpTestProxy struct {
	httpTestConfig

	srv *httptest.Server

	mu       sync.Mutex
	connects []string
}

func newHTTPTestProxy(t *testing.T, cfg httpTestConfig) *httpTestProxy {
	t.Helper()

	p := &httpTestProxy{httpTestConfig: cfg}
	p.srv = httptest.NewServer(http.HandlerFunc(p.handle))
	t.Cleanup(p.srv.Close)

	return p
}

func (p *httpTestProxy) Addr() string {
	return strings.TrimPrefix(p.srv.URL, "http://")
}

func (p *httpTestProxy) Connects() []string {
	p.mu.Lock()
	defer p.mu.Unlock()

	return append([]string(nil), p.connects...)
}

func (p *httpTestProxy) handle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodConnect {
		http.Error(w, "CONNECT only", http.StatusMethodNotAllowed)

		return
	}

	if p.auth != "" && r.Header.Get("Proxy-Authorization") != p.auth {
		http.Error(w, "credentials required", http.StatusProxyAuthRequired)

		return
	}

	p.mu.Lock()
	p.connects = append(p.connects, r.Host)
	p.mu.Unlock()

	d, err := net.DialTimeout("tcp", r.Host, testTimeout)

	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)

		return
	}

	dst := d.(*net.TCPConn)
	defer dst.Close()

	c, _, err := w.(http.Hijacker).Hijack()

	if err != nil {
		return
	}

	conn := c.(*net.TCPConn)
	defer conn.Close()

	conn.Write(append([]byte("HTTP/1.1 200 Connection established\r\n\r\n"), p.banner...))

	done := make(chan struct{}, 2)
	relay := func(w, r *net.TCPConn) {
		io.Copy(w, r)
		w.CloseWrite()
		done <- struct{}{}
	}

	go relay(dst, conn)
	go relay(conn, dst)

	<-done
	<-done
}

func TestHTTPConnectTunnel(t *testing.T) {
	dst := eofEchoServer(t)
	proxy := newHTTPTestProxy(t, httpTestConfig{})
	connector := NewHTTPConnector(NewDirectConnector(), parseProxyURL("http://"+proxy.Addr()))

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

func TestHTTPConnectKeepsBytesAfterResponse(t *testing.T) {
	dst := eofEchoServer(t)
	proxy := newHTTPTestProxy(t, httpTestConfig{banner: []byte("220 smtp ready\r\n")})
	connector := NewHTTPConnector(NewDirectConnector(), parseProxyURL("http://"+proxy.Addr()))

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

func TestHTTPConnectAuth(t *testing.T) {
	dst := eofEchoServer(t)
	proxy := newHTTPTestProxy(t, httpTestConfig{auth: "Basic YWxpY2U6czNjcmV0"}) // alice:s3cret

	good := NewHTTPConnector(NewDirectConnector(), parseProxyURL("http://alice:s3cret@"+proxy.Addr()))
	conn, err := good.DialContext(dialContext(t), "tcp", dst)

	if err != nil {
		t.Fatalf("authenticated dial: %v", err)
	}

	conn.Close()

	anonymous := NewHTTPConnector(NewDirectConnector(), parseProxyURL("http://"+proxy.Addr()))

	if conn, err := anonymous.DialContext(dialContext(t), "tcp", dst); err == nil {
		conn.Close()
		t.Fatal("dial without credentials succeeded")
	}
}

func TestHTTPConnectRefused(t *testing.T) {
	proxy := newHTTPTestProxy(t, httpTestConfig{})
	connector := NewHTTPConnector(NewDirectConnector(), parseProxyURL("http://"+proxy.Addr()))

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

func TestProxyChainWithHTTPHopHasNoUDP(t *testing.T) {
	proxies := parseProxyURLs([]string{"socks5://127.0.0.1:1080", "http://127.0.0.1:3128"})
	_, udpConn := buildProxyChain(discardLogger(), proxies)

	if _, err := udpConn.DialContext(dialContext(t), "udp", "192.0.2.1:53"); err == nil {
		t.Error("udp through an HTTP hop did not fail")
	}

	proxies = parseProxyURLs([]string{"127.0.0.1:1080", "socks5h://127.0.0.1:1081"})
	_, udpConn = buildProxyChain(discardLogger(), proxies)

	if _, ok := udpConn.(*socks5UDPConnector); !ok {
		t.Errorf("udp connector for a SOCKS-only chain is %T", udpConn)
	}
}

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
