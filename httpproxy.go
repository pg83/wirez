package main

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"net/textproto"
	"net/url"
	"strings"
	"time"
)

func NewHTTPConnector(connector Connector, proxy *ProxyAddr) Connector {
	return &httpConnector{tcpConnector: connector, proxy: proxy}
}

// httpConnector tunnels TCP through an HTTP proxy with CONNECT (RFC 9110
// section 9.3.6). UDP has no equivalent, so a chain with an HTTP hop carries
// TCP only.
type httpConnector struct {
	tcpConnector Connector
	proxy        *ProxyAddr
}

func (c *httpConnector) DialContext(ctx context.Context, network, address string) (conn net.Conn, err error) {
	err = Try(func() {
		conn = c.connect(ctx, network, address)
	}).AsError()

	if err != nil {
		err = fmt.Errorf("%s via %s: %w", address, c.proxy.Address, err)
	}

	return
}

func (c *httpConnector) connect(ctx context.Context, network, address string) net.Conn {
	if network != "tcp" {
		ThrowFmt("http proxy: network %s is not supported", network)
	}

	conn := Throw2(c.tcpConnector.DialContext(ctx, "tcp", c.proxy.Address))
	defer CloseOnThrow(conn)

	return httpConnect(ctx, conn, c.proxy.Auth, address)
}

// httpConnect asks the proxy for a tunnel to address. Bytes the proxy has
// already forwarded after the response headers stay readable through the
// returned connection.
func httpConnect(ctx context.Context, conn net.Conn, auth *url.Userinfo, address string) net.Conn {
	applyDeadline(ctx, conn)

	var req strings.Builder

	fmt.Fprintf(&req, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n", address, address)

	if auth != nil {
		pass, _ := auth.Password()
		credentials := base64.StdEncoding.EncodeToString([]byte(auth.Username() + ":" + pass))
		fmt.Fprintf(&req, "Proxy-Authorization: Basic %s\r\n", credentials)
	}

	req.WriteString("\r\n")
	Throw2(conn.Write([]byte(req.String())))

	br := bufio.NewReader(conn)
	tp := textproto.NewReader(br)
	status := Throw2(tp.ReadLine())
	parts := strings.SplitN(status, " ", 3)

	if len(parts) < 2 || !strings.HasPrefix(parts[0], "HTTP/") {
		ThrowFmt("http proxy: malformed response %q", status)
	}

	Throw2(tp.ReadMIMEHeader())

	if parts[1] != "200" {
		ThrowFmt("http proxy: %s", strings.TrimPrefix(status, parts[0]+" "))
	}

	Throw(conn.SetDeadline(time.Time{}))

	return &httpTunnel{Conn: conn, r: br}
}

// httpTunnel is an established CONNECT tunnel; reads drain what the response
// reader buffered before touching the connection.
type httpTunnel struct {
	net.Conn
	r *bufio.Reader
}

func (t *httpTunnel) Read(b []byte) (int, error) {
	return t.r.Read(b)
}

func (t *httpTunnel) CloseWrite() error {
	return closeWrite(t.Conn)
}
