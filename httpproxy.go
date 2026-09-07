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

func (c *httpConnector) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if network != "tcp" {
		return nil, fmt.Errorf("http proxy: network %s is not supported", network)
	}

	conn, err := c.tcpConnector.DialContext(ctx, "tcp", c.proxy.Address)

	if err != nil {
		return nil, err
	}

	tunnel, err := httpConnect(ctx, conn, c.proxy.Auth, address)

	if err != nil {
		conn.Close()

		return nil, fmt.Errorf("%s via %s: %w", address, c.proxy.Address, err)
	}

	return tunnel, nil
}

// httpConnect asks the proxy for a tunnel to address. Bytes the proxy has
// already forwarded after the response headers stay readable through the
// returned connection.
func httpConnect(ctx context.Context, conn net.Conn, auth *url.Userinfo, address string) (net.Conn, error) {
	if err := applyDeadline(ctx, conn); err != nil {
		return nil, err
	}

	var req strings.Builder

	fmt.Fprintf(&req, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n", address, address)

	if auth != nil {
		pass, _ := auth.Password()
		credentials := base64.StdEncoding.EncodeToString([]byte(auth.Username() + ":" + pass))
		fmt.Fprintf(&req, "Proxy-Authorization: Basic %s\r\n", credentials)
	}

	req.WriteString("\r\n")

	if _, err := conn.Write([]byte(req.String())); err != nil {
		return nil, err
	}

	br := bufio.NewReader(conn)
	tp := textproto.NewReader(br)
	status, err := tp.ReadLine()

	if err != nil {
		return nil, err
	}

	parts := strings.SplitN(status, " ", 3)

	if len(parts) < 2 || !strings.HasPrefix(parts[0], "HTTP/") {
		return nil, fmt.Errorf("http proxy: malformed response %q", status)
	}

	if _, err := tp.ReadMIMEHeader(); err != nil {
		return nil, err
	}

	if parts[1] != "200" {
		return nil, fmt.Errorf("http proxy: %s", strings.TrimPrefix(status, parts[0]+" "))
	}

	if err := conn.SetDeadline(time.Time{}); err != nil {
		return nil, err
	}

	return &httpTunnel{Conn: conn, r: br}, nil
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
