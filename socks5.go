package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/url"
	"strconv"
	"sync"
	"time"
)

// A minimal SOCKS5 client (RFC 1928) with username/password authentication
// (RFC 1929). Every reply is read with io.ReadFull for exactly its length, so
// bytes the destination sends right after the proxy's reply (SSH, SMTP, MySQL
// banners) are never swallowed.

const (
	socks5Version         = 0x05
	socks5AuthVersion     = 0x01
	socks5MethodNoAuth    = 0x00
	socks5MethodUserPass  = 0x02
	socks5CmdConnect      = 0x01
	socks5CmdUDPAssociate = 0x03
	socks5AddrIPv4        = 0x01
	socks5AddrDomain      = 0x03
	socks5AddrIPv6        = 0x04
	socks5Succeeded       = 0x00
)

var socks5ReplyText = map[byte]string{
	0x01: "general SOCKS server failure",
	0x02: "connection not allowed by ruleset",
	0x03: "network unreachable",
	0x04: "host unreachable",
	0x05: "connection refused",
	0x06: "TTL expired",
	0x07: "command not supported",
	0x08: "address type not supported",
}

func socks5ReplyError(rep byte) error {
	if text, ok := socks5ReplyText[rep]; ok {
		return errors.New("socks5: " + text)
	}

	return fmt.Errorf("socks5: reply code %d", rep)
}

// socks5AppendAddr appends ATYP, address and port. The host may be an IPv4 or
// IPv6 literal or a name.
func socks5AppendAddr(b []byte, host string, port uint16) []byte {
	ip := net.ParseIP(host)

	switch {
	case ip != nil && ip.To4() != nil:
		b = append(b, socks5AddrIPv4)
		b = append(b, ip.To4()...)
	case ip != nil:
		b = append(b, socks5AddrIPv6)
		b = append(b, ip.To16()...)
	default:
		if len(host) > 255 {
			host = host[:255]
		}

		b = append(b, socks5AddrDomain, byte(len(host)))
		b = append(b, host...)
	}

	return binary.BigEndian.AppendUint16(b, port)
}

// socks5ReadAddr reads ATYP, address and port, and nothing beyond them.
func socks5ReadAddr(r io.Reader) (string, uint16, error) {
	var atyp [1]byte

	if _, err := io.ReadFull(r, atyp[:]); err != nil {
		return "", 0, err
	}

	var host string

	switch atyp[0] {
	case socks5AddrIPv4:
		var b [net.IPv4len]byte

		if _, err := io.ReadFull(r, b[:]); err != nil {
			return "", 0, err
		}

		host = net.IP(b[:]).String()
	case socks5AddrIPv6:
		var b [net.IPv6len]byte

		if _, err := io.ReadFull(r, b[:]); err != nil {
			return "", 0, err
		}

		host = net.IP(b[:]).String()
	case socks5AddrDomain:
		var n [1]byte

		if _, err := io.ReadFull(r, n[:]); err != nil {
			return "", 0, err
		}

		b := make([]byte, n[0])

		if _, err := io.ReadFull(r, b); err != nil {
			return "", 0, err
		}

		host = string(b)
	default:
		return "", 0, fmt.Errorf("socks5: bad address type %d", atyp[0])
	}

	var p [2]byte

	if _, err := io.ReadFull(r, p[:]); err != nil {
		return "", 0, err
	}

	return host, binary.BigEndian.Uint16(p[:]), nil
}

// socks5Handshake negotiates the authentication method and authenticates.
func socks5Handshake(conn net.Conn, auth *url.Userinfo) error {
	methods := []byte{socks5MethodNoAuth}

	if auth != nil {
		methods = append(methods, socks5MethodUserPass)
	}

	if _, err := conn.Write(append([]byte{socks5Version, byte(len(methods))}, methods...)); err != nil {
		return err
	}

	var resp [2]byte

	if _, err := io.ReadFull(conn, resp[:]); err != nil {
		return err
	}

	if resp[0] != socks5Version {
		return fmt.Errorf("socks5: bad version %d", resp[0])
	}

	switch resp[1] {
	case socks5MethodNoAuth:
		return nil
	case socks5MethodUserPass:
		if auth == nil {
			return errors.New("socks5: proxy requires authentication")
		}

		return socks5Authenticate(conn, auth)
	default:
		return fmt.Errorf("socks5: no acceptable authentication method (%#x)", resp[1])
	}
}

func socks5Authenticate(conn net.Conn, auth *url.Userinfo) error {
	user := auth.Username()
	pass, _ := auth.Password()

	if len(user) > 255 || len(pass) > 255 {
		return errors.New("socks5: username or password longer than 255 bytes")
	}

	req := []byte{socks5AuthVersion, byte(len(user))}
	req = append(req, user...)
	req = append(req, byte(len(pass)))
	req = append(req, pass...)

	if _, err := conn.Write(req); err != nil {
		return err
	}

	var resp [2]byte

	if _, err := io.ReadFull(conn, resp[:]); err != nil {
		return err
	}

	if resp[1] != socks5Succeeded {
		return errors.New("socks5: authentication failed")
	}

	return nil
}

// socks5Request sends cmd for host:port and returns the bound address from
// the reply.
func socks5Request(conn net.Conn, cmd byte, host string, port uint16) (string, uint16, error) {
	req := socks5AppendAddr([]byte{socks5Version, cmd, 0x00}, host, port)

	if _, err := conn.Write(req); err != nil {
		return "", 0, err
	}

	var head [3]byte

	if _, err := io.ReadFull(conn, head[:]); err != nil {
		return "", 0, err
	}

	if head[0] != socks5Version {
		return "", 0, fmt.Errorf("socks5: bad version %d", head[0])
	}

	if head[1] != socks5Succeeded {
		return "", 0, socks5ReplyError(head[1])
	}

	return socks5ReadAddr(conn)
}

// socks5UDPDatagram wraps a payload for dst: RSV(2) FRAG(1) ATYP ADDR PORT DATA.
func socks5UDPDatagram(host string, port uint16, payload []byte) []byte {
	b := make([]byte, 0, 3+1+net.IPv6len+2+len(payload))
	b = append(b, 0x00, 0x00, 0x00)
	b = socks5AppendAddr(b, host, port)

	return append(b, payload...)
}

// socks5ParseUDPDatagram splits a relayed datagram into its source address
// and payload.
func socks5ParseUDPDatagram(b []byte) (string, uint16, []byte, error) {
	if len(b) < 4 {
		return "", 0, nil, errors.New("socks5: short udp datagram")
	}

	if b[2] != 0 {
		return "", 0, nil, errors.New("socks5: udp fragmentation is not supported")
	}

	r := bytes.NewReader(b[3:])
	host, port, err := socks5ReadAddr(r)

	if err != nil {
		return "", 0, nil, err
	}

	return host, port, b[len(b)-r.Len():], nil
}

func NewSOCKS5Connector(connector Connector, proxy *ProxyAddr) Connector {
	return &socks5Connector{tcpConnector: connector, proxy: proxy}
}

type socks5Connector struct {
	tcpConnector Connector
	proxy        *ProxyAddr
}

// DialContext opens a CONNECT stream through the proxy. The returned
// connection is the transport connection itself, so half-closes reach the
// proxy natively.
func (c *socks5Connector) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if network != "tcp" {
		return nil, fmt.Errorf("socks5: network %s is not supported", network)
	}

	host, port, err := splitHostPort(address)

	if err != nil {
		return nil, err
	}

	conn, err := c.tcpConnector.DialContext(ctx, "tcp", c.proxy.Address)

	if err != nil {
		return nil, err
	}

	if err := socks5Connect(ctx, conn, c.proxy.Auth, host, port); err != nil {
		conn.Close()

		return nil, fmt.Errorf("%s via %s: %w", address, c.proxy.Address, err)
	}

	return conn, nil
}

// socks5Connect runs the handshake and CONNECT on an open proxy connection,
// bounded by the context deadline.
func socks5Connect(ctx context.Context, conn net.Conn, auth *url.Userinfo, host string, port uint16) error {
	if err := applyDeadline(ctx, conn); err != nil {
		return err
	}

	if err := socks5Handshake(conn, auth); err != nil {
		return err
	}

	if _, _, err := socks5Request(conn, socks5CmdConnect, host, port); err != nil {
		return err
	}

	return conn.SetDeadline(time.Time{})
}

func NewSOCKS5UDPConnector(log *slog.Logger, tcpConnector Connector, udpConnector Connector, proxy *ProxyAddr) Connector {
	return &socks5UDPConnector{
		log:          log,
		tcpConnector: tcpConnector,
		udpConnector: udpConnector,
		proxy:        proxy,
		assocs:       make(map[string]*udpAssociation),
	}
}

type socks5UDPConnector struct {
	log          *slog.Logger
	tcpConnector Connector
	udpConnector Connector
	proxy        *ProxyAddr

	mu     sync.Mutex
	assocs map[string]*udpAssociation // shared associations by source endpoint
}

// DialContext returns a connection to one UDP destination through the proxy.
// When the context names the source endpoint of the flow, flows from that
// source share a single UDP association, as a NAT shares one external port.
func (c *socks5UDPConnector) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if network != "udp" {
		return nil, fmt.Errorf("socks5: network %s is not supported", network)
	}

	host, port, err := splitHostPort(address)

	if err != nil {
		return nil, err
	}

	if src, ok := udpSourceFromContext(ctx); ok {
		return c.dialShared(ctx, src, host, port)
	}

	control, relay, err := c.associate(ctx)

	if err != nil {
		return nil, err
	}

	return &socksUDPConn{relay: relay, control: control, host: host, port: port}, nil
}

func (c *socks5UDPConnector) dialShared(ctx context.Context, src, host string, port uint16) (net.Conn, error) {
	for {
		a, err := c.association(ctx, src)

		if err != nil {
			return nil, err
		}

		if flow, ok := a.open(host, port); ok {
			return flow, nil
		}

		// the association closed between the lookup and open, start over
	}
}

func (c *socks5UDPConnector) association(ctx context.Context, src string) (*udpAssociation, error) {
	c.mu.Lock()
	a := c.assocs[src]
	c.mu.Unlock()

	if a != nil {
		return a, nil
	}

	control, relay, err := c.associate(ctx)

	if err != nil {
		return nil, err
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if a := c.assocs[src]; a != nil {
		// lost the race with a concurrent flow of the same source
		control.Close()
		relay.Close()

		return a, nil
	}

	a = newUDPAssociation(c.log, control, relay, src, c.forget)
	c.assocs[src] = a

	return a, nil
}

func (c *socks5UDPConnector) forget(a *udpAssociation) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.assocs[a.src] == a {
		delete(c.assocs, a.src)
	}
}

// associate opens a UDP association: a TCP control connection, whose
// lifetime bounds the association (RFC 1928 section 7), and a UDP socket to
// the relay the proxy names.
func (c *socks5UDPConnector) associate(ctx context.Context) (control, relay net.Conn, err error) {
	control, err = c.tcpConnector.DialContext(ctx, "tcp", c.proxy.Address)

	if err != nil {
		return nil, nil, err
	}

	defer func() {
		if err != nil {
			control.Close()
		}
	}()

	if err = applyDeadline(ctx, control); err != nil {
		return nil, nil, err
	}

	if err = socks5Handshake(control, c.proxy.Auth); err != nil {
		return nil, nil, err
	}

	bindHost, bindPort, err := socks5Request(control, socks5CmdUDPAssociate, "0.0.0.0", 0)

	if err != nil {
		return nil, nil, err
	}

	// An unspecified bind address means "the host you reached me on".
	if ip := net.ParseIP(bindHost); ip != nil && ip.IsUnspecified() {
		bindHost, _, _ = net.SplitHostPort(c.proxy.Address)
	}

	relayAddr := net.JoinHostPort(bindHost, strconv.Itoa(int(bindPort)))
	c.log.Debug("socks5: udp associate", "proxy", c.proxy.Address, "relay", relayAddr)

	relay, err = c.udpConnector.DialContext(ctx, "udp", relayAddr)

	if err != nil {
		return nil, nil, err
	}

	if err = control.SetDeadline(time.Time{}); err != nil {
		relay.Close()

		return nil, nil, err
	}

	// A UDP association terminates when the TCP connection that the UDP
	// ASSOCIATE request arrived on terminates.
	go func() {
		io.Copy(io.Discard, control)
		control.Close()
		relay.Close()
	}()

	return control, relay, nil
}

// socksUDPConn is a dedicated association carrying one flow: datagrams are
// wrapped for a fixed destination and replies are unwrapped.
type socksUDPConn struct {
	relay   net.Conn
	control net.Conn
	host    string
	port    uint16
}

func (c *socksUDPConn) Read(b []byte) (int, error) {
	n, err := c.relay.Read(b)

	if err != nil {
		return 0, err
	}

	_, _, payload, err := socks5ParseUDPDatagram(b[:n])

	if err != nil {
		return 0, err
	}

	return copy(b, payload), nil
}

func (c *socksUDPConn) Write(b []byte) (int, error) {
	if _, err := c.relay.Write(socks5UDPDatagram(c.host, c.port, b)); err != nil {
		return 0, err
	}

	return len(b), nil
}

func (c *socksUDPConn) Close() error {
	return errors.Join(c.relay.Close(), c.control.Close())
}

func (c *socksUDPConn) LocalAddr() net.Addr {
	return c.relay.LocalAddr()
}

func (c *socksUDPConn) RemoteAddr() net.Addr {
	return &net.UDPAddr{IP: net.ParseIP(c.host), Port: int(c.port)}
}

func (c *socksUDPConn) SetDeadline(t time.Time) error {
	return c.relay.SetDeadline(t)
}

func (c *socksUDPConn) SetReadDeadline(t time.Time) error {
	return c.relay.SetReadDeadline(t)
}

func (c *socksUDPConn) SetWriteDeadline(t time.Time) error {
	return c.relay.SetWriteDeadline(t)
}
