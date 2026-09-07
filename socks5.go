package main

import (
	"bytes"
	"context"
	"encoding/binary"
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

func throwSocks5Reply(rep byte) {
	if text, ok := socks5ReplyText[rep]; ok {
		ThrowFmt("socks5: %s", text)
	}

	ThrowFmt("socks5: reply code %d", rep)
}

func readFull(r io.Reader, b []byte) {
	Throw2(io.ReadFull(r, b))
}

// socks5AppendAddr appends ATYP, address and port for an IP literal; the
// stack never dials names.
func socks5AppendAddr(b []byte, host string, port uint16) []byte {
	ip := net.ParseIP(host)

	if ip == nil {
		ThrowFmt("socks5: %q is not an IP address", host)
	}

	if ip4 := ip.To4(); ip4 != nil {
		b = append(b, socks5AddrIPv4)
		b = append(b, ip4...)
	} else {
		b = append(b, socks5AddrIPv6)
		b = append(b, ip.To16()...)
	}

	return binary.BigEndian.AppendUint16(b, port)
}

// socks5ReadAddr reads ATYP, address and port, and nothing beyond them.
func socks5ReadAddr(r io.Reader) (string, uint16) {
	var atyp [1]byte
	readFull(r, atyp[:])

	var host string

	switch atyp[0] {
	case socks5AddrIPv4:
		var b [net.IPv4len]byte
		readFull(r, b[:])
		host = net.IP(b[:]).String()
	case socks5AddrIPv6:
		var b [net.IPv6len]byte
		readFull(r, b[:])
		host = net.IP(b[:]).String()
	case socks5AddrDomain:
		var n [1]byte
		readFull(r, n[:])
		b := make([]byte, n[0])
		readFull(r, b)
		host = string(b)
	default:
		ThrowFmt("socks5: bad address type %d", atyp[0])
	}

	var p [2]byte
	readFull(r, p[:])

	return host, binary.BigEndian.Uint16(p[:])
}

// socks5Handshake negotiates the authentication method and authenticates.
func socks5Handshake(conn net.Conn, auth *url.Userinfo) {
	methods := []byte{socks5MethodNoAuth}

	if auth != nil {
		methods = append(methods, socks5MethodUserPass)
	}

	Throw2(conn.Write(append([]byte{socks5Version, byte(len(methods))}, methods...)))

	var resp [2]byte
	readFull(conn, resp[:])

	if resp[0] != socks5Version {
		ThrowFmt("socks5: bad version %d", resp[0])
	}

	switch resp[1] {
	case socks5MethodNoAuth:
	case socks5MethodUserPass:
		if auth == nil {
			ThrowFmt("socks5: proxy requires authentication")
		}

		socks5Authenticate(conn, auth)
	default:
		ThrowFmt("socks5: no acceptable authentication method (%#x)", resp[1])
	}
}

func socks5Authenticate(conn net.Conn, auth *url.Userinfo) {
	user := auth.Username()
	pass, _ := auth.Password()

	if len(user) > 255 || len(pass) > 255 {
		ThrowFmt("socks5: username or password longer than 255 bytes")
	}

	req := []byte{socks5AuthVersion, byte(len(user))}
	req = append(req, user...)
	req = append(req, byte(len(pass)))
	req = append(req, pass...)
	Throw2(conn.Write(req))

	var resp [2]byte
	readFull(conn, resp[:])

	if resp[1] != socks5Succeeded {
		ThrowFmt("socks5: authentication failed")
	}
}

// socks5Request sends cmd for host:port and returns the bound address from
// the reply.
func socks5Request(conn net.Conn, cmd byte, host string, port uint16) (string, uint16) {
	Throw2(conn.Write(socks5AppendAddr([]byte{socks5Version, cmd, 0x00}, host, port)))

	var head [3]byte
	readFull(conn, head[:])

	if head[0] != socks5Version {
		ThrowFmt("socks5: bad version %d", head[0])
	}

	if head[1] != socks5Succeeded {
		throwSocks5Reply(head[1])
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
func socks5ParseUDPDatagram(b []byte) (string, uint16, []byte) {
	if len(b) < 4 {
		ThrowFmt("socks5: short udp datagram")
	}

	if b[2] != 0 {
		ThrowFmt("socks5: udp fragmentation is not supported")
	}

	r := bytes.NewReader(b[3:])
	host, port := socks5ReadAddr(r)

	return host, port, b[len(b)-r.Len():]
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
func (c *socks5Connector) DialContext(ctx context.Context, network, address string) (conn net.Conn, err error) {
	err = Try(func() {
		conn = c.connect(ctx, network, address)
	}).AsError()

	if err != nil {
		err = fmt.Errorf("%s via %s: %w", address, c.proxy.Address, err)
	}

	return
}

func (c *socks5Connector) connect(ctx context.Context, _, address string) net.Conn {
	host, port := hostPort(address)

	conn := Throw2(c.tcpConnector.DialContext(ctx, "tcp", c.proxy.Address))
	defer CloseOnThrow(conn)

	applyDeadline(ctx, conn)
	socks5Handshake(conn, c.proxy.Auth)
	socks5Request(conn, socks5CmdConnect, host, port)
	Throw(conn.SetDeadline(time.Time{}))

	return conn
}

func NewSOCKS5UDPConnector(log *slog.Logger, tcpConnector Connector, udpConnector Connector, proxy *ProxyAddr) Connector {
	return &socks5UDPConnector{
		log:          log,
		tcpConnector: tcpConnector,
		udpConnector: udpConnector,
		proxy:        proxy,
		slots:        make(map[string]*associationSlot),
	}
}

type socks5UDPConnector struct {
	log          *slog.Logger
	tcpConnector Connector
	udpConnector Connector
	proxy        *ProxyAddr

	mu    sync.Mutex
	slots map[string]*associationSlot // shared associations by source endpoint
}

// associationSlot is one source endpoint's association, or the promise of
// it: flows that arrive while it is being set up wait for it instead of each
// opening their own.
type associationSlot struct {
	ready chan struct{}
	assoc *udpAssociation
	exc   *Exception
}

// DialContext returns a connection to one UDP destination through the proxy.
// The context names the source endpoint of the flow; flows from one source
// share a single UDP association, as a NAT shares one external port.
func (c *socks5UDPConnector) DialContext(ctx context.Context, network, address string) (conn net.Conn, err error) {
	err = Try(func() {
		conn = c.dial(ctx, network, address)
	}).AsError()

	return
}

func (c *socks5UDPConnector) dial(ctx context.Context, _, address string) net.Conn {
	host, port := hostPort(address)
	src, ok := udpSourceFromContext(ctx)

	if !ok {
		ThrowFmt("socks5: udp dial without a source endpoint")
	}

	for {
		if flow, ok := c.association(ctx, src).open(host, port); ok {
			return flow
		}

		// the association closed between the lookup and open, start over
	}
}

func (c *socks5UDPConnector) association(ctx context.Context, src string) *udpAssociation {
	c.mu.Lock()
	slot := c.slots[src]

	if slot != nil {
		c.mu.Unlock()

		select {
		case <-slot.ready:
		case <-ctx.Done():
			Throw(ctx.Err())
		}

		if slot.exc != nil {
			slot.exc.throw()
		}

		return slot.assoc
	}

	slot = &associationSlot{ready: make(chan struct{})}
	c.slots[src] = slot
	c.mu.Unlock()

	Try(func() {
		control, relay := c.associate(ctx)
		slot.assoc = newUDPAssociation(c.log, control, relay, src, c.forget)
	}).Catch(func(exc *Exception) {
		c.mu.Lock()
		delete(c.slots, src)
		c.mu.Unlock()

		slot.exc = exc
	})

	close(slot.ready)

	if slot.exc != nil {
		slot.exc.throw()
	}

	return slot.assoc
}

func (c *socks5UDPConnector) forget(a *udpAssociation) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if slot := c.slots[a.src]; slot != nil && slot.assoc == a {
		delete(c.slots, a.src)
	}
}

// associate opens a UDP association: a TCP control connection, whose
// lifetime bounds the association (RFC 1928 section 7), and a UDP socket to
// the relay the proxy names.
func (c *socks5UDPConnector) associate(ctx context.Context) (control, relay net.Conn) {
	control = Throw2(c.tcpConnector.DialContext(ctx, "tcp", c.proxy.Address))
	defer CloseOnThrow(control)

	applyDeadline(ctx, control)
	socks5Handshake(control, c.proxy.Auth)

	bindHost, bindPort := socks5Request(control, socks5CmdUDPAssociate, "0.0.0.0", 0)

	// An unspecified bind address means "the host you reached me on".
	if ip := net.ParseIP(bindHost); ip != nil && ip.IsUnspecified() {
		bindHost, _ = Throw3(net.SplitHostPort(c.proxy.Address))
	}

	relayAddr := net.JoinHostPort(bindHost, strconv.Itoa(int(bindPort)))
	c.log.Debug("socks5: udp associate", "proxy", c.proxy.Address, "relay", relayAddr)

	relay = Throw2(c.udpConnector.DialContext(ctx, "udp", relayAddr))
	defer CloseOnThrow(relay)

	Throw(control.SetDeadline(time.Time{}))

	// A UDP association terminates when the TCP connection that the UDP
	// ASSOCIATE request arrived on terminates.
	go func() {
		io.Copy(io.Discard, control)
		control.Close()
		relay.Close()
	}()

	return control, relay
}
