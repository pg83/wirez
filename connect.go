package main

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"errors"
	"log/slog"

	"github.com/ginuerzh/gosocks5"
	"github.com/ginuerzh/gosocks5/client"
)

const (
	// tcpIOTimeout is the default timeout for each TCP i/o operation.
	tcpIOTimeout = 1 * time.Minute
	// udpIOTimeout is the default timeout for each UDP i/o operation.
	udpIOTimeout = 15 * time.Second
	// connectTimeout is the default timeout for TCP/UDP dial connect
	connectTimeout = 3 * time.Second
)

// Connector is responsible for connecting to the destination address.
type Connector interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

func NewDirectConnector() Connector {
	return &net.Dialer{}
}

type SocksAddr struct {
	Address string
	Auth    *url.Userinfo
}

func NewSOCKS5Connector(connector Connector, socksAddr *SocksAddr) Connector {
	selector := client.DefaultSelector

	if socksAddr.Auth != nil {
		selector = client.NewClientSelector(socksAddr.Auth, gosocks5.MethodUserPass, gosocks5.MethodNoAuth)
	}

	return &socks5Connector{
		tcpConnector: connector,
		selector:     selector,
		socksAddress: socksAddr.Address,
	}
}

type socks5Connector struct {
	tcpConnector Connector
	selector     gosocks5.Selector
	socksAddress string
}

func (c *socks5Connector) DialContext(ctx context.Context, network, address string) (conn net.Conn, err error) {
	err = Try(func() {
		conn = c.connect(ctx, network, address)
	}).AsError()

	if conn != nil {
		err = errors.Join(err, conn.SetDeadline(time.Time{}))
	}

	return
}

func (c *socks5Connector) connect(ctx context.Context, network, address string) net.Conn {
	if network != "tcp" {
		ThrowFmt("network %s is not supported", network)
	}

	dstAddr := Throw2(gosocks5.NewAddr(address))

	conn := Throw2(c.tcpConnector.DialContext(ctx, "tcp", c.socksAddress))
	Throw(conn.SetDeadline(time.Now().Add(connectTimeout)))

	cc := gosocks5.ClientConn(conn, c.selector)
	Throw(cc.Handleshake())

	req := gosocks5.NewRequest(gosocks5.CmdConnect, dstAddr)

	Throw(req.Write(cc))

	reply := Throw2(gosocks5.ReadReply(cc))

	if reply.Rep != gosocks5.Succeeded {
		ThrowFmt("destination address [%s] is unavailable", dstAddr)
	}

	return &socks5Conn{Conn: cc, raw: conn}
}

// socks5Conn is an established SOCKS5 CONNECT stream. gosocks5.Conn hides the
// transport connection, so half-closes are forwarded to it here; with proxy
// chaining raw is itself a socks5Conn and the shutdown travels down the chain.
type socks5Conn struct {
	*gosocks5.Conn
	raw net.Conn
}

func (c *socks5Conn) CloseWrite() error {
	if cw, ok := c.raw.(closeWriter); ok {
		return cw.CloseWrite()
	}

	return errors.ErrUnsupported
}

func NewSOCKS5UDPConnector(log *slog.Logger, tcpConnector Connector, udpConnector Connector, socksAddr *SocksAddr) Connector {
	selector := client.DefaultSelector

	if socksAddr.Auth != nil {
		selector = client.NewClientSelector(socksAddr.Auth, gosocks5.MethodUserPass, gosocks5.MethodNoAuth)
	}

	return &socks5UDPConnector{
		log:          log,
		tcpConnector: tcpConnector,
		udpConnector: udpConnector,
		selector:     selector,
		socksAddress: socksAddr.Address,
	}
}

type socks5UDPConnector struct {
	log          *slog.Logger
	tcpConnector Connector
	udpConnector Connector
	selector     gosocks5.Selector
	socksAddress string
}

func (c *socks5UDPConnector) DialContext(ctx context.Context, network, address string) (result net.Conn, err error) {
	var socksConn net.Conn

	err = Try(func() {
		socksConn, result = c.connect(ctx, network, address)
	}).AsError()

	if socksConn != nil {
		err = errors.Join(err, socksConn.SetDeadline(time.Time{}))
	}

	if err != nil && socksConn != nil {
		err = errors.Join(err, socksConn.Close())
	}

	return
}

func (c *socks5UDPConnector) connect(ctx context.Context, network, address string) (net.Conn, net.Conn) {
	if network != "udp" {
		ThrowFmt("network %s is not supported", network)
	}

	dstAddr := Throw2(gosocks5.NewAddr(address))
	dstUDPAddr := Throw2(net.ResolveUDPAddr("udp", address))

	socksConn := Throw2(c.tcpConnector.DialContext(ctx, "tcp", c.socksAddress))
	Throw(socksConn.SetDeadline(time.Now().Add(connectTimeout)))

	cc := gosocks5.ClientConn(socksConn, c.selector)
	Throw(cc.Handleshake())

	socksConn = cc
	req := gosocks5.NewRequest(gosocks5.CmdUdp, &gosocks5.Addr{Type: dstAddr.Type})

	Throw(req.Write(socksConn))

	c.log.Debug("udp cmd request write success", "dstAddr", address)

	reply := Throw2(gosocks5.ReadReply(socksConn))

	if reply.Rep != gosocks5.Succeeded {
		ThrowFmt("service unavailable")
	}

	replyAddr := reply.Addr.String()

	c.log.Debug("udp cmd reply success", "dstAddr", address, "replyAddr", replyAddr)

	uc := Throw2(c.udpConnector.DialContext(ctx, "udp", replyAddr))

	c.log.Debug("local udp addr", "addr", uc.LocalAddr().String())

	//nolint:errcheck
	go func() {
		io.Copy(io.Discard, socksConn)
		socksConn.Close()
		// A UDP association terminates when the TCP connection that the UDP
		// ASSOCIATE request arrived on terminates. RFC1928
		uc.Close()
	}()

	if dstUDPAddr.IP.IsUnspecified() {
		return socksConn, newSocksRawUDPConn(c.log, uc, socksConn)
	}

	return socksConn, newSocksUDPConn(uc, socksConn, dstUDPAddr)
}

func newSocksRawUDPConn(log *slog.Logger, udpConn net.Conn, tcpConn net.Conn) *socksRawUDPConn {
	return &socksRawUDPConn{Conn: udpConn, log: log, tcpConn: tcpConn}
}

type socksRawUDPConn struct {
	net.Conn
	log     *slog.Logger
	tcpConn net.Conn
}

func (c *socksRawUDPConn) Write(b []byte) (n int, err error) {
	n, err = c.Conn.Write(b)

	if err != nil {
		c.log.Error("rawUDPConn error", "err", err)
	}

	return n, err
}

func (c *socksRawUDPConn) Close() error {
	err := c.Conn.Close()

	return errors.Join(err, c.tcpConn.Close())
}

func newSocksUDPConn(udpConn net.Conn, tcpConn net.Conn, dstAddr *net.UDPAddr) *socksUDPConn {
	return &socksUDPConn{Conn: udpConn, tcpConn: tcpConn, dstAddr: dstAddr}
}

type socksUDPConn struct {
	net.Conn
	tcpConn net.Conn
	dstAddr *net.UDPAddr
}

var _ net.Conn = (*socksUDPConn)(nil)

func (c *socksUDPConn) Read(b []byte) (n int, err error) {
	err = Try(func() {
		n = c.readFrom(b)
	}).AsError()

	return
}

func (c *socksUDPConn) Write(b []byte) (n int, err error) {
	err = Try(func() {
		c.writeTo(b, c.dstAddr)
		n = len(b)
	}).AsError()

	return
}

func (c *socksUDPConn) writeTo(b []byte, addr net.Addr) {
	toAddr := Throw2(gosocks5.NewAddr(addr.String()))

	// TODO buffer pool
	buf := &bytes.Buffer{}
	h := &gosocks5.UDPHeader{Addr: toAddr}
	Throw(h.Write(buf))
	Throw2(buf.Write(b))
	Throw2(c.Conn.Write(buf.Bytes()))
}

func (c *socksUDPConn) readFrom(b []byte) int {
	rn := Throw2(c.Conn.Read(b))
	packet := Throw2(gosocks5.ReadUDPDatagram(bytes.NewBuffer(b[:rn])))
	copy(b, packet.Data)

	return len(packet.Data)
}

func (c *socksUDPConn) Close() error {
	err := c.Conn.Close()

	return errors.Join(err, c.tcpConn.Close())
}

type localForwardingConnector struct {
	directConnector Connector
	socksConnector  Connector
	nat             AddressMapper
	bypass          []*net.IPNet
	nat64           *net.IPNet
}

func NewLocalForwardingConnector(directConnector Connector, socksConnector Connector, nat AddressMapper, bypass []*net.IPNet, nat64 *net.IPNet) Connector {
	return &localForwardingConnector{
		directConnector: directConnector,
		socksConnector:  socksConnector,
		nat:             nat,
		bypass:          bypass,
		nat64:           nat64,
	}
}

// DialContext picks the route for a destination: explicit -L mappings win,
// then -B bypass networks go direct (through NAT64 on an IPv6-only host),
// everything else goes to SOCKS. A NAT64-synthesized IPv6 destination is
// unmapped to its embedded IPv4 first, so the IPv4 rules govern it.
func (c *localForwardingConnector) DialContext(ctx context.Context, network, address string) (conn net.Conn, err error) {
	address = nat64Unmap(c.nat64, address)

	if newAddress, ok := c.nat.MapAddress(network, address); ok {
		return c.directConnector.DialContext(ctx, network, newAddress)
	}

	if c.matchBypass(address) {
		return c.directConnector.DialContext(ctx, network, nat64Map(c.nat64, address))
	}

	return c.socksConnector.DialContext(ctx, network, address)
}

func (c *localForwardingConnector) matchBypass(address string) bool {
	host, _, err := net.SplitHostPort(address)

	if err != nil {
		return false
	}

	ip := net.ParseIP(host)

	if ip == nil {
		return false
	}

	for _, n := range c.bypass {
		if n.Contains(ip) {
			return true
		}
	}

	return false
}

// nat64Unmap turns a destination inside the NAT64 prefix back into the IPv4
// address embedded in its low 32 bits; other destinations pass through.
func nat64Unmap(prefix *net.IPNet, address string) string {
	if prefix == nil {
		return address
	}

	host, port, err := net.SplitHostPort(address)

	if err != nil {
		return address
	}

	ip := net.ParseIP(host)

	if ip == nil || ip.To4() != nil || !prefix.Contains(ip) {
		return address
	}

	return net.JoinHostPort(net.IP(ip[12:16]).String(), port)
}

// nat64Map embeds an IPv4 destination into the NAT64 prefix so an IPv6-only
// host can dial it; IPv6 destinations pass through.
func nat64Map(prefix *net.IPNet, address string) string {
	if prefix == nil {
		return address
	}

	host, port, err := net.SplitHostPort(address)

	if err != nil {
		return address
	}

	ip4 := net.ParseIP(host).To4()

	if ip4 == nil {
		return address
	}

	ip := make(net.IP, net.IPv6len)
	copy(ip, prefix.IP.To16())
	copy(ip[12:], ip4)

	return net.JoinHostPort(ip.String(), port)
}

type AddressMapper interface {
	MapAddress(network, address string) (mappedAddress string, exists bool)
	AddAddressMapping(network, fromAddress, toAddress string)
}

type addressMapper struct {
	mu  sync.RWMutex
	nat map[string]map[string]string
}

func NewAddressMapper() AddressMapper {
	return &addressMapper{
		nat: make(map[string]map[string]string),
	}
}

func (m *addressMapper) MapAddress(network, address string) (mappedAddress string, exists bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if mappedAddress, exists = m.nat[network][address]; exists {
		return
	}

	port := address[strings.LastIndex(address, ":")+1:]
	mappedAddress, exists = m.nat[network][port]

	return
}

func (m *addressMapper) AddAddressMapping(network, fromAddress, toAddress string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, ok := m.nat[network]; !ok {
		m.nat[network] = make(map[string]string)
	}

	if !strings.Contains(fromAddress, ":") {
		fromAddress = ":" + fromAddress
	}

	host, port := Throw3(net.SplitHostPort(fromAddress))
	Throw2(strconv.ParseUint(port, 10, 16))

	if host == "" || host == "0.0.0.0" || host == "::" {
		fromAddress = port
	}

	m.nat[network][fromAddress] = toAddress
}
