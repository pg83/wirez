package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ginuerzh/gosocks5"
	"github.com/ginuerzh/gosocks5/client"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"go.uber.org/multierr"
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
	if network != "tcp" {
		return nil, fmt.Errorf("network %s is not supported", network)
	}

	err = Try(func() {
		dstAddr := Throw2(gosocks5.NewAddr(address))
		conn = Throw2(c.tcpConnector.DialContext(ctx, "tcp", c.socksAddress))
		Throw(conn.SetDeadline(time.Now().Add(connectTimeout)))

		cc := gosocks5.ClientConn(conn, c.selector)
		Throw(cc.Handleshake())
		conn = cc

		req := gosocks5.NewRequest(gosocks5.CmdConnect, dstAddr)
		Throw(req.Write(conn))
		reply := Throw2(gosocks5.ReadReply(conn))

		if reply.Rep != gosocks5.Succeeded {
			ThrowFmt("destination address [%s] is unavailable", dstAddr)
		}
	}).AsError()

	if conn != nil {
		err = multierr.Append(err, conn.SetDeadline(time.Time{}))
	}

	return
}

func NewSOCKS5UDPConnector(log *zerolog.Logger, tcpConnector Connector, udpConnector Connector, socksAddr *SocksAddr) Connector {
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
	log          *zerolog.Logger
	tcpConnector Connector
	udpConnector Connector
	selector     gosocks5.Selector
	socksAddress string
}

func (c *socks5UDPConnector) DialContext(ctx context.Context, network, address string) (result net.Conn, err error) {
	if network != "udp" {
		return nil, fmt.Errorf("network %s is not supported", network)
	}

	var socksConn net.Conn

	err = Try(func() {
		dstAddr := Throw2(gosocks5.NewAddr(address))
		dstUDPAddr := Throw2(net.ResolveUDPAddr("udp", address))

		socksConn = Throw2(c.tcpConnector.DialContext(ctx, "tcp", c.socksAddress))
		Throw(socksConn.SetDeadline(time.Now().Add(connectTimeout)))

		cc := gosocks5.ClientConn(socksConn, c.selector)
		Throw(cc.Handleshake())
		socksConn = cc

		req := gosocks5.NewRequest(gosocks5.CmdUdp, &gosocks5.Addr{Type: dstAddr.Type})
		Throw(req.Write(socksConn))
		c.log.Debug().Str("dstAddr", address).Msg("udp cmd request write success")
		reply := Throw2(gosocks5.ReadReply(socksConn))

		if reply.Rep != gosocks5.Succeeded {
			ThrowFmt("service unavailable")
		}

		replyAddr := reply.Addr.String()
		c.log.Debug().Str("dstAddr", address).Str("replyAddr", replyAddr).Msg("udp cmd reply success")

		uc := Throw2(c.udpConnector.DialContext(ctx, "udp", replyAddr))
		c.log.Debug().Str("local udp addr", uc.LocalAddr().String())

		//nolint:errcheck
		go func() {
			io.Copy(io.Discard, socksConn)
			socksConn.Close()
			// A UDP association terminates when the TCP connection that the UDP
			// ASSOCIATE request arrived on terminates. RFC1928
			uc.Close()
		}()

		if dstUDPAddr.IP.IsUnspecified() {
			result = newSocksRawUDPConn(uc, socksConn)
		} else {
			result = newSocksUDPConn(uc, socksConn, dstUDPAddr)
		}
	}).AsError()

	if socksConn != nil {
		err = multierr.Append(err, socksConn.SetDeadline(time.Time{}))
	}

	if err != nil && socksConn != nil {
		err = multierr.Append(err, socksConn.Close())
	}

	return
}

func newSocksRawUDPConn(udpConn net.Conn, tcpConn net.Conn) *socksRawUDPConn {
	return &socksRawUDPConn{Conn: udpConn, tcpConn: tcpConn}
}

type socksRawUDPConn struct {
	net.Conn
	tcpConn net.Conn
}

func (c *socksRawUDPConn) Write(b []byte) (n int, err error) {
	n, err = c.Conn.Write(b)

	if err != nil {
		log.Print("rawUDPConn error: ", err)
	}

	return n, err
}

func (c *socksRawUDPConn) Close() error {
	err := c.Conn.Close()
	return multierr.Append(err, c.tcpConn.Close())
}

func newSocksUDPConn(udpConn net.Conn, tcpConn net.Conn, dstAddr *net.UDPAddr) *socksUDPConn {
	return &socksUDPConn{Conn: udpConn, tcpConn: tcpConn, dstAddr: dstAddr}
}

type socksUDPConn struct {
	net.Conn
	tcpConn net.Conn
	dstAddr *net.UDPAddr
}

var _ net.PacketConn = (*socksUDPConn)(nil)
var _ net.Conn = (*socksUDPConn)(nil)

func (c *socksUDPConn) Read(b []byte) (n int, err error) {
	n, _, err = c.ReadFrom(b)
	return
}

func (c *socksUDPConn) Write(b []byte) (n int, err error) {
	n, err = c.WriteTo(b, c.dstAddr)
	return n, err
}

func (c *socksUDPConn) WriteTo(b []byte, addr net.Addr) (n int, err error) {
	toAddr, err := gosocks5.NewAddr(addr.String())

	if err != nil {
		return
	}

	// TODO buffer pool
	buf := &bytes.Buffer{}
	h := &gosocks5.UDPHeader{Addr: toAddr}

	if err = h.Write(buf); err != nil {
		return
	}

	if _, err = buf.Write(b); err != nil {
		return
	}

	_, err = c.Conn.Write(buf.Bytes())
	return len(b), err
}

func (c *socksUDPConn) ReadFrom(b []byte) (int, net.Addr, error) {
	n, err := c.Conn.Read(b)

	if err != nil {
		return 0, nil, err
	}

	buf := bytes.NewBuffer(b[:n])
	packet, err := gosocks5.ReadUDPDatagram(buf)

	if err != nil {
		return 0, nil, err
	}

	copy(b, packet.Data)
	fromAddr, err := net.ResolveUDPAddr("udp", packet.Header.Addr.String())

	if err != nil {
		return 0, nil, err
	}

	return len(packet.Data), fromAddr, nil
}

func (c *socksUDPConn) Close() error {
	err := c.Conn.Close()
	return multierr.Append(err, c.tcpConn.Close())
}

// TODO performance metrics
// TODO add/remove dynamic connectors

func NewRotationConnector(connectors []Connector) Connector {
	return &rotationConnector{connectors: connectors}
}

type rotationConnector struct {
	connectors []Connector
	robin      uint32
}

func (c *rotationConnector) DialContext(ctx context.Context, network, address string) (conn net.Conn, err error) {
	i := int(atomic.AddUint32(&c.robin, 1) % uint32(len(c.connectors)))
	return c.connectors[i].DialContext(ctx, network, address)
}

type localForwardingConnector struct {
	directConnector Connector
	socksConnector  Connector
	nat             AddressMapper
}

func NewLocalForwardingConnector(directConnector Connector, socksConnector Connector, nat AddressMapper) Connector {
	return &localForwardingConnector{
		directConnector: directConnector,
		socksConnector:  socksConnector,
		nat:             nat,
	}
}

func (c *localForwardingConnector) DialContext(ctx context.Context, network, address string) (conn net.Conn, err error) {
	if newAddress, ok := c.nat.MapAddress(network, address); ok {
		return c.directConnector.DialContext(ctx, network, newAddress)
	}

	return c.socksConnector.DialContext(ctx, network, address)
}

type AddressMapper interface {
	MapAddress(network, address string) (mappedAddress string, exists bool)
	AddAddressMapping(network, fromAddress, toAddress string) error
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

func (m *addressMapper) AddAddressMapping(network, fromAddress, toAddress string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.nat[network]; !ok {
		m.nat[network] = make(map[string]string)
	}

	if !strings.Contains(fromAddress, ":") {
		fromAddress = ":" + fromAddress
	}

	host, port, err := net.SplitHostPort(fromAddress)

	if err != nil {
		return err
	}

	if _, err = strconv.ParseUint(port, 10, 16); err != nil {
		return err
	}

	if host == "" || host == "0.0.0.0" {
		fromAddress = port
	}

	m.nat[network][fromAddress] = toAddress
	return nil
}
