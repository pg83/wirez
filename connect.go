package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	// udpIOTimeout is the default idle timeout of a UDP flow.
	udpIOTimeout = 15 * time.Second
	// connectTimeout is the default timeout for a TCP/UDP dial, proxy
	// handshakes included.
	connectTimeout = 10 * time.Second
)

// Connector is responsible for connecting to the destination address.
type Connector interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

func NewDirectConnector() Connector {
	return &net.Dialer{}
}

// unsupportedConnector refuses every dial with a fixed reason.
type unsupportedConnector struct {
	reason string
}

func (c *unsupportedConnector) DialContext(context.Context, string, string) (net.Conn, error) {
	return nil, errors.New(c.reason)
}

// closeWriter is implemented by stream connections that can shut down their
// sending side alone (net.TCPConn, gonet.TCPConn, TimeoutConn, httpTunnel).
type closeWriter interface {
	CloseWrite() error
}

// closeWrite half-closes conn when it supports that.
func closeWrite(conn net.Conn) error {
	if cw, ok := conn.(closeWriter); ok {
		return cw.CloseWrite()
	}

	return errors.ErrUnsupported
}

// applyDeadline bounds a proxy handshake on conn by the context deadline.
func applyDeadline(ctx context.Context, conn net.Conn) error {
	if deadline, ok := ctx.Deadline(); ok {
		return conn.SetDeadline(deadline)
	}

	return nil
}

// splitHostPort parses host:port into a host and a numeric port.
func splitHostPort(address string) (string, uint16, error) {
	host, portStr, err := net.SplitHostPort(address)

	if err != nil {
		return "", 0, err
	}

	port, err := strconv.ParseUint(portStr, 10, 16)

	if err != nil {
		return "", 0, fmt.Errorf("invalid port in %s: %w", address, err)
	}

	return host, uint16(port), nil
}

// udpSourceKey carries the source endpoint of a UDP flow in the dial context,
// so that flows from one socket can share a SOCKS5 UDP association.
type udpSourceKey struct{}

func withUDPSource(ctx context.Context, src string) context.Context {
	return context.WithValue(ctx, udpSourceKey{}, src)
}

func udpSourceFromContext(ctx context.Context) (string, bool) {
	src, ok := ctx.Value(udpSourceKey{}).(string)

	return src, ok
}

var errTUNRefused = errors.New("destination is the TUN address and has no -L mapping")

type localForwardingConnector struct {
	directConnector Connector
	socksConnector  Connector
	nat             AddressMapper
	bypass          []*net.IPNet
	tun             []*net.IPNet
	nat64           *net.IPNet
}

func NewLocalForwardingConnector(directConnector Connector, socksConnector Connector, nat AddressMapper, bypass, tun []*net.IPNet, nat64 *net.IPNet) Connector {
	return &localForwardingConnector{
		directConnector: directConnector,
		socksConnector:  socksConnector,
		nat:             nat,
		bypass:          bypass,
		tun:             tun,
		nat64:           nat64,
	}
}

// DialContext picks the route for a destination: explicit -L mappings win,
// then the TUN subnet itself is refused (nothing but wirez lives there, and a
// proxy must not be asked to reach it), then -B bypass networks go direct
// (through NAT64 on an IPv6-only host), everything else goes to the proxy. A
// NAT64-synthesized IPv6 destination is unmapped to its embedded IPv4 first,
// so the IPv4 rules govern it.
func (c *localForwardingConnector) DialContext(ctx context.Context, network, address string) (conn net.Conn, err error) {
	address = nat64Unmap(c.nat64, address)

	if newAddress, ok := c.nat.MapAddress(network, address); ok {
		return c.directConnector.DialContext(ctx, network, newAddress)
	}

	if matchNets(c.tun, address) {
		return nil, fmt.Errorf("%s: %w", address, errTUNRefused)
	}

	if matchNets(c.bypass, address) {
		return c.directConnector.DialContext(ctx, network, nat64Map(c.nat64, address))
	}

	return c.socksConnector.DialContext(ctx, network, address)
}

// matchNets reports whether the literal IP of a host:port address falls into
// one of the networks; names never match.
func matchNets(nets []*net.IPNet, address string) bool {
	host, _, err := net.SplitHostPort(address)

	if err != nil {
		return false
	}

	ip := net.ParseIP(host)

	if ip == nil {
		return false
	}

	for _, n := range nets {
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
