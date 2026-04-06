package connect

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/ginuerzh/gosocks5"
	"github.com/ginuerzh/gosocks5/server"
	"github.com/rs/zerolog"
	"github.com/v-byte-cpu/wirez/pkg/throw"
	"go.uber.org/multierr"
)

func NewSOCKS5ServerHandler(log *zerolog.Logger, socksTCPConn Connector, socksUDPConn Connector, transporter Transporter) server.Handler {
	return &serverHandler{
		log: log, selector: server.DefaultSelector,
		socksTCPConn: socksTCPConn, socksUDPConn: socksUDPConn, transporter: transporter,
		tcpIOTimeout:   tcpIOTimeout,
		udpIOTimeout:   udpIOTimeout,
		connectTimeout: connectTimeout,
	}
}

type serverHandler struct {
	log            *zerolog.Logger
	selector       gosocks5.Selector
	socksTCPConn   Connector
	socksUDPConn   Connector
	transporter    Transporter
	tcpIOTimeout   time.Duration
	udpIOTimeout   time.Duration
	connectTimeout time.Duration
}

func (h *serverHandler) Handle(conn net.Conn) (err error) {
	defer func() {
		if err != nil {
			h.log.Error().Err(err).Msg("")
		}
	}()
	conn = gosocks5.ServerConn(conn, h.selector)
	defer conn.Close()
	req := throw.Throw2(gosocks5.ReadRequest(conn))

	switch req.Cmd {
	case gosocks5.CmdConnect:
		return h.handleConnect(conn, req)
	case gosocks5.CmdUdp:
		return h.handleUDPAssociate(conn, req)
	default:
		return fmt.Errorf("%d: unsupported command", gosocks5.CmdUnsupported)
	}
}

func (h *serverHandler) handleConnect(localConn net.Conn, req *gosocks5.Request) error {
	ctx, cancel := context.WithTimeout(context.Background(), h.connectTimeout)
	defer cancel()
	dstConn, err := h.socksTCPConn.DialContext(ctx, "tcp", req.Addr.String())
	if err != nil {
		return multierr.Append(err, gosocks5.NewReply(gosocks5.HostUnreachable, nil).Write(localConn))
	}
	defer dstConn.Close()

	throw.Throw(gosocks5.NewReply(gosocks5.Succeeded, nil).Write(localConn))

	localConn = NewTimeoutConn(localConn, h.tcpIOTimeout)
	dstConn = NewTimeoutConn(dstConn, h.tcpIOTimeout)
	return h.transporter.Transport(localConn, dstConn)
}

func (h *serverHandler) handleUDPAssociate(localConn net.Conn, req *gosocks5.Request) error {
	localHost, _ := throw.Throw3(net.SplitHostPort(localConn.LocalAddr().String()))
	listenAddr := throw.Throw2(net.ResolveUDPAddr("udp", localHost+":"))
	listenConn := throw.Throw2(net.ListenUDP("udp", listenAddr))
	defer listenConn.Close()

	socksListenAddr := throw.Throw2(gosocks5.NewAddr(listenConn.LocalAddr().String()))
	throw.Throw(gosocks5.NewReply(gosocks5.Succeeded, socksListenAddr).Write(localConn))

	buf := trPool.Get().([]byte)
	n, sourceAddr := throw.Throw3(listenConn.ReadFromUDP(buf))

	ctx, cancel := context.WithTimeout(context.Background(), h.connectTimeout)
	defer cancel()
	dstAddr := net.IPv4zero
	if req.Addr.Type == gosocks5.AddrIPv6 {
		dstAddr = net.IPv6zero
	}
	dstConn := throw.Throw2(h.socksUDPConn.DialContext(ctx, "udp", dstAddr.String()+":0"))
	dstConn = NewTimeoutConn(dstConn, h.udpIOTimeout)
	throw.Throw2(dstConn.Write(buf[:n]))
	trPool.Put(buf) //nolint:staticcheck

	localUDPConn := &firstConnectUDPConn{UDPConn: listenConn, targetAddr: sourceAddr}
	localConn = NewTimeoutConn(localConn, h.udpIOTimeout)
	return h.transporter.Transport(localUDPConn, dstConn)
}

type firstConnectUDPConn struct {
	*net.UDPConn
	targetAddr *net.UDPAddr
}

func (c *firstConnectUDPConn) Read(b []byte) (n int, err error) {
	n, addr, err := c.UDPConn.ReadFromUDP(b)
	if err != nil {
		return
	}
	if !addr.IP.Equal(c.targetAddr.IP) || addr.Port != c.targetAddr.Port {
		return 0, errors.New("source ip address is invalid")
	}
	return
}

func (c *firstConnectUDPConn) Write(b []byte) (n int, err error) {
	return c.UDPConn.WriteToUDP(b, c.targetAddr)
}
