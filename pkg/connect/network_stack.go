//go:build linux

package connect

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"time"

	"github.com/rs/zerolog"
	"github.com/v-byte-cpu/wirez/pkg/throw"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/fdbased"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

type NetworkStack struct {
	*stack.Stack
	log            *zerolog.Logger
	socksTCPConn   Connector
	socksUDPConn   Connector
	transporter    Transporter
	TcpIOTimeout   time.Duration
	UdpIOTimeout   time.Duration
	ConnectTimeout time.Duration
}

func NewNetworkStack(log *zerolog.Logger, fd int, mtu uint32, tunNetworkAddr string,
	socksTCPConn Connector, socksUDPConn Connector, transporter Transporter) *NetworkStack {
	s := &NetworkStack{
		log:            log,
		socksTCPConn:   socksTCPConn,
		socksUDPConn:   socksUDPConn,
		TcpIOTimeout:   tcpIOTimeout,
		UdpIOTimeout:   udpIOTimeout,
		ConnectTimeout: connectTimeout,
		transporter:    transporter,
		Stack: stack.New(stack.Options{
			NetworkProtocols: []stack.NetworkProtocolFactory{
				ipv4.NewProtocol,
				ipv6.NewProtocol,
			},
			TransportProtocols: []stack.TransportProtocolFactory{
				tcp.NewProtocol,
				udp.NewProtocol,
			},
			DefaultIPTables: defaultIPTables,
		}),
	}

	ep := throw.Throw2(fdbased.New(&fdbased.Options{
		MTU: mtu,
		FDs: []int{fd},
		// TUN only
		EthernetHeader: false,
	}))

	var defaultNICID tcpip.NICID = 0x01
	throwTCPIP := func(err tcpip.Error) {
		if err != nil {
			throw.ThrowFmt("%s", err)
		}
	}
	throwTCPIP(s.CreateNIC(defaultNICID, ep))
	throwTCPIP(s.SetPromiscuousMode(defaultNICID, true))
	throwTCPIP(s.SetSpoofing(defaultNICID, true))

	s.setupRouting(defaultNICID, tunNetworkAddr)

	s.setTCPHandler()
	s.setUDPHandler()
	return s
}

func (s *NetworkStack) setupRouting(nic tcpip.NICID, assignNet string) {
	_, ipNet := throw.Throw3(net.ParseCIDR(assignNet))

	subnet := throw.Throw2(tcpip.NewSubnet(tcpip.AddrFrom4Slice(ipNet.IP.To4()), tcpip.MaskFromBytes(ipNet.Mask)))

	rt := s.GetRouteTable()
	rt = append(rt, tcpip.Route{
		Destination: subnet,
		NIC:         nic,
	})
	s.SetRouteTable(rt)
	s.log.Debug().Str("subnet", subnet.String()).Msg("gVisor routing configured")
}

func (s *NetworkStack) setTCPHandler() {
	tcpForwarder := tcp.NewForwarder(s.Stack, 0, 2<<10, func(r *tcp.ForwarderRequest) {
		var wq waiter.Queue
		id := r.ID()
		s.log.Debug().Str("handler", "tcp").
			Stringer("localAddress", id.LocalAddress).Uint16("localPort", id.LocalPort).
			Stringer("fromAddress", id.RemoteAddress).Uint16("fromPort", id.RemotePort).Msg("received request")
		ep, err := r.CreateEndpoint(&wq)
		if err != nil {
			s.log.Error().Str("handler", "tcp").Stringer("error", err).Msg("")
			// prevent potential half-open TCP connection leak.
			r.Complete(true)
			return
		}
		r.Complete(false)

		go func() {
			throw.Try(func() {
				s.handleTCP(gonet.NewTCPConn(&wq, ep), &id)
			}).Catch(func(exc *throw.Exception) {
				s.log.Error().Str("handler", "tcp").Err(exc).Msg("")
			})
		}()
	})
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpForwarder.HandlePacket)
}

func (s *NetworkStack) setUDPHandler() {
	udpForwarder := udp.NewForwarder(s.Stack, func(r *udp.ForwarderRequest) bool {
		var wq waiter.Queue
		id := r.ID()
		s.log.Debug().Str("handler", "udp").
			Stringer("localAddress", id.LocalAddress).Uint16("localPort", id.LocalPort).
			Stringer("fromAddress", id.RemoteAddress).Uint16("fromPort", id.RemotePort).Msg("received request")
		ep, err := r.CreateEndpoint(&wq)
		if err != nil {
			s.log.Error().Str("handler", "udp").Stringer("error", err).Msg("")
			return true
		}
		go func() {
			throw.Try(func() {
				s.handleUDP(gonet.NewUDPConn(&wq, ep), &id)
			}).Catch(func(exc *throw.Exception) {
				s.log.Error().Str("handler", "udp").Err(exc).Msg("")
			})
		}()
		return true
	})
	s.SetTransportProtocolHandler(udp.ProtocolNumber, udpForwarder.HandlePacket)
}

func (s *NetworkStack) handleTCP(localConn net.Conn, id *stack.TransportEndpointID) {
	defer localConn.Close()

	address := fmt.Sprintf("%s:%v", id.LocalAddress, id.LocalPort)

	ctx, cancel := context.WithTimeout(context.Background(), s.ConnectTimeout)
	defer cancel()
	dstConn := throw.Throw2(s.socksTCPConn.DialContext(ctx, "tcp", address))
	defer dstConn.Close()

	localConn = NewTimeoutConn(localConn, s.TcpIOTimeout)
	dstConn = NewTimeoutConn(dstConn, s.TcpIOTimeout)
	// relay TCP connections
	throw.Throw(s.transporter.Transport(localConn, dstConn))
}

func (s *NetworkStack) handleUDP(localConn net.Conn, id *stack.TransportEndpointID) {
	defer localConn.Close()

	dstAddress := fmt.Sprintf("%s:%v", id.LocalAddress, id.LocalPort)
	s.log.Debug().Str("dstAddr", dstAddress).Msg("handleUDP called")

	ctx, cancel := context.WithTimeout(context.Background(), s.ConnectTimeout)
	defer cancel()
	dstConn := throw.Throw2(s.socksUDPConn.DialContext(ctx, "udp", dstAddress))
	defer dstConn.Close()

	localConn = NewTimeoutConn(localConn, s.UdpIOTimeout)
	dstConn = NewTimeoutConn(dstConn, s.UdpIOTimeout)
	// relay UDP connections
	throw.Throw(s.transporter.Transport(localConn, dstConn))
}

// defaultIPTables creates iptables rules that allow only TCP and UDP traffic
func defaultIPTables(clock tcpip.Clock, rand *rand.Rand) *stack.IPTables {
	const (
		TCPAllowRuleNum = iota
		_
		DropRuleNum
		AllowRuleNum
	)
	iptables := stack.DefaultTables(clock, rand)
	ipv4filter := iptables.GetTable(stack.FilterID, false)
	ipv4filter.Rules = []stack.Rule{
		{
			Filter: stack.IPHeaderFilter{
				Protocol:      header.TCPProtocolNumber,
				CheckProtocol: true,
			},
			Target: &stack.AcceptTarget{NetworkProtocol: header.IPv4ProtocolNumber},
		},
		{
			Filter: stack.IPHeaderFilter{
				Protocol:      header.UDPProtocolNumber,
				CheckProtocol: true,
			},
			Target: &stack.AcceptTarget{NetworkProtocol: header.IPv4ProtocolNumber},
		},
		{Target: &stack.DropTarget{NetworkProtocol: header.IPv4ProtocolNumber}},
		{Target: &stack.AcceptTarget{NetworkProtocol: header.IPv4ProtocolNumber}},
	}
	ipv4filter.BuiltinChains = [stack.NumHooks]int{
		stack.Prerouting:  TCPAllowRuleNum,
		stack.Input:       TCPAllowRuleNum,
		stack.Forward:     TCPAllowRuleNum,
		stack.Output:      TCPAllowRuleNum,
		stack.Postrouting: AllowRuleNum,
	}
	ipv4filter.Underflows = [stack.NumHooks]int{
		stack.Prerouting:  DropRuleNum,
		stack.Input:       DropRuleNum,
		stack.Forward:     DropRuleNum,
		stack.Output:      DropRuleNum,
		stack.Postrouting: DropRuleNum,
	}
	iptables.ReplaceTable(stack.FilterID, ipv4filter, false)

	ipv6filter := iptables.GetTable(stack.FilterID, true)
	ipv6filter.Rules = []stack.Rule{
		{
			Filter: stack.IPHeaderFilter{
				Protocol:      header.TCPProtocolNumber,
				CheckProtocol: true,
			},
			Target: &stack.AcceptTarget{NetworkProtocol: header.IPv6ProtocolNumber},
		},
		{
			Filter: stack.IPHeaderFilter{
				Protocol:      header.UDPProtocolNumber,
				CheckProtocol: true,
			},
			Target: &stack.AcceptTarget{NetworkProtocol: header.IPv6ProtocolNumber},
		},
		{Target: &stack.DropTarget{NetworkProtocol: header.IPv6ProtocolNumber}},
		{Target: &stack.AcceptTarget{NetworkProtocol: header.IPv6ProtocolNumber}},
	}
	ipv6filter.BuiltinChains = [stack.NumHooks]int{
		stack.Prerouting:  TCPAllowRuleNum,
		stack.Input:       TCPAllowRuleNum,
		stack.Forward:     TCPAllowRuleNum,
		stack.Output:      TCPAllowRuleNum,
		stack.Postrouting: AllowRuleNum,
	}
	ipv6filter.Underflows = [stack.NumHooks]int{
		stack.Prerouting:  DropRuleNum,
		stack.Input:       DropRuleNum,
		stack.Forward:     DropRuleNum,
		stack.Output:      DropRuleNum,
		stack.Postrouting: DropRuleNum,
	}
	iptables.ReplaceTable(stack.FilterID, ipv6filter, true)

	return iptables
}
