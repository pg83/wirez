package main

import (
	"context"
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
	"log/slog"
	"math/rand"
	"net"
	"strconv"
	"time"
)

type NetworkStack struct {
	*stack.Stack
	log            *slog.Logger
	socksTCPConn   Connector
	socksUDPConn   Connector
	transporter    Transporter
	TcpIOTimeout   time.Duration
	UdpIOTimeout   time.Duration
	ConnectTimeout time.Duration
}

func NewNetworkStack(log *slog.Logger, fd int, mtu uint32, tunNetworkAddr string, tunNetworkAddr6 string,
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

	ep := Throw2(fdbased.New(&fdbased.Options{
		MTU: mtu,
		FDs: []int{fd},
		// TUN only
		EthernetHeader: false,
	}))

	var defaultNICID tcpip.NICID = 0x01

	throwTCPIP := func(err tcpip.Error) {
		if err != nil {
			ThrowFmt("%s", err)
		}
	}

	throwTCPIP(s.CreateNIC(defaultNICID, ep))
	throwTCPIP(s.SetPromiscuousMode(defaultNICID, true))
	throwTCPIP(s.SetSpoofing(defaultNICID, true))

	s.setupRouting(defaultNICID, tunNetworkAddr)

	if tunNetworkAddr6 != "" {
		s.setupRouting(defaultNICID, tunNetworkAddr6)
	}

	s.setTCPHandler()
	s.setUDPHandler()

	return s
}

func (s *NetworkStack) setupRouting(nic tcpip.NICID, assignNet string) {
	_, ipNet := Throw3(net.ParseCIDR(assignNet))
	addr := tcpip.AddrFrom16Slice(ipNet.IP.To16())

	if ip4 := ipNet.IP.To4(); ip4 != nil {
		addr = tcpip.AddrFrom4Slice(ip4)
	}

	subnet := Throw2(tcpip.NewSubnet(addr, tcpip.MaskFromBytes(ipNet.Mask)))

	rt := s.GetRouteTable()
	rt = append(rt, tcpip.Route{
		Destination: subnet,
		NIC:         nic,
	})
	s.SetRouteTable(rt)
	s.log.Debug("gVisor routing configured", "subnet", subnet.String())
}

func (s *NetworkStack) setTCPHandler() {
	tcpForwarder := tcp.NewForwarder(s.Stack, 0, 2<<10, func(r *tcp.ForwarderRequest) {
		id := r.ID()
		s.log.Debug("tcp: received request",
			"localAddress", id.LocalAddress, "localPort", id.LocalPort,
			"fromAddress", id.RemoteAddress, "fromPort", id.RemotePort)

		go func() {
			Try(func() {
				s.handleTCP(r, &id)
			}).Catch(func(exc *Exception) {
				s.log.Error("tcp: error", "err", exc)
			})
		}()
	})
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpForwarder.HandlePacket)
}

func (s *NetworkStack) setUDPHandler() {
	udpForwarder := udp.NewForwarder(s.Stack, func(r *udp.ForwarderRequest) bool {
		var wq waiter.Queue
		id := r.ID()
		s.log.Debug("udp: received request",
			"localAddress", id.LocalAddress, "localPort", id.LocalPort,
			"fromAddress", id.RemoteAddress, "fromPort", id.RemotePort)
		ep, err := r.CreateEndpoint(&wq)

		if err != nil {
			s.log.Error("udp: error", "err", err)

			return true
		}

		go func() {
			Try(func() {
				s.handleUDP(gonet.NewUDPConn(&wq, ep), &id)
			}).Catch(func(exc *Exception) {
				s.log.Error("udp: error", "err", exc)
			})
		}()

		return true
	})
	s.SetTransportProtocolHandler(udp.ProtocolNumber, udpForwarder.HandlePacket)
}

// handleTCP dials the destination before completing the client's handshake,
// so a failed upstream dial is reported to the client as a refused connection
// (RST to the SYN) instead of an accepted-then-reset one. That keeps
// happy-eyeballs style fallbacks working: the client moves on to its next
// address right away.
func (s *NetworkStack) handleTCP(r *tcp.ForwarderRequest, id *stack.TransportEndpointID) {
	address := net.JoinHostPort(id.LocalAddress.String(), strconv.Itoa(int(id.LocalPort)))
	ctx, cancel := context.WithTimeout(context.Background(), s.ConnectTimeout)
	defer cancel()

	dstConn, err := s.socksTCPConn.DialContext(ctx, "tcp", address)

	if err != nil {
		r.Complete(true)
		Throw(err)
	}

	defer dstConn.Close()

	var wq waiter.Queue

	ep, tcpErr := r.CreateEndpoint(&wq)

	if tcpErr != nil {
		// prevent potential half-open TCP connection leak.
		r.Complete(true)
		ThrowFmt("%s", tcpErr)
	}

	r.Complete(false)

	localConn := net.Conn(gonet.NewTCPConn(&wq, ep))
	defer localConn.Close()

	localConn = NewTimeoutConn(localConn, s.TcpIOTimeout)
	dstConn = NewTimeoutConn(dstConn, s.TcpIOTimeout)

	// relay TCP connections
	Throw(s.transporter.Transport(localConn, dstConn))
}

func (s *NetworkStack) handleUDP(localConn net.Conn, id *stack.TransportEndpointID) {
	defer localConn.Close()
	dstAddress := net.JoinHostPort(id.LocalAddress.String(), strconv.Itoa(int(id.LocalPort)))

	s.log.Debug("handleUDP called", "dstAddr", dstAddress)

	ctx, cancel := context.WithTimeout(context.Background(), s.ConnectTimeout)
	defer cancel()

	dstConn := Throw2(s.socksUDPConn.DialContext(ctx, "udp", dstAddress))
	defer dstConn.Close()

	localConn = NewTimeoutConn(localConn, s.UdpIOTimeout)
	dstConn = NewTimeoutConn(dstConn, s.UdpIOTimeout)

	// relay UDP connections
	Throw(s.transporter.Transport(localConn, dstConn))
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
