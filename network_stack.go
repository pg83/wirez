package main

import (
	"context"
	"log/slog"
	"math/rand"
	"net"
	"strconv"
	"time"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/fdbased"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

const defaultNICID tcpip.NICID = 1

// NetworkStackOptions configures NewNetworkStack.
type NetworkStackOptions struct {
	Log *slog.Logger
	// Link carries the container's packets, normally the TUN device.
	Link stack.LinkEndpoint
	// Networks are the TUN subnets (CIDR) routed into the stack.
	Networks    []string
	TCP         Connector
	UDP         Connector
	Transporter Transporter
	// ConnectTimeout bounds a dial, proxy handshakes included.
	ConnectTimeout time.Duration
	// TCPIdleTimeout closes a TCP connection that carried no data either way
	// for this long; zero disables it and leaves liveness to TCP keepalive.
	TCPIdleTimeout time.Duration
	// UDPIdleTimeout ends a UDP flow that carried no data for this long.
	UDPIdleTimeout time.Duration
}

type NetworkStack struct {
	*stack.Stack
	opts NetworkStackOptions
}

// newTUNEndpoint wraps a TUN file descriptor as a link endpoint.
func newTUNEndpoint(fd int, mtu uint32) stack.LinkEndpoint {
	return Throw2(fdbased.New(&fdbased.Options{
		MTU: mtu,
		FDs: []int{fd},
		// TUN only
		EthernetHeader: false,
	}))
}

func throwTCPIP(err tcpip.Error) {
	if err != nil {
		ThrowFmt("%s", err)
	}
}

func NewNetworkStack(opts NetworkStackOptions) *NetworkStack {
	s := &NetworkStack{
		opts: opts,
		Stack: stack.New(stack.Options{
			NetworkProtocols: []stack.NetworkProtocolFactory{
				ipv4.NewProtocol,
				ipv6.NewProtocol,
			},
			TransportProtocols: []stack.TransportProtocolFactory{
				tcp.NewProtocol,
				udp.NewProtocol,
				icmp.NewProtocol4,
				icmp.NewProtocol6,
			},
			DefaultIPTables: defaultIPTables,
		}),
	}

	// Handlers go in before the link is attached: from then on its
	// dispatcher may deliver packets concurrently.
	s.setTCPHandler()
	s.setUDPHandler()
	s.setICMPHandler()

	throwTCPIP(s.CreateNIC(defaultNICID, opts.Link))
	throwTCPIP(s.SetPromiscuousMode(defaultNICID, true))
	throwTCPIP(s.SetSpoofing(defaultNICID, true))

	for _, network := range opts.Networks {
		s.setupRouting(defaultNICID, network)
	}

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
	s.opts.Log.Debug("gVisor routing configured", "subnet", subnet.String())
}

// endpointAddress renders the destination of a forwarded connection as
// host:port.
func endpointAddress(id *stack.TransportEndpointID) string {
	return net.JoinHostPort(id.LocalAddress.String(), strconv.Itoa(int(id.LocalPort)))
}

// sourceAddress renders the origin of a forwarded connection as host:port.
func sourceAddress(id *stack.TransportEndpointID) string {
	return net.JoinHostPort(id.RemoteAddress.String(), strconv.Itoa(int(id.RemotePort)))
}

func (s *NetworkStack) setTCPHandler() {
	tcpForwarder := tcp.NewForwarder(s.Stack, 0, 2<<10, func(r *tcp.ForwarderRequest) {
		id := r.ID()
		s.opts.Log.Debug("tcp: received request",
			"localAddress", id.LocalAddress, "localPort", id.LocalPort,
			"fromAddress", id.RemoteAddress, "fromPort", id.RemotePort)

		go func() {
			Try(func() {
				s.handleTCP(r, &id)
			}).Catch(func(exc *Exception) {
				s.opts.Log.Error("tcp: error", "err", exc)
			})
		}()
	})
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpForwarder.HandlePacket)
}

func (s *NetworkStack) setUDPHandler() {
	udpForwarder := udp.NewForwarder(s.Stack, func(r *udp.ForwarderRequest) bool {
		var wq waiter.Queue
		id := r.ID()
		s.opts.Log.Debug("udp: received request",
			"localAddress", id.LocalAddress, "localPort", id.LocalPort,
			"fromAddress", id.RemoteAddress, "fromPort", id.RemotePort)
		ep, err := r.CreateEndpoint(&wq)

		if err != nil {
			s.opts.Log.Error("udp: error", "err", err)

			return true
		}

		go func() {
			Try(func() {
				s.handleUDP(gonet.NewUDPConn(&wq, ep), &id)
			}).Catch(func(exc *Exception) {
				s.opts.Log.Error("udp: error", "err", exc)
			})
		}()

		return true
	})
	s.SetTransportProtocolHandler(udp.ProtocolNumber, udpForwarder.HandlePacket)
}

// setICMPHandler answers ICMPv4 echo requests for any address, so ping works
// inside the container. Requests reach the handler because the NIC is
// promiscuous: gVisor leaves the reply for such "temporary" addresses to a
// custom handler. ICMPv6 echo is answered by the stack itself.
func (s *NetworkStack) setICMPHandler() {
	s.SetTransportProtocolHandler(header.ICMPv4ProtocolNumber, func(id stack.TransportEndpointID, pkt *stack.PacketBuffer) bool {
		return s.replyEcho(id, pkt)
	})
}

func (s *NetworkStack) replyEcho(id stack.TransportEndpointID, pkt *stack.PacketBuffer) bool {
	request := header.ICMPv4(pkt.TransportHeader().Slice())

	if len(request) < header.ICMPv4MinimumSize || request.Type() != header.ICMPv4Echo {
		return false
	}

	payload := pkt.Data().AsRange().ToSlice()
	route, err := s.FindRoute(defaultNICID, id.LocalAddress, id.RemoteAddress, ipv4.ProtocolNumber, false)

	if err != nil {
		s.opts.Log.Debug("icmp: no route for echo reply", "to", id.RemoteAddress, "err", err)

		return true
	}

	defer route.Release()

	reply := stack.NewPacketBuffer(stack.PacketBufferOptions{
		ReserveHeaderBytes: int(route.MaxHeaderLength()) + header.ICMPv4MinimumSize,
		Payload:            buffer.MakeWithData(payload),
	})
	defer reply.DecRef()

	icmpHdr := header.ICMPv4(reply.TransportHeader().Push(header.ICMPv4MinimumSize))
	copy(icmpHdr, request[:header.ICMPv4MinimumSize])
	icmpHdr.SetType(header.ICMPv4EchoReply)
	icmpHdr.SetChecksum(0)
	icmpHdr.SetChecksum(header.ICMPv4Checksum(icmpHdr, reply.Data().Checksum()))

	params := stack.NetworkHeaderParams{Protocol: header.ICMPv4ProtocolNumber, TTL: route.DefaultTTL()}

	if err := route.WritePacket(params, reply); err != nil {
		s.opts.Log.Debug("icmp: echo reply failed", "err", err)
	}

	return true
}

// handleTCP dials the destination before completing the client's handshake,
// so a failed upstream dial is reported to the client as a refused connection
// (RST to the SYN) instead of an accepted-then-reset one. That keeps
// happy-eyeballs style fallbacks working: the client moves on to its next
// address right away.
func (s *NetworkStack) handleTCP(r *tcp.ForwarderRequest, id *stack.TransportEndpointID) {
	address := endpointAddress(id)
	ctx, cancel := context.WithTimeout(context.Background(), s.opts.ConnectTimeout)
	defer cancel()

	dstConn, err := s.opts.TCP.DialContext(ctx, "tcp", address)

	if err != nil {
		// Routine for unreachable destinations and for IPv6 attempts the
		// client is expected to fall back from, so not an error.
		s.opts.Log.Debug("tcp: dial failed", "address", address, "err", err)
		r.Complete(true)

		return
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

	// Keepalive notices a vanished peer without an idle timeout.
	ep.SocketOptions().SetKeepAlive(true)

	localConn := net.Conn(gonet.NewTCPConn(&wq, ep))
	defer localConn.Close()

	if s.opts.TCPIdleTimeout > 0 {
		localConn = NewTimeoutConn(localConn, s.opts.TCPIdleTimeout)
		dstConn = NewTimeoutConn(dstConn, s.opts.TCPIdleTimeout)
	}

	// relay TCP connections
	Throw(s.opts.Transporter.Transport(localConn, dstConn))
}

func (s *NetworkStack) handleUDP(localConn net.Conn, id *stack.TransportEndpointID) {
	defer localConn.Close()
	dstAddress := endpointAddress(id)

	s.opts.Log.Debug("handleUDP called", "dstAddr", dstAddress)

	ctx := withUDPSource(context.Background(), sourceAddress(id))
	ctx, cancel := context.WithTimeout(ctx, s.opts.ConnectTimeout)
	defer cancel()

	dstConn, err := s.opts.UDP.DialContext(ctx, "udp", dstAddress)

	if err != nil {
		s.opts.Log.Debug("udp: dial failed", "address", dstAddress, "err", err)

		return
	}

	defer dstConn.Close()

	localConn = NewTimeoutConn(localConn, s.opts.UDPIdleTimeout)
	dstConn = NewTimeoutConn(dstConn, s.opts.UDPIdleTimeout)

	// relay UDP connections
	Throw(s.opts.Transporter.Transport(localConn, dstConn))
}

// icmpEchoMatcher matches ICMP echo requests and replies, the only ICMP that
// wirez lets through: ping works inside the container, nothing else does.
type icmpEchoMatcher struct {
	v6 bool
}

func (m icmpEchoMatcher) Match(_ stack.Hook, pkt *stack.PacketBuffer, _, _ string) (matches bool, hotdrop bool) {
	h := pkt.TransportHeader().Slice()

	if m.v6 {
		if len(h) < header.ICMPv6MinimumSize {
			return false, false
		}

		t := header.ICMPv6(h).Type()

		return t == header.ICMPv6EchoRequest || t == header.ICMPv6EchoReply, false
	}

	if len(h) < header.ICMPv4MinimumSize {
		return false, false
	}

	t := header.ICMPv4(h).Type()

	return t == header.ICMPv4Echo || t == header.ICMPv4EchoReply, false
}

// defaultIPTables creates iptables rules that allow only TCP, UDP and ICMP
// echo traffic.
func defaultIPTables(clock tcpip.Clock, rand *rand.Rand) *stack.IPTables {
	const (
		TCPAllowRuleNum = iota
		_
		_
		DropRuleNum
		AllowRuleNum
	)
	iptables := stack.DefaultTables(clock, rand)

	for _, family := range []struct {
		v6      bool
		network tcpip.NetworkProtocolNumber
		icmp    tcpip.TransportProtocolNumber
	}{
		{false, header.IPv4ProtocolNumber, header.ICMPv4ProtocolNumber},
		{true, header.IPv6ProtocolNumber, header.ICMPv6ProtocolNumber},
	} {
		filter := iptables.GetTable(stack.FilterID, family.v6)
		filter.Rules = []stack.Rule{
			{
				Filter: stack.IPHeaderFilter{
					Protocol:      header.TCPProtocolNumber,
					CheckProtocol: true,
				},
				Target: &stack.AcceptTarget{NetworkProtocol: family.network},
			},
			{
				Filter: stack.IPHeaderFilter{
					Protocol:      header.UDPProtocolNumber,
					CheckProtocol: true,
				},
				Target: &stack.AcceptTarget{NetworkProtocol: family.network},
			},
			{
				Filter: stack.IPHeaderFilter{
					Protocol:      family.icmp,
					CheckProtocol: true,
				},
				Matchers: []stack.Matcher{icmpEchoMatcher{v6: family.v6}},
				Target:   &stack.AcceptTarget{NetworkProtocol: family.network},
			},
			{Target: &stack.DropTarget{NetworkProtocol: family.network}},
			{Target: &stack.AcceptTarget{NetworkProtocol: family.network}},
		}
		filter.BuiltinChains = [stack.NumHooks]int{
			stack.Prerouting:  TCPAllowRuleNum,
			stack.Input:       TCPAllowRuleNum,
			stack.Forward:     TCPAllowRuleNum,
			stack.Output:      TCPAllowRuleNum,
			stack.Postrouting: AllowRuleNum,
		}
		filter.Underflows = [stack.NumHooks]int{
			stack.Prerouting:  DropRuleNum,
			stack.Input:       DropRuleNum,
			stack.Forward:     DropRuleNum,
			stack.Output:      DropRuleNum,
			stack.Postrouting: DropRuleNum,
		}
		iptables.ReplaceTable(stack.FilterID, filter, family.v6)
	}

	return iptables
}
