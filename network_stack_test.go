package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/pipe"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

const (
	clientIPv4 = "10.1.1.5"
	clientIPv6 = "2001:db8:1:1::5"
)

// backendDialer plays the proxy chain for the stack under test: it dials a
// fixed backend whatever destination is asked for and records the requests.
type backendDialer struct {
	backend string
	fail    bool

	mu        sync.Mutex
	addresses []string
	sources   []string
}

func (d *backendDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	src, _ := udpSourceFromContext(ctx)

	d.mu.Lock()
	d.addresses = append(d.addresses, address)
	d.sources = append(d.sources, src)
	d.mu.Unlock()

	if d.fail {
		return nil, errors.New("refused by test")
	}

	return (&net.Dialer{}).DialContext(ctx, network, d.backend)
}

func (d *backendDialer) requests() (addresses, sources []string) {
	d.mu.Lock()
	defer d.mu.Unlock()

	return append([]string(nil), d.addresses...), append([]string(nil), d.sources...)
}

func parseAddr(s string) tcpip.Address {
	ip := net.ParseIP(s)

	if ip4 := ip.To4(); ip4 != nil {
		return tcpip.AddrFrom4Slice(ip4)
	}

	return tcpip.AddrFrom16Slice(ip.To16())
}

func networkOf(host string) tcpip.NetworkProtocolNumber {
	if net.ParseIP(host).To4() != nil {
		return ipv4.ProtocolNumber
	}

	return ipv6.ProtocolNumber
}

// newStackHarness runs a NetworkStack on one end of a pipe link and a plain
// gVisor stack on the other end, playing the kernel inside the container.
func newStackHarness(t *testing.T, tcpDialer, udpDialer Connector, tcpIdle time.Duration) *stack.Stack {
	t.Helper()

	wirezLink, clientLink := pipe.New("", "", 1500)
	ns := NewNetworkStack(NetworkStackOptions{
		Log:            discardLogger(),
		Link:           wirezLink,
		Networks:       []string{tunNetworkAddr, tunNetworkAddrV6},
		TCP:            tcpDialer,
		UDP:            udpDialer,
		Transporter:    NewTransporter(discardLogger()),
		ConnectTimeout: testTimeout,
		TCPIdleTimeout: tcpIdle,
		UDPIdleTimeout: testTimeout,
	})
	t.Cleanup(ns.Close)

	client := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{
			tcp.NewProtocol, udp.NewProtocol, icmp.NewProtocol4, icmp.NewProtocol6,
		},
	})
	t.Cleanup(client.Close)

	if err := client.CreateNIC(1, clientLink); err != nil {
		t.Fatal(err)
	}

	for _, a := range []struct {
		proto  tcpip.NetworkProtocolNumber
		addr   string
		prefix int
	}{
		{ipv4.ProtocolNumber, clientIPv4, 24},
		{ipv6.ProtocolNumber, clientIPv6, 64},
	} {
		pa := tcpip.ProtocolAddress{
			Protocol:          a.proto,
			AddressWithPrefix: tcpip.AddressWithPrefix{Address: parseAddr(a.addr), PrefixLen: a.prefix},
		}

		if err := client.AddProtocolAddress(1, pa, stack.AddressProperties{}); err != nil {
			t.Fatal(err)
		}
	}

	client.SetRouteTable([]tcpip.Route{
		{Destination: header.IPv4EmptySubnet, NIC: 1},
		{Destination: header.IPv6EmptySubnet, NIC: 1},
	})

	return client
}

func dialThroughStack(t *testing.T, client *stack.Stack, host string, port uint16) (*gonet.TCPConn, error) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	return gonet.DialContextTCP(ctx, client, tcpip.FullAddress{Addr: parseAddr(host), Port: port}, networkOf(host))
}

func TestStackForwardsTCP(t *testing.T) {
	for _, host := range []string{"192.0.2.1", "2001:db8::1"} {
		t.Run(host, func(t *testing.T) {
			dialer := &backendDialer{backend: eofEchoServer(t)}
			client := newStackHarness(t, dialer, &backendDialer{fail: true}, 0)

			conn, err := dialThroughStack(t, client, host, 8080)

			if err != nil {
				t.Fatal(err)
			}

			defer conn.Close()
			conn.SetDeadline(time.Now().Add(testTimeout))

			if _, err := conn.Write([]byte("hello")); err != nil {
				t.Fatal(err)
			}

			if err := conn.CloseWrite(); err != nil {
				t.Fatal(err)
			}

			got, err := io.ReadAll(conn)

			if err != nil || string(got) != "echo:hello" {
				t.Fatalf("read %q, %v; want \"echo:hello\" and EOF", got, err)
			}

			want := net.JoinHostPort(host, "8080")

			if addresses, _ := dialer.requests(); len(addresses) != 1 || addresses[0] != want {
				t.Errorf("dialed %v, want [%s]", addresses, want)
			}
		})
	}
}

// A destination the chain cannot reach is refused right away, so clients
// with several addresses to try move on instead of waiting.
func TestStackRefusesWhenDialFails(t *testing.T) {
	client := newStackHarness(t, &backendDialer{fail: true}, &backendDialer{fail: true}, 0)

	start := time.Now()
	conn, err := dialThroughStack(t, client, "192.0.2.1", 80)

	if err == nil {
		conn.Close()
		t.Fatal("dial through a failing chain succeeded")
	}

	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("refusal took %v, want an immediate RST", elapsed)
	}
}

func TestStackForwardsUDP(t *testing.T) {
	dialer := &backendDialer{backend: udpEchoServer(t)}
	client := newStackHarness(t, &backendDialer{fail: true}, dialer, 0)

	conn, err := gonet.DialUDP(client, nil, &tcpip.FullAddress{Addr: parseAddr("192.0.2.1"), Port: 53}, ipv4.ProtocolNumber)

	if err != nil {
		t.Fatal(err)
	}

	defer conn.Close()
	conn.SetDeadline(time.Now().Add(testTimeout))

	if _, err := conn.Write([]byte("ping?")); err != nil {
		t.Fatal(err)
	}

	buf := make([]byte, 64)
	n, err := conn.Read(buf)

	if err != nil || string(buf[:n]) != "ping?" {
		t.Fatalf("read %q, %v; want the echo", buf[:n], err)
	}

	addresses, sources := dialer.requests()

	if len(addresses) != 1 || addresses[0] != "192.0.2.1:53" {
		t.Errorf("dialed %v, want [192.0.2.1:53]", addresses)
	}

	if len(sources) != 1 || !bytes.HasPrefix([]byte(sources[0]), []byte(clientIPv4+":")) {
		t.Errorf("udp source passed to the dialer = %v, want %s:port", sources, clientIPv4)
	}
}

func TestStackAnswersPing(t *testing.T) {
	client := newStackHarness(t, &backendDialer{fail: true}, &backendDialer{fail: true}, 0)

	for _, tc := range []struct {
		host      string
		transport tcpip.TransportProtocolNumber
		request   byte
		reply     byte
	}{
		{"192.0.2.1", icmp.ProtocolNumber4, byte(header.ICMPv4Echo), byte(header.ICMPv4EchoReply)},
		{"2001:db8::1", icmp.ProtocolNumber6, byte(header.ICMPv6EchoRequest), byte(header.ICMPv6EchoReply)},
	} {
		t.Run(tc.host, func(t *testing.T) {
			var wq waiter.Queue

			ep, err := client.NewEndpoint(tc.transport, networkOf(tc.host), &wq)

			if err != nil {
				t.Fatal(err)
			}

			defer ep.Close()

			if err := ep.Connect(tcpip.FullAddress{Addr: parseAddr(tc.host)}); err != nil {
				t.Fatal(err)
			}

			entry, ready := waiter.NewChannelEntry(waiter.ReadableEvents)
			wq.EventRegister(&entry)
			defer wq.EventUnregister(&entry)

			// type, code, checksum, ident, sequence, then the payload; the
			// endpoint fills in ident and checksum
			request := append([]byte{tc.request, 0, 0, 0, 0, 0, 0, 1}, "ping"...)

			if _, err := ep.Write(bytes.NewReader(request), tcpip.WriteOptions{}); err != nil {
				t.Fatal(err)
			}

			select {
			case <-ready:
			case <-time.After(testTimeout):
				t.Fatal("no echo reply")
			}

			var reply bytes.Buffer

			if _, err := ep.Read(&reply, tcpip.ReadOptions{}); err != nil {
				t.Fatal(err)
			}

			got := reply.Bytes()

			if len(got) < 8 || got[0] != tc.reply || !bytes.HasSuffix(got, []byte("ping")) {
				t.Errorf("echo reply = %x, want type %d with the payload", got, tc.reply)
			}
		})
	}
}

// With -tcp-timeout an idle connection is torn down; without it the
// connection stays up as long as both peers keep it.
func TestStackTCPIdleTimeout(t *testing.T) {
	backend := silentServer(t)

	t.Run("enabled", func(t *testing.T) {
		client := newStackHarness(t, &backendDialer{backend: backend}, &backendDialer{fail: true}, 300*time.Millisecond)
		conn, err := dialThroughStack(t, client, "192.0.2.1", 80)

		if err != nil {
			t.Fatal(err)
		}

		defer conn.Close()
		conn.SetReadDeadline(time.Now().Add(testTimeout))

		_, err = conn.Read(make([]byte, 1))

		var terr timeoutError

		if err == nil || (errors.As(err, &terr) && terr.Timeout()) {
			t.Errorf("idle connection read = %v, want it closed by the idle timeout", err)
		}
	})

	t.Run("disabled", func(t *testing.T) {
		client := newStackHarness(t, &backendDialer{backend: backend}, &backendDialer{fail: true}, 0)
		conn, err := dialThroughStack(t, client, "192.0.2.1", 80)

		if err != nil {
			t.Fatal(err)
		}

		defer conn.Close()
		conn.SetReadDeadline(time.Now().Add(700 * time.Millisecond))

		_, err = conn.Read(make([]byte, 1))

		var terr timeoutError

		if !errors.As(err, &terr) || !terr.Timeout() {
			t.Errorf("idle connection read = %v, want our own read deadline (connection still open)", err)
		}
	})
}
