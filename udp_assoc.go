package main

import (
	"log/slog"
	"net"
	"os"
	"strconv"
	"sync"
	"time"
)

// udpFlowQueue is how many datagrams a flow buffers before dropping, which is
// what UDP does anyway.
const udpFlowQueue = 64

// udpAssociation is one SOCKS5 UDP association shared by every flow of a
// single source endpoint, the way a NAT gives one internal socket one
// external port. Outgoing datagrams carry their destination in the SOCKS
// header; replies are demultiplexed to flows by the source address the proxy
// puts in the header of each relayed datagram.
type udpAssociation struct {
	log     *slog.Logger
	control net.Conn
	relay   net.Conn
	src     string
	forget  func(*udpAssociation)

	mu     sync.Mutex
	flows  map[string]*udpFlow
	closed bool
}

func newUDPAssociation(log *slog.Logger, control, relay net.Conn, src string, forget func(*udpAssociation)) *udpAssociation {
	a := &udpAssociation{
		log:     log,
		control: control,
		relay:   relay,
		src:     src,
		forget:  forget,
		flows:   make(map[string]*udpFlow),
	}

	go a.readLoop()

	return a
}

// udpFlowKey normalizes an address the way the proxy will spell it back.
func udpFlowKey(host string, port uint16) string {
	if ip := net.ParseIP(host); ip != nil {
		host = ip.String()
	}

	return net.JoinHostPort(host, strconv.Itoa(int(port)))
}

// open adds a flow to the association; it fails once the association is
// closed, which the caller handles by starting a fresh one.
func (a *udpAssociation) open(host string, port uint16) (*udpFlow, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.closed {
		return nil, false
	}

	f := &udpFlow{
		a:    a,
		key:  udpFlowKey(host, port),
		host: host,
		port: port,
		in:   make(chan []byte, udpFlowQueue),
		done: make(chan struct{}),
	}
	a.flows[f.key] = f

	return f, true
}

func (a *udpAssociation) readLoop() {
	buf := make([]byte, 64<<10)

	for {
		n, err := a.relay.Read(buf)

		if err != nil {
			a.shutdown()

			return
		}

		host, port, payload, err := socks5ParseUDPDatagram(buf[:n])

		if err != nil {
			a.log.Debug("socks5: bad udp datagram from relay", "err", err)

			continue
		}

		a.mu.Lock()
		f := a.flows[udpFlowKey(host, port)]
		a.mu.Unlock()

		if f == nil {
			continue
		}

		p := make([]byte, len(payload))
		copy(p, payload)

		select {
		case f.in <- p:
		default:
			// the reader is slower than the network, drop like a socket would
		}
	}
}

// closeFlow removes a flow; the last one to go takes the association down.
func (a *udpAssociation) closeFlow(f *udpFlow) {
	a.mu.Lock()

	if a.flows[f.key] == f {
		delete(a.flows, f.key)
	}

	last := len(a.flows) == 0 && !a.closed

	if last {
		a.closed = true
		a.forget(a)
	}

	a.mu.Unlock()

	if last {
		a.relay.Close()
		a.control.Close()
	}
}

// shutdown ends the association after the relay failed (usually because the
// proxy closed the control connection) and wakes up every flow.
func (a *udpAssociation) shutdown() {
	a.mu.Lock()

	if a.closed {
		a.mu.Unlock()

		return
	}

	a.closed = true
	flows := a.flows
	a.flows = make(map[string]*udpFlow)
	a.forget(a)
	a.mu.Unlock()

	a.relay.Close()
	a.control.Close()

	for _, f := range flows {
		f.once.Do(func() { close(f.done) })
	}
}

// udpFlow is one destination of a shared association, presented as a
// connected UDP net.Conn.
type udpFlow struct {
	a    *udpAssociation
	key  string
	host string
	port uint16
	in   chan []byte
	done chan struct{}
	once sync.Once

	mu       sync.Mutex
	deadline time.Time
}

func (f *udpFlow) Read(b []byte) (int, error) {
	f.mu.Lock()
	deadline := f.deadline
	f.mu.Unlock()

	var timeout <-chan time.Time

	if !deadline.IsZero() {
		timer := time.NewTimer(time.Until(deadline))
		defer timer.Stop()

		timeout = timer.C
	}

	select {
	case p := <-f.in:
		return copy(b, p), nil
	case <-f.done:
		return 0, net.ErrClosed
	case <-timeout:
		return 0, os.ErrDeadlineExceeded
	}
}

func (f *udpFlow) Write(b []byte) (int, error) {
	select {
	case <-f.done:
		return 0, net.ErrClosed
	default:
	}

	if _, err := f.a.relay.Write(socks5UDPDatagram(f.host, f.port, b)); err != nil {
		return 0, err
	}

	return len(b), nil
}

func (f *udpFlow) Close() error {
	f.once.Do(func() { close(f.done) })
	f.a.closeFlow(f)

	return nil
}

func (f *udpFlow) LocalAddr() net.Addr {
	return f.a.relay.LocalAddr()
}

func (f *udpFlow) RemoteAddr() net.Addr {
	return &net.UDPAddr{IP: net.ParseIP(f.host), Port: int(f.port)}
}

func (f *udpFlow) SetDeadline(t time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.deadline = t

	return nil
}

func (f *udpFlow) SetReadDeadline(t time.Time) error {
	return f.SetDeadline(t)
}

func (f *udpFlow) SetWriteDeadline(time.Time) error {
	return nil
}
