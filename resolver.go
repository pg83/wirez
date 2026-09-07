package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"sync/atomic"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

const (
	// dnsUpstreamTimeout bounds a single upstream DNS round-trip.
	dnsUpstreamTimeout = 5 * time.Second
	// dnsBufferSize is large enough for EDNS0 responses.
	dnsBufferSize = 4096
	// dnsStreamIdleTimeout closes a TCP client that sends nothing for this long.
	dnsStreamIdleTimeout = 10 * time.Second
	// dnsMaxMessageSize is the largest message the TCP length prefix can carry.
	dnsMaxMessageSize = 65535
)

// parseUpstreamDNS normalizes a -D value (bare IPv4/IPv6 or host:port) to a
// dialable host:port, defaulting to port 53.
func parseUpstreamDNS(s string) string {
	if s == "" {
		ThrowFmt("empty -D dns address")
	}

	if _, _, err := net.SplitHostPort(s); err == nil {
		return s
	}

	if ip := net.ParseIP(s); ip != nil {
		return net.JoinHostPort(s, "53")
	}

	ThrowFmt("invalid -D dns address %q", s)

	return ""
}

func parseUpstreamDNSList(list []string) []string {
	result := make([]string, 0, len(list))

	for _, s := range list {
		result = append(result, parseUpstreamDNS(s))
	}

	return result
}

// dnsUpstreams is the -D list. The upstream that answered last is asked
// first, so a dead server costs one timeout, not one per query.
type dnsUpstreams struct {
	addrs     []string
	preferred atomic.Int32
}

func newDNSUpstreams(addrs []string) *dnsUpstreams {
	return &dnsUpstreams{addrs: addrs}
}

func (u *dnsUpstreams) forward(query []byte) ([]byte, error) {
	start := int(u.preferred.Load())

	var errs []error

	for i := range u.addrs {
		idx := (start + i) % len(u.addrs)

		var resp []byte

		err := Try(func() {
			resp = forwardDNS(query, u.addrs[idx])
		}).AsError()

		if err == nil {
			if idx != start {
				u.preferred.Store(int32(idx))
			}

			return resp, nil
		}

		errs = append(errs, fmt.Errorf("%s: %w", u.addrs[idx], err))
	}

	return nil, errors.Join(errs...)
}

// dnsPolicy decides which AAAA answers the container is allowed to see.
// Without IPv6 on the TUN every AAAA query is answered NODATA. With IPv6 an
// AAAA answer is kept only if at least one address in it is dialable directly
// (falls into a -B network, possibly after NAT64 unmapping), because the
// SOCKS chain is assumed to have no working IPv6.
type dnsPolicy struct {
	ipv6  bool
	allow []*net.IPNet
	nat64 *net.IPNet
}

func (p *dnsPolicy) allowsAAAA(resp []byte) bool {
	if !p.ipv6 {
		return false
	}

	var parser dnsmessage.Parser

	if _, err := parser.Start(resp); err != nil {
		return false
	}

	if err := parser.SkipAllQuestions(); err != nil {
		return false
	}

	for {
		rr, err := parser.Answer()

		if err != nil {
			return false
		}

		aaaa, ok := rr.Body.(*dnsmessage.AAAAResource)

		if !ok {
			continue
		}

		ip := net.IP(aaaa.AAAA[:])

		if p.nat64 != nil && p.nat64.Contains(ip) {
			ip = ip[12:16]
		}

		for _, n := range p.allow {
			if n.Contains(ip) {
				return true
			}
		}
	}
}

// startDNSResolver takes ownership of a UDP socket and a TCP listener (both
// bound to 127.0.0.1:53 inside the container netns) and serves them from the
// host netns, so upstream queries reach the real resolvers directly,
// bypassing SOCKS.
func startDNSResolver(log *slog.Logger, udpFd, tcpFd int, upstreams *dnsUpstreams, policy *dnsPolicy) {
	udpFile := os.NewFile(uintptr(udpFd), "dns-udp")
	udpConn := Throw2(net.FilePacketConn(udpFile))
	Throw(udpFile.Close())

	tcpFile := os.NewFile(uintptr(tcpFd), "dns-tcp")
	tcpListener := Throw2(net.FileListener(tcpFile))
	Throw(tcpFile.Close())

	go serveDNS(log, udpConn, upstreams, policy)
	go serveDNSTCP(log, tcpListener, upstreams, policy)
}

// serveDNS answers queries on conn until it is closed.
func serveDNS(log *slog.Logger, conn net.PacketConn, upstreams *dnsUpstreams, policy *dnsPolicy) {
	for {
		buf := make([]byte, dnsBufferSize)
		n, addr, err := conn.ReadFrom(buf)

		if errors.Is(err, net.ErrClosed) {
			log.Debug("dns: listener closed")

			return
		}

		if err != nil {
			log.Debug("dns: read error", "err", err)

			continue
		}

		query := buf[:n:n]

		go func() {
			Try(func() {
				handleDNSQuery(log, conn, addr, query, upstreams, policy)
			}).Catch(func(exc *Exception) {
				log.Error("dns: error", "err", exc)
			})
		}()
	}
}

func handleDNSQuery(log *slog.Logger, conn net.PacketConn, addr net.Addr, query []byte, upstreams *dnsUpstreams, policy *dnsPolicy) {
	resp := resolveDNS(log, query, upstreams, policy)

	Throw2(conn.WriteTo(resp, addr))
}

// serveDNSTCP answers queries on TCP connections until the listener is
// closed.
func serveDNSTCP(log *slog.Logger, ln net.Listener, upstreams *dnsUpstreams, policy *dnsPolicy) {
	for {
		conn, err := ln.Accept()

		if errors.Is(err, net.ErrClosed) {
			log.Debug("dns: tcp listener closed")

			return
		}

		if err != nil {
			log.Debug("dns: accept error", "err", err)

			continue
		}

		go func() {
			defer conn.Close()

			Try(func() {
				handleDNSStream(log, conn, upstreams, policy)
			}).Catch(func(exc *Exception) {
				log.Debug("dns: tcp error", "err", exc)
			})
		}()
	}
}

// handleDNSStream answers length-prefixed queries on one TCP connection (RFC
// 1035 section 4.2.2) until the client closes it or goes idle.
func handleDNSStream(log *slog.Logger, conn net.Conn, upstreams *dnsUpstreams, policy *dnsPolicy) {
	for {
		Throw(conn.SetDeadline(time.Now().Add(dnsStreamIdleTimeout)))

		query, err := readDNSMessage(conn)

		if err != nil {
			return
		}

		Throw(writeDNSMessage(conn, resolveDNS(log, query, upstreams, policy)))
	}
}

// readDNSMessage reads one length-prefixed DNS message.
func readDNSMessage(r io.Reader) ([]byte, error) {
	var length [2]byte

	if _, err := io.ReadFull(r, length[:]); err != nil {
		return nil, err
	}

	msg := make([]byte, binary.BigEndian.Uint16(length[:]))

	if _, err := io.ReadFull(r, msg); err != nil {
		return nil, err
	}

	return msg, nil
}

// writeDNSMessage writes one length-prefixed DNS message.
func writeDNSMessage(w io.Writer, msg []byte) error {
	if len(msg) > dnsMaxMessageSize {
		return fmt.Errorf("dns: message of %d bytes does not fit a TCP frame", len(msg))
	}

	buf := make([]byte, 2+len(msg))
	binary.BigEndian.PutUint16(buf, uint16(len(msg)))
	copy(buf[2:], msg)

	_, err := w.Write(buf)

	return err
}

// resolveDNS forwards queries verbatim to the upstream resolvers, except that
// AAAA answers are replaced with an empty NOERROR (NODATA) whenever the policy
// says the container could not reach them, so applications fall back to IPv4.
func resolveDNS(log *slog.Logger, query []byte, upstreams *dnsUpstreams, policy *dnsPolicy) []byte {
	var parser dnsmessage.Parser

	header, err := parser.Start(query)

	if err != nil {
		log.Debug("dns: unparsable query, forwarding as-is", "err", err)

		return Throw2(upstreams.forward(query))
	}

	question, err := parser.Question()

	if err != nil {
		return Throw2(upstreams.forward(query))
	}

	if question.Type != dnsmessage.TypeAAAA {
		return Throw2(upstreams.forward(query))
	}

	if !policy.ipv6 {
		log.Debug("dns: blocking AAAA", "name", question.Name.String())

		return emptyResponse(header, question)
	}

	resp := Throw2(upstreams.forward(query))

	if policy.allowsAAAA(resp) {
		return resp
	}

	log.Debug("dns: hiding unreachable AAAA", "name", question.Name.String())

	return emptyResponse(header, question)
}

// emptyResponse builds a NOERROR reply carrying only the original question and
// no answer records.
func emptyResponse(query dnsmessage.Header, question dnsmessage.Question) []byte {
	header := dnsmessage.Header{
		ID:                 query.ID,
		Response:           true,
		OpCode:             query.OpCode,
		RecursionDesired:   query.RecursionDesired,
		RecursionAvailable: true,
		RCode:              dnsmessage.RCodeSuccess,
	}

	builder := dnsmessage.NewBuilder(nil, header)
	Throw(builder.StartQuestions())
	Throw(builder.Question(question))

	return Throw2(builder.Finish())
}

// forwardDNS sends the query to the upstream over UDP and, when the answer
// comes back truncated (TC bit set), fetches the complete one over TCP.
func forwardDNS(query []byte, upstream string) []byte {
	resp := forwardDNSUDP(query, upstream)

	if !isTruncated(resp) {
		return resp
	}

	return forwardDNSTCP(query, upstream)
}

func isTruncated(resp []byte) bool {
	var parser dnsmessage.Parser

	header, err := parser.Start(resp)

	return err == nil && header.Truncated
}

func forwardDNSUDP(query []byte, upstream string) []byte {
	conn := Throw2(net.DialTimeout("udp", upstream, dnsUpstreamTimeout))
	defer conn.Close()

	Throw(conn.SetDeadline(time.Now().Add(dnsUpstreamTimeout)))
	Throw2(conn.Write(query))

	resp := make([]byte, dnsBufferSize)
	n := Throw2(conn.Read(resp))

	return resp[:n]
}

// forwardDNSTCP speaks DNS over TCP (RFC 1035 section 4.2.2): every message
// is prefixed with its length as a 16-bit big-endian integer.
func forwardDNSTCP(query []byte, upstream string) []byte {
	conn := Throw2(net.DialTimeout("tcp", upstream, dnsUpstreamTimeout))
	defer conn.Close()

	Throw(conn.SetDeadline(time.Now().Add(dnsUpstreamTimeout)))
	Throw(writeDNSMessage(conn, query))

	return Throw2(readDNSMessage(conn))
}
