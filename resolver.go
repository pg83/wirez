package main

import (
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

const (
	// dnsUpstreamTimeout bounds a single upstream DNS round-trip.
	dnsUpstreamTimeout = 5 * time.Second
	// dnsBufferSize is large enough for EDNS0 responses.
	dnsBufferSize = 4096
)

// parseUpstreamDNS normalizes a -D value (bare IPv4/IPv6 or host:port) to a
// dialable host:port, defaulting to port 53.
func parseUpstreamDNS(s string) string {
	if s == "" {
		return ""
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

// startDNSResolver takes ownership of a UDP socket fd (bound to 127.0.0.1:53
// inside the container netns) and serves it from the host netns, so upstream
// queries reach the real resolver directly, bypassing SOCKS.
func startDNSResolver(log *slog.Logger, fd int, upstream string, policy *dnsPolicy) {
	f := os.NewFile(uintptr(fd), "dns")
	conn := Throw2(net.FilePacketConn(f))
	Throw(f.Close())

	go serveDNS(log, conn, upstream, policy)
}

// serveDNS answers queries on conn until it is closed.
func serveDNS(log *slog.Logger, conn net.PacketConn, upstream string, policy *dnsPolicy) {
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
				handleDNSQuery(log, conn, addr, query, upstream, policy)
			}).Catch(func(exc *Exception) {
				log.Error("dns: error", "err", exc)
			})
		}()
	}
}

func handleDNSQuery(log *slog.Logger, conn net.PacketConn, addr net.Addr, query []byte, upstream string, policy *dnsPolicy) {
	resp := resolveDNS(log, query, upstream, policy)

	Throw2(conn.WriteTo(resp, addr))
}

// resolveDNS forwards queries verbatim to the upstream resolver, except that
// AAAA answers are replaced with an empty NOERROR (NODATA) whenever the policy
// says the container could not reach them, so applications fall back to IPv4.
func resolveDNS(log *slog.Logger, query []byte, upstream string, policy *dnsPolicy) []byte {
	var parser dnsmessage.Parser

	header, err := parser.Start(query)

	if err != nil {
		log.Debug("dns: unparsable query, forwarding as-is", "err", err)

		return forwardDNS(query, upstream)
	}

	question, err := parser.Question()

	if err != nil {
		return forwardDNS(query, upstream)
	}

	if question.Type != dnsmessage.TypeAAAA {
		return forwardDNS(query, upstream)
	}

	if !policy.ipv6 {
		log.Debug("dns: blocking AAAA", "name", question.Name.String())

		return emptyResponse(header, question)
	}

	resp := forwardDNS(query, upstream)

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

	msg := make([]byte, 2+len(query))
	binary.BigEndian.PutUint16(msg, uint16(len(query)))
	copy(msg[2:], query)
	Throw2(conn.Write(msg))

	var length [2]byte
	Throw2(io.ReadFull(conn, length[:]))

	resp := make([]byte, binary.BigEndian.Uint16(length[:]))
	Throw2(io.ReadFull(conn, resp))

	return resp
}
