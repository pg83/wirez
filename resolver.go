package main

import (
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

// startDNSResolver takes ownership of a UDP socket fd (bound to 127.0.0.1:53
// inside the container netns) and serves it from the host netns, so upstream
// queries reach the real resolver directly, bypassing SOCKS.
func startDNSResolver(log *slog.Logger, fd int, upstream string) {
	f := os.NewFile(uintptr(fd), "dns")
	conn := Throw2(net.FilePacketConn(f))
	Throw(f.Close())

	go serveDNS(log, conn, upstream)
}

func serveDNS(log *slog.Logger, conn net.PacketConn, upstream string) {
	for {
		buf := make([]byte, dnsBufferSize)
		n, addr, err := conn.ReadFrom(buf)

		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Temporary() {
				continue
			}

			log.Debug("dns: listener closed", "err", err)

			return
		}

		query := buf[:n:n]

		go func() {
			Try(func() {
				handleDNSQuery(log, conn, addr, query, upstream)
			}).Catch(func(exc *Exception) {
				log.Error("dns: error", "err", exc)
			})
		}()
	}
}

func handleDNSQuery(log *slog.Logger, conn net.PacketConn, addr net.Addr, query []byte, upstream string) {
	resp := resolveIPv4Only(log, query, upstream)

	Throw2(conn.WriteTo(resp, addr))
}

// resolveIPv4Only answers AAAA queries locally with an empty NOERROR (NODATA)
// so applications fall back to IPv4, and forwards everything else verbatim to
// the upstream resolver.
func resolveIPv4Only(log *slog.Logger, query []byte, upstream string) []byte {
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

	if question.Type == dnsmessage.TypeAAAA {
		log.Debug("dns: blocking AAAA", "name", question.Name.String())

		return emptyResponse(header, question)
	}

	return forwardDNS(query, upstream)
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

func forwardDNS(query []byte, upstream string) []byte {
	conn := Throw2(net.DialTimeout("udp", upstream, dnsUpstreamTimeout))
	defer conn.Close()

	Throw(conn.SetDeadline(time.Now().Add(dnsUpstreamTimeout)))
	Throw2(conn.Write(query))

	resp := make([]byte, dnsBufferSize)
	n := Throw2(conn.Read(resp))

	return resp[:n]
}
