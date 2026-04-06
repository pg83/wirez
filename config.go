package main

import (
	"bufio"
	"io"
	"log/slog"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
)

func parseProxyFile(proxyFile io.Reader) []*SocksAddr {
	var socksAddrs []*SocksAddr
	bs := bufio.NewScanner(proxyFile)

	for bs.Scan() {
		rawSocksAddr := strings.Trim(bs.Text(), " ")
		if rawSocksAddr == "" || rawSocksAddr[0] == '#' {
			continue
		}
		socksAddrs = append(socksAddrs, parseProxyURL(rawSocksAddr))
	}

	Throw(bs.Err())

	return socksAddrs
}

func parseProxyURL(proxyURL string) *SocksAddr {
	proxyURL = strings.Trim(proxyURL, " ")

	if !strings.Contains(proxyURL, "//") {
		proxyURL = "socks5://" + proxyURL
	}

	socksURL := Throw2(url.Parse(proxyURL))

	if socksURL.Scheme != "socks5" {
		ThrowFmt("invalid socks5 scheme")
	}

	Throw3(net.SplitHostPort(socksURL.Host))
	return &SocksAddr{Address: socksURL.Host, Auth: socksURL.User}
}

func parseProxyURLs(proxyURLs []string) []*SocksAddr {
	result := make([]*SocksAddr, 0, len(proxyURLs))

	for _, proxyURL := range proxyURLs {
		result = append(result, parseProxyURL(proxyURL))
	}

	return result
}

func parseAddressMapper(addressMappings []string) AddressMapper {
	m := NewAddressMapper()

	for _, mapping := range addressMappings {
		network, fromAddress, targetAddress := parseMapping(mapping)
		Throw(m.AddAddressMapping(network, fromAddress, targetAddress))
	}

	return m
}

func parseMapping(mapping string) (network, fromAddress, targetAddress string) {
	parts := strings.Split(mapping, "/")

	if len(parts) < 2 {
		network = "tcp"
	} else {
		network = parts[1]
	}

	targetPort, rest := takeLastPort(parts[0])
	targetHost, rest := takeLastHost(rest)

	if len(targetHost) == 0 {
		ThrowFmt("empty target host in mapping %s", mapping)
	}

	fromPort, rest := takeLastPort(rest)
	fromHost, rest := takeLastHost(rest)

	if len(rest) > 0 {
		ThrowFmt("invalid source address in mapping %s", mapping)
	}

	fromAddress = net.JoinHostPort(fromHost, fromPort)
	targetAddress = net.JoinHostPort(targetHost, targetPort)

	return
}

func takeLastHost(input string) (host, rest string) {
	if len(input) == 0 {
		return
	}

	if input[len(input)-1] == ']' {
		return takeLastIPv6Host(input)
	}

	idx := strings.LastIndex(input, ":")
	host = input[idx+1:]

	if idx > 0 {
		rest = input[:idx]
	}

	return
}

func takeLastIPv6Host(input string) (host, rest string) {
	idx := strings.LastIndex(input, "[")

	if idx == -1 {
		ThrowFmt("invalid IPv6 address")
	}

	host = input[idx+1 : len(input)-1]

	if idx > 0 {
		if input[idx-1] != ':' {
			ThrowFmt("missing colon before host")
		}
		rest = input[:idx-1]
	}

	if ip := net.ParseIP(host); ip == nil {
		ThrowFmt("invalid IPv6 address")
	}

	return
}

func takeLastPort(input string) (port, rest string) {
	idx := strings.LastIndex(input, ":")
	port = input[idx+1:]

	if idx > 0 {
		rest = input[:idx]
	}

	Throw2(strconv.ParseUint(port, 10, 16))
	return
}

type stringArrayFlag []string

func (f *stringArrayFlag) String() string {
	return strings.Join(*f, ", ")
}

func (f *stringArrayFlag) Set(s string) error {
	*f = append(*f, s)

	return nil
}

type countFlag int

func (f *countFlag) String() string {
	return strconv.Itoa(int(*f))
}

func (f *countFlag) Set(string) error {
	*f++

	return nil
}

func (f *countFlag) IsBoolFlag() bool {
	return true
}

func setLogLevel(verboseLevel int) *slog.Logger {
	var level slog.Level

	switch {
	case verboseLevel < 0:
		level = slog.Level(100)
	case verboseLevel == 0:
		level = slog.LevelInfo
	case verboseLevel == 1:
		level = slog.LevelDebug
	case verboseLevel >= 2:
		level = slog.LevelDebug - 4
	}

	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
}
