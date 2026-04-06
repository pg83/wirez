package command

import (
	"bufio"
	"errors"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/rs/zerolog"
	"github.com/spf13/pflag"
	"github.com/v-byte-cpu/wirez/pkg/connect"
	"github.com/v-byte-cpu/wirez/pkg/throw"
)

func parseProxyFile(proxyFile io.Reader) []*connect.SocksAddr {
	var socksAddrs []*connect.SocksAddr
	bs := bufio.NewScanner(proxyFile)
	for bs.Scan() {
		rawSocksAddr := strings.Trim(bs.Text(), " ")
		if rawSocksAddr == "" || rawSocksAddr[0] == '#' {
			continue
		}
		socksAddrs = append(socksAddrs, parseProxyURL(rawSocksAddr))
	}
	throw.Throw(bs.Err())
	return socksAddrs
}

func parseProxyURL(proxyURL string) *connect.SocksAddr {
	proxyURL = strings.Trim(proxyURL, " ")
	if !strings.Contains(proxyURL, "//") {
		proxyURL = "socks5://" + proxyURL
	}
	socksURL := throw.Throw2(url.Parse(proxyURL))
	if socksURL.Scheme != "socks5" {
		throw.Throw(errors.New("invalid socks5 scheme"))
	}
	throw.Throw3(net.SplitHostPort(socksURL.Host))
	return &connect.SocksAddr{Address: socksURL.Host, Auth: socksURL.User}
}

func parseProxyURLs(proxyURLs []string) []*connect.SocksAddr {
	result := make([]*connect.SocksAddr, 0, len(proxyURLs))
	for _, proxyURL := range proxyURLs {
		result = append(result, parseProxyURL(proxyURL))
	}
	return result
}

func parseAddressMapper(addressMappings []string) connect.AddressMapper {
	m := connect.NewAddressMapper()
	for _, mapping := range addressMappings {
		network, fromAddress, targetAddress := parseMapping(mapping)
		throw.Throw(m.AddAddressMapping(network, fromAddress, targetAddress))
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
	targetPort, rest, err := takeLastPort(parts[0])
	if err != nil {
		throw.ThrowFmt("invalid target port in mapping %s: %w", mapping, err)
	}
	targetHost, rest, err := takeLastHost(rest)
	if err != nil {
		throw.ThrowFmt("invalid target host in mapping %s: %w", mapping, err)
	}
	if len(targetHost) == 0 {
		throw.ThrowFmt("empty target host in mapping %s", mapping)
	}
	fromPort, rest, err := takeLastPort(rest)
	if err != nil {
		throw.ThrowFmt("invalid source port in mapping %s: %w", mapping, err)
	}
	fromHost, rest, err := takeLastHost(rest)
	if err != nil {
		throw.ThrowFmt("invalid source host in mapping %s: %w", mapping, err)
	}
	if len(rest) > 0 {
		throw.ThrowFmt("invalid source address in mapping %s", mapping)
	}
	fromAddress = net.JoinHostPort(fromHost, fromPort)
	targetAddress = net.JoinHostPort(targetHost, targetPort)
	return
}

func takeLastHost(input string) (host, rest string, err error) {
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
	return host, rest, err
}

func takeLastIPv6Host(input string) (host, rest string, err error) {
	idx := strings.LastIndex(input, "[")
	if idx == -1 {
		return "", "", errors.New("invalid IPv6 address")
	}
	host = input[idx+1 : len(input)-1]
	if idx > 0 {
		if input[idx-1] != ':' {
			return "", "", errors.New("missing colon before host")
		}
		rest = input[:idx-1]
	}
	if ip := net.ParseIP(host); ip == nil {
		err = errors.New("invalid IPv6 address")
	}
	return host, rest, err
}

func takeLastPort(input string) (port, rest string, err error) {
	idx := strings.LastIndex(input, ":")
	port = input[idx+1:]
	if idx > 0 {
		rest = input[:idx]
	}
	_, err = strconv.ParseUint(port, 10, 16)
	return
}

type renamedTypeFlagValue struct {
	pflag.Value
	name        string
	hideDefault bool
}

func (v *renamedTypeFlagValue) Type() string {
	return v.name
}

func (v *renamedTypeFlagValue) String() string {
	if v.hideDefault {
		return ""
	}
	return v.Value.String()
}

func setLogLevel(log *zerolog.Logger, verboseLevel int) *zerolog.Logger {
	level := zerolog.InfoLevel
	switch {
	case verboseLevel < 0:
		level = zerolog.Disabled
	case verboseLevel == 1:
		level = zerolog.DebugLevel
	case verboseLevel >= 2:
		level = zerolog.TraceLevel
	}
	result := log.Level(level)
	return &result
}
