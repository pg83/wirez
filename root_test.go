package main

import (
	"flag"
	"strings"
	"testing"
	"time"
)

func TestUsageMentionsEveryFlag(t *testing.T) {
	fs, _ := newRunFlagSet()

	fs.VisitAll(func(f *flag.Flag) {
		if !strings.Contains(usageText, "\n  -"+f.Name+" ") {
			t.Errorf("usage text does not mention -%s", f.Name)
		}
	})
}

func TestRunFlagsParse(t *testing.T) {
	fs, f := newRunFlagSet()
	args := []string{
		"-F", "127.0.0.1:1080", "-F", "http://[::1]:3128",
		"-L", "53:1.1.1.1:53/udp", "-B", "10.0.0.0/8",
		"-D", "1.1.1.1", "-D", "[::1]:5353",
		"-6", "-nat64", "64:ff9b::/96",
		"-connect-timeout", "7s", "-tcp-timeout", "1m", "-udp-timeout", "30s",
		"-v", "-v", "-q", "-uid", "1000", "-gid", "1000",
		"--", "curl", "example.com",
	}

	if err := fs.Parse(args); err != nil {
		t.Fatal(err)
	}

	if len(f.forwardProxies) != 2 || f.forwardProxies[1] != "http://[::1]:3128" {
		t.Errorf("forwardProxies = %v", f.forwardProxies)
	}

	if len(f.localMappings) != 1 || len(f.bypassCIDRs) != 1 {
		t.Errorf("localMappings = %v, bypassCIDRs = %v", f.localMappings, f.bypassCIDRs)
	}

	if len(f.dnsServers) != 2 || f.dnsServers[1] != "[::1]:5353" {
		t.Errorf("dnsServers = %v", f.dnsServers)
	}

	if !f.ipv6 || f.nat64Prefix != "64:ff9b::/96" {
		t.Errorf("ipv6 = %v, nat64 = %q", f.ipv6, f.nat64Prefix)
	}

	if f.connectTimeout != 7*time.Second || f.tcpTimeout != time.Minute || f.udpTimeout != 30*time.Second {
		t.Errorf("timeouts = %v %v %v", f.connectTimeout, f.tcpTimeout, f.udpTimeout)
	}

	if f.verboseLevel != 2 || !f.quiet || f.uid != 1000 || f.gid != 1000 {
		t.Errorf("verboseLevel = %d, quiet = %v, uid = %d, gid = %d", f.verboseLevel, f.quiet, f.uid, f.gid)
	}

	if rest := fs.Args(); len(rest) != 2 || rest[0] != "curl" {
		t.Errorf("command = %v, want [curl example.com]", rest)
	}
}

func TestRunFlagDefaults(t *testing.T) {
	fs, f := newRunFlagSet()

	if err := fs.Parse([]string{"-F", "127.0.0.1:1080", "--", "true"}); err != nil {
		t.Fatal(err)
	}

	if f.connectTimeout != connectTimeout || f.tcpTimeout != 0 || f.udpTimeout != udpIOTimeout {
		t.Errorf("default timeouts = %v %v %v", f.connectTimeout, f.tcpTimeout, f.udpTimeout)
	}
}
