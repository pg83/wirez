package main

import (
	"slices"
	"strings"
	"testing"
)

func TestTunPeerAddr(t *testing.T) {
	if got := tunPeerAddr().String(); got != "10.1.1.2" {
		t.Errorf("tunPeerAddr = %s, want 10.1.1.2", got)
	}
}

func TestResolvConfContent(t *testing.T) {
	if got := resolvConfContent(true); got != "nameserver 127.0.0.1\n" {
		t.Errorf("with local resolver: %q", got)
	}

	if got := resolvConfContent(false); got != "nameserver 10.1.1.2\n" {
		t.Errorf("without local resolver: %q", got)
	}
}

func TestHostsContent(t *testing.T) {
	got := strings.Split(strings.TrimSuffix(hostsContent("box"), "\n"), "\n")
	want := []string{
		"127.0.0.1 localhost",
		"::1 localhost",
		"10.1.1.2 localhost",
		"127.0.0.1 box box.localdomain",
		"::1 box box.localdomain",
	}

	if !slices.Equal(got, want) {
		t.Errorf("hosts =\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}
