package main

import (
	"strings"
	"testing"
)

func TestTunPeerAddr(t *testing.T) {
	if got := tunPeerAddr().String(); got != "10.1.1.2" {
		t.Errorf("tunPeerAddr = %s, want 10.1.1.2", got)
	}
}

func TestResolvConfContent(t *testing.T) {
	host := "# generated\nnameserver 10.0.0.1\nnameserver 10.0.0.2\nsearch corp.example internal\noptions ndots:2 timeout:1\n\n"

	if got, want := resolvConfContent(true, host), "nameserver 127.0.0.1\nsearch corp.example internal\noptions ndots:2 timeout:1\n"; got != want {
		t.Errorf("with local resolver:\n%s\nwant\n%s", got, want)
	}

	if got, want := resolvConfContent(false, ""), "nameserver 10.1.1.2\n"; got != want {
		t.Errorf("without local resolver and host file: %q, want %q", got, want)
	}
}

func TestHostsContent(t *testing.T) {
	own := "127.0.0.1 localhost\n::1 localhost\n10.1.1.2 localhost\n127.0.0.1 box box.localdomain\n::1 box box.localdomain\n"

	if got := hostsContent("box", ""); got != own {
		t.Errorf("without host file:\n%s\nwant\n%s", got, own)
	}

	host := "127.0.0.1 localhost\n10.0.0.5 fileserver fileserver.corp.example\n"
	got := hostsContent("box", host)

	if !strings.HasPrefix(got, host) {
		t.Errorf("host entries not kept first:\n%s", got)
	}

	if !strings.HasSuffix(got, own) {
		t.Errorf("own entries not appended:\n%s", got)
	}
}
