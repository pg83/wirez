package main

import (
	"flag"
	"strings"
	"testing"
)

// usageText is written by hand; every flag the FlagSet declares has to be in
// it, which no end-to-end test can know without the FlagSet.
func TestUsageMentionsEveryFlag(t *testing.T) {
	fs, _ := newRunFlagSet()

	fs.VisitAll(func(f *flag.Flag) {
		if !strings.Contains(usageText, "\n  -"+f.Name+" ") {
			t.Errorf("usage text does not mention -%s", f.Name)
		}
	})
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
