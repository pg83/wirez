package main

import (
	"errors"
	"log/slog"
	"os"
	"os/exec"
)

// usageText has to describe every flag declared in newRunFlagSet;
// TestUsageMentionsEveryFlag keeps the two in sync.
const usageText = `Usage: wirez [flags] command

Proxy application traffic through the socks5 server.

Flags:
  -F address    socks5 proxy address to forward TCP/UDP packets
  -L mapping    local address mapping [target_host:]port:host:hostport[/proto]
  -B cidr       bypass CIDR — destinations in this network go direct, not via SOCKS
  -D address    upstream DNS for the local resolver on 127.0.0.1:53 (IPv4-only unless -6)
  -6            enable IPv6 on the TUN; AAAA answers are kept only for -B networks
  -nat64 prefix NAT64 /96 prefix of the host, e.g. 64:ff9b::/96
  -v            log verbose level (repeat for more)
  -q            suppress all log output
  -uid int      set uid of container process
  -gid int      set gid of container process
`

func main() {
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))

	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	Try(func() {
		switch os.Args[1] {
		case "runc":
			runContainer(os.Args[2:])
		default:
			runRun(log, os.Args[1:])
		}
	}).Catch(func(e *Exception) {
		var exitError *exec.ExitError

		if errors.As(e, &exitError) {
			os.Exit(exitError.ExitCode())
		}

		log.Error("error", "err", e)
		os.Exit(1)
	})
}

func printUsage() {
	os.Stderr.WriteString(usageText)
}
