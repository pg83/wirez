package main

import (
	"errors"
	"log/slog"
	"os"
	"os/exec"
	"syscall"
)

// usageText has to describe every flag declared in newRunFlagSet;
// TestUsageMentionsEveryFlag keeps the two in sync.
const usageText = `Usage: wirez [flags] command

Proxy application traffic through a SOCKS5 or HTTP CONNECT proxy.

Flags:
  -F address           proxy to forward through: [socks5://]host:port or http://host:port (repeat to chain)
  -L mapping           local address mapping [target_host:]port:host:hostport[/proto]
  -B cidr              bypass CIDR — destinations in this network go direct, not via the proxy
  -D address           upstream DNS for the local resolver on 127.0.0.1:53 (repeat for failover)
  -6                   enable IPv6 on the TUN; AAAA answers are kept only for -B networks
  -nat64 prefix        NAT64 /96 prefix of the host, e.g. 64:ff9b::/96
  -connect-timeout d   timeout of a dial, proxy handshakes included (default 10s)
  -tcp-timeout d       idle timeout of TCP connections, 0 disables it (default 0)
  -udp-timeout d       idle timeout of UDP flows (default 15s)
  -v                   log verbose level (repeat for more)
  -q                   suppress all log output
  -uid int             set uid of container process
  -gid int             set gid of container process
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
			os.Exit(exitCode(exitError))
		}

		log.Error("error", "err", e)
		os.Exit(1)
	})
}

// exitCode mirrors the container command's exit status the way a shell does:
// its own code, or 128 plus the signal number when a signal killed it.
func exitCode(err *exec.ExitError) int {
	if status, ok := err.Sys().(syscall.WaitStatus); ok && status.Signaled() {
		return 128 + int(status.Signal())
	}

	return err.ExitCode()
}

func printUsage() {
	os.Stderr.WriteString(usageText)
}
