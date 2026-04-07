package main

import (
	"errors"
	"log/slog"
	"os"
	"os/exec"
)

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
	os.Stderr.WriteString(`Usage: wirez [flags] command

Proxy application traffic through the socks5 server.

Flags:
  -F address    socks5 proxy address to forward TCP/UDP packets
  -L mapping    local address mapping [target_host:]port:host:hostport[/proto]
  -v            log verbose level (repeat for more)
  -q            suppress all log output
  -uid int      set uid of container process
  -gid int      set gid of container process
`)
}
