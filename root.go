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

	var err error

	switch os.Args[1] {
	case "runc":
		err = runContainer(os.Args[2:])
	default:
		err = runRun(log, os.Args[1:])
	}

	if err != nil {
		var exitError *exec.ExitError

		if errors.As(err, &exitError) {
			os.Exit(exitError.ExitCode())
		}

		log.Error("error", "err", err)
		os.Exit(1)
	}
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
