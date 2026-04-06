package main

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
)

func Main(version string) {
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))

	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	var err error

	switch os.Args[1] {
	case "server":
		err = runServer(log, os.Args[2:])
	case "run":
		err = runRun(log, os.Args[2:])
	case "runc":
		err = runContainer(os.Args[2:])
	case "version", "-version", "--version":
		fmt.Println(version)
	default:
		printUsage()
		os.Exit(1)
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
	fmt.Fprintf(os.Stderr, `Usage: wirez <command> [flags]

Commands:
  server    Start SOCKS5 server to load-balance requests
  run       Proxy application traffic through the socks5 server
  version   Print version
`)
}
