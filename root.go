package main

import (
	"errors"
	"log/slog"
	"os"
	"os/exec"

	"github.com/spf13/cobra"
)

func Main(version string) {
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))

	if err := newRootCmd(log, version).Execute(); err != nil {
		var exitError *exec.ExitError

		if errors.As(err, &exitError) {
			os.Exit(exitError.ExitCode())
		}

		log.Error("error", "err", err)
		os.Exit(1)
	}
}

func newRootCmd(log *slog.Logger, version string) *cobra.Command {
	cmd := &cobra.Command{
		Use:           "wirez",
		Short:         "socks5 proxy rotator",
		Version:       version,
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	cmd.AddCommand(
		newServerCmd(log).cmd,
		newRunCmd(log).cmd,
		newRunContainerCmd().cmd,
	)

	return cmd
}
