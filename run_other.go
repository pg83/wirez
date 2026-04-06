//go:build !linux

package main

import (
	"errors"
	"log/slog"
)

func runRun(log *slog.Logger, args []string) error {
	return errors.New("this command is not supported by your OS")
}
