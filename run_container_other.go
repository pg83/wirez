//go:build !linux

package main

import "errors"

const (
	loDevice       = "lo"
	tunDevice      = "tun0"
	tunNetworkAddr = "10.1.1.1/24"
)

func runContainer(args []string) error {
	return errors.New("this command is not supported by your OS")
}
