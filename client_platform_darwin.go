//go:build darwin

/* SPDX-License-Identifier: MIT */

package main

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

func clientInterfaceName(string) string {
	return "utun"
}

func validateClientPlatform() error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("configuration mode requires root privileges; run with sudo")
	}
	return nil
}

func clientTerminationSignals() []os.Signal {
	return []os.Signal{os.Interrupt, unix.SIGTERM}
}
