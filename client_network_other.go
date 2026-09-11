//go:build !darwin && !windows

/* SPDX-License-Identifier: MIT */

package main

import (
	"fmt"
	"os"

	"golang.zx2c4.com/wireguard/clientcfg"
)

func clientInterfaceName(string) string {
	return "wg0"
}

func validateClientPlatform() error {
	return fmt.Errorf("-c configuration mode is currently supported only on macOS")
}

func configureClientNetwork(string, *clientcfg.Config) (clientNetworkState, error) {
	return nil, fmt.Errorf("-c configuration mode is currently supported only on macOS")
}

func clientTerminationSignals() []os.Signal {
	return []os.Signal{os.Interrupt}
}
