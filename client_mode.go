/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"fmt"
	"os"
	"os/signal"

	"golang.zx2c4.com/wireguard/clientcfg"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
)

type clientNetworkState interface {
	Close() error
}

func runConfig(configPath string) error {
	if err := validateClientPlatform(); err != nil {
		return err
	}
	file, err := os.Open(configPath)
	if err != nil {
		return fmt.Errorf("open configuration: %w", err)
	}
	info, err := file.Stat()
	if err != nil {
		file.Close()
		return fmt.Errorf("inspect configuration: %w", err)
	}
	if info.Mode().Perm()&0o077 != 0 {
		fmt.Fprintf(os.Stderr, "Warning: %q is accessible by other users; use chmod 600\n", configPath)
	}
	config, err := clientcfg.Parse(file)
	file.Close()
	if err != nil {
		return fmt.Errorf("parse configuration: %w", err)
	}
	if err := config.ResolveEndpoints(); err != nil {
		return err
	}
	printEndpointResolutions(config)

	mtu := config.Interface.MTU
	if mtu == 0 {
		mtu = device.DefaultMTU
	}
	tdev, err := tun.CreateTUN(clientInterfaceName(configPath), mtu)
	if err != nil {
		return fmt.Errorf("create TUN device: %w", err)
	}
	interfaceName, err := tdev.Name()
	if err != nil {
		tdev.Close()
		return fmt.Errorf("get TUN device name: %w", err)
	}

	logger := device.NewLogger(configLogLevel(), fmt.Sprintf("(%s) ", interfaceName))
	wgDevice := device.NewDevice(tdev, conn.NewDefaultBind(), logger)
	defer wgDevice.Close()
	if err := wgDevice.IpcSet(config.UAPI()); err != nil {
		return fmt.Errorf("apply WireGuard configuration: %w", err)
	}

	networkState, err := configureClientNetwork(interfaceName, config)
	if err != nil {
		return fmt.Errorf("configure system network: %w", err)
	}
	defer func() {
		if err := networkState.Close(); err != nil {
			logger.Errorf("Network cleanup failed: %v", err)
		}
	}()

	if err := wgDevice.Up(); err != nil {
		return fmt.Errorf("bring WireGuard device up: %w", err)
	}
	logger.Verbosef("Client started from %s", configPath)
	fmt.Printf("WireGuard interface %s is up; press Ctrl+C to stop\n", interfaceName)

	terminated := make(chan os.Signal, 1)
	signal.Notify(terminated, clientTerminationSignals()...)
	defer signal.Stop(terminated)
	select {
	case <-terminated:
	case <-wgDevice.Wait():
	}
	fmt.Printf("Stopping WireGuard interface %s\n", interfaceName)
	return nil
}

func printEndpointResolutions(config *clientcfg.Config) {
	switch {
	case config.IP4P.Provider != "":
		fmt.Printf("Endpoint resolution mode: api (provider: %s)\n", config.IP4P.Provider)
	case config.IP4P.Mode == "lookup_text" || usesIP4PLookup(config.EndpointResolutions):
		fmt.Println("Endpoint resolution mode: lookup_text (system DNS)")
	default:
		fmt.Println("Endpoint resolution mode: standard")
	}
	for _, resolution := range config.EndpointResolutions {
		fmt.Printf(
			"Peer %d endpoint [%s]: %s -> %s\n",
			resolution.Peer,
			resolution.Method,
			resolution.Original,
			resolution.Resolved,
		)
	}
}

func usesIP4PLookup(resolutions []clientcfg.EndpointResolution) bool {
	for _, resolution := range resolutions {
		if resolution.Method != clientcfg.EndpointMethodStandard {
			return true
		}
	}
	return false
}

func configLogLevel() int {
	switch os.Getenv("LOG_LEVEL") {
	case "verbose", "debug":
		return device.LogLevelVerbose
	case "silent":
		return device.LogLevelSilent
	default:
		return device.LogLevelError
	}
}
