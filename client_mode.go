/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"fmt"
	"net/netip"
	"os"
	"os/signal"
	"time"

	"golang.zx2c4.com/wireguard/clientcfg"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
)

type clientNetworkState interface {
	EnsureEndpointRoute(netip.Addr, []netip.Prefix) error
	RemoveEndpointRoute(netip.Addr) error
	EnsureBypassRoute(netip.Prefix, []netip.Prefix) error
	RemoveBypassRoute(netip.Prefix) error
	Close() error
}

func runConfig(configPath string) error {
	if err := validateClientPlatform(); err != nil {
		return err
	}
	config, err := loadClientConfig(configPath)
	if err != nil {
		return err
	}
	printEndpointResolutions(config)
	printRoutingConfiguration(config)

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

	var refreshTimer *time.Ticker
	var endpointRefresh <-chan time.Time
	if usesIP4PLookup(config.EndpointResolutions) {
		if interval := config.EndpointRefreshInterval(); interval > 0 {
			refreshTimer = time.NewTicker(interval)
			endpointRefresh = refreshTimer.C
			defer refreshTimer.Stop()
			fmt.Printf("Endpoint auto-refresh: every %s\n", interval)
		} else {
			fmt.Println("Endpoint auto-refresh: disabled")
		}
	}
	var routingRefreshTimer *time.Ticker
	var routingRefresh <-chan time.Time
	if len(config.Routing.ExcludeDomains) > 0 {
		if interval := config.RoutingRefreshInterval(); interval > 0 {
			routingRefreshTimer = time.NewTicker(interval)
			routingRefresh = routingRefreshTimer.C
			defer routingRefreshTimer.Stop()
			fmt.Printf("Routing domain auto-refresh: every %s\n", interval)
		} else {
			fmt.Println("Routing domain auto-refresh: disabled")
		}
	}

	terminated := make(chan os.Signal, 1)
	signal.Notify(terminated, clientTerminationSignals()...)
	defer signal.Stop(terminated)
	for {
		select {
		case <-terminated:
			fmt.Printf("Stopping WireGuard interface %s\n", interfaceName)
			return nil
		case <-wgDevice.Wait():
			fmt.Printf("Stopping WireGuard interface %s\n", interfaceName)
			return nil
		case <-endpointRefresh:
			refreshClientEndpoints(config, networkState, wgDevice)
		case <-routingRefresh:
			refreshRoutingDomains(config, networkState)
		}
	}
}

func refreshRoutingDomains(config *clientcfg.Config, networkState clientNetworkState) {
	candidates, lookupErrors := config.RefreshRoutingDomains()
	for _, err := range lookupErrors {
		fmt.Fprintf(os.Stderr, "Routing domain refresh failed: %v\n", err)
	}
	for _, candidate := range candidates {
		current, ok := routingDomainResolution(config, candidate.Domain)
		if !ok || addressesEqual(current.Addresses, candidate.Addresses) {
			continue
		}
		oldSet := addressSet(current.Addresses)
		newSet := addressSet(candidate.Addresses)
		var added []netip.Prefix
		failed := false
		for _, address := range candidate.Addresses {
			if oldSet[address] {
				continue
			}
			prefix := netip.PrefixFrom(address, address.BitLen())
			if err := networkState.EnsureBypassRoute(prefix, config.AllowedIPs()); err != nil {
				fmt.Fprintf(os.Stderr, "Routing domain refresh failed for %s: protect route to %s: %v\n", candidate.Domain, address, err)
				failed = true
				break
			}
			added = append(added, prefix)
		}
		if failed {
			for _, prefix := range added {
				if !routingAddressInUse(config, prefix.Addr(), candidate.Domain) {
					_ = networkState.RemoveBypassRoute(prefix)
				}
			}
			continue
		}
		if err := config.ApplyRoutingDomainResolution(candidate); err != nil {
			fmt.Fprintf(os.Stderr, "Routing domain state update failed for %s: %v\n", candidate.Domain, err)
			continue
		}
		fmt.Printf("Routing exclusion changed: %s: %s -> %s\n", candidate.Domain, joinAddresses(current.Addresses), joinAddresses(candidate.Addresses))
		for _, address := range current.Addresses {
			if newSet[address] || routingAddressInUse(config, address, "") {
				continue
			}
			prefix := netip.PrefixFrom(address, address.BitLen())
			if err := networkState.RemoveBypassRoute(prefix); err != nil {
				fmt.Fprintf(os.Stderr, "Routing domain cleanup failed for %s: %v\n", address, err)
			}
		}
	}
}

func routingDomainResolution(config *clientcfg.Config, domain string) (clientcfg.DomainResolution, bool) {
	for _, resolution := range config.Routing.DomainResolutions {
		if resolution.Domain == domain {
			return resolution, true
		}
	}
	return clientcfg.DomainResolution{}, false
}

func addressSet(addresses []netip.Addr) map[netip.Addr]bool {
	set := make(map[netip.Addr]bool, len(addresses))
	for _, address := range addresses {
		set[address.Unmap()] = true
	}
	return set
}

func addressesEqual(left, right []netip.Addr) bool {
	if len(left) != len(right) {
		return false
	}
	leftSet := addressSet(left)
	for _, address := range right {
		if !leftSet[address.Unmap()] {
			return false
		}
	}
	return true
}

func routingAddressInUse(config *clientcfg.Config, address netip.Addr, skipDomain string) bool {
	hostPrefix := netip.PrefixFrom(address, address.BitLen())
	for _, prefix := range config.Routing.ExcludeIPs {
		if prefix.Masked() == hostPrefix {
			return true
		}
	}
	for _, resolution := range config.Routing.DomainResolutions {
		if resolution.Domain == skipDomain {
			continue
		}
		for _, candidate := range resolution.Addresses {
			if candidate.Unmap() == address.Unmap() {
				return true
			}
		}
	}
	return false
}

func printRoutingConfiguration(config *clientcfg.Config) {
	fmt.Printf("Routing mode: %s\n", config.EffectiveRoutingMode())
	for _, prefix := range config.Routing.ExcludeIPs {
		fmt.Printf("Routing exclusion [static]: %s\n", prefix)
	}
	for _, resolution := range config.Routing.DomainResolutions {
		fmt.Printf("Routing exclusion [DNS]: %s -> %s\n", resolution.Domain, joinAddresses(resolution.Addresses))
	}
}

func loadClientConfig(configPath string) (*clientcfg.Config, error) {
	file, err := os.Open(configPath)
	if err != nil {
		return nil, fmt.Errorf("open configuration: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("inspect configuration: %w", err)
	}
	if info.Mode().Perm()&0o077 != 0 {
		fmt.Fprintf(os.Stderr, "Warning: %q is accessible by other users; use chmod 600\n", configPath)
	}
	config, err := clientcfg.Parse(file)
	if err != nil {
		return nil, fmt.Errorf("parse configuration: %w", err)
	}
	if err := config.ResolveEndpoints(); err != nil {
		return nil, err
	}
	if err := config.ResolveRoutingDomains(); err != nil {
		return nil, err
	}
	return config, nil
}

func refreshClientEndpoints(config *clientcfg.Config, networkState clientNetworkState, wgDevice *device.Device) {
	candidates, lookupErrors := config.RefreshEndpointResolutions()
	for _, err := range lookupErrors {
		fmt.Fprintf(os.Stderr, "Endpoint refresh failed: %v\n", err)
	}
	for _, candidate := range candidates {
		peerIndex := candidate.Peer - 1
		if peerIndex < 0 || peerIndex >= len(config.Peers) {
			fmt.Fprintf(os.Stderr, "Endpoint refresh failed: invalid peer number %d\n", candidate.Peer)
			continue
		}
		oldEndpoint := config.Peers[peerIndex].Endpoint
		if candidate.Resolved == oldEndpoint {
			continue
		}
		oldAddress, oldErr := netip.ParseAddrPort(oldEndpoint)
		newAddress, newErr := netip.ParseAddrPort(candidate.Resolved)
		if oldErr != nil || newErr != nil {
			fmt.Fprintf(os.Stderr, "Endpoint refresh failed for Peer %d: invalid resolved endpoint %q -> %q\n", candidate.Peer, oldEndpoint, candidate.Resolved)
			continue
		}
		oldIP := oldAddress.Addr().Unmap()
		newIP := newAddress.Addr().Unmap()
		if oldIP != newIP {
			if err := networkState.EnsureEndpointRoute(newIP, config.AllowedIPs()); err != nil {
				fmt.Fprintf(os.Stderr, "Endpoint refresh failed for Peer %d: protect route to %s: %v\n", candidate.Peer, newIP, err)
				continue
			}
		}
		uapi := fmt.Sprintf("public_key=%s\nendpoint=%s\n\n", config.Peers[peerIndex].PublicKey, candidate.Resolved)
		if err := wgDevice.IpcSet(uapi); err != nil {
			fmt.Fprintf(os.Stderr, "Endpoint refresh failed for Peer %d: update live peer: %v\n", candidate.Peer, err)
			if oldIP != newIP && !endpointIPInUse(config, newIP, -1) {
				if routeErr := networkState.RemoveEndpointRoute(newIP); routeErr != nil {
					fmt.Fprintf(os.Stderr, "Endpoint refresh cleanup failed for %s: %v\n", newIP, routeErr)
				}
			}
			continue
		}
		if err := config.ApplyEndpointResolution(candidate); err != nil {
			fmt.Fprintf(os.Stderr, "Endpoint refresh state update failed for Peer %d: %v\n", candidate.Peer, err)
		}
		wgDevice.SendKeepalivesToPeersWithCurrentKeypair()
		fmt.Printf("Peer %d endpoint changed [%s]: %s -> %s\n", candidate.Peer, candidate.Method, oldEndpoint, candidate.Resolved)
		if oldIP != newIP && !endpointIPInUse(config, oldIP, -1) {
			if err := networkState.RemoveEndpointRoute(oldIP); err != nil {
				fmt.Fprintf(os.Stderr, "Endpoint refresh cleanup failed for %s: %v\n", oldIP, err)
			}
		}
	}
}

func endpointIPInUse(config *clientcfg.Config, address netip.Addr, skipPeer int) bool {
	for i, peer := range config.Peers {
		if i == skipPeer || peer.Endpoint == "" {
			continue
		}
		endpoint, err := netip.ParseAddrPort(peer.Endpoint)
		if err == nil && endpoint.Addr().Unmap() == address {
			return true
		}
	}
	return false
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
