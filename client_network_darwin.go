//go:build darwin

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"bytes"
	"errors"
	"fmt"
	"net/netip"
	"os/exec"
	"sort"
	"strings"

	"golang.zx2c4.com/wireguard/clientcfg"
)

type darwinNetworkState struct {
	interfaceName  string
	routes         []darwinRoute
	dns            []darwinDNSState
	endpointEgress map[string]darwinEgress
}

type darwinRoute struct {
	family   string
	target   string
	endpoint bool
}

type darwinEgress struct {
	gateway string
	iface   string
}

type darwinDNSState struct {
	service string
	servers []string
}

func configureClientNetwork(interfaceName string, config *clientcfg.Config) (clientNetworkState, error) {
	state := &darwinNetworkState{
		interfaceName:  interfaceName,
		endpointEgress: make(map[string]darwinEgress),
	}
	if err := state.configureAddresses(config.Interface.Addresses, config.Interface.MTU); err != nil {
		state.Close()
		return nil, err
	}
	if err := state.configureEndpointRoutes(config.EndpointIPs(), config.AllowedIPs()); err != nil {
		state.Close()
		return nil, err
	}
	state.cacheMissingEndpointEgress()
	if err := state.configureAllowedRoutes(config.AllowedIPs()); err != nil {
		state.Close()
		return nil, err
	}
	if err := state.configureDNS(config.Interface.DNS); err != nil {
		state.Close()
		return nil, err
	}
	return state, nil
}

func (state *darwinNetworkState) cacheMissingEndpointEgress() {
	for _, probe := range []netip.Addr{
		netip.MustParseAddr("1.1.1.1"),
		netip.MustParseAddr("2606:4700:4700::1111"),
	} {
		if _, ok := state.endpointEgress[routeFamily(probe)]; ok {
			continue
		}
		// A missing address family is valid on hosts without that connectivity.
		_ = state.ensureEndpointRoute(probe, nil, true)
	}
}

func (state *darwinNetworkState) configureAddresses(addresses []netip.Prefix, mtu int) error {
	if mtu != 0 {
		if err := runDarwinCommand("/sbin/ifconfig", state.interfaceName, "mtu", fmt.Sprint(mtu)); err != nil {
			return err
		}
	}
	for _, prefix := range addresses {
		address := prefix.Addr().String()
		if prefix.Addr().Is4() {
			if err := runDarwinCommand("/sbin/ifconfig", state.interfaceName, "inet", prefix.String(), address, "alias"); err != nil {
				return err
			}
		} else {
			if err := runDarwinCommand("/sbin/ifconfig", state.interfaceName, "inet6", prefix.String(), "alias"); err != nil {
				return err
			}
		}
	}
	return runDarwinCommand("/sbin/ifconfig", state.interfaceName, "up")
}

func (state *darwinNetworkState) configureEndpointRoutes(endpoints []netip.Addr, allowed []netip.Prefix) error {
	seen := make(map[netip.Addr]bool)
	for _, endpoint := range endpoints {
		if seen[endpoint] {
			continue
		}
		seen[endpoint] = true
		if err := state.ensureEndpointRoute(endpoint, allowed, true); err != nil {
			return err
		}
	}
	return nil
}

func (state *darwinNetworkState) EnsureEndpointRoute(endpoint netip.Addr, allowed []netip.Prefix) error {
	return state.ensureEndpointRoute(endpoint.Unmap(), allowed, false)
}

func (state *darwinNetworkState) ensureEndpointRoute(endpoint netip.Addr, allowed []netip.Prefix, initial bool) error {
	family := routeFamily(endpoint)
	egress, ok := state.endpointEgress[family]
	if !ok {
		gateway, iface, err := currentDarwinRoute(endpoint)
		if err != nil {
			return fmt.Errorf("determine existing route for endpoint %s: %w", endpoint, err)
		}
		if !initial && iface == state.interfaceName {
			return fmt.Errorf("cannot determine external route for new %s endpoint after tunnel routes are active", family)
		}
		egress = darwinEgress{gateway: gateway, iface: iface}
		state.endpointEgress[family] = egress
	}
	if !prefixesContain(allowed, endpoint) {
		return nil
	}
	for _, route := range state.routes {
		if route.endpoint && route.family == family && route.target == endpoint.String() {
			return nil
		}
	}
	args := []string{"-q", "-n", "add", family, endpoint.String()}
	if egress.gateway != "" {
		args = append(args, "-gateway", egress.gateway)
	} else if egress.iface != "" {
		args = append(args, "-interface", egress.iface)
	} else {
		return fmt.Errorf("external route for endpoint %s has no gateway or interface", endpoint)
	}
	if err := runDarwinCommand("/sbin/route", args...); err != nil {
		return err
	}
	state.routes = append(state.routes, darwinRoute{family: family, target: endpoint.String(), endpoint: true})
	return nil
}

func (state *darwinNetworkState) RemoveEndpointRoute(endpoint netip.Addr) error {
	endpoint = endpoint.Unmap()
	family := routeFamily(endpoint)
	target := endpoint.String()
	for i := len(state.routes) - 1; i >= 0; i-- {
		route := state.routes[i]
		if !route.endpoint || route.family != family || route.target != target {
			continue
		}
		if err := runDarwinCommand("/sbin/route", "-q", "-n", "delete", family, target); err != nil {
			return err
		}
		state.routes = append(state.routes[:i], state.routes[i+1:]...)
		return nil
	}
	return nil
}

func (state *darwinNetworkState) configureAllowedRoutes(prefixes []netip.Prefix) error {
	var routes []netip.Prefix
	seen := make(map[string]bool)
	for _, prefix := range prefixes {
		for _, route := range splitDefaultRoute(prefix.Masked()) {
			key := route.String()
			if !seen[key] {
				seen[key] = true
				routes = append(routes, route)
			}
		}
	}
	sort.SliceStable(routes, func(i, j int) bool { return routes[i].Bits() > routes[j].Bits() })
	for _, route := range routes {
		family := routeFamily(route.Addr())
		if err := runDarwinCommand("/sbin/route", "-q", "-n", "add", family, route.String(), "-interface", state.interfaceName); err != nil {
			return err
		}
		state.routes = append(state.routes, darwinRoute{family: family, target: route.String()})
	}
	return nil
}

func (state *darwinNetworkState) configureDNS(servers []netip.Addr) error {
	if len(servers) == 0 {
		return nil
	}
	servicesOutput, err := exec.Command("/usr/sbin/networksetup", "-listallnetworkservices").Output()
	if err != nil {
		return fmt.Errorf("list macOS network services: %w", err)
	}
	var serverArgs []string
	for _, server := range servers {
		serverArgs = append(serverArgs, server.String())
	}
	for _, line := range strings.Split(string(servicesOutput), "\n") {
		service := strings.TrimSpace(line)
		if service == "" || strings.HasPrefix(service, "An asterisk") || strings.HasPrefix(service, "*") {
			continue
		}
		oldServers, err := getDarwinDNSServers(service)
		if err != nil {
			return err
		}
		state.dns = append(state.dns, darwinDNSState{service: service, servers: oldServers})
		args := append([]string{"-setdnsservers", service}, serverArgs...)
		if err := runDarwinCommand("/usr/sbin/networksetup", args...); err != nil {
			return err
		}
	}
	return nil
}

func getDarwinDNSServers(service string) ([]string, error) {
	output, err := exec.Command("/usr/sbin/networksetup", "-getdnsservers", service).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("read DNS servers for %q: %w: %s", service, err, strings.TrimSpace(string(output)))
	}
	text := strings.TrimSpace(string(output))
	if text == "" || strings.HasPrefix(text, "There aren't any DNS Servers set on") {
		return nil, nil
	}
	return strings.Fields(text), nil
}

func currentDarwinRoute(address netip.Addr) (gateway, iface string, err error) {
	output, err := exec.Command("/sbin/route", "-n", "get", routeFamily(address), address.String()).CombinedOutput()
	if err != nil {
		return "", "", fmt.Errorf("%w: %s", err, strings.TrimSpace(string(output)))
	}
	for _, line := range strings.Split(string(output), "\n") {
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		switch strings.TrimSpace(key) {
		case "gateway":
			candidate := strings.TrimSpace(value)
			if _, parseErr := netip.ParseAddr(candidate); parseErr == nil {
				gateway = candidate
			}
		case "interface":
			iface = strings.TrimSpace(value)
		}
	}
	return gateway, iface, nil
}

func routeFamily(address netip.Addr) string {
	if address.Is4() {
		return "-inet"
	}
	return "-inet6"
}

func runDarwinCommand(path string, args ...string) error {
	command := exec.Command(path, args...)
	var output bytes.Buffer
	command.Stdout = &output
	command.Stderr = &output
	if err := command.Run(); err != nil {
		return fmt.Errorf("%s %s: %w: %s", path, strings.Join(args, " "), err, strings.TrimSpace(output.String()))
	}
	return nil
}

func (state *darwinNetworkState) Close() error {
	var cleanupErrors []error
	for i := len(state.dns) - 1; i >= 0; i-- {
		snapshot := state.dns[i]
		servers := snapshot.servers
		if len(servers) == 0 {
			servers = []string{"Empty"}
		}
		args := append([]string{"-setdnsservers", snapshot.service}, servers...)
		if err := runDarwinCommand("/usr/sbin/networksetup", args...); err != nil {
			cleanupErrors = append(cleanupErrors, err)
		}
	}
	for i := len(state.routes) - 1; i >= 0; i-- {
		route := state.routes[i]
		if err := runDarwinCommand("/sbin/route", "-q", "-n", "delete", route.family, route.target); err != nil {
			cleanupErrors = append(cleanupErrors, err)
		}
	}
	return errors.Join(cleanupErrors...)
}
