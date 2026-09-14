//go:build windows

/* SPDX-License-Identifier: MIT */

package main

import (
	"bytes"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/clientcfg"
)

type windowsNetworkState struct {
	interfaceIndex int
	routes         []windowsRoute
	endpointEgress map[string]windowsEgress
	addresses      []netip.Prefix
	dnsServers     []string
	dnsChanged     bool
	interfaces     []windowsIPInterfaceState
}

type windowsRoute struct {
	destination    string
	interfaceIndex int
	nextHop        string
	endpoint       bool
	bypass         bool
}

type windowsEgress struct {
	interfaceIndex int
	nextHop        string
}

type windowsIPInterfaceState struct {
	family string
	mtu    int
}

func clientInterfaceName(configPath string) string {
	name := strings.TrimSuffix(filepath.Base(configPath), filepath.Ext(configPath))
	if name == "" {
		return "WireGuard"
	}
	return name
}

func validateClientPlatform() error {
	if !windows.GetCurrentProcessToken().IsElevated() {
		return fmt.Errorf("configuration mode requires administrator privileges")
	}
	if _, err := exec.LookPath("powershell.exe"); err != nil {
		return fmt.Errorf("locate Windows PowerShell: %w", err)
	}
	return nil
}

func configureClientNetwork(interfaceName string, config *clientcfg.Config) (clientNetworkState, error) {
	interfaceIndex, err := findWindowsInterfaceIndex(interfaceName)
	if err != nil {
		return nil, err
	}
	state := &windowsNetworkState{
		interfaceIndex: interfaceIndex,
		endpointEgress: make(map[string]windowsEgress),
	}
	fail := func(err error) (clientNetworkState, error) {
		if cleanupErr := state.Close(); cleanupErr != nil {
			return nil, errors.Join(err, fmt.Errorf("roll back partial Windows network configuration: %w", cleanupErr))
		}
		return nil, err
	}

	if err := state.configureInterface(config.Interface.MTU); err != nil {
		return fail(err)
	}
	if err := state.configureEndpointRoutes(config.EndpointIPs(), config.AllowedIPs()); err != nil {
		return fail(err)
	}
	state.cacheMissingEndpointEgress()
	if err := state.configureBypassRoutes(config.RoutingBypassPrefixes(), config.AllowedIPs()); err != nil {
		return fail(err)
	}
	if err := state.configureAddresses(config.Interface.Addresses); err != nil {
		return fail(err)
	}
	if err := state.configureAllowedRoutes(config.AllowedIPs()); err != nil {
		return fail(err)
	}
	if err := state.configureDNS(config.Interface.DNS); err != nil {
		return fail(err)
	}
	return state, nil
}

func (state *windowsNetworkState) cacheMissingEndpointEgress() {
	for _, probe := range []netip.Addr{
		netip.MustParseAddr("1.1.1.1"),
		netip.MustParseAddr("2606:4700:4700::1111"),
	} {
		if _, ok := state.endpointEgress[windowsAddressFamily(probe)]; ok {
			continue
		}
		// A missing address family is valid on hosts without that connectivity.
		_ = state.ensureEndpointRoute(probe, nil, true)
	}
}

func findWindowsInterfaceIndex(interfaceName string) (int, error) {
	script := fmt.Sprintf(
		"(Get-NetAdapter -ErrorAction Stop | Where-Object { $_.Name -eq %s } | Select-Object -First 1 -ExpandProperty ifIndex)",
		quotePowerShell(interfaceName),
	)
	var lastErr error
	for attempt := 0; attempt < 20; attempt++ {
		output, err := runPowerShell(script)
		if err == nil {
			index, parseErr := strconv.Atoi(strings.TrimSpace(output))
			if parseErr == nil && index > 0 {
				return index, nil
			}
			lastErr = fmt.Errorf("invalid interface index %q", strings.TrimSpace(output))
		} else {
			lastErr = err
		}
		time.Sleep(100 * time.Millisecond)
	}
	return 0, fmt.Errorf("find Wintun interface %q: %w", interfaceName, lastErr)
}

func (state *windowsNetworkState) configureInterface(configuredMTU int) error {
	mtu := configuredMTU
	if mtu == 0 {
		mtu = 1420
	}
	script := fmt.Sprintf(
		"Get-NetIPInterface -InterfaceIndex %d -ErrorAction Stop | ForEach-Object { '{0}|{1}' -f $_.AddressFamily,$_.NlMtu }",
		state.interfaceIndex,
	)
	var interfaces []windowsIPInterfaceState
	var lastErr error
	for attempt := 0; attempt < 20; attempt++ {
		output, err := runPowerShell(script)
		if err == nil {
			interfaces, err = parseWindowsIPInterfaceSettings(output)
		}
		if err == nil {
			break
		}
		lastErr = err
		time.Sleep(100 * time.Millisecond)
	}
	if len(interfaces) == 0 {
		return fmt.Errorf("read Windows interface %d settings: %w", state.interfaceIndex, lastErr)
	}
	for _, iface := range interfaces {
		family, oldMTU := iface.family, iface.mtu
		state.interfaces = append(state.interfaces, windowsIPInterfaceState{family: family, mtu: oldMTU})
		setScript := fmt.Sprintf(
			"Set-NetIPInterface -InterfaceIndex %d -AddressFamily %s -NlMtuBytes %d -PolicyStore ActiveStore -ErrorAction Stop",
			state.interfaceIndex, family, mtu,
		)
		if _, err := runPowerShell(setScript); err != nil {
			return fmt.Errorf("set Windows %s MTU: %w", family, err)
		}
	}
	return nil
}

func parseWindowsIPInterfaceSettings(output string) ([]windowsIPInterfaceState, error) {
	lines := outputLines(output)
	if len(lines) == 0 {
		return nil, fmt.Errorf("no IP interface settings returned")
	}
	interfaces := make([]windowsIPInterfaceState, 0, len(lines))
	for _, line := range lines {
		parts := strings.SplitN(line, "|", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("parse Windows interface settings %q", line)
		}
		family := strings.TrimSpace(parts[0])
		if family != "IPv4" && family != "IPv6" {
			return nil, fmt.Errorf("unknown Windows address family %q", family)
		}
		mtuText := strings.TrimSpace(parts[1])
		oldMTU, err := strconv.Atoi(mtuText)
		if err != nil || oldMTU <= 0 {
			if err == nil {
				err = fmt.Errorf("must be positive")
			}
			return nil, fmt.Errorf("parse Windows MTU %q for %s: %w", mtuText, family, err)
		}
		interfaces = append(interfaces, windowsIPInterfaceState{family: family, mtu: oldMTU})
	}
	return interfaces, nil
}

func (state *windowsNetworkState) configureEndpointRoutes(endpoints []netip.Addr, allowed []netip.Prefix) error {
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

func (state *windowsNetworkState) EnsureEndpointRoute(endpoint netip.Addr, allowed []netip.Prefix) error {
	return state.ensureEndpointRoute(endpoint.Unmap(), allowed, false)
}

func (state *windowsNetworkState) ensureEndpointRoute(endpoint netip.Addr, allowed []netip.Prefix, initial bool) error {
	family := windowsAddressFamily(endpoint)
	egress, ok := state.endpointEgress[family]
	if !ok {
		lookupScript := fmt.Sprintf(
			"$route = Find-NetRoute -RemoteIPAddress %s -ErrorAction Stop | Where-Object { $_.PSObject.Properties.Name -contains 'DestinationPrefix' } | Select-Object -First 1; if ($null -eq $route) { throw 'No route returned' }; '{0}|{1}|{2}' -f $route.DestinationPrefix,$route.InterfaceIndex,$route.NextHop",
			quotePowerShell(endpoint.String()),
		)
		output, err := runPowerShell(lookupScript)
		if err != nil {
			return fmt.Errorf("find existing route for endpoint %s: %w", endpoint, err)
		}
		parts := strings.SplitN(strings.TrimSpace(output), "|", 3)
		if len(parts) != 3 {
			return fmt.Errorf("parse existing route for endpoint %s: %q", endpoint, output)
		}
		interfaceIndex, err := strconv.Atoi(parts[1])
		if err != nil || interfaceIndex <= 0 || strings.TrimSpace(parts[2]) == "" {
			return fmt.Errorf("invalid existing route for endpoint %s: %q", endpoint, output)
		}
		if !initial && interfaceIndex == state.interfaceIndex {
			return fmt.Errorf("cannot determine external route for new %s endpoint after tunnel routes are active", family)
		}
		egress = windowsEgress{interfaceIndex: interfaceIndex, nextHop: strings.TrimSpace(parts[2])}
		state.endpointEgress[family] = egress
	}
	if !prefixesContain(allowed, endpoint) {
		return nil
	}
	prefix := netip.PrefixFrom(endpoint, endpoint.BitLen()).String()
	for i := range state.routes {
		if strings.EqualFold(state.routes[i].destination, prefix) {
			state.routes[i].endpoint = true
			return nil
		}
	}
	added, err := addWindowsRoute(prefix, egress.interfaceIndex, egress.nextHop)
	if err != nil {
		return fmt.Errorf("pin route for endpoint %s: %w", endpoint, err)
	}
	if added {
		state.routes = append(state.routes, windowsRoute{
			destination:    prefix,
			interfaceIndex: egress.interfaceIndex,
			nextHop:        egress.nextHop,
			endpoint:       true,
		})
	}
	return nil
}

func (state *windowsNetworkState) RemoveEndpointRoute(endpoint netip.Addr) error {
	endpoint = endpoint.Unmap()
	prefix := netip.PrefixFrom(endpoint, endpoint.BitLen()).String()
	for i := len(state.routes) - 1; i >= 0; i-- {
		route := state.routes[i]
		if !route.endpoint || !strings.EqualFold(route.destination, prefix) {
			continue
		}
		state.routes[i].endpoint = false
		if state.routes[i].bypass {
			return nil
		}
		script := fmt.Sprintf(
			"Get-NetRoute -DestinationPrefix %s -InterfaceIndex %d -ErrorAction SilentlyContinue | Where-Object { $_.NextHop -eq %s } | Remove-NetRoute -Confirm:$false -ErrorAction Stop",
			quotePowerShell(route.destination), route.interfaceIndex, quotePowerShell(route.nextHop),
		)
		if _, err := runPowerShell(script); err != nil {
			state.routes[i].endpoint = true
			return fmt.Errorf("remove Windows endpoint route %s: %w", route.destination, err)
		}
		state.routes = append(state.routes[:i], state.routes[i+1:]...)
		return nil
	}
	return nil
}

func (state *windowsNetworkState) configureBypassRoutes(prefixes, allowed []netip.Prefix) error {
	for _, prefix := range prefixes {
		if err := state.EnsureBypassRoute(prefix, allowed); err != nil {
			return err
		}
	}
	return nil
}

func (state *windowsNetworkState) EnsureBypassRoute(prefix netip.Prefix, allowed []netip.Prefix) error {
	prefix = prefix.Masked()
	if !prefixesOverlap(allowed, prefix) {
		return nil
	}
	family := windowsAddressFamily(prefix.Addr())
	egress, ok := state.endpointEgress[family]
	if !ok {
		return fmt.Errorf("no external %s route is available for bypass %s", family, prefix)
	}
	for i := range state.routes {
		if strings.EqualFold(state.routes[i].destination, prefix.String()) {
			state.routes[i].bypass = true
			return nil
		}
	}
	added, err := addWindowsRoute(prefix.String(), egress.interfaceIndex, egress.nextHop)
	if err != nil {
		return fmt.Errorf("add Windows bypass route %s: %w", prefix, err)
	}
	if added {
		state.routes = append(state.routes, windowsRoute{
			destination: prefix.String(), interfaceIndex: egress.interfaceIndex,
			nextHop: egress.nextHop, bypass: true,
		})
	}
	return nil
}

func (state *windowsNetworkState) RemoveBypassRoute(prefix netip.Prefix) error {
	prefix = prefix.Masked()
	for i := len(state.routes) - 1; i >= 0; i-- {
		route := state.routes[i]
		if !route.bypass || !strings.EqualFold(route.destination, prefix.String()) {
			continue
		}
		state.routes[i].bypass = false
		if state.routes[i].endpoint {
			return nil
		}
		script := fmt.Sprintf(
			"Get-NetRoute -DestinationPrefix %s -InterfaceIndex %d -ErrorAction SilentlyContinue | Where-Object { $_.NextHop -eq %s } | Remove-NetRoute -Confirm:$false -ErrorAction Stop",
			quotePowerShell(route.destination), route.interfaceIndex, quotePowerShell(route.nextHop),
		)
		if _, err := runPowerShell(script); err != nil {
			state.routes[i].bypass = true
			return fmt.Errorf("remove Windows bypass route %s: %w", route.destination, err)
		}
		state.routes = append(state.routes[:i], state.routes[i+1:]...)
		return nil
	}
	return nil
}

func (state *windowsNetworkState) configureAddresses(addresses []netip.Prefix) error {
	for _, prefix := range addresses {
		family := windowsAddressFamily(prefix.Addr())
		added, err := addWindowsAddress(state.interfaceIndex, family, prefix)
		if err != nil {
			return fmt.Errorf("add Windows address %s: %w", prefix, err)
		}
		if added {
			state.addresses = append(state.addresses, prefix)
		}
	}
	return nil
}

func (state *windowsNetworkState) configureAllowedRoutes(prefixes []netip.Prefix) error {
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
		nextHop := "::"
		if route.Addr().Is4() {
			nextHop = "0.0.0.0"
		}
		added, err := addWindowsRoute(route.String(), state.interfaceIndex, nextHop)
		if err != nil {
			return fmt.Errorf("add Windows route %s: %w", route, err)
		}
		if added {
			state.routes = append(state.routes, windowsRoute{
				destination:    route.String(),
				interfaceIndex: state.interfaceIndex,
				nextHop:        nextHop,
			})
		}
	}
	return nil
}

func addWindowsAddress(interfaceIndex int, family string, prefix netip.Prefix) (bool, error) {
	script := fmt.Sprintf(
		"$existing = @(Get-NetIPAddress -InterfaceIndex %d -IPAddress %s -ErrorAction SilentlyContinue); if ($existing.Count -gt 0) { 'existing' } else { New-NetIPAddress -InterfaceIndex %d -AddressFamily %s -IPAddress %s -PrefixLength %d -PolicyStore ActiveStore -ErrorAction Stop | Out-Null; 'added' }",
		interfaceIndex, quotePowerShell(prefix.Addr().String()),
		interfaceIndex, family, quotePowerShell(prefix.Addr().String()), prefix.Bits(),
	)
	output, err := runPowerShell(script)
	if err != nil {
		return false, err
	}
	return parseWindowsAddResult(output)
}

func addWindowsRoute(destination string, interfaceIndex int, nextHop string) (bool, error) {
	script := fmt.Sprintf(
		"$existing = @(Get-NetRoute -DestinationPrefix %s -InterfaceIndex %d -ErrorAction SilentlyContinue | Where-Object { $_.NextHop -eq %s }); if ($existing.Count -gt 0) { 'existing' } else { New-NetRoute -DestinationPrefix %s -InterfaceIndex %d -NextHop %s -RouteMetric 0 -PolicyStore ActiveStore -ErrorAction Stop | Out-Null; 'added' }",
		quotePowerShell(destination), interfaceIndex, quotePowerShell(nextHop),
		quotePowerShell(destination), interfaceIndex, quotePowerShell(nextHop),
	)
	output, err := runPowerShell(script)
	if err != nil {
		return false, err
	}
	return parseWindowsAddResult(output)

}

func parseWindowsAddResult(output string) (bool, error) {
	switch strings.TrimSpace(output) {
	case "added":
		return true, nil
	case "existing":
		return false, nil
	default:
		return false, fmt.Errorf("unexpected PowerShell result %q", output)
	}
}

func (state *windowsNetworkState) configureDNS(servers []netip.Addr) error {
	if len(servers) == 0 {
		return nil
	}
	readScript := fmt.Sprintf(
		"Get-DnsClientServerAddress -InterfaceIndex %d -ErrorAction Stop | ForEach-Object { $_.ServerAddresses }",
		state.interfaceIndex,
	)
	output, err := runPowerShell(readScript)
	if err != nil {
		return fmt.Errorf("read Windows DNS servers: %w", err)
	}
	state.dnsServers = outputLines(output)
	state.dnsChanged = true

	serverValues := make([]string, 0, len(servers))
	for _, server := range servers {
		serverValues = append(serverValues, quotePowerShell(server.String()))
	}
	setScript := fmt.Sprintf(
		"Set-DnsClientServerAddress -InterfaceIndex %d -ServerAddresses @(%s) -ErrorAction Stop",
		state.interfaceIndex, strings.Join(serverValues, ","),
	)
	if _, err := runPowerShell(setScript); err != nil {
		return fmt.Errorf("set Windows DNS servers: %w", err)
	}
	return nil
}

func (state *windowsNetworkState) Close() error {
	var cleanupErrors []error
	if state.dnsChanged {
		var script string
		if len(state.dnsServers) == 0 {
			script = fmt.Sprintf(
				"Set-DnsClientServerAddress -InterfaceIndex %d -ResetServerAddresses -ErrorAction Stop",
				state.interfaceIndex,
			)
		} else {
			servers := make([]string, 0, len(state.dnsServers))
			for _, server := range state.dnsServers {
				servers = append(servers, quotePowerShell(server))
			}
			script = fmt.Sprintf(
				"Set-DnsClientServerAddress -InterfaceIndex %d -ServerAddresses @(%s) -ErrorAction Stop",
				state.interfaceIndex, strings.Join(servers, ","),
			)
		}
		if _, err := runPowerShell(script); err != nil {
			cleanupErrors = append(cleanupErrors, fmt.Errorf("restore Windows DNS servers: %w", err))
		}
	}
	for i := len(state.routes) - 1; i >= 0; i-- {
		route := state.routes[i]
		script := fmt.Sprintf(
			"Get-NetRoute -DestinationPrefix %s -InterfaceIndex %d -ErrorAction SilentlyContinue | Where-Object { $_.NextHop -eq %s } | Remove-NetRoute -Confirm:$false -ErrorAction Stop",
			quotePowerShell(route.destination), route.interfaceIndex, quotePowerShell(route.nextHop),
		)
		if _, err := runPowerShell(script); err != nil {
			cleanupErrors = append(cleanupErrors, fmt.Errorf("remove Windows route %s: %w", route.destination, err))
		}
	}
	for i := len(state.addresses) - 1; i >= 0; i-- {
		address := state.addresses[i]
		script := fmt.Sprintf(
			"Get-NetIPAddress -InterfaceIndex %d -IPAddress %s -ErrorAction SilentlyContinue | Remove-NetIPAddress -Confirm:$false -ErrorAction Stop",
			state.interfaceIndex, quotePowerShell(address.Addr().String()),
		)
		if _, err := runPowerShell(script); err != nil {
			cleanupErrors = append(cleanupErrors, fmt.Errorf("remove Windows address %s: %w", address, err))
		}
	}
	for i := len(state.interfaces) - 1; i >= 0; i-- {
		iface := state.interfaces[i]
		script := fmt.Sprintf(
			"Set-NetIPInterface -InterfaceIndex %d -AddressFamily %s -NlMtuBytes %d -PolicyStore ActiveStore -ErrorAction Stop",
			state.interfaceIndex, iface.family, iface.mtu,
		)
		if _, err := runPowerShell(script); err != nil {
			cleanupErrors = append(cleanupErrors, fmt.Errorf("restore Windows %s MTU: %w", iface.family, err))
		}
	}
	return errors.Join(cleanupErrors...)
}

func windowsAddressFamily(address netip.Addr) string {
	if address.Is4() {
		return "IPv4"
	}
	return "IPv6"
}

func quotePowerShell(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "''") + "'"
}

func outputLines(output string) []string {
	var lines []string
	for _, line := range strings.Split(strings.ReplaceAll(output, "\r\n", "\n"), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			lines = append(lines, line)
		}
	}
	return lines
}

func runPowerShell(script string) (string, error) {
	command := exec.Command(
		"powershell.exe",
		"-NoLogo",
		"-NoProfile",
		"-NonInteractive",
		"-ExecutionPolicy", "Bypass",
		"-Command", "$ErrorActionPreference = 'Stop'; $ProgressPreference = 'SilentlyContinue'; [Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false); "+script,
	)
	var output bytes.Buffer
	command.Stdout = &output
	command.Stderr = &output
	if err := command.Run(); err != nil {
		return "", fmt.Errorf("%w: %s", err, strings.TrimSpace(output.String()))
	}
	return strings.TrimSpace(output.String()), nil
}

func clientTerminationSignals() []os.Signal {
	return []os.Signal{os.Interrupt, windows.SIGTERM}
}
