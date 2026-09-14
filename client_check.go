/* SPDX-License-Identifier: MIT */

package main

import (
	"fmt"
	"net/netip"
	"strings"

	"golang.zx2c4.com/wireguard/clientcfg"
)

type clientCheckReport struct {
	IPv4FullTunnel bool
	IPv6FullTunnel bool
	Warnings       []string
}

func checkConfig(configPath string) error {
	config, err := loadClientConfig(configPath)
	if err != nil {
		return err
	}
	report := analyzeClientConfig(config)

	fmt.Printf("Configuration is valid: %s\n", configPath)
	fmt.Println("No TUN interface, route, address, MTU, or DNS setting was changed.")
	fmt.Printf("Interface addresses: %s\n", joinPrefixes(config.Interface.Addresses))
	fmt.Printf("Peers: %d\n", len(config.Peers))
	printEndpointResolutions(config)
	printRoutingConfiguration(config)
	fmt.Printf("IPv4 full tunnel: %s\n", yesNo(report.IPv4FullTunnel))
	fmt.Printf("IPv6 full tunnel: %s\n", yesNo(report.IPv6FullTunnel))
	if len(config.Interface.DNS) == 0 {
		fmt.Println("DNS override: no")
	} else {
		fmt.Printf("DNS override: yes (%s)\n", joinAddresses(config.Interface.DNS))
	}
	if usesIP4PLookup(config.EndpointResolutions) {
		if interval := config.EndpointRefreshInterval(); interval > 0 {
			fmt.Printf("Endpoint auto-refresh: every %s\n", interval)
		} else {
			fmt.Println("Endpoint auto-refresh: disabled")
		}
	}
	if len(config.Routing.ExcludeDomains) > 0 {
		if interval := config.RoutingRefreshInterval(); interval > 0 {
			fmt.Printf("Routing domain auto-refresh: every %s\n", interval)
		} else {
			fmt.Println("Routing domain auto-refresh: disabled")
		}
	}
	if len(report.Warnings) == 0 {
		fmt.Println("Warnings: none")
		return nil
	}
	fmt.Println("Warnings:")
	for _, warning := range report.Warnings {
		fmt.Printf("- %s\n", warning)
	}
	return nil
}

func analyzeClientConfig(config *clientcfg.Config) clientCheckReport {
	report := clientCheckReport{}
	for _, peer := range config.Peers {
		for _, prefix := range peer.AllowedIPs {
			if prefix.Bits() != 0 {
				continue
			}
			if prefix.Addr().Is4() {
				report.IPv4FullTunnel = true
			} else {
				report.IPv6FullTunnel = true
			}
		}
	}
	if report.IPv4FullTunnel || report.IPv6FullTunnel {
		report.Warnings = append(report.Warnings,
			"A default route is included in AllowedIPs; this can conflict with proxy software or another TUN/VPN client.",
		)
	}
	if len(config.Interface.DNS) > 0 {
		report.Warnings = append(report.Warnings,
			"The client will replace system DNS while running; proxy Fake-IP, encrypted DNS, and split-DNS rules may stop working.",
		)
	}
	for i, peer := range config.Peers {
		if peer.Endpoint == "" {
			report.Warnings = append(report.Warnings,
				fmt.Sprintf("Peer %d has no Endpoint and cannot initiate a connection until it receives authenticated traffic.", i+1),
			)
		}
	}
	return report
}

func joinPrefixes(prefixes []netip.Prefix) string {
	values := make([]string, len(prefixes))
	for i, prefix := range prefixes {
		values[i] = prefix.String()
	}
	return strings.Join(values, ", ")
}

func joinAddresses(addresses []netip.Addr) string {
	values := make([]string, len(addresses))
	for i, address := range addresses {
		values[i] = address.String()
	}
	return strings.Join(values, ", ")
}

func yesNo(value bool) string {
	if value {
		return "yes"
	}
	return "no"
}
