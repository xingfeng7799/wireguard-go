/* SPDX-License-Identifier: MIT */

package clientcfg

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"time"
)

const routingLookupTimeout = 10 * time.Second

func (config *Config) ResolveRoutingDomains() error {
	config.Routing.DomainResolutions = config.Routing.DomainResolutions[:0]
	for _, domain := range config.Routing.ExcludeDomains {
		addresses, err := resolveRoutingDomain(net.DefaultResolver, domain)
		if err != nil {
			return fmt.Errorf("resolve Routing.ExcludeDomains %q: %w", domain, err)
		}
		config.Routing.DomainResolutions = append(config.Routing.DomainResolutions, DomainResolution{
			Domain: domain, Addresses: addresses,
		})
	}
	return nil
}

func (config *Config) RefreshRoutingDomains() ([]DomainResolution, []error) {
	return config.refreshRoutingDomains(net.DefaultResolver)
}

func (config *Config) refreshRoutingDomains(resolver endpointResolver) ([]DomainResolution, []error) {
	var candidates []DomainResolution
	var lookupErrors []error
	for _, current := range config.Routing.DomainResolutions {
		addresses, err := resolveRoutingDomain(resolver, current.Domain)
		if err != nil {
			lookupErrors = append(lookupErrors, fmt.Errorf("resolve Routing.ExcludeDomains %q: %w", current.Domain, err))
			continue
		}
		candidates = append(candidates, DomainResolution{Domain: current.Domain, Addresses: addresses})
	}
	return candidates, lookupErrors
}

func (config *Config) ApplyRoutingDomainResolution(candidate DomainResolution) error {
	for i := range config.Routing.DomainResolutions {
		if config.Routing.DomainResolutions[i].Domain == candidate.Domain {
			config.Routing.DomainResolutions[i] = candidate
			return nil
		}
	}
	return fmt.Errorf("Routing.ExcludeDomains %q has no resolution state", candidate.Domain)
}

func resolveRoutingDomain(resolver endpointResolver, domain string) ([]netip.Addr, error) {
	ctx, cancel := context.WithTimeout(context.Background(), routingLookupTimeout)
	defer cancel()
	ips, err := resolver.LookupIP(ctx, "ip", domain)
	if err != nil {
		return nil, err
	}
	seen := make(map[netip.Addr]bool)
	addresses := make([]netip.Addr, 0, len(ips))
	for _, ip := range ips {
		address, ok := netip.AddrFromSlice(ip)
		if !ok {
			continue
		}
		address = address.Unmap()
		if !seen[address] {
			seen[address] = true
			addresses = append(addresses, address)
		}
	}
	if len(addresses) == 0 {
		return nil, fmt.Errorf("hostname resolved without an IP address")
	}
	sort.Slice(addresses, func(i, j int) bool { return addresses[i].Less(addresses[j]) })
	return addresses, nil
}
