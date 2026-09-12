/* SPDX-License-Identifier: MIT */

package clientcfg

import (
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

const endpointLookupTimeout = 10 * time.Second

const (
	EndpointMethodStandard = "standard"
	EndpointMethodDNSTXT   = "DNS TXT"
	EndpointMethodIP4PAAAA = "IP4P AAAA"
)

type endpointResolver interface {
	LookupIP(context.Context, string, string) ([]net.IP, error)
	LookupTXT(context.Context, string) ([]string, error)
}

func validateEndpointSyntax(endpoint string) error {
	if endpoint == "" {
		return fmt.Errorf("value is empty")
	}
	if host, port, err := net.SplitHostPort(endpoint); err == nil {
		if host == "" {
			return fmt.Errorf("host is empty")
		}
		if _, err := lookupUDPPort(port); err != nil {
			return err
		}
		return nil
	}
	if strings.ContainsAny(endpoint, "[]:/\\ \t\r\n") {
		return fmt.Errorf("expected host:port, [IPv6]:port, or an IP4P hostname without a port")
	}
	return nil
}

func (config *Config) ResolveEndpoints() error {
	provider, err := newTXTProvider(&config.IP4P, nil)
	if err != nil {
		return err
	}
	config.EndpointResolutions = config.EndpointResolutions[:0]
	for i := range config.Peers {
		peer := &config.Peers[i]
		if peer.Endpoint == "" {
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), endpointLookupTimeout)
		original := peer.Endpoint
		endpoint, method, err := resolveEndpointDetailed(ctx, net.DefaultResolver, provider, original)
		cancel()
		if err != nil {
			return fmt.Errorf("Peer %d: resolve Endpoint %q: %w", i+1, peer.Endpoint, err)
		}
		peer.Endpoint = endpoint
		config.EndpointResolutions = append(config.EndpointResolutions, EndpointResolution{
			Peer:     i + 1,
			Original: original,
			Resolved: endpoint,
			Method:   method,
		})
	}
	return nil
}

func resolveEndpoint(ctx context.Context, resolver endpointResolver, provider txtProvider, endpoint string) (string, error) {
	resolved, _, err := resolveEndpointDetailed(ctx, resolver, provider, endpoint)
	return resolved, err
}

func resolveEndpointDetailed(ctx context.Context, resolver endpointResolver, provider txtProvider, endpoint string) (string, string, error) {
	host, portText, err := net.SplitHostPort(endpoint)
	if err == nil {
		if _, parseErr := netip.ParseAddr(host); provider != nil && parseErr != nil {
			return resolveIP4PEndpoint(ctx, resolver, provider, host)
		}
		port, err := lookupUDPPort(portText)
		if err != nil {
			return "", "", err
		}
		resolved, err := resolveHostPort(ctx, resolver, host, port)
		return resolved, EndpointMethodStandard, err
	}
	return resolveIP4PEndpoint(ctx, resolver, provider, endpoint)
}

func resolveIP4PEndpoint(ctx context.Context, resolver endpointResolver, provider txtProvider, hostname string) (string, string, error) {
	if provider != nil {
		records, err := provider.GetTXTRecords(ctx, hostname)
		if err != nil {
			return "", "", fmt.Errorf("IP4P %s API lookup failed: %w", provider.Name(), err)
		}
		if endpoint, ok := endpointFromTXTRecords(ctx, resolver, records); ok {
			return endpoint, provider.Name() + " API TXT", nil
		}
		return "", "", fmt.Errorf("IP4P %s API returned no valid TXT endpoint", provider.Name())
	}

	records, txtErr := resolver.LookupTXT(ctx, hostname)
	if txtErr == nil {
		if endpoint, ok := endpointFromTXTRecords(ctx, resolver, records); ok {
			return endpoint, EndpointMethodDNSTXT, nil
		}
	}

	ips, ip6Err := resolver.LookupIP(ctx, "ip6", hostname)
	if ip6Err == nil {
		for _, ip := range ips {
			bytes := ip.To16()
			if bytes == nil || bytes[0] != 0x20 || bytes[1] != 0x01 || bytes[2] != 0 || bytes[3] != 0 {
				continue
			}
			address := netip.AddrFrom4([4]byte{bytes[12], bytes[13], bytes[14], bytes[15]})
			port := int(bytes[10])<<8 | int(bytes[11])
			return net.JoinHostPort(address.String(), strconv.Itoa(port)), EndpointMethodIP4PAAAA, nil
		}
	}

	if txtErr != nil && ip6Err != nil {
		return "", "", fmt.Errorf("IP4P TXT lookup failed (%v) and AAAA lookup failed (%v)", txtErr, ip6Err)
	}
	return "", "", fmt.Errorf("hostname has no valid IP4P TXT or encoded AAAA record")
}

func endpointFromTXTRecords(ctx context.Context, resolver endpointResolver, records []string) (string, bool) {
	for _, record := range records {
		decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(record))
		if err != nil {
			continue
		}
		host, portText, err := net.SplitHostPort(string(decoded))
		if err != nil {
			continue
		}
		port, err := lookupUDPPort(portText)
		if err != nil {
			continue
		}
		resolved, err := resolveHostPort(ctx, resolver, host, port)
		if err == nil {
			return resolved, true
		}
	}
	return "", false
}

func resolveHostPort(ctx context.Context, resolver endpointResolver, host string, port int) (string, error) {
	if address, err := netip.ParseAddr(host); err == nil {
		return net.JoinHostPort(address.Unmap().String(), strconv.Itoa(port)), nil
	}
	ips, err := resolver.LookupIP(ctx, "ip", host)
	if err != nil {
		return "", err
	}
	for _, ip := range ips {
		address, ok := netip.AddrFromSlice(ip)
		if ok {
			return net.JoinHostPort(address.Unmap().String(), strconv.Itoa(port)), nil
		}
	}
	return "", fmt.Errorf("hostname resolved without an IP address")
}

func lookupUDPPort(port string) (int, error) {
	number, err := net.LookupPort("udp", port)
	if err != nil {
		return 0, fmt.Errorf("invalid UDP port %q: %w", port, err)
	}
	return number, nil
}
