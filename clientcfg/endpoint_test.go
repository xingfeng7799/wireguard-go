/* SPDX-License-Identifier: MIT */

package clientcfg

import (
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"strings"
	"testing"
)

type fakeEndpointResolver struct {
	txtRecords map[string][]string
	ipRecords  map[string][]net.IP
}

type fakeTXTProvider struct {
	records []string
	err     error
}

func (*fakeTXTProvider) Name() string { return "fake" }

func (provider *fakeTXTProvider) GetTXTRecords(context.Context, string) ([]string, error) {
	return provider.records, provider.err
}

func (resolver *fakeEndpointResolver) LookupTXT(_ context.Context, host string) ([]string, error) {
	if records, ok := resolver.txtRecords[host]; ok {
		return records, nil
	}
	return nil, fmt.Errorf("TXT record not found")
}

func (resolver *fakeEndpointResolver) LookupIP(_ context.Context, network, host string) ([]net.IP, error) {
	if records, ok := resolver.ipRecords[network+"|"+host]; ok {
		return records, nil
	}
	return nil, fmt.Errorf("%s record not found", network)
}

func TestResolveEndpointBackwardCompatibility(t *testing.T) {
	resolver := &fakeEndpointResolver{
		ipRecords: map[string][]net.IP{
			"ip|vpn.example.com": {net.ParseIP("2001:db8::10")},
		},
	}
	tests := []struct {
		endpoint string
		want     string
	}{
		{endpoint: "192.0.2.10:51820", want: "192.0.2.10:51820"},
		{endpoint: "[2001:db8::20]:51820", want: "[2001:db8::20]:51820"},
		{endpoint: "vpn.example.com:51820", want: "[2001:db8::10]:51820"},
	}
	for _, test := range tests {
		t.Run(test.endpoint, func(t *testing.T) {
			got, err := resolveEndpoint(context.Background(), resolver, nil, test.endpoint)
			if err != nil {
				t.Fatal(err)
			}
			if got != test.want {
				t.Fatalf("resolveEndpoint(%q) = %q, want %q", test.endpoint, got, test.want)
			}
		})
	}
}

func TestResolveIP4PTXTEndpoint(t *testing.T) {
	tests := []struct {
		name   string
		record string
		want   string
	}{
		{name: "IPv4", record: "203.0.113.9:51820", want: "203.0.113.9:51820"},
		{name: "IPv6", record: "[2001:db8::9]:51820", want: "[2001:db8::9]:51820"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			resolver := &fakeEndpointResolver{
				txtRecords: map[string][]string{
					"ip4p.example.com": {base64.StdEncoding.EncodeToString([]byte(test.record))},
				},
			}
			got, err := resolveEndpoint(context.Background(), resolver, nil, "ip4p.example.com")
			if err != nil {
				t.Fatal(err)
			}
			if got != test.want {
				t.Fatalf("resolveEndpoint() = %q, want %q", got, test.want)
			}
		})
	}
}

func TestResolveIP4PEncodedAAAA(t *testing.T) {
	resolver := &fakeEndpointResolver{
		ipRecords: map[string][]net.IP{
			"ip6|ip4p.example.com": {net.ParseIP("2001:0000:0000:0000:0000:ca6c:cb00:7109")},
		},
	}
	got, err := resolveEndpoint(context.Background(), resolver, nil, "ip4p.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if want := "203.0.113.9:51820"; got != want {
		t.Fatalf("resolveEndpoint() = %q, want %q", got, want)
	}
}

func TestValidateEndpointSyntax(t *testing.T) {
	for _, endpoint := range []string{
		"vpn.example.com:51820",
		"[2001:db8::1]:51820",
		"ip4p.example.com",
	} {
		if err := validateEndpointSyntax(endpoint); err != nil {
			t.Errorf("validateEndpointSyntax(%q): %v", endpoint, err)
		}
	}
	for _, endpoint := range []string{"", "2001:db8::1", "bad host"} {
		if err := validateEndpointSyntax(endpoint); err == nil {
			t.Errorf("validateEndpointSyntax(%q) unexpectedly succeeded", endpoint)
		}
	}
}

func TestIP4PAPIModeDoesNotFallback(t *testing.T) {
	resolver := &fakeEndpointResolver{
		txtRecords: map[string][]string{
			"ip4p.example.com": {base64.StdEncoding.EncodeToString([]byte("203.0.113.9:51820"))},
		},
	}
	provider := &fakeTXTProvider{err: fmt.Errorf("provider unavailable")}
	_, err := resolveEndpoint(context.Background(), resolver, provider, "ip4p.example.com")
	if err == nil || !strings.Contains(err.Error(), "provider unavailable") {
		t.Fatalf("expected provider error without DNS fallback, got %v", err)
	}
}

func TestIP4PAPIModeOverridesExplicitPort(t *testing.T) {
	resolver := &fakeEndpointResolver{}
	provider := &fakeTXTProvider{
		records: []string{base64.StdEncoding.EncodeToString([]byte("[2001:db8::20]:54321"))},
	}
	endpoint, err := resolveEndpoint(context.Background(), resolver, provider, "ip4p.example.com:51820")
	if err != nil {
		t.Fatal(err)
	}
	if endpoint != "[2001:db8::20]:54321" {
		t.Fatalf("endpoint = %q", endpoint)
	}
}

func TestRefreshEndpointResolutions(t *testing.T) {
	host := "ip4p.example.com"
	resolver := &fakeEndpointResolver{txtRecords: map[string][]string{
		host: {base64.StdEncoding.EncodeToString([]byte("203.0.113.10:51820"))},
	}}
	config := &Config{
		Peers: []Peer{{Endpoint: "203.0.113.9:51820"}, {Endpoint: "192.0.2.1:51820"}},
		EndpointResolutions: []EndpointResolution{
			{Peer: 1, Original: host, Resolved: "203.0.113.9:51820", Method: EndpointMethodDNSTXT},
			{Peer: 2, Original: "vpn.example.com:51820", Resolved: "192.0.2.1:51820", Method: EndpointMethodStandard},
		},
	}
	candidates, errs := config.refreshEndpointResolutions(resolver, nil)
	if len(errs) != 0 {
		t.Fatalf("unexpected refresh errors: %v", errs)
	}
	if len(candidates) != 1 || candidates[0].Resolved != "203.0.113.10:51820" {
		t.Fatalf("unexpected refresh candidates: %#v", candidates)
	}
	if config.Peers[0].Endpoint != "203.0.113.9:51820" {
		t.Fatal("refresh mutated config before the candidate was applied")
	}
	if err := config.ApplyEndpointResolution(candidates[0]); err != nil {
		t.Fatal(err)
	}
	if config.Peers[0].Endpoint != "203.0.113.10:51820" {
		t.Fatalf("applied endpoint = %q", config.Peers[0].Endpoint)
	}
}
