/* SPDX-License-Identifier: MIT */

package clientcfg

import (
	"net"
	"net/netip"
	"testing"
)

func TestRefreshRoutingDomains(t *testing.T) {
	resolver := &fakeEndpointResolver{ipRecords: map[string][]net.IP{
		"ip|proxy.example.com": {net.ParseIP("203.0.113.20"), net.ParseIP("2001:db8::20")},
	}}
	config := &Config{Routing: Routing{DomainResolutions: []DomainResolution{{
		Domain: "proxy.example.com", Addresses: []netip.Addr{netip.MustParseAddr("203.0.113.10")},
	}}}}
	candidates, errs := config.refreshRoutingDomains(resolver)
	if len(errs) != 0 || len(candidates) != 1 {
		t.Fatalf("candidates=%#v errors=%v", candidates, errs)
	}
	if got := candidates[0].Addresses; len(got) != 2 || got[0].String() != "203.0.113.20" || got[1].String() != "2001:db8::20" {
		t.Fatalf("resolved addresses = %v", got)
	}
	if err := config.ApplyRoutingDomainResolution(candidates[0]); err != nil {
		t.Fatal(err)
	}
	if len(config.RoutingBypassPrefixes()) != 2 {
		t.Fatalf("bypass prefixes = %v", config.RoutingBypassPrefixes())
	}
}

func TestRefreshRoutingDomainFailureKeepsOldState(t *testing.T) {
	config := &Config{Routing: Routing{DomainResolutions: []DomainResolution{{
		Domain: "proxy.example.com", Addresses: []netip.Addr{netip.MustParseAddr("203.0.113.10")},
	}}}}
	candidates, errs := config.refreshRoutingDomains(&fakeEndpointResolver{})
	if len(candidates) != 0 || len(errs) != 1 {
		t.Fatalf("candidates=%#v errors=%v", candidates, errs)
	}
	if got := config.Routing.DomainResolutions[0].Addresses[0].String(); got != "203.0.113.10" {
		t.Fatalf("old routing state changed to %s", got)
	}
}
