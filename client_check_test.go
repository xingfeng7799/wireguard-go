/* SPDX-License-Identifier: MIT */

package main

import (
	"net/netip"
	"strings"
	"testing"

	"golang.zx2c4.com/wireguard/clientcfg"
)

func TestAnalyzeClientConfigWarnsAboutProxyConflicts(t *testing.T) {
	config := &clientcfg.Config{
		Interface: clientcfg.Interface{DNS: []netip.Addr{netip.MustParseAddr("192.168.0.1")}},
		Peers: []clientcfg.Peer{{
			Endpoint:   "203.0.113.1:51820",
			AllowedIPs: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0")},
		}},
	}
	report := analyzeClientConfig(config)
	if !report.IPv4FullTunnel || !report.IPv6FullTunnel {
		t.Fatalf("full tunnel detection failed: %#v", report)
	}
	if len(report.Warnings) != 2 {
		t.Fatalf("warnings = %#v", report.Warnings)
	}
	if !strings.Contains(report.Warnings[0], "proxy") || !strings.Contains(report.Warnings[1], "DNS") {
		t.Fatalf("unexpected warnings: %#v", report.Warnings)
	}
}

func TestAnalyzeClientConfigSplitTunnelHasNoWarning(t *testing.T) {
	config := &clientcfg.Config{Peers: []clientcfg.Peer{{
		Endpoint:   "203.0.113.1:51820",
		AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")},
	}}}
	report := analyzeClientConfig(config)
	if report.IPv4FullTunnel || report.IPv6FullTunnel || len(report.Warnings) != 0 {
		t.Fatalf("unexpected report: %#v", report)
	}
}

func TestAnalyzeClientConfigWarnsAboutPassivePeer(t *testing.T) {
	report := analyzeClientConfig(&clientcfg.Config{Peers: []clientcfg.Peer{{}}})
	if len(report.Warnings) != 1 || !strings.Contains(report.Warnings[0], "no Endpoint") {
		t.Fatalf("warnings = %#v", report.Warnings)
	}
}
