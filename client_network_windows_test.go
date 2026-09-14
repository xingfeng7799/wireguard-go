//go:build windows

package main

import "testing"

func TestParseWindowsIPInterfaceSettings(t *testing.T) {
	interfaces, err := parseWindowsIPInterfaceSettings("IPv4|1500\r\nIPv6|1280\r\n")
	if err != nil {
		t.Fatal(err)
	}
	if len(interfaces) != 2 || interfaces[0].family != "IPv4" || interfaces[0].mtu != 1500 || interfaces[1].family != "IPv6" || interfaces[1].mtu != 1280 {
		t.Fatalf("unexpected interfaces: %#v", interfaces)
	}
}

func TestParseWindowsIPInterfaceSettingsRejectsEmptyMTU(t *testing.T) {
	if _, err := parseWindowsIPInterfaceSettings("IPv4|"); err == nil {
		t.Fatal("expected an empty MTU to be rejected")
	}
}
