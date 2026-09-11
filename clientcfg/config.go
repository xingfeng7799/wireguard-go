/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

// Package clientcfg parses the common WireGuard configuration file format for
// the standalone client mode.
package clientcfg

import (
	"bufio"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

type Config struct {
	Interface Interface
	Peers     []Peer
}

type Interface struct {
	PrivateKey string
	ListenPort uint16
	Addresses  []netip.Prefix
	DNS        []netip.Addr
	MTU        int
}

type Peer struct {
	PublicKey           string
	PresharedKey        string
	Endpoint            string
	AllowedIPs          []netip.Prefix
	PersistentKeepalive uint16
}

func Parse(r io.Reader) (*Config, error) {
	config := new(Config)
	section := ""
	peerIndex := -1
	interfaceSeen := false
	scanner := bufio.NewScanner(r)
	for lineNumber := 1; scanner.Scan(); lineNumber++ {
		line := strings.TrimSpace(stripComment(scanner.Text()))
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.ToLower(strings.TrimSpace(line[1 : len(line)-1]))
			switch section {
			case "interface":
				if interfaceSeen {
					return nil, fmt.Errorf("line %d: duplicate Interface section", lineNumber)
				}
				interfaceSeen = true
			case "peer":
				config.Peers = append(config.Peers, Peer{})
				peerIndex = len(config.Peers) - 1
			default:
				return nil, fmt.Errorf("line %d: unknown section %q", lineNumber, section)
			}
			continue
		}

		key, value, ok := strings.Cut(line, "=")
		if !ok {
			return nil, fmt.Errorf("line %d: expected key = value", lineNumber)
		}
		key = strings.ToLower(strings.TrimSpace(key))
		value = strings.TrimSpace(value)
		var err error
		switch section {
		case "interface":
			err = parseInterface(&config.Interface, key, value)
		case "peer":
			if peerIndex < 0 {
				err = fmt.Errorf("Peer section is missing")
			} else {
				err = parsePeer(&config.Peers[peerIndex], key, value)
			}
		default:
			err = fmt.Errorf("setting appears before a section")
		}
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", lineNumber, err)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if config.Interface.PrivateKey == "" {
		return nil, fmt.Errorf("Interface.PrivateKey is required")
	}
	if len(config.Interface.Addresses) == 0 {
		return nil, fmt.Errorf("Interface.Address is required in client mode")
	}
	if len(config.Peers) == 0 {
		return nil, fmt.Errorf("at least one Peer section is required")
	}
	for i, peer := range config.Peers {
		if peer.PublicKey == "" {
			return nil, fmt.Errorf("Peer %d: PublicKey is required", i+1)
		}
		if len(peer.AllowedIPs) == 0 {
			return nil, fmt.Errorf("Peer %d: AllowedIPs is required", i+1)
		}
	}
	return config, nil
}

func stripComment(line string) string {
	if index := strings.IndexByte(line, '#'); index >= 0 {
		return line[:index]
	}
	return line
}

func parseInterface(iface *Interface, key, value string) error {
	switch key {
	case "privatekey":
		key, err := keyToHex(value)
		if err != nil {
			return fmt.Errorf("invalid PrivateKey: %w", err)
		}
		iface.PrivateKey = key
	case "listenport":
		port, err := parseUint16(value)
		if err != nil {
			return fmt.Errorf("invalid ListenPort: %w", err)
		}
		iface.ListenPort = port
	case "address":
		prefixes, err := parsePrefixes(value)
		if err != nil {
			return fmt.Errorf("invalid Address: %w", err)
		}
		iface.Addresses = append(iface.Addresses, prefixes...)
	case "dns":
		for _, item := range splitList(value) {
			address, err := netip.ParseAddr(item)
			if err != nil {
				return fmt.Errorf("DNS must be an IP address, got %q", item)
			}
			iface.DNS = append(iface.DNS, address.Unmap())
		}
	case "mtu":
		mtu, err := strconv.Atoi(value)
		if err != nil || mtu < 576 || mtu > 65535 {
			return fmt.Errorf("invalid MTU %q", value)
		}
		iface.MTU = mtu
	case "table", "preup", "postup", "predown", "postdown", "saveconfig":
		return fmt.Errorf("Interface.%s is not supported in native client mode", key)
	default:
		return fmt.Errorf("unknown Interface setting %q", key)
	}
	return nil
}

func parsePeer(peer *Peer, key, value string) error {
	switch key {
	case "publickey":
		key, err := keyToHex(value)
		if err != nil {
			return fmt.Errorf("invalid PublicKey: %w", err)
		}
		peer.PublicKey = key
	case "presharedkey":
		key, err := keyToHex(value)
		if err != nil {
			return fmt.Errorf("invalid PresharedKey: %w", err)
		}
		peer.PresharedKey = key
	case "endpoint":
		if _, _, err := net.SplitHostPort(value); err != nil {
			return fmt.Errorf("invalid Endpoint %q: %w", value, err)
		}
		peer.Endpoint = value
	case "allowedips":
		prefixes, err := parsePrefixes(value)
		if err != nil {
			return fmt.Errorf("invalid AllowedIPs: %w", err)
		}
		peer.AllowedIPs = append(peer.AllowedIPs, prefixes...)
	case "persistentkeepalive":
		seconds, err := parseUint16(value)
		if err != nil {
			return fmt.Errorf("invalid PersistentKeepalive: %w", err)
		}
		peer.PersistentKeepalive = seconds
	default:
		return fmt.Errorf("unknown Peer setting %q", key)
	}
	return nil
}

func parseUint16(value string) (uint16, error) {
	number, err := strconv.ParseUint(value, 10, 16)
	return uint16(number), err
}

func parsePrefixes(value string) ([]netip.Prefix, error) {
	items := splitList(value)
	prefixes := make([]netip.Prefix, 0, len(items))
	for _, item := range items {
		prefix, err := netip.ParsePrefix(item)
		if err != nil {
			return nil, fmt.Errorf("invalid network prefix %q", item)
		}
		prefixes = append(prefixes, prefix)
	}
	return prefixes, nil
}

func splitList(value string) []string {
	parts := strings.Split(value, ",")
	items := parts[:0]
	for _, part := range parts {
		if item := strings.TrimSpace(part); item != "" {
			items = append(items, item)
		}
	}
	return items
}

func keyToHex(value string) (string, error) {
	key, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return "", err
	}
	if len(key) != 32 {
		return "", fmt.Errorf("key has %d bytes instead of 32", len(key))
	}
	return hex.EncodeToString(key), nil
}

func (config *Config) ResolveEndpoints() error {
	for i := range config.Peers {
		peer := &config.Peers[i]
		if peer.Endpoint == "" {
			continue
		}
		address, err := net.ResolveUDPAddr("udp", peer.Endpoint)
		if err != nil {
			return fmt.Errorf("Peer %d: resolve Endpoint %q: %w", i+1, peer.Endpoint, err)
		}
		if address.IP == nil {
			return fmt.Errorf("Peer %d: Endpoint %q resolved without an IP address", i+1, peer.Endpoint)
		}
		peer.Endpoint = net.JoinHostPort(address.IP.String(), strconv.Itoa(address.Port))
	}
	return nil
}

func (config *Config) UAPI() string {
	var output strings.Builder
	fmt.Fprintf(&output, "private_key=%s\n", config.Interface.PrivateKey)
	fmt.Fprintf(&output, "listen_port=%d\n", config.Interface.ListenPort)
	output.WriteString("replace_peers=true\n")
	for _, peer := range config.Peers {
		fmt.Fprintf(&output, "public_key=%s\n", peer.PublicKey)
		if peer.PresharedKey != "" {
			fmt.Fprintf(&output, "preshared_key=%s\n", peer.PresharedKey)
		}
		if peer.Endpoint != "" {
			fmt.Fprintf(&output, "endpoint=%s\n", peer.Endpoint)
		}
		fmt.Fprintf(&output, "persistent_keepalive_interval=%d\n", peer.PersistentKeepalive)
		output.WriteString("replace_allowed_ips=true\n")
		for _, prefix := range peer.AllowedIPs {
			fmt.Fprintf(&output, "allowed_ip=%s\n", prefix)
		}
	}
	output.WriteByte('\n')
	return output.String()
}

func (config *Config) AllowedIPs() []netip.Prefix {
	var prefixes []netip.Prefix
	for _, peer := range config.Peers {
		prefixes = append(prefixes, peer.AllowedIPs...)
	}
	return prefixes
}

func (config *Config) EndpointIPs() []netip.Addr {
	var addresses []netip.Addr
	for _, peer := range config.Peers {
		if peer.Endpoint == "" {
			continue
		}
		address, err := netip.ParseAddrPort(peer.Endpoint)
		if err == nil {
			addresses = append(addresses, address.Addr().Unmap())
		}
	}
	return addresses
}
