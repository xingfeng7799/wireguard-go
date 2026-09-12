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
	"net/netip"
	"strconv"
	"strings"
)

type Config struct {
	Interface Interface
	Peers     []Peer
	IP4P      IP4P
}

type IP4P struct {
	Mode      string
	Provider  string
	APIKey    string
	APISecret string
	ZoneID    string
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
	ip4pSeen := false
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
			case "ip4p":
				if ip4pSeen {
					return nil, fmt.Errorf("line %d: duplicate IP4P section", lineNumber)
				}
				ip4pSeen = true
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
		case "ip4p":
			err = parseIP4P(&config.IP4P, key, value)
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
	if err := config.IP4P.validate(); err != nil {
		return nil, err
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
		if err := validateEndpointSyntax(value); err != nil {
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

func parseIP4P(config *IP4P, key, value string) error {
	switch key {
	case "mode":
		config.Mode = strings.ToLower(value)
	case "provider":
		config.Provider = strings.ToLower(value)
	case "apikey":
		config.APIKey = value
	case "apisecret":
		config.APISecret = value
	case "zoneid":
		config.ZoneID = value
	default:
		return fmt.Errorf("unknown IP4P setting %q", key)
	}
	return nil
}

func (config *IP4P) validate() error {
	if config.Mode != "" && config.Mode != "api" && config.Mode != "lookup_text" {
		return fmt.Errorf("IP4P.Mode must be api or lookup_text, got %q", config.Mode)
	}
	if config.Mode == "api" && config.Provider == "" {
		return fmt.Errorf("IP4P.Provider is required in api mode")
	}
	if config.Mode == "lookup_text" && (config.Provider != "" || config.APIKey != "" || config.APISecret != "" || config.ZoneID != "") {
		return fmt.Errorf("IP4P provider credentials cannot be used in lookup_text mode")
	}
	if config.Provider == "" {
		if config.APIKey != "" || config.APISecret != "" || config.ZoneID != "" {
			return fmt.Errorf("IP4P.Provider is required when API credentials are configured")
		}
		return nil
	}
	switch config.Provider {
	case "cloudflare":
		if config.APIKey == "" || config.ZoneID == "" {
			return fmt.Errorf("IP4P cloudflare requires APIKey and ZoneID")
		}
	case "tencent", "alibaba":
		if config.APIKey == "" || config.APISecret == "" {
			return fmt.Errorf("IP4P %s requires APIKey and APISecret", config.Provider)
		}
	default:
		return fmt.Errorf("unsupported IP4P.Provider %q", config.Provider)
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
