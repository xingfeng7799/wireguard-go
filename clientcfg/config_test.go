/* SPDX-License-Identifier: MIT */

package clientcfg

import (
	"encoding/base64"
	"strings"
	"testing"
)

func testKey(value byte) string {
	return base64.StdEncoding.EncodeToString([]byte(strings.Repeat(string([]byte{value}), 32)))
}

func TestParseAndUAPI(t *testing.T) {
	privateKey := testKey(1)
	publicKey := testKey(2)
	presharedKey := testKey(3)
	input := `[Interface]
PrivateKey = ` + privateKey + `
Address = 10.0.6.3/32, 2002::3/64
DNS = 192.168.0.1
MTU = 1420

[Peer]
PublicKey = ` + publicKey + `
PresharedKey = ` + presharedKey + `
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = 192.0.2.10:23456
PersistentKeepalive = 25
`
	config, err := Parse(strings.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	if len(config.Interface.Addresses) != 2 || len(config.Peers) != 1 {
		t.Fatalf("unexpected parsed config: %#v", config)
	}
	if err := config.ResolveEndpoints(); err != nil {
		t.Fatal(err)
	}
	uapi := config.UAPI()
	for _, expected := range []string{
		"private_key=0101010101010101010101010101010101010101010101010101010101010101",
		"replace_peers=true",
		"public_key=0202020202020202020202020202020202020202020202020202020202020202",
		"preshared_key=0303030303030303030303030303030303030303030303030303030303030303",
		"endpoint=192.0.2.10:23456",
		"persistent_keepalive_interval=25",
		"allowed_ip=0.0.0.0/0",
		"allowed_ip=::/0",
	} {
		if !strings.Contains(uapi, expected+"\n") {
			t.Errorf("UAPI output does not contain %q:\n%s", expected, uapi)
		}
	}
}

func TestRejectsUnsupportedQuickSetting(t *testing.T) {
	input := `[Interface]
PrivateKey = ` + testKey(1) + `
Address = 10.0.0.2/32
PostUp = echo unsafe

[Peer]
PublicKey = ` + testKey(2) + `
AllowedIPs = 0.0.0.0/0
`
	_, err := Parse(strings.NewReader(input))
	if err == nil || !strings.Contains(err.Error(), "not supported") {
		t.Fatalf("expected unsupported setting error, got %v", err)
	}
}

func TestRejectsInvalidKey(t *testing.T) {
	input := `[Interface]
PrivateKey = too-short
Address = 10.0.0.2/32
`
	_, err := Parse(strings.NewReader(input))
	if err == nil || !strings.Contains(err.Error(), "PrivateKey") {
		t.Fatalf("expected private key error, got %v", err)
	}
}
