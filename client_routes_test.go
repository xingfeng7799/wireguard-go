/* SPDX-License-Identifier: MIT */

package main

import (
	"net/netip"
	"reflect"
	"testing"
)

func TestSplitDefaultRoute(t *testing.T) {
	tests := []struct {
		input string
		want  []netip.Prefix
	}{
		{
			input: "0.0.0.0/0",
			want: []netip.Prefix{
				netip.MustParsePrefix("0.0.0.0/1"),
				netip.MustParsePrefix("128.0.0.0/1"),
			},
		},
		{
			input: "::/0",
			want: []netip.Prefix{
				netip.MustParsePrefix("::/1"),
				netip.MustParsePrefix("8000::/1"),
			},
		},
		{
			input: "10.0.0.0/8",
			want:  []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")},
		},
	}
	for _, test := range tests {
		t.Run(test.input, func(t *testing.T) {
			got := splitDefaultRoute(netip.MustParsePrefix(test.input))
			if !reflect.DeepEqual(got, test.want) {
				t.Fatalf("splitDefaultRoute(%q) = %v, want %v", test.input, got, test.want)
			}
		})
	}
}

func TestPrefixesContain(t *testing.T) {
	prefixes := []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("2001:db8::/32"),
	}
	if !prefixesContain(prefixes, netip.MustParseAddr("10.1.2.3")) {
		t.Fatal("expected IPv4 address to be contained")
	}
	if !prefixesContain(prefixes, netip.MustParseAddr("2001:db8::1")) {
		t.Fatal("expected IPv6 address to be contained")
	}
	if prefixesContain(prefixes, netip.MustParseAddr("192.0.2.1")) {
		t.Fatal("unexpected address containment")
	}
}
