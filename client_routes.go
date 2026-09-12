/* SPDX-License-Identifier: MIT */

package main

import "net/netip"

func prefixesContain(prefixes []netip.Prefix, address netip.Addr) bool {
	for _, prefix := range prefixes {
		if prefix.Contains(address) {
			return true
		}
	}
	return false
}

func prefixesOverlap(prefixes []netip.Prefix, candidate netip.Prefix) bool {
	candidate = candidate.Masked()
	for _, prefix := range prefixes {
		prefix = prefix.Masked()
		if prefix.Addr().BitLen() == candidate.Addr().BitLen() &&
			(prefix.Contains(candidate.Addr()) || candidate.Contains(prefix.Addr())) {
			return true
		}
	}
	return false
}

func splitDefaultRoute(prefix netip.Prefix) []netip.Prefix {
	if prefix.Bits() != 0 {
		return []netip.Prefix{prefix}
	}
	if prefix.Addr().Is4() {
		return []netip.Prefix{
			netip.MustParsePrefix("0.0.0.0/1"),
			netip.MustParsePrefix("128.0.0.0/1"),
		}
	}
	return []netip.Prefix{
		netip.MustParsePrefix("::/1"),
		netip.MustParsePrefix("8000::/1"),
	}
}
