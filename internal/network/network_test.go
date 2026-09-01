package network

import (
	"strings"
	"testing"
)

func TestFilterConfig(t *testing.T) {
	cfg := FilterConfig("10.89.0.0/24", DefaultBlockRanges())
	for _, want := range []string{
		"table inet lookingglass",
		"set lg_block_ranges",
		"10.0.0.0/8", "192.168.0.0/16",
		"chain forward",
		"chain input",
		"table ip lg_nat",
		"masquerade",
	} {
		if !strings.Contains(cfg, want) {
			t.Fatalf("filter missing %q:\n%s", want, cfg)
		}
	}
	// The IPv6 fail-closed rules must reference an IPv6 prefix, never the IPv4
	// guest subnet (using 10.89.0.0/24 as an `ip6 saddr` makes `nft -f` reject the
	// whole ruleset and breaks `lg new`). Regression guard for the IPv6-source bug.
	if strings.Contains(cfg, "ip6 saddr 10.89.0.0/24") {
		t.Fatalf("IPv6 rule references the IPv4 guest subnet (nft would reject):\n%s", cfg)
	}
	if !strings.Contains(cfg, "ip6 saddr "+DefaultGuestV6Subnet) {
		t.Fatalf("IPv6 rule missing the ULA guest subnet %q:\n%s", DefaultGuestV6Subnet, cfg)
	}
}
