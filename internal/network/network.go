// Package network manages the host-side networking for Looking Glass environments:
// the bridge, the egress-isolation nftables ruleset, NAT/masquerade, and the UFW
// forward allow (UFW's FORWARD policy is DROP and a separate-table accept does not
// bypass it). All operations are idempotent.
package network

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
)

// Default values used when a spec omits them.
const (
	DefaultBridge     = "lgbr0"
	DefaultBridgeCIDR = "10.89.0.1/24"
	DefaultSubnet     = "10.89.0.0/24"
)

func run(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("%s %v: %w\n%s", name, args, err, out)
	}
	return string(out), nil
}

// EnsureBridge creates the host bridge (idempotent) and brings it up with cidr.
func EnsureBridge(name, cidr string) error {
	_, _ = run("ip", "link", "add", name, "type", "bridge")
	_, _ = run("ip", "addr", "add", cidr, "dev", name) // ignore if already present
	if _, err := run("ip", "link", "set", name, "up"); err != nil {
		return err
	}
	return nil
}

// FilterConfig renders the isolation nftables ruleset for a given env subnet.
// Key lessons from the PoC:
//   - guest transit packets are delivered locally by the bridge, so they hit the
//     FORWARD hook (not INPUT); scope the INPUT drop to host-destined traffic only.
//   - host default route is via nordlynx, so masquerade must cover oifname != bridge.
//   - a separate-table accept does NOT bypass UFW's DROP FORWARD; allow in ufw-user-forward.
//
// Hardening (NEW MODEL, redefinition-audit §J/N6):
//   - DNS to private/LAN ranges is dropped (no plaintext DNS leak to the router/ISP).
//   - IPv6 egress to non-tunnel destinations is dropped (fail-closed on v6).
//   - guest→guest L3 traffic on the same subnet is dropped (cross-instance isolation;
//     L2 isolation additionally needs bridge-nf/ebtables, noted in docs).
func FilterConfig(subnet string, blockRanges []string) string {
	set := strings.Join(blockRanges, ", ")
	v6 := strings.Join(DefaultBlockRangesV6(), ", ")
	guestV6 := DefaultGuestV6Subnet
	return fmt.Sprintf(`table inet lookingglass {
    set lg_block_ranges {
        type ipv4_addr
        flags constant, interval
        elements = { %s }
    }
    set lg_block_ranges6 {
        type ipv6_addr
        flags constant, interval
        elements = { %s }
    }
    chain forward {
        type filter hook forward priority -10; policy accept;
        ct state established,related accept
        ip saddr %[3]s ip daddr %[3]s drop
        ip6 saddr %[4]s ip6 daddr %[4]s drop
        ip saddr %[3]s ip daddr @lg_block_ranges drop
        ip saddr %[3]s meta l4proto udp th dport 53 ip daddr @lg_block_ranges drop
        ip saddr %[3]s meta l4proto tcp th dport 53 ip daddr @lg_block_ranges drop
        ip6 saddr %[4]s ip6 daddr @lg_block_ranges6 drop
        ip saddr %[3]s accept
    }
    chain input {
        type filter hook input priority -10; policy accept;
        ip saddr %[3]s drop
    }
}
table ip lg_nat {
    chain lgpostrouting {
        type nat hook postrouting priority srcnat; policy accept;
        ip saddr %[3]s oifname != "lgbr0" masquerade
    }
}
`, set, v6, subnet, guestV6)
}

// DefaultBlockRangesV6 are the IPv6 ranges an env must never reach (fail-closed v6).
func DefaultBlockRangesV6() []string {
	return []string{"::1/128", "fe80::/10", "fc00::/7", "fec0::/10"}
}

// ApplyFilter loads the isolation ruleset (deletes then reloads for idempotency).
//
// The ruleset lives in GLOBAL host nftables tables (inet lookingglass / ip lg_nat)
// shared by every environment. When multiple Prompt VMs boot concurrently (each as
// its own `lg` process), two processes can run ApplyFilter at the same instant: one
// deletes/recreates the shared table while the other is mid-`nft -f`, failing with
// "Device or resource busy" (observed on vm53 → QUARANTINED / failed boot). We
// therefore serialize the WHOLE delete+load cycle with an exclusive flock on a
// host-wide lock file. Placed here (not in each backend) because BOTH nspawn and
// qemu call ApplyFilter, so a single lock covers every backend's boot path.
func ApplyFilter(subnet string, blockRanges []string) error {
	lock, err := os.OpenFile(nftLockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return fmt.Errorf("open nft lock: %w", err)
	}
	defer lock.Close()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		return fmt.Errorf("nft lock flock: %w", err)
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)

	cfg := FilterConfig(subnet, blockRanges)
	f, err := os.CreateTemp("", "lg-nft-*.conf")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err := f.WriteString(cfg); err != nil {
		return err
	}
	f.Close()
	_, _ = run("nft", "delete", "table", "inet", "lookingglass")
	_, _ = run("nft", "delete", "table", "ip", "lg_nat")
	if _, err := run("nft", "-f", f.Name()); err != nil {
		return err
	}
	return nil
}

// nftLockPath serializes ApplyFilter across concurrent lg processes (shared host
// nftables tables, so the delete+load cycle must be an indivisible critical section).
const nftLockPath = "/var/lock/lg-nft.lock"

// AllowForward inserts a UFW user-forward allow for the env subnet (UFW FORWARD
// policy is DROP). Idempotent.
func AllowForward(subnet string) error {
	out, _ := run("nft", "list", "chain", "ip", "filter", "ufw-user-forward")
	if strings.Contains(out, subnet) {
		return nil
	}
	_, err := run("nft", "insert", "rule", "ip", "filter", "ufw-user-forward", "ip", "saddr", subnet, "accept")
	return err
}

// DefaultBlockRanges are the private/LAN ranges an env must never reach.
func DefaultBlockRanges() []string {
	return []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16"}
}

// DefaultGuestV6Subnet is the ULA subnet used to identify guest-origin IPv6 traffic
// for the fail-closed IPv6 rules. Guests are not assigned IPv6 by default (no
// per-env tunnel), so these rules are inert unless a VPN provisions a v6 address;
// the in-guest kill-switch enforces v6 fail-closed when a tunnel is up. It MUST be
// an IPv6 prefix — using the IPv4 guest subnet here makes `nft -f` reject the ruleset.
const DefaultGuestV6Subnet = "fd89:0:0:0::/64"
