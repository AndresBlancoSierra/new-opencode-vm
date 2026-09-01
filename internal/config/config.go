// Package config defines the Looking Glass configuration model: global defaults
// plus per-environment overrides used by `lg new`. Config is stored as JSON so the
// daemon has no third-party dependencies and works fully offline.
package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"new-opencode-vm/internal/backend"
)

// ParseDuration parses a Go duration string (e.g. "30m", "1h").
func ParseDuration(s string) (time.Duration, error) {
	return time.ParseDuration(s)
}

func parseDuration(s string) (time.Duration, error) { return time.ParseDuration(s) }

// Default paths.
const (
	DefaultConfigPath = "~/.config/lookingglass/config.json"
	DefaultStatePath  = "~/.local/state/lookingglass/state.json"
)

// Config is the global Looking Glass configuration.
type Config struct {
	Bridge      string `json:"bridge"`
	Gateway     string `json:"gateway"`
	Subnet      string `json:"subnet"`
	RootfsCache string `json:"rootfs_cache"`
	BaseRootfs  string `json:"base_rootfs"`
	OpenCodeBin string `json:"opencode_bin"`
	SecretsFile string `json:"secrets_file"`
	// NotifyUser is the desktop user whose audio session receives the
	// notification sound. Empty = auto-detect from the workspace path owner.
	NotifyUser      string `json:"notify_user"`
	DefaultCountry  string `json:"default_country"`
	DefaultCPUQuota int    `json:"default_cpu_quota"` // percent
	DefaultMemMaxMB int    `json:"default_mem_max_mb"`
	DefaultPidsMax  int    `json:"default_pids_max"`
	DefaultTTL      string `json:"default_ttl"` // duration string, "" = none

	// Backend selection: "nspawn" (dev) or "qemu" (production).
	Backend string `json:"backend"`

	// QEMU/KVM production backend.
	QEMUBaseImage string `json:"qemu_base_image"`
	QEMUKernel    string `json:"qemu_kernel"`
	QEMUInitrd    string `json:"qemu_initrd"`
	QEMUImagesDir string `json:"qemu_images_dir"`
	VirtiofsdBin  string `json:"virtiofsd_bin"`
	SSHKeyDir     string `json:"ssh_key_dir"`
	RuntimeDir    string `json:"runtime_dir"`

	// NEW MODEL (redefinition-audit): broad, trusted host access + independent VPN.

	// HostMounts are host paths exposed read-write inside every environment so the
	// in-guest OpenCode operates on the host as if local. Default: home + projects.
	HostMounts []string `json:"host_mounts"`

	// GeoFallback is the deterministic country fallback order after Colombia
	// (great-circle-ish from co). Used by the VPN Identity Allocator.
	GeoFallback []string `json:"geo_fallback"`

	// AllocatorPath persists the instance-ID counter; ReservationPath persists the
	// VPN server reservation store.
	AllocatorPath   string `json:"allocator_path"`
	ReservationPath string `json:"reservation_path"`

	// VPNMeasureURLs are the endpoints used (from inside the guest) to measure the
	// effective public IPv4/IPv6 identity. Tried in order.
	VPNMeasureURLs []string `json:"vpn_measure_urls"`

	// Workspace is the OpenCode workspace presented inside the environment (a path
	// within the broad host mount). Default: ~/Proyects.
	Workspace string `json:"workspace"`
}

// Environment is a per-environment definition (used by `lg new` / supervisor).
type Environment struct {
	Name     string                 `json:"name"`
	Country  string                 `json:"country"`
	Rootfs   string                 `json:"rootfs"`
	CPUQuota int                    `json:"cpu_quota"`
	MemMaxMB int                    `json:"mem_max_mb"`
	PidsMax  int                    `json:"pids_max"`
	Projects []backend.ProjectMount `json:"projects"`
	VPN      bool                   `json:"vpn"`
	OpenCode bool                   `json:"opencode"`
	TTL      string                 `json:"ttl"`
}

// Default returns a Config populated with sensible defaults for this host.
func Default() *Config {
	home, _ := os.UserHomeDir()
	return &Config{
		Bridge:          "lgbr0",
		Gateway:         "10.89.0.1",
		Subnet:          "10.89.0.0/24",
		RootfsCache:     filepath.Join(home, ".cache", "lookingglass", "rootfs"),
		BaseRootfs:      "/home/andres/Proyects/lookingglass-poc/env1",
		OpenCodeBin:     "/usr/bin/opencode",
		SecretsFile:     filepath.Join(home, ".config", "lookingglass", "secrets.json"),
		DefaultCountry:  "de",
		DefaultCPUQuota: 50,
		DefaultMemMaxMB: 1024,
		DefaultPidsMax:  512,
		DefaultTTL:      "",
		Backend:         "nspawn",
		QEMUBaseImage:   "/var/lib/lookingglass/images/base.qcow2",
		QEMUKernel:      "/var/lib/lookingglass/images/base.vmlinuz",
		QEMUInitrd:      "/var/lib/lookingglass/images/base.initrd",
		QEMUImagesDir:   "/var/lib/lookingglass/images",
		VirtiofsdBin:    "/usr/lib/virtiofsd",
		SSHKeyDir:       "/var/lib/lookingglass/keys",
		RuntimeDir:      "/var/lib/lookingglass/runtime",
		// NEW MODEL defaults
		HostMounts:      []string{"/home/andres", "/home/andres/Proyects"},
		GeoFallback:     []string{"ec", "pe", "pa", "ve", "br", "cr", "mx"},
		AllocatorPath:   filepath.Join(home, ".local", "state", "lookingglass", "instances"),
		ReservationPath: filepath.Join(home, ".local", "state", "lookingglass", "reservations.json"),
		VPNMeasureURLs:  []string{"https://api.ipify.org", "https://ifconfig.me/ip"},
		Workspace:       "/home/andres/Proyects",
	}
}

// Load reads a Config from path, falling back to Default() when the file is absent.
func Load(path string) (*Config, error) {
	p := expand(path)
	if _, err := os.Stat(p); os.IsNotExist(err) {
		return Default(), nil
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return nil, fmt.Errorf("read config %s: %w", p, err)
	}
	c := Default()
	if err := json.Unmarshal(b, c); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", p, err)
	}
	return c, nil
}

// Save writes the Config as pretty JSON.
func (c *Config) Save(path string) error {
	p := expand(path)
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(p, b, 0o600)
}

// ExpandEnv merges an Environment onto the global Config to produce a concrete
// backend.EnvSpec. name is required; country defaults to Config.DefaultCountry.
func (c *Config) ExpandEnv(e Environment) (backend.EnvSpec, error) {
	if e.Name == "" {
		return backend.EnvSpec{}, fmt.Errorf("environment name is required")
	}
	country := e.Country
	if country == "" {
		country = c.DefaultCountry
	}
	spec := backend.EnvSpec{
		Name:             e.Name,
		Rootfs:           e.Rootfs,
		Bridge:           c.Bridge,
		Gateway:          c.Gateway,
		Subnet:           c.Subnet,
		Projects:         e.Projects,
		CPUQuota:         orDefault(e.CPUQuota, c.DefaultCPUQuota),
		MemMaxMB:         orDefault(e.MemMaxMB, c.DefaultMemMaxMB),
		PidsMax:          orDefault(e.PidsMax, c.DefaultPidsMax),
		EnableVPN:        e.VPN,
		VPNCountry:       country,
		VPNIface:         "lgwg0",
		EnableKillSwitch: true,
		OpenCode:         e.OpenCode,
		OpenCodeProject:  firstProjectGuest(e.Projects),
		OpenCodeExtraBin: c.OpenCodeBin,
		OpenCodePrefix:   openCodePrefix(c.OpenCodeBin),
	}
	if e.TTL != "" {
		if _, err := parseDuration(e.TTL); err != nil {
			return spec, fmt.Errorf("invalid ttl %q: %w", e.TTL, err)
		}
	}
	return spec, nil
}

func firstProjectGuest(p []backend.ProjectMount) string {
	if len(p) > 0 {
		return p[0].GuestPath
	}
	return ""
}

// openCodePrefix derives the node install prefix (the directory containing bin/
// and lib/) from the opencode binary path. For a mise layout like
// .../node/latest/bin/opencode the prefix is .../node/latest. This lets the
// backend bind the whole prefix so the opencode Node app resolves its
// node_modules inside the guest (binding only the opencode symlink leaves its
// relative ../lib/node_modules target dangling).
func openCodePrefix(bin string) string {
	if bin == "" {
		return ""
	}
	return filepath.Dir(filepath.Dir(expand(bin)))
}

// BroadMounts returns the host paths exposed read-write inside every environment
// under the NEW model (trusted broad host access). Each host path is mounted at the
// same absolute path inside the guest so OpenCode behaves like it does on the host.
func (c *Config) BroadMounts() []backend.ProjectMount {
	paths := c.HostMounts
	if len(paths) == 0 {
		paths = []string{"/home/andres", "/home/andres/Proyects"}
	}
	out := make([]backend.ProjectMount, 0, len(paths))
	for _, p := range paths {
		exp := expand(p)
		out = append(out, backend.ProjectMount{HostPath: exp, GuestPath: exp, ReadOnly: false})
	}
	return out
}

// IPForInstance derives a deterministic, unique bridge-subnet IP from the persistent
// instance ID (gateway + 1+id, wrapping within the /24). Unlike the old len(state)
// heuristic this never collides for distinct IDs.
func (c *Config) IPForInstance(id int) string {
	prefix := "10.89.0"
	if parts := strings.Split(c.Gateway, "."); len(parts) == 4 {
		prefix = strings.Join(parts[:3], ".")
	}
	host := 1 + (id % 253)
	return fmt.Sprintf("%s.%d", prefix, host)
}

// WorkspacePath returns the expanded OpenCode workspace path.
func (c *Config) WorkspacePath() string {
	return expand(c.Workspace)
}

func orDefault(v, def int) int {
	if v == 0 {
		return def
	}
	return v
}

func expand(p string) string {
	if len(p) > 0 && p[0] == '~' {
		home := os.Getenv("HOME")
		if home == "" {
			home, _ = os.UserHomeDir()
		}
		return filepath.Join(home, p[1:])
	}
	return p
}

// ExpandPath expands a leading ~ to the user's home directory.
func ExpandPath(p string) string { return expand(p) }
