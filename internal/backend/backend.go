// Package backend defines the EnvironmentBackend abstraction so multiple
// virtualization backends (nspawn now, QEMU/KVM later) can be swapped without
// changing the daemon/CLI.
package backend

import "context"

// ProjectMount describes a host path exposed to an environment.
type ProjectMount struct {
	HostPath  string
	GuestPath string
	ReadOnly  bool
}

// EnvSpec is the desired configuration of one environment.
type EnvSpec struct {
	Name             string
	Rootfs           string
	VCPUs            int
	MemMB            int
	Bridge           string // host bridge, e.g. lgbr0
	IP               string // container IP, e.g. 10.89.0.2
	Gateway          string // bridge IP, e.g. 10.89.0.1
	Subnet           string // e.g. 10.89.0.0/24
	Projects         []ProjectMount
	EnableKillSwitch bool

	// Resource limits (nspawn maps these to cgroup knobs).
	CPUQuota int // percent of one CPU, e.g. 50 == 0.5 vCPU; 0 = unset
	MemMaxMB int // hard memory limit; 0 = unset
	PidsMax  int // max processes; 0 = unset

	// VCPUs (declared above) is the QEMU/KVM allocation; ignored by nspawn.

	// Per-environment VPN (independent network identity).
	EnableVPN  bool
	VPNCountry string // ISO country code, e.g. "de"
	VPNIface   string // guest wireguard iface name, e.g. lgwg0

	// Runtime secrets injected into the guest (never persisted to rootfs).
	Secrets []string // secret keys to inject from the store

	// OpenCode agent launch inside the guest.
	OpenCode         bool
	OpenCodeProject  string // guest path the agent may operate on, e.g. /mnt/project
	OpenCodeExtraBin string // host path of the opencode binary to bind into the guest
	OpenCodePrefix   string // host path of the node install prefix (bin+lib) so the opencode Node app resolves its node_modules in-guest

	// VPN material prepared by the CLI (not persisted to rootfs).
	WGConfig   string // rendered WireGuard [Interface]/[Peer] config
	SecretsDir string // host dir (per-env) bind-mounted read-only into guest /run/secrets
}

// EnvStatus is a snapshot of an environment's state.
type EnvStatus struct {
	Name  string
	State string // running | stopped | unknown
}

// EnvironmentBackend abstracts a virtualization backend.
type EnvironmentBackend interface {
	Create(ctx context.Context, spec EnvSpec) error
	Start(ctx context.Context, spec EnvSpec) error
	Stop(ctx context.Context, name string) error
	Shell(ctx context.Context, name string) error
	// Exec runs a command inside the environment non-interactively and returns its
	// combined output. Used by OpenCode launch and security verification.
	Exec(ctx context.Context, name, cmdline string) (string, error)
	// ShellCmd runs a command inside the environment interactively (stdio attached),
	// e.g. to launch the OpenCode agent with a TTY.
	ShellCmd(ctx context.Context, name, cmdline string) error
	Status(ctx context.Context, name string) (EnvStatus, error)

	// List returns the names of all environments currently running on the host
	// under this backend (used by lifecycle reconcile to detect orphans/crashes).
	List(ctx context.Context) ([]string, error)

	// Destroy removes all host-side artifacts for an environment (overlay disk,
	// TAP, virtiofs sockets, SSH keys, runtime dir). Implies Stop.
	Destroy(ctx context.Context, name string) error
	// Snapshot captures the current guest disk state (offline; stop first).
	Snapshot(ctx context.Context, name string) error
	// Reset discards guest changes and returns the environment to its base image
	// (disposable-env model). Implies Stop then Start.
	Reset(ctx context.Context, name string) error
}
