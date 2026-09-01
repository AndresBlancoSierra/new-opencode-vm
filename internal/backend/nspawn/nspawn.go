// Package nspawn implements backend.EnvironmentBackend using systemd-nspawn. It is
// the Phase-2/3 dev backend; the production backend will be QEMU/KVM (same
// network/fs/kill-switch model, so this code validates the abstraction).
package nspawn

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"new-opencode-vm/internal/backend"
	"new-opencode-vm/internal/limits"
	"new-opencode-vm/internal/network"
	"new-opencode-vm/internal/vpn"
)

// NspawnBackend launches environments with systemd-nspawn on a shared host bridge.
type NspawnBackend struct{}

// New returns a ready nspawn backend.
func New() *NspawnBackend { return &NspawnBackend{} }

// Create prepares host networking for the environment (bridge, filter, NAT, UFW allow).
func (b *NspawnBackend) Create(ctx context.Context, spec backend.EnvSpec) error {
	if spec.Bridge == "" {
		spec.Bridge = "lgbr0"
	}
	if spec.Subnet == "" {
		spec.Subnet = "10.89.0.0/24"
	}
	if err := network.EnsureBridge(spec.Bridge, bridgeCIDR(spec)); err != nil {
		return err
	}
	if err := network.ApplyFilter(spec.Subnet, network.DefaultBlockRanges()); err != nil {
		return err
	}
	if err := network.AllowForward(spec.Subnet); err != nil {
		return err
	}
	return nil
}

// Start brings up the environment: host networking + nspawn guest with in-guest
// network setup (and optional per-env VPN + kill-switch), resource limits, secret
// bind-mounts, and an optional OpenCode binary bind-mount. The guest runs
// `sleep infinity` so it stays up and is manageable via machinectl.
func (b *NspawnBackend) Start(ctx context.Context, spec backend.EnvSpec) error {
	if spec.Rootfs == "" {
		return fmt.Errorf("nspawn: rootfs is required")
	}

	setup := fmt.Sprintf(`
ip addr add %s/24 dev host0 2>/dev/null
ip link set host0 up 2>/dev/null
ip route add default via %s 2>/dev/null
`, spec.IP, spec.Gateway)

	if spec.EnableVPN && spec.WGConfig != "" {
		// Per-env tunnel: DNS must resolve ONLY through the tunnel (Nord DNS), and
		// the hardened kill-switch is armed only after the tunnel is up (so we never
		// silently blackhole a working env).
		setup += fmt.Sprintf(`
mkdir -p /run/secrets
wg-quick up /run/secrets/lgwg0.conf 2>/dev/null && {
  echo 'nameserver 103.86.96.100' > /etc/resolv.conf
  echo 'nameserver 103.86.99.100' >> /etc/resolv.conf
  %s
}
`, vpn.KillSwitchScriptHardened(spec.VPNIface))
	} else {
		// No per-env tunnel: egress leaves via the host NordLynx tunnel, so a public
		// resolver is acceptable (still host-routed, not a LAN leak).
		setup += "echo nameserver 1.1.1.1 > /etc/resolv.conf\n"
	}

	// Stage 5: expose the host node (reachable via the /home/andres broad mount) on
	// the guest PATH so the ask-chatgpt.js bridge (Infinite -> ChatGPT) works inside
	// the VM. Derive the path from the opencode bin (same mise dir); fall back to PATH.
	nodeBin := filepath.Join(filepath.Dir(spec.OpenCodeExtraBin), "node")
	if _, serr := os.Stat(nodeBin); serr != nil {
		if p, perr := exec.LookPath("node"); perr == nil {
			nodeBin = p
		}
	}
	if nodeBin != "" {
		setup += fmt.Sprintf("ln -sf %s /usr/local/bin/node 2>/dev/null\n", nodeBin)
		setup += fmt.Sprintf("ln -sf %s /usr/local/bin/npx 2>/dev/null\n", filepath.Dir(nodeBin)+"/npx")
	}

	args := []string{
		"--machine=" + spec.Name,
		"-D", spec.Rootfs,
		"--network-veth",
		"--network-bridge", spec.Bridge,
		"--capability=CAP_NET_ADMIN,CAP_NET_RAW",
	}
	args = append(args, limits.Args(spec)...)

	for _, p := range spec.Projects {
		if _, err := os.Stat(p.HostPath); err != nil {
			fmt.Fprintf(os.Stderr, "warn: project mount source %q not found; skipping\n", p.HostPath)
			continue
		}
		if p.ReadOnly {
			args = append(args, "--bind-ro="+p.HostPath+":"+p.GuestPath)
		} else {
			args = append(args, "--bind="+p.HostPath+":"+p.GuestPath)
		}
	}
	if spec.SecretsDir != "" {
		args = append(args, "--bind-ro="+spec.SecretsDir+":/run/secrets")
	}
	if spec.OpenCode && spec.OpenCodeExtraBin != "" {
		// Bind the whole node install prefix (bin/ + lib/node_modules) so the
		// opencode Node app resolves its modules inside the guest. Binding only the
		// opencode symlink would leave its relative ../lib/node_modules target
		// dangling and opencode could not execute. Fall back to the single-binary
		// bind only if the prefix is unavailable.
		prefix := spec.OpenCodePrefix
		if prefix == "" {
			prefix = filepath.Dir(filepath.Dir(spec.OpenCodeExtraBin))
		}
		if _, err := os.Stat(prefix); err == nil {
			args = append(args, "--bind-ro="+prefix+":/opt/opencode")
			setup += "ln -sf /opt/opencode/bin/opencode /usr/local/bin/opencode 2>/dev/null\n"
			setup += "ln -sf /opt/opencode/bin/node /usr/local/bin/node 2>/dev/null\n"
			setup += "ln -sf /opt/opencode/bin/npx /usr/local/bin/npx 2>/dev/null\n"
		} else if _, err := os.Stat(spec.OpenCodeExtraBin); err == nil {
			args = append(args, "--bind-ro="+spec.OpenCodeExtraBin+":/usr/local/bin/opencode")
		} else {
			fmt.Fprintf(os.Stderr, "warn: opencode prefix %q not found; skipping bind-mount\n", prefix)
		}
	}

	args = append(args, "--", "/bin/sh", "-c", setup+"\nexec sleep infinity")

	cmd := exec.CommandContext(ctx, "systemd-nspawn", args...)
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("nspawn start: %w", err)
	}
	go func() { _ = cmd.Wait() }() // reap; guest keeps running under machined
	return nil
}

// Stop terminates the machine. The guest runs a sleep-based PID1 (no systemd
// init), so `poweroff` is ignored; use `terminate` (host-side kill) instead.
func (b *NspawnBackend) Stop(ctx context.Context, name string) error {
	out, err := exec.Command("machinectl", "terminate", name).CombinedOutput()
	if err != nil && !strings.Contains(string(out), "No such") {
		_, _ = exec.Command("machinectl", "kill", name).CombinedOutput()
	}
	return nil
}

// leaderPID returns the host PID of the environment's init (PID1), discovered via
// machinectl status. nspawn registers the container with machined even when the
// guest runs a non-systemd init (e.g. Alpine), so we use nsenter against this PID
// for shell/exec instead of `machinectl shell` (which needs a systemd D-Bus).
func leaderPID(name string) (int, error) {
	out, err := exec.Command("machinectl", "status", name).CombinedOutput()
	if err != nil {
		return 0, fmt.Errorf("machinectl status %s: %w", name, err)
	}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Leader:") {
			f := strings.Fields(line)
			if len(f) >= 2 {
				if pid, err := strconv.Atoi(f[1]); err == nil {
					return pid, nil
				}
			}
		}
	}
	return 0, fmt.Errorf("leader pid not found for %s", name)
}

// nsenterArgs builds the nsenter invocation that enters the guest's namespaces.
func nsenterArgs(pid int) []string {
	return []string{"-t", strconv.Itoa(pid), "-m", "-u", "-i", "-n", "-p", "--"}
}

// guestEnv ensures the entered shell can find the guest's busybox/coreutils
// (Alpine keeps them in /bin, which is absent from the host-inherited PATH).
func guestEnv() []string {
	env := os.Environ()
	out := make([]string, 0, len(env)+1)
	for _, e := range env {
		if strings.HasPrefix(e, "PATH=") {
			continue
		}
		out = append(out, e)
	}
	out = append(out, "PATH=/usr/local/sbin:/usr/local/bin:/usr/bin:/usr/sbin:/sbin:/bin")
	return out
}

// Shell opens an interactive shell into the running machine via nsenter.
func (b *NspawnBackend) Shell(ctx context.Context, name string) error {
	pid, err := leaderPID(name)
	if err != nil {
		return err
	}
	args := append(nsenterArgs(pid), "/bin/sh")
	cmd := exec.CommandContext(ctx, "nsenter", args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = guestEnv()
	return cmd.Run()
}

// Exec runs a command inside the environment non-interactively.
func (b *NspawnBackend) Exec(ctx context.Context, name, cmdline string) (string, error) {
	pid, err := leaderPID(name)
	if err != nil {
		return "", err
	}
	args := append(nsenterArgs(pid), "/bin/sh", "-c", cmdline)
	cmd := exec.CommandContext(ctx, "nsenter", args...)
	cmd.Env = guestEnv()
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("exec in %s: %w\n%s", name, err, out)
	}
	return string(out), nil
}

// ShellCmd runs a command inside the environment interactively (stdio attached).
func (b *NspawnBackend) ShellCmd(ctx context.Context, name, cmdline string) error {
	pid, err := leaderPID(name)
	if err != nil {
		return err
	}
	args := append(nsenterArgs(pid), "/bin/sh", "-c", cmdline)
	cmd := exec.CommandContext(ctx, "nsenter", args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = guestEnv()
	return cmd.Run()
}

// Status reports whether the machine is running.
func (b *NspawnBackend) Status(ctx context.Context, name string) (backend.EnvStatus, error) {
	// Bound machinectl: a hung D-Bus lookup must never stall the supervisor loop.
	cctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	out, _ := exec.CommandContext(cctx, "machinectl", "status", name).CombinedOutput()
	state := "unknown"
	if strings.Contains(string(out), "running") {
		state = "running"
	} else if strings.Contains(string(out), "No such") {
		state = "stopped"
	}
	return backend.EnvStatus{Name: name, State: state}, nil
}

// Destroy terminates the machine (nspawn has no extra host artifacts to clean).
func (b *NspawnBackend) Destroy(ctx context.Context, name string) error {
	return b.Stop(ctx, name)
}

// List returns the names of all nspawn machines currently registered with
// machined. Used by lifecycle reconcile to detect orphans and crashed envs. It is
// invoked only from the privileged lg/sudo boundary, never interactively.
func (b *NspawnBackend) List(ctx context.Context) ([]string, error) {
	cctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	out, err := exec.CommandContext(cctx, "machinectl", "list", "--no-legend").CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("machinectl list: %w", err)
	}
	names := []string{}
	for _, line := range strings.Split(string(out), "\n") {
		f := strings.Fields(line)
		// Skip the trailing "N machines listed." summary line; a real machine row
		// has the name in column 0 and its class ("container"/"vm") in column 1.
		if len(f) >= 2 && (f[1] == "container" || f[1] == "vm") {
			names = append(names, f[0])
		}
	}
	return names, nil
}

// Snapshot is not supported by the nspawn dev backend.
func (b *NspawnBackend) Snapshot(ctx context.Context, name string) error {
	return fmt.Errorf("nspawn backend does not support snapshots")
}

// Reset is not supported by the nspawn dev backend.
func (b *NspawnBackend) Reset(ctx context.Context, name string) error {
	return fmt.Errorf("nspawn backend does not support reset")
}

// ensureBridge/create/allowForward delegate to the network package.

func bridgeCIDR(spec backend.EnvSpec) string {
	parts := strings.Split(spec.Gateway, ".")
	if len(parts) != 4 {
		return "10.89.0.1/24"
	}
	return spec.Gateway + "/24"
}
