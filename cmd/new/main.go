// Command new spins up an isolated Linux environment (an nspawn VM) with its own
// independent NordVPN Colombia tunnel (measured-unique egress IP) + fail-closed
// kill-switch, boots it, launches a REAL interactive OpenCode session attached to
// the terminal, and on OpenCode exit destroys the VM and releases all resources.
//
// This is a separate, simpler sibling of LookingGlass + Infinite: there is NO
// infinite-loop, NO `opencode run`, NO `--continue`, NO watchdog/supervisor, NO
// daemon, NO Telegram/Brave/Xvfb. Each invocation creates a fresh VM and cleans it
// up when OpenCode exits (zero orphans).
//
// Infrastructure is invisible: you just type `new` and get OpenCode.
package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"new-opencode-vm/internal/allocator"
	"new-opencode-vm/internal/backend"
	"new-opencode-vm/internal/backend/nspawn"
	"new-opencode-vm/internal/config"
	"new-opencode-vm/internal/opencode"
	"new-opencode-vm/internal/secrets"
	"new-opencode-vm/internal/state"
	"new-opencode-vm/internal/vpn"
)

// New-project-specific state lives in its own directory so it never collides with
// the existing LookingGlass state (~/.local/state/lookingglass). The reusable
// config (base rootfs, opencode bin, nordvpn token) is still read from the shared
// ~/.config/lookingglass/config.json + secrets.json.
const (
	statePath      = "~/.local/state/new-opencode-vm/state.json"
	stateDir       = "~/.local/state/new-opencode-vm"
	allocatorFile  = "~/.local/state/new-opencode-vm/instances"
	reservationF   = "~/.local/state/new-opencode-vm/reservations.json"
	rootfsCacheDir = "~/.local/state/new-opencode-vm/rootfs"
)

func main() {
	// ensureRoot() re-execs this binary as root via `sudo <exe> new <original args...>`,
	// prepending "new" (so path-resolved invocations still hit the auto flow). Strip
	// that injected "new"/"up" marker so explicit subcommands (e.g. `new status`)
	// survive elevation to the correct handler.
	args := os.Args[1:]
	if len(args) >= 1 && (args[0] == "new" || args[0] == "up") {
		args = args[1:]
	}
	// Explicit subcommand dispatch precedes argv0 auto-mode: a binary actually named
	// "new"/"neww"/"newlinux" must still honor `new status`, `new up`, etc.
	if len(args) >= 1 {
		switch args[0] {
		case "new", "up":
			ensureRoot()
			newAuto(context.Background())
			return
		case "status":
			ensureRoot()
			statusAuto(context.Background())
			return
		case "help", "-h", "--help":
			usage()
			return
		}
	}
	// argv0 auto-mode: `new` (or `neww`) runs the automatic workflow, argc-free.
	if base := filepath.Base(os.Args[0]); base == "new" || base == "neww" || base == "newlinux" {
		ensureRoot()
		newAuto(context.Background())
		return
	}
	usage()
	os.Exit(1)
}

func usage() {
	fmt.Println("usage:")
	fmt.Println("  new         (no args) create a fresh isolated VM + Colombia VPN + interactive OpenCode,")
	fmt.Println("                      destroy the VM on OpenCode exit")
	fmt.Println("  new status  (read-only) list currently running new-opencode-vm VMs with VPN/kill-switch/egress state")
}

func loadConfig() *config.Config {
	c, err := config.Load(config.DefaultConfigPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "config:", err)
		os.Exit(1)
	}
	// Override coordination/state paths to the new project's own directory
	// (this project is fully separate from LookingGlass state). The rootfs cache
	// MUST also be overridden: reusing LookingGlass's shared cache lets our envN
	// names collide with stale Alpine rootfs dirs left behind by LookingGlass,
	// which silently breaks the fresh-clone guarantee (see README).
	c.AllocatorPath = expand(allocatorFile)
	c.ReservationPath = expand(reservationF)
	c.RootfsCache = expand(rootfsCacheDir)
	return c
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

func vpnClient(c *config.Config) *vpn.Client {
	if sec, err := secrets.Load(c.SecretsFile); err == nil {
		if tok, _ := sec.Get("nordvpn_token"); tok != "" {
			return vpn.NewClient(tok)
		}
	}
	return vpn.NewClient("")
}

// resolvedOpenCodePrefix returns the real (symlink-resolved) node install prefix
// that hosts the opencode binary. The mise `node/latest` directory is a symlink to
// a versioned dir; resolving the PREFIX (not the binary, which nests deeper under
// lib/node_modules) makes the nspawn bind source a concrete directory so
// `/opt/opencode/bin/opencode` resolves inside the guest.
func resolvedOpenCodePrefix(bin string) string {
	exp := config.ExpandPath(bin)
	prefix := filepath.Dir(filepath.Dir(exp))
	if real, err := filepath.EvalSymlinks(prefix); err == nil {
		prefix = real
	}
	return prefix
}

// allocateVPN picks a WireGuard server whose reservation is not held by another
// process and not unsuitable, Colombia first then geo-fallback, and builds the
// per-VM config WITHOUT mutating the host VPN.
func allocateVPN(ctx context.Context, c *config.Config, id int, cli *vpn.Client, store *vpn.ReservationStore) (*vpn.WGConfig, string, string, error) {
	countries := []string{c.DefaultCountry}
	countries = append(countries, c.GeoFallback...)
	if len(countries) == 0 {
		countries = []string{"co"}
	}
	var lastErr error
	for _, country := range countries {
		servers, err := cli.RecommendN(ctx, country, 10)
		if err != nil {
			lastErr = err
			continue
		}
		for _, srv := range servers {
			key := country + ":" + srv.Station
			if store.IsReservedByOther(key, id) {
				continue
			}
			if store.IsUnsuitable(key) {
				continue
			}
			if err := store.Reserve(key, id, 10*time.Minute); err != nil {
				continue
			}
			wg, gerr := vpn.GenerateForServer(ctx, cli, country, srv)
			if gerr != nil {
				_ = store.Release(key)
				lastErr = gerr
				continue
			}
			return wg, country, key, nil
		}
	}
	return nil, "", "", fmt.Errorf("vpn: no available server across %v (last error: %v)", countries, lastErr)
}

// measureIdentity measures the effective public identity from inside the guest.
func measureIdentity(ctx context.Context, b backend.EnvironmentBackend, name string, urls []string) vpn.Identity {
	id := vpn.Identity{}
	for _, ver := range []string{"4", "6"} {
		for _, u := range urls {
			out, err := b.Exec(ctx, name, fmt.Sprintf("curl -%s -s --max-time 12 %s", ver, u))
			if err == nil {
				ip := strings.TrimSpace(out)
				if ip != "" {
					if ver == "4" {
						id.V4 = ip
					} else {
						id.V6 = ip
					}
					break
				}
			}
		}
	}
	return id
}

// ensureRoot re-execs via passwordless sudo when not already root (privileged
// rootfs clone + nspawn/bridge setup require root). If elevation fails, exit
// with error instead of continuing as non-root (which would use the wrong HOME
// and fail on rootfs rsync with permission denied).
func ensureRoot() {
	if os.Getuid() == 0 {
		return
	}
	if os.Getenv("NEWVM_ROOTED") != "" {
		fmt.Fprintln(os.Stderr, "new: NEWVM_ROOTED set but not root — refusing to run as non-root")
		os.Exit(1)
	}
	exe, err := os.Executable()
	if err != nil {
		fmt.Fprintln(os.Stderr, "new: cannot determine executable:", err)
		os.Exit(1)
	}
	// Re-invoke as root, prepending "new" so the elevated process runs the
	// automatic flow regardless of the argv0 the shell used (a path-based /shell-
	// resolved `new` would not match the argv0 auto-mode check and would otherwise
	// fall through to usage()).
	args := []string{"-n", exe, "new"}
	args = append(args, os.Args[1:]...)
	cmd := exec.Command("sudo", args...)
	cmd.Env = append(os.Environ(), "NEWVM_ROOTED=1")
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err == nil {
		os.Exit(0)
	}
	fmt.Fprintln(os.Stderr, "new: failed to elevate to root (sudo -n):", err)
	fmt.Fprintln(os.Stderr, "hint: ensure passwordless sudo for", exe)
	os.Exit(1)
}

// ensureRootfs copies base -> dir if dir does not exist (idempotent).
func ensureRootfs(ctx context.Context, base, dir string) error {
	if base == "" {
		return fmt.Errorf("base_rootfs not configured")
	}
	if _, serr := os.Stat(base); serr != nil {
		return fmt.Errorf("base rootfs not found: %s", base)
	}
	if fi, err := os.Stat(filepath.Join(dir, "etc")); err == nil && fi.IsDir() {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(dir), 0o755); err != nil {
		return err
	}
	excludes := []string{"dev", "proc", "sys", "run", "tmp"}
	args := []string{"-aHAX", "--delete", base + "/", dir + "/"}
	for _, e := range excludes {
		args = append(args, "--exclude=/"+e)
	}
	out, err := exec.CommandContext(ctx, "rsync", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("rsync %s -> %s: %w\n%s", base, dir, err, out)
	}
	_ = os.MkdirAll(filepath.Join(dir, "dev"), 0o755)
	return nil
}

// verifyVMStopped confirms the nspawn machine is no longer running after teardown.
func verifyVMStopped(ctx context.Context, name string) bool {
	cctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	out, _ := exec.CommandContext(cctx, "machinectl", "status", name).CombinedOutput()
	return !strings.Contains(string(out), "running")
}

// newAuto is the primary workflow: create a fresh VM, connect a unique Colombia
// VPN, launch interactive OpenCode, and destroy everything on exit.
func newAuto(ctx context.Context) {
	c := loadConfig()
	st, err := state.New(expand(statePath))
	if err != nil {
		fmt.Fprintln(os.Stderr, "state:", err)
		os.Exit(1)
	}
	// Prune stale state: remove records for machines that are no longer running
	// (e.g. after a crash where teardown did not run). This keeps egress dedup
	// accurate and prevents ghost collisions.
	pruneStaleState(ctx, st)

	// Signal-aware context: Ctrl+C / SIGTERM triggers transactional cleanup.
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	// 1. Allocate a persistent, unique instance ID (#N) under flock.
	alloc := allocator.New(c.AllocatorPath)
	id, err := alloc.Allocate()
	if err != nil {
		fmt.Fprintln(os.Stderr, "allocator:", err)
		os.Exit(1)
	}
	name := fmt.Sprintf("env%d", id)
	fmt.Printf("STARTING environment %s (instance #%d)\n", name, id)

	b := nspawn.New()
	rootfsDir := filepath.Join(c.RootfsCache, name)
	if err := ensureRootfs(ctx, c.BaseRootfs, rootfsDir); err != nil {
		fmt.Fprintln(os.Stderr, "rootfs:", err)
		os.Exit(1)
	}

	spec := backend.EnvSpec{
		Name:             name,
		Rootfs:           rootfsDir,
		Bridge:           c.Bridge,
		Gateway:          c.Gateway,
		Subnet:           c.Subnet,
		Projects:         c.BroadMounts(),
		CPUQuota:         c.DefaultCPUQuota,
		MemMaxMB:         c.DefaultMemMaxMB,
		PidsMax:          c.DefaultPidsMax,
		EnableKillSwitch: true,
		EnableVPN:        true,
		VPNIface:         "lgwg0",
		OpenCode:         true,
		OpenCodeProject:  c.WorkspacePath(),
		OpenCodeExtraBin: c.OpenCodeBin,
		OpenCodePrefix:   resolvedOpenCodePrefix(c.OpenCodeBin),
		IP:               c.IPForInstance(id),
		VCPUs:            2,
	}

	sec, _ := secrets.Load(c.SecretsFile)
	secretsDir := expand(filepath.Join(stateDir, "secrets"))

	// 2 + 3 + 4. Per-environment VPN, measured-unique, coordinated cross-process.
	cli := vpnClient(c)
	store := vpn.NewReservationStore(c.ReservationPath)
	allocated := false
	var country, resKey, egressV4, egressV6 string

	// Deferred teardown: any failure or OpenCode exit destroys the VM and
	// releases all resources (zero orphans). Handles normal exit, VPN failure,
	// and SIGINT/SIGTERM (Ctrl+C) via signal.NotifyContext.
	destroyed := false
	teardown := func(why string) {
		if destroyed {
			return
		}
		destroyed = true
		fmt.Println("  TEARDOWN:", why)
		_ = b.Stop(ctx, name)
		_ = b.Destroy(ctx, name)
		_ = os.RemoveAll(rootfsDir)
		_ = os.RemoveAll(secretsDir)
		if resKey != "" {
			_ = store.MarkUnsuitable(resKey, 30*time.Minute)
			_ = store.Release(resKey)
		}
		_ = st.Remove(name)
		// Verify and retry once if still running (e.g. slow systemd-nspawn teardown).
		if !verifyVMStopped(ctx, name) {
			_ = b.Stop(ctx, name)
			_ = b.Destroy(ctx, name)
			time.Sleep(500 * time.Millisecond)
		}
		if verifyVMStopped(ctx, name) {
			fmt.Printf("  CLEAN: environment %s fully removed\n", name)
		} else {
			fmt.Fprintf(os.Stderr, "  WARN: %s may still be running on the host\n", name)
		}
	}
	// Signal handler: ensure Ctrl+C / SIGTERM always cleans up, even mid-provisioning.
	go func() {
		<-ctx.Done()
		if !destroyed {
			fmt.Fprintln(os.Stderr, "\nInterrupted — cleaning up…")
			teardown("interrupted")
			os.Exit(1)
		}
	}()

	for attempt := 0; attempt < 20; attempt++ {
		wg2, cc, key, gerr := allocateVPN(ctx, c, id, cli, store)
		if gerr != nil {
			fmt.Fprintln(os.Stderr, "  VPN: allocate failed:", gerr, "-> OpenCode will NOT start (fail-closed).")
			teardown("failed to allocate a unique VPN tunnel")
			os.Exit(1)
		}

		inject, ierr := sec.InjectDir(secretsDir, name, spec.Secrets)
		if ierr != nil {
			_ = store.Release(key)
			teardown("secrets injection failed")
			os.Exit(1)
		}
		spec.SecretsDir = inject
		if err := os.WriteFile(filepath.Join(inject, "lgwg0.conf"), []byte(vpn.ConfigString(wg2)), 0o600); err != nil {
			_ = store.Release(key)
			teardown("wg config write failed")
			os.Exit(1)
		}
		spec.WGConfig = vpn.ConfigString(wg2)
		spec.VPNCountry = cc

		if err := b.Create(ctx, spec); err != nil {
			_ = store.Release(key)
			teardown("host networking setup failed: " + err.Error())
			os.Exit(1)
		}
		// Provision the in-guest OpenCode config (minimal: workspace, system prompt,
		// and "permission": "allow" to mirror host behavior and disable permission
		// prompts). Written per-VM into root/.config/opencode/opencode.json; we do
		// NOT mount or copy the host OpenCode config wholesale. Must happen inside the
		// loop because an IP-collision retry re-clones the rootfs (wiping it).
		if err := opencode.ProvisionConfig(rootfsDir, config.ExpandPath(c.Workspace), cc); err != nil {
			_ = store.Release(key)
			teardown("provision opencode config failed: " + err.Error())
			os.Exit(1)
		}
		if err := b.Start(ctx, spec); err != nil {
			_ = store.Release(key)
			teardown("VM start failed: " + err.Error())
			os.Exit(1)
		}
		// Verify kill-switch is armed before measuring — fail-closed if not.
		// The nspawn setup runs wg-quick + nft synchronously before sleep infinity,
		// but b.Start returns immediately after cmd.Start, so allow a short grace.
		killOK := false
		for i := 0; i < 6; i++ {
			if hasKillSwitch(ctx, b, name) {
				killOK = true
				break
			}
			time.Sleep(500 * time.Millisecond)
		}
		if !killOK {
			fmt.Fprintf(os.Stderr, "  VPN: kill-switch not armed for %s; marking unsuitable and retrying\n", key)
			_ = store.MarkUnsuitable(key, 30*time.Minute)
			_ = store.Release(key)
			_ = b.Stop(ctx, name)
			_ = b.Destroy(ctx, name)
			_ = os.RemoveAll(rootfsDir)
			_ = os.RemoveAll(secretsDir)
			if err := ensureRootfs(ctx, c.BaseRootfs, rootfsDir); err != nil {
				teardown("rootfs re-clone failed: " + err.Error())
				os.Exit(1)
			}
			continue
		}
		fmt.Printf("  NETWORK: bridge=%s ip=%s\n", spec.Bridge, spec.IP)
		fmt.Printf("  VPN: connecting to %s (%s)…\n", key, cc)

		// Wait for WireGuard handshake before measuring egress — fail fast if no handshake.
		handshakeOK := false
		for i := 0; i < 15; i++ {
			if hasHandshake(ctx, b, name) {
				fmt.Printf("  VPN: WireGuard handshake OK\n")
				handshakeOK = true
				break
			}
			if i == 0 {
				fmt.Printf("  VPN: waiting for WireGuard handshake…\n")
			}
			select {
			case <-ctx.Done():
				fmt.Fprintln(os.Stderr, "  VPN: interrupted during handshake")
				_ = store.Release(key)
				teardown("interrupted during handshake")
				os.Exit(1)
			case <-time.After(2 * time.Second):
			}
		}
		if !handshakeOK {
			fmt.Fprintf(os.Stderr, "  VPN: handshake timeout for %s; marking unsuitable and retrying\n", key)
			_ = store.MarkUnsuitable(key, 30*time.Minute)
			_ = store.Release(key)
			_ = b.Stop(ctx, name)
			_ = b.Destroy(ctx, name)
			_ = os.RemoveAll(rootfsDir)
			_ = os.RemoveAll(secretsDir)
			if err := ensureRootfs(ctx, c.BaseRootfs, rootfsDir); err != nil {
				teardown("rootfs re-clone failed: " + err.Error())
				os.Exit(1)
			}
			continue
		}

		fmt.Printf("  VPN: measuring public egress IP (up to 60s)…\n")
		// Measure egress (bounded), retry on IP collision.
		resCh := make(chan vpn.Identity, 1)
		go func() {
			var m vpn.Identity
			for i := 0; i < 20; i++ {
				m = measureIdentity(ctx, b, name, c.VPNMeasureURLs)
				if m.V4 != "" {
					break
				}
				time.Sleep(3 * time.Second)
			}
			resCh <- m
		}()
		var m vpn.Identity
		select {
		case m = <-resCh:
		case <-time.After(60 * time.Second):
			fmt.Fprintln(os.Stderr, "  VPN: measurement timed out after 60s")
		}

		if m.V4 == "" {
			fmt.Fprintf(os.Stderr, "  VPN: egress measurement failed (no handshake/egress) for %s; marking unsuitable and retrying\n", key)
			_ = store.MarkUnsuitable(key, 30*time.Minute)
			_ = store.Release(key)
			_ = b.Stop(ctx, name)
			_ = b.Destroy(ctx, name)
			_ = os.RemoveAll(rootfsDir)
			_ = os.RemoveAll(secretsDir)
			if err := ensureRootfs(ctx, c.BaseRootfs, rootfsDir); err != nil {
				teardown("rootfs re-clone failed: " + err.Error())
				os.Exit(1)
			}
			continue
		}
		if !sharedVPNv4(expand(statePath), name, m.V4) {
			country, resKey = cc, key
			egressV4, egressV6 = m.V4, m.V6
			allocated = true
			break
		}
		fmt.Fprintf(os.Stderr, "  VPN: egress %q collides with another env; marking unsuitable and retrying\n", m.V4)
		_ = store.MarkUnsuitable(key, 30*time.Minute)
		_ = store.Release(key)
		_ = b.Stop(ctx, name)
		_ = b.Destroy(ctx, name)
		_ = os.RemoveAll(rootfsDir)
		_ = os.RemoveAll(secretsDir)
		// re-clone rootfs for the retry attempt
		if err := ensureRootfs(ctx, c.BaseRootfs, rootfsDir); err != nil {
			teardown("rootfs re-clone failed: " + err.Error())
			os.Exit(1)
		}
	}

	if !allocated {
		fmt.Fprintln(os.Stderr, "VPN: could not establish a unique tunnel after retries -> OpenCode not started (fail-closed).")
		teardown("no unique VPN tunnel after retries")
		os.Exit(1)
	}

	if resKey != "" {
		_ = store.Release(resKey) // egress IP now recorded in state
	}
	fmt.Printf("  VPN: CONNECTED country=%s public-ip=%s%s (kill-switch armed)\n", country, egressV4, v6Suffix(egressV6))

	// Record in state for dedup + lifecycle visibility.
	_ = st.Register(state.Record{
		Name: name, Country: country, Rootfs: rootfsDir, Backend: "nspawn",
		VPN: true, Projects: spec.Projects, CreatedAt: time.Now(),
		InstanceID: id, Region: country, VPNV4: egressV4, VPNV6: egressV6,
	})

	// 5. Auto-launch OpenCode (PTY attached). Starts only after unique VPN is up.
	// Setup a clean interactive launch: WORKSPACE printed for the user, then boot the
	// opencode TUI (gets its controlling terminal from the attached stdio).
	apiKey := ""
	if v, kerr := sec.Get("opencode_api_key"); kerr == nil {
		apiKey = v
	}
	launch := opencode.LaunchCommand("/usr/local/bin/opencode", config.ExpandPath(c.Workspace), apiKey, opencode.DefaultModel())
	fmt.Printf("  WORKSPACE: %s\n", config.ExpandPath(c.Workspace))
	fmt.Println("READY. Launching OpenCode...")
	if err := b.ShellCmd(ctx, name, launch); err != nil {
		fmt.Fprintln(os.Stderr, "opencode:", err)
	}

	fmt.Println("\nOpenCode exited. Destroying environment...")
	teardown("OpenCode exited")
}

func v6Suffix(v6 string) string {
	if v6 == "" {
		return ""
	}
	return ",v6=" + v6
}

// sharedVPNv4 reports whether v4 is currently claimed by ANOTHER VM, reading the
// persisted state fresh from disk and also checking live egress of running VMs
// (via machinectl + curl) to handle stale state where the recorded vpn_v4 may
// have drifted from the current live egress (e.g. Nord NAT IP changes).
func sharedVPNv4(path, self, v4 string) bool {
	if v4 == "" {
		return false
	}
	st, err := state.New(path)
	if err != nil {
		return false
	}
	for _, r := range st.List() {
		if r.Name == self || r.VPNV4 == "" {
			continue
		}
		if r.VPNV4 == v4 {
			return true
		}
	}
	// Also check live running new-opencode-vm VMs for current egress
	// (in case state.json is stale and live IP has drifted).
	b := nspawn.New()
	live, err := b.List(context.Background())
	if err != nil {
		return false
	}
	for _, name := range live {
		if name == self {
			continue
		}
		// Only check VMs that are in state (i.e. new-opencode-vm VMs)
		if _, ok := func() (state.Record, bool) {
			for _, r := range st.List() {
				if r.Name == name {
					return r, true
				}
			}
			return state.Record{}, false
		}(); !ok {
			continue
		}
		// Try live egress via curl (best effort, 3s timeout)
		ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
		egress, _ := b.Exec(ctx, name, "curl -4 -s --max-time 3 https://api.ipify.org 2>/dev/null")
		cancel()
		if strings.TrimSpace(egress) == v4 {
			return true
		}
	}
	return false
}

// pruneStaleState removes state records for machines that are no longer running
// (e.g. after a crash where teardown did not run). This prevents ghost collisions
// and keeps new status accurate. It is read-only with respect to LookingGlass.
func pruneStaleState(ctx context.Context, st *state.Store) {
	b := nspawn.New()
	live, err := b.List(ctx)
	if err != nil {
		return
	}
	liveSet := map[string]bool{}
	for _, n := range live {
		liveSet[n] = true
	}
	for _, r := range st.List() {
		if !liveSet[r.Name] {
			_ = st.Remove(r.Name)
			// Also prune its reservation if it was left behind (crash).
			store := vpn.NewReservationStore(expand(reservationF))
			_ = store.Release(r.Name) // no-op if not reserved by name; also try by server_key
			// Remove any reservation that was held by this instance's ID.
			// We cannot know the server_key, so we rely on TTL expiry for those.
		}
	}
}

// hasHandshake checks if lgwg0 has completed a WireGuard handshake (has non-zero RX).
func hasHandshake(ctx context.Context, b backend.EnvironmentBackend, name string) bool {
	out, err := b.Exec(ctx, name, "wg show lgwg0 2>/dev/null | grep -q 'latest handshake' && echo yes || echo no")
	if err != nil {
		return false
	}
	return strings.TrimSpace(out) == "yes"
}

func hasKillSwitch(ctx context.Context, b backend.EnvironmentBackend, name string) bool {
	return guestKillSwitch(ctx, b, name)
}

// statusAuto implements `new status`: a read-only report of the opencode-vm VMs that
// are CURRENTLY running (intersection of the state registry and the live machinectl
// list). For each VM it reports VPN up/down (wg handshake), country, measured live
// egress IP (falling back to the recorded IP), and kill-switch state. It never
// launches or destroys VMs.
func statusAuto(ctx context.Context) {
	st, err := state.New(expand(statePath))
	if err != nil {
		fmt.Fprintln(os.Stderr, "status: load state:", err)
		os.Exit(1)
	}
	byName := map[string]state.Record{}
	for _, r := range st.List() {
		byName[r.Name] = r
	}

	b := nspawn.New()
	live, err := b.List(ctx)
	if err != nil {
		fmt.Fprintln(os.Stderr, "status: list VMs:", err)
		os.Exit(1)
	}

	// Report only records that correspond to live running VMs.
	rows := []string{}
	for _, name := range live {
		rec, ok := byName[name]
		if !ok {
			continue // not a new-opencode-vm VM (e.g. LookingGlass envN); ignore
		}
		vpnState, vpnDetail := guestVPNState(ctx, b, name)
		ks := guestKillSwitch(ctx, b, name)
		egress := guestEgress(ctx, b, name)
		if egress == "" {
			egress = rec.VPNV4
		}
		rows = append(rows, fmt.Sprintf("%-7s %-3s %-6s %-11s %-16s %s",
			name, regionShort(rec), vpnState, gate(ks), egress, vpnDetail))
	}

	if len(rows) == 0 {
		fmt.Println("no running new-opencode-vm VMs")
		return
	}
	fmt.Printf("%-7s %-3s %-6s %-11s %-16s %s\n", "VM", "CC", "VPN", "KILL-SWITCH", "EGRESS-IP", "DETAIL")
	fmt.Printf("%-7s %-3s %-6s %-11s %-16s %s\n", "----", "--", "----", "-----------", "---------------", "------")
	for _, r := range rows {
		fmt.Println(r)
	}
}

func regionShort(rec state.Record) string {
	if rec.Region != "" {
		return rec.Region
	}
	return rec.Country
}

func gate(v bool) string {
	if v {
		return "ON"
	}
	return "OFF"
}

func guestVPNState(ctx context.Context, b backend.EnvironmentBackend, name string) (string, string) {
	out, err := b.Exec(ctx, name, "wg show lgwg0 2>/dev/null | grep -E '^(interface|  latest handshake)' | head -2")
	if err != nil {
		return "DOWN", "no lgwg0"
	}
	s := strings.TrimSpace(out)
	if s == "" {
		return "DOWN", "no lgwg0"
	}
	if strings.Contains(s, "latest handshake") {
		return "UP", firstLine(s)
	}
	return "UP?", firstLine(s)
}

func guestKillSwitch(ctx context.Context, b backend.EnvironmentBackend, name string) bool {
	out, err := b.Exec(ctx, name, "nft list table inet lgkill >/dev/null 2>&1 && echo yes || echo no")
	if err != nil {
		return false
	}
	return strings.TrimSpace(out) == "yes"
}

func guestEgress(ctx context.Context, b backend.EnvironmentBackend, name string) string {
	out, err := b.Exec(ctx, name, "curl -4 -s --max-time 8 https://api.ipify.org 2>/dev/null")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(out)
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return strings.TrimSpace(s[:i])
	}
	return strings.TrimSpace(s)
}
