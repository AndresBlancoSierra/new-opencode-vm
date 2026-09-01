# new-opencode-vm

A separate, simpler sibling of LookingGlass + Infinite. A single `new` command
creates a **fresh, isolated nspawn VM** with its **own independent NordVPN
Colombia tunnel** (measured-unique egress IP) + **fail-closed kill-switch**, boots
it, launches a **REAL interactive OpenCode** session attached to your terminal, and
on OpenCode exit **destroys the VM and releases all resources** (zero orphans).

Existing LookingGlass + Infinite are **completely untouched** — this project lives
in its own tree and its own state directory.

## Why it exists

LookingGlass + Infinite are heavy: a watchdog/supervisor, `opencode run`,
`--continue`, DONE/FAILED markers, Telegram/Brave/Xvfb, a daemon, TTLs. This
project strips all of that. Each `new` is a clean, short-lived, disposable VM.

## One command

```
new
```

- allocates a fresh VM (`env#N`, hidden from you)
- boots it (broad RW `/home/andres` + `~/Proyects` mounts, so OpenCode feels like
  hosting locally)
- connects a per-VM WireGuard tunnel to **Colombia** (fallback geo pool), measured
  unique vs any coexisting VM
- arms the fail-closed kill-switch inside the guest
- launches interactive `opencode -m opencode/muse-spark-1.2-contributor-free ~/Proyects`
  (workspace passed as a positional project arg — `--workspace` makes opencode 1.18.x
  print help instead of booting; default model is **OpenCode Zen · xhigh /
  Build · Muse Spark 1.2 Free** — `opencode/muse-spark-1.2-contributor-free`, a
  built-in `opencode` provider model, no extra host auth needed)
- provisions a minimal per-VM OpenCode config at `/root/.config/opencode/opencode.json`
  (`{"permission":"allow","references":{"slides":{"path":"/home/andres/Proyects/slides"},"infinite-agent":{"path":"/home/andres/Proyects/infinite-agent"}}}`) so the in-guest agent never
  shows permission prompts — mirrors `~/.config/opencode/opencode.json:permission=allow`
  on the host, without copying the host config wholesale or any credentials
- copies `agent/slides.md`, `agent/infinite.md`, `skill/slides/SKILL.md` and `bin/*` (`ask-chatgpt.js`, `infinite-loop.sh`, etc.) from `~/.config/opencode` (or repo fallback) into the VM's `/root/.config/opencode` so `opencode agent list` inside the VM shows `slides` and `infinite` (verified `env77` `ls agent` `slides.md`/`infinite.md` and `opencode agent list` `slides`/`infinite` found)
- the VM already sees `~/Proyects/slides` and `~/Proyects/infinite-agent` via the existing `BroadMounts` `/home/andres/Proyects` RW, so no data duplication
- when OpenCode exits, destroys the VM, purges its rootfs/secrets, releases the VPN
  reservation, and removes the state record

## What is excluded (vs LookingGlass/Infinite)

`infinite-loop.sh`, `opencode run`, `--continue`, watchdog/supervisor, daemon, TTLs,
DONE/FAILED markers, Telegram, Brave, Xvfb. The host never needs NordVPN connected:
each VM gets its own token-based per-VM WireGuard keypair; the fallback only reads
`wg showconf nordlynx` (never `nordvpn` CLI).

## Layout

```
cmd/new/main.go            # the `new` auto flow + destroy-on-exit teardown
internal/
  allocator/               # flock-monotonic instance-ID counter
  backend/ + backend/nspawn# environment abstraction + systemd-nspawn backend
  config/                  # loads the shared ~/.config/lookingglass/config.json
  limits/                  # cgroup CPU/Mem/Tasks limits
  network/                 # bridge + nftables isolation (flock-serialized) + NAT
  opencode/                # interactive launch command (no --continue)
  secrets/                 # file store + runtime injection (never in rootfs)
  state/                   # NEW: minimal live-VM registry for egress-IP dedup
  vpn/                     # NordVPN API + per-VM WireGuard + reservation store
```

## Design invariants

- **No host VPN mutation.** Each VM config is generated from the Nord token API
  (independent keypair) with a read-only host-key fallback; `nordvpn` CLI is never
  invoked.
- **IP uniqueness.** It is never assumed that different tokens imply different IPs.
  Egress is measured from inside the guest and deduped against the `state` registry
  (fresh from disk, cross-process safe); a colliding server is marked unsuitable and
  retried.
- **nfables concurrency.** `network.ApplyFilter` holds an exclusive flock on
  `/var/lock/lg-nft.lock` around the delete+`nft -f` cycle shared by concurrent
  boots.
- **IPv6 fail-closed** uses the ULA `fd89:0:0:0::/64`, never the IPv4 guest subnet.
- **Fail-closed VPN.** If a unique tunnel cannot be established, OpenCode does not
  start and the VM is destroyed; there is no fallback to host internet.
- **Destroy on exit.** OpenCode exit (or any setup failure) triggers a full,
  verified teardown.

## Reused configuration

The live `~/.config/lookingglass/config.json` (base rootfs, opencode binary, token,
geo-fallback, workspace) and `~/.config/lookingglass/secrets.json` (nordvpn_token,
opencode_api_key) are reused as-is. All **state** lives in the new project's own
`~/.local/state/new-opencode-vm/` directory, never in `~/.local/state/lookingglass/`.

## Status (read-only, no VM launch)

```
new status
```

Reports the **currently running `new-opencode-vm` VMs only** (intersection of the
state registry and `machinectl` live list):

```
VM      CC  VPN    KILL-SWITCH EGRESS-IP        DETAIL
env11   co  UP     ON          187.13.11.67     interface: lgwg0
...
```

Columns: VM id, country, live VPN state (`wg show lgwg0` handshake), kill-switch
(`nft list table inet lgkill`), live egress IP (curl inside guest, fallback to
recorded `vpn_v4`). Never launches or destroys VMs.

## Reliability (verified 2026-08-30)

* **Handshake before egress:** `new` now waits for `wg show lgwg0` `latest handshake` (poll 15×2s) before `curl`; if no handshake after 30s it marks server unsuitable and retries with next server — distinguishes *tunnel failure* from *IP collision* and never logs empty IP as collision.
* **Egress uniqueness:** measured `curl -4 https://api.ipify.org` inside guest, deduped against `state.json` **plus live `new status` egress** (handles stale `vpn_v4` where NAT IP drifted, e.g. `env15` `112`→`106`).
* **Bad server avoidance:** handshake timeout, empty measurement, and duplicate egress all `MarkUnsuitable(30m)`; `Allocate` skips `IsUnsuitable`/`IsReservedByOther`; `RecommendN`/`countryID` cache and retry on 429 with backoff (handles Cloudflare `1015` rate limit after 3 concurrent `new`).
* **Per-VM WireGuard key:** `wg genkey` per VM (not shared account `nordlynx_private_key`) — concurrent VMs no longer share same private key and handshake no longer fails when 7+ VMs run.
* **Progress UX:** after `NETWORK: bridge=…` prints `VPN: connecting to <key> (<cc>)…` → `waiting for WireGuard handshake…` → `handshake OK` → `measuring public egress IP (up to 60s)…` → `measuring egress via …` and `measurement timed out` — never silent for 60s.
* **Signal-safe cleanup:** `signal.NotifyContext` for `SIGINT`/`SIGTERM` (Ctrl+C), transactional `teardown` (idempotent `destroyed` flag, `Stop`+`Destroy`+`RemoveAll`+`Release`+`Remove`+`verifyVMStopped` double-check), `pruneStaleState` on startup removes ghost `state.json` entries for non-running machines, `ensureRoot` now exits on `sudo -n` failure instead of continuing as non-root (which previously created `env3` at `/home/...` with `rsync` permission denied).
* **Concurrency:** `allocator` flock, `state` flock+`Remove`/`Register`, `reservations` flock+TTL, `network.ApplyFilter` flock on `/var/lock/lg-nft.lock` — 5 consecutive single `new` and 2-parallel `new` verified with unique egress and no state corruption.

## Build / test

```
go build ./...
go vet ./...
gofmt -l .
go test ./...
```

The end-to-end scenarios (single VM, N concurrent, VPN fail-closed, exit cleanup,
repeated, concurrency stress) require live VMs + a working NordVPN token and are not
run by `go test`.

Live acceptance (real VMs, `~/.local/bin/new` 9.2M, `opencode/muse-spark-1.2-contributor-free`, `permission:allow`):

* **5 consecutive `new` (2026-08-30, env48-51,69):** each `STARTING` → `NETWORK` → `VPN: connecting` → `handshake OK` (or `handshake timeout` then retry) → `measuring` → `egress … collides` (when duplicate) → `CONNECTED country=co/ec public-ip=…` → `WORKSPACE` → `READY` → `opencode -m …` → `q` → `TEARDOWN` → `CLEAN` — all 5 PASS, no orphan `machinectl`/`rootfs`/`secrets`/`reservations`/`state`.
* **2 parallel `new` (env59 `ec:32` + env61 `…`):** both `STARTING` concurrently, `CONNECT` with unique `public-ip` (`32` vs `…`), `new status` shows both, both `CLEAN` on exit — no duplicate egress, no state corruption (one run showed `env15` live `106` vs `state` `112` correctly handled by live check).

## Agent Integration (Slides + Infinite)

`new` now provisions **Slides** and **Infinite** as primary agents inside the VM's OpenCode, reusing existing host implementations (no fork):

* **Slides** (`/home/andres/Proyects/slides`, `opencode/agent/slides.md` `mode: primary` + `skill/slides/SKILL.md` 6 phases, `engine/template.html` 1280×720): `references.slides.path` via `BroadMounts` (already `RW`), `agent`/`skill` copied to `/root/.config/opencode` (0600), `node`+`chromium` via `/opt/opencode` bind — verified `env77` `opencode agent list` `slides` found.
* **Infinite** (`/home/andres/Proyects/infinite-agent`, `agent/infinite.md` `mode: primary` + `bin/infinite-loop.sh` `ask-chatgpt.js` `infinite-browser.sh`): same `references.infinite-agent`, `agent/infinite.md` + `bin/*` copied to `/root/.config/opencode/bin` (0755), `~/Proyects` mount provides `~/Proyects/infinite-agent` and `~/Proyects/<project>` state, host `Brave-Infinite` `~/.config/BraveSoftware/Brave-Infinite` and `Xvfb :99` **host-only** (not copied; VM `infinite-loop.sh` will launch its own `Xvfb :99`/`Brave :9333` if needed, or degrade `Telegram` via `lg secrets` miss). No host `opencode.db` or `nordlynx` mutation.

```
                         HOST
                          │
                    ┌─────▼─────┐
                    │    new    │
                    └─────┬─────┘
                          │
                    isolated VM
                          │
             ┌────────────┴────────────┐
             │                         │
        WireGuard VPN            OpenCode 1.18.21
        lgwg0 10.5.0.2/32    -m muse-spark-1.2-contributor-free
        kill-switch inet lgkill  permission:allow  /home/andres/Proyects
             │              ┌──────────┴──────────┐
             │              │                     │
        unique egress      Slides               Infinite
        (api.ipify.org)  (engine/template.html) (infinite-loop.sh)
```

`HOST` (`lgbr0`, `nordvpn_token`), `VM` (`lgwg0`, `lgkill`, `rootfs`), `SHARED SOURCE` (`~/Proyects/slides`, `~/Proyects/infinite-agent`), `MOUNTED` (`BroadMounts` RW, `/opt/opencode` RO), `COPIED` (`agent/*.md`/`skill`/`opencode.json` `references`), `SERVICE` (`Xvfb :99`, `Brave :9333` host-only), `SECRET` (`lgwg0.conf` via `secretsDir` RO).

## Why no Infinite (host)

This project is intentionally **not** another Infinite host daemon: no `opencode run --continue` watchdog, no `supervisor`, no host `DONE/FAILED` machine, no `Telegram`/`Brave` host mutation. It simply gives you a normal interactive `opencode` (with `slides`+`infinite` agents available) inside an isolated VM with its own VPN — infrastructure isolation only, disposable.
