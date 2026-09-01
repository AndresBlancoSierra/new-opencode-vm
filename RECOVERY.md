# STABLE CHECKPOINT
new-opencode-vm stable lifecycle + Slides/Infinite integration + explicit workspace
Date: 2026-08-31
Branch: main
Commit: 6765d61 + new [path] explicit workspace (Option A)
Build: go1.26.6, binary 9.2M, BuildID a7618a7a
OpenCode: 1.18.21
Model: opencode/muse-spark-1.2-contributor-free
Permission: allow
Workspace: explicit via new [path] (default /home/andres/Proyects, no vm-* auto-creation in ~/Proyects)
VM: nspawn lgwg0 10.5.0.2/32, lgbr0 10.89.0.1/24, kill-switch inet lgkill, per-VM wg genkey
Agents: slides + infinite via references + agent/skill copy to /root/.config/opencode, BroadMounts provides ~/Proyects/slides + ~/Proyects/infinite-agent
State: /root/.local/state/new-opencode-vm/state.json 7 env11-17, instances 78, reservations 5
Verified: 5 consecutive single new PASS, 2-parallel PASS, env77/78 slides+infinite verified, new [path] /tmp/test-workspace verified, no orphans, LookingGlass/Infinite/host VPN untouched
Recovery: git clone https://github.com/AndresBlancoSierra/new-opencode-vm.git && go build -o ~/.local/bin/new ./cmd/new
