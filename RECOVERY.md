# STABLE CHECKPOINT
new-opencode-vm stable lifecycle + Slides/Infinite integration
Date: 2026-08-31
Branch: main
Commit: d6dc2d9 (prev) + opencode agent integration
Build: go1.26.6, binary 9.2M, BuildID a7618a7a (before), now with references
OpenCode: 1.18.21
Model: opencode/muse-spark-1.2-contributor-free
Permission: allow
Workspace: /home/andres/Proyects (positional arg, not in config)
VM: nspawn lgwg0 10.5.0.2/32, lgbr0 10.89.0.1/24, kill-switch inet lgkill, per-VM wg genkey
Agents: slides (engine/template.html) + infinite (infinite-loop.sh) via references + agent/skill copy to /root/.config/opencode, BroadMounts provides ~/Proyects/slides + ~/Proyects/infinite-agent
State: /root/.local/state/new-opencode-vm/state.json 7 env11-17, instances 78, reservations 5
Verified: 5 consecutive single new PASS (env48-51,69), 2-parallel PASS, env77 slides+infinite verified (opencode agent list, references, mounts), no orphans, LookingGlass/Infinite/host VPN untouched
Recovery: git clone https://github.com/AndresBlancoSierra/new-opencode-vm.git && go build -o ~/.local/bin/new ./cmd/new
