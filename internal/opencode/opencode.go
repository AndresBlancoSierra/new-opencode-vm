// Package opencode integrates the OpenCode agent inside a Looking Glass environment.
// The isolation guarantee comes from the mount namespace: the guest only sees its
// rootfs plus the explicitly authorized project(s), so an agent launched here can
// only read/modify what was mounted. We additionally pin its workspace to the
// project guest path and inject the OpenCode API key as a runtime secret (never
// persisted to the rootfs).
package opencode

import (
	"fmt"
	"os"
	"path/filepath"

	"new-opencode-vm/internal/backend"
)

// defaultModel is the exact model ID selected by default when OpenCode boots inside
// the VM. It is a built-in `opencode` provider model (same provider as big-pickle),
// so it is available without any extra host provider config; the VM already injects
// the opencode_api_key that authorizes it. "OpenCode Zen · xhigh" is the display
// branding/tier of this model; the provider/model ID is muse-spark-1.2-contributor-free.
const defaultModel = "opencode/muse-spark-1.2-contributor-free"

// DefaultModel returns the model ID used by default when launching OpenCode in the VM.
func DefaultModel() string { return defaultModel }

// configRelPath is where the in-guest OpenCode reads its config when launched as root
// (HOME=/root inside the guest): ~/.config/opencode/opencode.json.
const configRelPath = "root/.config/opencode/opencode.json"

// SystemPrompt returns the (neutral) prompt given to the in-guest agent. Under the
// NEW model the environment has broad, trusted read-write access to the host
// filesystem (mounted at the same absolute paths), so we do NOT lie about isolation;
// we only note that the network identity is isolated via an independent VPN with a
// fail-closed kill-switch.
func SystemPrompt(projectGuestPath, country string) string {
	return fmt.Sprintf(`You are running inside a Looking Glass environment.
Filesystem: you have broad read-write access to the host (mounted at the same absolute paths); operate naturally on %s.
Network: your egress uses an independent VPN (exit: %s) with a fail-closed kill-switch — do not attempt to disable it.
Report what you changed.`, projectGuestPath, country)
}

// ConfigJSON renders the minimal OpenCode config provisioned into every VM.
// For opencode v1.18.21 the only required field to suppress permission prompts
// is the top-level "permission": "allow" (verified against host
// ~/.config/opencode/opencode.json and https://opencode.ai/config.json schema:
//   - "workspace" is not a valid Config property (schema has no such field)
//   - "agent.systemPrompt" as string is invalid (1.18.21 expects object, got string)
//   - "agent.prompt" as string is valid but not needed for the base behavior
//
// The VM already gets its workspace via the positional project arg and its model
// via -m, so the config stays minimal and valid. The previous SystemPrompt
// is kept for reference but not rendered into the JSON.
//
// For Slides/Infinite integration, the VM also gets `references` for the shared
// projects (via the existing BroadMounts /home/andres/Proyects) and the agent/
// skill files are copied into the VM's /root/.config/opencode by ProvisionConfig.
func ConfigJSON(projectGuestPath, country string) string {
	_ = projectGuestPath
	_ = country
	return `{
  "$schema": "https://opencode.ai/config.json",
  "permission": "allow",
  "references": {
    "slides": {
      "path": "/home/andres/Proyects/slides",
      "description": "Base de conocimiento, motor, plantillas y docs del agente slides (decks HTML profesionales)."
    },
    "infinite-agent": {
      "path": "/home/andres/Proyects/infinite-agent",
      "description": "Infinite primary agent (opencode run --continue, watchdog, Brave, Telegram)."
    }
  }
}
`
}

// ProvisionConfig writes the in-guest OpenCode config into the VM rootfs at
// root/.config/opencode/opencode.json (the path OpenCode reads when launched as root
// with HOME=/root). The per-VM copy keeps the NEW configuration isolated to this
// project and avoids mounting/reusing the host OpenCode config wholesale.
//
// It also provisions the Slides and Infinite primary agents so they are available
// inside the VM's OpenCode without forking their logic:
//   - copies agent/slides.md, agent/infinite.md, skill/slides/SKILL.md from the
//     host's ~/.config/opencode (or repo fallback) into the VM's
//     /root/.config/opencode
//   - copies bin/* (ask-chatgpt.js, infinite-loop.sh, etc.) if present
//   - the VM already sees ~/Proyects/slides and ~/Proyects/infinite-agent via
//     BroadMounts (/home/andres/Proyects RW), so no data duplication is needed
func ProvisionConfig(rootfsDir, projectGuestPath, country string) error {
	if rootfsDir == "" {
		return fmt.Errorf("rootfs dir empty")
	}
	p := filepath.Join(rootfsDir, filepath.FromSlash(configRelPath))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return fmt.Errorf("mkdir config dir: %w", err)
	}
	if err := os.WriteFile(p, []byte(ConfigJSON(projectGuestPath, country)), 0o600); err != nil {
		return fmt.Errorf("write opencode config: %w", err)
	}
	// Provision Slides + Infinite agent/skill files into the VM's /root/.config/opencode
	// so `opencode agent list` inside the VM sees them. These are copies (not mounts)
	// to keep the VM's HOME=/root isolated and to avoid writing to the host's config
	// from inside the VM. Failures are non-fatal (e.g. host files missing).
	hostHome, _ := os.UserHomeDir()
	// Use andres's home explicitly for host files (the VM runs as root, but host files
	// live at /home/andres/.config/opencode, not /root/.config/opencode).
	if hostHome == "/root" {
		hostHome = "/home/andres"
	}
	hostCfg := filepath.Join(hostHome, ".config", "opencode")
	vmCfg := filepath.Join(rootfsDir, "root", ".config", "opencode")
	for _, rel := range []string{
		"agent/slides.md",
		"agent/infinite.md",
		"skill/slides/SKILL.md",
	} {
		src := filepath.Join(hostCfg, rel)
		dst := filepath.Join(vmCfg, rel)
		if _, err := os.Stat(src); err != nil {
			// Fallback to repo source for slides (opencode/agent/slides.md)
			if rel == "agent/slides.md" {
				src = "/home/andres/Proyects/slides/opencode/agent/slides.md"
			} else if rel == "skill/slides/SKILL.md" {
				src = "/home/andres/Proyects/slides/opencode/skill/slides/SKILL.md"
			} else if rel == "agent/infinite.md" {
				src = "/home/andres/Proyects/infinite-agent/agent/infinite.md"
			}
		}
		if _, err := os.Stat(src); err != nil {
			continue
		}
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			continue
		}
		if data, err := os.ReadFile(src); err == nil {
			_ = os.WriteFile(dst, data, 0o600)
		}
	}
	// Copy bin/* if present (ask-chatgpt.js, infinite-loop.sh, etc.) — also non-fatal
	binSrc := filepath.Join(hostCfg, "bin")
	binDst := filepath.Join(vmCfg, "bin")
	if _, err := os.Stat(binSrc); err == nil {
		_ = os.MkdirAll(binDst, 0o755)
		if entries, err := os.ReadDir(binSrc); err == nil {
			for _, e := range entries {
				if e.IsDir() {
					continue
				}
				src := filepath.Join(binSrc, e.Name())
				dst := filepath.Join(binDst, e.Name())
				if data, err := os.ReadFile(src); err == nil {
					_ = os.WriteFile(dst, data, 0o755)
				}
			}
		}
	}
	return nil
}

// LaunchCommand returns the shell command (for backend.ShellCmd) that launches
// OpenCode inside the guest with the API key injected as a runtime env var, the
// default model selected via -m, and the given workspace. The key is single-quoted to
// avoid shell expansion. The workspace is passed as a positional project arg (not
// --workspace), because opencode 1.18.x prints its usage/help and exits when given
// --workspace instead of a project path.
func LaunchCommand(bin, workspace, apiKey, model string) string {
	if model == "" {
		model = defaultModel
	}
	if apiKey != "" {
		return fmt.Sprintf("env OPENCODE_API_KEY='%s' %s -m %s %s", apiKey, bin, model, workspace)
	}
	return fmt.Sprintf("%s -m %s %s", bin, model, workspace)
}

// ShellArgs returns the machinectl shell invocation that launches opencode inside the
// guest. opencodeBin is the in-guest path of the bind-mounted binary. The project path
// is passed positionally (not --workspace), matching LaunchCommand.
func ShellArgs(name, opencodeBin, projectGuestPath string, env map[string]string) []string {
	args := []string{"shell", name}
	for k, v := range env {
		args = append(args, "--setenv="+k+"="+v)
	}
	args = append(args, "--", opencodeBin, projectGuestPath)
	return args
}

// BindSpec returns the host->guest bind for the opencode binary (read-only).
func BindSpec(hostBin, guestBin string) backend.ProjectMount {
	return backend.ProjectMount{HostPath: hostBin, GuestPath: guestBin, ReadOnly: true}
}
