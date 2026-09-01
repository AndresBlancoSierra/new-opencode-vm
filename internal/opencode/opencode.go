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
func ConfigJSON(projectGuestPath, country string) string {
	_ = projectGuestPath
	_ = country
	return `{
  "permission": "allow"
}
`
}

// ProvisionConfig writes the in-guest OpenCode config into the VM rootfs at
// root/.config/opencode/opencode.json (the path OpenCode reads when launched as root
// with HOME=/root). The per-VM copy keeps the NEW configuration isolated to this
// project and avoids mounting/reusing the host OpenCode config wholesale.
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
