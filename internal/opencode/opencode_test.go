package opencode

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDefaultModel(t *testing.T) {
	if got := DefaultModel(); got != "opencode/muse-spark-1.2-contributor-free" {
		t.Fatalf("DefaultModel() = %q, want opencode/muse-spark-1.2-contributor-free", got)
	}
}

func TestLaunchCommandIncludesModel(t *testing.T) {
	got := LaunchCommand("/usr/local/bin/opencode", "/home/andres/Proyects", "sekret", "opencode/muse-spark-1.2-contributor-free")
	for _, want := range []string{"OPENCODE_API_KEY='sekret'", "-m opencode/muse-spark-1.2-contributor-free", "/home/andres/Proyects"} {
		if !strings.Contains(got, want) {
			t.Fatalf("LaunchCommand() = %q, missing %q", got, want)
		}
	}
}

func TestLaunchCommandDefaultModelWhenEmpty(t *testing.T) {
	got := LaunchCommand("opencode", "/ws", "", "")
	if !strings.Contains(got, "-m "+defaultModel) {
		t.Fatalf("LaunchCommand() with empty model should use default: %q", got)
	}
	if strings.Contains(got, "OPENCODE_API_KEY") {
		t.Fatalf("LaunchCommand() should omit API key when empty: %q", got)
	}
}

func TestConfigJSONPermissionAllow(t *testing.T) {
	cfg := ConfigJSON("/home/andres/Proyects", "co")
	if !strings.Contains(cfg, `"permission": "allow"`) {
		t.Fatalf("ConfigJSON() missing permission allow in:\n%s", cfg)
	}
	// For v1.18.21, workspace and agent.systemPrompt as string are invalid
	// (workspace not in Config schema, systemPrompt expects object). The minimal
	// valid config is just permission:allow, model/workspace are via CLI args.
	for _, notWant := range []string{`"workspace"`, "systemPrompt"} {
		if strings.Contains(cfg, notWant) {
			t.Fatalf("ConfigJSON() should not contain %q for v1.18.21, got:\n%s", notWant, cfg)
		}
	}
}

func TestProvisionConfigWritesAtExpectedPath(t *testing.T) {
	dir := t.TempDir()
	if err := ProvisionConfig(dir, "/home/andres/Proyects", "co"); err != nil {
		t.Fatalf("ProvisionConfig: %v", err)
	}
	p := filepath.Join(dir, filepath.FromSlash(configRelPath))
	data, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("read provisioned config: %v", err)
	}
	if got := string(data); !strings.Contains(got, `"permission": "allow"`) {
		t.Fatalf("provisioned config missing permission allow:\n%s", got)
	}
	if st, err := os.Stat(p); err == nil && st.Mode().Perm()&0o077 != 0 {
		t.Fatalf("provisioned config should be 0600, got %v", st.Mode().Perm())
	}
}
