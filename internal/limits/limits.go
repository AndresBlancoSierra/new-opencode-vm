// Package limits translates resource requests into systemd-nspawn cgroup flags.
// (The QEMU backend will map the same fields to <vcpu> and <memory> instead.)
package limits

import (
	"fmt"

	"new-opencode-vm/internal/backend"
)

// Args returns the nspawn resource-limit flags for a spec. systemd-nspawn expresses
// cgroup limits via -p/--property=UNIT_PROPERTY=VALUE (CPUQuota is a percent,
// MemoryMax a size, TasksMax the max task count). Unset limits are omitted.
func Args(spec backend.EnvSpec) []string {
	var a []string
	if spec.CPUQuota > 0 {
		a = append(a, fmt.Sprintf("--property=CPUQuota=%d%%", spec.CPUQuota))
	}
	if spec.MemMaxMB > 0 {
		a = append(a, fmt.Sprintf("--property=MemoryMax=%dM", spec.MemMaxMB))
	}
	if spec.PidsMax > 0 {
		a = append(a, fmt.Sprintf("--property=TasksMax=%d", spec.PidsMax))
	}
	return a
}
