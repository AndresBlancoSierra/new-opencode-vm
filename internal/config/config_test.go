package config

import "testing"

func TestExpandEnvDefaults(t *testing.T) {
	c := Default()
	e := Environment{Name: "germany"}
	spec, err := c.ExpandEnv(e)
	if err != nil {
		t.Fatal(err)
	}
	if spec.Name != "germany" {
		t.Fatalf("name=%q", spec.Name)
	}
	if spec.VPNCountry != c.DefaultCountry {
		t.Fatalf("country=%q want %q", spec.VPNCountry, c.DefaultCountry)
	}
	if spec.CPUQuota != c.DefaultCPUQuota {
		t.Fatalf("cpu=%d", spec.CPUQuota)
	}
	if spec.MemMaxMB != c.DefaultMemMaxMB {
		t.Fatalf("mem=%d", spec.MemMaxMB)
	}
	if !spec.EnableKillSwitch {
		t.Fatal("kill-switch should default on")
	}
	if spec.VPNIface != "lgwg0" {
		t.Fatalf("vpn iface=%q", spec.VPNIface)
	}
}

func TestExpandEnvOverride(t *testing.T) {
	c := Default()
	e := Environment{Name: "us", Country: "us", CPUQuota: 200, MemMaxMB: 2048, TTL: "45m"}
	spec, err := c.ExpandEnv(e)
	if err != nil {
		t.Fatal(err)
	}
	if spec.CPUQuota != 200 || spec.MemMaxMB != 2048 {
		t.Fatalf("override failed: %+v", spec)
	}
	if spec.VPNCountry != "us" {
		t.Fatalf("country=%q", spec.VPNCountry)
	}
}

func TestExpandEnvBadTTL(t *testing.T) {
	c := Default()
	e := Environment{Name: "x", TTL: "notaduration"}
	if _, err := c.ExpandEnv(e); err == nil {
		t.Fatal("expected TTL parse error")
	}
}

func TestExpandEnvNoName(t *testing.T) {
	c := Default()
	if _, err := c.ExpandEnv(Environment{}); err == nil {
		t.Fatal("expected name error")
	}
}
