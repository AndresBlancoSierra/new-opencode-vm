package state

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"new-opencode-vm/internal/vpn"
)

func TestRegisterGetList(t *testing.T) {
	dir := t.TempDir()
	st, err := New(filepath.Join(dir, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	r := Record{Name: "env1", Country: "co", VPNV4: "1.2.3.4", InstanceID: 1, CreatedAt: time.Now()}
	if err := st.Register(r); err != nil {
		t.Fatal(err)
	}
	got, ok := st.Get("env1")
	if !ok {
		t.Fatal("expected env1 record")
	}
	if got.VPNV4 != "1.2.3.4" {
		t.Fatalf("expected 1.2.3.4, got %q", got.VPNV4)
	}
	if len(st.List()) != 1 {
		t.Fatalf("expected 1 record, got %d", len(st.List()))
	}
}

func TestRemove(t *testing.T) {
	dir := t.TempDir()
	st, _ := New(filepath.Join(dir, "state.json"))
	st.Register(Record{Name: "env1", VPNV4: "1.2.3.4"})
	if err := st.Remove("env1"); err != nil {
		t.Fatal(err)
	}
	if _, ok := st.Get("env1"); ok {
		t.Fatal("env1 should be removed")
	}
}

// TestActiveIdentities ensures dedup only considers VMs that actually hold an egress
// identity (VM without measured IP is ignored by the collision check).
func TestActiveIdentities(t *testing.T) {
	dir := t.TempDir()
	st, _ := New(filepath.Join(dir, "state.json"))
	st.Register(Record{Name: "a", VPNV4: "5.5.5.5"})
	st.Register(Record{Name: "b", VPNV4: ""})
	ids := st.ActiveIdentities()
	if _, ok := ids["a"]; !ok {
		t.Fatal("a should be active")
	}
	if _, ok := ids["b"]; ok {
		t.Fatal("b (no egress) should not be active")
	}
}

// TestPersistAcrossReload verifies the store round-trips to disk and that a fresh
// Store instance (simulating a concurrent `new` process) reads the same records.
func TestPersistAcrossReload(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	st, _ := New(path)
	st.Register(Record{Name: "env1", VPNV4: "9.9.9.9"})

	other, _ := New(path)
	got, ok := other.Get("env1")
	if !ok {
		t.Fatal("env1 should be visible to a concurrent store")
	}
	if got.VPNV4 != "9.9.9.9" {
		t.Fatalf("expected 9.9.9.9, got %q", got.VPNV4)
	}
}

// TestCrossProcessMerge simulates two concurrent processes registering different
// VMs; neither may clobber the other (the flock + merge persist must hold), and a
// reloaded/fresh store observes both.
func TestCrossProcessMerge(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	a, _ := New(path)
	b, _ := New(path)
	if err := a.Register(Record{Name: "env1", VPNV4: "1.1.1.1"}); err != nil {
		t.Fatal(err)
	}
	if err := b.Register(Record{Name: "env2", VPNV4: "2.2.2.2"}); err != nil {
		t.Fatal(err)
	}
	// A fresh store reads the latest on-disk state (what a concurrent `new` sees).
	fresh, _ := New(path)
	for _, name := range []string{"env1", "env2"} {
		if _, ok := fresh.Get(name); !ok {
			t.Fatalf("fresh store should hold %s after both writes", name)
		}
	}
	// a can reload to observe b's write.
	if err := a.Reload(); err != nil {
		t.Fatal(err)
	}
	if _, ok := a.Get("env2"); !ok {
		t.Fatal("a after Reload should observe env2")
	}
}

func TestCollisionHelper(t *testing.T) {
	ids := map[string]vpn.Identity{"a": {V4: "8.8.8.8"}}
	for _, tc := range []struct {
		name string
		m    map[string]vpn.Identity
		id   vpn.Identity
		want bool
	}{
		{"collides", ids, vpn.Identity{V4: "8.8.8.8"}, true},
		{"distinct", ids, vpn.Identity{V4: "8.8.4.4"}, false},
		{"no-v4-ignored", ids, vpn.Identity{V4: ""}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := identityIn(tc.m, tc.id); got != tc.want {
				t.Fatalf("identityIn = %v, want %v", got, tc.want)
			}
		})
	}
}

func identityIn(m map[string]vpn.Identity, id vpn.Identity) bool {
	for _, e := range m {
		if id.V4 != "" && id.V4 == e.V4 {
			return true
		}
		if id.V6 != "" && e.V6 != "" && id.V6 == e.V6 {
			return true
		}
	}
	return false
}

func TestMain(m *testing.M) {
	os.Exit(m.Run())
}
