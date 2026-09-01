// Package state tracks environment records across CLI invocations. It is the
// trimmed equivalent of LookingGlass's daemon package (no daemon loop, no TTL
// scheduling): it only persists which VMs are live and their measured egress
// identities, so concurrent `new` processes can detect VPN-IP collisions. State
// is persisted as JSON with a cross-process flock so writers never clobber each
// other (atomic temp-file + rename).
package state

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"new-opencode-vm/internal/backend"
	"new-opencode-vm/internal/config"
	"new-opencode-vm/internal/vpn"
)

// Record is a persisted VM record.
type Record struct {
	Name      string                 `json:"name"`
	Country   string                 `json:"country"`
	Rootfs    string                 `json:"rootfs"`
	Backend   string                 `json:"backend"` // nspawn
	VPN       bool                   `json:"vpn"`
	Projects  []backend.ProjectMount `json:"projects"`
	CreatedAt time.Time              `json:"created_at"`

	InstanceID int    `json:"instance_id"`
	Region     string `json:"region"`
	VPNV4      string `json:"vpn_v4"`
	VPNV6      string `json:"vpn_v6"`
}

// Store is the on-disk + in-memory VM registry.
type Store struct {
	mu       sync.Mutex
	path     string
	lockPath string
	envs     map[string]Record
	removed  map[string]bool
}

// New loads (or initializes) state from path.
func New(path string) (*Store, error) {
	p := config.ExpandPath(path)
	s := &Store{path: p, lockPath: p + ".lock", envs: map[string]Record{}, removed: map[string]bool{}}
	if b, err := os.ReadFile(p); err == nil {
		_ = json.Unmarshal(b, &s.envs)
	}
	return s, nil
}

// Register adds/updates a record and persists.
func (s *Store) Register(r Record) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.envs[r.Name] = r
	delete(s.removed, r.Name)
	return s.persist()
}

// Remove deletes a record and persists.
func (s *Store) Remove(name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.envs, name)
	s.removed[name] = true
	return s.persist()
}

// Get returns a record.
func (s *Store) Get(name string) (Record, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.envs[name]
	return r, ok
}

// List returns all records.
func (s *Store) List() []Record {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Record, 0, len(s.envs))
	for _, r := range s.envs {
		out = append(out, r)
	}
	return out
}

// Reload re-reads the on-disk state so a long-running process observes records
// registered by other `new` processes (e.g. a concurrent VM's egress IP).
func (s *Store) Reload() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			s.envs = map[string]Record{}
			return nil
		}
		return err
	}
	envs := map[string]Record{}
	if err := json.Unmarshal(b, &envs); err != nil {
		return err
	}
	s.envs = envs
	return nil
}

// ActiveIdentities returns the measured VPN identities of live VMs. Used by the
// egress-dedup safety net.
func (s *Store) ActiveIdentities() map[string]vpn.Identity {
	s.mu.Lock()
	defer s.mu.Unlock()
	m := map[string]vpn.Identity{}
	for _, r := range s.envs {
		if r.VPNV4 == "" && r.VPNV6 == "" {
			continue
		}
		m[r.Name] = vpn.Identity{V4: r.VPNV4, V6: r.VPNV6}
	}
	return m
}

// persist writes state to disk atomically with a cross-process flock so
// concurrent `new` processes never clobber each other's records.
func (s *Store) persist() error {
	lk, err := os.OpenFile(s.lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return err
	}
	defer lk.Close()
	if err := syscall.Flock(int(lk.Fd()), syscall.LOCK_EX); err != nil {
		return err
	}
	defer syscall.Flock(int(lk.Fd()), syscall.LOCK_UN)

	disk := map[string]Record{}
	if b, rerr := os.ReadFile(s.path); rerr == nil {
		_ = json.Unmarshal(b, &disk)
	}
	merged := disk
	for k := range s.removed {
		delete(merged, k)
	}
	for k, v := range s.envs {
		merged[k] = v
	}

	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(merged, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}
