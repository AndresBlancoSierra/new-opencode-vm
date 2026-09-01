package vpn

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"
)

// reservation is one persisted VPN-server reservation or unsuitability mark.
type reservation struct {
	ServerKey  string    `json:"server_key"` // country:station
	InstanceID int       `json:"instance_id"`
	ExpiresAt  time.Time `json:"expires_at"`
	Unsuitable bool      `json:"unsuitable"`
}

// ReservationStore tracks which WireGuard servers are claimed by which environment
// (so two environments never pick the same server) and which servers have produced
// a colliding identity (so they are skipped). It is flock-protected for safety
// across concurrent `new` processes, and entries carry a TTL so a crashed allocator
// releases its claim automatically.
type ReservationStore struct {
	mu       sync.Mutex
	path     string
	lockPath string
}

// NewReservationStore returns a store persisting to path (default:
// ~/.local/state/lookingglass/reservations.json).
func NewReservationStore(path string) *ReservationStore {
	if path == "" {
		home, _ := os.UserHomeDir()
		path = filepath.Join(home, ".local", "state", "lookingglass", "reservations.json")
	}
	return &ReservationStore{path: path, lockPath: path + ".lock"}
}

func (r *ReservationStore) load() ([]reservation, error) {
	data, err := os.ReadFile(r.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var list []reservation
	if err := json.Unmarshal(data, &list); err != nil {
		return nil, err
	}
	return list, nil
}

func (r *ReservationStore) save(list []reservation) error {
	if err := os.MkdirAll(filepath.Dir(r.path), 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(r.path, b, 0o600)
}

// withLock runs fn under a cross-process flock, persisting the returned list.
func (r *ReservationStore) withLock(fn func(list []reservation) ([]reservation, error)) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	lk, err := os.OpenFile(r.lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return err
	}
	defer lk.Close()
	if err := syscall.Flock(int(lk.Fd()), syscall.LOCK_EX); err != nil {
		return err
	}
	defer syscall.Flock(int(lk.Fd()), syscall.LOCK_UN)
	list, err := r.load()
	if err != nil {
		return err
	}
	list, err = fn(list)
	if err != nil {
		return err
	}
	return r.save(list)
}

// Reserve claims serverKey for instanceID for ttl. It fails if the server is already
// reserved by a different instance or marked unsuitable.
func (r *ReservationStore) Reserve(key string, id int, ttl time.Duration) error {
	return r.withLock(func(list []reservation) ([]reservation, error) {
		now := time.Now()
		kept := list[:0]
		for _, x := range list {
			if x.ExpiresAt.After(now) {
				kept = append(kept, x)
			}
		}
		list = kept
		for _, x := range list {
			if x.ServerKey != key {
				continue
			}
			if x.Unsuitable {
				return list, fmt.Errorf("server %s is unsuitable", key)
			}
			if x.InstanceID != id {
				return list, fmt.Errorf("server %s reserved by instance %d", key, x.InstanceID)
			}
		}
		list = append(list, reservation{ServerKey: key, InstanceID: id, ExpiresAt: now.Add(ttl)})
		return list, nil
	})
}

// Release drops a (non-unsuitable) reservation for serverKey.
func (r *ReservationStore) Release(key string) error {
	return r.withLock(func(list []reservation) ([]reservation, error) {
		out := list[:0]
		for _, x := range list {
			if x.ServerKey != key || x.Unsuitable {
				out = append(out, x)
			}
		}
		return out, nil
	})
}

// MarkUnsuitable records that serverKey yields a colliding identity, so it is
// skipped for ttl even after its reservation is released.
func (r *ReservationStore) MarkUnsuitable(key string, ttl time.Duration) error {
	return r.withLock(func(list []reservation) ([]reservation, error) {
		now := time.Now()
		kept := list[:0]
		for _, x := range list {
			if x.ServerKey == key && !x.Unsuitable {
				continue
			}
			kept = append(kept, x)
		}
		kept = append(kept, reservation{ServerKey: key, InstanceID: -1, ExpiresAt: now.Add(ttl), Unsuitable: true})
		return kept, nil
	})
}

// IsReservedByOther reports whether serverKey is currently held by another instance.
func (r *ReservationStore) IsReservedByOther(key string, id int) bool {
	list, err := r.load()
	if err != nil || list == nil {
		return false
	}
	now := time.Now()
	for _, x := range list {
		if x.ServerKey == key && x.ExpiresAt.After(now) && !x.Unsuitable && x.InstanceID != id {
			return true
		}
	}
	return false
}

// IsUnsuitable reports whether serverKey is currently marked unsuitable.
func (r *ReservationStore) IsUnsuitable(key string) bool {
	list, err := r.load()
	if err != nil || list == nil {
		return false
	}
	now := time.Now()
	for _, x := range list {
		if x.ServerKey == key && x.Unsuitable && x.ExpiresAt.After(now) {
			return true
		}
	}
	return false
}
