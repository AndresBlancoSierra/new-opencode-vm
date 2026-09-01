// Package allocator assigns persistent, unique instance IDs (#N) to Looking Glass
// environments. IDs are allocated under a cross-process flock so concurrent `new`
// invocations (each a separate process) never collide, and the counter is persisted
// to disk so IDs are never reused even across daemon/host restarts.
package allocator

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
)

// Allocator hands out unique, monotonic instance IDs.
type Allocator struct {
	mu       sync.Mutex // serializes in-process callers
	path     string     // counter file (holds the last allocated ID)
	lockPath string     // flock file guarding the read-increment-write
}

// New returns an Allocator persisting its counter at path (default:
// ~/.local/state/lookingglass/instances).
func New(path string) *Allocator {
	if path == "" {
		home, _ := os.UserHomeDir()
		path = filepath.Join(home, ".local", "state", "lookingglass", "instances")
	}
	return &Allocator{path: path, lockPath: path + ".lock"}
}

// Allocate reserves and returns the next unique instance ID (1-based). It is safe
// for concurrent processes: a flock serializes the read-increment-write, and the
// counter is persisted so IDs are never reused.
func (a *Allocator) Allocate() (int, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if err := os.MkdirAll(filepath.Dir(a.lockPath), 0o700); err != nil {
		return 0, fmt.Errorf("allocator mkdir: %w", err)
	}
	lk, err := os.OpenFile(a.lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return 0, fmt.Errorf("allocator lock open: %w", err)
	}
	defer lk.Close()
	if err := syscall.Flock(int(lk.Fd()), syscall.LOCK_EX); err != nil {
		return 0, fmt.Errorf("allocator flock: %w", err)
	}
	defer syscall.Flock(int(lk.Fd()), syscall.LOCK_UN)

	if err := os.MkdirAll(filepath.Dir(a.path), 0o700); err != nil {
		return 0, err
	}
	n := 0
	if data, rerr := os.ReadFile(a.path); rerr == nil {
		if v, perr := strconv.Atoi(strings.TrimSpace(string(data))); perr == nil {
			n = v
		}
	}
	n++
	if err := os.WriteFile(a.path, []byte(strconv.Itoa(n)), 0o600); err != nil {
		return 0, fmt.Errorf("allocator write: %w", err)
	}
	return n, nil
}

// Peek returns the last allocated ID without allocating a new one (0 if none).
func (a *Allocator) Peek() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	if data, err := os.ReadFile(a.path); err == nil {
		if v, err := strconv.Atoi(strings.TrimSpace(string(data))); err == nil {
			return v
		}
	}
	return 0
}
