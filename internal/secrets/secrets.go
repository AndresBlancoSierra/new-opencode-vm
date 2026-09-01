// Package secrets provides a minimal, file-based secret store. Secrets are read
// from a JSON file (mode 0600) or from environment variables, and are injected into
// a guest at runtime via a per-environment directory that is bind-mounted read-only
// into the guest's /run/secrets. They are NEVER written into the guest rootfs, so
// they do not survive a snapshot and are not visible to other environments.
package secrets

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Store holds secret key/value pairs.
type Store struct {
	path string
	data map[string]string
}

// Load reads secrets from path (JSON object). Environment variables override file
// values when they share the same key. A missing file yields an empty store.
func Load(path string) (*Store, error) {
	s := &Store{path: path, data: map[string]string{}}
	if path == "" {
		s.loadEnv()
		return s, nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			s.loadEnv()
			return s, nil
		}
		return nil, fmt.Errorf("read secrets %s: %w", path, err)
	}
	if err := json.Unmarshal(b, &s.data); err != nil {
		return nil, fmt.Errorf("parse secrets %s: %w", path, err)
	}
	s.loadEnv()
	return s, nil
}

func (s *Store) loadEnv() {
	// File values can be overridden by a same-named environment variable.
	for k := range s.data {
		if ev, ok := os.LookupEnv(k); ok {
			s.data[k] = ev
		}
	}
	// Secrets may also be supplied purely via the environment using the
	// LG_SECRET_<NAME> prefix (e.g. LG_SECRET_NORDVPN_TOKEN), which is handy in
	// CI / containerized runs where no secrets file is mounted.
	for _, e := range os.Environ() {
		if strings.HasPrefix(e, "LG_SECRET_") {
			kv := strings.SplitN(e, "=", 2)
			if len(kv) == 2 {
				name := strings.ToLower(strings.TrimPrefix(kv[0], "LG_SECRET_"))
				s.data[name] = kv[1]
			}
		}
	}
}

// Get returns a secret value.
func (s *Store) Get(key string) (string, error) {
	v, ok := s.data[key]
	if !ok || v == "" {
		return "", fmt.Errorf("secret %q not found", key)
	}
	return v, nil
}

// Has reports whether a key exists and is non-empty.
func (s *Store) Has(key string) bool {
	v, ok := s.data[key]
	return ok && v != ""
}

// Keys lists available secret keys.
func (s *Store) Keys() []string {
	ks := make([]string, 0, len(s.data))
	for k := range s.data {
		ks = append(ks, k)
	}
	return ks
}

// Set stores key/value and persists the store to its backing file (mode 0600).
func (s *Store) Set(key, value string) error {
	s.data[key] = value
	return s.Save()
}

// Save writes the store back to its backing file (mode 0600). A store with no
// configured path cannot be persisted.
func (s *Store) Save() error {
	if s.path == "" {
		return fmt.Errorf("secrets: no backing file configured (cannot persist)")
	}
	b, err := json.MarshalIndent(s.data, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.path, b, 0o600)
}

// InjectDir materializes the requested secret keys into a per-environment directory
// under baseDir/<name>/secrets (one file per key, mode 0600) and returns that path.
// The caller bind-mounts it read-only into the guest. Files are written fresh each
// call so revoked/rotated values take effect on next launch.
func (s *Store) InjectDir(baseDir, name string, keys []string) (string, error) {
	dir := filepath.Join(baseDir, name, "secrets")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	for _, k := range keys {
		v, err := s.Get(k)
		if err != nil {
			// Skip unavailable optional secrets rather than failing the whole launch.
			continue
		}
		if err := os.WriteFile(filepath.Join(dir, k), []byte(v), 0o600); err != nil {
			return "", fmt.Errorf("write secret %s: %w", k, err)
		}
	}
	return dir, nil
}
