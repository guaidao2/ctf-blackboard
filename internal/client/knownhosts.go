package client

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/guaidao2/ctf-blackboard/internal/secure"
)

type knownHostEntry struct {
	Pin       string    `json:"pin"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
}

type knownHostsDoc struct {
	Version int                        `json:"version"`
	Hosts   map[string]*knownHostEntry `json:"hosts"`
}

// KnownHosts remembers accepted server fingerprints, like SSH's known_hosts.
// The file lives in the per-user config directory and is written 0600.
type KnownHosts struct {
	path string

	mu    sync.Mutex
	hosts map[string]*knownHostEntry
}

// DefaultKnownHostsPath returns e.g. %AppData%\ctfbb\known_hosts.json on
// Windows, ~/.config/ctfbb/known_hosts.json on Linux.
func DefaultKnownHostsPath() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		home, herr := os.UserHomeDir()
		if herr != nil {
			return "", fmt.Errorf("cannot locate user config directory: %w", err)
		}
		dir = filepath.Join(home, ".config")
	}
	return filepath.Join(dir, "ctfbb", "known_hosts.json"), nil
}

// LoadKnownHosts loads the known-hosts file. A missing file is an empty set.
func LoadKnownHosts(path string) (*KnownHosts, error) {
	k := &KnownHosts{path: path, hosts: map[string]*knownHostEntry{}}
	if path == "" {
		return k, nil
	}
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return k, nil
	}
	if err != nil {
		return nil, err
	}
	var doc knownHostsDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("parse known_hosts: %w", err)
	}
	if doc.Version != 0 && doc.Version != 1 {
		return nil, fmt.Errorf("unsupported known_hosts version %d", doc.Version)
	}
	for server, entry := range doc.Hosts {
		if entry != nil && entry.Pin != "" {
			k.hosts[normalizeServerKey(server)] = entry
		}
	}
	return k, nil
}

func newKnownHosts(path string) *KnownHosts {
	return &KnownHosts{path: path, hosts: map[string]*knownHostEntry{}}
}

// Path returns the known_hosts location.
func (k *KnownHosts) Path() string { return k.path }

// Lookup returns the remembered fingerprint for a server URL.
func (k *KnownHosts) Lookup(server string) (string, bool) {
	k.mu.Lock()
	defer k.mu.Unlock()
	entry, ok := k.hosts[normalizeServerKey(server)]
	if !ok || entry.Pin == "" {
		return "", false
	}
	return entry.Pin, true
}

// Remember stores (or refreshes) the accepted fingerprint.
func (k *KnownHosts) Remember(server, pin string) error {
	canonical, err := secure.NormalizeFingerprint(pin)
	if err != nil {
		return err
	}
	server = normalizeServerKey(server)
	if server == "" {
		return errors.New("empty server URL")
	}

	k.mu.Lock()
	defer k.mu.Unlock()
	now := time.Now().UTC()
	if entry := k.hosts[server]; entry != nil {
		entry.Pin = canonical
		entry.LastSeen = now
	} else {
		k.hosts[server] = &knownHostEntry{Pin: canonical, FirstSeen: now, LastSeen: now}
	}
	return k.saveLocked()
}

// normalizeServerKey makes URL spellings that point at the same endpoint share
// one entry (case, trailing slash, fragment).
func normalizeServerKey(raw string) string {
	s := strings.TrimSpace(raw)
	u, err := url.Parse(s)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return strings.TrimRight(s, "/")
	}
	u.Scheme = strings.ToLower(u.Scheme)
	u.Host = strings.ToLower(u.Host)
	u.Path = strings.TrimRight(u.Path, "/")
	u.RawQuery = ""
	u.Fragment = ""
	return u.String()
}

func (k *KnownHosts) saveLocked() error {
	if k.path == "" {
		return errors.New("known_hosts path is empty")
	}
	if err := os.MkdirAll(filepath.Dir(k.path), 0o700); err != nil {
		return fmt.Errorf("create known_hosts directory: %w", err)
	}
	raw, err := json.MarshalIndent(knownHostsDoc{Version: 1, Hosts: k.hosts}, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')

	tmp, err := os.CreateTemp(filepath.Dir(k.path), ".known-hosts-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(raw); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, k.path); err != nil {
		return err
	}
	_ = os.Chmod(k.path, 0o600)
	return nil
}
