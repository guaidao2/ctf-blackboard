// Package store persists the blackboard as a plain JSON document with atomic
// replacement and a best-effort previous-version backup. Communication is
// encrypted; the file itself relies on the server's disk permissions.
package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/guaidao2/ctf-blackboard/internal/model"
)

const (
	stateFile  = "state.json"
	backupFile = "state.json.bak"
)

type Store struct {
	dir       string
	path      string
	mu        sync.Mutex
	recovered bool
}

// Open loads the state in dir, creating it with initial when absent. If the
// main document is corrupt or missing, a valid .bak is restored instead of
// discarding the blackboard.
func Open(dir string, initial model.Settings) (*Store, *model.State, bool, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, nil, false, fmt.Errorf("create data directory: %w", err)
	}
	s := &Store{dir: dir, path: filepath.Join(dir, stateFile)}
	backupPath := filepath.Join(dir, backupFile)

	raw, readErr := os.ReadFile(s.path)
	if readErr == nil {
		st, err := decodeState(raw)
		if err == nil {
			normalize(st, initial)
			return s, st, false, nil
		}
		readErr = err
	} else if !errors.Is(readErr, os.ErrNotExist) {
		return nil, nil, false, fmt.Errorf("read state: %w", readErr)
	}

	// Main document is absent or unusable; try the previous version.
	bakRaw, bakErr := os.ReadFile(backupPath)
	if bakErr == nil {
		st, err := decodeState(bakRaw)
		if err == nil {
			normalize(st, initial)
			if !errors.Is(readErr, os.ErrNotExist) {
				corruptPath := filepath.Join(s.dir, fmt.Sprintf("state.corrupt-%d.json", time.Now().Unix()))
				_ = os.Rename(s.path, corruptPath)
			}
			s.recovered = true
			if err := s.Save(st); err != nil {
				return nil, nil, false, fmt.Errorf("restore backup: %w", err)
			}
			return s, st, false, nil
		}
	}

	if errors.Is(readErr, os.ErrNotExist) {
		if bakErr == nil {
			return nil, nil, false, errors.New("state is missing and the backup is unreadable")
		}
		st := model.NewState(initial)
		if err := s.Save(st); err != nil {
			return nil, nil, false, err
		}
		return s, st, true, nil
	}
	return nil, nil, false, fmt.Errorf("parse state (corrupt or not a blackboard state file): %w", readErr)
}

func decodeState(raw []byte) (*model.State, error) {
	var st model.State
	if err := json.Unmarshal(raw, &st); err != nil {
		return nil, err
	}
	if st.Version != 1 {
		return nil, fmt.Errorf("unsupported state version %d", st.Version)
	}
	return &st, nil
}

// Recovered reports whether Open restored the state from .bak.
func (s *Store) Recovered() bool { return s.recovered }

// Save writes the state atomically and refreshes the .bak copy.
func (s *Store) Save(st *model.State) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if st == nil {
		return errors.New("nil state")
	}
	st.UpdatedAt = time.Now().UTC()
	normalize(st, st.Settings)

	raw, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return fmt.Errorf("encode state: %w", err)
	}
	raw = append(raw, '\n')

	tmp, err := os.CreateTemp(s.dir, ".state-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp state: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)

	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return fmt.Errorf("chmod temp state: %w", err)
	}
	if _, err := tmp.Write(raw); err != nil {
		tmp.Close()
		return fmt.Errorf("write temp state: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("sync temp state: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp state: %w", err)
	}

	// Best effort: keep the previous document before replacing it.
	copyFile(s.path, filepath.Join(s.dir, backupFile))

	if err := os.Rename(tmpName, s.path); err != nil {
		return fmt.Errorf("replace state: %w", err)
	}
	_ = os.Chmod(s.path, 0o600)
	return nil
}

// Path returns the state file location, for startup logging.
func (s *Store) Path() string { return s.path }

func normalize(st *model.State, fallback model.Settings) {
	if st.Solvers == nil {
		st.Solvers = []*model.Solver{}
	}
	if st.Slots == nil {
		st.Slots = []*model.Slot{}
	}
	if st.Chat == nil {
		st.Chat = []model.Message{}
	}
	if st.Activity == nil {
		st.Activity = []model.Activity{}
	}
	if st.Settings.ServerName == "" {
		st.Settings.ServerName = fallback.ServerName
	}
	// SlotLimit may legitimately be zero (no container slots), so it is not
	// filled from the startup default when loading an existing state.
	if st.CreatedAt.IsZero() {
		st.CreatedAt = time.Now().UTC()
	}
	if st.NextMessageID == 0 {
		for _, m := range st.Chat {
			if m.ID >= st.NextMessageID {
				st.NextMessageID = m.ID
			}
		}
	}
	if st.NextActivityID == 0 {
		for _, a := range st.Activity {
			if a.ID >= st.NextActivityID {
				st.NextActivityID = a.ID
			}
		}
	}
}

func copyFile(src, dst string) {
	in, err := os.Open(src)
	if err != nil {
		return
	}
	defer in.Close()

	tmp, err := os.CreateTemp(filepath.Dir(dst), ".bak-*.tmp")
	if err != nil {
		return
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)

	if _, err := io.Copy(tmp, in); err != nil {
		tmp.Close()
		return
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return
	}
	if err := tmp.Close(); err != nil {
		return
	}
	_ = os.Chmod(tmpName, 0o600)
	_ = os.Remove(dst)
	_ = os.Rename(tmpName, dst)
}
