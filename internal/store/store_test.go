package store

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/guaidao2/ctf-blackboard/internal/model"
)

func initial() model.Settings {
	return model.Settings{
		ServerName:      "test board",
		Motd:            "hello",
		SlotLimit:       5,
		TotalChallenges: 12,
	}
}

func TestOpenCreatesAndReloads(t *testing.T) {
	dir := t.TempDir()
	s, st, created, err := Open(dir, initial())
	if err != nil {
		t.Fatal(err)
	}
	if !created {
		t.Fatal("expected a new state")
	}
	if st.Settings.ServerName != "test board" || st.Settings.SlotLimit != 5 || st.Settings.TotalChallenges != 12 {
		t.Fatalf("unexpected initial settings: %+v", st.Settings)
	}
	if _, err := os.Stat(s.Path()); err != nil {
		t.Fatalf("state file missing: %v", err)
	}

	now := time.Now().UTC()
	st.Solvers = append(st.Solvers, &model.Solver{
		ID: "s1", Challenge: "ezsql", Nick: "alice", Writeup: "union select",
		CreatedBy: "alice", CreatedAt: now, UpdatedAt: now,
	})
	st.Slots = append(st.Slots, &model.Slot{
		ID: "c1", Challenge: "ezsql", Owner: "alice",
		Status: model.SlotActive, CreatedAt: now, UpdatedAt: now,
	})
	if err := s.Save(st); err != nil {
		t.Fatal(err)
	}

	s2, st2, created2, err := Open(dir, initial())
	if err != nil {
		t.Fatal(err)
	}
	if created2 {
		t.Fatal("reopened state should not be created")
	}
	if len(st2.Solvers) != 1 || st2.Solvers[0].Challenge != "ezsql" {
		t.Fatalf("solver was not persisted: %+v", st2.Solvers)
	}
	if len(st2.Slots) != 1 || st2.Slots[0].Challenge != "ezsql" {
		t.Fatalf("slot was not persisted: %+v", st2.Slots)
	}
	if st2.Settings.TotalChallenges != 12 {
		t.Fatalf("settings changed after reload: %+v", st2.Settings)
	}
	if s2.Path() != s.Path() {
		t.Fatalf("path changed: %s vs %s", s2.Path(), s.Path())
	}
}

func TestSaveKeepsPreviousBackup(t *testing.T) {
	dir := t.TempDir()
	s, st, _, err := Open(dir, initial())
	if err != nil {
		t.Fatal(err)
	}
	st.Solvers = append(st.Solvers, &model.Solver{ID: "s1", Challenge: "one", Nick: "a", CreatedAt: time.Now().UTC()})
	if err := s.Save(st); err != nil {
		t.Fatal(err)
	}
	st.Solvers = append(st.Solvers, &model.Solver{ID: "s2", Challenge: "two", Nick: "b", CreatedAt: time.Now().UTC()})
	if err := s.Save(st); err != nil {
		t.Fatal(err)
	}

	backup, err := os.ReadFile(filepath.Join(dir, backupFile))
	if err != nil {
		t.Fatalf("backup missing: %v", err)
	}
	var old model.State
	if err := json.Unmarshal(backup, &old); err != nil {
		t.Fatalf("backup is not valid JSON: %v", err)
	}
	if len(old.Solvers) != 1 || old.Solvers[0].Challenge != "one" {
		t.Fatalf("backup does not hold the previous document: %+v", old.Solvers)
	}

	main, err := os.ReadFile(s.Path())
	if err != nil {
		t.Fatal(err)
	}
	var cur model.State
	if err := json.Unmarshal(main, &cur); err != nil {
		t.Fatal(err)
	}
	if len(cur.Solvers) != 2 {
		t.Fatalf("current document has %d solvers", len(cur.Solvers))
	}

	tmps, _ := filepath.Glob(filepath.Join(dir, ".state-*.tmp"))
	if len(tmps) != 0 {
		t.Fatalf("temporary files left behind: %v", tmps)
	}
}

func TestNormalizeNextIDs(t *testing.T) {
	dir := t.TempDir()
	st := model.NewState(initial())
	st.Chat = []model.Message{{ID: 7, Text: "a"}, {ID: 9, Text: "b"}}
	st.Activity = []model.Activity{{ID: 3}, {ID: 4}}
	st.NextMessageID = 0
	st.NextActivityID = 0
	raw, err := json.Marshal(st)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, stateFile), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	_, got, _, err := Open(dir, initial())
	if err != nil {
		t.Fatal(err)
	}
	if got.NextMessageID != 9 {
		t.Fatalf("NextMessageID = %d, want 9", got.NextMessageID)
	}
	if got.NextActivityID != 4 {
		t.Fatalf("NextActivityID = %d, want 4", got.NextActivityID)
	}
}

func TestOpenRejectsCorruptOrUnknownState(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, stateFile), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := Open(dir, initial()); err == nil {
		t.Fatal("corrupt state was accepted")
	}

	dir2 := t.TempDir()
	st := model.NewState(initial())
	st.Version = 99
	raw, _ := json.Marshal(st)
	if err := os.WriteFile(filepath.Join(dir2, stateFile), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := Open(dir2, initial()); err == nil {
		t.Fatal("unsupported version was accepted")
	}
}

func TestStateHelpers(t *testing.T) {
	st := model.NewState(initial())
	st.Solvers = append(st.Solvers,
		&model.Solver{ID: "s1", Challenge: "EZSQL", Nick: "alice"},
		&model.Solver{ID: "s2", Challenge: "pwn1", Nick: "bob"},
	)
	st.Slots = append(st.Slots,
		&model.Slot{ID: "c1", Challenge: "ezsql", Owner: "alice", Status: model.SlotActive},
		&model.Slot{ID: "c2", Challenge: "pwn1", Owner: "alice", Status: model.SlotReleased},
		&model.Slot{ID: "c3", Challenge: "web3", Owner: "bob", Status: model.SlotActive},
	)
	if got := st.FindSolverByChallenge("ezsql"); got == nil || got.ID != "s1" {
		t.Fatalf("case-insensitive challenge lookup failed: %+v", got)
	}
	if got := st.FindSlot("c3"); got == nil || got.Challenge != "web3" {
		t.Fatalf("slot lookup failed: %+v", got)
	}
	if got := st.ActiveSlots(); got != 2 {
		t.Fatalf("ActiveSlots = %d, want 2", got)
	}
}

func TestOpenRecoversPreviousBackup(t *testing.T) {
	dir := t.TempDir()
	s, st, _, err := Open(dir, initial())
	if err != nil {
		t.Fatal(err)
	}
	st.Solvers = append(st.Solvers, &model.Solver{ID: "s1", Challenge: "one", Nick: "alice", CreatedAt: time.Now().UTC()})
	if err := s.Save(st); err != nil {
		t.Fatal(err)
	}
	st.Solvers = append(st.Solvers, &model.Solver{ID: "s2", Challenge: "two", Nick: "bob", CreatedAt: time.Now().UTC()})
	if err := s.Save(st); err != nil {
		t.Fatal(err)
	}
	// The main document is damaged after the second save; .bak holds the
	// previous valid document with the first solver.
	if err := os.WriteFile(filepath.Join(dir, stateFile), []byte("{broken"), 0o600); err != nil {
		t.Fatal(err)
	}

	s2, st2, created, err := Open(dir, initial())
	if err != nil {
		t.Fatalf("Open did not recover from backup: %v", err)
	}
	if created {
		t.Fatal("recovered state should not be reported as newly created")
	}
	if !s2.Recovered() {
		t.Fatal("Store.Recovered is false")
	}
	if len(st2.Solvers) != 1 || st2.Solvers[0].Challenge != "one" {
		t.Fatalf("unexpected recovered solvers: %+v", st2.Solvers)
	}
	corrupt, _ := filepath.Glob(filepath.Join(dir, "state.corrupt-*.json"))
	if len(corrupt) != 1 {
		t.Fatalf("corrupt document was not preserved: %v", corrupt)
	}
	raw, err := os.ReadFile(s2.Path())
	if err != nil {
		t.Fatal(err)
	}
	var restored model.State
	if err := json.Unmarshal(raw, &restored); err != nil {
		t.Fatalf("restored main document is invalid: %v", err)
	}
	if len(restored.Solvers) != 1 {
		t.Fatalf("restored main document has %d solvers", len(restored.Solvers))
	}
}
