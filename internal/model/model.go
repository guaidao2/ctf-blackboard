// Package model holds the domain objects of the blackboard. Everything in
// State is persisted by the server; presence and transport details are not.
package model

import (
	"strings"
	"time"
)

const (
	SlotActive   = "active"
	SlotReleased = "released"

	MessageChat   = "chat"
	MessageSystem = "system"
	MessageSolve  = "solve"
)

// Operator is a live connection. It is never persisted.
type Operator struct {
	Nick     string    `json:"nick"`
	JoinedAt time.Time `json:"joined_at"`
	Remote   string    `json:"remote,omitempty"`
}

// Solver is one solved challenge: the final person who submitted the flag and
// the writeup for it. A challenge has at most one Solver entry.
type Solver struct {
	ID         string    `json:"id"`
	Challenge  string    `json:"challenge"`
	Nick       string    `json:"nick"`
	Writeup    string    `json:"writeup,omitempty"`
	HasWriteup bool      `json:"has_writeup"`
	CreatedBy  string    `json:"created_by"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

// Slot is one container slot in the competition. It records which challenge
// instance is open and who opened it. Opening is refused when all slots are
// active, so a new container cannot silently evict an old one.
type Slot struct {
	ID         string    `json:"id"`
	Challenge  string    `json:"challenge"`
	Owner      string    `json:"owner"`
	URL        string    `json:"url,omitempty"`
	Notes      string    `json:"notes,omitempty"`
	Status     string    `json:"status"`
	CreatedAt  time.Time `json:"created_at"`
	ReleasedAt time.Time `json:"released_at,omitempty"`
	UpdatedAt  time.Time `json:"updated_at"`
}

func (s *Slot) Active() bool { return s.Status == SlotActive }

// Message is one persisted chat entry. ID is monotonic and is the client's
// replay cursor.
type Message struct {
	ID   int64     `json:"id"`
	Nick string    `json:"nick"`
	Text string    `json:"text"`
	At   time.Time `json:"at"`
	Kind string    `json:"kind"`
}

// Activity is the persisted operational feed (solver added, slot opened,
// kick, settings changed, ...).
type Activity struct {
	ID   int64     `json:"id"`
	At   time.Time `json:"at"`
	Nick string    `json:"nick"`
	Kind string    `json:"kind"`
	Text string    `json:"text"`
}

// Settings are the mutable knobs of the blackboard. TotalChallenges is edited
// as the competition adds challenges; SlotLimit is the hard container cap.
type Settings struct {
	ServerName      string `json:"server_name"`
	Motd            string `json:"motd"`
	SlotLimit       int    `json:"slot_limit"`
	TotalChallenges int    `json:"total_challenges"`
}

// Board is the compact situation report shown in the header.
type Board struct {
	ServerName       string     `json:"server_name"`
	Motd             string     `json:"motd"`
	TotalChallenges  int        `json:"total_challenges"`
	SolvedChallenges int        `json:"solved_challenges"`
	ActiveSlots      int        `json:"active_slots"`
	SlotLimit        int        `json:"slot_limit"`
	Operators        []Operator `json:"operators"`
	ServerTime       time.Time  `json:"server_time"`
}

// State is the complete persisted blackboard.
type State struct {
	Version        int        `json:"version"`
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
	Settings       Settings   `json:"settings"`
	Solvers        []*Solver  `json:"solvers"`
	Slots          []*Slot    `json:"slots"`
	Chat           []Message  `json:"chat"`
	Activity       []Activity `json:"activity"`
	NextMessageID  int64      `json:"next_message_id"`
	NextActivityID int64      `json:"next_activity_id"`
}

func NewState(settings Settings) *State {
	now := time.Now().UTC()
	return &State{
		Version:   1,
		CreatedAt: now,
		UpdatedAt: now,
		Settings:  settings,
		Solvers:   []*Solver{},
		Slots:     []*Slot{},
		Chat:      []Message{},
		Activity:  []Activity{},
	}
}

func (s *State) FindSolver(ref string) *Solver {
	ref = strings.TrimSpace(ref)
	for _, sv := range s.Solvers {
		if sv.ID == ref {
			return sv
		}
	}
	return nil
}

func (s *State) FindSolverByChallenge(name string) *Solver {
	name = strings.TrimSpace(name)
	for _, sv := range s.Solvers {
		if strings.EqualFold(sv.Challenge, name) {
			return sv
		}
	}
	return nil
}

func (s *State) FindSlot(ref string) *Slot {
	ref = strings.TrimSpace(ref)
	for _, sl := range s.Slots {
		if sl.ID == ref {
			return sl
		}
	}
	return nil
}

func (s *State) ActiveSlots() int {
	n := 0
	for _, sl := range s.Slots {
		if sl.Active() {
			n++
		}
	}
	return n
}
