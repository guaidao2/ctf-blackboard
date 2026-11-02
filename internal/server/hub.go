package server

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/guaidao2/ctf-blackboard/internal/model"
	"github.com/guaidao2/ctf-blackboard/internal/protocol"
	"github.com/guaidao2/ctf-blackboard/internal/store"
)

// Hub owns the state and every live connection. All mutations take mu, mutate
// state, persist it and broadcast the resulting view before releasing the lock.
type Hub struct {
	cfg   Config
	log   *slog.Logger
	state *model.State
	store *store.Store

	mu           sync.Mutex
	clients      map[*Client]struct{}
	byNick       map[string]*Client
	kickCooldown map[string]time.Time
	limiter      *loginLimiter
	closed       bool
}

func newHub(cfg Config, st *model.State, storer *store.Store) *Hub {
	return &Hub{
		cfg:          cfg,
		log:          cfg.Logger,
		state:        st,
		store:        storer,
		clients:      map[*Client]struct{}{},
		byNick:       map[string]*Client{},
		kickCooldown: map[string]time.Time{},
		limiter:      newLoginLimiter(8, 5*time.Minute, 5*time.Minute),
	}
}

func (h *Hub) snapshotLocked(you string) protocol.Snapshot {
	solvers := make([]model.Solver, 0, len(h.state.Solvers))
	for _, sv := range h.state.Solvers {
		cp := *sv
		cp.HasWriteup = strings.TrimSpace(cp.Writeup) != ""
		// Writeups are fetched on demand so a large blackboard still fits in
		// one encrypted frame.
		cp.Writeup = ""
		solvers = append(solvers, cp)
	}
	sort.SliceStable(solvers, func(i, j int) bool {
		return solvers[i].CreatedAt.After(solvers[j].CreatedAt)
	})

	slots := make([]model.Slot, 0, len(h.state.Slots))
	for _, sl := range h.state.Slots {
		slots = append(slots, *sl)
	}
	sort.SliceStable(slots, func(i, j int) bool {
		if slots[i].Active() != slots[j].Active() {
			return slots[i].Active()
		}
		return slots[i].CreatedAt.After(slots[j].CreatedAt)
	})

	chat := lastMessages(h.state.Chat, 100)
	activity := lastActivity(h.state.Activity, 100)

	return protocol.Snapshot{
		You:      you,
		Settings: h.state.Settings,
		Solvers:  solvers,
		Slots:    slots,
		Chat:     chat,
		Activity: activity,
		Board:    h.boardLocked(),
	}
}

func (h *Hub) settings() model.Settings {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.state.Settings
}

func (h *Hub) boardLocked() model.Board {
	operators := make([]model.Operator, 0, len(h.clients))
	for c := range h.clients {
		operators = append(operators, model.Operator{
			Nick:     c.nick,
			JoinedAt: c.joined,
			Remote:   c.remote,
		})
	}
	sort.SliceStable(operators, func(i, j int) bool {
		return operators[i].JoinedAt.Before(operators[j].JoinedAt)
	})

	return model.Board{
		ServerName:       h.state.Settings.ServerName,
		Motd:             h.state.Settings.Motd,
		TotalChallenges:  h.state.Settings.TotalChallenges,
		SolvedChallenges: len(h.state.Solvers),
		ActiveSlots:      h.state.ActiveSlots(),
		SlotLimit:        h.state.Settings.SlotLimit,
		Operators:        operators,
		ServerTime:       time.Now().UTC(),
	}
}

func (h *Hub) broadcastLocked(name string, data any) {
	env, err := protocol.NewEvent(name, data)
	if err != nil {
		h.log.Error("cannot encode event", "event", name, "err", err)
		return
	}
	raw, err := json.Marshal(env)
	if err != nil {
		h.log.Error("cannot marshal event", "event", name, "err", err)
		return
	}
	for c := range h.clients {
		c.enqueue(raw)
	}
}

func (h *Hub) sendEventLocked(c *Client, name string, data any) {
	env, err := protocol.NewEvent(name, data)
	if err != nil {
		h.log.Error("cannot encode event", "event", name, "err", err)
		return
	}
	raw, err := json.Marshal(env)
	if err != nil {
		h.log.Error("cannot marshal event", "event", name, "err", err)
		return
	}
	c.enqueue(raw)
}

func (h *Hub) broadcastBoardLocked() {
	h.broadcastLocked(protocol.EventBoard, protocol.BoardEvent{Board: h.boardLocked()})
}

// addChatLocked assigns an ID, trims history and broadcasts the message.
func (h *Hub) addChatLocked(nick, text, kind string) model.Message {
	h.state.NextMessageID++
	msg := model.Message{
		ID:   h.state.NextMessageID,
		Nick: nick,
		Text: text,
		At:   time.Now().UTC(),
		Kind: kind,
	}
	h.state.Chat = append(h.state.Chat, msg)
	if len(h.state.Chat) > h.cfg.MaxChatHistory {
		h.state.Chat = append([]model.Message(nil), h.state.Chat[len(h.state.Chat)-h.cfg.MaxChatHistory:]...)
	}
	h.broadcastLocked(protocol.EventMessage, protocol.MessageEvent{Message: msg})
	return msg
}

func (h *Hub) addActivityLocked(nick, kind, text string) model.Activity {
	h.state.NextActivityID++
	act := model.Activity{
		ID:   h.state.NextActivityID,
		At:   time.Now().UTC(),
		Nick: nick,
		Kind: kind,
		Text: text,
	}
	h.state.Activity = append(h.state.Activity, act)
	if len(h.state.Activity) > h.cfg.MaxActivity {
		h.state.Activity = append([]model.Activity(nil), h.state.Activity[len(h.state.Activity)-h.cfg.MaxActivity:]...)
	}
	h.broadcastLocked(protocol.EventActivity, protocol.ActivityEvent{Activity: act})
	return act
}

func (h *Hub) saveLocked() error {
	if err := h.store.Save(h.state); err != nil {
		h.log.Error("cannot persist state", "err", err)
		return fmt.Errorf("写入磁盘失败：%v", err)
	}
	return nil
}

func (h *Hub) removeClient(c *Client) {
	h.mu.Lock()
	if _, ok := h.clients[c]; ok {
		delete(h.clients, c)
		key := lowerNick(c.nick)
		if h.byNick[key] == c {
			delete(h.byNick, key)
		}
		if !h.closed {
			h.broadcastBoardLocked()
		}
	}
	h.mu.Unlock()
	c.close()
	c.log.Info("operator disconnected")
}

func (h *Hub) shutdown() {
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		return
	}
	h.closed = true
	clients := make([]*Client, 0, len(h.clients))
	for c := range h.clients {
		clients = append(clients, c)
	}
	h.mu.Unlock()

	for _, c := range clients {
		c.close()
	}

	h.mu.Lock()
	defer h.mu.Unlock()
	if err := h.store.Save(h.state); err != nil {
		h.log.Error("cannot persist state during shutdown", "err", err)
	} else {
		h.log.Info("state saved", "file", h.store.Path())
	}
}

func (h *Hub) nickTakenLocked(nick string) bool {
	_, ok := h.byNick[lowerNick(nick)]
	return ok
}

func (h *Hub) findClientLocked(nick string) *Client {
	return h.byNick[lowerNick(nick)]
}

func (h *Hub) kickRemaining(nick string) time.Duration {
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.kickCooldown) > 1024 {
		now := time.Now()
		for k, until := range h.kickCooldown {
			if now.After(until) {
				delete(h.kickCooldown, k)
			}
		}
	}
	until, ok := h.kickCooldown[lowerNick(nick)]
	if !ok {
		return 0
	}
	if time.Now().After(until) {
		delete(h.kickCooldown, lowerNick(nick))
		return 0
	}
	return time.Until(until)
}

func lowerNick(nick string) string { return strings.ToLower(strings.TrimSpace(nick)) }

func lastMessages(in []model.Message, n int) []model.Message {
	if len(in) <= n {
		return append([]model.Message(nil), in...)
	}
	return append([]model.Message(nil), in[len(in)-n:]...)
}

func lastActivity(in []model.Activity, n int) []model.Activity {
	if len(in) <= n {
		return append([]model.Activity(nil), in...)
	}
	return append([]model.Activity(nil), in[len(in)-n:]...)
}

func newID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("%x", time.Now().UnixNano())
	}
	return hex.EncodeToString(b[:])
}
