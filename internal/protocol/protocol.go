// Package protocol defines the wire format shared by the server and the
// client. Application frames after login are encrypted by secure.FrameCipher;
// the JSON types here are what travels inside those frames.
package protocol

import (
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/guaidao2/ctf-blackboard/internal/model"
)

const (
	Version = 2

	TypeHello     = "hello"
	TypeChallenge = "challenge"
	TypeAuth      = "auth"
	TypeWelcome   = "welcome"
	TypeError     = "error"
	TypeRequest   = "req"
	TypeResponse  = "resp"
	TypeEvent     = "event"

	// Event names.
	EventSnapshot     = "snapshot"
	EventBoard        = "board"
	EventMessage      = "message"
	EventSolverUpsert = "solver.upsert"
	EventSolverDelete = "solver.delete"
	EventSlotUpsert   = "slot.upsert"
	EventSettings     = "settings"
	EventActivity     = "activity"
	EventKicked       = "kicked"
	EventError        = "server.error"
)

// Commands.
const (
	CmdChatSend       = "chat.send"
	CmdSolverAdd      = "solver.add"
	CmdSolverGet      = "solver.get"
	CmdSolverUpdate   = "solver.update"
	CmdSolverDelete   = "solver.delete"
	CmdSlotOpen       = "slot.open"
	CmdSlotUpdate     = "slot.update"
	CmdSlotRelease    = "slot.release"
	CmdSettingsUpdate = "settings.update"
	CmdKick           = "kick"
	CmdStateGet       = "state.get"
)

// Envelope is the single frame shape for handshake messages, requests,
// responses and events.
type Envelope struct {
	Type    string          `json:"t"`
	ID      string          `json:"id,omitempty"`
	ReplyTo string          `json:"re,omitempty"`
	Name    string          `json:"n,omitempty"`
	OK      bool            `json:"ok,omitempty"`
	Error   string          `json:"err,omitempty"`
	Data    json.RawMessage `json:"d,omitempty"`
}

// Hello is sent by the client in plaintext (inside TLS) before login.
type Hello struct {
	Version int    `json:"version"`
	Nick    string `json:"nick"`
	Nonce   string `json:"nonce"` // base64, 32 bytes
	Client  string `json:"client,omitempty"`
}

// Challenge is the server's login challenge. A fresh salt is used for every
// connection, so PBKDF2 work cannot be precomputed across sessions.
type Challenge struct {
	Version    int    `json:"version"`
	Server     string `json:"server"`
	Salt       string `json:"salt"` // base64, 16 bytes
	Nonce      string `json:"nonce"`
	Iterations int    `json:"iterations"`
}

// Auth carries the HMAC proof. The password itself is never sent.
type Auth struct {
	Proof string `json:"proof"` // base64
}

// Welcome proves the server knows the password and marks the start of the
// encrypted session.
type Welcome struct {
	Version int    `json:"version"`
	Server  string `json:"server"`
	You     string `json:"you"`
	Proof   string `json:"proof"` // base64
}

// Request is the payload of an application request.
type Request struct {
	Cmd  string          `json:"cmd"`
	Args json.RawMessage `json:"args,omitempty"`
}

// Snapshot is the complete client view sent after login and on reconnect.
type Snapshot struct {
	You      string           `json:"you"`
	Settings model.Settings   `json:"settings"`
	Solvers  []model.Solver   `json:"solvers"`
	Slots    []model.Slot     `json:"slots"`
	Chat     []model.Message  `json:"chat"`
	Activity []model.Activity `json:"activity"`
	Board    model.Board      `json:"board"`
}

// ---- command arguments ----

type ChatSendArgs struct {
	Text string `json:"text"`
}

type SolverAddArgs struct {
	Challenge string `json:"challenge"`
	Nick      string `json:"nick"`
	Writeup   string `json:"writeup"`
}

type SolverUpdateArgs struct {
	ID        string `json:"id"`
	Challenge string `json:"challenge"`
	Nick      string `json:"nick"`
	Writeup   string `json:"writeup"`
}

type IDArgs struct {
	ID string `json:"id"`
}

type SlotOpenArgs struct {
	Challenge string `json:"challenge"`
	URL       string `json:"url"`
	Notes     string `json:"notes"`
}

type SlotUpdateArgs struct {
	ID        string `json:"id"`
	Challenge string `json:"challenge"`
	URL       string `json:"url"`
	Notes     string `json:"notes"`
}

// SettingsUpdateArgs uses pointers so "not provided" is distinct from zero.
type SettingsUpdateArgs struct {
	TotalChallenges *int    `json:"total_challenges,omitempty"`
	SlotLimit       *int    `json:"slot_limit,omitempty"`
	Motd            *string `json:"motd,omitempty"`
}

type KickArgs struct {
	Nick string `json:"nick"`
}

// ---- command results / events ----

type SolverResult struct {
	Solver model.Solver `json:"solver"`
	Board  model.Board  `json:"board"`
}

type SolverDeleted struct {
	ID    string      `json:"id"`
	Board model.Board `json:"board"`
}

type SlotResult struct {
	Slot  model.Slot  `json:"slot"`
	Board model.Board `json:"board"`
}

type SettingsResult struct {
	Settings model.Settings `json:"settings"`
	Board    model.Board    `json:"board"`
}

type BoardEvent struct {
	Board model.Board `json:"board"`
}

type MessageEvent struct {
	Message model.Message `json:"message"`
}

type ActivityEvent struct {
	Activity model.Activity `json:"activity"`
}

type KickedEvent struct {
	By     string `json:"by"`
	Reason string `json:"reason"`
}

// NewEvent marshals data into an event envelope.
func NewEvent(name string, data any) (Envelope, error) {
	raw, err := marshalData(data)
	if err != nil {
		return Envelope{}, err
	}
	return Envelope{Type: TypeEvent, Name: name, Data: raw}, nil
}

// NewResponse marshals a successful response.
func NewResponse(id string, data any) Envelope {
	raw, err := marshalData(data)
	if err != nil {
		return Envelope{Type: TypeResponse, ReplyTo: id, Error: "internal encoding error"}
	}
	return Envelope{Type: TypeResponse, ReplyTo: id, OK: true, Data: raw}
}

// NewErrorResponse returns a failed response.
func NewErrorResponse(id, msg string) Envelope {
	return Envelope{Type: TypeResponse, ReplyTo: id, Error: msg}
}

// Decode unmarshals an envelope's data into v.
func Decode(env Envelope, v any) error {
	if len(env.Data) == 0 {
		return nil
	}
	if err := json.Unmarshal(env.Data, v); err != nil {
		return fmt.Errorf("decode %s: %w", env.Type, err)
	}
	return nil
}

// NewData Envelope helper for handshake messages.
func NewDataEnvelope(typ string, data any) (Envelope, error) {
	raw, err := marshalData(data)
	if err != nil {
		return Envelope{}, err
	}
	return Envelope{Type: typ, Data: raw}, nil
}

func marshalData(data any) (json.RawMessage, error) {
	if data == nil {
		return nil, nil
	}
	raw, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("encode data: %w", err)
	}
	return raw, nil
}

// B64 encodes bytes for the handshake JSON.
func B64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

// UnB64 decodes a handshake field and enforces an expected length when n > 0.
func UnB64(s string, n int) ([]byte, error) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("invalid base64 field")
	}
	if n > 0 && len(b) != n {
		return nil, fmt.Errorf("invalid field length")
	}
	return b, nil
}
