package protocol

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sync/atomic"
	"time"
)

const (
	// FragmentSize is the raw payload carried by one encrypted frame before
	// base64 expansion. 640 KiB becomes ~854 KiB of JSON, safely below
	// secure.MaxFrameSize (1 MiB).
	FragmentSize = 640 << 10

	// MaxMessageSize is a transport memory-safety ceiling, not a state cap:
	// it is far above a tournament's realistic state and prevents a peer from
	// forcing unbounded reassembly buffers.
	MaxMessageSize = 64 << 20

	// ClientRequestMax is the server's inbound reassembly bound. Client
	// requests are small; keeping this separate avoids pinning snapshot-sized
	// buffers on the server.
	ClientRequestMax = 4 << 20

	fragmentTimeout = 30 * time.Second
)

var fragmentCounter atomic.Uint64

// Fragment is the JSON wrapper for one piece of a logical protocol message.
type Fragment struct {
	Type  string `json:"t"`
	ID    string `json:"id"`
	Seq   int    `json:"seq"`
	Total int    `json:"total"`
	Data  string `json:"d"`
}

// Split turns one logical message into one or more frame payloads, using the
// full MaxMessageSize bound.
func Split(raw []byte) ([][]byte, error) {
	return SplitLimit(raw, MaxMessageSize)
}

// SplitLimit is Split with an explicit logical-message bound. The receiver
// must accept at least the same limit.
func SplitLimit(raw []byte, limit int) ([][]byte, error) {
	if limit <= 0 {
		limit = MaxMessageSize
	}
	if len(raw) <= FragmentSize {
		return [][]byte{raw}, nil
	}
	if len(raw) > limit {
		return nil, fmt.Errorf("message is %d bytes, transport limit is %d", len(raw), limit)
	}
	total := (len(raw) + FragmentSize - 1) / FragmentSize
	id := fmt.Sprintf("f%d", fragmentCounter.Add(1))
	out := make([][]byte, 0, total)
	for seq := 0; seq < total; seq++ {
		start := seq * FragmentSize
		end := start + FragmentSize
		if end > len(raw) {
			end = len(raw)
		}
		frame, err := json.Marshal(Fragment{
			Type:  "frag",
			ID:    id,
			Seq:   seq,
			Total: total,
			Data:  base64.StdEncoding.EncodeToString(raw[start:end]),
		})
		if err != nil {
			return nil, err
		}
		out = append(out, frame)
	}
	return out, nil
}

// Assembler reconstructs logical messages from ordered fragments. It is used
// by exactly one reader goroutine per connection.
//
// Max may be set per direction: the server accepts only small client requests,
// while the client must accept a full snapshot. Zero means MaxMessageSize.
type Assembler struct {
	Max     int
	Timeout time.Duration

	active bool
	id     string
	total  int
	next   int
	size   int
	last   time.Time
	buf    bytes.Buffer
}

func (a *Assembler) limit() int {
	if a.Max > 0 && a.Max < MaxMessageSize {
		return a.Max
	}
	return MaxMessageSize
}

func (a *Assembler) timeout() time.Duration {
	if a.Timeout > 0 {
		return a.Timeout
	}
	return fragmentTimeout
}

func (a *Assembler) reset() {
	a.active = false
	a.id = ""
	a.total = 0
	a.next = 0
	a.size = 0
	a.last = time.Time{}
	// Do not keep a large backing array alive for the connection lifetime.
	a.buf = bytes.Buffer{}
}

// Add consumes one decrypted frame. It returns the complete message when the
// last fragment arrives. Non-fragment frames pass through unchanged.
func (a *Assembler) Add(raw []byte) ([]byte, bool, error) {
	var head struct {
		Type string `json:"t"`
	}
	if err := json.Unmarshal(raw, &head); err != nil {
		// Let the caller report the malformed application envelope.
		return raw, true, nil
	}
	if head.Type != "frag" {
		if a.active {
			a.reset()
			return nil, false, errors.New("unfragmented message arrived mid-fragment")
		}
		return raw, true, nil
	}

	if a.active && time.Since(a.last) > a.timeout() {
		a.reset()
		return nil, false, errors.New("fragment timeout")
	}

	var f Fragment
	if err := json.Unmarshal(raw, &f); err != nil {
		return nil, false, fmt.Errorf("parse fragment: %w", err)
	}
	if f.ID == "" || f.Total <= 0 || f.Total > maxFragments(a.limit()) || f.Seq < 0 || f.Seq >= f.Total {
		return nil, false, errors.New("invalid fragment header")
	}
	if f.Seq == 0 {
		if a.active {
			a.reset()
			return nil, false, errors.New("new fragment sequence started before the previous one completed")
		}
		a.active = true
		a.id = f.ID
		a.total = f.Total
		a.next = 0
		a.size = 0
		a.buf.Reset()
	}
	if !a.active || f.ID != a.id || f.Total != a.total || f.Seq != a.next {
		a.reset()
		return nil, false, errors.New("fragment sequence mismatch")
	}
	chunk, err := base64.StdEncoding.DecodeString(f.Data)
	if err != nil {
		a.reset()
		return nil, false, fmt.Errorf("decode fragment: %w", err)
	}
	if a.size+len(chunk) > a.limit() {
		a.reset()
		return nil, false, errors.New("reassembled message exceeds transport limit")
	}
	a.buf.Write(chunk)
	a.size += len(chunk)
	a.next++
	a.last = time.Now()
	if a.next != a.total {
		return nil, false, nil
	}
	out := append([]byte(nil), a.buf.Bytes()...)
	a.reset()
	return out, true, nil
}

func maxFragments(limit int) int {
	return (limit + FragmentSize - 1) / FragmentSize
}
