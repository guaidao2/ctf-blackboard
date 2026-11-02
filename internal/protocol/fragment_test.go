package protocol

import (
	"bytes"
	"testing"
	"time"
)

func TestFragmentRoundTrip(t *testing.T) {
	raw := bytes.Repeat([]byte("0123456789abcdef"), (2<<20)/16+17)
	frames, err := Split(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(frames) < 2 {
		t.Fatalf("expected multiple frames, got %d", len(frames))
	}
	for i, frame := range frames {
		if len(frame) > 1<<20 {
			t.Fatalf("fragment %d = %d bytes, exceeds 1 MiB", i, len(frame))
		}
	}
	var a Assembler
	var out []byte
	for i, frame := range frames {
		message, complete, err := a.Add(frame)
		if err != nil {
			t.Fatalf("fragment %d: %v", i, err)
		}
		if complete {
			out = message
		}
	}
	if !bytes.Equal(out, raw) {
		t.Fatalf("reassembled %d bytes, want %d", len(out), len(raw))
	}
}

func TestAssemblerPassesSmallMessages(t *testing.T) {
	raw := []byte(`{"t":"event","n":"message","d":{"text":"hi"}}`)
	var a Assembler
	out, complete, err := a.Add(raw)
	if err != nil || !complete || !bytes.Equal(out, raw) {
		t.Fatalf("passthrough failed: complete=%v err=%v", complete, err)
	}
}

func TestAssemblerRejectsOutOfOrder(t *testing.T) {
	raw := bytes.Repeat([]byte("x"), FragmentSize*2+1)
	frames, err := Split(raw)
	if err != nil {
		t.Fatal(err)
	}
	var a Assembler
	if _, _, err := a.Add(frames[1]); err == nil {
		t.Fatal("out-of-order first fragment was accepted")
	}
}

func TestSplitRejectsOversizeMessage(t *testing.T) {
	if _, err := Split(make([]byte, MaxMessageSize+1)); err == nil {
		t.Fatal("oversize logical message was accepted")
	}
}

func TestAssemblerEnforcesMessageBound(t *testing.T) {
	raw := bytes.Repeat([]byte("x"), FragmentSize*2)
	frames, err := Split(raw)
	if err != nil {
		t.Fatal(err)
	}
	var a Assembler
	a.Max = FragmentSize + 1
	if _, _, err := a.Add(frames[0]); err != nil {
		t.Fatal(err)
	}
	if _, _, err := a.Add(frames[1]); err == nil {
		t.Fatal("reassembly limit was not enforced")
	}
}

func TestAssemblerTimesOutStalledFragments(t *testing.T) {
	raw := bytes.Repeat([]byte("y"), FragmentSize+1)
	frames, err := Split(raw)
	if err != nil {
		t.Fatal(err)
	}
	var a Assembler
	a.Timeout = time.Millisecond
	if _, _, err := a.Add(frames[0]); err != nil {
		t.Fatal(err)
	}
	time.Sleep(5 * time.Millisecond)
	if _, _, err := a.Add(frames[1]); err == nil {
		t.Fatal("stalled fragment sequence was not timed out")
	}
}

func TestSplitLimitRejectsOversizeMessage(t *testing.T) {
	if _, err := SplitLimit(make([]byte, ClientRequestMax+1), ClientRequestMax); err == nil {
		t.Fatal("oversize request was accepted")
	}
}

func TestAssemblerRejectsMidFragmentMessage(t *testing.T) {
	raw := bytes.Repeat([]byte("z"), FragmentSize+1)
	frames, err := Split(raw)
	if err != nil {
		t.Fatal(err)
	}
	var a Assembler
	if _, _, err := a.Add(frames[0]); err != nil {
		t.Fatal(err)
	}
	if _, _, err := a.Add([]byte(`{"t":"event"}`)); err == nil {
		t.Fatal("unfragmented message was accepted mid-fragment")
	}
}
