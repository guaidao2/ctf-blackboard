package secure

import (
	"bytes"
	"crypto/sha256"
	"testing"
)

func fixedNonces() ([]byte, []byte) {
	c := bytes.Repeat([]byte{0x11}, 32)
	s := bytes.Repeat([]byte{0x22}, 32)
	return c, s
}

func TestLoginKeyAndProofs(t *testing.T) {
	salt := bytes.Repeat([]byte{0x33}, 16)
	c, s := fixedNonces()

	key1, err := DeriveLoginKey("correct horse battery staple", salt, MinIterations)
	if err != nil {
		t.Fatal(err)
	}
	key2, err := DeriveLoginKey("correct horse battery staple", salt, MinIterations)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(key1, key2) {
		t.Fatal("PBKDF2 is not deterministic")
	}
	if len(key1) != KeyLen {
		t.Fatalf("key length = %d", len(key1))
	}

	cp := ClientProof(key1, "alice", c, s)
	if !VerifyMAC(cp, ClientProof(key2, "alice", c, s)) {
		t.Fatal("client proof did not verify")
	}
	if VerifyMAC(cp, ClientProof(key2, "mallory", c, s)) {
		t.Fatal("proof must be bound to the nickname")
	}
	if VerifyMAC(cp, ServerProof(key2, "alice", c, s)) {
		t.Fatal("client and server proofs must use different labels")
	}
	if VerifyMAC(cp, cp[:len(cp)-1]) {
		t.Fatal("truncated MAC must not verify")
	}
}

func TestSessionKeysAreDirectionalAndBound(t *testing.T) {
	master := bytes.Repeat([]byte{0x44}, KeyLen)
	c, s := fixedNonces()

	c2s, s2c, err := SessionKeys(master, "alice", c, s)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(c2s, s2c) {
		t.Fatal("directional keys must differ")
	}
	if len(c2s) != KeyLen || len(s2c) != KeyLen {
		t.Fatal("unexpected session key length")
	}

	c2s2, _, err := SessionKeys(master, "alice", c, s)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(c2s, c2s2) {
		t.Fatal("session derivation is not deterministic")
	}

	otherC, _, err := SessionKeys(master, "bob", c, s)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(c2s, otherC) {
		t.Fatal("session key must be bound to nickname")
	}

	_, _, err = SessionKeys(master, "alice", bytes.Repeat([]byte{1}, 32), s)
	if err != nil {
		t.Fatal(err)
	}
	changed, _, _ := SessionKeys(master, "alice", bytes.Repeat([]byte{1}, 32), s)
	if bytes.Equal(c2s, changed) {
		t.Fatal("session key must be bound to client nonce")
	}
}

func TestFrameCipherOrderAndTamper(t *testing.T) {
	key := bytes.Repeat([]byte{0x55}, KeyLen)
	send, err := NewFrameCipher(key, DirectionClientToServer)
	if err != nil {
		t.Fatal(err)
	}
	recv, err := NewFrameCipher(key, DirectionClientToServer)
	if err != nil {
		t.Fatal(err)
	}

	first, err := send.Seal([]byte("first"))
	if err != nil {
		t.Fatal(err)
	}
	second, err := send.Seal([]byte("second"))
	if err != nil {
		t.Fatal(err)
	}

	// Reordering fails because the sequence number is authenticated.
	if _, err := recv.Open(second); err == nil {
		t.Fatal("out-of-order frame was accepted")
	}

	// Recreate the receiver after the deliberate failure.
	recv, _ = NewFrameCipher(key, DirectionClientToServer)
	plain, err := recv.Open(first)
	if err != nil {
		t.Fatal(err)
	}
	if string(plain) != "first" {
		t.Fatalf("plaintext = %q", plain)
	}

	tampered := append([]byte{}, first...)
	tampered[len(tampered)-1] ^= 0x01
	recv, _ = NewFrameCipher(key, DirectionClientToServer)
	if _, err := recv.Open(tampered); err == nil {
		t.Fatal("tampered frame was accepted")
	}
}

func TestFrameCipherRejectsReflection(t *testing.T) {
	key := bytes.Repeat([]byte{0x66}, KeyLen)
	c2s, err := NewFrameCipher(key, DirectionClientToServer)
	if err != nil {
		t.Fatal(err)
	}
	s2c, err := NewFrameCipher(key, DirectionServerToClient)
	if err != nil {
		t.Fatal(err)
	}

	frame, err := c2s.Seal([]byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s2c.Open(frame); err == nil {
		t.Fatal("frame reflected into the other direction was accepted")
	}
}

func TestFrameCipherRejectsOversize(t *testing.T) {
	key := bytes.Repeat([]byte{0x77}, KeyLen)
	c, _ := NewFrameCipher(key, DirectionClientToServer)
	if _, err := c.Seal(make([]byte, MaxFrameSize+1)); err == nil {
		t.Fatal("oversize frame was sealed")
	}
}

func TestFingerprintNormalization(t *testing.T) {
	raw := bytes.Repeat([]byte{0xab}, 32)
	want := FormatFingerprint(raw)
	if want != "AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB" {
		t.Fatalf("unexpected format: %s", want)
	}

	got, err := NormalizeFingerprint(" ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ")
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("normalized = %s, want %s", got, want)
	}
	if _, err := NormalizeFingerprint("not-a-fingerprint"); err == nil {
		t.Fatal("invalid fingerprint accepted")
	}
	sum := sha256.Sum256(raw)
	if got := Fingerprint(raw); got != FormatFingerprint(sum[:]) {
		t.Fatalf("Fingerprint(DER) = %s", got)
	}
}
