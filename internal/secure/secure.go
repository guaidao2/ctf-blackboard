// Package secure implements the cryptographic core of CTF Blackboard:
// password-based key derivation, challenge-response authentication, per-session
// keys and the authenticated-encryption frame codec used after login.
//
// The design deliberately transmits no password material. The password is
// stretched with PBKDF2-HMAC-SHA256 (per-connection random salt), used to prove
// knowledge of the shared secret with HMAC, and then only per-session keys
// derived with HKDF are used to protect application frames.
package secure

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

const (
	// ProtocolVersion is bound into every authentication proof so an attacker
	// cannot downgrade a session across incompatible protocol revisions.
	ProtocolVersion = 1

	// DefaultIterations is the PBKDF2 work factor for online logins.
	DefaultIterations = 210_000

	// MinIterations is accepted from a peer only at or above this floor.
	MinIterations = 100_000

	// KeyLen is the AES-256 key length used for state and session keys.
	KeyLen = 32

	// NonceLen is the AES-GCM nonce length.
	NonceLen = 12

	// TagLen is the AES-GCM authentication tag length.
	TagLen = 16

	// FrameOverhead is nonce + tag.
	FrameOverhead = NonceLen + TagLen

	// MaxFrameSize bounds a single decrypted protocol frame (1 MiB).
	MaxFrameSize = 1 << 20

	// DirectionClientToServer and DirectionServerToClient are bound into frame
	// AAD so a captured frame can never be reflected back to its sender.
	DirectionClientToServer byte = 1
	DirectionServerToClient byte = 2
)

var (
	ErrAuth       = errors.New("authentication failed")
	ErrBadFrame   = errors.New("malformed encrypted frame")
	ErrReplay     = errors.New("encrypted frame sequence mismatch")
	ErrTooLarge   = errors.New("encrypted frame too large")
	ErrDecrypt    = errors.New("frame decryption failed")
	ErrSaltLength = errors.New("salt must be 16 bytes")
)

// RandomBytes returns n cryptographically random bytes.
func RandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("random: %w", err)
	}
	return b, nil
}

// DeriveLoginKey stretches the shared password for one login attempt. A fresh
// random salt is supplied by the server for every connection.
func DeriveLoginKey(password string, salt []byte, iterations int) ([]byte, error) {
	if iterations < MinIterations {
		return nil, fmt.Errorf("pbkdf2 iterations %d below minimum %d", iterations, MinIterations)
	}
	if len(salt) < 16 {
		return nil, ErrSaltLength
	}
	key, err := pbkdf2.Key(sha256.New, password, salt, iterations, KeyLen)
	if err != nil {
		return nil, fmt.Errorf("pbkdf2: %w", err)
	}
	return key, nil
}

// transcript builds the unambiguous byte string that both sides MAC during
// authentication.
func transcript(role, nick string, clientNonce, serverNonce []byte) []byte {
	var b []byte
	appendField := func(s []byte) {
		var n [4]byte
		binary.BigEndian.PutUint32(n[:], uint32(len(s)))
		b = append(b, n[:]...)
		b = append(b, s...)
	}
	b = append(b, []byte("ctfbb-auth-v1")...)
	appendField([]byte(role))
	appendField([]byte(fmt.Sprintf("%d", ProtocolVersion)))
	appendField([]byte(nick))
	appendField(clientNonce)
	appendField(serverNonce)
	return b
}

// ClientProof proves the client knows the shared password.
func ClientProof(master []byte, nick string, clientNonce, serverNonce []byte) []byte {
	return mac(master, transcript("client", nick, clientNonce, serverNonce))
}

// ServerProof proves the server knows the same shared password, giving the
// client mutual authentication on top of certificate pinning.
func ServerProof(master []byte, nick string, clientNonce, serverNonce []byte) []byte {
	return mac(master, transcript("server", nick, clientNonce, serverNonce))
}

func mac(key, msg []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(msg)
	return h.Sum(nil)
}

// VerifyMAC compares two MACs in constant time.
func VerifyMAC(expected, got []byte) bool {
	return subtle.ConstantTimeCompare(expected, got) == 1
}

// SessionKeys derives independent client->server and server->client AES keys.
// Both nonces and the operator nick are bound into the derivation, so keys are
// unique per session even when the shared password is reused.
func SessionKeys(master []byte, nick string, clientNonce, serverNonce []byte) (c2s, s2c []byte, err error) {
	salt := append(append([]byte{}, clientNonce...), serverNonce...)
	base := "ctfbb/session-v1|" + nick
	c2s, err = hkdf.Key(sha256.New, master, salt, base+"|client-to-server", KeyLen)
	if err != nil {
		return nil, nil, fmt.Errorf("hkdf c2s: %w", err)
	}
	s2c, err = hkdf.Key(sha256.New, master, salt, base+"|server-to-client", KeyLen)
	if err != nil {
		return nil, nil, fmt.Errorf("hkdf s2c: %w", err)
	}
	return c2s, s2c, nil
}

// FrameCipher seals and opens ordered application frames. The sequence number
// is authenticated as AAD; the receiver requires exact ordering, so dropping,
// reordering or replaying a frame aborts the session instead of silently
// succeeding.
type FrameCipher struct {
	aead cipher.AEAD
	dir  byte
	seq  uint64
}

// NewFrameCipher creates a codec for one direction. key must be 32 bytes.
func NewFrameCipher(key []byte, direction byte) (*FrameCipher, error) {
	if len(key) != KeyLen {
		return nil, fmt.Errorf("frame key must be %d bytes, got %d", KeyLen, len(key))
	}
	if direction != DirectionClientToServer && direction != DirectionServerToClient {
		return nil, errors.New("invalid frame direction")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("gcm: %w", err)
	}
	return &FrameCipher{aead: aead, dir: direction}, nil
}

func (f *FrameCipher) aad() []byte {
	var aad [9]byte
	aad[0] = f.dir
	binary.BigEndian.PutUint64(aad[1:], f.seq)
	return aad[:]
}

// Seal encrypts one frame: nonce || ciphertext || tag.
func (f *FrameCipher) Seal(plain []byte) ([]byte, error) {
	if len(plain) > MaxFrameSize {
		return nil, ErrTooLarge
	}
	if f.seq == ^uint64(0) {
		return nil, errors.New("frame sequence exhausted; reconnect required")
	}
	out := make([]byte, NonceLen, NonceLen+len(plain)+TagLen)
	if _, err := rand.Read(out); err != nil {
		return nil, fmt.Errorf("frame nonce: %w", err)
	}
	out = f.aead.Seal(out, out[:NonceLen], plain, f.aad())
	f.seq++
	return out, nil
}

// Open authenticates and decrypts one frame, enforcing strict ordering.
func (f *FrameCipher) Open(frame []byte) ([]byte, error) {
	if len(frame) < FrameOverhead {
		return nil, ErrBadFrame
	}
	if len(frame) > MaxFrameSize+FrameOverhead {
		return nil, ErrTooLarge
	}
	if f.seq == ^uint64(0) {
		return nil, ErrReplay
	}
	nonce := frame[:NonceLen]
	plain, err := f.aead.Open(nil, nonce, frame[NonceLen:], f.aad())
	if err != nil {
		return nil, ErrDecrypt
	}
	f.seq++
	return plain, nil
}

// Fingerprint returns the conventional uppercase colon-separated SHA-256
// fingerprint of a DER certificate.
func Fingerprint(der []byte) string {
	sum := sha256.Sum256(der)
	return FormatFingerprint(sum[:])
}

// FormatFingerprint renders raw bytes as AA:BB:... uppercase hex.
func FormatFingerprint(sum []byte) string {
	hexed := strings.ToUpper(hex.EncodeToString(sum))
	var b strings.Builder
	for i := 0; i < len(hexed); i += 2 {
		if i > 0 {
			b.WriteByte(':')
		}
		b.WriteString(hexed[i : i+2])
	}
	return b.String()
}

// NormalizeFingerprint accepts "aa:bb", "aabb", spaces, or mixed case, and
// returns a canonical colon-separated uppercase form. An empty string is an
// error because silently disabling pinning is never acceptable.
func NormalizeFingerprint(s string) (string, error) {
	clean := strings.NewReplacer(":", "", " ", "", "-", "", ".", "").Replace(strings.TrimSpace(s))
	if len(clean) != sha256.Size*2 {
		return "", fmt.Errorf("fingerprint must be %d hex characters (got %d)", sha256.Size*2, len(clean))
	}
	raw, err := hex.DecodeString(clean)
	if err != nil {
		return "", fmt.Errorf("fingerprint is not valid hex: %w", err)
	}
	return FormatFingerprint(raw), nil
}
