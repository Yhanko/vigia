package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"strings"
)

const (
	keySizeBytes = 32 // AES-256
	keyHexLen    = keySizeBytes * 2
	maxKeyIDLen  = 16
)

// ErrInvalidKeyring indicates that ENCRYPTION_KEY_FILE is empty, uses the
// legacy unprefixed format, or contains malformed/duplicate key entries.
// Error messages never include raw key bytes.
var ErrInvalidKeyring = errors.New("crypto: invalid encryption keyring")

// Keyring holds one or more AES-256 Key Encryption Keys (KEKs) indexed by
// key_id. The first key in the keyring file is the active KEK for new
// encryptions; remaining entries are retained for decryption during rotation.
type Keyring struct {
	activeID string
	ciphers  map[string]cipher.AEAD
}

// String implements fmt.Stringer and always redacts the keyring.
func (*Keyring) String() string { return "[REDACTED]" }

// GoString implements fmt.GoStringer and always redacts the keyring.
func (*Keyring) GoString() string { return `"[REDACTED]"` }

// LogValue implements slog.LogValuer and always redacts the keyring.
func (*Keyring) LogValue() slog.Value { return slog.StringValue("[REDACTED]") }

// ActiveKeyID returns the non-secret identifier of the active KEK.
func (k *Keyring) ActiveKeyID() string {
	if k == nil {
		return ""
	}
	return k.activeID
}

// ParseKeyring parses ENCRYPTION_KEY_FILE contents in the ADR-015 keyring
// format: one "<key_id>:<64-hex-chars>" entry per non-empty line, where the
// first entry is the active KEK. Error messages never leak key material.
func ParseKeyring(raw []byte) (*Keyring, error) {
	text := strings.TrimSpace(string(raw))
	if text == "" {
		return nil, fmt.Errorf("%w: keyring is empty", ErrInvalidKeyring)
	}

	kr := &Keyring{
		ciphers: make(map[string]cipher.AEAD),
	}

	lines := strings.Split(text, "\n")
	for i, line := range lines {
		lineNum := i + 1
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		colon := strings.IndexByte(line, ':')
		if colon < 0 {
			return nil, fmt.Errorf("%w: line %d missing '<key_id>:<64-hex>' prefix (legacy unprefixed format is not supported; see ADR-015)", ErrInvalidKeyring, lineNum)
		}

		keyID := line[:colon]
		hexKey := line[colon+1:]

		if !isValidKeyID(keyID) {
			return nil, fmt.Errorf("%w: line %d has invalid key_id (must be 1-%d chars of [a-z0-9_-])", ErrInvalidKeyring, lineNum, maxKeyIDLen)
		}
		if _, dup := kr.ciphers[keyID]; dup {
			return nil, fmt.Errorf("%w: line %d duplicates key_id %q", ErrInvalidKeyring, lineNum, keyID)
		}
		if len(hexKey) != keyHexLen {
			return nil, fmt.Errorf("%w: line %d (key_id %q) must have exactly %d hex characters (256 bits)", ErrInvalidKeyring, lineNum, keyID, keyHexLen)
		}

		keyBytes, err := hex.DecodeString(hexKey)
		if err != nil || len(keyBytes) != keySizeBytes {
			return nil, fmt.Errorf("%w: line %d (key_id %q) contains non-hex characters", ErrInvalidKeyring, lineNum, keyID)
		}

		block, err := aes.NewCipher(keyBytes)
		clear(keyBytes)
		if err != nil {
			return nil, fmt.Errorf("%w: line %d (key_id %q) init cipher failed", ErrInvalidKeyring, lineNum, keyID)
		}
		aead, err := cipher.NewGCM(block)
		if err != nil {
			return nil, fmt.Errorf("%w: line %d (key_id %q) init gcm failed", ErrInvalidKeyring, lineNum, keyID)
		}

		if kr.activeID == "" {
			kr.activeID = keyID
		}
		kr.ciphers[keyID] = aead
	}

	if kr.activeID == "" {
		return nil, fmt.Errorf("%w: no keys found", ErrInvalidKeyring)
	}
	return kr, nil
}

func isValidKeyID(id string) bool {
	if len(id) == 0 || len(id) > maxKeyIDLen {
		return false
	}
	for i := range len(id) {
		c := id[i]
		ok := (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' || c == '-'
		if !ok {
			return false
		}
	}
	return true
}
