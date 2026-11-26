// Package crypto implements application-layer envelope encryption using
// AES-256-GCM with per-record DEKs, KEK rotation via key_id, and mandatory
// AAD binding to owner, table, column, and record ID (ADR-015).
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

const (
	envelopeVersion byte = 0x01
	gcmNonceSize         = 12 // 96-bit standard GCM nonce
	gcmTagSize           = 16 // 128-bit standard GCM tag
	wrappedDEKSize       = keySizeBytes + gcmTagSize
)

// ErrDecrypt is returned for all envelope decryption failures (unknown version,
// unknown key_id, wrong AAD, truncated or tampered ciphertext) so callers
// cannot distinguish failure reasons.
var ErrDecrypt = errors.New("crypto: decryption failed")

// Encrypter defines the minimal envelope encryption contract consumed by
// domain modules (ADR-015 §3.4).
type Encrypter interface {
	Encrypt(scope Scope, plaintext []byte) ([]byte, error)
	Decrypt(scope Scope, envelope []byte) ([]byte, error)
	Rewrap(scope Scope, envelope []byte) ([]byte, bool, error)
}

// EnvelopeEncrypter implements Encrypter using AES-256-GCM KEK/DEK envelopes.
type EnvelopeEncrypter struct {
	keyring *Keyring
}

// NewEnvelopeEncrypter constructs an EnvelopeEncrypter backed by keyring.
func NewEnvelopeEncrypter(keyring *Keyring) (*EnvelopeEncrypter, error) {
	if keyring == nil || keyring.activeID == "" {
		return nil, fmt.Errorf("%w: keyring must not be nil or empty", ErrInvalidKeyring)
	}
	return &EnvelopeEncrypter{keyring: keyring}, nil
}

// Encrypt generates a fresh 256-bit DEK and two independent 96-bit nonces via
// crypto/rand, encrypts plaintext under the DEK with Scope AAD, wraps the DEK
// under the active KEK with the same AAD, and encodes the versioned envelope.
func (e *EnvelopeEncrypter) Encrypt(scope Scope, plaintext []byte) ([]byte, error) {
	if err := scope.Validate(); err != nil {
		return nil, err
	}

	aad := scope.encodeAAD()

	dek := make([]byte, keySizeBytes)
	defer clear(dek)
	if _, err := io.ReadFull(rand.Reader, dek); err != nil {
		return nil, fmt.Errorf("crypto: generate dek: %w", err)
	}

	dekBlock, err := aes.NewCipher(dek)
	if err != nil {
		return nil, fmt.Errorf("crypto: init dek cipher: %w", err)
	}
	dekGCM, err := cipher.NewGCM(dekBlock)
	if err != nil {
		return nil, fmt.Errorf("crypto: init dek gcm: %w", err)
	}

	dataNonce := make([]byte, gcmNonceSize)
	if _, err := io.ReadFull(rand.Reader, dataNonce); err != nil {
		return nil, fmt.Errorf("crypto: generate data nonce: %w", err)
	}
	ciphertext := dekGCM.Seal(nil, dataNonce, plaintext, aad)

	dekNonce := make([]byte, gcmNonceSize)
	if _, err := io.ReadFull(rand.Reader, dekNonce); err != nil {
		return nil, fmt.Errorf("crypto: generate dek nonce: %w", err)
	}
	kekGCM := e.keyring.ciphers[e.keyring.activeID]
	wrappedDEK := kekGCM.Seal(nil, dekNonce, dek, aad)

	return encodeEnvelope(e.keyring.activeID, dekNonce, wrappedDEK, dataNonce, ciphertext), nil
}

// Decrypt validates the envelope structure, unwraps the DEK with the KEK
// identified by key_id, and authenticates/decrypts the payload using Scope AAD.
// Any failure other than an invalid Scope returns the generic ErrDecrypt.
func (e *EnvelopeEncrypter) Decrypt(scope Scope, envelope []byte) ([]byte, error) {
	if err := scope.Validate(); err != nil {
		return nil, err
	}

	parsed, ok := parseEnvelope(envelope)
	if !ok {
		return nil, ErrDecrypt
	}

	kekGCM, exists := e.keyring.ciphers[parsed.keyID]
	if !exists {
		return nil, ErrDecrypt
	}

	aad := scope.encodeAAD()
	dek, err := kekGCM.Open(nil, parsed.dekNonce, parsed.wrappedDEK, aad)
	if err != nil || len(dek) != keySizeBytes {
		clear(dek)
		return nil, ErrDecrypt
	}
	defer clear(dek)

	dekBlock, err := aes.NewCipher(dek)
	if err != nil {
		return nil, ErrDecrypt
	}
	dekGCM, err := cipher.NewGCM(dekBlock)
	if err != nil {
		return nil, ErrDecrypt
	}

	plaintext, err := dekGCM.Open(nil, parsed.dataNonce, parsed.ciphertext, aad)
	if err != nil {
		return nil, ErrDecrypt
	}
	return plaintext, nil
}

// Rewrap re-encrypts only the DEK under the active KEK when the envelope was
// created with an older key_id, avoiding re-encrypting the payload. Returns
// (envelope, false, nil) if already using the active key_id.
func (e *EnvelopeEncrypter) Rewrap(scope Scope, envelope []byte) ([]byte, bool, error) {
	if err := scope.Validate(); err != nil {
		return nil, false, err
	}

	parsed, ok := parseEnvelope(envelope)
	if !ok {
		return nil, false, ErrDecrypt
	}

	oldKEK, exists := e.keyring.ciphers[parsed.keyID]
	if !exists {
		return nil, false, ErrDecrypt
	}

	aad := scope.encodeAAD()
	dek, err := oldKEK.Open(nil, parsed.dekNonce, parsed.wrappedDEK, aad)
	if err != nil || len(dek) != keySizeBytes {
		clear(dek)
		return nil, false, ErrDecrypt
	}
	defer clear(dek)

	if parsed.keyID == e.keyring.activeID {
		// Still authenticate the payload before reporting unchanged.
		if !verifyPayload(dek, parsed.dataNonce, parsed.ciphertext, aad) {
			return nil, false, ErrDecrypt
		}
		out := make([]byte, len(envelope))
		copy(out, envelope)
		return out, false, nil
	}

	// Authenticate payload before emitting a re-wrapped envelope.
	if !verifyPayload(dek, parsed.dataNonce, parsed.ciphertext, aad) {
		return nil, false, ErrDecrypt
	}

	newDEKNonce := make([]byte, gcmNonceSize)
	if _, err := io.ReadFull(rand.Reader, newDEKNonce); err != nil {
		return nil, false, fmt.Errorf("crypto: generate dek nonce: %w", err)
	}
	newWrappedDEK := e.keyring.ciphers[e.keyring.activeID].Seal(nil, newDEKNonce, dek, aad)

	return encodeEnvelope(e.keyring.activeID, newDEKNonce, newWrappedDEK, parsed.dataNonce, parsed.ciphertext), true, nil
}

func verifyPayload(dek, dataNonce, ciphertext, aad []byte) bool {
	block, err := aes.NewCipher(dek)
	if err != nil {
		return false
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return false
	}
	pt, err := gcm.Open(nil, dataNonce, ciphertext, aad)
	clear(pt)
	return err == nil
}

type parsedEnvelope struct {
	keyID      string
	dekNonce   []byte
	wrappedDEK []byte
	dataNonce  []byte
	ciphertext []byte
}

func encodeEnvelope(keyID string, dekNonce, wrappedDEK, dataNonce, ciphertext []byte) []byte {
	keyIDLen := len(keyID)
	total := 1 + 1 + keyIDLen + gcmNonceSize + 2 + len(wrappedDEK) + gcmNonceSize + len(ciphertext)
	out := make([]byte, 0, total)

	out = append(out, envelopeVersion)
	out = append(out, byte(keyIDLen)) //nolint:gosec // G115: keyIDLen is validated 1..maxKeyIDLen (16) by ParseKeyring
	out = append(out, keyID...)
	out = append(out, dekNonce...)
	out = binary.BigEndian.AppendUint16(out, uint16(len(wrappedDEK))) //nolint:gosec // G115: wrappedDEK is fixed 48 bytes
	out = append(out, wrappedDEK...)
	out = append(out, dataNonce...)
	out = append(out, ciphertext...)
	return out
}

// parseEnvelope validates every version and length field BEFORE slicing so
// malformed or truncated inputs never panic or read out of bounds.
func parseEnvelope(env []byte) (parsedEnvelope, bool) {
	// Minimum possible size: version(1) + key_id_len(1) + key_id(1) +
	// dek_nonce(12) + wrapped_dek_len(2) + wrapped_dek(48) + data_nonce(12) + tag(16) = 93 bytes.
	const minHeaderBeforeKeyID = 2
	if len(env) < minHeaderBeforeKeyID {
		return parsedEnvelope{}, false
	}
	if env[0] != envelopeVersion {
		return parsedEnvelope{}, false
	}

	keyIDLen := int(env[1])
	if keyIDLen == 0 || keyIDLen > maxKeyIDLen {
		return parsedEnvelope{}, false
	}

	pos := minHeaderBeforeKeyID
	if len(env)-pos < keyIDLen+gcmNonceSize+2 {
		return parsedEnvelope{}, false
	}
	keyID := string(env[pos : pos+keyIDLen])
	pos += keyIDLen

	dekNonce := env[pos : pos+gcmNonceSize]
	pos += gcmNonceSize

	wrappedLen := int(binary.BigEndian.Uint16(env[pos : pos+2]))
	pos += 2
	if wrappedLen != wrappedDEKSize {
		return parsedEnvelope{}, false
	}

	if len(env)-pos < wrappedLen+gcmNonceSize+gcmTagSize {
		return parsedEnvelope{}, false
	}
	wrappedDEK := env[pos : pos+wrappedLen]
	pos += wrappedLen

	dataNonce := env[pos : pos+gcmNonceSize]
	pos += gcmNonceSize

	ciphertext := env[pos:]
	return parsedEnvelope{
		keyID:      keyID,
		dekNonce:   dekNonce,
		wrappedDEK: wrappedDEK,
		dataNonce:  dataNonce,
		ciphertext: ciphertext,
	}, true
}
