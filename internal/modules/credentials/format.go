// Package credentials implements API credential generation, strict
// position-based parsing, HMAC-SHA256 verification, Redis caching with
// immediate revocation, and HTTP auth middleware (ADR-005 §3.2, TASKS 1.3).
package credentials

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
)

const (
	KindIngest = "ingest"
	KindClient = "client"
	KindDSN    = "dsn"

	// Exact fixed lengths from ADR-005 §3.2 (never parsed with strings.Split).
	SecretKeyLength  = 84 // "vg_ing_" (7) + prefix (12 hex) + "_" (1) + secret (64 hex)
	PrefixOffset     = 7
	PrefixLength     = 12
	SeparatorOffset  = 19
	SecretOffset     = 20
	SecretHexLength  = 64
	DSNKeyLength     = 32 // 128-bit CSPRNG lowercase hex
	DSNPrefixLength  = 8
	MaxCollisionTry  = 3
)

var (
	// ErrInvalidCredential is returned for malformed, unknown, expired, or revoked credentials.
	ErrInvalidCredential = errors.New("credentials: invalid api credential")

	// ErrInsufficientScope is returned when a credential kind is used outside its permitted routes.
	ErrInsufficientScope = errors.New("credentials: insufficient scope for credential kind")
)

// ParsedKey holds the kind and lookup prefix extracted strictly by byte position.
type ParsedKey struct {
	Kind   string
	Prefix string
}

// GenerateSecretKey generates a new ingest ("vg_ing_") or client ("vg_cli_")
// credential with 48-bit prefix and 256-bit CSPRNG secret (ADR-005 §3.2).
func GenerateSecretKey(kind string) (fullKey, prefix string, err error) {
	var tag string
	switch kind {
	case KindIngest:
		tag = "vg_ing_"
	case KindClient:
		tag = "vg_cli_"
	default:
		return "", "", fmt.Errorf("credentials: unsupported secret key kind %q", kind)
	}

	var preBuf [6]byte // 12 hex
	var secBuf [32]byte // 64 hex (256 bits)
	if _, err := io.ReadFull(rand.Reader, preBuf[:]); err != nil {
		return "", "", fmt.Errorf("credentials: generate prefix: %w", err)
	}
	if _, err := io.ReadFull(rand.Reader, secBuf[:]); err != nil {
		return "", "", fmt.Errorf("credentials: generate secret: %w", err)
	}
	defer clear(secBuf[:])

	prefix = hex.EncodeToString(preBuf[:])
	fullKey = tag + prefix + "_" + hex.EncodeToString(secBuf[:])
	return fullKey, prefix, nil
}

// GenerateDSNKey generates a 128-bit (32 lowercase hex) public DSN key and its 8-hex prefix.
func GenerateDSNKey() (publicKey, prefix string, err error) {
	var buf [16]byte
	if _, err := io.ReadFull(rand.Reader, buf[:]); err != nil {
		return "", "", fmt.Errorf("credentials: generate dsn key: %w", err)
	}
	publicKey = hex.EncodeToString(buf[:])
	return publicKey, publicKey[:DSNPrefixLength], nil
}

// ParseSecretKey validates an 84-character vg_ing_ or vg_cli_ key strictly by
// position and lowercase hexadecimal alphabet [0-9a-f] (ADR-005 §3.2).
func ParseSecretKey(raw string) (ParsedKey, error) {
	if len(raw) != SecretKeyLength {
		return ParsedKey{}, ErrInvalidCredential
	}
	var kind string
	switch raw[:PrefixOffset] {
	case "vg_ing_":
		kind = KindIngest
	case "vg_cli_":
		kind = KindClient
	default:
		return ParsedKey{}, ErrInvalidCredential
	}
	if raw[SeparatorOffset] != '_' {
		return ParsedKey{}, ErrInvalidCredential
	}
	prefix := raw[PrefixOffset:SeparatorOffset]
	secret := raw[SecretOffset:]
	if !isLowerHex(prefix) || !isLowerHex(secret) {
		return ParsedKey{}, ErrInvalidCredential
	}
	return ParsedKey{Kind: kind, Prefix: prefix}, nil
}

// HashSecret computes HMAC-SHA256(pepper, fullKey).
func HashSecret(pepper []byte, fullKey string) []byte {
	mac := hmac.New(sha256.New, pepper)
	_, _ = mac.Write([]byte(fullKey))
	return mac.Sum(nil)
}

// VerifySecret compares HashSecret(pepper, fullKey) against expectedHash in constant time.
func VerifySecret(pepper []byte, fullKey string, expectedHash []byte) bool {
	if len(expectedHash) != sha256.Size {
		return false
	}
	actual := HashSecret(pepper, fullKey)
	return subtle.ConstantTimeCompare(actual, expectedHash) == 1
}

// FormatDSN returns the Sentry-compatible DSN string (TASKS 1.3 / 2.1):
// https://<public_key>@<host>/<public_id>
func FormatDSN(publicKey, host string, publicID int64) string {
	return fmt.Sprintf("https://%s@%s/%d", publicKey, host, publicID)
}

// CacheKey returns the ADR-005 §3.2 Redis cache key:
//   - cred:ingest:<prefix>
//   - cred:client:<prefix>
//   - cred:dsn:<public_key>
func CacheKey(kind, prefixOrPublicKey string) string {
	return "cred:" + kind + ":" + prefixOrPublicKey
}

func isLowerHex(s string) bool {
	for i := range len(s) {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return len(s) > 0
}
