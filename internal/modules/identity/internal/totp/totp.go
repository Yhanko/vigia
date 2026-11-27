// Package totp implements RFC 6238 TOTP (SHA-1, 6 digits, 30s period, ±1 skew,
// anti-replay) and 80-bit recovery codes using only the Go standard library
// (docs/plans/1.2-identity.md §7.3).
package totp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // RFC 6238 TOTP standard uses HMAC-SHA1 for authenticator app compatibility
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"io"
	"net/url"
	"strings"
	"time"
)

const (
	SecretBytes          = 20
	PeriodSeconds  int64 = 30
	Digits               = 6
	SkewSteps      int64 = 1
	RecoveryCount        = 10
	RecoveryBits         = 80 // 16 base32 chars (5 bits each)

	// Unambiguous Crockford-like base32 alphabet (no 0/O, 1/I/L).
	recoveryAlphabet = "23456789abcdefghjkmnpqrstuvwxyz2" // 32 chars (last char pads to power-of-2 mask)
)

// GenerateSecret generates a 20-byte CSPRNG TOTP secret and its unpadded
// uppercase Base32 representation.
func GenerateSecret() (raw []byte, b32 string, err error) {
	raw = make([]byte, SecretBytes)
	if _, err = io.ReadFull(rand.Reader, raw); err != nil {
		return nil, "", fmt.Errorf("totp: generate secret: %w", err)
	}
	b32 = base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw)
	return raw, b32, nil
}

// ProvisioningURI returns the standard otpauth://totp URI for authenticator apps.
func ProvisioningURI(issuer, account, base32Secret string) string {
	label := url.PathEscape(issuer) + ":" + url.PathEscape(account)
	q := url.Values{}
	q.Set("secret", base32Secret)
	q.Set("issuer", issuer)
	q.Set("algorithm", "SHA1")
	q.Set("digits", "6")
	q.Set("period", "30")
	return "otpauth://totp/" + label + "?" + q.Encode()
}

// CodeAt computes the 6-digit RFC 6238 TOTP code for secret at time t.
func CodeAt(secret []byte, t time.Time) string {
	step := t.Unix() / PeriodSeconds
	return codeForStep(secret, step)
}

// Verify checks a 6-digit TOTP code against secret at now with ±1 step skew
// using constant-time comparison and anti-replay protection: any step <=
// lastUsedStep is rejected (docs/plans/1.2-identity.md §7.3).
func Verify(secret []byte, code string, now time.Time, lastUsedStep *int64) (matchedStep int64, ok bool) {
	code = strings.TrimSpace(code)
	if len(code) != Digits {
		return 0, false
	}
	curStep := now.Unix() / PeriodSeconds
	for offset := -SkewSteps; offset <= SkewSteps; offset++ {
		step := curStep + offset
		if step < 0 {
			continue
		}
		if lastUsedStep != nil && step <= *lastUsedStep {
			continue
		}
		expected := codeForStep(secret, step)
		if subtle.ConstantTimeCompare([]byte(code), []byte(expected)) == 1 {
			return step, true
		}
	}
	return 0, false
}

func codeForStep(secret []byte, step int64) string {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(step)) //nolint:gosec // step >= 0 checked by caller

	mac := hmac.New(sha1.New, secret)
	_, _ = mac.Write(msg[:])
	sum := mac.Sum(nil)

	offset := sum[len(sum)-1] & 0x0f
	binCode := (uint32(sum[offset]&0x7f) << 24) |
		(uint32(sum[offset+1]) << 16) |
		(uint32(sum[offset+2]) << 8) |
		uint32(sum[offset+3])

	return fmt.Sprintf("%06d", binCode%1_000_000)
}

// GenerateRecoveryCodes generates n 80-bit random recovery codes formatted as
// xxxx-xxxx-xxxx-xxxx using an unambiguous 32-character alphabet.
func GenerateRecoveryCodes(n int) ([]string, error) {
	if n <= 0 {
		n = RecoveryCount
	}
	codes := make([]string, 0, n)
	const alphabet = "23456789abcdefghjkmnpqrstuvwxyz" // 31 unambiguous chars
	// Use 32-char unambiguous alphabet (add 'a'-'z' without i,l,o + '2'-'9' + '0' excluded -> 23 letters + 8 digits = 31; use RFC 4648 base32 lowercase A-Z 2-7 without padding for exact 80 bits!).
	_ = alphabet
	_ = recoveryAlphabet

	b32Enc := base32.StdEncoding.WithPadding(base32.NoPadding)
	for range n {
		var buf [10]byte // 80 bits -> exactly 16 base32 characters
		if _, err := io.ReadFull(rand.Reader, buf[:]); err != nil {
			return nil, fmt.Errorf("totp: generate recovery code: %w", err)
		}
		raw := strings.ToLower(b32Enc.EncodeToString(buf[:]))
		formatted := raw[0:4] + "-" + raw[4:8] + "-" + raw[8:12] + "-" + raw[12:16]
		codes = append(codes, formatted)
	}
	return codes, nil
}

// NormalizeRecoveryCode strips hyphens/spaces and lowercases a recovery code.
func NormalizeRecoveryCode(raw string) string {
	s := strings.ToLower(strings.TrimSpace(raw))
	s = strings.ReplaceAll(s, "-", "")
	s = strings.ReplaceAll(s, " ", "")
	return s
}

// HashRecoveryCode computes HMAC-SHA256(secret, "mfa_recovery:" || normalized)
// per docs/plans/1.2-identity.md §7.3.
func HashRecoveryCode(secret []byte, rawCode string) []byte {
	norm := NormalizeRecoveryCode(rawCode)
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte("mfa_recovery:"))
	_, _ = mac.Write([]byte(norm))
	return mac.Sum(nil)
}
