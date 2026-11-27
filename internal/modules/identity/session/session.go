// Package session generates opaque session and CSRF tokens, derives
// HMAC-SHA256 digests for database storage, and builds hardened session
// cookies (ADR-005 §3.1, docs/decisions/business-defaults.md §2).
package session

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"
)

const (
	// TokenBytes is the CSPRNG entropy size (256 bits) for session and CSRF tokens.
	TokenBytes = 32

	// MinSecretBytes enforces at least 256 bits of key material for HMAC-SHA256.
	MinSecretBytes = 32

	// CookieNameDev is used in development (where HTTP localhost cannot set __Host-).
	CookieNameDev = "vigia_session"
	// CookieNameProd is used in staging and production (requires Secure + Path=/ + no Domain).
	CookieNameProd = "__Host-vigia_session"

	// Session lifetime defaults from docs/decisions/business-defaults.md §2.
	DefaultIdleTTL      = 7 * 24 * time.Hour
	DefaultAbsoluteTTL  = 30 * 24 * time.Hour
	DefaultReauthWindow = 10 * time.Minute

	csrfDomainPrefix = "csrf:"
)

// ErrInvalidSecret is returned when the configured session secret is too short.
var ErrInvalidSecret = errors.New("session: secret must be at least 32 bytes")

// Codec generates and hashes opaque session/CSRF tokens and builds session cookies.
// Its String, GoString, and LogValue methods always redact the HMAC secret.
type Codec struct {
	secret []byte
	secure bool
}

// NewCodec creates a session Codec for the given environment and HMAC secret.
// Outside "development", cookies use the __Host- prefix and Secure=true.
func NewCodec(secret []byte, appEnv string) (*Codec, error) {
	if len(secret) < MinSecretBytes {
		return nil, ErrInvalidSecret
	}
	copied := make([]byte, len(secret))
	copy(copied, secret)
	return &Codec{
		secret: copied,
		secure: appEnv != "development",
	}, nil
}

// String implements fmt.Stringer without exposing the secret.
func (*Codec) String() string { return "session.Codec{[REDACTED]}" }

// GoString implements fmt.GoStringer without exposing the secret.
func (*Codec) GoString() string { return "session.Codec{[REDACTED]}" }

// LogValue implements slog.LogValuer without exposing the secret.
func (*Codec) LogValue() slog.Value { return slog.StringValue("session.Codec{[REDACTED]}") }

// CookieName returns the environment-appropriate session cookie name.
func (c *Codec) CookieName() string {
	if c.secure {
		return CookieNameProd
	}
	return CookieNameDev
}

// NewToken generates a fresh 32-byte CSPRNG token encoded with base64url (no padding)
// together with its HMAC-SHA256 digest for storage in sessions.token_hash.
func (c *Codec) NewToken() (token string, tokenHash []byte, err error) {
	token, err = generateBase64URLToken()
	if err != nil {
		return "", nil, fmt.Errorf("session: generate token: %w", err)
	}
	return token, c.HashToken(token), nil
}

// HashToken computes HMAC-SHA256(SESSION_SECRET, token) for database lookup.
func (c *Codec) HashToken(token string) []byte {
	mac := hmac.New(sha256.New, c.secret)
	_, _ = mac.Write([]byte(token))
	return mac.Sum(nil)
}

// NewCSRFToken generates a fresh 32-byte CSPRNG CSRF token (base64url, no padding)
// and its domain-separated HMAC-SHA256 digest for storage in sessions.csrf_token_hash.
func (c *Codec) NewCSRFToken() (token string, tokenHash []byte, err error) {
	token, err = generateBase64URLToken()
	if err != nil {
		return "", nil, fmt.Errorf("session: generate csrf token: %w", err)
	}
	return token, c.HashCSRFToken(token), nil
}

// HashCSRFToken computes a domain-separated HMAC-SHA256 digest for a CSRF token
// so session and CSRF digests can never collide.
func (c *Codec) HashCSRFToken(token string) []byte {
	mac := hmac.New(sha256.New, c.secret)
	_, _ = mac.Write([]byte(csrfDomainPrefix))
	_, _ = mac.Write([]byte(token))
	return mac.Sum(nil)
}

// VerifyCSRFToken compares a client-supplied CSRF token against the stored
// digest in constant time.
func (c *Codec) VerifyCSRFToken(providedToken string, expectedHash []byte) bool {
	if providedToken == "" || len(expectedHash) != sha256.Size {
		return false
	}
	actual := c.HashCSRFToken(providedToken)
	return subtle.ConstantTimeCompare(actual, expectedHash) == 1
}

// BuildCookie constructs the hardened session cookie with HttpOnly, Path=/,
// SameSite=Lax, and Secure=true outside development (ADR-005 §3.1).
func (c *Codec) BuildCookie(token string, expiresAt time.Time, maxAge time.Duration) *http.Cookie {
	maxAgeSec := int(maxAge.Seconds())
	if maxAgeSec < 0 {
		maxAgeSec = 0
	}
	return &http.Cookie{ //nolint:gosec // G124: ADR-005 §3.1 mandates HttpOnly, SameSite=Lax, and Secure=true in staging/production (HTTP localhost only in development)
		Name:     c.CookieName(),
		Value:    token,
		Path:     "/",
		Expires:  expiresAt.UTC(),
		MaxAge:   maxAgeSec,
		HttpOnly: true,
		Secure:   c.secure,
		SameSite: http.SameSiteLaxMode,
	}
}

// ClearCookie constructs an expired cookie that instructs browsers to delete
// the active session cookie on logout.
func (c *Codec) ClearCookie() *http.Cookie {
	return &http.Cookie{ //nolint:gosec // G124: ADR-005 §3.1 mandates HttpOnly, SameSite=Lax, and Secure=true in staging/production (HTTP localhost only in development)
		Name:     c.CookieName(),
		Value:    "",
		Path:     "/",
		Expires:  time.Unix(0, 0).UTC(),
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   c.secure,
		SameSite: http.SameSiteLaxMode,
	}
}

func generateBase64URLToken() (string, error) {
	buf := make([]byte, TokenBytes)
	if _, err := io.ReadFull(rand.Reader, buf); err != nil {
		return "", err
	}
	defer clear(buf)
	return base64.RawURLEncoding.EncodeToString(buf), nil
}
