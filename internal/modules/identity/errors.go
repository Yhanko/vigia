package identity

import (
	"errors"
	"fmt"

	"github.com/Yhanko/vigia/internal/platform/ratelimit"
)

var (
	// ErrNotFound is returned by store lookups when a user or session does not exist.
	ErrNotFound = errors.New("identity: not found")

	// ErrEmailExists is returned when creating a user with an already-registered email.
	ErrEmailExists = errors.New("identity: email already exists")

	// ErrInvalidCredentials is returned on failed login without revealing whether
	// the account exists or is inactive (ADR-005 anti-enumeration).
	ErrInvalidCredentials = errors.New("identity: invalid credentials")

	// ErrMFARequired is returned when password verification succeeds for an account
	// with MFA enabled (CTO #20: intermediate MFA flow designed before D8).
	ErrMFARequired = errors.New("identity: mfa required")

	// ErrInvalidMFACode is returned when a TOTP or recovery code is invalid or replayed.
	ErrInvalidMFACode = errors.New("identity: invalid mfa code")

	// ErrReauthRequired is returned when a high-risk operation requires recent auth (<= 10m).
	ErrReauthRequired = errors.New("identity: recent authentication required")

	// ErrSessionExpired is returned when a session cookie is missing, expired,
	// revoked, or belongs to a non-active user.
	ErrSessionExpired = errors.New("identity: session expired")

	// ErrServiceUnavailable is returned on backpressure (Argon2id semaphore full
	// or Redis rate-limiter outage on fail-closed auth routes).
	ErrServiceUnavailable = errors.New("identity: service unavailable")
)

// ValidationError carries field-level validation failures mapped to 400 VALIDATION_FAILED.
type ValidationError struct {
	Field   string
	Message string
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("validation failed on %s: %s", e.Field, e.Message)
}

// RateLimitError carries the rate-limit evaluation so the HTTP layer can write
// RateLimit-* and Retry-After headers alongside 429 RATE_LIMIT_EXCEEDED.
type RateLimitError struct {
	Result ratelimit.Result
}

func (e *RateLimitError) Error() string {
	return "identity: rate limit exceeded"
}
