package quotas

import "errors"

var (
	// ErrQuotaExceeded is returned when an organization has reached a plan quota.
	ErrQuotaExceeded = errors.New("quotas: plan quota exceeded")
	// ErrServiceUnavailable is returned when Redis is unavailable (fail-closed, ADR-009 §3.3).
	ErrServiceUnavailable = errors.New("quotas: quota backend unavailable")
	// ErrNotFound is returned when the organization or plan is not found (or cross-tenant).
	ErrNotFound = errors.New("quotas: resource not found")
	// ErrForbidden is returned when the caller lacks RBAC permission.
	ErrForbidden = errors.New("quotas: forbidden")
	// ErrMFARequired is returned when privileged MFA setup is enforced.
	ErrMFARequired = errors.New("quotas: mfa setup required")
	// ErrInvalidInput is returned for invalid parameters.
	ErrInvalidInput = errors.New("quotas: invalid input")
)
