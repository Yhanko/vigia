package organizations

import (
	"errors"
	"fmt"
)

var (
	ErrNotFound          = errors.New("organizations: not found")
	ErrConflict          = errors.New("organizations: conflict")
	ErrForbidden         = errors.New("organizations: forbidden")
	ErrProtectedResource = errors.New("organizations: protected resource")
	ErrMFASetupRequired  = errors.New("organizations: mfa setup required for privileged role")
	ErrReauthRequired    = errors.New("organizations: recent authentication required")
)

// ValidationError carries field-level validation failures mapped to 400 VALIDATION_FAILED.
type ValidationError struct {
	Field   string
	Message string
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("validation failed on %s: %s", e.Field, e.Message)
}
