package projects

import "errors"

var (
	ErrForbidden           = errors.New("projects: forbidden")
	ErrMFARequired         = errors.New("projects: mfa required for privileged role")
	ErrReauthRequired      = errors.New("projects: recent authentication required")
	ErrProjectNotFound     = errors.New("projects: project not found")
	ErrEnvironmentNotFound = errors.New("projects: environment not found")
	ErrSlugTaken           = errors.New("projects: project slug already exists in organization")
	ErrEnvironmentExists   = errors.New("projects: environment already exists in project")
	ErrProtectedResource   = errors.New("projects: protected environment cannot be deleted")
	ErrInvalidInput        = errors.New("projects: invalid input")
	ErrSlugConfirmation    = errors.New("projects: confirmation slug does not match project slug")
	ErrPublicIDCollision   = errors.New("projects: failed to allocate unique public_id after retries")
)
