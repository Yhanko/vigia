package identity

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"strings"
	"time"

	"github.com/Yhanko/vigia/internal/modules/identity/internal/policy"
	"github.com/Yhanko/vigia/internal/modules/identity/password"
	"github.com/Yhanko/vigia/internal/modules/identity/session"
	"github.com/Yhanko/vigia/internal/platform/clock"
	"github.com/Yhanko/vigia/internal/platform/ratelimit"
)

// Rate-limit defaults from docs/decisions/business-defaults.md §4.
const (
	RegisterLimitPerIP     = 5
	RegisterWindow         = time.Hour
	LoginLimitPerIP        = 10
	LoginLimitPerAccountIP = 5
	LoginWindow            = 15 * time.Minute

	maxStoredUserAgentLen = 200
)

// User represents a global identity user record.
type User struct {
	ID           string
	Email        string
	Name         string
	PasswordHash string
	MFAEnabled   bool
	Status       string
}

// SessionRecord holds the fields required to persist a new session row.
type SessionRecord struct {
	ID                string
	UserID            string
	TokenHash         []byte
	CSRFTokenHash     []byte
	LastAuthAt        time.Time
	ExpiresAt         time.Time
	AbsoluteExpiresAt time.Time
	IPPrefix          *string
	UserAgent         *string
}

// ActiveSession represents a validated, non-revoked, non-expired session joined
// with an active user (CTO #14).
type ActiveSession struct {
	ID                string
	UserID            string
	CSRFTokenHash     []byte
	LastAuthAt        time.Time
	ExpiresAt         time.Time
	AbsoluteExpiresAt time.Time
	UserEmail         string
	UserName          string
	UserMFAEnabled    bool
}

// AuditEvent represents a global authentication audit entry (organization_id = NULL).
type AuditEvent struct {
	ID           string
	ActorType    string // "user" or "system"
	ActorID      string // empty when ActorType == "system"
	Action       string // e.g. "auth.login", "auth.logout"
	ResourceType string
	ResourceID   string
	Result       string // "success", "denied", "failure"
	IPPrefix     *string
	UserAgent    *string
	RequestID    string
	ChangesJSON  []byte
}

// RequestMeta carries non-secret request metadata for session and audit records.
type RequestMeta struct {
	ClientIP  string
	UserAgent string
	RequestID string
}

// Store is the consumer-defined persistence interface for the identity service.
type Store interface {
	CreateUser(ctx context.Context, u User) (User, error)
	GetUserByEmail(ctx context.Context, normalizedEmail string) (User, error)
	UpdateUserPasswordHash(ctx context.Context, userID, passwordHash string, updatedAt time.Time) error
	DeactivateUser(ctx context.Context, userID, status string, now time.Time) error
	CreateSession(ctx context.Context, s SessionRecord) error
	GetActiveSessionByTokenHash(ctx context.Context, tokenHash []byte, now time.Time) (ActiveSession, error)
	RevokeSession(ctx context.Context, sessionID string, revokedAt time.Time) error
	RotateSession(ctx context.Context, oldSessionID string, next SessionRecord, revokedAt time.Time) error
	InsertGlobalAuditLog(ctx context.Context, ev AuditEvent) error
}

// PasswordHasher is the consumer-defined interface for Argon2id hashing.
type PasswordHasher interface {
	Hash(ctx context.Context, plain string) (string, error)
	Verify(ctx context.Context, plain, encodedHash string) (bool, error)
	DummyVerify(ctx context.Context) error
	NeedsRehash(encodedHash string) bool
}

// RateLimiter is the consumer-defined interface for sliding-window rate limiting.
type RateLimiter interface {
	Allow(ctx context.Context, key string, limit int, window time.Duration) (ratelimit.Result, error)
}

// ServiceConfig holds the dependencies for the identity domain service.
type ServiceConfig struct {
	Store           Store
	Hasher          PasswordHasher
	Sessions        *session.Codec
	Limiter         RateLimiter
	RateLimitSecret []byte
	Clock           clock.Clock
	Logger          *slog.Logger
}

// Service implements register, login, logout, refresh, and session authentication.
type Service struct {
	store           Store
	hasher          PasswordHasher
	sessions        *session.Codec
	limiter         RateLimiter
	rateLimitSecret []byte
	clk             clock.Clock
	logger          *slog.Logger
}

// NewService constructs an identity Service with explicit dependency injection.
func NewService(cfg ServiceConfig) (*Service, error) {
	if cfg.Store == nil {
		return nil, errors.New("identity: store is required")
	}
	if cfg.Hasher == nil {
		return nil, errors.New("identity: hasher is required")
	}
	if cfg.Sessions == nil {
		return nil, errors.New("identity: session codec is required")
	}
	if cfg.Limiter == nil {
		return nil, errors.New("identity: rate limiter is required")
	}
	if len(cfg.RateLimitSecret) < session.MinSecretBytes {
		return nil, errors.New("identity: rate limit secret must be at least 32 bytes")
	}
	clk := cfg.Clock
	if clk == nil {
		clk = clock.System{}
	}
	secretCopy := make([]byte, len(cfg.RateLimitSecret))
	copy(secretCopy, cfg.RateLimitSecret)

	return &Service{
		store:           cfg.Store,
		hasher:          cfg.Hasher,
		sessions:        cfg.Sessions,
		limiter:         cfg.Limiter,
		rateLimitSecret: secretCopy,
		clk:             clk,
		logger:          cfg.Logger,
	}, nil
}

// RegisterInput holds user registration parameters.
type RegisterInput struct {
	Email    string
	Name     string
	Password string
	Meta     RequestMeta
}

// Register validates input, rate-limits by IP, hashes the password, and creates
// the user. Duplicate emails perform the same Argon2id work and return nil so
// the HTTP layer always responds with the same generic 202 (anti-enumeration).
func (s *Service) Register(ctx context.Context, in RegisterInput) error {
	if err := s.checkRateLimit(ctx, "auth:register:ip:"+in.Meta.ClientIP, RegisterLimitPerIP, RegisterWindow); err != nil {
		return err
	}

	email, err := policy.NormalizeEmail(in.Email)
	if err != nil {
		return &ValidationError{Field: "email", Message: "must be a valid email address"}
	}
	name, err := policy.NormalizeName(in.Name)
	if err != nil {
		return &ValidationError{Field: "name", Message: "must be between 1 and 120 characters"}
	}
	if err := policy.ValidatePassword(in.Password, email); err != nil {
		return mapPasswordPolicyError(err)
	}

	hash, err := s.hasher.Hash(ctx, in.Password)
	if err != nil {
		if errors.Is(err, password.ErrHasherBusy) {
			return ErrServiceUnavailable
		}
		if errors.Is(err, password.ErrPasswordTooLong) {
			return &ValidationError{Field: "password", Message: "must be at most 128 characters"}
		}
		return fmt.Errorf("register hash password: %w", err)
	}

	userID, err := newUUIDv4()
	if err != nil {
		return fmt.Errorf("register generate user id: %w", err)
	}

	_, err = s.store.CreateUser(ctx, User{
		ID:           userID,
		Email:        email,
		Name:         name,
		PasswordHash: hash,
		Status:       "active",
	})
	if err != nil {
		if errors.Is(err, ErrEmailExists) {
			// Anti-enumeration: identical work done, identical 202 response.
			return nil
		}
		return fmt.Errorf("register create user: %w", err)
	}
	return nil
}

// LoginInput holds user login parameters.
type LoginInput struct {
	Email    string
	Password string
	Meta     RequestMeta
}

// AuthResult carries the newly issued session credentials and user summary.
type AuthResult struct {
	UserID       string
	Email        string
	Name         string
	MFAEnabled   bool
	SessionToken string
	CSRFToken    string
	ExpiresAt    time.Time
	Now          time.Time
}

// Login authenticates a user with strict rate limiting BEFORE Argon2id,
// constant-work anti-enumeration, transparent rehash, and session rotation.
func (s *Service) Login(ctx context.Context, in LoginInput) (AuthResult, error) {
	email, err := policy.NormalizeEmail(in.Email)
	if err != nil {
		return AuthResult{}, &ValidationError{Field: "email", Message: "must be a valid email address"}
	}
	if in.Password == "" || len(in.Password) > password.MaxPasswordBytes {
		return AuthResult{}, &ValidationError{Field: "password", Message: "is required"}
	}

	// ADR-005 §3.1: rate-limit by IP and by (account+IP) BEFORE any Argon2id work.
	if err := s.checkRateLimit(ctx, "auth:login:ip:"+in.Meta.ClientIP, LoginLimitPerIP, LoginWindow); err != nil {
		return AuthResult{}, err
	}
	acctKey := "auth:login:acct_ip:" + ratelimit.HashIdentifier(s.rateLimitSecret, email) + ":" + in.Meta.ClientIP
	if err := s.checkRateLimit(ctx, acctKey, LoginLimitPerAccountIP, LoginWindow); err != nil {
		return AuthResult{}, err
	}

	user, err := s.store.GetUserByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			if dErr := s.hasher.DummyVerify(ctx); dErr != nil {
				if errors.Is(dErr, password.ErrHasherBusy) {
					return AuthResult{}, ErrServiceUnavailable
				}
				return AuthResult{}, fmt.Errorf("login dummy verify: %w", dErr)
			}
			s.recordAudit(ctx, "system", "", "auth.login", "session", "", "failure", in.Meta, nil)
			return AuthResult{}, ErrInvalidCredentials
		}
		return AuthResult{}, fmt.Errorf("login lookup user: %w", err)
	}

	// CTO #14: always execute real Argon2id Verify even if user.Status != "active"
	// so inactive accounts have no timing shortcut.
	ok, err := s.hasher.Verify(ctx, in.Password, user.PasswordHash)
	if err != nil {
		if errors.Is(err, password.ErrHasherBusy) {
			return AuthResult{}, ErrServiceUnavailable
		}
		if errors.Is(err, password.ErrPasswordTooLong) || errors.Is(err, password.ErrInvalidHash) {
			s.recordAudit(ctx, "user", user.ID, "auth.login", "session", "", "failure", in.Meta, nil)
			return AuthResult{}, ErrInvalidCredentials
		}
		return AuthResult{}, fmt.Errorf("login verify password: %w", err)
	}
	if !ok || user.Status != "active" {
		s.recordAudit(ctx, "user", user.ID, "auth.login", "session", "", "failure", in.Meta, nil)
		return AuthResult{}, ErrInvalidCredentials
	}

	// CTO #20: stop here when MFA is enabled; intermediate MFA flow comes before D8.
	if user.MFAEnabled {
		s.recordAudit(ctx, "user", user.ID, "auth.login", "session", "", "denied", in.Meta, []byte(`{"reason":"mfa_required"}`))
		return AuthResult{}, ErrMFARequired
	}

	now := s.clk.Now().UTC()

	// Transparent Argon2id parameter upgrade when hash parameters are outdated.
	if s.hasher.NeedsRehash(user.PasswordHash) {
		if newHash, hErr := s.hasher.Hash(ctx, in.Password); hErr == nil {
			if uErr := s.store.UpdateUserPasswordHash(ctx, user.ID, newHash, now); uErr != nil && s.logger != nil {
				s.logger.Warn("failed to persist rehashed password", "user_id", user.ID, "error", uErr)
			}
		}
	}

	sessToken, tokenHash, err := s.sessions.NewToken()
	if err != nil {
		return AuthResult{}, fmt.Errorf("login new session token: %w", err)
	}
	csrfToken, csrfHash, err := s.sessions.NewCSRFToken()
	if err != nil {
		return AuthResult{}, fmt.Errorf("login new csrf token: %w", err)
	}
	sessID, err := newUUIDv4()
	if err != nil {
		return AuthResult{}, fmt.Errorf("login generate session id: %w", err)
	}

	expiresAt := now.Add(session.DefaultIdleTTL)
	absExpiresAt := now.Add(session.DefaultAbsoluteTTL)

	if err := s.store.CreateSession(ctx, SessionRecord{
		ID:                sessID,
		UserID:            user.ID,
		TokenHash:         tokenHash,
		CSRFTokenHash:     csrfHash,
		LastAuthAt:        now,
		ExpiresAt:         expiresAt,
		AbsoluteExpiresAt: absExpiresAt,
		IPPrefix:          truncateIPPrefix(in.Meta.ClientIP),
		UserAgent:         truncateUserAgent(in.Meta.UserAgent),
	}); err != nil {
		return AuthResult{}, fmt.Errorf("login create session: %w", err)
	}

	s.recordAudit(ctx, "user", user.ID, "auth.login", "session", sessID, "success", in.Meta, nil)

	return AuthResult{
		UserID:       user.ID,
		Email:        user.Email,
		Name:         user.Name,
		MFAEnabled:   user.MFAEnabled,
		SessionToken: sessToken,
		CSRFToken:    csrfToken,
		ExpiresAt:    expiresAt,
		Now:          now,
	}, nil
}

// AuthenticateSession validates an opaque session token from a cookie against
// active, non-revoked, non-expired sessions belonging to an active user.
func (s *Service) AuthenticateSession(ctx context.Context, rawToken string) (ActiveSession, error) {
	if rawToken == "" {
		return ActiveSession{}, ErrSessionExpired
	}
	hash := s.sessions.HashToken(rawToken)
	active, err := s.store.GetActiveSessionByTokenHash(ctx, hash, s.clk.Now().UTC())
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return ActiveSession{}, ErrSessionExpired
		}
		return ActiveSession{}, fmt.Errorf("authenticate session: %w", err)
	}
	return active, nil
}

// Logout revokes the active session and records a global audit log entry.
func (s *Service) Logout(ctx context.Context, active ActiveSession, meta RequestMeta) error {
	now := s.clk.Now().UTC()
	if err := s.store.RevokeSession(ctx, active.ID, now); err != nil {
		return fmt.Errorf("logout revoke session: %w", err)
	}
	s.recordAudit(ctx, "user", active.UserID, "auth.logout", "session", active.ID, "success", meta, nil)
	return nil
}

// Refresh rotates the session token and CSRF token, extending the sliding 7-day
// expiry without ever exceeding the 30-day absolute expiry or extending last_auth_at.
func (s *Service) Refresh(ctx context.Context, active ActiveSession, meta RequestMeta) (AuthResult, error) {
	now := s.clk.Now().UTC()
	if !active.ExpiresAt.After(now) || !active.AbsoluteExpiresAt.After(now) {
		return AuthResult{}, ErrSessionExpired
	}

	newExpires := now.Add(session.DefaultIdleTTL)
	if newExpires.After(active.AbsoluteExpiresAt) {
		newExpires = active.AbsoluteExpiresAt
	}

	sessToken, tokenHash, err := s.sessions.NewToken()
	if err != nil {
		return AuthResult{}, fmt.Errorf("refresh new session token: %w", err)
	}
	csrfToken, csrfHash, err := s.sessions.NewCSRFToken()
	if err != nil {
		return AuthResult{}, fmt.Errorf("refresh new csrf token: %w", err)
	}
	newSessID, err := newUUIDv4()
	if err != nil {
		return AuthResult{}, fmt.Errorf("refresh generate session id: %w", err)
	}

	if err := s.store.RotateSession(ctx, active.ID, SessionRecord{
		ID:                newSessID,
		UserID:            active.UserID,
		TokenHash:         tokenHash,
		CSRFTokenHash:     csrfHash,
		LastAuthAt:        active.LastAuthAt,
		ExpiresAt:         newExpires,
		AbsoluteExpiresAt: active.AbsoluteExpiresAt,
		IPPrefix:          truncateIPPrefix(meta.ClientIP),
		UserAgent:         truncateUserAgent(meta.UserAgent),
	}, now); err != nil {
		return AuthResult{}, fmt.Errorf("refresh rotate session: %w", err)
	}

	return AuthResult{
		UserID:       active.UserID,
		Email:        active.UserEmail,
		Name:         active.UserName,
		MFAEnabled:   active.UserMFAEnabled,
		SessionToken: sessToken,
		CSRFToken:    csrfToken,
		ExpiresAt:    newExpires,
		Now:          now,
	}, nil
}

// DeactivateUser transitions a user out of 'active' and revokes all their
// active sessions atomically (CTO #14).
func (s *Service) DeactivateUser(ctx context.Context, userID, status string) error {
	if status != "disabled" && status != "deleted" {
		return &ValidationError{Field: "status", Message: "must be disabled or deleted"}
	}
	return s.store.DeactivateUser(ctx, userID, status, s.clk.Now().UTC())
}

func (s *Service) checkRateLimit(ctx context.Context, key string, limit int, window time.Duration) error {
	res, err := s.limiter.Allow(ctx, key, limit, window)
	if err != nil {
		if s.logger != nil {
			s.logger.Error("auth rate limiter unavailable; failing closed", "error", err)
		}
		return ErrServiceUnavailable
	}
	if !res.Allowed {
		return &RateLimitError{Result: res}
	}
	return nil
}

func (s *Service) recordAudit(ctx context.Context, actorType, actorID, action, resType, resID, result string, meta RequestMeta, changes []byte) {
	id, err := newUUIDv4()
	if err != nil {
		return
	}
	reqID := meta.RequestID
	if strings.TrimSpace(reqID) == "" {
		reqID = "unknown"
	}
	if len(changes) == 0 {
		changes = []byte("{}")
	}
	if err := s.store.InsertGlobalAuditLog(ctx, AuditEvent{
		ID:           id,
		ActorType:    actorType,
		ActorID:      actorID,
		Action:       action,
		ResourceType: resType,
		ResourceID:   resID,
		Result:       result,
		IPPrefix:     truncateIPPrefix(meta.ClientIP),
		UserAgent:    truncateUserAgent(meta.UserAgent),
		RequestID:    reqID,
		ChangesJSON:  changes,
	}); err != nil && s.logger != nil {
		s.logger.Warn("failed to persist global auth audit log", "action", action, "error", err)
	}
}

func mapPasswordPolicyError(err error) *ValidationError {
	switch {
	case errors.Is(err, policy.ErrPasswordTooShort):
		return &ValidationError{Field: "password", Message: "must be at least 12 characters"}
	case errors.Is(err, policy.ErrPasswordTooLong):
		return &ValidationError{Field: "password", Message: "must be at most 128 characters"}
	case errors.Is(err, policy.ErrPasswordCommon):
		return &ValidationError{Field: "password", Message: "is too common; choose a stronger password"}
	case errors.Is(err, policy.ErrPasswordHasEmail):
		return &ValidationError{Field: "password", Message: "must not match or contain your email"}
	default:
		return &ValidationError{Field: "password", Message: "is invalid"}
	}
}

func truncateIPPrefix(raw string) *string {
	addr, err := netip.ParseAddr(strings.TrimSpace(raw))
	if err != nil {
		return nil
	}
	bits := 24
	if addr.Is6() {
		bits = 48
	}
	p, err := addr.Prefix(bits)
	if err != nil {
		return nil
	}
	s := p.String()
	return &s
}

func truncateUserAgent(raw string) *string {
	s := strings.TrimSpace(raw)
	if s == "" {
		return nil
	}
	if len(s) > maxStoredUserAgentLen {
		s = s[:maxStoredUserAgentLen]
	}
	return &s
}

func newUUIDv4() (string, error) {
	var b [16]byte
	if _, err := io.ReadFull(rand.Reader, b[:]); err != nil {
		return "", err
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16],
	), nil
}
