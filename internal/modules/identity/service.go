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
	"unicode/utf8"

	"github.com/Yhanko/vigia/internal/modules/identity/internal/policy"
	"github.com/Yhanko/vigia/internal/modules/identity/password"
	"github.com/Yhanko/vigia/internal/modules/identity/session"
	"github.com/Yhanko/vigia/internal/platform/clock"
	"github.com/Yhanko/vigia/internal/platform/ratelimit"
)

// Rate-limit defaults from docs/decisions/business-defaults.md §4.
const (
	RegisterLimitPerIP            = 5
	RegisterWindow                = time.Hour
	LoginLimitPerIP               = 10
	LoginLimitPerAccountIP        = 5
	LoginWindow                   = 15 * time.Minute
	PasswordForgotLimitPerEmail   = 3
	PasswordForgotLimitPerIP      = 10
	PasswordForgotWindow          = 15 * time.Minute
	PasswordResetLimitPerIP       = 10
	PasswordResetWindow           = 15 * time.Minute
	VerifyEmailLimitPerIP         = 20
	VerifyEmailWindow             = 15 * time.Minute

	maxStoredUserAgentLen = 200
)

// User represents a global identity user record.
type User struct {
	ID                 string
	Email              string
	Name               string
	PasswordHash       string
	MFAEnabled         bool
	MFASecretEncrypted []byte
	MFALastUsedStep    *int64
	Status             string
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
	MFAPending        bool
}

// ActiveSession represents a validated, non-revoked, non-expired session joined
// with an active user (CTO #14).
type ActiveSession struct {
	ID                     string
	UserID                 string
	CSRFTokenHash          []byte
	LastAuthAt             time.Time
	ExpiresAt              time.Time
	AbsoluteExpiresAt      time.Time
	MFAPending             bool
	MFAFailedAttempts      int16
	UserEmail              string
	UserName               string
	UserMFAEnabled         bool
	UserMFASecretEncrypted []byte
	UserMFALastUsedStep    *int64
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

// UserTokenRecord holds the fields for inserting a hashed ephemeral token.
type UserTokenRecord struct {
	ID        string
	UserID    string
	Kind      string
	TokenHash []byte
	ExpiresAt *time.Time
}

// Mailer is the consumer-defined interface for sending transactional plain-text emails.
type Mailer interface {
	Send(ctx context.Context, to, subject, textBody string) error
}

// Store is the consumer-defined persistence interface for the identity service.
type Store interface {
	CreateUser(ctx context.Context, u User) (User, error)
	GetUserByEmail(ctx context.Context, normalizedEmail string) (User, error)
	GetUserByID(ctx context.Context, userID string) (User, error)
	UpdateUserPasswordHash(ctx context.Context, userID, passwordHash string, updatedAt time.Time) error
	DeactivateUser(ctx context.Context, userID, status string, now time.Time) error
	CreateSession(ctx context.Context, s SessionRecord) error
	GetActiveSessionByTokenHash(ctx context.Context, tokenHash []byte, now time.Time) (ActiveSession, error)
	GetPendingMFASessionByTokenHash(ctx context.Context, tokenHash []byte, now time.Time) (ActiveSession, error)
	RevokeSession(ctx context.Context, sessionID string, revokedAt time.Time) error
	RotateSession(ctx context.Context, oldSessionID string, next SessionRecord, revokedAt time.Time) error
	SetUserPendingMFASecret(ctx context.Context, userID string, encrypted []byte, now time.Time) error
	ActivateMFA(ctx context.Context, userID, oldSessionID string, step int64, recoveryTokens []UserTokenRecord, next SessionRecord, now time.Time) error
	CompleteMFALogin(ctx context.Context, userID, pendingSessionID string, step *int64, recoveryTokenHash []byte, next SessionRecord, now time.Time) error
	RecordPendingMFAFailure(ctx context.Context, pendingSessionID string, now time.Time) (revoked bool, err error)
	UpdateUserMFALastUsedStep(ctx context.Context, userID string, step int64, now time.Time) error
	CreateUserToken(ctx context.Context, rec UserTokenRecord) error
	ReplaceUserToken(ctx context.Context, rec UserTokenRecord, now time.Time) error
	VerifyEmailByToken(ctx context.Context, tokenHash []byte, now time.Time) (string, error)
	ResetPasswordByToken(ctx context.Context, tokenHash []byte, newPasswordHash string, now time.Time) (User, error)
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
	Peek(ctx context.Context, key string, limit int, window time.Duration) (ratelimit.Result, error)
	Reset(ctx context.Context, key string) error
}

// ServiceConfig holds the dependencies for the identity domain service.
type ServiceConfig struct {
	Store           Store
	Hasher          PasswordHasher
	Sessions        *session.Codec
	Limiter         RateLimiter
	RateLimitSecret []byte
	Encrypter       SecretEncrypter
	Mailer          Mailer
	AppURL          string
	Clock           clock.Clock
	Logger          *slog.Logger
}

// Service implements register, login, logout, refresh, email verification,
// password reset, MFA, reauth, and session authentication.
type Service struct {
	store           Store
	hasher          PasswordHasher
	sessions        *session.Codec
	limiter         RateLimiter
	rateLimitSecret []byte
	encrypter       SecretEncrypter
	mailer          Mailer
	appURL          string
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
		encrypter:       cfg.Encrypter,
		mailer:          cfg.Mailer,
		appURL:          strings.TrimRight(strings.TrimSpace(cfg.AppURL), "/"),
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

	// Issue single-use email verification token (24h) and send email outside DB tx.
	if rawTok, tErr := generateOpaqueToken(); tErr == nil {
		if tokID, idErr := newUUIDv4(); idErr == nil {
			exp := s.clk.Now().UTC().Add(EmailVerifyTokenTTL)
			if cErr := s.store.CreateUserToken(ctx, UserTokenRecord{
				ID:        tokID,
				UserID:    userID,
				Kind:      TokenKindEmailVerify,
				TokenHash: hashUserToken(s.rateLimitSecret, TokenKindEmailVerify, rawTok),
				ExpiresAt: &exp,
			}); cErr == nil {
				s.sendEmail(ctx, email, "Verify your Vigia email",
					fmt.Sprintf("Hello %s,\n\nVerify your Vigia account by opening:\n%s/verify-email?token=%s\n\nThis link expires in 24 hours.\n", name, s.appURL, rawTok))
			} else if s.logger != nil {
				s.logger.Warn("failed to create email verification token", "user_id", userID, "error", cErr)
			}
		}
	}
	return nil
}

// VerifyEmail consumes a single-use 24h verification token and marks the user's
// email as verified.
func (s *Service) VerifyEmail(ctx context.Context, rawToken string, meta RequestMeta) error {
	if err := s.checkRateLimit(ctx, "auth:verify_email:ip:"+meta.ClientIP, VerifyEmailLimitPerIP, VerifyEmailWindow); err != nil {
		return err
	}
	rawToken = strings.TrimSpace(rawToken)
	if rawToken == "" {
		return &ValidationError{Field: "token", Message: "is invalid or expired"}
	}

	tokHash := hashUserToken(s.rateLimitSecret, TokenKindEmailVerify, rawToken)
	userID, err := s.store.VerifyEmailByToken(ctx, tokHash, s.clk.Now().UTC())
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return &ValidationError{Field: "token", Message: "is invalid or expired"}
		}
		return fmt.Errorf("verify email: %w", err)
	}

	s.recordAudit(ctx, "user", userID, "auth.email_verified", "user", userID, "success", meta, nil)
	return nil
}

// ForgotPassword initiates password recovery with strict rate limits (3/15m per
// email and 10/15m per IP), invalidates previous reset tokens, and sends a
// single-use 30-minute reset link outside any DB transaction (critical-flows.md §2).
// Always returns nil on valid input (anti-enumeration).
func (s *Service) ForgotPassword(ctx context.Context, rawEmail string, meta RequestMeta) error {
	email, err := policy.NormalizeEmail(rawEmail)
	if err != nil {
		return &ValidationError{Field: "email", Message: "must be a valid email address"}
	}

	if err := s.checkRateLimit(ctx, "auth:pwforgot:ip:"+meta.ClientIP, PasswordForgotLimitPerIP, PasswordForgotWindow); err != nil {
		return err
	}
	emailKey := "auth:pwforgot:email:" + ratelimit.HashIdentifier(s.rateLimitSecret, email)
	if err := s.checkRateLimit(ctx, emailKey, PasswordForgotLimitPerEmail, PasswordForgotWindow); err != nil {
		return err
	}

	user, err := s.store.GetUserByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		return fmt.Errorf("forgot password lookup: %w", err)
	}
	if user.Status != "active" {
		return nil
	}

	rawTok, err := generateOpaqueToken()
	if err != nil {
		return fmt.Errorf("forgot password generate token: %w", err)
	}
	tokID, err := newUUIDv4()
	if err != nil {
		return fmt.Errorf("forgot password generate token id: %w", err)
	}
	now := s.clk.Now().UTC()
	exp := now.Add(PasswordResetTokenTTL)
	if err := s.store.ReplaceUserToken(ctx, UserTokenRecord{
		ID:        tokID,
		UserID:    user.ID,
		Kind:      TokenKindPasswordReset,
		TokenHash: hashUserToken(s.rateLimitSecret, TokenKindPasswordReset, rawTok),
		ExpiresAt: &exp,
	}, now); err != nil {
		return fmt.Errorf("forgot password store token: %w", err)
	}

	s.sendEmail(ctx, user.Email, "Reset your Vigia password",
		fmt.Sprintf("Hello %s,\n\nA password reset was requested for your Vigia account.\nOpen the link below within 30 minutes:\n%s/reset-password?token=%s\n\nIf you did not request this, you can safely ignore this email.\n", user.Name, s.appURL, rawTok))
	return nil
}

// ResetPassword validates the new password, consumes the single-use reset token,
// updates password_hash, revokes ALL active sessions, records an audit event,
// and sends a security notification email outside the DB transaction.
func (s *Service) ResetPassword(ctx context.Context, rawToken, newPassword string, meta RequestMeta) error {
	if err := s.checkRateLimit(ctx, "auth:pwreset:ip:"+meta.ClientIP, PasswordResetLimitPerIP, PasswordResetWindow); err != nil {
		return err
	}
	rawToken = strings.TrimSpace(rawToken)
	if rawToken == "" {
		return &ValidationError{Field: "token", Message: "is invalid or expired"}
	}
	if err := policy.ValidatePassword(newPassword, ""); err != nil {
		return mapPasswordPolicyError(err)
	}

	hash, err := s.hasher.Hash(ctx, newPassword)
	if err != nil {
		if errors.Is(err, password.ErrHasherBusy) {
			return ErrServiceUnavailable
		}
		if errors.Is(err, password.ErrPasswordTooLong) {
			return &ValidationError{Field: "password", Message: "must be at most 128 characters"}
		}
		return fmt.Errorf("reset password hash: %w", err)
	}

	tokHash := hashUserToken(s.rateLimitSecret, TokenKindPasswordReset, rawToken)
	user, err := s.store.ResetPasswordByToken(ctx, tokHash, hash, s.clk.Now().UTC())
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return &ValidationError{Field: "token", Message: "is invalid or expired"}
		}
		return fmt.Errorf("reset password persist: %w", err)
	}

	s.recordAudit(ctx, "user", user.ID, "auth.password_reset", "user", user.ID, "success", meta, nil)
	s.sendEmail(ctx, user.Email, "Your Vigia password was changed",
		fmt.Sprintf("Hello %s,\n\nYour Vigia password has been reset and all active sessions have been signed out.\nIf you did not perform this action, contact support immediately.\n", user.Name))
	return nil
}

func (s *Service) sendEmail(ctx context.Context, to, subject, body string) {
	if s.mailer == nil {
		return
	}
	if err := s.mailer.Send(ctx, to, subject, body); err != nil && s.logger != nil {
		s.logger.Warn("failed to send transactional email", "subject", subject, "error", err)
	}
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
	MFAPending   bool
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

	// ADR-005 §3.1 & CTO #23: rate-limit by IP (all attempts) and Peek
	// (account+IP) failure lockout BEFORE any Argon2id work.
	if err := s.checkRateLimit(ctx, "auth:login:ip:"+in.Meta.ClientIP, LoginLimitPerIP, LoginWindow); err != nil {
		return AuthResult{}, err
	}
	acctKey := "auth:login:acct_ip:" + ratelimit.HashIdentifier(s.rateLimitSecret, email) + ":" + in.Meta.ClientIP
	if err := s.peekRateLimit(ctx, acctKey, LoginLimitPerAccountIP, LoginWindow); err != nil {
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
			s.recordLoginFailure(ctx, acctKey)
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
			s.recordLoginFailure(ctx, acctKey)
			s.recordAudit(ctx, "user", user.ID, "auth.login", "session", "", "failure", in.Meta, nil)
			return AuthResult{}, ErrInvalidCredentials
		}
		return AuthResult{}, fmt.Errorf("login verify password: %w", err)
	}
	if !ok || user.Status != "active" {
		s.recordLoginFailure(ctx, acctKey)
		s.recordAudit(ctx, "user", user.ID, "auth.login", "session", "", "failure", in.Meta, nil)
		return AuthResult{}, ErrInvalidCredentials
	}

	// Successful password verification resets the (account+IP) failure lockout counter (CTO #23).
	if rErr := s.limiter.Reset(ctx, acctKey); rErr != nil && s.logger != nil {
		s.logger.Warn("failed to reset login failure counter", "error", rErr)
	}

	now := s.clk.Now().UTC()

	// Two-step MFA login (§7.1): create short-lived (10m) mfa_pending session and return 202.
	if user.MFAEnabled {
		sessToken, tokenHash, err := s.sessions.NewToken()
		if err != nil {
			return AuthResult{}, fmt.Errorf("login pending mfa token: %w", err)
		}
		csrfToken, csrfHash, err := s.sessions.NewCSRFToken()
		if err != nil {
			return AuthResult{}, fmt.Errorf("login pending mfa csrf: %w", err)
		}
		sessID, err := newUUIDv4()
		if err != nil {
			return AuthResult{}, fmt.Errorf("login pending mfa id: %w", err)
		}
		pendingExp := now.Add(PendingMFASessionTTL)
		if err := s.store.CreateSession(ctx, SessionRecord{
			ID:                sessID,
			UserID:            user.ID,
			TokenHash:         tokenHash,
			CSRFTokenHash:     csrfHash,
			LastAuthAt:        now,
			ExpiresAt:         pendingExp,
			AbsoluteExpiresAt: pendingExp,
			IPPrefix:          truncateIPPrefix(in.Meta.ClientIP),
			UserAgent:         truncateUserAgent(in.Meta.UserAgent),
			MFAPending:        true,
		}); err != nil {
			return AuthResult{}, fmt.Errorf("login create pending mfa session: %w", err)
		}
		s.recordAudit(ctx, "user", user.ID, "auth.login", "session", sessID, "success", in.Meta, []byte(`{"mfa_pending":true}`))
		return AuthResult{
			UserID:       user.ID,
			Email:        user.Email,
			Name:         user.Name,
			MFAEnabled:   true,
			MFAPending:   true,
			SessionToken: sessToken,
			CSRFToken:    csrfToken,
			ExpiresAt:    pendingExp,
			Now:          now,
		}, nil
	}

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

func (s *Service) peekRateLimit(ctx context.Context, key string, limit int, window time.Duration) error {
	res, err := s.limiter.Peek(ctx, key, limit, window)
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

func (s *Service) recordLoginFailure(ctx context.Context, acctKey string) {
	if _, err := s.limiter.Allow(ctx, acctKey, LoginLimitPerAccountIP, LoginWindow); err != nil && s.logger != nil {
		s.logger.Warn("failed to record login failure in rate limiter", "error", err)
	}
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
	// Sanitize invalid UTF-8 and NUL bytes (rejected by PostgreSQL text columns)
	// and truncate on a rune boundary so UTF-8 is never split mid-sequence (CTO #24).
	s := strings.ReplaceAll(strings.ToValidUTF8(strings.TrimSpace(raw), ""), "\x00", "")
	if s == "" {
		return nil
	}
	if len(s) > maxStoredUserAgentLen {
		cut := 0
		for i := range s {
			if i > maxStoredUserAgentLen {
				break
			}
			cut = i
		}
		if cut == 0 {
			_, size := utf8.DecodeRuneInString(s)
			if size <= maxStoredUserAgentLen {
				cut = size
			}
		}
		s = s[:cut]
	}
	if s == "" {
		return nil
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
