package identity

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Yhanko/vigia/internal/modules/identity/internal/totp"
	"github.com/Yhanko/vigia/internal/modules/identity/password"
	"github.com/Yhanko/vigia/internal/modules/identity/session"
	"github.com/Yhanko/vigia/internal/platform/crypto"
)

const (
	PendingMFASessionTTL   = 10 * time.Minute
	MFAVerifyLimitPerIP    = 5
	MFAVerifyWindow        = 15 * time.Minute
	ReauthLimitPerSession  = 5
	ReauthWindowPerSession = 15 * time.Minute
	mfaIssuerName          = "Vigia"
)

// SecretEncrypter is the consumer-defined minimal interface satisfied by
// *crypto.EnvelopeEncrypter (CTO #7, ADR-015).
type SecretEncrypter interface {
	Encrypt(scope crypto.Scope, plaintext []byte) ([]byte, error)
	Decrypt(scope crypto.Scope, envelope []byte) ([]byte, error)
}

// MFASetupResult holds the provisioning secret and otpauth URI shown once.
type MFASetupResult struct {
	Secret     string
	OtpauthURI string
}

// MFAVerifyResult extends AuthResult with one-time recovery codes on activation.
type MFAVerifyResult struct {
	AuthResult
	RecoveryCodes []string
}

func mfaSecretScope(userID string) crypto.Scope {
	return crypto.Scope{
		OwnerType: crypto.OwnerTypeUser,
		OwnerID:   userID,
		Table:     "users",
		Column:    "mfa_secret_encrypted",
		RecordID:  userID,
	}
}

// AuthenticatePendingMFASession validates an opaque cookie token for a pending
// MFA session (used ONLY by /auth/mfa/verify and /auth/logout, §7.1).
func (s *Service) AuthenticatePendingMFASession(ctx context.Context, rawToken string) (ActiveSession, error) {
	if rawToken == "" {
		return ActiveSession{}, ErrSessionExpired
	}
	hash := s.sessions.HashToken(rawToken)
	active, err := s.store.GetPendingMFASessionByTokenHash(ctx, hash, s.clk.Now().UTC())
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return ActiveSession{}, ErrSessionExpired
		}
		return ActiveSession{}, fmt.Errorf("authenticate pending mfa session: %w", err)
	}
	return active, nil
}

// SetupMFA generates a fresh 20-byte TOTP secret, encrypts it with the injected
// EnvelopeEncrypter (ADR-015), and stores it while keeping mfa_enabled=false
// until verified via VerifyMFA (§7.2). Requires recent authentication (<= 10m).
func (s *Service) SetupMFA(ctx context.Context, active ActiveSession) (MFASetupResult, error) {
	now := s.clk.Now().UTC()
	if now.Sub(active.LastAuthAt) > session.DefaultReauthWindow {
		return MFASetupResult{}, ErrReauthRequired
	}
	if active.UserMFAEnabled {
		return MFASetupResult{}, &ValidationError{Field: "mfa", Message: "MFA is already enabled"}
	}
	if s.encrypter == nil {
		return MFASetupResult{}, ErrServiceUnavailable
	}

	rawSecret, b32Secret, err := totp.GenerateSecret()
	if err != nil {
		return MFASetupResult{}, fmt.Errorf("mfa setup generate secret: %w", err)
	}
	defer clear(rawSecret)

	encrypted, err := s.encrypter.Encrypt(mfaSecretScope(active.UserID), rawSecret)
	if err != nil {
		return MFASetupResult{}, fmt.Errorf("mfa setup encrypt secret: %w", err)
	}

	if err := s.store.SetUserPendingMFASecret(ctx, active.UserID, encrypted, now); err != nil {
		return MFASetupResult{}, fmt.Errorf("mfa setup store secret: %w", err)
	}

	return MFASetupResult{
		Secret:     b32Secret,
		OtpauthURI: totp.ProvisioningURI(mfaIssuerName, active.UserEmail, b32Secret),
	}, nil
}

// VerifyMFA handles both MFA activation (normal session with mfa_enabled=false)
// and two-step login completion (mfa_pending session with mfa_enabled=true) (§7.1–7.3).
func (s *Service) VerifyMFA(ctx context.Context, active ActiveSession, code, recoveryCode string, meta RequestMeta) (MFAVerifyResult, error) {
	if err := s.checkRateLimit(ctx, "auth:mfa:ip:"+meta.ClientIP, MFAVerifyLimitPerIP, MFAVerifyWindow); err != nil {
		return MFAVerifyResult{}, err
	}
	if s.encrypter == nil {
		return MFAVerifyResult{}, ErrServiceUnavailable
	}

	code = strings.TrimSpace(code)
	recoveryCode = strings.TrimSpace(recoveryCode)
	if code == "" && recoveryCode == "" {
		return MFAVerifyResult{}, &ValidationError{Field: "code", Message: "either code or recoveryCode is required"}
	}

	now := s.clk.Now().UTC()

	// Branch 1: Completing initial MFA enrollment (normal session, mfa_enabled == false).
	if !active.MFAPending {
		if active.UserMFAEnabled {
			return MFAVerifyResult{}, &ValidationError{Field: "mfa", Message: "MFA is already enabled"}
		}
		if code == "" || len(active.UserMFASecretEncrypted) == 0 {
			return MFAVerifyResult{}, ErrInvalidMFACode
		}

		rawSecret, err := s.encrypter.Decrypt(mfaSecretScope(active.UserID), active.UserMFASecretEncrypted)
		if err != nil {
			return MFAVerifyResult{}, fmt.Errorf("mfa verify decrypt secret: %w", err)
		}
		defer clear(rawSecret)

		step, ok := totp.Verify(rawSecret, code, now, active.UserMFALastUsedStep)
		if !ok {
			s.recordAudit(ctx, "user", active.UserID, "auth.mfa.verify", "user", active.UserID, "failure", meta, nil)
			return MFAVerifyResult{}, ErrInvalidMFACode
		}

		recoveryCodes, err := totp.GenerateRecoveryCodes(totp.RecoveryCount)
		if err != nil {
			return MFAVerifyResult{}, fmt.Errorf("mfa verify generate recovery codes: %w", err)
		}
		tokenRecs := make([]UserTokenRecord, 0, len(recoveryCodes))
		for _, rc := range recoveryCodes {
			tid, err := newUUIDv4()
			if err != nil {
				return MFAVerifyResult{}, err
			}
			tokenRecs = append(tokenRecs, UserTokenRecord{
				ID:        tid,
				UserID:    active.UserID,
				Kind:      TokenKindMFARecovery,
				TokenHash: totp.HashRecoveryCode(s.rateLimitSecret, rc),
			})
		}

		nextSess, sessToken, csrfToken, err := s.buildFullSession(active.UserID, now, meta)
		if err != nil {
			return MFAVerifyResult{}, err
		}

		if err := s.store.ActivateMFA(ctx, active.UserID, active.ID, step, tokenRecs, nextSess, now); err != nil {
			if errors.Is(err, ErrInvalidMFACode) {
				s.recordAudit(ctx, "user", active.UserID, "auth.mfa.verify", "user", active.UserID, "failure", meta, nil)
				return MFAVerifyResult{}, ErrInvalidMFACode
			}
			return MFAVerifyResult{}, fmt.Errorf("mfa activate: %w", err)
		}

		s.recordAudit(ctx, "user", active.UserID, "auth.mfa.enabled", "user", active.UserID, "success", meta, nil)
		s.sendEmail(ctx, active.UserEmail, "Multi-factor authentication enabled on Vigia",
			fmt.Sprintf("Hello %s,\n\nMulti-factor authentication (TOTP) has been enabled on your Vigia account and all other sessions have been signed out.\n", active.UserName))

		return MFAVerifyResult{
			AuthResult: AuthResult{
				UserID:       active.UserID,
				Email:        active.UserEmail,
				Name:         active.UserName,
				MFAEnabled:   true,
				SessionToken: sessToken,
				CSRFToken:    csrfToken,
				ExpiresAt:    nextSess.ExpiresAt,
				Now:          now,
			},
			RecoveryCodes: recoveryCodes,
		}, nil
	}

	// Branch 2: Completing two-step login (mfa_pending == true).
	var (
		matchedStep *int64
		usedRecHash []byte
	)
	if code != "" {
		if len(active.UserMFASecretEncrypted) == 0 {
			return MFAVerifyResult{}, ErrInvalidMFACode
		}
		rawSecret, err := s.encrypter.Decrypt(mfaSecretScope(active.UserID), active.UserMFASecretEncrypted)
		if err != nil {
			return MFAVerifyResult{}, fmt.Errorf("mfa login decrypt secret: %w", err)
		}
		defer clear(rawSecret)

		step, ok := totp.Verify(rawSecret, code, now, active.UserMFALastUsedStep)
		if !ok {
			return s.handlePendingMFAFailure(ctx, active, now, meta)
		}
		matchedStep = &step
	} else {
		usedRecHash = totp.HashRecoveryCode(s.rateLimitSecret, recoveryCode)
	}

	nextSess, sessToken, csrfToken, err := s.buildFullSession(active.UserID, now, meta)
	if err != nil {
		return MFAVerifyResult{}, err
	}

	if err := s.store.CompleteMFALogin(ctx, active.UserID, active.ID, matchedStep, usedRecHash, nextSess, now); err != nil {
		if errors.Is(err, ErrInvalidMFACode) {
			return s.handlePendingMFAFailure(ctx, active, now, meta)
		}
		return MFAVerifyResult{}, fmt.Errorf("mfa complete login: %w", err)
	}

	s.recordAudit(ctx, "user", active.UserID, "auth.mfa.verify", "session", nextSess.ID, "success", meta, nil)

	return MFAVerifyResult{
		AuthResult: AuthResult{
			UserID:       active.UserID,
			Email:        active.UserEmail,
			Name:         active.UserName,
			MFAEnabled:   true,
			SessionToken: sessToken,
			CSRFToken:    csrfToken,
			ExpiresAt:    nextSess.ExpiresAt,
			Now:          now,
		},
	}, nil
}

func (s *Service) handlePendingMFAFailure(ctx context.Context, active ActiveSession, now time.Time, meta RequestMeta) (MFAVerifyResult, error) {
	s.recordAudit(ctx, "user", active.UserID, "auth.mfa.verify", "session", active.ID, "failure", meta, nil)
	revoked, err := s.store.RecordPendingMFAFailure(ctx, active.ID, now)
	if err != nil {
		return MFAVerifyResult{}, fmt.Errorf("record mfa failure: %w", err)
	}
	if revoked {
		return MFAVerifyResult{}, ErrSessionExpired
	}
	return MFAVerifyResult{}, ErrInvalidMFACode
}

// Reauth verifies password (and TOTP code when MFA is enabled), rotates the
// active session, and updates last_auth_at = now (§7.4). Enforces a per-session
// lockout of 5 failures / 15m; on the 5th failure the session is revoked (CTO #35).
func (s *Service) Reauth(ctx context.Context, active ActiveSession, plainPassword, totpCode string, meta RequestMeta) (AuthResult, error) {
	if err := s.checkRateLimit(ctx, "auth:login:ip:"+meta.ClientIP, LoginLimitPerIP, LoginWindow); err != nil {
		return AuthResult{}, err
	}
	sessKey := "auth:reauth:session:" + active.ID
	now := s.clk.Now().UTC()
	if peekRes, err := s.limiter.Peek(ctx, sessKey, ReauthLimitPerSession, ReauthWindowPerSession); err != nil {
		return AuthResult{}, ErrServiceUnavailable
	} else if !peekRes.Allowed {
		_ = s.store.RevokeSession(ctx, active.ID, now)
		s.recordAudit(ctx, "user", active.UserID, "auth.reauth.session_revoked", "session", active.ID, "denied", meta, nil)
		return AuthResult{}, ErrSessionExpired
	}

	if plainPassword == "" || len(plainPassword) > password.MaxPasswordBytes {
		return AuthResult{}, &ValidationError{Field: "password", Message: "is required"}
	}

	user, err := s.store.GetUserByID(ctx, active.UserID)
	if err != nil {
		return AuthResult{}, fmt.Errorf("reauth lookup user: %w", err)
	}
	ok, err := s.hasher.Verify(ctx, plainPassword, user.PasswordHash)
	if err != nil {
		if errors.Is(err, password.ErrHasherBusy) {
			return AuthResult{}, ErrServiceUnavailable
		}
		return AuthResult{}, s.handleReauthFailure(ctx, active, sessKey, now, meta, ErrInvalidCredentials)
	}
	if !ok || user.Status != "active" {
		return AuthResult{}, s.handleReauthFailure(ctx, active, sessKey, now, meta, ErrInvalidCredentials)
	}

	var matchedStep *int64
	if user.MFAEnabled {
		if s.encrypter == nil {
			return AuthResult{}, ErrServiceUnavailable
		}
		rawSecret, err := s.encrypter.Decrypt(mfaSecretScope(user.ID), user.MFASecretEncrypted)
		if err != nil {
			return AuthResult{}, fmt.Errorf("reauth decrypt mfa secret: %w", err)
		}
		defer clear(rawSecret)

		step, ok := totp.Verify(rawSecret, totpCode, now, user.MFALastUsedStep)
		if !ok {
			return AuthResult{}, s.handleReauthFailure(ctx, active, sessKey, now, meta, ErrInvalidMFACode)
		}
		matchedStep = &step
	}

	nextSess, sessToken, csrfToken, err := s.buildFullSession(active.UserID, now, meta)
	if err != nil {
		return AuthResult{}, err
	}
	nextSess.AbsoluteExpiresAt = active.AbsoluteExpiresAt
	if nextSess.ExpiresAt.After(active.AbsoluteExpiresAt) {
		nextSess.ExpiresAt = active.AbsoluteExpiresAt
	}

	if err := s.store.ReauthRotate(ctx, user.ID, active.ID, matchedStep, nextSess, now); err != nil {
		if errors.Is(err, ErrInvalidMFACode) {
			return AuthResult{}, s.handleReauthFailure(ctx, active, sessKey, now, meta, ErrInvalidMFACode)
		}
		if errors.Is(err, ErrSessionExpired) {
			return AuthResult{}, ErrSessionExpired
		}
		return AuthResult{}, fmt.Errorf("reauth rotate session: %w", err)
	}

	_ = s.limiter.Reset(ctx, sessKey)
	s.recordAudit(ctx, "user", active.UserID, "auth.reauth", "session", nextSess.ID, "success", meta, nil)
	return AuthResult{
		UserID:       user.ID,
		Email:        user.Email,
		Name:         user.Name,
		MFAEnabled:   user.MFAEnabled,
		SessionToken: sessToken,
		CSRFToken:    csrfToken,
		ExpiresAt:    nextSess.ExpiresAt,
		Now:          now,
	}, nil
}

func (s *Service) handleReauthFailure(ctx context.Context, active ActiveSession, sessKey string, now time.Time, meta RequestMeta, baseErr error) error {
	s.recordAudit(ctx, "user", active.UserID, "auth.reauth", "session", active.ID, "failure", meta, nil)
	res, err := s.limiter.Allow(ctx, sessKey, ReauthLimitPerSession, ReauthWindowPerSession)
	if err != nil {
		return ErrServiceUnavailable
	}
	if !res.Allowed || res.Remaining == 0 {
		_ = s.store.RevokeSession(ctx, active.ID, now)
		s.recordAudit(ctx, "user", active.UserID, "auth.reauth.session_revoked", "session", active.ID, "denied", meta, nil)
		return ErrSessionExpired
	}
	return baseErr
}

func (s *Service) buildFullSession(userID string, now time.Time, meta RequestMeta) (SessionRecord, string, string, error) {
	sessToken, tokenHash, err := s.sessions.NewToken()
	if err != nil {
		return SessionRecord{}, "", "", fmt.Errorf("new session token: %w", err)
	}
	csrfToken, csrfHash, err := s.sessions.NewCSRFToken()
	if err != nil {
		return SessionRecord{}, "", "", fmt.Errorf("new csrf token: %w", err)
	}
	sessID, err := newUUIDv4()
	if err != nil {
		return SessionRecord{}, "", "", fmt.Errorf("generate session id: %w", err)
	}
	return SessionRecord{
		ID:                sessID,
		UserID:            userID,
		TokenHash:         tokenHash,
		CSRFTokenHash:     csrfHash,
		LastAuthAt:        now,
		ExpiresAt:         now.Add(session.DefaultIdleTTL),
		AbsoluteExpiresAt: now.Add(session.DefaultAbsoluteTTL),
		IPPrefix:          truncateIPPrefix(meta.ClientIP),
		UserAgent:         truncateUserAgent(meta.UserAgent),
		MFAPending:        false,
	}, sessToken, csrfToken, nil
}
