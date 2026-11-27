package identity

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Yhanko/vigia/internal/platform/database"
	"github.com/Yhanko/vigia/internal/platform/database/sqlcgen"
)

// PostgresStore implements Store on top of pgxpool and sqlcgen.
type PostgresStore struct {
	pool *pgxpool.Pool
	q    *sqlcgen.Queries
}

// NewPostgresStore creates a PostgreSQL-backed identity Store.
func NewPostgresStore(pool *pgxpool.Pool) (*PostgresStore, error) {
	if pool == nil {
		return nil, errors.New("identity: pgx pool is required")
	}
	return &PostgresStore{
		pool: pool,
		q:    sqlcgen.New(pool),
	}, nil
}

func (s *PostgresStore) CreateUser(ctx context.Context, u User) (User, error) {
	uid, err := toPGUUID(u.ID)
	if err != nil {
		return User{}, err
	}
	row, err := s.q.CreateUser(ctx, sqlcgen.CreateUserParams{
		ID:           uid,
		PasswordHash: u.PasswordHash,
		Email:        u.Email,
		Name:         u.Name,
	})
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return User{}, ErrEmailExists
		}
		return User{}, fmt.Errorf("create user: %w", err)
	}
	return mapUser(row), nil
}

func (s *PostgresStore) GetUserByEmail(ctx context.Context, normalizedEmail string) (User, error) {
	row, err := s.q.GetUserByEmail(ctx, normalizedEmail)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return User{}, ErrNotFound
		}
		return User{}, fmt.Errorf("get user by email: %w", err)
	}
	return mapUser(row), nil
}

func (s *PostgresStore) GetUserByID(ctx context.Context, userID string) (User, error) {
	uid, err := toPGUUID(userID)
	if err != nil {
		return User{}, err
	}
	row, err := s.q.GetUserByID(ctx, uid)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return User{}, ErrNotFound
		}
		return User{}, fmt.Errorf("get user by id: %w", err)
	}
	return mapUser(row), nil
}

func (s *PostgresStore) CreateUserToken(ctx context.Context, rec UserTokenRecord) error {
	tid, err := toPGUUID(rec.ID)
	if err != nil {
		return err
	}
	uid, err := toPGUUID(rec.UserID)
	if err != nil {
		return err
	}
	var exp pgtype.Timestamptz
	if rec.ExpiresAt != nil {
		exp = pgtype.Timestamptz{Time: rec.ExpiresAt.UTC(), Valid: true}
	}
	return s.q.CreateUserToken(ctx, sqlcgen.CreateUserTokenParams{
		ID:        tid,
		UserID:    uid,
		Kind:      rec.Kind,
		TokenHash: rec.TokenHash,
		ExpiresAt: exp,
	})
}

func (s *PostgresStore) ReplaceUserToken(ctx context.Context, rec UserTokenRecord, now time.Time) error {
	tid, err := toPGUUID(rec.ID)
	if err != nil {
		return err
	}
	uid, err := toPGUUID(rec.UserID)
	if err != nil {
		return err
	}
	var exp pgtype.Timestamptz
	if rec.ExpiresAt != nil {
		exp = pgtype.Timestamptz{Time: rec.ExpiresAt.UTC(), Valid: true}
	}
	ts := pgtype.Timestamptz{Time: now.UTC(), Valid: true}
	return database.WithTx(ctx, s.pool, func(tx pgx.Tx) error {
		qtx := s.q.WithTx(tx)
		if err := qtx.InvalidateUserTokensByKind(ctx, sqlcgen.InvalidateUserTokensByKindParams{
			UserID: uid,
			Kind:   rec.Kind,
			UsedAt: ts,
		}); err != nil {
			return fmt.Errorf("invalidate previous tokens: %w", err)
		}
		if err := qtx.CreateUserToken(ctx, sqlcgen.CreateUserTokenParams{
			ID:        tid,
			UserID:    uid,
			Kind:      rec.Kind,
			TokenHash: rec.TokenHash,
			ExpiresAt: exp,
		}); err != nil {
			return fmt.Errorf("create replacement token: %w", err)
		}
		return nil
	})
}

func (s *PostgresStore) VerifyEmailByToken(ctx context.Context, tokenHash []byte, now time.Time) (string, error) {
	ts := pgtype.Timestamptz{Time: now.UTC(), Valid: true}
	var userID string
	err := database.WithTx(ctx, s.pool, func(tx pgx.Tx) error {
		qtx := s.q.WithTx(tx)
		tok, err := qtx.ConsumeUserToken(ctx, sqlcgen.ConsumeUserTokenParams{
			TokenHash: tokenHash,
			Kind:      TokenKindEmailVerify,
			Now:       ts,
		})
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrNotFound
			}
			return fmt.Errorf("consume email verify token: %w", err)
		}
		if err := qtx.MarkUserEmailVerified(ctx, sqlcgen.MarkUserEmailVerifiedParams{
			ID:         tok.UserID,
			VerifiedAt: ts,
		}); err != nil {
			return fmt.Errorf("mark email verified: %w", err)
		}
		userID = tok.UserID.String()
		return nil
	})
	return userID, err
}

func (s *PostgresStore) ResetPasswordByToken(ctx context.Context, tokenHash []byte, newPasswordHash string, now time.Time) (User, error) {
	ts := pgtype.Timestamptz{Time: now.UTC(), Valid: true}
	var out User
	err := database.WithTx(ctx, s.pool, func(tx pgx.Tx) error {
		qtx := s.q.WithTx(tx)
		tok, err := qtx.ConsumeUserToken(ctx, sqlcgen.ConsumeUserTokenParams{
			TokenHash: tokenHash,
			Kind:      TokenKindPasswordReset,
			Now:       ts,
		})
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrNotFound
			}
			return fmt.Errorf("consume password reset token: %w", err)
		}
		if err := qtx.UpdateUserPasswordHash(ctx, sqlcgen.UpdateUserPasswordHashParams{
			ID:           tok.UserID,
			PasswordHash: newPasswordHash,
			UpdatedAt:    ts,
		}); err != nil {
			return fmt.Errorf("update password hash: %w", err)
		}
		if _, err := qtx.RevokeAllUserSessions(ctx, sqlcgen.RevokeAllUserSessionsParams{
			UserID:    tok.UserID,
			RevokedAt: ts,
		}); err != nil {
			return fmt.Errorf("revoke all sessions on reset: %w", err)
		}
		row, err := qtx.GetUserByID(ctx, tok.UserID)
		if err != nil {
			return fmt.Errorf("get user after reset: %w", err)
		}
		out = mapUser(row)
		return nil
	})
	return out, err
}

func (s *PostgresStore) UpdateUserPasswordHash(ctx context.Context, userID, passwordHash string, updatedAt time.Time) error {
	uid, err := toPGUUID(userID)
	if err != nil {
		return err
	}
	return s.q.UpdateUserPasswordHash(ctx, sqlcgen.UpdateUserPasswordHashParams{
		ID:           uid,
		PasswordHash: passwordHash,
		UpdatedAt:    pgtype.Timestamptz{Time: updatedAt.UTC(), Valid: true},
	})
}

func (s *PostgresStore) DeactivateUser(ctx context.Context, userID, status string, now time.Time) error {
	uid, err := toPGUUID(userID)
	if err != nil {
		return err
	}
	ts := pgtype.Timestamptz{Time: now.UTC(), Valid: true}
	return database.WithTx(ctx, s.pool, func(tx pgx.Tx) error {
		qtx := s.q.WithTx(tx)
		if err := qtx.UpdateUserStatus(ctx, sqlcgen.UpdateUserStatusParams{
			ID:        uid,
			Status:    status,
			UpdatedAt: ts,
		}); err != nil {
			return fmt.Errorf("update user status: %w", err)
		}
		if _, err := qtx.RevokeAllUserSessions(ctx, sqlcgen.RevokeAllUserSessionsParams{
			UserID:    uid,
			RevokedAt: ts,
		}); err != nil {
			return fmt.Errorf("revoke all user sessions: %w", err)
		}
		return nil
	})
}

func (s *PostgresStore) CreateSession(ctx context.Context, rec SessionRecord) error {
	params, err := toCreateSessionParams(rec)
	if err != nil {
		return err
	}
	_, err = s.q.CreateSession(ctx, params)
	if err != nil {
		return fmt.Errorf("create session: %w", err)
	}
	return nil
}

func (s *PostgresStore) GetActiveSessionByTokenHash(ctx context.Context, tokenHash []byte, now time.Time) (ActiveSession, error) {
	row, err := s.q.GetActiveSessionByTokenHash(ctx, sqlcgen.GetActiveSessionByTokenHashParams{
		TokenHash: tokenHash,
		Now:       pgtype.Timestamptz{Time: now.UTC(), Valid: true},
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ActiveSession{}, ErrNotFound
		}
		return ActiveSession{}, fmt.Errorf("get active session: %w", err)
	}
	return ActiveSession{
		ID:                     row.ID.String(),
		UserID:                 row.UserID.String(),
		CSRFTokenHash:          row.CsrfTokenHash,
		LastAuthAt:             row.LastAuthAt.Time.UTC(),
		ExpiresAt:              row.ExpiresAt.Time.UTC(),
		AbsoluteExpiresAt:      row.AbsoluteExpiresAt.Time.UTC(),
		MFAPending:             false,
		UserEmail:              row.UserEmail,
		UserName:               row.UserName,
		UserMFAEnabled:         row.UserMfaEnabled,
		UserMFASecretEncrypted: row.UserMfaSecretEncrypted,
		UserMFALastUsedStep:    row.UserMfaLastUsedStep,
	}, nil
}

func (s *PostgresStore) GetPendingMFASessionByTokenHash(ctx context.Context, tokenHash []byte, now time.Time) (ActiveSession, error) {
	row, err := s.q.GetPendingMFASessionByTokenHash(ctx, sqlcgen.GetPendingMFASessionByTokenHashParams{
		TokenHash: tokenHash,
		Now:       pgtype.Timestamptz{Time: now.UTC(), Valid: true},
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ActiveSession{}, ErrNotFound
		}
		return ActiveSession{}, fmt.Errorf("get pending mfa session: %w", err)
	}
	return ActiveSession{
		ID:                     row.ID.String(),
		UserID:                 row.UserID.String(),
		CSRFTokenHash:          row.CsrfTokenHash,
		LastAuthAt:             row.LastAuthAt.Time.UTC(),
		ExpiresAt:              row.ExpiresAt.Time.UTC(),
		AbsoluteExpiresAt:      row.AbsoluteExpiresAt.Time.UTC(),
		MFAPending:             true,
		MFAFailedAttempts:      row.MfaFailedAttempts,
		UserEmail:              row.UserEmail,
		UserName:               row.UserName,
		UserMFAEnabled:         row.UserMfaEnabled,
		UserMFASecretEncrypted: row.UserMfaSecretEncrypted,
		UserMFALastUsedStep:    row.UserMfaLastUsedStep,
	}, nil
}

func (s *PostgresStore) SetUserPendingMFASecret(ctx context.Context, userID string, encrypted []byte, now time.Time) error {
	uid, err := toPGUUID(userID)
	if err != nil {
		return err
	}
	return s.q.SetUserPendingMFASecret(ctx, sqlcgen.SetUserPendingMFASecretParams{
		ID:                 uid,
		MfaSecretEncrypted: encrypted,
		UpdatedAt:          pgtype.Timestamptz{Time: now.UTC(), Valid: true},
	})
}

func (s *PostgresStore) ActivateMFA(ctx context.Context, userID, oldSessionID string, step int64, recoveryTokens []UserTokenRecord, next SessionRecord, now time.Time) error {
	uid, err := toPGUUID(userID)
	if err != nil {
		return err
	}
	oldSID, err := toPGUUID(oldSessionID)
	if err != nil {
		return err
	}
	nextParams, err := toCreateSessionParams(next)
	if err != nil {
		return err
	}
	ts := pgtype.Timestamptz{Time: now.UTC(), Valid: true}

	return database.WithTx(ctx, s.pool, func(tx pgx.Tx) error {
		qtx := s.q.WithTx(tx)
		if err := qtx.EnableUserMFA(ctx, sqlcgen.EnableUserMFAParams{
			ID:              uid,
			MfaLastUsedStep: &step,
			UpdatedAt:       ts,
		}); err != nil {
			return fmt.Errorf("enable user mfa: %w", err)
		}
		if err := qtx.InvalidateUserTokensByKind(ctx, sqlcgen.InvalidateUserTokensByKindParams{
			UserID: uid,
			Kind:   TokenKindMFARecovery,
			UsedAt: ts,
		}); err != nil {
			return fmt.Errorf("invalidate old recovery codes: %w", err)
		}
		for _, rec := range recoveryTokens {
			tid, err := toPGUUID(rec.ID)
			if err != nil {
				return err
			}
			if err := qtx.CreateUserToken(ctx, sqlcgen.CreateUserTokenParams{
				ID:        tid,
				UserID:    uid,
				Kind:      TokenKindMFARecovery,
				TokenHash: rec.TokenHash,
			}); err != nil {
				return fmt.Errorf("create recovery code: %w", err)
			}
		}
		if _, err := qtx.RevokeAllUserSessions(ctx, sqlcgen.RevokeAllUserSessionsParams{
			UserID:    uid,
			RevokedAt: ts,
		}); err != nil {
			return fmt.Errorf("revoke all sessions on mfa activation: %w", err)
		}
		_ = oldSID
		if _, err := qtx.CreateSession(ctx, nextParams); err != nil {
			return fmt.Errorf("create rotated mfa session: %w", err)
		}
		return nil
	})
}

func (s *PostgresStore) CompleteMFALogin(ctx context.Context, userID, pendingSessionID string, step *int64, recoveryTokenHash []byte, next SessionRecord, now time.Time) error {
	uid, err := toPGUUID(userID)
	if err != nil {
		return err
	}
	pendID, err := toPGUUID(pendingSessionID)
	if err != nil {
		return err
	}
	nextParams, err := toCreateSessionParams(next)
	if err != nil {
		return err
	}
	ts := pgtype.Timestamptz{Time: now.UTC(), Valid: true}

	return database.WithTx(ctx, s.pool, func(tx pgx.Tx) error {
		qtx := s.q.WithTx(tx)
		if len(recoveryTokenHash) > 0 {
			tok, err := qtx.ConsumeUserToken(ctx, sqlcgen.ConsumeUserTokenParams{
				TokenHash: recoveryTokenHash,
				Kind:      TokenKindMFARecovery,
				Now:       ts,
			})
			if err != nil {
				if errors.Is(err, pgx.ErrNoRows) {
					return ErrInvalidMFACode
				}
				return fmt.Errorf("consume recovery code: %w", err)
			}
			if tok.UserID != uid {
				return ErrInvalidMFACode
			}
		}
		affected, err := qtx.RevokeSession(ctx, sqlcgen.RevokeSessionParams{
			ID:        pendID,
			RevokedAt: ts,
		})
		if err != nil {
			return fmt.Errorf("revoke pending mfa session: %w", err)
		}
		if affected == 0 {
			return ErrSessionExpired
		}
		if step != nil {
			if err := qtx.UpdateUserMFALastUsedStep(ctx, sqlcgen.UpdateUserMFALastUsedStepParams{
				ID:              uid,
				MfaLastUsedStep: step,
				UpdatedAt:       ts,
			}); err != nil {
				return fmt.Errorf("update mfa last used step: %w", err)
			}
		}
		if _, err := qtx.CreateSession(ctx, nextParams); err != nil {
			return fmt.Errorf("create full session after mfa: %w", err)
		}
		return nil
	})
}

func (s *PostgresStore) RecordPendingMFAFailure(ctx context.Context, pendingSessionID string, now time.Time) (bool, error) {
	sid, err := toPGUUID(pendingSessionID)
	if err != nil {
		return false, err
	}
	row, err := s.q.IncrementSessionMFAFailedAttempts(ctx, sqlcgen.IncrementSessionMFAFailedAttemptsParams{
		ID:  sid,
		Now: pgtype.Timestamptz{Time: now.UTC(), Valid: true},
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return true, nil
		}
		return false, fmt.Errorf("increment mfa failed attempts: %w", err)
	}
	return row.RevokedAt.Valid, nil
}

func (s *PostgresStore) UpdateUserMFALastUsedStep(ctx context.Context, userID string, step int64, now time.Time) error {
	uid, err := toPGUUID(userID)
	if err != nil {
		return err
	}
	return s.q.UpdateUserMFALastUsedStep(ctx, sqlcgen.UpdateUserMFALastUsedStepParams{
		ID:              uid,
		MfaLastUsedStep: &step,
		UpdatedAt:       pgtype.Timestamptz{Time: now.UTC(), Valid: true},
	})
}

func (s *PostgresStore) RevokeSession(ctx context.Context, sessionID string, revokedAt time.Time) error {
	sid, err := toPGUUID(sessionID)
	if err != nil {
		return err
	}
	_, err = s.q.RevokeSession(ctx, sqlcgen.RevokeSessionParams{
		ID:        sid,
		RevokedAt: pgtype.Timestamptz{Time: revokedAt.UTC(), Valid: true},
	})
	if err != nil {
		return fmt.Errorf("revoke session: %w", err)
	}
	return nil
}

func (s *PostgresStore) RotateSession(ctx context.Context, oldSessionID string, next SessionRecord, revokedAt time.Time) error {
	oldID, err := toPGUUID(oldSessionID)
	if err != nil {
		return err
	}
	nextParams, err := toCreateSessionParams(next)
	if err != nil {
		return err
	}
	return database.WithTx(ctx, s.pool, func(tx pgx.Tx) error {
		qtx := s.q.WithTx(tx)
		affected, err := qtx.RevokeSession(ctx, sqlcgen.RevokeSessionParams{
			ID:        oldID,
			RevokedAt: pgtype.Timestamptz{Time: revokedAt.UTC(), Valid: true},
		})
		if err != nil {
			return fmt.Errorf("revoke old session: %w", err)
		}
		if affected == 0 {
			// Another concurrent request already revoked/rotated this session (CTO #22).
			return ErrSessionExpired
		}
		if _, err := qtx.CreateSession(ctx, nextParams); err != nil {
			return fmt.Errorf("create rotated session: %w", err)
		}
		return nil
	})
}

func (s *PostgresStore) InsertGlobalAuditLog(ctx context.Context, ev AuditEvent) error {
	id, err := toPGUUID(ev.ID)
	if err != nil {
		return err
	}
	var actorID pgtype.UUID
	if ev.ActorID != "" {
		actorID, err = toPGUUID(ev.ActorID)
		if err != nil {
			return err
		}
	}
	var resID *string
	if ev.ResourceID != "" {
		v := ev.ResourceID
		resID = &v
	}
	return s.q.InsertGlobalAuditLog(ctx, sqlcgen.InsertGlobalAuditLogParams{
		ID:           id,
		ActorType:    ev.ActorType,
		ActorID:      actorID,
		Action:       ev.Action,
		ResourceType: ev.ResourceType,
		ResourceID:   resID,
		Result:       ev.Result,
		IpPrefix:     ev.IPPrefix,
		UserAgent:    ev.UserAgent,
		RequestID:    ev.RequestID,
		Changes:      ev.ChangesJSON,
	})
}

func toCreateSessionParams(rec SessionRecord) (sqlcgen.CreateSessionParams, error) {
	sid, err := toPGUUID(rec.ID)
	if err != nil {
		return sqlcgen.CreateSessionParams{}, err
	}
	uid, err := toPGUUID(rec.UserID)
	if err != nil {
		return sqlcgen.CreateSessionParams{}, err
	}
	return sqlcgen.CreateSessionParams{
		ID:                sid,
		UserID:            uid,
		TokenHash:         rec.TokenHash,
		CsrfTokenHash:     rec.CSRFTokenHash,
		LastAuthAt:        pgtype.Timestamptz{Time: rec.LastAuthAt.UTC(), Valid: true},
		ExpiresAt:         pgtype.Timestamptz{Time: rec.ExpiresAt.UTC(), Valid: true},
		AbsoluteExpiresAt: pgtype.Timestamptz{Time: rec.AbsoluteExpiresAt.UTC(), Valid: true},
		IpPrefix:          rec.IPPrefix,
		UserAgent:         rec.UserAgent,
		MfaPending:        rec.MFAPending,
	}, nil
}

func toPGUUID(raw string) (pgtype.UUID, error) {
	var u pgtype.UUID
	if err := u.Scan(raw); err != nil {
		return pgtype.UUID{}, fmt.Errorf("invalid uuid %q: %w", raw, err)
	}
	return u, nil
}

func mapUser(row sqlcgen.User) User {
	return User{
		ID:                 row.ID.String(),
		Email:              row.Email,
		Name:               row.Name,
		PasswordHash:       row.PasswordHash,
		MFAEnabled:         row.MfaEnabled,
		MFASecretEncrypted: row.MfaSecretEncrypted,
		MFALastUsedStep:    row.MfaLastUsedStep,
		Status:             row.Status,
	}
}
