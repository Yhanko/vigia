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
		ID:                row.ID.String(),
		UserID:            row.UserID.String(),
		CSRFTokenHash:     row.CsrfTokenHash,
		LastAuthAt:        row.LastAuthAt.Time.UTC(),
		ExpiresAt:         row.ExpiresAt.Time.UTC(),
		AbsoluteExpiresAt: row.AbsoluteExpiresAt.Time.UTC(),
		UserEmail:         row.UserEmail,
		UserName:          row.UserName,
		UserMFAEnabled:    row.UserMfaEnabled,
	}, nil
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
		if _, err := qtx.RevokeSession(ctx, sqlcgen.RevokeSessionParams{
			ID:        oldID,
			RevokedAt: pgtype.Timestamptz{Time: revokedAt.UTC(), Valid: true},
		}); err != nil {
			return fmt.Errorf("revoke old session: %w", err)
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
		ID:           row.ID.String(),
		Email:        row.Email,
		Name:         row.Name,
		PasswordHash: row.PasswordHash,
		MFAEnabled:   row.MfaEnabled,
		Status:       row.Status,
	}
}
