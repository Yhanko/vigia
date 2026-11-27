//go:build integration

package sqlcgen_test

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/url"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/Yhanko/vigia/internal/platform/database"
	"github.com/Yhanko/vigia/internal/platform/database/sqlcgen"
	"github.com/Yhanko/vigia/migrations"
)

const timescaleImage = "timescale/timescaledb:2.32.1-pg18@sha256:70e6526ad8e31e3f4833f2c5863b50b92d7a6bee4d432ad1f660e2c6dd956d94"

func mustUUID(t *testing.T, s string) pgtype.UUID {
	t.Helper()
	var u pgtype.UUID
	if err := u.Scan(s); err != nil {
		t.Fatalf("parse uuid %q: %v", s, err)
	}
	return u
}

func randomBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

func TestIdentityQueriesIntegration(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	ctr, err := postgres.Run(ctx,
		timescaleImage,
		postgres.WithDatabase("vigia_sqlc_test"),
		postgres.WithUsername("vigia"),
		postgres.WithPassword("vigia_test_pass"),
		testcontainers.WithEnv(map[string]string{"TIMESCALEDB_TELEMETRY": "off"}),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(2*time.Minute),
		),
	)
	if err != nil {
		t.Fatalf("start timescale container: %v", err)
	}
	t.Cleanup(func() {
		if err := testcontainers.TerminateContainer(ctr); err != nil {
			t.Logf("terminate container: %v", err)
		}
	})

	adminDSN, err := ctr.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		t.Fatalf("connection string: %v", err)
	}

	appPass := hex.EncodeToString(randomBytes(t, 24))
	if err := database.EnsureRoles(ctx, adminDSN, appPass); err != nil {
		t.Fatalf("EnsureRoles: %v", err)
	}
	if err := database.Migrate(ctx, adminDSN, migrations.FS, "up"); err != nil {
		t.Fatalf("Migrate up: %v", err)
	}

	u, err := url.Parse(adminDSN)
	if err != nil {
		t.Fatal(err)
	}
	u.User = url.UserPassword("vigia_app", appPass)

	pool, err := database.NewPool(ctx, u.String(), database.PoolOptions{
		MaxConns:         4,
		StatementTimeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("connect as vigia_app: %v", err)
	}
	defer pool.Close()

	q := sqlcgen.New(pool)

	userID := mustUUID(t, "10000000-0000-4000-8000-000000000010")
	created, err := q.CreateUser(ctx, sqlcgen.CreateUserParams{
		ID:           userID,
		PasswordHash: "$argon2id$v=19$m=19456,t=2,p=1$dummy$dummy",
		Email:        "  Alice@Example.COM ",
		Name:         "  Alice Silva  ",
	})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if created.Email != "alice@example.com" || created.Name != "Alice Silva" || created.Status != "active" {
		t.Fatalf("unexpected created user: %+v", created)
	}

	byEmail, err := q.GetUserByEmail(ctx, " ALICE@example.com ")
	if err != nil {
		t.Fatalf("GetUserByEmail: %v", err)
	}
	if byEmail.ID != created.ID {
		t.Fatalf("GetUserByEmail ID = %v, want %v", byEmail.ID, created.ID)
	}

	byID, err := q.GetUserByID(ctx, userID)
	if err != nil {
		t.Fatalf("GetUserByID: %v", err)
	}
	if byID.Email != "alice@example.com" {
		t.Fatalf("GetUserByID email = %q, want alice@example.com", byID.Email)
	}

	now := time.Date(2026, 11, 27, 12, 0, 0, 0, time.UTC)
	sess1ID := mustUUID(t, "20000000-0000-4000-8000-000000000011")
	sess2ID := mustUUID(t, "20000000-0000-4000-8000-000000000012")
	tok1Hash := randomBytes(t, 32)
	tok2Hash := randomBytes(t, 32)
	csrf1Hash := randomBytes(t, 32)
	csrf2Hash := randomBytes(t, 32)
	ipPrefix := "192.0.2.0/24"
	ua := "VigiaTest/1.0"

	s1, err := q.CreateSession(ctx, sqlcgen.CreateSessionParams{
		ID:                sess1ID,
		UserID:            userID,
		TokenHash:         tok1Hash,
		CsrfTokenHash:     csrf1Hash,
		LastAuthAt:        pgtype.Timestamptz{Time: now, Valid: true},
		ExpiresAt:         pgtype.Timestamptz{Time: now.Add(7 * 24 * time.Hour), Valid: true},
		AbsoluteExpiresAt: pgtype.Timestamptz{Time: now.Add(30 * 24 * time.Hour), Valid: true},
		IpPrefix:          &ipPrefix,
		UserAgent:         &ua,
	})
	if err != nil {
		t.Fatalf("CreateSession #1: %v", err)
	}
	if s1.ID != sess1ID {
		t.Fatalf("session #1 ID mismatch")
	}

	if _, err := q.CreateSession(ctx, sqlcgen.CreateSessionParams{
		ID:                sess2ID,
		UserID:            userID,
		TokenHash:         tok2Hash,
		CsrfTokenHash:     csrf2Hash,
		LastAuthAt:        pgtype.Timestamptz{Time: now, Valid: true},
		ExpiresAt:         pgtype.Timestamptz{Time: now.Add(7 * 24 * time.Hour), Valid: true},
		AbsoluteExpiresAt: pgtype.Timestamptz{Time: now.Add(30 * 24 * time.Hour), Valid: true},
	}); err != nil {
		t.Fatalf("CreateSession #2: %v", err)
	}

	// Active session lookup succeeds before expiry and includes active user fields (CTO #14).
	active, err := q.GetActiveSessionByTokenHash(ctx, sqlcgen.GetActiveSessionByTokenHashParams{
		TokenHash: tok1Hash,
		Now:       pgtype.Timestamptz{Time: now.Add(1 * time.Hour), Valid: true},
	})
	if err != nil || active.ID != sess1ID || active.UserEmail != "alice@example.com" || active.UserStatus != "active" {
		t.Fatalf("GetActiveSessionByTokenHash(active) = (%+v, %v), want session %v for active user", active, err, sess1ID)
	}

	// CTO #14: disabling a user immediately invalidates session lookup even before revocation.
	if err := q.UpdateUserStatus(ctx, sqlcgen.UpdateUserStatusParams{
		ID:        userID,
		Status:    "disabled",
		UpdatedAt: pgtype.Timestamptz{Time: now.Add(90 * time.Minute), Valid: true},
	}); err != nil {
		t.Fatalf("UpdateUserStatus(disabled): %v", err)
	}
	_, err = q.GetActiveSessionByTokenHash(ctx, sqlcgen.GetActiveSessionByTokenHashParams{
		TokenHash: tok1Hash,
		Now:       pgtype.Timestamptz{Time: now.Add(95 * time.Minute), Valid: true},
	})
	if !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("GetActiveSessionByTokenHash(disabled user) err = %v, want pgx.ErrNoRows", err)
	}
	// Restore user to active for remaining revocation checks.
	if err := q.UpdateUserStatus(ctx, sqlcgen.UpdateUserStatusParams{
		ID:        userID,
		Status:    "active",
		UpdatedAt: pgtype.Timestamptz{Time: now.Add(96 * time.Minute), Valid: true},
	}); err != nil {
		t.Fatalf("UpdateUserStatus(active): %v", err)
	}

	// Expired session lookup returns pgx.ErrNoRows.
	_, err = q.GetActiveSessionByTokenHash(ctx, sqlcgen.GetActiveSessionByTokenHashParams{
		TokenHash: tok1Hash,
		Now:       pgtype.Timestamptz{Time: now.Add(8 * 24 * time.Hour), Valid: true},
	})
	if !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("GetActiveSessionByTokenHash(expired) err = %v, want pgx.ErrNoRows", err)
	}

	// RevokeSession revokes only session #1 and is idempotent.
	n, err := q.RevokeSession(ctx, sqlcgen.RevokeSessionParams{
		ID:        sess1ID,
		RevokedAt: pgtype.Timestamptz{Time: now.Add(2 * time.Hour), Valid: true},
	})
	if err != nil || n != 1 {
		t.Fatalf("RevokeSession = (%d, %v), want (1, nil)", n, err)
	}
	_, err = q.GetActiveSessionByTokenHash(ctx, sqlcgen.GetActiveSessionByTokenHashParams{
		TokenHash: tok1Hash,
		Now:       pgtype.Timestamptz{Time: now.Add(3 * time.Hour), Valid: true},
	})
	if !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("GetActiveSessionByTokenHash(revoked) err = %v, want pgx.ErrNoRows", err)
	}

	// RevokeAllUserSessions revokes the remaining active session (#2).
	n, err = q.RevokeAllUserSessions(ctx, sqlcgen.RevokeAllUserSessionsParams{
		UserID:    userID,
		RevokedAt: pgtype.Timestamptz{Time: now.Add(4 * time.Hour), Valid: true},
	})
	if err != nil || n != 1 {
		t.Fatalf("RevokeAllUserSessions = (%d, %v), want (1, nil)", n, err)
	}
	_, err = q.GetActiveSessionByTokenHash(ctx, sqlcgen.GetActiveSessionByTokenHashParams{
		TokenHash: tok2Hash,
		Now:       pgtype.Timestamptz{Time: now.Add(5 * time.Hour), Valid: true},
	})
	if !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("GetActiveSessionByTokenHash(revoked all) err = %v, want pgx.ErrNoRows", err)
	}
}
