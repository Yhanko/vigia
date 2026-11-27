//go:build integration

package identity_test

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/Yhanko/vigia/internal/modules/identity"
	"github.com/Yhanko/vigia/internal/platform/database"
	"github.com/Yhanko/vigia/migrations"
)

const timescaleImage = "timescale/timescaledb:2.32.1-pg18@sha256:70e6526ad8e31e3f4833f2c5863b50b92d7a6bee4d432ad1f660e2c6dd956d94"

func randHex(t *testing.T, n int) string {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b)
}

func randBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

func TestRotateSessionConcurrencyPreventsBifurcation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	ctr, err := postgres.Run(ctx,
		timescaleImage,
		postgres.WithDatabase("vigia_id_test"),
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
		t.Fatal(err)
	}
	appPass := randHex(t, 24)
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
		MaxConns:         12,
		StatementTimeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("connect vigia_app: %v", err)
	}
	defer pool.Close()

	store, err := identity.NewPostgresStore(pool)
	if err != nil {
		t.Fatal(err)
	}

	const (
		userID = "10000000-0000-4000-8000-000000000022"
		sessID = "20000000-0000-4000-8000-000000000022"
	)
	now := time.Date(2026, 11, 27, 16, 0, 0, 0, time.UTC)

	if _, err := store.CreateUser(ctx, identity.User{
		ID:           userID,
		Email:        "race@example.com",
		Name:         "Race User",
		PasswordHash: "$argon2id$v=19$m=19456,t=2,p=1$dummy$dummy",
		Status:       "active",
	}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if err := store.CreateSession(ctx, identity.SessionRecord{
		ID:                sessID,
		UserID:            userID,
		TokenHash:         randBytes(t, 32),
		CSRFTokenHash:     randBytes(t, 32),
		LastAuthAt:        now,
		ExpiresAt:         now.Add(7 * 24 * time.Hour),
		AbsoluteExpiresAt: now.Add(30 * 24 * time.Hour),
	}); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	// Fire N concurrent RotateSession calls for the same session ID (CTO #22).
	const workers = 8
	start := make(chan struct{})
	var (
		wg        sync.WaitGroup
		succeeded atomic.Int32
		expired   atomic.Int32
		otherErrs atomic.Int32
	)
	for i := range workers {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			<-start
			nextID := fmt.Sprintf("30000000-0000-4000-8000-%012d", idx+1)
			err := store.RotateSession(ctx, sessID, identity.SessionRecord{
				ID:                nextID,
				UserID:            userID,
				TokenHash:         randBytes(t, 32),
				CSRFTokenHash:     randBytes(t, 32),
				LastAuthAt:        now,
				ExpiresAt:         now.Add(8 * 24 * time.Hour),
				AbsoluteExpiresAt: now.Add(30 * 24 * time.Hour),
			}, now.Add(time.Minute))
			switch {
			case err == nil:
				succeeded.Add(1)
			case errors.Is(err, identity.ErrSessionExpired):
				expired.Add(1)
			default:
				t.Logf("worker %d unexpected err: %v", idx, err)
				otherErrs.Add(1)
			}
		}(i)
	}
	close(start)
	wg.Wait()

	if succeeded.Load() != 1 || expired.Load() != workers-1 || otherErrs.Load() != 0 {
		t.Fatalf("concurrent RotateSession results: succeeded=%d expired=%d other=%d, want (1, %d, 0)",
			succeeded.Load(), expired.Load(), otherErrs.Load(), workers-1)
	}

	var activeCount int
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM sessions WHERE user_id = $1 AND revoked_at IS NULL", userID).Scan(&activeCount); err != nil {
		t.Fatalf("count active sessions: %v", err)
	}
	if activeCount != 1 {
		t.Fatalf("active sessions after concurrent rotate = %d, want exactly 1", activeCount)
	}
}
