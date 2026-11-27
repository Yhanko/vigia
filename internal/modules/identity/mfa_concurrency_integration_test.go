//go:build integration

package identity_test

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/Yhanko/vigia/internal/modules/identity"
	"github.com/Yhanko/vigia/internal/platform/database"
	"github.com/Yhanko/vigia/migrations"
)

const timescaleImageMFA = "timescale/timescaledb:2.32.1-pg18@sha256:70e6526ad8e31e3f4833f2c5863b50b92d7a6bee4d432ad1f660e2c6dd956d94"

func randHexMFA(t *testing.T, n int) string {
	t.Helper()
	b := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return hex.EncodeToString(b)
}

func startMFAPG(t *testing.T) *pgxpool.Pool {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	adminPass := randHexMFA(t, 16)
	appPass := randHexMFA(t, 16)

	ctr, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image:        timescaleImageMFA,
			ExposedPorts: []string{"5432/tcp"},
			Env: map[string]string{
				"POSTGRES_USER":     "vigia",
				"POSTGRES_PASSWORD": adminPass,
				"POSTGRES_DB":       "vigia",
			},
			WaitingFor: wait.ForLog("database system is ready to accept connections").WithOccurrence(2).WithStartupTimeout(90 * time.Second),
		},
		Started: true,
	})
	if err != nil {
		t.Fatalf("start pg: %v", err)
	}
	t.Cleanup(func() { _ = ctr.Terminate(context.Background()) })

	host, _ := ctr.Host(ctx)
	port, _ := ctr.MappedPort(ctx, "5432/tcp")
	adminDSN := fmt.Sprintf("postgres://vigia:%s@%s:%s/vigia?sslmode=disable", url.QueryEscape(adminPass), host, port.Port())
	appDSN := fmt.Sprintf("postgres://vigia_app:%s@%s:%s/vigia?sslmode=disable", url.QueryEscape(appPass), host, port.Port())

	if err := database.EnsureRoles(ctx, adminDSN, appPass); err != nil {
		t.Fatalf("EnsureRoles: %v", err)
	}
	if err := database.Migrate(ctx, adminDSN, migrations.FS, "up"); err != nil {
		t.Fatalf("Migrate up: %v", err)
	}
	pool, err := database.NewPool(ctx, appDSN, database.PoolOptions{MaxConns: 20})
	if err != nil {
		t.Fatalf("NewPool: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

func newSessRec(t *testing.T, userID string, pending bool, now time.Time) identity.SessionRecord {
	t.Helper()
	tok := make([]byte, 32)
	csrf := make([]byte, 32)
	_, _ = io.ReadFull(rand.Reader, tok)
	_, _ = io.ReadFull(rand.Reader, csrf)
	return identity.SessionRecord{
		ID:                uuid.New().String(),
		UserID:            userID,
		TokenHash:         tok,
		CSRFTokenHash:     csrf,
		LastAuthAt:        now,
		ExpiresAt:         now.Add(12 * time.Hour),
		AbsoluteExpiresAt: now.Add(7 * 24 * time.Hour),
		MFAPending:        pending,
	}
}

// TestTOTPAtomicAntiReplay_CTO30 verifies CTO #30:
//  1. 10 concurrent ActivateMFA calls with the same step -> exactly 1 succeeds.
//  2. 10 concurrent CompleteMFALogin calls with DIFFERENT pending sessions but the SAME TOTP step -> exactly 1 succeeds.
//  3. 10 concurrent ReauthRotate calls with DIFFERENT active sessions but the SAME TOTP step -> exactly 1 succeeds.
//  4. Replaying a previous TOTP step (< mfa_last_used_step) -> ErrInvalidMFACode and no new session created.
func TestTOTPAtomicAntiReplay_CTO30(t *testing.T) {
	ctx := context.Background()
	pool := startMFAPG(t)
	store, err := identity.NewPostgresStore(pool)
	if err != nil {
		t.Fatalf("NewPostgresStore: %v", err)
	}

	now := time.Now().UTC()
	const workers = 10

	// Helper to create a user.
	mkUser := func(email string) string {
		uid := uuid.New().String()
		_, err := store.CreateUser(ctx, identity.User{
			ID:           uid,
			Email:        email,
			Name:         "TOTP Race",
			PasswordHash: "placeholder-hash",
		})
		if err != nil {
			t.Fatalf("CreateUser: %v", err)
		}
		return uid
	}

	// 1. Concurrent ActivateMFA with same step -> exactly 1 success.
	t.Run("ActivateMFA concurrency", func(t *testing.T) {
		uid := mkUser("totp-act@vigia.test")
		initSess := newSessRec(t, uid, false, now)
		if err := store.CreateSession(ctx, initSess); err != nil {
			t.Fatalf("CreateSession: %v", err)
		}
		var okCount atomic.Int32
		start := make(chan struct{})
		var wg sync.WaitGroup
		for range workers {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				next := newSessRec(t, uid, false, now)
				if err := store.ActivateMFA(ctx, uid, initSess.ID, 1000, nil, next, now); err == nil {
					okCount.Add(1)
				}
			}()
		}
		close(start)
		wg.Wait()
		if got := okCount.Load(); got != 1 {
			t.Fatalf("ActivateMFA concurrent successes = %d, want exactly 1", got)
		}
	})

	// 2. Concurrent CompleteMFALogin across 10 distinct pending sessions using the SAME TOTP step -> exactly 1 success.
	t.Run("CompleteMFALogin concurrency", func(t *testing.T) {
		uid := mkUser("totp-login@vigia.test")
		pendingIDs := make([]string, workers)
		for i := range workers {
			ps := newSessRec(t, uid, true, now)
			if err := store.CreateSession(ctx, ps); err != nil {
				t.Fatalf("CreateSession pending: %v", err)
			}
			pendingIDs[i] = ps.ID
		}
		step := int64(2000)
		var okCount atomic.Int32
		start := make(chan struct{})
		var wg sync.WaitGroup
		for i := range workers {
			wg.Add(1)
			go func(pid string) {
				defer wg.Done()
				<-start
				next := newSessRec(t, uid, false, now)
				if err := store.CompleteMFALogin(ctx, uid, pid, &step, nil, next, now); err == nil {
					okCount.Add(1)
				}
			}(pendingIDs[i])
		}
		close(start)
		wg.Wait()
		if got := okCount.Load(); got != 1 {
			t.Fatalf("CompleteMFALogin concurrent successes = %d, want exactly 1", got)
		}

		// Previous step (< 2000) MUST be rejected with ErrInvalidMFACode.
		oldStep := int64(1999)
		ps := newSessRec(t, uid, true, now)
		if err := store.CreateSession(ctx, ps); err != nil {
			t.Fatalf("CreateSession pending oldStep: %v", err)
		}
		if err := store.CompleteMFALogin(ctx, uid, ps.ID, &oldStep, nil, newSessRec(t, uid, false, now), now); !errors.Is(err, identity.ErrInvalidMFACode) {
			t.Fatalf("CompleteMFALogin oldStep = %v, want ErrInvalidMFACode", err)
		}
	})

	// 3. Concurrent ReauthRotate across 10 distinct active sessions using the SAME TOTP step -> exactly 1 success.
	t.Run("ReauthRotate concurrency", func(t *testing.T) {
		uid := mkUser("totp-reauth@vigia.test")
		sessIDs := make([]string, workers)
		for i := range workers {
			s := newSessRec(t, uid, false, now)
			if err := store.CreateSession(ctx, s); err != nil {
				t.Fatalf("CreateSession active: %v", err)
			}
			sessIDs[i] = s.ID
		}
		step := int64(3000)
		var okCount atomic.Int32
		start := make(chan struct{})
		var wg sync.WaitGroup
		for i := range workers {
			wg.Add(1)
			go func(sid string) {
				defer wg.Done()
				<-start
				next := newSessRec(t, uid, false, now)
				if err := store.ReauthRotate(ctx, uid, sid, &step, next, now); err == nil {
					okCount.Add(1)
				}
			}(sessIDs[i])
		}
		close(start)
		wg.Wait()
		if got := okCount.Load(); got != 1 {
			t.Fatalf("ReauthRotate concurrent successes = %d, want exactly 1", got)
		}

		// Replaying step <= 3000 MUST return ErrInvalidMFACode.
		oldStep := int64(2999)
		s := newSessRec(t, uid, false, now)
		if err := store.CreateSession(ctx, s); err != nil {
			t.Fatalf("CreateSession oldStep: %v", err)
		}
		if err := store.ReauthRotate(ctx, uid, s.ID, &oldStep, newSessRec(t, uid, false, now), now); !errors.Is(err, identity.ErrInvalidMFACode) {
			t.Fatalf("ReauthRotate oldStep = %v, want ErrInvalidMFACode", err)
		}
	})
}
