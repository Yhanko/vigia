//go:build integration

package database

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/Yhanko/vigia/migrations"
)

// Exact image and digest pinned in compose.yaml (README §26.3, TASKS 1.1).
const timescaleImage = "timescale/timescaledb:2.32.1-pg18@sha256:70e6526ad8e31e3f4833f2c5863b50b92d7a6bee4d432ad1f660e2c6dd956d94"

func startTimescaleContainer(t *testing.T) string {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	ctr, err := postgres.Run(ctx,
		timescaleImage,
		postgres.WithDatabase("vigia_test"),
		postgres.WithUsername("vigia"),
		postgres.WithPassword("vigia_test_pass"),
		testcontainers.WithEnv(map[string]string{
			"TIMESCALEDB_TELEMETRY": "off",
		}),
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
			t.Logf("terminate timescale container: %v", err)
		}
	})

	dsn, err := ctr.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		t.Fatalf("container connection string: %v", err)
	}
	return dsn
}

func TestDatabaseIntegration(t *testing.T) {
	dsn := startTimescaleContainer(t)
	ctx := context.Background()

	t.Run("Migrate up, version, down, up", func(t *testing.T) {
		if err := Migrate(ctx, dsn, migrations.FS, "up"); err != nil {
			t.Fatalf("Migrate up: %v", err)
		}
		if err := Migrate(ctx, dsn, migrations.FS, "version"); err != nil {
			t.Fatalf("Migrate version: %v", err)
		}
		if err := Migrate(ctx, dsn, migrations.FS, "down"); err != nil {
			t.Fatalf("Migrate down: %v", err)
		}
		if err := Migrate(ctx, dsn, migrations.FS, "up"); err != nil {
			t.Fatalf("Migrate up (idempotent): %v", err)
		}
	})

	t.Run("NewPool enforces statement_timeout", func(t *testing.T) {
		pool, err := NewPool(ctx, dsn, PoolOptions{
			MaxConns:         5,
			StatementTimeout: 200 * time.Millisecond,
		})
		if err != nil {
			t.Fatalf("NewPool: %v", err)
		}
		defer pool.Close()

		var one int
		if err := pool.QueryRow(ctx, "SELECT 1").Scan(&one); err != nil || one != 1 {
			t.Fatalf("fast query failed: one=%d err=%v", one, err)
		}

		// Query slower than statement_timeout must fail with PostgreSQL SQLSTATE 57014 (query_canceled).
		_, err = pool.Exec(ctx, "SELECT pg_sleep(2)")
		if err == nil {
			t.Fatal("expected slow query to fail with statement_timeout, got nil")
		}
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) || pgErr.Code != "57014" {
			t.Fatalf("expected pg error 57014 (query_canceled), got: %v", err)
		}
	})

	t.Run("WithTx commit, rollback on error, rollback on panic", func(t *testing.T) {
		pool, err := NewPool(ctx, dsn, PoolOptions{
			MaxConns:         5,
			StatementTimeout: 5 * time.Second,
		})
		if err != nil {
			t.Fatalf("NewPool: %v", err)
		}
		defer pool.Close()

		if _, err := pool.Exec(ctx, "CREATE TABLE tx_probe (id INT PRIMARY KEY)"); err != nil {
			t.Fatalf("create probe table: %v", err)
		}

		// Commit succeeds.
		if err := WithTx(ctx, pool, func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, "INSERT INTO tx_probe (id) VALUES (1)")
			return err
		}); err != nil {
			t.Fatalf("WithTx commit: %v", err)
		}

		// Error triggers rollback.
		wantErr := errors.New("boom")
		err = WithTx(ctx, pool, func(tx pgx.Tx) error {
			if _, execErr := tx.Exec(ctx, "INSERT INTO tx_probe (id) VALUES (2)"); execErr != nil {
				return execErr
			}
			return wantErr
		})
		if !errors.Is(err, wantErr) {
			t.Fatalf("WithTx error = %v, want %v", err, wantErr)
		}

		// Panic triggers rollback and propagates panic.
		func() {
			defer func() {
				if r := recover(); r == nil {
					t.Fatal("expected panic to propagate")
				}
			}()
			_ = WithTx(ctx, pool, func(tx pgx.Tx) error {
				_, _ = tx.Exec(ctx, "INSERT INTO tx_probe (id) VALUES (3)")
				panic("unexpected panic")
			})
		}()

		var count int
		if err := pool.QueryRow(ctx, "SELECT count(*) FROM tx_probe").Scan(&count); err != nil {
			t.Fatalf("count probe rows: %v", err)
		}
		if count != 1 {
			t.Fatalf("row count = %d, want 1 (only committed row)", count)
		}
	})

	t.Run("EnsureRoles creates SCRAM-SHA-256 vigia_app without superuser/bypassrls", func(t *testing.T) {
		rawPass := make([]byte, 24)
		if _, err := rand.Read(rawPass); err != nil {
			t.Fatal(err)
		}
		appPass := hex.EncodeToString(rawPass)

		// Must be idempotent across repeated invocations.
		if err := EnsureRoles(ctx, dsn, appPass); err != nil {
			t.Fatalf("first EnsureRoles: %v", err)
		}
		if err := EnsureRoles(ctx, dsn, appPass); err != nil {
			t.Fatalf("second EnsureRoles (idempotent): %v", err)
		}

		// Verify stored verifier in pg_authid starts with SCRAM-SHA-256$.
		adminPool, err := NewPool(ctx, dsn, PoolOptions{MaxConns: 2, StatementTimeout: 5 * time.Second})
		if err != nil {
			t.Fatalf("admin pool: %v", err)
		}
		defer adminPool.Close()

		var storedHash string
		if err := adminPool.QueryRow(ctx, "SELECT rolpassword FROM pg_authid WHERE rolname = 'vigia_app'").Scan(&storedHash); err != nil {
			t.Fatalf("query pg_authid: %v", err)
		}
		if !strings.HasPrefix(storedHash, "SCRAM-SHA-256$") {
			t.Fatalf("vigia_app rolpassword = %q, want SCRAM-SHA-256$ prefix", storedHash)
		}

		// Authenticate as vigia_app with the generated password.
		appDSN := replaceDSNUser(t, dsn, "vigia_app", appPass)
		appPool, err := NewPool(ctx, appDSN, PoolOptions{MaxConns: 2, StatementTimeout: 5 * time.Second})
		if err != nil {
			t.Fatalf("connect as vigia_app: %v", err)
		}
		defer appPool.Close()

		var curUser string
		var rolSuper, rolBypassRLS bool
		if err := appPool.QueryRow(ctx, "SELECT current_user, rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user").
			Scan(&curUser, &rolSuper, &rolBypassRLS); err != nil {
			t.Fatalf("query current role: %v", err)
		}
		if curUser != "vigia_app" || rolSuper || rolBypassRLS {
			t.Fatalf("unexpected runtime role: user=%q rolsuper=%v rolbypassrls=%v", curUser, rolSuper, rolBypassRLS)
		}

		// vigia_app must NOT be able to escalate to vigia or vigia_definer, nor read pg_authid.
		for _, forbidden := range []string{
			"SET ROLE vigia",
			"SET ROLE vigia_definer",
			"SELECT rolpassword FROM pg_authid LIMIT 1",
		} {
			if _, err := appPool.Exec(ctx, forbidden); err == nil {
				t.Fatalf("vigia_app unexpectedly succeeded on forbidden statement: %s", forbidden)
			}
		}
	})
}

func replaceDSNUser(t *testing.T, dsn, user, pass string) string {
	t.Helper()
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatalf("parse dsn: %v", err)
	}
	u.User = url.UserPassword(user, pass)
	return u.String()
}
