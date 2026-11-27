//go:build integration

package database

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
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

	rawPass := make([]byte, 24)
	if _, err := rand.Read(rawPass); err != nil {
		t.Fatal(err)
	}
	appPass := hex.EncodeToString(rawPass)

	// Ensure cluster-level roles exist before running migrations that GRANT to them.
	if err := EnsureRoles(ctx, dsn, appPass); err != nil {
		t.Fatalf("initial EnsureRoles: %v", err)
	}

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
		// Must be idempotent across repeated invocations.
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

		// VerifyNonPrivilegedRole must reject the superuser adminPool and accept vigia_app (CTO #12).
		if err := VerifyNonPrivilegedRole(ctx, adminPool); !errors.Is(err, ErrPrivilegedRole) {
			t.Fatalf("VerifyNonPrivilegedRole(adminPool) = %v, want ErrPrivilegedRole", err)
		} else if !strings.Contains(err.Error(), "rolsuper=true") {
			t.Fatalf("VerifyNonPrivilegedRole(adminPool) error %q should identify rolsuper=true", err.Error())
		}
		if err := VerifyNonPrivilegedRole(ctx, appPool); err != nil {
			t.Fatalf("VerifyNonPrivilegedRole(appPool) unexpected error: %v", err)
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

	t.Run("Catalog guard: every public table with organization_id has ENABLE+FORCE RLS and audit_logs is append-only", func(t *testing.T) {
		adminPool, err := NewPool(ctx, dsn, PoolOptions{MaxConns: 2, StatementTimeout: 5 * time.Second})
		if err != nil {
			t.Fatalf("admin pool: %v", err)
		}
		defer adminPool.Close()

		rows, err := adminPool.Query(ctx, `
			SELECT c.relname, c.relrowsecurity, c.relforcerowsecurity
			FROM pg_class c
			JOIN pg_namespace n ON n.oid = c.relnamespace
			JOIN pg_attribute a ON a.attrelid = c.oid
			WHERE n.nspname = 'public'
			  AND c.relkind IN ('r', 'p')
			  AND a.attname = 'organization_id'
			  AND NOT a.attisdropped
			ORDER BY c.relname
		`)
		if err != nil {
			t.Fatalf("query pg_class catalog: %v", err)
		}
		defer rows.Close()

		checked := 0
		for rows.Next() {
			var table string
			var rlsEnabled, rlsForced bool
			if err := rows.Scan(&table, &rlsEnabled, &rlsForced); err != nil {
				t.Fatalf("scan catalog row: %v", err)
			}
			checked++
			if !rlsEnabled || !rlsForced {
				t.Fatalf("table %q has organization_id but RLS flags are (enabled=%v, forced=%v); both must be true", table, rlsEnabled, rlsForced)
			}
		}
		if err := rows.Err(); err != nil {
			t.Fatalf("catalog rows err: %v", err)
		}
		if checked < 5 {
			t.Fatalf("expected at least 5 tenant-scoped tables with organization_id, checked %d", checked)
		}

		// Verify organizations itself also has ENABLE + FORCE RLS.
		var orgEnabled, orgForced bool
		if err := adminPool.QueryRow(ctx, `
			SELECT c.relrowsecurity, c.relforcerowsecurity
			FROM pg_class c
			JOIN pg_namespace n ON n.oid = c.relnamespace
			WHERE n.nspname = 'public' AND c.relname = 'organizations'
		`).Scan(&orgEnabled, &orgForced); err != nil {
			t.Fatalf("query organizations RLS: %v", err)
		}
		if !orgEnabled || !orgForced {
			t.Fatalf("organizations RLS flags = (%v, %v), want (true, true)", orgEnabled, orgForced)
		}

		// Guard: vigia_app must NEVER have UPDATE or DELETE on audit_logs.
		var canUpdate, canDelete bool
		if err := adminPool.QueryRow(ctx, `
			SELECT has_table_privilege('vigia_app', 'public.audit_logs', 'UPDATE'),
			       has_table_privilege('vigia_app', 'public.audit_logs', 'DELETE')
		`).Scan(&canUpdate, &canDelete); err != nil {
			t.Fatalf("query audit_logs privileges: %v", err)
		}
		if canUpdate || canDelete {
			t.Fatalf("vigia_app has forbidden audit_logs privileges: UPDATE=%v DELETE=%v", canUpdate, canDelete)
		}

		// Guard: vigia_app must NEVER have DELETE on organizations (soft delete only; ADR-008 §4).
		var canDeleteOrg bool
		if err := adminPool.QueryRow(ctx, `
			SELECT has_table_privilege('vigia_app', 'public.organizations', 'DELETE')
		`).Scan(&canDeleteOrg); err != nil {
			t.Fatalf("query organizations DELETE privilege: %v", err)
		}
		if canDeleteOrg {
			t.Fatal("vigia_app has forbidden DELETE privilege on organizations")
		}
	})

	t.Run("RLS fail-closed, cross-tenant isolation, and append-only audit_logs", func(t *testing.T) {
		appDSN := replaceDSNUser(t, dsn, "vigia_app", appPass)
		appPool, err := NewPool(ctx, appDSN, PoolOptions{MaxConns: 4, StatementTimeout: 5 * time.Second})
		if err != nil {
			t.Fatalf("connect as vigia_app: %v", err)
		}
		defer appPool.Close()

		const (
			userA  = "10000000-0000-4000-8000-000000000001"
			userB  = "10000000-0000-4000-8000-000000000002"
			orgA   = "20000000-0000-4000-8000-000000000001"
			orgB   = "20000000-0000-4000-8000-000000000002"
			memA   = "30000000-0000-4000-8000-000000000001"
			memB   = "30000000-0000-4000-8000-000000000002"
			teamA  = "40000000-0000-4000-8000-000000000001"
			teamB  = "40000000-0000-4000-8000-000000000002"
			auditA = "50000000-0000-4000-8000-000000000001"
			auditB = "50000000-0000-4000-8000-000000000002"
			auditG = "50000000-0000-4000-8000-000000000003"
		)

		// Seed two users (global table).
		if _, err := appPool.Exec(ctx, `
			INSERT INTO users (id, email, name, password_hash)
			VALUES ($1, 'alice@example.com', 'Alice', 'hash-a'),
			       ($2, 'bob@example.com', 'Bob', 'hash-b')
		`, userA, userB); err != nil {
			t.Fatalf("seed users: %v", err)
		}

		// Seed Org A inside tenant A tx.
		if err := WithTx(ctx, appPool, func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, "SELECT set_config('app.organization_id', $1, true)", orgA); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, "INSERT INTO organizations (id, name, slug) VALUES ($1, 'Org A', 'org-a')", orgA); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, "INSERT INTO memberships (id, organization_id, user_id, role) VALUES ($1, $2, $3, 'owner')", memA, orgA, userA); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, "INSERT INTO teams (id, organization_id, name, slug) VALUES ($1, $2, 'Core A', 'core-a')", teamA, orgA); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, "INSERT INTO team_members (organization_id, team_id, user_id) VALUES ($1, $2, $3)", orgA, teamA, userA); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, "INSERT INTO audit_logs (id, organization_id, actor_type, actor_id, action, resource_type, result, request_id) VALUES ($1, $2, 'user', $3, 'org.created', 'organization', 'success', 'req_a')", auditA, orgA, userA); err != nil {
				return err
			}
			return nil
		}); err != nil {
			t.Fatalf("seed Org A: %v", err)
		}

		// Seed Org B inside tenant B tx + one global auth audit log (organization_id IS NULL).
		if err := WithTx(ctx, appPool, func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, "SELECT set_config('app.organization_id', $1, true)", orgB); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, "INSERT INTO organizations (id, name, slug) VALUES ($1, 'Org B', 'org-b')", orgB); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, "INSERT INTO memberships (id, organization_id, user_id, role) VALUES ($1, $2, $3, 'owner')", memB, orgB, userB); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, "INSERT INTO teams (id, organization_id, name, slug) VALUES ($1, $2, 'Core B', 'core-b')", teamB, orgB); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, "INSERT INTO audit_logs (id, organization_id, actor_type, actor_id, action, resource_type, result, request_id) VALUES ($1, $2, 'user', $3, 'org.created', 'organization', 'success', 'req_b')", auditB, orgB, userB); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, "INSERT INTO audit_logs (id, organization_id, actor_type, actor_id, action, resource_type, result, request_id) VALUES ($1, NULL, 'user', $2, 'auth.login', 'session', 'success', 'req_g')", auditG, userB); err != nil {
				return err
			}
			return nil
		}); err != nil {
			t.Fatalf("seed Org B: %v", err)
		}

		// Fail-closed: without app.organization_id, SELECT must return 0 rows on all tenant-scoped tables.
		for _, tbl := range []string{"organizations", "memberships", "invitations", "teams", "team_members", "audit_logs"} {
			var n int
			if err := appPool.QueryRow(ctx, "SELECT count(*) FROM "+tbl).Scan(&n); err != nil {
				t.Fatalf("fail-closed SELECT on %s: %v", tbl, err)
			}
			if n != 0 {
				t.Fatalf("fail-closed violation on %s: got %d rows without app.organization_id, want 0", tbl, n)
			}
		}

		// Tenant A context sees ONLY Org A and cannot write Org B.
		if err := WithTx(ctx, appPool, func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, "SELECT set_config('app.organization_id', $1, true)", orgA); err != nil {
				return err
			}
			var orgCount, teamCount, auditCount int
			if err := tx.QueryRow(ctx, "SELECT count(*) FROM organizations").Scan(&orgCount); err != nil {
				return err
			}
			if err := tx.QueryRow(ctx, "SELECT count(*) FROM teams").Scan(&teamCount); err != nil {
				return err
			}
			if err := tx.QueryRow(ctx, "SELECT count(*) FROM audit_logs").Scan(&auditCount); err != nil {
				return err
			}
			if orgCount != 1 || teamCount != 1 || auditCount != 1 {
				t.Fatalf("tenant A counts = (orgs:%d teams:%d audits:%d), want (1, 1, 1)", orgCount, teamCount, auditCount)
			}
			return nil
		}); err != nil {
			t.Fatalf("tenant A read verification tx: %v", err)
		}

		// Cross-tenant INSERT into Org B from Tenant A context must be blocked by RLS WITH CHECK (SQLSTATE 42501).
		err = WithTx(ctx, appPool, func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, "SELECT set_config('app.organization_id', $1, true)", orgA); err != nil {
				return err
			}
			_, err := tx.Exec(ctx, "INSERT INTO teams (id, organization_id, name, slug) VALUES ('40000000-0000-4000-8000-000000000099', $1, 'Evil', 'evil')", orgB)
			return err
		})
		var rlsErr *pgconn.PgError
		if !errors.As(err, &rlsErr) || rlsErr.Code != "42501" {
			t.Fatalf("expected SQLSTATE 42501 for cross-tenant INSERT into Org B, got: %v", err)
		}

		// audit_logs must reject UPDATE and DELETE with SQLSTATE 42501 (insufficient_privilege).
		for _, stmt := range []string{
			"UPDATE audit_logs SET action = 'tampered' WHERE id = $1",
			"DELETE FROM audit_logs WHERE id = $1",
		} {
			_, err := appPool.Exec(ctx, stmt, auditA)
			var pgErr *pgconn.PgError
			if !errors.As(err, &pgErr) || pgErr.Code != "42501" {
				t.Fatalf("expected SQLSTATE 42501 for %q, got: %v", stmt, err)
			}
		}

		// Seed an invitation in Org A to test lookup_invitation_by_token_hash.
		const invA = "60000000-0000-4000-8000-000000000001"
		invHash := make([]byte, 32)
		if _, err := rand.Read(invHash); err != nil {
			t.Fatal(err)
		}
		if err := WithTx(ctx, appPool, func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, "SELECT set_config('app.organization_id', $1, true)", orgA); err != nil {
				return err
			}
			_, err := tx.Exec(ctx, `
				INSERT INTO invitations (id, organization_id, email, role, token_hash, invited_by, expires_at)
				VALUES ($1, $2, 'carol@example.com', 'member', $3, $4, now() + interval '7 days')
			`, invA, orgA, invHash, userA)
			return err
		}); err != nil {
			t.Fatalf("seed invitation: %v", err)
		}

		// SECURITY DEFINER: list_user_organizations returns ONLY userA's active org (Org A, never Org B).
		var gotOrgID, gotName, gotSlug, gotOrgStatus, gotRole, gotMemStatus string
		if err := appPool.QueryRow(ctx,
			"SELECT organization_id, name, slug, org_status, role, membership_status FROM list_user_organizations($1)",
			userA,
		).Scan(&gotOrgID, &gotName, &gotSlug, &gotOrgStatus, &gotRole, &gotMemStatus); err != nil {
			t.Fatalf("list_user_organizations(userA): %v", err)
		}
		if gotOrgID != orgA || gotSlug != "org-a" || gotRole != "owner" {
			t.Fatalf("unexpected list_user_organizations result: org=%s slug=%s role=%s", gotOrgID, gotSlug, gotRole)
		}

		// SECURITY DEFINER: lookup_invitation_by_token_hash returns ONLY (invitation_id, organization_id).
		var gotInvID, gotInvOrgID string
		if err := appPool.QueryRow(ctx,
			"SELECT invitation_id, organization_id FROM lookup_invitation_by_token_hash($1)",
			invHash,
		).Scan(&gotInvID, &gotInvOrgID); err != nil {
			t.Fatalf("lookup_invitation_by_token_hash: %v", err)
		}
		if gotInvID != invA || gotInvOrgID != orgA {
			t.Fatalf("unexpected invitation lookup: inv=%s org=%s, want (%s, %s)", gotInvID, gotInvOrgID, invA, orgA)
		}

		// Verify WithTenantTx helper sets RLS context and enforces tenant isolation.
		tidA, err := ParseTenantID(orgA)
		if err != nil {
			t.Fatal(err)
		}
		if err := WithTenantTx(ctx, appPool, tidA, func(tx pgx.Tx) error {
			var slug string
			if err := tx.QueryRow(ctx, "SELECT slug FROM organizations").Scan(&slug); err != nil {
				return err
			}
			if slug != "org-a" {
				t.Fatalf("WithTenantTx(tidA) saw slug=%q, want org-a", slug)
			}
			return nil
		}); err != nil {
			t.Fatalf("WithTenantTx(tidA): %v", err)
		}

		// organizations must reject physical DELETE as vigia_app with SQLSTATE 42501.
		err = WithTenantTx(ctx, appPool, tidA, func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, "DELETE FROM organizations WHERE id = $1", orgA)
			return err
		})
		var delOrgErr *pgconn.PgError
		if !errors.As(err, &delOrgErr) || delOrgErr.Code != "42501" {
			t.Fatalf("expected SQLSTATE 42501 for DELETE on organizations as vigia_app, got: %v", err)
		}

		// Cross-tenant UPDATE and DELETE from Tenant A context targeting Org B rows
		// (memberships and teams) must affect 0 rows and leave Org B intact (CTO #10).
		if err := WithTenantTx(ctx, appPool, tidA, func(tx pgx.Tx) error {
			for _, tc := range []struct {
				name string
				sql  string
				arg  string
			}{
				{"UPDATE memberships Org B", "UPDATE memberships SET role = 'viewer' WHERE id = $1", memB},
				{"DELETE memberships Org B", "DELETE FROM memberships WHERE id = $1", memB},
				{"UPDATE teams Org B", "UPDATE teams SET name = 'Tampered', slug = 'tampered' WHERE id = $1", teamB},
				{"DELETE teams Org B", "DELETE FROM teams WHERE id = $1", teamB},
			} {
				tag, err := tx.Exec(ctx, tc.sql, tc.arg)
				if err != nil {
					return err
				}
				if tag.RowsAffected() != 0 {
					t.Fatalf("cross-tenant %s affected %d rows, want 0", tc.name, tag.RowsAffected())
				}
			}
			return nil
		}); err != nil {
			t.Fatalf("cross-tenant UPDATE/DELETE test tx: %v", err)
		}

		// Verify ownership = vigia_definer (not vigia) and PUBLIC has NO EXECUTE on both functions.
		adminPool, err := NewPool(ctx, dsn, PoolOptions{MaxConns: 2, StatementTimeout: 5 * time.Second})
		if err != nil {
			t.Fatalf("admin pool: %v", err)
		}
		defer adminPool.Close()

		// Re-read Org B rows as admin and compare field by field to prove zero mutation.
		var bMemID, bMemOrgID, bMemUserID, bMemRole, bMemStatus string
		if err := adminPool.QueryRow(ctx,
			"SELECT id, organization_id, user_id, role, status FROM memberships WHERE id = $1", memB,
		).Scan(&bMemID, &bMemOrgID, &bMemUserID, &bMemRole, &bMemStatus); err != nil {
			t.Fatalf("re-read Org B membership as admin: %v", err)
		}
		if bMemID != memB || bMemOrgID != orgB || bMemUserID != userB || bMemRole != "owner" || bMemStatus != "active" {
			t.Fatalf("Org B membership mutated: got (%s, %s, %s, %s, %s), want (%s, %s, %s, owner, active)",
				bMemID, bMemOrgID, bMemUserID, bMemRole, bMemStatus, memB, orgB, userB)
		}

		var bTeamID, bTeamOrgID, bTeamName, bTeamSlug string
		if err := adminPool.QueryRow(ctx,
			"SELECT id, organization_id, name, slug FROM teams WHERE id = $1", teamB,
		).Scan(&bTeamID, &bTeamOrgID, &bTeamName, &bTeamSlug); err != nil {
			t.Fatalf("re-read Org B team as admin: %v", err)
		}
		if bTeamID != teamB || bTeamOrgID != orgB || bTeamName != "Core B" || bTeamSlug != "core-b" {
			t.Fatalf("Org B team mutated: got (%s, %s, %s, %s), want (%s, %s, Core B, core-b)",
				bTeamID, bTeamOrgID, bTeamName, bTeamSlug, teamB, orgB)
		}

		// Dynamic catalog guard (CTO #33): EVERY SECURITY DEFINER function in public schema
		// must be owned by vigia_definer, pin search_path in proconfig, and revoke PUBLIC EXECUTE.
		checkedFuncs, violations, err := auditSecurityDefinerFunctions(ctx, adminPool)
		if err != nil {
			t.Fatalf("auditSecurityDefinerFunctions: %v", err)
		}
		if len(violations) > 0 {
			t.Fatalf("SECURITY DEFINER guard violations: %v", violations)
		}
		seenLookupCred := false
		for _, fn := range checkedFuncs {
			if fn == "lookup_api_credential_by_prefix" {
				seenLookupCred = true
			}
		}
		if !seenLookupCred {
			t.Fatalf("dynamic SECURITY DEFINER guard did not find lookup_api_credential_by_prefix; saw %v", checkedFuncs)
		}

		// Negative proof (CTO #33): creating a non-compliant SECURITY DEFINER function MUST be caught.
		if _, err := adminPool.Exec(ctx, `CREATE FUNCTION public._test_bad_secdef() RETURNS int LANGUAGE sql SECURITY DEFINER AS $$ SELECT 1 $$`); err != nil {
			t.Fatalf("create negative test function: %v", err)
		}
		t.Cleanup(func() {
			_, _ = adminPool.Exec(context.Background(), `DROP FUNCTION IF EXISTS public._test_bad_secdef()`)
		})
		_, badViolations, err := auditSecurityDefinerFunctions(ctx, adminPool)
		if err != nil {
			t.Fatalf("auditSecurityDefinerFunctions (negative): %v", err)
		}
		if len(badViolations) == 0 {
			t.Fatal("expected SECURITY DEFINER guard to catch _test_bad_secdef, but got 0 violations")
		}
		if _, err := adminPool.Exec(ctx, `DROP FUNCTION public._test_bad_secdef()`); err != nil {
			t.Fatalf("drop negative test function: %v", err)
		}
	})
}

func auditSecurityDefinerFunctions(ctx context.Context, adminPool *pgxpool.Pool) (checked []string, violations []string, err error) {
	rows, err := adminPool.Query(ctx, `
		SELECT p.proname,
		       r.rolname,
		       EXISTS (
		           SELECT 1
		           FROM unnest(coalesce(p.proconfig, ARRAY[]::text[])) cfg
		           WHERE cfg LIKE 'search_path=%'
		       ) AS has_search_path,
		       has_function_privilege('public', p.oid, 'EXECUTE') AS public_exec
		FROM pg_proc p
		JOIN pg_namespace n ON n.oid = p.pronamespace
		JOIN pg_roles r ON r.oid = p.proowner
		WHERE n.nspname = 'public'
		  AND p.prosecdef = true
		ORDER BY p.proname
	`)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var name, owner string
		var hasSearchPath, publicExec bool
		if err := rows.Scan(&name, &owner, &hasSearchPath, &publicExec); err != nil {
			return nil, nil, err
		}
		checked = append(checked, name)
		if owner != "vigia_definer" {
			violations = append(violations, fmt.Sprintf("%s: owner=%q (want vigia_definer)", name, owner))
		}
		if !hasSearchPath {
			violations = append(violations, fmt.Sprintf("%s: missing pinned search_path in proconfig", name))
		}
		if publicExec {
			violations = append(violations, fmt.Sprintf("%s: PUBLIC has EXECUTE", name))
		}
	}
	return checked, violations, rows.Err()
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
