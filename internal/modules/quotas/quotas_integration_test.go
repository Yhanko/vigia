//go:build integration

package quotas_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/redis/go-redis/v9"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/Yhanko/vigia/internal/modules/organizations"
	"github.com/Yhanko/vigia/internal/modules/projects"
	"github.com/Yhanko/vigia/internal/modules/quotas"
	"github.com/Yhanko/vigia/internal/platform/clock"
	"github.com/Yhanko/vigia/internal/platform/database"
	"github.com/Yhanko/vigia/migrations"
)

const (
	timescaleImage = "timescale/timescaledb:2.32.1-pg18@sha256:70e6526ad8e31e3f4833f2c5863b50b92d7a6bee4d432ad1f660e2c6dd956d94"
	redisImage     = "redis:8.12.0-alpine3.23@sha256:5af80107c1eeecb484a2269b80a26d12bfa6521787da4663bd9f19f60a163483"
)

type captureMailer struct {
	mu   sync.Mutex
	sent []string
}

func (m *captureMailer) Send(_ context.Context, to, subject, _ string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sent = append(m.sent, to+"|"+subject)
	return nil
}

func (m *captureMailer) count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.sent)
}

func TestQuotasIntegration(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	// Start TimescaleDB.
	pgContainer, err := testcontainers.Run(ctx, timescaleImage,
		testcontainers.WithEnv(map[string]string{
			"POSTGRES_USER":     "vigia_admin",
			"POSTGRES_PASSWORD": "test_admin_password",
			"POSTGRES_DB":       "vigia",
			"NO_TS_TUNE":        "true",
		}),
		testcontainers.WithExposedPorts("5432/tcp"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").WithOccurrence(2).WithStartupTimeout(90*time.Second),
		),
	)
	if err != nil {
		t.Fatalf("start timescaledb: %v", err)
	}
	defer func() { _ = testcontainers.TerminateContainer(pgContainer) }()

	pgHost, _ := pgContainer.Host(ctx)
	pgPort, _ := pgContainer.MappedPort(ctx, "5432/tcp")
	adminDSN := "postgres://vigia_admin:test_admin_password@" + pgHost + ":" + pgPort.Port() + "/vigia?sslmode=disable"

	if err := database.EnsureRoles(ctx, adminDSN, "test_app_password"); err != nil {
		t.Fatalf("EnsureRoles: %v", err)
	}
	if err := database.Migrate(ctx, adminDSN, migrations.FS, "up"); err != nil {
		t.Fatalf("Migrate up: %v", err)
	}

	appDSN := "postgres://vigia_app:test_app_password@" + pgHost + ":" + pgPort.Port() + "/vigia?sslmode=disable"
	pool, err := database.NewPool(ctx, appDSN, database.PoolOptions{MaxConns: 16, StatementTimeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("NewPool: %v", err)
	}
	defer pool.Close()

	adminPool, err := database.NewPool(ctx, adminDSN, database.PoolOptions{MaxConns: 4, StatementTimeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("admin NewPool: %v", err)
	}
	defer adminPool.Close()

	// Start Redis.
	redisContainer, err := testcontainers.Run(ctx, redisImage,
		testcontainers.WithExposedPorts("6379/tcp"),
		testcontainers.WithWaitStrategy(wait.ForLog("Ready to accept connections").WithStartupTimeout(30*time.Second)),
	)
	if err != nil {
		t.Fatalf("start redis: %v", err)
	}
	defer func() { _ = testcontainers.TerminateContainer(redisContainer) }()

	rHost, _ := redisContainer.Host(ctx)
	rPort, _ := redisContainer.MappedPort(ctx, "6379/tcp")
	rdb := redis.NewClient(&redis.Options{Addr: rHost + ":" + rPort.Port()})
	defer rdb.Close()

	// Seed a tiny test plan alongside 'beta' so we can test 80%, 100%, daily/monthly rollover, and concurrency quickly.
	_, err = adminPool.Exec(ctx, `
		INSERT INTO plans (
			id, name, max_events_per_month, max_events_per_day,
			rate_limit_org_per_min, rate_limit_key_per_min, max_whatsapp_per_month,
			max_projects, max_members, max_alert_rules_per_project,
			max_notification_targets, max_artifact_bytes, event_retention_days
		) VALUES ('tiny_test', 'Tiny Test', 10, 6, 100, 60, 5, 2, 2, 10, 10, 1024, 30)
	`)
	if err != nil {
		t.Fatalf("insert tiny_test plan: %v", err)
	}

	// Create user + orgA (tiny_test) + orgB (beta).
	userA := uuid.New()
	userB := uuid.New()
	orgA := uuid.New()
	orgB := uuid.New()

	_, err = adminPool.Exec(ctx, `
		INSERT INTO users (id, email, name, password_hash, status, email_verified_at)
		VALUES ($1, 'owner-a@example.com', 'Owner A', 'hash', 'active', now()),
		       ($2, 'owner-b@example.com', 'Owner B', 'hash', 'active', now())
	`, userA, userB)
	if err != nil {
		t.Fatalf("seed users: %v", err)
	}
	_, err = adminPool.Exec(ctx, `
		INSERT INTO organizations (id, name, slug, status, plan)
		VALUES ($1, 'Org A', 'org-a', 'active', 'tiny_test'),
		       ($2, 'Org B', 'org-b', 'active', 'beta')
	`, orgA, orgB)
	if err != nil {
		t.Fatalf("seed orgs: %v", err)
	}
	_, err = adminPool.Exec(ctx, `
		INSERT INTO memberships (id, organization_id, user_id, role, status)
		VALUES ($1, $2, $3, 'owner', 'active'),
		       ($4, $5, $6, 'owner', 'active')
	`, uuid.New(), orgA, userA, uuid.New(), orgB, userB)
	if err != nil {
		t.Fatalf("seed memberships: %v", err)
	}

	tidA, _ := database.ParseTenantID(orgA.String())
	tidB, _ := database.ParseTenantID(orgB.String())

	fakeClock := clock.NewFake(time.Date(2026, 11, 28, 23, 55, 0, 0, time.UTC))
	mailer := &captureMailer{}

	orgSvc, err := organizations.NewService(organizations.ServiceConfig{
		Pool:  pool,
		Clock: fakeClock,
	})
	if err != nil {
		t.Fatalf("organizations.NewService: %v", err)
	}
	svc, err := quotas.NewService(quotas.ServiceConfig{
		Pool:       pool,
		Redis:      rdb,
		Mailer:     mailer,
		Authorizer: orgSvc,
		Clock:      fakeClock,
	})
	if err != nil {
		t.Fatalf("quotas.NewService: %v", err)
	}

	t.Run("daily and monthly UTC rollover + one-time 80% and 100% alerts", func(t *testing.T) {
		// Day limit = 6, Month limit = 10.
		for i := range 6 {
			dec, err := svc.ConsumeEvents(ctx, tidA, 1)
			if err != nil {
				t.Fatalf("consume #%d: %v", i, err)
			}
			if !dec.Allowed {
				t.Fatalf("expected event #%d allowed", i)
			}
		}
		// 7th event on same UTC day must be rejected (daily limit = 6).
		dec, err := svc.ConsumeEvents(ctx, tidA, 1)
		if err != nil {
			t.Fatalf("consume 7th: %v", err)
		}
		if dec.Allowed || dec.Window != "day" || dec.RetryAfter < 4*time.Minute || dec.RetryAfter > 6*time.Minute {
			t.Fatalf("expected day quota rejection with ~5m retry, got %+v", dec)
		}

		// Flush to usage_aggregates (idempotent double flush).
		flushed, err := svc.FlushDirtyUsage(ctx)
		if err != nil || flushed != 1 {
			t.Fatalf("FlushDirtyUsage: flushed=%d err=%v", flushed, err)
		}
		if _, err := svc.FlushDirtyUsage(ctx); err != nil {
			t.Fatalf("second FlushDirtyUsage: %v", err)
		}

		// Advance clock past UTC midnight (2026-11-29 00:01 UTC): daily resets, monthly stays at 6.
		fakeClock.Set(time.Date(2026, 11, 29, 0, 1, 0, 0, time.UTC))

		// Simulate Redis restart (FLUSHDB) — next ConsumeEvents must reconstruct month=6 from usage_aggregates!
		if err := rdb.FlushDB(ctx).Err(); err != nil {
			t.Fatalf("FlushDB: %v", err)
		}

		// Events 7 and 8 bring monthly to 8 (80% of 10) -> should send ONE 80% alert email.
		for range 2 {
			dec, err := svc.ConsumeEvents(ctx, tidA, 1)
			if err != nil || !dec.Allowed {
				t.Fatalf("post-midnight consume failed: dec=%+v err=%v", dec, err)
			}
		}
		if dec, err := svc.ConsumeEvents(ctx, tidA, 1); err != nil || !dec.Allowed || dec.MonthUsed != 9 {
			t.Fatalf("expected month=9 after reconstruction, got dec=%+v err=%v", dec, err)
		}
		if got := mailer.count(); got != 1 {
			t.Fatalf("expected exactly 1 email at 80%% threshold (no duplicates at 90%%), got %d", got)
		}

		// Event 10 hits 100% -> sends ONE 100% alert email.
		if dec, err := svc.ConsumeEvents(ctx, tidA, 1); err != nil || !dec.Allowed || dec.MonthUsed != 10 {
			t.Fatalf("expected 10th event allowed, got dec=%+v err=%v", dec, err)
		}
		if got := mailer.count(); got != 2 {
			t.Fatalf("expected 2 emails total (80%% + 100%%), got %d", got)
		}

		// 11th event rejected by monthly quota (and no duplicate 100% email).
		dec, err = svc.ConsumeEvents(ctx, tidA, 1)
		if err != nil {
			t.Fatalf("consume 11th: %v", err)
		}
		if dec.Allowed || dec.Window != "month" || dec.RetryAfter <= 0 {
			t.Fatalf("expected month quota rejection, got %+v", dec)
		}
		if got := mailer.count(); got != 2 {
			t.Fatalf("expected still 2 emails (no duplicate 100%%), got %d", got)
		}

		// Advance clock to next UTC month (2026-12-01 00:00:05 UTC): both daily and monthly reset.
		fakeClock.Set(time.Date(2026, 12, 1, 0, 0, 5, 0, time.UTC))
		dec, err = svc.ConsumeEvents(ctx, tidA, 1)
		if err != nil || !dec.Allowed || dec.DayUsed != 1 || dec.MonthUsed != 1 {
			t.Fatalf("expected fresh month counters (1,1), got dec=%+v err=%v", dec, err)
		}
	})

	t.Run("concurrency at limit allows zero events above limit", func(t *testing.T) {
		// Jump to a fresh month (2027-01-01) where dayLimit=6, monthLimit=10.
		fakeClock.Set(time.Date(2027, 1, 1, 12, 0, 0, 0, time.UTC))
		const workers = 25
		var allowedCount atomic.Int64
		var wg sync.WaitGroup
		wg.Add(workers)
		for range workers {
			go func() {
				defer wg.Done()
				dec, err := svc.ConsumeEvents(ctx, tidA, 1)
				if err != nil {
					t.Errorf("concurrent ConsumeEvents error: %v", err)
					return
				}
				if dec.Allowed {
					allowedCount.Add(1)
				}
			}()
		}
		wg.Wait()
		if got := allowedCount.Load(); got != 6 {
			t.Fatalf("concurrency breach: expected exactly 6 allowed (daily limit), got %d", got)
		}
	})

	t.Run("Redis unavailable fails closed with ErrServiceUnavailable", func(t *testing.T) {
		badRedis := redis.NewClient(&redis.Options{
			Addr:        "127.0.0.1:1",
			DialTimeout: 100 * time.Millisecond,
			MaxRetries:  0,
		})
		defer badRedis.Close()

		failSvc, err := quotas.NewService(quotas.ServiceConfig{
			Pool:  pool,
			Redis: badRedis,
			Clock: fakeClock,
		})
		if err != nil {
			t.Fatalf("NewService: %v", err)
		}
		_, err = failSvc.ConsumeEvents(ctx, tidA, 1)
		if !errors.Is(err, quotas.ErrServiceUnavailable) {
			t.Fatalf("expected ErrServiceUnavailable when Redis is down, got %v", err)
		}
	})

	t.Run("hard limits enforce max_projects and max_members", func(t *testing.T) {
		projSvc, err := projects.NewService(projects.ServiceConfig{
			Pool:         pool,
			QuotaChecker: svc,
			Clock:        fakeClock,
		})
		if err != nil {
			t.Fatalf("projects.NewService: %v", err)
		}
		actorA := organizations.Actor{UserID: userA.String(), Email: "owner-a@example.com", MFAEnabled: true, LastAuthAt: fakeClock.Now()}

		// tiny_test max_projects = 2.
		if _, err := projSvc.CreateProject(ctx, tidA, actorA, "P1", "proj-one", "go"); err != nil {
			t.Fatalf("CreateProject 1: %v", err)
		}
		if _, err := projSvc.CreateProject(ctx, tidA, actorA, "P2", "proj-two", "go"); err != nil {
			t.Fatalf("CreateProject 2: %v", err)
		}
		if _, err := projSvc.CreateProject(ctx, tidA, actorA, "P3", "proj-three", "go"); !errors.Is(err, projects.ErrQuotaExceeded) {
			t.Fatalf("expected projects.ErrQuotaExceeded on 3rd project, got %v", err)
		}

		// tiny_test max_members = 2 (already has 1 owner; 1 pending invite allowed; 2nd invite rejected).
		orgSvcWithQuota, err := organizations.NewService(organizations.ServiceConfig{
			Pool:         pool,
			QuotaChecker: svc,
			Clock:        fakeClock,
		})
		if err != nil {
			t.Fatalf("organizations.NewService: %v", err)
		}
		if _, _, err := orgSvcWithQuota.CreateInvitation(ctx, tidA, actorA, "inv1@example.com", "member"); err != nil {
			t.Fatalf("CreateInvitation 1: %v", err)
		}
		if _, _, err := orgSvcWithQuota.CreateInvitation(ctx, tidA, actorA, "inv2@example.com", "member"); !errors.Is(err, organizations.ErrQuotaExceeded) {
			t.Fatalf("expected organizations.ErrQuotaExceeded on 2nd invite, got %v", err)
		}
	})

	t.Run("GetUsage and GetQuotas enforce RBAC and cross-tenant 404", func(t *testing.T) {
		actorA := organizations.Actor{UserID: userA.String(), Email: "owner-a@example.com", MFAEnabled: true}
		actorB := organizations.Actor{UserID: userB.String(), Email: "owner-b@example.com", MFAEnabled: true}

		p, err := svc.GetQuotas(ctx, tidA, actorA)
		if err != nil || p.ID != "tiny_test" || p.MaxEventsPerMonth != 10 {
			t.Fatalf("GetQuotas orgA: plan=%+v err=%v", p, err)
		}
		u, err := svc.GetUsage(ctx, tidA, actorA)
		if err != nil || u.ActiveProjects != 2 || u.ActiveMembersAndInvites != 2 {
			t.Fatalf("GetUsage orgA: usage=%+v err=%v", u, err)
		}

		// Cross-tenant: actorB accessing orgA must receive ErrNotFound (404, ADR-008).
		if _, err := svc.GetQuotas(ctx, tidA, actorB); !errors.Is(err, quotas.ErrNotFound) {
			t.Fatalf("expected ErrNotFound for cross-tenant GetQuotas, got %v", err)
		}
		if _, err := svc.GetUsage(ctx, tidA, actorB); !errors.Is(err, quotas.ErrNotFound) {
			t.Fatalf("expected ErrNotFound for cross-tenant GetUsage, got %v", err)
		}

		// Also verify beta plan defaults on orgB.
		betaPlan, err := svc.GetQuotas(ctx, tidB, actorB)
		if err != nil || betaPlan.ID != "beta" || betaPlan.MaxEventsPerMonth != 100000 || betaPlan.MaxEventsPerDay != 20000 || betaPlan.MaxProjects != 10 || betaPlan.MaxMembers != 15 {
			t.Fatalf("unexpected beta plan defaults: %+v err=%v", betaPlan, err)
		}

		// Verify HTTP handler JSON response shape on unauthenticated request (401).
		h, err := quotas.NewHandler(svc, nil, nil)
		if err != nil {
			t.Fatalf("NewHandler: %v", err)
		}
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/api/v1/organizations/"+orgA.String()+"/quotas", nil)
		h.GetOrganizationQuotas(rec, req, orgA.String())
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401 without session, got %d", rec.Code)
		}
		var errEnv map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &errEnv); err != nil {
			t.Fatalf("invalid error JSON: %v", err)
		}

		// Verify pgx.Tx helper doesn't leak across tenants.
		var orgUUID pgtype.UUID
		_ = orgUUID.Scan(orgA.String())
		_ = database.WithTenantTx(ctx, pool, tidB, func(tx pgx.Tx) error {
			err := svc.CheckProjectLimitTx(ctx, tx, orgUUID)
			if !errors.Is(err, quotas.ErrNotFound) {
				t.Fatalf("expected ErrNotFound for cross-tenant CheckProjectLimitTx, got %v", err)
			}
			return nil
		})
	})
}
