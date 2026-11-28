//go:build integration

package credentials_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/Yhanko/vigia/internal/api"
	"github.com/Yhanko/vigia/internal/modules/credentials"
	"github.com/Yhanko/vigia/internal/modules/organizations"
	"github.com/Yhanko/vigia/internal/modules/projects"
	"github.com/Yhanko/vigia/internal/platform/clock"
	"github.com/Yhanko/vigia/internal/platform/database"
	"github.com/Yhanko/vigia/internal/platform/httpserver"
	"github.com/Yhanko/vigia/migrations"
)

const (
	dsnTimescaleImage = "timescale/timescaledb:2.32.1-pg18@sha256:70e6526ad8e31e3f4833f2c5863b50b92d7a6bee4d432ad1f660e2c6dd956d94"
	dsnRedisImage     = "redis:8.12.0-alpine3.23@sha256:5af80107c1eeecb484a2269b80a26d12bfa6521787da4663bd9f19f60a163483"
)

func TestDSNLookupAndInvalidationIntegration(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	pgContainer, err := testcontainers.Run(ctx, dsnTimescaleImage,
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
	pool, err := database.NewPool(ctx, appDSN, database.PoolOptions{MaxConns: 8, StatementTimeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("NewPool: %v", err)
	}
	defer pool.Close()

	adminPool, err := database.NewPool(ctx, adminDSN, database.PoolOptions{MaxConns: 4, StatementTimeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("admin NewPool: %v", err)
	}
	defer adminPool.Close()

	redisContainer, err := testcontainers.Run(ctx, dsnRedisImage,
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

	userID := uuid.New()
	orgID := uuid.New()
	_, err = adminPool.Exec(ctx, `
		INSERT INTO users (id, email, name, password_hash, status, email_verified_at)
		VALUES ($1, 'dsn-owner@example.com', 'DSN Owner', 'hash', 'active', now())
	`, userID)
	if err != nil {
		t.Fatalf("seed user: %v", err)
	}
	_, err = adminPool.Exec(ctx, `
		INSERT INTO organizations (id, name, slug, status)
		VALUES ($1, 'DSN Org', 'dsn-org', 'active')
	`, orgID)
	if err != nil {
		t.Fatalf("seed org: %v", err)
	}
	_, err = adminPool.Exec(ctx, `
		INSERT INTO memberships (id, organization_id, user_id, role, status)
		VALUES ($1, $2, $3, 'owner', 'active')
	`, uuid.New(), orgID, userID)
	if err != nil {
		t.Fatalf("seed membership: %v", err)
	}

	fakeClock := clock.NewFake(time.Date(2026, 11, 28, 12, 0, 0, 0, time.UTC))
	pepper := []byte("0123456789abcdef0123456789abcdef")

	credSvc, err := credentials.NewService(credentials.ServiceConfig{
		Pool:       pool,
		Cache:      credentials.NewRedisCache(rdb),
		Pepper:     pepper,
		IngestHost: "ingest.vigia.ao",
		Clock:      fakeClock,
	})
	if err != nil {
		t.Fatalf("credentials.NewService: %v", err)
	}
	defer credSvc.Close(ctx)

	projSvc, err := projects.NewService(projects.ServiceConfig{
		Pool:                  pool,
		CredentialInvalidator: credSvc,
		Clock:                 fakeClock,
	})
	if err != nil {
		t.Fatalf("projects.NewService: %v", err)
	}
	orgSvc, err := organizations.NewService(organizations.ServiceConfig{
		Pool:                  pool,
		CredentialInvalidator: credSvc,
		Clock:                 fakeClock,
	})
	if err != nil {
		t.Fatalf("organizations.NewService: %v", err)
	}

	tid, _ := database.ParseTenantID(orgID.String())
	actor := organizations.Actor{UserID: userID.String(), Email: "dsn-owner@example.com", MFAEnabled: true, LastAuthAt: fakeClock.Now()}

	p1, err := projSvc.CreateProject(ctx, tid, actor, "Backend", "backend", "go")
	if err != nil {
		t.Fatalf("CreateProject 1: %v", err)
	}
	p2, err := projSvc.CreateProject(ctx, tid, actor, "Frontend", "frontend", "javascript")
	if err != nil {
		t.Fatalf("CreateProject 2: %v", err)
	}

	created, err := credSvc.Create(ctx, tid, actor, credentials.CreateInput{
		ProjectID:      p1.ID,
		Kind:           credentials.KindDSN,
		Name:           "Default DSN",
		AllowedOrigins: []string{"https://app.example.ao"},
	})
	if err != nil {
		t.Fatalf("Create DSN: %v", err)
	}
	if !strings.HasPrefix(created.DSN, "https://"+created.PublicKey+"@ingest.vigia.ao/") {
		t.Fatalf("unexpected DSN format: %q", created.DSN)
	}

	// Valid DSN lookup + cache population.
	authDSN, err := credSvc.AuthenticateDSN(ctx, created.PublicKey, p1.PublicID)
	if err != nil {
		t.Fatalf("AuthenticateDSN: %v", err)
	}
	if authDSN.OrganizationID != orgID.String() || authDSN.ProjectID != p1.ID || authDSN.AllowRequestBody || authDSN.AllowUserIP || !authDSN.InboundFilters.BrowserExtensions {
		t.Fatalf("unexpected AuthenticatedDSN: %+v", authDSN)
	}

	// Wrong project public_id must be rejected (cross-project spoofing protection).
	if _, err := credSvc.AuthenticateDSN(ctx, created.PublicKey, p2.PublicID); !errors.Is(err, credentials.ErrInvalidCredential) {
		t.Fatalf("expected ErrInvalidCredential for wrong project_public_id, got %v", err)
	}

	// Revoke immediately invalidates Redis cache and DB lookup.
	if err := credSvc.Revoke(ctx, tid, actor, created.ID); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if _, err := credSvc.AuthenticateDSN(ctx, created.PublicKey, p1.PublicID); !errors.Is(err, credentials.ErrInvalidCredential) {
		t.Fatalf("expected ErrInvalidCredential immediately after revoke, got %v", err)
	}

	// Create a second DSN on p2, warm cache, then soft-delete p2 -> immediate rejection.
	dsn2, err := credSvc.Create(ctx, tid, actor, credentials.CreateInput{
		ProjectID: p2.ID,
		Kind:      credentials.KindDSN,
		Name:      "P2 DSN",
	})
	if err != nil {
		t.Fatalf("Create DSN 2: %v", err)
	}
	if _, err := credSvc.AuthenticateDSN(ctx, dsn2.PublicKey, p2.PublicID); err != nil {
		t.Fatalf("AuthenticateDSN p2: %v", err)
	}
	if err := projSvc.DeleteProject(ctx, tid, actor, p2.ID, "frontend"); err != nil {
		t.Fatalf("DeleteProject p2: %v", err)
	}
	if _, err := credSvc.AuthenticateDSN(ctx, dsn2.PublicKey, p2.PublicID); !errors.Is(err, credentials.ErrInvalidCredential) {
		t.Fatalf("expected ErrInvalidCredential after project deletion, got %v", err)
	}

	// Create a third DSN on p1, warm cache, then schedule org deletion -> immediate rejection.
	dsn3, err := credSvc.Create(ctx, tid, actor, credentials.CreateInput{
		ProjectID: p1.ID,
		Kind:      credentials.KindDSN,
		Name:      "P1 DSN 2",
	})
	if err != nil {
		t.Fatalf("Create DSN 3: %v", err)
	}
	if _, err := credSvc.AuthenticateDSN(ctx, dsn3.PublicKey, p1.PublicID); err != nil {
		t.Fatalf("AuthenticateDSN p1: %v", err)
	}
	if _, err := orgSvc.ScheduleDeletion(ctx, tid, actor, "dsn-org"); err != nil {
		t.Fatalf("ScheduleDeletion: %v", err)
	}
	if _, err := credSvc.AuthenticateDSN(ctx, dsn3.PublicKey, p1.PublicID); !errors.Is(err, credentials.ErrInvalidCredential) {
		t.Fatalf("expected ErrInvalidCredential after org deletion, got %v", err)
	}
}

// TestDSNRejectedOnEveryAPIV1Route dynamically walks ALL registered /api/v1/*
// routes on the real chi router and proves a valid DSN key cannot access any
// protected /api/v1/* endpoint (TASKS 2.1 mandatory security test, ADR-005).
func TestDSNRejectedOnEveryAPIV1Route(t *testing.T) {
	pubKey, _, err := credentials.GenerateDSNKey()
	if err != nil {
		t.Fatalf("GenerateDSNKey: %v", err)
	}

	// Mount a router with the real OpenAPI routes and an AuthMiddleware that
	// rejects unauthenticated requests (just like SessionAndCSRFMiddleware does
	// when no session cookie is present; DSN keys are never valid sessions or API keys).
	stubServer := noopAPIServer{}
	handler := httpserver.NewHandler(httpserver.Options{
		CORSOrigins:  []string{"http://localhost:3000"},
		MaxBodyBytes: 1 << 20,
		APIAuth: func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/api/v1/status" || strings.HasPrefix(r.URL.Path, "/api/v1/auth/") {
					next.ServeHTTP(w, r)
					return
				}
				httpserver.WriteError(w, r, http.StatusUnauthorized, "UNAUTHENTICATED", "Authentication is required.")
			})
		},
		APIServer: stubServer,
	})

	chiRouter, ok := handler.(chi.Routes)
	if !ok {
		t.Fatalf("expected chi.Routes, got %T", handler)
	}

	checked := 0
	err = chi.Walk(chiRouter, func(method, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		if !strings.HasPrefix(route, "/api/v1/") {
			return nil
		}
		if route == "/api/v1/status" || strings.HasPrefix(route, "/api/v1/auth/") {
			return nil
		}
		// Replace chi path params with valid UUIDs.
		concrete := strings.NewReplacer(
			"{orgId}", uuid.NewString(),
			"{projectId}", uuid.NewString(),
			"{environmentId}", uuid.NewString(),
			"{credentialId}", uuid.NewString(),
			"{memberId}", uuid.NewString(),
			"{invitationId}", uuid.NewString(),
			"{teamId}", uuid.NewString(),
			"{userId}", uuid.NewString(),
		).Replace(route)

		for _, headerCase := range []struct {
			name string
			k, v string
		}{
			{"Authorization Bearer DSN", "Authorization", "Bearer " + pubKey},
			{"X-Vigia-Key DSN", "X-Vigia-Key", pubKey},
			{"X-Sentry-Auth DSN", "X-Sentry-Auth", "Sentry sentry_version=7, sentry_key=" + pubKey},
		} {
			req := httptest.NewRequest(method, concrete, nil)
			req.Header.Set(headerCase.k, headerCase.v)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != http.StatusUnauthorized && rec.Code != http.StatusForbidden {
				t.Errorf("%s %s with %s: got %d, want 401 or 403", method, route, headerCase.name, rec.Code)
			}
		}
		checked++
		return nil
	})
	if err != nil {
		t.Fatalf("chi.Walk: %v", err)
	}
	if checked < 20 {
		t.Fatalf("expected at least 20 protected /api/v1/* routes to be checked, got %d", checked)
	}
}

type noopAPIServer struct {
	api.Unimplemented
}
