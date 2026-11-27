//go:build integration

package security_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/Yhanko/vigia/internal/modules/audit"
	"github.com/Yhanko/vigia/internal/modules/credentials"
	"github.com/Yhanko/vigia/internal/modules/organizations"
	"github.com/Yhanko/vigia/internal/modules/projects"
	"github.com/Yhanko/vigia/internal/platform/clock"
	"github.com/Yhanko/vigia/internal/platform/database"
	"github.com/Yhanko/vigia/internal/platform/queue"
	"github.com/Yhanko/vigia/migrations"
)

const (
	timescaleImage = "timescale/timescaledb:2.32.1-pg18@sha256:70e6526ad8e31e3f4833f2c5863b50b92d7a6bee4d432ad1f660e2c6dd956d94"
	redisImage     = "redis:8.12.0-alpine3.23@sha256:5af80107c1eeecb484a2269b80a26d12bfa6521787da4663bd9f19f60a163483"
)

func randomHex(t *testing.T, nBytes int) string {
	t.Helper()
	b := make([]byte, nBytes)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return hex.EncodeToString(b)
}

func startPGAndRedis(t *testing.T) (*pgxpool.Pool, *pgxpool.Pool, *redis.Client) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	adminPass := randomHex(t, 16)
	appPass := randomHex(t, 16)
	redisPass := randomHex(t, 16)

	pgCtr, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image:        timescaleImage,
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
		t.Fatalf("start postgres: %v", err)
	}
	t.Cleanup(func() { _ = pgCtr.Terminate(context.Background()) })

	pgHost, err := pgCtr.Host(ctx)
	if err != nil {
		t.Fatalf("pg host: %v", err)
	}
	pgPort, err := pgCtr.MappedPort(ctx, "5432/tcp")
	if err != nil {
		t.Fatalf("pg port: %v", err)
	}

	adminDSN := fmt.Sprintf("postgres://vigia:%s@%s:%s/vigia?sslmode=disable", url.QueryEscape(adminPass), pgHost, pgPort.Port())
	appDSN := fmt.Sprintf("postgres://vigia_app:%s@%s:%s/vigia?sslmode=disable", url.QueryEscape(appPass), pgHost, pgPort.Port())

	if err := database.EnsureRoles(ctx, adminDSN, appPass); err != nil {
		t.Fatalf("EnsureRoles: %v", err)
	}
	if err := database.Migrate(ctx, adminDSN, migrations.FS, "up"); err != nil {
		t.Fatalf("Migrate up: %v", err)
	}

	adminPool, err := database.NewPool(ctx, adminDSN, database.PoolOptions{MaxConns: 5})
	if err != nil {
		t.Fatalf("adminPool: %v", err)
	}
	t.Cleanup(adminPool.Close)

	appPool, err := database.NewPool(ctx, appDSN, database.PoolOptions{MaxConns: 10})
	if err != nil {
		t.Fatalf("appPool: %v", err)
	}
	t.Cleanup(appPool.Close)

	// Verify vigia_app is non-privileged (enforces RLS).
	if err := database.VerifyNonPrivilegedRole(ctx, appPool); err != nil {
		t.Fatalf("VerifyNonPrivilegedRole: %v", err)
	}

	redisCtr, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image:        redisImage,
			ExposedPorts: []string{"6379/tcp"},
			Cmd:          []string{"redis-server", "--requirepass", redisPass},
			WaitingFor:   wait.ForLog("Ready to accept connections").WithStartupTimeout(60 * time.Second),
		},
		Started: true,
	})
	if err != nil {
		t.Fatalf("start redis: %v", err)
	}
	t.Cleanup(func() { _ = redisCtr.Terminate(context.Background()) })

	rHost, err := redisCtr.Host(ctx)
	if err != nil {
		t.Fatalf("redis host: %v", err)
	}
	rPort, err := redisCtr.MappedPort(ctx, "6379/tcp")
	if err != nil {
		t.Fatalf("redis port: %v", err)
	}

	rdb, err := queue.NewRedisClient(ctx, rHost+":"+rPort.Port(), redisPass)
	if err != nil {
		t.Fatalf("NewRedisClient: %v", err)
	}
	t.Cleanup(func() { _ = rdb.Close() })

	return adminPool, appPool, rdb
}

func insertTestUser(t *testing.T, ctx context.Context, pool *pgxpool.Pool, email, name string) string {
	t.Helper()
	uid := uuid.New().String()
	_, err := pool.Exec(ctx, `
		INSERT INTO users (id, email, name, password_hash, status, email_verified_at, mfa_enabled)
		VALUES ($1, $2, $3, 'placeholder-hash', 'active', now(), true)
	`, uid, email, name)
	if err != nil {
		t.Fatalf("insert user %s: %v", email, err)
	}
	return uid
}

// TestFase1SecuritySuite verifies:
//   - Cross-tenant isolation across organizations, memberships, invitations, teams,
//     audit_logs, projects, environments, and api_credentials.
//   - RBAC privilege escalation negative cases (viewer/member/admin vs owner).
//   - Protected environment deletion guard (PROTECTED_RESOURCE).
//   - Immediate API credential revocation with Redis cache eviction.
//   - Zero secret leaks in logs, credential list responses, and audit_logs.
func TestFase1SecuritySuite(t *testing.T) {
	ctx := context.Background()
	_, appPool, rdb := startPGAndRedis(t)

	var logBuf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	clk := clock.System{}
	pepper := []byte(randomHex(t, 32))

	orgSvc, err := organizations.NewService(organizations.ServiceConfig{
		Pool:                     appPool,
		AppURL:                   "https://app.vigia.ao",
		MFARequiredForPrivileged: true,
		Clock:                    clk,
	})
	if err != nil {
		t.Fatalf("organizations.NewService: %v", err)
	}
	audSvc, err := audit.NewService(appPool)
	if err != nil {
		t.Fatalf("audit.NewService: %v", err)
	}
	credSvc, err := credentials.NewService(credentials.ServiceConfig{
		Pool:                     appPool,
		Cache:                    credentials.NewRedisCache(rdb),
		Pepper:                   pepper,
		IngestHost:               "ingest.vigia.ao",
		MFARequiredForPrivileged: true,
		Clock:                    clk,
		Logger:                   logger,
	})
	if err != nil {
		t.Fatalf("credentials.NewService: %v", err)
	}
	t.Cleanup(func() { credSvc.Close(context.Background()) })

	projSvc, err := projects.NewService(projects.ServiceConfig{
		Pool:                     appPool,
		CredentialInvalidator:    credSvc,
		MFARequiredForPrivileged: true,
		Clock:                    clk,
	})
	if err != nil {
		t.Fatalf("projects.NewService: %v", err)
	}

	now := clk.Now().UTC()
	ownerAID := insertTestUser(t, ctx, appPool, "owner-a@vigia.test", "Owner A")
	adminAID := insertTestUser(t, ctx, appPool, "admin-a@vigia.test", "Admin A")
	memberAID := insertTestUser(t, ctx, appPool, "member-a@vigia.test", "Member A")
	viewerAID := insertTestUser(t, ctx, appPool, "viewer-a@vigia.test", "Viewer A")
	ownerBID := insertTestUser(t, ctx, appPool, "owner-b@vigia.test", "Owner B")

	actor := func(uid, email string) organizations.Actor {
		return organizations.Actor{
			UserID:     uid,
			Email:      email,
			MFAEnabled: true,
			LastAuthAt: now,
			RequestID:  "sec-test-req",
		}
	}

	ownerA := actor(ownerAID, "owner-a@vigia.test")
	adminA := actor(adminAID, "admin-a@vigia.test")
	memberA := actor(memberAID, "member-a@vigia.test")
	viewerA := actor(viewerAID, "viewer-a@vigia.test")
	ownerB := actor(ownerBID, "owner-b@vigia.test")

	orgA, err := orgSvc.Create(ctx, ownerA, "Tenant Alpha", "tenant-alpha")
	if err != nil {
		t.Fatalf("create orgA: %v", err)
	}
	orgB, err := orgSvc.Create(ctx, ownerB, "Tenant Beta", "tenant-beta")
	if err != nil {
		t.Fatalf("create orgB: %v", err)
	}
	tidA, _ := database.ParseTenantID(orgA.ID)
	tidB, _ := database.ParseTenantID(orgB.ID)

	// Invite and accept admin, member, and viewer into Org A.
	for _, u := range []struct {
		act  organizations.Actor
		role string
	}{
		{adminA, organizations.RoleAdmin},
		{memberA, organizations.RoleMember},
		{viewerA, organizations.RoleViewer},
	} {
		_, tok, err := orgSvc.CreateInvitation(ctx, tidA, ownerA, u.act.Email, u.role)
		if err != nil {
			t.Fatalf("invite %s: %v", u.role, err)
		}
		if _, err := orgSvc.AcceptInvitation(ctx, u.act, tok); err != nil {
			t.Fatalf("accept %s: %v", u.role, err)
		}
	}

	// Create pending invitation, team, project, protected & non-protected envs, and API credentials in Org A.
	invA, rawInvToken, err := orgSvc.CreateInvitation(ctx, tidA, ownerA, "pending-a@vigia.test", organizations.RoleViewer)
	if err != nil {
		t.Fatalf("create pending invA: %v", err)
	}
	teamA, err := orgSvc.CreateTeam(ctx, tidA, ownerA, "Core Team", "core-team")
	if err != nil {
		t.Fatalf("create teamA: %v", err)
	}
	projA, err := projSvc.CreateProject(ctx, tidA, ownerA, "Alpha API", "alpha-api", "go")
	if err != nil {
		t.Fatalf("create projA: %v", err)
	}
	prodEnvA, err := projSvc.CreateEnvironment(ctx, tidA, ownerA, projA.ID, "production", true)
	if err != nil {
		t.Fatalf("create prod env: %v", err)
	}
	stgEnvA, err := projSvc.CreateEnvironment(ctx, tidA, ownerA, projA.ID, "staging", false)
	if err != nil {
		t.Fatalf("create staging env: %v", err)
	}
	ingCredA, err := credSvc.Create(ctx, tidA, ownerA, credentials.CreateInput{
		ProjectID:     projA.ID,
		EnvironmentID: prodEnvA.ID,
		Kind:          credentials.KindIngest,
		Name:          "Alpha Ingest Key",
	})
	if err != nil {
		t.Fatalf("create ingest credA: %v", err)
	}
	if ingCredA.Secret == "" {
		t.Fatal("expected raw secret on creation")
	}

	// 1. Cross-tenant isolation: Owner B must NOT read or mutate ANY resource in Org A.
	// organizations.Authorize returns ErrNotFound for non-members (anti-enumeration).
	t.Run("cross-tenant isolation", func(t *testing.T) {
		if _, err := orgSvc.Get(ctx, tidA, ownerB); !errors.Is(err, organizations.ErrNotFound) {
			t.Errorf("OrgB Get(orgA) = %v, want ErrNotFound", err)
		}
		if _, err := orgSvc.Update(ctx, tidA, ownerB, "Hacked"); !errors.Is(err, organizations.ErrNotFound) {
			t.Errorf("OrgB Update(orgA) = %v, want ErrNotFound", err)
		}
		if _, err := orgSvc.ListMembers(ctx, tidA, ownerB, 50); !errors.Is(err, organizations.ErrNotFound) {
			t.Errorf("OrgB ListMembers(orgA) = %v, want ErrNotFound", err)
		}
		if err := orgSvc.RevokeInvitation(ctx, tidA, ownerB, invA.ID); !errors.Is(err, organizations.ErrNotFound) {
			t.Errorf("OrgB RevokeInvitation(orgA) = %v, want ErrNotFound", err)
		}
		if err := orgSvc.DeleteTeam(ctx, tidA, ownerB, teamA.ID); !errors.Is(err, organizations.ErrNotFound) {
			t.Errorf("OrgB DeleteTeam(orgA) = %v, want ErrNotFound", err)
		}
		if _, err := projSvc.GetProject(ctx, tidA, ownerB, projA.ID); !errors.Is(err, projects.ErrForbidden) {
			t.Errorf("OrgB GetProject(orgA) = %v, want ErrForbidden", err)
		}
		if _, err := projSvc.GetProject(ctx, tidB, ownerB, projA.ID); !errors.Is(err, projects.ErrProjectNotFound) {
			t.Errorf("OrgB GetProject(orgB, projA) = %v, want ErrProjectNotFound (RLS)", err)
		}
		if err := projSvc.DeleteEnvironment(ctx, tidB, ownerB, stgEnvA.ID); !errors.Is(err, projects.ErrEnvironmentNotFound) {
			t.Errorf("OrgB DeleteEnvironment(orgB, stgEnvA) = %v, want ErrEnvironmentNotFound (RLS)", err)
		}
		if err := credSvc.Revoke(ctx, tidB, ownerB, ingCredA.ID); !errors.Is(err, credentials.ErrNotFound) {
			t.Errorf("OrgB Revoke(orgB, credA) = %v, want ErrNotFound (RLS)", err)
		}
		// Audit logs under Org B must not contain any Org A entries.
		pageB, err := audSvc.List(ctx, tidB, 100, "")
		if err != nil {
			t.Fatalf("audSvc.List(orgB): %v", err)
		}
		for _, e := range pageB.Items {
			if e.OrganizationID != orgB.ID {
				t.Errorf("cross-tenant audit leak: got org %s inside orgB page", e.OrganizationID)
			}
		}
	})

	// 2. RBAC privilege escalation & protected resource negative tests.
	t.Run("rbac escalation and protected env", func(t *testing.T) {
		if _, _, err := orgSvc.CreateInvitation(ctx, tidA, viewerA, "x@vigia.test", organizations.RoleViewer); !errors.Is(err, organizations.ErrForbidden) {
			t.Errorf("viewer CreateInvitation = %v, want ErrForbidden", err)
		}
		if _, err := projSvc.CreateProject(ctx, tidA, viewerA, "Nope", "nope-proj", "go"); !errors.Is(err, projects.ErrForbidden) {
			t.Errorf("viewer CreateProject = %v, want ErrForbidden", err)
		}
		if _, err := credSvc.Create(ctx, tidA, memberA, credentials.CreateInput{ProjectID: projA.ID, Kind: credentials.KindIngest, Name: "No"}); !errors.Is(err, credentials.ErrForbidden) {
			t.Errorf("member CreateCredential = %v, want ErrForbidden", err)
		}
		if _, err := orgSvc.ScheduleDeletion(ctx, tidA, adminA, orgA.Slug); !errors.Is(err, organizations.ErrForbidden) {
			t.Errorf("admin ScheduleDeletion = %v, want ErrForbidden", err)
		}

		// Find Owner A's membership ID and verify Admin A cannot demote or remove Owner A.
		members, err := orgSvc.ListMembers(ctx, tidA, ownerA, 50)
		if err != nil {
			t.Fatalf("ListMembers: %v", err)
		}
		var ownerMemID string
		for _, m := range members {
			if m.UserID == ownerAID {
				ownerMemID = m.ID
			}
		}
		if ownerMemID == "" {
			t.Fatal("owner membership not found")
		}
		if _, err := orgSvc.UpdateMemberRole(ctx, tidA, adminA, ownerMemID, organizations.RoleMember); !errors.Is(err, organizations.ErrForbidden) {
			t.Errorf("admin demote owner = %v, want ErrForbidden", err)
		}
		if err := orgSvc.RemoveMember(ctx, tidA, adminA, ownerMemID); !errors.Is(err, organizations.ErrForbidden) {
			t.Errorf("admin remove owner = %v, want ErrForbidden", err)
		}

		// Protected environment cannot be deleted.
		if err := projSvc.DeleteEnvironment(ctx, tidA, ownerA, prodEnvA.ID); !errors.Is(err, projects.ErrProtectedResource) {
			t.Errorf("DeleteEnvironment(protected) = %v, want ErrProtectedResource", err)
		}
		// Non-protected environment can be deleted.
		if err := projSvc.DeleteEnvironment(ctx, tidA, ownerA, stgEnvA.ID); err != nil {
			t.Errorf("DeleteEnvironment(staging) = %v, want nil", err)
		}
	})

	// 3. Immediate API credential revocation with Redis cache eviction.
	t.Run("immediate revocation and cache eviction", func(t *testing.T) {
		// Authenticate once (populates Redis cache).
		authCred, err := credSvc.AuthenticateSecret(ctx, ingCredA.Secret, "198.51.100.10")
		if err != nil {
			t.Fatalf("AuthenticateSecret (cold): %v", err)
		}
		if authCred.OrganizationID != orgA.ID || authCred.ProjectID != projA.ID {
			t.Fatalf("unexpected authCred: %+v", authCred)
		}
		cacheKey := credentials.CacheKey(credentials.KindIngest, ingCredA.Prefix)
		exists, err := rdb.Exists(ctx, cacheKey).Result()
		if err != nil || exists != 1 {
			t.Fatalf("expected Redis cache key %s to exist, exists=%d err=%v", cacheKey, exists, err)
		}

		// Authenticate from cache with a different IP prefix to trigger anomalous_ip audit event.
		if _, err := credSvc.AuthenticateSecret(ctx, ingCredA.Secret, "203.0.113.42"); err != nil {
			t.Fatalf("AuthenticateSecret (cached): %v", err)
		}

		// Revoke and verify IMMEDIATE rejection + Redis eviction.
		if err := credSvc.Revoke(ctx, tidA, ownerA, ingCredA.ID); err != nil {
			t.Fatalf("Revoke: %v", err)
		}
		exists, err = rdb.Exists(ctx, cacheKey).Result()
		if err != nil || exists != 0 {
			t.Fatalf("expected Redis cache key %s evicted immediately, exists=%d err=%v", cacheKey, exists, err)
		}
		if _, err := credSvc.AuthenticateSecret(ctx, ingCredA.Secret, "198.51.100.10"); !errors.Is(err, credentials.ErrInvalidCredential) {
			t.Fatalf("AuthenticateSecret after revoke = %v, want ErrInvalidCredential", err)
		}
	})

	// 4. Zero secret leaks in logs, List(), and audit_logs.
	t.Run("zero secret leaks", func(t *testing.T) {
		secretsToCheck := []string{ingCredA.Secret, rawInvToken, string(pepper)}

		logOutput := logBuf.String()
		for _, sec := range secretsToCheck {
			if strings.Contains(logOutput, sec) {
				t.Errorf("secret leaked in logs!")
			}
		}

		listed, err := credSvc.List(ctx, tidA, ownerA, projA.ID)
		if err != nil {
			t.Fatalf("credSvc.List: %v", err)
		}
		listDump := fmt.Sprintf("%+v", listed)
		if strings.Contains(listDump, ingCredA.Secret) {
			t.Errorf("raw credential secret leaked in List()!")
		}

		pageA, err := audSvc.List(ctx, tidA, 100, "")
		if err != nil {
			t.Fatalf("audSvc.List: %v", err)
		}
		foundAnomalous := false
		for _, e := range pageA.Items {
			if e.Action == "credential.anomalous_ip" {
				foundAnomalous = true
			}
			raw := string(e.ChangesJSON)
			for _, sec := range secretsToCheck {
				if strings.Contains(raw, sec) {
					t.Errorf("secret leaked in audit_logs action=%s!", e.Action)
				}
			}
		}
		if !foundAnomalous {
			t.Errorf("expected credential.anomalous_ip audit event when key was used from a new IP prefix")
		}
	})
}
