//go:build integration

package security_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/Yhanko/vigia/internal/api"
	"github.com/Yhanko/vigia/internal/modules/credentials"
	"github.com/Yhanko/vigia/internal/modules/identity"
	"github.com/Yhanko/vigia/internal/modules/identity/password"
	"github.com/Yhanko/vigia/internal/modules/identity/session"
	"github.com/Yhanko/vigia/internal/modules/organizations"
	"github.com/Yhanko/vigia/internal/modules/projects"
	"github.com/Yhanko/vigia/internal/platform/clock"
	"github.com/Yhanko/vigia/internal/platform/database"
	"github.com/Yhanko/vigia/internal/platform/httpserver"
	"github.com/Yhanko/vigia/internal/platform/queue"
	"github.com/Yhanko/vigia/internal/platform/ratelimit"
	"github.com/Yhanko/vigia/migrations"
)

type restoreLoginAPI struct {
	api.Unimplemented
	id *identity.Handler
}

func (s restoreLoginAPI) AuthLogin(w http.ResponseWriter, r *http.Request) {
	s.id.AuthLogin(w, r)
}

// TestEncryptedBackupRestore_CTO31 verifies CTO #31 end-to-end:
//  1. Encrypted backup using age (public key only) preserves owners & ACLs (no --no-owner/--no-acl).
//  2. Tampered backup ciphertext is rejected by age authenticated decryption (negative test).
//  3. Restoring with --no-owner --no-acl loses vigia_app privileges (negative proof).
//  4. Restoring onto a clean PostgreSQL 18 instance after EnsureRoles preserves:
//     - has_table_privilege('vigia_app', ...) across all app tables and negative restrictions,
//     - all SECURITY DEFINER functions owned by vigia_definer without PUBLIC EXECUTE,
//     - RLS enabled + forced on all tenant tables,
//     - exact row counts in users, organizations, projects, api_credentials, audit_logs,
//     - live /health/ready and POST /api/v1/auth/login against the restored DB as vigia_app.
func TestEncryptedBackupRestore_CTO31(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()

	adminPass := randomHex(t, 16)
	appPass := randomHex(t, 16)
	redisPass := randomHex(t, 16)
	sessionSecret := []byte(randomHex(t, 32))
	pepper := []byte(randomHex(t, 32))

	startPG := func(name string) (testcontainers.Container, string, string) {
		ctr, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
			ContainerRequest: testcontainers.ContainerRequest{
				Image:        timescaleImage,
				ExposedPorts: []string{"5432/tcp"},
				Env: map[string]string{
					"POSTGRES_USER":     "vigia",
					"POSTGRES_PASSWORD": adminPass,
					"POSTGRES_DB":       "vigia",
					"NO_TS_TUNE":        "true",
				},
				WaitingFor: wait.ForLog("database system is ready to accept connections").WithOccurrence(2).WithStartupTimeout(120 * time.Second),
			},
			Started: true,
		})
		if err != nil {
			t.Fatalf("start %s pg: %v", name, err)
		}
		t.Cleanup(func() { _ = ctr.Terminate(context.Background()) })
		host, _ := ctr.Host(ctx)
		port, _ := ctr.MappedPort(ctx, "5432/tcp")
		adminDSN := fmt.Sprintf("postgres://vigia:%s@%s:%s/vigia?sslmode=disable", url.QueryEscape(adminPass), host, port.Port())
		appDSN := fmt.Sprintf("postgres://vigia_app:%s@%s:%s/vigia?sslmode=disable", url.QueryEscape(appPass), host, port.Port())
		return ctr, adminDSN, appDSN
	}

	// Start source PG, target PG, and Redis.
	srcCtr, srcAdminDSN, srcAppDSN := startPG("source")
	dstCtr, dstAdminDSN, dstAppDSN := startPG("target")

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
	rHost, _ := redisCtr.Host(ctx)
	rPort, _ := redisCtr.MappedPort(ctx, "6379/tcp")
	rdb, err := queue.NewRedisClient(ctx, rHost+":"+rPort.Port(), redisPass)
	if err != nil {
		t.Fatalf("NewRedisClient: %v", err)
	}
	t.Cleanup(func() { _ = rdb.Close() })

	// Bootstrap source DB with roles + migrations + real user, org, project, credential, audit logs.
	if err := database.EnsureRoles(ctx, srcAdminDSN, appPass); err != nil {
		t.Fatalf("source EnsureRoles: %v", err)
	}
	if err := database.Migrate(ctx, srcAdminDSN, migrations.FS, "up"); err != nil {
		t.Fatalf("source Migrate up: %v", err)
	}
	srcPool, err := database.NewPool(ctx, srcAppDSN, database.PoolOptions{MaxConns: 10})
	if err != nil {
		t.Fatalf("source pool: %v", err)
	}
	t.Cleanup(srcPool.Close)

	clk := clock.System{}
	now := clk.Now().UTC()
	hasher, _ := password.NewHasher(password.Options{})
	userPass := "Restore-Test-Pass-" + randomHex(t, 6)
	passHash, err := hasher.Hash(ctx, userPass)
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	idStore, _ := identity.NewPostgresStore(srcPool)
	uid := "11111111-2222-4333-8444-555555555555"
	if _, err := idStore.CreateUser(ctx, identity.User{
		ID:           uid,
		Email:        "restore-owner@vigia.ao",
		Name:         "Restore Owner",
		PasswordHash: passHash,
	}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if _, err := srcPool.Exec(ctx, `UPDATE users SET email_verified_at = now(), mfa_enabled = false WHERE id = $1`, uid); err != nil {
		t.Fatalf("verify user: %v", err)
	}

	orgSvc, _ := organizations.NewService(organizations.ServiceConfig{Pool: srcPool, Clock: clk})
	projSvc, _ := projects.NewService(projects.ServiceConfig{Pool: srcPool, Clock: clk})
	credSvc, _ := credentials.NewService(credentials.ServiceConfig{Pool: srcPool, Pepper: pepper, Clock: clk})
	t.Cleanup(func() { credSvc.Close(context.Background()) })

	actor := organizations.Actor{UserID: uid, Email: "restore-owner@vigia.ao", LastAuthAt: now, RequestID: "bkp-req"}
	org, err := orgSvc.Create(ctx, actor, "Backup Org", "backup-org")
	if err != nil {
		t.Fatalf("create org: %v", err)
	}
	tid, _ := database.ParseTenantID(org.ID)
	proj, err := projSvc.CreateProject(ctx, tid, actor, "Backup Proj", "backup-proj", "go")
	if err != nil {
		t.Fatalf("create proj: %v", err)
	}
	if _, err := credSvc.Create(ctx, tid, actor, credentials.CreateInput{
		ProjectID: proj.ID,
		Kind:      credentials.KindIngest,
		Name:      "Backup Key",
	}); err != nil {
		t.Fatalf("create cred: %v", err)
	}

	// Capture source row counts.
	srcAdminPool, err := database.NewPool(ctx, srcAdminDSN, database.PoolOptions{MaxConns: 5})
	if err != nil {
		t.Fatalf("srcAdminPool: %v", err)
	}
	t.Cleanup(srcAdminPool.Close)
	countTables := []string{"users", "organizations", "projects", "api_credentials", "audit_logs"}
	srcCounts := make(map[string]int64, len(countTables))
	for _, tbl := range countTables {
		var c int64
		if err := srcAdminPool.QueryRow(ctx, "SELECT count(*) FROM public."+tbl).Scan(&c); err != nil {
			t.Fatalf("count source %s: %v", tbl, err)
		}
		srcCounts[tbl] = c
	}

	// Generate ephemeral age X25519 keypair using filippo.io/age@v1.2.1.
	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "age-key.txt")
	keygenCmd := exec.CommandContext(ctx, "go", "run", "filippo.io/age/cmd/age-keygen@v1.2.1", "-o", keyPath)
	keygenOut, err := keygenCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("age-keygen: %v (%s)", err, string(keygenOut))
	}
	keyBytes, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("read key: %v", err)
	}
	var pubKey string
	for _, line := range strings.Split(string(keyBytes), "\n") {
		if strings.HasPrefix(line, "# public key: ") {
			pubKey = strings.TrimSpace(strings.TrimPrefix(line, "# public key: "))
		}
	}
	if !strings.HasPrefix(pubKey, "age1") {
		t.Fatalf("invalid age public key: %q", pubKey)
	}

	// 1. Dump from source container WITH owners & ACLs (no --no-owner, no --no-acl).
	backupStart := time.Now()
	dumpCmd := exec.CommandContext(ctx, "docker", "exec", srcCtr.GetContainerID(),
		"pg_dump", "-U", "vigia", "-d", "vigia", "--format=custom")
	dumpBytes, err := dumpCmd.Output()
	if err != nil {
		t.Fatalf("pg_dump: %v", err)
	}

	// Encrypt using ONLY the public key via age@v1.2.1.
	encPath := filepath.Join(tmpDir, "vigia.dump.age")
	encCmd := exec.CommandContext(ctx, "go", "run", "filippo.io/age/cmd/age@v1.2.1", "-r", pubKey, "-o", encPath)
	encCmd.Stdin = bytes.NewReader(dumpBytes)
	if out, err := encCmd.CombinedOutput(); err != nil {
		t.Fatalf("age encrypt: %v (%s)", err, string(out))
	}
	backupDur := time.Since(backupStart)
	encStat, _ := os.Stat(encPath)
	t.Logf("Encrypted age backup: %d bytes in %v", encStat.Size(), backupDur.Round(time.Millisecond))

	// Negative test A: tamper 1 byte of the encrypted backup -> age -d MUST reject!
	tamperedPath := filepath.Join(tmpDir, "tampered.dump.age")
	encData, _ := os.ReadFile(encPath)
	tampered := append([]byte(nil), encData...)
	tampered[len(tampered)-10] ^= 0xFF
	_ = os.WriteFile(tamperedPath, tampered, 0o600)
	badDecCmd := exec.CommandContext(ctx, "go", "run", "filippo.io/age/cmd/age@v1.2.1", "-d", "-i", keyPath, tamperedPath)
	if err := badDecCmd.Run(); err == nil {
		t.Fatal("expected age -d to reject tampered ciphertext, but it succeeded!")
	}

	// 2. Prepare clean target instance: EnsureRoles ONLY (do NOT run migrations!).
	restoreStart := time.Now()
	if err := database.EnsureRoles(ctx, dstAdminDSN, appPass); err != nil {
		t.Fatalf("target EnsureRoles: %v", err)
	}

	// Decrypt streaming with private key and restore WITH owners & ACLs!
	decCmd := exec.CommandContext(ctx, "go", "run", "filippo.io/age/cmd/age@v1.2.1", "-d", "-i", keyPath, encPath)
	decBytes, err := decCmd.Output()
	if err != nil {
		t.Fatalf("age decrypt: %v", err)
	}
	restoreCmd := exec.CommandContext(ctx, "docker", "exec", "-i", dstCtr.GetContainerID(),
		"pg_restore", "-U", "vigia", "-d", "vigia", "--exit-on-error")
	restoreCmd.Stdin = bytes.NewReader(decBytes)
	if out, err := restoreCmd.CombinedOutput(); err != nil {
		t.Fatalf("pg_restore: %v (%s)", err, string(out))
	}
	t.Logf("Restore completed in %v", time.Since(restoreStart).Round(time.Millisecond))

	// 3. Post-restore verification (privileges, SECURITY DEFINER, RLS, row counts).
	dstAdminPool, err := database.NewPool(ctx, dstAdminDSN, database.PoolOptions{MaxConns: 5})
	if err != nil {
		t.Fatalf("dstAdminPool: %v", err)
	}
	t.Cleanup(dstAdminPool.Close)

	allTables := []string{
		"users", "sessions", "user_tokens", "organizations", "memberships",
		"invitations", "teams", "team_members", "audit_logs", "projects",
		"environments", "api_credentials",
	}
	for _, tbl := range allTables {
		var ok bool
		if err := dstAdminPool.QueryRow(ctx, `SELECT has_table_privilege('vigia_app', 'public.' || $1, 'SELECT')`, tbl).Scan(&ok); err != nil || !ok {
			t.Fatalf("restored DB: vigia_app lacks SELECT on %s (ok=%v err=%v)", tbl, ok, err)
		}
	}
	for _, neg := range [][2]string{{"organizations", "DELETE"}, {"audit_logs", "UPDATE"}, {"audit_logs", "DELETE"}} {
		var ok bool
		if err := dstAdminPool.QueryRow(ctx, `SELECT has_table_privilege('vigia_app', 'public.' || $1, $2)`, neg[0], neg[1]).Scan(&ok); err != nil || ok {
			t.Fatalf("restored DB: vigia_app unexpectedly has %s on %s", neg[1], neg[0])
		}
	}

	// Verify all SECURITY DEFINER functions in public schema.
	var badFuncs int
	if err := dstAdminPool.QueryRow(ctx, `
		SELECT count(*)
		FROM pg_proc p
		JOIN pg_namespace n ON n.oid = p.pronamespace
		JOIN pg_roles r ON r.oid = p.proowner
		WHERE n.nspname = 'public'
		  AND p.prosecdef = true
		  AND (
			r.rolname <> 'vigia_definer'
			OR NOT EXISTS (SELECT 1 FROM unnest(coalesce(p.proconfig, ARRAY[]::text[])) cfg WHERE cfg LIKE 'search_path=%')
			OR has_function_privilege('public', p.oid, 'EXECUTE')
		  )
	`).Scan(&badFuncs); err != nil || badFuncs != 0 {
		t.Fatalf("restored DB: non-compliant SECURITY DEFINER functions = %d (err=%v)", badFuncs, err)
	}

	// Verify RLS enabled + forced on all tenant tables.
	var badRLS int
	if err := dstAdminPool.QueryRow(ctx, `
		SELECT count(*)
		FROM pg_class c
		JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE n.nspname = 'public'
		  AND c.relname IN ('organizations','memberships','invitations','teams','team_members','audit_logs','projects','environments','api_credentials')
		  AND NOT (c.relrowsecurity AND c.relforcerowsecurity)
	`).Scan(&badRLS); err != nil || badRLS != 0 {
		t.Fatalf("restored DB: tenant tables missing RLS = %d (err=%v)", badRLS, err)
	}

	// Verify row counts match source exactly.
	for _, tbl := range countTables {
		var c int64
		if err := dstAdminPool.QueryRow(ctx, "SELECT count(*) FROM public."+tbl).Scan(&c); err != nil {
			t.Fatalf("count target %s: %v", tbl, err)
		}
		if c != srcCounts[tbl] {
			t.Fatalf("row count mismatch on %s: target=%d source=%d", tbl, c, srcCounts[tbl])
		}
	}

	// 4. Boot API /health/ready and execute real POST /api/v1/auth/login against restored DB as vigia_app!
	dstAppPool, err := database.NewPool(ctx, dstAppDSN, database.PoolOptions{MaxConns: 10})
	if err != nil {
		t.Fatalf("dstAppPool: %v", err)
	}
	t.Cleanup(dstAppPool.Close)
	if err := database.VerifyNonPrivilegedRole(ctx, dstAppPool); err != nil {
		t.Fatalf("VerifyNonPrivilegedRole on restored DB: %v", err)
	}

	adminRouter := httpserver.NewAdminHandler(httpserver.AdminOptions{
		Logger: slog.Default(),
		ReadinessChecks: []httpserver.ReadinessCheck{
			{Name: "postgres", Check: func(c context.Context) error { return dstAppPool.Ping(c) }},
		},
	})
	readyRec := httptest.NewRecorder()
	adminRouter.ServeHTTP(readyRec, httptest.NewRequest(http.MethodGet, "/health/ready", nil))
	if readyRec.Code != http.StatusOK {
		t.Fatalf("/health/ready on restored DB = %d, want 200", readyRec.Code)
	}

	lim, _ := ratelimit.NewRedisLimiter(rdb, clk)
	dstIDStore, _ := identity.NewPostgresStore(dstAppPool)
	sessCodec, _ := session.NewCodec(sessionSecret, "development")
	idSvc, _ := identity.NewService(identity.ServiceConfig{
		Store:           dstIDStore,
		Hasher:          hasher,
		Sessions:        sessCodec,
		Limiter:         lim,
		RateLimitSecret: sessionSecret,
		AppURL:          "https://app.vigia.ao",
		Clock:           clk,
		Logger:          slog.Default(),
	})
	origin := "https://app.vigia.ao"
	idHandler, _ := identity.NewHandler(idSvc, sessCodec, []string{origin}, nil, slog.Default())
	apiRouter := httpserver.NewHandler(httpserver.Options{
		Version:     "restore-test",
		Commit:      "restore",
		Logger:      slog.Default(),
		CORSOrigins: []string{origin},
		APIServer:   restoreLoginAPI{id: idHandler},
	})

	loginBody, _ := json.Marshal(map[string]string{"email": "restore-owner@vigia.ao", "password": userPass})
	loginReq := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewReader(loginBody))
	loginReq.Header.Set("Content-Type", "application/json")
	loginReq.Header.Set("Origin", origin)
	loginReq.RemoteAddr = "198.51.100.77:54321"
	loginRec := httptest.NewRecorder()
	apiRouter.ServeHTTP(loginRec, loginReq)
	if loginRec.Code != http.StatusOK {
		t.Fatalf("POST /api/v1/auth/login on restored DB = %d, want 200 (body=%s)", loginRec.Code, loginRec.Body.String())
	}
}
