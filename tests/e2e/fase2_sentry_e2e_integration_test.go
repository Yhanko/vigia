//go:build integration

package e2e_test

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/getsentry/sentry-go"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"github.com/riverqueue/river"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/Yhanko/vigia/internal/modules/credentials"
	"github.com/Yhanko/vigia/internal/modules/ingestion"
	"github.com/Yhanko/vigia/internal/modules/organizations"
	"github.com/Yhanko/vigia/internal/modules/projects"
	"github.com/Yhanko/vigia/internal/modules/quotas"
	"github.com/Yhanko/vigia/internal/platform/clock"
	"github.com/Yhanko/vigia/internal/platform/database"
	"github.com/Yhanko/vigia/internal/platform/httpserver"
	"github.com/Yhanko/vigia/internal/platform/jobs"
	"github.com/Yhanko/vigia/internal/platform/ratelimit"
	"github.com/Yhanko/vigia/migrations"
)

type recordingEventWorker struct {
	river.WorkerDefaults[ingestion.ProcessErrorEventArgs]
	mu     sync.Mutex
	events []ingestion.ProcessErrorEventArgs
	notify chan struct{}
}

func (w *recordingEventWorker) Work(_ context.Context, job *river.Job[ingestion.ProcessErrorEventArgs]) error {
	w.mu.Lock()
	w.events = append(w.events, job.Args)
	w.mu.Unlock()
	select {
	case w.notify <- struct{}{}:
	default:
	}
	return nil
}

func (w *recordingEventWorker) snapshot() []ingestion.ProcessErrorEventArgs {
	w.mu.Lock()
	defer w.mu.Unlock()
	out := make([]ingestion.ProcessErrorEventArgs, len(w.events))
	copy(out, w.events)
	return out
}

func (w *recordingEventWorker) waitForCount(t *testing.T, want int, timeout time.Duration) []ingestion.ProcessErrorEventArgs {
	t.Helper()
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	for {
		snap := w.snapshot()
		if len(snap) >= want {
			return snap
		}
		select {
		case <-w.notify:
		case <-deadline.C:
			t.Fatalf("timed out waiting for %d processed River events; got %d", want, len(snap))
		}
	}
}

// TestFase2SentrySDKEndToEnd exercises the full Fase 2 ingestion pipeline over
// real TimescaleDB 2.32.1 + PostgreSQL 18 (vigia_app + RLS), Redis 8.12.0,
// HTTP server, and River worker using the official Sentry Go SDK (v0.50.0) and
// browser-SDK CORS/query-auth wire flows (TASKS 2.0-2.2, ADR-004, ADR-009, ADR-017).
func TestFase2SentrySDKEndToEnd(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	adminPass := randomHex(t, 16)
	appPass := randomHex(t, 16)
	pepper := []byte(randomHex(t, 32))

	pgCtr, err := testcontainers.Run(ctx, timescaleImage,
		testcontainers.WithEnv(map[string]string{
			"POSTGRES_USER":     "vigia_admin",
			"POSTGRES_PASSWORD": adminPass,
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
	t.Cleanup(func() { _ = testcontainers.TerminateContainer(pgCtr) })

	pgHost, _ := pgCtr.Host(ctx)
	pgPort, _ := pgCtr.MappedPort(ctx, "5432/tcp")
	adminDSN := fmt.Sprintf("postgres://vigia_admin:%s@%s:%s/vigia?sslmode=disable", adminPass, pgHost, pgPort.Port())
	if err := database.EnsureRoles(ctx, adminDSN, appPass); err != nil {
		t.Fatalf("EnsureRoles: %v", err)
	}
	if err := database.Migrate(ctx, adminDSN, migrations.FS, "up"); err != nil {
		t.Fatalf("Migrate up: %v", err)
	}

	adminPool, err := database.NewPool(ctx, adminDSN, database.PoolOptions{MaxConns: 4, StatementTimeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("admin pool: %v", err)
	}
	t.Cleanup(adminPool.Close)

	appDSN := fmt.Sprintf("postgres://vigia_app:%s@%s:%s/vigia?sslmode=disable", appPass, pgHost, pgPort.Port())
	pool, err := database.NewPool(ctx, appDSN, database.PoolOptions{MaxConns: 16, StatementTimeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("app pool: %v", err)
	}
	t.Cleanup(pool.Close)

	redisCtr, err := testcontainers.Run(ctx, redisImage,
		testcontainers.WithExposedPorts("6379/tcp"),
		testcontainers.WithWaitStrategy(wait.ForLog("Ready to accept connections").WithStartupTimeout(30*time.Second)),
	)
	if err != nil {
		t.Fatalf("start redis: %v", err)
	}
	t.Cleanup(func() { _ = testcontainers.TerminateContainer(redisCtr) })

	rHost, _ := redisCtr.Host(ctx)
	rPort, _ := redisCtr.MappedPort(ctx, "6379/tcp")
	rdb := redis.NewClient(&redis.Options{Addr: rHost + ":" + rPort.Port()})
	t.Cleanup(func() { _ = rdb.Close() })

	// Seed a tiny test plan (max_events_per_day = 3) so we can verify real 429 quota enforcement.
	_, err = adminPool.Exec(ctx, `
		INSERT INTO plans (
			id, name, max_events_per_month, max_events_per_day,
			rate_limit_org_per_min, rate_limit_key_per_min, max_whatsapp_per_month,
			max_projects, max_members, max_alert_rules_per_project,
			max_notification_targets, max_artifact_bytes, event_retention_days
		) VALUES ('e2e_tiny', 'E2E Tiny', 10, 3, 1000, 600, 10, 10, 15, 50, 50, 1048576, 30)
	`)
	if err != nil {
		t.Fatalf("seed e2e_tiny plan: %v", err)
	}

	// Seed user + org + owner membership.
	userID := uuid.New()
	orgID := uuid.New()
	_, err = adminPool.Exec(ctx, `
		INSERT INTO users (id, email, name, password_hash, status, email_verified_at)
		VALUES ($1, 'e2e-owner@vigia.ao', 'E2E Owner', 'hash', 'active', now())
	`, userID)
	if err != nil {
		t.Fatalf("seed user: %v", err)
	}
	_, err = adminPool.Exec(ctx, `
		INSERT INTO organizations (id, name, slug, status, plan)
		VALUES ($1, 'E2E Org', 'e2e-org', 'active', 'e2e_tiny')
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

	clk := clock.System{}
	tid, _ := database.ParseTenantID(orgID.String())
	actor := organizations.Actor{UserID: userID.String(), Email: "e2e-owner@vigia.ao", MFAEnabled: true, LastAuthAt: clk.Now()}

	credSvc, err := credentials.NewService(credentials.ServiceConfig{
		Pool:       pool,
		Cache:      credentials.NewRedisCache(rdb),
		Pepper:     pepper,
		IngestHost: "127.0.0.1",
		Clock:      clk,
	})
	if err != nil {
		t.Fatalf("credentials.NewService: %v", err)
	}
	t.Cleanup(func() { credSvc.Close(context.Background()) })

	projSvc, err := projects.NewService(projects.ServiceConfig{
		Pool:                  pool,
		CredentialInvalidator: credSvc,
		Clock:                 clk,
	})
	if err != nil {
		t.Fatalf("projects.NewService: %v", err)
	}

	proj, err := projSvc.CreateProject(ctx, tid, actor, "Payments API", "payments-api", "go")
	if err != nil {
		t.Fatalf("CreateProject: %v", err)
	}
	dsnCred, err := credSvc.Create(ctx, tid, actor, credentials.CreateInput{
		ProjectID:      proj.ID,
		Kind:           credentials.KindDSN,
		Name:           "SDK DSN",
		AllowedOrigins: []string{"https://checkout.vigia.ao"},
	})
	if err != nil {
		t.Fatalf("Create DSN: %v", err)
	}

	limiter, err := ratelimit.NewRedisLimiter(rdb, clk)
	if err != nil {
		t.Fatalf("NewRedisLimiter: %v", err)
	}
	quotaSvc, err := quotas.NewService(quotas.ServiceConfig{
		Pool:  pool,
		Redis: rdb,
		Clock: clk,
	})
	if err != nil {
		t.Fatalf("quotas.NewService: %v", err)
	}

	// Start real River worker consuming jobs.QueueIngest.
	recWorker := &recordingEventWorker{notify: make(chan struct{}, 32)}
	workers := river.NewWorkers()
	river.AddWorker(workers, recWorker)
	workerClient, err := jobs.NewClient(jobs.ClientOptions{
		Pool:    pool,
		Role:    jobs.RoleWorker,
		Workers: workers,
	})
	if err != nil {
		t.Fatalf("jobs.NewClient worker: %v", err)
	}
	if err := workerClient.Start(ctx); err != nil {
		t.Fatalf("workerClient.Start: %v", err)
	}
	t.Cleanup(func() {
		stopCtx, stopCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer stopCancel()
		_ = workerClient.Stop(stopCtx)
	})

	insertClient, err := jobs.NewClient(jobs.ClientOptions{
		Pool: pool,
		Role: jobs.RoleInsertOnly,
	})
	if err != nil {
		t.Fatalf("jobs.NewClient insert-only: %v", err)
	}

	ingestHandler, err := ingestion.NewHandler(ingestion.HandlerOptions{
		DSNAuth:              credSvc,
		Quotas:               quotaSvc,
		Limiter:              limiter,
		Redis:                rdb,
		Enqueuer:             ingestion.RiverEnqueuer{Client: insertClient},
		Backpressure:         jobs.NewBackpressureChecker(pool, jobs.QueueIngest),
		AdvertiseUnsupported: true,
		Clock:                clk,
	})
	if err != nil {
		t.Fatalf("ingestion.NewHandler: %v", err)
	}

	httpHandler := httpserver.NewHandler(httpserver.Options{
		CORSOrigins:    []string{"https://app.vigia.ao"},
		MaxBodyBytes:   1 << 20,
		MountIngestion: ingestHandler.Mount,
	})
	ts := httptest.NewServer(httpHandler)
	t.Cleanup(ts.Close)

	hostPort := strings.TrimPrefix(ts.URL, "http://")
	sentryDSN := fmt.Sprintf("http://%s@%s/%d", dsnCred.PublicKey, hostPort, proj.PublicID)

	// 1. Official Sentry Go SDK (v0.50.0): real CaptureException with SendDefaultPII=true.
	client, err := sentry.NewClient(sentry.ClientOptions{
		Dsn:              sentryDSN,
		Environment:      "staging",
		Release:          "payments-api@2.0.0",
		EnableTracing:    true,
		TracesSampleRate: 1.0,
	})
	if err != nil {
		t.Fatalf("sentry.NewClient: %v", err)
	}
	hub := sentry.NewHub(client, sentry.NewScope())
	hub.Scope().SetContext("debug", sentry.Context{"password": "super-secret-password-123"})
	hub.Scope().SetTag("service", "payments")

	// Send a real transaction FIRST (before SDK receives X-Sentry-Rate-Limits for unsupported categories):
	// Vigia must accept (200), drop it without enqueuing, and advertise unsupported categories.
	txSpan := sentry.StartTransaction(sentry.SetHubOnContext(ctx, hub), "GET /checkout")
	txSpan.Finish()
	if !client.Flush(5 * time.Second) {
		t.Fatal("sentry-go client.Flush (transaction) timed out")
	}
	if ingestHandler.Metrics().DroppedCount("transaction") < 1 {
		t.Fatalf("expected transaction dropped count >= 1, got %d", ingestHandler.Metrics().DroppedCount("transaction"))
	}

	// Now capture a real error: SDK must still send errors even after unsupported categories were rate-limited!
	hub.CaptureException(errors.New("database connection timeout on checkout"))
	if !client.Flush(5 * time.Second) {
		t.Fatal("sentry-go client.Flush (error) timed out")
	}

	// Wait for the River worker to deliver event #1.
	events := recWorker.waitForCount(t, 1, 10*time.Second)
	ev1 := events[0]
	if ev1.OrganizationID != orgID.String() || ev1.ProjectID != proj.ID {
		t.Fatalf("tenant/project mismatch: got org=%s proj=%s", ev1.OrganizationID, ev1.ProjectID)
	}
	if ev1.Environment != "staging" {
		t.Fatalf("expected environment=staging, got %q", ev1.Environment)
	}
	payloadStr := string(ev1.Payload)
	if !strings.Contains(payloadStr, "payments-api@2.0.0") || !strings.Contains(payloadStr, "database connection timeout") {
		t.Fatalf("expected release and error message in payload: %s", payloadStr)
	}
	if strings.Contains(payloadStr, "super-secret-password-123") {
		t.Fatalf("PII secret leaked into enqueued payload despite redaction: %s", payloadStr)
	}

	// 2. Browser-SDK wire flow: ?sentry_key= + Origin CORS + gzip + resend dedup.
	dupEventID := "11112222333344445555666677778888"
	browserEnv := fmt.Sprintf("{\"event_id\":\"%s\"}\n{\"type\":\"event\"}\n{\"event_id\":\"%s\",\"message\":\"TypeError: Cannot read property 'id' of undefined\",\"release\":\"web@2.0.0\"}\n", dupEventID, dupEventID)
	var gzBuf bytes.Buffer
	gz := gzip.NewWriter(&gzBuf)
	_, _ = gz.Write([]byte(browserEnv))
	_ = gz.Close()

	httpClient := &http.Client{Timeout: 5 * time.Second}
	sendBrowser := func() *http.Response {
		req, _ := http.NewRequestWithContext(ctx, http.MethodPost,
			fmt.Sprintf("%s/api/%d/envelope/?sentry_key=%s&sentry_version=7", ts.URL, proj.PublicID, dsnCred.PublicKey),
			bytes.NewReader(gzBuf.Bytes()),
		)
		req.Header.Set("Origin", "https://checkout.vigia.ao")
		req.Header.Set("Content-Encoding", "gzip")
		resp, err := httpClient.Do(req)
		if err != nil {
			t.Fatalf("browser envelope POST: %v", err)
		}
		return resp
	}

	resp1 := sendBrowser()
	defer resp1.Body.Close()
	if resp1.StatusCode != http.StatusOK {
		t.Fatalf("browser event #1: status=%d", resp1.StatusCode)
	}
	if resp1.Header.Get("Access-Control-Allow-Origin") != "https://checkout.vigia.ao" {
		t.Fatalf("expected ACAO=https://checkout.vigia.ao, got %q", resp1.Header.Get("Access-Control-Allow-Origin"))
	}
	if !strings.Contains(resp1.Header.Get("Access-Control-Expose-Headers"), "X-Sentry-Rate-Limits") {
		t.Fatalf("expected Access-Control-Expose-Headers to include X-Sentry-Rate-Limits")
	}

	// Resend same event_id -> 200 OK, deduplicated in Redis (does NOT consume quota or enqueue).
	resp2 := sendBrowser()
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("browser duplicate event: status=%d", resp2.StatusCode)
	}
	if ingestHandler.Metrics().EventsDeduped.Load() < 1 {
		t.Fatalf("expected duplicate event_id to be deduplicated")
	}

	// Event #3 (fills daily quota of 3 on e2e_tiny plan).
	hub.CaptureMessage("third unique event filling daily quota")
	client.Flush(5 * time.Second)
	recWorker.waitForCount(t, 3, 10*time.Second)

	// 3. Event #4 exceeds daily quota -> MUST return 429 with Retry-After and X-Sentry-Rate-Limits.
	overQuotaEnv := "{\"event_id\":\"99998888777766665555444433332222\"}\n{\"type\":\"event\"}\n{\"message\":\"over quota\"}\n"
	req4, _ := http.NewRequestWithContext(ctx, http.MethodPost,
		fmt.Sprintf("%s/api/%d/envelope/", ts.URL, proj.PublicID),
		strings.NewReader(overQuotaEnv),
	)
	req4.Header.Set("X-Sentry-Auth", "Sentry sentry_version=7, sentry_key="+dsnCred.PublicKey)
	resp4, err := httpClient.Do(req4)
	if err != nil {
		t.Fatalf("over-quota POST: %v", err)
	}
	defer resp4.Body.Close()
	if resp4.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("expected 429 on over-quota event, got %d", resp4.StatusCode)
	}
	rlHdr := resp4.Header.Get("X-Sentry-Rate-Limits")
	if !strings.Contains(rlHdr, ":error;default:organization:quota_exceeded") || resp4.Header.Get("Retry-After") == "" {
		t.Fatalf("unexpected 429 headers: X-Sentry-Rate-Limits=%q Retry-After=%q", rlHdr, resp4.Header.Get("Retry-After"))
	}
	var errBody map[string]string
	_ = json.NewDecoder(resp4.Body).Decode(&errBody)
	if errBody["detail"] == "" {
		t.Fatalf("expected Sentry-format {\"detail\": ...} error body")
	}
}
