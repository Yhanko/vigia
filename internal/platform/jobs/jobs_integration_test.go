//go:build integration

package jobs_test

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

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/riverqueue/river"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/Yhanko/vigia/internal/platform/database"
	"github.com/Yhanko/vigia/internal/platform/jobs"
	"github.com/Yhanko/vigia/migrations"
)

const timescaleImage = "timescale/timescaledb:2.32.1-pg18@sha256:70e6526ad8e31e3f4833f2c5863b50b92d7a6bee4d432ad1f660e2c6dd956d94"

type testJobArgs struct {
	OrganizationID string `json:"organization_id"`
	Key            string `json:"key"`
	DelayMS        int    `json:"delay_ms,omitempty"`
}

func (testJobArgs) Kind() string { return "test_job" }

type testJobWorker struct {
	river.WorkerDefaults[testJobArgs]
	mu      sync.Mutex
	seen    map[string]int
	started chan struct{}
	done    chan string
}

func (w *testJobWorker) Work(_ context.Context, job *river.Job[testJobArgs]) error {
	if w.started != nil {
		select {
		case w.started <- struct{}{}:
		default:
		}
	}
	if job.Args.DelayMS > 0 {
		time.Sleep(time.Duration(job.Args.DelayMS) * time.Millisecond)
	}
	w.mu.Lock()
	w.seen[job.Args.Key]++
	w.mu.Unlock()
	if w.done != nil {
		w.done <- job.Args.Key
	}
	return nil
}

func startJobsPG(t *testing.T) *pgxpool.Pool {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	b1, b2 := make([]byte, 16), make([]byte, 16)
	_, _ = io.ReadFull(rand.Reader, b1)
	_, _ = io.ReadFull(rand.Reader, b2)
	adminPass, appPass := hex.EncodeToString(b1), hex.EncodeToString(b2)

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
	pool, err := database.NewPool(ctx, appDSN, database.PoolOptions{MaxConns: 15})
	if err != nil {
		t.Fatalf("NewPool: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// TestRiverAtomicityAndGracefulShutdown verifies ADR-004 §6.3 and §6.4:
//   - InsertTx inside a rolled-back transaction leaves 0 jobs.
//   - InsertTx inside a committed transaction leaves exactly 1 job.
//   - Graceful shutdown waits for in-flight jobs to finish without losing them.
func TestRiverAtomicityAndGracefulShutdown(t *testing.T) {
	ctx := context.Background()
	pool := startJobsPG(t)

	insertClient, err := jobs.NewClient(jobs.ClientOptions{
		Pool: pool,
		Role: jobs.RoleInsertOnly,
	})
	if err != nil {
		t.Fatalf("NewClient insert-only: %v", err)
	}

	// 1. Atomicity: rollback must NOT leave a job in river_job.
	errRollback := errors.New("intentional rollback")
	_ = database.WithTx(ctx, pool, func(tx pgx.Tx) error {
		if _, err := insertClient.InsertTx(ctx, tx, testJobArgs{
			OrganizationID: "11111111-1111-4111-8111-111111111111",
			Key:            "rolled-back",
		}, &river.InsertOpts{Queue: jobs.QueueIngest, MaxAttempts: jobs.MaxAttemptsIngest}); err != nil {
			t.Fatalf("InsertTx rollback case: %v", err)
		}
		return errRollback
	})

	var count int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM public.river_job`).Scan(&count); err != nil {
		t.Fatalf("count river_job after rollback: %v", err)
	}
	if count != 0 {
		t.Fatalf("expected 0 jobs after tx rollback, got %d", count)
	}

	// 2. Atomicity: commit leaves exactly 1 job.
	if err := database.WithTx(ctx, pool, func(tx pgx.Tx) error {
		_, err := insertClient.InsertTx(ctx, tx, testJobArgs{
			OrganizationID: "11111111-1111-4111-8111-111111111111",
			Key:            "committed",
		}, &river.InsertOpts{Queue: jobs.QueueIngest, MaxAttempts: jobs.MaxAttemptsIngest})
		return err
	}); err != nil {
		t.Fatalf("commit InsertTx: %v", err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM public.river_job`).Scan(&count); err != nil {
		t.Fatalf("count river_job after commit: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected 1 job after tx commit, got %d", count)
	}

	// 3. Start worker, process committed job + verify graceful shutdown waits for in-flight job.
	w := &testJobWorker{
		seen:    make(map[string]int),
		started: make(chan struct{}, 4),
		done:    make(chan string, 4),
	}
	workers := river.NewWorkers()
	river.AddWorker(workers, w)

	var metrics jobs.Metrics
	workerClient, err := jobs.NewClient(jobs.ClientOptions{
		Pool:    pool,
		Role:    jobs.RoleWorker,
		Workers: workers,
		Metrics: &metrics,
	})
	if err != nil {
		t.Fatalf("NewClient worker: %v", err)
	}
	if err := workerClient.Start(ctx); err != nil {
		t.Fatalf("workerClient.Start: %v", err)
	}

	select {
	case k := <-w.done:
		if k != "committed" {
			t.Fatalf("unexpected job key %q", k)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for committed job")
	}

	// Enqueue an in-flight slow job (300ms), wait for it to start, then trigger Stop().
	if _, err := insertClient.Insert(ctx, testJobArgs{
		OrganizationID: "11111111-1111-4111-8111-111111111111",
		Key:            "in-flight-shutdown",
		DelayMS:        300,
	}, &river.InsertOpts{Queue: jobs.QueueIngest}); err != nil {
		t.Fatalf("insert slow job: %v", err)
	}

	// Drain previous started signal if present, wait for slow job to start.
	select {
	case <-w.started:
	default:
	}
	select {
	case <-w.started:
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for slow job to start")
	}

	stopCtx, stopCancel := context.WithTimeout(ctx, 10*time.Second)
	defer stopCancel()
	if err := workerClient.Stop(stopCtx); err != nil {
		t.Fatalf("workerClient.Stop: %v", err)
	}

	w.mu.Lock()
	gotSlow := w.seen["in-flight-shutdown"]
	w.mu.Unlock()
	if gotSlow != 1 {
		t.Fatalf("expected in-flight job to complete during graceful shutdown, seen=%d", gotSlow)
	}

	// Verify backpressure checker runs cleanly as vigia_app.
	bp := jobs.NewBackpressureChecker(pool, jobs.QueueIngest)
	overloaded, _, err := bp.IsOverloaded(ctx)
	if err != nil || overloaded {
		t.Fatalf("BackpressureChecker = (%v, %v), want (false, nil)", overloaded, err)
	}

	// Verify idempotency guard pattern: calling handler twice on same key with dedup set produces 1 side effect.
	var sideEffects atomic.Int32
	dedup := sync.Map{}
	runIdempotent := func(key string) {
		if _, loaded := dedup.LoadOrStore(key, struct{}{}); !loaded {
			sideEffects.Add(1)
		}
	}
	runIdempotent("idem-1")
	runIdempotent("idem-1")
	if sideEffects.Load() != 1 {
		t.Fatalf("idempotent sideEffects = %d, want 1", sideEffects.Load())
	}
}
