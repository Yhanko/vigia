//go:build benchmark

package jobs_test

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net/url"
	"os"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/riverqueue/river"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/Yhanko/vigia/internal/platform/database"
	"github.com/Yhanko/vigia/internal/platform/jobs"
	"github.com/Yhanko/vigia/migrations"
)

type benchJobArgs struct {
	OrganizationID string `json:"organization_id"`
	Payload        string `json:"payload"`
}

func (benchJobArgs) Kind() string { return "bench_ingest_8k" }

type benchWorker struct {
	river.WorkerDefaults[benchJobArgs]
	processed *atomic.Int64
}

func (w *benchWorker) Work(_ context.Context, _ *river.Job[benchJobArgs]) error {
	w.processed.Add(1)
	return nil
}

// TestRiverThroughputBenchmark_ADR004 runs the ADR-004 §6 sustained throughput
// benchmark: 250 jobs/s with 8 KiB payloads, measuring InsertTx P95 latency and
// queue drain lag. Set VIGIA_BENCH_DURATION (default 5m) to adjust duration.
func TestRiverThroughputBenchmark_ADR004(t *testing.T) {
	dur := 5 * time.Minute
	if v := os.Getenv("VIGIA_BENCH_DURATION"); v != "" {
		if parsed, err := time.ParseDuration(v); err == nil && parsed > 0 {
			dur = parsed
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), dur+3*time.Minute)
	defer cancel()

	b1, b2 := make([]byte, 16), make([]byte, 16)
	_, _ = io.ReadFull(rand.Reader, b1)
	_, _ = io.ReadFull(rand.Reader, b2)
	adminPass, appPass := hex.EncodeToString(b1), hex.EncodeToString(b2)

	ctr, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image:        "timescale/timescaledb:2.32.1-pg18@sha256:70e6526ad8e31e3f4833f2c5863b50b92d7a6bee4d432ad1f660e2c6dd956d94",
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
	pool, err := database.NewPool(ctx, appDSN, database.PoolOptions{MaxConns: 25})
	if err != nil {
		t.Fatalf("NewPool: %v", err)
	}
	t.Cleanup(pool.Close)

	var processed atomic.Int64
	workers := river.NewWorkers()
	river.AddWorker(workers, &benchWorker{processed: &processed})

	workerClient, err := jobs.NewClient(jobs.ClientOptions{
		Pool:    pool,
		Role:    jobs.RoleWorker,
		Workers: workers,
	})
	if err != nil {
		t.Fatalf("NewClient worker: %v", err)
	}
	if err := workerClient.Start(ctx); err != nil {
		t.Fatalf("worker Start: %v", err)
	}
	t.Cleanup(func() {
		stopCtx, stopCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer stopCancel()
		_ = workerClient.Stop(stopCtx)
	})

	payload8K := make([]byte, 4096) // 8192 hex chars = 8 KiB
	_, _ = io.ReadFull(rand.Reader, payload8K)
	args := benchJobArgs{
		OrganizationID: "11111111-1111-4111-8111-111111111111",
		Payload:        hex.EncodeToString(payload8K),
	}

	const ratePerSec = 250
	const producers = 8
	interval := time.Second / ratePerSec
	deadline := time.Now().Add(dur)

	var (
		latMu     sync.Mutex
		latencies []time.Duration
		inserted  atomic.Int64
		tickCh    = make(chan struct{}, 256)
	)

	var wg sync.WaitGroup
	for range producers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			local := make([]time.Duration, 0, 1024)
			for range tickCh {
				t0 := time.Now()
				err := database.WithTx(ctx, pool, func(tx pgx.Tx) error {
					_, e := workerClient.InsertTx(ctx, tx, args, &river.InsertOpts{
						Queue:       jobs.QueueIngest,
						MaxAttempts: jobs.MaxAttemptsIngest,
					})
					return e
				})
				if err != nil {
					t.Errorf("InsertTx: %v", err)
					return
				}
				local = append(local, time.Since(t0))
				inserted.Add(1)
			}
			latMu.Lock()
			latencies = append(latencies, local...)
			latMu.Unlock()
		}()
	}

	ticker := time.NewTicker(interval)
	for time.Now().Before(deadline) {
		<-ticker.C
		tickCh <- struct{}{}
	}
	ticker.Stop()
	close(tickCh)
	wg.Wait()

	// Wait up to 30s for queue to drain.
	drainStart := time.Now()
	totalInserted := inserted.Load()
	for processed.Load() < totalInserted && time.Since(drainStart) < 30*time.Second {
		time.Sleep(50 * time.Millisecond)
	}
	drainLag := time.Since(drainStart)

	slices.Sort(latencies)
	p50 := latencies[len(latencies)*50/100]
	p95 := latencies[len(latencies)*95/100]
	p99 := latencies[len(latencies)*99/100]

	t.Logf("ADR-004 River benchmark (duration=%v, rate=%d/s, payload=8KiB): inserted=%d processed=%d p50=%v p95=%v p99=%v drain_lag=%v",
		dur, ratePerSec, totalInserted, processed.Load(), p50, p95, p99, drainLag.Round(time.Millisecond))

	if processed.Load() < totalInserted {
		t.Fatalf("queue did not drain within 30s: processed=%d inserted=%d", processed.Load(), totalInserted)
	}
}
