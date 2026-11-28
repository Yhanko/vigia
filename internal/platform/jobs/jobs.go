// Package jobs provides the River durable job queue client, queue policies,
// observability counters, and ingest backpressure checks (ADR-004, TASKS 2.0).
package jobs

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/riverdriver/riverpgxv5"
	"github.com/riverqueue/river/rivertype"
)

// Queue names and initial concurrency/attempt limits from ADR-004 §3.2.
const (
	QueueIngest        = "ingest"
	QueueAlerts        = "alerts"
	QueueNotifications = "notifications"
	QueueMaintenance   = "maintenance"

	ConcurrencyIngest        = 8
	ConcurrencyAlerts        = 4
	ConcurrencyNotifications = 8
	ConcurrencyMaintenance   = 2

	MaxAttemptsIngest        = 5
	MaxAttemptsAlerts        = 5
	MaxAttemptsNotifications = 8
	MaxAttemptsMaintenance   = 3

	// Completed/cancelled/discarded job retention from ADR-004 §3.4.
	RetentionCompleted = 1 * time.Hour
	RetentionCancelled = 24 * time.Hour
	RetentionDiscarded = 7 * 24 * time.Hour

	// Backpressure thresholds from ADR-004 §3.5.
	BackpressureMaxAvailable = 50_000
	BackpressureMaxOldestAge = 5 * time.Minute
	backpressureCacheTTL     = 5 * time.Second
)

// Metrics tracks per-client job lifecycle counters (ADR-004 §3.6).
type Metrics struct {
	Inserted        atomic.Int64
	Completed       atomic.Int64
	Failed          atomic.Int64
	Discarded       atomic.Int64
	TotalDurationNS atomic.Int64
}

// Role selects which queues a River client processes.
type Role string

const (
	RoleInsertOnly Role = "insert_only"
	RoleWorker     Role = "worker"
	RoleDispatcher Role = "dispatcher"
)

// ClientOptions configures a River client for API, worker, or dispatcher processes.
type ClientOptions struct {
	Pool         *pgxpool.Pool
	Role         Role
	Workers      *river.Workers
	PeriodicJobs []*river.PeriodicJob
	Logger       *slog.Logger
	Metrics      *Metrics
}

// NewClient constructs a River client with ADR-004 queue concurrency, retention,
// and structured logging.
func NewClient(opts ClientOptions) (*river.Client[pgx.Tx], error) {
	if opts.Pool == nil {
		return nil, errors.New("jobs: pgx pool is required")
	}
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}

	cfg := &river.Config{
		Logger:                      logger,
		JobCleanerTimeout:           30 * time.Second,
		CompletedJobRetentionPeriod: RetentionCompleted,
		CancelledJobRetentionPeriod: RetentionCancelled,
		DiscardedJobRetentionPeriod: RetentionDiscarded,
		ReindexerSchedule:           nil,
	}

	switch opts.Role {
	case RoleInsertOnly:
		// Insert-only client (API process): no queues or workers.
	case RoleWorker:
		if opts.Workers == nil {
			opts.Workers = river.NewWorkers()
		}
		cfg.Workers = opts.Workers
		cfg.PeriodicJobs = opts.PeriodicJobs
		cfg.Queues = map[string]river.QueueConfig{
			QueueIngest:      {MaxWorkers: ConcurrencyIngest},
			QueueAlerts:      {MaxWorkers: ConcurrencyAlerts},
			QueueMaintenance: {MaxWorkers: ConcurrencyMaintenance},
		}
	case RoleDispatcher:
		if opts.Workers == nil {
			opts.Workers = river.NewWorkers()
		}
		cfg.Workers = opts.Workers
		cfg.Queues = map[string]river.QueueConfig{
			QueueNotifications: {MaxWorkers: ConcurrencyNotifications},
		}
	default:
		return nil, fmt.Errorf("jobs: unsupported role %q", opts.Role)
	}

	client, err := river.NewClient(riverpgxv5.New(opts.Pool), cfg)
	if err != nil {
		return nil, fmt.Errorf("jobs: create river client: %w", err)
	}

	if opts.Metrics != nil && opts.Role != RoleInsertOnly {
		subCh, _ := client.Subscribe(
			river.EventKindJobCompleted,
			river.EventKindJobFailed,
			river.EventKindJobCancelled,
		)
		go observeEvents(subCh, opts.Metrics)
	}

	return client, nil
}

func observeEvents(ch <-chan *river.Event, m *Metrics) {
	for ev := range ch {
		if ev == nil || ev.Job == nil {
			continue
		}
		if ev.Job.AttemptedAt != nil && ev.Job.FinalizedAt != nil {
			if d := ev.Job.FinalizedAt.Sub(*ev.Job.AttemptedAt); d > 0 {
				m.TotalDurationNS.Add(d.Nanoseconds())
			}
		}
		switch ev.Kind {
		case river.EventKindJobCompleted:
			m.Completed.Add(1)
		case river.EventKindJobFailed:
			m.Failed.Add(1)
			if ev.Job.State == rivertype.JobStateDiscarded {
				m.Discarded.Add(1)
			}
		case river.EventKindJobCancelled:
			m.Discarded.Add(1)
		}
	}
}

// QueueStats holds depth and oldest available job age for a River queue.
type QueueStats struct {
	Available int64
	OldestAge time.Duration
}

// BackpressureChecker caches ingest queue depth/age for a few seconds so the
// ingestion hot path does not query PostgreSQL on every request (ADR-004 §3.5).
type BackpressureChecker struct {
	pool      *pgxpool.Pool
	queueName string
	maxAvail  int64
	maxAge    time.Duration
	cacheTTL  time.Duration

	mu        sync.Mutex
	checkedAt time.Time
	stats     QueueStats
}

// NewBackpressureChecker constructs a cached queue backpressure checker.
func NewBackpressureChecker(pool *pgxpool.Pool, queueName string) *BackpressureChecker {
	if queueName == "" {
		queueName = QueueIngest
	}
	return &BackpressureChecker{
		pool:      pool,
		queueName: queueName,
		maxAvail:  BackpressureMaxAvailable,
		maxAge:    BackpressureMaxOldestAge,
		cacheTTL:  backpressureCacheTTL,
	}
}

// IsOverloaded returns true when the queue exceeds ADR-004 §3.5 thresholds.
func (b *BackpressureChecker) IsOverloaded(ctx context.Context) (bool, QueueStats, error) {
	if b == nil || b.pool == nil {
		return false, QueueStats{}, nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()

	now := time.Now()
	if !b.checkedAt.IsZero() && now.Sub(b.checkedAt) < b.cacheTTL {
		return b.overloaded(b.stats), b.stats, nil
	}

	var avail int64
	var oldest *time.Time
	err := b.pool.QueryRow(ctx, `
		SELECT count(*), min(scheduled_at)
		FROM public.river_job
		WHERE queue = $1
		  AND state = 'available'
	`, b.queueName).Scan(&avail, &oldest)
	if err != nil {
		return false, QueueStats{}, fmt.Errorf("jobs: check backpressure: %w", err)
	}

	st := QueueStats{Available: avail}
	if oldest != nil {
		if age := now.Sub(*oldest); age > 0 {
			st.OldestAge = age
		}
	}
	b.stats = st
	b.checkedAt = now
	return b.overloaded(st), st, nil
}

func (b *BackpressureChecker) overloaded(st QueueStats) bool {
	return st.Available > b.maxAvail || st.OldestAge > b.maxAge
}
