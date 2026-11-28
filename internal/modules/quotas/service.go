// Package quotas implements plan limits, atomic Redis event quota enforcement
// with fail-closed semantics, periodic persistence to usage_aggregates, counter
// reconstruction after Redis restart, and one-time 80%/100% threshold alerts
// (TASKS 2.0, ADR-009).
package quotas

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"github.com/riverqueue/river"

	"github.com/Yhanko/vigia/internal/modules/organizations"
	"github.com/Yhanko/vigia/internal/platform/clock"
	"github.com/Yhanko/vigia/internal/platform/database"
	"github.com/Yhanko/vigia/internal/platform/database/sqlcgen"
	"github.com/Yhanko/vigia/internal/platform/jobs"
)

const (
	dayKeyTTLSeconds   = 48 * 3600      // 48h (ADR-009 §3.3)
	monthKeyTTLSeconds = 35 * 24 * 3600 // 35d (ADR-009 §3.3)
	dirtyOrgsRedisKey  = "quota:dirty"
	planCacheTTL       = 60 * time.Second
)

// consumeEventsScript atomically verifies both daily and monthly event quotas
// before incrementing either counter (ADR-009 §3.3).
// Returns {allowed (1|0), exceededWindow (0=none, 1=day, 2=month), dayUsed, monthUsed}.
var consumeEventsScript = redis.NewScript(`
local dayUsed = tonumber(redis.call('GET', KEYS[1]) or '0')
local monthUsed = tonumber(redis.call('GET', KEYS[2]) or '0')
local count = tonumber(ARGV[1])
local dayLimit = tonumber(ARGV[2])
local monthLimit = tonumber(ARGV[3])

if monthUsed + count > monthLimit then
  return {0, 2, dayUsed, monthUsed}
end
if dayUsed + count > dayLimit then
  return {0, 1, dayUsed, monthUsed}
end

local newDay = redis.call('INCRBY', KEYS[1], count)
if redis.call('TTL', KEYS[1]) < 0 then
  redis.call('EXPIRE', KEYS[1], tonumber(ARGV[4]))
end

local newMonth = redis.call('INCRBY', KEYS[2], count)
if redis.call('TTL', KEYS[2]) < 0 then
  redis.call('EXPIRE', KEYS[2], tonumber(ARGV[5]))
end

redis.call('SADD', KEYS[3], ARGV[6])
return {1, 0, newDay, newMonth}
`)

// refundEventsScript best-effort decrements daily and monthly counters without
// ever dropping below 0 (CTO #41).
var refundEventsScript = redis.NewScript(`
local count = tonumber(ARGV[1])
for i = 1, 2 do
  local cur = tonumber(redis.call('GET', KEYS[i]) or '0')
  if cur > 0 then
    local nextVal = cur - count
    if nextVal < 0 then
      nextVal = 0
    end
    redis.call('SET', KEYS[i], nextVal, 'KEEPTTL')
  end
end
return 1
`)

// Mailer sends threshold warning emails to organization owners and admins.
type Mailer interface {
	Send(ctx context.Context, to, subject, textBody string) error
}

// Authorizer checks RBAC permissions inside WithTenantTx.
type Authorizer interface {
	Authorize(ctx context.Context, tenantID database.TenantID, actor organizations.Actor, perm organizations.Permission) (string, error)
}

// EventCountReconstructor optionally counts events from issue_event_ids when
// reconstructing missing Redis counters (ADR-009 §3.3).
type EventCountReconstructor func(ctx context.Context, tx pgx.Tx, orgUUID pgtype.UUID, since time.Time) (int64, error)

// Plan represents an organization's plan limits from the plans table.
type Plan struct {
	ID                      string
	Name                    string
	MaxEventsPerMonth       int64
	MaxEventsPerDay         int64
	RateLimitOrgPerMin      int32
	RateLimitKeyPerMin      int32
	MaxWhatsAppPerMonth     int32
	MaxProjects             int32
	MaxMembers              int32
	MaxAlertRulesPerProject int32
	MaxNotificationTargets  int32
	MaxArtifactBytes        int64
	EventRetentionDays      int32
}

// UsageSnapshot summarizes current UTC day/month usage and resource counts.
type UsageSnapshot struct {
	PlanID                  string
	DayStart                string
	MonthStart              string
	EventsUsedToday         int64
	EventsLimitDay          int64
	EventsUsedMonth         int64
	EventsLimitMonth        int64
	WhatsAppUsedMonth       int64
	WhatsAppLimitMonth      int32
	ActiveProjects          int32
	MaxProjects             int32
	ActiveMembersAndInvites int32
	MaxMembers              int32
}

// QuotaDecision is returned by ConsumeEvents.
type QuotaDecision struct {
	Allowed    bool
	Window     string // "" | "day" | "month"
	RetryAfter time.Duration
	DayUsed    int64
	DayLimit   int64
	MonthUsed  int64
	MonthLimit int64
}

type cachedPlan struct {
	plan      Plan
	expiresAt time.Time
}

// Service manages plan limits, event quota counters, periodic persistence,
// and hard resource limits (projects, members).
type Service struct {
	pool          *pgxpool.Pool
	q             *sqlcgen.Queries
	rdb           *redis.Client
	mailer        Mailer
	authz         Authorizer
	reconstructor EventCountReconstructor
	clk           clock.Clock
	logger        *slog.Logger

	planMu    sync.RWMutex
	planCache map[string]cachedPlan
}

// ServiceConfig holds explicit dependencies for the quotas Service.
type ServiceConfig struct {
	Pool          *pgxpool.Pool
	Redis         *redis.Client
	Mailer        Mailer
	Authorizer    Authorizer
	Reconstructor EventCountReconstructor
	Clock         clock.Clock
	Logger        *slog.Logger
}

// NewService constructs a quotas Service.
func NewService(cfg ServiceConfig) (*Service, error) {
	if cfg.Pool == nil {
		return nil, errors.New("quotas: pgx pool is required")
	}
	clk := cfg.Clock
	if clk == nil {
		clk = clock.System{}
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	return &Service{
		pool:          cfg.Pool,
		q:             sqlcgen.New(cfg.Pool),
		rdb:           cfg.Redis,
		mailer:        cfg.Mailer,
		authz:         cfg.Authorizer,
		reconstructor: cfg.Reconstructor,
		clk:           clk,
		logger:        logger,
		planCache:     make(map[string]cachedPlan),
	}, nil
}

// GetPlan returns the active plan for tenantID (cached up to 60s).
func (s *Service) GetPlan(ctx context.Context, tenantID database.TenantID) (Plan, error) {
	now := s.clk.Now().UTC()
	key := tenantID.String()

	s.planMu.RLock()
	if cp, ok := s.planCache[key]; ok && now.Before(cp.expiresAt) {
		s.planMu.RUnlock()
		return cp.plan, nil
	}
	s.planMu.RUnlock()

	orgUUID, err := parseUUID(key)
	if err != nil {
		return Plan{}, ErrInvalidInput
	}

	var plan Plan
	err = database.WithTenantTx(ctx, s.pool, tenantID, func(tx pgx.Tx) error {
		row, qErr := s.q.WithTx(tx).GetOrganizationPlan(ctx, orgUUID)
		if qErr != nil {
			if errors.Is(qErr, pgx.ErrNoRows) {
				return ErrNotFound
			}
			return qErr
		}
		plan = mapPlan(row)
		return nil
	})
	if err != nil {
		return Plan{}, err
	}

	s.planMu.Lock()
	s.planCache[key] = cachedPlan{plan: plan, expiresAt: now.Add(planCacheTTL)}
	s.planMu.Unlock()
	return plan, nil
}

// InvalidatePlanCache evicts the cached plan for an organization.
func (s *Service) InvalidatePlanCache(orgID string) {
	s.planMu.Lock()
	delete(s.planCache, orgID)
	s.planMu.Unlock()
}

// ConsumeEvents atomically checks and increments the daily and monthly UTC
// event quotas in Redis. Fails closed (ErrServiceUnavailable) if Redis is down.
func (s *Service) ConsumeEvents(ctx context.Context, tenantID database.TenantID, count int64) (QuotaDecision, error) {
	if count <= 0 {
		return QuotaDecision{Allowed: true}, nil
	}
	if s.rdb == nil {
		return QuotaDecision{}, ErrServiceUnavailable
	}

	plan, err := s.GetPlan(ctx, tenantID)
	if err != nil {
		return QuotaDecision{}, err
	}

	now := s.clk.Now().UTC()
	orgID := tenantID.String()
	dayKey := eventDayKey(orgID, now)
	monthKey := eventMonthKey(orgID, now)

	// Reconstruct missing Redis keys from usage_aggregates (+ issue_event_ids)
	// before executing the atomic Lua script (ADR-009 §3.3).
	existsCount, err := s.rdb.Exists(ctx, dayKey, monthKey).Result()
	if err != nil {
		s.logger.Warn("redis unavailable during quota check (fail-closed)", "error", err)
		return QuotaDecision{}, ErrServiceUnavailable
	}
	if existsCount < 2 {
		if rErr := s.reconstructEventCounters(ctx, tenantID, now, dayKey, monthKey); rErr != nil {
			if errors.Is(rErr, ErrServiceUnavailable) {
				return QuotaDecision{}, ErrServiceUnavailable
			}
			s.logger.Warn("quota counter reconstruction failed", "org_id", orgID, "error", rErr)
		}
	}

	raw, err := consumeEventsScript.Run(ctx, s.rdb,
		[]string{dayKey, monthKey, dirtyOrgsRedisKey},
		count,
		plan.MaxEventsPerDay,
		plan.MaxEventsPerMonth,
		dayKeyTTLSeconds,
		monthKeyTTLSeconds,
		orgID,
	).Slice()
	if err != nil {
		s.logger.Warn("redis unavailable during atomic quota increment (fail-closed)", "error", err)
		return QuotaDecision{}, ErrServiceUnavailable
	}
	if len(raw) != 4 {
		return QuotaDecision{}, ErrServiceUnavailable
	}

	allowed := toInt64(raw[0]) == 1
	exceededWin := toInt64(raw[1])
	dayUsed := toInt64(raw[2])
	monthUsed := toInt64(raw[3])

	dec := QuotaDecision{
		Allowed:    allowed,
		DayUsed:    dayUsed,
		DayLimit:   plan.MaxEventsPerDay,
		MonthUsed:  monthUsed,
		MonthLimit: plan.MaxEventsPerMonth,
	}

	monthStart := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)

	if !allowed {
		if exceededWin == 2 {
			dec.Window = "month"
			dec.RetryAfter = retryAfterDuration(now, nextUTCMonth(now))
			s.maybeNotifyThreshold(ctx, tenantID, "events", monthStart, 100, monthUsed, plan.MaxEventsPerMonth)
		} else {
			dec.Window = "day"
			dec.RetryAfter = retryAfterDuration(now, nextUTCDay(now))
		}
		return dec, nil
	}

	// Emit one-time 80% and 100% monthly threshold warnings (ADR-009 §3.3).
	if plan.MaxEventsPerMonth > 0 {
		if monthUsed >= plan.MaxEventsPerMonth {
			s.maybeNotifyThreshold(ctx, tenantID, "events", monthStart, 100, monthUsed, plan.MaxEventsPerMonth)
		} else if monthUsed*100 >= plan.MaxEventsPerMonth*80 {
			s.maybeNotifyThreshold(ctx, tenantID, "events", monthStart, 80, monthUsed, plan.MaxEventsPerMonth)
		}
	}

	return dec, nil
}

// RefundEvents best-effort returns consumed event quota units when enqueue fails
// after ConsumeEvents succeeded (CTO #41).
func (s *Service) RefundEvents(ctx context.Context, tenantID database.TenantID, count int64) {
	if count <= 0 || s.rdb == nil {
		return
	}
	now := s.clk.Now().UTC()
	orgID := tenantID.String()
	dayKey := eventDayKey(orgID, now)
	monthKey := eventMonthKey(orgID, now)
	if err := refundEventsScript.Run(ctx, s.rdb, []string{dayKey, monthKey}, count).Err(); err != nil {
		s.logger.Warn("failed to refund event quota (best effort)", "org_id", orgID, "error", err)
	}
}

// CheckProjectLimitTx enforces the plan's hard max_projects limit inside an
// active WithTenantTx transaction (ADR-009 §3.1).
func (s *Service) CheckProjectLimitTx(ctx context.Context, tx pgx.Tx, orgUUID pgtype.UUID) error {
	qtx := s.q.WithTx(tx)
	plan, err := qtx.GetOrganizationPlan(ctx, orgUUID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		return err
	}
	active, err := qtx.CountActiveProjectsByOrg(ctx, orgUUID)
	if err != nil {
		return err
	}
	if active >= plan.MaxProjects {
		return ErrQuotaExceeded
	}
	return nil
}

// CheckMemberLimitTx enforces the plan's hard max_members limit (active members
// plus unexpired pending invitations) inside an active WithTenantTx (ADR-009 §3.1).
func (s *Service) CheckMemberLimitTx(ctx context.Context, tx pgx.Tx, orgUUID pgtype.UUID) error {
	qtx := s.q.WithTx(tx)
	plan, err := qtx.GetOrganizationPlan(ctx, orgUUID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		return err
	}
	now := s.clk.Now().UTC()
	total, err := qtx.CountMembersAndPendingInvitesByOrg(ctx, sqlcgen.CountMembersAndPendingInvitesByOrgParams{
		OrganizationID: orgUUID,
		ExpiresAt:      pgtype.Timestamptz{Time: now, Valid: true},
	})
	if err != nil {
		return err
	}
	if total >= plan.MaxMembers {
		return ErrQuotaExceeded
	}
	return nil
}

// GetQuotas returns the organization's plan limits after RBAC authorization.
func (s *Service) GetQuotas(ctx context.Context, tenantID database.TenantID, actor organizations.Actor) (Plan, error) {
	if err := s.authorize(ctx, tenantID, actor, organizations.PermOrgRead); err != nil {
		return Plan{}, err
	}
	return s.GetPlan(ctx, tenantID)
}

// GetUsage returns the organization's current UTC day/month usage and resource counts.
func (s *Service) GetUsage(ctx context.Context, tenantID database.TenantID, actor organizations.Actor) (UsageSnapshot, error) {
	if err := s.authorize(ctx, tenantID, actor, organizations.PermOrgRead); err != nil {
		return UsageSnapshot{}, err
	}
	plan, err := s.GetPlan(ctx, tenantID)
	if err != nil {
		return UsageSnapshot{}, err
	}

	now := s.clk.Now().UTC()
	dayStart := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	monthStart := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
	orgID := tenantID.String()
	orgUUID, err := parseUUID(orgID)
	if err != nil {
		return UsageSnapshot{}, ErrInvalidInput
	}

	var (
		dbDayUsed      int64
		dbMonthUsed    int64
		dbWAMonthUsed  int64
		activeProjects int32
		totalMembers   int32
	)
	err = database.WithTenantTx(ctx, s.pool, tenantID, func(tx pgx.Tx) error {
		qtx := s.q.WithTx(tx)
		if v, qErr := qtx.GetUsageAggregate(ctx, sqlcgen.GetUsageAggregateParams{
			OrganizationID: orgUUID,
			Resource:       "events",
			PeriodKind:     "day",
			PeriodStart:    pgDate(dayStart),
		}); qErr == nil {
			dbDayUsed = v
		} else if !errors.Is(qErr, pgx.ErrNoRows) {
			return qErr
		}
		if v, qErr := qtx.GetUsageAggregate(ctx, sqlcgen.GetUsageAggregateParams{
			OrganizationID: orgUUID,
			Resource:       "events",
			PeriodKind:     "month",
			PeriodStart:    pgDate(monthStart),
		}); qErr == nil {
			dbMonthUsed = v
		} else if !errors.Is(qErr, pgx.ErrNoRows) {
			return qErr
		}
		if v, qErr := qtx.GetUsageAggregate(ctx, sqlcgen.GetUsageAggregateParams{
			OrganizationID: orgUUID,
			Resource:       "whatsapp",
			PeriodKind:     "month",
			PeriodStart:    pgDate(monthStart),
		}); qErr == nil {
			dbWAMonthUsed = v
		} else if !errors.Is(qErr, pgx.ErrNoRows) {
			return qErr
		}
		var qErr error
		activeProjects, qErr = qtx.CountActiveProjectsByOrg(ctx, orgUUID)
		if qErr != nil {
			return qErr
		}
		totalMembers, qErr = qtx.CountMembersAndPendingInvitesByOrg(ctx, sqlcgen.CountMembersAndPendingInvitesByOrgParams{
			OrganizationID: orgUUID,
			ExpiresAt:      pgtype.Timestamptz{Time: now, Valid: true},
		})
		return qErr
	})
	if err != nil {
		return UsageSnapshot{}, err
	}

	// Merge live Redis counters with persisted usage_aggregates (taking max).
	dayUsed := dbDayUsed
	monthUsed := dbMonthUsed
	waMonthUsed := dbWAMonthUsed
	if s.rdb != nil {
		if v, rErr := s.rdb.Get(ctx, eventDayKey(orgID, now)).Int64(); rErr == nil && v > dayUsed {
			dayUsed = v
		}
		if v, rErr := s.rdb.Get(ctx, eventMonthKey(orgID, now)).Int64(); rErr == nil && v > monthUsed {
			monthUsed = v
		}
		if v, rErr := s.rdb.Get(ctx, whatsappMonthKey(orgID, now)).Int64(); rErr == nil && v > waMonthUsed {
			waMonthUsed = v
		}
	}

	return UsageSnapshot{
		PlanID:                  plan.ID,
		DayStart:                dayStart.Format("2006-01-02"),
		MonthStart:              monthStart.Format("2006-01"),
		EventsUsedToday:         dayUsed,
		EventsLimitDay:          plan.MaxEventsPerDay,
		EventsUsedMonth:         monthUsed,
		EventsLimitMonth:        plan.MaxEventsPerMonth,
		WhatsAppUsedMonth:       waMonthUsed,
		WhatsAppLimitMonth:      plan.MaxWhatsAppPerMonth,
		ActiveProjects:          activeProjects,
		MaxProjects:             plan.MaxProjects,
		ActiveMembersAndInvites: totalMembers,
		MaxMembers:              plan.MaxMembers,
	}, nil
}

// FlushDirtyUsage persists all dirty organization Redis counters into PostgreSQL
// usage_aggregates using GREATEST so execution is idempotent (ADR-009 §3.3).
func (s *Service) FlushDirtyUsage(ctx context.Context) (int, error) {
	if s.rdb == nil {
		return 0, nil
	}
	orgIDs, err := s.rdb.SMembers(ctx, dirtyOrgsRedisKey).Result()
	if err != nil {
		return 0, fmt.Errorf("read dirty quota orgs: %w", err)
	}
	if len(orgIDs) == 0 {
		return 0, nil
	}

	now := s.clk.Now().UTC()
	dayStart := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	monthStart := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)

	flushed := 0
	for _, orgID := range orgIDs {
		tid, parseErr := database.ParseTenantID(orgID)
		if parseErr != nil {
			_ = s.rdb.SRem(ctx, dirtyOrgsRedisKey, orgID).Err()
			continue
		}
		orgUUID, _ := parseUUID(orgID)

		dayVal, dayErr := s.rdb.Get(ctx, eventDayKey(orgID, now)).Int64()
		monthVal, monthErr := s.rdb.Get(ctx, eventMonthKey(orgID, now)).Int64()

		txErr := database.WithTenantTx(ctx, s.pool, tid, func(tx pgx.Tx) error {
			qtx := s.q.WithTx(tx)
			if dayErr == nil && dayVal > 0 {
				if err := qtx.UpsertUsageAggregate(ctx, sqlcgen.UpsertUsageAggregateParams{
					OrganizationID: orgUUID,
					Resource:       "events",
					PeriodKind:     "day",
					PeriodStart:    pgDate(dayStart),
					Used:           dayVal,
					UpdatedAt:      pgtype.Timestamptz{Time: now, Valid: true},
				}); err != nil {
					return err
				}
			}
			if monthErr == nil && monthVal > 0 {
				if err := qtx.UpsertUsageAggregate(ctx, sqlcgen.UpsertUsageAggregateParams{
					OrganizationID: orgUUID,
					Resource:       "events",
					PeriodKind:     "month",
					PeriodStart:    pgDate(monthStart),
					Used:           monthVal,
					UpdatedAt:      pgtype.Timestamptz{Time: now, Valid: true},
				}); err != nil {
					return err
				}
			}
			return nil
		})
		if txErr != nil {
			s.logger.Warn("failed to flush usage aggregate", "org_id", orgID, "error", txErr)
			continue
		}
		_ = s.rdb.SRem(ctx, dirtyOrgsRedisKey, orgID).Err()
		flushed++
	}
	return flushed, nil
}

func (s *Service) reconstructEventCounters(ctx context.Context, tenantID database.TenantID, now time.Time, dayKey, monthKey string) error {
	dayStart := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	monthStart := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
	orgUUID, err := parseUUID(tenantID.String())
	if err != nil {
		return err
	}

	var dayBase, monthBase int64
	err = database.WithTenantTx(ctx, s.pool, tenantID, func(tx pgx.Tx) error {
		qtx := s.q.WithTx(tx)
		if v, qErr := qtx.GetUsageAggregate(ctx, sqlcgen.GetUsageAggregateParams{
			OrganizationID: orgUUID,
			Resource:       "events",
			PeriodKind:     "day",
			PeriodStart:    pgDate(dayStart),
		}); qErr == nil {
			dayBase = v
		} else if !errors.Is(qErr, pgx.ErrNoRows) {
			return qErr
		}
		if v, qErr := qtx.GetUsageAggregate(ctx, sqlcgen.GetUsageAggregateParams{
			OrganizationID: orgUUID,
			Resource:       "events",
			PeriodKind:     "month",
			PeriodStart:    pgDate(monthStart),
		}); qErr == nil {
			monthBase = v
		} else if !errors.Is(qErr, pgx.ErrNoRows) {
			return qErr
		}
		if s.reconstructor != nil {
			if cnt, rErr := s.reconstructor(ctx, tx, orgUUID, dayStart); rErr == nil && cnt > dayBase {
				dayBase = cnt
			}
			if cnt, rErr := s.reconstructor(ctx, tx, orgUUID, monthStart); rErr == nil && cnt > monthBase {
				monthBase = cnt
			}
		}
		return nil
	})
	if err != nil {
		return err
	}

	if err := s.rdb.SetNX(ctx, dayKey, dayBase, time.Duration(dayKeyTTLSeconds)*time.Second).Err(); err != nil {
		return ErrServiceUnavailable
	}
	if err := s.rdb.SetNX(ctx, monthKey, monthBase, time.Duration(monthKeyTTLSeconds)*time.Second).Err(); err != nil {
		return ErrServiceUnavailable
	}
	return nil
}

func (s *Service) maybeNotifyThreshold(ctx context.Context, tenantID database.TenantID, resource string, monthStart time.Time, thresholdPct int32, used, limit int64) {
	orgUUID, err := parseUUID(tenantID.String())
	if err != nil {
		return
	}
	now := s.clk.Now().UTC()
	var recipients []string
	var shouldSend bool

	err = database.WithTenantTx(ctx, s.pool, tenantID, func(tx pgx.Tx) error {
		qtx := s.q.WithTx(tx)
		_, rErr := qtx.RecordQuotaNotification(ctx, sqlcgen.RecordQuotaNotificationParams{
			OrganizationID: orgUUID,
			Resource:       resource,
			PeriodStart:    pgDate(monthStart),
			ThresholdPct:   thresholdPct,
			NotifiedAt:     pgtype.Timestamptz{Time: now, Valid: true},
		})
		if errors.Is(rErr, pgx.ErrNoRows) {
			// Already notified for this (org, resource, month, threshold).
			return nil
		}
		if rErr != nil {
			return rErr
		}
		shouldSend = true
		recipients, rErr = qtx.ListOrgOwnerAndAdminEmails(ctx, orgUUID)
		return rErr
	})
	if err != nil || !shouldSend || s.mailer == nil {
		return
	}

	subject := fmt.Sprintf("[Vigia] %d%% of monthly %s quota reached (%s)", thresholdPct, resource, monthStart.Format("2006-01"))
	body := fmt.Sprintf(
		"Your Vigia organization has reached %d%% of its monthly %s quota (%d / %d) for %s.\n",
		thresholdPct, resource, used, limit, monthStart.Format("2006-01"),
	)
	for _, email := range recipients {
		if mErr := s.mailer.Send(ctx, email, subject, body); mErr != nil {
			s.logger.Warn("failed to send quota threshold email", "threshold_pct", thresholdPct, "error", mErr)
		}
	}
}

func (s *Service) authorize(ctx context.Context, tenantID database.TenantID, actor organizations.Actor, perm organizations.Permission) error {
	if s.authz == nil {
		return ErrForbidden
	}
	_, err := s.authz.Authorize(ctx, tenantID, actor, perm)
	if err == nil {
		return nil
	}
	switch {
	case errors.Is(err, organizations.ErrNotFound):
		return ErrNotFound
	case errors.Is(err, organizations.ErrMFASetupRequired):
		return ErrMFARequired
	case errors.Is(err, organizations.ErrForbidden):
		return ErrForbidden
	default:
		return err
	}
}

// FlushUsageArgs is the River job argument for periodic usage_aggregates flushing.
type FlushUsageArgs struct{}

// Kind implements river.JobArgs.
func (FlushUsageArgs) Kind() string { return "quotas.flush_usage" }

// InsertOpts pins the periodic flush job to the maintenance queue (ADR-004, ADR-009).
func (FlushUsageArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{
		Queue:       jobs.QueueMaintenance,
		MaxAttempts: 3,
	}
}

// FlushUsageWorker flushes dirty Redis quota counters into usage_aggregates.
type FlushUsageWorker struct {
	river.WorkerDefaults[FlushUsageArgs]
	svc *Service
}

// NewFlushUsageWorker constructs a River worker for periodic usage flushing.
func NewFlushUsageWorker(svc *Service) *FlushUsageWorker {
	return &FlushUsageWorker{svc: svc}
}

// Work executes an idempotent flush of dirty Redis counters to PostgreSQL.
func (w *FlushUsageWorker) Work(ctx context.Context, _ *river.Job[FlushUsageArgs]) error {
	_, err := w.svc.FlushDirtyUsage(ctx)
	return err
}

func eventDayKey(orgID string, now time.Time) string {
	return "quota:" + orgID + ":events:" + now.UTC().Format("2006-01-02")
}

func eventMonthKey(orgID string, now time.Time) string {
	return "quota:" + orgID + ":events:" + now.UTC().Format("2006-01")
}

func whatsappMonthKey(orgID string, now time.Time) string {
	return "quota:" + orgID + ":whatsapp:" + now.UTC().Format("2006-01")
}

func nextUTCDay(now time.Time) time.Time {
	u := now.UTC()
	return time.Date(u.Year(), u.Month(), u.Day()+1, 0, 0, 0, 0, time.UTC)
}

func nextUTCMonth(now time.Time) time.Time {
	u := now.UTC()
	return time.Date(u.Year(), u.Month()+1, 1, 0, 0, 0, 0, time.UTC)
}

func retryAfterDuration(now, until time.Time) time.Duration {
	d := until.Sub(now)
	if d < time.Second {
		return time.Second
	}
	return d.Truncate(time.Second)
}

func pgDate(t time.Time) pgtype.Date {
	return pgtype.Date{Time: t.UTC(), Valid: true}
}

func parseUUID(s string) (pgtype.UUID, error) {
	var u pgtype.UUID
	if err := u.Scan(s); err != nil {
		return pgtype.UUID{}, err
	}
	return u, nil
}

func mapPlan(r sqlcgen.GetOrganizationPlanRow) Plan {
	return Plan{
		ID:                      r.ID,
		Name:                    r.Name,
		MaxEventsPerMonth:       r.MaxEventsPerMonth,
		MaxEventsPerDay:         r.MaxEventsPerDay,
		RateLimitOrgPerMin:      r.RateLimitOrgPerMin,
		RateLimitKeyPerMin:      r.RateLimitKeyPerMin,
		MaxWhatsAppPerMonth:     r.MaxWhatsappPerMonth,
		MaxProjects:             r.MaxProjects,
		MaxMembers:              r.MaxMembers,
		MaxAlertRulesPerProject: r.MaxAlertRulesPerProject,
		MaxNotificationTargets:  r.MaxNotificationTargets,
		MaxArtifactBytes:        r.MaxArtifactBytes,
		EventRetentionDays:      r.EventRetentionDays,
	}
}

func toInt64(v any) int64 {
	switch x := v.(type) {
	case int64:
		return x
	case int:
		return int64(x)
	case string:
		n, _ := strconv.ParseInt(x, 10, 64)
		return n
	default:
		return 0
	}
}
