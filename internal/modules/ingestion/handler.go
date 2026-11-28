package ingestion

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"
	"github.com/redis/go-redis/v9"
	"github.com/riverqueue/river"

	"github.com/Yhanko/vigia/internal/modules/credentials"
	"github.com/Yhanko/vigia/internal/modules/quotas"
	"github.com/Yhanko/vigia/internal/platform/clock"
	"github.com/Yhanko/vigia/internal/platform/database"
	"github.com/Yhanko/vigia/internal/platform/jobs"
	"github.com/Yhanko/vigia/internal/platform/ratelimit"
	"github.com/Yhanko/vigia/internal/platform/redaction"
)

const (
	dedupTTL                 = 24 * time.Hour // ADR-003 §3.4 / ADR-009 §3.5
	unsupportedCategoriesHdr = "3600:transaction;span;session;replay;profile;profile_chunk;attachment;monitor;log_item;metric_bucket;feedback:project:unsupported"
	defaultRateLimitOrgMin   = 1000
	defaultRateLimitKeyMin   = 600
)

// DSNAuthenticator resolves a Sentry public DSN key for a project public_id.
type DSNAuthenticator interface {
	AuthenticateDSN(ctx context.Context, publicKey string, expectedProjectPublicID int64) (credentials.AuthenticatedDSN, error)
}

// QuotaConsumer checks and increments event quotas for an organization.
type QuotaConsumer interface {
	GetPlan(ctx context.Context, tenantID database.TenantID) (quotas.Plan, error)
	ConsumeEvents(ctx context.Context, tenantID database.TenantID, count int64) (quotas.QuotaDecision, error)
}

// EventEnqueuer persists a ProcessErrorEventArgs job into River.
type EventEnqueuer interface {
	EnqueueErrorEvent(ctx context.Context, args ProcessErrorEventArgs) error
}

// BackpressureChecker reports whether the ingest queue is overloaded (ADR-004 §3.5).
type BackpressureChecker interface {
	IsOverloaded(ctx context.Context) (bool, jobs.QueueStats, error)
}

// RiverEnqueuer adapts a *river.Client[pgx.Tx] to EventEnqueuer.
type RiverEnqueuer struct {
	Client *river.Client[pgx.Tx]
}

// EnqueueErrorEvent inserts the ProcessErrorEventArgs job into River.
func (e RiverEnqueuer) EnqueueErrorEvent(ctx context.Context, args ProcessErrorEventArgs) error {
	_, err := e.Client.Insert(ctx, args, nil)
	return err
}

// Metrics tracks ingestion operational counters (including sentry_items_dropped_total{type}).
type Metrics struct {
	EventsAccepted atomic.Int64
	EventsDeduped  atomic.Int64
	EventsFiltered atomic.Int64
	droppedByType  sync.Map // map[string]*atomic.Int64
}

// IncDropped increments sentry_items_dropped_total{type=<itemType>}.
func (m *Metrics) IncDropped(itemType string, n int64) {
	if m == nil || n <= 0 {
		return
	}
	v, _ := m.droppedByType.LoadOrStore(itemType, &atomic.Int64{})
	v.(*atomic.Int64).Add(n)
}

// DroppedCount returns the dropped count for a specific Sentry item type.
func (m *Metrics) DroppedCount(itemType string) int64 {
	if m == nil {
		return 0
	}
	v, ok := m.droppedByType.Load(itemType)
	if !ok {
		return 0
	}
	return v.(*atomic.Int64).Load()
}

// HandlerOptions configures the Sentry-compatible ingestion HTTP handler.
type HandlerOptions struct {
	DSNAuth              DSNAuthenticator
	Quotas               QuotaConsumer
	Limiter              ratelimit.Limiter
	Redis                *redis.Client
	Enqueuer             EventEnqueuer
	Backpressure         BackpressureChecker
	AdvertiseUnsupported bool
	Clock                clock.Clock
	Logger               *slog.Logger
	Metrics              *Metrics
}

// Handler implements POST/OPTIONS /api/{project_id}/envelope/ and /store/ (ADR-017).
type Handler struct {
	dsnAuth              DSNAuthenticator
	quotas               QuotaConsumer
	limiter              ratelimit.Limiter
	rdb                  *redis.Client
	enqueuer             EventEnqueuer
	backpressure         BackpressureChecker
	advertiseUnsupported bool
	clk                  clock.Clock
	logger               *slog.Logger
	metrics              *Metrics
}

// NewHandler constructs a Sentry-compatible ingestion Handler.
func NewHandler(opts HandlerOptions) (*Handler, error) {
	if opts.DSNAuth == nil {
		return nil, errors.New("ingestion: DSNAuthenticator is required")
	}
	if opts.Enqueuer == nil {
		return nil, errors.New("ingestion: EventEnqueuer is required")
	}
	clk := opts.Clock
	if clk == nil {
		clk = clock.System{}
	}
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}
	metrics := opts.Metrics
	if metrics == nil {
		metrics = &Metrics{}
	}
	return &Handler{
		dsnAuth:              opts.DSNAuth,
		quotas:               opts.Quotas,
		limiter:              opts.Limiter,
		rdb:                  opts.Redis,
		enqueuer:             opts.Enqueuer,
		backpressure:         opts.Backpressure,
		advertiseUnsupported: opts.AdvertiseUnsupported,
		clk:                  clk,
		logger:               logger,
		metrics:              metrics,
	}, nil
}

// Metrics returns the handler's ingestion metrics.
func (h *Handler) Metrics() *Metrics { return h.metrics }

// Mount registers Sentry ingestion routes OUTSIDE /api/v1 (ADR-017 §3.1):
//   - POST/OPTIONS /api/{project_id}/envelope/ and /api/{project_id}/envelope
//   - POST/OPTIONS /api/{project_id}/store/    and /api/{project_id}/store
func (h *Handler) Mount(r chi.Router) {
	r.Post("/api/{project_id}/envelope/", h.handleEnvelope)
	r.Post("/api/{project_id}/envelope", h.handleEnvelope)
	r.Options("/api/{project_id}/envelope/", h.handlePreflight)
	r.Options("/api/{project_id}/envelope", h.handlePreflight)

	r.Post("/api/{project_id}/store/", h.handleStore)
	r.Post("/api/{project_id}/store", h.handleStore)
	r.Options("/api/{project_id}/store/", h.handlePreflight)
	r.Options("/api/{project_id}/store", h.handlePreflight)
}

func (h *Handler) handlePreflight(w http.ResponseWriter, r *http.Request) {
	origin := strings.TrimSpace(r.Header.Get("Origin"))
	if origin != "" {
		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.Header().Add("Vary", "Origin")
	} else {
		w.Header().Set("Access-Control-Allow-Origin", "*")
	}
	w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Content-Encoding, X-Sentry-Auth, Authorization, sentry-trace, baggage")
	w.Header().Set("Access-Control-Expose-Headers", "X-Sentry-Rate-Limits, Retry-After")
	w.Header().Set("Access-Control-Max-Age", "3600")
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) handleEnvelope(w http.ResponseWriter, r *http.Request) {
	projectPublicID, ok := parseProjectPublicID(w, r)
	if !ok {
		return
	}

	// Step 1: Extract auth from headers / query string (steps 1-3 of ADR-017 §3.2).
	authParams, authErr := ExtractAuthFromRequest(r)
	if errors.Is(authErr, ErrInvalidVersion) {
		writeSentryError(w, http.StatusBadRequest, "unsupported sentry_version")
		return
	}
	if errors.Is(authErr, ErrInvalidAuth) {
		writeSentryError(w, http.StatusUnauthorized, "invalid sentry authentication")
		return
	}

	// If auth is already present (steps 1-3), authenticate & check CORS/limits BEFORE reading body!
	var dsn credentials.AuthenticatedDSN
	authenticated := false
	if authErr == nil {
		var ok bool
		dsn, ok = h.authenticateAndCheckCORS(w, r, authParams.PublicKey, projectPublicID)
		if !ok {
			return
		}
		authenticated = true
	}

	// Stream-decompress body enforcing 1 MiB compressed / 10 MiB decompressed limits.
	decReader, err := DecompressReader(r.Body, r.Header.Get("Content-Encoding"), MaxCompressedBodyBytes, MaxDecompressedBodyBytes)
	if err != nil {
		h.writeDecompressError(w, err)
		return
	}
	defer decReader.Close()

	env, err := ParseEnvelope(decReader)
	if err != nil {
		h.writeParseError(w, err)
		return
	}

	// Step 4 fallback: DSN inside envelope header (tunnels, ADR-017 §3.2).
	if !authenticated {
		dsnAuth, dErr := ExtractAuthFromDSN(env.Header.DSN)
		if dErr != nil {
			writeSentryError(w, http.StatusUnauthorized, "missing sentry authentication")
			return
		}
		authParams = dsnAuth
		var ok bool
		dsn, ok = h.authenticateAndCheckCORS(w, r, authParams.PublicKey, projectPublicID)
		if !ok {
			return
		}
	}

	// Record dropped non-event items (ADR-017 §3.5).
	for itemType, count := range env.DroppedItems {
		h.metrics.IncDropped(itemType, int64(count))
	}

	if authParams.ClientSDK == "" && env.Header.SDK != nil && env.Header.SDK.Name != "" {
		sdkStr := env.Header.SDK.Name
		if env.Header.SDK.Version != "" {
			sdkStr += "/" + env.Header.SDK.Version
		}
		authParams.ClientSDK = truncateString(sdkStr, maxClientSDKLen)
	}

	// If envelope contained no `event` items (e.g., only transaction/session), return 200 immediately (ADR-017 §3.5).
	if len(env.Events) == 0 {
		respID := NormalizeEventID(env.Header.EventID)
		if respID == "" {
			respID = generateEventID()
		}
		h.writeSuccess(w, respID)
		return
	}

	h.processEvents(w, r, dsn, authParams, env.Header.EventID, env.Events)
}

func (h *Handler) handleStore(w http.ResponseWriter, r *http.Request) {
	projectPublicID, ok := parseProjectPublicID(w, r)
	if !ok {
		return
	}

	authParams, authErr := ExtractAuthFromRequest(r)
	if errors.Is(authErr, ErrInvalidVersion) {
		writeSentryError(w, http.StatusBadRequest, "unsupported sentry_version")
		return
	}
	if authErr != nil {
		writeSentryError(w, http.StatusUnauthorized, "missing or invalid sentry authentication")
		return
	}

	dsn, ok := h.authenticateAndCheckCORS(w, r, authParams.PublicKey, projectPublicID)
	if !ok {
		return
	}

	decReader, err := DecompressReader(r.Body, r.Header.Get("Content-Encoding"), MaxCompressedBodyBytes, MaxEventItemBytes)
	if err != nil {
		h.writeDecompressError(w, err)
		return
	}
	defer decReader.Close()

	raw, err := io.ReadAll(decReader)
	if err != nil {
		h.writeDecompressError(w, err)
		return
	}
	trimmed := bytes.TrimSpace(raw)
	// Legacy base64+zlib format is explicitly unsupported (ADR-017 §3.4).
	if len(trimmed) == 0 || trimmed[0] != '{' {
		writeSentryError(w, http.StatusBadRequest, "expected JSON event body")
		return
	}

	h.processEvents(w, r, dsn, authParams, "", [][]byte{trimmed})
}

func (h *Handler) processEvents(
	w http.ResponseWriter,
	r *http.Request,
	dsn credentials.AuthenticatedDSN,
	authParams AuthParams,
	envelopeEventID string,
	rawEvents [][]byte,
) {
	ctx := r.Context()
	tid, err := database.ParseTenantID(dsn.OrganizationID)
	if err != nil {
		writeSentryError(w, http.StatusInternalServerError, "internal error")
		return
	}

	// 1. Queue backpressure check (ADR-004 §3.5, ADR-017 §3.6).
	if h.backpressure != nil {
		overloaded, _, bpErr := h.backpressure.IsOverloaded(ctx)
		if bpErr != nil {
			h.logger.Warn("backpressure check failed", "error", bpErr)
		} else if overloaded {
			writeSentryRateLimit(w, 60, "", "organization", "backpressure")
			return
		}
	}

	// 2. Per-minute rate limits (1000/min org, 600/min key from plan; ADR-009 §3.1, ADR-017 §3.6).
	orgRPM := defaultRateLimitOrgMin
	keyRPM := defaultRateLimitKeyMin
	if h.quotas != nil {
		if plan, pErr := h.quotas.GetPlan(ctx, tid); pErr == nil {
			if plan.RateLimitOrgPerMin > 0 {
				orgRPM = int(plan.RateLimitOrgPerMin)
			}
			if plan.RateLimitKeyPerMin > 0 {
				keyRPM = int(plan.RateLimitKeyPerMin)
			}
		}
	}
	if h.limiter != nil {
		resKey, rErr := h.limiter.Allow(ctx, "ingest:key:"+dsn.ID, keyRPM, time.Minute)
		if rErr != nil {
			w.Header().Set("Retry-After", "30")
			writeSentryError(w, http.StatusServiceUnavailable, "rate limit backend unavailable")
			return
		}
		if !resKey.Allowed {
			sec := maxInt(1, int(resKey.RetryAfter.Seconds()))
			writeSentryRateLimit(w, sec, "error;default", "key", "rate_limited")
			return
		}
		resOrg, rErr := h.limiter.Allow(ctx, "ingest:org:"+dsn.OrganizationID, orgRPM, time.Minute)
		if rErr != nil {
			w.Header().Set("Retry-After", "30")
			writeSentryError(w, http.StatusServiceUnavailable, "rate limit backend unavailable")
			return
		}
		if !resOrg.Allowed {
			sec := maxInt(1, int(resOrg.RetryAfter.Seconds()))
			writeSentryRateLimit(w, sec, "error;default", "organization", "rate_limited")
			return
		}
	}

	now := h.clk.Now().UTC()
	privacy := redaction.Options{
		AllowRequestBody: dsn.AllowRequestBody,
		AllowUserIP:      dsn.AllowUserIP,
	}
	httpUA := r.UserAgent()
	var lastEventID string

	for _, rawEvent := range rawEvents {
		norm, filtered, nErr := NormalizeEvent(rawEvent, now, envelopeEventID, "", privacy, dsn.InboundFilters, httpUA)
		if nErr != nil {
			if errors.Is(nErr, ErrJSONTooDeep) || errors.Is(nErr, ErrInvalidEventJSON) {
				writeSentryError(w, http.StatusBadRequest, "invalid event payload")
				return
			}
			writeSentryError(w, http.StatusBadRequest, "invalid event payload")
			return
		}
		if filtered {
			h.metrics.EventsFiltered.Add(1)
			continue
		}
		lastEventID = norm.EventID

		// 3. Fast Redis deduplication (ADR-003 §3.4, ADR-009 §3.2 — duplicates do NOT count toward quota).
		if h.rdb != nil {
			dedupKey := "dedup:" + dsn.ProjectID + ":" + norm.EventID
			set, dErr := h.rdb.SetNX(ctx, dedupKey, "1", dedupTTL).Result()
			if dErr != nil {
				w.Header().Set("Retry-After", "30")
				writeSentryError(w, http.StatusServiceUnavailable, "deduplication backend unavailable")
				return
			}
			if !set {
				h.metrics.EventsDeduped.Add(1)
				continue
			}
		}

		// 4. Atomic quota check + increment (ADR-009 §3.2-3.3 — fail-closed 503 if Redis down).
		if h.quotas != nil {
			dec, qErr := h.quotas.ConsumeEvents(ctx, tid, 1)
			if qErr != nil {
				if errors.Is(qErr, quotas.ErrServiceUnavailable) {
					w.Header().Set("Retry-After", "30")
					writeSentryError(w, http.StatusServiceUnavailable, "quota service unavailable")
					return
				}
				h.logger.Error("quota consumption failed", "org_id", dsn.OrganizationID, "error", qErr)
				writeSentryError(w, http.StatusInternalServerError, "internal error")
				return
			}
			if !dec.Allowed {
				sec := maxInt(1, int(dec.RetryAfter.Seconds()))
				writeSentryRateLimit(w, sec, "error;default", "organization", "quota_exceeded")
				return
			}
		}

		// 5. Durable enqueue in River (ADR-004).
		jobArgs := ProcessErrorEventArgs{
			OrganizationID: dsn.OrganizationID,
			ProjectID:      dsn.ProjectID,
			Environment:    norm.Environment,
			EventID:        norm.EventID,
			ReceivedAt:     now,
			ClientSDK:      authParams.ClientSDK,
			Payload:        norm.Payload,
		}
		if err := h.enqueuer.EnqueueErrorEvent(ctx, jobArgs); err != nil {
			h.logger.Error("failed to enqueue error event", "org_id", dsn.OrganizationID, "project_id", dsn.ProjectID, "error", err)
			w.Header().Set("Retry-After", "5")
			writeSentryError(w, http.StatusServiceUnavailable, "queue temporarily unavailable")
			return
		}
		h.metrics.EventsAccepted.Add(1)
	}

	if lastEventID == "" {
		lastEventID = NormalizeEventID(envelopeEventID)
		if lastEventID == "" {
			lastEventID = generateEventID()
		}
	}
	h.writeSuccess(w, lastEventID)
}

func (h *Handler) authenticateAndCheckCORS(w http.ResponseWriter, r *http.Request, publicKey string, projectPublicID int64) (credentials.AuthenticatedDSN, bool) {
	if len(publicKey) != credentials.DSNKeyLength {
		writeSentryError(w, http.StatusUnauthorized, "invalid dsn key")
		return credentials.AuthenticatedDSN{}, false
	}
	dsn, err := h.dsnAuth.AuthenticateDSN(r.Context(), publicKey, projectPublicID)
	if err != nil {
		// Distinguish malformed (already 401 above) vs revoked/wrong project -> 403 per ADR-017 §3.1.
		writeSentryError(w, http.StatusForbidden, "invalid, revoked, or mismatched dsn key")
		return credentials.AuthenticatedDSN{}, false
	}

	// CORS enforcement (ADR-017 §3.3).
	origin := strings.TrimSpace(r.Header.Get("Origin"))
	if origin != "" {
		if len(dsn.AllowedOrigins) > 0 {
			if !originAllowed(origin, dsn.AllowedOrigins) {
				writeSentryError(w, http.StatusForbidden, "origin not allowed")
				return credentials.AuthenticatedDSN{}, false
			}
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Add("Vary", "Origin")
		} else {
			w.Header().Set("Access-Control-Allow-Origin", "*")
		}
		w.Header().Set("Access-Control-Expose-Headers", "X-Sentry-Rate-Limits, Retry-After")
	}

	return dsn, true
}

func (h *Handler) writeSuccess(w http.ResponseWriter, eventID string) {
	if h.advertiseUnsupported {
		w.Header().Set("X-Sentry-Rate-Limits", unsupportedCategoriesHdr)
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]string{"id": eventID})
}

func (h *Handler) writeDecompressError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrPayloadTooLarge):
		writeSentryError(w, http.StatusRequestEntityTooLarge, "payload too large")
	case errors.Is(err, ErrUnsupportedEncoding):
		writeSentryError(w, http.StatusUnsupportedMediaType, "unsupported content-encoding")
	default:
		writeSentryError(w, http.StatusBadRequest, "malformed compressed body")
	}
}

func (h *Handler) writeParseError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrPayloadTooLarge):
		writeSentryError(w, http.StatusRequestEntityTooLarge, "payload too large")
	default:
		writeSentryError(w, http.StatusBadRequest, "malformed sentry envelope")
	}
}

func parseProjectPublicID(w http.ResponseWriter, r *http.Request) (int64, bool) {
	raw := strings.TrimSpace(chi.URLParam(r, "project_id"))
	id, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || id <= 0 {
		writeSentryError(w, http.StatusBadRequest, "invalid project id")
		return 0, false
	}
	return id, true
}

func writeSentryError(w http.ResponseWriter, status int, detail string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"detail": detail})
}

func writeSentryRateLimit(w http.ResponseWriter, retryAfterSeconds int, categories, scope, reason string) {
	w.Header().Set("Retry-After", strconv.Itoa(retryAfterSeconds))
	w.Header().Set("X-Sentry-Rate-Limits", fmt.Sprintf("%d:%s:%s:%s", retryAfterSeconds, categories, scope, reason))
	writeSentryError(w, http.StatusTooManyRequests, reason)
}

func originAllowed(origin string, allowed []string) bool {
	for _, a := range allowed {
		a = strings.TrimSpace(a)
		if a == "*" || strings.EqualFold(a, origin) {
			return true
		}
	}
	return false
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
