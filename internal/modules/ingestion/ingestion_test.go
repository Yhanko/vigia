package ingestion_test

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/andybalholm/brotli"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/klauspost/compress/zstd"

	"github.com/Yhanko/vigia/internal/modules/credentials"
	"github.com/Yhanko/vigia/internal/modules/ingestion"
	"github.com/Yhanko/vigia/internal/modules/quotas"
	"github.com/Yhanko/vigia/internal/platform/clock"
	"github.com/Yhanko/vigia/internal/platform/database"
	"github.com/Yhanko/vigia/internal/platform/jobs"
	"github.com/Yhanko/vigia/internal/platform/ratelimit"
)

type fakeDSNAuth struct {
	mu   sync.RWMutex
	keys map[string]credentials.AuthenticatedDSN
	err  error
}

func (f *fakeDSNAuth) AuthenticateDSN(_ context.Context, publicKey string, expectedProjectPublicID int64) (credentials.AuthenticatedDSN, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	if f.err != nil {
		return credentials.AuthenticatedDSN{}, f.err
	}
	d, ok := f.keys[publicKey]
	if !ok || d.ProjectPublicID != expectedProjectPublicID {
		return credentials.AuthenticatedDSN{}, credentials.ErrInvalidCredential
	}
	return d, nil
}

type fakeEnqueuer struct {
	mu   sync.Mutex
	jobs []ingestion.ProcessErrorEventArgs
	err  error
}

func (f *fakeEnqueuer) EnqueueErrorEvent(_ context.Context, args ingestion.ProcessErrorEventArgs) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return f.err
	}
	f.jobs = append(f.jobs, args)
	return nil
}

func (f *fakeEnqueuer) last() ingestion.ProcessErrorEventArgs {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.jobs[len(f.jobs)-1]
}

func (f *fakeEnqueuer) len() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.jobs)
}

type fakeQuota struct {
	decision quotas.QuotaDecision
	err      error
	refunds  int64
}

func (f *fakeQuota) GetPlan(_ context.Context, _ database.TenantID) (quotas.Plan, error) {
	return quotas.Plan{RateLimitOrgPerMin: 1000, RateLimitKeyPerMin: 600, MaxEventsPerDay: 20000, MaxEventsPerMonth: 100000}, nil
}

func (f *fakeQuota) ConsumeEvents(_ context.Context, _ database.TenantID, _ int64) (quotas.QuotaDecision, error) {
	if f.err != nil {
		return quotas.QuotaDecision{}, f.err
	}
	return f.decision, nil
}

func (f *fakeQuota) RefundEvents(_ context.Context, _ database.TenantID, count int64) {
	f.refunds += count
}

type memDedupStore struct {
	mu   sync.Mutex
	keys map[string]struct{}
}

func newMemDedupStore() *memDedupStore {
	return &memDedupStore{keys: make(map[string]struct{})}
}

func (m *memDedupStore) SetNX(_ context.Context, key string, _ time.Duration) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.keys[key]; exists {
		return false, nil
	}
	m.keys[key] = struct{}{}
	return true, nil
}

func (m *memDedupStore) Del(_ context.Context, key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.keys, key)
	return nil
}

type fakeBackpressure struct {
	overloaded bool
}

func (f *fakeBackpressure) IsOverloaded(_ context.Context) (bool, jobs.QueueStats, error) {
	return f.overloaded, jobs.QueueStats{}, nil
}

type fakeLimiter struct {
	allowed bool
	retry   time.Duration
}

func (f *fakeLimiter) Allow(_ context.Context, _ string, limit int, _ time.Duration) (ratelimit.Result, error) {
	return ratelimit.Result{Allowed: f.allowed, Limit: limit, RetryAfter: f.retry}, nil
}

func (f *fakeLimiter) Peek(_ context.Context, _ string, limit int, _ time.Duration) (ratelimit.Result, error) {
	return ratelimit.Result{Allowed: f.allowed, Limit: limit, RetryAfter: f.retry}, nil
}

func (f *fakeLimiter) Reset(_ context.Context, _ string) error {
	return nil
}

func setupTestRouter(t *testing.T, opts ingestion.HandlerOptions) (chi.Router, *ingestion.Handler) {
	t.Helper()
	h, err := ingestion.NewHandler(opts)
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}
	r := chi.NewRouter()
	h.Mount(r)
	return r, h
}

func makeEnvelope(eventID, dsn string, eventJSON string, extraItems ...string) []byte {
	hdr := map[string]any{}
	if eventID != "" {
		hdr["event_id"] = eventID
	}
	if dsn != "" {
		hdr["dsn"] = dsn
	}
	hdrBytes, _ := json.Marshal(hdr)
	var buf bytes.Buffer
	buf.Write(hdrBytes)
	buf.WriteByte('\n')
	if eventJSON != "" {
		fmt.Fprintf(&buf, `{"type":"event","length":%d}`, len(eventJSON))
		buf.WriteByte('\n')
		buf.WriteString(eventJSON)
		buf.WriteByte('\n')
	}
	for _, it := range extraItems {
		buf.WriteString(it)
	}
	return buf.Bytes()
}

func TestIngestionAuthPrecedenceAndNegativeCases(t *testing.T) {
	pubKey := "0123456789abcdef0123456789abcdef"
	orgID := uuid.NewString()
	projID := uuid.NewString()
	const publicID int64 = 424242

	auth := &fakeDSNAuth{keys: map[string]credentials.AuthenticatedDSN{
		pubKey: {
			ID:              uuid.NewString(),
			OrganizationID:  orgID,
			ProjectID:       projID,
			ProjectPublicID: publicID,
			AllowedOrigins:  []string{"https://allowed.example.ao"},
			InboundFilters:  credentials.InboundFilters{BrowserExtensions: true, Localhost: true, Crawlers: true},
		},
	}}
	enq := &fakeEnqueuer{}
	r, h := setupTestRouter(t, ingestion.HandlerOptions{
		DSNAuth:              auth,
		Quotas:               &fakeQuota{decision: quotas.QuotaDecision{Allowed: true}},
		Enqueuer:             enq,
		AdvertiseUnsupported: true,
		Clock:                clock.NewFake(time.Date(2026, 11, 28, 12, 0, 0, 0, time.UTC)),
	})

	eventBody := `{"message":"boom","level":"error"}`

	// 1. X-Sentry-Auth header works (and trailing slash optional).
	for _, path := range []string{"/api/424242/envelope/", "/api/424242/envelope"} {
		req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(makeEnvelope("", "", eventBody)))
		req.Header.Set("X-Sentry-Auth", "Sentry sentry_version=7, sentry_key="+pubKey+", sentry_secret=ignored, sentry_client=sentry.go/0.27.0")
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("POST %s: got %d body=%s", path, rec.Code, rec.Body.String())
		}
		if !strings.Contains(rec.Header().Get("X-Sentry-Rate-Limits"), "unsupported") {
			t.Fatalf("expected unsupported categories header on 200, got %q", rec.Header().Get("X-Sentry-Rate-Limits"))
		}
	}

	// 2. Authorization: Sentry header works.
	req := httptest.NewRequest(http.MethodPost, "/api/424242/envelope/", bytes.NewReader(makeEnvelope("", "", eventBody)))
	req.Header.Set("Authorization", "Sentry sentry_key="+pubKey)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("Authorization Sentry: got %d", rec.Code)
	}

	// 3. Query string ?sentry_key= works (browser SDKs).
	req = httptest.NewRequest(http.MethodPost, "/api/424242/envelope/?sentry_key="+pubKey+"&sentry_version=7", bytes.NewReader(makeEnvelope("", "", eventBody)))
	req.Header.Set("Origin", "https://allowed.example.ao")
	rec = httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("query sentry_key: got %d", rec.Code)
	}
	if rec.Header().Get("Access-Control-Allow-Origin") != "https://allowed.example.ao" {
		t.Fatalf("missing ACAO header: %q", rec.Header().Get("Access-Control-Allow-Origin"))
	}
	if !strings.Contains(rec.Header().Get("Access-Control-Expose-Headers"), "X-Sentry-Rate-Limits") {
		t.Fatalf("missing Access-Control-Expose-Headers")
	}

	// 4. Envelope header dsn fallback (tunnel).
	envWithDSN := makeEnvelope("", fmt.Sprintf("https://%s@ingest.vigia.ao/%d", pubKey, publicID), eventBody)
	req = httptest.NewRequest(http.MethodPost, "/api/424242/envelope/", bytes.NewReader(envWithDSN))
	rec = httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("envelope dsn fallback: got %d body=%s", rec.Code, rec.Body.String())
	}

	// 5. OPTIONS preflight returns 204 with CORS headers.
	req = httptest.NewRequest(http.MethodOptions, "/api/424242/envelope/", nil)
	req.Header.Set("Origin", "https://allowed.example.ao")
	rec = httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent || !strings.Contains(rec.Header().Get("Access-Control-Expose-Headers"), "X-Sentry-Rate-Limits") {
		t.Fatalf("OPTIONS preflight: code=%d expose=%q", rec.Code, rec.Header().Get("Access-Control-Expose-Headers"))
	}

	// 6. Disallowed origin -> 403.
	req = httptest.NewRequest(http.MethodPost, "/api/424242/envelope/?sentry_key="+pubKey, bytes.NewReader(makeEnvelope("", "", eventBody)))
	req.Header.Set("Origin", "https://evil.example.com")
	rec = httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("disallowed origin: got %d, want 403", rec.Code)
	}

	// 7. Wrong project public_id -> 403.
	req = httptest.NewRequest(http.MethodPost, "/api/999999/envelope/", bytes.NewReader(makeEnvelope("", "", eventBody)))
	req.Header.Set("X-Sentry-Auth", "Sentry sentry_key="+pubKey)
	rec = httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("wrong project public_id: got %d, want 403", rec.Code)
	}

	// 8. Non-numeric project_id -> 400.
	req = httptest.NewRequest(http.MethodPost, "/api/not-a-number/envelope/", bytes.NewReader(makeEnvelope("", "", eventBody)))
	rec = httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("non-numeric project_id: got %d, want 400", rec.Code)
	}

	// 9. Unsupported sentry_version -> 400.
	req = httptest.NewRequest(http.MethodPost, "/api/424242/envelope/", bytes.NewReader(makeEnvelope("", "", eventBody)))
	req.Header.Set("X-Sentry-Auth", "Sentry sentry_version=6, sentry_key="+pubKey)
	rec = httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid sentry_version: got %d, want 400", rec.Code)
	}

	// 10. Non-event items (transaction, session) dropped with 200 and counted.
	txOnly := makeEnvelope("", "", "", `{"type":"transaction","length":2}`+"\n{}\n"+`{"type":"session"}`+"\n{\"sid\":\"1\"}\n")
	req = httptest.NewRequest(http.MethodPost, "/api/424242/envelope/", bytes.NewReader(txOnly))
	req.Header.Set("X-Sentry-Auth", "Sentry sentry_key="+pubKey)
	rec = httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("transaction-only envelope: got %d", rec.Code)
	}
	if h.Metrics().DroppedCount("transaction") != 1 || h.Metrics().DroppedCount("session") != 1 {
		t.Fatalf("expected dropped counts (1,1), got tx=%d session=%d", h.Metrics().DroppedCount("transaction"), h.Metrics().DroppedCount("session"))
	}

	// 11. Legacy /store/ JSON accepted; legacy base64+zlib rejected (400).
	req = httptest.NewRequest(http.MethodPost, "/api/424242/store/", strings.NewReader(eventBody))
	req.Header.Set("X-Sentry-Auth", "Sentry sentry_key="+pubKey)
	rec = httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("/store/ JSON: got %d", rec.Code)
	}
	req = httptest.NewRequest(http.MethodPost, "/api/424242/store/", strings.NewReader("eJxLTEpOSU0CAA=="))
	req.Header.Set("X-Sentry-Auth", "Sentry sentry_key="+pubKey)
	rec = httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("/store/ base64+zlib: got %d, want 400", rec.Code)
	}
}

func TestCompressionCodecsAndZipBombs(t *testing.T) {
	pubKey := "0123456789abcdef0123456789abcdef"
	auth := &fakeDSNAuth{keys: map[string]credentials.AuthenticatedDSN{
		pubKey: {ID: uuid.NewString(), OrganizationID: uuid.NewString(), ProjectID: uuid.NewString(), ProjectPublicID: 77},
	}}
	enq := &fakeEnqueuer{}
	r, _ := setupTestRouter(t, ingestion.HandlerOptions{
		DSNAuth:  auth,
		Quotas:   &fakeQuota{decision: quotas.QuotaDecision{Allowed: true}},
		Enqueuer: enq,
	})

	normalEnv := makeEnvelope("", "", `{"message":"compressed ok"}`)
	// Valid envelope with a 12 MiB attachment item compresses to a few KiB -> zip bomb (> 10 MiB decompressed limit)!
	var bombBuf bytes.Buffer
	bombBuf.WriteString("{}\n{\"type\":\"attachment\",\"length\":12582912}\n")
	bombBuf.Write(bytes.Repeat([]byte("A"), 12<<20))
	bombBuf.WriteByte('\n')
	bombPayload := bombBuf.Bytes()

	compress := func(codec string, data []byte) []byte {
		var buf bytes.Buffer
		switch codec {
		case "gzip":
			w := gzip.NewWriter(&buf)
			_, _ = w.Write(data)
			_ = w.Close()
		case "deflate-zlib":
			w := zlib.NewWriter(&buf)
			_, _ = w.Write(data)
			_ = w.Close()
		case "deflate-raw":
			w, _ := flate.NewWriter(&buf, flate.BestCompression)
			_, _ = w.Write(data)
			_ = w.Close()
		case "br":
			w := brotli.NewWriter(&buf)
			_, _ = w.Write(data)
			_ = w.Close()
		case "zstd":
			w, _ := zstd.NewWriter(&buf)
			_, _ = w.Write(data)
			_ = w.Close()
		}
		return buf.Bytes()
	}

	for _, tc := range []struct {
		name   string
		header string
	}{
		{"gzip", "gzip"},
		{"deflate-zlib", "deflate"},
		{"deflate-raw", "deflate"},
		{"br", "br"},
		{"zstd", "zstd"},
	} {
		t.Run("valid_"+tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/api/77/envelope/", bytes.NewReader(compress(tc.name, normalEnv)))
			req.Header.Set("X-Sentry-Auth", "Sentry sentry_key="+pubKey)
			req.Header.Set("Content-Encoding", tc.header)
			rec := httptest.NewRecorder()
			r.ServeHTTP(rec, req)
			if rec.Code != http.StatusOK {
				t.Fatalf("%s valid: got %d body=%s", tc.name, rec.Code, rec.Body.String())
			}
		})

		t.Run("zipbomb_"+tc.name, func(t *testing.T) {
			bomb := compress(tc.name, bombPayload)
			if int64(len(bomb)) >= ingestion.MaxCompressedBodyBytes {
				t.Fatalf("%s bomb unexpectedly large compressed: %d", tc.name, len(bomb))
			}
			req := httptest.NewRequest(http.MethodPost, "/api/77/envelope/", bytes.NewReader(bomb))
			req.Header.Set("X-Sentry-Auth", "Sentry sentry_key="+pubKey)
			req.Header.Set("Content-Encoding", tc.header)
			rec := httptest.NewRecorder()
			r.ServeHTTP(rec, req)
			if rec.Code != http.StatusRequestEntityTooLarge {
				t.Fatalf("%s zip-bomb: got %d, want 413", tc.name, rec.Code)
			}
		})
	}

	// Unsupported encoding -> 415.
	req := httptest.NewRequest(http.MethodPost, "/api/77/envelope/", bytes.NewReader(normalEnv))
	req.Header.Set("X-Sentry-Auth", "Sentry sentry_key="+pubKey)
	req.Header.Set("Content-Encoding", "lz4")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("unsupported encoding: got %d, want 415", rec.Code)
	}
}

func TestEnvelopeSecurityLimitsAndRedaction(t *testing.T) {
	pubKey := "0123456789abcdef0123456789abcdef"
	auth := &fakeDSNAuth{keys: map[string]credentials.AuthenticatedDSN{
		pubKey: {ID: uuid.NewString(), OrganizationID: uuid.NewString(), ProjectID: uuid.NewString(), ProjectPublicID: 88},
	}}
	enq := &fakeEnqueuer{}
	r, _ := setupTestRouter(t, ingestion.HandlerOptions{
		DSNAuth:  auth,
		Quotas:   &fakeQuota{decision: quotas.QuotaDecision{Allowed: true}},
		Enqueuer: enq,
	})

	// 1. Lying length (declares 50 bytes, provides 5) -> 400.
	lying := "{}\n{\"type\":\"event\",\"length\":50}\nhello\n"
	req := httptest.NewRequest(http.MethodPost, "/api/88/envelope/", strings.NewReader(lying))
	req.Header.Set("X-Sentry-Auth", "Sentry sentry_key="+pubKey)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("lying length: got %d, want 400", rec.Code)
	}

	// 2. Deep JSON (> 64 levels) -> 400.
	deep := strings.Repeat(`{"a":`, 70) + `1` + strings.Repeat(`}`, 70)
	req = httptest.NewRequest(http.MethodPost, "/api/88/envelope/", bytes.NewReader(makeEnvelope("", "", deep)))
	req.Header.Set("X-Sentry-Auth", "Sentry sentry_key="+pubKey)
	rec = httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("deep JSON: got %d, want 400", rec.Code)
	}

	// 3. Thousands of frames & breadcrumbs + PII -> truncated with _meta and PII scrubbed BEFORE enqueue.
	frames := make([]map[string]any, 400)
	for i := range frames {
		frames[i] = map[string]any{"filename": fmt.Sprintf("f%d.go", i), "function": "fn"}
	}
	crumbs := make([]map[string]any, 250)
	for i := range crumbs {
		crumbs[i] = map[string]any{"message": fmt.Sprintf("c%d", i)}
	}
	hugeEvent, _ := json.Marshal(map[string]any{
		"message":       "failed with secret",
		"unknown_field": "must_be_dropped",
		"exception": map[string]any{
			"values": []map[string]any{
				{"type": "Err", "value": "Bearer supersecretvalue1234567890", "stacktrace": map[string]any{"frames": frames}},
			},
		},
		"breadcrumbs": map[string]any{"values": crumbs},
		"request": map[string]any{
			"data":    map[string]any{"password": "my-secret-password"},
			"cookies": "session=secretcookie",
			"headers": map[string]any{"Authorization": "Bearer leakme1234567890"},
		},
	})
	req = httptest.NewRequest(http.MethodPost, "/api/88/envelope/", bytes.NewReader(makeEnvelope("", "", string(hugeEvent))))
	req.Header.Set("X-Sentry-Auth", "Sentry sentry_key="+pubKey)
	rec = httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("huge event: got %d body=%s", rec.Code, rec.Body.String())
	}
	payloadStr := string(enq.last().Payload)
	if strings.Contains(payloadStr, "my-secret-password") || strings.Contains(payloadStr, "secretcookie") || strings.Contains(payloadStr, "leakme1234567890") || strings.Contains(payloadStr, "supersecretvalue") {
		t.Fatalf("PII/secret leaked into enqueued payload: %s", payloadStr)
	}
	if strings.Contains(payloadStr, "unknown_field") {
		t.Fatalf("unknown top-level field was not dropped")
	}
	if !strings.Contains(payloadStr, `"_meta":{"fields":[`) || !strings.Contains(payloadStr, `"truncated":true`) {
		t.Fatalf("expected _meta.truncated=true in payload")
	}
}

func TestRateLimitQuotaAndBackpressureHeaders(t *testing.T) {
	pubKey := "0123456789abcdef0123456789abcdef"
	auth := &fakeDSNAuth{keys: map[string]credentials.AuthenticatedDSN{
		pubKey: {ID: uuid.NewString(), OrganizationID: uuid.NewString(), ProjectID: uuid.NewString(), ProjectPublicID: 99},
	}}
	env := makeEnvelope("", "", `{"message":"err"}`)

	// Backpressure -> 429 X-Sentry-Rate-Limits: 60::organization:backpressure.
	rBP, _ := setupTestRouter(t, ingestion.HandlerOptions{
		DSNAuth:      auth,
		Enqueuer:     &fakeEnqueuer{},
		Backpressure: &fakeBackpressure{overloaded: true},
	})
	req := httptest.NewRequest(http.MethodPost, "/api/99/envelope/", bytes.NewReader(env))
	req.Header.Set("X-Sentry-Auth", "Sentry sentry_key="+pubKey)
	rec := httptest.NewRecorder()
	rBP.ServeHTTP(rec, req)
	if rec.Code != http.StatusTooManyRequests || rec.Header().Get("X-Sentry-Rate-Limits") != "60::organization:backpressure" {
		t.Fatalf("backpressure: code=%d hdr=%q", rec.Code, rec.Header().Get("X-Sentry-Rate-Limits"))
	}

	// Quota exceeded -> 429 X-Sentry-Rate-Limits: <sec>:error;default:organization:quota_exceeded.
	rQ, _ := setupTestRouter(t, ingestion.HandlerOptions{
		DSNAuth:  auth,
		Enqueuer: &fakeEnqueuer{},
		Quotas:   &fakeQuota{decision: quotas.QuotaDecision{Allowed: false, Window: "day", RetryAfter: 3600 * time.Second}},
	})
	req = httptest.NewRequest(http.MethodPost, "/api/99/envelope/", bytes.NewReader(env))
	req.Header.Set("X-Sentry-Auth", "Sentry sentry_key="+pubKey)
	rec = httptest.NewRecorder()
	rQ.ServeHTTP(rec, req)
	if rec.Code != http.StatusTooManyRequests || rec.Header().Get("X-Sentry-Rate-Limits") != "3600:error;default:organization:quota_exceeded" || rec.Header().Get("Retry-After") != "3600" {
		t.Fatalf("quota exceeded: code=%d hdr=%q retry=%q", rec.Code, rec.Header().Get("X-Sentry-Rate-Limits"), rec.Header().Get("Retry-After"))
	}

	// Rate limited -> 429 X-Sentry-Rate-Limits: 45:error;default:key:rate_limited.
	rRL, _ := setupTestRouter(t, ingestion.HandlerOptions{
		DSNAuth:  auth,
		Enqueuer: &fakeEnqueuer{},
		Limiter:  &fakeLimiter{allowed: false, retry: 45 * time.Second},
	})
	req = httptest.NewRequest(http.MethodPost, "/api/99/envelope/", bytes.NewReader(env))
	req.Header.Set("X-Sentry-Auth", "Sentry sentry_key="+pubKey)
	rec = httptest.NewRecorder()
	rRL.ServeHTTP(rec, req)
	if rec.Code != http.StatusTooManyRequests || rec.Header().Get("X-Sentry-Rate-Limits") != "45:error;default:key:rate_limited" {
		t.Fatalf("rate limited: code=%d hdr=%q", rec.Code, rec.Header().Get("X-Sentry-Rate-Limits"))
	}
}

// TestDedupReleasedAndQuotaRefunded_CTO37_41 verifies:
//   - CTO #37: quota rejection (429) or enqueue failure (503) releases the dedup key
//     so an SDK retry with the exact same event_id is accepted and enqueued.
//   - CTO #41: enqueue failure refunds the consumed quota unit.
func TestDedupReleasedAndQuotaRefunded_CTO37_41(t *testing.T) {
	pubKey := strings.Repeat("a", 32)
	auth := &fakeDSNAuth{keys: map[string]credentials.AuthenticatedDSN{
		pubKey: {ID: uuid.NewString(), OrganizationID: uuid.NewString(), ProjectID: uuid.NewString(), ProjectPublicID: 101},
	}}

	t.Run("quota_exceeded_releases_dedup_key", func(t *testing.T) {
		dedup := newMemDedupStore()
		enq := &fakeEnqueuer{}
		q := &fakeQuota{decision: quotas.QuotaDecision{Allowed: false, Window: "day", RetryAfter: 60 * time.Second}}
		r, _ := setupTestRouter(t, ingestion.HandlerOptions{
			DSNAuth:  auth,
			Quotas:   q,
			Dedup:    dedup,
			Enqueuer: enq,
		})

		evID := strings.Repeat("b", 32)
		env := makeEnvelope(evID, "", `{"event_id":"`+evID+`","message":"retry after quota"}`)

		// Attempt 1: quota exceeded -> 429, nothing enqueued.
		req1 := httptest.NewRequest(http.MethodPost, "/api/101/envelope/", bytes.NewReader(env))
		req1.Header.Set("X-Sentry-Auth", "Sentry sentry_key="+pubKey)
		rec1 := httptest.NewRecorder()
		r.ServeHTTP(rec1, req1)
		if rec1.Code != http.StatusTooManyRequests || enq.len() != 0 {
			t.Fatalf("attempt 1: code=%d enqueued=%d", rec1.Code, enq.len())
		}

		// Quota raised -> SDK retries the exact same event_id -> MUST be accepted and enqueued.
		q.decision = quotas.QuotaDecision{Allowed: true}
		req2 := httptest.NewRequest(http.MethodPost, "/api/101/envelope/", bytes.NewReader(env))
		req2.Header.Set("X-Sentry-Auth", "Sentry sentry_key="+pubKey)
		rec2 := httptest.NewRecorder()
		r.ServeHTTP(rec2, req2)
		if rec2.Code != http.StatusOK || enq.len() != 1 {
			t.Fatalf("attempt 2 after quota raised: code=%d enqueued=%d, want 200 and 1", rec2.Code, enq.len())
		}
	})

	t.Run("enqueue_failure_releases_dedup_and_refunds_quota", func(t *testing.T) {
		dedup := newMemDedupStore()
		enq := &fakeEnqueuer{err: errors.New("river insert failed")}
		q := &fakeQuota{decision: quotas.QuotaDecision{Allowed: true}}
		r, _ := setupTestRouter(t, ingestion.HandlerOptions{
			DSNAuth:  auth,
			Quotas:   q,
			Dedup:    dedup,
			Enqueuer: enq,
		})

		evID := strings.Repeat("c", 32)
		env := makeEnvelope(evID, "", `{"event_id":"`+evID+`","message":"retry after enqueue fail"}`)

		// Attempt 1: enqueue fails -> 503, dedup released, quota refunded.
		req1 := httptest.NewRequest(http.MethodPost, "/api/101/envelope/", bytes.NewReader(env))
		req1.Header.Set("X-Sentry-Auth", "Sentry sentry_key="+pubKey)
		rec1 := httptest.NewRecorder()
		r.ServeHTTP(rec1, req1)
		if rec1.Code != http.StatusServiceUnavailable {
			t.Fatalf("attempt 1: code=%d, want 503", rec1.Code)
		}
		if q.refunds != 1 {
			t.Fatalf("expected 1 quota refund on enqueue failure, got %d", q.refunds)
		}

		// Enqueue recovers -> SDK retries the exact same event_id -> MUST be accepted and enqueued.
		enq.err = nil
		req2 := httptest.NewRequest(http.MethodPost, "/api/101/envelope/", bytes.NewReader(env))
		req2.Header.Set("X-Sentry-Auth", "Sentry sentry_key="+pubKey)
		rec2 := httptest.NewRecorder()
		r.ServeHTTP(rec2, req2)
		if rec2.Code != http.StatusOK || enq.len() != 1 {
			t.Fatalf("attempt 2 after enqueue recovery: code=%d enqueued=%d, want 200 and 1", rec2.Code, enq.len())
		}
	})
}

// TestDSNAuthBackendErrorReturns503_CTO38 verifies that a DB outage during DSN
// auth returns 503 + Retry-After so Sentry SDKs retry instead of dropping (CTO #38).
func TestDSNAuthBackendErrorReturns503_CTO38(t *testing.T) {
	pubKey := strings.Repeat("a", 32)
	r, _ := setupTestRouter(t, ingestion.HandlerOptions{
		DSNAuth:  &fakeDSNAuth{err: credentials.ErrBackendUnavailable},
		Enqueuer: &fakeEnqueuer{},
	})
	req := httptest.NewRequest(http.MethodPost, "/api/101/envelope/", bytes.NewReader(makeEnvelope("", "", `{"message":"db down"}`)))
	req.Header.Set("X-Sentry-Auth", "Sentry sentry_key="+pubKey)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable || rec.Header().Get("Retry-After") == "" {
		t.Fatalf("DB outage during DSN auth: code=%d retry=%q, want 503 with Retry-After", rec.Code, rec.Header().Get("Retry-After"))
	}
}

// BenchmarkIngestion20KiB measures ingestion P95 latency for a 20 KiB event
// (ADR-017 §6 target: P95 < 50ms without network).
func BenchmarkIngestion20KiB(b *testing.B) {
	pubKey := "0123456789abcdef0123456789abcdef"
	auth := &fakeDSNAuth{keys: map[string]credentials.AuthenticatedDSN{
		pubKey: {ID: uuid.NewString(), OrganizationID: uuid.NewString(), ProjectID: uuid.NewString(), ProjectPublicID: 55},
	}}
	h, err := ingestion.NewHandler(ingestion.HandlerOptions{
		DSNAuth:  auth,
		Quotas:   &fakeQuota{decision: quotas.QuotaDecision{Allowed: true}},
		Enqueuer: &fakeEnqueuer{},
	})
	if err != nil {
		b.Fatal(err)
	}
	r := chi.NewRouter()
	h.Mount(r)

	// Build ~20 KiB event payload.
	frames := make([]map[string]any, 40)
	for i := range frames {
		frames[i] = map[string]any{
			"filename":     fmt.Sprintf("internal/service/handler_%d.go", i),
			"function":     fmt.Sprintf("HandleRequest_%d", i),
			"lineno":       100 + i,
			"in_app":       true,
			"context_line": strings.Repeat("x", 300),
		}
	}
	evBytes, _ := json.Marshal(map[string]any{
		"message":   "benchmark error",
		"level":     "error",
		"exception": map[string]any{"values": []map[string]any{{"type": "RuntimeError", "value": "something failed", "stacktrace": map[string]any{"frames": frames}}}},
	})
	env := makeEnvelope("", "", string(evBytes))

	latencies := make([]time.Duration, 0, b.N)
	b.ResetTimer()
	for range b.N {
		start := time.Now()
		req := httptest.NewRequest(http.MethodPost, "/api/55/envelope/", bytes.NewReader(env))
		req.Header.Set("X-Sentry-Auth", "Sentry sentry_version=7, sentry_key="+pubKey)
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			b.Fatalf("status=%d", rec.Code)
		}
		latencies = append(latencies, time.Since(start))
	}
	b.StopTimer()
	if len(latencies) > 0 {
		sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })
		p95 := latencies[int(float64(len(latencies))*0.95)]
		b.ReportMetric(float64(p95.Microseconds())/1000.0, "p95_ms")
	}
}
