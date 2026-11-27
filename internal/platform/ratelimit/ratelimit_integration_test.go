//go:build integration

package ratelimit_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/Yhanko/vigia/internal/api"
	"github.com/Yhanko/vigia/internal/platform/clock"
	"github.com/Yhanko/vigia/internal/platform/httpserver"
	"github.com/Yhanko/vigia/internal/platform/ratelimit"
)

type statusOnlyAPI struct {
	api.Unimplemented
}

func (statusOnlyAPI) GetStatus(w http.ResponseWriter, _ *http.Request) {
	httpserver.WriteJSON(w, http.StatusOK, api.StatusResponse{
		Service: "vigia",
		Status:  "ok",
		Version: "test",
		Commit:  "abc",
	})
}

// Exact Redis image and digest pinned in compose.yaml.
const redisImage = "redis:8.12.0-alpine3.23@sha256:5af80107c1eeecb484a2269b80a26d12bfa6521787da4663bd9f19f60a163483"

func startRedis(t *testing.T) *redis.Client {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	ctr, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image:        redisImage,
			ExposedPorts: []string{"6379/tcp"},
			WaitingFor:   wait.ForLog("Ready to accept connections").WithStartupTimeout(1 * time.Minute),
		},
		Started: true,
	})
	if err != nil {
		t.Fatalf("start redis container: %v", err)
	}
	t.Cleanup(func() {
		if err := testcontainers.TerminateContainer(ctr); err != nil {
			t.Logf("terminate redis container: %v", err)
		}
	})

	endpoint, err := ctr.Endpoint(ctx, "")
	if err != nil {
		t.Fatalf("redis endpoint: %v", err)
	}
	client := redis.NewClient(&redis.Options{Addr: endpoint})
	t.Cleanup(func() { _ = client.Close() })

	if err := client.Ping(ctx).Err(); err != nil {
		t.Fatalf("ping redis: %v", err)
	}
	return client
}

func TestRedisLimiterAndStatus429Integration(t *testing.T) {
	rdb := startRedis(t)
	ctx := context.Background()

	fakeClk := clock.NewFake(time.Date(2026, 11, 27, 15, 0, 0, 0, time.UTC))
	limiter, err := ratelimit.NewRedisLimiter(rdb, fakeClk)
	if err != nil {
		t.Fatalf("NewRedisLimiter: %v", err)
	}

	// Sliding window allows 2 requests, blocks the 3rd, and allows again after window slides.
	for i := range 2 {
		res, err := limiter.Allow(ctx, "test:window", 2, 10*time.Second)
		if err != nil || !res.Allowed {
			t.Fatalf("req %d: got (%+v, %v), want allowed", i+1, res, err)
		}
	}
	blocked, err := limiter.Allow(ctx, "test:window", 2, 10*time.Second)
	if err != nil || blocked.Allowed || blocked.RetryAfter <= 0 {
		t.Fatalf("req 3: got (%+v, %v), want blocked with RetryAfter > 0", blocked, err)
	}
	fakeClk.Advance(11 * time.Second)
	afterWindow, err := limiter.Allow(ctx, "test:window", 2, 10*time.Second)
	if err != nil || !afterWindow.Allowed {
		t.Fatalf("after window slide: got (%+v, %v), want allowed", afterWindow, err)
	}

	// CTO #23: Peek checks without incrementing; Reset clears recorded entries.
	peek1, err := limiter.Peek(ctx, "test:peek", 1, time.Minute)
	if err != nil || !peek1.Allowed || peek1.Remaining != 1 {
		t.Fatalf("Peek(empty) = (%+v, %v), want allowed remaining=1", peek1, err)
	}
	peek2, err := limiter.Peek(ctx, "test:peek", 1, time.Minute)
	if err != nil || !peek2.Allowed || peek2.Remaining != 1 {
		t.Fatalf("second Peek must not consume quota: (%+v, %v)", peek2, err)
	}
	if res, err := limiter.Allow(ctx, "test:peek", 1, time.Minute); err != nil || !res.Allowed {
		t.Fatalf("Allow after Peek = (%+v, %v), want allowed", res, err)
	}
	if res, err := limiter.Peek(ctx, "test:peek", 1, time.Minute); err != nil || res.Allowed {
		t.Fatalf("Peek after full = (%+v, %v), want blocked", res, err)
	}
	if err := limiter.Reset(ctx, "test:peek"); err != nil {
		t.Fatalf("Reset: %v", err)
	}
	if res, err := limiter.Peek(ctx, "test:peek", 1, time.Minute); err != nil || !res.Allowed {
		t.Fatalf("Peek after Reset = (%+v, %v), want allowed", res, err)
	}

	// CTO #5: GET /api/v1/status above limit returns 429 RATE_LIMIT_EXCEEDED + headers.
	handler := httpserver.NewHandler(httpserver.Options{
		Version:   "test",
		Commit:    "abc",
		APIServer: statusOnlyAPI{},
		APIRateLimit: ratelimit.Middleware(ratelimit.MiddlewareOptions{
			Limiter:    limiter,
			KeyPrefix:  "api",
			Limit:      2,
			Window:     time.Minute,
			FailClosed: false,
		}),
	})

	for i := range 2 {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
		req.RemoteAddr = "198.51.100.7:12345"
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status request %d = %d, want 200", i+1, rec.Code)
		}
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
	req.RemoteAddr = "198.51.100.7:12345"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("3rd /api/v1/status = %d, want 429", rec.Code)
	}
	for _, hdr := range []string{"RateLimit-Limit", "RateLimit-Remaining", "RateLimit-Reset", "Retry-After"} {
		if rec.Header().Get(hdr) == "" {
			t.Fatalf("missing required header %s on 429 response", hdr)
		}
	}
	var env httpserver.ErrorResponse
	if err := json.NewDecoder(rec.Body).Decode(&env); err != nil {
		t.Fatalf("decode 429 body: %v", err)
	}
	if env.Error.Code != "RATE_LIMIT_EXCEEDED" {
		t.Fatalf("error.code = %q, want RATE_LIMIT_EXCEEDED", env.Error.Code)
	}
}
