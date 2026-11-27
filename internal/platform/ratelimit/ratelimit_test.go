package ratelimit

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Yhanko/vigia/internal/platform/httpserver"
)

type fakeLimiter struct {
	res Result
	err error
}

func (f fakeLimiter) Allow(_ context.Context, _ string, _ int, _ time.Duration) (Result, error) {
	return f.res, f.err
}

func (f fakeLimiter) Peek(_ context.Context, _ string, _ int, _ time.Duration) (Result, error) {
	return f.res, f.err
}

func (f fakeLimiter) Reset(_ context.Context, _ string) error {
	return f.err
}

func TestHashIdentifierNoPIIAndDeterministic(t *testing.T) {
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		t.Fatal(err)
	}
	h1 := HashIdentifier(secret, "Alice@Example.COM")
	h2 := HashIdentifier(secret, "  alice@example.com ")
	if h1 != h2 {
		t.Fatalf("HashIdentifier not normalized/deterministic: %q != %q", h1, h2)
	}
	if strings.Contains(h1, "alice") || strings.Contains(h1, "example") {
		t.Fatalf("HashIdentifier leaked PII: %q", h1)
	}
	if len(h1) != 64 {
		t.Fatalf("HashIdentifier hex length = %d, want 64", len(h1))
	}
}

func TestMiddlewareBlockedReturns429AndHeaders(t *testing.T) {
	h := Middleware(MiddlewareOptions{
		Limiter: fakeLimiter{res: Result{
			Allowed:    false,
			Limit:      10,
			Remaining:  0,
			ResetAfter: 45 * time.Second,
			RetryAfter: 12 * time.Second,
		}},
		KeyPrefix: "api",
		Limit:     10,
		Window:    time.Minute,
	})(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
	req.RemoteAddr = "192.0.2.10:54321"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429", rec.Code)
	}
	if got := rec.Header().Get("RateLimit-Limit"); got != "10" {
		t.Fatalf("RateLimit-Limit = %q, want 10", got)
	}
	if got := rec.Header().Get("RateLimit-Remaining"); got != "0" {
		t.Fatalf("RateLimit-Remaining = %q, want 0", got)
	}
	if got := rec.Header().Get("RateLimit-Reset"); got != "45" {
		t.Fatalf("RateLimit-Reset = %q, want 45", got)
	}
	if got := rec.Header().Get("Retry-After"); got != "12" {
		t.Fatalf("Retry-After = %q, want 12", got)
	}

	var env httpserver.ErrorResponse
	if err := json.NewDecoder(rec.Body).Decode(&env); err != nil {
		t.Fatalf("decode error envelope: %v", err)
	}
	if env.Error.Code != "RATE_LIMIT_EXCEEDED" {
		t.Fatalf("error.code = %q, want RATE_LIMIT_EXCEEDED", env.Error.Code)
	}
}

func TestMiddlewareFailClosedAndFailOpen(t *testing.T) {
	t.Run("fail-closed returns 503 with Retry-After", func(t *testing.T) {
		var buf bytes.Buffer
		logger := slog.New(slog.NewJSONHandler(&buf, nil))

		h := Middleware(MiddlewareOptions{
			Limiter:    fakeLimiter{err: errors.New("redis down")},
			KeyPrefix:  "auth",
			Limit:      10,
			Window:     15 * time.Minute,
			FailClosed: true,
			Logger:     logger,
		})(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)

		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("status = %d, want 503", rec.Code)
		}
		if rec.Header().Get("Retry-After") == "" {
			t.Fatal("expected Retry-After header on 503")
		}
	})

	t.Run("fail-open logs warning and allows request", func(t *testing.T) {
		var buf bytes.Buffer
		logger := slog.New(slog.NewJSONHandler(&buf, nil))

		h := Middleware(MiddlewareOptions{
			Limiter:    fakeLimiter{err: errors.New("redis down")},
			KeyPrefix:  "status",
			Limit:      60,
			Window:     time.Minute,
			FailClosed: false,
			Logger:     logger,
		})(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

		req := httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rec.Code)
		}
		if !strings.Contains(buf.String(), `"level":"WARN"`) {
			t.Fatalf("expected WARN log on fail-open, got: %s", buf.String())
		}
	})
}
