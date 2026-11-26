package httpserver

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRoutesAndErrorEnvelopes(t *testing.T) {
	h := NewHandler(Options{
		Version:     "test-1.0",
		Commit:      "abc1234",
		CORSOrigins: []string{"http://127.0.0.1:5173"},
	})

	tests := []struct {
		name       string
		method     string
		path       string
		wantStatus int
		wantCode   string
	}{
		{"liveness", http.MethodGet, "/health/live", http.StatusOK, ""},
		{"readiness without deps", http.MethodGet, "/health/ready", http.StatusOK, ""},
		{"api v1 status", http.MethodGet, "/api/v1/status", http.StatusOK, ""},
		{"not found envelope", http.MethodGet, "/api/v1/does-not-exist", http.StatusNotFound, "RESOURCE_NOT_FOUND"},
		{"method not allowed envelope", http.MethodPost, "/api/v1/status", http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(tt.method, tt.path, nil)
			h.ServeHTTP(rec, req)

			if rec.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d (body: %s)", rec.Code, tt.wantStatus, rec.Body.String())
			}
			if rec.Header().Get("X-Request-Id") == "" {
				t.Fatalf("missing X-Request-Id header")
			}
			if rec.Header().Get("X-Content-Type-Options") != "nosniff" {
				t.Fatalf("missing security header X-Content-Type-Options")
			}

			if tt.wantCode != "" {
				var resp ErrorResponse
				if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
					t.Fatalf("unmarshal error envelope: %v", err)
				}
				if resp.Error.Code != tt.wantCode {
					t.Fatalf("error.code = %q, want %q", resp.Error.Code, tt.wantCode)
				}
				if resp.Error.RequestID == "" {
					t.Fatalf("error.requestId is empty")
				}
			}
		})
	}
}

func TestReadinessChecks(t *testing.T) {
	t.Run("all healthy", func(t *testing.T) {
		h := NewHandler(Options{
			ReadinessChecks: []ReadinessCheck{
				{Name: "postgres", Check: func(context.Context) error { return nil }},
				{Name: "redis", Check: func(context.Context) error { return nil }},
			},
		})
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/health/ready", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rec.Code)
		}
	})

	t.Run("dependency failure returns 503 without leaking details", func(t *testing.T) {
		h := NewHandler(Options{
			ReadinessChecks: []ReadinessCheck{
				{Name: "postgres", Check: func(context.Context) error { return nil }},
				{Name: "redis", Check: func(context.Context) error { return errors.New("secret-password-in-err") }},
			},
		})
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/health/ready", nil))
		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("status = %d, want 503", rec.Code)
		}
		if strings.Contains(rec.Body.String(), "secret-password-in-err") {
			t.Fatalf("readiness response leaked internal error: %s", rec.Body.String())
		}
	})
}

func TestCORSAllowlist(t *testing.T) {
	h := NewHandler(Options{
		CORSOrigins: []string{"http://127.0.0.1:5173"},
	})

	req := httptest.NewRequest(http.MethodOptions, "/api/v1/status", nil)
	req.Header.Set("Origin", "http://127.0.0.1:5173")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("preflight status = %d, want 204", rec.Code)
	}
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "http://127.0.0.1:5173" {
		t.Fatalf("ACAO = %q, want allowed origin", got)
	}

	req2 := httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
	req2.Header.Set("Origin", "https://evil.example")
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, req2)
	if got := rec2.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Fatalf("unexpected ACAO for disallowed origin: %q", got)
	}
}

func TestSecurityHardening(t *testing.T) {
	t.Run("rejects malicious X-Request-Id header injection", func(t *testing.T) {
		h := NewHandler(Options{})
		req := httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
		req.Header.Set("X-Request-Id", "evil\r\nSet-Cookie: session=hacked")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)

		gotID := rec.Header().Get("X-Request-Id")
		if !strings.HasPrefix(gotID, "req_") || strings.ContainsAny(gotID, "\r\n ") {
			t.Fatalf("malicious X-Request-Id was not sanitized: %q", gotID)
		}
	})

	t.Run("recoverer does not leak panic details to client", func(t *testing.T) {
		panicHandler := RequestIDMiddleware(RecovererMiddleware(nil)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			panic("internal db password leaked in panic")
		})))

		rec := httptest.NewRecorder()
		panicHandler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/panic", nil))

		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("status = %d, want 500", rec.Code)
		}
		if strings.Contains(rec.Body.String(), "internal db password") {
			t.Fatalf("panic message leaked in response: %s", rec.Body.String())
		}
	})

	t.Run("MaxBytesMiddleware blocks oversized request bodies", func(t *testing.T) {
		handler := MaxBytesMiddleware(16)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			buf := make([]byte, 64)
			if _, err := r.Body.Read(buf); err != nil {
				var maxErr *http.MaxBytesError
				if errors.As(err, &maxErr) {
					WriteError(w, r, http.StatusRequestEntityTooLarge, "PAYLOAD_TOO_LARGE", "Request body exceeds limit.")
					return
				}
			}
			w.WriteHeader(http.StatusOK)
		}))

		req := httptest.NewRequest(http.MethodPost, "/api/v1/test", strings.NewReader(strings.Repeat("a", 32)))
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusRequestEntityTooLarge {
			t.Fatalf("status = %d, want 413", rec.Code)
		}
	})
}
