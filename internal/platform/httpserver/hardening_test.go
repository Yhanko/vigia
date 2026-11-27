package httpserver

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
)

func TestSecurityHeaders(t *testing.T) {
	t.Run("CSP on every response, no HSTS by default", func(t *testing.T) {
		rec := httptest.NewRecorder()
		NewHandler(Options{APIServer: testStatusServer{}}).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/status", nil))

		if got := rec.Header().Get("Content-Security-Policy"); !strings.Contains(got, "default-src 'none'") {
			t.Fatalf("CSP = %q, want default-src 'none'", got)
		}
		if got := rec.Header().Get("Strict-Transport-Security"); got != "" {
			t.Fatalf("HSTS must be off unless enabled, got %q", got)
		}
	})

	t.Run("HSTS when enabled", func(t *testing.T) {
		rec := httptest.NewRecorder()
		NewHandler(Options{HSTS: true, APIServer: testStatusServer{}}).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/status", nil))
		if got := rec.Header().Get("Strict-Transport-Security"); !strings.HasPrefix(got, "max-age=") {
			t.Fatalf("HSTS = %q, want max-age", got)
		}
	})
}

// A panic inside a handler mounted on the real router returns the standard
// envelope with the request ID and the security headers (middleware order).
func TestRouterRecoversPanicsWithHeaders(t *testing.T) {
	h := NewHandler(Options{}).(chi.Router)
	h.Get("/api/v1/boom", func(http.ResponseWriter, *http.Request) {
		panic("db password: hunter2")
	})

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/boom", nil))

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "hunter2") {
		t.Fatalf("panic leaked: %s", rec.Body.String())
	}
	if rec.Header().Get("X-Request-Id") == "" || rec.Header().Get("Content-Security-Policy") == "" {
		t.Fatalf("recovered response missing request id or security headers: %v", rec.Header())
	}
}

func TestRecovererRepanicsAbortHandler(t *testing.T) {
	h := RecovererMiddleware(nil)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic(http.ErrAbortHandler)
	}))
	defer func() {
		if err, ok := recover().(error); !ok || !errors.Is(err, http.ErrAbortHandler) {
			t.Fatalf("expected ErrAbortHandler to propagate, got %v", err)
		}
	}()
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
}

func TestDecodeJSON(t *testing.T) {
	type input struct {
		Name  string `json:"name"`
		Count int    `json:"count"`
	}

	handler := MaxBytesMiddleware(64)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var in input
		if !DecodeJSON(w, r, &in) {
			return
		}
		WriteJSON(w, http.StatusOK, in)
	}))

	tests := []struct {
		name        string
		contentType string
		body        string
		wantStatus  int
		wantCode    string
	}{
		{"valid", "application/json", `{"name":"a","count":1}`, http.StatusOK, ""},
		{"valid with charset", "application/json; charset=utf-8", `{"name":"a"}`, http.StatusOK, ""},
		{"wrong content type", "text/plain", `{"name":"a"}`, http.StatusUnsupportedMediaType, "UNSUPPORTED_MEDIA_TYPE"},
		{"empty body", "application/json", ``, http.StatusBadRequest, "INVALID_JSON"},
		{"malformed", "application/json", `{"name":`, http.StatusBadRequest, "INVALID_JSON"},
		{"unknown field", "application/json", `{"name":"a","isAdmin":true}`, http.StatusBadRequest, "VALIDATION_FAILED"},
		{"wrong type", "application/json", `{"count":"x"}`, http.StatusBadRequest, "VALIDATION_FAILED"},
		{"two objects", "application/json", `{"name":"a"}{"name":"b"}`, http.StatusBadRequest, "INVALID_JSON"},
		{"too large", "application/json", `{"name":"` + strings.Repeat("a", 100) + `"}`, http.StatusRequestEntityTooLarge, "PAYLOAD_TOO_LARGE"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(tt.body))
			req.Header.Set("Content-Type", tt.contentType)
			rec := httptest.NewRecorder()
			RequestIDMiddleware(handler).ServeHTTP(rec, req)

			if rec.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d (body: %s)", rec.Code, tt.wantStatus, rec.Body.String())
			}
			if tt.wantCode == "" {
				return
			}
			var resp ErrorResponse
			if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if resp.Error.Code != tt.wantCode {
				t.Fatalf("code = %q, want %q", resp.Error.Code, tt.wantCode)
			}
			if strings.Contains(rec.Body.String(), "isAdmin") {
				t.Fatalf("unknown field name echoed back: %s", rec.Body.String())
			}
		})
	}
}
