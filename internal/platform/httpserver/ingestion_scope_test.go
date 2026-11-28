package httpserver_test

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/Yhanko/vigia/internal/api"
	"github.com/Yhanko/vigia/internal/platform/httpserver"
)

type stubServer struct {
	api.Unimplemented
}

func (stubServer) GetStatus(w http.ResponseWriter, _ *http.Request) {
	httpserver.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (stubServer) AuthLogin(w http.ResponseWriter, r *http.Request) {
	var dst map[string]any
	if !httpserver.DecodeJSON(w, r, &dst) {
		return
	}
	httpserver.WriteJSON(w, http.StatusOK, map[string]string{"ok": "1"})
}

// TestAPIV1MiddlewaresDoNotBlockIngestion verifies that moving CORSMiddleware
// and MaxBytesMiddleware into /api/v1 keeps /api/v1 protected while allowing
// Sentry ingestion routes outside /api/v1 to manage their own CORS and limits.
func TestAPIV1MiddlewaresDoNotBlockIngestion(t *testing.T) {
	h := httpserver.NewHandler(httpserver.Options{
		CORSOrigins:  []string{"https://app.vigia.ao"},
		MaxBodyBytes: 64, // tiny limit for /api/v1
		APIServer:    stubServer{},
		MountIngestion: func(r chi.Router) {
			r.Post("/api/{project_id}/envelope/", func(w http.ResponseWriter, req *http.Request) {
				buf := new(bytes.Buffer)
				_, _ = buf.ReadFrom(req.Body)
				w.Header().Set("Access-Control-Allow-Origin", req.Header.Get("Origin"))
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"id":"ok"}`))
			})
		},
	})

	// 1. /api/v1 enforces MaxBodyBytes (64 bytes -> 413).
	largeBody := append(append([]byte(`{"x":"`), bytes.Repeat([]byte("a"), 256)...), []byte(`"}`)...)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewReader(largeBody))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("/api/v1 large body: got %d, want 413", rec.Code)
	}

	// 2. /api/v1 enforces CORSMiddleware (disallowed origin gets no ACAO header).
	req = httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
	req.Header.Set("Origin", "https://evil.example.com")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Fatalf("/api/v1 disallowed origin leaked ACAO=%q", got)
	}

	// 3. Ingestion route outside /api/v1 is NOT blocked by /api/v1's 64-byte cap or CORS allowlist.
	req = httptest.NewRequest(http.MethodPost, "/api/12345/envelope/", bytes.NewReader(largeBody))
	req.Header.Set("Origin", "https://customer-app.example.ao")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("ingestion route blocked by /api/v1 middleware: got %d, want 200", rec.Code)
	}
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "https://customer-app.example.ao" {
		t.Fatalf("ingestion route ACAO=%q, want customer origin", got)
	}
}
