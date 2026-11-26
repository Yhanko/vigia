package httpserver

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRoutes(t *testing.T) {
	tests := []struct {
		name       string
		method     string
		path       string
		wantStatus int
		wantBody   string
	}{
		{"olá mundo", http.MethodGet, "/", http.StatusOK, "Olá, mundo!"},
		{"liveness", http.MethodGet, "/health/live", http.StatusOK, ""},
		{"rota inexistente", http.MethodGet, "/nao-existe", http.StatusNotFound, ""},
		{"método não permitido", http.MethodPost, "/", http.StatusMethodNotAllowed, ""},
	}

	h := NewHandler()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, httptest.NewRequest(tt.method, tt.path, nil))

			if rec.Code != tt.wantStatus {
				t.Fatalf("status = %d, quero %d", rec.Code, tt.wantStatus)
			}
			if tt.wantBody != "" && strings.TrimSpace(rec.Body.String()) != tt.wantBody {
				t.Fatalf("body = %q, quero %q", rec.Body.String(), tt.wantBody)
			}
		})
	}
}
