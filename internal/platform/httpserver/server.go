// Package httpserver assembles the HTTP API router, middleware stack,
// operational health endpoints, and JSON error conventions (README §§9, 11.5, 14.2).
package httpserver

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
)

// ReadinessCheck verifies that an external dependency (e.g. PostgreSQL, Redis) is reachable.
type ReadinessCheck struct {
	Name  string
	Check func(ctx context.Context) error
}

// Options configures the HTTP server and its router.
type Options struct {
	Port        int
	Version     string
	Commit      string
	Logger      *slog.Logger
	CORSOrigins []string
	// MaxBodyBytes caps request bodies on the product API (ingestion routes
	// will apply their own limit on their route group).
	MaxBodyBytes int64
	// HSTS enables Strict-Transport-Security; set only when served over TLS (production).
	HSTS            bool
	ReadinessChecks []ReadinessCheck
}

// NewHandler constructs the chi router with operational and /api/v1 routes.
func NewHandler(opts Options) http.Handler {
	r := chi.NewRouter()

	// Order matters: the request ID and security headers come first so every
	// response (including a recovered panic) carries them; the recoverer then
	// wraps everything that can fail after that.
	r.Use(RequestIDMiddleware)
	r.Use(SecurityHeadersMiddleware(opts.HSTS))
	r.Use(RecovererMiddleware(opts.Logger))
	r.Use(RequestLoggerMiddleware(opts.Logger))
	r.Use(CORSMiddleware(opts.CORSOrigins))
	r.Use(MaxBytesMiddleware(opts.MaxBodyBytes))

	r.NotFound(func(w http.ResponseWriter, req *http.Request) {
		WriteError(w, req, http.StatusNotFound, "RESOURCE_NOT_FOUND", "The requested resource was not found.")
	})
	r.MethodNotAllowed(func(w http.ResponseWriter, req *http.Request) {
		WriteError(w, req, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "The HTTP method is not allowed for this endpoint.")
	})

	// Operational endpoints outside /api/v1 (README §9.3).
	r.Get("/health/live", func(w http.ResponseWriter, _ *http.Request) {
		WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})

	r.Get("/health/ready", func(w http.ResponseWriter, req *http.Request) {
		ctx, cancel := context.WithTimeout(req.Context(), 3*time.Second)
		defer cancel()

		checks := make(map[string]string, len(opts.ReadinessChecks))
		healthy := true
		for _, c := range opts.ReadinessChecks {
			if err := c.Check(ctx); err != nil {
				healthy = false
				checks[c.Name] = "error"
				if opts.Logger != nil {
					opts.Logger.Warn("readiness check failed",
						slog.String("check", c.Name),
						slog.String("error", err.Error()),
					)
				}
			} else {
				checks[c.Name] = "ok"
			}
		}

		status := http.StatusOK
		overall := "ok"
		if !healthy {
			status = http.StatusServiceUnavailable
			overall = "degraded"
		}
		WriteJSON(w, status, map[string]any{
			"status": overall,
			"checks": checks,
		})
	})

	// Versioned product API (README §9).
	r.Route("/api/v1", func(api chi.Router) {
		api.Get("/status", func(w http.ResponseWriter, _ *http.Request) {
			WriteJSON(w, http.StatusOK, map[string]string{
				"service": "vigia",
				"status":  "ok",
				"version": opts.Version,
				"commit":  opts.Commit,
			})
		})
	})

	return r
}

// New creates an http.Server with explicit timeouts (never use zero defaults).
func New(opts Options) *http.Server {
	return &http.Server{
		Addr:              fmt.Sprintf(":%d", opts.Port),
		Handler:           NewHandler(opts),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
}
