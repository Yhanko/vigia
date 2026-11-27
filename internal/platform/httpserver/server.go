// Package httpserver assembles the public HTTP API router, the internal admin
// operational router (/health/live, /health/ready, future /metrics), middleware
// stacks, and JSON error conventions (README §§9, 11.5, 14.2).
package httpserver

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/Yhanko/vigia/internal/api"
)

// ReadinessCheck verifies that an external dependency (e.g. PostgreSQL, Redis) is reachable.
type ReadinessCheck struct {
	Name  string
	Check func(ctx context.Context) error
}

// Options configures the public HTTP API server and its router.
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
	HSTS bool
	// APIRateLimit optionally wraps the /api/v1 route group with base per-IP rate limiting.
	APIRateLimit func(http.Handler) http.Handler
	// APIAuth optionally wraps the /api/v1 route group with session and CSRF middleware.
	APIAuth func(http.Handler) http.Handler
	// APIServer provides the composed OpenAPI ServerInterface mounted under /api/v1
	// via api.HandlerWithOptions (CTO #6, #18). Domain handlers live in internal/modules/*.
	APIServer api.ServerInterface
}

// AdminOptions configures the internal operational listener (ADMIN_PORT),
// exposing /health/live, /health/ready, and future /metrics (README §9.3).
type AdminOptions struct {
	Port            int
	Logger          *slog.Logger
	HSTS            bool
	ReadinessChecks []ReadinessCheck
}

// NewHandler constructs the public chi router with /api/v1 routes.
// Operational endpoints (/health/*) are intentionally NOT mounted here.
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

	// Versioned product API (README §9), mounted via oapi-codegen ServerInterface (CTO #18).
	if opts.APIServer != nil {
		r.Route("/api/v1", func(v1 chi.Router) {
			if opts.APIRateLimit != nil {
				v1.Use(opts.APIRateLimit)
			}
			if opts.APIAuth != nil {
				v1.Use(opts.APIAuth)
			}
			api.HandlerWithOptions(opts.APIServer, api.ChiServerOptions{
				BaseRouter: v1,
				ErrorHandlerFunc: func(w http.ResponseWriter, req *http.Request, err error) {
					var reqHdr *api.RequiredHeaderError
					if errors.As(err, &reqHdr) && strings.EqualFold(reqHdr.ParamName, "X-CSRF-Token") {
						WriteError(w, req, http.StatusForbidden, "CSRF_INVALID", "Invalid or missing CSRF token.")
						return
					}
					WriteError(w, req, http.StatusBadRequest, "VALIDATION_FAILED", "Invalid request parameters.")
				},
			})
		})
	}

	return r
}

// NewAdminHandler constructs the internal operational router (README §9.3).
// It applies request ID, security headers, recoverer, and logging, without CORS.
func NewAdminHandler(opts AdminOptions) http.Handler {
	r := chi.NewRouter()

	r.Use(RequestIDMiddleware)
	r.Use(SecurityHeadersMiddleware(opts.HSTS))
	r.Use(RecovererMiddleware(opts.Logger))
	r.Use(RequestLoggerMiddleware(opts.Logger))

	r.NotFound(func(w http.ResponseWriter, req *http.Request) {
		WriteError(w, req, http.StatusNotFound, "RESOURCE_NOT_FOUND", "The requested resource was not found.")
	})
	r.MethodNotAllowed(func(w http.ResponseWriter, req *http.Request) {
		WriteError(w, req, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "The HTTP method is not allowed for this endpoint.")
	})

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

	return r
}

func newServer(port int, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:              fmt.Sprintf(":%d", port),
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
}

// New creates the public API http.Server with explicit timeouts.
func New(opts Options) *http.Server {
	return newServer(opts.Port, NewHandler(opts))
}

// NewAdmin creates the internal admin http.Server with the same explicit timeouts.
func NewAdmin(opts AdminOptions) *http.Server {
	return newServer(opts.Port, NewAdminHandler(opts))
}
