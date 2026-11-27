package ratelimit

import (
	"log/slog"
	"math"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Yhanko/vigia/internal/platform/httpserver"
)

const failClosedRetryAfterSeconds = "5"

// MiddlewareOptions configures the HTTP rate-limiting middleware.
type MiddlewareOptions struct {
	Limiter    Limiter
	KeyPrefix  string
	Limit      int
	Window     time.Duration
	FailClosed bool
	Logger     *slog.Logger
}

// Middleware enforces a per-IP sliding-window rate limit, emitting standard
// RateLimit-* and Retry-After headers and the API error envelope on 429.
// When Redis is unavailable: FailClosed=true returns 503 + Retry-After (auth
// routes); FailClosed=false logs a warning and allows the request (status).
func Middleware(opts MiddlewareOptions) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if opts.Limiter == nil {
				if opts.FailClosed {
					w.Header().Set("Retry-After", failClosedRetryAfterSeconds)
					httpserver.WriteError(w, r, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", "Service temporarily unavailable.")
					return
				}
				next.ServeHTTP(w, r)
				return
			}

			key := opts.KeyPrefix + ":" + ClientIP(r)
			res, err := opts.Limiter.Allow(r.Context(), key, opts.Limit, opts.Window)
			if err != nil {
				if opts.FailClosed {
					if opts.Logger != nil {
						opts.Logger.Error("rate limiter unavailable; failing closed",
							slog.String("request_id", httpserver.RequestIDFromContext(r.Context())),
							slog.String("key_prefix", opts.KeyPrefix),
							slog.Any("error", err),
						)
					}
					w.Header().Set("Retry-After", failClosedRetryAfterSeconds)
					httpserver.WriteError(w, r, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", "Service temporarily unavailable.")
					return
				}
				if opts.Logger != nil {
					opts.Logger.Warn("rate limiter unavailable; failing open",
						slog.String("request_id", httpserver.RequestIDFromContext(r.Context())),
						slog.String("key_prefix", opts.KeyPrefix),
						slog.Any("error", err),
					)
				}
				next.ServeHTTP(w, r)
				return
			}

			WriteHeaders(w, res)
			if !res.Allowed {
				httpserver.WriteError(w, r, http.StatusTooManyRequests, "RATE_LIMIT_EXCEEDED", "Rate limit exceeded. Please try again later.")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// WriteHeaders writes RateLimit-Limit, RateLimit-Remaining, RateLimit-Reset,
// and (when blocked) Retry-After headers.
func WriteHeaders(w http.ResponseWriter, res Result) {
	resetSec := ceilSeconds(res.ResetAfter)
	w.Header().Set("RateLimit-Limit", strconv.Itoa(res.Limit))
	w.Header().Set("RateLimit-Remaining", strconv.Itoa(max(0, res.Remaining)))
	w.Header().Set("RateLimit-Reset", strconv.Itoa(resetSec))
	if !res.Allowed {
		retrySec := ceilSeconds(res.RetryAfter)
		if retrySec < 1 {
			retrySec = 1
		}
		w.Header().Set("Retry-After", strconv.Itoa(retrySec))
	}
}

// ClientIP extracts the remote IP address without port from r.RemoteAddr.
func ClientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(strings.TrimSpace(r.RemoteAddr))
	if err == nil && host != "" {
		return host
	}
	if addr := strings.TrimSpace(r.RemoteAddr); addr != "" {
		return addr
	}
	return "unknown"
}

func ceilSeconds(d time.Duration) int {
	if d <= 0 {
		return 0
	}
	return int(math.Ceil(d.Seconds()))
}
