package identity

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/Yhanko/vigia/internal/modules/identity/session"
	"github.com/Yhanko/vigia/internal/platform/clock"
	"github.com/Yhanko/vigia/internal/platform/httpserver"
)

type ctxKeyActiveSession struct{}

// ActiveSessionFromContext retrieves the authenticated ActiveSession attached
// by SessionMiddleware, if present.
func ActiveSessionFromContext(ctx context.Context) (ActiveSession, bool) {
	s, ok := ctx.Value(ctxKeyActiveSession{}).(ActiveSession)
	return s, ok
}

// WithActiveSession returns a child context carrying active.
func WithActiveSession(ctx context.Context, active ActiveSession) context.Context {
	return context.WithValue(ctx, ctxKeyActiveSession{}, active)
}

// SessionMiddleware authenticates cookie-based requests, rejecting missing
// cookies with 401 UNAUTHENTICATED and expired/revoked/inactive-user sessions
// with 401 SESSION_EXPIRED (ADR-005, CTO #14).
func SessionMiddleware(svc *Service, sessions *session.Codec) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			active, ok := authenticateCookie(w, r, svc, sessions)
			if !ok {
				return
			}
			next.ServeHTTP(w, r.WithContext(WithActiveSession(r.Context(), active)))
		})
	}
}

// CSRFMiddleware enforces strict Origin allowlist + constant-time X-CSRF-Token
// validation on state-changing cookie-authenticated requests (ADR-005 §3.1).
func CSRFMiddleware(sessions *session.Codec, allowedOrigins []string) func(http.Handler) http.Handler {
	allowed := makeOriginSet(allowedOrigins)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.Method {
			case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
				if !isAllowedOrigin(r.Header.Get("Origin"), allowed) {
					httpserver.WriteError(w, r, http.StatusForbidden, "CSRF_INVALID", "Invalid or missing request origin.")
					return
				}
				active, ok := ActiveSessionFromContext(r.Context())
				if !ok {
					httpserver.WriteError(w, r, http.StatusUnauthorized, "UNAUTHENTICATED", "Authentication is required.")
					return
				}
				token := r.Header.Get("X-CSRF-Token")
				if !sessions.VerifyCSRFToken(token, active.CSRFTokenHash) {
					httpserver.WriteError(w, r, http.StatusForbidden, "CSRF_INVALID", "Invalid or missing CSRF token.")
					return
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}

// RequireRecentAuth enforces a fresh authentication window (default 10m) on
// high-risk operations (ADR-005 §3.1, docs/plans/1.2-identity.md §7.4).
func RequireRecentAuth(clk clock.Clock, window time.Duration) func(http.Handler) http.Handler {
	if clk == nil {
		clk = clock.System{}
	}
	if window <= 0 {
		window = session.DefaultReauthWindow
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			active, ok := ActiveSessionFromContext(r.Context())
			if !ok {
				httpserver.WriteError(w, r, http.StatusUnauthorized, "UNAUTHENTICATED", "Authentication is required.")
				return
			}
			if clk.Now().UTC().Sub(active.LastAuthAt) > window {
				httpserver.WriteError(w, r, http.StatusUnauthorized, "REAUTH_REQUIRED", "Recent authentication is required for this operation.")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// CheckPrivilegedMFA enforces MFA_REQUIRED_FOR_PRIVILEGED for owner/admin roles (§7.4).
func CheckPrivilegedMFA(enforce bool, active ActiveSession, role string) bool {
	if !enforce {
		return true
	}
	if (role == "owner" || role == "admin") && !active.UserMFAEnabled {
		return false
	}
	return true
}

func authenticateCookie(w http.ResponseWriter, r *http.Request, svc *Service, sessions *session.Codec) (ActiveSession, bool) {
	ck, err := r.Cookie(sessions.CookieName())
	if err != nil || strings.TrimSpace(ck.Value) == "" {
		httpserver.WriteError(w, r, http.StatusUnauthorized, "UNAUTHENTICATED", "Authentication is required.")
		return ActiveSession{}, false
	}
	active, err := svc.AuthenticateSession(r.Context(), ck.Value)
	if err != nil {
		if errors.Is(err, ErrSessionExpired) {
			httpserver.WriteError(w, r, http.StatusUnauthorized, "SESSION_EXPIRED", "Session has expired or been revoked.")
			return ActiveSession{}, false
		}
		httpserver.WriteError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "An internal error occurred.")
		return ActiveSession{}, false
	}
	return active, true
}

func makeOriginSet(origins []string) map[string]struct{} {
	set := make(map[string]struct{}, len(origins))
	for _, o := range origins {
		o = strings.TrimSpace(o)
		if o != "" {
			set[o] = struct{}{}
		}
	}
	return set
}

func isAllowedOrigin(origin string, allowed map[string]struct{}) bool {
	origin = strings.TrimSpace(origin)
	if origin == "" {
		return false
	}
	_, ok := allowed[origin]
	return ok
}
