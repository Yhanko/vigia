package credentials

import (
	"context"
	"net/http"
	"net/netip"
	"strings"

	"github.com/Yhanko/vigia/internal/platform/httpserver"
)

// AccessScope defines the broad endpoint class for API credential authorization.
type AccessScope string

const (
	ScopeIngest AccessScope = "ingest"
	ScopeRead   AccessScope = "read"
	ScopeAdmin  AccessScope = "admin"
)

type credContextKey struct{}

// AuthenticatedCredential holds the verified tenant and project context for an API credential.
type AuthenticatedCredential struct {
	ID             string
	OrganizationID string
	ProjectID      string
	EnvironmentID  string
	Kind           string
	Scopes         []string
}

// CredentialFromContext extracts the authenticated API credential attached by Middleware.
func CredentialFromContext(ctx context.Context) (AuthenticatedCredential, bool) {
	c, ok := ctx.Value(credContextKey{}).(AuthenticatedCredential)
	return c, ok
}

// Authenticator is the consumer-defined interface used by the HTTP middleware.
type Authenticator interface {
	AuthenticateSecret(ctx context.Context, rawKey, clientIP string) (AuthenticatedCredential, error)
}

// AuthMiddleware authenticates an API credential from Authorization: Bearer <key>
// (or X-Vigia-Key for ingest) and enforces strict kind/scope separation (ADR-005 §3.2):
//   - vg_ing_ (ingest): allowed ONLY on ScopeIngest; blocked on ScopeRead/ScopeAdmin (403 INSUFFICIENT_SCOPE).
//   - vg_cli_ (client): allowed ONLY on ScopeRead; blocked on ScopeIngest/ScopeAdmin (403 INSUFFICIENT_SCOPE).
//   - dsn: blocked on all /api/v1/* endpoints (403 INSUFFICIENT_SCOPE).
func AuthMiddleware(auth Authenticator, required AccessScope, trustedProxies []netip.Prefix) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			rawKey := extractRawCredential(r, required)
			if rawKey == "" {
				httpserver.WriteError(w, r, http.StatusUnauthorized, "UNAUTHORIZED", "Missing or invalid API credential.")
				return
			}

			// Explicit DSN block on /api/v1/* (32-hex DSN keys cannot access API routes).
			if len(rawKey) == DSNKeyLength && isLowerHex(rawKey) {
				httpserver.WriteError(w, r, http.StatusForbidden, "INSUFFICIENT_SCOPE", "DSN keys cannot access this endpoint.")
				return
			}

			clientIP := httpserver.ClientIP(r, trustedProxies)
			cred, err := auth.AuthenticateSecret(r.Context(), rawKey, clientIP)
			if err != nil {
				httpserver.WriteError(w, r, http.StatusUnauthorized, "UNAUTHORIZED", "Invalid, expired, or revoked API credential.")
				return
			}

			if !KindAllowsScope(cred.Kind, required) {
				httpserver.WriteError(w, r, http.StatusForbidden, "INSUFFICIENT_SCOPE", "API credential kind is not permitted for this endpoint.")
				return
			}

			ctx := context.WithValue(r.Context(), credContextKey{}, cred)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// KindAllowsScope enforces ADR-005 §3.2 strict credential kind separation.
func KindAllowsScope(kind string, required AccessScope) bool {
	switch required {
	case ScopeIngest:
		return kind == KindIngest
	case ScopeRead:
		return kind == KindClient
	case ScopeAdmin:
		// Admin endpoints require human session auth; API credentials cannot perform admin actions.
		return false
	default:
		return false
	}
}

func extractRawCredential(r *http.Request, required AccessScope) string {
	if authz := r.Header.Get("Authorization"); authz != "" {
		const prefix = "Bearer "
		if strings.HasPrefix(authz, prefix) {
			return strings.TrimSpace(authz[len(prefix):])
		}
	}
	if required == ScopeIngest {
		if k := strings.TrimSpace(r.Header.Get("X-Vigia-Key")); k != "" {
			return k
		}
	}
	return ""
}
