package httpserver

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"
)

const (
	// IdempotencyKeyHeader is the standard client-supplied idempotency header (README §9.1).
	IdempotencyKeyHeader = "Idempotency-Key"
	maxIdempotencyKeyLen = 128
	defaultIdempotencyTT = 24 * time.Hour
	defaultLockTTL       = 30 * time.Second
)

// ErrIdempotencyMiss is returned when no entry exists for a key.
var ErrIdempotencyMiss = errors.New("httpserver: idempotency key not found")

// IdempotencyRecord caches the body hash and HTTP response for a POST request.
type IdempotencyRecord struct {
	InProgress bool   `json:"in_progress,omitempty"`
	BodyHash   string `json:"body_hash"`
	Status     int    `json:"status,omitempty"`
	Body       []byte `json:"body,omitempty"`
}

// IdempotencyStore persists IdempotencyRecords with atomic in-progress locking (e.g. Redis).
type IdempotencyStore interface {
	// Acquire atomically looks up key or reserves it with an in-progress marker (SET NX).
	// If an entry already exists, returns (rec, false, nil) when completed or (nil, true, nil) when in-progress.
	// If reserved cleanly for this caller, returns (nil, false, nil).
	Acquire(ctx context.Context, key, bodyHash string, lockTTL time.Duration) (existing *IdempotencyRecord, inProgress bool, err error)
	// Complete replaces the in-progress marker with the final cached response for ttl.
	Complete(ctx context.Context, key string, rec IdempotencyRecord, ttl time.Duration) error
	// Release deletes the in-progress marker when a handler fails so the caller can retry.
	Release(ctx context.Context, key string) error
}

// IdempotencyOptions configures principal-scoped Idempotency-Key enforcement (CTO #32).
type IdempotencyOptions struct {
	Store IdempotencyStore
	// Principal extracts the authenticated caller scope ("user:<id>" or "cred:<id>").
	// If nil or returns ok=false, idempotency caching is skipped (never share cache across anonymous callers).
	Principal func(r *http.Request) (string, bool)
	// AllowRoute optionally restricts which POST routes participate in idempotency.
	// Defaults to IsIdempotentCreationRoute (organizations, invitations, teams, projects, environments),
	// explicitly excluding all /auth/* and /credentials/* secret-bearing routes.
	AllowRoute func(r *http.Request) bool
	TTL        time.Duration
	LockTTL    time.Duration
}

// IsIdempotentCreationRoute returns true ONLY for safe creation POST endpoints
// (organizations, invitations, teams, projects, environments) and ALWAYS false
// for /auth/* and /credentials/* routes that may return secrets (CTO #32).
func IsIdempotentCreationRoute(r *http.Request) bool {
	if r.Method != http.MethodPost {
		return false
	}
	p := r.URL.Path
	// Explicit denylist for secret-bearing paths (defense in depth).
	if strings.HasPrefix(p, "/api/v1/auth/") || strings.Contains(p, "/credentials") {
		return false
	}
	if p == "/api/v1/organizations" {
		return true
	}
	if !strings.HasPrefix(p, "/api/v1/organizations/") {
		return false
	}
	// /api/v1/organizations/{orgId}/{invitations|teams|projects}
	// /api/v1/organizations/{orgId}/projects/{projectId}/environments
	parts := strings.Split(strings.TrimPrefix(p, "/api/v1/organizations/"), "/")
	if len(parts) == 2 {
		return parts[1] == "invitations" || parts[1] == "teams" || parts[1] == "projects"
	}
	if len(parts) == 4 && parts[1] == "projects" && parts[3] == "environments" {
		return true
	}
	return false
}

// IdempotencyMiddleware enforces principal-scoped Idempotency-Key semantics on
// allowed POST creation routes AFTER authentication (CTO #32):
//   - Cache key: idem:<principal>:<method>:<path>:<sha256(Idempotency-Key)>
//   - Concurrent in-flight request -> 409 IDEMPOTENCY_IN_PROGRESS
//   - Same principal + same key + same body -> replays cached response with Idempotency-Replayed: true
//   - Same principal + same key + different body -> 409 IDEMPOTENCY_CONFLICT
//   - Different principal + same key -> independent cache entry (zero cross-user leakage)
//   - Secret-bearing routes (/auth/*, /credentials*) -> never cached.
func IdempotencyMiddleware(opts IdempotencyOptions) func(http.Handler) http.Handler {
	ttl := opts.TTL
	if ttl <= 0 {
		ttl = defaultIdempotencyTT
	}
	lockTTL := opts.LockTTL
	if lockTTL <= 0 {
		lockTTL = defaultLockTTL
	}
	allowRoute := opts.AllowRoute
	if allowRoute == nil {
		allowRoute = IsIdempotentCreationRoute
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if opts.Store == nil || opts.Principal == nil || !allowRoute(r) {
				next.ServeHTTP(w, r)
				return
			}
			// Never cache secret-bearing paths even if a custom AllowRoute is supplied.
			if strings.HasPrefix(r.URL.Path, "/api/v1/auth/") || strings.Contains(r.URL.Path, "/credentials") {
				next.ServeHTTP(w, r)
				return
			}

			rawKey := strings.TrimSpace(r.Header.Get(IdempotencyKeyHeader))
			if rawKey == "" {
				next.ServeHTTP(w, r)
				return
			}
			if len(rawKey) > maxIdempotencyKeyLen || strings.ContainsAny(rawKey, "\r\n\x00 ") {
				WriteError(w, r, http.StatusBadRequest, "VALIDATION_FAILED", "Invalid Idempotency-Key header.")
				return
			}

			principal, ok := opts.Principal(r)
			if !ok || strings.TrimSpace(principal) == "" {
				// Unauthenticated callers never participate in idempotency cache.
				next.ServeHTTP(w, r)
				return
			}

			bodyBytes, err := io.ReadAll(r.Body)
			if err != nil {
				var maxErr *http.MaxBytesError
				if errors.As(err, &maxErr) {
					WriteError(w, r, http.StatusRequestEntityTooLarge, "PAYLOAD_TOO_LARGE", "Request body exceeds the allowed size.")
					return
				}
				WriteError(w, r, http.StatusBadRequest, "INVALID_JSON", "Failed to read request body.")
				return
			}
			r.Body = io.NopCloser(bytes.NewReader(bodyBytes))

			bodySum := sha256.Sum256(bodyBytes)
			bodyHash := hex.EncodeToString(bodySum[:])
			keySum := sha256.Sum256([]byte(rawKey))
			cacheKey := "idem:" + principal + ":" + r.Method + ":" + r.URL.Path + ":" + hex.EncodeToString(keySum[:])

			existing, inProgress, err := opts.Store.Acquire(r.Context(), cacheKey, bodyHash, lockTTL)
			if err != nil {
				// Fail open on transient store errors rather than blocking writes.
				next.ServeHTTP(w, r)
				return
			}
			if inProgress {
				WriteError(w, r, http.StatusConflict, "IDEMPOTENCY_IN_PROGRESS", "A request with this Idempotency-Key is currently in progress.")
				return
			}
			if existing != nil {
				if existing.BodyHash != bodyHash {
					WriteError(w, r, http.StatusConflict, "IDEMPOTENCY_CONFLICT", "Idempotency-Key was already used with a different request payload.")
					return
				}
				w.Header().Set("Content-Type", "application/json; charset=utf-8")
				w.Header().Set("Idempotency-Replayed", "true")
				w.WriteHeader(existing.Status)
				_, _ = w.Write(existing.Body) //nolint:gosec // G705: replays server-generated JSON with Content-Type: application/json and nosniff
				return
			}

			capW := &responseCaptureWriter{ResponseWriter: w, status: http.StatusOK}
			completed := false
			defer func() {
				if !completed {
					_ = opts.Store.Release(r.Context(), cacheKey)
				}
			}()

			next.ServeHTTP(capW, r)

			if capW.status >= 200 && capW.status < 300 {
				if err := opts.Store.Complete(r.Context(), cacheKey, IdempotencyRecord{
					BodyHash: bodyHash,
					Status:   capW.status,
					Body:     capW.buf.Bytes(),
				}, ttl); err == nil {
					completed = true
				}
			}
		})
	}
}

type responseCaptureWriter struct {
	http.ResponseWriter
	status int
	buf    bytes.Buffer
}

func (c *responseCaptureWriter) WriteHeader(code int) {
	c.status = code
	c.ResponseWriter.WriteHeader(code)
}

func (c *responseCaptureWriter) Write(p []byte) (int, error) {
	_, _ = c.buf.Write(p)
	return c.ResponseWriter.Write(p)
}

// MarshalIdempotencyRecord encodes an IdempotencyRecord as JSON.
func MarshalIdempotencyRecord(r IdempotencyRecord) ([]byte, error) {
	return json.Marshal(r)
}

// UnmarshalIdempotencyRecord decodes an IdempotencyRecord from JSON.
func UnmarshalIdempotencyRecord(data []byte) (IdempotencyRecord, error) {
	var r IdempotencyRecord
	err := json.Unmarshal(data, &r)
	return r, err
}
