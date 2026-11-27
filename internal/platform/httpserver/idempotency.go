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
)

// ErrIdempotencyMiss is returned by IdempotencyStore.Get when no entry exists.
var ErrIdempotencyMiss = errors.New("httpserver: idempotency key not found")

// IdempotencyRecord caches the body hash and HTTP response for a POST request.
type IdempotencyRecord struct {
	BodyHash string `json:"body_hash"`
	Status   int    `json:"status"`
	Body     []byte `json:"body"`
}

// IdempotencyStore persists IdempotencyRecords with TTL (e.g. Redis).
type IdempotencyStore interface {
	Get(ctx context.Context, key string) (IdempotencyRecord, error)
	Set(ctx context.Context, key string, rec IdempotencyRecord, ttl time.Duration) error
}

// IdempotencyMiddleware enforces Idempotency-Key semantics on POST requests:
//   - same key + same body hash → replays cached status & JSON response;
//   - same key + different body hash → 409 IDEMPOTENCY_CONFLICT.
func IdempotencyMiddleware(store IdempotencyStore, ttl time.Duration) func(http.Handler) http.Handler {
	if ttl <= 0 {
		ttl = defaultIdempotencyTT
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if store == nil || r.Method != http.MethodPost {
				next.ServeHTTP(w, r)
				return
			}
			key := strings.TrimSpace(r.Header.Get(IdempotencyKeyHeader))
			if key == "" {
				next.ServeHTTP(w, r)
				return
			}
			if len(key) > maxIdempotencyKeyLen || strings.ContainsAny(key, "\r\n\x00 ") {
				WriteError(w, r, http.StatusBadRequest, "VALIDATION_FAILED", "Invalid Idempotency-Key header.")
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

			sum := sha256.Sum256(bodyBytes)
			bodyHash := hex.EncodeToString(sum[:])
			cacheKey := "idem:" + r.URL.Path + ":" + key

			if cached, err := store.Get(r.Context(), cacheKey); err == nil {
				if cached.BodyHash != bodyHash {
					WriteError(w, r, http.StatusConflict, "IDEMPOTENCY_CONFLICT", "Idempotency-Key was already used with a different request payload.")
					return
				}
				w.Header().Set("Content-Type", "application/json; charset=utf-8")
				w.Header().Set("Idempotency-Replayed", "true")
				w.WriteHeader(cached.Status)
				_, _ = w.Write(cached.Body)
				return
			}

			capW := &responseCaptureWriter{ResponseWriter: w, status: http.StatusOK}
			next.ServeHTTP(capW, r)

			if capW.status >= 200 && capW.status < 300 {
				_ = store.Set(r.Context(), cacheKey, IdempotencyRecord{
					BodyHash: bodyHash,
					Status:   capW.status,
					Body:     capW.buf.Bytes(),
				}, ttl)
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
