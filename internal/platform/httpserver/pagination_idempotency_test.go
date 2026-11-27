package httpserver_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Yhanko/vigia/internal/platform/httpserver"
)

func TestCursorRoundTripAndTamperRejection(t *testing.T) {
	t.Parallel()

	ts := time.Date(2026, 11, 27, 14, 30, 0, 123456000, time.UTC)
	in := httpserver.Cursor{
		CreatedAt: ts,
		ID:        "019a2f7d-8b4c-7e10-8345-6789abcdef01",
	}
	encoded := httpserver.EncodeCursor(in)
	if encoded == "" {
		t.Fatal("expected non-empty encoded cursor")
	}

	got, err := httpserver.DecodeCursor(encoded)
	if err != nil {
		t.Fatalf("DecodeCursor: %v", err)
	}
	if !got.CreatedAt.Equal(in.CreatedAt) || got.ID != in.ID {
		t.Fatalf("round-trip mismatch: got=%+v want=%+v", got, in)
	}

	for _, bad := range []string{"", "not-base64!!!", "e30", "eyJjIjoiMjAyNiIsImkiOiIifQ"} {
		if _, err := httpserver.DecodeCursor(bad); err == nil {
			t.Errorf("DecodeCursor(%q) succeeded, want error", bad)
		}
	}
}

type memIdempotencyStore struct {
	mu   sync.Mutex
	data map[string]httpserver.IdempotencyRecord
}

func newMemIdem() *memIdempotencyStore {
	return &memIdempotencyStore{data: make(map[string]httpserver.IdempotencyRecord)}
}

func (m *memIdempotencyStore) Acquire(_ context.Context, key, bodyHash string, _ time.Duration) (*httpserver.IdempotencyRecord, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if rec, ok := m.data[key]; ok {
		if rec.InProgress {
			return nil, true, nil
		}
		cp := rec
		return &cp, false, nil
	}
	m.data[key] = httpserver.IdempotencyRecord{InProgress: true, BodyHash: bodyHash}
	return nil, false, nil
}

func (m *memIdempotencyStore) Complete(_ context.Context, key string, rec httpserver.IdempotencyRecord, _ time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	rec.InProgress = false
	m.data[key] = rec
	return nil
}

func (m *memIdempotencyStore) Release(_ context.Context, key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.data, key)
	return nil
}

func TestIdempotencyMiddleware_PrincipalIsolationAndOptOut_CTO32(t *testing.T) {
	t.Parallel()

	store := newMemIdem()
	var calls atomic.Int32

	mw := httpserver.IdempotencyMiddleware(httpserver.IdempotencyOptions{
		Store: store,
		Principal: func(r *http.Request) (string, bool) {
			u := r.Header.Get("X-Test-User")
			if u == "" {
				return "", false
			}
			return "user:" + u, true
		},
		TTL: time.Hour,
	})

	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := calls.Add(1)
		httpserver.WriteJSON(w, http.StatusCreated, map[string]any{
			"call": n,
			"user": r.Header.Get("X-Test-User"),
		})
	}))

	// 1. User A first call -> 201, executed.
	req1 := httptest.NewRequest(http.MethodPost, "/api/v1/organizations", strings.NewReader(`{"name":"Acme"}`))
	req1.Header.Set("Idempotency-Key", "shared-key-1")
	req1.Header.Set("X-Test-User", "user-a")
	rec1 := httptest.NewRecorder()
	handler.ServeHTTP(rec1, req1)
	if rec1.Code != http.StatusCreated || calls.Load() != 1 {
		t.Fatalf("first call: status=%d calls=%d", rec1.Code, calls.Load())
	}

	// 2. User A replay (same key, same body) -> 201 replayed, handler NOT called again.
	req2 := httptest.NewRequest(http.MethodPost, "/api/v1/organizations", strings.NewReader(`{"name":"Acme"}`))
	req2.Header.Set("Idempotency-Key", "shared-key-1")
	req2.Header.Set("X-Test-User", "user-a")
	rec2 := httptest.NewRecorder()
	handler.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusCreated || rec2.Header().Get("Idempotency-Replayed") != "true" || calls.Load() != 1 {
		t.Fatalf("replay: status=%d replayed=%q calls=%d", rec2.Code, rec2.Header().Get("Idempotency-Replayed"), calls.Load())
	}

	// 3. NEGATIVE: User B uses the EXACT same Idempotency-Key -> MUST NOT get User A's cached response!
	req3 := httptest.NewRequest(http.MethodPost, "/api/v1/organizations", strings.NewReader(`{"name":"Acme"}`))
	req3.Header.Set("Idempotency-Key", "shared-key-1")
	req3.Header.Set("X-Test-User", "user-b")
	rec3 := httptest.NewRecorder()
	handler.ServeHTTP(rec3, req3)
	if rec3.Code != http.StatusCreated || rec3.Header().Get("Idempotency-Replayed") != "" || calls.Load() != 2 {
		t.Fatalf("user-b isolation failed: status=%d replayed=%q calls=%d", rec3.Code, rec3.Header().Get("Idempotency-Replayed"), calls.Load())
	}
	if !strings.Contains(rec3.Body.String(), `"user":"user-b"`) {
		t.Fatalf("user-b got wrong response body: %s", rec3.Body.String())
	}

	// 4. Same user, same key, different body -> 409 IDEMPOTENCY_CONFLICT.
	req4 := httptest.NewRequest(http.MethodPost, "/api/v1/organizations", strings.NewReader(`{"name":"Different"}`))
	req4.Header.Set("Idempotency-Key", "shared-key-1")
	req4.Header.Set("X-Test-User", "user-a")
	rec4 := httptest.NewRecorder()
	handler.ServeHTTP(rec4, req4)
	if rec4.Code != http.StatusConflict || !strings.Contains(rec4.Body.String(), "IDEMPOTENCY_CONFLICT") {
		t.Fatalf("conflict: status=%d body=%s", rec4.Code, rec4.Body.String())
	}

	// 5. NEGATIVE: Secret-bearing routes (/auth/*, /credentials) MUST NEVER be cached!
	beforeEntries := len(store.data)
	for _, secretPath := range []string{
		"/api/v1/auth/mfa/setup",
		"/api/v1/auth/mfa/verify",
		"/api/v1/organizations/11111111-1111-4111-8111-111111111111/projects/22222222-2222-4222-8222-222222222222/credentials",
		"/api/v1/organizations/11111111-1111-4111-8111-111111111111/credentials/33333333-3333-4333-8333-333333333333/rotate",
	} {
		req := httptest.NewRequest(http.MethodPost, secretPath, strings.NewReader(`{}`))
		req.Header.Set("Idempotency-Key", "secret-route-key")
		req.Header.Set("X-Test-User", "user-a")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusCreated {
			t.Fatalf("secret route %s status=%d", secretPath, rec.Code)
		}
	}
	if len(store.data) != beforeEntries {
		t.Fatalf("secret-bearing routes wrote %d entries into idempotency cache, want 0", len(store.data)-beforeEntries)
	}

	// 6. Concurrent in-flight request -> 409 IDEMPOTENCY_IN_PROGRESS.
	blockCh := make(chan struct{})
	startedCh := make(chan struct{})
	slowHandler := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		close(startedCh)
		<-blockCh
		httpserver.WriteJSON(w, http.StatusCreated, map[string]string{"ok": "yes"})
	}))
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		rA := httptest.NewRequest(http.MethodPost, "/api/v1/organizations", strings.NewReader(`{"name":"Slow"}`))
		rA.Header.Set("Idempotency-Key", "in-flight-key")
		rA.Header.Set("X-Test-User", "user-a")
		slowHandler.ServeHTTP(httptest.NewRecorder(), rA)
	}()
	<-startedCh
	rB := httptest.NewRequest(http.MethodPost, "/api/v1/organizations", strings.NewReader(`{"name":"Slow"}`))
	rB.Header.Set("Idempotency-Key", "in-flight-key")
	rB.Header.Set("X-Test-User", "user-a")
	recB := httptest.NewRecorder()
	slowHandler.ServeHTTP(recB, rB)
	close(blockCh)
	wg.Wait()
	if recB.Code != http.StatusConflict || !strings.Contains(recB.Body.String(), "IDEMPOTENCY_IN_PROGRESS") {
		t.Fatalf("concurrent in-flight: status=%d body=%s", recB.Code, recB.Body.String())
	}
}
