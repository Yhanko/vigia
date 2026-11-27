package httpserver

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestCursorEncodeDecode(t *testing.T) {
	now := time.Date(2026, 11, 27, 17, 0, 0, 123000000, time.UTC)
	c := Cursor{CreatedAt: now, ID: "550E8400-E29B-41D4-A716-446655440000"}
	tok := EncodeCursor(c)

	got, err := DecodeCursor(tok)
	if err != nil {
		t.Fatalf("DecodeCursor() error = %v", err)
	}
	if !got.CreatedAt.Equal(now) || got.ID != "550e8400-e29b-41d4-a716-446655440000" {
		t.Fatalf("DecodeCursor() = %+v, want (%v, lowercase uuid)", got, now)
	}

	for _, bad := range []string{"", "!!!not-base64!!!", "e30", "eyJ0IjoiMjAyNi0xMS0yN1QxNzowMDowMFoiLCJpZCI6ImJhZCJ9"} {
		if _, err := DecodeCursor(bad); !errors.Is(err, ErrInvalidCursor) {
			t.Fatalf("DecodeCursor(%q) err = %v, want ErrInvalidCursor", bad, err)
		}
	}

	if n, err := ParseLimit("", 20, 100); err != nil || n != 20 {
		t.Fatalf("ParseLimit(empty) = (%d, %v), want (20, nil)", n, err)
	}
	if _, err := ParseLimit("101", 20, 100); err == nil {
		t.Fatal("ParseLimit(101) expected error")
	}
}

type memIdemStore struct {
	items map[string]IdempotencyRecord
}

func (m *memIdemStore) Get(_ context.Context, key string) (IdempotencyRecord, error) {
	v, ok := m.items[key]
	if !ok {
		return IdempotencyRecord{}, ErrIdempotencyMiss
	}
	return v, nil
}

func (m *memIdemStore) Set(_ context.Context, key string, rec IdempotencyRecord, _ time.Duration) error {
	m.items[key] = rec
	return nil
}

func TestIdempotencyMiddlewareReplayAndConflict(t *testing.T) {
	store := &memIdemStore{items: make(map[string]IdempotencyRecord)}
	calls := 0
	h := IdempotencyMiddleware(store, time.Hour)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		WriteJSON(w, http.StatusCreated, map[string]int{"call": calls})
	}))

	// 1st POST executes handler.
	req1 := httptest.NewRequest(http.MethodPost, "/api/v1/organizations", strings.NewReader(`{"name":"Acme"}`))
	req1.Header.Set(IdempotencyKeyHeader, "idem-key-1")
	rec1 := httptest.NewRecorder()
	h.ServeHTTP(rec1, req1)
	if rec1.Code != http.StatusCreated || calls != 1 {
		t.Fatalf("1st POST = (%d, calls=%d), want (201, 1)", rec1.Code, calls)
	}

	// 2nd POST with same key + same body replays cached response without calling handler.
	req2 := httptest.NewRequest(http.MethodPost, "/api/v1/organizations", strings.NewReader(`{"name":"Acme"}`))
	req2.Header.Set(IdempotencyKeyHeader, "idem-key-1")
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusCreated || calls != 1 || rec2.Header().Get("Idempotency-Replayed") != "true" {
		t.Fatalf("replayed POST = (%d, calls=%d, hdr=%q)", rec2.Code, calls, rec2.Header().Get("Idempotency-Replayed"))
	}

	// 3rd POST with same key + different body → 409 IDEMPOTENCY_CONFLICT.
	req3 := httptest.NewRequest(http.MethodPost, "/api/v1/organizations", strings.NewReader(`{"name":"Different"}`))
	req3.Header.Set(IdempotencyKeyHeader, "idem-key-1")
	rec3 := httptest.NewRecorder()
	h.ServeHTTP(rec3, req3)
	if rec3.Code != http.StatusConflict {
		t.Fatalf("conflict POST = %d, want 409", rec3.Code)
	}
	var env ErrorResponse
	_ = json.NewDecoder(rec3.Body).Decode(&env)
	if env.Error.Code != "IDEMPOTENCY_CONFLICT" {
		t.Fatalf("error.code = %q, want IDEMPOTENCY_CONFLICT", env.Error.Code)
	}
}
