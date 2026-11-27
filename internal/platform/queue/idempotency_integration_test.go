//go:build integration

package queue_test

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/Yhanko/vigia/internal/platform/httpserver"
	"github.com/Yhanko/vigia/internal/platform/queue"
)

const redisTestImage = "redis:8.12.0-alpine3.23@sha256:5af80107c1eeecb484a2269b80a26d12bfa6521787da4663bd9f19f60a163483"

func TestIdempotencyRedisIsolation_CTO32(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	passBuf := make([]byte, 16)
	_, _ = io.ReadFull(rand.Reader, passBuf)
	redisPass := hex.EncodeToString(passBuf)

	ctr, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image:        redisTestImage,
			ExposedPorts: []string{"6379/tcp"},
			Cmd:          []string{"redis-server", "--requirepass", redisPass},
			WaitingFor:   wait.ForLog("Ready to accept connections").WithStartupTimeout(60 * time.Second),
		},
		Started: true,
	})
	if err != nil {
		t.Fatalf("start redis: %v", err)
	}
	t.Cleanup(func() { _ = ctr.Terminate(context.Background()) })

	host, _ := ctr.Host(ctx)
	port, _ := ctr.MappedPort(ctx, "6379/tcp")
	rdb, err := queue.NewRedisClient(ctx, host+":"+port.Port(), redisPass)
	if err != nil {
		t.Fatalf("NewRedisClient: %v", err)
	}
	t.Cleanup(func() { _ = rdb.Close() })

	store, err := queue.NewRedisIdempotencyStore(rdb)
	if err != nil {
		t.Fatalf("NewRedisIdempotencyStore: %v", err)
	}

	var calls atomic.Int32
	fakeSecret := "vg_ing_" + hex.EncodeToString(passBuf[:6]) + "_" + hex.EncodeToString(passBuf) + hex.EncodeToString(passBuf)

	mw := httpserver.IdempotencyMiddleware(httpserver.IdempotencyOptions{
		Store: store,
		Principal: func(r *http.Request) (string, bool) {
			u := r.Header.Get("X-Principal")
			if u == "" {
				return "", false
			}
			return u, true
		},
		TTL: 24 * time.Hour,
	})

	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := calls.Add(1)
		if strings.Contains(r.URL.Path, "/credentials") {
			httpserver.WriteJSON(w, http.StatusCreated, map[string]any{"secret": fakeSecret, "call": n})
			return
		}
		httpserver.WriteJSON(w, http.StatusCreated, map[string]any{"owner": r.Header.Get("X-Principal"), "call": n})
	}))

	// 1. User A creates org -> cached in Redis with 24h TTL.
	r1 := httptest.NewRequest(http.MethodPost, "/api/v1/organizations", strings.NewReader(`{"name":"OrgA","slug":"org-a"}`))
	r1.Header.Set("Idempotency-Key", "k-org-1")
	r1.Header.Set("X-Principal", "user:aaa")
	rec1 := httptest.NewRecorder()
	handler.ServeHTTP(rec1, r1)
	if rec1.Code != http.StatusCreated || calls.Load() != 1 {
		t.Fatalf("r1: code=%d calls=%d", rec1.Code, calls.Load())
	}

	// 2. User A replays -> Idempotency-Replayed: true, no second call.
	r2 := httptest.NewRequest(http.MethodPost, "/api/v1/organizations", strings.NewReader(`{"name":"OrgA","slug":"org-a"}`))
	r2.Header.Set("Idempotency-Key", "k-org-1")
	r2.Header.Set("X-Principal", "user:aaa")
	rec2 := httptest.NewRecorder()
	handler.ServeHTTP(rec2, r2)
	if rec2.Code != http.StatusCreated || rec2.Header().Get("Idempotency-Replayed") != "true" || calls.Load() != 1 {
		t.Fatalf("r2 replay: code=%d replayed=%q calls=%d", rec2.Code, rec2.Header().Get("Idempotency-Replayed"), calls.Load())
	}

	// 3. User B uses same key -> independent execution (does NOT see User A's response).
	r3 := httptest.NewRequest(http.MethodPost, "/api/v1/organizations", strings.NewReader(`{"name":"OrgA","slug":"org-a"}`))
	r3.Header.Set("Idempotency-Key", "k-org-1")
	r3.Header.Set("X-Principal", "user:bbb")
	rec3 := httptest.NewRecorder()
	handler.ServeHTTP(rec3, r3)
	if rec3.Code != http.StatusCreated || rec3.Header().Get("Idempotency-Replayed") != "" || calls.Load() != 2 {
		t.Fatalf("r3 cross-user: code=%d replayed=%q calls=%d", rec3.Code, rec3.Header().Get("Idempotency-Replayed"), calls.Load())
	}

	// 4. User A same key with different body -> 409 IDEMPOTENCY_CONFLICT.
	r4 := httptest.NewRequest(http.MethodPost, "/api/v1/organizations", strings.NewReader(`{"name":"Other","slug":"other"}`))
	r4.Header.Set("Idempotency-Key", "k-org-1")
	r4.Header.Set("X-Principal", "user:aaa")
	rec4 := httptest.NewRecorder()
	handler.ServeHTTP(rec4, r4)
	if rec4.Code != http.StatusConflict || !strings.Contains(rec4.Body.String(), "IDEMPOTENCY_CONFLICT") {
		t.Fatalf("r4 conflict: code=%d body=%s", rec4.Code, rec4.Body.String())
	}

	// 5. Creating an API credential with Idempotency-Key MUST NOT store the secret anywhere in Redis!
	rCred := httptest.NewRequest(http.MethodPost, "/api/v1/organizations/11111111-1111-4111-8111-111111111111/projects/22222222-2222-4222-8222-222222222222/credentials", strings.NewReader(`{"kind":"ingest","name":"k"}`))
	rCred.Header.Set("Idempotency-Key", "k-cred-secret")
	rCred.Header.Set("X-Principal", "user:aaa")
	recCred := httptest.NewRecorder()
	handler.ServeHTTP(recCred, rCred)
	if recCred.Code != http.StatusCreated {
		t.Fatalf("rCred: code=%d", recCred.Code)
	}

	keys, err := rdb.Keys(ctx, "*").Result()
	if err != nil {
		t.Fatalf("redis KEYS: %v", err)
	}
	for _, k := range keys {
		val, _ := rdb.Get(ctx, k).Result()
		if strings.Contains(val, fakeSecret) || strings.Contains(k, "credentials") {
			t.Fatalf("secret or credentials route cached in Redis! key=%q", k)
		}
	}
}
