package identity_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Yhanko/vigia/internal/api"
	"github.com/Yhanko/vigia/internal/modules/identity"
	"github.com/Yhanko/vigia/internal/modules/identity/password"
	"github.com/Yhanko/vigia/internal/modules/identity/session"
	"github.com/Yhanko/vigia/internal/platform/clock"
	"github.com/Yhanko/vigia/internal/platform/httpserver"
	"github.com/Yhanko/vigia/internal/platform/ratelimit"
)

// ─── In-memory fakes (Liskov-compliant with PostgresStore & RedisLimiter) ────

type memStore struct {
	mu       sync.Mutex
	users    map[string]identity.User          // by normalized email
	usersID  map[string]identity.User          // by id
	sessions map[string]identity.SessionRecord // by id
	revoked  map[string]time.Time
	audits   []identity.AuditEvent
}

func newMemStore() *memStore {
	return &memStore{
		users:    make(map[string]identity.User),
		usersID:  make(map[string]identity.User),
		sessions: make(map[string]identity.SessionRecord),
		revoked:  make(map[string]time.Time),
	}
}

func (m *memStore) CreateUser(_ context.Context, u identity.User) (identity.User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.users[u.Email]; exists {
		return identity.User{}, identity.ErrEmailExists
	}
	m.users[u.Email] = u
	m.usersID[u.ID] = u
	return u, nil
}

func (m *memStore) GetUserByEmail(_ context.Context, email string) (identity.User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	u, ok := m.users[email]
	if !ok {
		return identity.User{}, identity.ErrNotFound
	}
	return u, nil
}

func (m *memStore) UpdateUserPasswordHash(_ context.Context, userID, hash string, _ time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	u, ok := m.usersID[userID]
	if !ok {
		return identity.ErrNotFound
	}
	u.PasswordHash = hash
	m.usersID[userID] = u
	m.users[u.Email] = u
	return nil
}

func (m *memStore) DeactivateUser(_ context.Context, userID, status string, now time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	u, ok := m.usersID[userID]
	if !ok {
		return identity.ErrNotFound
	}
	u.Status = status
	m.usersID[userID] = u
	m.users[u.Email] = u
	for id, s := range m.sessions {
		if s.UserID == userID {
			m.revoked[id] = now
		}
	}
	return nil
}

func (m *memStore) CreateSession(_ context.Context, rec identity.SessionRecord) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sessions[rec.ID] = rec
	return nil
}

func (m *memStore) GetActiveSessionByTokenHash(_ context.Context, tokenHash []byte, now time.Time) (identity.ActiveSession, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for id, s := range m.sessions {
		if !bytes.Equal(s.TokenHash, tokenHash) {
			continue
		}
		if _, isRevoked := m.revoked[id]; isRevoked {
			return identity.ActiveSession{}, identity.ErrNotFound
		}
		if !s.ExpiresAt.After(now) || !s.AbsoluteExpiresAt.After(now) {
			return identity.ActiveSession{}, identity.ErrNotFound
		}
		u, ok := m.usersID[s.UserID]
		if !ok || u.Status != "active" {
			return identity.ActiveSession{}, identity.ErrNotFound
		}
		return identity.ActiveSession{
			ID:                s.ID,
			UserID:            s.UserID,
			CSRFTokenHash:     s.CSRFTokenHash,
			LastAuthAt:        s.LastAuthAt,
			ExpiresAt:         s.ExpiresAt,
			AbsoluteExpiresAt: s.AbsoluteExpiresAt,
			UserEmail:         u.Email,
			UserName:          u.Name,
			UserMFAEnabled:    u.MFAEnabled,
		}, nil
	}
	return identity.ActiveSession{}, identity.ErrNotFound
}

func (m *memStore) RevokeSession(_ context.Context, sessionID string, revokedAt time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.revoked[sessionID] = revokedAt
	return nil
}

func (m *memStore) RotateSession(_ context.Context, oldSessionID string, next identity.SessionRecord, revokedAt time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.revoked[oldSessionID] = revokedAt
	m.sessions[next.ID] = next
	return nil
}

func (m *memStore) InsertGlobalAuditLog(_ context.Context, ev identity.AuditEvent) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.audits = append(m.audits, ev)
	return nil
}

type memLimiter struct {
	mu      sync.Mutex
	counts  map[string]int
	forceEr error
}

func newMemLimiter() *memLimiter {
	return &memLimiter{counts: make(map[string]int)}
}

func (l *memLimiter) Allow(_ context.Context, key string, limit int, window time.Duration) (ratelimit.Result, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.forceEr != nil {
		return ratelimit.Result{}, l.forceEr
	}
	l.counts[key]++
	if l.counts[key] > limit {
		return ratelimit.Result{
			Allowed:    false,
			Limit:      limit,
			Remaining:  0,
			ResetAfter: window,
			RetryAfter: 60 * time.Second,
		}, nil
	}
	return ratelimit.Result{
		Allowed:    true,
		Limit:      limit,
		Remaining:  limit - l.counts[key],
		ResetAfter: window,
	}, nil
}

// spyHasher wraps a real password.Hasher to count Hash/Verify/DummyVerify calls.
type spyHasher struct {
	inner       *password.Hasher
	hashCalls   int
	verifyCalls int
	dummyCalls  int
	forceErr    error
}

func (s *spyHasher) Hash(ctx context.Context, plain string) (string, error) {
	s.hashCalls++
	if s.forceErr != nil {
		return "", s.forceErr
	}
	return s.inner.Hash(ctx, plain)
}

func (s *spyHasher) Verify(ctx context.Context, plain, encodedHash string) (bool, error) {
	s.verifyCalls++
	if s.forceErr != nil {
		return false, s.forceErr
	}
	return s.inner.Verify(ctx, plain, encodedHash)
}

func (s *spyHasher) DummyVerify(ctx context.Context) error {
	s.dummyCalls++
	if s.forceErr != nil {
		return s.forceErr
	}
	return s.inner.DummyVerify(ctx)
}

func (s *spyHasher) NeedsRehash(encodedHash string) bool {
	return s.inner.NeedsRehash(encodedHash)
}

type testAPIServer struct {
	*identity.Handler
}

func (testAPIServer) GetStatus(w http.ResponseWriter, _ *http.Request) {
	httpserver.WriteJSON(w, http.StatusOK, api.StatusResponse{
		Service: "vigia", Status: "ok", Version: "test", Commit: "abc",
	})
}

type harness struct {
	router  http.Handler
	svc     *identity.Service
	store   *memStore
	limiter *memLimiter
	hasher  *spyHasher
	codec   *session.Codec
	clk     *clock.Fake
	logs    *bytes.Buffer
	secret  []byte
	origin  string
}

func newHarness(t *testing.T, appEnv string) *harness {
	t.Helper()
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		t.Fatal(err)
	}
	realHasher, err := password.NewHasher(password.Options{
		Params: password.Params{
			MemoryKiB:   4096, // fast in unit tests while exercising full Argon2id PHC path
			Iterations:  1,
			Parallelism: 1,
			SaltBytes:   16,
			KeyBytes:    32,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	spy := &spyHasher{inner: realHasher}
	store := newMemStore()
	lim := newMemLimiter()
	clk := clock.NewFake(time.Date(2026, 11, 27, 15, 0, 0, 0, time.UTC))
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logBuf, nil))

	codec, err := session.NewCodec(secret, appEnv)
	if err != nil {
		t.Fatal(err)
	}
	svc, err := identity.NewService(identity.ServiceConfig{
		Store:           store,
		Hasher:          spy,
		Sessions:        codec,
		Limiter:         lim,
		RateLimitSecret: secret,
		Clock:           clk,
		Logger:          logger,
	})
	if err != nil {
		t.Fatal(err)
	}
	origin := "https://app.vigia.ao"
	h, err := identity.NewHandler(svc, codec, []string{origin}, logger)
	if err != nil {
		t.Fatal(err)
	}
	router := httpserver.NewHandler(httpserver.Options{
		Version:     "test",
		Commit:      "abc",
		Logger:      logger,
		CORSOrigins: []string{origin},
		APIServer:   testAPIServer{Handler: h},
	})

	return &harness{
		router:  router,
		svc:     svc,
		store:   store,
		limiter: lim,
		hasher:  spy,
		codec:   codec,
		clk:     clk,
		logs:    &logBuf,
		secret:  secret,
		origin:  origin,
	}
}

func (h *harness) doJSON(method, path, body, origin, ip string, ck *http.Cookie, csrf string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	if ip != "" {
		req.RemoteAddr = ip + ":54321"
	}
	if ck != nil {
		req.AddCookie(ck)
	}
	if csrf != "" {
		req.Header.Set("X-CSRF-Token", csrf)
	}
	rec := httptest.NewRecorder()
	h.router.ServeHTTP(rec, req)
	return rec
}

func decodeErrCode(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var env httpserver.ErrorResponse
	if err := json.NewDecoder(bytes.NewReader(rec.Body.Bytes())).Decode(&env); err != nil {
		t.Fatalf("decode error envelope (status %d, body %q): %v", rec.Code, rec.Body.String(), err)
	}
	return env.Error.Code
}

// ─── Tests ───────────────────────────────────────────────────────────────────

func TestRegisterAndLoginAntiEnumerationAndValidation(t *testing.T) {
	h := newHarness(t, "production")
	pass := "vG9!xQ2#mK7$pR4@zN"

	// CTO #16: malformed email returns 400 VALIDATION_FAILED (not INVALID_JSON).
	badEmail := h.doJSON(http.MethodPost, "/api/v1/auth/register",
		`{"email":"not-an-email","name":"Alice","password":"`+pass+`"}`, h.origin, "198.51.100.1", nil, "")
	if badEmail.Code != http.StatusBadRequest || decodeErrCode(t, badEmail) != "VALIDATION_FAILED" {
		t.Fatalf("malformed email register = (%d, %s), want (400, VALIDATION_FAILED)", badEmail.Code, badEmail.Body.String())
	}

	// Register new email → 202 generic.
	r1 := h.doJSON(http.MethodPost, "/api/v1/auth/register",
		`{"email":"Alice@Example.com","name":"Alice","password":"`+pass+`"}`, h.origin, "198.51.100.1", nil, "")
	if r1.Code != http.StatusAccepted {
		t.Fatalf("register #1 = %d (%s), want 202", r1.Code, r1.Body.String())
	}

	// Register duplicate email → identical 202 status & body, AND Argon2id Hash ran again.
	r2 := h.doJSON(http.MethodPost, "/api/v1/auth/register",
		`{"email":"alice@example.com","name":"Alice Clone","password":"`+pass+`"}`, h.origin, "198.51.100.1", nil, "")
	if r2.Code != http.StatusAccepted || r2.Body.String() != r1.Body.String() {
		t.Fatalf("duplicate register anti-enumeration failed: got (%d, %q), want (%d, %q)", r2.Code, r2.Body.String(), r1.Code, r1.Body.String())
	}
	if h.hasher.hashCalls != 2 {
		t.Fatalf("expected Argon2id Hash on both register attempts, got %d calls", h.hasher.hashCalls)
	}

	// Login nonexistent email → DummyVerify called + generic 401 INVALID_CREDENTIALS.
	lMissing := h.doJSON(http.MethodPost, "/api/v1/auth/login",
		`{"email":"nobody@example.com","password":"`+pass+`"}`, h.origin, "198.51.100.2", nil, "")
	if lMissing.Code != http.StatusUnauthorized || decodeErrCode(t, lMissing) != "INVALID_CREDENTIALS" {
		t.Fatalf("nonexistent login = (%d, %s), want (401, INVALID_CREDENTIALS)", lMissing.Code, lMissing.Body.String())
	}
	if h.hasher.dummyCalls != 1 {
		t.Fatalf("expected 1 DummyVerify call for nonexistent email, got %d", h.hasher.dummyCalls)
	}

	// Login wrong password → identical 401 INVALID_CREDENTIALS.
	lWrong := h.doJSON(http.MethodPost, "/api/v1/auth/login",
		`{"email":"alice@example.com","password":"wrong-password-1234"}`, h.origin, "198.51.100.3", nil, "")
	if lWrong.Code != http.StatusUnauthorized || decodeErrCode(t, lWrong) != "INVALID_CREDENTIALS" {
		t.Fatalf("wrong password login = (%d, %s), want (401, INVALID_CREDENTIALS)", lWrong.Code, lWrong.Body.String())
	}

	// CTO #14: disabled user with valid password runs real Verify (no shortcut) and returns 401 INVALID_CREDENTIALS.
	alice := h.store.users["alice@example.com"]
	if err := h.svc.DeactivateUser(context.Background(), alice.ID, "disabled"); err != nil {
		t.Fatal(err)
	}
	prevVerify := h.hasher.verifyCalls
	lDisabled := h.doJSON(http.MethodPost, "/api/v1/auth/login",
		`{"email":"alice@example.com","password":"`+pass+`"}`, h.origin, "198.51.100.4", nil, "")
	if lDisabled.Code != http.StatusUnauthorized || decodeErrCode(t, lDisabled) != "INVALID_CREDENTIALS" {
		t.Fatalf("disabled user login = (%d, %s), want (401, INVALID_CREDENTIALS)", lDisabled.Code, lDisabled.Body.String())
	}
	if h.hasher.verifyCalls != prevVerify+1 {
		t.Fatal("disabled user login must still run real Argon2id Verify (no timing shortcut)")
	}
}

func TestOriginEnforcementOnPublicAuthEndpoints(t *testing.T) {
	h := newHarness(t, "production")

	for _, path := range []string{"/api/v1/auth/register", "/api/v1/auth/login"} {
		for _, origin := range []string{"", "https://evil.example"} {
			rec := h.doJSON(http.MethodPost, path, `{"email":"a@b.com","password":"x"}`, origin, "198.51.100.1", nil, "")
			if rec.Code != http.StatusForbidden || decodeErrCode(t, rec) != "CSRF_INVALID" {
				t.Fatalf("POST %s with Origin=%q got (%d, %s), want (403, CSRF_INVALID)", path, origin, rec.Code, rec.Body.String())
			}
		}
	}
}

func TestRateLimitBeforeHashAndAccountIPLockoutIsolation(t *testing.T) {
	h := newHarness(t, "production")
	pass := "vG9!xQ2#mK7$pR4@zN"

	_ = h.doJSON(http.MethodPost, "/api/v1/auth/register",
		`{"email":"bob@example.com","name":"Bob","password":"`+pass+`"}`, h.origin, "198.51.100.1", nil, "")

	// 5 failed logins from IP1 exhaust (bob + IP1) tuple.
	for i := range identity.LoginLimitPerAccountIP {
		rec := h.doJSON(http.MethodPost, "/api/v1/auth/login",
			`{"email":"bob@example.com","password":"wrong-password-1234"}`, h.origin, "203.0.113.10", nil, "")
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d from IP1 = %d, want 401", i+1, rec.Code)
		}
	}

	// 6th attempt from IP1 MUST return 429 BEFORE calling Argon2id Verify or DummyVerify.
	beforeVerify, beforeDummy := h.hasher.verifyCalls, h.hasher.dummyCalls
	blocked := h.doJSON(http.MethodPost, "/api/v1/auth/login",
		`{"email":"bob@example.com","password":"wrong-password-1234"}`, h.origin, "203.0.113.10", nil, "")
	if blocked.Code != http.StatusTooManyRequests || decodeErrCode(t, blocked) != "RATE_LIMIT_EXCEEDED" {
		t.Fatalf("6th attempt = (%d, %s), want (429, RATE_LIMIT_EXCEEDED)", blocked.Code, blocked.Body.String())
	}
	if blocked.Header().Get("Retry-After") == "" {
		t.Fatal("missing Retry-After header on 429")
	}
	if h.hasher.verifyCalls != beforeVerify || h.hasher.dummyCalls != beforeDummy {
		t.Fatal("Argon2id was executed despite rate limit block!")
	}

	// Victim logging in from IP2 MUST NOT be locked out by attacker on IP1.
	victim := h.doJSON(http.MethodPost, "/api/v1/auth/login",
		`{"email":"bob@example.com","password":"`+pass+`"}`, h.origin, "203.0.113.99", nil, "")
	if victim.Code != http.StatusOK {
		t.Fatalf("legitimate login from IP2 = %d (%s), want 200", victim.Code, victim.Body.String())
	}
}

func TestSessionLifecycleRotationCSRFExpiryAndNoSecretLeaks(t *testing.T) {
	h := newHarness(t, "production")
	pass := "vG9!xQ2#mK7$pR4@zN"

	_ = h.doJSON(http.MethodPost, "/api/v1/auth/register",
		`{"email":"carol@example.com","name":"Carol","password":"`+pass+`"}`, h.origin, "198.51.100.1", nil, "")

	// Login succeeds, sets __Host-vigia_session cookie with Secure+HttpOnly+SameSite=Lax+Path=/.
	loginRec := h.doJSON(http.MethodPost, "/api/v1/auth/login",
		`{"email":"carol@example.com","password":"`+pass+`"}`, h.origin, "198.51.100.2", nil, "")
	if loginRec.Code != http.StatusOK {
		t.Fatalf("login = %d (%s), want 200", loginRec.Code, loginRec.Body.String())
	}
	cookies := loginRec.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("expected 1 Set-Cookie, got %d", len(cookies))
	}
	ck1 := cookies[0]
	if ck1.Name != session.CookieNameProd || !ck1.HttpOnly || !ck1.Secure || ck1.SameSite != http.SameSiteLaxMode || ck1.Path != "/" {
		t.Fatalf("unexpected production cookie attributes: %+v", ck1)
	}
	var sess1 api.AuthSessionResponse
	if err := json.NewDecoder(loginRec.Body).Decode(&sess1); err != nil {
		t.Fatalf("decode login response: %v", err)
	}

	// CSRF negative tests on /refresh and /logout: missing token, wrong token, foreign Origin → 403 CSRF_INVALID.
	noCSRF := h.doJSON(http.MethodPost, "/api/v1/auth/refresh", "", h.origin, "198.51.100.2", ck1, "")
	if noCSRF.Code != http.StatusForbidden || decodeErrCode(t, noCSRF) != "CSRF_INVALID" {
		t.Fatalf("refresh without CSRF = (%d, %s), want (403, CSRF_INVALID)", noCSRF.Code, noCSRF.Body.String())
	}
	badCSRF := h.doJSON(http.MethodPost, "/api/v1/auth/refresh", "", h.origin, "198.51.100.2", ck1, "wrong-csrf-token")
	if badCSRF.Code != http.StatusForbidden || decodeErrCode(t, badCSRF) != "CSRF_INVALID" {
		t.Fatalf("refresh with wrong CSRF = (%d, %s), want (403, CSRF_INVALID)", badCSRF.Code, badCSRF.Body.String())
	}
	badOrigin := h.doJSON(http.MethodPost, "/api/v1/auth/logout", "", "https://evil.example", "198.51.100.2", ck1, sess1.CsrfToken)
	if badOrigin.Code != http.StatusForbidden || decodeErrCode(t, badOrigin) != "CSRF_INVALID" {
		t.Fatalf("logout with foreign Origin = (%d, %s), want (403, CSRF_INVALID)", badOrigin.Code, badOrigin.Body.String())
	}

	// Valid refresh rotates cookie and CSRF token; old cookie returns 401 SESSION_EXPIRED.
	h.clk.Advance(2 * 24 * time.Hour)
	refRec := h.doJSON(http.MethodPost, "/api/v1/auth/refresh", "", h.origin, "198.51.100.2", ck1, sess1.CsrfToken)
	if refRec.Code != http.StatusOK {
		t.Fatalf("refresh = %d (%s), want 200", refRec.Code, refRec.Body.String())
	}
	ck2 := refRec.Result().Cookies()[0]
	var sess2 api.AuthSessionResponse
	if err := json.NewDecoder(refRec.Body).Decode(&sess2); err != nil {
		t.Fatal(err)
	}
	if ck2.Value == ck1.Value || sess2.CsrfToken == sess1.CsrfToken {
		t.Fatal("refresh must rotate both session cookie and CSRF token")
	}

	oldReuse := h.doJSON(http.MethodPost, "/api/v1/auth/refresh", "", h.origin, "198.51.100.2", ck1, sess1.CsrfToken)
	if oldReuse.Code != http.StatusUnauthorized || decodeErrCode(t, oldReuse) != "SESSION_EXPIRED" {
		t.Fatalf("reusing rotated-out cookie = (%d, %s), want (401, SESSION_EXPIRED)", oldReuse.Code, oldReuse.Body.String())
	}

	// Idle expiry (advance > 7d) → 401 SESSION_EXPIRED.
	h.clk.Advance(8 * 24 * time.Hour)
	idleExp := h.doJSON(http.MethodPost, "/api/v1/auth/refresh", "", h.origin, "198.51.100.2", ck2, sess2.CsrfToken)
	if idleExp.Code != http.StatusUnauthorized || decodeErrCode(t, idleExp) != "SESSION_EXPIRED" {
		t.Fatalf("idle-expired session = (%d, %s), want (401, SESSION_EXPIRED)", idleExp.Code, idleExp.Body.String())
	}

	// Fresh login → advance near 30d absolute limit via sliding refreshes → clamps to 30d then expires.
	login2 := h.doJSON(http.MethodPost, "/api/v1/auth/login",
		`{"email":"carol@example.com","password":"`+pass+`"}`, h.origin, "198.51.100.2", nil, "")
	curCk := login2.Result().Cookies()[0]
	var curResp api.AuthSessionResponse
	_ = json.NewDecoder(login2.Body).Decode(&curResp)
	absLimit := h.clk.Now().Add(session.DefaultAbsoluteTTL)

	for range 5 { // 5 * 6d = 30d
		h.clk.Advance(6 * 24 * time.Hour)
		if !h.clk.Now().Before(absLimit) {
			break
		}
		r := h.doJSON(http.MethodPost, "/api/v1/auth/refresh", "", h.origin, "198.51.100.2", curCk, curResp.CsrfToken)
		if r.Code != http.StatusOK {
			t.Fatalf("sliding refresh within 30d failed: %d %s", r.Code, r.Body.String())
		}
		curCk = r.Result().Cookies()[0]
		_ = json.NewDecoder(r.Body).Decode(&curResp)
		if curResp.ExpiresAt.After(absLimit) {
			t.Fatalf("refresh exceeded 30d absolute expiry: %v > %v", curResp.ExpiresAt, absLimit)
		}
	}
	h.clk.Advance(2 * 24 * time.Hour)
	absExp := h.doJSON(http.MethodPost, "/api/v1/auth/refresh", "", h.origin, "198.51.100.2", curCk, curResp.CsrfToken)
	if absExp.Code != http.StatusUnauthorized || decodeErrCode(t, absExp) != "SESSION_EXPIRED" {
		t.Fatalf("absolute-expired session = (%d, %s), want (401, SESSION_EXPIRED)", absExp.Code, absExp.Body.String())
	}

	// Fresh login + logout → 204, cookie cleared, token revoked.
	login3 := h.doJSON(http.MethodPost, "/api/v1/auth/login",
		`{"email":"carol@example.com","password":"`+pass+`"}`, h.origin, "198.51.100.2", nil, "")
	ck3 := login3.Result().Cookies()[0]
	var resp3 api.AuthSessionResponse
	_ = json.NewDecoder(login3.Body).Decode(&resp3)

	logoutRec := h.doJSON(http.MethodPost, "/api/v1/auth/logout", "", h.origin, "198.51.100.2", ck3, resp3.CsrfToken)
	if logoutRec.Code != http.StatusNoContent {
		t.Fatalf("logout = %d, want 204", logoutRec.Code)
	}
	if cleared := logoutRec.Result().Cookies()[0]; cleared.MaxAge != -1 || cleared.Value != "" {
		t.Fatalf("logout did not clear cookie: %+v", cleared)
	}

	// Verify audit logs recorded login + logout and ZERO secrets leaked to logs.
	if len(h.store.audits) < 3 {
		t.Fatalf("expected audit logs for logins/logout, got %d", len(h.store.audits))
	}
	logOut := h.logs.String()
	for _, secretVal := range []string{pass, ck1.Value, ck2.Value, ck3.Value, sess1.CsrfToken, sess2.CsrfToken, resp3.CsrfToken, string(h.secret)} {
		if strings.Contains(logOut, secretVal) {
			t.Fatalf("secret value leaked into application logs")
		}
	}
}

func TestMFARequiredAndBackpressure503(t *testing.T) {
	h := newHarness(t, "development")
	pass := "vG9!xQ2#mK7$pR4@zN"

	_ = h.doJSON(http.MethodPost, "/api/v1/auth/register",
		`{"email":"dave@example.com","name":"Dave","password":"`+pass+`"}`, h.origin, "198.51.100.1", nil, "")

	// Enable MFA on user → login stops at 401 MFA_REQUIRED with no cookie (CTO #20).
	u := h.store.users["dave@example.com"]
	u.MFAEnabled = true
	h.store.users[u.Email] = u
	h.store.usersID[u.ID] = u

	mfaRec := h.doJSON(http.MethodPost, "/api/v1/auth/login",
		`{"email":"dave@example.com","password":"`+pass+`"}`, h.origin, "198.51.100.2", nil, "")
	if mfaRec.Code != http.StatusUnauthorized || decodeErrCode(t, mfaRec) != "MFA_REQUIRED" {
		t.Fatalf("MFA user login = (%d, %s), want (401, MFA_REQUIRED)", mfaRec.Code, mfaRec.Body.String())
	}
	if len(mfaRec.Result().Cookies()) != 0 {
		t.Fatal("MFA_REQUIRED response must not issue a session cookie")
	}

	// ErrHasherBusy → 503 SERVICE_UNAVAILABLE + Retry-After.
	h.hasher.forceErr = password.ErrHasherBusy
	busyRec := h.doJSON(http.MethodPost, "/api/v1/auth/login",
		`{"email":"dave@example.com","password":"`+pass+`"}`, h.origin, "198.51.100.3", nil, "")
	if busyRec.Code != http.StatusServiceUnavailable || decodeErrCode(t, busyRec) != "SERVICE_UNAVAILABLE" || busyRec.Header().Get("Retry-After") == "" {
		t.Fatalf("ErrHasherBusy login = (%d, %s, Retry-After=%q), want (503, SERVICE_UNAVAILABLE)", busyRec.Code, busyRec.Body.String(), busyRec.Header().Get("Retry-After"))
	}
	h.hasher.forceErr = nil

	// Redis unavailable on /auth/* → fail-closed 503 SERVICE_UNAVAILABLE + Retry-After.
	h.limiter.forceEr = errors.New("redis connection refused")
	downRec := h.doJSON(http.MethodPost, "/api/v1/auth/login",
		`{"email":"dave@example.com","password":"`+pass+`"}`, h.origin, "198.51.100.4", nil, "")
	if downRec.Code != http.StatusServiceUnavailable || decodeErrCode(t, downRec) != "SERVICE_UNAVAILABLE" || downRec.Header().Get("Retry-After") == "" {
		t.Fatalf("Redis outage login = (%d, %s), want fail-closed 503", downRec.Code, downRec.Body.String())
	}
}

func TestSessionAndCSRFMiddleware(t *testing.T) {
	h := newHarness(t, "development")
	pass := "vG9!xQ2#mK7$pR4@zN"

	_ = h.doJSON(http.MethodPost, "/api/v1/auth/register",
		`{"email":"eve@example.com","name":"Eve","password":"`+pass+`"}`, h.origin, "198.51.100.1", nil, "")
	loginRec := h.doJSON(http.MethodPost, "/api/v1/auth/login",
		`{"email":"eve@example.com","password":"`+pass+`"}`, h.origin, "198.51.100.2", nil, "")
	ck := loginRec.Result().Cookies()[0]
	if ck.Name != session.CookieNameDev || ck.Secure {
		t.Fatalf("development cookie should be %s with Secure=false, got %+v", session.CookieNameDev, ck)
	}
	var resp api.AuthSessionResponse
	_ = json.NewDecoder(loginRec.Body).Decode(&resp)

	protected := identity.SessionMiddleware(h.svc, h.codec)(
		identity.CSRFMiddleware(h.codec, []string{h.origin})(
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				active, ok := identity.ActiveSessionFromContext(r.Context())
				if !ok || active.UserEmail != "eve@example.com" {
					t.Fatal("missing ActiveSession in context")
				}
				w.WriteHeader(http.StatusOK)
			}),
		),
	)

	// Valid cookie + valid Origin + valid CSRF passes.
	req := httptest.NewRequest(http.MethodPost, "/protected", nil)
	req.AddCookie(ck)
	req.Header.Set("Origin", h.origin)
	req.Header.Set("X-CSRF-Token", resp.CsrfToken)
	rec := httptest.NewRecorder()
	protected.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("valid protected POST = %d, want 200", rec.Code)
	}

	// Deactivate user → session immediately invalid (CTO #14).
	if err := h.svc.DeactivateUser(context.Background(), h.store.users["eve@example.com"].ID, "disabled"); err != nil {
		t.Fatal(err)
	}
	rec2 := httptest.NewRecorder()
	protected.ServeHTTP(rec2, req)
	if rec2.Code != http.StatusUnauthorized || decodeErrCode(t, rec2) != "SESSION_EXPIRED" {
		t.Fatalf("deactivated user protected POST = (%d, %s), want (401, SESSION_EXPIRED)", rec2.Code, rec2.Body.String())
	}
}
