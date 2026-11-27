package identity_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base32"
	"encoding/hex"
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
	"github.com/Yhanko/vigia/internal/modules/identity/internal/totp"
	"github.com/Yhanko/vigia/internal/modules/identity/password"
	"github.com/Yhanko/vigia/internal/modules/identity/session"
	"github.com/Yhanko/vigia/internal/platform/clock"
	"github.com/Yhanko/vigia/internal/platform/crypto"
	"github.com/Yhanko/vigia/internal/platform/httpserver"
	"github.com/Yhanko/vigia/internal/platform/ratelimit"
)

// ─── In-memory fakes (Liskov-compliant with PostgresStore & RedisLimiter) ────

type memToken struct {
	rec  identity.UserTokenRecord
	used bool
}

type memStore struct {
	mu       sync.Mutex
	users    map[string]identity.User          // by normalized email
	usersID  map[string]identity.User          // by id
	verified map[string]time.Time              // by user id
	sessions map[string]identity.SessionRecord // by id
	revoked  map[string]time.Time
	mfaFails map[string]int16
	tokens   []memToken
	audits   []identity.AuditEvent
}

func newMemStore() *memStore {
	return &memStore{
		users:    make(map[string]identity.User),
		usersID:  make(map[string]identity.User),
		verified: make(map[string]time.Time),
		sessions: make(map[string]identity.SessionRecord),
		revoked:  make(map[string]time.Time),
		mfaFails: make(map[string]int16),
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

func (m *memStore) GetUserByID(_ context.Context, userID string) (identity.User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	u, ok := m.usersID[userID]
	if !ok {
		return identity.User{}, identity.ErrNotFound
	}
	return u, nil
}

func (m *memStore) CreateUserToken(_ context.Context, rec identity.UserTokenRecord) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.tokens = append(m.tokens, memToken{rec: rec})
	return nil
}

func (m *memStore) ReplaceUserToken(_ context.Context, rec identity.UserTokenRecord, _ time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := range m.tokens {
		if m.tokens[i].rec.UserID == rec.UserID && m.tokens[i].rec.Kind == rec.Kind {
			m.tokens[i].used = true
		}
	}
	m.tokens = append(m.tokens, memToken{rec: rec})
	return nil
}

func (m *memStore) VerifyEmailByToken(_ context.Context, tokenHash []byte, now time.Time) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := range m.tokens {
		t := &m.tokens[i]
		if t.used || t.rec.Kind != identity.TokenKindEmailVerify || !bytes.Equal(t.rec.TokenHash, tokenHash) {
			continue
		}
		if t.rec.ExpiresAt != nil && !t.rec.ExpiresAt.After(now) {
			return "", identity.ErrNotFound
		}
		t.used = true
		m.verified[t.rec.UserID] = now
		return t.rec.UserID, nil
	}
	return "", identity.ErrNotFound
}

func (m *memStore) ResetPasswordByToken(_ context.Context, tokenHash []byte, newPasswordHash string, now time.Time) (identity.User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := range m.tokens {
		t := &m.tokens[i]
		if t.used || t.rec.Kind != identity.TokenKindPasswordReset || !bytes.Equal(t.rec.TokenHash, tokenHash) {
			continue
		}
		if t.rec.ExpiresAt != nil && !t.rec.ExpiresAt.After(now) {
			return identity.User{}, identity.ErrNotFound
		}
		t.used = true
		u := m.usersID[t.rec.UserID]
		u.PasswordHash = newPasswordHash
		m.usersID[u.ID] = u
		m.users[u.Email] = u
		for sid, s := range m.sessions {
			if s.UserID == u.ID {
				m.revoked[sid] = now
			}
		}
		return u, nil
	}
	return identity.User{}, identity.ErrNotFound
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
	return m.lookupSession(tokenHash, now, false)
}

func (m *memStore) GetPendingMFASessionByTokenHash(_ context.Context, tokenHash []byte, now time.Time) (identity.ActiveSession, error) {
	return m.lookupSession(tokenHash, now, true)
}

func (m *memStore) lookupSession(tokenHash []byte, now time.Time, pending bool) (identity.ActiveSession, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for id, s := range m.sessions {
		if s.MFAPending != pending || !bytes.Equal(s.TokenHash, tokenHash) {
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
			ID:                     s.ID,
			UserID:                 s.UserID,
			CSRFTokenHash:          s.CSRFTokenHash,
			LastAuthAt:             s.LastAuthAt,
			ExpiresAt:              s.ExpiresAt,
			AbsoluteExpiresAt:      s.AbsoluteExpiresAt,
			MFAPending:             s.MFAPending,
			MFAFailedAttempts:      m.mfaFails[id],
			UserEmail:              u.Email,
			UserName:               u.Name,
			UserMFAEnabled:         u.MFAEnabled,
			UserMFASecretEncrypted: u.MFASecretEncrypted,
			UserMFALastUsedStep:    u.MFALastUsedStep,
		}, nil
	}
	return identity.ActiveSession{}, identity.ErrNotFound
}

func (m *memStore) SetUserPendingMFASecret(_ context.Context, userID string, encrypted []byte, _ time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	u := m.usersID[userID]
	u.MFASecretEncrypted = encrypted
	m.usersID[userID] = u
	m.users[u.Email] = u
	return nil
}

func (m *memStore) ActivateMFA(_ context.Context, userID, _ string, step int64, recoveryTokens []identity.UserTokenRecord, next identity.SessionRecord, now time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	u := m.usersID[userID]
	u.MFAEnabled = true
	st := step
	u.MFALastUsedStep = &st
	m.usersID[userID] = u
	m.users[u.Email] = u
	for i := range m.tokens {
		if m.tokens[i].rec.UserID == userID && m.tokens[i].rec.Kind == identity.TokenKindMFARecovery {
			m.tokens[i].used = true
		}
	}
	for _, rec := range recoveryTokens {
		m.tokens = append(m.tokens, memToken{rec: rec})
	}
	for sid, s := range m.sessions {
		if s.UserID == userID {
			m.revoked[sid] = now
		}
	}
	m.sessions[next.ID] = next
	return nil
}

func (m *memStore) CompleteMFALogin(_ context.Context, userID, pendingSessionID string, step *int64, recoveryTokenHash []byte, next identity.SessionRecord, now time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(recoveryTokenHash) > 0 {
		found := false
		for i := range m.tokens {
			t := &m.tokens[i]
			if !t.used && t.rec.UserID == userID && t.rec.Kind == identity.TokenKindMFARecovery && bytes.Equal(t.rec.TokenHash, recoveryTokenHash) {
				t.used = true
				found = true
				break
			}
		}
		if !found {
			return identity.ErrInvalidMFACode
		}
	}
	if _, already := m.revoked[pendingSessionID]; already {
		return identity.ErrSessionExpired
	}
	m.revoked[pendingSessionID] = now
	if step != nil {
		u := m.usersID[userID]
		st := *step
		u.MFALastUsedStep = &st
		m.usersID[userID] = u
		m.users[u.Email] = u
	}
	m.sessions[next.ID] = next
	return nil
}

func (m *memStore) RecordPendingMFAFailure(_ context.Context, pendingSessionID string, now time.Time) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.mfaFails[pendingSessionID]++
	if m.mfaFails[pendingSessionID] >= 5 {
		m.revoked[pendingSessionID] = now
		return true, nil
	}
	return false, nil
}

func (m *memStore) ReauthRotate(_ context.Context, userID, oldSessionID string, step *int64, next identity.SessionRecord, now time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, already := m.revoked[oldSessionID]; already {
		return identity.ErrSessionExpired
	}
	if step != nil {
		u := m.usersID[userID]
		if u.MFALastUsedStep != nil && *u.MFALastUsedStep >= *step {
			return identity.ErrInvalidMFACode
		}
		st := *step
		u.MFALastUsedStep = &st
		m.usersID[userID] = u
		m.users[u.Email] = u
	}
	m.revoked[oldSessionID] = now
	m.sessions[string(next.TokenHash)] = next
	return nil
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
	if _, alreadyRevoked := m.revoked[oldSessionID]; alreadyRevoked {
		return identity.ErrSessionExpired
	}
	if _, exists := m.sessions[oldSessionID]; !exists {
		return identity.ErrSessionExpired
	}
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
	if l.counts[key] >= limit {
		return ratelimit.Result{
			Allowed:    false,
			Limit:      limit,
			Remaining:  0,
			ResetAfter: window,
			RetryAfter: 60 * time.Second,
		}, nil
	}
	l.counts[key]++
	return ratelimit.Result{
		Allowed:    true,
		Limit:      limit,
		Remaining:  limit - l.counts[key],
		ResetAfter: window,
	}, nil
}

func (l *memLimiter) Peek(_ context.Context, key string, limit int, window time.Duration) (ratelimit.Result, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.forceEr != nil {
		return ratelimit.Result{}, l.forceEr
	}
	if l.counts[key] >= limit {
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

func (l *memLimiter) Reset(_ context.Context, key string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.forceEr != nil {
		return l.forceEr
	}
	delete(l.counts, key)
	return nil
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
	api.Unimplemented
	h *identity.Handler
}

func (s testAPIServer) AuthRegister(w http.ResponseWriter, r *http.Request) {
	s.h.AuthRegister(w, r)
}
func (s testAPIServer) AuthLogin(w http.ResponseWriter, r *http.Request) { s.h.AuthLogin(w, r) }
func (s testAPIServer) AuthLogout(w http.ResponseWriter, r *http.Request, p api.AuthLogoutParams) {
	s.h.AuthLogout(w, r, p)
}
func (s testAPIServer) AuthRefresh(w http.ResponseWriter, r *http.Request, p api.AuthRefreshParams) {
	s.h.AuthRefresh(w, r, p)
}
func (s testAPIServer) AuthVerifyEmail(w http.ResponseWriter, r *http.Request) {
	s.h.AuthVerifyEmail(w, r)
}
func (s testAPIServer) AuthPasswordForgot(w http.ResponseWriter, r *http.Request) {
	s.h.AuthPasswordForgot(w, r)
}
func (s testAPIServer) AuthPasswordReset(w http.ResponseWriter, r *http.Request) {
	s.h.AuthPasswordReset(w, r)
}
func (s testAPIServer) AuthMFASetup(w http.ResponseWriter, r *http.Request, p api.AuthMFASetupParams) {
	s.h.AuthMFASetup(w, r, p)
}
func (s testAPIServer) AuthMFAVerify(w http.ResponseWriter, r *http.Request, p api.AuthMFAVerifyParams) {
	s.h.AuthMFAVerify(w, r, p)
}
func (s testAPIServer) AuthReauth(w http.ResponseWriter, r *http.Request, p api.AuthReauthParams) {
	s.h.AuthReauth(w, r, p)
}

func (testAPIServer) GetStatus(w http.ResponseWriter, _ *http.Request) {
	httpserver.WriteJSON(w, http.StatusOK, api.StatusResponse{
		Service: "vigia", Status: "ok", Version: "test", Commit: "abc",
	})
}

type sentEmail struct {
	to      string
	subject string
	body    string
}

type fakeMailer struct {
	mu   sync.Mutex
	sent []sentEmail
}

func (f *fakeMailer) Send(_ context.Context, to, subject, body string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sent = append(f.sent, sentEmail{to: to, subject: subject, body: body})
	return nil
}

type harness struct {
	router  http.Handler
	svc     *identity.Service
	store   *memStore
	limiter *memLimiter
	hasher  *spyHasher
	mailer  *fakeMailer
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
	kekBytes := make([]byte, 32)
	if _, err := rand.Read(kekBytes); err != nil {
		t.Fatal(err)
	}
	kr, err := crypto.ParseKeyring([]byte("k1:" + hex.EncodeToString(kekBytes)))
	if err != nil {
		t.Fatal(err)
	}
	enc, err := crypto.NewEnvelopeEncrypter(kr)
	if err != nil {
		t.Fatal(err)
	}

	mail := &fakeMailer{}
	svc, err := identity.NewService(identity.ServiceConfig{
		Store:           store,
		Hasher:          spy,
		Sessions:        codec,
		Limiter:         lim,
		RateLimitSecret: secret,
		Encrypter:       enc,
		Mailer:          mail,
		AppURL:          "https://app.vigia.ao",
		Clock:           clk,
		Logger:          logger,
	})
	if err != nil {
		t.Fatal(err)
	}
	origin := "https://app.vigia.ao"
	h, err := identity.NewHandler(svc, codec, []string{origin}, nil, logger)
	if err != nil {
		t.Fatal(err)
	}
	router := httpserver.NewHandler(httpserver.Options{
		Version:     "test",
		Commit:      "abc",
		Logger:      logger,
		CORSOrigins: []string{origin},
		APIAuth:     identity.SessionAndCSRFMiddleware(svc, codec, []string{origin}),
		APIServer:   testAPIServer{h: h},
	})

	return &harness{
		router:  router,
		svc:     svc,
		store:   store,
		limiter: lim,
		hasher:  spy,
		mailer:  mail,
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

	// CTO #23: 6 consecutive successful logins from same (account+IP) within IP limit MUST all succeed,
	// and a successful login after 4 failures resets the failure counter.
	for i := range 6 {
		okRec := h.doJSON(http.MethodPost, "/api/v1/auth/login",
			`{"email":"bob@example.com","password":"`+pass+`"}`, h.origin, "203.0.113.50", nil, "")
		if okRec.Code != http.StatusOK {
			t.Fatalf("successful login #%d = %d, want 200 (successes must not trip failure lockout)", i+1, okRec.Code)
		}
	}
	for i := range 4 {
		rec := h.doJSON(http.MethodPost, "/api/v1/auth/login",
			`{"email":"bob@example.com","password":"wrong-password-1234"}`, h.origin, "203.0.113.60", nil, "")
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("failure #%d = %d, want 401", i+1, rec.Code)
		}
	}
	// 5th attempt succeeds → resets counter.
	if rec := h.doJSON(http.MethodPost, "/api/v1/auth/login",
		`{"email":"bob@example.com","password":"`+pass+`"}`, h.origin, "203.0.113.60", nil, ""); rec.Code != http.StatusOK {
		t.Fatalf("success after 4 failures = %d, want 200", rec.Code)
	}
	// Another failure after reset must return 401 (not 429).
	if rec := h.doJSON(http.MethodPost, "/api/v1/auth/login",
		`{"email":"bob@example.com","password":"wrong-password-1234"}`, h.origin, "203.0.113.60", nil, ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("failure after reset = %d, want 401", rec.Code)
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

	// Enable MFA on user → two-step login returns 202 with pending session cookie (§7.1).
	u := h.store.users["dave@example.com"]
	u.MFAEnabled = true
	h.store.users[u.Email] = u
	h.store.usersID[u.ID] = u

	mfaRec := h.doJSON(http.MethodPost, "/api/v1/auth/login",
		`{"email":"dave@example.com","password":"`+pass+`"}`, h.origin, "198.51.100.2", nil, "")
	if mfaRec.Code != http.StatusAccepted {
		t.Fatalf("MFA user login = (%d, %s), want 202", mfaRec.Code, mfaRec.Body.String())
	}
	var chal api.MFAChallengeResponse
	if err := json.NewDecoder(mfaRec.Body).Decode(&chal); err != nil || !chal.MfaRequired || chal.CsrfToken == "" {
		t.Fatalf("unexpected MFA challenge body: %+v err=%v", chal, err)
	}
	if len(mfaRec.Result().Cookies()) != 1 {
		t.Fatal("expected pending session cookie on 202 MFA challenge")
	}
	// Pending session MUST NOT be accepted on /refresh!
	pendCk := mfaRec.Result().Cookies()[0]
	refPend := h.doJSON(http.MethodPost, "/api/v1/auth/refresh", "", h.origin, "198.51.100.2", pendCk, chal.CsrfToken)
	if refPend.Code != http.StatusUnauthorized || decodeErrCode(t, refPend) != "SESSION_EXPIRED" {
		t.Fatalf("pending session on /refresh = (%d, %s), want (401, SESSION_EXPIRED)", refPend.Code, refPend.Body.String())
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

func extractTokenFromEmail(t *testing.T, body string) string {
	t.Helper()
	const marker = "?token="
	idx := strings.Index(body, marker)
	if idx == -1 {
		t.Fatalf("email body does not contain %q: %q", marker, body)
	}
	rest := body[idx+len(marker):]
	if nl := strings.IndexAny(rest, "\r\n "); nl != -1 {
		rest = rest[:nl]
	}
	return rest
}

func TestEmailVerificationAndPasswordResetFlow(t *testing.T) {
	h := newHarness(t, "production")
	pass1 := "vG9!xQ2#mK7$pR4@zN"
	pass2 := "nZ4@rP7$kM2#qX9!gV"

	// Register sends verification email with single-use 24h token.
	reg := h.doJSON(http.MethodPost, "/api/v1/auth/register",
		`{"email":"frank@example.com","name":"Frank","password":"`+pass1+`"}`, h.origin, "198.51.100.1", nil, "")
	if reg.Code != http.StatusAccepted {
		t.Fatalf("register = %d, want 202", reg.Code)
	}
	if len(h.mailer.sent) != 1 || h.mailer.sent[0].to != "frank@example.com" {
		t.Fatalf("expected 1 verification email, got %+v", h.mailer.sent)
	}
	verifyTok := extractTokenFromEmail(t, h.mailer.sent[0].body)

	// Verify email succeeds once, then rejects replay.
	v1 := h.doJSON(http.MethodPost, "/api/v1/auth/verify-email", `{"token":"`+verifyTok+`"}`, h.origin, "198.51.100.1", nil, "")
	if v1.Code != http.StatusOK {
		t.Fatalf("verify-email = %d (%s), want 200", v1.Code, v1.Body.String())
	}
	v2 := h.doJSON(http.MethodPost, "/api/v1/auth/verify-email", `{"token":"`+verifyTok+`"}`, h.origin, "198.51.100.1", nil, "")
	if v2.Code != http.StatusBadRequest || decodeErrCode(t, v2) != "VALIDATION_FAILED" {
		t.Fatalf("reused verify-email = (%d, %s), want (400, VALIDATION_FAILED)", v2.Code, v2.Body.String())
	}

	// Login to obtain an active session that must be revoked by password reset.
	loginRec := h.doJSON(http.MethodPost, "/api/v1/auth/login",
		`{"email":"frank@example.com","password":"`+pass1+`"}`, h.origin, "198.51.100.2", nil, "")
	if loginRec.Code != http.StatusOK {
		t.Fatalf("login = %d, want 200", loginRec.Code)
	}
	activeCk := loginRec.Result().Cookies()[0]
	var activeResp api.AuthSessionResponse
	_ = json.NewDecoder(loginRec.Body).Decode(&activeResp)

	// Password forgot: nonexistent email returns identical generic 202 (anti-enumeration).
	fMissing := h.doJSON(http.MethodPost, "/api/v1/auth/password/forgot",
		`{"email":"ghost@example.com"}`, h.origin, "198.51.100.3", nil, "")
	if fMissing.Code != http.StatusAccepted {
		t.Fatalf("forgot(nonexistent) = %d, want 202", fMissing.Code)
	}

	// Password forgot #1 then #2: #2 invalidates #1; 4th request for same email hits 429 (limit 3/15m).
	f1 := h.doJSON(http.MethodPost, "/api/v1/auth/password/forgot",
		`{"email":"frank@example.com"}`, h.origin, "198.51.100.4", nil, "")
	f2 := h.doJSON(http.MethodPost, "/api/v1/auth/password/forgot",
		`{"email":"frank@example.com"}`, h.origin, "198.51.100.4", nil, "")
	f3 := h.doJSON(http.MethodPost, "/api/v1/auth/password/forgot",
		`{"email":"frank@example.com"}`, h.origin, "198.51.100.4", nil, "")
	f4 := h.doJSON(http.MethodPost, "/api/v1/auth/password/forgot",
		`{"email":"frank@example.com"}`, h.origin, "198.51.100.4", nil, "")
	if f1.Code != http.StatusAccepted || f2.Code != http.StatusAccepted || f3.Code != http.StatusAccepted {
		t.Fatalf("first 3 forgot requests should be 202, got %d/%d/%d", f1.Code, f2.Code, f3.Code)
	}
	if f4.Code != http.StatusTooManyRequests || decodeErrCode(t, f4) != "RATE_LIMIT_EXCEEDED" {
		t.Fatalf("4th forgot request = (%d, %s), want (429, RATE_LIMIT_EXCEEDED)", f4.Code, f4.Body.String())
	}

	tok1 := extractTokenFromEmail(t, h.mailer.sent[1].body)
	tok3 := extractTokenFromEmail(t, h.mailer.sent[3].body)

	// Invalidated tok1 must be rejected.
	rOld := h.doJSON(http.MethodPost, "/api/v1/auth/password/reset",
		`{"token":"`+tok1+`","password":"`+pass2+`"}`, h.origin, "198.51.100.4", nil, "")
	if rOld.Code != http.StatusBadRequest {
		t.Fatalf("reset with superseded token = %d, want 400", rOld.Code)
	}

	// Valid tok3 resets password, revokes all active sessions, and sends security email.
	rOK := h.doJSON(http.MethodPost, "/api/v1/auth/password/reset",
		`{"token":"`+tok3+`","password":"`+pass2+`"}`, h.origin, "198.51.100.4", nil, "")
	if rOK.Code != http.StatusOK {
		t.Fatalf("reset with valid token = %d (%s), want 200", rOK.Code, rOK.Body.String())
	}
	// Previous active session MUST now be revoked (401 SESSION_EXPIRED).
	refAfterReset := h.doJSON(http.MethodPost, "/api/v1/auth/refresh", "", h.origin, "198.51.100.2", activeCk, activeResp.CsrfToken)
	if refAfterReset.Code != http.StatusUnauthorized || decodeErrCode(t, refAfterReset) != "SESSION_EXPIRED" {
		t.Fatalf("session after password reset = (%d, %s), want (401, SESSION_EXPIRED)", refAfterReset.Code, refAfterReset.Body.String())
	}
	// New password works for login.
	loginNew := h.doJSON(http.MethodPost, "/api/v1/auth/login",
		`{"email":"frank@example.com","password":"`+pass2+`"}`, h.origin, "198.51.100.5", nil, "")
	if loginNew.Code != http.StatusOK {
		t.Fatalf("login with new password = %d, want 200", loginNew.Code)
	}
}

func TestMFASetupVerifyTwoStepLoginRecoveryAndReauth(t *testing.T) {
	h := newHarness(t, "production")
	pass := "vG9!xQ2#mK7$pR4@zN"

	_ = h.doJSON(http.MethodPost, "/api/v1/auth/register",
		`{"email":"grace@example.com","name":"Grace","password":"`+pass+`"}`, h.origin, "198.51.100.1", nil, "")
	loginRec := h.doJSON(http.MethodPost, "/api/v1/auth/login",
		`{"email":"grace@example.com","password":"`+pass+`"}`, h.origin, "198.51.100.2", nil, "")
	ck := loginRec.Result().Cookies()[0]
	var sess api.AuthSessionResponse
	_ = json.NewDecoder(loginRec.Body).Decode(&sess)

	// Advance > 10m so setup requires reauth (401 REAUTH_REQUIRED).
	h.clk.Advance(11 * time.Minute)
	setupStale := h.doJSON(http.MethodPost, "/api/v1/auth/mfa/setup", "", h.origin, "198.51.100.2", ck, sess.CsrfToken)
	if setupStale.Code != http.StatusUnauthorized || decodeErrCode(t, setupStale) != "REAUTH_REQUIRED" {
		t.Fatalf("mfa/setup after 11m = (%d, %s), want (401, REAUTH_REQUIRED)", setupStale.Code, setupStale.Body.String())
	}

	// Reauth refreshes last_auth_at and rotates session.
	reauthRec := h.doJSON(http.MethodPost, "/api/v1/auth/reauth", `{"password":"`+pass+`"}`, h.origin, "198.51.100.2", ck, sess.CsrfToken)
	if reauthRec.Code != http.StatusOK {
		t.Fatalf("reauth = %d (%s), want 200", reauthRec.Code, reauthRec.Body.String())
	}
	ck = reauthRec.Result().Cookies()[0]
	_ = json.NewDecoder(reauthRec.Body).Decode(&sess)

	// MFA setup succeeds and returns secret + otpauthUri.
	setupRec := h.doJSON(http.MethodPost, "/api/v1/auth/mfa/setup", "", h.origin, "198.51.100.2", ck, sess.CsrfToken)
	if setupRec.Code != http.StatusOK {
		t.Fatalf("mfa/setup = %d (%s), want 200", setupRec.Code, setupRec.Body.String())
	}
	var setupResp api.MFASetupResponse
	if err := json.NewDecoder(setupRec.Body).Decode(&setupResp); err != nil {
		t.Fatal(err)
	}
	rawSecret, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(setupResp.Secret)
	if err != nil {
		t.Fatalf("decode setup secret: %v", err)
	}

	// Confirm MFA setup with valid TOTP code → returns 10 recovery codes and enables MFA.
	code1 := totp.CodeAt(rawSecret, h.clk.Now())
	actRec := h.doJSON(http.MethodPost, "/api/v1/auth/mfa/verify", `{"code":"`+code1+`"}`, h.origin, "198.51.100.2", ck, sess.CsrfToken)
	if actRec.Code != http.StatusOK {
		t.Fatalf("mfa/verify activation = %d (%s), want 200", actRec.Code, actRec.Body.String())
	}
	var actResp api.MFAVerifyResponse
	if err := json.NewDecoder(actRec.Body).Decode(&actResp); err != nil {
		t.Fatal(err)
	}
	if actResp.RecoveryCodes == nil || len(*actResp.RecoveryCodes) != 10 {
		t.Fatalf("expected 10 recovery codes, got %v", actResp.RecoveryCodes)
	}
	recoveryCode := (*actResp.RecoveryCodes)[0]

	// Two-step login: step 1 returns 202 pending session.
	l2 := h.doJSON(http.MethodPost, "/api/v1/auth/login",
		`{"email":"grace@example.com","password":"`+pass+`"}`, h.origin, "198.51.100.3", nil, "")
	if l2.Code != http.StatusAccepted {
		t.Fatalf("2-step login = %d, want 202", l2.Code)
	}
	pendCk := l2.Result().Cookies()[0]
	var chal api.MFAChallengeResponse
	_ = json.NewDecoder(l2.Body).Decode(&chal)

	// Replaying code1 from the same TOTP step MUST fail (anti-replay).
	replayRec := h.doJSON(http.MethodPost, "/api/v1/auth/mfa/verify", `{"code":"`+code1+`"}`, h.origin, "198.51.100.3", pendCk, chal.CsrfToken)
	if replayRec.Code != http.StatusUnauthorized || decodeErrCode(t, replayRec) != "INVALID_MFA_CODE" {
		t.Fatalf("replayed TOTP code = (%d, %s), want (401, INVALID_MFA_CODE)", replayRec.Code, replayRec.Body.String())
	}

	// Advance 30s to next step and verify with recovery code → 200 full session.
	h.clk.Advance(30 * time.Second)
	recVerify := h.doJSON(http.MethodPost, "/api/v1/auth/mfa/verify", `{"recoveryCode":"`+recoveryCode+`"}`, h.origin, "198.51.100.3", pendCk, chal.CsrfToken)
	if recVerify.Code != http.StatusOK {
		t.Fatalf("recovery code login = %d (%s), want 200", recVerify.Code, recVerify.Body.String())
	}

	// Reusing the same recovery code on a new login fails; 5 failures revoke pending session.
	l3 := h.doJSON(http.MethodPost, "/api/v1/auth/login",
		`{"email":"grace@example.com","password":"`+pass+`"}`, h.origin, "198.51.100.4", nil, "")
	pendCk3 := l3.Result().Cookies()[0]
	var chal3 api.MFAChallengeResponse
	_ = json.NewDecoder(l3.Body).Decode(&chal3)

	for i := range 5 {
		failRec := h.doJSON(http.MethodPost, "/api/v1/auth/mfa/verify", `{"recoveryCode":"`+recoveryCode+`"}`, h.origin, "198.51.100.5", pendCk3, chal3.CsrfToken)
		if i < 4 {
			if failRec.Code != http.StatusUnauthorized || decodeErrCode(t, failRec) != "INVALID_MFA_CODE" {
				t.Fatalf("mfa fail #%d = (%d, %s), want (401, INVALID_MFA_CODE)", i+1, failRec.Code, failRec.Body.String())
			}
		} else {
			if failRec.Code != http.StatusUnauthorized || decodeErrCode(t, failRec) != "SESSION_EXPIRED" {
				t.Fatalf("5th mfa fail = (%d, %s), want (401, SESSION_EXPIRED)", failRec.Code, failRec.Body.String())
			}
		}
	}

	// CheckPrivilegedMFA helper enforces owner/admin MFA when enabled.
	if identity.CheckPrivilegedMFA(true, identity.ActiveSession{UserMFAEnabled: false}, "owner") {
		t.Fatal("CheckPrivilegedMFA must block owner without MFA when enforced")
	}
	if !identity.CheckPrivilegedMFA(true, identity.ActiveSession{UserMFAEnabled: true}, "owner") {
		t.Fatal("CheckPrivilegedMFA must allow owner with MFA")
	}
	if !identity.CheckPrivilegedMFA(true, identity.ActiveSession{UserMFAEnabled: false}, "member") {
		t.Fatal("CheckPrivilegedMFA must allow non-privileged member without MFA")
	}
}
