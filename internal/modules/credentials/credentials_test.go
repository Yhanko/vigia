package credentials

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

type stubAuth struct {
	cred AuthenticatedCredential
	err  error
}

func (s stubAuth) AuthenticateSecret(_ context.Context, _, _ string) (AuthenticatedCredential, error) {
	if s.err != nil {
		return AuthenticatedCredential{}, s.err
	}
	return s.cred, nil
}

func TestAuthMiddlewareScopeSeparation(t *testing.T) {
	t.Parallel()

	ingestKey, _, err := GenerateSecretKey(KindIngest)
	if err != nil {
		t.Fatalf("GenerateSecretKey(ingest): %v", err)
	}
	clientKey, _, err := GenerateSecretKey(KindClient)
	if err != nil {
		t.Fatalf("GenerateSecretKey(client): %v", err)
	}
	dsnKey, _, err := GenerateDSNKey()
	if err != nil {
		t.Fatalf("GenerateDSNKey: %v", err)
	}

	okHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := CredentialFromContext(r.Context()); !ok {
			t.Errorf("expected AuthenticatedCredential in context")
		}
		w.WriteHeader(http.StatusOK)
	})

	cases := []struct {
		name     string
		header   string
		key      string
		kind     string
		authErr  error
		scope    AccessScope
		wantCode int
	}{
		{"missing header", "", "", "", nil, ScopeIngest, http.StatusUnauthorized},
		{"dsn blocked on read", "Authorization", "Bearer " + dsnKey, KindDSN, nil, ScopeRead, http.StatusForbidden},
		{"dsn blocked on admin", "Authorization", "Bearer " + dsnKey, KindDSN, nil, ScopeAdmin, http.StatusForbidden},
		{"ingest allowed on ingest (Bearer)", "Authorization", "Bearer " + ingestKey, KindIngest, nil, ScopeIngest, http.StatusOK},
		{"ingest allowed on ingest (X-Vigia-Key)", "X-Vigia-Key", ingestKey, KindIngest, nil, ScopeIngest, http.StatusOK},
		{"ingest blocked on read", "Authorization", "Bearer " + ingestKey, KindIngest, nil, ScopeRead, http.StatusForbidden},
		{"ingest blocked on admin", "Authorization", "Bearer " + ingestKey, KindIngest, nil, ScopeAdmin, http.StatusForbidden},
		{"client allowed on read", "Authorization", "Bearer " + clientKey, KindClient, nil, ScopeRead, http.StatusOK},
		{"client blocked on ingest", "Authorization", "Bearer " + clientKey, KindClient, nil, ScopeIngest, http.StatusForbidden},
		{"client blocked on admin", "Authorization", "Bearer " + clientKey, KindClient, nil, ScopeAdmin, http.StatusForbidden},
		{"revoked/invalid rejected with 401", "Authorization", "Bearer " + ingestKey, KindIngest, ErrInvalidCredential, ScopeIngest, http.StatusUnauthorized},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			mw := AuthMiddleware(stubAuth{
				cred: AuthenticatedCredential{ID: "c1", OrganizationID: "o1", ProjectID: "p1", Kind: tc.kind},
				err:  tc.authErr,
			}, tc.scope, nil)

			req := httptest.NewRequest(http.MethodGet, "/api/v1/test", nil)
			if tc.header != "" {
				req.Header.Set(tc.header, tc.key)
			}
			rec := httptest.NewRecorder()
			mw(okHandler).ServeHTTP(rec, req)
			if rec.Code != tc.wantCode {
				t.Fatalf("status = %d, want %d (body=%s)", rec.Code, tc.wantCode, rec.Body.String())
			}
		})
	}
}
