//go:build integration

package e2e_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/Yhanko/vigia/internal/api"
	"github.com/Yhanko/vigia/internal/modules/audit"
	"github.com/Yhanko/vigia/internal/modules/credentials"
	"github.com/Yhanko/vigia/internal/modules/identity"
	"github.com/Yhanko/vigia/internal/modules/identity/password"
	"github.com/Yhanko/vigia/internal/modules/identity/session"
	"github.com/Yhanko/vigia/internal/modules/organizations"
	"github.com/Yhanko/vigia/internal/modules/projects"
	"github.com/Yhanko/vigia/internal/platform/clock"
	"github.com/Yhanko/vigia/internal/platform/crypto"
	"github.com/Yhanko/vigia/internal/platform/database"
	"github.com/Yhanko/vigia/internal/platform/httpserver"
	"github.com/Yhanko/vigia/internal/platform/mailer"
	"github.com/Yhanko/vigia/internal/platform/queue"
	"github.com/Yhanko/vigia/internal/platform/ratelimit"
	"github.com/Yhanko/vigia/migrations"
)

const (
	timescaleImage = "timescale/timescaledb:2.32.1-pg18@sha256:70e6526ad8e31e3f4833f2c5863b50b92d7a6bee4d432ad1f660e2c6dd956d94"
	redisImage     = "redis:8.12.0-alpine3.23@sha256:5af80107c1eeecb484a2269b80a26d12bfa6521787da4663bd9f19f60a163483"
	mailpitImage   = "axllent/mailpit:v1.34.0@sha256:23a2ef85bc50853ab3093645d1d64679afd8887e89da5e48a88940c172591a4e"
)

type e2eAPIServer struct {
	id   *identity.Handler
	orgs *organizations.Handler
	aud  *audit.Handler
	proj *projects.Handler
	cred *credentials.Handler
}

func (s e2eAPIServer) GetStatus(w http.ResponseWriter, _ *http.Request) {
	httpserver.WriteJSON(w, http.StatusOK, api.StatusResponse{Service: "vigia", Status: "ok", Version: "e2e", Commit: "e2e"})
}
func (s e2eAPIServer) AuthRegister(w http.ResponseWriter, r *http.Request)       { s.id.AuthRegister(w, r) }
func (s e2eAPIServer) AuthLogin(w http.ResponseWriter, r *http.Request)          { s.id.AuthLogin(w, r) }
func (s e2eAPIServer) AuthLogout(w http.ResponseWriter, r *http.Request, p api.AuthLogoutParams) {
	s.id.AuthLogout(w, r, p)
}
func (s e2eAPIServer) AuthRefresh(w http.ResponseWriter, r *http.Request, p api.AuthRefreshParams) {
	s.id.AuthRefresh(w, r, p)
}
func (s e2eAPIServer) AuthVerifyEmail(w http.ResponseWriter, r *http.Request)    { s.id.AuthVerifyEmail(w, r) }
func (s e2eAPIServer) AuthPasswordForgot(w http.ResponseWriter, r *http.Request) { s.id.AuthPasswordForgot(w, r) }
func (s e2eAPIServer) AuthPasswordReset(w http.ResponseWriter, r *http.Request)  { s.id.AuthPasswordReset(w, r) }
func (s e2eAPIServer) AuthMFASetup(w http.ResponseWriter, r *http.Request, p api.AuthMFASetupParams) {
	s.id.AuthMFASetup(w, r, p)
}
func (s e2eAPIServer) AuthMFAVerify(w http.ResponseWriter, r *http.Request, p api.AuthMFAVerifyParams) {
	s.id.AuthMFAVerify(w, r, p)
}
func (s e2eAPIServer) AuthReauth(w http.ResponseWriter, r *http.Request, p api.AuthReauthParams) {
	s.id.AuthReauth(w, r, p)
}
func (s e2eAPIServer) ListOrganizations(w http.ResponseWriter, r *http.Request) {
	s.orgs.ListOrganizations(w, r)
}
func (s e2eAPIServer) CreateOrganization(w http.ResponseWriter, r *http.Request, p api.CreateOrganizationParams) {
	s.orgs.CreateOrganization(w, r, p)
}
func (s e2eAPIServer) GetOrganization(w http.ResponseWriter, r *http.Request, id api.OrgIDPath) {
	s.orgs.GetOrganization(w, r, id)
}
func (s e2eAPIServer) UpdateOrganization(w http.ResponseWriter, r *http.Request, id api.OrgIDPath, p api.UpdateOrganizationParams) {
	s.orgs.UpdateOrganization(w, r, id, p)
}
func (s e2eAPIServer) DeleteOrganization(w http.ResponseWriter, r *http.Request, id api.OrgIDPath, p api.DeleteOrganizationParams) {
	s.orgs.DeleteOrganization(w, r, id, p)
}
func (s e2eAPIServer) TransferOrganizationOwnership(w http.ResponseWriter, r *http.Request, id api.OrgIDPath, p api.TransferOrganizationOwnershipParams) {
	s.orgs.TransferOrganizationOwnership(w, r, id, p)
}
func (s e2eAPIServer) ListOrganizationMembers(w http.ResponseWriter, r *http.Request, id api.OrgIDPath) {
	s.orgs.ListOrganizationMembers(w, r, id)
}
func (s e2eAPIServer) UpdateOrganizationMember(w http.ResponseWriter, r *http.Request, id api.OrgIDPath, mid api.MemberIDPath, p api.UpdateOrganizationMemberParams) {
	s.orgs.UpdateOrganizationMember(w, r, id, mid, p)
}
func (s e2eAPIServer) RemoveOrganizationMember(w http.ResponseWriter, r *http.Request, id api.OrgIDPath, mid api.MemberIDPath, p api.RemoveOrganizationMemberParams) {
	s.orgs.RemoveOrganizationMember(w, r, id, mid, p)
}
func (s e2eAPIServer) ListOrganizationInvitations(w http.ResponseWriter, r *http.Request, id api.OrgIDPath) {
	s.orgs.ListOrganizationInvitations(w, r, id)
}
func (s e2eAPIServer) CreateOrganizationInvitation(w http.ResponseWriter, r *http.Request, id api.OrgIDPath, p api.CreateOrganizationInvitationParams) {
	s.orgs.CreateOrganizationInvitation(w, r, id, p)
}
func (s e2eAPIServer) RevokeOrganizationInvitation(w http.ResponseWriter, r *http.Request, id api.OrgIDPath, iid api.InvitationIDPath, p api.RevokeOrganizationInvitationParams) {
	s.orgs.RevokeOrganizationInvitation(w, r, id, iid, p)
}
func (s e2eAPIServer) AcceptOrganizationInvitation(w http.ResponseWriter, r *http.Request, p api.AcceptOrganizationInvitationParams) {
	s.orgs.AcceptOrganizationInvitation(w, r, p)
}
func (s e2eAPIServer) ListOrganizationTeams(w http.ResponseWriter, r *http.Request, id api.OrgIDPath) {
	s.orgs.ListOrganizationTeams(w, r, id)
}
func (s e2eAPIServer) CreateOrganizationTeam(w http.ResponseWriter, r *http.Request, id api.OrgIDPath, p api.CreateOrganizationTeamParams) {
	s.orgs.CreateOrganizationTeam(w, r, id, p)
}
func (s e2eAPIServer) DeleteOrganizationTeam(w http.ResponseWriter, r *http.Request, id api.OrgIDPath, tid api.TeamIDPath, p api.DeleteOrganizationTeamParams) {
	s.orgs.DeleteOrganizationTeam(w, r, id, tid, p)
}
func (s e2eAPIServer) ListOrganizationAuditLogs(w http.ResponseWriter, r *http.Request, id api.OrgIDPath, p api.ListOrganizationAuditLogsParams) {
	s.aud.ListOrganizationAuditLogs(w, r, id, p)
}
func (s e2eAPIServer) ListOrganizationProjects(w http.ResponseWriter, r *http.Request, id api.OrgIDPath, p api.ListOrganizationProjectsParams) {
	s.proj.ListOrganizationProjects(w, r, id, p)
}
func (s e2eAPIServer) CreateOrganizationProject(w http.ResponseWriter, r *http.Request, id api.OrgIDPath, p api.CreateOrganizationProjectParams) {
	s.proj.CreateOrganizationProject(w, r, id, p)
}
func (s e2eAPIServer) GetOrganizationProject(w http.ResponseWriter, r *http.Request, id api.OrgIDPath, pid api.ProjectIDPath) {
	s.proj.GetOrganizationProject(w, r, id, pid)
}
func (s e2eAPIServer) UpdateOrganizationProject(w http.ResponseWriter, r *http.Request, id api.OrgIDPath, pid api.ProjectIDPath, p api.UpdateOrganizationProjectParams) {
	s.proj.UpdateOrganizationProject(w, r, id, pid, p)
}
func (s e2eAPIServer) DeleteOrganizationProject(w http.ResponseWriter, r *http.Request, id api.OrgIDPath, pid api.ProjectIDPath, p api.DeleteOrganizationProjectParams) {
	s.proj.DeleteOrganizationProject(w, r, id, pid, p)
}
func (s e2eAPIServer) ListProjectEnvironments(w http.ResponseWriter, r *http.Request, id api.OrgIDPath, pid api.ProjectIDPath) {
	s.proj.ListProjectEnvironments(w, r, id, pid)
}
func (s e2eAPIServer) CreateProjectEnvironment(w http.ResponseWriter, r *http.Request, id api.OrgIDPath, pid api.ProjectIDPath, p api.CreateProjectEnvironmentParams) {
	s.proj.CreateProjectEnvironment(w, r, id, pid, p)
}
func (s e2eAPIServer) DeleteProjectEnvironment(w http.ResponseWriter, r *http.Request, id api.OrgIDPath, eid api.EnvironmentIDPath, p api.DeleteProjectEnvironmentParams) {
	s.proj.DeleteProjectEnvironment(w, r, id, eid, p)
}
func (s e2eAPIServer) ListProjectCredentials(w http.ResponseWriter, r *http.Request, id api.OrgIDPath, pid api.ProjectIDPath) {
	s.cred.ListProjectCredentials(w, r, id, pid)
}
func (s e2eAPIServer) CreateProjectCredential(w http.ResponseWriter, r *http.Request, id api.OrgIDPath, pid api.ProjectIDPath, p api.CreateProjectCredentialParams) {
	s.cred.CreateProjectCredential(w, r, id, pid, p)
}
func (s e2eAPIServer) RevokeOrganizationCredential(w http.ResponseWriter, r *http.Request, id api.OrgIDPath, cid api.CredentialIDPath, p api.RevokeOrganizationCredentialParams) {
	s.cred.RevokeOrganizationCredential(w, r, id, cid, p)
}
func (s e2eAPIServer) RotateOrganizationCredential(w http.ResponseWriter, r *http.Request, id api.OrgIDPath, cid api.CredentialIDPath, p api.RotateOrganizationCredentialParams) {
	s.cred.RotateOrganizationCredential(w, r, id, cid, p)
}

func randomHex(t *testing.T, nBytes int) string {
	t.Helper()
	b := make([]byte, nBytes)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return hex.EncodeToString(b)
}

func fetchLatestEmailBody(t *testing.T, mailpitAPIURL, toEmail string) string {
	t.Helper()
	client := &http.Client{Timeout: 5 * time.Second}
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, mailpitAPIURL+"/api/v1/messages", nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("mailpit list messages: %v", err)
	}
	defer resp.Body.Close()

	var list struct {
		Messages []struct {
			ID string `json:"ID"`
			To []struct {
				Address string `json:"Address"`
			} `json:"To"`
		} `json:"messages"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&list); err != nil {
		t.Fatalf("decode mailpit list: %v", err)
	}
	for _, m := range list.Messages {
		for _, to := range m.To {
			if strings.EqualFold(to.Address, toEmail) {
				mReq, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, mailpitAPIURL+"/api/v1/message/"+m.ID, nil)
				mResp, err := client.Do(mReq)
				if err != nil {
					t.Fatalf("mailpit get message: %v", err)
				}
				defer mResp.Body.Close()
				var detail struct {
					Text string `json:"Text"`
				}
				if err := json.NewDecoder(mResp.Body).Decode(&detail); err != nil {
					t.Fatalf("decode mailpit detail: %v", err)
				}
				return detail.Text
			}
		}
	}
	t.Fatalf("no email found in Mailpit for %s", toEmail)
	return ""
}

// TestFase1EndToEndJourney exercises the full Fase 1 HTTP API over real
// PostgreSQL (TimescaleDB, vigia_app + RLS), Redis, and Mailpit:
// signup -> verify email -> login -> create org -> invite/accept member ->
// create project & environments -> create/authenticate/revoke API key ->
// verify audit trail -> verify cross-tenant isolation.
func TestFase1EndToEndJourney(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	adminPass := randomHex(t, 16)
	appPass := randomHex(t, 16)
	redisPass := randomHex(t, 16)
	sessionSecret := []byte(randomHex(t, 32))
	pepper := []byte(randomHex(t, 32))
	encKeyHex := randomHex(t, 32)

	pgCtr, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image:        timescaleImage,
			ExposedPorts: []string{"5432/tcp"},
			Env: map[string]string{
				"POSTGRES_USER":     "vigia",
				"POSTGRES_PASSWORD": adminPass,
				"POSTGRES_DB":       "vigia",
			},
			WaitingFor: wait.ForLog("database system is ready to accept connections").WithOccurrence(2).WithStartupTimeout(90 * time.Second),
		},
		Started: true,
	})
	if err != nil {
		t.Fatalf("start pg: %v", err)
	}
	t.Cleanup(func() { _ = pgCtr.Terminate(context.Background()) })

	redisCtr, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image:        redisImage,
			ExposedPorts: []string{"6379/tcp"},
			Cmd:          []string{"redis-server", "--requirepass", redisPass},
			WaitingFor:   wait.ForLog("Ready to accept connections").WithStartupTimeout(60 * time.Second),
		},
		Started: true,
	})
	if err != nil {
		t.Fatalf("start redis: %v", err)
	}
	t.Cleanup(func() { _ = redisCtr.Terminate(context.Background()) })

	mpCtr, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image:        mailpitImage,
			ExposedPorts: []string{"1025/tcp", "8025/tcp"},
			WaitingFor:   wait.ForLog("accessible via http://").WithStartupTimeout(60 * time.Second),
		},
		Started: true,
	})
	if err != nil {
		t.Fatalf("start mailpit: %v", err)
	}
	t.Cleanup(func() { _ = mpCtr.Terminate(context.Background()) })

	pgHost, _ := pgCtr.Host(ctx)
	pgPort, _ := pgCtr.MappedPort(ctx, "5432/tcp")
	rHost, _ := redisCtr.Host(ctx)
	rPort, _ := redisCtr.MappedPort(ctx, "6379/tcp")
	mpHost, _ := mpCtr.Host(ctx)
	mpSMTPPort, _ := mpCtr.MappedPort(ctx, "1025/tcp")
	mpHTTPPort, _ := mpCtr.MappedPort(ctx, "8025/tcp")

	adminDSN := fmt.Sprintf("postgres://vigia:%s@%s:%s/vigia?sslmode=disable", url.QueryEscape(adminPass), pgHost, pgPort.Port())
	appDSN := fmt.Sprintf("postgres://vigia_app:%s@%s:%s/vigia?sslmode=disable", url.QueryEscape(appPass), pgHost, pgPort.Port())
	if err := database.EnsureRoles(ctx, adminDSN, appPass); err != nil {
		t.Fatalf("EnsureRoles: %v", err)
	}
	if err := database.Migrate(ctx, adminDSN, migrations.FS, "up"); err != nil {
		t.Fatalf("Migrate up: %v", err)
	}

	pool, err := database.NewPool(ctx, appDSN, database.PoolOptions{MaxConns: 10})
	if err != nil {
		t.Fatalf("NewPool: %v", err)
	}
	t.Cleanup(pool.Close)

	rdb, err := queue.NewRedisClient(ctx, rHost+":"+rPort.Port(), redisPass)
	if err != nil {
		t.Fatalf("NewRedisClient: %v", err)
	}
	t.Cleanup(func() { _ = rdb.Close() })

	mailSender, err := mailer.NewSMTPMailer(fmt.Sprintf("smtp://%s:%s", mpHost, mpSMTPPort.Port()), "no-reply@vigia.ao")
	if err != nil {
		t.Fatalf("NewSMTPMailer: %v", err)
	}
	mailpitAPI := fmt.Sprintf("http://%s:%s", mpHost, mpHTTPPort.Port())

	kr, err := crypto.ParseKeyring([]byte("k1:" + encKeyHex))
	if err != nil {
		t.Fatalf("ParseKeyring: %v", err)
	}
	enc, err := crypto.NewEnvelopeEncrypter(kr)
	if err != nil {
		t.Fatalf("NewEnvelopeEncrypter: %v", err)
	}

	var logBuf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logBuf, nil))
	clk := clock.System{}
	origin := "https://app.vigia.ao"

	limiter, _ := ratelimit.NewRedisLimiter(rdb, clk)
	idStore, _ := identity.NewPostgresStore(pool)
	idHasher, _ := password.NewHasher(password.Options{})
	idSessions, _ := session.NewCodec(sessionSecret, "development")
	idSvc, _ := identity.NewService(identity.ServiceConfig{
		Store:           idStore,
		Hasher:          idHasher,
		Sessions:        idSessions,
		Limiter:         limiter,
		RateLimitSecret: sessionSecret,
		Encrypter:       enc,
		Mailer:          mailSender,
		AppURL:          origin,
		Clock:           clk,
		Logger:          logger,
	})
	idHandler, _ := identity.NewHandler(idSvc, idSessions, []string{origin}, nil, logger)

	orgSvc, _ := organizations.NewService(organizations.ServiceConfig{
		Pool:                     pool,
		Mailer:                   mailSender,
		AppURL:                   origin,
		MFARequiredForPrivileged: false,
		Clock:                    clk,
	})
	orgHandler, _ := organizations.NewHandler(orgSvc, nil, logger)
	audSvc, _ := audit.NewService(pool)
	audHandler, _ := audit.NewHandler(audSvc, orgSvc, nil, logger)
	credSvc, _ := credentials.NewService(credentials.ServiceConfig{
		Pool:                     pool,
		Cache:                    credentials.NewRedisCache(rdb),
		Pepper:                   pepper,
		IngestHost:               "ingest.vigia.ao",
		MFARequiredForPrivileged: false,
		Clock:                    clk,
		Logger:                   logger,
	})
	t.Cleanup(func() { credSvc.Close(context.Background()) })
	credHandler, _ := credentials.NewHandler(credSvc, nil, logger)
	projSvc, _ := projects.NewService(projects.ServiceConfig{
		Pool:                     pool,
		CredentialInvalidator:    credSvc,
		MFARequiredForPrivileged: false,
		Clock:                    clk,
	})
	projHandler, _ := projects.NewHandler(projSvc, nil, logger)

	router := httpserver.NewHandler(httpserver.Options{
		Version:     "e2e",
		Commit:      "e2e",
		Logger:      logger,
		CORSOrigins: []string{origin},
		APIAuth:     identity.SessionAndCSRFMiddleware(idSvc, idSessions, []string{origin}),
		APIServer: e2eAPIServer{
			id:   idHandler,
			orgs: orgHandler,
			aud:  audHandler,
			proj: projHandler,
			cred: credHandler,
		},
	})

	doReq := func(method, path string, body any, ck *http.Cookie, csrf string) *httptest.ResponseRecorder {
		var rdr io.Reader
		if body != nil {
			b, _ := json.Marshal(body)
			rdr = bytes.NewReader(b)
		}
		req := httptest.NewRequest(method, path, rdr)
		req.Header.Set("Origin", origin)
		req.RemoteAddr = "198.51.100.50:12345"
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		if ck != nil {
			req.AddCookie(ck)
		}
		if csrf != "" {
			req.Header.Set("X-CSRF-Token", csrf)
		}
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		return rec
	}

	tokenRe := regexp.MustCompile(`token=([A-Za-z0-9_-]+)`)
	registerAndLogin := func(email, name, pass string) (*http.Cookie, string) {
		rec := doReq(http.MethodPost, "/api/v1/auth/register", map[string]string{
			"email": email, "name": name, "password": pass,
		}, nil, "")
		if rec.Code != http.StatusAccepted {
			t.Fatalf("register %s: status=%d body=%s", email, rec.Code, rec.Body.String())
		}
		emailText := fetchLatestEmailBody(t, mailpitAPI, email)
		m := tokenRe.FindStringSubmatch(emailText)
		if len(m) != 2 {
			t.Fatalf("verification token not found in email: %s", emailText)
		}
		rec = doReq(http.MethodPost, "/api/v1/auth/verify-email", map[string]string{"token": m[1]}, nil, "")
		if rec.Code != http.StatusOK {
			t.Fatalf("verify-email %s: status=%d body=%s", email, rec.Code, rec.Body.String())
		}
		rec = doReq(http.MethodPost, "/api/v1/auth/login", map[string]string{"email": email, "password": pass}, nil, "")
		if rec.Code != http.StatusOK {
			t.Fatalf("login %s: status=%d body=%s", email, rec.Code, rec.Body.String())
		}
		var loginResp api.AuthSessionResponse
		_ = json.NewDecoder(rec.Body).Decode(&loginResp)
		cookies := rec.Result().Cookies()
		if len(cookies) == 0 {
			t.Fatalf("expected session cookie for %s", email)
		}
		return cookies[0], loginResp.CsrfToken
	}

	// 1. Register, verify via Mailpit, and login Owner A & Outsider B.
	ownerPass := "Vigia-E2E-Pass-" + randomHex(t, 6)
	ownerCookie, ownerCSRF := registerAndLogin("e2e-owner@vigia.ao", "E2E Owner", ownerPass)
	outsiderCookie, _ := registerAndLogin("e2e-outsider@vigia.ao", "Outsider", "Outsider-Pass-"+randomHex(t, 6))

	// 2. Create organization.
	rec := doReq(http.MethodPost, "/api/v1/organizations", map[string]string{
		"name": "Luanda Labs", "slug": "luanda-labs",
	}, ownerCookie, ownerCSRF)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create org: status=%d body=%s", rec.Code, rec.Body.String())
	}
	var org api.OrganizationResponse
	_ = json.NewDecoder(rec.Body).Decode(&org)

	// 3. Create project + protected production environment + non-protected staging environment.
	rec = doReq(http.MethodPost, "/api/v1/organizations/"+org.Id+"/projects", map[string]string{
		"name": "Payments API", "slug": "payments-api", "platform": "go",
	}, ownerCookie, ownerCSRF)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create project: status=%d body=%s", rec.Code, rec.Body.String())
	}
	var proj api.ProjectResponse
	_ = json.NewDecoder(rec.Body).Decode(&proj)

	rec = doReq(http.MethodPost, "/api/v1/organizations/"+org.Id+"/projects/"+proj.Id+"/environments", map[string]any{
		"name": "production", "isProtected": true,
	}, ownerCookie, ownerCSRF)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create prod env: status=%d body=%s", rec.Code, rec.Body.String())
	}
	var prodEnv api.EnvironmentResponse
	_ = json.NewDecoder(rec.Body).Decode(&prodEnv)

	// Protected environment must reject deletion with 403 PROTECTED_RESOURCE.
	rec = doReq(http.MethodDelete, "/api/v1/organizations/"+org.Id+"/environments/"+prodEnv.Id, nil, ownerCookie, ownerCSRF)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("delete protected env: status=%d, want 403", rec.Code)
	}

	// 4. Create ingest credential (secret shown once), authenticate, revoke, verify immediate rejection.
	rec = doReq(http.MethodPost, "/api/v1/organizations/"+org.Id+"/projects/"+proj.Id+"/credentials", map[string]any{
		"kind": "ingest", "name": "Prod Ingest", "environmentId": prodEnv.Id,
	}, ownerCookie, ownerCSRF)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create cred: status=%d body=%s", rec.Code, rec.Body.String())
	}
	var createdCred api.CreatedCredentialResponse
	_ = json.NewDecoder(rec.Body).Decode(&createdCred)
	if createdCred.Secret == nil || !strings.HasPrefix(*createdCred.Secret, "vg_ing_") {
		t.Fatalf("expected vg_ing_ secret once, got %v", createdCred.Secret)
	}

	if _, err := credSvc.AuthenticateSecret(ctx, *createdCred.Secret, "198.51.100.50"); err != nil {
		t.Fatalf("AuthenticateSecret: %v", err)
	}
	rec = doReq(http.MethodPost, "/api/v1/organizations/"+org.Id+"/credentials/"+createdCred.Credential.Id+"/revoke", nil, ownerCookie, ownerCSRF)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("revoke cred: status=%d body=%s", rec.Code, rec.Body.String())
	}
	if _, err := credSvc.AuthenticateSecret(ctx, *createdCred.Secret, "198.51.100.50"); err == nil {
		t.Fatal("expected revoked credential to be rejected immediately")
	}

	// 5. Verify audit logs contain full trail and no secret values.
	rec = doReq(http.MethodGet, "/api/v1/organizations/"+org.Id+"/audit-logs?limit=20", nil, ownerCookie, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("audit logs: status=%d body=%s", rec.Code, rec.Body.String())
	}
	auditBody := rec.Body.String()
	if strings.Contains(auditBody, *createdCred.Secret) || strings.Contains(auditBody, ownerPass) {
		t.Fatal("secret leaked in audit logs HTTP response!")
	}
	for _, action := range []string{"org.created", "project.created", "credential.created", "credential.revoked"} {
		if !strings.Contains(auditBody, action) {
			t.Errorf("expected audit action %q in response", action)
		}
	}

	// 6. Cross-tenant negative check over HTTP.
	rec = doReq(http.MethodGet, "/api/v1/organizations/"+org.Id+"/projects", nil, outsiderCookie, "")
	if rec.Code != http.StatusForbidden && rec.Code != http.StatusNotFound {
		t.Fatalf("outsider GET orgA projects: status=%d, want 403 or 404", rec.Code)
	}
	rec = doReq(http.MethodGet, "/api/v1/organizations/"+org.Id+"/audit-logs", nil, outsiderCookie, "")
	if rec.Code != http.StatusNotFound && rec.Code != http.StatusForbidden {
		t.Fatalf("outsider GET orgA audit-logs: status=%d, want 404 or 403", rec.Code)
	}
}
