// Command vigia: single static binary with one subcommand per runtime role (README §4.4).
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"

	"github.com/Yhanko/vigia/internal/api"
	"github.com/Yhanko/vigia/internal/modules/audit"
	"github.com/Yhanko/vigia/internal/modules/credentials"
	"github.com/Yhanko/vigia/internal/modules/identity"
	"github.com/Yhanko/vigia/internal/modules/identity/password"
	"github.com/Yhanko/vigia/internal/modules/identity/session"
	"github.com/Yhanko/vigia/internal/modules/organizations"
	"github.com/Yhanko/vigia/internal/modules/projects"
	"github.com/Yhanko/vigia/internal/platform/clock"
	"github.com/Yhanko/vigia/internal/platform/config"
	"github.com/Yhanko/vigia/internal/platform/crypto"
	"github.com/Yhanko/vigia/internal/platform/database"
	"github.com/Yhanko/vigia/internal/platform/httpserver"
	"github.com/Yhanko/vigia/internal/platform/mailer"
	"github.com/Yhanko/vigia/internal/platform/queue"
	"github.com/Yhanko/vigia/internal/platform/ratelimit"
	"github.com/Yhanko/vigia/internal/platform/telemetry"
	"github.com/Yhanko/vigia/migrations"
)

// Injected at build time via -ldflags "-X main.version=... -X main.commit=...".
var (
	version = "dev"
	commit  = "none"
)

const usage = `Usage: vigia <command>

Commands:
  api                            Start the HTTP API server
  migrate [up|down|status|version]  Run embedded SQL database migrations (default: up)
  db ensure-roles                Create/update PostgreSQL runtime roles (vigia_app, vigia_definer) without running migrations
  healthcheck                    Check local /health/live (for container HEALTHCHECK)
  version                        Print binary version

Planned (next phases): worker, scheduler, evaluator, dispatcher`

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, nil)))

	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, usage)
		os.Exit(2)
	}

	var err error
	switch os.Args[1] {
	case "api":
		err = runAPI()
	case "migrate":
		action := "up"
		if len(os.Args) >= 3 {
			action = os.Args[2]
		}
		err = runMigrate(action)
	case "db":
		if len(os.Args) >= 3 && os.Args[2] == "ensure-roles" {
			err = runEnsureRoles()
		} else {
			fmt.Fprintln(os.Stderr, usage)
			os.Exit(2)
		}
	case "healthcheck":
		err = runHealthcheck()
	case "version":
		fmt.Printf("vigia %s (commit %s)\n", version, commit)
		return
	case "-h", "--help", "help":
		fmt.Println(usage)
		return
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %q\n\n%s\n", os.Args[1], usage)
		os.Exit(2)
	}

	if err != nil {
		slog.Error("process exited with error", "error", err)
		os.Exit(1)
	}
}

func runAPI() error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}

	logger, err := telemetry.NewLogger(os.Stdout, cfg.LogLevel, "vigia-api", cfg.AppEnv)
	if err != nil {
		return err
	}
	slog.SetDefault(logger)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var encrypter *crypto.EnvelopeEncrypter
	if !cfg.EncryptionKey.IsEmpty() {
		kr, err := crypto.ParseKeyring([]byte(cfg.EncryptionKey.Value()))
		if err != nil {
			return fmt.Errorf("load ENCRYPTION_KEY_FILE: %w", err)
		}
		encrypter, err = crypto.NewEnvelopeEncrypter(kr)
		if err != nil {
			return fmt.Errorf("init envelope encrypter: %w", err)
		}
		logger.Info("encryption keyring loaded", "active_key_id", kr.ActiveKeyID())
	} else {
		logger.Warn("ENCRYPTION_KEY_FILE not set; running without envelope encryption")
	}

	var (
		checks []httpserver.ReadinessCheck
		pool   *pgxpool.Pool
		rdb    *redis.Client
	)

	if cfg.DatabaseURL != "" {
		dsn, err := cfg.DatabaseDSN()
		if err != nil {
			return err
		}
		pool, err = database.NewPool(ctx, dsn, database.PoolOptions{
			MaxConns:         cfg.DatabaseMaxConns,
			StatementTimeout: cfg.DatabaseStatementTimeout,
		})
		if err != nil {
			return err
		}
		defer pool.Close()
		logger.Info("connected to PostgreSQL")

		if err := enforceRuntimeDBRole(cfg.AppEnv, database.VerifyNonPrivilegedRole(ctx, pool), logger); err != nil {
			return err
		}

		checks = append(checks, httpserver.ReadinessCheck{
			Name:  "postgres",
			Check: func(c context.Context) error { return pool.Ping(c) },
		})
	} else {
		logger.Warn("DATABASE_URL not set; running without database connection")
	}

	if cfg.RedisAddr != "" {
		rdb, err = queue.NewRedisClient(ctx, cfg.RedisAddr, cfg.RedisPassword.Value())
		if err != nil {
			return err
		}
		defer rdb.Close()
		logger.Info("connected to Redis", "addr", cfg.RedisAddr)

		checks = append(checks, httpserver.ReadinessCheck{
			Name:  "redis",
			Check: func(c context.Context) error { return rdb.Ping(c).Err() },
		})
	} else {
		logger.Warn("REDIS_ADDR not set; running without Redis connection")
	}

	clk := clock.System{}
	var (
		limiter        *ratelimit.RedisLimiter
		apiRateLimitMW func(http.Handler) http.Handler
	)
	if rdb != nil {
		limiter, err = ratelimit.NewRedisLimiter(rdb, clk)
		if err != nil {
			return err
		}
		apiRateLimitMW = ratelimit.Middleware(ratelimit.MiddlewareOptions{
			Limiter:        limiter,
			KeyPrefix:      "api",
			Limit:          120,
			Window:         time.Minute,
			FailClosed:     false,
			TrustedProxies: cfg.TrustedProxies,
			Logger:         logger,
		})
	}

	var (
		idHandler   *identity.Handler
		orgHandler  *organizations.Handler
		audHandler  *audit.Handler
		projHandler *projects.Handler
		credHandler *credentials.Handler
		apiAuthMW   func(http.Handler) http.Handler
		credSvc     *credentials.Service
	)
	allowedOrigins := buildAllowedOrigins(cfg)

	var mailSender *mailer.SMTPMailer
	if cfg.SMTPURL != "" {
		mailSender, err = mailer.NewSMTPMailer(cfg.SMTPURL, "no-reply@vigia.ao")
		if err != nil {
			return err
		}
	}

	if pool != nil && limiter != nil && !cfg.SessionSecret.IsEmpty() {
		idStore, err := identity.NewPostgresStore(pool)
		if err != nil {
			return err
		}
		idHasher, err := password.NewHasher(password.Options{})
		if err != nil {
			return err
		}
		idSessions, err := session.NewCodec([]byte(cfg.SessionSecret.Value()), cfg.AppEnv)
		if err != nil {
			return err
		}
		var idMailer identity.Mailer
		if mailSender != nil {
			idMailer = mailSender
		}
		var idEnc identity.SecretEncrypter
		if encrypter != nil {
			idEnc = encrypter
		}
		idSvc, err := identity.NewService(identity.ServiceConfig{
			Store:           idStore,
			Hasher:          idHasher,
			Sessions:        idSessions,
			Limiter:         limiter,
			RateLimitSecret: []byte(cfg.SessionSecret.Value()),
			Encrypter:       idEnc,
			Mailer:          idMailer,
			AppURL:          cfg.AppURL,
			Clock:           clk,
			Logger:          logger,
		})
		if err != nil {
			return err
		}
		idHandler, err = identity.NewHandler(idSvc, idSessions, allowedOrigins, cfg.TrustedProxies, logger)
		if err != nil {
			return err
		}
		apiAuthMW = identity.SessionAndCSRFMiddleware(idSvc, idSessions, allowedOrigins)

		var (
			credInvalidator    projects.CredentialCacheInvalidator
			orgCredInvalidator organizations.CredentialCacheInvalidator
		)
		if !cfg.APIKeyPepper.IsEmpty() {
			var credCache credentials.Cache
			if rdb != nil {
				credCache = credentials.NewRedisCache(rdb)
			}
			ingestHost := "ingest.vigia.local"
			if u, uErr := url.Parse(cfg.AppURL); uErr == nil && u.Host != "" {
				ingestHost = u.Host
			}
			credSvc, err = credentials.NewService(credentials.ServiceConfig{
				Pool:                     pool,
				Cache:                    credCache,
				Pepper:                   []byte(cfg.APIKeyPepper.Value()),
				IngestHost:               ingestHost,
				MFARequiredForPrivileged: cfg.MFARequiredForPrivileged,
				Clock:                    clk,
				Logger:                   logger,
			})
			if err != nil {
				return err
			}
			defer func() {
				flushCtx, flushCancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer flushCancel()
				credSvc.Close(flushCtx)
			}()
			credInvalidator = credSvc
			orgCredInvalidator = credSvc
			credHandler, err = credentials.NewHandler(credSvc, cfg.TrustedProxies, logger)
			if err != nil {
				return err
			}
		}

		var orgMailer organizations.Mailer
		if mailSender != nil {
			orgMailer = mailSender
		}
		orgSvc, err := organizations.NewService(organizations.ServiceConfig{
			Pool:                     pool,
			Mailer:                   orgMailer,
			CredentialInvalidator:    orgCredInvalidator,
			AppURL:                   cfg.AppURL,
			MFARequiredForPrivileged: cfg.MFARequiredForPrivileged,
			Clock:                    clk,
		})
		if err != nil {
			return err
		}
		orgHandler, err = organizations.NewHandler(orgSvc, cfg.TrustedProxies, logger)
		if err != nil {
			return err
		}

		audSvc, err := audit.NewService(pool)
		if err != nil {
			return err
		}
		audHandler, err = audit.NewHandler(audSvc, orgSvc, cfg.TrustedProxies, logger)
		if err != nil {
			return err
		}

		projSvc, err := projects.NewService(projects.ServiceConfig{
			Pool:                     pool,
			CredentialInvalidator:    credInvalidator,
			MFARequiredForPrivileged: cfg.MFARequiredForPrivileged,
			Clock:                    clk,
		})
		if err != nil {
			return err
		}
		projHandler, err = projects.NewHandler(projSvc, cfg.TrustedProxies, logger)
		if err != nil {
			return err
		}
	} else {
		logger.Warn("identity endpoints disabled (requires DATABASE_URL, REDIS_ADDR, and SESSION_SECRET_FILE)")
	}

	composedAPI := compositeAPIServer{
		version:     version,
		commit:      commit,
		identity:    idHandler,
		orgs:        orgHandler,
		audit:       audHandler,
		projects:    projHandler,
		credentials: credHandler,
	}

	srv := httpserver.New(httpserver.Options{
		Port:         cfg.Port,
		Version:      version,
		Commit:       commit,
		Logger:       logger,
		CORSOrigins:  cfg.CORSOrigins,
		MaxBodyBytes: cfg.APIMaxBodyBytes,
		HSTS:         cfg.AppEnv == "production",
		APIRateLimit: apiRateLimitMW,
		APIAuth:      apiAuthMW,
		APIServer:    composedAPI,
	})
	adminSrv := httpserver.NewAdmin(httpserver.AdminOptions{
		Port:            cfg.AdminPort,
		Logger:          logger,
		HSTS:            cfg.AppEnv == "production",
		ReadinessChecks: checks,
	})

	errCh := make(chan error, 2)
	go func() {
		logger.Info("API listening", "addr", srv.Addr, "version", version, "commit", commit)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- fmt.Errorf("public api server: %w", err)
		}
	}()
	go func() {
		logger.Info("admin server listening", "addr", adminSrv.Addr)
		if err := adminSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- fmt.Errorf("admin server: %w", err)
		}
	}()

	var runErr error
	select {
	case err := <-errCh:
		runErr = err
		logger.Error("server failed, shutting down both listeners", "error", err)
	case <-ctx.Done():
		logger.Info("shutting down API and admin listeners")
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	shutdownErr := errors.Join(
		srv.Shutdown(shutdownCtx),
		adminSrv.Shutdown(shutdownCtx),
	)
	return errors.Join(runErr, shutdownErr)
}

// compositeAPIServer composes domain handlers with the infrastructure /status
// endpoint to satisfy api.ServerInterface (CTO #6, #18).
type compositeAPIServer struct {
	version     string
	commit      string
	identity    *identity.Handler
	orgs        *organizations.Handler
	audit       *audit.Handler
	projects    *projects.Handler
	credentials *credentials.Handler
}

func (s compositeAPIServer) GetStatus(w http.ResponseWriter, _ *http.Request) {
	httpserver.WriteJSON(w, http.StatusOK, api.StatusResponse{
		Service: "vigia",
		Status:  "ok",
		Version: s.version,
		Commit:  s.commit,
	})
}

func (s compositeAPIServer) AuthRegister(w http.ResponseWriter, r *http.Request) {
	if s.identity == nil {
		w.Header().Set("Retry-After", "5")
		httpserver.WriteError(w, r, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", "Authentication service unavailable.")
		return
	}
	s.identity.AuthRegister(w, r)
}

func (s compositeAPIServer) AuthLogin(w http.ResponseWriter, r *http.Request) {
	if s.identity == nil {
		w.Header().Set("Retry-After", "5")
		httpserver.WriteError(w, r, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", "Authentication service unavailable.")
		return
	}
	s.identity.AuthLogin(w, r)
}

func (s compositeAPIServer) AuthLogout(w http.ResponseWriter, r *http.Request, params api.AuthLogoutParams) {
	if s.identity == nil {
		w.Header().Set("Retry-After", "5")
		httpserver.WriteError(w, r, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", "Authentication service unavailable.")
		return
	}
	s.identity.AuthLogout(w, r, params)
}

func (s compositeAPIServer) AuthRefresh(w http.ResponseWriter, r *http.Request, params api.AuthRefreshParams) {
	if s.identity == nil {
		w.Header().Set("Retry-After", "5")
		httpserver.WriteError(w, r, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", "Authentication service unavailable.")
		return
	}
	s.identity.AuthRefresh(w, r, params)
}

func (s compositeAPIServer) AuthVerifyEmail(w http.ResponseWriter, r *http.Request) {
	if s.identity == nil {
		w.Header().Set("Retry-After", "5")
		httpserver.WriteError(w, r, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", "Authentication service unavailable.")
		return
	}
	s.identity.AuthVerifyEmail(w, r)
}

func (s compositeAPIServer) AuthPasswordForgot(w http.ResponseWriter, r *http.Request) {
	if s.identity == nil {
		w.Header().Set("Retry-After", "5")
		httpserver.WriteError(w, r, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", "Authentication service unavailable.")
		return
	}
	s.identity.AuthPasswordForgot(w, r)
}

func (s compositeAPIServer) AuthPasswordReset(w http.ResponseWriter, r *http.Request) {
	if s.identity == nil {
		w.Header().Set("Retry-After", "5")
		httpserver.WriteError(w, r, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", "Authentication service unavailable.")
		return
	}
	s.identity.AuthPasswordReset(w, r)
}

func (s compositeAPIServer) AuthMFASetup(w http.ResponseWriter, r *http.Request, params api.AuthMFASetupParams) {
	if s.identity == nil {
		w.Header().Set("Retry-After", "5")
		httpserver.WriteError(w, r, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", "Authentication service unavailable.")
		return
	}
	s.identity.AuthMFASetup(w, r, params)
}

func (s compositeAPIServer) AuthMFAVerify(w http.ResponseWriter, r *http.Request, params api.AuthMFAVerifyParams) {
	if s.identity == nil {
		w.Header().Set("Retry-After", "5")
		httpserver.WriteError(w, r, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", "Authentication service unavailable.")
		return
	}
	s.identity.AuthMFAVerify(w, r, params)
}

func (s compositeAPIServer) AuthReauth(w http.ResponseWriter, r *http.Request, params api.AuthReauthParams) {
	if s.identity == nil {
		writeServiceUnavailable(w, r)
		return
	}
	s.identity.AuthReauth(w, r, params)
}

func (s compositeAPIServer) ListOrganizations(w http.ResponseWriter, r *http.Request) {
	if s.orgs == nil {
		writeServiceUnavailable(w, r)
		return
	}
	s.orgs.ListOrganizations(w, r)
}

func (s compositeAPIServer) CreateOrganization(w http.ResponseWriter, r *http.Request, params api.CreateOrganizationParams) {
	if s.orgs == nil {
		writeServiceUnavailable(w, r)
		return
	}
	s.orgs.CreateOrganization(w, r, params)
}

func (s compositeAPIServer) GetOrganization(w http.ResponseWriter, r *http.Request, orgId api.OrgIDPath) {
	if s.orgs == nil {
		writeServiceUnavailable(w, r)
		return
	}
	s.orgs.GetOrganization(w, r, orgId)
}

func (s compositeAPIServer) UpdateOrganization(w http.ResponseWriter, r *http.Request, orgId api.OrgIDPath, params api.UpdateOrganizationParams) {
	if s.orgs == nil {
		writeServiceUnavailable(w, r)
		return
	}
	s.orgs.UpdateOrganization(w, r, orgId, params)
}

func (s compositeAPIServer) DeleteOrganization(w http.ResponseWriter, r *http.Request, orgId api.OrgIDPath, params api.DeleteOrganizationParams) {
	if s.orgs == nil {
		writeServiceUnavailable(w, r)
		return
	}
	s.orgs.DeleteOrganization(w, r, orgId, params)
}

func (s compositeAPIServer) TransferOrganizationOwnership(w http.ResponseWriter, r *http.Request, orgId api.OrgIDPath, params api.TransferOrganizationOwnershipParams) {
	if s.orgs == nil {
		writeServiceUnavailable(w, r)
		return
	}
	s.orgs.TransferOrganizationOwnership(w, r, orgId, params)
}

func (s compositeAPIServer) ListOrganizationMembers(w http.ResponseWriter, r *http.Request, orgId api.OrgIDPath) {
	if s.orgs == nil {
		writeServiceUnavailable(w, r)
		return
	}
	s.orgs.ListOrganizationMembers(w, r, orgId)
}

func (s compositeAPIServer) UpdateOrganizationMember(w http.ResponseWriter, r *http.Request, orgId api.OrgIDPath, memberId api.MemberIDPath, params api.UpdateOrganizationMemberParams) {
	if s.orgs == nil {
		writeServiceUnavailable(w, r)
		return
	}
	s.orgs.UpdateOrganizationMember(w, r, orgId, memberId, params)
}

func (s compositeAPIServer) RemoveOrganizationMember(w http.ResponseWriter, r *http.Request, orgId api.OrgIDPath, memberId api.MemberIDPath, params api.RemoveOrganizationMemberParams) {
	if s.orgs == nil {
		writeServiceUnavailable(w, r)
		return
	}
	s.orgs.RemoveOrganizationMember(w, r, orgId, memberId, params)
}

func (s compositeAPIServer) ListOrganizationInvitations(w http.ResponseWriter, r *http.Request, orgId api.OrgIDPath) {
	if s.orgs == nil {
		writeServiceUnavailable(w, r)
		return
	}
	s.orgs.ListOrganizationInvitations(w, r, orgId)
}

func (s compositeAPIServer) CreateOrganizationInvitation(w http.ResponseWriter, r *http.Request, orgId api.OrgIDPath, params api.CreateOrganizationInvitationParams) {
	if s.orgs == nil {
		writeServiceUnavailable(w, r)
		return
	}
	s.orgs.CreateOrganizationInvitation(w, r, orgId, params)
}

func (s compositeAPIServer) RevokeOrganizationInvitation(w http.ResponseWriter, r *http.Request, orgId api.OrgIDPath, invitationId api.InvitationIDPath, params api.RevokeOrganizationInvitationParams) {
	if s.orgs == nil {
		writeServiceUnavailable(w, r)
		return
	}
	s.orgs.RevokeOrganizationInvitation(w, r, orgId, invitationId, params)
}

func (s compositeAPIServer) AcceptOrganizationInvitation(w http.ResponseWriter, r *http.Request, params api.AcceptOrganizationInvitationParams) {
	if s.orgs == nil {
		writeServiceUnavailable(w, r)
		return
	}
	s.orgs.AcceptOrganizationInvitation(w, r, params)
}

func (s compositeAPIServer) ListOrganizationTeams(w http.ResponseWriter, r *http.Request, orgId api.OrgIDPath) {
	if s.orgs == nil {
		writeServiceUnavailable(w, r)
		return
	}
	s.orgs.ListOrganizationTeams(w, r, orgId)
}

func (s compositeAPIServer) CreateOrganizationTeam(w http.ResponseWriter, r *http.Request, orgId api.OrgIDPath, params api.CreateOrganizationTeamParams) {
	if s.orgs == nil {
		writeServiceUnavailable(w, r)
		return
	}
	s.orgs.CreateOrganizationTeam(w, r, orgId, params)
}

func (s compositeAPIServer) DeleteOrganizationTeam(w http.ResponseWriter, r *http.Request, orgId api.OrgIDPath, teamId api.TeamIDPath, params api.DeleteOrganizationTeamParams) {
	if s.orgs == nil {
		writeServiceUnavailable(w, r)
		return
	}
	s.orgs.DeleteOrganizationTeam(w, r, orgId, teamId, params)
}

func (s compositeAPIServer) ListOrganizationAuditLogs(w http.ResponseWriter, r *http.Request, orgId api.OrgIDPath, params api.ListOrganizationAuditLogsParams) {
	if s.audit == nil {
		writeServiceUnavailable(w, r)
		return
	}
	s.audit.ListOrganizationAuditLogs(w, r, orgId, params)
}

func (s compositeAPIServer) ListOrganizationProjects(w http.ResponseWriter, r *http.Request, orgId api.OrgIDPath, params api.ListOrganizationProjectsParams) {
	if s.projects == nil {
		writeServiceUnavailable(w, r)
		return
	}
	s.projects.ListOrganizationProjects(w, r, orgId, params)
}

func (s compositeAPIServer) CreateOrganizationProject(w http.ResponseWriter, r *http.Request, orgId api.OrgIDPath, params api.CreateOrganizationProjectParams) {
	if s.projects == nil {
		writeServiceUnavailable(w, r)
		return
	}
	s.projects.CreateOrganizationProject(w, r, orgId, params)
}

func (s compositeAPIServer) GetOrganizationProject(w http.ResponseWriter, r *http.Request, orgId api.OrgIDPath, projectId api.ProjectIDPath) {
	if s.projects == nil {
		writeServiceUnavailable(w, r)
		return
	}
	s.projects.GetOrganizationProject(w, r, orgId, projectId)
}

func (s compositeAPIServer) UpdateOrganizationProject(w http.ResponseWriter, r *http.Request, orgId api.OrgIDPath, projectId api.ProjectIDPath, params api.UpdateOrganizationProjectParams) {
	if s.projects == nil {
		writeServiceUnavailable(w, r)
		return
	}
	s.projects.UpdateOrganizationProject(w, r, orgId, projectId, params)
}

func (s compositeAPIServer) DeleteOrganizationProject(w http.ResponseWriter, r *http.Request, orgId api.OrgIDPath, projectId api.ProjectIDPath, params api.DeleteOrganizationProjectParams) {
	if s.projects == nil {
		writeServiceUnavailable(w, r)
		return
	}
	s.projects.DeleteOrganizationProject(w, r, orgId, projectId, params)
}

func (s compositeAPIServer) ListProjectEnvironments(w http.ResponseWriter, r *http.Request, orgId api.OrgIDPath, projectId api.ProjectIDPath) {
	if s.projects == nil {
		writeServiceUnavailable(w, r)
		return
	}
	s.projects.ListProjectEnvironments(w, r, orgId, projectId)
}

func (s compositeAPIServer) CreateProjectEnvironment(w http.ResponseWriter, r *http.Request, orgId api.OrgIDPath, projectId api.ProjectIDPath, params api.CreateProjectEnvironmentParams) {
	if s.projects == nil {
		writeServiceUnavailable(w, r)
		return
	}
	s.projects.CreateProjectEnvironment(w, r, orgId, projectId, params)
}

func (s compositeAPIServer) DeleteProjectEnvironment(w http.ResponseWriter, r *http.Request, orgId api.OrgIDPath, environmentId api.EnvironmentIDPath, params api.DeleteProjectEnvironmentParams) {
	if s.projects == nil {
		writeServiceUnavailable(w, r)
		return
	}
	s.projects.DeleteProjectEnvironment(w, r, orgId, environmentId, params)
}

func (s compositeAPIServer) ListProjectCredentials(w http.ResponseWriter, r *http.Request, orgId api.OrgIDPath, projectId api.ProjectIDPath) {
	if s.credentials == nil {
		writeServiceUnavailable(w, r)
		return
	}
	s.credentials.ListProjectCredentials(w, r, orgId, projectId)
}

func (s compositeAPIServer) CreateProjectCredential(w http.ResponseWriter, r *http.Request, orgId api.OrgIDPath, projectId api.ProjectIDPath, params api.CreateProjectCredentialParams) {
	if s.credentials == nil {
		writeServiceUnavailable(w, r)
		return
	}
	s.credentials.CreateProjectCredential(w, r, orgId, projectId, params)
}

func (s compositeAPIServer) RevokeOrganizationCredential(w http.ResponseWriter, r *http.Request, orgId api.OrgIDPath, credentialId api.CredentialIDPath, params api.RevokeOrganizationCredentialParams) {
	if s.credentials == nil {
		writeServiceUnavailable(w, r)
		return
	}
	s.credentials.RevokeOrganizationCredential(w, r, orgId, credentialId, params)
}

func (s compositeAPIServer) RotateOrganizationCredential(w http.ResponseWriter, r *http.Request, orgId api.OrgIDPath, credentialId api.CredentialIDPath, params api.RotateOrganizationCredentialParams) {
	if s.credentials == nil {
		writeServiceUnavailable(w, r)
		return
	}
	s.credentials.RotateOrganizationCredential(w, r, orgId, credentialId, params)
}

func writeServiceUnavailable(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Retry-After", "5")
	httpserver.WriteError(w, r, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", "Service temporarily unavailable.")
}

func buildAllowedOrigins(cfg config.Config) []string {
	origins := make([]string, 0, len(cfg.CORSOrigins)+1)
	origins = append(origins, cfg.CORSOrigins...)
	if u, err := url.Parse(cfg.AppURL); err == nil && u.Scheme != "" && u.Host != "" {
		origins = append(origins, u.Scheme+"://"+u.Host)
	}
	return origins
}

// enforceRuntimeDBRole applies the ADR-008 runtime role policy by environment:
// staging and production refuse to start with a privileged role (rolsuper or
// rolbypassrls), while development logs a warning and continues.
func enforceRuntimeDBRole(appEnv string, verifyErr error, logger *slog.Logger) error {
	if verifyErr == nil {
		return nil
	}
	if errors.Is(verifyErr, database.ErrPrivilegedRole) && appEnv == "development" {
		logger.Warn("database runtime role is privileged; RLS may be bypassed in development", "error", verifyErr)
		return nil
	}
	return verifyErr
}

func runMigrate(action string) error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}

	logger, err := telemetry.NewLogger(os.Stdout, cfg.LogLevel, "vigia-migrate", cfg.AppEnv)
	if err != nil {
		return err
	}
	slog.SetDefault(logger)

	dsn, err := cfg.DatabaseDSN()
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if action == "up" && !cfg.DatabaseAppPassword.IsEmpty() {
		logger.Info("ensuring PostgreSQL runtime roles")
		if err := database.EnsureRoles(ctx, dsn, cfg.DatabaseAppPassword.Value()); err != nil {
			return err
		}
	}

	logger.Info("running database migrations", "action", action)
	if err := database.Migrate(ctx, dsn, migrations.FS, action); err != nil {
		return err
	}
	logger.Info("database migrations completed", "action", action)
	return nil
}

// runEnsureRoles creates/updates cluster-global runtime roles (vigia_app, vigia_definer)
// without executing schema migrations (required before pg_restore on a clean instance, CTO #31).
func runEnsureRoles() error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	logger, err := telemetry.NewLogger(os.Stdout, cfg.LogLevel, "vigia-db", cfg.AppEnv)
	if err != nil {
		return err
	}
	slog.SetDefault(logger)

	if cfg.DatabaseAppPassword.IsEmpty() {
		return errors.New("DATABASE_APP_PASSWORD_FILE is required to ensure runtime roles")
	}
	dsn, err := cfg.DatabaseDSN()
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	logger.Info("ensuring PostgreSQL runtime roles")
	if err := database.EnsureRoles(ctx, dsn, cfg.DatabaseAppPassword.Value()); err != nil {
		return err
	}
	logger.Info("PostgreSQL runtime roles ensured")
	return nil
}

// runHealthcheck probes /health/live inside the container without logging on success.
func runHealthcheck() error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("http://127.0.0.1:%d/health/live", cfg.AdminPort), nil)
	if err != nil {
		return fmt.Errorf("healthcheck request: %w", err)
	}
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("healthcheck failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("healthcheck failed: status %d", resp.StatusCode)
	}
	return nil
}
