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
	"github.com/Yhanko/vigia/internal/modules/identity"
	"github.com/Yhanko/vigia/internal/modules/identity/password"
	"github.com/Yhanko/vigia/internal/modules/identity/session"
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

	if !cfg.EncryptionKey.IsEmpty() {
		kr, err := crypto.ParseKeyring([]byte(cfg.EncryptionKey.Value()))
		if err != nil {
			return fmt.Errorf("load ENCRYPTION_KEY_FILE: %w", err)
		}
		if _, err := crypto.NewEnvelopeEncrypter(kr); err != nil {
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

	var idHandler *identity.Handler
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
		var mailSender identity.Mailer
		if cfg.SMTPURL != "" {
			mailSender, err = mailer.NewSMTPMailer(cfg.SMTPURL, "no-reply@vigia.ao")
			if err != nil {
				return err
			}
		}
		idSvc, err := identity.NewService(identity.ServiceConfig{
			Store:           idStore,
			Hasher:          idHasher,
			Sessions:        idSessions,
			Limiter:         limiter,
			RateLimitSecret: []byte(cfg.SessionSecret.Value()),
			Mailer:          mailSender,
			AppURL:          cfg.AppURL,
			Clock:           clk,
			Logger:          logger,
		})
		if err != nil {
			return err
		}
		idHandler, err = identity.NewHandler(idSvc, idSessions, buildAllowedOrigins(cfg), cfg.TrustedProxies, logger)
		if err != nil {
			return err
		}
	} else {
		logger.Warn("identity endpoints disabled (requires DATABASE_URL, REDIS_ADDR, and SESSION_SECRET_FILE)")
	}

	composedAPI := compositeAPIServer{
		version:  version,
		commit:   commit,
		identity: idHandler,
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
	version  string
	commit   string
	identity *identity.Handler
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
