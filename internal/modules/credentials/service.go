package credentials

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"

	"github.com/Yhanko/vigia/internal/modules/organizations"
	"github.com/Yhanko/vigia/internal/platform/clock"
	"github.com/Yhanko/vigia/internal/platform/database"
	"github.com/Yhanko/vigia/internal/platform/database/sqlcgen"
)

const (
	cacheTTL           = 60 * time.Second
	anomalousIPSetTTL  = 30 * 24 * time.Hour
	lastUsedFlushEvery = 30 * time.Second
	lastUsedMaxBatch   = 256
)

var (
	ErrForbidden       = errors.New("credentials: forbidden")
	ErrMFARequired     = errors.New("credentials: mfa required for privileged role")
	ErrReauthRequired  = errors.New("credentials: recent authentication required")
	ErrNotFound        = errors.New("credentials: credential not found")
	ErrInvalidInput    = errors.New("credentials: invalid input")
	ErrPrefixCollision = errors.New("credentials: failed to allocate unique prefix after retries")
	ErrProjectNotFound = errors.New("credentials: project not found")
)

// Cache abstracts the Redis operations needed for credential caching, immediate
// revocation invalidation, and anomalous IP tracking.
type Cache interface {
	Get(ctx context.Context, key string) ([]byte, error)
	Set(ctx context.Context, key string, val []byte, ttl time.Duration) error
	Del(ctx context.Context, keys ...string) error
	SAdd(ctx context.Context, key string, member string, ttl time.Duration) (added int64, cardinality int64, err error)
}

// RedisCache adapts *redis.Client to Cache.
type RedisCache struct {
	client *redis.Client
}

// NewRedisCache wraps a *redis.Client as a credential Cache.
func NewRedisCache(client *redis.Client) *RedisCache {
	return &RedisCache{client: client}
}

func (c *RedisCache) Get(ctx context.Context, key string) ([]byte, error) {
	b, err := c.client.Get(ctx, key).Bytes()
	if errors.Is(err, redis.Nil) {
		return nil, nil
	}
	return b, err
}

func (c *RedisCache) Set(ctx context.Context, key string, val []byte, ttl time.Duration) error {
	return c.client.Set(ctx, key, val, ttl).Err()
}

func (c *RedisCache) Del(ctx context.Context, keys ...string) error {
	if len(keys) == 0 {
		return nil
	}
	return c.client.Del(ctx, keys...).Err()
}

func (c *RedisCache) SAdd(ctx context.Context, key string, member string, ttl time.Duration) (int64, int64, error) {
	pipe := c.client.Pipeline()
	addCmd := pipe.SAdd(ctx, key, member)
	cardCmd := pipe.SCard(ctx, key)
	pipe.Expire(ctx, key, ttl)
	if _, err := pipe.Exec(ctx); err != nil {
		return 0, 0, err
	}
	return addCmd.Val(), cardCmd.Val(), nil
}

// Credential is the safe public metadata representation (never includes secret_hash or plaintext secret).
type Credential struct {
	ID             string
	OrganizationID string
	ProjectID      string
	EnvironmentID  string
	Kind           string
	Name           string
	Prefix         string
	PublicKey      string
	DSN            string
	Scopes         []string
	AllowedOrigins []string
	ExpiresAt      *time.Time
	LastUsedAt     *time.Time
	RevokedAt      *time.Time
	CreatedBy      string
	CreatedAt      time.Time
}

// CreatedCredential embeds Credential and includes Secret ONLY once at creation/rotation.
type CreatedCredential struct {
	Credential
	Secret string // empty for DSN; shown once for ingest/client
}

// CreateInput defines parameters for creating a new API credential.
type CreateInput struct {
	ProjectID      string
	EnvironmentID  string
	Kind           string // "ingest", "client", "dsn"
	Name           string
	Scopes         []string
	AllowedOrigins []string
	ExpiresAt      *time.Time
}

type cachedCredential struct {
	ID             string     `json:"id"`
	OrganizationID string     `json:"org_id"`
	ProjectID      string     `json:"proj_id"`
	EnvironmentID  string     `json:"env_id,omitempty"`
	Kind           string     `json:"kind"`
	SecretHash     []byte     `json:"secret_hash"`
	Scopes         []string   `json:"scopes,omitempty"`
	ExpiresAt      *time.Time `json:"expires_at,omitempty"`
}

type lastUsedEntry struct {
	orgID  string
	credID string
	at     time.Time
}

// Service manages API credential lifecycle, verification, Redis caching,
// immediate revocation, batched last_used_at updates, and anomalous IP detection.
type Service struct {
	pool                     *pgxpool.Pool
	q                        *sqlcgen.Queries
	cache                    Cache
	pepper                   []byte
	ingestHost               string
	mfaRequiredForPrivileged bool
	clk                      clock.Clock
	logger                   *slog.Logger

	touchMu   sync.Mutex
	pending   map[string]lastUsedEntry
	stopCh    chan struct{}
	closeOnce sync.Once
	wg        sync.WaitGroup
}

// ServiceConfig holds explicit dependencies for the credentials Service.
type ServiceConfig struct {
	Pool                     *pgxpool.Pool
	Cache                    Cache
	Pepper                   []byte
	IngestHost               string
	MFARequiredForPrivileged bool
	Clock                    clock.Clock
	Logger                   *slog.Logger
}

// NewService constructs a credentials Service and starts its background last_used_at flusher.
func NewService(cfg ServiceConfig) (*Service, error) {
	if cfg.Pool == nil {
		return nil, errors.New("credentials: pgx pool is required")
	}
	if len(cfg.Pepper) < 32 {
		return nil, errors.New("credentials: pepper must be at least 32 bytes")
	}
	clk := cfg.Clock
	if clk == nil {
		clk = clock.System{}
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	host := strings.TrimSpace(cfg.IngestHost)
	if host == "" {
		host = "ingest.vigia.local"
	}
	pepperCopy := make([]byte, len(cfg.Pepper))
	copy(pepperCopy, cfg.Pepper)

	s := &Service{
		pool:                     cfg.Pool,
		q:                        sqlcgen.New(cfg.Pool),
		cache:                    cfg.Cache,
		pepper:                   pepperCopy,
		ingestHost:               host,
		mfaRequiredForPrivileged: cfg.MFARequiredForPrivileged,
		clk:                      clk,
		logger:                   logger,
		pending:                  make(map[string]lastUsedEntry),
		stopCh:                   make(chan struct{}),
	}
	s.wg.Add(1)
	go s.flushLoop()
	return s, nil
}

// Close flushes pending last_used_at updates and stops the background worker.
func (s *Service) Close(ctx context.Context) {
	s.closeOnce.Do(func() {
		close(s.stopCh)
	})
	s.wg.Wait()
	s.flushPending(ctx)
}

// Create generates and stores a new API credential, returning the raw secret (or DSN) ONCE.
func (s *Service) Create(ctx context.Context, tenantID database.TenantID, actor organizations.Actor, in CreateInput) (CreatedCredential, error) {
	if err := s.requireRecentAuth(actor); err != nil {
		return CreatedCredential{}, err
	}
	name := strings.TrimSpace(in.Name)
	if name == "" || len(name) > 120 {
		return CreatedCredential{}, ErrInvalidInput
	}
	switch in.Kind {
	case KindIngest, KindClient, KindDSN:
	default:
		return CreatedCredential{}, ErrInvalidInput
	}

	orgUUID, err := parseUUID(tenantID.String())
	if err != nil {
		return CreatedCredential{}, ErrInvalidInput
	}
	projUUID, err := parseUUID(in.ProjectID)
	if err != nil {
		return CreatedCredential{}, ErrInvalidInput
	}
	userUUID, err := parseUUID(actor.UserID)
	if err != nil {
		return CreatedCredential{}, ErrInvalidInput
	}
	var envUUID pgtype.UUID
	if in.EnvironmentID != "" {
		envUUID, err = parseUUID(in.EnvironmentID)
		if err != nil {
			return CreatedCredential{}, ErrInvalidInput
		}
	}

	scopes := in.Scopes
	if scopes == nil {
		scopes = []string{}
	}
	origins := in.AllowedOrigins
	if origins == nil {
		origins = []string{}
	}
	var expiresAt pgtype.Timestamptz
	if in.ExpiresAt != nil {
		expiresAt = pgtype.Timestamptz{Time: in.ExpiresAt.UTC(), Valid: true}
	}

	var result CreatedCredential
	for attempt := range MaxCollisionTry {
		var fullSecret, prefix string
		var secretHash []byte
		var publicKey *string

		if in.Kind == KindDSN {
			pk, pre, genErr := GenerateDSNKey()
			if genErr != nil {
				return CreatedCredential{}, genErr
			}
			prefix = pre
			publicKey = &pk
		} else {
			raw, pre, genErr := GenerateSecretKey(in.Kind)
			if genErr != nil {
				return CreatedCredential{}, genErr
			}
			fullSecret = raw
			prefix = pre
			secretHash = HashSecret(s.pepper, raw)
		}

		credID := uuid.New()
		var credUUID pgtype.UUID
		_ = credUUID.Scan(credID.String())

		var row sqlcgen.CreateAPICredentialRow
		var projPublicID int64

		txErr := database.WithTenantTx(ctx, s.pool, tenantID, func(tx pgx.Tx) error {
			qtx := s.q.WithTx(tx)
			if err := s.requirePermission(ctx, qtx, orgUUID, userUUID, actor.MFAEnabled, organizations.PermAPIKeyCreate); err != nil {
				return err
			}
			proj, err := qtx.GetProjectByID(ctx, sqlcgen.GetProjectByIDParams{
				OrganizationID: orgUUID,
				ID:             projUUID,
			})
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrProjectNotFound
			}
			if err != nil {
				return fmt.Errorf("credentials: get project: %w", err)
			}
			projPublicID = proj.PublicID

			row, err = qtx.CreateAPICredential(ctx, sqlcgen.CreateAPICredentialParams{
				ID:             credUUID,
				OrganizationID: orgUUID,
				ProjectID:      projUUID,
				EnvironmentID:  envUUID,
				Kind:           in.Kind,
				Btrim:          name,
				Prefix:         prefix,
				SecretHash:     secretHash,
				PublicKey:      publicKey,
				Scopes:         scopes,
				AllowedOrigins: origins,
				ExpiresAt:      expiresAt,
				CreatedBy:      userUUID,
			})
			if err != nil {
				return err
			}

			resID := credID.String()
			changes, _ := json.Marshal(map[string]any{
				"kind":       in.Kind,
				"prefix":     prefix,
				"project_id": in.ProjectID,
			})
			return qtx.InsertTenantAuditLog(ctx, sqlcgen.InsertTenantAuditLogParams{
				ID:             newPgUUID(),
				OrganizationID: orgUUID,
				ActorType:      "user",
				ActorID:        userUUID,
				Action:         "credential.created",
				ResourceType:   "api_credential",
				ResourceID:     &resID,
				Result:         "success",
				IpPrefix:       actor.IPPrefix,
				UserAgent:      actor.UserAgent,
				RequestID:      nonEmptyRequestID(actor.RequestID),
				Changes:        changes,
			})
		})
		if txErr != nil {
			var pgErr *pgconn.PgError
			if errors.As(txErr, &pgErr) && pgErr.Code == "23505" && attempt < MaxCollisionTry-1 {
				continue
			}
			if errors.As(txErr, &pgErr) && pgErr.Code == "23505" {
				return CreatedCredential{}, ErrPrefixCollision
			}
			return CreatedCredential{}, txErr
		}

		c := mapCredentialRow(row.ID, row.OrganizationID, row.ProjectID, row.EnvironmentID, row.Kind, row.Name, row.Prefix, row.PublicKey, row.Scopes, row.AllowedOrigins, row.ExpiresAt, row.LastUsedAt, row.RevokedAt, row.CreatedBy, row.CreatedAt, s.ingestHost, projPublicID)
		result = CreatedCredential{
			Credential: c,
			Secret:     fullSecret,
		}
		return result, nil
	}
	return CreatedCredential{}, ErrPrefixCollision
}

// List returns all credentials for a project (metadata only, never secret_hash).
func (s *Service) List(ctx context.Context, tenantID database.TenantID, actor organizations.Actor, projectID string) ([]Credential, error) {
	orgUUID, err := parseUUID(tenantID.String())
	if err != nil {
		return nil, ErrInvalidInput
	}
	projUUID, err := parseUUID(projectID)
	if err != nil {
		return nil, ErrInvalidInput
	}
	userUUID, err := parseUUID(actor.UserID)
	if err != nil {
		return nil, ErrInvalidInput
	}

	var rows []sqlcgen.ListProjectCredentialsRow
	var projPublicID int64

	err = database.WithTenantTx(ctx, s.pool, tenantID, func(tx pgx.Tx) error {
		qtx := s.q.WithTx(tx)
		if err := s.requirePermission(ctx, qtx, orgUUID, userUUID, actor.MFAEnabled, organizations.PermAPIKeyRead); err != nil {
			return err
		}
		proj, err := qtx.GetProjectByID(ctx, sqlcgen.GetProjectByIDParams{
			OrganizationID: orgUUID,
			ID:             projUUID,
		})
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrProjectNotFound
		}
		if err != nil {
			return err
		}
		projPublicID = proj.PublicID
		rows, err = qtx.ListProjectCredentials(ctx, sqlcgen.ListProjectCredentialsParams{
			OrganizationID: orgUUID,
			ProjectID:      projUUID,
		})
		return err
	})
	if err != nil {
		return nil, err
	}

	out := make([]Credential, 0, len(rows))
	for _, r := range rows {
		out = append(out, mapCredentialRow(r.ID, r.OrganizationID, r.ProjectID, r.EnvironmentID, r.Kind, r.Name, r.Prefix, r.PublicKey, r.Scopes, r.AllowedOrigins, r.ExpiresAt, r.LastUsedAt, r.RevokedAt, r.CreatedBy, r.CreatedAt, s.ingestHost, projPublicID))
	}
	return out, nil
}

// Revoke immediately revokes a credential in PostgreSQL and evicts its Redis cache entry.
func (s *Service) Revoke(ctx context.Context, tenantID database.TenantID, actor organizations.Actor, credentialID string) error {
	if err := s.requireRecentAuth(actor); err != nil {
		return err
	}
	orgUUID, err := parseUUID(tenantID.String())
	if err != nil {
		return ErrInvalidInput
	}
	credUUID, err := parseUUID(credentialID)
	if err != nil {
		return ErrInvalidInput
	}
	userUUID, err := parseUUID(actor.UserID)
	if err != nil {
		return ErrInvalidInput
	}

	now := s.clk.Now().UTC()
	var revoked sqlcgen.RevokeAPICredentialRow

	err = database.WithTenantTx(ctx, s.pool, tenantID, func(tx pgx.Tx) error {
		qtx := s.q.WithTx(tx)
		if err := s.requirePermission(ctx, qtx, orgUUID, userUUID, actor.MFAEnabled, organizations.PermAPIKeyRevoke); err != nil {
			return err
		}
		var rErr error
		revoked, rErr = qtx.RevokeAPICredential(ctx, sqlcgen.RevokeAPICredentialParams{
			OrganizationID: orgUUID,
			ID:             credUUID,
			RevokedAt:      pgtype.Timestamptz{Time: now, Valid: true},
		})
		if errors.Is(rErr, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if rErr != nil {
			return rErr
		}
		resID := credentialID
		changes, _ := json.Marshal(map[string]any{
			"kind":   revoked.Kind,
			"prefix": revoked.Prefix,
		})
		return qtx.InsertTenantAuditLog(ctx, sqlcgen.InsertTenantAuditLogParams{
			ID:             newPgUUID(),
			OrganizationID: orgUUID,
			ActorType:      "user",
			ActorID:        userUUID,
			Action:         "credential.revoked",
			ResourceType:   "api_credential",
			ResourceID:     &resID,
			Result:         "success",
			IpPrefix:       actor.IPPrefix,
			UserAgent:      actor.UserAgent,
			RequestID:      nonEmptyRequestID(actor.RequestID),
			Changes:        changes,
		})
	})
	if err != nil {
		return err
	}

	s.InvalidateCache(ctx, revoked.Kind, revoked.Prefix, revoked.PublicKey)
	return nil
}

// Rotate creates a replacement credential with the same metadata and either sets
// an overlap expiry on the old credential or revokes it immediately if overlap <= 0.
func (s *Service) Rotate(ctx context.Context, tenantID database.TenantID, actor organizations.Actor, credentialID string, overlap time.Duration) (CreatedCredential, error) {
	if err := s.requireRecentAuth(actor); err != nil {
		return CreatedCredential{}, err
	}
	orgUUID, err := parseUUID(tenantID.String())
	if err != nil {
		return CreatedCredential{}, ErrInvalidInput
	}
	credUUID, err := parseUUID(credentialID)
	if err != nil {
		return CreatedCredential{}, ErrInvalidInput
	}
	userUUID, err := parseUUID(actor.UserID)
	if err != nil {
		return CreatedCredential{}, ErrInvalidInput
	}

	// Read existing credential metadata inside tenant tx.
	var origKind, origName, origPrefix, projID, envID string
	var origPublicKey *string
	var origScopes, origOrigins []string
	err = database.WithTenantTx(ctx, s.pool, tenantID, func(tx pgx.Tx) error {
		qtx := s.q.WithTx(tx)
		if err := s.requirePermission(ctx, qtx, orgUUID, userUUID, actor.MFAEnabled, organizations.PermAPIKeyRevoke); err != nil {
			return err
		}
		var pID, eID pgtype.UUID
		row := tx.QueryRow(ctx, `
			SELECT project_id, environment_id, kind, name, prefix, public_key, scopes, allowed_origins
			FROM api_credentials
			WHERE organization_id = $1 AND id = $2 AND revoked_at IS NULL
		`, orgUUID, credUUID)
		if scanErr := row.Scan(&pID, &eID, &origKind, &origName, &origPrefix, &origPublicKey, &origScopes, &origOrigins); scanErr != nil {
			if errors.Is(scanErr, pgx.ErrNoRows) {
				return ErrNotFound
			}
			return scanErr
		}
		projID = pID.String()
		if eID.Valid {
			envID = eID.String()
		}
		return nil
	})
	if err != nil {
		return CreatedCredential{}, err
	}

	created, err := s.Create(ctx, tenantID, actor, CreateInput{
		ProjectID:      projID,
		EnvironmentID:  envID,
		Kind:           origKind,
		Name:           origName,
		Scopes:         origScopes,
		AllowedOrigins: origOrigins,
	})
	if err != nil {
		return CreatedCredential{}, err
	}

	now := s.clk.Now().UTC()
	if overlap <= 0 {
		if revErr := s.Revoke(ctx, tenantID, actor, credentialID); revErr != nil && !errors.Is(revErr, ErrNotFound) {
			return created, revErr
		}
	} else {
		exp := now.Add(overlap)
		_ = database.WithTenantTx(ctx, s.pool, tenantID, func(tx pgx.Tx) error {
			_, uErr := tx.Exec(ctx, `
				UPDATE api_credentials
				SET expires_at = LEAST(COALESCE(expires_at, $3::timestamptz), $3::timestamptz)
				WHERE organization_id = $1 AND id = $2 AND revoked_at IS NULL
			`, orgUUID, credUUID, exp)
			return uErr
		})
		s.InvalidateCache(ctx, origKind, origPrefix, origPublicKey)
	}
	return created, nil
}

// InvalidateCache immediately evicts a credential from Redis cache.
func (s *Service) InvalidateCache(ctx context.Context, kind, prefix string, publicKey *string) {
	if s.cache == nil {
		return
	}
	key := CacheKey(kind, prefix)
	if kind == KindDSN && publicKey != nil {
		key = CacheKey(KindDSN, *publicKey)
	}
	if err := s.cache.Del(ctx, key); err != nil {
		s.logger.WarnContext(ctx, "credentials: failed to evict redis cache key", "kind", kind, "err", err)
	}
}

// AuthenticateSecret validates a vg_ing_ or vg_cli_ secret key via Redis cache
// or PostgreSQL lookup_api_credential_by_prefix, verifies HMAC in constant time,
// queues batched last_used_at update, and checks anomalous IP prefix usage.
func (s *Service) AuthenticateSecret(ctx context.Context, rawKey, clientIP string) (AuthenticatedCredential, error) {
	parsed, err := ParseSecretKey(rawKey)
	if err != nil {
		return AuthenticatedCredential{}, ErrInvalidCredential
	}

	now := s.clk.Now().UTC()
	cacheKey := CacheKey(parsed.Kind, parsed.Prefix)

	var meta *cachedCredential
	if s.cache != nil {
		if raw, cErr := s.cache.Get(ctx, cacheKey); cErr == nil && len(raw) > 0 {
			var decoded cachedCredential
			if json.Unmarshal(raw, &decoded) == nil {
				meta = &decoded
			}
		}
	}

	if meta == nil {
		var (
			credID, orgID, projID, envID pgtype.UUID
			kind                         string
			secretHash                   []byte
			scopes                       []string
			expiresAt, revokedAt         pgtype.Timestamptz
		)
		row := s.pool.QueryRow(ctx,
			`SELECT credential_id, organization_id, project_id, environment_id, kind, secret_hash, scopes, expires_at, revoked_at
			 FROM lookup_api_credential_by_prefix($1, $2)`,
			parsed.Kind, parsed.Prefix,
		)
		if scanErr := row.Scan(&credID, &orgID, &projID, &envID, &kind, &secretHash, &scopes, &expiresAt, &revokedAt); scanErr != nil {
			return AuthenticatedCredential{}, ErrInvalidCredential
		}
		if revokedAt.Valid {
			return AuthenticatedCredential{}, ErrInvalidCredential
		}
		var expPtr *time.Time
		if expiresAt.Valid {
			t := expiresAt.Time.UTC()
			if !t.After(now) {
				return AuthenticatedCredential{}, ErrInvalidCredential
			}
			expPtr = &t
		}
		envStr := ""
		if envID.Valid {
			envStr = envID.String()
		}
		meta = &cachedCredential{
			ID:             credID.String(),
			OrganizationID: orgID.String(),
			ProjectID:      projID.String(),
			EnvironmentID:  envStr,
			Kind:           kind,
			SecretHash:     secretHash,
			Scopes:         scopes,
			ExpiresAt:      expPtr,
		}
		if s.cache != nil {
			if encoded, mErr := json.Marshal(meta); mErr == nil {
				_ = s.cache.Set(ctx, cacheKey, encoded, cacheTTL)
			}
		}
	}

	if meta.ExpiresAt != nil && !meta.ExpiresAt.After(now) {
		return AuthenticatedCredential{}, ErrInvalidCredential
	}
	if !VerifySecret(s.pepper, rawKey, meta.SecretHash) {
		return AuthenticatedCredential{}, ErrInvalidCredential
	}

	s.enqueueLastUsed(meta.OrganizationID, meta.ID, now)
	s.checkAnomalousIP(ctx, meta.OrganizationID, meta.ID, clientIP)

	return AuthenticatedCredential{
		ID:             meta.ID,
		OrganizationID: meta.OrganizationID,
		ProjectID:      meta.ProjectID,
		EnvironmentID:  meta.EnvironmentID,
		Kind:           meta.Kind,
		Scopes:         meta.Scopes,
	}, nil
}

func (s *Service) enqueueLastUsed(orgID, credID string, now time.Time) {
	s.touchMu.Lock()
	defer s.touchMu.Unlock()
	if len(s.pending) >= lastUsedMaxBatch {
		return
	}
	s.pending[credID] = lastUsedEntry{orgID: orgID, credID: credID, at: now}
}

func (s *Service) flushLoop() {
	defer s.wg.Done()
	ticker := time.NewTicker(lastUsedFlushEvery)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			s.flushPending(ctx)
			cancel()
		case <-s.stopCh:
			return
		}
	}
}

func (s *Service) flushPending(ctx context.Context) {
	s.touchMu.Lock()
	if len(s.pending) == 0 {
		s.touchMu.Unlock()
		return
	}
	batch := s.pending
	s.pending = make(map[string]lastUsedEntry)
	s.touchMu.Unlock()

	for _, item := range batch {
		tid, err := database.ParseTenantID(item.orgID)
		if err != nil {
			continue
		}
		orgUUID, err := parseUUID(item.orgID)
		if err != nil {
			continue
		}
		credUUID, err := parseUUID(item.credID)
		if err != nil {
			continue
		}
		_ = database.WithTenantTx(ctx, s.pool, tid, func(tx pgx.Tx) error {
			return s.q.WithTx(tx).TouchAPICredentialLastUsed(ctx, sqlcgen.TouchAPICredentialLastUsedParams{
				OrganizationID: orgUUID,
				ID:             credUUID,
				LastUsedAt:     pgtype.Timestamptz{Time: item.at.UTC(), Valid: true},
			})
		})
	}
}

func (s *Service) checkAnomalousIP(ctx context.Context, orgID, credID, clientIP string) {
	if s.cache == nil || clientIP == "" {
		return
	}
	prefix := maskIPPrefix(clientIP)
	if prefix == "" {
		return
	}
	added, card, err := s.cache.SAdd(ctx, "cred:ips:"+credID, prefix, anomalousIPSetTTL)
	if err != nil || added == 0 || card <= 1 {
		return
	}
	// New IP prefix observed after prior IPs were already recorded: emit audit event.
	tid, err := database.ParseTenantID(orgID)
	if err != nil {
		return
	}
	orgUUID, err := parseUUID(orgID)
	if err != nil {
		return
	}
	resID := credID
	credUUID, _ := parseUUID(credID)
	changes, _ := json.Marshal(map[string]any{
		"observed_ip_prefix": prefix,
		"known_prefixes":     card,
	})
	_ = database.WithTenantTx(ctx, s.pool, tid, func(tx pgx.Tx) error {
		return s.q.WithTx(tx).InsertTenantAuditLog(ctx, sqlcgen.InsertTenantAuditLogParams{
			ID:             newPgUUID(),
			OrganizationID: orgUUID,
			ActorType:      "credential",
			ActorID:        credUUID,
			Action:         "credential.anomalous_ip",
			ResourceType:   "api_credential",
			ResourceID:     &resID,
			Result:         "success",
			IpPrefix:       &prefix,
			RequestID:      "cred-auth",
			Changes:        changes,
		})
	})
}

func (s *Service) requireRecentAuth(actor organizations.Actor) error {
	now := s.clk.Now().UTC()
	if actor.LastAuthAt.IsZero() || now.Sub(actor.LastAuthAt) > organizations.ReauthWindow {
		return ErrReauthRequired
	}
	return nil
}

func (s *Service) requirePermission(ctx context.Context, qtx *sqlcgen.Queries, orgUUID, userUUID pgtype.UUID, mfaEnabled bool, perm organizations.Permission) error {
	m, err := qtx.GetMembershipByUser(ctx, sqlcgen.GetMembershipByUserParams{
		OrganizationID: orgUUID,
		UserID:         userUUID,
	})
	if errors.Is(err, pgx.ErrNoRows) || m.Status != "active" {
		return ErrForbidden
	}
	if err != nil {
		return fmt.Errorf("credentials: get membership: %w", err)
	}
	role := m.Role
	if !organizations.HasPermission(role, perm) {
		return ErrForbidden
	}
	if s.mfaRequiredForPrivileged && (role == organizations.RoleOwner || role == organizations.RoleAdmin) && !mfaEnabled {
		return ErrMFARequired
	}
	return nil
}

func mapCredentialRow(
	id, orgID, projID, envID pgtype.UUID,
	kind, name, prefix string,
	publicKey *string,
	scopes, origins []string,
	expiresAt, lastUsedAt, revokedAt pgtype.Timestamptz,
	createdBy pgtype.UUID,
	createdAt pgtype.Timestamptz,
	ingestHost string,
	projPublicID int64,
) Credential {
	c := Credential{
		ID:             id.String(),
		OrganizationID: orgID.String(),
		ProjectID:      projID.String(),
		Kind:           kind,
		Name:           name,
		Prefix:         prefix,
		Scopes:         scopes,
		AllowedOrigins: origins,
		CreatedBy:      createdBy.String(),
		CreatedAt:      createdAt.Time.UTC(),
	}
	if envID.Valid {
		c.EnvironmentID = envID.String()
	}
	if publicKey != nil {
		c.PublicKey = *publicKey
		if kind == KindDSN && projPublicID > 0 {
			c.DSN = FormatDSN(*publicKey, ingestHost, projPublicID)
		}
	}
	if expiresAt.Valid {
		t := expiresAt.Time.UTC()
		c.ExpiresAt = &t
	}
	if lastUsedAt.Valid {
		t := lastUsedAt.Time.UTC()
		c.LastUsedAt = &t
	}
	if revokedAt.Valid {
		t := revokedAt.Time.UTC()
		c.RevokedAt = &t
	}
	return c
}

func maskIPPrefix(rawIP string) string {
	addr, err := netip.ParseAddr(strings.TrimSpace(rawIP))
	if err != nil {
		return ""
	}
	addr = addr.Unmap()
	bits := 24
	if addr.Is6() {
		bits = 48
	}
	p, err := addr.Prefix(bits)
	if err != nil {
		return ""
	}
	return p.String()
}

func parseUUID(s string) (pgtype.UUID, error) {
	var u pgtype.UUID
	if err := u.Scan(s); err != nil {
		return pgtype.UUID{}, err
	}
	return u, nil
}

func newPgUUID() pgtype.UUID {
	var u pgtype.UUID
	_ = u.Scan(uuid.New().String())
	return u
}

func nonEmptyRequestID(reqID string) string {
	if strings.TrimSpace(reqID) == "" {
		return "req-unknown"
	}
	return reqID
}
