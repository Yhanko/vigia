// Package projects implements tenant-scoped project and environment management
// with 53-bit random public_id allocation, protected environment guards, and
// soft-deletion with immediate credential revocation (TASKS 1.3, ADR-008).
package projects

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Yhanko/vigia/internal/modules/organizations"
	"github.com/Yhanko/vigia/internal/platform/clock"
	"github.com/Yhanko/vigia/internal/platform/database"
	"github.com/Yhanko/vigia/internal/platform/database/sqlcgen"
)

const (
	maxPublicIDRetries = 3
	maxSafeInt53       = (uint64(1) << 53) - 1
	defaultListLimit   = 50
)

var (
	slugPattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{1,61}[a-z0-9])?$`)
	envPattern  = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
)

// CredentialCacheInvalidator evicts revoked credentials from Redis immediately.
type CredentialCacheInvalidator interface {
	InvalidateCache(ctx context.Context, kind, prefix string, publicKey *string)
}

// Project represents a tenant-scoped Vigia project.
type Project struct {
	ID             string
	OrganizationID string
	PublicID       int64
	Name           string
	Slug           string
	Platform       string
	Status         string
	DeletedAt      *time.Time
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

// Environment represents a deployment environment belonging to a project.
type Environment struct {
	ID             string
	OrganizationID string
	ProjectID      string
	Name           string
	IsProtected    bool
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

// Service manages tenant-scoped projects and environments.
type Service struct {
	pool                     *pgxpool.Pool
	q                        *sqlcgen.Queries
	invalidator              CredentialCacheInvalidator
	mfaRequiredForPrivileged bool
	clk                      clock.Clock
}

// ServiceConfig holds explicit dependencies for the projects Service.
type ServiceConfig struct {
	Pool                     *pgxpool.Pool
	CredentialInvalidator    CredentialCacheInvalidator
	MFARequiredForPrivileged bool
	Clock                    clock.Clock
}

// NewService constructs a projects Service.
func NewService(cfg ServiceConfig) (*Service, error) {
	if cfg.Pool == nil {
		return nil, errors.New("projects: pgx pool is required")
	}
	clk := cfg.Clock
	if clk == nil {
		clk = clock.System{}
	}
	return &Service{
		pool:                     cfg.Pool,
		q:                        sqlcgen.New(cfg.Pool),
		invalidator:              cfg.CredentialInvalidator,
		mfaRequiredForPrivileged: cfg.MFARequiredForPrivileged,
		clk:                      clk,
	}, nil
}

// CreateProject creates a new project with a 53-bit random public_id (retry x3 on collision).
func (s *Service) CreateProject(ctx context.Context, tenantID database.TenantID, actor organizations.Actor, name, slug, platform string) (Project, error) {
	name = strings.TrimSpace(name)
	slug = strings.ToLower(strings.TrimSpace(slug))
	platform = strings.ToLower(strings.TrimSpace(platform))
	if platform == "" {
		platform = "other"
	}
	if name == "" || len(name) > 120 || !slugPattern.MatchString(slug) || len(platform) > 40 {
		return Project{}, ErrInvalidInput
	}

	orgUUID, err := parseUUID(tenantID.String())
	if err != nil {
		return Project{}, ErrInvalidInput
	}
	userUUID, err := parseUUID(actor.UserID)
	if err != nil {
		return Project{}, ErrInvalidInput
	}

	for attempt := range maxPublicIDRetries {
		pubID, genErr := generatePublicID53()
		if genErr != nil {
			return Project{}, genErr
		}
		projID := uuid.New()
		var projUUID pgtype.UUID
		_ = projUUID.Scan(projID.String())

		var row sqlcgen.Project
		txErr := database.WithTenantTx(ctx, s.pool, tenantID, func(tx pgx.Tx) error {
			qtx := s.q.WithTx(tx)
			if err := s.requirePermission(ctx, qtx, orgUUID, userUUID, actor.MFAEnabled, organizations.PermProjectCreate); err != nil {
				return err
			}
			var cErr error
			row, cErr = qtx.CreateProject(ctx, sqlcgen.CreateProjectParams{
				ID:             projUUID,
				OrganizationID: orgUUID,
				PublicID:       pubID,
				Btrim:          name,
				Btrim_2:        slug,
				Btrim_3:        platform,
			})
			if cErr != nil {
				return cErr
			}
			resID := projID.String()
			changes, _ := json.Marshal(map[string]any{
				"slug":      slug,
				"platform":  platform,
				"public_id": pubID,
			})
			return qtx.InsertTenantAuditLog(ctx, sqlcgen.InsertTenantAuditLogParams{
				ID:             newPgUUID(),
				OrganizationID: orgUUID,
				ActorType:      "user",
				ActorID:        userUUID,
				Action:         "project.created",
				ResourceType:   "project",
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
			if errors.As(txErr, &pgErr) && pgErr.Code == "23505" {
				if strings.Contains(pgErr.ConstraintName, "slug") {
					return Project{}, ErrSlugTaken
				}
				if attempt < maxPublicIDRetries-1 {
					continue
				}
				return Project{}, ErrPublicIDCollision
			}
			return Project{}, txErr
		}
		return mapProject(row), nil
	}
	return Project{}, ErrPublicIDCollision
}

// ListProjects returns active projects for the tenant organization.
func (s *Service) ListProjects(ctx context.Context, tenantID database.TenantID, actor organizations.Actor, limit int) ([]Project, error) {
	if limit <= 0 || limit > 100 {
		limit = defaultListLimit
	}
	orgUUID, err := parseUUID(tenantID.String())
	if err != nil {
		return nil, ErrInvalidInput
	}
	userUUID, err := parseUUID(actor.UserID)
	if err != nil {
		return nil, ErrInvalidInput
	}

	var rows []sqlcgen.Project
	err = database.WithTenantTx(ctx, s.pool, tenantID, func(tx pgx.Tx) error {
		qtx := s.q.WithTx(tx)
		if err := s.requirePermission(ctx, qtx, orgUUID, userUUID, actor.MFAEnabled, organizations.PermProjectRead); err != nil {
			return err
		}
		var qErr error
		rows, qErr = qtx.ListProjects(ctx, sqlcgen.ListProjectsParams{
			OrganizationID: orgUUID,
			PageLimit:      int32(limit), //nolint:gosec // bounded <= 100
		})
		return qErr
	})
	if err != nil {
		return nil, err
	}
	out := make([]Project, 0, len(rows))
	for _, r := range rows {
		out = append(out, mapProject(r))
	}
	return out, nil
}

// GetProject returns an active project by ID.
func (s *Service) GetProject(ctx context.Context, tenantID database.TenantID, actor organizations.Actor, projectID string) (Project, error) {
	orgUUID, err := parseUUID(tenantID.String())
	if err != nil {
		return Project{}, ErrInvalidInput
	}
	projUUID, err := parseUUID(projectID)
	if err != nil {
		return Project{}, ErrInvalidInput
	}
	userUUID, err := parseUUID(actor.UserID)
	if err != nil {
		return Project{}, ErrInvalidInput
	}

	var row sqlcgen.Project
	err = database.WithTenantTx(ctx, s.pool, tenantID, func(tx pgx.Tx) error {
		qtx := s.q.WithTx(tx)
		if err := s.requirePermission(ctx, qtx, orgUUID, userUUID, actor.MFAEnabled, organizations.PermProjectRead); err != nil {
			return err
		}
		var qErr error
		row, qErr = qtx.GetProjectByID(ctx, sqlcgen.GetProjectByIDParams{
			OrganizationID: orgUUID,
			ID:             projUUID,
		})
		if errors.Is(qErr, pgx.ErrNoRows) {
			return ErrProjectNotFound
		}
		return qErr
	})
	if err != nil {
		return Project{}, err
	}
	return mapProject(row), nil
}

// UpdateProject updates a project's name and platform.
func (s *Service) UpdateProject(ctx context.Context, tenantID database.TenantID, actor organizations.Actor, projectID, name, platform string) (Project, error) {
	name = strings.TrimSpace(name)
	platform = strings.ToLower(strings.TrimSpace(platform))
	if name == "" || len(name) > 120 || platform == "" || len(platform) > 40 {
		return Project{}, ErrInvalidInput
	}
	orgUUID, err := parseUUID(tenantID.String())
	if err != nil {
		return Project{}, ErrInvalidInput
	}
	projUUID, err := parseUUID(projectID)
	if err != nil {
		return Project{}, ErrInvalidInput
	}
	userUUID, err := parseUUID(actor.UserID)
	if err != nil {
		return Project{}, ErrInvalidInput
	}

	now := s.clk.Now().UTC()
	var row sqlcgen.Project
	err = database.WithTenantTx(ctx, s.pool, tenantID, func(tx pgx.Tx) error {
		qtx := s.q.WithTx(tx)
		if err := s.requirePermission(ctx, qtx, orgUUID, userUUID, actor.MFAEnabled, organizations.PermProjectUpdate); err != nil {
			return err
		}
		var qErr error
		row, qErr = qtx.UpdateProject(ctx, sqlcgen.UpdateProjectParams{
			OrganizationID: orgUUID,
			ID:             projUUID,
			Btrim:          name,
			Btrim_2:        platform,
			UpdatedAt:      pgtype.Timestamptz{Time: now, Valid: true},
		})
		if errors.Is(qErr, pgx.ErrNoRows) {
			return ErrProjectNotFound
		}
		if qErr != nil {
			return qErr
		}
		resID := projectID
		changes, _ := json.Marshal(map[string]any{"name": name, "platform": platform})
		return qtx.InsertTenantAuditLog(ctx, sqlcgen.InsertTenantAuditLogParams{
			ID:             newPgUUID(),
			OrganizationID: orgUUID,
			ActorType:      "user",
			ActorID:        userUUID,
			Action:         "project.updated",
			ResourceType:   "project",
			ResourceID:     &resID,
			Result:         "success",
			IpPrefix:       actor.IPPrefix,
			UserAgent:      actor.UserAgent,
			RequestID:      nonEmptyRequestID(actor.RequestID),
			Changes:        changes,
		})
	})
	if err != nil {
		return Project{}, err
	}
	return mapProject(row), nil
}

// DeleteProject soft-deletes a project after checking recent authentication,
// slug confirmation, revoking all project credentials, and evicting Redis cache.
func (s *Service) DeleteProject(ctx context.Context, tenantID database.TenantID, actor organizations.Actor, projectID, confirmSlug string) error {
	now := s.clk.Now().UTC()
	if actor.LastAuthAt.IsZero() || now.Sub(actor.LastAuthAt) > organizations.ReauthWindow {
		return ErrReauthRequired
	}
	orgUUID, err := parseUUID(tenantID.String())
	if err != nil {
		return ErrInvalidInput
	}
	projUUID, err := parseUUID(projectID)
	if err != nil {
		return ErrInvalidInput
	}
	userUUID, err := parseUUID(actor.UserID)
	if err != nil {
		return ErrInvalidInput
	}

	var revokedCreds []sqlcgen.RevokeAllProjectCredentialsRow
	err = database.WithTenantTx(ctx, s.pool, tenantID, func(tx pgx.Tx) error {
		qtx := s.q.WithTx(tx)
		if err := s.requirePermission(ctx, qtx, orgUUID, userUUID, actor.MFAEnabled, organizations.PermProjectDelete); err != nil {
			return err
		}
		proj, qErr := qtx.GetProjectByID(ctx, sqlcgen.GetProjectByIDParams{
			OrganizationID: orgUUID,
			ID:             projUUID,
		})
		if errors.Is(qErr, pgx.ErrNoRows) {
			return ErrProjectNotFound
		}
		if qErr != nil {
			return qErr
		}
		if strings.ToLower(strings.TrimSpace(confirmSlug)) != proj.Slug {
			return ErrSlugConfirmation
		}

		if _, qErr = qtx.SoftDeleteProject(ctx, sqlcgen.SoftDeleteProjectParams{
			OrganizationID: orgUUID,
			ID:             projUUID,
			Now:            pgtype.Timestamptz{Time: now, Valid: true},
		}); qErr != nil {
			if errors.Is(qErr, pgx.ErrNoRows) {
				return ErrProjectNotFound
			}
			return qErr
		}

		revokedCreds, qErr = qtx.RevokeAllProjectCredentials(ctx, sqlcgen.RevokeAllProjectCredentialsParams{
			OrganizationID: orgUUID,
			ProjectID:      projUUID,
			RevokedAt:      pgtype.Timestamptz{Time: now, Valid: true},
		})
		if qErr != nil {
			return qErr
		}

		resID := projectID
		changes, _ := json.Marshal(map[string]any{
			"slug":                proj.Slug,
			"revoked_credentials": len(revokedCreds),
		})
		return qtx.InsertTenantAuditLog(ctx, sqlcgen.InsertTenantAuditLogParams{
			ID:             newPgUUID(),
			OrganizationID: orgUUID,
			ActorType:      "user",
			ActorID:        userUUID,
			Action:         "project.deleted",
			ResourceType:   "project",
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

	if s.invalidator != nil {
		for _, c := range revokedCreds {
			s.invalidator.InvalidateCache(ctx, c.Kind, c.Prefix, c.PublicKey)
		}
	}
	return nil
}

// CreateEnvironment adds an environment to a project.
func (s *Service) CreateEnvironment(ctx context.Context, tenantID database.TenantID, actor organizations.Actor, projectID, name string, isProtected bool) (Environment, error) {
	name = strings.ToLower(strings.TrimSpace(name))
	if !envPattern.MatchString(name) {
		return Environment{}, ErrInvalidInput
	}
	orgUUID, err := parseUUID(tenantID.String())
	if err != nil {
		return Environment{}, ErrInvalidInput
	}
	projUUID, err := parseUUID(projectID)
	if err != nil {
		return Environment{}, ErrInvalidInput
	}
	userUUID, err := parseUUID(actor.UserID)
	if err != nil {
		return Environment{}, ErrInvalidInput
	}

	envID := uuid.New()
	var envUUID pgtype.UUID
	_ = envUUID.Scan(envID.String())

	var row sqlcgen.Environment
	err = database.WithTenantTx(ctx, s.pool, tenantID, func(tx pgx.Tx) error {
		qtx := s.q.WithTx(tx)
		if err := s.requirePermission(ctx, qtx, orgUUID, userUUID, actor.MFAEnabled, organizations.PermProjectUpdate); err != nil {
			return err
		}
		if _, qErr := qtx.GetProjectByID(ctx, sqlcgen.GetProjectByIDParams{
			OrganizationID: orgUUID,
			ID:             projUUID,
		}); qErr != nil {
			if errors.Is(qErr, pgx.ErrNoRows) {
				return ErrProjectNotFound
			}
			return qErr
		}
		var qErr error
		row, qErr = qtx.CreateEnvironment(ctx, sqlcgen.CreateEnvironmentParams{
			ID:             envUUID,
			OrganizationID: orgUUID,
			ProjectID:      projUUID,
			Btrim:          name,
			IsProtected:    isProtected,
		})
		if qErr != nil {
			return qErr
		}
		resID := envID.String()
		changes, _ := json.Marshal(map[string]any{
			"project_id":   projectID,
			"name":         name,
			"is_protected": isProtected,
		})
		return qtx.InsertTenantAuditLog(ctx, sqlcgen.InsertTenantAuditLogParams{
			ID:             newPgUUID(),
			OrganizationID: orgUUID,
			ActorType:      "user",
			ActorID:        userUUID,
			Action:         "environment.created",
			ResourceType:   "environment",
			ResourceID:     &resID,
			Result:         "success",
			IpPrefix:       actor.IPPrefix,
			UserAgent:      actor.UserAgent,
			RequestID:      nonEmptyRequestID(actor.RequestID),
			Changes:        changes,
		})
	})
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return Environment{}, ErrEnvironmentExists
		}
		return Environment{}, err
	}
	return mapEnvironment(row), nil
}

// ListEnvironments returns all environments for a project.
func (s *Service) ListEnvironments(ctx context.Context, tenantID database.TenantID, actor organizations.Actor, projectID string) ([]Environment, error) {
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

	var rows []sqlcgen.Environment
	err = database.WithTenantTx(ctx, s.pool, tenantID, func(tx pgx.Tx) error {
		qtx := s.q.WithTx(tx)
		if err := s.requirePermission(ctx, qtx, orgUUID, userUUID, actor.MFAEnabled, organizations.PermProjectRead); err != nil {
			return err
		}
		var qErr error
		rows, qErr = qtx.ListProjectEnvironments(ctx, sqlcgen.ListProjectEnvironmentsParams{
			OrganizationID: orgUUID,
			ProjectID:      projUUID,
		})
		return qErr
	})
	if err != nil {
		return nil, err
	}
	out := make([]Environment, 0, len(rows))
	for _, r := range rows {
		out = append(out, mapEnvironment(r))
	}
	return out, nil
}

// DeleteEnvironment deletes a non-protected environment; protected environments return ErrProtectedResource.
func (s *Service) DeleteEnvironment(ctx context.Context, tenantID database.TenantID, actor organizations.Actor, environmentID string) error {
	orgUUID, err := parseUUID(tenantID.String())
	if err != nil {
		return ErrInvalidInput
	}
	envUUID, err := parseUUID(environmentID)
	if err != nil {
		return ErrInvalidInput
	}
	userUUID, err := parseUUID(actor.UserID)
	if err != nil {
		return ErrInvalidInput
	}

	return database.WithTenantTx(ctx, s.pool, tenantID, func(tx pgx.Tx) error {
		qtx := s.q.WithTx(tx)
		if err := s.requirePermission(ctx, qtx, orgUUID, userUUID, actor.MFAEnabled, organizations.PermProjectUpdate); err != nil {
			return err
		}
		env, qErr := qtx.GetEnvironmentByID(ctx, sqlcgen.GetEnvironmentByIDParams{
			OrganizationID: orgUUID,
			ID:             envUUID,
		})
		if errors.Is(qErr, pgx.ErrNoRows) {
			return ErrEnvironmentNotFound
		}
		if qErr != nil {
			return qErr
		}
		if env.IsProtected {
			return ErrProtectedResource
		}
		affected, qErr := qtx.DeleteEnvironment(ctx, sqlcgen.DeleteEnvironmentParams{
			OrganizationID: orgUUID,
			ID:             envUUID,
		})
		if qErr != nil {
			return qErr
		}
		if affected == 0 {
			return ErrEnvironmentNotFound
		}
		resID := environmentID
		changes, _ := json.Marshal(map[string]any{"name": env.Name, "project_id": env.ProjectID.String()})
		return qtx.InsertTenantAuditLog(ctx, sqlcgen.InsertTenantAuditLogParams{
			ID:             newPgUUID(),
			OrganizationID: orgUUID,
			ActorType:      "user",
			ActorID:        userUUID,
			Action:         "environment.deleted",
			ResourceType:   "environment",
			ResourceID:     &resID,
			Result:         "success",
			IpPrefix:       actor.IPPrefix,
			UserAgent:      actor.UserAgent,
			RequestID:      nonEmptyRequestID(actor.RequestID),
			Changes:        changes,
		})
	})
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
		return fmt.Errorf("projects: get membership: %w", err)
	}
	if !organizations.HasPermission(m.Role, perm) {
		return ErrForbidden
	}
	if s.mfaRequiredForPrivileged && (m.Role == organizations.RoleOwner || m.Role == organizations.RoleAdmin) && !mfaEnabled {
		return ErrMFARequired
	}
	return nil
}

func generatePublicID53() (int64, error) {
	var buf [8]byte
	if _, err := io.ReadFull(rand.Reader, buf[:]); err != nil {
		return 0, fmt.Errorf("projects: generate public_id: %w", err)
	}
	val := binary.BigEndian.Uint64(buf[:]) & maxSafeInt53
	if val == 0 {
		val = 1
	}
	return int64(val), nil //nolint:gosec // bounded by 2^53 - 1
}

func mapProject(r sqlcgen.Project) Project {
	p := Project{
		ID:             r.ID.String(),
		OrganizationID: r.OrganizationID.String(),
		PublicID:       r.PublicID,
		Name:           r.Name,
		Slug:           r.Slug,
		Platform:       r.Platform,
		Status:         r.Status,
		CreatedAt:      r.CreatedAt.Time.UTC(),
		UpdatedAt:      r.UpdatedAt.Time.UTC(),
	}
	if r.DeletedAt.Valid {
		t := r.DeletedAt.Time.UTC()
		p.DeletedAt = &t
	}
	return p
}

func mapEnvironment(r sqlcgen.Environment) Environment {
	return Environment{
		ID:             r.ID.String(),
		OrganizationID: r.OrganizationID.String(),
		ProjectID:      r.ProjectID.String(),
		Name:           r.Name,
		IsProtected:    r.IsProtected,
		CreatedAt:      r.CreatedAt.Time.UTC(),
		UpdatedAt:      r.UpdatedAt.Time.UTC(),
	}
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
