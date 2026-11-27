package organizations

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Yhanko/vigia/internal/platform/clock"
	"github.com/Yhanko/vigia/internal/platform/database"
	"github.com/Yhanko/vigia/internal/platform/database/sqlcgen"
)

const (
	InvitationTTL       = 7 * 24 * time.Hour
	OrgDeletionGraceTTL = 14 * 24 * time.Hour
	ReauthWindow        = 10 * time.Minute
	defaultListLimit    = 50
)

var slugPattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{1,61}[a-z0-9])?$`)

// Mailer is the consumer-defined interface for sending invitation emails.
type Mailer interface {
	Send(ctx context.Context, to, subject, textBody string) error
}

// Actor carries the authenticated caller's identity and session security context.
type Actor struct {
	UserID     string
	Email      string
	MFAEnabled bool
	LastAuthAt time.Time
	RequestID  string
	IPPrefix   *string
	UserAgent  *string
}

// Organization represents a tenant organization.
type Organization struct {
	ID         string
	Name       string
	Slug       string
	Status     string
	PurgeAfter *time.Time
	CreatedAt  time.Time
}

// UserOrgSummary is returned by list_user_organizations (SECURITY DEFINER).
type UserOrgSummary struct {
	OrganizationID   string
	Name             string
	Slug             string
	OrgStatus        string
	Role             string
	MembershipStatus string
}

// Member represents an active organization membership joined with user info.
type Member struct {
	ID             string
	OrganizationID string
	UserID         string
	Email          string
	Name           string
	Role           string
	Status         string
	CreatedAt      time.Time
}

// Invitation represents a pending organization invitation (never stores raw token).
type Invitation struct {
	ID             string
	OrganizationID string
	Email          string
	Role           string
	InvitedBy      string
	ExpiresAt      time.Time
	CreatedAt      time.Time
}

// Team represents a tenant-scoped team.
type Team struct {
	ID             string
	OrganizationID string
	Name           string
	Slug           string
	CreatedAt      time.Time
}

// Service implements tenant-scoped organization, membership, invitation, team,
// ownership transfer, and soft-deletion workflows (ADR-008, critical-flows.md).
type Service struct {
	pool                     *pgxpool.Pool
	q                        *sqlcgen.Queries
	mailer                   Mailer
	appURL                   string
	mfaRequiredForPrivileged bool
	clk                      clock.Clock
}

// ServiceConfig holds explicit dependencies for the organizations Service.
type ServiceConfig struct {
	Pool                     *pgxpool.Pool
	Mailer                   Mailer
	AppURL                   string
	MFARequiredForPrivileged bool
	Clock                    clock.Clock
}

// NewService constructs an organizations Service.
func NewService(cfg ServiceConfig) (*Service, error) {
	if cfg.Pool == nil {
		return nil, errors.New("organizations: pgx pool is required")
	}
	clk := cfg.Clock
	if clk == nil {
		clk = clock.System{}
	}
	return &Service{
		pool:                     cfg.Pool,
		q:                        sqlcgen.New(cfg.Pool),
		mailer:                   cfg.Mailer,
		appURL:                   strings.TrimRight(strings.TrimSpace(cfg.AppURL), "/"),
		mfaRequiredForPrivileged: cfg.MFARequiredForPrivileged,
		clk:                      clk,
	}, nil
}

// ListForUser lists active organizations for actor via the SECURITY DEFINER function.
func (s *Service) ListForUser(ctx context.Context, actor Actor) ([]UserOrgSummary, error) {
	rows, err := s.pool.Query(ctx,
		"SELECT organization_id, name, slug, org_status, role, membership_status FROM list_user_organizations($1)",
		actor.UserID,
	)
	if err != nil {
		return nil, fmt.Errorf("list user organizations: %w", err)
	}
	defer rows.Close()

	out := make([]UserOrgSummary, 0)
	for rows.Next() {
		var u UserOrgSummary
		if err := rows.Scan(&u.OrganizationID, &u.Name, &u.Slug, &u.OrgStatus, &u.Role, &u.MembershipStatus); err != nil {
			return nil, fmt.Errorf("scan user org: %w", err)
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// Create creates an organization, grants creator 'owner' membership, and writes
// an audit log inside a single WithTenantTx transaction.
func (s *Service) Create(ctx context.Context, actor Actor, name, slug string) (Organization, error) {
	name = strings.TrimSpace(name)
	slug = strings.ToLower(strings.TrimSpace(slug))
	if name == "" || len(name) > 120 {
		return Organization{}, &ValidationError{Field: "name", Message: "must be between 1 and 120 characters"}
	}
	if !slugPattern.MatchString(slug) {
		return Organization{}, &ValidationError{Field: "slug", Message: "must be 3-63 lowercase alphanumeric characters or hyphens"}
	}

	orgIDStr, err := newUUIDv4()
	if err != nil {
		return Organization{}, err
	}
	tid, err := database.ParseTenantID(orgIDStr)
	if err != nil {
		return Organization{}, err
	}
	memIDStr, err := newUUIDv4()
	if err != nil {
		return Organization{}, err
	}

	orgUUID := mustScanUUID(orgIDStr)
	memUUID := mustScanUUID(memIDStr)
	userUUID := mustScanUUID(actor.UserID)

	var created Organization
	err = database.WithTenantTx(ctx, s.pool, tid, func(tx pgx.Tx) error {
		qtx := s.q.WithTx(tx)
		orgRow, err := qtx.CreateOrganization(ctx, sqlcgen.CreateOrganizationParams{
			ID:    orgUUID,
			Btrim: name,
			Btrim_2: slug,
		})
		if err != nil {
			if isUniqueViolation(err) {
				return ErrConflict
			}
			return fmt.Errorf("create organization: %w", err)
		}
		if _, err := qtx.CreateMembership(ctx, sqlcgen.CreateMembershipParams{
			ID:             memUUID,
			OrganizationID: orgUUID,
			UserID:         userUUID,
			Role:           RoleOwner,
		}); err != nil {
			return fmt.Errorf("create owner membership: %w", err)
		}
		s.writeAuditTx(ctx, qtx, orgUUID, actor, "org.created", "organization", orgIDStr, "success", []byte(`{}`))
		created = mapOrg(orgRow)
		return nil
	})
	return created, err
}

// Authorize checks membership, MFA-for-privileged enforcement, and RBAC permission
// inside WithTenantTx. Non-members receive ErrNotFound (404, ADR-008).
func (s *Service) Authorize(ctx context.Context, tenantID database.TenantID, actor Actor, perm Permission) (string, error) {
	var role string
	err := database.WithTenantTx(ctx, s.pool, tenantID, func(tx pgx.Tx) error {
		qtx := s.q.WithTx(tx)
		m, err := qtx.GetMembershipByUser(ctx, sqlcgen.GetMembershipByUserParams{
			OrganizationID: mustScanUUID(tenantID.String()),
			UserID:         mustScanUUID(actor.UserID),
		})
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrNotFound
			}
			return err
		}
		role = m.Role
		return nil
	})
	if err != nil {
		return "", err
	}
	if s.mfaRequiredForPrivileged && (role == RoleOwner || role == RoleAdmin) && !actor.MFAEnabled {
		return "", ErrMFASetupRequired
	}
	if !HasPermission(role, perm) {
		return "", ErrForbidden
	}
	return role, nil
}

// Get returns organization details for an authorized member.
func (s *Service) Get(ctx context.Context, tenantID database.TenantID, actor Actor) (Organization, error) {
	if _, err := s.Authorize(ctx, tenantID, actor, PermOrgRead); err != nil {
		return Organization{}, err
	}
	var out Organization
	err := database.WithTenantTx(ctx, s.pool, tenantID, func(tx pgx.Tx) error {
		row, err := s.q.WithTx(tx).GetOrganizationByID(ctx, mustScanUUID(tenantID.String()))
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrNotFound
			}
			return err
		}
		out = mapOrg(row)
		return nil
	})
	return out, err
}

// Update updates the organization name (requires PermOrgUpdate).
func (s *Service) Update(ctx context.Context, tenantID database.TenantID, actor Actor, name string) (Organization, error) {
	if _, err := s.Authorize(ctx, tenantID, actor, PermOrgUpdate); err != nil {
		return Organization{}, err
	}
	name = strings.TrimSpace(name)
	if name == "" || len(name) > 120 {
		return Organization{}, &ValidationError{Field: "name", Message: "must be between 1 and 120 characters"}
	}
	now := s.clk.Now().UTC()
	orgUUID := mustScanUUID(tenantID.String())
	var out Organization
	err := database.WithTenantTx(ctx, s.pool, tenantID, func(tx pgx.Tx) error {
		qtx := s.q.WithTx(tx)
		row, err := qtx.UpdateOrganization(ctx, sqlcgen.UpdateOrganizationParams{
			ID:        orgUUID,
			Btrim:     name,
			UpdatedAt: pgtype.Timestamptz{Time: now, Valid: true},
		})
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrNotFound
			}
			return err
		}
		s.writeAuditTx(ctx, qtx, orgUUID, actor, "org.updated", "organization", tenantID.String(), "success", []byte(`{}`))
		out = mapOrg(row)
		return nil
	})
	return out, err
}

// ScheduleDeletion soft-deletes an organization with a 14-day grace period
// (owner only, recent auth <= 10m, slug confirmation, revokes pending invitations).
func (s *Service) ScheduleDeletion(ctx context.Context, tenantID database.TenantID, actor Actor, confirmSlug string) (Organization, error) {
	if _, err := s.Authorize(ctx, tenantID, actor, PermOrgDelete); err != nil {
		return Organization{}, err
	}
	if err := s.requireRecentAuth(actor); err != nil {
		return Organization{}, err
	}
	now := s.clk.Now().UTC()
	purgeAfter := now.Add(OrgDeletionGraceTTL)
	orgUUID := mustScanUUID(tenantID.String())

	var out Organization
	err := database.WithTenantTx(ctx, s.pool, tenantID, func(tx pgx.Tx) error {
		qtx := s.q.WithTx(tx)
		cur, err := qtx.GetOrganizationByID(ctx, orgUUID)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrNotFound
			}
			return err
		}
		if cur.Slug != strings.ToLower(strings.TrimSpace(confirmSlug)) {
			return &ValidationError{Field: "confirmSlug", Message: "does not match organization slug"}
		}
		row, err := qtx.ScheduleOrganizationDeletion(ctx, sqlcgen.ScheduleOrganizationDeletionParams{
			ID:         orgUUID,
			PurgeAfter: pgtype.Timestamptz{Time: purgeAfter, Valid: true},
			UpdatedAt:  pgtype.Timestamptz{Time: now, Valid: true},
		})
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrConflict
			}
			return err
		}
		if err := qtx.RevokeAllPendingOrgInvitations(ctx, sqlcgen.RevokeAllPendingOrgInvitationsParams{
			OrganizationID: orgUUID,
			RevokedAt:      pgtype.Timestamptz{Time: now, Valid: true},
		}); err != nil {
			return err
		}
		s.writeAuditTx(ctx, qtx, orgUUID, actor, "organization.deletion_scheduled", "organization", tenantID.String(), "success", []byte(`{}`))
		out = mapOrg(row)
		return nil
	})
	return out, err
}

// CancelDeletion restores a pending_deletion organization back to active (owner + reauth).
func (s *Service) CancelDeletion(ctx context.Context, tenantID database.TenantID, actor Actor) (Organization, error) {
	if _, err := s.Authorize(ctx, tenantID, actor, PermOrgDelete); err != nil {
		return Organization{}, err
	}
	if err := s.requireRecentAuth(actor); err != nil {
		return Organization{}, err
	}
	now := s.clk.Now().UTC()
	orgUUID := mustScanUUID(tenantID.String())
	var out Organization
	err := database.WithTenantTx(ctx, s.pool, tenantID, func(tx pgx.Tx) error {
		qtx := s.q.WithTx(tx)
		row, err := qtx.CancelOrganizationDeletion(ctx, sqlcgen.CancelOrganizationDeletionParams{
			ID:        orgUUID,
			UpdatedAt: pgtype.Timestamptz{Time: now, Valid: true},
		})
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrConflict
			}
			return err
		}
		s.writeAuditTx(ctx, qtx, orgUUID, actor, "organization.deletion_canceled", "organization", tenantID.String(), "success", []byte(`{}`))
		out = mapOrg(row)
		return nil
	})
	return out, err
}

// TransferOwnership atomically promotes targetUserID to owner and demotes actor
// to admin inside WithTenantTx (owner only, recent auth <= 10m, slug confirmation).
func (s *Service) TransferOwnership(ctx context.Context, tenantID database.TenantID, actor Actor, targetUserID, confirmSlug string) error {
	if _, err := s.Authorize(ctx, tenantID, actor, PermOrgTransferOwnership); err != nil {
		return err
	}
	if err := s.requireRecentAuth(actor); err != nil {
		return err
	}
	if targetUserID == actor.UserID {
		return &ValidationError{Field: "targetUserId", Message: "must be another active member"}
	}
	now := s.clk.Now().UTC()
	orgUUID := mustScanUUID(tenantID.String())
	ts := pgtype.Timestamptz{Time: now, Valid: true}

	return database.WithTenantTx(ctx, s.pool, tenantID, func(tx pgx.Tx) error {
		qtx := s.q.WithTx(tx)
		org, err := qtx.GetOrganizationByID(ctx, orgUUID)
		if err != nil {
			return ErrNotFound
		}
		if org.Slug != strings.ToLower(strings.TrimSpace(confirmSlug)) {
			return &ValidationError{Field: "confirmSlug", Message: "does not match organization slug"}
		}
		actorMem, err := qtx.GetMembershipByUser(ctx, sqlcgen.GetMembershipByUserParams{
			OrganizationID: orgUUID,
			UserID:         mustScanUUID(actor.UserID),
		})
		if err != nil {
			return ErrForbidden
		}
		targetMem, err := qtx.GetMembershipByUser(ctx, sqlcgen.GetMembershipByUserParams{
			OrganizationID: orgUUID,
			UserID:         mustScanUUID(targetUserID),
		})
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrNotFound
			}
			return err
		}
		if _, err := qtx.UpdateMembershipRole(ctx, sqlcgen.UpdateMembershipRoleParams{
			OrganizationID: orgUUID,
			ID:             targetMem.ID,
			Role:           RoleOwner,
			UpdatedAt:      ts,
		}); err != nil {
			return err
		}
		if _, err := qtx.UpdateMembershipRole(ctx, sqlcgen.UpdateMembershipRoleParams{
			OrganizationID: orgUUID,
			ID:             actorMem.ID,
			Role:           RoleAdmin,
			UpdatedAt:      ts,
		}); err != nil {
			return err
		}
		s.writeAuditTx(ctx, qtx, orgUUID, actor, "organization.ownership_transferred", "organization", tenantID.String(), "success", []byte(`{}`))
		return nil
	})
}

// ListMembers lists active members of an organization.
func (s *Service) ListMembers(ctx context.Context, tenantID database.TenantID, actor Actor, limit int) ([]Member, error) {
	if _, err := s.Authorize(ctx, tenantID, actor, PermMemberRead); err != nil {
		return nil, err
	}
	if limit <= 0 || limit > 100 {
		limit = defaultListLimit
	}
	var out []Member
	err := database.WithTenantTx(ctx, s.pool, tenantID, func(tx pgx.Tx) error {
		rows, err := s.q.WithTx(tx).ListOrganizationMembers(ctx, sqlcgen.ListOrganizationMembersParams{
			OrganizationID: mustScanUUID(tenantID.String()),
			PageLimit:      int32(limit), //nolint:gosec // bounded <= 100
		})
		if err != nil {
			return err
		}
		out = make([]Member, 0, len(rows))
		for _, r := range rows {
			out = append(out, Member{
				ID:             r.ID.String(),
				OrganizationID: r.OrganizationID.String(),
				UserID:         r.UserID.String(),
				Email:          r.UserEmail,
				Name:           r.UserName,
				Role:           r.Role,
				Status:         r.Status,
				CreatedAt:      r.CreatedAt.Time.UTC(),
			})
		}
		return nil
	})
	return out, err
}

// UpdateMemberRole updates another member's role with RBAC anti-escalation and recent-auth enforcement.
func (s *Service) UpdateMemberRole(ctx context.Context, tenantID database.TenantID, actor Actor, memberID, newRole string) (Member, error) {
	actorRole, err := s.Authorize(ctx, tenantID, actor, PermMemberUpdateRole)
	if err != nil {
		return Member{}, err
	}
	if err := s.requireRecentAuth(actor); err != nil {
		return Member{}, err
	}
	now := s.clk.Now().UTC()
	orgUUID := mustScanUUID(tenantID.String())
	memUUID := mustScanUUID(memberID)

	var out Member
	err = database.WithTenantTx(ctx, s.pool, tenantID, func(tx pgx.Tx) error {
		qtx := s.q.WithTx(tx)
		target, err := qtx.GetMembershipByID(ctx, sqlcgen.GetMembershipByIDParams{
			OrganizationID: orgUUID,
			ID:             memUUID,
		})
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrNotFound
			}
			return err
		}
		if !CanModifyMember(actorRole, actor.UserID, target.Role, target.UserID.String(), newRole) {
			return ErrForbidden
		}
		if target.Role == RoleOwner && newRole != RoleOwner {
			owners, err := qtx.CountActiveOwners(ctx, orgUUID)
			if err != nil {
				return err
			}
			if owners <= 1 {
				return ErrProtectedResource
			}
		}
		updated, err := qtx.UpdateMembershipRole(ctx, sqlcgen.UpdateMembershipRoleParams{
			OrganizationID: orgUUID,
			ID:             memUUID,
			Role:           newRole,
			UpdatedAt:      pgtype.Timestamptz{Time: now, Valid: true},
		})
		if err != nil {
			return err
		}
		s.writeAuditTx(ctx, qtx, orgUUID, actor, "member.role_updated", "membership", memberID, "success", []byte(`{}`))
		out = Member{
			ID:             updated.ID.String(),
			OrganizationID: updated.OrganizationID.String(),
			UserID:         updated.UserID.String(),
			Role:           updated.Role,
			Status:         updated.Status,
			CreatedAt:      updated.CreatedAt.Time.UTC(),
		}
		return nil
	})
	return out, err
}

// RemoveMember removes a member (preventing removal of the last owner or owner by admin).
func (s *Service) RemoveMember(ctx context.Context, tenantID database.TenantID, actor Actor, memberID string) error {
	actorRole, err := s.Authorize(ctx, tenantID, actor, PermMemberRemove)
	if err != nil {
		return err
	}
	orgUUID := mustScanUUID(tenantID.String())
	memUUID := mustScanUUID(memberID)
	return database.WithTenantTx(ctx, s.pool, tenantID, func(tx pgx.Tx) error {
		qtx := s.q.WithTx(tx)
		target, err := qtx.GetMembershipByID(ctx, sqlcgen.GetMembershipByIDParams{
			OrganizationID: orgUUID,
			ID:             memUUID,
		})
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrNotFound
			}
			return err
		}
		if !CanModifyMember(actorRole, actor.UserID, target.Role, target.UserID.String(), "") {
			return ErrForbidden
		}
		if target.Role == RoleOwner {
			owners, err := qtx.CountActiveOwners(ctx, orgUUID)
			if err != nil {
				return err
			}
			if owners <= 1 {
				return ErrProtectedResource
			}
		}
		if _, err := qtx.DeleteMembership(ctx, sqlcgen.DeleteMembershipParams{
			OrganizationID: orgUUID,
			ID:             memUUID,
		}); err != nil {
			return err
		}
		s.writeAuditTx(ctx, qtx, orgUUID, actor, "member.removed", "membership", memberID, "success", []byte(`{}`))
		return nil
	})
}

// CreateInvitation generates a 256-bit CSPRNG invitation token (stored as SHA-256
// hash, 7d expiry), persists it inside WithTenantTx, and emails the invitee outside tx.
func (s *Service) CreateInvitation(ctx context.Context, tenantID database.TenantID, actor Actor, email, role string) (Invitation, string, error) {
	actorRole, err := s.Authorize(ctx, tenantID, actor, PermMemberInvite)
	if err != nil {
		return Invitation{}, "", err
	}
	if !CanInviteRole(actorRole, role) {
		return Invitation{}, "", ErrForbidden
	}
	email = strings.ToLower(strings.TrimSpace(email))
	if email == "" || !strings.Contains(email, "@") || len(email) > 254 {
		return Invitation{}, "", &ValidationError{Field: "email", Message: "must be a valid email address"}
	}

	rawToken, err := generateToken32()
	if err != nil {
		return Invitation{}, "", err
	}
	tokHash := sha256.Sum256([]byte(rawToken))
	invIDStr, err := newUUIDv4()
	if err != nil {
		return Invitation{}, "", err
	}
	now := s.clk.Now().UTC()
	exp := now.Add(InvitationTTL)
	orgUUID := mustScanUUID(tenantID.String())

	var created Invitation
	err = database.WithTenantTx(ctx, s.pool, tenantID, func(tx pgx.Tx) error {
		qtx := s.q.WithTx(tx)
		row, err := qtx.CreateInvitation(ctx, sqlcgen.CreateInvitationParams{
			ID:             mustScanUUID(invIDStr),
			OrganizationID: orgUUID,
			Btrim:          email,
			Role:           role,
			TokenHash:      tokHash[:],
			InvitedBy:      mustScanUUID(actor.UserID),
			ExpiresAt:      pgtype.Timestamptz{Time: exp, Valid: true},
		})
		if err != nil {
			if isUniqueViolation(err) {
				return ErrConflict
			}
			return err
		}
		s.writeAuditTx(ctx, qtx, orgUUID, actor, "member.invited", "invitation", invIDStr, "success", []byte(`{}`))
		created = Invitation{
			ID:             row.ID.String(),
			OrganizationID: row.OrganizationID.String(),
			Email:          row.Email,
			Role:           row.Role,
			InvitedBy:      row.InvitedBy.String(),
			ExpiresAt:      row.ExpiresAt.Time.UTC(),
			CreatedAt:      row.CreatedAt.Time.UTC(),
		}
		return nil
	})
	if err != nil {
		return Invitation{}, "", err
	}

	if s.mailer != nil {
		_ = s.mailer.Send(ctx, email, "You have been invited to a Vigia organization",
			fmt.Sprintf("You have been invited to join a Vigia organization.\nAccept within 7 days:\n%s/invitations/%s\n", s.appURL, rawToken))
	}
	return created, rawToken, nil
}

// AcceptInvitation resolves (invitation_id, organization_id) via SECURITY DEFINER
// lookup_invitation_by_token_hash, then atomically accepts and creates membership inside WithTenantTx.
func (s *Service) AcceptInvitation(ctx context.Context, actor Actor, rawToken string) (Member, error) {
	rawToken = strings.TrimSpace(rawToken)
	if rawToken == "" {
		return Member{}, ErrNotFound
	}
	tokHash := sha256.Sum256([]byte(rawToken))

	var invIDStr, orgIDStr string
	if err := s.pool.QueryRow(ctx,
		"SELECT invitation_id, organization_id FROM lookup_invitation_by_token_hash($1)",
		tokHash[:],
	).Scan(&invIDStr, &orgIDStr); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Member{}, ErrNotFound
		}
		return Member{}, fmt.Errorf("lookup invitation: %w", err)
	}

	tid, err := database.ParseTenantID(orgIDStr)
	if err != nil {
		return Member{}, ErrNotFound
	}
	memIDStr, err := newUUIDv4()
	if err != nil {
		return Member{}, err
	}
	now := s.clk.Now().UTC()
	orgUUID := mustScanUUID(orgIDStr)

	var out Member
	err = database.WithTenantTx(ctx, s.pool, tid, func(tx pgx.Tx) error {
		qtx := s.q.WithTx(tx)
		inv, err := qtx.AcceptInvitation(ctx, sqlcgen.AcceptInvitationParams{
			OrganizationID: orgUUID,
			ID:             mustScanUUID(invIDStr),
			Now:            pgtype.Timestamptz{Time: now, Valid: true},
			UserEmail:      actor.Email,
		})
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrNotFound
			}
			return err
		}
		m, err := qtx.CreateMembership(ctx, sqlcgen.CreateMembershipParams{
			ID:             mustScanUUID(memIDStr),
			OrganizationID: orgUUID,
			UserID:         mustScanUUID(actor.UserID),
			Role:           inv.Role,
		})
		if err != nil {
			if isUniqueViolation(err) {
				return ErrConflict
			}
			return err
		}
		s.writeAuditTx(ctx, qtx, orgUUID, actor, "member.joined", "membership", memIDStr, "success", []byte(`{}`))
		out = Member{
			ID:             m.ID.String(),
			OrganizationID: m.OrganizationID.String(),
			UserID:         m.UserID.String(),
			Email:          actor.Email,
			Role:           m.Role,
			Status:         m.Status,
			CreatedAt:      m.CreatedAt.Time.UTC(),
		}
		return nil
	})
	return out, err
}

// CreateTeam creates a team inside WithTenantTx (requires PermTeamManage).
func (s *Service) CreateTeam(ctx context.Context, tenantID database.TenantID, actor Actor, name, slug string) (Team, error) {
	if _, err := s.Authorize(ctx, tenantID, actor, PermTeamManage); err != nil {
		return Team{}, err
	}
	name = strings.TrimSpace(name)
	slug = strings.ToLower(strings.TrimSpace(slug))
	if name == "" || !slugPattern.MatchString(slug) {
		return Team{}, &ValidationError{Field: "slug", Message: "invalid team name or slug"}
	}
	teamIDStr, err := newUUIDv4()
	if err != nil {
		return Team{}, err
	}
	orgUUID := mustScanUUID(tenantID.String())
	var out Team
	err = database.WithTenantTx(ctx, s.pool, tenantID, func(tx pgx.Tx) error {
		qtx := s.q.WithTx(tx)
		row, err := qtx.CreateTeam(ctx, sqlcgen.CreateTeamParams{
			ID:             mustScanUUID(teamIDStr),
			OrganizationID: orgUUID,
			Btrim:          name,
			Btrim_2:        slug,
		})
		if err != nil {
			if isUniqueViolation(err) {
				return ErrConflict
			}
			return err
		}
		s.writeAuditTx(ctx, qtx, orgUUID, actor, "team.created", "team", teamIDStr, "success", []byte(`{}`))
		out = Team{
			ID:             row.ID.String(),
			OrganizationID: row.OrganizationID.String(),
			Name:           row.Name,
			Slug:           row.Slug,
			CreatedAt:      row.CreatedAt.Time.UTC(),
		}
		return nil
	})
	return out, err
}

// ListTeams lists teams for an organization (requires PermTeamRead).
func (s *Service) ListTeams(ctx context.Context, tenantID database.TenantID, actor Actor, limit int) ([]Team, error) {
	if _, err := s.Authorize(ctx, tenantID, actor, PermTeamRead); err != nil {
		return nil, err
	}
	if limit <= 0 || limit > 100 {
		limit = defaultListLimit
	}
	var out []Team
	err := database.WithTenantTx(ctx, s.pool, tenantID, func(tx pgx.Tx) error {
		rows, err := s.q.WithTx(tx).ListOrganizationTeams(ctx, sqlcgen.ListOrganizationTeamsParams{
			OrganizationID: mustScanUUID(tenantID.String()),
			PageLimit:      int32(limit), //nolint:gosec // bounded <= 100
		})
		if err != nil {
			return err
		}
		out = make([]Team, 0, len(rows))
		for _, r := range rows {
			out = append(out, Team{
				ID:             r.ID.String(),
				OrganizationID: r.OrganizationID.String(),
				Name:           r.Name,
				Slug:           r.Slug,
				CreatedAt:      r.CreatedAt.Time.UTC(),
			})
		}
		return nil
	})
	return out, err
}

func (s *Service) requireRecentAuth(actor Actor) error {
	if s.clk.Now().UTC().Sub(actor.LastAuthAt) > ReauthWindow {
		return ErrReauthRequired
	}
	return nil
}

func (s *Service) writeAuditTx(ctx context.Context, qtx *sqlcgen.Queries, orgUUID pgtype.UUID, actor Actor, action, resType, resID, result string, changes []byte) {
	aid, err := newUUIDv4()
	if err != nil {
		return
	}
	reqID := actor.RequestID
	if strings.TrimSpace(reqID) == "" {
		reqID = "unknown"
	}
	_ = qtx.InsertTenantAuditLog(ctx, sqlcgen.InsertTenantAuditLogParams{
		ID:             mustScanUUID(aid),
		OrganizationID: orgUUID,
		ActorType:      "user",
		ActorID:        mustScanUUID(actor.UserID),
		Action:         action,
		ResourceType:   resType,
		ResourceID:     &resID,
		Result:         result,
		IpPrefix:       actor.IPPrefix,
		UserAgent:      actor.UserAgent,
		RequestID:      reqID,
		Changes:        changes,
	})
}

func mapOrg(r sqlcgen.Organization) Organization {
	o := Organization{
		ID:        r.ID.String(),
		Name:      r.Name,
		Slug:      r.Slug,
		Status:    r.Status,
		CreatedAt: r.CreatedAt.Time.UTC(),
	}
	if r.PurgeAfter.Valid {
		t := r.PurgeAfter.Time.UTC()
		o.PurgeAfter = &t
	}
	return o
}

func mustScanUUID(raw string) pgtype.UUID {
	var u pgtype.UUID
	_ = u.Scan(raw)
	return u
}

func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

func generateToken32() (string, error) {
	var b [32]byte
	if _, err := io.ReadFull(rand.Reader, b[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}

func newUUIDv4() (string, error) {
	var b [16]byte
	if _, err := io.ReadFull(rand.Reader, b[:]); err != nil {
		return "", err
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16],
	), nil
}
