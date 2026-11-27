//go:build integration

package security_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/Yhanko/vigia/internal/modules/credentials"
	"github.com/Yhanko/vigia/internal/modules/organizations"
	"github.com/Yhanko/vigia/internal/modules/projects"
	"github.com/Yhanko/vigia/internal/platform/clock"
	"github.com/Yhanko/vigia/internal/platform/database"
)

// TestOrgDeletionRevokesCredentials_CTO28 verifies CTO #28:
//  1. Valid API key stops authenticating immediately after org ScheduleDeletion (even with warm Redis cache).
//  2. Revoked key stays revoked after CancelDeletion.
//  3. lookup_api_credential_by_prefix returns 0 rows when project.status <> 'active' or org.status <> 'active'.
func TestOrgDeletionRevokesCredentials_CTO28(t *testing.T) {
	ctx := context.Background()
	adminPool, appPool, rdb := startPGAndRedis(t)
	clk := clock.System{}
	now := clk.Now().UTC()
	pepper := []byte(randomHex(t, 32))

	credSvc, err := credentials.NewService(credentials.ServiceConfig{
		Pool:                     appPool,
		Cache:                    credentials.NewRedisCache(rdb),
		Pepper:                   pepper,
		IngestHost:               "ingest.vigia.ao",
		MFARequiredForPrivileged: true,
		Clock:                    clk,
	})
	if err != nil {
		t.Fatalf("credentials.NewService: %v", err)
	}
	t.Cleanup(func() { credSvc.Close(context.Background()) })

	orgSvc, err := organizations.NewService(organizations.ServiceConfig{
		Pool:                     appPool,
		CredentialInvalidator:    credSvc,
		AppURL:                   "https://app.vigia.ao",
		MFARequiredForPrivileged: true,
		Clock:                    clk,
	})
	if err != nil {
		t.Fatalf("organizations.NewService: %v", err)
	}
	projSvc, err := projects.NewService(projects.ServiceConfig{
		Pool:                     appPool,
		CredentialInvalidator:    credSvc,
		MFARequiredForPrivileged: true,
		Clock:                    clk,
	})
	if err != nil {
		t.Fatalf("projects.NewService: %v", err)
	}

	ownerID := insertTestUser(t, ctx, appPool, "owner28@vigia.test", "Owner 28")
	owner := organizations.Actor{UserID: ownerID, Email: "owner28@vigia.test", MFAEnabled: true, LastAuthAt: now, RequestID: "r28"}

	org, err := orgSvc.Create(ctx, owner, "Org 28", "org-28")
	if err != nil {
		t.Fatalf("create org: %v", err)
	}
	tid, _ := database.ParseTenantID(org.ID)

	proj, err := projSvc.CreateProject(ctx, tid, owner, "Proj 28", "proj-28", "go")
	if err != nil {
		t.Fatalf("create project: %v", err)
	}
	cred, err := credSvc.Create(ctx, tid, owner, credentials.CreateInput{
		ProjectID: proj.ID,
		Kind:      credentials.KindIngest,
		Name:      "Key 28",
	})
	if err != nil {
		t.Fatalf("create credential: %v", err)
	}

	// Warm Redis cache with a valid authentication.
	if _, err := credSvc.AuthenticateSecret(ctx, cred.Secret, "198.51.100.1"); err != nil {
		t.Fatalf("AuthenticateSecret before org deletion: %v", err)
	}

	// 1. ScheduleDeletion MUST revoke all org credentials and evict Redis cache immediately.
	if _, err := orgSvc.ScheduleDeletion(ctx, tid, owner, org.Slug); err != nil {
		t.Fatalf("ScheduleDeletion: %v", err)
	}
	if _, err := credSvc.AuthenticateSecret(ctx, cred.Secret, "198.51.100.1"); !errors.Is(err, credentials.ErrInvalidCredential) {
		t.Fatalf("AuthenticateSecret after ScheduleDeletion = %v, want ErrInvalidCredential", err)
	}

	// 2. CancelDeletion MUST NOT restore revoked credentials.
	if _, err := orgSvc.CancelDeletion(ctx, tid, owner); err != nil {
		t.Fatalf("CancelDeletion: %v", err)
	}
	if _, err := credSvc.AuthenticateSecret(ctx, cred.Secret, "198.51.100.1"); !errors.Is(err, credentials.ErrInvalidCredential) {
		t.Fatalf("AuthenticateSecret after CancelDeletion = %v, want ErrInvalidCredential", err)
	}

	// 3. Direct DB check: lookup_api_credential_by_prefix MUST reject credentials of non-active projects
	// even if api_credentials.revoked_at is NULL (defense in depth).
	cred2, err := credSvc.Create(ctx, tid, owner, credentials.CreateInput{
		ProjectID: proj.ID,
		Kind:      credentials.KindIngest,
		Name:      "Key 28b",
	})
	if err != nil {
		t.Fatalf("create cred2: %v", err)
	}
	if _, err := adminPool.Exec(ctx, `UPDATE projects SET status = 'deleting' WHERE id = $1`, proj.ID); err != nil {
		t.Fatalf("mark project deleting: %v", err)
	}
	var cid string
	err = appPool.QueryRow(ctx, `SELECT credential_id FROM lookup_api_credential_by_prefix($1, $2)`, credentials.KindIngest, cred2.Prefix).Scan(&cid)
	if !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("lookup_api_credential_by_prefix for non-active project = (%q, %v), want pgx.ErrNoRows", cid, err)
	}
}

// TestCredentialsAndHighRiskReauth_CTO29 verifies CTO #29:
//   - Session with last_auth_at 11 minutes ago MUST be rejected with ErrReauthRequired
//     on credentials.Create, Revoke, Rotate (with zero DB writes), as well as
//     UpdateMemberRole, TransferOwnership, ScheduleDeletion, CancelDeletion, and DeleteProject.
//   - After fresh reauth (last_auth_at = now), Create, Rotate, and Revoke succeed.
func TestCredentialsAndHighRiskReauth_CTO29(t *testing.T) {
	ctx := context.Background()
	_, appPool, rdb := startPGAndRedis(t)
	now := time.Now().UTC().Truncate(time.Second)
	clk := clock.NewFake(now)
	pepper := []byte(randomHex(t, 32))

	credSvc, err := credentials.NewService(credentials.ServiceConfig{
		Pool:                     appPool,
		Cache:                    credentials.NewRedisCache(rdb),
		Pepper:                   pepper,
		IngestHost:               "ingest.vigia.ao",
		MFARequiredForPrivileged: true,
		Clock:                    clk,
	})
	if err != nil {
		t.Fatalf("credentials.NewService: %v", err)
	}
	t.Cleanup(func() { credSvc.Close(context.Background()) })

	orgSvc, err := organizations.NewService(organizations.ServiceConfig{
		Pool:                     appPool,
		CredentialInvalidator:    credSvc,
		AppURL:                   "https://app.vigia.ao",
		MFARequiredForPrivileged: true,
		Clock:                    clk,
	})
	if err != nil {
		t.Fatalf("organizations.NewService: %v", err)
	}
	projSvc, err := projects.NewService(projects.ServiceConfig{
		Pool:                     appPool,
		CredentialInvalidator:    credSvc,
		MFARequiredForPrivileged: true,
		Clock:                    clk,
	})
	if err != nil {
		t.Fatalf("projects.NewService: %v", err)
	}

	ownerID := insertTestUser(t, ctx, appPool, "owner29@vigia.test", "Owner 29")
	memberID := insertTestUser(t, ctx, appPool, "member29@vigia.test", "Member 29")
	freshOwner := organizations.Actor{UserID: ownerID, Email: "owner29@vigia.test", MFAEnabled: true, LastAuthAt: now, RequestID: "r29"}
	memberActor := organizations.Actor{UserID: memberID, Email: "member29@vigia.test", MFAEnabled: true, LastAuthAt: now, RequestID: "r29"}

	org, err := orgSvc.Create(ctx, freshOwner, "Org 29", "org-29")
	if err != nil {
		t.Fatalf("create org: %v", err)
	}
	tid, _ := database.ParseTenantID(org.ID)
	_, tok, err := orgSvc.CreateInvitation(ctx, tid, freshOwner, memberActor.Email, organizations.RoleMember)
	if err != nil {
		t.Fatalf("invite member: %v", err)
	}
	mem, err := orgSvc.AcceptInvitation(ctx, memberActor, tok)
	if err != nil {
		t.Fatalf("accept member: %v", err)
	}
	proj, err := projSvc.CreateProject(ctx, tid, freshOwner, "Proj 29", "proj-29", "go")
	if err != nil {
		t.Fatalf("create proj: %v", err)
	}
	existingCred, err := credSvc.Create(ctx, tid, freshOwner, credentials.CreateInput{
		ProjectID: proj.ID,
		Kind:      credentials.KindIngest,
		Name:      "Initial Key",
	})
	if err != nil {
		t.Fatalf("create initial cred: %v", err)
	}

	// Advance clock by 11 minutes -> session LastAuthAt is now stale (> 10m window).
	clk.Advance(11 * time.Minute)
	staleOwner := freshOwner // LastAuthAt is still 11 minutes ago

	if _, err := credSvc.Create(ctx, tid, staleOwner, credentials.CreateInput{
		ProjectID: proj.ID,
		Kind:      credentials.KindIngest,
		Name:      "Should Fail",
	}); !errors.Is(err, credentials.ErrReauthRequired) {
		t.Fatalf("stale credSvc.Create = %v, want ErrReauthRequired", err)
	}
	if err := credSvc.Revoke(ctx, tid, staleOwner, existingCred.ID); !errors.Is(err, credentials.ErrReauthRequired) {
		t.Fatalf("stale credSvc.Revoke = %v, want ErrReauthRequired", err)
	}
	if _, err := credSvc.Rotate(ctx, tid, staleOwner, existingCred.ID, 0); !errors.Is(err, credentials.ErrReauthRequired) {
		t.Fatalf("stale credSvc.Rotate = %v, want ErrReauthRequired", err)
	}
	// Verify nothing was created or revoked.
	list, err := credSvc.List(ctx, tid, staleOwner, proj.ID)
	if err != nil {
		t.Fatalf("credSvc.List: %v", err)
	}
	if len(list) != 1 || list[0].RevokedAt != nil {
		t.Fatalf("expected exactly 1 active credential untouched, got %+v", list)
	}

	// Also verify all other ADR-005 high-risk operations require recent auth.
	if _, err := orgSvc.UpdateMemberRole(ctx, tid, staleOwner, mem.ID, organizations.RoleAdmin); !errors.Is(err, organizations.ErrReauthRequired) {
		t.Fatalf("stale UpdateMemberRole = %v, want ErrReauthRequired", err)
	}
	if err := orgSvc.TransferOwnership(ctx, tid, staleOwner, memberID, org.Slug); !errors.Is(err, organizations.ErrReauthRequired) {
		t.Fatalf("stale TransferOwnership = %v, want ErrReauthRequired", err)
	}
	if _, err := orgSvc.ScheduleDeletion(ctx, tid, staleOwner, org.Slug); !errors.Is(err, organizations.ErrReauthRequired) {
		t.Fatalf("stale ScheduleDeletion = %v, want ErrReauthRequired", err)
	}
	if _, err := orgSvc.CancelDeletion(ctx, tid, staleOwner); !errors.Is(err, organizations.ErrReauthRequired) {
		t.Fatalf("stale CancelDeletion = %v, want ErrReauthRequired", err)
	}
	if err := projSvc.DeleteProject(ctx, tid, staleOwner, proj.ID, proj.Slug); !errors.Is(err, projects.ErrReauthRequired) {
		t.Fatalf("stale DeleteProject = %v, want ErrReauthRequired", err)
	}

	// Simulate fresh POST /auth/reauth -> LastAuthAt = clk.Now().
	reauthedOwner := staleOwner
	reauthedOwner.LastAuthAt = clk.Now().UTC()

	created, err := credSvc.Create(ctx, tid, reauthedOwner, credentials.CreateInput{
		ProjectID: proj.ID,
		Kind:      credentials.KindClient,
		Name:      "After Reauth",
	})
	if err != nil {
		t.Fatalf("reauthed credSvc.Create: %v", err)
	}
	if _, err := credSvc.Rotate(ctx, tid, reauthedOwner, created.ID, 0); err != nil {
		t.Fatalf("reauthed credSvc.Rotate: %v", err)
	}
	if err := credSvc.Revoke(ctx, tid, reauthedOwner, existingCred.ID); err != nil {
		t.Fatalf("reauthed credSvc.Revoke: %v", err)
	}
}
