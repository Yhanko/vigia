//go:build integration

package security_test

import (
	"context"
	"errors"
	"testing"

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
