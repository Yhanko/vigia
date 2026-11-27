//go:build integration

package organizations_test

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/url"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/Yhanko/vigia/internal/modules/organizations"
	"github.com/Yhanko/vigia/internal/platform/clock"
	"github.com/Yhanko/vigia/internal/platform/database"
	"github.com/Yhanko/vigia/migrations"
)

const timescaleImage = "timescale/timescaledb:2.32.1-pg18@sha256:70e6526ad8e31e3f4833f2c5863b50b92d7a6bee4d432ad1f660e2c6dd956d94"

func randHex(t *testing.T, n int) string {
	t.Helper()
	b := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return hex.EncodeToString(b)
}

func startOrgPG(t *testing.T) *pgxpool.Pool {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	adminPass := randHex(t, 16)
	appPass := randHex(t, 16)

	ctr, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
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
	t.Cleanup(func() { _ = ctr.Terminate(context.Background()) })

	host, _ := ctr.Host(ctx)
	port, _ := ctr.MappedPort(ctx, "5432/tcp")
	adminDSN := fmt.Sprintf("postgres://vigia:%s@%s:%s/vigia?sslmode=disable", url.QueryEscape(adminPass), host, port.Port())
	appDSN := fmt.Sprintf("postgres://vigia_app:%s@%s:%s/vigia?sslmode=disable", url.QueryEscape(appPass), host, port.Port())

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
	return pool
}

func insertUser(t *testing.T, ctx context.Context, pool *pgxpool.Pool, email, name string, verified, mfa bool) string {
	t.Helper()
	uid := uuid.New().String()
	var verifiedAt any
	if verified {
		verifiedAt = time.Now().UTC()
	}
	_, err := pool.Exec(ctx, `
		INSERT INTO users (id, email, name, password_hash, status, email_verified_at, mfa_enabled)
		VALUES ($1, $2, $3, 'placeholder-hash', 'active', $4, $5)
	`, uid, email, name, verifiedAt, mfa)
	if err != nil {
		t.Fatalf("insert user %s: %v", email, err)
	}
	return uid
}

// TestEmailVerificationGuards_CTO27 verifies CTO #27 negative and positive cases:
//  1. Unverified account with matching email CANNOT accept invitation -> ErrEmailNotVerified, invitation stays pending.
//  2. After verifying email, the exact same invitation CAN be accepted.
//  3. Unverified account CANNOT create an organization -> ErrEmailNotVerified.
//  4. Ownership transfer to an unverified member -> ErrEmailNotVerified; transfer to member without MFA (when enforced) -> ErrMFASetupRequired.
func TestEmailVerificationGuards_CTO27(t *testing.T) {
	ctx := context.Background()
	pool := startOrgPG(t)
	clk := clock.System{}
	now := clk.Now().UTC()

	svc, err := organizations.NewService(organizations.ServiceConfig{
		Pool:                     pool,
		AppURL:                   "https://app.vigia.ao",
		MFARequiredForPrivileged: true,
		Clock:                    clk,
	})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}

	ownerID := insertUser(t, ctx, pool, "owner27@vigia.test", "Owner", true, true)
	unverifiedID := insertUser(t, ctx, pool, "victim@empresa.com", "Attacker Unverified", false, true)
	noMFAID := insertUser(t, ctx, pool, "nomfa@empresa.com", "Verified No MFA", true, false)

	owner := organizations.Actor{UserID: ownerID, Email: "owner27@vigia.test", MFAEnabled: true, LastAuthAt: now, RequestID: "r27"}
	unverified := organizations.Actor{UserID: unverifiedID, Email: "victim@empresa.com", MFAEnabled: true, LastAuthAt: now, RequestID: "r27"}
	noMFA := organizations.Actor{UserID: noMFAID, Email: "nomfa@empresa.com", MFAEnabled: false, LastAuthAt: now, RequestID: "r27"}

	// Case 3: Unverified account cannot create an organization.
	if _, err := svc.Create(ctx, unverified, "Unverified Org", "unverified-org"); !errors.Is(err, organizations.ErrEmailNotVerified) {
		t.Fatalf("unverified Create org = %v, want ErrEmailNotVerified", err)
	}

	// Verified owner creates organization and invites victim@empresa.com.
	org, err := svc.Create(ctx, owner, "Empresa Real", "empresa-real")
	if err != nil {
		t.Fatalf("owner Create org: %v", err)
	}
	tid, _ := database.ParseTenantID(org.ID)

	inv, rawToken, err := svc.CreateInvitation(ctx, tid, owner, "victim@empresa.com", organizations.RoleAdmin)
	if err != nil {
		t.Fatalf("CreateInvitation: %v", err)
	}

	// Case 1: Unverified user with matching email MUST be rejected and invitation must stay pending.
	if _, err := svc.AcceptInvitation(ctx, unverified, rawToken); !errors.Is(err, organizations.ErrEmailNotVerified) {
		t.Fatalf("unverified AcceptInvitation = %v, want ErrEmailNotVerified", err)
	}

	pending, err := svc.ListInvitations(ctx, tid, owner)
	if err != nil {
		t.Fatalf("ListInvitations: %v", err)
	}
	if len(pending) != 1 || pending[0].ID != inv.ID {
		t.Fatalf("expected invitation %s to remain pending after rejected unverified accept, got %+v", inv.ID, pending)
	}

	// Case 2: Verify email in DB, then the exact same invitation succeeds.
	if _, err := pool.Exec(ctx, `UPDATE users SET email_verified_at = now() WHERE id = $1`, unverifiedID); err != nil {
		t.Fatalf("verify user email: %v", err)
	}
	if _, err := svc.AcceptInvitation(ctx, unverified, rawToken); err != nil {
		t.Fatalf("verified AcceptInvitation failed: %v", err)
	}

	// Case 4a: Ownership transfer to a member whose email becomes unverified must fail with ErrEmailNotVerified.
	if _, err := pool.Exec(ctx, `UPDATE users SET email_verified_at = NULL WHERE id = $1`, unverifiedID); err != nil {
		t.Fatalf("unverify target: %v", err)
	}
	if err := svc.TransferOwnership(ctx, tid, owner, unverifiedID, org.Slug); !errors.Is(err, organizations.ErrEmailNotVerified) {
		t.Fatalf("TransferOwnership to unverified member = %v, want ErrEmailNotVerified", err)
	}

	// Case 4b: Ownership transfer to a verified member WITHOUT MFA when MFARequiredForPrivileged=true must fail.
	_, noMFATok, err := svc.CreateInvitation(ctx, tid, owner, noMFA.Email, organizations.RoleMember)
	if err != nil {
		t.Fatalf("invite noMFA: %v", err)
	}
	if _, err := svc.AcceptInvitation(ctx, noMFA, noMFATok); err != nil {
		t.Fatalf("accept noMFA: %v", err)
	}
	if err := svc.TransferOwnership(ctx, tid, owner, noMFAID, org.Slug); !errors.Is(err, organizations.ErrMFASetupRequired) {
		t.Fatalf("TransferOwnership to member without MFA = %v, want ErrMFASetupRequired", err)
	}
}
