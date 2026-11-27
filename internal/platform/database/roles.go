package database

import (
	"context"
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ErrPrivilegedRole is returned by VerifyNonPrivilegedRole when the runtime
// PostgreSQL role has SUPERUSER or BYPASSRLS privileges (ADR-008).
var ErrPrivilegedRole = errors.New("database: runtime role is privileged")

// VerifyNonPrivilegedRole queries PostgreSQL for the active connection's role
// attributes and returns an error wrapping ErrPrivilegedRole if rolsuper or
// rolbypassrls is true. The error identifies the role name and offending
// attribute(s) and never includes connection DSN details.
func VerifyNonPrivilegedRole(ctx context.Context, pool *pgxpool.Pool) error {
	var (
		roleName     string
		rolSuper     bool
		rolBypassRLS bool
	)
	err := pool.QueryRow(ctx,
		"SELECT current_user, rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user",
	).Scan(&roleName, &rolSuper, &rolBypassRLS)
	if err != nil {
		return fmt.Errorf("verify runtime role: %w", err)
	}

	switch {
	case rolSuper && rolBypassRLS:
		return fmt.Errorf("%w: role %q has rolsuper=true and rolbypassrls=true", ErrPrivilegedRole, roleName)
	case rolSuper:
		return fmt.Errorf("%w: role %q has rolsuper=true", ErrPrivilegedRole, roleName)
	case rolBypassRLS:
		return fmt.Errorf("%w: role %q has rolbypassrls=true", ErrPrivilegedRole, roleName)
	default:
		return nil
	}
}

const (
	scramSaltBytes  = 16
	scramIterations = 4096
	scramKeyBytes   = 32
)

// EnsureRoles idempotently creates and synchronizes the cluster-level
// PostgreSQL roles required by ADR-008:
//   - vigia_definer: NOLOGIN NOSUPERUSER BYPASSRLS (owner of SECURITY DEFINER functions)
//   - vigia_app:     LOGIN NOSUPERUSER NOBYPASSRLS (runtime application role)
//
// Roles live outside goose migrations (cluster-global; Migrate down never drops
// roles). The password is never sent in plaintext and DDL logging is silenced
// for the transaction (SET LOCAL log_statement = 'none'): Go computes a
// SCRAM-SHA-256 verifier and PostgreSQL quotes the literal via format(%L).
func EnsureRoles(ctx context.Context, adminDSN, appPassword string) error {
	if appPassword == "" {
		return errors.New("ensure roles: app password is required")
	}

	verifier, err := scramSHA256Verifier(appPassword)
	if err != nil {
		return fmt.Errorf("ensure roles: build scram verifier: %w", err)
	}

	cfg, err := parseMigrateConfig(adminDSN)
	if err != nil {
		return fmt.Errorf("ensure roles: %w", err)
	}

	conn, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		return fmt.Errorf("ensure roles: connect: %w", err)
	}
	defer func() { _ = conn.Close(ctx) }()

	tx, err := conn.Begin(ctx)
	if err != nil {
		return fmt.Errorf("ensure roles: begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// Prevent ALTER ROLE ... PASSWORD from appearing in PostgreSQL DDL logs.
	if _, err := tx.Exec(ctx, "SET LOCAL log_statement = 'none'"); err != nil {
		return fmt.Errorf("ensure roles: silence log_statement: %w", err)
	}

	const createRolesSQL = `
DO $$
BEGIN
	IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'vigia_definer') THEN
		CREATE ROLE vigia_definer NOLOGIN NOSUPERUSER BYPASSRLS NOCREATEDB NOCREATEROLE;
	ELSE
		ALTER ROLE vigia_definer NOLOGIN NOSUPERUSER BYPASSRLS NOCREATEDB NOCREATEROLE;
	END IF;

	IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'vigia_app') THEN
		CREATE ROLE vigia_app LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE;
	END IF;
END
$$;`
	if _, err := tx.Exec(ctx, createRolesSQL); err != nil {
		return fmt.Errorf("ensure roles: create roles: %w", err)
	}

	// DDL does not accept bind parameters; let PostgreSQL quote the verifier via format(%L).
	var alterSQL string
	err = tx.QueryRow(ctx,
		"SELECT format('ALTER ROLE vigia_app WITH LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE PASSWORD %L', $1::text)",
		verifier,
	).Scan(&alterSQL)
	if err != nil {
		return fmt.Errorf("ensure roles: format alter role: %w", err)
	}
	if _, err := tx.Exec(ctx, alterSQL); err != nil {
		return fmt.Errorf("ensure roles: alter vigia_app password: %w", err)
	}

	const schemaGrantsSQL = `
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO vigia_app, vigia_definer;
`
	if _, err := tx.Exec(ctx, schemaGrantsSQL); err != nil {
		return fmt.Errorf("ensure roles: schema grants: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("ensure roles: commit: %w", err)
	}
	return nil
}

// scramSHA256Verifier computes a PostgreSQL-compatible SCRAM-SHA-256 password
// verifier (RFC 7677 / PostgreSQL format):
//
//	SCRAM-SHA-256$4096:<base64-salt>$<base64-StoredKey>:<base64-ServerKey>
func scramSHA256Verifier(password string) (string, error) {
	salt := make([]byte, scramSaltBytes)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return "", fmt.Errorf("generate salt: %w", err)
	}

	saltedPassword, err := pbkdf2.Key(sha256.New, password, salt, scramIterations, scramKeyBytes)
	if err != nil {
		return "", fmt.Errorf("pbkdf2: %w", err)
	}
	defer clear(saltedPassword)

	clientMac := hmac.New(sha256.New, saltedPassword)
	_, _ = clientMac.Write([]byte("Client Key"))
	clientKey := clientMac.Sum(nil)
	defer clear(clientKey)

	storedKey := sha256.Sum256(clientKey)

	serverMac := hmac.New(sha256.New, saltedPassword)
	_, _ = serverMac.Write([]byte("Server Key"))
	serverKey := serverMac.Sum(nil)
	defer clear(serverKey)

	return fmt.Sprintf("SCRAM-SHA-256$%d:%s$%s:%s",
		scramIterations,
		base64.StdEncoding.EncodeToString(salt),
		base64.StdEncoding.EncodeToString(storedKey[:]),
		base64.StdEncoding.EncodeToString(serverKey),
	), nil
}
