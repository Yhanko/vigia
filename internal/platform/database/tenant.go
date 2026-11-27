package database

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Yhanko/vigia/internal/platform/ids"
)

const nilUUID = "00000000-0000-0000-0000-000000000000"

// ErrInvalidTenantID is returned when a TenantID is empty, malformed, or the
// nil UUID (00000000-0000-0000-0000-000000000000).
var ErrInvalidTenantID = errors.New("database: invalid tenant id")

// TenantID is a validated, lowercase canonical UUID identifying an
// organization. Repositories for tenant-scoped tables must require TenantID
// explicitly in their method signatures (README §11.1, ADR-008).
type TenantID struct {
	value string
}

// ParseTenantID validates raw as a non-nil canonical UUID and normalizes it to lowercase.
func ParseTenantID(raw string) (TenantID, error) {
	v, err := ids.NormalizeUUID(strings.TrimSpace(raw))
	if err != nil || v == nilUUID {
		return TenantID{}, fmt.Errorf("%w: must be a non-nil canonical UUID", ErrInvalidTenantID)
	}
	return TenantID{value: v}, nil
}

// String returns the canonical lowercase UUID string.
func (t TenantID) String() string { return t.value }

// IsValid reports whether t holds a valid non-nil UUID.
func (t TenantID) IsValid() bool {
	return ids.IsCanonicalUUID(t.value) && t.value != nilUUID
}

// WithTenantTx runs fn inside a PostgreSQL transaction scoped to tenantID via
// SELECT set_config('app.organization_id', $1, true) (ADR-008 §3.2).
// It rejects empty or nil TenantIDs BEFORE opening a transaction.
func WithTenantTx(ctx context.Context, pool *pgxpool.Pool, tenantID TenantID, fn func(pgx.Tx) error) error {
	if !tenantID.IsValid() {
		return fmt.Errorf("%w: cannot open tenant transaction without valid tenant id", ErrInvalidTenantID)
	}
	return WithTx(ctx, pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, "SELECT set_config('app.organization_id', $1, true)", tenantID.value); err != nil {
			return fmt.Errorf("set tenant rls context: %w", err)
		}
		return fn(tx)
	})
}
