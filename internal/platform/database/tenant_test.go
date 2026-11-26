package database

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"
)

func TestParseTenantID(t *testing.T) {
	t.Run("normalizes uppercase UUID to lowercase", func(t *testing.T) {
		id, err := ParseTenantID("  AAAA1111-1111-4111-8111-111111111111 ")
		if err != nil {
			t.Fatalf("ParseTenantID() error = %v", err)
		}
		if id.String() != "aaaa1111-1111-4111-8111-111111111111" || !id.IsValid() {
			t.Fatalf("unexpected TenantID: %q (valid=%v)", id.String(), id.IsValid())
		}
	})

	for _, raw := range []string{
		"",
		"   ",
		"not-a-uuid",
		"00000000-0000-0000-0000-000000000000",
		"00000000-0000-0000-0000-000000000000 ",
		"11111111-1111-4111-8111-11111111111g",
	} {
		t.Run("rejects "+raw, func(t *testing.T) {
			if _, err := ParseTenantID(raw); !errors.Is(err, ErrInvalidTenantID) {
				t.Fatalf("ParseTenantID(%q) err = %v, want ErrInvalidTenantID", raw, err)
			}
		})
	}
}

func TestWithTenantTxRejectsInvalidTenantBeforeOpeningTx(t *testing.T) {
	// Passing nil pool proves validation happens BEFORE touching the database pool.
	for _, id := range []TenantID{
		{},
		{value: nilUUID},
		{value: "invalid"},
	} {
		err := WithTenantTx(context.Background(), nil, id, func(pgx.Tx) error {
			t.Fatal("callback must not be invoked for invalid TenantID")
			return nil
		})
		if !errors.Is(err, ErrInvalidTenantID) {
			t.Fatalf("WithTenantTx(%q) err = %v, want ErrInvalidTenantID", id.String(), err)
		}
	}
}
