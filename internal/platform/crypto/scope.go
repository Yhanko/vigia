package crypto

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/Yhanko/vigia/internal/platform/ids"
)

// OwnerType values allowed in Scope (ADR-015 §3.2).
const (
	OwnerTypeOrg  = "org"
	OwnerTypeUser = "user"
)

// ErrInvalidScope is returned when an encryption Scope is missing required
// fields, has an unsupported OwnerType, or carries a non-UUID RecordID.
var ErrInvalidScope = errors.New("crypto: invalid encryption scope")

// Scope binds an encrypted envelope to its exact owner, table, column, and
// record via AES-GCM Additional Authenticated Data (AAD), preventing
// ciphertext swapping across tenants, columns, or records (ADR-015 §3.2).
type Scope struct {
	OwnerType string // "org" or "user"
	OwnerID   string // organization_id or user_id
	Table     string // database table name
	Column    string // encrypted column name
	RecordID  string // UUID of the row (generated before INSERT)
}

// Validate checks that Scope satisfies all ADR-015 invariants before any
// cryptographic operation is attempted.
func (s Scope) Validate() error {
	if s.OwnerType != OwnerTypeOrg && s.OwnerType != OwnerTypeUser {
		return fmt.Errorf("%w: owner_type must be %q or %q", ErrInvalidScope, OwnerTypeOrg, OwnerTypeUser)
	}
	if !ids.IsCanonicalUUID(s.OwnerID) {
		return fmt.Errorf("%w: owner_id must be a valid UUID", ErrInvalidScope)
	}
	if strings.TrimSpace(s.Table) == "" {
		return fmt.Errorf("%w: table is required", ErrInvalidScope)
	}
	if strings.TrimSpace(s.Column) == "" {
		return fmt.Errorf("%w: column is required", ErrInvalidScope)
	}
	if !ids.IsCanonicalUUID(s.RecordID) {
		return fmt.Errorf("%w: record_id must be a valid UUID", ErrInvalidScope)
	}
	return nil
}

// encodeAAD produces a deterministic, length-prefixed AAD byte slice so field
// boundaries can never be confused. OwnerID and RecordID are normalized to
// lowercase so canonical UUID casing differences never break decryption.
func (s Scope) encodeAAD() []byte {
	var b strings.Builder
	b.WriteString("v1")
	for _, field := range []string{
		s.OwnerType,
		strings.ToLower(s.OwnerID),
		s.Table,
		s.Column,
		strings.ToLower(s.RecordID),
	} {
		b.WriteByte('|')
		b.WriteString(strconv.Itoa(len(field)))
		b.WriteByte(':')
		b.WriteString(field)
	}
	return []byte(b.String())
}
