// Package audit provides tenant-scoped append-only audit log querying with
// keyset cursor pagination (README §7.10, §9.2, ADR-008).
package audit

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Yhanko/vigia/internal/platform/database"
	"github.com/Yhanko/vigia/internal/platform/database/sqlcgen"
	"github.com/Yhanko/vigia/internal/platform/httpserver"
)

const (
	DefaultPageLimit = 50
	MaxPageLimit     = 100
)

// Entry represents a single append-only audit log record.
type Entry struct {
	ID             string
	OrganizationID string
	ActorType      string
	ActorID        string
	Action         string
	ResourceType   string
	ResourceID     string
	Result         string
	IPPrefix       string
	UserAgent      string
	RequestID      string
	ChangesJSON    []byte
	CreatedAt      time.Time
}

// Page holds a cursor-paginated slice of audit log entries.
type Page struct {
	Items      []Entry
	NextCursor string
}

// Service queries tenant-scoped audit logs inside database.WithTenantTx.
type Service struct {
	pool *pgxpool.Pool
	q    *sqlcgen.Queries
}

// NewService constructs a tenant-scoped audit Service.
func NewService(pool *pgxpool.Pool) (*Service, error) {
	if pool == nil {
		return nil, errors.New("audit: pgx pool is required")
	}
	return &Service{pool: pool, q: sqlcgen.New(pool)}, nil
}

// List returns a cursor-paginated page of audit logs for tenantID.
func (s *Service) List(ctx context.Context, tenantID database.TenantID, limit int, rawCursor string) (Page, error) {
	if limit <= 0 || limit > MaxPageLimit {
		limit = DefaultPageLimit
	}
	var cur *httpserver.Cursor
	if rawCursor != "" {
		decoded, err := httpserver.DecodeCursor(rawCursor)
		if err != nil {
			return Page{}, err
		}
		cur = &decoded
	}

	var orgUUID pgtype.UUID
	if err := orgUUID.Scan(tenantID.String()); err != nil {
		return Page{}, fmt.Errorf("audit: parse tenant uuid: %w", err)
	}

	fetchLimit := int32(limit + 1) //nolint:gosec // bounded by MaxPageLimit+1
	var rows []sqlcgen.AuditLog

	err := database.WithTenantTx(ctx, s.pool, tenantID, func(tx pgx.Tx) error {
		qtx := s.q.WithTx(tx)
		var qErr error
		if cur == nil {
			rows, qErr = qtx.ListTenantAuditLogsFirstPage(ctx, sqlcgen.ListTenantAuditLogsFirstPageParams{
				OrganizationID: orgUUID,
				PageLimit:      fetchLimit,
			})
		} else {
			var curUUID pgtype.UUID
			if err := curUUID.Scan(cur.ID); err != nil {
				return httpserver.ErrInvalidCursor
			}
			rows, qErr = qtx.ListTenantAuditLogsAfterCursor(ctx, sqlcgen.ListTenantAuditLogsAfterCursorParams{
				OrganizationID:  orgUUID,
				CursorCreatedAt: pgtype.Timestamptz{Time: cur.CreatedAt.UTC(), Valid: true},
				CursorID:        curUUID,
				PageLimit:       fetchLimit,
			})
		}
		return qErr
	})
	if err != nil {
		return Page{}, fmt.Errorf("audit: list logs: %w", err)
	}

	hasMore := len(rows) > limit
	if hasMore {
		rows = rows[:limit]
	}

	items := make([]Entry, 0, len(rows))
	for _, r := range rows {
		e := Entry{
			ID:             r.ID.String(),
			OrganizationID: tenantID.String(),
			ActorType:      r.ActorType,
			Action:         r.Action,
			ResourceType:   r.ResourceType,
			Result:         r.Result,
			RequestID:      r.RequestID,
			ChangesJSON:    r.Changes,
			CreatedAt:      r.CreatedAt.Time.UTC(),
		}
		if r.ActorID.Valid {
			e.ActorID = r.ActorID.String()
		}
		if r.ResourceID != nil {
			e.ResourceID = *r.ResourceID
		}
		if r.IpPrefix != nil {
			e.IPPrefix = *r.IpPrefix
		}
		if r.UserAgent != nil {
			e.UserAgent = *r.UserAgent
		}
		items = append(items, e)
	}

	var nextCursor string
	if hasMore && len(items) > 0 {
		last := items[len(items)-1]
		nextCursor = httpserver.EncodeCursor(httpserver.Cursor{
			CreatedAt: last.CreatedAt,
			ID:        last.ID,
		})
	}
	return Page{Items: items, NextCursor: nextCursor}, nil
}
