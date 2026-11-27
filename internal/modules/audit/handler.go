package audit

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/netip"

	"github.com/Yhanko/vigia/internal/api"
	"github.com/Yhanko/vigia/internal/modules/organizations"
	"github.com/Yhanko/vigia/internal/platform/database"
	"github.com/Yhanko/vigia/internal/platform/httpserver"
)

// Authorizer checks tenant RBAC permission before querying audit logs.
type Authorizer interface {
	Authorize(ctx context.Context, tenantID database.TenantID, actor organizations.Actor, perm organizations.Permission) (string, error)
}

// Handler implements GET /api/v1/organizations/{orgId}/audit-logs.
type Handler struct {
	svc            *Service
	authz          Authorizer
	trustedProxies []netip.Prefix
	logger         *slog.Logger
}

// NewHandler constructs an audit HTTP Handler.
func NewHandler(svc *Service, authz Authorizer, trustedProxies []netip.Prefix, logger *slog.Logger) (*Handler, error) {
	if svc == nil {
		return nil, errors.New("audit: service is required")
	}
	if authz == nil {
		return nil, errors.New("audit: authorizer is required")
	}
	return &Handler{svc: svc, authz: authz, trustedProxies: trustedProxies, logger: logger}, nil
}

func (h *Handler) ListOrganizationAuditLogs(w http.ResponseWriter, r *http.Request, orgId api.OrgIDPath, params api.ListOrganizationAuditLogsParams) {
	actor, ok := organizations.ActorFromRequest(r, h.trustedProxies)
	if !ok {
		httpserver.WriteError(w, r, http.StatusUnauthorized, "UNAUTHENTICATED", "Authentication is required.")
		return
	}
	tid, err := database.ParseTenantID(orgId)
	if err != nil {
		httpserver.WriteError(w, r, http.StatusBadRequest, "VALIDATION_FAILED", "Invalid organization ID.")
		return
	}
	if _, err := h.authz.Authorize(r.Context(), tid, actor, organizations.PermAuditRead); err != nil {
		switch {
		case errors.Is(err, organizations.ErrNotFound):
			httpserver.WriteError(w, r, http.StatusNotFound, "RESOURCE_NOT_FOUND", "The requested resource was not found.")
		case errors.Is(err, organizations.ErrMFASetupRequired):
			httpserver.WriteError(w, r, http.StatusForbidden, "MFA_SETUP_REQUIRED", "Multi-factor authentication setup is required for privileged roles.")
		case errors.Is(err, organizations.ErrForbidden):
			httpserver.WriteError(w, r, http.StatusForbidden, "FORBIDDEN", "You do not have permission to view audit logs.")
		default:
			if h.logger != nil {
				h.logger.Error("audit authorize error", slog.Any("error", err))
			}
			httpserver.WriteError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "An internal error occurred.")
		}
		return
	}

	limit := DefaultPageLimit
	if params.Limit != nil {
		limit = *params.Limit
	}
	cursor := ""
	if params.Cursor != nil {
		cursor = *params.Cursor
	}

	page, err := h.svc.List(r.Context(), tid, limit, cursor)
	if err != nil {
		if errors.Is(err, httpserver.ErrInvalidCursor) {
			httpserver.WriteError(w, r, http.StatusBadRequest, "VALIDATION_FAILED", "Invalid pagination cursor.")
			return
		}
		if h.logger != nil {
			h.logger.Error("audit list error", slog.Any("error", err))
		}
		httpserver.WriteError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "An internal error occurred.")
		return
	}

	items := make([]api.AuditLogEntryResponse, 0, len(page.Items))
	for _, e := range page.Items {
		entry := api.AuditLogEntryResponse{
			Id:             e.ID,
			OrganizationId: e.OrganizationID,
			ActorType:      e.ActorType,
			Action:         e.Action,
			ResourceType:   e.ResourceType,
			Result:         e.Result,
			RequestId:      e.RequestID,
			CreatedAt:      e.CreatedAt,
		}
		if e.ActorID != "" {
			v := e.ActorID
			entry.ActorId = &v
		}
		if e.ResourceID != "" {
			v := e.ResourceID
			entry.ResourceId = &v
		}
		if e.IPPrefix != "" {
			v := e.IPPrefix
			entry.IpPrefix = &v
		}
		if e.UserAgent != "" {
			v := e.UserAgent
			entry.UserAgent = &v
		}
		if len(e.ChangesJSON) > 0 {
			var m map[string]any
			if json.Unmarshal(e.ChangesJSON, &m) == nil {
				entry.Changes = &m
			}
		}
		items = append(items, entry)
	}

	resp := api.AuditLogPageResponse{Items: items}
	if page.NextCursor != "" {
		nc := page.NextCursor
		resp.NextCursor = &nc
	}
	httpserver.WriteJSON(w, http.StatusOK, resp)
}
