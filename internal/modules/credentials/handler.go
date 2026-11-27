package credentials

import (
	"errors"
	"log/slog"
	"net/http"
	"net/netip"
	"time"

	"github.com/Yhanko/vigia/internal/api"
	"github.com/Yhanko/vigia/internal/modules/organizations"
	"github.com/Yhanko/vigia/internal/platform/database"
	"github.com/Yhanko/vigia/internal/platform/httpserver"
)

// Handler implements /api/v1/organizations/{orgId}/projects/{projectId}/credentials
// and /api/v1/organizations/{orgId}/credentials/{credentialId}/{revoke,rotate}.
type Handler struct {
	svc            *Service
	trustedProxies []netip.Prefix
	logger         *slog.Logger
}

// NewHandler constructs a credentials HTTP Handler.
func NewHandler(svc *Service, trustedProxies []netip.Prefix, logger *slog.Logger) (*Handler, error) {
	if svc == nil {
		return nil, errors.New("credentials: service is required")
	}
	return &Handler{svc: svc, trustedProxies: trustedProxies, logger: logger}, nil
}

func (h *Handler) ListProjectCredentials(w http.ResponseWriter, r *http.Request, orgId api.OrgIDPath, projectId api.ProjectIDPath) {
	actor, tid, ok := h.actorAndTenant(w, r, orgId)
	if !ok {
		return
	}
	creds, err := h.svc.List(r.Context(), tid, actor, projectId)
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	items := make([]api.CredentialResponse, 0, len(creds))
	for _, c := range creds {
		items = append(items, toCredentialResponse(c))
	}
	httpserver.WriteJSON(w, http.StatusOK, api.CredentialListResponse{Items: items})
}

func (h *Handler) CreateProjectCredential(w http.ResponseWriter, r *http.Request, orgId api.OrgIDPath, projectId api.ProjectIDPath, _ api.CreateProjectCredentialParams) {
	actor, tid, ok := h.actorAndTenant(w, r, orgId)
	if !ok {
		return
	}
	var req api.CreateCredentialRequest
	if !httpserver.DecodeJSON(w, r, &req) {
		return
	}
	in := CreateInput{
		ProjectID: projectId,
		Kind:      string(req.Kind),
		Name:      req.Name,
		ExpiresAt: req.ExpiresAt,
	}
	if req.EnvironmentId != nil {
		in.EnvironmentID = *req.EnvironmentId
	}
	if req.Scopes != nil {
		in.Scopes = *req.Scopes
	}
	if req.AllowedOrigins != nil {
		in.AllowedOrigins = *req.AllowedOrigins
	}

	created, err := h.svc.Create(r.Context(), tid, actor, in)
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	httpserver.WriteJSON(w, http.StatusCreated, toCreatedCredentialResponse(created))
}

func (h *Handler) RevokeOrganizationCredential(w http.ResponseWriter, r *http.Request, orgId api.OrgIDPath, credentialId api.CredentialIDPath, _ api.RevokeOrganizationCredentialParams) {
	actor, tid, ok := h.actorAndTenant(w, r, orgId)
	if !ok {
		return
	}
	if err := h.svc.Revoke(r.Context(), tid, actor, credentialId); err != nil {
		h.writeError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) RotateOrganizationCredential(w http.ResponseWriter, r *http.Request, orgId api.OrgIDPath, credentialId api.CredentialIDPath, _ api.RotateOrganizationCredentialParams) {
	actor, tid, ok := h.actorAndTenant(w, r, orgId)
	if !ok {
		return
	}
	var overlap time.Duration
	if r.Body != nil && r.ContentLength != 0 {
		var req api.RotateCredentialRequest
		if !httpserver.DecodeJSON(w, r, &req) {
			return
		}
		if req.OverlapSeconds != nil && *req.OverlapSeconds > 0 {
			overlap = time.Duration(*req.OverlapSeconds) * time.Second
		}
	}
	created, err := h.svc.Rotate(r.Context(), tid, actor, credentialId, overlap)
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	httpserver.WriteJSON(w, http.StatusCreated, toCreatedCredentialResponse(created))
}

func (h *Handler) actorAndTenant(w http.ResponseWriter, r *http.Request, orgID string) (organizations.Actor, database.TenantID, bool) {
	actor, ok := organizations.ActorFromRequest(r, h.trustedProxies)
	if !ok {
		httpserver.WriteError(w, r, http.StatusUnauthorized, "UNAUTHENTICATED", "Authentication is required.")
		return organizations.Actor{}, database.TenantID{}, false
	}
	tid, err := database.ParseTenantID(orgID)
	if err != nil {
		httpserver.WriteError(w, r, http.StatusBadRequest, "VALIDATION_FAILED", "Invalid organization ID.")
		return organizations.Actor{}, database.TenantID{}, false
	}
	return actor, tid, true
}

func (h *Handler) writeError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, ErrInvalidInput):
		httpserver.WriteError(w, r, http.StatusBadRequest, "VALIDATION_FAILED", "Invalid credential parameters.")
	case errors.Is(err, ErrReauthRequired):
		httpserver.WriteError(w, r, http.StatusUnauthorized, "REAUTH_REQUIRED", "Recent authentication is required for this operation.")
	case errors.Is(err, ErrMFARequired):
		httpserver.WriteError(w, r, http.StatusForbidden, "MFA_SETUP_REQUIRED", "Multi-factor authentication setup is required for privileged roles.")
	case errors.Is(err, ErrForbidden):
		httpserver.WriteError(w, r, http.StatusForbidden, "FORBIDDEN", "You do not have permission to manage API credentials.")
	case errors.Is(err, ErrNotFound), errors.Is(err, ErrProjectNotFound):
		httpserver.WriteError(w, r, http.StatusNotFound, "RESOURCE_NOT_FOUND", "The requested resource was not found.")
	default:
		if h.logger != nil {
			h.logger.Error("credentials handler internal error",
				slog.String("request_id", httpserver.RequestIDFromContext(r.Context())),
				slog.Any("error", err),
			)
		}
		httpserver.WriteError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "An internal error occurred.")
	}
}

func toCredentialResponse(c Credential) api.CredentialResponse {
	resp := api.CredentialResponse{
		Id:             c.ID,
		OrganizationId: c.OrganizationID,
		ProjectId:      c.ProjectID,
		Kind:           c.Kind,
		Name:           c.Name,
		Prefix:         c.Prefix,
		ExpiresAt:      c.ExpiresAt,
		LastUsedAt:     c.LastUsedAt,
		RevokedAt:      c.RevokedAt,
		CreatedBy:      c.CreatedBy,
		CreatedAt:      c.CreatedAt,
	}
	if c.EnvironmentID != "" {
		v := c.EnvironmentID
		resp.EnvironmentId = &v
	}
	if c.PublicKey != "" {
		v := c.PublicKey
		resp.PublicKey = &v
	}
	if c.DSN != "" {
		v := c.DSN
		resp.Dsn = &v
	}
	if len(c.Scopes) > 0 {
		s := c.Scopes
		resp.Scopes = &s
	}
	if len(c.AllowedOrigins) > 0 {
		o := c.AllowedOrigins
		resp.AllowedOrigins = &o
	}
	return resp
}

func toCreatedCredentialResponse(c CreatedCredential) api.CreatedCredentialResponse {
	resp := api.CreatedCredentialResponse{
		Credential: toCredentialResponse(c.Credential),
	}
	if c.Secret != "" {
		s := c.Secret
		resp.Secret = &s
	}
	return resp
}
