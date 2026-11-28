package projects

import (
	"errors"
	"log/slog"
	"net/http"
	"net/netip"

	"github.com/Yhanko/vigia/internal/api"
	"github.com/Yhanko/vigia/internal/modules/organizations"
	"github.com/Yhanko/vigia/internal/platform/database"
	"github.com/Yhanko/vigia/internal/platform/httpserver"
)

// Handler implements /api/v1/organizations/{orgId}/projects/* and environments endpoints.
type Handler struct {
	svc            *Service
	trustedProxies []netip.Prefix
	logger         *slog.Logger
}

// NewHandler constructs a projects HTTP Handler.
func NewHandler(svc *Service, trustedProxies []netip.Prefix, logger *slog.Logger) (*Handler, error) {
	if svc == nil {
		return nil, errors.New("projects: service is required")
	}
	return &Handler{svc: svc, trustedProxies: trustedProxies, logger: logger}, nil
}

func (h *Handler) ListOrganizationProjects(w http.ResponseWriter, r *http.Request, orgId api.OrgIDPath, params api.ListOrganizationProjectsParams) {
	actor, tid, ok := h.actorAndTenant(w, r, orgId)
	if !ok {
		return
	}
	limit := defaultListLimit
	if params.Limit != nil {
		limit = *params.Limit
	}
	list, err := h.svc.ListProjects(r.Context(), tid, actor, limit)
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	items := make([]api.ProjectResponse, 0, len(list))
	for _, p := range list {
		items = append(items, toProjectResponse(p))
	}
	httpserver.WriteJSON(w, http.StatusOK, api.ProjectListResponse{Items: items})
}

func (h *Handler) CreateOrganizationProject(w http.ResponseWriter, r *http.Request, orgId api.OrgIDPath, _ api.CreateOrganizationProjectParams) {
	actor, tid, ok := h.actorAndTenant(w, r, orgId)
	if !ok {
		return
	}
	var req api.CreateProjectRequest
	if !httpserver.DecodeJSON(w, r, &req) {
		return
	}
	platform := ""
	if req.Platform != nil {
		platform = *req.Platform
	}
	p, err := h.svc.CreateProject(r.Context(), tid, actor, req.Name, req.Slug, platform)
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	httpserver.WriteJSON(w, http.StatusCreated, toProjectResponse(p))
}

func (h *Handler) GetOrganizationProject(w http.ResponseWriter, r *http.Request, orgId api.OrgIDPath, projectId api.ProjectIDPath) {
	actor, tid, ok := h.actorAndTenant(w, r, orgId)
	if !ok {
		return
	}
	p, err := h.svc.GetProject(r.Context(), tid, actor, projectId)
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	httpserver.WriteJSON(w, http.StatusOK, toProjectResponse(p))
}

func (h *Handler) UpdateOrganizationProject(w http.ResponseWriter, r *http.Request, orgId api.OrgIDPath, projectId api.ProjectIDPath, _ api.UpdateOrganizationProjectParams) {
	actor, tid, ok := h.actorAndTenant(w, r, orgId)
	if !ok {
		return
	}
	var req api.UpdateProjectRequest
	if !httpserver.DecodeJSON(w, r, &req) {
		return
	}
	p, err := h.svc.UpdateProject(r.Context(), tid, actor, projectId, req.Name, req.Platform)
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	httpserver.WriteJSON(w, http.StatusOK, toProjectResponse(p))
}

func (h *Handler) DeleteOrganizationProject(w http.ResponseWriter, r *http.Request, orgId api.OrgIDPath, projectId api.ProjectIDPath, _ api.DeleteOrganizationProjectParams) {
	actor, tid, ok := h.actorAndTenant(w, r, orgId)
	if !ok {
		return
	}
	var req api.ConfirmSlugRequest
	if !httpserver.DecodeJSON(w, r, &req) {
		return
	}
	if err := h.svc.DeleteProject(r.Context(), tid, actor, projectId, req.ConfirmSlug); err != nil {
		h.writeError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) ListProjectEnvironments(w http.ResponseWriter, r *http.Request, orgId api.OrgIDPath, projectId api.ProjectIDPath) {
	actor, tid, ok := h.actorAndTenant(w, r, orgId)
	if !ok {
		return
	}
	envs, err := h.svc.ListEnvironments(r.Context(), tid, actor, projectId)
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	items := make([]api.EnvironmentResponse, 0, len(envs))
	for _, e := range envs {
		items = append(items, toEnvironmentResponse(e))
	}
	httpserver.WriteJSON(w, http.StatusOK, api.EnvironmentListResponse{Items: items})
}

func (h *Handler) CreateProjectEnvironment(w http.ResponseWriter, r *http.Request, orgId api.OrgIDPath, projectId api.ProjectIDPath, _ api.CreateProjectEnvironmentParams) {
	actor, tid, ok := h.actorAndTenant(w, r, orgId)
	if !ok {
		return
	}
	var req api.CreateEnvironmentRequest
	if !httpserver.DecodeJSON(w, r, &req) {
		return
	}
	isProtected := false
	if req.IsProtected != nil {
		isProtected = *req.IsProtected
	}
	env, err := h.svc.CreateEnvironment(r.Context(), tid, actor, projectId, req.Name, isProtected)
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	httpserver.WriteJSON(w, http.StatusCreated, toEnvironmentResponse(env))
}

func (h *Handler) DeleteProjectEnvironment(w http.ResponseWriter, r *http.Request, orgId api.OrgIDPath, environmentId api.EnvironmentIDPath, _ api.DeleteProjectEnvironmentParams) {
	actor, tid, ok := h.actorAndTenant(w, r, orgId)
	if !ok {
		return
	}
	if err := h.svc.DeleteEnvironment(r.Context(), tid, actor, environmentId); err != nil {
		h.writeError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
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
	case errors.Is(err, ErrInvalidInput), errors.Is(err, ErrSlugConfirmation):
		httpserver.WriteError(w, r, http.StatusBadRequest, "VALIDATION_FAILED", err.Error())
	case errors.Is(err, ErrReauthRequired):
		httpserver.WriteError(w, r, http.StatusUnauthorized, "REAUTH_REQUIRED", "Recent authentication is required for this operation.")
	case errors.Is(err, ErrMFARequired):
		httpserver.WriteError(w, r, http.StatusForbidden, "MFA_SETUP_REQUIRED", "Multi-factor authentication setup is required for privileged roles.")
	case errors.Is(err, ErrProtectedResource):
		httpserver.WriteError(w, r, http.StatusForbidden, "PROTECTED_RESOURCE", "Protected environments cannot be deleted.")
	case errors.Is(err, ErrForbidden):
		httpserver.WriteError(w, r, http.StatusForbidden, "FORBIDDEN", "You do not have permission to perform this action.")
	case errors.Is(err, ErrProjectNotFound), errors.Is(err, ErrEnvironmentNotFound):
		httpserver.WriteError(w, r, http.StatusNotFound, "RESOURCE_NOT_FOUND", "The requested resource was not found.")
	case errors.Is(err, ErrSlugTaken), errors.Is(err, ErrEnvironmentExists):
		httpserver.WriteError(w, r, http.StatusConflict, "RESOURCE_CONFLICT", "The requested resource already exists.")
	case errors.Is(err, ErrQuotaExceeded):
		httpserver.WriteError(w, r, http.StatusTooManyRequests, "QUOTA_EXCEEDED", "Organization project limit reached for your plan.")
	default:
		if h.logger != nil {
			h.logger.Error("projects handler internal error",
				slog.String("request_id", httpserver.RequestIDFromContext(r.Context())),
				slog.Any("error", err),
			)
		}
		httpserver.WriteError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "An internal error occurred.")
	}
}

func toProjectResponse(p Project) api.ProjectResponse {
	return api.ProjectResponse{
		Id:             p.ID,
		OrganizationId: p.OrganizationID,
		PublicId:       p.PublicID,
		Name:           p.Name,
		Slug:           p.Slug,
		Platform:       p.Platform,
		Status:         p.Status,
		DeletedAt:      p.DeletedAt,
		CreatedAt:      p.CreatedAt,
		UpdatedAt:      p.UpdatedAt,
	}
}

func toEnvironmentResponse(e Environment) api.EnvironmentResponse {
	return api.EnvironmentResponse{
		Id:             e.ID,
		OrganizationId: e.OrganizationID,
		ProjectId:      e.ProjectID,
		Name:           e.Name,
		IsProtected:    e.IsProtected,
		CreatedAt:      e.CreatedAt,
		UpdatedAt:      e.UpdatedAt,
	}
}
