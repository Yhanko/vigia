package organizations

import (
	"errors"
	"log/slog"
	"net/http"
	"net/netip"
	"strings"

	"github.com/Yhanko/vigia/internal/api"
	"github.com/Yhanko/vigia/internal/modules/identity"
	"github.com/Yhanko/vigia/internal/platform/database"
	"github.com/Yhanko/vigia/internal/platform/httpserver"
)

// Handler implements the /api/v1/organizations/* and /api/v1/invitations/accept
// HTTP endpoints backed by organizations.Service.
type Handler struct {
	svc            *Service
	trustedProxies []netip.Prefix
	logger         *slog.Logger
}

// NewHandler constructs an organizations HTTP Handler.
func NewHandler(svc *Service, trustedProxies []netip.Prefix, logger *slog.Logger) (*Handler, error) {
	if svc == nil {
		return nil, errors.New("organizations: service is required")
	}
	return &Handler{svc: svc, trustedProxies: trustedProxies, logger: logger}, nil
}

// ActorFromRequest builds an organizations.Actor from the authenticated session context.
func ActorFromRequest(r *http.Request, trustedProxies []netip.Prefix) (Actor, bool) {
	active, ok := identity.ActiveSessionFromContext(r.Context())
	if !ok {
		return Actor{}, false
	}
	var ipPrefix *string
	if ip := httpserver.ClientIP(r, trustedProxies); ip != "" {
		if p := maskIPPrefix(ip); p != "" {
			ipPrefix = &p
		}
	}
	var ua *string
	if rawUA := strings.TrimSpace(r.UserAgent()); rawUA != "" {
		ua = &rawUA
	}
	return Actor{
		UserID:     active.UserID,
		Email:      active.UserEmail,
		MFAEnabled: active.UserMFAEnabled,
		LastAuthAt: active.LastAuthAt,
		RequestID:  httpserver.RequestIDFromContext(r.Context()),
		IPPrefix:   ipPrefix,
		UserAgent:  ua,
	}, true
}

func (h *Handler) ListOrganizations(w http.ResponseWriter, r *http.Request) {
	actor, ok := ActorFromRequest(r, h.trustedProxies)
	if !ok {
		httpserver.WriteError(w, r, http.StatusUnauthorized, "UNAUTHENTICATED", "Authentication is required.")
		return
	}
	orgs, err := h.svc.ListForUser(r.Context(), actor)
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	items := make([]api.OrganizationSummary, 0, len(orgs))
	for _, o := range orgs {
		items = append(items, api.OrganizationSummary{
			OrganizationId:   o.OrganizationID,
			Name:             o.Name,
			Slug:             o.Slug,
			OrgStatus:        o.OrgStatus,
			Role:             o.Role,
			MembershipStatus: o.MembershipStatus,
		})
	}
	httpserver.WriteJSON(w, http.StatusOK, api.OrganizationSummaryListResponse{Items: items})
}

func (h *Handler) CreateOrganization(w http.ResponseWriter, r *http.Request, _ api.CreateOrganizationParams) {
	actor, ok := ActorFromRequest(r, h.trustedProxies)
	if !ok {
		httpserver.WriteError(w, r, http.StatusUnauthorized, "UNAUTHENTICATED", "Authentication is required.")
		return
	}
	var req api.CreateOrganizationRequest
	if !httpserver.DecodeJSON(w, r, &req) {
		return
	}
	org, err := h.svc.Create(r.Context(), actor, req.Name, req.Slug)
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	httpserver.WriteJSON(w, http.StatusCreated, toOrgResponse(org))
}

func (h *Handler) GetOrganization(w http.ResponseWriter, r *http.Request, orgId api.OrgIDPath) {
	actor, tid, ok := h.actorAndTenant(w, r, orgId)
	if !ok {
		return
	}
	org, err := h.svc.Get(r.Context(), tid, actor)
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	httpserver.WriteJSON(w, http.StatusOK, toOrgResponse(org))
}

func (h *Handler) UpdateOrganization(w http.ResponseWriter, r *http.Request, orgId api.OrgIDPath, _ api.UpdateOrganizationParams) {
	actor, tid, ok := h.actorAndTenant(w, r, orgId)
	if !ok {
		return
	}
	var req api.UpdateOrganizationRequest
	if !httpserver.DecodeJSON(w, r, &req) {
		return
	}
	org, err := h.svc.Update(r.Context(), tid, actor, req.Name)
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	httpserver.WriteJSON(w, http.StatusOK, toOrgResponse(org))
}

func (h *Handler) DeleteOrganization(w http.ResponseWriter, r *http.Request, orgId api.OrgIDPath, _ api.DeleteOrganizationParams) {
	actor, tid, ok := h.actorAndTenant(w, r, orgId)
	if !ok {
		return
	}
	var req api.ConfirmSlugRequest
	if !httpserver.DecodeJSON(w, r, &req) {
		return
	}
	if _, err := h.svc.ScheduleDeletion(r.Context(), tid, actor, req.ConfirmSlug); err != nil {
		h.writeError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) TransferOrganizationOwnership(w http.ResponseWriter, r *http.Request, orgId api.OrgIDPath, _ api.TransferOrganizationOwnershipParams) {
	actor, tid, ok := h.actorAndTenant(w, r, orgId)
	if !ok {
		return
	}
	var req api.TransferOwnershipRequest
	if !httpserver.DecodeJSON(w, r, &req) {
		return
	}
	if err := h.svc.TransferOwnership(r.Context(), tid, actor, req.NewOwnerUserId, req.ConfirmSlug); err != nil {
		h.writeError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) ListOrganizationMembers(w http.ResponseWriter, r *http.Request, orgId api.OrgIDPath) {
	actor, tid, ok := h.actorAndTenant(w, r, orgId)
	if !ok {
		return
	}
	members, err := h.svc.ListMembers(r.Context(), tid, actor, defaultListLimit)
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	items := make([]api.MemberResponse, 0, len(members))
	for _, m := range members {
		items = append(items, api.MemberResponse{
			Id:             m.ID,
			OrganizationId: m.OrganizationID,
			UserId:         m.UserID,
			Email:          m.Email,
			Name:           m.Name,
			Role:           m.Role,
			Status:         m.Status,
			CreatedAt:      m.CreatedAt,
		})
	}
	httpserver.WriteJSON(w, http.StatusOK, api.MemberListResponse{Items: items})
}

func (h *Handler) UpdateOrganizationMember(w http.ResponseWriter, r *http.Request, orgId api.OrgIDPath, memberId api.MemberIDPath, _ api.UpdateOrganizationMemberParams) {
	actor, tid, ok := h.actorAndTenant(w, r, orgId)
	if !ok {
		return
	}
	var req api.UpdateMemberRoleRequest
	if !httpserver.DecodeJSON(w, r, &req) {
		return
	}
	if _, err := h.svc.UpdateMemberRole(r.Context(), tid, actor, memberId, string(req.Role)); err != nil {
		h.writeError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) RemoveOrganizationMember(w http.ResponseWriter, r *http.Request, orgId api.OrgIDPath, memberId api.MemberIDPath, _ api.RemoveOrganizationMemberParams) {
	actor, tid, ok := h.actorAndTenant(w, r, orgId)
	if !ok {
		return
	}
	if err := h.svc.RemoveMember(r.Context(), tid, actor, memberId); err != nil {
		h.writeError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) ListOrganizationInvitations(w http.ResponseWriter, r *http.Request, orgId api.OrgIDPath) {
	actor, tid, ok := h.actorAndTenant(w, r, orgId)
	if !ok {
		return
	}
	invs, err := h.svc.ListInvitations(r.Context(), tid, actor)
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	items := make([]api.InvitationResponse, 0, len(invs))
	for _, inv := range invs {
		items = append(items, toInvitationResponse(inv))
	}
	httpserver.WriteJSON(w, http.StatusOK, api.InvitationListResponse{Items: items})
}

func (h *Handler) CreateOrganizationInvitation(w http.ResponseWriter, r *http.Request, orgId api.OrgIDPath, _ api.CreateOrganizationInvitationParams) {
	actor, tid, ok := h.actorAndTenant(w, r, orgId)
	if !ok {
		return
	}
	var req api.CreateInvitationRequest
	if !httpserver.DecodeJSON(w, r, &req) {
		return
	}
	inv, _, err := h.svc.CreateInvitation(r.Context(), tid, actor, req.Email, string(req.Role))
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	httpserver.WriteJSON(w, http.StatusCreated, toInvitationResponse(inv))
}

func (h *Handler) RevokeOrganizationInvitation(w http.ResponseWriter, r *http.Request, orgId api.OrgIDPath, invitationId api.InvitationIDPath, _ api.RevokeOrganizationInvitationParams) {
	actor, tid, ok := h.actorAndTenant(w, r, orgId)
	if !ok {
		return
	}
	if err := h.svc.RevokeInvitation(r.Context(), tid, actor, invitationId); err != nil {
		h.writeError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) AcceptOrganizationInvitation(w http.ResponseWriter, r *http.Request, _ api.AcceptOrganizationInvitationParams) {
	actor, ok := ActorFromRequest(r, h.trustedProxies)
	if !ok {
		httpserver.WriteError(w, r, http.StatusUnauthorized, "UNAUTHENTICATED", "Authentication is required.")
		return
	}
	var req api.AcceptInvitationRequest
	if !httpserver.DecodeJSON(w, r, &req) {
		return
	}
	mem, err := h.svc.AcceptInvitation(r.Context(), actor, req.Token)
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	httpserver.WriteJSON(w, http.StatusOK, api.AcceptInvitationResponse{
		OrganizationId: mem.OrganizationID,
	})
}

func (h *Handler) ListOrganizationTeams(w http.ResponseWriter, r *http.Request, orgId api.OrgIDPath) {
	actor, tid, ok := h.actorAndTenant(w, r, orgId)
	if !ok {
		return
	}
	teams, err := h.svc.ListTeams(r.Context(), tid, actor, defaultListLimit)
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	items := make([]api.TeamResponse, 0, len(teams))
	for _, t := range teams {
		items = append(items, toTeamResponse(t))
	}
	httpserver.WriteJSON(w, http.StatusOK, api.TeamListResponse{Items: items})
}

func (h *Handler) CreateOrganizationTeam(w http.ResponseWriter, r *http.Request, orgId api.OrgIDPath, _ api.CreateOrganizationTeamParams) {
	actor, tid, ok := h.actorAndTenant(w, r, orgId)
	if !ok {
		return
	}
	var req api.CreateTeamRequest
	if !httpserver.DecodeJSON(w, r, &req) {
		return
	}
	team, err := h.svc.CreateTeam(r.Context(), tid, actor, req.Name, req.Slug)
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	httpserver.WriteJSON(w, http.StatusCreated, toTeamResponse(team))
}

func (h *Handler) DeleteOrganizationTeam(w http.ResponseWriter, r *http.Request, orgId api.OrgIDPath, teamId api.TeamIDPath, _ api.DeleteOrganizationTeamParams) {
	actor, tid, ok := h.actorAndTenant(w, r, orgId)
	if !ok {
		return
	}
	if err := h.svc.DeleteTeam(r.Context(), tid, actor, teamId); err != nil {
		h.writeError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) actorAndTenant(w http.ResponseWriter, r *http.Request, orgID string) (Actor, database.TenantID, bool) {
	actor, ok := ActorFromRequest(r, h.trustedProxies)
	if !ok {
		httpserver.WriteError(w, r, http.StatusUnauthorized, "UNAUTHENTICATED", "Authentication is required.")
		return Actor{}, database.TenantID{}, false
	}
	tid, err := database.ParseTenantID(orgID)
	if err != nil {
		httpserver.WriteError(w, r, http.StatusBadRequest, "VALIDATION_FAILED", "Invalid organization ID.")
		return Actor{}, database.TenantID{}, false
	}
	return actor, tid, true
}

func (h *Handler) writeError(w http.ResponseWriter, r *http.Request, err error) {
	var valErr *ValidationError
	if errors.As(err, &valErr) {
		httpserver.WriteError(w, r, http.StatusBadRequest, "VALIDATION_FAILED", "One or more fields are invalid.",
			httpserver.ErrorDetail{Field: valErr.Field, Message: valErr.Message})
		return
	}
	switch {
	case errors.Is(err, ErrReauthRequired):
		httpserver.WriteError(w, r, http.StatusUnauthorized, "REAUTH_REQUIRED", "Recent authentication is required for this operation.")
	case errors.Is(err, ErrMFASetupRequired):
		httpserver.WriteError(w, r, http.StatusForbidden, "MFA_SETUP_REQUIRED", "Multi-factor authentication setup is required for privileged roles.")
	case errors.Is(err, ErrProtectedResource):
		httpserver.WriteError(w, r, http.StatusForbidden, "PROTECTED_RESOURCE", "This resource is protected and cannot be deleted.")
	case errors.Is(err, ErrForbidden):
		httpserver.WriteError(w, r, http.StatusForbidden, "FORBIDDEN", "You do not have permission to perform this action.")
	case errors.Is(err, ErrNotFound):
		httpserver.WriteError(w, r, http.StatusNotFound, "RESOURCE_NOT_FOUND", "The requested resource was not found.")
	case errors.Is(err, ErrConflict):
		httpserver.WriteError(w, r, http.StatusConflict, "RESOURCE_CONFLICT", "The requested resource already exists or conflicts with current state.")
	default:
		if h.logger != nil {
			h.logger.Error("organizations handler internal error",
				slog.String("request_id", httpserver.RequestIDFromContext(r.Context())),
				slog.Any("error", err),
			)
		}
		httpserver.WriteError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "An internal error occurred.")
	}
}

func toOrgResponse(o Organization) api.OrganizationResponse {
	return api.OrganizationResponse{
		Id:         o.ID,
		Name:       o.Name,
		Slug:       o.Slug,
		Status:     o.Status,
		PurgeAfter: o.PurgeAfter,
		CreatedAt:  o.CreatedAt,
	}
}

func toInvitationResponse(inv Invitation) api.InvitationResponse {
	return api.InvitationResponse{
		Id:             inv.ID,
		OrganizationId: inv.OrganizationID,
		Email:          inv.Email,
		Role:           inv.Role,
		InvitedBy:      inv.InvitedBy,
		ExpiresAt:      inv.ExpiresAt,
		CreatedAt:      inv.CreatedAt,
	}
}

func toTeamResponse(t Team) api.TeamResponse {
	return api.TeamResponse{
		Id:             t.ID,
		OrganizationId: t.OrganizationID,
		Name:           t.Name,
		Slug:           t.Slug,
		CreatedAt:      t.CreatedAt,
	}
}

func maskIPPrefix(rawIP string) string {
	addr, err := netip.ParseAddr(strings.TrimSpace(rawIP))
	if err != nil {
		return ""
	}
	addr = addr.Unmap()
	bits := 24
	if addr.Is6() {
		bits = 48
	}
	p, err := addr.Prefix(bits)
	if err != nil {
		return ""
	}
	return p.String()
}
