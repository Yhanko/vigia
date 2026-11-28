package quotas

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

// Handler implements /api/v1/organizations/{orgId}/usage and /quotas endpoints.
type Handler struct {
	svc            *Service
	trustedProxies []netip.Prefix
	logger         *slog.Logger
}

// NewHandler constructs a quotas HTTP Handler.
func NewHandler(svc *Service, trustedProxies []netip.Prefix, logger *slog.Logger) (*Handler, error) {
	if svc == nil {
		return nil, errors.New("quotas: service is required")
	}
	return &Handler{svc: svc, trustedProxies: trustedProxies, logger: logger}, nil
}

// GetOrganizationUsage serves GET /api/v1/organizations/{orgId}/usage.
func (h *Handler) GetOrganizationUsage(w http.ResponseWriter, r *http.Request, orgId api.OrgIDPath) {
	actor, tid, ok := h.actorAndTenant(w, r, orgId)
	if !ok {
		return
	}
	u, err := h.svc.GetUsage(r.Context(), tid, actor)
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	httpserver.WriteJSON(w, http.StatusOK, api.OrganizationUsageResponse{
		PlanId:                  u.PlanID,
		DayStart:                u.DayStart,
		MonthStart:              u.MonthStart,
		EventsUsedToday:         u.EventsUsedToday,
		EventsLimitDay:          u.EventsLimitDay,
		EventsUsedMonth:         u.EventsUsedMonth,
		EventsLimitMonth:        u.EventsLimitMonth,
		WhatsappUsedMonth:       u.WhatsAppUsedMonth,
		WhatsappLimitMonth:      int(u.WhatsAppLimitMonth),
		ActiveProjects:          int(u.ActiveProjects),
		MaxProjects:             int(u.MaxProjects),
		ActiveMembersAndInvites: int(u.ActiveMembersAndInvites),
		MaxMembers:              int(u.MaxMembers),
	})
}

// GetOrganizationQuotas serves GET /api/v1/organizations/{orgId}/quotas.
func (h *Handler) GetOrganizationQuotas(w http.ResponseWriter, r *http.Request, orgId api.OrgIDPath) {
	actor, tid, ok := h.actorAndTenant(w, r, orgId)
	if !ok {
		return
	}
	p, err := h.svc.GetQuotas(r.Context(), tid, actor)
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	httpserver.WriteJSON(w, http.StatusOK, api.OrganizationQuotasResponse{
		PlanId:                  p.ID,
		PlanName:                p.Name,
		MaxEventsPerMonth:       p.MaxEventsPerMonth,
		MaxEventsPerDay:         p.MaxEventsPerDay,
		RateLimitOrgPerMin:      int(p.RateLimitOrgPerMin),
		RateLimitKeyPerMin:      int(p.RateLimitKeyPerMin),
		MaxWhatsappPerMonth:     int(p.MaxWhatsAppPerMonth),
		MaxProjects:             int(p.MaxProjects),
		MaxMembers:              int(p.MaxMembers),
		MaxAlertRulesPerProject: int(p.MaxAlertRulesPerProject),
		MaxNotificationTargets:  int(p.MaxNotificationTargets),
		MaxArtifactBytes:        p.MaxArtifactBytes,
		EventRetentionDays:      int(p.EventRetentionDays),
	})
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
		httpserver.WriteError(w, r, http.StatusBadRequest, "VALIDATION_FAILED", err.Error())
	case errors.Is(err, ErrMFARequired):
		httpserver.WriteError(w, r, http.StatusForbidden, "MFA_SETUP_REQUIRED", "Multi-factor authentication setup is required for privileged roles.")
	case errors.Is(err, ErrForbidden):
		httpserver.WriteError(w, r, http.StatusForbidden, "FORBIDDEN", "You do not have permission to perform this action.")
	case errors.Is(err, ErrNotFound):
		httpserver.WriteError(w, r, http.StatusNotFound, "RESOURCE_NOT_FOUND", "The requested resource was not found.")
	case errors.Is(err, ErrQuotaExceeded):
		httpserver.WriteError(w, r, http.StatusTooManyRequests, "QUOTA_EXCEEDED", "Organization plan quota exceeded.")
	case errors.Is(err, ErrServiceUnavailable):
		w.Header().Set("Retry-After", "30")
		httpserver.WriteError(w, r, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", "Quota service temporarily unavailable.")
	default:
		if h.logger != nil {
			h.logger.Error("quotas handler internal error",
				slog.String("request_id", httpserver.RequestIDFromContext(r.Context())),
				slog.String("error", err.Error()),
			)
		}
		httpserver.WriteError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "An internal error occurred.")
	}
}
