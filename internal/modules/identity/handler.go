package identity

import (
	"errors"
	"log/slog"
	"net/http"
	"net/netip"

	"github.com/google/uuid"
	openapi_types "github.com/oapi-codegen/runtime/types"

	"github.com/Yhanko/vigia/internal/api"
	"github.com/Yhanko/vigia/internal/modules/identity/session"
	"github.com/Yhanko/vigia/internal/platform/httpserver"
	"github.com/Yhanko/vigia/internal/platform/ratelimit"
)

const serviceUnavailableRetryAfter = "5"

// Handler implements the /api/v1/auth/* HTTP boundary (CTO #6).
// Domain rules live in Service; this type only decodes, checks Origin/CSRF,
// invokes Service, sets cookies, and maps errors to docs/api/error-catalog.md.
type Handler struct {
	svc            *Service
	sessions       *session.Codec
	allowedOrigins map[string]struct{}
	trustedProxies []netip.Prefix
	logger         *slog.Logger
}

// NewHandler constructs an identity HTTP Handler.
func NewHandler(svc *Service, sessions *session.Codec, allowedOrigins []string, trustedProxies []netip.Prefix, logger *slog.Logger) (*Handler, error) {
	if svc == nil {
		return nil, errors.New("identity: service is required")
	}
	if sessions == nil {
		return nil, errors.New("identity: session codec is required")
	}
	return &Handler{
		svc:            svc,
		sessions:       sessions,
		allowedOrigins: makeOriginSet(allowedOrigins),
		trustedProxies: trustedProxies,
		logger:         logger,
	}, nil
}

// AuthRegister handles POST /api/v1/auth/register.
func (h *Handler) AuthRegister(w http.ResponseWriter, r *http.Request) {
	// CTO #17: enforce Origin allowlist on public POST /auth/* endpoints.
	if !isAllowedOrigin(r.Header.Get("Origin"), h.allowedOrigins) {
		httpserver.WriteError(w, r, http.StatusForbidden, "CSRF_INVALID", "Invalid or missing request origin.")
		return
	}

	var req api.RegisterRequest
	if !httpserver.DecodeJSON(w, r, &req) {
		return
	}

	err := h.svc.Register(r.Context(), RegisterInput{
		Email:    req.Email,
		Name:     req.Name,
		Password: req.Password,
		Meta:     h.extractRequestMeta(r),
	})
	if err != nil {
		h.writeServiceError(w, r, err)
		return
	}

	httpserver.WriteJSON(w, http.StatusAccepted, api.AcceptedMessageResponse{
		Message: "If your request is eligible, check your email for further instructions.",
	})
}

// AuthLogin handles POST /api/v1/auth/login.
func (h *Handler) AuthLogin(w http.ResponseWriter, r *http.Request) {
	// CTO #17: enforce Origin allowlist to prevent login CSRF.
	if !isAllowedOrigin(r.Header.Get("Origin"), h.allowedOrigins) {
		httpserver.WriteError(w, r, http.StatusForbidden, "CSRF_INVALID", "Invalid or missing request origin.")
		return
	}

	var req api.LoginRequest
	if !httpserver.DecodeJSON(w, r, &req) {
		return
	}

	res, err := h.svc.Login(r.Context(), LoginInput{
		Email:    req.Email,
		Password: req.Password,
		Meta:     h.extractRequestMeta(r),
	})
	if err != nil {
		h.writeServiceError(w, r, err)
		return
	}

	if res.MFAPending {
		http.SetCookie(w, h.sessions.BuildCookie(res.SessionToken, res.ExpiresAt, res.Now))
		httpserver.WriteJSON(w, http.StatusAccepted, api.MFAChallengeResponse{
			MfaRequired: true,
			CsrfToken:   res.CSRFToken,
			ExpiresAt:   res.ExpiresAt.UTC(),
		})
		return
	}

	h.writeAuthSession(w, res)
}

// AuthLogout handles POST /api/v1/auth/logout (accepts full or mfa_pending session).
func (h *Handler) AuthLogout(w http.ResponseWriter, r *http.Request, params api.AuthLogoutParams) {
	active, ok := h.authenticateAnyAndVerifyCSRF(w, r, params.XCSRFToken)
	if !ok {
		return
	}

	if err := h.svc.Logout(r.Context(), active, h.extractRequestMeta(r)); err != nil {
		h.writeServiceError(w, r, err)
		return
	}

	http.SetCookie(w, h.sessions.ClearCookie())
	w.WriteHeader(http.StatusNoContent)
}

// AuthRefresh handles POST /api/v1/auth/refresh.
func (h *Handler) AuthRefresh(w http.ResponseWriter, r *http.Request, params api.AuthRefreshParams) {
	active, ok := h.authenticateAndVerifyCSRF(w, r, params.XCSRFToken)
	if !ok {
		return
	}

	res, err := h.svc.Refresh(r.Context(), active, h.extractRequestMeta(r))
	if err != nil {
		h.writeServiceError(w, r, err)
		return
	}

	h.writeAuthSession(w, res)
}

// AuthVerifyEmail handles POST /api/v1/auth/verify-email.
func (h *Handler) AuthVerifyEmail(w http.ResponseWriter, r *http.Request) {
	if !isAllowedOrigin(r.Header.Get("Origin"), h.allowedOrigins) {
		httpserver.WriteError(w, r, http.StatusForbidden, "CSRF_INVALID", "Invalid or missing request origin.")
		return
	}
	var req api.VerifyEmailRequest
	if !httpserver.DecodeJSON(w, r, &req) {
		return
	}
	if err := h.svc.VerifyEmail(r.Context(), req.Token, h.extractRequestMeta(r)); err != nil {
		h.writeServiceError(w, r, err)
		return
	}
	httpserver.WriteJSON(w, http.StatusOK, api.AcceptedMessageResponse{
		Message: "Email address verified.",
	})
}

// AuthPasswordForgot handles POST /api/v1/auth/password/forgot.
func (h *Handler) AuthPasswordForgot(w http.ResponseWriter, r *http.Request) {
	if !isAllowedOrigin(r.Header.Get("Origin"), h.allowedOrigins) {
		httpserver.WriteError(w, r, http.StatusForbidden, "CSRF_INVALID", "Invalid or missing request origin.")
		return
	}
	var req api.PasswordForgotRequest
	if !httpserver.DecodeJSON(w, r, &req) {
		return
	}
	if err := h.svc.ForgotPassword(r.Context(), req.Email, h.extractRequestMeta(r)); err != nil {
		h.writeServiceError(w, r, err)
		return
	}
	httpserver.WriteJSON(w, http.StatusAccepted, api.AcceptedMessageResponse{
		Message: "If an account exists for this email, instructions have been sent.",
	})
}

// AuthPasswordReset handles POST /api/v1/auth/password/reset.
func (h *Handler) AuthPasswordReset(w http.ResponseWriter, r *http.Request) {
	if !isAllowedOrigin(r.Header.Get("Origin"), h.allowedOrigins) {
		httpserver.WriteError(w, r, http.StatusForbidden, "CSRF_INVALID", "Invalid or missing request origin.")
		return
	}
	var req api.PasswordResetRequest
	if !httpserver.DecodeJSON(w, r, &req) {
		return
	}
	if err := h.svc.ResetPassword(r.Context(), req.Token, req.Password, h.extractRequestMeta(r)); err != nil {
		h.writeServiceError(w, r, err)
		return
	}
	httpserver.WriteJSON(w, http.StatusOK, api.AcceptedMessageResponse{
		Message: "Password has been reset.",
	})
}

// AuthMFASetup handles POST /api/v1/auth/mfa/setup.
func (h *Handler) AuthMFASetup(w http.ResponseWriter, r *http.Request, params api.AuthMFASetupParams) {
	active, ok := h.authenticateAndVerifyCSRF(w, r, params.XCSRFToken)
	if !ok {
		return
	}
	res, err := h.svc.SetupMFA(r.Context(), active)
	if err != nil {
		h.writeServiceError(w, r, err)
		return
	}
	httpserver.WriteJSON(w, http.StatusOK, api.MFASetupResponse{
		Secret:     res.Secret,
		OtpauthUri: res.OtpauthURI,
	})
}

// AuthMFAVerify handles POST /api/v1/auth/mfa/verify (setup confirmation or two-step login).
func (h *Handler) AuthMFAVerify(w http.ResponseWriter, r *http.Request, params api.AuthMFAVerifyParams) {
	active, ok := h.authenticateAnyAndVerifyCSRF(w, r, params.XCSRFToken)
	if !ok {
		return
	}
	var req api.MFAVerifyRequest
	if !httpserver.DecodeJSON(w, r, &req) {
		return
	}
	var code, recovery string
	if req.Code != nil {
		code = *req.Code
	}
	if req.RecoveryCode != nil {
		recovery = *req.RecoveryCode
	}
	res, err := h.svc.VerifyMFA(r.Context(), active, code, recovery, h.extractRequestMeta(r))
	if err != nil {
		h.writeServiceError(w, r, err)
		return
	}
	http.SetCookie(w, h.sessions.BuildCookie(res.SessionToken, res.ExpiresAt, res.Now))
	uid, _ := uuid.Parse(res.UserID)
	out := api.MFAVerifyResponse{
		User: api.AuthUser{
			Id:         uid,
			Email:      openapi_types.Email(res.Email),
			Name:       res.Name,
			MfaEnabled: res.MFAEnabled,
		},
		CsrfToken: res.CSRFToken,
		ExpiresAt: res.ExpiresAt.UTC(),
	}
	if len(res.RecoveryCodes) > 0 {
		rc := res.RecoveryCodes
		out.RecoveryCodes = &rc
	}
	httpserver.WriteJSON(w, http.StatusOK, out)
}

// AuthReauth handles POST /api/v1/auth/reauth.
func (h *Handler) AuthReauth(w http.ResponseWriter, r *http.Request, params api.AuthReauthParams) {
	active, ok := h.authenticateAndVerifyCSRF(w, r, params.XCSRFToken)
	if !ok {
		return
	}
	var req api.ReauthRequest
	if !httpserver.DecodeJSON(w, r, &req) {
		return
	}
	var code string
	if req.Code != nil {
		code = *req.Code
	}
	res, err := h.svc.Reauth(r.Context(), active, req.Password, code, h.extractRequestMeta(r))
	if err != nil {
		h.writeServiceError(w, r, err)
		return
	}
	h.writeAuthSession(w, res)
}

func (h *Handler) authenticateAnyAndVerifyCSRF(w http.ResponseWriter, r *http.Request, csrfToken string) (ActiveSession, bool) {
	ck, err := r.Cookie(h.sessions.CookieName())
	if err != nil || ck.Value == "" {
		httpserver.WriteError(w, r, http.StatusUnauthorized, "UNAUTHENTICATED", "Authentication is required.")
		return ActiveSession{}, false
	}
	active, err := h.svc.AuthenticateSession(r.Context(), ck.Value)
	if err != nil {
		if errors.Is(err, ErrSessionExpired) {
			active, err = h.svc.AuthenticatePendingMFASession(r.Context(), ck.Value)
		}
		if err != nil {
			if errors.Is(err, ErrSessionExpired) {
				httpserver.WriteError(w, r, http.StatusUnauthorized, "SESSION_EXPIRED", "Session has expired or been revoked.")
				return ActiveSession{}, false
			}
			httpserver.WriteError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "An internal error occurred.")
			return ActiveSession{}, false
		}
	}
	if !isAllowedOrigin(r.Header.Get("Origin"), h.allowedOrigins) {
		httpserver.WriteError(w, r, http.StatusForbidden, "CSRF_INVALID", "Invalid or missing request origin.")
		return ActiveSession{}, false
	}
	if !h.sessions.VerifyCSRFToken(csrfToken, active.CSRFTokenHash) {
		httpserver.WriteError(w, r, http.StatusForbidden, "CSRF_INVALID", "Invalid or missing CSRF token.")
		return ActiveSession{}, false
	}
	return active, true
}

func (h *Handler) authenticateAndVerifyCSRF(w http.ResponseWriter, r *http.Request, csrfToken string) (ActiveSession, bool) {
	active, ok := authenticateCookie(w, r, h.svc, h.sessions)
	if !ok {
		return ActiveSession{}, false
	}
	if !isAllowedOrigin(r.Header.Get("Origin"), h.allowedOrigins) {
		httpserver.WriteError(w, r, http.StatusForbidden, "CSRF_INVALID", "Invalid or missing request origin.")
		return ActiveSession{}, false
	}
	if !h.sessions.VerifyCSRFToken(csrfToken, active.CSRFTokenHash) {
		httpserver.WriteError(w, r, http.StatusForbidden, "CSRF_INVALID", "Invalid or missing CSRF token.")
		return ActiveSession{}, false
	}
	return active, true
}

func (h *Handler) writeAuthSession(w http.ResponseWriter, res AuthResult) {
	http.SetCookie(w, h.sessions.BuildCookie(res.SessionToken, res.ExpiresAt, res.Now))

	uid, _ := uuid.Parse(res.UserID)
	httpserver.WriteJSON(w, http.StatusOK, api.AuthSessionResponse{
		User: api.AuthUser{
			Id:         uid,
			Email:      openapi_types.Email(res.Email),
			Name:       res.Name,
			MfaEnabled: res.MFAEnabled,
		},
		CsrfToken: res.CSRFToken,
		ExpiresAt: res.ExpiresAt.UTC(),
	})
}

func (h *Handler) writeServiceError(w http.ResponseWriter, r *http.Request, err error) {
	var valErr *ValidationError
	if errors.As(err, &valErr) {
		httpserver.WriteError(w, r, http.StatusBadRequest, "VALIDATION_FAILED", "One or more fields are invalid.",
			httpserver.ErrorDetail{Field: valErr.Field, Message: valErr.Message})
		return
	}

	var rlErr *RateLimitError
	if errors.As(err, &rlErr) {
		ratelimit.WriteHeaders(w, rlErr.Result)
		httpserver.WriteError(w, r, http.StatusTooManyRequests, "RATE_LIMIT_EXCEEDED", "Rate limit exceeded. Please try again later.")
		return
	}

	switch {
	case errors.Is(err, ErrInvalidCredentials):
		httpserver.WriteError(w, r, http.StatusUnauthorized, "INVALID_CREDENTIALS", "Invalid email or password.")
	case errors.Is(err, ErrMFARequired):
		httpserver.WriteError(w, r, http.StatusUnauthorized, "MFA_REQUIRED", "Multi-factor authentication is required.")
	case errors.Is(err, ErrInvalidMFACode):
		httpserver.WriteError(w, r, http.StatusUnauthorized, "INVALID_MFA_CODE", "Invalid authentication code.")
	case errors.Is(err, ErrReauthRequired):
		httpserver.WriteError(w, r, http.StatusUnauthorized, "REAUTH_REQUIRED", "Recent authentication is required for this operation.")
	case errors.Is(err, ErrSessionExpired):
		httpserver.WriteError(w, r, http.StatusUnauthorized, "SESSION_EXPIRED", "Session has expired or been revoked.")
	case errors.Is(err, ErrServiceUnavailable):
		w.Header().Set("Retry-After", serviceUnavailableRetryAfter)
		httpserver.WriteError(w, r, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", "Service temporarily unavailable.")
	default:
		if h.logger != nil {
			h.logger.Error("identity handler internal error",
				slog.String("request_id", httpserver.RequestIDFromContext(r.Context())),
				slog.Any("error", err),
			)
		}
		httpserver.WriteError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "An internal error occurred.")
	}
}

func (h *Handler) extractRequestMeta(r *http.Request) RequestMeta {
	return RequestMeta{
		ClientIP:  httpserver.ClientIP(r, h.trustedProxies),
		UserAgent: r.UserAgent(),
		RequestID: httpserver.RequestIDFromContext(r.Context()),
	}
}
