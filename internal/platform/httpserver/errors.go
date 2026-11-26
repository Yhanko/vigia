package httpserver

import (
	"encoding/json"
	"net/http"
)

// ErrorDetail describes a single field or validation issue inside an ErrorBody.
type ErrorDetail struct {
	Field   string `json:"field,omitempty"`
	Message string `json:"message"`
}

// ErrorBody matches the standard API error envelope (README §9.1).
type ErrorBody struct {
	Code      string        `json:"code"`
	Message   string        `json:"message"`
	RequestID string        `json:"requestId"`
	Details   []ErrorDetail `json:"details"`
}

// ErrorResponse wraps ErrorBody under the top-level "error" key.
type ErrorResponse struct {
	Error ErrorBody `json:"error"`
}

// WriteJSON serializes v as JSON and writes it with the given HTTP status code.
func WriteJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// WriteError writes a standardized JSON error response without leaking internals.
func WriteError(w http.ResponseWriter, r *http.Request, status int, code, message string, details ...ErrorDetail) {
	if details == nil {
		details = []ErrorDetail{}
	}
	WriteJSON(w, status, ErrorResponse{
		Error: ErrorBody{
			Code:      code,
			Message:   message,
			RequestID: RequestIDFromContext(r.Context()),
			Details:   details,
		},
	})
}
