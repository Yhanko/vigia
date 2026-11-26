package httpserver

import (
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strings"
)

// DecodeJSON strictly decodes a single JSON object from the request body into dst
// (README §11.5): Content-Type must be application/json, unknown fields are
// rejected, trailing data is rejected and the body limit set by MaxBytesMiddleware
// maps to 413. On failure it writes the standard error envelope and returns false,
// so handlers can write `if !DecodeJSON(w, r, &in) { return }`.
//
// Error messages never echo the raw body, unknown field names or Go internals.
func DecodeJSON(w http.ResponseWriter, r *http.Request, dst any) bool {
	if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mt != "application/json" {
		WriteError(w, r, http.StatusUnsupportedMediaType, "UNSUPPORTED_MEDIA_TYPE", "Content-Type must be application/json.")
		return false
	}

	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()

	if err := dec.Decode(dst); err != nil {
		writeDecodeError(w, r, err)
		return false
	}

	// Anything after the first value (a second object, garbage) is rejected.
	if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			writeDecodeError(w, r, err)
			return false
		}
		WriteError(w, r, http.StatusBadRequest, "INVALID_JSON", "Request body must contain a single JSON object.")
		return false
	}
	return true
}

func writeDecodeError(w http.ResponseWriter, r *http.Request, err error) {
	var (
		maxErr    *http.MaxBytesError
		syntaxErr *json.SyntaxError
		typeErr   *json.UnmarshalTypeError
	)
	switch {
	case errors.As(err, &maxErr):
		WriteError(w, r, http.StatusRequestEntityTooLarge, "PAYLOAD_TOO_LARGE", "Request body exceeds the allowed size.")
	case errors.Is(err, io.EOF):
		WriteError(w, r, http.StatusBadRequest, "INVALID_JSON", "Request body must not be empty.")
	case errors.As(err, &syntaxErr), errors.Is(err, io.ErrUnexpectedEOF):
		WriteError(w, r, http.StatusBadRequest, "INVALID_JSON", "Request body contains malformed JSON.")
	case errors.As(err, &typeErr):
		WriteError(w, r, http.StatusBadRequest, "VALIDATION_FAILED", "Request body has a field with an invalid type.",
			ErrorDetail{Field: typeErr.Field, Message: "invalid type"})
	case strings.HasPrefix(err.Error(), "json: unknown field "):
		// encoding/json has no typed error for DisallowUnknownFields.
		WriteError(w, r, http.StatusBadRequest, "VALIDATION_FAILED", "Request body contains an unknown field.")
	default:
		WriteError(w, r, http.StatusBadRequest, "INVALID_JSON", "Request body could not be decoded.")
	}
}
