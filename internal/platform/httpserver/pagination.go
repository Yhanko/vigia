package httpserver

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/Yhanko/vigia/internal/platform/ids"
)

// ErrInvalidCursor is returned when a pagination cursor cannot be decoded or validated.
var ErrInvalidCursor = errors.New("httpserver: invalid pagination cursor")

// Cursor represents a keyset pagination cursor ordered by (created_at DESC, id DESC).
type Cursor struct {
	CreatedAt time.Time `json:"t"`
	ID        string    `json:"id"`
}

// EncodeCursor serializes c to an opaque URL-safe base64 string.
func EncodeCursor(c Cursor) string {
	payload, _ := json.Marshal(Cursor{
		CreatedAt: c.CreatedAt.UTC(),
		ID:        strings.ToLower(c.ID),
	})
	return base64.RawURLEncoding.EncodeToString(payload)
}

// DecodeCursor decodes and validates an opaque base64url pagination cursor.
func DecodeCursor(raw string) (Cursor, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" || len(raw) > 256 {
		return Cursor{}, ErrInvalidCursor
	}
	data, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return Cursor{}, ErrInvalidCursor
	}
	var c Cursor
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return Cursor{}, ErrInvalidCursor
	}
	if c.CreatedAt.IsZero() {
		return Cursor{}, ErrInvalidCursor
	}
	normID, err := ids.NormalizeUUID(c.ID)
	if err != nil {
		return Cursor{}, ErrInvalidCursor
	}
	c.ID = normID
	c.CreatedAt = c.CreatedAt.UTC()
	return c, nil
}

// ParseLimit parses a ?limit= query parameter within [1, maxLimit], falling
// back to defaultLimit when empty.
func ParseLimit(raw string, defaultLimit, maxLimit int) (int, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return defaultLimit, nil
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 1 || n > maxLimit {
		return 0, errors.New("limit must be between 1 and " + strconv.Itoa(maxLimit))
	}
	return n, nil
}
