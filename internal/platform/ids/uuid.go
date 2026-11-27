// Package ids provides canonical identifier validation and normalization
// helpers shared across platform and domain packages without external
// dependencies.
package ids

import (
	"errors"
	"strings"
)

// ErrInvalidUUID is returned when a string is not a canonical 36-character
// RFC 4122 UUID (xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx).
var ErrInvalidUUID = errors.New("ids: invalid canonical uuid")

// IsCanonicalUUID reports whether s is a canonical 36-character UUID
// (xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx) with ASCII hexadecimal digits.
// Non-canonical encodings such as "{...}", "urn:uuid:...", or 32-char hex
// strings without hyphens are intentionally rejected.
func IsCanonicalUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i := range 36 {
		c := s[i]
		switch i {
		case 8, 13, 18, 23:
			if c != '-' {
				return false
			}
		default:
			isHex := (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
			if !isHex {
				return false
			}
		}
	}
	return true
}

// NormalizeUUID validates s as a canonical 36-character UUID and returns it
// normalized to lowercase.
func NormalizeUUID(s string) (string, error) {
	if !IsCanonicalUUID(s) {
		return "", ErrInvalidUUID
	}
	return strings.ToLower(s), nil
}
