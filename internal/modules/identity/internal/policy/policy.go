// Package policy enforces domain validation rules for passwords, emails, and
// user display names (docs/decisions/business-defaults.md §1, CTO #16).
package policy

import (
	"bufio"
	_ "embed"
	"errors"
	"net/mail"
	"strings"
	"sync"
	"unicode"
	"unicode/utf8"
)

const (
	MinPasswordRunes = 12
	MaxPasswordRunes = 128
	MaxPasswordBytes = 512

	MaxEmailBytes = 254
	MaxNameRunes  = 120
)

var (
	ErrPasswordTooShort = errors.New("policy: password must be at least 12 characters")
	ErrPasswordTooLong  = errors.New("policy: password must be at most 128 characters")
	ErrPasswordCommon   = errors.New("policy: password is too common")
	ErrPasswordHasEmail = errors.New("policy: password must not match or contain email")
	ErrInvalidEmail     = errors.New("policy: invalid email address")
	ErrInvalidName      = errors.New("policy: invalid display name")
)

//go:embed common_passwords.txt
var commonPasswordsRaw string

var (
	commonOnce sync.Once
	commonSet  map[string]struct{}
)

func loadCommonPasswords() map[string]struct{} {
	commonOnce.Do(func() {
		set := make(map[string]struct{}, 128)
		sc := bufio.NewScanner(strings.NewReader(commonPasswordsRaw))
		for sc.Scan() {
			line := strings.ToLower(strings.TrimSpace(sc.Text()))
			if line != "" && !strings.HasPrefix(line, "#") {
				set[line] = struct{}{}
			}
		}
		commonSet = set
	})
	return commonSet
}

// ValidatePassword checks NIST SP 800-63B / business-defaults.md §1 rules:
// 12–128 Unicode runes, <= 512 bytes, not in embedded common list, and not
// matching/containing the user's normalized email.
func ValidatePassword(password, email string) error {
	if len(password) > MaxPasswordBytes {
		return ErrPasswordTooLong
	}
	runes := utf8.RuneCountInString(password)
	if runes < MinPasswordRunes {
		return ErrPasswordTooShort
	}
	if runes > MaxPasswordRunes {
		return ErrPasswordTooLong
	}

	lowerPass := strings.ToLower(password)
	if _, found := loadCommonPasswords()[lowerPass]; found {
		return ErrPasswordCommon
	}

	normEmail := strings.ToLower(strings.TrimSpace(email))
	if normEmail != "" {
		if lowerPass == normEmail || strings.Contains(lowerPass, normEmail) {
			return ErrPasswordHasEmail
		}
	}
	return nil
}

// NormalizeEmail trims and lowercases an email address and validates its
// structure (<= 254 bytes, bare addr-spec without display name, dot in domain,
// no whitespace or control characters).
func NormalizeEmail(raw string) (string, error) {
	norm := strings.ToLower(strings.TrimSpace(raw))
	if norm == "" || len(norm) > MaxEmailBytes {
		return "", ErrInvalidEmail
	}
	for _, r := range norm {
		if unicode.IsSpace(r) || unicode.IsControl(r) {
			return "", ErrInvalidEmail
		}
	}

	parsed, err := mail.ParseAddress(norm)
	if err != nil || parsed.Name != "" || parsed.Address != norm {
		return "", ErrInvalidEmail
	}

	at := strings.LastIndexByte(norm, '@')
	if at <= 0 || at == len(norm)-1 {
		return "", ErrInvalidEmail
	}
	local := norm[:at]
	domain := norm[at+1:]
	if len(local) > 64 || !strings.Contains(domain, ".") ||
		strings.HasPrefix(domain, ".") || strings.HasSuffix(domain, ".") ||
		strings.Contains(domain, "..") {
		return "", ErrInvalidEmail
	}
	return norm, nil
}

// NormalizeName trims a user's display name and enforces 1–120 runes.
func NormalizeName(raw string) (string, error) {
	norm := strings.TrimSpace(raw)
	n := utf8.RuneCountInString(norm)
	if n == 0 || n > MaxNameRunes {
		return "", ErrInvalidName
	}
	return norm, nil
}
