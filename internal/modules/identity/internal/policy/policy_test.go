package policy

import (
	"errors"
	"strings"
	"testing"
)

func TestValidatePassword(t *testing.T) {
	tests := []struct {
		name     string
		password string
		email    string
		wantErr  error
	}{
		{
			name:     "valid 12 ASCII chars",
			password: "k9#mP2!vQ8@x",
			email:    "alice@example.com",
			wantErr:  nil,
		},
		{
			name:     "valid 12 multi-byte unicode runes",
			password: "áéíóúâêîôûãõ",
			email:    "alice@example.com",
			wantErr:  nil,
		},
		{
			name:     "11 unicode runes rejected even though 22 bytes",
			password: "áéíóúâêîôûã",
			email:    "alice@example.com",
			wantErr:  ErrPasswordTooShort,
		},
		{
			name:     "128 runes accepted",
			password: strings.Repeat("x", 128),
			email:    "alice@example.com",
			wantErr:  nil,
		},
		{
			name:     "129 runes rejected",
			password: strings.Repeat("x", 129),
			email:    "alice@example.com",
			wantErr:  ErrPasswordTooLong,
		},
		{
			name:     "common password rejected case-insensitively",
			password: "Password123456",
			email:    "alice@example.com",
			wantErr:  ErrPasswordCommon,
		},
		{
			name:     "password equal to email rejected",
			password: "Alice@Example.com",
			email:    "alice@example.com",
			wantErr:  ErrPasswordHasEmail,
		},
		{
			name:     "password containing email rejected",
			password: "my-alice@example.com-pass",
			email:    "alice@example.com",
			wantErr:  ErrPasswordHasEmail,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidatePassword(tc.password, tc.email)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("ValidatePassword() err = %v, want %v", err, tc.wantErr)
			}
		})
	}
}

func TestNormalizeEmail(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr error
	}{
		{"valid normalized", "  Alice.Silva+dev@Example.AO  ", "alice.silva+dev@example.ao", nil},
		{"empty", "", "", ErrInvalidEmail},
		{"missing at", "not-an-email", "", ErrInvalidEmail},
		{"no dot in domain", "alice@localhost", "", ErrInvalidEmail},
		{"display name rejected", "Alice <alice@example.com>", "", ErrInvalidEmail},
		{"leading dot in domain", "alice@.example.com", "", ErrInvalidEmail},
		{"double dot in domain", "alice@example..com", "", ErrInvalidEmail},
		{"too long > 254 bytes", strings.Repeat("a", 60) + "@" + strings.Repeat("b", 195) + ".ao", "", ErrInvalidEmail},
		{"embedded newline", "alice@example.com\n", "alice@example.com", nil}, // trimmed
		{"internal space", "ali ce@example.com", "", ErrInvalidEmail},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := NormalizeEmail(tc.input)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("NormalizeEmail(%q) err = %v, want %v", tc.input, err, tc.wantErr)
			}
			if got != tc.want {
				t.Fatalf("NormalizeEmail(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

func TestNormalizeName(t *testing.T) {
	if got, err := NormalizeName("  Maria João  "); err != nil || got != "Maria João" {
		t.Fatalf("NormalizeName(valid) = (%q, %v)", got, err)
	}
	if _, err := NormalizeName("   "); !errors.Is(err, ErrInvalidName) {
		t.Fatalf("NormalizeName(blank) err = %v, want ErrInvalidName", err)
	}
	if _, err := NormalizeName(strings.Repeat("a", MaxNameRunes+1)); !errors.Is(err, ErrInvalidName) {
		t.Fatalf("NormalizeName(too long) err = %v, want ErrInvalidName", err)
	}
}
