package ids

import (
	"errors"
	"testing"
)

func TestCanonicalUUID(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantOK  bool
		wantOut string
	}{
		{
			name:    "canonical lowercase",
			input:   "550e8400-e29b-41d4-a716-446655440000",
			wantOK:  true,
			wantOut: "550e8400-e29b-41d4-a716-446655440000",
		},
		{
			name:    "canonical uppercase normalized to lowercase",
			input:   "550E8400-E29B-41D4-A716-446655440000",
			wantOK:  true,
			wantOut: "550e8400-e29b-41d4-a716-446655440000",
		},
		{
			name:    "canonical mixed case normalized to lowercase",
			input:   "AbCdEf01-2345-6789-aBcD-Ef0123456789",
			wantOK:  true,
			wantOut: "abcdef01-2345-6789-abcd-ef0123456789",
		},
		{
			name:   "empty string",
			input:  "",
			wantOK: false,
		},
		{
			name:   "35 characters (too short)",
			input:  "550e8400-e29b-41d4-a716-44665544000",
			wantOK: false,
		},
		{
			name:   "37 characters (too long)",
			input:  "550e8400-e29b-41d4-a716-4466554400000",
			wantOK: false,
		},
		{
			name:   "hyphens in wrong positions",
			input:  "550e840-0e29b-41d4-a716-446655440000",
			wantOK: false,
		},
		{
			name:   "non-hex character",
			input:  "550e8400-e29b-41d4-a716-44665544000g",
			wantOK: false,
		},
		{
			name:   "braced format rejected",
			input:  "{550e8400-e29b-41d4-a716-446655440000}",
			wantOK: false,
		},
		{
			name:   "urn prefix rejected",
			input:  "urn:uuid:550e8400-e29b-41d4-a716-446655440000",
			wantOK: false,
		},
		{
			name:   "32 hex without hyphens rejected",
			input:  "550e8400e29b41d4a716446655440000",
			wantOK: false,
		},
		{
			name:   "leading/trailing whitespace rejected",
			input:  " 550e8400-e29b-41d4-a716-446655440000 ",
			wantOK: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsCanonicalUUID(tc.input); got != tc.wantOK {
				t.Fatalf("IsCanonicalUUID(%q) = %v, want %v", tc.input, got, tc.wantOK)
			}

			norm, err := NormalizeUUID(tc.input)
			if tc.wantOK {
				if err != nil {
					t.Fatalf("NormalizeUUID(%q) unexpected error: %v", tc.input, err)
				}
				if norm != tc.wantOut {
					t.Fatalf("NormalizeUUID(%q) = %q, want %q", tc.input, norm, tc.wantOut)
				}
			} else {
				if !errors.Is(err, ErrInvalidUUID) {
					t.Fatalf("NormalizeUUID(%q) err = %v, want ErrInvalidUUID", tc.input, err)
				}
				if norm != "" {
					t.Fatalf("NormalizeUUID(%q) returned %q on error, want empty", tc.input, norm)
				}
			}
		})
	}
}
