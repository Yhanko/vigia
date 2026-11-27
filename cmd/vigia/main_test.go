package main

import (
	"bytes"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"github.com/Yhanko/vigia/internal/platform/database"
)

func TestEnforceRuntimeDBRole(t *testing.T) {
	privErr := fmt.Errorf("%w: role %q has rolsuper=true", database.ErrPrivilegedRole, "vigia")
	queryErr := errors.New("connection refused")

	tests := []struct {
		name      string
		appEnv    string
		verifyErr error
		wantErr   bool
		wantWarn  bool
	}{
		{
			name:      "non-privileged role succeeds in production",
			appEnv:    "production",
			verifyErr: nil,
			wantErr:   false,
		},
		{
			name:      "privileged role warns and continues in development",
			appEnv:    "development",
			verifyErr: privErr,
			wantErr:   false,
			wantWarn:  true,
		},
		{
			name:      "privileged role fails startup in staging",
			appEnv:    "staging",
			verifyErr: privErr,
			wantErr:   true,
		},
		{
			name:      "privileged role fails startup in production",
			appEnv:    "production",
			verifyErr: privErr,
			wantErr:   true,
		},
		{
			name:      "unexpected query error fails even in development",
			appEnv:    "development",
			verifyErr: queryErr,
			wantErr:   true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			logger := slog.New(slog.NewJSONHandler(&buf, nil))

			err := enforceRuntimeDBRole(tc.appEnv, tc.verifyErr, logger)
			if tc.wantErr && err == nil {
				t.Fatal("expected error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tc.wantWarn && !strings.Contains(buf.String(), `"level":"WARN"`) {
				t.Fatalf("expected WARN log in development, got: %s", buf.String())
			}
		})
	}
}
