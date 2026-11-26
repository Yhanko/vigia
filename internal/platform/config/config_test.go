package config

import (
	"bytes"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSecretRedaction(t *testing.T) {
	s := Secret("super-secret-value")

	if got := s.String(); got != "[REDACTED]" {
		t.Fatalf("String() = %q, want [REDACTED]", got)
	}
	if got := s.GoString(); got != `"[REDACTED]"` {
		t.Fatalf("GoString() = %q, want redacted", got)
	}

	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))
	logger.Info("check", "secret", s)
	if strings.Contains(buf.String(), "super-secret-value") {
		t.Fatalf("secret leaked in slog output: %s", buf.String())
	}
	if s.Value() != "super-secret-value" {
		t.Fatalf("Value() did not return underlying secret")
	}
}

func TestLoadFromDefaultsAndSecretFile(t *testing.T) {
	dir := t.TempDir()
	dbPassFile := filepath.Join(dir, "pg_pass.txt")
	if err := os.WriteFile(dbPassFile, []byte("p@ss:word/123\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	env := stagingEnv(t, dir)
	env["PORT"] = "9090"
	env["LOG_LEVEL"] = "debug"
	env["DATABASE_PASSWORD_FILE"] = dbPassFile
	env["CORS_ORIGINS"] = "http://127.0.0.1:5173, https://vigia.example.com"

	cfg, err := LoadFrom(func(k string) string { return env[k] })
	if err != nil {
		t.Fatalf("LoadFrom() error = %v", err)
	}

	if cfg.AppEnv != "staging" || cfg.Port != 9090 || cfg.LogLevel != "debug" {
		t.Fatalf("unexpected cfg basics: %+v", cfg)
	}
	if len(cfg.CORSOrigins) != 2 || cfg.CORSOrigins[1] != "https://vigia.example.com" {
		t.Fatalf("unexpected CORSOrigins: %v", cfg.CORSOrigins)
	}

	dsn, err := cfg.DatabaseDSN()
	if err != nil {
		t.Fatalf("DatabaseDSN() error = %v", err)
	}
	if !strings.Contains(dsn, "vigia:p%40ss%3Aword%2F123@127.0.0.1:5432/vigia") {
		t.Fatalf("DatabaseDSN() = %q, expected URL-encoded password", dsn)
	}
}

func TestLoadFromValidationErrors(t *testing.T) {
	tests := []struct {
		name string
		env  map[string]string
	}{
		{"invalid port", map[string]string{"PORT": "70000"}},
		{"non-numeric port", map[string]string{"PORT": "abc"}},
		{"invalid env", map[string]string{"APP_ENV": "invalid"}},
		{"invalid log level", map[string]string{"LOG_LEVEL": "verbose"}},
		{"invalid database url", map[string]string{"DATABASE_URL": "http://localhost:5432"}},
		{"missing secret file", map[string]string{"REDIS_PASSWORD_FILE": "/does/not/exist.txt"}},
		{"wildcard cors", map[string]string{"CORS_ORIGINS": "*"}},
		{"cors origin with path", map[string]string{"CORS_ORIGINS": "https://app.example.com/login"}},
		{"cors origin with trailing slash", map[string]string{"CORS_ORIGINS": "https://app.example.com/"}},
		{"cors origin bad scheme", map[string]string{"CORS_ORIGINS": "ftp://app.example.com"}},
		{"invalid smtp url", map[string]string{"SMTP_URL": "http://mailpit:1025"}},
		{"invalid api body limit", map[string]string{"API_MAX_BODY_BYTES": "0"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := LoadFrom(func(k string) string { return tt.env[k] }); err == nil {
				t.Fatalf("expected error for %s, got nil", tt.name)
			}
		})
	}
}

// writeKey writes a secret file with the given content and returns its path.
func writeKey(t *testing.T, dir, name, value string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(value), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// stagingEnv returns a minimal valid environment for APP_ENV=staging.
func stagingEnv(t *testing.T, dir string) map[string]string {
	t.Helper()
	key := strings.Repeat("a", 64)
	return map[string]string{
		"APP_ENV":             "staging",
		"DATABASE_URL":        "postgresql://vigia@127.0.0.1:5432/vigia?sslmode=disable",
		"REDIS_ADDR":          "127.0.0.1:6379",
		"SESSION_SECRET_FILE": writeKey(t, dir, "session.txt", key),
		"API_KEY_PEPPER_FILE": writeKey(t, dir, "pepper.txt", key),
		"ENCRYPTION_KEY_FILE": writeKey(t, dir, "enc.txt", key),
	}
}

func TestLoadFromDevelopmentAllowsMissingDependencies(t *testing.T) {
	cfg, err := LoadFrom(func(string) string { return "" })
	if err != nil {
		t.Fatalf("development defaults should load, got %v", err)
	}
	if !cfg.IsDevelopment() || cfg.APIMaxBodyBytes != 256<<10 {
		t.Fatalf("unexpected defaults: %+v", cfg)
	}
}

func TestLoadFromFailFastOutsideDevelopment(t *testing.T) {
	dir := t.TempDir()

	for _, key := range []string{"DATABASE_URL", "REDIS_ADDR", "SESSION_SECRET_FILE", "API_KEY_PEPPER_FILE", "ENCRYPTION_KEY_FILE"} {
		t.Run("missing "+key, func(t *testing.T) {
			env := stagingEnv(t, dir)
			delete(env, key)
			_, err := LoadFrom(func(k string) string { return env[k] })
			if err == nil || !strings.Contains(err.Error(), key) {
				t.Fatalf("expected error naming %s, got %v", key, err)
			}
		})
	}

	t.Run("short key rejected", func(t *testing.T) {
		env := stagingEnv(t, dir)
		env["API_KEY_PEPPER_FILE"] = writeKey(t, dir, "short.txt", "too-short")
		_, err := LoadFrom(func(k string) string { return env[k] })
		if err == nil || !strings.Contains(err.Error(), "API_KEY_PEPPER_FILE") {
			t.Fatalf("expected short key error, got %v", err)
		}
		if strings.Contains(err.Error(), "too-short") {
			t.Fatalf("error leaked the secret value: %v", err)
		}
	})

	t.Run("production requires https", func(t *testing.T) {
		env := stagingEnv(t, dir)
		env["APP_ENV"] = "production"
		env["APP_URL"] = "https://vigia.example.com"
		env["CORS_ORIGINS"] = "http://vigia.example.com"
		if _, err := LoadFrom(func(k string) string { return env[k] }); err == nil {
			t.Fatal("expected error for http CORS origin in production")
		}

		env["CORS_ORIGINS"] = "https://vigia.example.com"
		env["APP_URL"] = "http://vigia.example.com"
		if _, err := LoadFrom(func(k string) string { return env[k] }); err == nil {
			t.Fatal("expected error for http APP_URL in production")
		}

		env["APP_URL"] = "https://vigia.example.com"
		if _, err := LoadFrom(func(k string) string { return env[k] }); err != nil {
			t.Fatalf("valid production config rejected: %v", err)
		}
	})
}
