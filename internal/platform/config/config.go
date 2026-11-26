// Package config reads and validates application configuration from environment
// variables and secret files (*_FILE). Secret values are wrapped in Secret so
// they are never accidentally printed or logged.
package config

import (
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Secret holds a sensitive string value that redacts itself when formatted or logged.
type Secret string

// String implements fmt.Stringer and always redacts the secret.
func (Secret) String() string { return "[REDACTED]" }

// GoString implements fmt.GoStringer and always redacts the secret.
func (Secret) GoString() string { return `"[REDACTED]"` }

// LogValue implements slog.LogValuer and always redacts the secret.
func (Secret) LogValue() slog.Value { return slog.StringValue("[REDACTED]") }

// Value returns the raw secret value. Use only at the boundary where the secret is required.
func (s Secret) Value() string { return string(s) }

// IsEmpty reports whether the secret is unset.
func (s Secret) IsEmpty() bool { return len(s) == 0 }

// Config holds the validated runtime configuration for a Vigia process.
type Config struct {
	AppEnv   string
	Port     int
	AppURL   string
	LogLevel string

	DatabaseURL      string
	DatabasePassword Secret

	RedisAddr     string
	RedisPassword Secret

	SessionSecret Secret
	APIKeyPepper  Secret
	EncryptionKey Secret

	CORSOrigins []string

	// APIMaxBodyBytes caps request bodies on the product API. Ingestion endpoints
	// apply their own limit (IngestMaxPayloadBytes) on their route group.
	APIMaxBodyBytes       int64
	IngestMaxPayloadBytes int64
	IngestMaxBatchItems   int
	QueryMaxRangeDays     int

	SMTPURL         string
	VAPIDPublicKey  string
	VAPIDPrivateKey Secret
	VAPIDSubject    string
}

// Load reads configuration from environment variables (and *_FILE secret paths)
// and fails fast if any value is invalid.
func Load() (Config, error) {
	return LoadFrom(os.Getenv)
}

// LoadFrom loads configuration using the supplied lookup function (useful for tests).
func LoadFrom(getenv func(string) string) (Config, error) {
	cfg := Config{
		AppEnv:                "development",
		Port:                  8080,
		AppURL:                "http://127.0.0.1:8080",
		LogLevel:              "info",
		CORSOrigins:           []string{"http://127.0.0.1:5173"},
		APIMaxBodyBytes:       256 << 10, // 256 KiB
		IngestMaxPayloadBytes: 1 << 20,   // 1 MiB
		IngestMaxBatchItems:   500,
		QueryMaxRangeDays:     31,
		SMTPURL:               "smtp://mailpit:1025",
	}

	if v := strings.TrimSpace(getenv("APP_ENV")); v != "" {
		switch v {
		case "development", "staging", "production":
			cfg.AppEnv = v
		default:
			return Config{}, fmt.Errorf("invalid APP_ENV %q: must be development, staging, or production", v)
		}
	}

	if v := strings.TrimSpace(getenv("PORT")); v != "" {
		p, err := strconv.Atoi(v)
		if err != nil || p < 1 || p > 65535 {
			return Config{}, fmt.Errorf("invalid PORT %q: must be an integer between 1 and 65535", v)
		}
		cfg.Port = p
	}

	if v := strings.TrimSpace(getenv("APP_URL")); v != "" {
		u, err := url.Parse(v)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return Config{}, fmt.Errorf("invalid APP_URL %q: must be a valid http(s) URL", v)
		}
		cfg.AppURL = v
	}

	if v := strings.ToLower(strings.TrimSpace(getenv("LOG_LEVEL"))); v != "" {
		switch v {
		case "debug", "info", "warn", "error":
			cfg.LogLevel = v
		default:
			return Config{}, fmt.Errorf("invalid LOG_LEVEL %q: must be debug, info, warn, or error", v)
		}
	}

	if v := strings.TrimSpace(getenv("DATABASE_URL")); v != "" {
		u, err := url.Parse(v)
		if err != nil || (u.Scheme != "postgres" && u.Scheme != "postgresql") || u.Host == "" {
			return Config{}, fmt.Errorf("invalid DATABASE_URL: must be a valid postgres(ql) URL")
		}
		cfg.DatabaseURL = v
	}

	var err error
	if cfg.DatabasePassword, err = readSecretFile(getenv, "DATABASE_PASSWORD_FILE"); err != nil {
		return Config{}, err
	}

	cfg.RedisAddr = strings.TrimSpace(getenv("REDIS_ADDR"))
	if cfg.RedisPassword, err = readSecretFile(getenv, "REDIS_PASSWORD_FILE"); err != nil {
		return Config{}, err
	}

	if cfg.SessionSecret, err = readSecretFile(getenv, "SESSION_SECRET_FILE"); err != nil {
		return Config{}, err
	}
	if cfg.APIKeyPepper, err = readSecretFile(getenv, "API_KEY_PEPPER_FILE"); err != nil {
		return Config{}, err
	}
	if cfg.EncryptionKey, err = readSecretFile(getenv, "ENCRYPTION_KEY_FILE"); err != nil {
		return Config{}, err
	}

	if v := strings.TrimSpace(getenv("CORS_ORIGINS")); v != "" {
		parts := strings.Split(v, ",")
		origins := make([]string, 0, len(parts))
		for _, p := range parts {
			p = strings.TrimSpace(p)
			if p != "" {
				origins = append(origins, p)
			}
		}
		cfg.CORSOrigins = origins
	}
	for _, o := range cfg.CORSOrigins {
		if err := validateOrigin(o); err != nil {
			return Config{}, err
		}
	}

	if v := strings.TrimSpace(getenv("API_MAX_BODY_BYTES")); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n <= 0 {
			return Config{}, fmt.Errorf("invalid API_MAX_BODY_BYTES %q: must be a positive integer", v)
		}
		cfg.APIMaxBodyBytes = n
	}

	if v := strings.TrimSpace(getenv("INGEST_MAX_PAYLOAD_BYTES")); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n <= 0 {
			return Config{}, fmt.Errorf("invalid INGEST_MAX_PAYLOAD_BYTES %q: must be a positive integer", v)
		}
		cfg.IngestMaxPayloadBytes = n
	}

	if v := strings.TrimSpace(getenv("INGEST_MAX_BATCH_ITEMS")); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 {
			return Config{}, fmt.Errorf("invalid INGEST_MAX_BATCH_ITEMS %q: must be a positive integer", v)
		}
		cfg.IngestMaxBatchItems = n
	}

	if v := strings.TrimSpace(getenv("QUERY_MAX_RANGE_DAYS")); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 || n > 366 {
			return Config{}, fmt.Errorf("invalid QUERY_MAX_RANGE_DAYS %q: must be between 1 and 366", v)
		}
		cfg.QueryMaxRangeDays = n
	}

	if v := strings.TrimSpace(getenv("SMTP_URL")); v != "" {
		u, err := url.Parse(v)
		if err != nil || (u.Scheme != "smtp" && u.Scheme != "smtps") || u.Host == "" {
			return Config{}, fmt.Errorf("invalid SMTP_URL: must be a valid smtp:// or smtps:// URL")
		}
		cfg.SMTPURL = v
	}

	cfg.VAPIDPublicKey = strings.TrimSpace(getenv("VAPID_PUBLIC_KEY"))
	if cfg.VAPIDPrivateKey, err = readSecretFile(getenv, "VAPID_PRIVATE_KEY_FILE"); err != nil {
		return Config{}, err
	}
	cfg.VAPIDSubject = strings.TrimSpace(getenv("VAPID_SUBJECT"))

	if err := cfg.validateForEnv(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// MinKeyLength is the minimum length (in characters) accepted for the session
// secret, API key pepper and encryption key. 32 characters of hex is 128 bits;
// the documented generator (openssl rand -hex 32) produces 64.
const MinKeyLength = 32

// IsDevelopment reports whether the process runs with APP_ENV=development.
func (c Config) IsDevelopment() bool { return c.AppEnv == "development" }

// validateForEnv enforces fail-fast rules outside development: every dependency
// and key the platform needs must be present, and browser-facing URLs must be
// HTTPS in production. Development keeps everything optional so the API can
// run on its own.
func (c Config) validateForEnv() error {
	if c.IsDevelopment() {
		return nil
	}

	var missing []string
	if c.DatabaseURL == "" {
		missing = append(missing, "DATABASE_URL")
	}
	if c.RedisAddr == "" {
		missing = append(missing, "REDIS_ADDR")
	}
	if c.SessionSecret.IsEmpty() {
		missing = append(missing, "SESSION_SECRET_FILE")
	}
	if c.APIKeyPepper.IsEmpty() {
		missing = append(missing, "API_KEY_PEPPER_FILE")
	}
	if c.EncryptionKey.IsEmpty() {
		missing = append(missing, "ENCRYPTION_KEY_FILE")
	}
	if len(missing) > 0 {
		return fmt.Errorf("APP_ENV=%s requires: %s", c.AppEnv, strings.Join(missing, ", "))
	}

	for name, key := range map[string]Secret{
		"SESSION_SECRET_FILE": c.SessionSecret,
		"API_KEY_PEPPER_FILE": c.APIKeyPepper,
		"ENCRYPTION_KEY_FILE": c.EncryptionKey,
	} {
		if len(key.Value()) < MinKeyLength {
			return fmt.Errorf("%s must contain at least %d characters", name, MinKeyLength)
		}
	}

	if c.AppEnv == "production" {
		if !strings.HasPrefix(c.AppURL, "https://") {
			return fmt.Errorf("APP_URL must use https in production")
		}
		for _, o := range c.CORSOrigins {
			if !strings.HasPrefix(o, "https://") {
				return fmt.Errorf("CORS origin %q must use https in production", o)
			}
		}
	}
	return nil
}

// validateOrigin accepts only exact browser origins (scheme://host[:port]).
// Wildcards are rejected because the API allows credentials.
func validateOrigin(o string) error {
	if o == "*" {
		return fmt.Errorf("invalid CORS_ORIGINS: wildcard \"*\" is not allowed with credentials")
	}
	u, err := url.Parse(o)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" ||
		u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.User != nil {
		return fmt.Errorf("invalid CORS origin %q: must be scheme://host[:port]", o)
	}
	return nil
}

// DatabaseDSN returns the PostgreSQL connection string with the password from
// DATABASE_PASSWORD_FILE safely injected (if provided).
func (c Config) DatabaseDSN() (string, error) {
	if c.DatabaseURL == "" {
		return "", fmt.Errorf("DATABASE_URL is required")
	}
	if c.DatabasePassword.IsEmpty() {
		return c.DatabaseURL, nil
	}
	u, err := url.Parse(c.DatabaseURL)
	if err != nil {
		return "", fmt.Errorf("parse DATABASE_URL: %w", err)
	}
	username := ""
	if u.User != nil {
		username = u.User.Username()
	}
	u.User = url.UserPassword(username, c.DatabasePassword.Value())
	return u.String(), nil
}

func readSecretFile(getenv func(string) string, envKey string) (Secret, error) {
	path := strings.TrimSpace(getenv(envKey))
	if path == "" {
		return "", nil
	}
	// The path comes from an operator-controlled *_FILE variable, never from a request.
	raw, err := os.ReadFile(filepath.Clean(path)) //nolint:gosec // G304: trusted, operator-supplied path
	if err != nil {
		return "", fmt.Errorf("read %s (%q): %w", envKey, path, err)
	}
	val := strings.TrimRight(string(raw), "\r\n")
	if val == "" {
		return "", fmt.Errorf("%s (%q) is empty", envKey, path)
	}
	return Secret(val), nil
}
