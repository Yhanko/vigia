package database

import (
	"testing"
	"time"
)

func TestParsePoolConfigAppliesLimits(t *testing.T) {
	dsn := "postgresql://vigia:secret@127.0.0.1:5432/vigia?sslmode=disable"

	t.Run("explicit max conns and statement timeout", func(t *testing.T) {
		cfg, err := parsePoolConfig(dsn, PoolOptions{
			MaxConns:         35,
			StatementTimeout: 15 * time.Second,
		})
		if err != nil {
			t.Fatalf("parsePoolConfig() error = %v", err)
		}
		if cfg.MaxConns != 35 || cfg.MinConns != defaultMinConns {
			t.Fatalf("pool sizes = (%d, %d), want (35, %d)", cfg.MaxConns, cfg.MinConns, defaultMinConns)
		}
		if got := cfg.ConnConfig.RuntimeParams["statement_timeout"]; got != "15000" {
			t.Fatalf("statement_timeout = %q, want %q", got, "15000")
		}
	})

	t.Run("max conns = 1 caps min conns to 1", func(t *testing.T) {
		cfg, err := parsePoolConfig(dsn, PoolOptions{MaxConns: 1})
		if err != nil {
			t.Fatalf("parsePoolConfig() error = %v", err)
		}
		if cfg.MaxConns != 1 || cfg.MinConns != 1 {
			t.Fatalf("pool sizes = (%d, %d), want (1, 1)", cfg.MaxConns, cfg.MinConns)
		}
		if _, exists := cfg.ConnConfig.RuntimeParams["statement_timeout"]; exists {
			t.Fatalf("statement_timeout should not be set when duration is zero")
		}
	})
}

func TestParseMigrateConfigHasNoStatementTimeout(t *testing.T) {
	dsn := "postgresql://vigia:secret@127.0.0.1:5432/vigia?sslmode=disable&statement_timeout=5000"
	cfg, err := parseMigrateConfig(dsn)
	if err != nil {
		t.Fatalf("parseMigrateConfig() error = %v", err)
	}
	if _, exists := cfg.RuntimeParams["statement_timeout"]; exists {
		t.Fatalf("migrate connection must not carry runtime statement_timeout")
	}
}
