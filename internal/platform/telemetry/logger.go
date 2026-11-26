// Package telemetry configures structured JSON logging (slog), OpenTelemetry,
// and Prometheus metrics for Vigia self-observability (README §14).
package telemetry

import (
	"fmt"
	"io"
	"log/slog"
	"strings"
)

// NewLogger creates a structured JSON slog.Logger with service and environment
// metadata attached to every log entry.
func NewLogger(w io.Writer, levelStr, service, env string) (*slog.Logger, error) {
	var level slog.Level
	switch strings.ToLower(strings.TrimSpace(levelStr)) {
	case "", "info":
		level = slog.LevelInfo
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		return nil, fmt.Errorf("invalid log level %q", levelStr)
	}

	handler := slog.NewJSONHandler(w, &slog.HandlerOptions{
		Level: level,
	})
	return slog.New(handler).With(
		slog.String("service", service),
		slog.String("environment", env),
	), nil
}
