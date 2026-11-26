package telemetry

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestNewLogger(t *testing.T) {
	var buf bytes.Buffer
	logger, err := NewLogger(&buf, "warn", "vigia-api", "staging")
	if err != nil {
		t.Fatal(err)
	}

	logger.Info("filtered out")
	if buf.Len() != 0 {
		t.Fatalf("info logged at warn level: %s", buf.String())
	}

	logger.Warn("kept")
	var entry map[string]any
	if err := json.Unmarshal(buf.Bytes(), &entry); err != nil {
		t.Fatalf("log line is not JSON: %v (%s)", err, buf.String())
	}
	if entry["service"] != "vigia-api" || entry["environment"] != "staging" || entry["msg"] != "kept" {
		t.Fatalf("unexpected log entry: %v", entry)
	}
}

func TestNewLoggerRejectsInvalidLevel(t *testing.T) {
	if _, err := NewLogger(&bytes.Buffer{}, "verbose", "s", "e"); err == nil {
		t.Fatal("expected error for invalid level")
	}
}
