package ingestion

import (
	"encoding/json"
	"time"

	"github.com/riverqueue/river"

	"github.com/Yhanko/vigia/internal/platform/jobs"
)

// ProcessErrorEventArgs is the durable River job payload enqueued by ingestion
// and consumed by the issues worker (ADR-004, ADR-017).
// Tenant, project, and environment come exclusively from the verified DSN key.
type ProcessErrorEventArgs struct {
	OrganizationID string          `json:"organization_id"`
	ProjectID      string          `json:"project_id"`
	Environment    string          `json:"environment"`
	EventID        string          `json:"event_id"`
	ReceivedAt     time.Time       `json:"received_at"`
	ClientSDK      string          `json:"client_sdk,omitempty"`
	Payload        json.RawMessage `json:"payload"`
}

// Kind implements river.JobArgs.
func (ProcessErrorEventArgs) Kind() string { return "ingestion.process_error_event" }

// InsertOpts pins error event processing to the ingest queue with 5 attempts (ADR-004 §3.3).
func (ProcessErrorEventArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{
		Queue:       jobs.QueueIngest,
		MaxAttempts: 5,
	}
}
