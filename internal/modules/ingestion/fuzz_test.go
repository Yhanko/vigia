package ingestion_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/Yhanko/vigia/internal/modules/ingestion"
)

// FuzzParseEnvelope fuzzes the streaming Sentry envelope parser (TASKS 2.2, ADR-017 §3.4 & §6).
func FuzzParseEnvelope(f *testing.F) {
	dummyKey := strings.Repeat("a", 32)
	seeds := []string{
		"{\"event_id\":\"" + dummyKey + "\"}\n{\"type\":\"event\",\"length\":18}\n{\"message\":\"boom\"}\n",
		"{}\n{\"type\":\"event\"}\n{\"message\":\"no length\"}\n",
		"{\"dsn\":\"https://" + dummyKey + "@ingest.vigia.ao/1\"}\n{\"type\":\"transaction\",\"length\":2}\n{}\n{\"type\":\"session\"}\n{\"sid\":\"1\"}\n",
		"{}\n{\"type\":\"event\",\"length\":99999}\nshort",
		"{}\n{\"type\":\"event\",\"length\":-1}\n{}",
		"",
		"not json\n",
		"{}\n{\"type\":\"\"}\n{}",
		"{}\n{\"type\":\"attachment\",\"length\":5}\nhello\n{\"type\":\"event\",\"length\":2}\n{}\n",
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}

	f.Fuzz(func(_ *testing.T, data []byte) {
		_, _ = ingestion.ParseEnvelope(bytes.NewReader(data))
	})
}

// FuzzParseSentryAuth fuzzes the X-Sentry-Auth / Authorization: Sentry header parser (TASKS 2.2, ADR-017 §6).
func FuzzParseSentryAuth(f *testing.F) {
	dummyKey := strings.Repeat("a", 32)
	seeds := []string{
		"Sentry sentry_version=7, sentry_key=" + dummyKey + ", sentry_client=sentry.go/0.27.0",
		"Sentry sentry_key=\"" + dummyKey + "\", sentry_secret=oldsecret",
		"Sentry sentry_version=6, sentry_key=" + dummyKey,
		"Bearer token",
		"Sentry ",
		"Sentry =",
		"Sentry a=b, c",
		"",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(_ *testing.T, header string) {
		_, _ = ingestion.ParseSentryAuth(header)
	})
}
