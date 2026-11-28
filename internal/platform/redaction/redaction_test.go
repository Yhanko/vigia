package redaction_test

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/Yhanko/vigia/internal/platform/redaction"
)

func TestScrubStringPatterns(t *testing.T) {
	t.Parallel()

	// Build synthetic secrets at runtime (never literal keys in source).
	synKey := "vg_ing_" + hex.EncodeToString(bytes.Repeat([]byte{0xab}, 6)) + "_" + hex.EncodeToString(bytes.Repeat([]byte{0xcd}, 32))
	// Standard test Visa PAN (valid Luhn: 4111-1111-1111-1111).
	synCard := "4111" + "-1111" + "-1111" + "-1111"
	synBI := "001234567" + "LA042"
	synBearer := "Bearer " + hex.EncodeToString(bytes.Repeat([]byte{0x55}, 12))

	cases := []struct {
		name      string
		in        string
		forbidden string
		wantSame  bool
	}{
		{"credit card luhn", "charged " + synCard + " ok", synCard, false},
		{"non-luhn number preserved", "order 4111111111111112 ok", "", true},
		{"angolan BI", "user bi=" + synBI, synBI, false},
		{"vigia ingest key", "leak " + synKey, synKey, false},
		{"bearer token", "hdr " + synBearer, synBearer, false},
		{"url query secret", "https://api.example.ao/cb?token=supersecret123&page=2", "supersecret123", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := redaction.ScrubString(tc.in)
			if tc.wantSame {
				if got != tc.in {
					t.Fatalf("ScrubString(%q) = %q, want unchanged", tc.in, got)
				}
				return
			}
			if strings.Contains(got, tc.forbidden) {
				t.Fatalf("ScrubString leaked sensitive value %q in %q", tc.forbidden, got)
			}
			if !strings.Contains(got, redaction.FilteredValue) && !strings.Contains(got, "%5BFiltered%5D") {
				t.Fatalf("expected %q marker in %q", redaction.FilteredValue, got)
			}
		})
	}
}

func TestScrubEventMapRemovesAllSensitiveFields(t *testing.T) {
	t.Parallel()

	synPass := "my-secret-pass-999"
	synCookie := "vigia_session=abc123xyz"
	synAuth := "Bearer " + hex.EncodeToString(bytes.Repeat([]byte{0x44}, 16))
	synBody := "raw-credit-card-body-payload"

	ev := map[string]any{
		"message": "failed for https://app.vigia.ao/reset?token=reset987&ok=1",
		"extra": map[string]any{
			"password":    synPass,
			"api_key":     "secret-api-key-val",
			"mysql_pwd":   "db-pwd-val",
			"private_key": "pem-data",
			"safe_field":  "hello",
		},
		"request": map[string]any{
			"url":          "https://app.vigia.ao/pay?access_token=tok123&item=5",
			"query_string": "api_key=k999&sort=asc",
			"data":         synBody,
			"cookies":      synCookie,
			"headers": map[string]any{
				"Authorization": synAuth,
				"Cookie":        synCookie,
				"User-Agent":    "Mozilla/5.0",
			},
		},
		"user": map[string]any{
			"id":         "u-42",
			"ip_address": "198.51.100.77",
		},
	}

	out := redaction.ScrubEventMap(ev, redaction.Options{
		AllowRequestBody: false,
		AllowUserIP:      false,
	})
	raw, _ := json.Marshal(out)
	s := string(raw)

	for _, forbidden := range []string{synPass, synCookie, synAuth, synBody, "secret-api-key-val", "db-pwd-val", "pem-data", "reset987", "tok123", "k999", "198.51.100.77"} {
		if strings.Contains(s, forbidden) {
			t.Fatalf("sensitive data %q survived ScrubEventMap: %s", forbidden, s)
		}
	}
	if !strings.Contains(s, "198.51.100.0/24") {
		t.Fatalf("expected truncated /24 IP prefix in %s", s)
	}
	if !strings.Contains(s, `"safe_field":"hello"`) {
		t.Fatalf("safe_field was unexpectedly altered: %s", s)
	}
}
