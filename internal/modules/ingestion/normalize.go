package ingestion

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/Yhanko/vigia/internal/modules/credentials"
	"github.com/Yhanko/vigia/internal/platform/redaction"
)

const (
	maxExceptionsPerEvent = 10
	maxFramesPerTrace     = 250
	keepOutermostFrames   = 50
	keepInnermostFrames   = 200
	maxBreadcrumbs        = 100
	maxTags               = 50
	maxTagKeyLen          = 32
	maxTagValLen          = 200
	maxMessageBytes       = 8 << 10  // 8 KiB
	maxContextLineBytes   = 1 << 10  // 1 KiB
	maxContextNeighbors   = 5        // 5 pre, 5 post
	maxMapSerializedBytes = 16 << 10 // 16 KiB for extra / contexts
	maxFingerprintItems   = 10
	maxFingerprintItemLen = 256
)

var (
	ErrInvalidEventJSON = errors.New("ingestion: invalid event json")
)

// allowedTopLevelFields is the strict allowlist of Sentry event fields kept in
// normalized payloads (ADR-017 §3.9 — unknown top-level fields are discarded).
var allowedTopLevelFields = map[string]struct{}{
	"event_id":    {},
	"timestamp":   {},
	"platform":    {},
	"level":       {},
	"logger":      {},
	"transaction": {},
	"server_name": {},
	"release":     {},
	"dist":        {},
	"environment": {},
	"fingerprint": {},
	"message":     {},
	"logentry":    {},
	"exception":   {},
	"threads":     {},
	"stacktrace":  {},
	"breadcrumbs": {},
	"tags":        {},
	"extra":       {},
	"contexts":    {},
	"user":        {},
	"request":     {},
	"sdk":         {},
	"debug_meta":  {},
	"modules":     {},
	"culprit":     {},
}

// NormalizedEvent is the sanitized, bounded, PII-redacted event ready for River.
type NormalizedEvent struct {
	EventID     string
	Environment string
	Level       string
	Timestamp   time.Time
	Payload     json.RawMessage
	Truncated   bool
}

// NormalizeEvent validates, filters, normalizes, truncates, and PII-redacts a
// raw Sentry event JSON object (ADR-017 §3.7 & §3.9).
// Returns filtered=true if the event matched an enabled project inbound filter.
func NormalizeEvent(
	raw []byte,
	receivedAt time.Time,
	envelopeEventID string,
	defaultEnv string,
	privacy redaction.Options,
	filters credentials.InboundFilters,
	httpUserAgent string,
) (NormalizedEvent, bool, error) {
	if err := CheckJSONDepth(raw, MaxJSONDepth); err != nil {
		return NormalizedEvent{}, false, err
	}

	var src map[string]any
	if err := json.Unmarshal(raw, &src); err != nil || src == nil {
		return NormalizedEvent{}, false, ErrInvalidEventJSON
	}

	// Keep only allowlisted top-level fields.
	out := make(map[string]any, len(src))
	for k, v := range src {
		if _, ok := allowedTopLevelFields[k]; ok {
			out[k] = v
		}
	}

	// Inbound filters check BEFORE normalization/quota (ADR-009 §3.2, ADR-017).
	if matchesInboundFilters(out, filters, httpUserAgent) {
		return NormalizedEvent{}, true, nil
	}

	truncatedFields := make(map[string]struct{})
	markTruncated := func(field string) {
		truncatedFields[field] = struct{}{}
	}

	// 1. event_id: 32 lowercase hex (accepts hyphenated UUID; generates if absent/invalid).
	eventID := NormalizeEventID(stringVal(out["event_id"]))
	if eventID == "" {
		eventID = NormalizeEventID(envelopeEventID)
	}
	if eventID == "" {
		eventID = generateEventID()
	}
	out["event_id"] = eventID

	// 2. timestamp: epoch float/int or ISO-8601; absent -> receivedAt.
	ts := normalizeTimestamp(out["timestamp"], receivedAt)
	out["timestamp"] = ts.UTC().Format(time.RFC3339Nano)

	// 3. level: fatal | error | warning | info | debug (unknown -> error).
	level := normalizeLevel(stringVal(out["level"]))
	out["level"] = level

	// 4. environment: event -> key default -> "production".
	env := strings.TrimSpace(stringVal(out["environment"]))
	if env == "" {
		env = strings.TrimSpace(defaultEnv)
	}
	if env == "" {
		env = "production"
	}
	if len(env) > 64 {
		env = env[:64]
		markTruncated("environment")
	}
	out["environment"] = env

	// 5. message / logentry truncation (8 KiB).
	if msg, ok := out["message"].(string); ok && len(msg) > maxMessageBytes {
		out["message"] = msg[:maxMessageBytes]
		markTruncated("message")
	}
	if le, ok := out["logentry"].(map[string]any); ok {
		if m, ok := le["message"].(string); ok && len(m) > maxMessageBytes {
			le["message"] = m[:maxMessageBytes]
			markTruncated("logentry.message")
		}
		if f, ok := le["formatted"].(string); ok && len(f) > maxMessageBytes {
			le["formatted"] = f[:maxMessageBytes]
			markTruncated("logentry.formatted")
		}
	}

	// 6. fingerprint: max 10 strings, each <= 256 chars (ADR-017 §3.9).
	if rawFP, ok := out["fingerprint"].([]any); ok {
		if len(rawFP) > maxFingerprintItems {
			rawFP = rawFP[:maxFingerprintItems]
			markTruncated("fingerprint")
		}
		cleanFP := make([]string, 0, len(rawFP))
		for _, item := range rawFP {
			s := stringVal(item)
			if s == "" {
				continue
			}
			if len(s) > maxFingerprintItemLen {
				s = s[:maxFingerprintItemLen]
				markTruncated("fingerprint")
			}
			cleanFP = append(cleanFP, s)
		}
		if len(cleanFP) > 0 {
			out["fingerprint"] = cleanFP
		} else {
			delete(out, "fingerprint")
		}
	}

	// 7. exception: max 10 chained exceptions (most recent), value <= 8 KiB, frames <= 250.
	if exc, ok := out["exception"].(map[string]any); ok {
		if vals, ok := exc["values"].([]any); ok {
			if len(vals) > maxExceptionsPerEvent {
				vals = vals[len(vals)-maxExceptionsPerEvent:]
				markTruncated("exception.values")
			}
			for _, item := range vals {
				em, ok := item.(map[string]any)
				if !ok {
					continue
				}
				if v, ok := em["value"].(string); ok && len(v) > maxMessageBytes {
					em["value"] = v[:maxMessageBytes]
					markTruncated("exception.value")
				}
				if st, ok := em["stacktrace"].(map[string]any); ok {
					truncateStacktrace(st, markTruncated)
				}
			}
			exc["values"] = vals
		}
	}
	if st, ok := out["stacktrace"].(map[string]any); ok {
		truncateStacktrace(st, markTruncated)
	}
	if th, ok := out["threads"].(map[string]any); ok {
		if vals, ok := th["values"].([]any); ok {
			for _, item := range vals {
				if tm, ok := item.(map[string]any); ok {
					if st, ok := tm["stacktrace"].(map[string]any); ok {
						truncateStacktrace(st, markTruncated)
					}
				}
			}
		}
	}

	// 8. breadcrumbs: max 100 most recent.
	if bc, ok := out["breadcrumbs"]; ok {
		switch b := bc.(type) {
		case map[string]any:
			if vals, ok := b["values"].([]any); ok && len(vals) > maxBreadcrumbs {
				b["values"] = vals[len(vals)-maxBreadcrumbs:]
				markTruncated("breadcrumbs")
			}
		case []any:
			if len(b) > maxBreadcrumbs {
				out["breadcrumbs"] = b[len(b)-maxBreadcrumbs:]
				markTruncated("breadcrumbs")
			}
		}
	}

	// 9. tags: max 50, key <= 32, value <= 200.
	if rawTags, ok := out["tags"]; ok {
		out["tags"] = normalizeTags(rawTags, markTruncated)
	}

	// 10. extra and contexts: <= 16 KiB serialized each.
	if ex, ok := out["extra"].(map[string]any); ok {
		if b, err := json.Marshal(ex); err == nil && len(b) > maxMapSerializedBytes {
			out["extra"] = truncateMapToBytes(ex, maxMapSerializedBytes)
			markTruncated("extra")
		}
	}
	if cx, ok := out["contexts"].(map[string]any); ok {
		if b, err := json.Marshal(cx); err == nil && len(b) > maxMapSerializedBytes {
			out["contexts"] = truncateMapToBytes(cx, maxMapSerializedBytes)
			markTruncated("contexts")
		}
	}

	// 11. Mandatory PII redaction BEFORE enqueue (ADR-017 §3.9, TASKS 2.3).
	out = redaction.ScrubEventMap(out, privacy)

	// Attach _meta if any field was truncated.
	attachMeta(out, truncatedFields)

	// 12. Final normalized payload cap: 256 KiB (ADR-017 §3.7).
	// Truncate in exact order: extra -> breadcrumbs -> frame context lines.
	payload, err := json.Marshal(out)
	if err != nil {
		return NormalizedEvent{}, false, ErrInvalidEventJSON
	}
	if len(payload) > MaxNormalizedPayloadBytes {
		delete(out, "extra")
		markTruncated("extra")
		attachMeta(out, truncatedFields)
		payload, _ = json.Marshal(out)
	}
	if len(payload) > MaxNormalizedPayloadBytes {
		delete(out, "breadcrumbs")
		markTruncated("breadcrumbs")
		attachMeta(out, truncatedFields)
		payload, _ = json.Marshal(out)
	}
	if len(payload) > MaxNormalizedPayloadBytes {
		stripFrameContextLines(out)
		markTruncated("stacktrace.context")
		attachMeta(out, truncatedFields)
		payload, _ = json.Marshal(out)
	}
	if len(payload) > MaxNormalizedPayloadBytes {
		delete(out, "contexts")
		delete(out, "modules")
		markTruncated("contexts")
		attachMeta(out, truncatedFields)
		payload, _ = json.Marshal(out)
	}

	return NormalizedEvent{
		EventID:     eventID,
		Environment: env,
		Level:       level,
		Timestamp:   ts.UTC(),
		Payload:     payload,
		Truncated:   len(truncatedFields) > 0,
	}, false, nil
}

// NormalizeEventID normalizes a Sentry event_id (32 hex, optionally hyphenated UUID)
// to 32 lowercase hex characters. Returns "" if invalid.
func NormalizeEventID(raw string) string {
	s := strings.ToLower(strings.TrimSpace(raw))
	s = strings.ReplaceAll(s, "-", "")
	if len(s) != 32 {
		return ""
	}
	for i := range len(s) {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return ""
		}
	}
	return s
}

func generateEventID() string {
	var b [16]byte
	_, _ = io.ReadFull(rand.Reader, b[:])
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return hex.EncodeToString(b[:])
}

func normalizeTimestamp(raw any, fallback time.Time) time.Time {
	switch v := raw.(type) {
	case float64:
		if !math.IsNaN(v) && !math.IsInf(v, 0) && v > 0 {
			sec, frac := math.Modf(v)
			return time.Unix(int64(sec), int64(frac*1e9)).UTC()
		}
	case string:
		s := strings.TrimSpace(v)
		for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02T15:04:05"} {
			if t, err := time.Parse(layout, s); err == nil {
				return t.UTC()
			}
		}
	}
	return fallback.UTC()
}

func normalizeLevel(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "fatal":
		return "fatal"
	case "error":
		return "error"
	case "warning", "warn":
		return "warning"
	case "info":
		return "info"
	case "debug":
		return "debug"
	default:
		return "error"
	}
}

func truncateStacktrace(st map[string]any, markTruncated func(string)) {
	frames, ok := st["frames"].([]any)
	if !ok {
		return
	}
	if len(frames) > maxFramesPerTrace {
		kept := make([]any, 0, maxFramesPerTrace)
		kept = append(kept, frames[:keepOutermostFrames]...)
		kept = append(kept, frames[len(frames)-keepInnermostFrames:]...)
		frames = kept
		st["frames"] = frames
		markTruncated("stacktrace.frames")
	}
	for _, f := range frames {
		fm, ok := f.(map[string]any)
		if !ok {
			continue
		}
		if cl, ok := fm["context_line"].(string); ok && len(cl) > maxContextLineBytes {
			fm["context_line"] = cl[:maxContextLineBytes]
			markTruncated("stacktrace.context_line")
		}
		for _, key := range []string{"pre_context", "post_context"} {
			lines, ok := fm[key].([]any)
			if !ok {
				continue
			}
			if len(lines) > maxContextNeighbors {
				if key == "pre_context" {
					lines = lines[len(lines)-maxContextNeighbors:]
				} else {
					lines = lines[:maxContextNeighbors]
				}
				markTruncated("stacktrace." + key)
			}
			for i, l := range lines {
				if ls, ok := l.(string); ok && len(ls) > maxContextLineBytes {
					lines[i] = ls[:maxContextLineBytes]
					markTruncated("stacktrace." + key)
				}
			}
			fm[key] = lines
		}
	}
}

func stripFrameContextLines(ev map[string]any) {
	stripST := func(st map[string]any) {
		frames, ok := st["frames"].([]any)
		if !ok {
			return
		}
		for _, f := range frames {
			if fm, ok := f.(map[string]any); ok {
				delete(fm, "context_line")
				delete(fm, "pre_context")
				delete(fm, "post_context")
				delete(fm, "vars")
			}
		}
	}
	if st, ok := ev["stacktrace"].(map[string]any); ok {
		stripST(st)
	}
	if exc, ok := ev["exception"].(map[string]any); ok {
		if vals, ok := exc["values"].([]any); ok {
			for _, item := range vals {
				if em, ok := item.(map[string]any); ok {
					if st, ok := em["stacktrace"].(map[string]any); ok {
						stripST(st)
					}
				}
			}
		}
	}
}

func normalizeTags(raw any, markTruncated func(string)) map[string]string {
	out := make(map[string]string)
	addTag := func(k, v string) {
		if len(out) >= maxTags {
			markTruncated("tags")
			return
		}
		k = strings.TrimSpace(k)
		if k == "" {
			return
		}
		if len(k) > maxTagKeyLen {
			k = k[:maxTagKeyLen]
			markTruncated("tags")
		}
		if len(v) > maxTagValLen {
			v = v[:maxTagValLen]
			markTruncated("tags")
		}
		out[k] = v
	}

	switch t := raw.(type) {
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			addTag(k, stringVal(t[k]))
		}
	case []any:
		for _, pair := range t {
			if arr, ok := pair.([]any); ok && len(arr) >= 2 {
				addTag(stringVal(arr[0]), stringVal(arr[1]))
			}
		}
	}
	return out
}

func truncateMapToBytes(m map[string]any, limit int) map[string]any {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make(map[string]any)
	used := 2 // "{}"
	for _, k := range keys {
		vb, err := json.Marshal(m[k])
		if err != nil {
			continue
		}
		entryLen := len(k) + len(vb) + 4
		if used+entryLen > limit {
			break
		}
		out[k] = m[k]
		used += entryLen
	}
	return out
}

func attachMeta(out map[string]any, fields map[string]struct{}) {
	if len(fields) == 0 {
		return
	}
	list := make([]string, 0, len(fields))
	for f := range fields {
		list = append(list, f)
	}
	sort.Strings(list)
	out["_meta"] = map[string]any{
		"truncated": true,
		"fields":    list,
	}
}

func matchesInboundFilters(ev map[string]any, filters credentials.InboundFilters, httpUA string) bool {
	if filters.BrowserExtensions && hasBrowserExtensionFrameOrURL(ev) {
		return true
	}
	if filters.Localhost && isLocalhostEvent(ev) {
		return true
	}
	if filters.Crawlers && isCrawlerEvent(ev, httpUA) {
		return true
	}
	return false
}

var extensionPrefixes = []string{
	"chrome-extension://",
	"moz-extension://",
	"safari-extension://",
	"safari-web-extension://",
	"ms-browser-extension://",
}

func hasBrowserExtensionFrameOrURL(ev map[string]any) bool {
	hasExt := func(s string) bool {
		low := strings.ToLower(strings.TrimSpace(s))
		for _, p := range extensionPrefixes {
			if strings.HasPrefix(low, p) {
				return true
			}
		}
		return false
	}
	if req, ok := ev["request"].(map[string]any); ok {
		if hasExt(stringVal(req["url"])) {
			return true
		}
	}
	if exc, ok := ev["exception"].(map[string]any); ok {
		if vals, ok := exc["values"].([]any); ok {
			for _, item := range vals {
				em, ok := item.(map[string]any)
				if !ok {
					continue
				}
				st, ok := em["stacktrace"].(map[string]any)
				if !ok {
					continue
				}
				frames, ok := st["frames"].([]any)
				if !ok {
					continue
				}
				for _, f := range frames {
					if fm, ok := f.(map[string]any); ok {
						if hasExt(stringVal(fm["filename"])) || hasExt(stringVal(fm["abs_path"])) {
							return true
						}
					}
				}
			}
		}
	}
	return false
}

func isLocalhostEvent(ev map[string]any) bool {
	req, ok := ev["request"].(map[string]any)
	if !ok {
		return false
	}
	rawURL := strings.TrimSpace(stringVal(req["url"]))
	if rawURL == "" {
		return false
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	host := strings.ToLower(u.Hostname())
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}

var crawlerTokens = []string{
	"googlebot", "bingbot", "yandexbot", "baiduspider",
	"duckduckbot", "slurp", "facebookexternalhit", "twitterbot",
	"ahrefsbot", "semrushbot", "mj12bot", "dotbot",
}

func isCrawlerEvent(ev map[string]any, httpUA string) bool {
	check := func(ua string) bool {
		low := strings.ToLower(ua)
		for _, tok := range crawlerTokens {
			if strings.Contains(low, tok) {
				return true
			}
		}
		return false
	}
	if httpUA != "" && check(httpUA) {
		return true
	}
	if req, ok := ev["request"].(map[string]any); ok {
		if hdrs, ok := req["headers"].(map[string]any); ok {
			for k, v := range hdrs {
				if strings.EqualFold(k, "user-agent") && check(stringVal(v)) {
					return true
				}
			}
		}
	}
	return false
}

func stringVal(v any) string {
	s, _ := v.(string)
	return s
}
