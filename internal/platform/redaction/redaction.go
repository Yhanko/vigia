// Package redaction implements server-side PII and credential scrubbing for
// ingested error events before they enter the durable job queue (README §2.3,
// §11.4, §17.3; ADR-017 §3.9; TASKS 2.0, 2.2, 2.3).
//
// All regular expressions use Go's RE2 engine (linear-time, anti-ReDoS) with
// an explicit per-string length cap.
package redaction

import (
	"net/netip"
	"net/url"
	"regexp"
	"strings"
)

const (
	// FilteredValue replaces redacted values deterministically.
	FilteredValue = "[Filtered]"

	// MaxInputBytes caps any single string scanned by regexes (anti-ReDoS / DoS).
	MaxInputBytes = 64 << 10 // 64 KiB
)

// Options controls project-level opt-in privacy overrides (ADR-017 §3.9).
type Options struct {
	AllowRequestBody bool
	AllowUserIP      bool
}

var sensitiveKeySubstrings = []string{
	"password",
	"passwd",
	"secret",
	"api_key",
	"apikey",
	"token",
	"access_token",
	"auth",
	"authorization",
	"credentials",
	"cookie",
	"set-cookie",
	"session",
	"private_key",
	"mysql_pwd",
}

var sensitiveHeaderKeys = map[string]struct{}{
	"authorization":       {},
	"proxy-authorization": {},
	"cookie":              {},
	"set-cookie":          {},
	"x-api-key":           {},
	"x-vigia-key":         {},
	"x-sentry-auth":       {},
	"x-csrf-token":        {},
}

var (
	// Credit card candidate: 13-19 digits with optional spaces or hyphens.
	ccCandidateRe = regexp.MustCompile(`\b(?:\d[ -]?){13,19}\b`)
	// Bearer / Basic auth headers embedded in free text.
	bearerRe = regexp.MustCompile(`(?i)\b(?:bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}\b`)
	// Vigia secret keys (vg_ing_ / vg_cli_).
	vigiaKeyRe = regexp.MustCompile(`\bvg_(?:ing|cli)_[0-9a-f]{12}_[0-9a-f]{64}\b`)
	// Angolan BI (9 digits + 2 uppercase letters + 3 digits) and US SSN (XXX-XX-XXXX).
	docIDRe = regexp.MustCompile(`\b(?:\d{9}[A-Z]{2}\d{3}|\d{3}-\d{2}-\d{4})\b`)
	// Inline URL with query string inside free text.
	urlQueryRe = regexp.MustCompile(`https?://[^\s"'<>]+\?[^\s"'<>]+`)
)

// IsSensitiveKey reports whether a map/object key or query parameter name
// matches the mandatory scrubbing list (TASKS 2.3).
func IsSensitiveKey(key string) bool {
	lk := strings.ToLower(strings.TrimSpace(key))
	if lk == "" {
		return false
	}
	for _, sub := range sensitiveKeySubstrings {
		if strings.Contains(lk, sub) {
			return true
		}
	}
	return false
}

// ScrubString redacts credit cards (Luhn-validated), Bearer/Basic credentials,
// Vigia secret keys, document patterns, and sensitive URL query parameters.
func ScrubString(s string) string {
	if s == "" {
		return s
	}
	truncatedSuffix := ""
	if len(s) > MaxInputBytes {
		s = s[:MaxInputBytes]
		truncatedSuffix = "…"
	}

	s = vigiaKeyRe.ReplaceAllString(s, FilteredValue)
	s = bearerRe.ReplaceAllString(s, FilteredValue)
	s = docIDRe.ReplaceAllString(s, FilteredValue)
	s = ccCandidateRe.ReplaceAllStringFunc(s, func(match string) string {
		if passesLuhn(match) {
			return FilteredValue
		}
		return match
	})
	s = urlQueryRe.ReplaceAllStringFunc(s, ScrubURL)
	return s + truncatedSuffix
}

// ScrubURL redacts sensitive query parameters and embedded userinfo in rawURL.
func ScrubURL(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	if u.User != nil {
		u.User = url.User(FilteredValue)
	}
	if u.RawQuery != "" {
		u.RawQuery = ScrubQueryString(u.RawQuery)
	}
	return u.String()
}

// ScrubQueryString redacts values of sensitive query parameters while preserving
// non-sensitive parameter names and values.
func ScrubQueryString(rawQuery string) string {
	if rawQuery == "" {
		return ""
	}
	q, err := url.ParseQuery(rawQuery)
	if err != nil {
		return FilteredValue
	}
	for k, vals := range q {
		if IsSensitiveKey(k) || strings.EqualFold(k, "sentry_key") || strings.EqualFold(k, "key") {
			for i := range vals {
				vals[i] = FilteredValue
			}
			q[k] = vals
			continue
		}
		for i, v := range vals {
			vals[i] = ScrubString(v)
		}
		q[k] = vals
	}
	return q.Encode()
}

// ScrubHeaders redacts Authorization, Cookie, Set-Cookie, API key headers, and
// any header whose name matches IsSensitiveKey.
func ScrubHeaders(headers map[string]string) map[string]string {
	if headers == nil {
		return nil
	}
	out := make(map[string]string, len(headers))
	for k, v := range headers {
		lk := strings.ToLower(strings.TrimSpace(k))
		if _, blocked := sensitiveHeaderKeys[lk]; blocked || IsSensitiveKey(lk) {
			out[k] = FilteredValue
			continue
		}
		out[k] = ScrubString(v)
	}
	return out
}

// ScrubIP returns rawIP unchanged when allowUserIP is true; otherwise truncates
// IPv4 to /24 and IPv6 to /48 (ADR-017 §3.9). Invalid IPs return "".
func ScrubIP(rawIP string, allowUserIP bool) string {
	rawIP = strings.TrimSpace(rawIP)
	if rawIP == "" {
		return ""
	}
	addr, err := netip.ParseAddr(rawIP)
	if err != nil {
		return ""
	}
	addr = addr.Unmap()
	if allowUserIP {
		return addr.String()
	}
	bits := 24
	if addr.Is6() {
		bits = 48
	}
	p, err := addr.Prefix(bits)
	if err != nil {
		return ""
	}
	return p.String()
}

// ScrubValue recursively scrubs arbitrary JSON-like structures (maps, slices,
// strings) respecting sensitive keys and maximum recursion depth.
func ScrubValue(v any, depth int) any {
	if depth > 32 {
		return FilteredValue
	}
	switch x := v.(type) {
	case string:
		return ScrubString(x)
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, val := range x {
			if IsSensitiveKey(k) {
				out[k] = FilteredValue
				continue
			}
			out[k] = ScrubValue(val, depth+1)
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, item := range x {
			out[i] = ScrubValue(item, depth+1)
		}
		return out
	default:
		return v
	}
}

// ScrubEventMap applies full server-side privacy scrubbing to a normalized
// Sentry-compatible event map before enqueuing (ADR-017 §3.9).
func ScrubEventMap(ev map[string]any, opts Options) map[string]any {
	if ev == nil {
		return nil
	}
	scrubbed, _ := ScrubValue(ev, 0).(map[string]any)
	if scrubbed == nil {
		return nil
	}

	// Handle request block: drop request.data & cookies unless opt-in; scrub headers & URL.
	if req, ok := scrubbed["request"].(map[string]any); ok {
		if !opts.AllowRequestBody {
			delete(req, "data")
			delete(req, "cookies")
		}
		if rawURL, ok := req["url"].(string); ok {
			req["url"] = ScrubURL(rawURL)
		}
		if rawQS, ok := req["query_string"].(string); ok {
			req["query_string"] = ScrubQueryString(rawQS)
		}
		if hdrs, ok := req["headers"].(map[string]any); ok {
			for k, v := range hdrs {
				lk := strings.ToLower(strings.TrimSpace(k))
				if _, blocked := sensitiveHeaderKeys[lk]; blocked || IsSensitiveKey(lk) {
					hdrs[k] = FilteredValue
				} else if sv, ok := v.(string); ok {
					hdrs[k] = ScrubString(sv)
				}
			}
		}
	}

	// Handle user.ip_address according to project privacy setting.
	if usr, ok := scrubbed["user"].(map[string]any); ok {
		if ip, ok := usr["ip_address"].(string); ok {
			usr["ip_address"] = ScrubIP(ip, opts.AllowUserIP)
		}
	}

	return scrubbed
}

// passesLuhn checks whether digits extracted from s satisfy the Luhn checksum
// and fall within standard PAN length (13-19 digits).
func passesLuhn(s string) bool {
	digits := make([]int, 0, 19)
	for i := range len(s) {
		c := s[i]
		if c >= '0' && c <= '9' {
			digits = append(digits, int(c-'0'))
		}
	}
	if len(digits) < 13 || len(digits) > 19 {
		return false
	}
	sum := 0
	alt := false
	for i := len(digits) - 1; i >= 0; i-- {
		d := digits[i]
		if alt {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
		alt = !alt
	}
	return sum%10 == 0
}
