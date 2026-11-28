// Package ingestion implements the Sentry SDK-compatible HTTP ingestion
// protocol (envelopes, legacy store, streaming decompression, normalization,
// PII redaction, deduplication, rate limits, quotas, and River enqueue)
// strictly following ADR-017 and ADR-009.
package ingestion

import (
	"errors"
	"net/http"
	"net/url"
	"strings"
)

var (
	ErrMissingAuth    = errors.New("ingestion: missing sentry authentication")
	ErrInvalidAuth    = errors.New("ingestion: invalid sentry authentication header")
	ErrInvalidVersion = errors.New("ingestion: unsupported sentry_version")
)

const maxClientSDKLen = 64

// AuthParams holds parsed Sentry ingestion authentication fields (ADR-017 §3.2).
type AuthParams struct {
	PublicKey string
	Version   string
	ClientSDK string
}

// ParseSentryAuth parses an X-Sentry-Auth or Authorization: Sentry header value.
// Format: "Sentry sentry_version=7, sentry_key=<32hex>, sentry_client=<sdk>/<ver>"
// sentry_secret is intentionally ignored (ADR-017 §3.2).
func ParseSentryAuth(header string) (AuthParams, error) {
	s := strings.TrimSpace(header)
	if len(s) < 7 || !strings.EqualFold(s[:7], "Sentry ") {
		return AuthParams{}, ErrInvalidAuth
	}
	rest := strings.TrimSpace(s[7:])
	if rest == "" {
		return AuthParams{}, ErrInvalidAuth
	}

	var p AuthParams
	for _, part := range strings.Split(rest, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		eq := strings.IndexByte(part, '=')
		if eq <= 0 {
			return AuthParams{}, ErrInvalidAuth
		}
		k := strings.ToLower(strings.TrimSpace(part[:eq]))
		v := strings.TrimSpace(part[eq+1:])
		if len(v) >= 2 && ((v[0] == '"' && v[len(v)-1] == '"') || (v[0] == '\'' && v[len(v)-1] == '\'')) {
			v = v[1 : len(v)-1]
		}
		switch k {
		case "sentry_key":
			p.PublicKey = v
		case "sentry_version":
			p.Version = v
		case "sentry_client":
			p.ClientSDK = truncateString(v, maxClientSDKLen)
		case "sentry_secret", "sentry_timestamp":
			// Accepted and ignored per ADR-017 §3.2.
		default:
			// Ignore unknown auth parameters for forward compatibility.
		}
	}
	if p.Version != "" && p.Version != "7" {
		return AuthParams{}, ErrInvalidVersion
	}
	if p.PublicKey == "" {
		return AuthParams{}, ErrMissingAuth
	}
	if p.Version == "" {
		p.Version = "7"
	}
	return p, nil
}

// ExtractAuthFromRequest extracts Sentry auth from headers or query string
// in the exact precedence order of ADR-017 §3.2:
//  1. X-Sentry-Auth
//  2. Authorization: Sentry ...
//  3. Query string ?sentry_key=...
//
// Returns ErrMissingAuth if none of 1-3 are present (caller may then fall back
// to step 4: envelope header `dsn` field).
func ExtractAuthFromRequest(r *http.Request) (AuthParams, error) {
	if h := strings.TrimSpace(r.Header.Get("X-Sentry-Auth")); h != "" {
		return ParseSentryAuth(h)
	}
	if h := strings.TrimSpace(r.Header.Get("Authorization")); len(h) >= 7 && strings.EqualFold(h[:7], "Sentry ") {
		return ParseSentryAuth(h)
	}
	q := r.URL.Query()
	if key := strings.TrimSpace(q.Get("sentry_key")); key != "" {
		ver := strings.TrimSpace(q.Get("sentry_version"))
		if ver != "" && ver != "7" {
			return AuthParams{}, ErrInvalidVersion
		}
		if ver == "" {
			ver = "7"
		}
		return AuthParams{
			PublicKey: key,
			Version:   ver,
			ClientSDK: truncateString(strings.TrimSpace(q.Get("sentry_client")), maxClientSDKLen),
		}, nil
	}
	if ver := strings.TrimSpace(q.Get("sentry_version")); ver != "" && ver != "7" {
		return AuthParams{}, ErrInvalidVersion
	}
	return AuthParams{}, ErrMissingAuth
}

// ExtractAuthFromDSN parses the public key from a Sentry DSN URL in the
// envelope header (step 4 of ADR-017 §3.2, used by SDK tunnels).
func ExtractAuthFromDSN(dsn string) (AuthParams, error) {
	dsn = strings.TrimSpace(dsn)
	if dsn == "" {
		return AuthParams{}, ErrMissingAuth
	}
	u, err := url.Parse(dsn)
	if err != nil || u.User == nil {
		return AuthParams{}, ErrInvalidAuth
	}
	key := strings.TrimSpace(u.User.Username())
	if key == "" {
		return AuthParams{}, ErrInvalidAuth
	}
	return AuthParams{
		PublicKey: key,
		Version:   "7",
	}, nil
}

func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen]
}
