package identity

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestTruncateUserAgentUTF8Safe(t *testing.T) {
	t.Run("multibyte rune crossing byte 200 boundary", func(t *testing.T) {
		raw := strings.Repeat("a", 199) + "🔥tail"
		got := truncateUserAgent(raw)
		if got == nil {
			t.Fatal("expected non-nil user agent")
		}
		if len(*got) > maxStoredUserAgentLen {
			t.Fatalf("len = %d, want <= %d", len(*got), maxStoredUserAgentLen)
		}
		if !utf8.ValidString(*got) {
			t.Fatalf("truncated user agent is not valid UTF-8: %q", *got)
		}
		if *got != strings.Repeat("a", 199) {
			t.Fatalf("expected clean cut before 4-byte rune, got len=%d", len(*got))
		}
	})

	t.Run("invalid UTF-8 and NUL bytes stripped", func(t *testing.T) {
		raw := "Mozilla/5.0\x00\xff\xfeSafe"
		got := truncateUserAgent(raw)
		if got == nil || !utf8.ValidString(*got) || strings.ContainsRune(*got, 0) {
			t.Fatalf("unexpected sanitized user agent: %v", got)
		}
		if *got != "Mozilla/5.0Safe" {
			t.Fatalf("got %q, want %q", *got, "Mozilla/5.0Safe")
		}
	})

	t.Run("blank returns nil", func(t *testing.T) {
		if got := truncateUserAgent("   "); got != nil {
			t.Fatalf("expected nil for blank user agent, got %q", *got)
		}
	})
}
