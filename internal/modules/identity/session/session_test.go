package session

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"
)

func testSecret(t *testing.T) []byte {
	t.Helper()
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

func TestNewCodecRejectsShortSecret(t *testing.T) {
	short := bytes.Repeat([]byte{0x42}, MinSecretBytes-1)
	if _, err := NewCodec(short, "production"); !errors.Is(err, ErrInvalidSecret) {
		t.Fatalf("NewCodec(short) err = %v, want ErrInvalidSecret", err)
	}
}

func TestCodecRedaction(t *testing.T) {
	secret := testSecret(t)
	c, err := NewCodec(secret, "production")
	if err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))
	logger.Info("codec", "codec", c)

	needle := string(secret)
	for _, out := range []string{fmt.Sprint(c), fmt.Sprintf("%#v", c), buf.String()} {
		if strings.Contains(out, needle) {
			t.Fatal("session secret leaked into formatted/logged output")
		}
		if !strings.Contains(out, "[REDACTED]") {
			t.Fatalf("expected [REDACTED] in %q", out)
		}
	}
}

func TestSessionTokenGenerationAndHash(t *testing.T) {
	c, err := NewCodec(testSecret(t), "production")
	if err != nil {
		t.Fatal(err)
	}

	tok1, hash1, err := c.NewToken()
	if err != nil {
		t.Fatalf("NewToken() error = %v", err)
	}
	tok2, hash2, err := c.NewToken()
	if err != nil {
		t.Fatalf("NewToken() #2 error = %v", err)
	}
	if tok1 == tok2 || bytes.Equal(hash1, hash2) {
		t.Fatal("two generated tokens must not collide")
	}

	raw, err := base64.RawURLEncoding.DecodeString(tok1)
	if err != nil {
		t.Fatalf("token is not valid base64url: %v", err)
	}
	if len(raw) != TokenBytes {
		t.Fatalf("decoded token length = %d, want %d", len(raw), TokenBytes)
	}
	if len(hash1) != sha256.Size {
		t.Fatalf("token hash length = %d, want %d", len(hash1), sha256.Size)
	}
	if !bytes.Equal(c.HashToken(tok1), hash1) {
		t.Fatal("HashToken is not deterministic")
	}
	if bytes.Equal(c.HashToken(tok1), c.HashCSRFToken(tok1)) {
		t.Fatal("session token hash and CSRF token hash must be domain-separated")
	}
}

func TestCSRFTokenVerification(t *testing.T) {
	c, err := NewCodec(testSecret(t), "production")
	if err != nil {
		t.Fatal(err)
	}

	csrfTok, csrfHash, err := c.NewCSRFToken()
	if err != nil {
		t.Fatalf("NewCSRFToken() error = %v", err)
	}
	if !c.VerifyCSRFToken(csrfTok, csrfHash) {
		t.Fatal("VerifyCSRFToken(valid) = false, want true")
	}
	if c.VerifyCSRFToken(csrfTok+"x", csrfHash) {
		t.Fatal("VerifyCSRFToken(tampered) = true, want false")
	}
	if c.VerifyCSRFToken("", csrfHash) {
		t.Fatal("VerifyCSRFToken(empty) = true, want false")
	}
	if c.VerifyCSRFToken(csrfTok, csrfHash[:len(csrfHash)-1]) {
		t.Fatal("VerifyCSRFToken(short hash) = true, want false")
	}
}

func TestBuildAndClearCookieByEnvironment(t *testing.T) {
	secret := testSecret(t)
	expires := time.Date(2026, 12, 4, 12, 0, 0, 0, time.UTC)

	tests := []struct {
		env        string
		wantName   string
		wantSecure bool
	}{
		{"development", CookieNameDev, false},
		{"staging", CookieNameProd, true},
		{"production", CookieNameProd, true},
	}

	for _, tc := range tests {
		t.Run(tc.env, func(t *testing.T) {
			c, err := NewCodec(secret, tc.env)
			if err != nil {
				t.Fatal(err)
			}

			tok, _, err := c.NewToken()
			if err != nil {
				t.Fatal(err)
			}

			ck := c.BuildCookie(tok, expires, DefaultIdleTTL)
			if ck.Name != tc.wantName {
				t.Fatalf("cookie Name = %q, want %q", ck.Name, tc.wantName)
			}
			if ck.Value != tok {
				t.Fatal("cookie Value mismatch")
			}
			if !ck.HttpOnly {
				t.Fatal("cookie HttpOnly must be true")
			}
			if ck.Secure != tc.wantSecure {
				t.Fatalf("cookie Secure = %v, want %v", ck.Secure, tc.wantSecure)
			}
			if ck.SameSite != http.SameSiteLaxMode {
				t.Fatalf("cookie SameSite = %v, want SameSiteLaxMode", ck.SameSite)
			}
			if ck.Path != "/" {
				t.Fatalf("cookie Path = %q, want /", ck.Path)
			}
			if ck.Domain != "" {
				t.Fatalf("cookie Domain = %q, must be empty for __Host- compliance", ck.Domain)
			}

			cleared := c.ClearCookie()
			if cleared.Name != tc.wantName || cleared.Value != "" || cleared.MaxAge != -1 || !cleared.HttpOnly || cleared.Secure != tc.wantSecure {
				t.Fatalf("unexpected ClearCookie: %+v", cleared)
			}
		})
	}
}
