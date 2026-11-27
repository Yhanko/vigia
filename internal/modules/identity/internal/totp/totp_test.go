package totp

import (
	"bytes"
	"crypto/rand"
	"strings"
	"testing"
	"time"
)

// TestRFC6238AppendixBSHA1Vectors verifies our TOTP implementation against all
// SHA-1 test vectors from RFC 6238 Appendix B (6-digit truncation of the 8-digit
// RFC reference values with seed "12345678901234567890").
func TestRFC6238AppendixBSHA1Vectors(t *testing.T) {
	seed := []byte("12345678901234567890")
	vectors := []struct {
		unix int64
		want string // last 6 digits of RFC 6238 Appendix B 8-digit SHA-1 output
	}{
		{59, "287082"},          // 94287082
		{1111111109, "081804"},  // 07081804
		{1111111111, "050471"},  // 14050471
		{1234567890, "005924"},  // 89005924
		{2000000000, "279037"},  // 69279037
		{20000000000, "353130"}, // 65353130
	}

	for _, v := range vectors {
		got := CodeAt(seed, time.Unix(v.unix, 0).UTC())
		if got != v.want {
			t.Fatalf("CodeAt(unix=%d) = %q, want %q", v.unix, got, v.want)
		}
	}
}

func TestVerifySkewAndAntiReplay(t *testing.T) {
	raw, b32, err := GenerateSecret()
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) != SecretBytes || b32 == "" {
		t.Fatalf("unexpected generated secret: len=%d b32=%q", len(raw), b32)
	}

	uri := ProvisioningURI("Vigia", "alice@example.com", b32)
	if !strings.HasPrefix(uri, "otpauth://totp/Vigia:") || !strings.Contains(uri, "secret="+b32) {
		t.Fatalf("unexpected provisioning URI: %q", uri)
	}

	now := time.Unix(1700000100, 0).UTC()
	code := CodeAt(raw, now)

	step, ok := Verify(raw, code, now, nil)
	if !ok || step != now.Unix()/PeriodSeconds {
		t.Fatalf("Verify(current) = (%d, %v), want (%d, true)", step, ok, now.Unix()/PeriodSeconds)
	}

	// Anti-replay: reusing the same step or any earlier step MUST be rejected.
	if _, ok := Verify(raw, code, now, &step); ok {
		t.Fatal("Verify accepted replayed TOTP code for same step")
	}
	prevCode := CodeAt(raw, now.Add(-30*time.Second))
	if _, ok := Verify(raw, prevCode, now, &step); ok {
		t.Fatal("Verify accepted older TOTP step <= lastUsedStep")
	}

	// +1 step skew succeeds when step > lastUsedStep.
	nextCode := CodeAt(raw, now.Add(30*time.Second))
	nextStep, ok := Verify(raw, nextCode, now, &step)
	if !ok || nextStep != step+1 {
		t.Fatalf("Verify(+1 skew) = (%d, %v), want (%d, true)", nextStep, ok, step+1)
	}
}

func TestRecoveryCodesGenerationAndHMAC(t *testing.T) {
	codes, err := GenerateRecoveryCodes(RecoveryCount)
	if err != nil {
		t.Fatal(err)
	}
	if len(codes) != RecoveryCount {
		t.Fatalf("len(codes) = %d, want %d", len(codes), RecoveryCount)
	}
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		t.Fatal(err)
	}
	seen := make(map[string]struct{}, RecoveryCount)
	for _, c := range codes {
		if len(c) != 19 || c[4] != '-' || c[9] != '-' || c[14] != '-' {
			t.Fatalf("unexpected recovery code format: %q", c)
		}
		if _, dup := seen[c]; dup {
			t.Fatalf("duplicate recovery code generated: %q", c)
		}
		seen[c] = struct{}{}
	}

	h1 := HashRecoveryCode(secret, codes[0])
	h2 := HashRecoveryCode(secret, strings.ToUpper(strings.ReplaceAll(codes[0], "-", " ")))
	if !bytes.Equal(h1, h2) {
		t.Fatal("HashRecoveryCode not normalized/deterministic")
	}
}
