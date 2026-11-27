package credentials

import (
	"crypto/rand"
	"errors"
	"strings"
	"testing"
)

func TestGenerateParseAndVerifySecretKeys(t *testing.T) {
	pepper := make([]byte, 32)
	if _, err := rand.Read(pepper); err != nil {
		t.Fatal(err)
	}

	for _, kind := range []string{KindIngest, KindClient} {
		full, prefix, err := GenerateSecretKey(kind)
		if err != nil {
			t.Fatalf("GenerateSecretKey(%s): %v", kind, err)
		}
		if len(full) != SecretKeyLength || len(prefix) != PrefixLength {
			t.Fatalf("unexpected lengths: full=%d prefix=%d", len(full), len(prefix))
		}
		parsed, err := ParseSecretKey(full)
		if err != nil || parsed.Kind != kind || parsed.Prefix != prefix {
			t.Fatalf("ParseSecretKey(%s) = (%+v, %v)", kind, parsed, err)
		}

		hash := HashSecret(pepper, full)
		if !VerifySecret(pepper, full, hash) {
			t.Fatal("VerifySecret(valid) = false")
		}
		if VerifySecret(pepper, full[:len(full)-1]+"0", hash) && full[len(full)-1] != '0' {
			t.Fatal("VerifySecret(tampered) = true")
		}
	}

	// Negative parser cases (ADR-005 §3.2 position-based strictness).
	validIng, _, _ := GenerateSecretKey(KindIngest)
	badKeys := []string{
		"",
		"vg_dsn_" + strings.Repeat("a", 12) + "_" + strings.Repeat("b", 64),
		strings.ToUpper(validIng),
		validIng[:19] + "-" + validIng[20:],
		validIng + "a",
		validIng[:len(validIng)-1],
		validIng[:20] + "g" + validIng[21:],
		strings.Repeat("a", 32), // DSN key must be rejected as secret bearer key
	}
	for _, bad := range badKeys {
		if _, err := ParseSecretKey(bad); !errors.Is(err, ErrInvalidCredential) {
			t.Fatalf("ParseSecretKey(%q) err = %v, want ErrInvalidCredential", bad, err)
		}
	}

	// DSN key + FormatDSN + CacheKey.
	pub, dsnPre, err := GenerateDSNKey()
	if err != nil || len(pub) != DSNKeyLength || len(dsnPre) != DSNPrefixLength {
		t.Fatalf("GenerateDSNKey() = (%q, %q, %v)", pub, dsnPre, err)
	}
	if got := FormatDSN(pub, "ingest.vigia.ao", 4817263); got != "https://"+pub+"@ingest.vigia.ao/4817263" {
		t.Fatalf("FormatDSN = %q", got)
	}
	if got := CacheKey(KindDSN, pub); got != "cred:dsn:"+pub {
		t.Fatalf("CacheKey(dsn) = %q", got)
	}
}
