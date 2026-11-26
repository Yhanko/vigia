package database

import (
	"strings"
	"testing"
)

func TestScramSHA256VerifierFormat(t *testing.T) {
	v1, err := scramSHA256Verifier("test-runtime-password")
	if err != nil {
		t.Fatalf("scramSHA256Verifier() error = %v", err)
	}
	v2, err := scramSHA256Verifier("test-runtime-password")
	if err != nil {
		t.Fatalf("second scramSHA256Verifier() error = %v", err)
	}
	if v1 == v2 {
		t.Fatalf("two verifiers for the same password must use distinct random salts")
	}
	if !strings.HasPrefix(v1, "SCRAM-SHA-256$4096:") {
		t.Fatalf("unexpected verifier prefix: %q", v1)
	}
	if strings.Contains(v1, "test-runtime-password") {
		t.Fatalf("verifier leaked plaintext password")
	}
}
