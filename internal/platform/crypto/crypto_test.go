package crypto

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"
)

const (
	testKey1Hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	testKey2Hex = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
	testUUID1   = "11111111-1111-4111-8111-111111111111"
	testUUID2   = "22222222-2222-4222-8222-222222222222"
)

func testScope() Scope {
	return Scope{
		OwnerType: OwnerTypeOrg,
		OwnerID:   "org-11111111-1111-4111-8111-111111111111",
		Table:     "notification_destinations",
		Column:    "config_encrypted",
		RecordID:  testUUID1,
	}
}

func TestParseKeyringAndRedaction(t *testing.T) {
	kr, err := ParseKeyring([]byte("k2:" + testKey2Hex + "\nk1:" + testKey1Hex + "\n"))
	if err != nil {
		t.Fatalf("ParseKeyring() error = %v", err)
	}
	if kr.ActiveKeyID() != "k2" {
		t.Fatalf("ActiveKeyID() = %q, want k2", kr.ActiveKeyID())
	}

	// Verify fmt and slog never leak key bytes.
	if got := fmt.Sprintf("%s %v %#v", kr, kr, kr); strings.Contains(got, testKey1Hex) || strings.Contains(got, testKey2Hex) {
		t.Fatalf("fmt leaked key material: %s", got)
	}
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))
	logger.Info("loaded keyring", "keyring", kr)
	if strings.Contains(buf.String(), testKey1Hex) || strings.Contains(buf.String(), testKey2Hex) {
		t.Fatalf("slog leaked key material: %s", buf.String())
	}
}

func TestParseKeyringValidationAndNoKeyLeakInErrors(t *testing.T) {
	secretSample := "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
	badHexSample := "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"

	tests := []struct {
		name string
		raw  string
	}{
		{"empty", ""},
		{"whitespace only", "   \n\t\n"},
		{"legacy unprefixed 64 hex", secretSample},
		{"empty key id", ":" + secretSample},
		{"invalid key id chars", "K1!:" + secretSample},
		{"key id too long", "thiskeyidistoolong123:" + secretSample},
		{"short key", "k1:deadbeef"},
		{"non-hex key", "k1:" + badHexSample},
		{"duplicate key id", "k1:" + testKey1Hex + "\nk1:" + testKey2Hex},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseKeyring([]byte(tt.raw))
			if !errors.Is(err, ErrInvalidKeyring) {
				t.Fatalf("expected ErrInvalidKeyring, got %v", err)
			}
			if strings.Contains(err.Error(), secretSample) || strings.Contains(err.Error(), badHexSample) ||
				strings.Contains(err.Error(), testKey1Hex) || strings.Contains(err.Error(), testKey2Hex) {
				t.Fatalf("ParseKeyring error leaked key material: %v", err)
			}
		})
	}
}

func TestScopeValidation(t *testing.T) {
	kr, err := ParseKeyring([]byte("k1:" + testKey1Hex))
	if err != nil {
		t.Fatal(err)
	}
	enc, err := NewEnvelopeEncrypter(kr)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name  string
		scope Scope
	}{
		{"invalid owner type", Scope{OwnerType: "project", OwnerID: "a", Table: "t", Column: "c", RecordID: testUUID1}},
		{"empty owner id", Scope{OwnerType: OwnerTypeOrg, OwnerID: "", Table: "t", Column: "c", RecordID: testUUID1}},
		{"empty table", Scope{OwnerType: OwnerTypeOrg, OwnerID: "a", Table: "", Column: "c", RecordID: testUUID1}},
		{"empty column", Scope{OwnerType: OwnerTypeOrg, OwnerID: "a", Table: "t", Column: "", RecordID: testUUID1}},
		{"non-uuid record id", Scope{OwnerType: OwnerTypeOrg, OwnerID: "a", Table: "t", Column: "c", RecordID: "not-a-uuid"}},
		{"empty record id", Scope{OwnerType: OwnerTypeUser, OwnerID: "a", Table: "users", Column: "mfa_secret", RecordID: ""}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := enc.Encrypt(tt.scope, []byte("secret")); !errors.Is(err, ErrInvalidScope) {
				t.Fatalf("Encrypt() err = %v, want ErrInvalidScope", err)
			}
			if _, err := enc.Decrypt(tt.scope, []byte("anything")); !errors.Is(err, ErrInvalidScope) {
				t.Fatalf("Decrypt() err = %v, want ErrInvalidScope", err)
			}
		})
	}
}

func TestEncryptDecryptRoundTripAndConfidentiality(t *testing.T) {
	kr, err := ParseKeyring([]byte("k1:" + testKey1Hex))
	if err != nil {
		t.Fatal(err)
	}
	enc, err := NewEnvelopeEncrypter(kr)
	if err != nil {
		t.Fatal(err)
	}

	scope := testScope()
	payloads := [][]byte{
		{},
		[]byte("+244923456789"),
		bytes.Repeat([]byte("sensitive-totp-or-webhook-secret-"), 200),
	}

	for _, pt := range payloads {
		env1, err := enc.Encrypt(scope, pt)
		if err != nil {
			t.Fatalf("Encrypt() error = %v", err)
		}
		env2, err := enc.Encrypt(scope, pt)
		if err != nil {
			t.Fatalf("second Encrypt() error = %v", err)
		}
		if bytes.Equal(env1, env2) {
			t.Fatalf("two encryptions of same plaintext produced identical envelopes (nonce/DEK reuse)")
		}

		// Envelope must not contain plaintext in clear.
		if len(pt) > 0 && bytes.Contains(env1, pt) {
			t.Fatalf("envelope contains plaintext in clear")
		}

		// Unwrap DEK directly and verify the raw DEK bytes do not appear in clear in envelope.
		parsed, ok := parseEnvelope(env1)
		if !ok {
			t.Fatalf("parseEnvelope failed on valid envelope")
		}
		dek, err := kr.ciphers["k1"].Open(nil, parsed.dekNonce, parsed.wrappedDEK, scope.encodeAAD())
		if err != nil {
			t.Fatalf("unwrap DEK: %v", err)
		}
		if bytes.Contains(env1, dek) {
			t.Fatalf("envelope contains raw DEK in clear")
		}
		// Raw KEK bytes must also never appear in envelope.
		kekBytes, _ := hex.DecodeString(testKey1Hex)
		if bytes.Contains(env1, kekBytes) {
			t.Fatalf("envelope contains raw KEK in clear")
		}

		got, err := enc.Decrypt(scope, env1)
		if err != nil {
			t.Fatalf("Decrypt() error = %v", err)
		}
		if !bytes.Equal(got, pt) {
			t.Fatalf("decrypted payload mismatch: got %q, want %q", got, pt)
		}
	}
}

func TestDecryptRejectsWrongAADAndTampering(t *testing.T) {
	kr, err := ParseKeyring([]byte("k1:" + testKey1Hex))
	if err != nil {
		t.Fatal(err)
	}
	enc, err := NewEnvelopeEncrypter(kr)
	if err != nil {
		t.Fatal(err)
	}

	scope := testScope()
	env, err := enc.Encrypt(scope, []byte("top-secret-token"))
	if err != nil {
		t.Fatal(err)
	}

	t.Run("wrong AAD fields all return generic ErrDecrypt", func(t *testing.T) {
		wrongScopes := []struct {
			name  string
			scope Scope
		}{
			{"different owner type", Scope{OwnerType: OwnerTypeUser, OwnerID: scope.OwnerID, Table: scope.Table, Column: scope.Column, RecordID: scope.RecordID}},
			{"different org/owner id", Scope{OwnerType: scope.OwnerType, OwnerID: "org-other", Table: scope.Table, Column: scope.Column, RecordID: scope.RecordID}},
			{"different table", Scope{OwnerType: scope.OwnerType, OwnerID: scope.OwnerID, Table: "collectors", Column: scope.Column, RecordID: scope.RecordID}},
			{"different column", Scope{OwnerType: scope.OwnerType, OwnerID: scope.OwnerID, Table: scope.Table, Column: "other_col", RecordID: scope.RecordID}},
			{"different record id (same tenant)", Scope{OwnerType: scope.OwnerType, OwnerID: scope.OwnerID, Table: scope.Table, Column: scope.Column, RecordID: testUUID2}},
		}
		for _, tt := range wrongScopes {
			t.Run(tt.name, func(t *testing.T) {
				if _, err := enc.Decrypt(tt.scope, env); !errors.Is(err, ErrDecrypt) {
					t.Fatalf("Decrypt(%s) err = %v, want ErrDecrypt", tt.name, err)
				}
			})
		}
	})

	t.Run("single bit flip anywhere in envelope returns ErrDecrypt", func(t *testing.T) {
		for pos := range len(env) {
			tampered := append([]byte(nil), env...)
			tampered[pos] ^= 0x01
			if _, err := enc.Decrypt(scope, tampered); !errors.Is(err, ErrDecrypt) {
				t.Fatalf("bit flip at offset %d succeeded or returned wrong error: %v", pos, err)
			}
		}
	})
}

func TestKeyRotationAndRewrap(t *testing.T) {
	scope := testScope()
	plaintext := []byte("bot-token-xyz-123")

	kr1, err := ParseKeyring([]byte("k1:" + testKey1Hex))
	if err != nil {
		t.Fatal(err)
	}
	enc1, err := NewEnvelopeEncrypter(kr1)
	if err != nil {
		t.Fatal(err)
	}
	envK1, err := enc1.Encrypt(scope, plaintext)
	if err != nil {
		t.Fatal(err)
	}

	// Rotate keyring to [k2, k1].
	kr21, err := ParseKeyring([]byte("k2:" + testKey2Hex + "\nk1:" + testKey1Hex))
	if err != nil {
		t.Fatal(err)
	}
	enc21, err := NewEnvelopeEncrypter(kr21)
	if err != nil {
		t.Fatal(err)
	}

	// Old envelope still decrypts under [k2, k1].
	got, err := enc21.Decrypt(scope, envK1)
	if err != nil || !bytes.Equal(got, plaintext) {
		t.Fatalf("Decrypt with rotated keyring failed: got=%q err=%v", got, err)
	}

	// Rewrap moves DEK from k1 to k2.
	envK2, changed, err := enc21.Rewrap(scope, envK1)
	if err != nil || !changed {
		t.Fatalf("Rewrap(k1->k2) changed=%v err=%v", changed, err)
	}
	// Second Rewrap is a no-op (already on active key k2).
	_, changedAgain, err := enc21.Rewrap(scope, envK2)
	if err != nil || changedAgain {
		t.Fatalf("second Rewrap should be unchanged: changed=%v err=%v", changedAgain, err)
	}

	// Drop k1 from keyring: k2-only keyring decrypts re-wrapped envelope, rejects k1 envelope with ErrDecrypt.
	kr2Only, err := ParseKeyring([]byte("k2:" + testKey2Hex))
	if err != nil {
		t.Fatal(err)
	}
	enc2Only, err := NewEnvelopeEncrypter(kr2Only)
	if err != nil {
		t.Fatal(err)
	}
	got2, err := enc2Only.Decrypt(scope, envK2)
	if err != nil || !bytes.Equal(got2, plaintext) {
		t.Fatalf("Decrypt(envK2) with k2-only failed: got=%q err=%v", got2, err)
	}
	if _, err := enc2Only.Decrypt(scope, envK1); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("Decrypt(envK1) with k2-only err = %v, want ErrDecrypt", err)
	}
}

func FuzzDecrypt(f *testing.F) {
	kr, err := ParseKeyring([]byte("k1:" + testKey1Hex))
	if err != nil {
		f.Fatal(err)
	}
	enc, err := NewEnvelopeEncrypter(kr)
	if err != nil {
		f.Fatal(err)
	}
	scope := testScope()
	validEnv, err := enc.Encrypt(scope, []byte("seed-plaintext"))
	if err != nil {
		f.Fatal(err)
	}

	// Seed corpus covering empty, truncated, wrong-version, and valid envelopes.
	f.Add([]byte{})
	f.Add([]byte{0x01})
	f.Add([]byte{0x02, 0x02, 'k', '1'})
	f.Add([]byte{0x01, 0x00})
	f.Add([]byte{0x01, 0xff, 'k', '1'})
	f.Add(validEnv[:len(validEnv)/2])
	f.Add(validEnv)

	f.Fuzz(func(t *testing.T, data []byte) {
		_, err := enc.Decrypt(scope, data)
		if err != nil && !errors.Is(err, ErrDecrypt) {
			t.Fatalf("Decrypt returned non-ErrDecrypt error: %v", err)
		}
	})
}
