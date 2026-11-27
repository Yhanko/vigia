package password

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestHasherRoundTripAndTamperDetection(t *testing.T) {
	h, err := NewHasher(Options{})
	if err != nil {
		t.Fatalf("NewHasher() error = %v", err)
	}
	ctx := context.Background()

	pass := "correct-horse-battery-staple-2026"
	encoded, err := h.Hash(ctx, pass)
	if err != nil {
		t.Fatalf("Hash() error = %v", err)
	}
	if !strings.HasPrefix(encoded, "$argon2id$v=19$m=19456,t=2,p=1$") {
		t.Fatalf("unexpected PHC prefix: %q", encoded)
	}

	ok, err := h.Verify(ctx, pass, encoded)
	if err != nil || !ok {
		t.Fatalf("Verify(correct) = (%v, %v), want (true, nil)", ok, err)
	}

	ok, err = h.Verify(ctx, pass+"!", encoded)
	if err != nil || ok {
		t.Fatalf("Verify(wrong) = (%v, %v), want (false, nil)", ok, err)
	}

	// Tamper last character of the encoded hash digest.
	last := encoded[len(encoded)-1]
	replacement := byte('A')
	if last == 'A' {
		replacement = 'B'
	}
	tampered := encoded[:len(encoded)-1] + string(replacement)
	ok, err = h.Verify(ctx, pass, tampered)
	if err != nil || ok {
		t.Fatalf("Verify(tampered) = (%v, %v), want (false, nil)", ok, err)
	}

	if h.NeedsRehash(encoded) {
		t.Fatal("NeedsRehash() = true for freshly hashed password with current params")
	}
}

func TestHasherNeedsRehash(t *testing.T) {
	oldHasher, err := NewHasher(Options{
		Params: Params{
			MemoryKiB:   8192,
			Iterations:  1,
			Parallelism: 1,
			SaltBytes:   16,
			KeyBytes:    32,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	currentHasher, err := NewHasher(Options{})
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	encoded, err := oldHasher.Hash(ctx, "upgrade-me-safely-123")
	if err != nil {
		t.Fatal(err)
	}

	ok, err := currentHasher.Verify(ctx, "upgrade-me-safely-123", encoded)
	if err != nil || !ok {
		t.Fatalf("currentHasher.Verify(oldHash) = (%v, %v), want (true, nil)", ok, err)
	}
	if !currentHasher.NeedsRehash(encoded) {
		t.Fatal("NeedsRehash() = false for hash with older parameters, want true")
	}
	if currentHasher.NeedsRehash("not-a-valid-phc") {
		t.Fatal("NeedsRehash() = true for malformed string, want false")
	}
}

func TestHasherDummyVerify(t *testing.T) {
	h, err := NewHasher(Options{})
	if err != nil {
		t.Fatal(err)
	}
	if err := h.DummyVerify(context.Background()); err != nil {
		t.Fatalf("DummyVerify() error = %v", err)
	}
}

func TestHasherMalformedPHC(t *testing.T) {
	h, err := NewHasher(Options{})
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name string
		phc  string
	}{
		{"empty", ""},
		{"wrong algorithm", "$argon2i$v=19$m=19456,t=2,p=1$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"},
		{"wrong version", "$argon2id$v=18$m=19456,t=2,p=1$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"},
		{"missing segments", "$argon2id$v=19$m=19456,t=2,p=1$AAAAAAAAAAAAAAAAAAAAAA"},
		{"bad params order", "$argon2id$v=19$t=2,m=19456,p=1$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"},
		{"zero memory", "$argon2id$v=19$m=0,t=2,p=1$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"},
		{"excessive memory", "$argon2id$v=19$m=99999999,t=2,p=1$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"},
		{"invalid salt base64", "$argon2id$v=19$m=19456,t=2,p=1$!!!not-b64!!!$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"},
		{"salt too short", "$argon2id$v=19$m=19456,t=2,p=1$AAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"},
		{"key too short", "$argon2id$v=19$m=19456,t=2,p=1$AAAAAAAAAAAAAAAAAAAAAA$AAAA"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ok, err := h.Verify(context.Background(), "any-password", tc.phc)
			if ok || !errors.Is(err, ErrInvalidHash) {
				t.Fatalf("Verify(%q) = (%v, %v), want (false, ErrInvalidHash)", tc.phc, ok, err)
			}
		})
	}
}

func TestHasherSemaphoreSaturation(t *testing.T) {
	h, err := NewHasher(Options{
		MaxConcurrent:  2,
		AcquireTimeout: 25 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Manually fill both semaphore slots to simulate 100% saturation deterministically.
	h.sem <- struct{}{}
	h.sem <- struct{}{}
	defer func() {
		<-h.sem
		<-h.sem
	}()

	if _, err := h.Hash(context.Background(), "saturated-hash"); !errors.Is(err, ErrHasherBusy) {
		t.Fatalf("Hash() when saturated = %v, want ErrHasherBusy", err)
	}
	if err := h.DummyVerify(context.Background()); !errors.Is(err, ErrHasherBusy) {
		t.Fatalf("DummyVerify() when saturated = %v, want ErrHasherBusy", err)
	}
}

func BenchmarkHash(b *testing.B) {
	h, err := NewHasher(Options{})
	if err != nil {
		b.Fatal(err)
	}
	ctx := context.Background()
	b.ResetTimer()
	for b.Loop() {
		if _, err := h.Hash(ctx, "benchmark-password-123456"); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVerify(b *testing.B) {
	h, err := NewHasher(Options{})
	if err != nil {
		b.Fatal(err)
	}
	ctx := context.Background()
	encoded, err := h.Hash(ctx, "benchmark-password-123456")
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for b.Loop() {
		ok, err := h.Verify(ctx, "benchmark-password-123456", encoded)
		if err != nil || !ok {
			b.Fatalf("Verify failed: ok=%v err=%v", ok, err)
		}
	}
}
