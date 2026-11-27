// Package password implements Argon2id password hashing and verification with
// bounded concurrency to prevent CPU/memory DoS inside constrained containers
// (ADR-005 §3.1, docs/decisions/business-defaults.md §1).
package password

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/argon2"
)

// Default Argon2id parameters from ADR-005 §3.1 (OWASP minimum memory profile
// sized for a 256 MiB API container with 4 concurrent hashes <= ~76 MiB RAM).
const (
	DefaultMemoryKiB      uint32 = 19456 // 19 MiB
	DefaultIterations     uint32 = 2
	DefaultParallelism    uint8  = 1
	DefaultSaltBytes      uint32 = 16
	DefaultKeyBytes       uint32 = 32
	DefaultMaxConcurrent         = 4
	DefaultAcquireTimeout        = 250 * time.Millisecond

	// MaxPasswordBytes is a defense-in-depth cap enforced by Hash/Verify before
	// acquiring an Argon2id slot (domain policy separately caps passwords at 128 runes).
	MaxPasswordBytes = 512

	// Bounds for verifying stored PHC hashes so a crafted hash cannot trigger
	// an unbounded memory allocation inside a 256 MiB container (CTO #15).
	maxVerifyMemoryKiB   uint32 = 2 * DefaultMemoryKiB // 38912 KiB (38 MiB)
	maxVerifyIterations  uint32 = 16
	maxVerifyParallelism uint8  = 8
	minSaltBytes                = 8
	maxSaltBytes                = 64
	minKeyBytes                 = 16
	maxKeyBytes                 = 64
)

var (
	// ErrHasherBusy is returned when all Argon2id concurrency slots remain full
	// past the configured acquire timeout. HTTP handlers map this to
	// 503 SERVICE_UNAVAILABLE with Retry-After (ADR-005 §3.1).
	ErrHasherBusy = errors.New("password: argon2id concurrency limit reached")

	// ErrInvalidHash is returned when a stored PHC string is malformed or uses
	// an unsupported algorithm/version/parameter range.
	ErrInvalidHash = errors.New("password: invalid phc argon2id hash")

	// ErrPasswordTooLong is returned when a password exceeds MaxPasswordBytes.
	ErrPasswordTooLong = errors.New("password: exceeds maximum byte length")
)

// Params configures Argon2id cost and output sizes.
type Params struct {
	MemoryKiB   uint32
	Iterations  uint32
	Parallelism uint8
	SaltBytes   uint32
	KeyBytes    uint32
}

// DefaultParams returns the ADR-005 §3.1 Argon2id parameter set.
func DefaultParams() Params {
	return Params{
		MemoryKiB:   DefaultMemoryKiB,
		Iterations:  DefaultIterations,
		Parallelism: DefaultParallelism,
		SaltBytes:   DefaultSaltBytes,
		KeyBytes:    DefaultKeyBytes,
	}
}

// Options configures a Hasher instance. Zero fields use ADR-005 defaults.
type Options struct {
	Params         Params
	MaxConcurrent  int
	AcquireTimeout time.Duration
}

// Hasher performs concurrency-limited Argon2id hashing and verification.
type Hasher struct {
	params         Params
	sem            chan struct{}
	acquireTimeout time.Duration
	dummySalt      []byte
	dummyKey       []byte
}

// NewHasher builds a Hasher with bounded concurrency and a pre-generated dummy
// target for constant-work anti-enumeration checks.
func NewHasher(opts Options) (*Hasher, error) {
	p := opts.Params
	if p == (Params{}) {
		p = DefaultParams()
	}
	if p.MemoryKiB == 0 || p.MemoryKiB > maxVerifyMemoryKiB ||
		p.Iterations == 0 || p.Iterations > maxVerifyIterations ||
		p.Parallelism == 0 || p.Parallelism > maxVerifyParallelism ||
		p.SaltBytes < minSaltBytes || p.SaltBytes > maxSaltBytes ||
		p.KeyBytes < minKeyBytes || p.KeyBytes > maxKeyBytes {
		return nil, errors.New("password: invalid argon2id parameters")
	}

	maxConc := opts.MaxConcurrent
	if maxConc <= 0 {
		maxConc = DefaultMaxConcurrent
	}
	timeout := opts.AcquireTimeout
	if timeout <= 0 {
		timeout = DefaultAcquireTimeout
	}

	dummySalt := make([]byte, p.SaltBytes)
	if _, err := io.ReadFull(rand.Reader, dummySalt); err != nil {
		return nil, fmt.Errorf("password: generate dummy salt: %w", err)
	}
	dummyKey := make([]byte, p.KeyBytes)

	return &Hasher{
		params:         p,
		sem:            make(chan struct{}, maxConc),
		acquireTimeout: timeout,
		dummySalt:      dummySalt,
		dummyKey:       dummyKey,
	}, nil
}

// Hash derives an Argon2id PHC string for password using a fresh CSPRNG salt.
func (h *Hasher) Hash(ctx context.Context, password string) (string, error) {
	if len(password) > MaxPasswordBytes {
		return "", ErrPasswordTooLong
	}
	if err := h.acquire(ctx); err != nil {
		return "", err
	}
	defer h.release()

	salt := make([]byte, h.params.SaltBytes)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return "", fmt.Errorf("password: generate salt: %w", err)
	}

	key := argon2.IDKey(
		[]byte(password),
		salt,
		h.params.Iterations,
		h.params.MemoryKiB,
		h.params.Parallelism,
		h.params.KeyBytes,
	)
	defer clear(key)

	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version,
		h.params.MemoryKiB,
		h.params.Iterations,
		h.params.Parallelism,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key),
	), nil
}

// Verify checks password against a PHC-encoded Argon2id hash using
// constant-time comparison.
func (h *Hasher) Verify(ctx context.Context, password, encodedHash string) (bool, error) {
	if len(password) > MaxPasswordBytes {
		return false, ErrPasswordTooLong
	}
	parsed, err := parsePHC(encodedHash)
	if err != nil {
		return false, err
	}

	if err := h.acquire(ctx); err != nil {
		return false, err
	}
	defer h.release()

	derived := argon2.IDKey(
		[]byte(password),
		parsed.salt,
		parsed.params.Iterations,
		parsed.params.MemoryKiB,
		parsed.params.Parallelism,
		parsed.params.KeyBytes,
	)
	defer clear(derived)

	match := subtle.ConstantTimeCompare(derived, parsed.key) == 1
	return match, nil
}

// DummyVerify performs a full Argon2id derivation with the configured
// parameters (and through the same concurrency semaphore) to keep login timing
// consistent when an email does not exist (ADR-005 §3.1).
func (h *Hasher) DummyVerify(ctx context.Context) error {
	if err := h.acquire(ctx); err != nil {
		return err
	}
	defer h.release()

	derived := argon2.IDKey(
		[]byte("vigia-dummy-password-anti-enumeration"),
		h.dummySalt,
		h.params.Iterations,
		h.params.MemoryKiB,
		h.params.Parallelism,
		h.params.KeyBytes,
	)
	defer clear(derived)

	_ = subtle.ConstantTimeCompare(derived, h.dummyKey)
	return nil
}

// NeedsRehash reports whether a valid PHC hash was generated with parameters
// different from the Hasher's current configuration (enabling transparent
// parameter upgrades on the next successful login).
func (h *Hasher) NeedsRehash(encodedHash string) bool {
	parsed, err := parsePHC(encodedHash)
	if err != nil {
		return false
	}
	return parsed.params != h.params
}

func (h *Hasher) acquire(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case h.sem <- struct{}{}:
		return nil
	default:
	}

	timer := time.NewTimer(h.acquireTimeout)
	defer timer.Stop()

	select {
	case h.sem <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return ErrHasherBusy
	}
}

func (h *Hasher) release() {
	<-h.sem
}

type parsedPHC struct {
	params Params
	salt   []byte
	key    []byte
}

func parsePHC(encoded string) (parsedPHC, error) {
	// Format: $argon2id$v=19$m=19456,t=2,p=1$<salt>$<hash>
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" {
		return parsedPHC{}, ErrInvalidHash
	}

	if !strings.HasPrefix(parts[2], "v=") {
		return parsedPHC{}, ErrInvalidHash
	}
	ver, err := strconv.Atoi(strings.TrimPrefix(parts[2], "v="))
	if err != nil || ver != argon2.Version {
		return parsedPHC{}, ErrInvalidHash
	}

	kv := strings.Split(parts[3], ",")
	if len(kv) != 3 {
		return parsedPHC{}, ErrInvalidHash
	}
	mem, err := parseUintParam(kv[0], "m=")
	if err != nil || mem == 0 || mem > uint64(maxVerifyMemoryKiB) {
		return parsedPHC{}, ErrInvalidHash
	}
	iters, err := parseUintParam(kv[1], "t=")
	if err != nil || iters == 0 || iters > uint64(maxVerifyIterations) {
		return parsedPHC{}, ErrInvalidHash
	}
	par, err := parseUintParam(kv[2], "p=")
	if err != nil || par == 0 || par > uint64(maxVerifyParallelism) {
		return parsedPHC{}, ErrInvalidHash
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil || len(salt) < minSaltBytes || len(salt) > maxSaltBytes {
		return parsedPHC{}, ErrInvalidHash
	}
	key, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil || len(key) < minKeyBytes || len(key) > maxKeyBytes {
		return parsedPHC{}, ErrInvalidHash
	}

	return parsedPHC{
		params: Params{
			MemoryKiB:   uint32(mem),       //nolint:gosec // bounded by maxVerifyMemoryKiB
			Iterations:  uint32(iters),     //nolint:gosec // bounded by maxVerifyIterations
			Parallelism: uint8(par),        //nolint:gosec // bounded by maxVerifyParallelism
			SaltBytes:   uint32(len(salt)), //nolint:gosec // bounded by maxSaltBytes
			KeyBytes:    uint32(len(key)),  //nolint:gosec // bounded by maxKeyBytes
		},
		salt: salt,
		key:  key,
	}, nil
}

func parseUintParam(token, prefix string) (uint64, error) {
	if !strings.HasPrefix(token, prefix) {
		return 0, ErrInvalidHash
	}
	return strconv.ParseUint(strings.TrimPrefix(token, prefix), 10, 32)
}
