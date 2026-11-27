// Package ratelimit implements an atomic Redis sliding-window rate limiter
// (via Lua) and HTTP middleware returning standard RateLimit-* / Retry-After
// headers and the API error envelope (ADR-005, business-defaults.md §4).
package ratelimit

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/Yhanko/vigia/internal/platform/clock"
)

const keyPrefix = "rl:"

// Result reports the outcome of a single rate-limit evaluation.
type Result struct {
	Allowed    bool
	Limit      int
	Remaining  int
	ResetAfter time.Duration
	RetryAfter time.Duration
}

// Limiter evaluates sliding-window rate limits for arbitrary keys.
type Limiter interface {
	// Allow checks the limit and records the attempt if allowed.
	Allow(ctx context.Context, key string, limit int, window time.Duration) (Result, error)
	// Peek checks whether key is currently under limit without recording an attempt.
	Peek(ctx context.Context, key string, limit int, window time.Duration) (Result, error)
	// Reset clears all recorded attempts for key (e.g. after a successful login).
	Reset(ctx context.Context, key string) error
}

// slidingWindowScript atomically handles allow, peek, and reset operations on
// a Redis sorted-set sliding window (CTO #23).
//
// KEYS[1] = sorted set key
// ARGV[1] = mode ("allow" | "peek" | "reset")
// ARGV[2] = now (unix ms)
// ARGV[3] = window (ms)
// ARGV[4] = limit (int)
// ARGV[5] = unique member id (used for "allow")
//
// Returns: {allowed (0|1), remaining, reset_after_ms, retry_after_ms}
var slidingWindowScript = redis.NewScript(`
local key = KEYS[1]
local mode = ARGV[1]

if mode == 'reset' then
	redis.call('DEL', key)
	return {1, 0, 0, 0}
end

local now = tonumber(ARGV[2])
local window = tonumber(ARGV[3])
local limit = tonumber(ARGV[4])
local member = ARGV[5]

local cutoff = now - window
redis.call('ZREMRANGEBYSCORE', key, '-inf', cutoff)

local count = redis.call('ZCARD', key)
if count < limit then
	if mode == 'allow' then
		redis.call('ZADD', key, now, member)
		redis.call('PEXPIRE', key, window)
		count = count + 1
	end
	local oldest = redis.call('ZRANGE', key, 0, 0, 'WITHSCORES')
	local reset_ms = window
	if #oldest >= 2 then
		reset_ms = math.max(1, (tonumber(oldest[2]) + window) - now)
	end
	return {1, math.max(0, limit - count), reset_ms, 0}
end

local oldest = redis.call('ZRANGE', key, 0, 0, 'WITHSCORES')
local retry_ms = window
if #oldest >= 2 then
	retry_ms = math.max(1, (tonumber(oldest[2]) + window) - now)
end
redis.call('PEXPIRE', key, window)
return {0, 0, retry_ms, retry_ms}
`)

// RedisLimiter implements Limiter using an atomic Lua sliding window in Redis.
type RedisLimiter struct {
	client redis.UniversalClient
	clk    clock.Clock
	seq    atomic.Uint64
}

// NewRedisLimiter creates a RedisLimiter. If clk is nil, clock.System{} is used.
func NewRedisLimiter(client redis.UniversalClient, clk clock.Clock) (*RedisLimiter, error) {
	if client == nil {
		return nil, errors.New("ratelimit: redis client is required")
	}
	if clk == nil {
		clk = clock.System{}
	}
	return &RedisLimiter{
		client: client,
		clk:    clk,
	}, nil
}

// Allow evaluates whether a request for key is within limit over window and
// records the attempt when allowed.
func (l *RedisLimiter) Allow(ctx context.Context, key string, limit int, window time.Duration) (Result, error) {
	return l.eval(ctx, "allow", key, limit, window)
}

// Peek evaluates whether key is currently within limit over window without
// recording an attempt.
func (l *RedisLimiter) Peek(ctx context.Context, key string, limit int, window time.Duration) (Result, error) {
	return l.eval(ctx, "peek", key, limit, window)
}

// Reset removes all recorded attempts for key.
func (l *RedisLimiter) Reset(ctx context.Context, key string) error {
	if key == "" {
		return errors.New("ratelimit: key is required")
	}
	if _, err := slidingWindowScript.Run(ctx, l.client, []string{keyPrefix + key}, "reset", 0, 0, 0, "").Int64Slice(); err != nil {
		return fmt.Errorf("ratelimit: reset lua: %w", err)
	}
	return nil
}

func (l *RedisLimiter) eval(ctx context.Context, mode, key string, limit int, window time.Duration) (Result, error) {
	if key == "" || limit <= 0 || window <= 0 {
		return Result{}, errors.New("ratelimit: key, positive limit, and positive window are required")
	}

	nowMs := l.clk.Now().UnixMilli()
	windowMs := window.Milliseconds()
	if windowMs <= 0 {
		windowMs = 1
	}
	member := strconv.FormatInt(nowMs, 10) + ":" + strconv.FormatUint(l.seq.Add(1), 10)

	raw, err := slidingWindowScript.Run(ctx, l.client, []string{keyPrefix + key}, mode, nowMs, windowMs, limit, member).Int64Slice()
	if err != nil {
		return Result{}, fmt.Errorf("ratelimit: eval lua: %w", err)
	}
	if len(raw) != 4 {
		return Result{}, fmt.Errorf("ratelimit: unexpected lua result length %d", len(raw))
	}

	return Result{
		Allowed:    raw[0] == 1,
		Limit:      limit,
		Remaining:  int(raw[1]),
		ResetAfter: time.Duration(raw[2]) * time.Millisecond,
		RetryAfter: time.Duration(raw[3]) * time.Millisecond,
	}, nil
}

// HashIdentifier derives a non-reversible, PII-free Redis key component from
// an identifier (such as a normalized email) using HMAC-SHA256.
func HashIdentifier(secret []byte, identifier string) string {
	normalized := strings.ToLower(strings.TrimSpace(identifier))
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte("rl:"))
	_, _ = mac.Write([]byte(normalized))
	return hex.EncodeToString(mac.Sum(nil))
}
