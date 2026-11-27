package queue

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/Yhanko/vigia/internal/platform/httpserver"
)

// RedisIdempotencyStore implements httpserver.IdempotencyStore backed by Redis
// using atomic SET NX locking for in-flight requests and 24h TTL on completion (CTO #32).
type RedisIdempotencyStore struct {
	client *redis.Client
}

// NewRedisIdempotencyStore wraps a *redis.Client as an IdempotencyStore.
func NewRedisIdempotencyStore(client *redis.Client) (*RedisIdempotencyStore, error) {
	if client == nil {
		return nil, errors.New("queue: redis client is required")
	}
	return &RedisIdempotencyStore{client: client}, nil
}

func (s *RedisIdempotencyStore) Acquire(ctx context.Context, key, bodyHash string, lockTTL time.Duration) (*httpserver.IdempotencyRecord, bool, error) {
	placeholder, err := httpserver.MarshalIdempotencyRecord(httpserver.IdempotencyRecord{
		InProgress: true,
		BodyHash:   bodyHash,
	})
	if err != nil {
		return nil, false, fmt.Errorf("marshal idempotency lock: %w", err)
	}

	acquired, err := s.client.SetNX(ctx, key, placeholder, lockTTL).Result()
	if err != nil {
		return nil, false, fmt.Errorf("redis idempotency setnx: %w", err)
	}
	if acquired {
		return nil, false, nil
	}

	raw, err := s.client.Get(ctx, key).Bytes()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			// Expired between SetNX and Get; let caller proceed without cache collision.
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("redis idempotency get: %w", err)
	}
	rec, err := httpserver.UnmarshalIdempotencyRecord(raw)
	if err != nil {
		return nil, false, fmt.Errorf("unmarshal idempotency record: %w", err)
	}
	if rec.InProgress {
		return nil, true, nil
	}
	return &rec, false, nil
}

func (s *RedisIdempotencyStore) Complete(ctx context.Context, key string, rec httpserver.IdempotencyRecord, ttl time.Duration) error {
	rec.InProgress = false
	raw, err := httpserver.MarshalIdempotencyRecord(rec)
	if err != nil {
		return fmt.Errorf("marshal idempotency record: %w", err)
	}
	if err := s.client.Set(ctx, key, raw, ttl).Err(); err != nil {
		return fmt.Errorf("redis idempotency set: %w", err)
	}
	return nil
}

func (s *RedisIdempotencyStore) Release(ctx context.Context, key string) error {
	return s.client.Del(ctx, key).Err()
}
