// Package queue provides Redis connectivity for queues, distributed locks,
// deduplication, and rate limiting.
package queue

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// NewRedisClient creates a Redis client with explicit timeouts and verifies
// connectivity with PING.
func NewRedisClient(ctx context.Context, addr, password string) (*redis.Client, error) {
	if addr == "" {
		return nil, fmt.Errorf("REDIS_ADDR is required")
	}

	client := redis.NewClient(&redis.Options{
		Addr:         addr,
		Password:     password,
		DialTimeout:  5 * time.Second,
		ReadTimeout:  3 * time.Second,
		WriteTimeout: 3 * time.Second,
	})

	pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := client.Ping(pingCtx).Err(); err != nil {
		_ = client.Close()
		return nil, fmt.Errorf("ping redis: %w", err)
	}

	return client, nil
}
