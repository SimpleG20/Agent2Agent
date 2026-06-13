// Package storage provides data access abstractions for Key Guard,
// including revocation checks, nonce deduplication, and budget tracking.
package storage

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// DefaultRedisTimeout is the maximum time for Redis operations.
const DefaultRedisTimeout = 100 * time.Millisecond

// RedisClient wraps go-redis with a strict timeout.
type RedisClient struct {
	client  *redis.Client
	timeout time.Duration
}

// NewRedisClient creates a new Redis client with the given URL and timeout.
// If timeout is zero, DefaultRedisTimeout (100ms) is used.
func NewRedisClient(redisURL string, timeout time.Duration) (*RedisClient, error) {
	if redisURL == "" {
		return nil, fmt.Errorf("redis URL cannot be empty")
	}
	opts, err := redis.ParseURL(redisURL)
	if err != nil {
		return nil, fmt.Errorf("invalid redis URL %q: %w", redactedURL(redisURL), err)
	}
	if timeout <= 0 {
		timeout = DefaultRedisTimeout
	}
	rdb := redis.NewClient(opts)
	return &RedisClient{client: rdb, timeout: timeout}, nil
}

// Ping checks connectivity to Redis.
func (rc *RedisClient) Ping(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, rc.timeout)
	defer cancel()
	return rc.client.Ping(ctx).Err()
}

// Get returns the value for a key. Returns redis.Nil if not found.
func (rc *RedisClient) Get(ctx context.Context, key string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, rc.timeout)
	defer cancel()
	return rc.client.Get(ctx, key).Result()
}

// Set sets a key with value and TTL.
func (rc *RedisClient) Set(ctx context.Context, key, value string, ttl time.Duration) error {
	ctx, cancel := context.WithTimeout(ctx, rc.timeout)
	defer cancel()
	return rc.client.Set(ctx, key, value, ttl).Err()
}

// Del deletes one or more keys.
func (rc *RedisClient) Del(ctx context.Context, keys ...string) error {
	ctx, cancel := context.WithTimeout(ctx, rc.timeout)
	defer cancel()
	return rc.client.Del(ctx, keys...).Err()
}

// Exists checks if a key exists.
func (rc *RedisClient) Exists(ctx context.Context, key string) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, rc.timeout)
	defer cancel()
	n, err := rc.client.Exists(ctx, key).Result()
	return n > 0, err
}

// Incr increments a key and returns the new value.
func (rc *RedisClient) Incr(ctx context.Context, key string) (int64, error) {
	ctx, cancel := context.WithTimeout(ctx, rc.timeout)
	defer cancel()
	return rc.client.Incr(ctx, key).Result()
}

// Expire sets a TTL on a key.
func (rc *RedisClient) Expire(ctx context.Context, key string, ttl time.Duration) error {
	ctx, cancel := context.WithTimeout(ctx, rc.timeout)
	defer cancel()
	return rc.client.Expire(ctx, key, ttl).Err()
}

// TTL returns the remaining time-to-live for a key.
// Returns -1 if the key has no TTL, -2 if the key does not exist.
func (rc *RedisClient) TTL(ctx context.Context, key string) (time.Duration, error) {
	ctx, cancel := context.WithTimeout(ctx, rc.timeout)
	defer cancel()
	return rc.client.TTL(ctx, key).Result()
}

// Scan iterates over keys matching pattern using SCAN (non-blocking).
// Returns up to count keys per cursor iteration. Use a small count to avoid
// blocking Redis on large keyspaces.
func (rc *RedisClient) Scan(ctx context.Context, pattern string, count int64) ([]string, error) {
	ctx, cancel := context.WithTimeout(ctx, rc.timeout*5) // scan can be longer
	defer cancel()
	if count <= 0 {
		count = 100
	}
	var (
		cursor uint64
		keys   []string
	)
	for {
		batch, next, err := rc.client.Scan(ctx, cursor, pattern, count).Result()
		if err != nil {
			return keys, err
		}
		keys = append(keys, batch...)
		if next == 0 {
			break
		}
		cursor = next
	}
	return keys, nil
}

// Close closes the Redis connection.
func (rc *RedisClient) Close() error {
	return rc.client.Close()
}

// redactedURL returns the URL with password masked for logging.
func redactedURL(u string) string {
	opts, err := redis.ParseURL(u)
	if err != nil {
		return "<invalid>"
	}
	// Keep everything except password
	if opts.Password == "" {
		return u
	}
	return fmt.Sprintf("redis://%s@%s/", opts.Username, opts.Addr)
}
