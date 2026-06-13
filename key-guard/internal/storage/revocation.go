package storage

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// RevocationStatus represents the status of a credential revocation.
type RevocationStatus string

const (
	StatusActive    RevocationStatus = "active"
	StatusRevoked   RevocationStatus = "revoked"
	StatusSuspended RevocationStatus = "suspended"
)

const (
	// RevocationKeyPrefix is the Redis key prefix for revocation entries.
	RevocationKeyPrefix = "revocation:"

	// DefaultRevocationTTL is how long revocation entries live in Redis.
	DefaultRevocationTTL = 5 * time.Minute

	// CacheTTL is how long we cache revocation status in memory.
	CacheTTL = 10 * time.Second
)

// cacheEntry holds a cached revocation status with its expiry.
type cacheEntry struct {
	status    RevocationStatus
	expiresAt time.Time
}

func (e *cacheEntry) isExpired() bool {
	return time.Now().After(e.expiresAt)
}

// RevocationStore checks credential revocation status with an in-memory cache.
type RevocationStore struct {
	client   *RedisClient
	cache    sync.Map
	cacheTTL time.Duration
	ttl      time.Duration
}

// NewRevocationStore creates a RevocationStore with the given Redis client.
func NewRevocationStore(client *RedisClient) *RevocationStore {
	return &RevocationStore{
		client:   client,
		cacheTTL: CacheTTL,
		ttl:      DefaultRevocationTTL,
	}
}

// NewRevocationStoreWithTTL creates a RevocationStore with custom TTLs.
func NewRevocationStoreWithTTL(client *RedisClient, cacheTTL, revocationTTL time.Duration) *RevocationStore {
	return &RevocationStore{
		client:   client,
		cacheTTL: cacheTTL,
		ttl:      revocationTTL,
	}
}

// revocationKey builds the Redis key for a DID.
func revocationKey(did string) string {
	return RevocationKeyPrefix + did
}

// CheckRevoked checks if a DID has been revoked.
// Returns true if the credential is revoked or suspended.
func (rs *RevocationStore) CheckRevoked(ctx context.Context, did string) (bool, error) {
	// Check in-memory cache first
	status, err := rs.getCached(did)
	if err == nil {
		return status == StatusRevoked || status == StatusSuspended, nil
	}

	// Cache miss or expired — query Redis
	val, err := rs.client.Get(ctx, revocationKey(did))
	if err != nil {
		// Redis error (including key not found) — return as active
		rs.setCached(did, StatusActive)
		return false, nil
	}

	status = RevocationStatus(val)
	rs.setCached(did, status)
	return status == StatusRevoked || status == StatusSuspended, nil
}

// Revoke marks a DID as revoked. It also updates the local cache.
func (rs *RevocationStore) Revoke(ctx context.Context, did string) error {
	return rs.revokeWithStatus(ctx, did, StatusRevoked)
}

// Suspend marks a DID as suspended with a shorter TTL.
func (rs *RevocationStore) Suspend(ctx context.Context, did string) error {
	return rs.revokeWithStatus(ctx, did, StatusSuspended)
}

// RevokeWithTTL marks a DID with the given status and a custom TTL (seconds).
// If ttlSeconds <= 0, the default store TTL is used.
func (rs *RevocationStore) RevokeWithTTL(ctx context.Context, did string, status RevocationStatus, ttlSeconds int) error {
	key := revocationKey(did)
	ttl := rs.ttl
	if ttlSeconds > 0 {
		ttl = time.Duration(ttlSeconds) * time.Second
	}
	if err := rs.client.Set(ctx, key, string(status), ttl); err != nil {
		return fmt.Errorf("revoke %s: %w", did, err)
	}
	rs.setCached(did, status)
	return nil
}

// RevocationEntry is a single revocation record returned by ListRevocations.
type RevocationEntry struct {
	DID    string
	Status RevocationStatus
	TTL    time.Duration
}

// ListRevocations scans Redis for all revocation: keys and returns active entries.
// Uses SCAN (non-blocking) instead of KEYS.
func (rs *RevocationStore) ListRevocations(ctx context.Context) ([]RevocationEntry, error) {
	keys, err := rs.client.Scan(ctx, RevocationKeyPrefix+"*", 100)
	if err != nil {
		return nil, fmt.Errorf("scan revocations: %w", err)
	}
	out := make([]RevocationEntry, 0, len(keys))
	for _, key := range keys {
		// Strip prefix to get the DID
		did := key
		if len(key) > len(RevocationKeyPrefix) {
			did = key[len(RevocationKeyPrefix):]
		}
		val, err := rs.client.Get(ctx, key)
		if err != nil {
			continue
		}
		ttl, err := rs.client.TTL(ctx, key)
		if err != nil || ttl < 0 {
			ttl = rs.ttl
		}
		out = append(out, RevocationEntry{
			DID:    did,
			Status: RevocationStatus(val),
			TTL:    ttl,
		})
	}
	return out, nil
}

// ClearRevocation removes a revocation record for a DID.
func (rs *RevocationStore) ClearRevocation(ctx context.Context, did string) error {
	key := revocationKey(did)
	if err := rs.client.Del(ctx, key); err != nil {
		return fmt.Errorf("clear revocation for %s: %w", did, err)
	}
	rs.cache.Delete(did)
	return nil
}

// revokeWithStatus sets a revocation status with the configured TTL.
func (rs *RevocationStore) revokeWithStatus(ctx context.Context, did string, status RevocationStatus) error {
	key := revocationKey(did)
	if err := rs.client.Set(ctx, key, string(status), rs.ttl); err != nil {
		return fmt.Errorf("revoke %s: %w", did, err)
	}
	rs.setCached(did, status)
	return nil
}

// getCached returns cached status. Returns error if not cached or expired.
func (rs *RevocationStore) getCached(did string) (RevocationStatus, error) {
	val, ok := rs.cache.Load(did)
	if !ok {
		return "", fmt.Errorf("not cached")
	}
	entry := val.(*cacheEntry)
	if entry.isExpired() {
		rs.cache.Delete(did)
		return "", fmt.Errorf("cache expired")
	}
	return entry.status, nil
}

// setCached stores status in the in-memory cache.
func (rs *RevocationStore) setCached(did string, status RevocationStatus) {
	rs.cache.Store(did, &cacheEntry{
		status:    status,
		expiresAt: time.Now().Add(rs.cacheTTL),
	})
}
