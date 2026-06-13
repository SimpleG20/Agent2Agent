package tests

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stumgart/a2a/key-guard/internal/storage"
)

// helperRedis creates a miniredis server and returns a storage.RedisClient connected to it.
func helperRedis(t *testing.T) (*storage.RedisClient, *miniredis.Miniredis) {
	t.Helper()
	srv := miniredis.RunT(t)
	client, err := storage.NewRedisClient("redis://"+srv.Addr(), 100*time.Millisecond)
	if err != nil {
		t.Fatalf("NewRedisClient: %v", err)
	}
	return client, srv
}

// helperStore creates a RevocationStore backed by miniredis.
func helperStore(t *testing.T) (*storage.RevocationStore, *miniredis.Miniredis) {
	t.Helper()
	client, srv := helperRedis(t)
	store := storage.NewRevocationStoreWithTTL(client, time.Second, 5*time.Minute)
	return store, srv
}

func TestRedisClient_Ping(t *testing.T) {
	client, srv := helperRedis(t)
	defer client.Close()

	ctx := context.Background()
	if err := client.Ping(ctx); err != nil {
		t.Fatalf("Ping failed: %v", err)
	}

	srv.Close()
	if err := client.Ping(ctx); err == nil {
		t.Fatal("expected error after closing Redis, got nil")
	}
}

func TestRedisClient_SetGet(t *testing.T) {
	client, _ := helperRedis(t)
	defer client.Close()
	ctx := context.Background()

	err := client.Set(ctx, "test:key", "hello", time.Minute)
	if err != nil {
		t.Fatalf("Set failed: %v", err)
	}

	val, err := client.Get(ctx, "test:key")
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	if val != "hello" {
		t.Fatalf("expected 'hello', got '%s'", val)
	}
}

func TestRedisClient_Get_Missing(t *testing.T) {
	client, _ := helperRedis(t)
	defer client.Close()
	ctx := context.Background()

	val, err := client.Get(ctx, "nonexistent")
	if err != redis.Nil && err != nil {
		t.Fatalf("expected redis.Nil or nil, got %v", err)
	}
	if val != "" {
		t.Fatalf("expected empty string, got '%s'", val)
	}
}

func TestRedisClient_Del(t *testing.T) {
	client, _ := helperRedis(t)
	defer client.Close()
	ctx := context.Background()

	client.Set(ctx, "test:del", "value", time.Minute)
	err := client.Del(ctx, "test:del")
	if err != nil {
		t.Fatalf("Del failed: %v", err)
	}

	exists, err := client.Exists(ctx, "test:del")
	if err != nil {
		t.Fatalf("Exists failed: %v", err)
	}
	if exists {
		t.Fatal("expected key to be deleted")
	}
}

func TestRedisClient_Exists(t *testing.T) {
	client, _ := helperRedis(t)
	defer client.Close()
	ctx := context.Background()

	client.Set(ctx, "test:exists", "val", time.Minute)

	exists, err := client.Exists(ctx, "test:exists")
	if err != nil {
		t.Fatalf("Exists failed: %v", err)
	}
	if !exists {
		t.Fatal("expected key to exist")
	}

	exists, err = client.Exists(ctx, "test:nonexistent")
	if err != nil {
		t.Fatalf("Exists(nonexistent) failed: %v", err)
	}
	if exists {
		t.Fatal("expected key to not exist")
	}
}

func TestRedisClient_Incr(t *testing.T) {
	client, _ := helperRedis(t)
	defer client.Close()
	ctx := context.Background()

	n, err := client.Incr(ctx, "test:counter")
	if err != nil {
		t.Fatalf("Incr failed: %v", err)
	}
	if n != 1 {
		t.Fatalf("expected 1, got %d", n)
	}

	n, err = client.Incr(ctx, "test:counter")
	if err != nil {
		t.Fatalf("Incr #2 failed: %v", err)
	}
	if n != 2 {
		t.Fatalf("expected 2, got %d", n)
	}
}

func TestRedisClient_Expire(t *testing.T) {
	client, srv := helperRedis(t)
	defer client.Close()
	ctx := context.Background()

	client.Set(ctx, "test:exp", "val", 0)
	err := client.Expire(ctx, "test:exp", time.Second)
	if err != nil {
		t.Fatalf("Expire failed: %v", err)
	}

	srv.FastForward(2 * time.Second)

	exists, err := client.Exists(ctx, "test:exp")
	if err != nil {
		t.Fatalf("Exists failed: %v", err)
	}
	if exists {
		t.Fatal("expected key to have expired")
	}
}

// --- RevocationStore Tests ---

func TestRevocationStore_Active(t *testing.T) {
	store, _ := helperStore(t)
	ctx := context.Background()

	revoked, err := store.CheckRevoked(ctx, "did:peer:2.abc123")
	if err != nil {
		t.Fatalf("CheckRevoked failed: %v", err)
	}
	if revoked {
		t.Fatal("expected active (not revoked) for unknown DID")
	}
}

func TestRevocationStore_Revoke(t *testing.T) {
	store, srv := helperStore(t)
	ctx := context.Background()

	dids := []string{
		"did:peer:2.Ez6LSbys",
		"did:peer:2.Ez6LTest123",
	}

	for _, did := range dids {
		err := store.Revoke(ctx, did)
		if err != nil {
			t.Fatalf("Revoke(%q) failed: %v", did, err)
		}

		// Verify Redis has the key
		val, err := srv.Get("revocation:" + did)
		if err != nil {
			t.Fatalf("Redis get failed for %q: %v", did, err)
		}
		if val != "revoked" {
			t.Fatalf("expected 'revoked', got '%s'", val)
		}

		// Verify check returns revoked
		revoked, err := store.CheckRevoked(ctx, did)
		if err != nil {
			t.Fatalf("CheckRevoked(%q) failed: %v", did, err)
		}
		if !revoked {
			t.Fatalf("expected %q to be revoked", did)
		}
	}
}

func TestRevocationStore_Cache(t *testing.T) {
	store, srv := helperStore(t)
	ctx := context.Background()
	did := "did:peer:2.cache-test"

	// Manually insert into Redis (bypass store)
	srv.Set("revocation:"+did, "revoked")

	// First call — should hit Redis
	revoked, err := store.CheckRevoked(ctx, did)
	if err != nil {
		t.Fatalf("CheckRevoked #1: %v", err)
	}
	if !revoked {
		t.Fatal("first call should detect revoked")
	}

	// Delete from Redis to verify cache is used
	srv.Del("revocation:" + did)

	// Second call — should use cache (still revoked)
	revoked, err = store.CheckRevoked(ctx, did)
	if err != nil {
		t.Fatalf("CheckRevoked #2: %v", err)
	}
	if !revoked {
		t.Fatal("second call should use cache and return revoked")
	}
}

func TestRevocationStore_CacheExpiry(t *testing.T) {
	client, srv := helperRedis(t)
	defer client.Close()
	ctx := context.Background()
	did := "did:peer:2.cache-expire"

	// Use a short cache TTL (10ms) so we can test expiry quickly
	store := storage.NewRevocationStoreWithTTL(client, 10*time.Millisecond, 5*time.Minute)

	srv.Set("revocation:"+did, "revoked")

	// Warm the cache
	revoked, err := store.CheckRevoked(ctx, did)
	if err != nil {
		t.Fatalf("CheckRevoked #1: %v", err)
	}
	if !revoked {
		t.Fatal("first call should detect revoked")
	}

	// Delete from Redis
	srv.Del("revocation:" + did)

	// Should still be in cache
	revoked, err = store.CheckRevoked(ctx, did)
	if err != nil {
		t.Fatalf("CheckRevoked #2: %v", err)
	}
	if !revoked {
		t.Fatal("second call should use cache and return revoked")
	}

	// Wait for cache to expire
	time.Sleep(50 * time.Millisecond)

	// Cache expired, Redis has no key — should return active
	revoked, err = store.CheckRevoked(ctx, did)
	if err != nil {
		t.Fatalf("CheckRevoked after expiry: %v", err)
	}
	if revoked {
		t.Fatal("expected not revoked after cache expiry + Redis delete")
	}
}

func TestRevocationStore_Suspend(t *testing.T) {
	store, srv := helperStore(t)
	ctx := context.Background()
	did := "did:peer:2.suspend-test"

	err := store.Suspend(ctx, did)
	if err != nil {
		t.Fatalf("Suspend failed: %v", err)
	}

	val, err := srv.Get("revocation:" + did)
	if err != nil {
		t.Fatalf("Redis get: %v", err)
	}
	if val != "suspended" {
		t.Fatalf("expected 'suspended', got '%s'", val)
	}

	revoked, err := store.CheckRevoked(ctx, did)
	if err != nil {
		t.Fatalf("CheckRevoked failed: %v", err)
	}
	if !revoked {
		t.Fatal("suspended should also return revoked=true")
	}
}

func TestRevocationStore_Clear(t *testing.T) {
	store, srv := helperStore(t)
	ctx := context.Background()
	did := "did:peer:2.clear-test"

	store.Revoke(ctx, did)

	// Verify it's revoked
	revoked, _ := store.CheckRevoked(ctx, did)
	if !revoked {
		t.Fatal("expected revoked before clear")
	}

	// Clear
	err := store.ClearRevocation(ctx, did)
	if err != nil {
		t.Fatalf("ClearRevocation failed: %v", err)
	}

	// Redis should be empty
	_, err = srv.Get("revocation:" + did)
	if err == nil {
		t.Fatal("expected key to be deleted from Redis")
	}

	// Check should return active (cache was also cleared)
	revoked, err = store.CheckRevoked(ctx, did)
	if err != nil {
		t.Fatalf("CheckRevoked after clear: %v", err)
	}
	if revoked {
		t.Fatal("expected active after clear")
	}
}

// --- NonceStore Tests ---

func TestNonceStore_Accept(t *testing.T) {
	ns := storage.NewNonceStore(time.Minute)
	defer ns.Stop()

	if !ns.CheckAndSet("nonce-1") {
		t.Fatal("expected first use to be accepted")
	}
}

func TestNonceStore_Replay(t *testing.T) {
	ns := storage.NewNonceStore(time.Minute)
	defer ns.Stop()

	ns.CheckAndSet("nonce-1")
	if ns.CheckAndSet("nonce-1") {
		t.Fatal("expected replay to be rejected")
	}
}

func TestNonceStore_MultipleNonces(t *testing.T) {
	ns := storage.NewNonceStore(time.Minute)
	defer ns.Stop()

	nonces := []string{"a", "b", "c", "d", "e"}
	for _, n := range nonces {
		if !ns.CheckAndSet(n) {
			t.Fatalf("expected %q to be accepted", n)
		}
	}

	// Replays
	for _, n := range nonces {
		if ns.CheckAndSet(n) {
			t.Fatalf("expected %q replay to be rejected", n)
		}
	}

	if ns.Len() != 5 {
		t.Fatalf("expected 5 nonces, got %d", ns.Len())
	}
}

func TestNonceStore_Expiry(t *testing.T) {
	ns := storage.NewNonceStore(50 * time.Millisecond)
	defer ns.Stop()

	ns.CheckAndSet("expiring-nonce")
	time.Sleep(100 * time.Millisecond)

	// After expiry, same nonce should be accepted again
	if !ns.CheckAndSet("expiring-nonce") {
		t.Fatal("expected expired nonce to be accepted again")
	}
}

func TestNonceStore_Purge(t *testing.T) {
	// Use a short TTL and short cleanup interval so purge runs quickly
	ns := storage.NewNonceStoreWithCleanup(50*time.Millisecond, 20*time.Millisecond)
	ns.Start()
	defer ns.Stop()

	ns.CheckAndSet("purge-me")

	// Wait for cleanup to run (20ms interval, 3 ticks should be enough)
	time.Sleep(100 * time.Millisecond)

	if ns.Len() != 0 {
		t.Fatalf("expected all nonces purged, got %d", ns.Len())
	}
}

func TestNonceStore_Concurrent(t *testing.T) {
	ns := storage.NewNonceStore(time.Minute)
	defer ns.Stop()

	done := make(chan bool)
	n := 50
	for i := range n {
		go func(id int) {
			nonce := "nonce-" + string(rune('a'+id%26))
			ns.CheckAndSet(nonce)
			done <- true
		}(i)
	}
	for range n {
		<-done
	}
	// If we got here without races — test passes
}

func TestNonceStore_DefaultTTL(t *testing.T) {
	ns := storage.NewNonceStore(0)
	defer ns.Stop()

	if ns.Len() != 0 {
		t.Fatal("expected empty store")
	}
}

// --- Edge Cases ---

func TestRevocationStore_EmptyDID(t *testing.T) {
	store, _ := helperStore(t)
	ctx := context.Background()

	revoked, err := store.CheckRevoked(ctx, "")
	if err != nil {
		t.Fatalf("CheckRevoked(empty) failed: %v", err)
	}
	if revoked {
		t.Fatal("empty DID should not be revoked")
	}
}

func TestRevocationStore_RevokeEmptyDID(t *testing.T) {
	store, _ := helperStore(t)
	ctx := context.Background()

	err := store.Revoke(ctx, "")
	if err != nil {
		t.Fatalf("Revoke(empty) should not fail: %v", err)
	}
}
