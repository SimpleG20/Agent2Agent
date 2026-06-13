package storage

import (
	"sync"
	"time"
)

const (
	// DefaultNonceTTL is how long a nonce is remembered for replay protection.
	DefaultNonceTTL = 5 * time.Minute

	// cleanupInterval is how often expired nonces are swept.
	cleanupInterval = 1 * time.Minute
)

// nonceEntry stores a nonce with its expiry time.
type nonceEntry struct {
	nonce     string
	expiresAt time.Time
}

func (e *nonceEntry) isExpired() bool {
	return time.Now().After(e.expiresAt)
}

// NonceStore provides replay protection by remembering seen nonces.
// Safe for concurrent use via sync.Map.
type NonceStore struct {
	mu              sync.Mutex
	nonces          map[string]*nonceEntry
	ttl             time.Duration
	cleanupInterval time.Duration
	done            chan struct{}
	started         bool
}

// NewNonceStore creates a NonceStore with the given TTL.
// If ttl is zero, DefaultNonceTTL (5 min) is used.
// The cleanup goroutine runs every minute.
func NewNonceStore(ttl time.Duration) *NonceStore {
	if ttl <= 0 {
		ttl = DefaultNonceTTL
	}
	ns := &NonceStore{
		nonces:          make(map[string]*nonceEntry),
		ttl:             ttl,
		cleanupInterval: cleanupInterval,
		done:            make(chan struct{}),
	}
	return ns
}

// NewNonceStoreWithCleanup creates a NonceStore with configurable TTL and cleanup interval.
func NewNonceStoreWithCleanup(ttl, cleanupInterval time.Duration) *NonceStore {
	if ttl <= 0 {
		ttl = DefaultNonceTTL
	}
	if cleanupInterval <= 0 {
		cleanupInterval = 1 * time.Minute
	}
	ns := &NonceStore{
		nonces:          make(map[string]*nonceEntry),
		ttl:             ttl,
		cleanupInterval: cleanupInterval,
		done:            make(chan struct{}),
	}
	return ns
}

// Start begins the background cleanup goroutine.
func (ns *NonceStore) Start() {
	ns.mu.Lock()
	defer ns.mu.Unlock()
	if ns.started {
		return
	}
	ns.started = true
	go ns.cleanupLoop()
}

// Stop terminates the background cleanup goroutine.
func (ns *NonceStore) Stop() {
	ns.mu.Lock()
	defer ns.mu.Unlock()
	if !ns.started {
		return
	}
	close(ns.done)
	ns.started = false
}

// CheckAndSet atomically checks if a nonce exists and stores it if not.
// Returns true if the nonce was accepted (first time seen).
// Returns false if the nonce was already seen (replay detected).
func (ns *NonceStore) CheckAndSet(nonce string) bool {
	ns.mu.Lock()
	defer ns.mu.Unlock()

	// Check existing
	if entry, exists := ns.nonces[nonce]; exists {
		if !entry.isExpired() {
			return false // replay detected
		}
		// Expired entry — treat as new
	}

	// Store with TTL
	ns.nonces[nonce] = &nonceEntry{
		nonce:     nonce,
		expiresAt: time.Now().Add(ns.ttl),
	}
	return true
}

// cleanupLoop periodically removes expired nonces.
func (ns *NonceStore) cleanupLoop() {
	ticker := time.NewTicker(ns.cleanupInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			ns.purgeExpired()
		case <-ns.done:
			return
		}
	}
}

// purgeExpired removes all expired nonces from the map.
func (ns *NonceStore) purgeExpired() {
	ns.mu.Lock()
	defer ns.mu.Unlock()
	now := time.Now()
	for k, v := range ns.nonces {
		if now.After(v.expiresAt) {
			delete(ns.nonces, k)
		}
	}
}

// Len returns the current number of nonces (for testing/metrics).
func (ns *NonceStore) Len() int {
	ns.mu.Lock()
	defer ns.mu.Unlock()
	return len(ns.nonces)
}
