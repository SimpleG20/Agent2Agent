package rules

import (
	"context"
	"sync"
	"testing"
	"time"
)

// mockRedis implements RedisCmdRunner for testing.
type mockRedis struct {
	mu    sync.Mutex
	store map[string]string
	ttls  map[string]time.Duration
}

func newMockRedis() *mockRedis {
	return &mockRedis{
		store: make(map[string]string),
		ttls:  make(map[string]time.Duration),
	}
}

func (m *mockRedis) Set(ctx context.Context, key, value string, ttl time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.store[key] = value
	m.ttls[key] = ttl
	return nil
}

func (m *mockRedis) Ping(ctx context.Context) error {
	return nil
}

func TestRevocationPublisher_Publish(t *testing.T) {
	mr := newMockRedis()
	pub := NewRevocationPublisher(mr, 5*time.Minute)
	ctx := context.Background()

	result := RuleResult{
		RuleName: "injection",
		Score:    10,
		AgentDID: "did:peer:alpha",
	}

	if err := pub.Publish(ctx, result); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	key := "revocation:did:peer:alpha"
	if mr.store[key] != "revoked" {
		t.Errorf("expected 'revoked', got %q", mr.store[key])
	}
	if mr.ttls[key] != 5*time.Minute {
		t.Errorf("expected TTL 5m, got %v", mr.ttls[key])
	}
}

func TestRevocationPublisher_EmptyDID(t *testing.T) {
	mr := newMockRedis()
	pub := NewRevocationPublisher(mr, 5*time.Minute)
	ctx := context.Background()

	result := RuleResult{
		RuleName: "hallucination",
		Score:    2,
		AgentDID: "",
	}

	if err := pub.Publish(ctx, result); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(mr.store) != 0 {
		t.Errorf("expected no keys for empty DID, got %v", mr.store)
	}
}

func TestRevocationPublisher_MultipleAgents(t *testing.T) {
	mr := newMockRedis()
	pub := NewRevocationPublisher(mr, time.Minute)
	ctx := context.Background()

	pub.Publish(ctx, RuleResult{AgentDID: "did:peer:alpha", Score: 10})
	pub.Publish(ctx, RuleResult{AgentDID: "did:peer:beta", Score: 10})

	if len(mr.store) != 2 {
		t.Errorf("expected 2 keys, got %d", len(mr.store))
	}
	if mr.store["revocation:did:peer:alpha"] != "revoked" {
		t.Error("alpha not revoked")
	}
	if mr.store["revocation:did:peer:beta"] != "revoked" {
		t.Error("beta not revoked")
	}
}
