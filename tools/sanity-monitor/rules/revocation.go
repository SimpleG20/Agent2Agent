package rules

import (
	"context"
	"fmt"
	"log"
	"time"
)

// RevocationPublisher publishes revocation events to Redis.
type RevocationPublisher struct {
	redis     RedisCmdRunner
	ttl       time.Duration
	keyPrefix string
}

// RedisCmdRunner is the minimal Redis interface needed for publishing revocations.
type RedisCmdRunner interface {
	Set(ctx context.Context, key, value string, ttl time.Duration) error
	Ping(ctx context.Context) error
}

// NewRevocationPublisher creates a publisher that writes revocation: prefixed keys.
func NewRevocationPublisher(redis RedisCmdRunner, ttl time.Duration) *RevocationPublisher {
	return &RevocationPublisher{
		redis:     redis,
		ttl:       ttl,
		keyPrefix: "revocation:",
	}
}

// Publish writes a revocation event to Redis if the agent DID is non-empty.
func (p *RevocationPublisher) Publish(ctx context.Context, result RuleResult) error {
	if result.AgentDID == "" {
		return nil // cannot revoke without a DID
	}
	key := p.keyPrefix + result.AgentDID
	val := "revoked"
	if err := p.redis.Set(ctx, key, val, p.ttl); err != nil {
		return fmt.Errorf("revocation publish failed for %s: %w", result.AgentDID, err)
	}
	log.Printf("[REVOKE] did=%s rule=%s score=%d ttl=%s",
		result.AgentDID, result.RuleName, result.Score, p.ttl)
	return nil
}

// Close is a no-op for interface satisfaction; caller should close the Redis client.
func (p *RevocationPublisher) Close() {}
