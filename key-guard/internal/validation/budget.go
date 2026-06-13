package validation

import (
	"fmt"
	"sync"
	"time"
)

// Default rate/budget limits.
const (
	DefaultRateLimit    = 100  // signatures per window
	DefaultBudgetLimit  = 1000 // signatures per hour
	DefaultRateWindow   = time.Minute
	DefaultBudgetWindow = time.Hour
)

// AgentBudget tracks signing usage for a single agent.
type AgentBudget struct {
	mu sync.Mutex

	rateWindow  time.Duration
	rateLimit   int
	rateEntries []time.Time

	budgetWindow  time.Duration
	budgetLimit   int
	budgetEntries []time.Time
}

// BudgetStore manages per-agent budget and rate limit tracking.
type BudgetStore struct {
	mu     sync.Mutex
	agents map[string]*AgentBudget

	rateLimit    int
	rateWindow   time.Duration
	budgetLimit  int
	budgetWindow time.Duration
}

// NewBudgetStore creates a new budget store with default limits.
func NewBudgetStore() *BudgetStore {
	return &BudgetStore{
		agents:       make(map[string]*AgentBudget),
		rateLimit:    DefaultRateLimit,
		rateWindow:   DefaultRateWindow,
		budgetLimit:  DefaultBudgetLimit,
		budgetWindow: DefaultBudgetWindow,
	}
}

// getOrCreate returns the budget tracker for an agent, creating one if needed.
func (s *BudgetStore) getOrCreate(agentID string) *AgentBudget {
	s.mu.Lock()
	defer s.mu.Unlock()

	ab, ok := s.agents[agentID]
	if !ok {
		ab = &AgentBudget{
			rateWindow:    s.rateWindow,
			rateLimit:     s.rateLimit,
			rateEntries:   make([]time.Time, 0),
			budgetWindow:  s.budgetWindow,
			budgetLimit:   s.budgetLimit,
			budgetEntries: make([]time.Time, 0),
		}
		s.agents[agentID] = ab
	}
	return ab
}

// Allow checks if the agent is within rate and budget limits.
// If Allow returns true, the request has been counted.
// If Allow returns false, the request was NOT counted and the caller
// should reject it.
func (s *BudgetStore) Allow(agentID string, now time.Time) (bool, string) {
	ab := s.getOrCreate(agentID)
	ab.mu.Lock()
	defer ab.mu.Unlock()

	// Prune expired entries
	ab.prune(now)

	// Check rate limit (rolling window)
	if len(ab.rateEntries) >= ab.rateLimit {
		return false, fmt.Sprintf("rate limit exceeded: %d requests per %v", ab.rateLimit, ab.rateWindow)
	}

	// Check budget (rolling window)
	if len(ab.budgetEntries) >= ab.budgetLimit {
		return false, fmt.Sprintf("budget limit exceeded: %d requests per %v", ab.budgetLimit, ab.budgetWindow)
	}

	// Count this request
	ab.rateEntries = append(ab.rateEntries, now)
	ab.budgetEntries = append(ab.budgetEntries, now)

	return true, ""
}

// prune removes expired entries from both windows.
func (ab *AgentBudget) prune(now time.Time) {
	rateCutoff := now.Add(-ab.rateWindow)
	budgetCutoff := now.Add(-ab.budgetWindow)

	ab.rateEntries = filterAfter(ab.rateEntries, rateCutoff)
	ab.budgetEntries = filterAfter(ab.budgetEntries, budgetCutoff)
}

// filterAfter returns only entries that are >= cutoff.
func filterAfter(entries []time.Time, cutoff time.Time) []time.Time {
	var result []time.Time
	for _, t := range entries {
		if t.After(cutoff) || t.Equal(cutoff) {
			result = append(result, t)
		}
	}
	return result
}
