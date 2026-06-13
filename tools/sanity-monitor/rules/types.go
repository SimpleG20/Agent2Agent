// Package rules implements deterministic pattern-matching rules for
// detecting anomalous agent behavior (hallucination, prompt injection)
// and publishing revocation events to Redis.
package rules

import "time"

// Severity level for a rule match.
type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityWarning  Severity = "warning"
	SeverityCritical Severity = "critical"
)

// RuleResult describes a single pattern match.
type RuleResult struct {
	RuleName  string    `json:"rule_name"`
	Pattern   string    `json:"pattern"`
	Severity  Severity  `json:"severity"`
	Score     int       `json:"score"`
	AgentDID  string    `json:"agent_did,omitempty"`
	LogLine   string    `json:"log_line,omitempty"`
	Timestamp time.Time `json:"timestamp"`
}

// Rule defines the interface for a single detection rule.
type Rule interface {
	// Name returns a human-readable identifier for the rule.
	Name() string
	// Evaluate checks a single log line and returns a result.
	// Returns nil if the rule does not match.
	Evaluate(line string, agentDID string) *RuleResult
}

// ScoreTracker accumulates scores per agent DID with a rolling time window.
type ScoreTracker struct {
	threshold int
	window    time.Duration
	entries   map[string][]scoreEntry
}

type scoreEntry struct {
	score     int
	timestamp time.Time
}

// NewScoreTracker creates a tracker that triggers when accumulated score
// within the rolling window reaches the threshold.
func NewScoreTracker(threshold int, window time.Duration) *ScoreTracker {
	return &ScoreTracker{
		threshold: threshold,
		window:    window,
		entries:   make(map[string][]scoreEntry),
	}
}

// Add records a score for an agent and returns true if the threshold is reached.
func (st *ScoreTracker) Add(agentDID string, score int, now time.Time) bool {
	cutoff := now.Add(-st.window)

	// Prune expired entries and add the new one.
	entries := st.entries[agentDID]
	fresh := entries[:0]
	for _, e := range entries {
		if e.timestamp.After(cutoff) {
			fresh = append(fresh, e)
		}
	}
	fresh = append(fresh, scoreEntry{score: score, timestamp: now})
	st.entries[agentDID] = fresh

	// Sum scores in the window.
	var total int
	for _, e := range fresh {
		total += e.score
	}
	return total >= st.threshold
}

// Reset clears all tracked scores for an agent.
func (st *ScoreTracker) Reset(agentDID string) {
	delete(st.entries, agentDID)
}

// Threshold returns the configured threshold.
func (st *ScoreTracker) Threshold() int {
	return st.threshold
}

// Score returns the current accumulated score for an agent.
func (st *ScoreTracker) Score(agentDID string, now time.Time) int {
	cutoff := now.Add(-st.window)
	entries := st.entries[agentDID]
	var total int
	for _, e := range entries {
		if e.timestamp.After(cutoff) {
			total += e.score
		}
	}
	return total
}
