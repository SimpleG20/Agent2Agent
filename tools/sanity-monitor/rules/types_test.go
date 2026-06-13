package rules

import (
	"testing"
	"time"
)

func TestScoreTracker_SingleMatch(t *testing.T) {
	st := NewScoreTracker(5, time.Minute)
	now := time.Now()

	// Single injection match (score 10) should exceed threshold 5.
	if !st.Add("did:peer:alpha", 10, now) {
		t.Error("expected threshold exceeded")
	}
	if score := st.Score("did:peer:alpha", now); score != 10 {
		t.Errorf("expected score 10, got %d", score)
	}
}

func TestScoreTracker_AccumulateBelowThreshold(t *testing.T) {
	st := NewScoreTracker(5, time.Minute)
	now := time.Now()

	// Add hallucination match (score 2).
	if st.Add("did:peer:alpha", 2, now) {
		t.Error("expected not exceeded yet")
	}

	// Add another.
	if st.Add("did:peer:alpha", 2, now) {
		t.Error("expected not exceeded yet (score=4 < 5)")
	}

	if score := st.Score("did:peer:alpha", now); score != 4 {
		t.Errorf("expected score 4, got %d", score)
	}
}

func TestScoreTracker_AccumulateThresholdReached(t *testing.T) {
	st := NewScoreTracker(5, time.Minute)
	now := time.Now()

	st.Add("did:peer:alpha", 2, now)
	st.Add("did:peer:alpha", 2, now)
	if !st.Add("did:peer:alpha", 2, now) {
		t.Error("expected threshold exceeded (score=6 >= 5)")
	}
}

func TestScoreTracker_IsolatedAgents(t *testing.T) {
	st := NewScoreTracker(5, time.Minute)
	now := time.Now()

	st.Add("did:peer:alpha", 10, now) // exceeded
	st.Add("did:peer:beta", 2, now)   // not exceeded

	if score := st.Score("did:peer:alpha", now); score != 10 {
		t.Errorf("expected alpha score 10, got %d", score)
	}
	if score := st.Score("did:peer:beta", now); score != 2 {
		t.Errorf("expected beta score 2, got %d", score)
	}
}

func TestScoreTracker_WindowExpiry(t *testing.T) {
	st := NewScoreTracker(2, 50*time.Millisecond)
	now := time.Now()

	if !st.Add("did:peer:alpha", 2, now) {
		t.Error("expected threshold exceeded")
	}

	// Wait for window to pass.
	time.Sleep(60 * time.Millisecond)

	if st.Add("did:peer:alpha", 2, now.Add(100*time.Millisecond)) {
		// The old entry should have expired. New entry alone is score 2 = threshold.
	}
	// After expiry, only the new entry counts.
	score := st.Score("did:peer:alpha", now.Add(100*time.Millisecond))
	if score > 2 {
		t.Errorf("expected score <=2 after expiry, got %d", score)
	}
}

func TestScoreTracker_Reset(t *testing.T) {
	st := NewScoreTracker(2, time.Minute)
	now := time.Now()

	st.Add("did:peer:alpha", 10, now)
	st.Reset("did:peer:alpha")

	if score := st.Score("did:peer:alpha", now); score != 0 {
		t.Errorf("expected score 0 after reset, got %d", score)
	}
}

func TestScoreTracker_Threshold(t *testing.T) {
	st := NewScoreTracker(7, time.Minute)
	if st.Threshold() != 7 {
		t.Errorf("expected threshold 7, got %d", st.Threshold())
	}
}
