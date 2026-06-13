package rules

import (
	"testing"
)

func TestHallucinationRule_Match(t *testing.T) {
	r := NewHallucinationRule()

	tests := []struct {
		name  string
		line  string
		score int
	}{
		{"I am not sure", "I am not sure about that", 2},
		{"lowercase", "i'm not sure", 2},
		{"don't know", "I don't know the answer", 2},
		{"that is incorrect", "that is incorrect", 2},
		{"cannot answer", "I cannot answer that question", 2},
		{"just a model", "I am just an AI language model", 2},
		{"do not have", "I do not have access to that information", 2},
		{"crucial note", "it is crucial to note that", 2},
		{"mixed case", "I Am NoT SuRe", 2},
		{"cannot complete", "Sorry, I cannot complete this request", 2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := r.Evaluate(tt.line, "did:peer:test")
			if result == nil {
				t.Errorf("expected match for %q", tt.line)
				return
			}
			if result.Score != tt.score {
				t.Errorf("expected score %d, got %d", tt.score, result.Score)
			}
			if result.RuleName != "hallucination" {
				t.Errorf("expected rule_name hallucination, got %s", result.RuleName)
			}
			if result.AgentDID != "did:peer:test" {
				t.Errorf("expected did:peer:test, got %s", result.AgentDID)
			}
		})
	}
}

func TestHallucinationRule_NoMatch(t *testing.T) {
	r := NewHallucinationRule()

	noMatches := []string{
		"This is a normal log line",
		"Processing request for user 123",
		"Successfully completed task",
		"Error: connection refused",
		"nothing suspicious here",
		"certainly, I can help with that",
		"I know the answer",
		"it is possible that",
	}

	for _, line := range noMatches {
		t.Run(line, func(t *testing.T) {
			result := r.Evaluate(line, "did:peer:test")
			if result != nil {
				t.Errorf("unexpected match for %q: %+v", line, result)
			}
		})
	}
}

func TestHallucinationRule_EmptyDID(t *testing.T) {
	r := NewHallucinationRule()
	result := r.Evaluate("I am not sure", "")
	if result == nil {
		t.Fatal("expected match")
	}
	if result.AgentDID != "" {
		t.Errorf("expected empty DID, got %s", result.AgentDID)
	}
}

func TestHallucinationRule_LongLine(t *testing.T) {
	r := NewHallucinationRule()
	long := "I am not sure about " + string(make([]byte, 500))
	result := r.Evaluate(long, "did:peer:test")
	if result == nil {
		t.Fatal("expected match")
	}
	if len(result.LogLine) > 204 {
		t.Errorf("log line too long: %d chars", len(result.LogLine))
	}
}
