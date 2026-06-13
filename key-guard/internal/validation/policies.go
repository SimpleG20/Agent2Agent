package validation

import (
	"encoding/json"
	"fmt"
	"strings"
)

// PolicyFunc is a deterministic rule that evaluates a signing intent.
// All policies must pass for a signing request to be approved.
type PolicyFunc func(intent *SigningIntent) *ValidationResult

// DefaultPolicies is the standard set of policies applied to every signing request.
var DefaultPolicies = []PolicyFunc{
	MaxMessageSize(10 * 1024), // max 10KB payload
	NoSystemPromptOverride(),
	ValidAction(),
}

// MaxMessageSize returns a policy that ensures the payload content does not
// exceed the specified maximum size in bytes.
func MaxMessageSize(maxBytes int) PolicyFunc {
	return func(intent *SigningIntent) *ValidationResult {
		content := string(intent.Payload)
		if len(content) > maxBytes {
			return &ValidationResult{
				Valid:  false,
				Reason: fmt.Sprintf("message size %d exceeds maximum %d bytes", len(content), maxBytes),
			}
		}
		return &ValidationResult{Valid: true}
	}
}

// blockedPromptPatterns are content patterns commonly associated with prompt
// injection or system prompt override attempts.
var blockedPromptPatterns = []string{
	"ignore previous instructions",
	"ignore all previous",
	"ignore the above",
	"ignore your",
	"system prompt",
	"new prompt:",
	"you are now",
	"do not follow",
	"dan mode",
	"act as a",
}

// NoSystemPromptOverride returns a policy that blocks known prompt injection
// patterns in the payload content.
func NoSystemPromptOverride() PolicyFunc {
	return func(intent *SigningIntent) *ValidationResult {
		// Parse the structured payload to check content
		var pc PayloadContent
		if err := parsePayload(intent.Payload, &pc); err != nil {
			// If we can't parse, still check the raw payload as fallback
			content := strings.ToLower(string(intent.Payload))
			return checkPatterns(content)
		}

		content := strings.ToLower(pc.Content)
		return checkPatterns(content)
	}
}

func parsePayload(raw json.RawMessage, target interface{}) error {
	return json.Unmarshal(raw, target)
}

func checkPatterns(content string) *ValidationResult {
	for _, pattern := range blockedPromptPatterns {
		if strings.Contains(content, pattern) {
			return &ValidationResult{
				Valid:  false,
				Reason: fmt.Sprintf("payload contains blocked pattern: %q", pattern),
			}
		}
	}
	return &ValidationResult{Valid: true}
}

// ValidAction returns a policy that verifies the intent's action is in the
// allowed set.
func ValidAction() PolicyFunc {
	return func(intent *SigningIntent) *ValidationResult {
		if !AllowedActions[intent.Action] {
			return &ValidationResult{
				Valid:  false,
				Reason: fmt.Sprintf("action %q is not allowed", intent.Action),
			}
		}
		return &ValidationResult{Valid: true}
	}
}

// RunPolicies executes all policies sequentially. The first failure short-circuits.
func RunPolicies(intent *SigningIntent, policies []PolicyFunc) *ValidationResult {
	for _, policy := range policies {
		if result := policy(intent); !result.Valid {
			return result
		}
	}
	return &ValidationResult{Valid: true}
}
