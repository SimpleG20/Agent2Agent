package validation

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/xeipuuv/gojsonschema"
)

// Allowed actions that an agent can request signing for.
var AllowedActions = map[string]bool{
	"a2a.message.sign":     true,
	"a2a.credential.issue": true,
	"did.update":           true,
}

// SigningIntentSchema is the JSON Schema that all signing requests must validate against.
const SigningIntentSchema = `{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "required": ["action", "payload", "agent_id", "timestamp", "nonce"],
  "properties": {
    "action": {
      "type": "string",
      "enum": ["a2a.message.sign", "a2a.credential.issue", "did.update"]
    },
    "payload": {
      "type": "object",
      "required": ["content"],
      "properties": {
        "content": { "type": "string" },
        "content_type": { "type": "string" },
        "recipient_did": { "type": "string", "pattern": "^did:" }
      }
    },
    "agent_id": {
      "type": "string",
      "minLength": 1,
      "maxLength": 128
    },
    "timestamp": {
      "type": "integer",
      "minimum": 1
    },
    "nonce": {
      "type": "string",
      "minLength": 16,
      "maxLength": 64
    }
  }
}`

// MaxTimestampSkew is the maximum allowed clock drift between agent and server (in seconds).
const MaxTimestampSkew = 60

// SigningIntent is the parsed, validated signing request from an agent.
type SigningIntent struct {
	Action    string          `json:"action"`
	Payload   json.RawMessage `json:"payload"`
	AgentID   string          `json:"agent_id"`
	Timestamp int64           `json:"timestamp"`
	Nonce     string          `json:"nonce"`
}

// PayloadContent is the structured content inside a signing intent's payload.
type PayloadContent struct {
	Content      string `json:"content"`
	ContentType  string `json:"content_type,omitempty"`
	RecipientDID string `json:"recipient_did,omitempty"`
}

// ValidationResult holds the outcome of schema + policy validation.
type ValidationResult struct {
	Valid  bool   `json:"valid"`
	Reason string `json:"reason,omitempty"`
}

// ValidateIntent validates the raw JSON body against the signing intent schema.
func ValidateIntent(body []byte) (*SigningIntent, *ValidationResult) {
	schemaLoader := gojsonschema.NewStringLoader(SigningIntentSchema)
	docLoader := gojsonschema.NewBytesLoader(body)

	result, err := gojsonschema.Validate(schemaLoader, docLoader)
	if err != nil {
		return nil, &ValidationResult{
			Valid:  false,
			Reason: fmt.Sprintf("schema validation error: %v", err),
		}
	}

	if !result.Valid() {
		var errs []string
		for _, desc := range result.Errors() {
			errs = append(errs, desc.String())
		}
		return nil, &ValidationResult{
			Valid:  false,
			Reason: fmt.Sprintf("schema validation failed: %v", errs),
		}
	}

	var intent SigningIntent
	if err := json.Unmarshal(body, &intent); err != nil {
		return nil, &ValidationResult{
			Valid:  false,
			Reason: fmt.Sprintf("failed to parse intent: %v", err),
		}
	}

	return &intent, &ValidationResult{Valid: true}
}

// ValidateTimestamp checks if the intent's timestamp is within the allowed
// skew window of the server's current time.
func ValidateTimestamp(timestamp int64, now time.Time) *ValidationResult {
	skew := now.Unix() - timestamp
	if skew < -MaxTimestampSkew || skew > MaxTimestampSkew {
		return &ValidationResult{
			Valid:  false,
			Reason: fmt.Sprintf("timestamp skew %ds exceeds max %ds", skew, MaxTimestampSkew),
		}
	}
	return &ValidationResult{Valid: true}
}
