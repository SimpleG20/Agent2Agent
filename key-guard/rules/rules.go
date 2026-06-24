package rules

import (
	"encoding/json"
	"fmt"
	"strings"
)

// ValidatePayload checks if the JSON payload complies with security and business rules.
func ValidatePayload(jsonBytes []byte) error {
	rawStr := string(jsonBytes)
	lowerStr := strings.ToLower(rawStr)

	// Rule 1: No forbidden words to prevent private key leaks or command execution injection
	forbiddenWords := []string{"secret_key", "private_key", "sudo"}
	for _, word := range forbiddenWords {
		if strings.Contains(lowerStr, word) {
			return fmt.Errorf("security violation: payload contains forbidden keyword '%s'", word)
		}
	}

	// Rule 2: Limit message content length to <= 100 characters
	var data map[string]interface{}
	if err := json.Unmarshal(jsonBytes, &data); err == nil {
		if contentVal, ok := data["content"]; ok {
			if contentStr, ok := contentVal.(string); ok {
				if len(contentStr) > 100 {
					return fmt.Errorf("business rule violation: message content length (%d) exceeds limit of 100 characters", len(contentStr))
				}
			}
		}
	} else {
		// If it's not JSON, check raw string length
		if len(rawStr) > 100 {
			return fmt.Errorf("business rule violation: message length (%d) exceeds limit of 100 characters", len(rawStr))
		}
	}

	return nil
}
