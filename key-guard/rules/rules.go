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

	// Rule 2: Limit amount fields to <= 100.0
	var data map[string]interface{}
	if err := json.Unmarshal(jsonBytes, &data); err != nil {
		// If it's not a JSON object, it's fine for simple strings, but we still scan strings.
		return nil
	}

	if err := checkAmountLimit(data); err != nil {
		return err
	}

	return nil
}

func checkAmountLimit(data map[string]interface{}) error {
	for k, v := range data {
		if strings.ToLower(k) == "amount" {
			switch num := v.(type) {
			case float64:
				if num > 100.0 {
					return fmt.Errorf("business rule violation: amount %f exceeds limit of 100.0", num)
				}
			case int:
				if num > 100 {
					return fmt.Errorf("business rule violation: amount %d exceeds limit of 100.0", num)
				}
			}
		}

		// Recurse into nested maps
		if nestedMap, ok := v.(map[string]interface{}); ok {
			if err := checkAmountLimit(nestedMap); err != nil {
				return err
			}
		}

		// Recurse into slices of maps
		if sliceVal, ok := v.([]interface{}); ok {
			for _, item := range sliceVal {
				if itemMap, ok := item.(map[string]interface{}); ok {
					if err := checkAmountLimit(itemMap); err != nil {
						return err
			}
				}
			}
		}
	}
	return nil
}
