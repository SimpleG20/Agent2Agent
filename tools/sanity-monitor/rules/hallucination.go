package rules

import (
	"regexp"
	"strings"
	"time"
)

// HallucinationRule detects language patterns commonly associated with
// LLM hallucination or uncertainty.
type HallucinationRule struct {
	patterns []*regexp.Regexp
}

// NewHallucinationRule creates a rule with default hallucination patterns.
func NewHallucinationRule() *HallucinationRule {
	raw := []string{
		`(?i)i(?:'m|\s+am)\s+not\s+(sure|certain|confident)`,
		`(?i)i\s+(?:do\s+not|dont|don't)\s+know`,
		`(?i)that\s+is\s+(incorrect|wrong|false)`,
		`(?i)cannot\s+(answer|respond|process|complete)`,
		`(?i)i(?:'m|\s+am)\s+(?:just\s+)?(?:an?\s+)?(?:ai\s+)?(?:language\s+)?(?:model|assistant)`,
		`(?i)i\s+do\s+not\s+have\s+(access|information|data|the\s+ability)`,
		`(?i)it\s+is\s+(important|essential|crucial)\s+to\s+note`,
	}
	compiled := make([]*regexp.Regexp, 0, len(raw))
	for _, r := range raw {
		compiled = append(compiled, regexp.MustCompile(r))
	}
	return &HallucinationRule{patterns: compiled}
}

// Name returns the rule identifier.
func (r *HallucinationRule) Name() string {
	return "hallucination"
}

// Evaluate checks a log line for hallucination patterns.
// Returns nil if no pattern matches.
func (r *HallucinationRule) Evaluate(line string, agentDID string) *RuleResult {
	lower := strings.ToLower(line)
	for _, re := range r.patterns {
		if re.MatchString(lower) {
			return &RuleResult{
				RuleName:  r.Name(),
				Pattern:   re.String(),
				Severity:  SeverityWarning,
				Score:     2,
				AgentDID:  agentDID,
				LogLine:   truncate(line, 200),
				Timestamp: time.Now(),
			}
		}
	}
	return nil
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
