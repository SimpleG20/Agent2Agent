package rules

import (
	"regexp"
	"strings"
	"time"
)

// InjectionRule detects patterns commonly associated with prompt injection,
// jailbreak attempts, and system prompt leakage.
type InjectionRule struct {
	patterns []*regexp.Regexp
}

// NewInjectionRule creates a rule with default injection patterns.
func NewInjectionRule() *InjectionRule {
	raw := []string{
		`(?i)ignore\s+(all\s+)?(previous|the\s+above|your)\s+(instructions|prompts|directions|commands)`,
		`(?i)system\s+prompt`,
		`(?i)dan\s+mode`,
		`(?i)you\s+are\s+now\s+`,
		`(?i)do\s+not\s+follow`,
		`(?i)new\s+prompt\s*[=:]`,
		`(?i)role\s+play`,
		`(?i)act\s+as\s+`,
		`(?i)forget\s+(all\s+)?(previous|everything)`,
		`(?i)[A-Za-z0-9+/]{60,}={0,2}`,
	}
	compiled := make([]*regexp.Regexp, 0, len(raw))
	for _, r := range raw {
		compiled = append(compiled, regexp.MustCompile(r))
	}
	return &InjectionRule{patterns: compiled}
}

// Name returns the rule identifier.
func (r *InjectionRule) Name() string {
	return "injection"
}

// Evaluate checks a log line for injection patterns.
// Returns nil if no pattern matches.
func (r *InjectionRule) Evaluate(line string, agentDID string) *RuleResult {
	lower := strings.ToLower(line)
	for _, re := range r.patterns {
		if re.MatchString(lower) {
			return &RuleResult{
				RuleName:  r.Name(),
				Pattern:   re.String(),
				Severity:  SeverityCritical,
				Score:     10,
				AgentDID:  agentDID,
				LogLine:   truncate(line, 200),
				Timestamp: time.Now(),
			}
		}
	}
	return nil
}
