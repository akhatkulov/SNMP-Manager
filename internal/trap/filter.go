package trap

import (
	"regexp"
	"sync"

	"github.com/rs/zerolog"
)

// FilterRuleConfig is the YAML-serialisable form of a trap filter rule.
// Add entries under trap_receiver.filters in config.yaml.
type FilterRuleConfig struct {
	Name    string `yaml:"name"`
	Field   string `yaml:"field"`   // "oid" | "source_ip" | "value"
	Pattern string `yaml:"pattern"` // Go regex
	Action  string `yaml:"action"`  // "drop" | "keep"
}

type compiledRule struct {
	name    string
	field   string
	pattern *regexp.Regexp
	action  string
}

// TrapFilter applies a list of regex rules to incoming traps in-memory,
// before any deduplication or pipeline submission.
// Rules are evaluated in order; the first matching rule wins.
// If no rule matches, the trap is allowed through (default-allow).
type TrapFilter struct {
	log   zerolog.Logger
	mu    sync.RWMutex
	rules []*compiledRule
}

// NewTrapFilter compiles rules from YAML config.
// Invalid regex patterns are logged and skipped (never panic).
func NewTrapFilter(log zerolog.Logger, rules []FilterRuleConfig) *TrapFilter {
	f := &TrapFilter{
		log: log.With().Str("component", "trap-filter").Logger(),
	}
	for _, r := range rules {
		compiled, err := regexp.Compile(r.Pattern)
		if err != nil {
			f.log.Warn().
				Str("rule", r.Name).
				Str("pattern", r.Pattern).
				Err(err).
				Msg("skipping trap filter rule: invalid regex")
			continue
		}
		f.rules = append(f.rules, &compiledRule{
			name:    r.Name,
			field:   r.Field,
			pattern: compiled,
			action:  r.Action,
		})
	}
	f.log.Info().Int("rules", len(f.rules)).Msg("trap filter initialised")
	return f
}

// ShouldProcess returns false if the trap should be silently dropped
// based on the configured rules.
//
// Parameters:
//   - trapOID:  the trap OID string (used when rule.field == "oid")
//   - sourceIP: the sender's IP address (used when rule.field == "source_ip")
//   - values:   string representations of all varbind values (used when rule.field == "value")
func (f *TrapFilter) ShouldProcess(trapOID, sourceIP string, values []string) bool {
	f.mu.RLock()
	defer f.mu.RUnlock()

	for _, rule := range f.rules {
		var subject string
		switch rule.field {
		case "oid":
			subject = trapOID
		case "source_ip":
			subject = sourceIP
		case "value":
			for _, v := range values {
				if rule.pattern.MatchString(v) {
					subject = v
					break
				}
			}
		default:
			continue
		}

		if subject == "" {
			continue
		}

		if rule.pattern.MatchString(subject) {
			drop := rule.action == "drop"
			if drop {
				f.log.Debug().
					Str("rule", rule.name).
					Str("field", rule.field).
					Str("subject", subject).
					Msg("trap dropped by filter rule")
			}
			return !drop
		}
	}

	return true // default: allow
}

// RuleCount returns the number of compiled filter rules.
func (f *TrapFilter) RuleCount() int {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return len(f.rules)
}
