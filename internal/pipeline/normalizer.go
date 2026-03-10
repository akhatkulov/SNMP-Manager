package pipeline

import (
	"fmt"
	"net"

	"github.com/rs/zerolog"

	"github.com/me262/snmp-manager/internal/mib"
)

// Normalizer resolves OIDs to names, classifies events, and assigns severity.
type Normalizer struct {
	resolver *mib.Resolver
	log      zerolog.Logger
}

// NewNormalizer creates a new event normalizer.
func NewNormalizer(resolver *mib.Resolver, log zerolog.Logger) *Normalizer {
	return &Normalizer{
		resolver: resolver,
		log:      log.With().Str("component", "normalizer").Logger(),
	}
}

// Process normalizes a raw SNMP event in-place.
func (n *Normalizer) Process(event *SNMPEvent) {
	// Resolve main OID
	if event.SNMP.OIDName == "" && event.SNMP.OID != "" {
		entry, found := n.resolver.Resolve(event.SNMP.OID)
		if found {
			event.SNMP.OIDName = entry.Name
			event.SNMP.OIDModule = entry.Module
		} else {
			event.SNMP.OIDName = event.SNMP.OID
		}
	}

	// Resolve OIDs in variable bindings
	for i := range event.SNMP.Variables {
		if event.SNMP.Variables[i].OIDName == "" {
			entry, found := n.resolver.Resolve(event.SNMP.Variables[i].OID)
			if found {
				event.SNMP.Variables[i].OIDName = entry.Name
			}
		}
	}

	// Value to string conversion
	if event.SNMP.ValueString == "" && event.SNMP.Value != nil {
		event.SNMP.ValueString = fmt.Sprintf("%v", event.SNMP.Value)
	}

	// Resolve hostname from IP
	if event.Source.Hostname == "" && event.Source.IP != "" {
		names, err := net.LookupAddr(event.Source.IP)
		if err == nil && len(names) > 0 {
			event.Source.Hostname = names[0]
		}
	}

	// Classify severity based on OID and event type
	n.classifySeverity(event)

	// Classify category
	n.classifyCategory(event)
}

// classifySeverity assigns a severity level based on the event content.
func (n *Normalizer) classifySeverity(event *SNMPEvent) {
	if event.Severity > 0 {
		return // already classified
	}

	oidName := event.SNMP.OIDName

	// Trap-based severity
	switch oidName {
	case "authenticationFailure":
		event.Severity = SeverityHigh
	case "linkDown":
		event.Severity = SeverityHigh
	case "coldStart":
		event.Severity = SeverityMedium
	case "warmStart":
		event.Severity = SeverityLow
	case "linkUp":
		event.Severity = SeverityInfo
	default:
		// Check for error-related OIDs
		switch {
		case containsAny(oidName, "Error", "Fail", "Down", "Critical"):
			event.Severity = SeverityHigh
		case containsAny(oidName, "Warn", "Discard", "Drop"):
			event.Severity = SeverityMedium
		case containsAny(oidName, "Up", "Active", "Normal"):
			event.Severity = SeverityInfo
		default:
			event.Severity = SeverityLow
		}
	}

	event.SeverityLabel = event.Severity.String()
}

// classifyCategory determines the event category.
func (n *Normalizer) classifyCategory(event *SNMPEvent) {
	if event.Category != "" {
		return
	}

	oidName := event.SNMP.OIDName

	switch {
	case containsAny(oidName, "authentication", "auth", "security"):
		event.Category = "security"
	case containsAny(oidName, "if", "link", "interface", "Octets"):
		event.Category = "network"
	case containsAny(oidName, "cpu", "Processor", "Load", "memory", "mem", "Storage"):
		event.Category = "performance"
	case containsAny(oidName, "coldStart", "warmStart", "UpTime", "uptime"):
		event.Category = "availability"
	case containsAny(oidName, "sys"):
		event.Category = "system"
	default:
		event.Category = "general"
	}
}

// containsAny checks if s contains any of the substrings (case-insensitive).
func containsAny(s string, substrs ...string) bool {
	sLower := toLower(s)
	for _, sub := range substrs {
		subLower := toLower(sub)
		if len(subLower) <= len(sLower) {
			for i := 0; i <= len(sLower)-len(subLower); i++ {
				if sLower[i:i+len(subLower)] == subLower {
					return true
				}
			}
		}
	}
	return false
}

func toLower(s string) string {
	b := make([]byte, len(s))
	for i := range s {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 32
		} else {
			b[i] = c
		}
	}
	return string(b)
}
