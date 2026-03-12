package pipeline

import (
	"fmt"
	"net"
	"sync"

	"github.com/rs/zerolog"

	"github.com/me262/snmp-manager/internal/mib"
)

// Normalizer resolves OIDs to names, classifies events, and assigns severity.
type Normalizer struct {
	resolver         *mib.Resolver
	log              zerolog.Logger
	resolveHostnames bool
	dnsCache         map[string]string
	dnsCacheMu       sync.RWMutex
}

// NewNormalizer creates a new event normalizer.
func NewNormalizer(resolver *mib.Resolver, log zerolog.Logger, resolveHostnames bool) *Normalizer {
	return &Normalizer{
		resolver:         resolver,
		log:              log.With().Str("component", "normalizer").Logger(),
		resolveHostnames: resolveHostnames,
		dnsCache:         make(map[string]string),
	}
}

// Process normalizes a raw SNMP event in-place.
func (n *Normalizer) Process(event *SNMPEvent) {
	// Resolve main OID
	if event.SNMP.OID != "" {
		entry, found := n.resolver.Resolve(event.SNMP.OID)
		if found {
			if event.SNMP.OIDName == "" {
				event.SNMP.OIDName = entry.Name
			}
			if event.SNMP.OIDModule == "" {
				event.SNMP.OIDModule = entry.Module
			}
			event.SNMP.OIDDescription = entry.Description
			event.SNMP.OIDSyntax = entry.Syntax
		} else if event.SNMP.OIDName == "" {
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

	// Resolve hostname from IP (cached, only if enabled)
	if n.resolveHostnames && event.Source.Hostname == "" && event.Source.IP != "" {
		event.Source.Hostname = n.lookupHost(event.Source.IP)
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

// lookupHost resolves an IP to a hostname with caching.
func (n *Normalizer) lookupHost(ip string) string {
	// Check cache first
	n.dnsCacheMu.RLock()
	if host, ok := n.dnsCache[ip]; ok {
		n.dnsCacheMu.RUnlock()
		return host
	}
	n.dnsCacheMu.RUnlock()

	// DNS lookup (slow)
	host := ""
	names, err := net.LookupAddr(ip)
	if err == nil && len(names) > 0 {
		host = names[0]
	}

	// Store in cache
	n.dnsCacheMu.Lock()
	n.dnsCache[ip] = host
	n.dnsCacheMu.Unlock()

	return host
}
