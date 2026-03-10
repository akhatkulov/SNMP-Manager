package pipeline

import (
	"github.com/rs/zerolog"
)

// Enricher adds contextual information to events from external sources.
type Enricher struct {
	log    zerolog.Logger
	assets map[string]AssetInfo // IP → asset info
}

// AssetInfo holds information about a known network asset.
type AssetInfo struct {
	Hostname     string `json:"hostname"`
	Department   string `json:"department"`
	Owner        string `json:"owner"`
	Criticality  string `json:"criticality"` // critical, high, medium, low
	Location     string `json:"location"`
	Environment  string `json:"environment"` // production, staging, development
}

// NewEnricher creates a new event enricher.
func NewEnricher(log zerolog.Logger) *Enricher {
	return &Enricher{
		log:    log.With().Str("component", "enricher").Logger(),
		assets: make(map[string]AssetInfo),
	}
}

// LoadAssets loads asset information from a map.
func (e *Enricher) LoadAssets(assets map[string]AssetInfo) {
	e.assets = assets
	e.log.Info().Int("count", len(assets)).Msg("assets loaded for enrichment")
}

// Process enriches an event in-place with additional context.
func (e *Enricher) Process(event *SNMPEvent) {
	// Enrich from asset database
	if asset, ok := e.assets[event.Source.IP]; ok {
		event.Enrichment.AssetCriticality = asset.Criticality
		if event.Source.Hostname == "" {
			event.Source.Hostname = asset.Hostname
		}
		if event.Source.Location == "" {
			event.Source.Location = asset.Location
		}
		if event.Enrichment.CustomFields == nil {
			event.Enrichment.CustomFields = make(map[string]string)
		}
		event.Enrichment.CustomFields["department"] = asset.Department
		event.Enrichment.CustomFields["owner"] = asset.Owner
		event.Enrichment.CustomFields["environment"] = asset.Environment
	}

	// Adjust severity based on asset criticality
	e.adjustSeverity(event)

	// Add default tags
	e.addTags(event)
}

// adjustSeverity increases severity for critical assets.
func (e *Enricher) adjustSeverity(event *SNMPEvent) {
	if event.Enrichment.AssetCriticality == "critical" && event.Severity < SeverityHigh {
		event.Severity = event.Severity + 2
		if event.Severity > SeverityCritical {
			event.Severity = SeverityCritical
		}
		event.SeverityLabel = event.Severity.String()
	}
}

// addTags adds contextual tags to the event.
func (e *Enricher) addTags(event *SNMPEvent) {
	if event.Tags == nil {
		event.Tags = make([]string, 0)
	}

	// Add SNMP version tag
	if event.SNMP.Version != "" {
		event.Tags = append(event.Tags, "snmp-"+event.SNMP.Version)
	}

	// Add event type tag
	if event.EventType != "" {
		event.Tags = append(event.Tags, "type-"+string(event.EventType))
	}

	// Add vendor tag
	if event.Source.Vendor != "" {
		event.Tags = append(event.Tags, "vendor-"+toLower(event.Source.Vendor))
	}

	// Add category tag
	if event.Category != "" {
		event.Tags = append(event.Tags, "cat-"+event.Category)
	}

	// Security-specific tags
	if event.Category == "security" {
		event.Tags = append(event.Tags, "security-alert")
	}
}
