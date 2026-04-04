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
	Hostname    string `json:"hostname"`
	Department  string `json:"department"`
	Owner       string `json:"owner"`
	Criticality string `json:"criticality"` // critical, high, medium, low
	Location    string `json:"location"`
	Environment string `json:"environment"` // production, staging, development
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
	if asset, ok := e.assets[event.DeviceIP]; ok {
		event.AssetCriticality = asset.Criticality

		if event.DeviceHostname == "" {
			event.DeviceHostname = asset.Hostname
		}
		if event.DeviceLocation == "" {
			event.DeviceLocation = asset.Location
		}
		if event.CustomFields == nil {
			event.CustomFields = make(map[string]string)
		}
		event.CustomFields["department"] = asset.Department
		event.CustomFields["owner"] = asset.Owner
		event.CustomFields["environment"] = asset.Environment
	}

	e.adjustSeverity(event)
	e.addTags(event)
}

func (e *Enricher) adjustSeverity(event *SNMPEvent) {
	if event.AssetCriticality == "critical" && event.Severity < SeverityHigh {
		event.Severity = event.Severity + 2
		if event.Severity > SeverityCritical {
			event.Severity = SeverityCritical
		}
		event.SeverityLabel = event.Severity.String()
	}
}

func (e *Enricher) addTags(event *SNMPEvent) {
	if event.Tags == nil {
		event.Tags = make([]string, 0)
	}

	if event.Version != "" {
		event.Tags = append(event.Tags, "snmp-"+event.Version)
	}
	if event.EventType != "" {
		event.Tags = append(event.Tags, "type-"+string(event.EventType))
	}
	if event.DeviceVendor != "" {
		event.Tags = append(event.Tags, "vendor-"+toLower(event.DeviceVendor))
	}
	if event.Category != "" {
		event.Tags = append(event.Tags, "cat-"+string(event.Category))
	}
	if event.Category == CategorySecurity {
		event.Tags = append(event.Tags, "security-alert")
	}
}
