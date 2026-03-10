package pipeline

import (
	"time"
)

// Severity represents the event severity level (0-10).
type Severity int

const (
	SeverityInfo     Severity = 0
	SeverityLow      Severity = 3
	SeverityMedium   Severity = 5
	SeverityHigh     Severity = 7
	SeverityCritical Severity = 10
)

// String returns the severity label.
func (s Severity) String() string {
	switch {
	case s >= 9:
		return "critical"
	case s >= 7:
		return "high"
	case s >= 5:
		return "medium"
	case s >= 3:
		return "low"
	default:
		return "info"
	}
}

// EventType indicates the origin of the event.
type EventType string

const (
	EventTypePoll EventType = "poll"
	EventTypeTrap EventType = "trap"
	EventTypeInform EventType = "inform"
	EventTypeDiscovery EventType = "discovery"
)

// SNMPEvent is the core data structure that flows through the pipeline.
type SNMPEvent struct {
	// Identification
	ID        string    `json:"id"`
	Timestamp time.Time `json:"timestamp"`
	EventType EventType `json:"event_type"`

	// Source device info
	Source SourceInfo `json:"source"`

	// Raw SNMP data
	SNMP SNMPData `json:"snmp"`

	// Enrichment (added during pipeline processing)
	Enrichment EnrichmentData `json:"enrichment,omitempty"`

	// Classification
	Severity      Severity `json:"severity"`
	SeverityLabel string   `json:"severity_label"`
	Category      string   `json:"category"`
	Tags          []string `json:"tags,omitempty"`

	// Pipeline metadata
	ProcessedAt time.Time `json:"processed_at,omitempty"`
	PipelineMs  int64     `json:"pipeline_ms,omitempty"`
}

// SourceInfo describes the device that generated the event.
type SourceInfo struct {
	IP         string `json:"ip"`
	Port       int    `json:"port,omitempty"`
	Hostname   string `json:"hostname,omitempty"`
	DeviceType string `json:"device_type,omitempty"`
	Vendor     string `json:"vendor,omitempty"`
	Location   string `json:"location,omitempty"`
	SysName    string `json:"sys_name,omitempty"`
}

// SNMPData holds the raw and resolved SNMP information.
type SNMPData struct {
	Version     string     `json:"version"`
	Community   string     `json:"-"` // never expose community strings
	OID         string     `json:"oid"`
	OIDName     string     `json:"oid_name"`
	OIDModule   string     `json:"oid_module,omitempty"`
	Value       any        `json:"value"`
	ValueType   string     `json:"value_type"`
	ValueString string     `json:"value_string"`
	RequestType string     `json:"request_type"`
	Variables   []Variable `json:"variables,omitempty"`
}

// Variable represents a single SNMP variable binding.
type Variable struct {
	OID       string `json:"oid"`
	OIDName   string `json:"oid_name,omitempty"`
	Value     any    `json:"value"`
	ValueType string `json:"value_type"`
}

// EnrichmentData holds additional context added during enrichment.
type EnrichmentData struct {
	AssetCriticality string            `json:"asset_criticality,omitempty"`
	GeoIP            *GeoIPInfo        `json:"geo_ip,omitempty"`
	CustomFields     map[string]string `json:"custom_fields,omitempty"`
}

// GeoIPInfo holds geographic information for an IP address.
type GeoIPInfo struct {
	Country     string  `json:"country,omitempty"`
	CountryCode string  `json:"country_code,omitempty"`
	City        string  `json:"city,omitempty"`
	Latitude    float64 `json:"latitude,omitempty"`
	Longitude   float64 `json:"longitude,omitempty"`
}
