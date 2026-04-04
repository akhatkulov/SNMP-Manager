package pipeline

import (
	"time"
)

// ─── Severity ────────────────────────────────────────────────────────────────

// Severity represents the event severity level (0-10).
type Severity int

const (
	SeverityInfo     Severity = 0
	SeverityLow      Severity = 3
	SeverityMedium   Severity = 5
	SeverityHigh     Severity = 7
	SeverityCritical Severity = 10
)

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

// ─── Event types ─────────────────────────────────────────────────────────────

type EventType string

const (
	EventTypePoll      EventType = "poll"
	EventTypeTrap      EventType = "trap"
	EventTypeInform    EventType = "inform"
	EventTypeDiscovery EventType = "discovery"
)

// ─── Category ─────────────────────────────────────────────────────────────────

type Category string

const (
	CategoryAvailability Category = "availability"
	CategoryNetwork      Category = "network"
	CategoryPerformance  Category = "performance"
	CategoryEnvironment  Category = "environment"
	CategorySecurity     Category = "security"
	CategorySystem       Category = "system"
	CategoryStorage      Category = "storage"
	CategoryVoIP         Category = "voip"
	CategoryWireless     Category = "wireless"
	CategoryVPN          Category = "vpn"
	CategoryBGP          Category = "bgp"
	CategoryOSPF         Category = "ospf"
	CategoryVLAN         Category = "vlan"
	CategoryPoE          Category = "poe"
	CategoryUPS          Category = "ups"
	CategoryPrinter      Category = "printer"
	CategoryTrap         Category = "trap"
	CategoryGeneral      Category = "general"
)

// ─── SNMPEvent — canonical output format ─────────────────────────────────────
//
// Design principles:
//   - ECS-inspired (Elastic Common Schema) field naming
//   - Flat structure: no deeply nested objects to simplify ES mapping & queries
//   - Every field has a clear, consistent type
//   - Self-describing: a single document tells the full story without lookups
//   - NDJSON-safe: one event = one line when marshalled without indentation
//
// Field naming convention:
//   - dot-grouped prefixes map to JSON object keys (e.g. "device.*", "snmp.*")
//   - snake_case throughout
//   - bool fields: is_* or has_*
//   - time fields: *_at
//   - count/numeric fields: *_count, *_ms, *_bytes
type SNMPEvent struct {
	// ── Core identity ──────────────────────────────────────────────────────
	ID        string    `json:"id"`                   // UUID v4
	Timestamp time.Time `json:"@timestamp"`           // RFC3339Nano — ES standard
	EventType EventType `json:"event_type"`           // poll|trap|inform|discovery
	Version   string    `json:"snmp_version"`         // v1|v2c|v3

	// ── Device (source) ────────────────────────────────────────────────────
	DeviceIP       string `json:"device_ip"`                 // "10.10.11.53"
	DeviceHostname string `json:"device_hostname,omitempty"` // "SW2.dc.local"
	DeviceSysName  string `json:"device_sysname,omitempty"`  // from sysName OID
	DeviceType     string `json:"device_type,omitempty"`     // network-switch|router|server
	DeviceVendor   string `json:"device_vendor,omitempty"`   // Cisco|MikroTik|Huawei
	DeviceModel    string `json:"device_model,omitempty"`
	DeviceLocation string `json:"device_location,omitempty"` // DC-Tashkent

	// ── OID info ───────────────────────────────────────────────────────────
	OID            string `json:"oid"`                        // "1.3.6.1.4.1.14988.1.1.3.10"
	OIDName        string `json:"oid_name"`                   // "mtxrHlCpuTemperature"
	OIDModule      string `json:"oid_module,omitempty"`       // "MIKROTIK-MIB"
	OIDDescription string `json:"oid_description,omitempty"`  // human description
	OIDSyntax      string `json:"oid_syntax,omitempty"`       // Integer|Counter32|OctetString

	// ── Value — raw ────────────────────────────────────────────────────────
	Value      any    `json:"value"`        // Go-native: int64|float64|string|[]byte
	ValueType  string `json:"value_type"`   // Integer|OctetString|Counter32|Gauge32|TimeTicks|OID|IPAddress|Counter64
	ValueStr   string `json:"value_str"`    // human-readable (always populated)

	// ── Value — processed (metric) ─────────────────────────────────────────
	// Only populated when value is numeric
	MetricValue     *float64 `json:"metric_value,omitempty"`      // after multiplier/preprocessing
	MetricUnit      string   `json:"metric_unit,omitempty"`       // °C|%|bps|pps|V|W|ms|s|B
	MetricRaw       *float64 `json:"metric_raw,omitempty"`        // original counter value
	MetricIsRate    bool     `json:"metric_is_rate,omitempty"`    // true = per-second rate
	ThresholdWarn   *float64 `json:"threshold_warn,omitempty"`    // warn threshold
	ThresholdCrit   *float64 `json:"threshold_crit,omitempty"`    // critical threshold

	// ── Trap-specific ──────────────────────────────────────────────────────
	// Populated only for trap/inform events
	TrapOID       string     `json:"trap_oid,omitempty"`        // SNMPv2: snmpTrapOID value
	TrapOIDName   string     `json:"trap_oid_name,omitempty"`   // resolved name
	Enterprise    string     `json:"enterprise,omitempty"`      // v1 enterprise OID
	GenericTrap   int        `json:"generic_trap,omitempty"`    // v1 generic trap number (0-6)
	SpecificTrap  int        `json:"specific_trap,omitempty"`   // v1 specific trap number
	Variables     []Variable `json:"variables,omitempty"`       // all PDU varbinds

	// ── Classification ─────────────────────────────────────────────────────
	Severity      Severity `json:"severity"`        // 0|3|5|7|10
	SeverityLabel string   `json:"severity_label"`  // info|low|medium|high|critical
	Category      Category `json:"category"`         // availability|network|environment|...

	// ── Enrichment ─────────────────────────────────────────────────────────
	AssetCriticality string            `json:"asset_criticality,omitempty"` // critical|high|medium|low
	Tags             []string          `json:"tags,omitempty"`
	CustomFields     map[string]string `json:"custom_fields,omitempty"`

	// ── Pipeline metadata ──────────────────────────────────────────────────
	FilterReason string    `json:"filter_reason,omitempty"` // new|changed|heartbeat
	ProcessedAt  time.Time `json:"processed_at,omitempty"`
	PipelineMs   int64     `json:"pipeline_ms,omitempty"`
}

// Variable represents a single SNMP variable binding (varbind) in a PDU.
type Variable struct {
	OID      string `json:"oid"`
	OIDName  string `json:"oid_name,omitempty"`
	Value    any    `json:"value"`
	Type     string `json:"type"`
	ValueStr string `json:"value_str,omitempty"`
}

// ─── Legacy compatibility aliases ────────────────────────────────────────────
// These helper methods let existing code that used the nested struct fields
// continue to compile without changes.

// Source returns a SourceInfo view (for backward compat with tests/enricher).
func (e *SNMPEvent) sourceIP() string { return e.DeviceIP }

// ─── Enrichment data (used by enricher.go internally) ────────────────────────

// EnrichmentData is kept for Enricher.Process() compatibility.
// Fields are mapped directly to flat SNMPEvent fields.
type EnrichmentData struct {
	AssetCriticality string            `json:"asset_criticality,omitempty"`
	GeoIP            *GeoIPInfo        `json:"geo_ip,omitempty"`
	CustomFields     map[string]string `json:"custom_fields,omitempty"`
}

type GeoIPInfo struct {
	Country     string  `json:"country,omitempty"`
	CountryCode string  `json:"country_code,omitempty"`
	City        string  `json:"city,omitempty"`
	Latitude    float64 `json:"latitude,omitempty"`
	Longitude   float64 `json:"longitude,omitempty"`
}
