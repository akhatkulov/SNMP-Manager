package pipeline

import (
	"testing"
	"time"
)

// ── Event Model Tests ────────────────────────────────────────────────

func TestSeverityString(t *testing.T) {
	tests := []struct {
		sev  Severity
		want string
	}{
		{SeverityInfo, "info"},
		{1, "info"},
		{2, "info"},
		{SeverityLow, "low"},
		{4, "low"},
		{SeverityMedium, "medium"},
		{6, "medium"},
		{SeverityHigh, "high"},
		{8, "high"},
		{9, "critical"},
		{SeverityCritical, "critical"},
	}

	for _, tt := range tests {
		got := tt.sev.String()
		if got != tt.want {
			t.Errorf("Severity(%d).String(): want %q, got %q", tt.sev, tt.want, got)
		}
	}
}

func TestEventCreate(t *testing.T) {
	event := &SNMPEvent{
		ID:        "test-id-001",
		Timestamp: time.Now(),
		EventType: EventTypeTrap,
		Source: SourceInfo{
			IP:       "10.0.0.1",
			Hostname: "router-01",
			Vendor:   "Cisco",
		},
		SNMP: SNMPData{
			Version:     "v2c",
			OID:         "1.3.6.1.6.3.1.1.5.3",
			OIDName:     "linkDown",
			Value:       2,
			ValueType:   "Integer",
			RequestType: "trap",
		},
		Severity: SeverityHigh,
		Category: "network",
	}

	if event.ID != "test-id-001" {
		t.Errorf("ID: want %q, got %q", "test-id-001", event.ID)
	}
	if event.EventType != EventTypeTrap {
		t.Errorf("EventType: want %q, got %q", EventTypeTrap, event.EventType)
	}
	if event.Source.Vendor != "Cisco" {
		t.Errorf("Vendor: want %q, got %q", "Cisco", event.Source.Vendor)
	}
	if event.Severity != SeverityHigh {
		t.Errorf("Severity: want %d, got %d", SeverityHigh, event.Severity)
	}
}

func TestEventVariables(t *testing.T) {
	event := &SNMPEvent{
		SNMP: SNMPData{
			Variables: []Variable{
				{OID: "1.3.6.1.2.1.2.2.1.8.1", OIDName: "ifOperStatus.1", Value: 2, ValueType: "Integer"},
				{OID: "1.3.6.1.2.1.2.2.1.2.1", OIDName: "ifDescr.1", Value: "GigabitEthernet0/1", ValueType: "OctetString"},
			},
		},
	}

	if len(event.SNMP.Variables) != 2 {
		t.Fatalf("variables: want 2, got %d", len(event.SNMP.Variables))
	}
	if event.SNMP.Variables[0].OIDName != "ifOperStatus.1" {
		t.Errorf("var 0 name: want %q, got %q", "ifOperStatus.1", event.SNMP.Variables[0].OIDName)
	}
}

func TestEnrichmentData(t *testing.T) {
	event := &SNMPEvent{
		Enrichment: EnrichmentData{
			AssetCriticality: "critical",
			GeoIP: &GeoIPInfo{
				Country:     "Uzbekistan",
				CountryCode: "UZ",
				City:        "Tashkent",
			},
			CustomFields: map[string]string{
				"department": "IT",
				"owner":      "admin@company.com",
			},
		},
	}

	if event.Enrichment.AssetCriticality != "critical" {
		t.Errorf("criticality: want %q, got %q", "critical", event.Enrichment.AssetCriticality)
	}
	if event.Enrichment.GeoIP.City != "Tashkent" {
		t.Errorf("city: want %q, got %q", "Tashkent", event.Enrichment.GeoIP.City)
	}
	if event.Enrichment.CustomFields["owner"] != "admin@company.com" {
		t.Errorf("owner field missing")
	}
}
