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
		ID:             "test-id-001",
		Timestamp:      time.Now(),
		EventType:      EventTypeTrap,
		Version:        "v2c",
		DeviceIP:       "10.0.0.1",
		DeviceHostname: "router-01",
		DeviceVendor:   "Cisco",
		OID:            "1.3.6.1.6.3.1.1.5.3",
		OIDName:        "linkDown",
		Value:          2,
		ValueType:      "Integer",
		ValueStr:       "2",
		Severity:       SeverityHigh,
		Category:       "network",
	}

	if event.ID != "test-id-001" {
		t.Errorf("ID: want %q, got %q", "test-id-001", event.ID)
	}
	if event.EventType != EventTypeTrap {
		t.Errorf("EventType: want %q, got %q", EventTypeTrap, event.EventType)
	}
	if event.DeviceVendor != "Cisco" {
		t.Errorf("DeviceVendor: want %q, got %q", "Cisco", event.DeviceVendor)
	}
	if event.Severity != SeverityHigh {
		t.Errorf("Severity: want %d, got %d", SeverityHigh, event.Severity)
	}
	if event.OIDName != "linkDown" {
		t.Errorf("OIDName: want %q, got %q", "linkDown", event.OIDName)
	}
}
