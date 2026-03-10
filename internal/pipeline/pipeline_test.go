package pipeline

import (
	"testing"
	"time"

	"github.com/rs/zerolog"

	"github.com/me262/snmp-manager/internal/mib"
)

func newTestNormalizer() *Normalizer {
	resolver := mib.NewResolver(zerolog.Nop())
	return NewNormalizer(resolver, zerolog.Nop())
}

func TestNormalizerOIDResolution(t *testing.T) {
	n := newTestNormalizer()

	event := &SNMPEvent{
		SNMP: SNMPData{
			OID: "1.3.6.1.2.1.1.1",
		},
		Source: SourceInfo{IP: "10.0.0.1"},
	}

	n.Process(event)

	if event.SNMP.OIDName != "sysDescr" {
		t.Errorf("OID name: want %q, got %q", "sysDescr", event.SNMP.OIDName)
	}
	if event.SNMP.OIDModule != "SNMPv2-MIB" {
		t.Errorf("OID module: want %q, got %q", "SNMPv2-MIB", event.SNMP.OIDModule)
	}
}

func TestNormalizerVariableResolution(t *testing.T) {
	n := newTestNormalizer()

	event := &SNMPEvent{
		SNMP: SNMPData{
			OID:     "1.3.6.1.6.3.1.1.5.3",
			OIDName: "linkDown", // pre-set
			Variables: []Variable{
				{OID: "1.3.6.1.2.1.2.2.1.8.1"},
				{OID: "1.3.6.1.2.1.2.2.1.2.1"},
			},
		},
		Source: SourceInfo{IP: "10.0.0.1"},
	}

	n.Process(event)

	if event.SNMP.Variables[0].OIDName != "ifOperStatus.1" {
		t.Errorf("var 0 name: want %q, got %q", "ifOperStatus.1", event.SNMP.Variables[0].OIDName)
	}
	if event.SNMP.Variables[1].OIDName != "ifDescr.1" {
		t.Errorf("var 1 name: want %q, got %q", "ifDescr.1", event.SNMP.Variables[1].OIDName)
	}
}

func TestNormalizerValueToString(t *testing.T) {
	n := newTestNormalizer()

	event := &SNMPEvent{
		SNMP: SNMPData{
			OID:   "1.3.6.1.2.1.1.1",
			Value: "Cisco IOS",
		},
		Source: SourceInfo{IP: "10.0.0.1"},
	}

	n.Process(event)

	if event.SNMP.ValueString != "Cisco IOS" {
		t.Errorf("value string: want %q, got %q", "Cisco IOS", event.SNMP.ValueString)
	}
}

func TestNormalizerSeverityClassification(t *testing.T) {
	n := newTestNormalizer()

	tests := []struct {
		name       string
		oidName    string
		wantSev    Severity
		wantLabel  string
	}{
		{"auth failure", "authenticationFailure", SeverityHigh, "high"},
		{"link down", "linkDown", SeverityHigh, "high"},
		{"cold start", "coldStart", SeverityMedium, "medium"},
		{"warm start", "warmStart", SeverityLow, "low"},
		{"link up", "linkUp", SeverityInfo, "info"},
		{"error keyword", "ifInErrors", SeverityHigh, "high"},
		{"discard keyword", "ifInDiscards", SeverityMedium, "medium"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			event := &SNMPEvent{
				SNMP:   SNMPData{OIDName: tt.oidName},
				Source: SourceInfo{IP: "10.0.0.1"},
			}
			n.Process(event)

			if event.Severity != tt.wantSev {
				t.Errorf("severity: want %d (%s), got %d (%s)",
					tt.wantSev, tt.wantSev.String(), event.Severity, event.Severity.String())
			}
			if event.SeverityLabel != tt.wantLabel {
				t.Errorf("severity label: want %q, got %q", tt.wantLabel, event.SeverityLabel)
			}
		})
	}
}

func TestNormalizerCategoryClassification(t *testing.T) {
	n := newTestNormalizer()

	tests := []struct {
		oidName  string
		wantCat  string
	}{
		{"authenticationFailure", "security"},
		{"ifOperStatus", "network"},
		{"ifInOctets", "network"},
		{"hrProcessorLoad", "performance"},
		{"memTotalReal", "performance"},
		{"sysUpTime", "availability"},
		{"coldStart", "availability"},
		{"sysDescr", "system"},
		{"customOID", "general"},
	}

	for _, tt := range tests {
		t.Run(tt.oidName, func(t *testing.T) {
			event := &SNMPEvent{
				SNMP:   SNMPData{OIDName: tt.oidName},
				Source: SourceInfo{IP: "10.0.0.1"},
			}
			n.Process(event)

			if event.Category != tt.wantCat {
				t.Errorf("category for %q: want %q, got %q", tt.oidName, tt.wantCat, event.Category)
			}
		})
	}
}

func TestNormalizerSkipsPresetSeverity(t *testing.T) {
	n := newTestNormalizer()

	event := &SNMPEvent{
		SNMP:     SNMPData{OIDName: "linkDown"},
		Source:   SourceInfo{IP: "10.0.0.1"},
		Severity: SeverityCritical, // pre-set, should not be overwritten
	}
	n.Process(event)

	if event.Severity != SeverityCritical {
		t.Errorf("preset severity changed: want %d, got %d", SeverityCritical, event.Severity)
	}
}

func TestNormalizerSkipsPresetCategory(t *testing.T) {
	n := newTestNormalizer()

	event := &SNMPEvent{
		SNMP:     SNMPData{OIDName: "ifOperStatus"},
		Source:   SourceInfo{IP: "10.0.0.1"},
		Category: "custom-category",
	}
	n.Process(event)

	if event.Category != "custom-category" {
		t.Errorf("preset category changed: want %q, got %q", "custom-category", event.Category)
	}
}

// ── Enricher Tests ───────────────────────────────────────────────────

func TestEnricherAssetLookup(t *testing.T) {
	e := NewEnricher(zerolog.Nop())
	e.LoadAssets(map[string]AssetInfo{
		"10.0.0.1": {
			Hostname:    "core-router",
			Department:  "Network Engineering",
			Owner:       "admin@corp.local",
			Criticality: "critical",
			Location:    "DC-Tashkent-01",
			Environment: "production",
		},
	})

	event := &SNMPEvent{
		Source:   SourceInfo{IP: "10.0.0.1"},
		SNMP:    SNMPData{Version: "v2c"},
		Severity: SeverityLow,
	}
	e.Process(event)

	if event.Enrichment.AssetCriticality != "critical" {
		t.Errorf("criticality: want %q, got %q", "critical", event.Enrichment.AssetCriticality)
	}
	if event.Source.Hostname != "core-router" {
		t.Errorf("hostname: want %q, got %q", "core-router", event.Source.Hostname)
	}
	if event.Source.Location != "DC-Tashkent-01" {
		t.Errorf("location: want %q, got %q", "DC-Tashkent-01", event.Source.Location)
	}
	if event.Enrichment.CustomFields["department"] != "Network Engineering" {
		t.Error("department field missing")
	}
	if event.Enrichment.CustomFields["owner"] != "admin@corp.local" {
		t.Error("owner field missing")
	}
}

func TestEnricherSeverityAdjustment(t *testing.T) {
	e := NewEnricher(zerolog.Nop())
	e.LoadAssets(map[string]AssetInfo{
		"10.0.0.1": {Criticality: "critical"},
	})

	event := &SNMPEvent{
		Source:   SourceInfo{IP: "10.0.0.1"},
		SNMP:    SNMPData{Version: "v2c"},
		Severity: SeverityLow, // 3
	}
	e.Process(event)

	// Critical asset should bump severity by +2
	if event.Severity != SeverityMedium { // 3 + 2 = 5
		t.Errorf("adjusted severity: want %d, got %d", SeverityMedium, event.Severity)
	}
}

func TestEnricherSeverityNoAdjustForNonCritical(t *testing.T) {
	e := NewEnricher(zerolog.Nop())
	e.LoadAssets(map[string]AssetInfo{
		"10.0.0.1": {Criticality: "low"},
	})

	event := &SNMPEvent{
		Source:   SourceInfo{IP: "10.0.0.1"},
		SNMP:    SNMPData{Version: "v2c"},
		Severity: SeverityLow,
	}
	e.Process(event)

	if event.Severity != SeverityLow {
		t.Errorf("severity should not change for non-critical: want %d, got %d", SeverityLow, event.Severity)
	}
}

func TestEnricherTags(t *testing.T) {
	e := NewEnricher(zerolog.Nop())

	event := &SNMPEvent{
		Source:    SourceInfo{IP: "10.0.0.1", Vendor: "Cisco"},
		SNMP:     SNMPData{Version: "v3"},
		EventType: EventTypeTrap,
		Category: "security",
	}
	e.Process(event)

	expectedTags := map[string]bool{
		"snmp-v3":        true,
		"type-trap":      true,
		"vendor-cisco":   true,
		"cat-security":   true,
		"security-alert": true,
	}

	for _, tag := range event.Tags {
		delete(expectedTags, tag)
	}
	for missing := range expectedTags {
		t.Errorf("missing expected tag: %q", missing)
	}
}

func TestEnricherUnknownAsset(t *testing.T) {
	e := NewEnricher(zerolog.Nop())

	event := &SNMPEvent{
		Source: SourceInfo{IP: "99.99.99.99"},
		SNMP:  SNMPData{Version: "v2c"},
	}
	e.Process(event)

	// Should not crash, enrichment should be empty
	if event.Enrichment.AssetCriticality != "" {
		t.Errorf("unknown asset should have no criticality, got %q", event.Enrichment.AssetCriticality)
	}
}

func TestEnricherPreservesExistingHostname(t *testing.T) {
	e := NewEnricher(zerolog.Nop())
	e.LoadAssets(map[string]AssetInfo{
		"10.0.0.1": {Hostname: "asset-hostname"},
	})

	event := &SNMPEvent{
		Source: SourceInfo{IP: "10.0.0.1", Hostname: "original-hostname"},
		SNMP:  SNMPData{Version: "v2c"},
	}
	e.Process(event)

	// Should NOT overwrite existing hostname
	if event.Source.Hostname != "original-hostname" {
		t.Errorf("hostname overwritten: want %q, got %q", "original-hostname", event.Source.Hostname)
	}
}

// ── Pipeline Integration Tests ───────────────────────────────────────

func TestPipelineSubmitAndStats(t *testing.T) {
	normalizer := NewNormalizer(mib.NewResolver(zerolog.Nop()), zerolog.Nop())
	enricher := NewEnricher(zerolog.Nop())

	pipe := NewPipeline(zerolog.Nop(), PipelineConfig{
		BufferSize: 100,
		Workers:    2,
	}, normalizer, enricher, nil)

	// Test submit
	event := &SNMPEvent{
		ID:        "test-001",
		Timestamp: time.Now(),
		SNMP:      SNMPData{OID: "1.3.6.1.2.1.1.1"},
		Source:    SourceInfo{IP: "10.0.0.1"},
	}

	ok := pipe.Submit(event)
	if !ok {
		t.Error("submit should succeed when buffer is not full")
	}

	stats := pipe.Stats()
	if stats.EventsIn != 1 {
		t.Errorf("events in: want 1, got %d", stats.EventsIn)
	}
	if stats.RawQueueCap != 100 {
		t.Errorf("raw queue cap: want 100, got %d", stats.RawQueueCap)
	}
}

func TestPipelineBackPressure(t *testing.T) {
	pipe := NewPipeline(zerolog.Nop(), PipelineConfig{
		BufferSize: 2,
		Workers:    1,
	}, nil, nil, nil)

	// Fill the buffer
	for i := 0; i < 2; i++ {
		pipe.Submit(&SNMPEvent{
			ID:        "fill",
			Timestamp: time.Now(),
			Source:    SourceInfo{IP: "10.0.0.1"},
		})
	}

	// Next submit should fail (buffer full)
	ok := pipe.Submit(&SNMPEvent{
		ID:        "overflow",
		Timestamp: time.Now(),
		Source:    SourceInfo{IP: "10.0.0.1"},
	})

	if ok {
		t.Error("submit should fail when buffer is full")
	}

	stats := pipe.Stats()
	if stats.EventsDropped != 1 {
		t.Errorf("events dropped: want 1, got %d", stats.EventsDropped)
	}
}

// ── Helper Function Tests ────────────────────────────────────────────

func TestContainsAny(t *testing.T) {
	tests := []struct {
		s      string
		subs   []string
		want   bool
	}{
		{"ifOperStatus", []string{"if", "link"}, true},
		{"authenticationFailure", []string{"auth", "security"}, true},
		{"hrProcessorLoad", []string{"cpu", "Processor"}, true},
		{"customOID", []string{"auth", "if"}, false},
		{"", []string{"any"}, false},
		{"anything", []string{}, false},
	}

	for _, tt := range tests {
		got := containsAny(tt.s, tt.subs...)
		if got != tt.want {
			t.Errorf("containsAny(%q, %v): want %v, got %v", tt.s, tt.subs, tt.want, got)
		}
	}
}

func TestToLower(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"Hello", "hello"},
		{"UPPER", "upper"},
		{"already lower", "already lower"},
		{"MiXeD123", "mixed123"},
		{"", ""},
	}

	for _, tt := range tests {
		got := toLower(tt.input)
		if got != tt.want {
			t.Errorf("toLower(%q): want %q, got %q", tt.input, tt.want, got)
		}
	}
}
