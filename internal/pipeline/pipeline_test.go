package pipeline

import (
	"testing"
	"time"

	"github.com/rs/zerolog"

	"github.com/me262/snmp-manager/internal/mib"
)

func newTestNormalizer() *Normalizer {
	resolver := mib.NewResolver(zerolog.Nop())
	return NewNormalizer(resolver, zerolog.Nop(), false)
}

func TestNormalizerOIDResolution(t *testing.T) {
	n := newTestNormalizer()

	event := &SNMPEvent{
		OID:      "1.3.6.1.2.1.1.1",
		DeviceIP: "10.0.0.1",
	}

	n.Process(event)

	if event.OIDName != "sysDescr" {
		t.Errorf("OID name: want %q, got %q", "sysDescr", event.OIDName)
	}
}

func TestNormalizerCategorySystem(t *testing.T) {
	n := newTestNormalizer()

	event := &SNMPEvent{
		OID:      "1.3.6.1.2.1.1.5.0",
		DeviceIP: "10.0.0.1",
	}
	n.Process(event)

	if event.Category != CategorySystem {
		t.Errorf("category: want %q, got %q", CategorySystem, event.Category)
	}
}

func TestNormalizerCategoryNetwork(t *testing.T) {
	n := newTestNormalizer()

	event := &SNMPEvent{
		OID:      "1.3.6.1.2.1.2.2.1.8.1",
		DeviceIP: "10.0.0.1",
	}
	n.Process(event)

	if event.Category != CategoryNetwork {
		t.Errorf("category: want %q, got %q", CategoryNetwork, event.Category)
	}
}

func TestNormalizerCategoryEnvironment(t *testing.T) {
	n := newTestNormalizer()

	// MikroTik CPU temperature
	event := &SNMPEvent{
		OID:      "1.3.6.1.4.1.14988.1.1.3.10",
		DeviceIP: "10.0.0.1",
	}
	n.Process(event)

	if event.Category != CategoryEnvironment {
		t.Errorf("category: want %q, got %q", CategoryEnvironment, event.Category)
	}
}

func TestNormalizerTemperatureMetric(t *testing.T) {
	n := newTestNormalizer()

	// MikroTik temperature raw value = 420 (42.0°C)
	event := &SNMPEvent{
		OID:      "1.3.6.1.4.1.14988.1.1.3.10",
		OIDName:  "mtxrHlCpuTemperature",
		Value:    420,
		DeviceIP: "10.0.0.1",
	}
	n.Process(event)

	if event.MetricUnit != "°C" {
		t.Errorf("unit: want °C, got %q", event.MetricUnit)
	}
	if event.MetricValue == nil || *event.MetricValue != 42.0 {
		t.Errorf("metric value: want 42.0, got %v", event.MetricValue)
	}
}

func TestNormalizerSeverityLinkDown(t *testing.T) {
	n := newTestNormalizer()

	event := &SNMPEvent{
		OID:       "1.3.6.1.6.3.1.1.5.3",
		OIDName:   "linkDown",
		EventType: EventTypeTrap,
		TrapOID:   "1.3.6.1.6.3.1.1.5.3",
		DeviceIP:  "10.0.0.1",
	}
	n.Process(event)

	if event.Severity != SeverityHigh {
		t.Errorf("severity for linkDown: want %d (high), got %d", SeverityHigh, event.Severity)
	}
}

func TestNormalizerSeverityAuthFailure(t *testing.T) {
	n := newTestNormalizer()

	event := &SNMPEvent{
		OID:       "1.3.6.1.6.3.1.1.5.5",
		OIDName:   "authenticationFailure",
		EventType: EventTypeTrap,
		TrapOID:   "1.3.6.1.6.3.1.1.5.5",
		DeviceIP:  "10.0.0.1",
	}
	n.Process(event)

	if event.Severity != SeverityHigh {
		t.Errorf("severity for authFailure: want %d (high), got %d", SeverityHigh, event.Severity)
	}
}

func TestValueStrPopulated(t *testing.T) {
	n := newTestNormalizer()

	event := &SNMPEvent{
		OID:      "1.3.6.1.2.1.1.1",
		Value:    "Cisco IOS Software",
		DeviceIP: "10.0.0.1",
	}
	n.Process(event)

	if event.ValueStr == "" {
		t.Error("ValueStr should be populated after normalization")
	}
}

// ── Enricher Tests ───────────────────────────────────────────────────

func TestEnricherLoadAndEnrich(t *testing.T) {
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
		DeviceIP: "10.0.0.1",
		Version:  "v2c",
		Severity: SeverityLow,
	}
	e.Process(event)

	if event.AssetCriticality != "critical" {
		t.Errorf("criticality: want %q, got %q", "critical", event.AssetCriticality)
	}
	if event.DeviceHostname != "core-router" {
		t.Errorf("hostname: want %q, got %q", "core-router", event.DeviceHostname)
	}
	if event.DeviceLocation != "DC-Tashkent-01" {
		t.Errorf("location: want %q, got %q", "DC-Tashkent-01", event.DeviceLocation)
	}
	if event.CustomFields["department"] != "Network Engineering" {
		t.Error("department field missing")
	}
	if event.CustomFields["owner"] != "admin@corp.local" {
		t.Error("owner field missing")
	}
}

func TestEnricherSeverityAdjustment(t *testing.T) {
	e := NewEnricher(zerolog.Nop())
	e.LoadAssets(map[string]AssetInfo{
		"10.0.0.1": {Criticality: "critical"},
	})

	event := &SNMPEvent{
		DeviceIP: "10.0.0.1",
		Version:  "v2c",
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
		DeviceIP: "10.0.0.1",
		Version:  "v2c",
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
		DeviceIP:     "10.0.0.1",
		DeviceVendor: "Cisco",
		Version:      "v3",
		EventType:    EventTypeTrap,
		Category:     CategorySecurity,
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

	event := &SNMPEvent{DeviceIP: "99.99.99.99", Version: "v2c"}
	e.Process(event)

	// Should not crash, enrichment should be empty
	if event.AssetCriticality != "" {
		t.Errorf("unknown asset should have no criticality, got %q", event.AssetCriticality)
	}
}

func TestEnricherPreservesExistingHostname(t *testing.T) {
	e := NewEnricher(zerolog.Nop())
	e.LoadAssets(map[string]AssetInfo{
		"10.0.0.1": {Hostname: "asset-hostname"},
	})

	event := &SNMPEvent{
		DeviceIP:       "10.0.0.1",
		DeviceHostname: "original-hostname",
		Version:        "v2c",
	}
	e.Process(event)

	// Should NOT overwrite existing hostname
	if event.DeviceHostname != "original-hostname" {
		t.Errorf("hostname overwritten: want %q, got %q", "original-hostname", event.DeviceHostname)
	}
}

// ── Pipeline Integration Tests ───────────────────────────────────────

func TestPipelineSubmitAndStats(t *testing.T) {
	normalizer := NewNormalizer(mib.NewResolver(zerolog.Nop()), zerolog.Nop(), false)
	enricher := NewEnricher(zerolog.Nop())

	pipe := NewPipeline(zerolog.Nop(), PipelineConfig{
		BufferSize: 100,
		Workers:    2,
	}, normalizer, enricher, nil)

	// Test submit
	event := &SNMPEvent{
		ID:        "test-001",
		Timestamp: time.Now(),
		OID:       "1.3.6.1.2.1.1.1",
		DeviceIP:  "10.0.0.1",
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
			DeviceIP:  "10.0.0.1",
		})
	}

	// Next submit should fail (buffer full)
	ok := pipe.Submit(&SNMPEvent{
		ID:        "overflow",
		Timestamp: time.Now(),
		DeviceIP:  "10.0.0.1",
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
		s    string
		subs []string
		want bool
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
