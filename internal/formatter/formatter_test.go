package formatter

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/me262/snmp-manager/internal/pipeline"
)

func sampleEvent() *pipeline.SNMPEvent {
	return &pipeline.SNMPEvent{
		ID:        "evt-12345678-abcd",
		Timestamp: time.Date(2026, 3, 10, 12, 0, 0, 0, time.UTC),
		EventType: pipeline.EventTypeTrap,
		Source: pipeline.SourceInfo{
			IP:         "192.168.1.1",
			Hostname:   "core-router-01",
			DeviceType: "router",
			Vendor:     "Cisco",
			Location:   "DC-Tashkent",
		},
		SNMP: pipeline.SNMPData{
			Version:     "v2c",
			OID:         "1.3.6.1.6.3.1.1.5.3",
			OIDName:     "linkDown",
			OIDModule:   "IF-MIB",
			Value:       2,
			ValueType:   "Integer",
			ValueString: "down",
			RequestType: "trap",
			Variables: []pipeline.Variable{
				{OID: "1.3.6.1.2.1.2.2.1.8.1", OIDName: "ifOperStatus.1", Value: 2, ValueType: "Integer"},
				{OID: "1.3.6.1.2.1.2.2.1.2.1", OIDName: "ifDescr.1", Value: "GigabitEthernet0/1", ValueType: "OctetString"},
			},
		},
		Severity:      pipeline.SeverityHigh,
		SeverityLabel: "high",
		Category:      "network",
		Tags:          []string{"snmp-v2c", "type-trap", "vendor-cisco"},
	}
}

// ── CEF Formatter Tests ─────────────────────────────────────────────

func TestCEFFormatBasic(t *testing.T) {
	f := NewCEFFormatter()
	event := sampleEvent()

	result, err := f.Format(event)
	if err != nil {
		t.Fatalf("CEF format error: %v", err)
	}

	// Check CEF header prefix
	if !strings.HasPrefix(result, "CEF:0|") {
		t.Errorf("CEF should start with 'CEF:0|', got: %s", result[:20])
	}

	// Check vendor
	if !strings.Contains(result, "SNMPManager") {
		t.Error("CEF should contain vendor name")
	}

	// Check event name
	if !strings.Contains(result, "linkDown") {
		t.Error("CEF should contain event name 'linkDown'")
	}

	// Check severity (7 = high)
	if !strings.Contains(result, "|7|") {
		t.Error("CEF should contain severity 7")
	}

	// Check extensions
	if !strings.Contains(result, "src=192.168.1.1") {
		t.Error("CEF should contain src IP")
	}
	if !strings.Contains(result, "shost=core-router-01") {
		t.Error("CEF should contain hostname")
	}
	if !strings.Contains(result, "cat=network") {
		t.Error("CEF should contain category")
	}
}

func TestCEFFormatClassID(t *testing.T) {
	f := NewCEFFormatter()

	tests := []struct {
		oid     string
		classID string
	}{
		{"1.3.6.1.6.3.1.1.5.1", "SNMP-COLD-START"},
		{"1.3.6.1.6.3.1.1.5.3", "SNMP-LINK-DOWN"},
		{"1.3.6.1.6.3.1.1.5.5", "SNMP-AUTH-FAIL"},
		{"1.3.6.1.2.1.1.1.0", "SNMP-EVENT"},
	}

	for _, tt := range tests {
		event := sampleEvent()
		event.SNMP.OID = tt.oid
		result, _ := f.Format(event)
		if !strings.Contains(result, tt.classID) {
			t.Errorf("OID %s: CEF should contain class ID %q", tt.oid, tt.classID)
		}
	}
}

func TestCEFEscaping(t *testing.T) {
	f := NewCEFFormatter()
	event := sampleEvent()
	event.SNMP.ValueString = "value=with|special\\chars"

	result, err := f.Format(event)
	if err != nil {
		t.Fatalf("error: %v", err)
	}

	// Value should be escaped
	if strings.Contains(result, "value=with|special\\chars") {
		t.Error("CEF should escape special characters in extension values")
	}
}

// ── JSON Formatter Tests ────────────────────────────────────────────

func TestJSONFormat(t *testing.T) {
	f := NewJSONFormatter(false)
	event := sampleEvent()

	result, err := f.Format(event)
	if err != nil {
		t.Fatalf("JSON format error: %v", err)
	}

	// Should be valid JSON
	var parsed map[string]any
	if err := json.Unmarshal([]byte(result), &parsed); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	// Check key fields
	if parsed["id"] != "evt-12345678-abcd" {
		t.Errorf("id: want %q, got %v", "evt-12345678-abcd", parsed["id"])
	}
	if parsed["severity_label"] != "high" {
		t.Errorf("severity_label: want %q, got %v", "high", parsed["severity_label"])
	}
	if parsed["category"] != "network" {
		t.Errorf("category: want %q, got %v", "network", parsed["category"])
	}

	// Check nested source
	source, ok := parsed["source"].(map[string]any)
	if !ok {
		t.Fatal("source field not a map")
	}
	if source["ip"] != "192.168.1.1" {
		t.Errorf("source.ip: want %q, got %v", "192.168.1.1", source["ip"])
	}
}

func TestJSONFormatPretty(t *testing.T) {
	f := NewJSONFormatter(true)
	event := sampleEvent()

	result, err := f.Format(event)
	if err != nil {
		t.Fatalf("error: %v", err)
	}

	// Pretty JSON should have indentation
	if !strings.Contains(result, "\n") {
		t.Error("pretty JSON should contain newlines")
	}
	if !strings.Contains(result, "  ") {
		t.Error("pretty JSON should contain indentation")
	}
}

func TestJSONNoSensitiveData(t *testing.T) {
	f := NewJSONFormatter(false)
	event := sampleEvent()
	event.SNMP.Community = "super-secret-community"

	result, _ := f.Format(event)

	// Community string should NOT appear in output (json:"-" tag)
	if strings.Contains(result, "super-secret-community") {
		t.Error("JSON output should NOT contain community string")
	}
}

// ── Syslog Formatter Tests ──────────────────────────────────────────

func TestSyslogFormat(t *testing.T) {
	f := NewSyslogFormatter()
	event := sampleEvent()

	result, err := f.Format(event)
	if err != nil {
		t.Fatalf("Syslog format error: %v", err)
	}

	// Check priority (facility=16, severity=3 for high → priority = 16*8+3 = 131)
	if !strings.HasPrefix(result, "<131>1") {
		t.Errorf("Syslog priority: want <131>1, got prefix: %s", result[:10])
	}

	// Check hostname
	if !strings.Contains(result, "core-router-01") {
		t.Error("Syslog should contain hostname")
	}

	// Check structured data
	if !strings.Contains(result, "[snmp") {
		t.Error("Syslog should contain structured data [snmp ...]")
	}
	if !strings.Contains(result, `oid="1.3.6.1.6.3.1.1.5.3"`) {
		t.Error("Syslog SD should contain OID")
	}
	if !strings.Contains(result, `name="linkDown"`) {
		t.Error("Syslog SD should contain OID name")
	}

	// Check msg ID
	if !strings.Contains(result, "SNMP_TRAP") {
		t.Error("Syslog should contain msg ID SNMP_TRAP")
	}
}

func TestSyslogSeverityMapping(t *testing.T) {
	tests := []struct {
		severity pipeline.Severity
		syslog   int
	}{
		{pipeline.SeverityCritical, 2},
		{pipeline.SeverityHigh, 3},
		{pipeline.SeverityMedium, 4},
		{pipeline.SeverityLow, 5},
		{pipeline.SeverityInfo, 6},
	}

	for _, tt := range tests {
		got := mapToSyslogSeverity(tt.severity)
		if got != tt.syslog {
			t.Errorf("mapToSyslogSeverity(%d): want %d, got %d", tt.severity, tt.syslog, got)
		}
	}
}

func TestSyslogFallbackHostname(t *testing.T) {
	f := NewSyslogFormatter()
	event := sampleEvent()
	event.Source.Hostname = "" // No hostname

	result, _ := f.Format(event)

	// Should fall back to IP
	if !strings.Contains(result, "192.168.1.1") {
		t.Error("Syslog should use IP when hostname is empty")
	}
}

// ── LEEF Formatter Tests ────────────────────────────────────────────

func TestLEEFFormat(t *testing.T) {
	f := NewLEEFFormatter()
	event := sampleEvent()

	result, err := f.Format(event)
	if err != nil {
		t.Fatalf("LEEF format error: %v", err)
	}

	if !strings.HasPrefix(result, "LEEF:2.0|") {
		t.Errorf("LEEF should start with 'LEEF:2.0|', got: %s", result[:15])
	}

	if !strings.Contains(result, "SNMPManager") {
		t.Error("LEEF should contain vendor")
	}
	if !strings.Contains(result, "linkDown") {
		t.Error("LEEF should contain event ID")
	}
	if !strings.Contains(result, "src=192.168.1.1") {
		t.Error("LEEF should contain source IP")
	}
	if !strings.Contains(result, "sev=7") {
		t.Error("LEEF should contain severity")
	}
}

// ── Helper Function Tests ───────────────────────────────────────────

func TestMapOIDToClassID(t *testing.T) {
	tests := []struct {
		oid  string
		want string
	}{
		{"1.3.6.1.6.3.1.1.5.1", "SNMP-COLD-START"},
		{"1.3.6.1.6.3.1.1.5.2", "SNMP-WARM-START"},
		{"1.3.6.1.6.3.1.1.5.3", "SNMP-LINK-DOWN"},
		{"1.3.6.1.6.3.1.1.5.4", "SNMP-LINK-UP"},
		{"1.3.6.1.6.3.1.1.5.5", "SNMP-AUTH-FAIL"},
		{"1.3.6.1.2.1.1.1.0", "SNMP-EVENT"},
	}

	for _, tt := range tests {
		got := mapOIDToClassID(tt.oid)
		if got != tt.want {
			t.Errorf("mapOIDToClassID(%q): want %q, got %q", tt.oid, tt.want, got)
		}
	}
}

func TestEscCEFHeader(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"no special", "no special"},
		{"pipe|here", "pipe\\|here"},
		{"back\\slash", "back\\\\slash"},
		{"both|and\\mixed", "both\\|and\\\\mixed"},
	}

	for _, tt := range tests {
		got := escCEFHeader(tt.input)
		if got != tt.want {
			t.Errorf("escCEFHeader(%q): want %q, got %q", tt.input, tt.want, got)
		}
	}
}

func TestEscCEF(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"normal", "normal"},
		{"key=value", "key\\=value"},
		{"line\nbreak", "line\\nbreak"},
		{"back\\slash", "back\\\\slash"},
	}

	for _, tt := range tests {
		got := escCEF(tt.input)
		if got != tt.want {
			t.Errorf("escCEF(%q): want %q, got %q", tt.input, tt.want, got)
		}
	}
}

func TestEscSD(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"normal", "normal"},
		{`say "hello"`, `say \"hello\"`},
		{"close]bracket", "close\\]bracket"},
		{"back\\slash", "back\\\\slash"},
	}

	for _, tt := range tests {
		got := escSD(tt.input)
		if got != tt.want {
			t.Errorf("escSD(%q): want %q, got %q", tt.input, tt.want, got)
		}
	}
}

func TestMapEventTypeToMsgID(t *testing.T) {
	tests := []struct {
		et   pipeline.EventType
		want string
	}{
		{pipeline.EventTypeTrap, "SNMP_TRAP"},
		{pipeline.EventTypePoll, "SNMP_POLL"},
		{pipeline.EventTypeInform, "SNMP_INFORM"},
		{pipeline.EventType("other"), "SNMP_EVENT"},
	}

	for _, tt := range tests {
		got := mapEventTypeToMsgID(tt.et)
		if got != tt.want {
			t.Errorf("mapEventTypeToMsgID(%q): want %q, got %q", tt.et, tt.want, got)
		}
	}
}
