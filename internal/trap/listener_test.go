package trap

import (
	"testing"
	"time"

	"github.com/gosnmp/gosnmp"
	"github.com/rs/zerolog"

	"github.com/me262/snmp-manager/internal/config"
	"github.com/me262/snmp-manager/internal/device"
	"github.com/me262/snmp-manager/internal/mib"
	"github.com/me262/snmp-manager/internal/pipeline"
)

func newTestListener() *Listener {
	log := zerolog.Nop()
	registry := device.NewRegistry(log)
	registry.Add(&device.Device{
		Name: "test-router", IP: "10.0.0.1", Port: 161,
		SysName: "router-01", Vendor: "Cisco", DeviceType: "router",
		Tags: map[string]string{"location": "DC-1"},
	})

	resolver := mib.NewResolver(log)
	pp := pipeline.NewPipeline(log, pipeline.PipelineConfig{BufferSize: 100, Workers: 1}, nil, nil, nil)

	return NewListener(log, config.TrapReceiverConfig{
		Enabled:       true,
		ListenAddress: "0.0.0.0:11620",
	}, registry, resolver, pp)
}

func TestVersionString(t *testing.T) {
	tests := []struct {
		ver  gosnmp.SnmpVersion
		want string
	}{
		{gosnmp.Version1, "v1"},
		{gosnmp.Version2c, "v2c"},
		{gosnmp.Version3, "v3"},
		{99, "unknown"},
	}

	for _, tt := range tests {
		got := versionString(tt.ver)
		if got != tt.want {
			t.Errorf("versionString(%v): want %q, got %q", tt.ver, tt.want, got)
		}
	}
}

func TestExtractTrapValue(t *testing.T) {
	tests := []struct {
		name     string
		pdu      gosnmp.SnmpPDU
		wantType string
	}{
		{"OctetString", gosnmp.SnmpPDU{Type: gosnmp.OctetString, Value: []byte("test")}, "OctetString"},
		{"Integer", gosnmp.SnmpPDU{Type: gosnmp.Integer, Value: 42}, "Integer"},
		{"Counter32", gosnmp.SnmpPDU{Type: gosnmp.Counter32, Value: uint(100)}, "Counter32"},
		{"Counter64", gosnmp.SnmpPDU{Type: gosnmp.Counter64, Value: uint64(999)}, "Counter64"},
		{"Gauge32", gosnmp.SnmpPDU{Type: gosnmp.Gauge32, Value: uint(50)}, "Gauge32"},
		{"IPAddress", gosnmp.SnmpPDU{Type: gosnmp.IPAddress, Value: "1.2.3.4"}, "IPAddress"},
		{"ObjectIdentifier", gosnmp.SnmpPDU{Type: gosnmp.ObjectIdentifier, Value: ".1.3.6.1"}, "ObjectIdentifier"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			val, typ := extractTrapValue(&tt.pdu)
			if typ != tt.wantType {
				t.Errorf("type: want %q, got %q", tt.wantType, typ)
			}
			if val == nil {
				t.Error("value should not be nil")
			}
		})
	}
}

func TestIsDuplicate(t *testing.T) {
	l := newTestListener()
	l.dedupTTL = 1 * time.Second

	event := &pipeline.SNMPEvent{
		Source: pipeline.SourceInfo{IP: "10.0.0.1"},
		SNMP:   pipeline.SNMPData{OID: "1.3.6.1.6.3.1.1.5.3"},
	}

	// First time — not duplicate
	if l.isDuplicate(event) {
		t.Error("first event should not be duplicate")
	}

	// Second time — is duplicate
	if !l.isDuplicate(event) {
		t.Error("second event should be duplicate")
	}

	// Different OID — not duplicate
	event2 := &pipeline.SNMPEvent{
		Source: pipeline.SourceInfo{IP: "10.0.0.1"},
		SNMP:   pipeline.SNMPData{OID: "1.3.6.1.6.3.1.1.5.4"},
	}
	if l.isDuplicate(event2) {
		t.Error("different OID should not be duplicate")
	}

	// Different IP — not duplicate
	event3 := &pipeline.SNMPEvent{
		Source: pipeline.SourceInfo{IP: "10.0.0.2"},
		SNMP:   pipeline.SNMPData{OID: "1.3.6.1.6.3.1.1.5.3"},
	}
	if l.isDuplicate(event3) {
		t.Error("different IP should not be duplicate")
	}

	// After TTL expires — not duplicate
	time.Sleep(1100 * time.Millisecond)
	if l.isDuplicate(event) {
		t.Error("event should not be duplicate after TTL expires")
	}
}

func TestTrapToEventsV2c(t *testing.T) {
	l := newTestListener()

	packet := &gosnmp.SnmpPacket{
		Version: gosnmp.Version2c,
		Variables: []gosnmp.SnmpPDU{
			// sysUpTime.0
			{Name: ".1.3.6.1.2.1.1.3.0", Type: gosnmp.TimeTicks, Value: uint32(123456)},
			// snmpTrapOID.0 → linkDown
			{Name: ".1.3.6.1.6.3.1.1.4.1.0", Type: gosnmp.ObjectIdentifier, Value: ".1.3.6.1.6.3.1.1.5.3"},
			// ifOperStatus.1 = down(2)
			{Name: ".1.3.6.1.2.1.2.2.1.8.1", Type: gosnmp.Integer, Value: 2},
			// ifDescr.1
			{Name: ".1.3.6.1.2.1.2.2.1.2.1", Type: gosnmp.OctetString, Value: []byte("GigabitEthernet0/1")},
		},
	}

	events := l.trapToEvents(packet, "10.0.0.1")

	if len(events) != 1 {
		t.Fatalf("events: want 1, got %d", len(events))
	}

	evt := events[0]
	// Should have extracted the trap OID
	if evt.SNMP.OID != "1.3.6.1.6.3.1.1.5.3" {
		t.Errorf("trap OID: want %q, got %q", "1.3.6.1.6.3.1.1.5.3", evt.SNMP.OID)
	}
	if evt.SNMP.Version != "v2c" {
		t.Errorf("version: want %q, got %q", "v2c", evt.SNMP.Version)
	}
	if evt.EventType != pipeline.EventTypeTrap {
		t.Errorf("event type: want %q, got %q", pipeline.EventTypeTrap, evt.EventType)
	}

	// Should have 2 variables (sysUpTime and snmpTrapOID are filtered out)
	if len(evt.SNMP.Variables) != 2 {
		t.Errorf("variables: want 2, got %d", len(evt.SNMP.Variables))
	}

	// Source info from known device
	if evt.Source.Hostname != "router-01" {
		t.Errorf("hostname: want %q, got %q", "router-01", evt.Source.Hostname)
	}
	if evt.Source.Vendor != "Cisco" {
		t.Errorf("vendor: want %q, got %q", "Cisco", evt.Source.Vendor)
	}
	if evt.Source.Location != "DC-1" {
		t.Errorf("location: want %q, got %q", "DC-1", evt.Source.Location)
	}
}

func TestTrapToEventsUnknownDevice(t *testing.T) {
	l := newTestListener()

	packet := &gosnmp.SnmpPacket{
		Version: gosnmp.Version2c,
		Variables: []gosnmp.SnmpPDU{
			{Name: ".1.3.6.1.6.3.1.1.4.1.0", Type: gosnmp.ObjectIdentifier, Value: ".1.3.6.1.6.3.1.1.5.5"},
		},
	}

	events := l.trapToEvents(packet, "99.99.99.99")

	if len(events) != 1 {
		t.Fatalf("events: want 1, got %d", len(events))
	}

	// Unknown device — should have IP but no hostname/vendor
	if events[0].Source.IP != "99.99.99.99" {
		t.Errorf("IP: want %q, got %q", "99.99.99.99", events[0].Source.IP)
	}
	if events[0].Source.Hostname != "" {
		t.Errorf("hostname should be empty for unknown device, got %q", events[0].Source.Hostname)
	}
}

func TestTrapStats(t *testing.T) {
	l := newTestListener()
	l.totalTraps = 100
	l.v1Traps = 10
	l.v2cTraps = 70
	l.v3Traps = 15
	l.droppedTraps = 5

	stats := l.Stats()
	if stats.TotalTraps != 100 {
		t.Errorf("total: want 100, got %d", stats.TotalTraps)
	}
	if stats.V2cTraps != 70 {
		t.Errorf("v2c: want 70, got %d", stats.V2cTraps)
	}
	if stats.DroppedTraps != 5 {
		t.Errorf("dropped: want 5, got %d", stats.DroppedTraps)
	}
}

func TestParseAuthProtocolTrap(t *testing.T) {
	tests := []struct {
		input string
		want  gosnmp.SnmpV3AuthProtocol
	}{
		{"SHA256", gosnmp.SHA256},
		{"MD5", gosnmp.MD5},
		{"unknown", gosnmp.SHA256},
	}
	for _, tt := range tests {
		got := parseAuthProtocol(tt.input)
		if got != tt.want {
			t.Errorf("parseAuthProtocol(%q): want %v, got %v", tt.input, tt.want, got)
		}
	}
}

func TestParsePrivProtocolTrap(t *testing.T) {
	tests := []struct {
		input string
		want  gosnmp.SnmpV3PrivProtocol
	}{
		{"AES256", gosnmp.AES256},
		{"DES", gosnmp.DES},
		{"unknown", gosnmp.AES256},
	}
	for _, tt := range tests {
		got := parsePrivProtocol(tt.input)
		if got != tt.want {
			t.Errorf("parsePrivProtocol(%q): want %v, got %v", tt.input, tt.want, got)
		}
	}
}
