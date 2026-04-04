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

// ── trapToEvents Tests ───────────────────────────────────────────────

func TestTrapToEventsV2c(t *testing.T) {
	l := newTestListener()

	packet := &gosnmp.SnmpPacket{
		Version:   gosnmp.Version2c,
		Community: "public",
		Variables: []gosnmp.SnmpPDU{
			{
				Name:  ".1.3.6.1.2.1.1.3.0",
				Type:  gosnmp.TimeTicks,
				Value: uint32(12345),
			},
			{
				Name:  ".1.3.6.1.6.3.1.1.4.1.0",
				Type:  gosnmp.ObjectIdentifier,
				Value: "1.3.6.1.6.3.1.1.5.3",
			},
			{
				Name:  ".1.3.6.1.2.1.2.2.1.8.1",
				Type:  gosnmp.Integer,
				Value: 2,
			},
		},
	}

	events := l.trapToEvents(packet, "10.0.0.1")

	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}

	evt := events[0]

	if evt.EventType != pipeline.EventTypeTrap {
		t.Errorf("event type: want %q, got %q", pipeline.EventTypeTrap, evt.EventType)
	}
	if evt.Version != "v2c" {
		t.Errorf("version: want %q, got %q", "v2c", evt.Version)
	}
	if evt.OID != "1.3.6.1.6.3.1.1.5.3" {
		t.Errorf("trap OID: want %q, got %q", "1.3.6.1.6.3.1.1.5.3", evt.OID)
	}
	if evt.DeviceIP != "10.0.0.1" {
		t.Errorf("device ip: want %q, got %q", "10.0.0.1", evt.DeviceIP)
	}
	if evt.DeviceHostname != "router-01" {
		t.Errorf("device hostname: want %q, got %q", "router-01", evt.DeviceHostname)
	}
	if evt.DeviceVendor != "Cisco" {
		t.Errorf("device vendor: want %q, got %q", "Cisco", evt.DeviceVendor)
	}
	if evt.DeviceLocation != "DC-1" {
		t.Errorf("device location: want %q, got %q", "DC-1", evt.DeviceLocation)
	}
}

func TestTrapToEventsV1(t *testing.T) {
	l := newTestListener()

	packet := &gosnmp.SnmpPacket{
		Version: gosnmp.Version1,
		SnmpTrap: gosnmp.SnmpTrap{
			Enterprise:   ".1.3.6.1.4.1.9.9.13",
			GenericTrap:  6,
			SpecificTrap: 1,
		},
		Variables: []gosnmp.SnmpPDU{
			{
				Name:  ".1.3.6.1.4.1.9.9.13.1.3.1.3.1",
				Type:  gosnmp.Integer,
				Value: 55,
			},
		},
	}

	events := l.trapToEvents(packet, "10.0.0.1")

	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}

	evt := events[0]
	if evt.EventType != pipeline.EventTypeTrap {
		t.Errorf("event type: want %q, got %q", pipeline.EventTypeTrap, evt.EventType)
	}
	if evt.Version != "v1" {
		t.Errorf("version: want %q, got %q", "v1", evt.Version)
	}
}

func TestTrapToEventsVarsPopulated(t *testing.T) {
	l := newTestListener()

	packet := &gosnmp.SnmpPacket{
		Version: gosnmp.Version2c,
		Variables: []gosnmp.SnmpPDU{
			{
				Name:  ".1.3.6.1.6.3.1.1.4.1.0",
				Type:  gosnmp.ObjectIdentifier,
				Value: "1.3.6.1.6.3.1.1.5.3",
			},
			{
				Name:  ".1.3.6.1.2.1.2.2.1.8.1",
				Type:  gosnmp.Integer,
				Value: 2,
			},
			{
				Name:  ".1.3.6.1.2.1.2.2.1.2.1",
				Type:  gosnmp.OctetString,
				Value: []byte("GigabitEthernet0/1"),
			},
		},
	}

	events := l.trapToEvents(packet, "10.0.0.1")
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}

	evt := events[0]
	if len(evt.Variables) != 2 {
		t.Errorf("variables: want 2, got %d", len(evt.Variables))
	}
	if evt.Value == nil {
		t.Error("primary value should be set from first variable")
	}
}

// ── Source device enrichment ─────────────────────────────────────────

func TestTrapEnrichesFromRegistry(t *testing.T) {
	l := newTestListener()

	packet := &gosnmp.SnmpPacket{
		Version: gosnmp.Version2c,
		Variables: []gosnmp.SnmpPDU{
			{
				Name:  ".1.3.6.1.6.3.1.1.4.1.0",
				Type:  gosnmp.ObjectIdentifier,
				Value: "1.3.6.1.6.3.1.1.5.3",
			},
		},
	}

	events := l.trapToEvents(packet, "10.0.0.1")
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}

	if events[0].DeviceHostname != "router-01" {
		t.Errorf("hostname: want %q, got %q", "router-01", events[0].DeviceHostname)
	}
	if events[0].DeviceVendor != "Cisco" {
		t.Errorf("vendor: want %q, got %q", "Cisco", events[0].DeviceVendor)
	}
}

// ── isDuplicate Tests ────────────────────────────────────────────────

func TestIsDuplicateFirstSeen(t *testing.T) {
	l := newTestListener()

	evt := &pipeline.SNMPEvent{
		ID:        "test-id",
		Timestamp: time.Now(),
		DeviceIP:  "10.0.0.1",
		OID:       "1.3.6.1.6.3.1.1.5.3",
	}

	if l.isDuplicate(evt) {
		t.Error("first time should not be duplicate")
	}
}

func TestIsDuplicateReplay(t *testing.T) {
	l := newTestListener()

	evt := &pipeline.SNMPEvent{
		ID:        "test-id",
		Timestamp: time.Now(),
		DeviceIP:  "10.0.0.1",
		OID:       "1.3.6.1.6.3.1.1.5.3",
	}

	l.isDuplicate(evt) // first time: register
	if !l.isDuplicate(evt) {
		t.Error("second time should be duplicate within TTL")
	}
}

// ── extractTrapValue Tests ───────────────────────────────────────────

func TestExtractTrapValueInteger(t *testing.T) {
	pdu := &gosnmp.SnmpPDU{
		Type:  gosnmp.Integer,
		Value: 42,
	}
	val, typ := extractTrapValue(pdu)
	if val != 42 {
		t.Errorf("value: want 42, got %v", val)
	}
	if typ != "Integer" {
		t.Errorf("type: want Integer, got %s", typ)
	}
}

func TestExtractTrapValueOctetString(t *testing.T) {
	pdu := &gosnmp.SnmpPDU{
		Type:  gosnmp.OctetString,
		Value: []byte("hello"),
	}
	val, typ := extractTrapValue(pdu)
	if val != "hello" {
		t.Errorf("value: want %q, got %v", "hello", val)
	}
	if typ != "OctetString" {
		t.Errorf("type: want OctetString, got %s", typ)
	}
}

func TestExtractTrapValueIPAddress(t *testing.T) {
	pdu := &gosnmp.SnmpPDU{
		Type:  gosnmp.IPAddress,
		Value: "192.168.1.1",
	}
	val, typ := extractTrapValue(pdu)
	if val != "192.168.1.1" {
		t.Errorf("value: want %q, got %v", "192.168.1.1", val)
	}
	if typ != "IPAddress" {
		t.Errorf("type: want IPAddress, got %s", typ)
	}
}

// ── versionString Tests ──────────────────────────────────────────────

func TestVersionString(t *testing.T) {
	tests := []struct {
		v    gosnmp.SnmpVersion
		want string
	}{
		{gosnmp.Version1, "v1"},
		{gosnmp.Version2c, "v2c"},
		{gosnmp.Version3, "v3"},
		{gosnmp.SnmpVersion(99), "unknown"},
	}

	for _, tt := range tests {
		got := versionString(tt.v)
		if got != tt.want {
			t.Errorf("versionString(%v): want %q, got %q", tt.v, tt.want, got)
		}
	}
}
