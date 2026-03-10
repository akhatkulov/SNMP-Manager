package poller

import (
	"testing"

	"github.com/gosnmp/gosnmp"

	"github.com/me262/snmp-manager/internal/config"
)

func TestParseAuthProtocol(t *testing.T) {
	tests := []struct {
		input string
		want  gosnmp.SnmpV3AuthProtocol
	}{
		{"MD5", gosnmp.MD5},
		{"SHA", gosnmp.SHA},
		{"SHA1", gosnmp.SHA},
		{"SHA224", gosnmp.SHA224},
		{"SHA256", gosnmp.SHA256},
		{"SHA384", gosnmp.SHA384},
		{"SHA512", gosnmp.SHA512},
		{"sha256", gosnmp.SHA256},
		{"unknown", gosnmp.SHA256},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := parseAuthProtocol(tt.input)
			if got != tt.want {
				t.Errorf("parseAuthProtocol(%q): want %v, got %v", tt.input, tt.want, got)
			}
		})
	}
}

func TestParsePrivProtocol(t *testing.T) {
	tests := []struct {
		input string
		want  gosnmp.SnmpV3PrivProtocol
	}{
		{"DES", gosnmp.DES},
		{"AES", gosnmp.AES},
		{"AES128", gosnmp.AES},
		{"AES192", gosnmp.AES192},
		{"AES256", gosnmp.AES256},
		{"AES192C", gosnmp.AES192C},
		{"AES256C", gosnmp.AES256C},
		{"aes256", gosnmp.AES256},
		{"unknown", gosnmp.AES256},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := parsePrivProtocol(tt.input)
			if got != tt.want {
				t.Errorf("parsePrivProtocol(%q): want %v, got %v", tt.input, tt.want, got)
			}
		})
	}
}

func TestExtractValue(t *testing.T) {
	tests := []struct {
		name     string
		pdu      gosnmp.SnmpPDU
		wantType string
	}{
		{
			name:     "OctetString",
			pdu:      gosnmp.SnmpPDU{Name: ".1.3.6.1.2.1.1.1.0", Type: gosnmp.OctetString, Value: []byte("Cisco IOS")},
			wantType: "OctetString",
		},
		{
			name:     "Integer",
			pdu:      gosnmp.SnmpPDU{Name: ".1.3.6.1.2.1.2.2.1.8.1", Type: gosnmp.Integer, Value: 1},
			wantType: "Integer",
		},
		{
			name:     "Counter32",
			pdu:      gosnmp.SnmpPDU{Name: ".1.3.6.1.2.1.2.2.1.10.1", Type: gosnmp.Counter32, Value: uint(123456)},
			wantType: "Counter32",
		},
		{
			name:     "Counter64",
			pdu:      gosnmp.SnmpPDU{Name: ".1.3.6.1.2.1.31.1.1.1.6.1", Type: gosnmp.Counter64, Value: uint64(999999999)},
			wantType: "Counter64",
		},
		{
			name:     "Gauge32",
			pdu:      gosnmp.SnmpPDU{Name: ".1.3.6.1.2.1.25.3.3.1.2.1", Type: gosnmp.Gauge32, Value: uint(75)},
			wantType: "Gauge32",
		},
		{
			name:     "TimeTicks",
			pdu:      gosnmp.SnmpPDU{Name: ".1.3.6.1.2.1.1.3.0", Type: gosnmp.TimeTicks, Value: uint32(123456)},
			wantType: "TimeTicks",
		},
		{
			name:     "IPAddress",
			pdu:      gosnmp.SnmpPDU{Name: ".1.3.6.1.2.1.4.20.1.1.1", Type: gosnmp.IPAddress, Value: "192.168.1.1"},
			wantType: "IPAddress",
		},
		{
			name:     "ObjectIdentifier",
			pdu:      gosnmp.SnmpPDU{Name: ".1.3.6.1.2.1.1.2.0", Type: gosnmp.ObjectIdentifier, Value: ".1.3.6.1.4.1.9"},
			wantType: "ObjectIdentifier",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			value, valueType := extractValue(&tt.pdu)
			if valueType != tt.wantType {
				t.Errorf("type: want %q, got %q", tt.wantType, valueType)
			}
			if value == nil {
				t.Error("value should not be nil")
			}
		})
	}
}

func TestExtractValueOctetString(t *testing.T) {
	pdu := gosnmp.SnmpPDU{Type: gosnmp.OctetString, Value: []byte("Cisco IOS XE")}
	value, _ := extractValue(&pdu)

	str, ok := value.(string)
	if !ok {
		t.Fatal("OctetString value should be string")
	}
	if str != "Cisco IOS XE" {
		t.Errorf("value: want %q, got %q", "Cisco IOS XE", str)
	}
}

func TestExtractValueRaw(t *testing.T) {
	// OctetString → should be converted to string
	pdu := gosnmp.SnmpPDU{Type: gosnmp.OctetString, Value: []byte("test")}
	val := extractValueRaw(&pdu)
	if str, ok := val.(string); !ok || str != "test" {
		t.Errorf("raw OctetString: want %q, got %v", "test", val)
	}

	// Integer → should remain as-is
	pdu = gosnmp.SnmpPDU{Type: gosnmp.Integer, Value: 42}
	val = extractValueRaw(&pdu)
	if v, ok := val.(int); !ok || v != 42 {
		t.Errorf("raw Integer: want %d, got %v", 42, val)
	}
}

func TestPollerStats(t *testing.T) {
	p := &Poller{
		totalPolls:  100,
		totalErrors: 5,
		jobCh:       make(chan *pollJob, 20),
		cfg:         config.PollerConfig{Workers: 10},
	}

	stats := p.Stats()
	if stats.TotalPolls != 100 {
		t.Errorf("total polls: want 100, got %d", stats.TotalPolls)
	}
	if stats.TotalErrors != 5 {
		t.Errorf("total errors: want 5, got %d", stats.TotalErrors)
	}
	if stats.Workers != 10 {
		t.Errorf("workers: want 10, got %d", stats.Workers)
	}
	if stats.QueueCap != 20 {
		t.Errorf("queue cap: want 20, got %d", stats.QueueCap)
	}
}
