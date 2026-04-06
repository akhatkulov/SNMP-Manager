package discovery

import (
	"net"
	"testing"
)

func TestExpandCIDR_24(t *testing.T) {
	ips, err := expandCIDR("192.168.1.0/24")
	if err != nil {
		t.Fatalf("expandCIDR: %v", err)
	}
	// /24 = 256 - 2 (network + broadcast) = 254 hosts
	if len(ips) != 254 {
		t.Fatalf("expected 254 hosts from /24, got %d", len(ips))
	}
	// First should be .1
	if ips[0].String() != "192.168.1.1" {
		t.Errorf("first IP = %s, want 192.168.1.1", ips[0])
	}
	// Last should be .254
	if ips[len(ips)-1].String() != "192.168.1.254" {
		t.Errorf("last IP = %s, want 192.168.1.254", ips[len(ips)-1])
	}
}

func TestExpandCIDR_30(t *testing.T) {
	ips, err := expandCIDR("10.0.0.0/30")
	if err != nil {
		t.Fatalf("expandCIDR: %v", err)
	}
	// /30 = 4 - 2 = 2 usable hosts
	if len(ips) != 2 {
		t.Fatalf("expected 2 hosts from /30, got %d", len(ips))
	}
	if ips[0].String() != "10.0.0.1" {
		t.Errorf("first IP = %s, want 10.0.0.1", ips[0])
	}
}

func TestExpandCIDR_TooLarge(t *testing.T) {
	_, err := expandCIDR("10.0.0.0/8")
	if err == nil {
		t.Error("expected error for /8 (too many hosts)")
	}
}

func TestExpandCIDR_Invalid(t *testing.T) {
	_, err := expandCIDR("not-a-cidr")
	if err == nil {
		t.Error("expected error for invalid CIDR")
	}
}

func TestIPConversion(t *testing.T) {
	ip := net.ParseIP("192.168.1.100")
	val := ipToUint32(ip)
	back := uint32ToIP(val)
	if back.String() != "192.168.1.100" {
		t.Errorf("round-trip failed: got %s", back)
	}
}

func TestDetectVendor(t *testing.T) {
	tests := []struct {
		descr  string
		vendor string
	}{
		{"Cisco IOS Software, C2960 Software", "Cisco"},
		{"RouterOS 6.49.7 (stable)", "MikroTik"},
		{"Linux ubuntu 5.15.0", "Linux"},
		{"Hardware: Intel64 Family 6 Model 154 Stepping 3 AT/AT COMPATIBLE - Software: Windows Version 6.3", "Windows"},
		{"Huawei Versatile Routing Platform VRP", "Huawei"},
		{"Unknown device xyz123", "Unknown"},
		{"Eltex MES2124M", "Eltex"},
	}

	for _, tt := range tests {
		got := detectVendor(tt.descr)
		if got != tt.vendor {
			t.Errorf("detectVendor(%q) = %q, want %q", tt.descr, got, tt.vendor)
		}
	}
}

func TestDetectDeviceType(t *testing.T) {
	tests := []struct {
		descr  string
		dtype  string
	}{
		{"Cisco IOS Software, C2960 Software (C2960-LANBASEK9-M)", "switch"},
		{"RouterOS 6.49.7 (stable) on RB3011", "router"},
		{"Palo Alto Networks PAN-OS 10.2", "firewall"},
		{"Linux ubuntu 5.15.0-76-generic", "server"},
	}

	for _, tt := range tests {
		got := detectDeviceType(tt.descr)
		if got != tt.dtype {
			t.Errorf("detectDeviceType(%q) = %q, want %q", tt.descr, got, tt.dtype)
		}
	}
}

func TestNormalizeLinkID(t *testing.T) {
	id1 := normalizeLinkID("10.0.0.1", "10.0.0.2")
	id2 := normalizeLinkID("10.0.0.2", "10.0.0.1")
	if id1 != id2 {
		t.Errorf("link IDs should be direction-independent: %q vs %q", id1, id2)
	}
}

func TestMatchTemplate(t *testing.T) {
	templates := []string{"network-switch", "network-router", "linux-server"}

	dev1 := &DiscoveredDevice{SysDescr: "Cisco Catalyst 2960 Switch"}
	m1 := MatchTemplate(dev1, templates)
	if m1 == nil || m1.TemplateID != "network-switch" {
		t.Errorf("expected network-switch match for Cisco switch, got %v", m1)
	}

	dev2 := &DiscoveredDevice{SysDescr: "Linux Ubuntu 22.04"}
	m2 := MatchTemplate(dev2, templates)
	if m2 == nil || m2.TemplateID != "linux-server" {
		t.Errorf("expected linux-server match for Ubuntu, got %v", m2)
	}

	dev3 := &DiscoveredDevice{SysDescr: "Unknown proprietary device"}
	m3 := MatchTemplate(dev3, templates)
	if m3 != nil {
		t.Errorf("expected no match for unknown device, got %v", m3)
	}
}

func TestSortByIP(t *testing.T) {
	devices := []DiscoveredDevice{
		{IP: "192.168.1.100"},
		{IP: "192.168.1.1"},
		{IP: "10.0.0.1"},
		{IP: "192.168.1.50"},
	}
	SortByIP(devices)
	if devices[0].IP != "10.0.0.1" {
		t.Errorf("first should be 10.0.0.1, got %s", devices[0].IP)
	}
	if devices[3].IP != "192.168.1.100" {
		t.Errorf("last should be 192.168.1.100, got %s", devices[3].IP)
	}
}

func TestDefaultScanConfig(t *testing.T) {
	cfg := DefaultScanConfig()
	if cfg.Concurrency != 50 {
		t.Errorf("default concurrency = %d, want 50", cfg.Concurrency)
	}
	if cfg.Port != 161 {
		t.Errorf("default port = %d, want 161", cfg.Port)
	}
	if len(cfg.Communities) != 2 {
		t.Errorf("default communities count = %d, want 2", len(cfg.Communities))
	}
}
