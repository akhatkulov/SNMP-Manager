package device

import (
	"sync"
	"testing"
	"time"

	"github.com/me262/snmp-manager/internal/config"
)

// ── Device Model Tests ───────────────────────────────────────────────

func TestNewDeviceFromConfig(t *testing.T) {
	enabled := true
	cfg := config.DeviceConfig{
		Name:         "test-router",
		IP:           "10.0.0.1",
		Port:         161,
		SNMPVersion:  "v2c",
		Community:    "public",
		PollInterval: 30 * time.Second,
		OIDGroups:    []string{"system", "interfaces"},
		Tags:         map[string]string{"location": "DC-1"},
		Enabled:      &enabled,
	}

	dev := NewDeviceFromConfig(cfg)

	if dev.Name != "test-router" {
		t.Errorf("name: want %q, got %q", "test-router", dev.Name)
	}
	if dev.IP != "10.0.0.1" {
		t.Errorf("ip: want %q, got %q", "10.0.0.1", dev.IP)
	}
	if dev.Port != 161 {
		t.Errorf("port: want 161, got %d", dev.Port)
	}
	if dev.SNMPVersion != "v2c" {
		t.Errorf("version: want %q, got %q", "v2c", dev.SNMPVersion)
	}
	if dev.Status != StatusUnknown {
		t.Errorf("initial status: want %q, got %q", StatusUnknown, dev.Status)
	}
	if !dev.Enabled {
		t.Error("enabled: want true, got false")
	}
	if len(dev.OIDGroups) != 2 {
		t.Errorf("oid groups: want 2, got %d", len(dev.OIDGroups))
	}
}

func TestNewDeviceFromConfigDefaults(t *testing.T) {
	cfg := config.DeviceConfig{
		Name: "minimal",
		IP:   "10.0.0.2",
	}

	dev := NewDeviceFromConfig(cfg)
	if !dev.Enabled {
		t.Error("default enabled: want true")
	}
	if dev.Status != StatusUnknown {
		t.Errorf("default status: want %q, got %q", StatusUnknown, dev.Status)
	}
}

func TestDeviceUpdateStatus(t *testing.T) {
	dev := &Device{Name: "test", Status: StatusUnknown}

	// Successful poll
	dev.UpdateStatus(StatusUp, 50*time.Millisecond, nil)
	if dev.Status != StatusUp {
		t.Errorf("status after success: want %q, got %q", StatusUp, dev.Status)
	}
	if dev.PollCount != 1 {
		t.Errorf("poll count: want 1, got %d", dev.PollCount)
	}
	if dev.ErrorCount != 0 {
		t.Errorf("error count: want 0, got %d", dev.ErrorCount)
	}
	if dev.LastError != "" {
		t.Errorf("last error: want empty, got %q", dev.LastError)
	}
	if dev.AvgLatency != 50*time.Millisecond {
		t.Errorf("avg latency: want 50ms, got %v", dev.AvgLatency)
	}

	// Failed poll
	dev.UpdateStatus(StatusError, 100*time.Millisecond, &testError{"connection refused"})
	if dev.Status != StatusError {
		t.Errorf("status after error: want %q, got %q", StatusError, dev.Status)
	}
	if dev.PollCount != 2 {
		t.Errorf("poll count: want 2, got %d", dev.PollCount)
	}
	if dev.ErrorCount != 1 {
		t.Errorf("error count: want 1, got %d", dev.ErrorCount)
	}
	if dev.LastError != "connection refused" {
		t.Errorf("last error: want %q, got %q", "connection refused", dev.LastError)
	}
}

func TestDeviceUpdateStatusConcurrent(t *testing.T) {
	dev := &Device{Name: "concurrent-test"}
	var wg sync.WaitGroup

	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			dev.UpdateStatus(StatusUp, 10*time.Millisecond, nil)
		}()
	}
	wg.Wait()

	if dev.PollCount != 100 {
		t.Errorf("concurrent poll count: want 100, got %d", dev.PollCount)
	}
}

func TestDeviceAvgLatency(t *testing.T) {
	dev := &Device{Name: "latency-test"}

	dev.UpdateStatus(StatusUp, 100*time.Millisecond, nil)
	dev.UpdateStatus(StatusUp, 200*time.Millisecond, nil)
	dev.UpdateStatus(StatusUp, 300*time.Millisecond, nil)

	// Running average of 100, 200, 300 = different from arithmetic mean
	// but should be in reasonable range
	if dev.AvgLatency < 100*time.Millisecond || dev.AvgLatency > 300*time.Millisecond {
		t.Errorf("avg latency out of range: %v", dev.AvgLatency)
	}
}

func TestDeviceIncrementTrapCount(t *testing.T) {
	dev := &Device{Name: "trap-test"}

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			dev.IncrementTrapCount()
		}()
	}
	wg.Wait()

	if dev.TrapCount != 50 {
		t.Errorf("trap count: want 50, got %d", dev.TrapCount)
	}
}

func TestDeviceSetSysInfo(t *testing.T) {
	dev := &Device{Name: "sysinfo-test"}
	dev.SetSysInfo("Cisco IOS XE Software, Version 17.06.05", "core-router", "12345678")

	if dev.SysDescr != "Cisco IOS XE Software, Version 17.06.05" {
		t.Errorf("sysDescr: got %q", dev.SysDescr)
	}
	if dev.SysName != "core-router" {
		t.Errorf("sysName: got %q", dev.SysName)
	}
	if dev.Vendor != "Cisco" {
		t.Errorf("vendor: want %q, got %q", "Cisco", dev.Vendor)
	}
	if dev.DeviceType != "router" {
		t.Errorf("device type: want %q, got %q", "router", dev.DeviceType)
	}
}

func TestDeviceAddress(t *testing.T) {
	dev := &Device{IP: "192.168.1.1", Port: 161}
	want := "192.168.1.1:161"
	if got := dev.Address(); got != want {
		t.Errorf("address: want %q, got %q", want, got)
	}
}

func TestGetStatus(t *testing.T) {
	dev := &Device{Status: StatusUp}
	if dev.GetStatus() != StatusUp {
		t.Errorf("get status: want %q, got %q", StatusUp, dev.GetStatus())
	}
}

// ── Vendor Detection Tests ──────────────────────────────────────────

func TestDetectVendor(t *testing.T) {
	tests := []struct {
		descr string
		want  string
	}{
		{"Cisco IOS XE Software, Version 17.06.05", "Cisco"},
		{"Cisco Adaptive Security Appliance ASA 9.16", "Cisco"},
		{"Juniper Networks, Inc. JUNOS 21.4R3", "Juniper"},
		{"HP ProCurve Switch 2920", "HP"},
		{"Huawei Versatile Routing Platform Software VRP", "Huawei"},
		{"MikroTik RouterOS 7.10.2", "MikroTik"},
		{"FortiGate-100F v7.4.2", "Fortinet"},
		{"Palo Alto Networks PAN-OS 11.0.2", "Palo Alto"},
		{"Linux 5.15.0 Ubuntu 22.04", "Linux"},
		{"Hardware: Intel64 Family - Microsoft Windows Server 2022", "Windows"},
		{"VMware ESXi 8.0.1 build-21495797", "VMware"},
		{"Some Unknown Device", "Unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := detectVendor(tt.descr)
			if got != tt.want {
				t.Errorf("detectVendor(%q): want %q, got %q", tt.descr, tt.want, got)
			}
		})
	}
}

func TestDetectDeviceType(t *testing.T) {
	tests := []struct {
		descr string
		want  string
	}{
		{"Cisco IOS router", "router"},
		{"ProCurve Switch 2920", "switch"},
		{"FortiGate firewall", "firewall"},
		{"Linux 5.15.0 Ubuntu", "server"},
		{"Aruba access point AP-505", "ap"},
		{"HP LaserJet printer", "printer"},
		{"Generic device", "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := detectDeviceType(tt.descr)
			if got != tt.want {
				t.Errorf("detectDeviceType(%q): want %q, got %q", tt.descr, tt.want, got)
			}
		})
	}
}

// helper
type testError struct{ msg string }

func (e *testError) Error() string { return e.msg }
