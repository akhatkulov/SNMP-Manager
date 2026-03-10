package device

import (
	"testing"

	"github.com/rs/zerolog"

	"github.com/me262/snmp-manager/internal/config"
)

func newTestRegistry() *Registry {
	return NewRegistry(zerolog.Nop())
}

func TestRegistryLoadFromConfig(t *testing.T) {
	r := newTestRegistry()
	devices := []config.DeviceConfig{
		{Name: "r1", IP: "10.0.0.1", Community: "pub", SNMPVersion: "v2c"},
		{Name: "r2", IP: "10.0.0.2", Community: "pub", SNMPVersion: "v2c"},
	}

	if err := r.LoadFromConfig(devices); err != nil {
		t.Fatalf("load from config: %v", err)
	}
	if r.Count() != 2 {
		t.Errorf("count: want 2, got %d", r.Count())
	}
}

func TestRegistryLoadDuplicateName(t *testing.T) {
	r := newTestRegistry()
	devices := []config.DeviceConfig{
		{Name: "same", IP: "10.0.0.1", Community: "pub", SNMPVersion: "v2c"},
		{Name: "same", IP: "10.0.0.2", Community: "pub", SNMPVersion: "v2c"},
	}

	err := r.LoadFromConfig(devices)
	if err == nil {
		t.Fatal("expected error for duplicate names")
	}
}

func TestRegistryGetAndGetByIP(t *testing.T) {
	r := newTestRegistry()
	dev := &Device{Name: "test-dev", IP: "192.168.1.1", Port: 161, Enabled: true}
	if err := r.Add(dev); err != nil {
		t.Fatalf("add: %v", err)
	}

	// Get by name
	got, ok := r.Get("test-dev")
	if !ok {
		t.Fatal("Get by name: not found")
	}
	if got.IP != "192.168.1.1" {
		t.Errorf("ip: want %q, got %q", "192.168.1.1", got.IP)
	}

	// Get by IP
	got, ok = r.GetByIP("192.168.1.1")
	if !ok {
		t.Fatal("GetByIP: not found")
	}
	if got.Name != "test-dev" {
		t.Errorf("name: want %q, got %q", "test-dev", got.Name)
	}

	// Not found
	_, ok = r.Get("nonexistent")
	if ok {
		t.Error("expected not found for nonexistent device")
	}
}

func TestRegistryAddDuplicate(t *testing.T) {
	r := newTestRegistry()
	dev := &Device{Name: "d1", IP: "10.0.0.1"}
	r.Add(dev)

	err := r.Add(&Device{Name: "d1", IP: "10.0.0.2"})
	if err == nil {
		t.Fatal("expected error when adding duplicate name")
	}
}

func TestRegistryRemove(t *testing.T) {
	r := newTestRegistry()
	r.Add(&Device{Name: "d1", IP: "10.0.0.1"})

	if err := r.Remove("d1"); err != nil {
		t.Fatalf("remove: %v", err)
	}
	if r.Count() != 0 {
		t.Errorf("count after remove: want 0, got %d", r.Count())
	}

	// Remove nonexistent
	err := r.Remove("nonexistent")
	if err == nil {
		t.Fatal("expected error when removing nonexistent device")
	}
}

func TestRegistryList(t *testing.T) {
	r := newTestRegistry()
	r.Add(&Device{Name: "d1", IP: "10.0.0.1", Enabled: true})
	r.Add(&Device{Name: "d2", IP: "10.0.0.2", Enabled: false})
	r.Add(&Device{Name: "d3", IP: "10.0.0.3", Enabled: true})

	all := r.List()
	if len(all) != 3 {
		t.Errorf("list all: want 3, got %d", len(all))
	}

	enabled := r.ListEnabled()
	if len(enabled) != 2 {
		t.Errorf("list enabled: want 2, got %d", len(enabled))
	}
}

func TestRegistryStats(t *testing.T) {
	r := newTestRegistry()
	r.Add(&Device{Name: "d1", IP: "10.0.0.1", Enabled: true, Status: StatusUp})
	r.Add(&Device{Name: "d2", IP: "10.0.0.2", Enabled: true, Status: StatusDown})
	r.Add(&Device{Name: "d3", IP: "10.0.0.3", Enabled: false, Status: StatusUnknown})
	r.Add(&Device{Name: "d4", IP: "10.0.0.4", Enabled: true, Status: StatusError})

	stats := r.Stats()
	if stats.Total != 4 {
		t.Errorf("total: want 4, got %d", stats.Total)
	}
	if stats.Enabled != 3 {
		t.Errorf("enabled: want 3, got %d", stats.Enabled)
	}
	if stats.Up != 1 {
		t.Errorf("up: want 1, got %d", stats.Up)
	}
	if stats.Down != 1 {
		t.Errorf("down: want 1, got %d", stats.Down)
	}
	if stats.Error != 1 {
		t.Errorf("error: want 1, got %d", stats.Error)
	}
	if stats.Unknown != 1 {
		t.Errorf("unknown: want 1, got %d", stats.Unknown)
	}
}
