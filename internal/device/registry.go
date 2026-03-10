package device

import (
	"fmt"
	"sync"

	"github.com/rs/zerolog"

	"github.com/me262/snmp-manager/internal/config"
)

// Registry manages the set of monitored SNMP devices.
type Registry struct {
	mu      sync.RWMutex
	devices map[string]*Device // key: device name
	byIP    map[string]*Device // key: device IP
	log     zerolog.Logger
}

// NewRegistry creates a new device registry.
func NewRegistry(log zerolog.Logger) *Registry {
	return &Registry{
		devices: make(map[string]*Device),
		byIP:    make(map[string]*Device),
		log:     log.With().Str("component", "device-registry").Logger(),
	}
}

// LoadFromConfig loads all devices from the configuration.
func (r *Registry) LoadFromConfig(devices []config.DeviceConfig) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	for _, cfg := range devices {
		dev := NewDeviceFromConfig(cfg)
		if _, exists := r.devices[dev.Name]; exists {
			return fmt.Errorf("duplicate device name: %q", dev.Name)
		}
		if _, exists := r.byIP[dev.IP]; exists {
			r.log.Warn().Str("ip", dev.IP).Str("name", dev.Name).Msg("duplicate IP address detected")
		}
		r.devices[dev.Name] = dev
		r.byIP[dev.IP] = dev
		r.log.Info().
			Str("name", dev.Name).
			Str("ip", dev.IP).
			Str("version", dev.SNMPVersion).
			Bool("enabled", dev.Enabled).
			Msg("device registered")
	}

	r.log.Info().Int("total", len(r.devices)).Msg("devices loaded from configuration")
	return nil
}

// Get returns a device by name.
func (r *Registry) Get(name string) (*Device, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	dev, ok := r.devices[name]
	return dev, ok
}

// GetByIP returns a device by its IP address.
func (r *Registry) GetByIP(ip string) (*Device, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	dev, ok := r.byIP[ip]
	return dev, ok
}

// Add adds a new device to the registry.
func (r *Registry) Add(dev *Device) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.devices[dev.Name]; exists {
		return fmt.Errorf("device %q already exists", dev.Name)
	}

	r.devices[dev.Name] = dev
	r.byIP[dev.IP] = dev
	r.log.Info().Str("name", dev.Name).Str("ip", dev.IP).Msg("device added")
	return nil
}

// Remove removes a device from the registry.
func (r *Registry) Remove(name string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	dev, exists := r.devices[name]
	if !exists {
		return fmt.Errorf("device %q not found", name)
	}

	delete(r.devices, name)
	delete(r.byIP, dev.IP)
	r.log.Info().Str("name", name).Msg("device removed")
	return nil
}

// List returns all registered devices.
func (r *Registry) List() []*Device {
	r.mu.RLock()
	defer r.mu.RUnlock()

	result := make([]*Device, 0, len(r.devices))
	for _, dev := range r.devices {
		result = append(result, dev)
	}
	return result
}

// ListEnabled returns only enabled devices.
func (r *Registry) ListEnabled() []*Device {
	r.mu.RLock()
	defer r.mu.RUnlock()

	result := make([]*Device, 0)
	for _, dev := range r.devices {
		if dev.Enabled {
			result = append(result, dev)
		}
	}
	return result
}

// Count returns the total number of devices.
func (r *Registry) Count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.devices)
}

// Stats returns aggregated statistics.
func (r *Registry) Stats() RegistryStats {
	r.mu.RLock()
	defer r.mu.RUnlock()

	stats := RegistryStats{}
	for _, dev := range r.devices {
		stats.Total++
		if dev.Enabled {
			stats.Enabled++
		}
		switch dev.GetStatus() {
		case StatusUp:
			stats.Up++
		case StatusDown:
			stats.Down++
		case StatusError:
			stats.Error++
		default:
			stats.Unknown++
		}
	}
	return stats
}

// RegistryStats holds aggregated device statistics.
type RegistryStats struct {
	Total   int `json:"total"`
	Enabled int `json:"enabled"`
	Up      int `json:"up"`
	Down    int `json:"down"`
	Error   int `json:"error"`
	Unknown int `json:"unknown"`
}
