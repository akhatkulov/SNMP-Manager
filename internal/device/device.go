package device

import (
	"fmt"
	"sync"
	"time"

	"github.com/me262/snmp-manager/internal/config"
)

// Status represents the current state of a device.
type Status string

const (
	StatusUnknown     Status = "unknown"
	StatusUp          Status = "up"
	StatusDown        Status = "down"
	StatusUnreachable Status = "unreachable"
	StatusError       Status = "error"
)

// Device represents a managed SNMP device with its operational state.
type Device struct {
	mu sync.RWMutex

	// Configuration (from config file)
	Name        string            `json:"name"`
	IP          string            `json:"ip"`
	Port        int               `json:"port"`
	SNMPVersion string            `json:"snmp_version"`
	Community   string            `json:"-"` // Never expose in JSON
	Credentials *config.V3Credentials `json:"-"`
	OIDGroups   []string          `json:"oid_groups"`
	Tags        map[string]string `json:"tags"`
	Enabled     bool              `json:"enabled"`

	// Polling
	PollInterval time.Duration `json:"poll_interval"`

	// Runtime state
	Status        Status    `json:"status"`
	LastPoll      time.Time `json:"last_poll"`
	LastPollOK    time.Time `json:"last_poll_ok"`
	LastError     string    `json:"last_error,omitempty"`
	PollCount     int64     `json:"poll_count"`
	ErrorCount    int64     `json:"error_count"`
	TrapCount     int64     `json:"trap_count"`
	AvgLatency    time.Duration `json:"avg_latency_ms"`

	// Device info (discovered via SNMP)
	SysDescr  string `json:"sys_descr,omitempty"`
	SysName   string `json:"sys_name,omitempty"`
	SysUpTime string `json:"sys_uptime,omitempty"`
	Vendor    string `json:"vendor,omitempty"`
	DeviceType string `json:"device_type,omitempty"`
}

// NewDeviceFromConfig creates a Device from a configuration entry.
func NewDeviceFromConfig(cfg config.DeviceConfig) *Device {
	enabled := true
	if cfg.Enabled != nil {
		enabled = *cfg.Enabled
	}
	return &Device{
		Name:         cfg.Name,
		IP:           cfg.IP,
		Port:         cfg.Port,
		SNMPVersion:  cfg.SNMPVersion,
		Community:    cfg.Community,
		Credentials:  cfg.Credentials,
		OIDGroups:    cfg.OIDGroups,
		Tags:         cfg.Tags,
		Enabled:      enabled,
		PollInterval: cfg.PollInterval,
		Status:       StatusUnknown,
	}
}

// UpdateStatus records a poll result.
func (d *Device) UpdateStatus(status Status, latency time.Duration, err error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.Status = status
	d.LastPoll = time.Now()
	d.PollCount++

	if err != nil {
		d.ErrorCount++
		d.LastError = err.Error()
	} else {
		d.LastPollOK = time.Now()
		d.LastError = ""
	}

	// Running average latency
	if d.PollCount == 1 {
		d.AvgLatency = latency
	} else {
		d.AvgLatency = (d.AvgLatency*time.Duration(d.PollCount-1) + latency) / time.Duration(d.PollCount)
	}
}

// IncrementTrapCount increments the trap counter.
func (d *Device) IncrementTrapCount() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.TrapCount++
}

// SetSysInfo sets discovered system information.
func (d *Device) SetSysInfo(descr, name, uptime string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.SysDescr = descr
	d.SysName = name
	d.SysUpTime = uptime
	d.Vendor = detectVendor(descr)
	d.DeviceType = detectDeviceType(descr)
}

// GetStatus safely reads the current status.
func (d *Device) GetStatus() Status {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.Status
}

// Address returns the SNMP target address (ip:port).
func (d *Device) Address() string {
	return fmt.Sprintf("%s:%d", d.IP, d.Port)
}

// detectVendor tries to identify the vendor from sysDescr.
func detectVendor(descr string) string {
	vendors := map[string][]string{
		"Cisco":    {"Cisco", "IOS", "NXOS", "ASA"},
		"Juniper":  {"Juniper", "JUNOS"},
		"HP":       {"HP", "Hewlett", "ProCurve", "Aruba"},
		"Huawei":   {"Huawei", "VRP"},
		"MikroTik": {"MikroTik", "RouterOS"},
		"Fortinet": {"Fortinet", "FortiGate", "FortiOS"},
		"Palo Alto": {"Palo Alto", "PAN-OS"},
		"Linux":    {"Linux", "Ubuntu", "CentOS", "Debian"},
		"Windows":  {"Windows", "Microsoft"},
		"VMware":   {"VMware", "ESXi"},
	}
	for vendor, keywords := range vendors {
		for _, kw := range keywords {
			if containsCI(descr, kw) {
				return vendor
			}
		}
	}
	return "Unknown"
}

// detectDeviceType tries to identify the device type from sysDescr.
func detectDeviceType(descr string) string {
	types := map[string][]string{
		"router":   {"router", "IOS", "JUNOS", "RouterOS"},
		"switch":   {"switch", "ProCurve", "Catalyst", "NXOS"},
		"firewall": {"firewall", "ASA", "FortiGate", "PAN-OS"},
		"server":   {"Linux", "Windows", "Ubuntu", "CentOS", "ESXi"},
		"ap":       {"access point", "AP", "Aruba"},
		"printer":  {"printer", "LaserJet", "Xerox"},
	}
	for dtype, keywords := range types {
		for _, kw := range keywords {
			if containsCI(descr, kw) {
				return dtype
			}
		}
	}
	return "unknown"
}

func containsCI(s, substr string) bool {
	sLower := make([]byte, len(s))
	subLower := make([]byte, len(substr))
	for i := range s {
		if s[i] >= 'A' && s[i] <= 'Z' {
			sLower[i] = s[i] + 32
		} else {
			sLower[i] = s[i]
		}
	}
	for i := range substr {
		if substr[i] >= 'A' && substr[i] <= 'Z' {
			subLower[i] = substr[i] + 32
		} else {
			subLower[i] = substr[i]
		}
	}
	return bytesContains(sLower, subLower)
}

func bytesContains(s, sub []byte) bool {
	if len(sub) > len(s) {
		return false
	}
	for i := 0; i <= len(s)-len(sub); i++ {
		match := true
		for j := range sub {
			if s[i+j] != sub[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}
