package discovery

// scanner.go — Network Auto-Discovery engine.
// Scans subnets using ICMP-like probing (TCP :161 connect) and SNMP community
// probing to discover network devices automatically.

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gosnmp/gosnmp"
	"github.com/rs/zerolog"
)

// ── Config ────────────────────────────────────────────────────────────────────

// ScanConfig defines parameters for a network discovery scan.
type ScanConfig struct {
	Subnets      []string      `json:"subnets"`       // CIDR notation, e.g. ["10.0.0.0/24"]
	Communities  []string      `json:"communities"`    // SNMP community strings to try
	SNMPVersions []string      `json:"snmp_versions"`  // ["v2c", "v1"]
	Concurrency  int           `json:"concurrency"`    // Max parallel probes
	Timeout      time.Duration `json:"timeout"`        // Per-host timeout
	Port         int           `json:"port"`           // SNMP port (default 161)
}

// DefaultScanConfig returns sensible defaults.
func DefaultScanConfig() ScanConfig {
	return ScanConfig{
		Communities:  []string{"public", "private"},
		SNMPVersions: []string{"v2c"},
		Concurrency:  50,
		Timeout:      3 * time.Second,
		Port:         161,
	}
}

// ── Discovered Device ─────────────────────────────────────────────────────────

// DiscoveredDevice holds information about a device found during scanning.
type DiscoveredDevice struct {
	IP           string            `json:"ip"`
	Port         int               `json:"port"`
	SNMPVersion  string            `json:"snmp_version"`
	Community    string            `json:"community"`       // The community that worked
	SysDescr     string            `json:"sys_descr"`
	SysName      string            `json:"sys_name"`
	SysObjectID  string            `json:"sys_object_id"`
	SysUpTime    string            `json:"sys_uptime"`
	SysContact   string            `json:"sys_contact"`
	SysLocation  string            `json:"sys_location"`
	Vendor       string            `json:"vendor"`
	DeviceType   string            `json:"device_type"`
	Registered   bool              `json:"registered"`       // Already in device registry
	MatchedTemplate string         `json:"matched_template"` // Auto-matched template ID
	DiscoveredAt time.Time         `json:"discovered_at"`
	ResponseTime time.Duration     `json:"response_time_ms"`
	Interfaces   int               `json:"interfaces"`       // Number of interfaces
	Extra        map[string]string `json:"extra,omitempty"`
}

// ── Scan Status ───────────────────────────────────────────────────────────────

// ScanStatus tracks the progress of a running scan.
type ScanStatus struct {
	ID          string             `json:"id"`
	State       string             `json:"state"`         // "running", "completed", "failed", "cancelled"
	StartedAt   time.Time          `json:"started_at"`
	CompletedAt time.Time          `json:"completed_at,omitempty"`
	TotalIPs    int                `json:"total_ips"`
	ScannedIPs  int64              `json:"scanned_ips"`
	FoundDevices int               `json:"found_devices"`
	Errors      int64              `json:"errors"`
	Elapsed     string             `json:"elapsed"`
	Percent     float64            `json:"percent"`
	Config      ScanConfig         `json:"config"`
	Results     []DiscoveredDevice `json:"results,omitempty"`
}

// ── Scanner ───────────────────────────────────────────────────────────────────

// Scanner performs network discovery scans.
type Scanner struct {
	log zerolog.Logger

	mu         sync.RWMutex
	lastScan   *ScanStatus
	scanCancel context.CancelFunc
}

// NewScanner creates a new Scanner.
func NewScanner(log zerolog.Logger) *Scanner {
	return &Scanner{
		log: log.With().Str("component", "discovery").Logger(),
	}
}

// StartScan begins a new subnet scan asynchronously.
func (s *Scanner) StartScan(parentCtx context.Context, cfg ScanConfig) (*ScanStatus, error) {
	s.mu.Lock()
	// Cancel any running scan
	if s.scanCancel != nil {
		s.scanCancel()
	}

	if len(cfg.Subnets) == 0 {
		s.mu.Unlock()
		return nil, fmt.Errorf("at least one subnet is required")
	}
	if len(cfg.Communities) == 0 {
		cfg.Communities = []string{"public"}
	}
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = 50
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 3 * time.Second
	}
	if cfg.Port <= 0 {
		cfg.Port = 161
	}
	if len(cfg.SNMPVersions) == 0 {
		cfg.SNMPVersions = []string{"v2c"}
	}

	// Enumerate all IPs
	var allIPs []net.IP
	for _, cidr := range cfg.Subnets {
		ips, err := expandCIDR(cidr)
		if err != nil {
			s.mu.Unlock()
			return nil, fmt.Errorf("invalid subnet %q: %w", cidr, err)
		}
		allIPs = append(allIPs, ips...)
	}

	ctx, cancel := context.WithCancel(parentCtx)
	s.scanCancel = cancel

	status := &ScanStatus{
		ID:        fmt.Sprintf("scan-%d", time.Now().UnixMilli()),
		State:     "running",
		StartedAt: time.Now(),
		TotalIPs:  len(allIPs),
		Config:    cfg,
	}
	s.lastScan = status
	s.mu.Unlock()

	s.log.Info().
		Int("total_ips", len(allIPs)).
		Strs("subnets", cfg.Subnets).
		Int("concurrency", cfg.Concurrency).
		Msg("starting network discovery scan")

	// Run scan in background
	go s.runScan(ctx, cfg, allIPs, status)

	return status, nil
}

// GetStatus returns the current/last scan status.
func (s *Scanner) GetStatus() *ScanStatus {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.lastScan == nil {
		return nil
	}
	// Return a copy with updated elapsed
	copy := *s.lastScan
	if copy.State == "running" {
		copy.Elapsed = time.Since(copy.StartedAt).Round(time.Millisecond).String()
		scanned := atomic.LoadInt64(&copy.ScannedIPs)
		if copy.TotalIPs > 0 {
			copy.Percent = float64(scanned) / float64(copy.TotalIPs) * 100
		}
	}
	return &copy
}

// GetResults returns the results of the last scan.
func (s *Scanner) GetResults() []DiscoveredDevice {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.lastScan == nil {
		return nil
	}
	return s.lastScan.Results
}

// CancelScan cancels the running scan.
func (s *Scanner) CancelScan() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.scanCancel != nil {
		s.scanCancel()
		if s.lastScan != nil && s.lastScan.State == "running" {
			s.lastScan.State = "cancelled"
			s.lastScan.CompletedAt = time.Now()
		}
	}
}

// ── Internal scan logic ──────────────────────────────────────────────────────

func (s *Scanner) runScan(ctx context.Context, cfg ScanConfig, ips []net.IP, status *ScanStatus) {
	var (
		resultsMu sync.Mutex
		results   []DiscoveredDevice
		wg        sync.WaitGroup
		sem       = make(chan struct{}, cfg.Concurrency)
	)

	for _, ip := range ips {
		select {
		case <-ctx.Done():
			goto done
		default:
		}

		ipStr := ip.String()
		sem <- struct{}{}
		wg.Add(1)
		go func(target string) {
			defer wg.Done()
			defer func() { <-sem }()

			atomic.AddInt64(&status.ScannedIPs, 1)

			device, err := s.probeHost(ctx, target, cfg)
			if err != nil {
				atomic.AddInt64(&status.Errors, 1)
				return
			}
			if device != nil {
				resultsMu.Lock()
				results = append(results, *device)
				resultsMu.Unlock()

				s.log.Info().
					Str("ip", target).
					Str("vendor", device.Vendor).
					Str("sysName", device.SysName).
					Msg("device discovered")
			}
		}(ipStr)
	}

	wg.Wait()

done:
	s.mu.Lock()
	status.Results = results
	status.FoundDevices = len(results)
	if status.State == "running" {
		status.State = "completed"
	}
	status.CompletedAt = time.Now()
	status.Elapsed = status.CompletedAt.Sub(status.StartedAt).Round(time.Millisecond).String()
	status.Percent = 100
	s.mu.Unlock()

	s.log.Info().
		Int("found", len(results)).
		Int64("scanned", atomic.LoadInt64(&status.ScannedIPs)).
		Str("elapsed", status.Elapsed).
		Msg("discovery scan completed")
}

// probeHost tries to connect to a single host via SNMP.
func (s *Scanner) probeHost(ctx context.Context, ip string, cfg ScanConfig) (*DiscoveredDevice, error) {
	for _, version := range cfg.SNMPVersions {
		for _, community := range cfg.Communities {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			default:
			}

			device, err := s.snmpProbe(ctx, ip, cfg.Port, version, community, cfg.Timeout)
			if err != nil {
				continue // Try next community/version
			}
			return device, nil
		}
	}
	return nil, nil // Host not reachable via SNMP
}

// snmpProbe performs a single SNMP GET on system OIDs.
func (s *Scanner) snmpProbe(ctx context.Context, ip string, port int, version, community string, timeout time.Duration) (*DiscoveredDevice, error) {
	snmp := &gosnmp.GoSNMP{
		Target:    ip,
		Port:      uint16(port),
		Community: community,
		Timeout:   timeout,
		Retries:   0,
	}

	switch version {
	case "v1":
		snmp.Version = gosnmp.Version1
	case "v2c":
		snmp.Version = gosnmp.Version2c
	default:
		snmp.Version = gosnmp.Version2c
	}

	start := time.Now()
	if err := snmp.ConnectIPv4(); err != nil {
		return nil, err
	}
	defer snmp.Conn.Close()

	// System MIB OIDs
	oids := []string{
		"1.3.6.1.2.1.1.1.0", // sysDescr
		"1.3.6.1.2.1.1.2.0", // sysObjectID
		"1.3.6.1.2.1.1.3.0", // sysUpTime
		"1.3.6.1.2.1.1.4.0", // sysContact
		"1.3.6.1.2.1.1.5.0", // sysName
		"1.3.6.1.2.1.1.6.0", // sysLocation
	}

	result, err := snmp.Get(oids)
	if err != nil {
		return nil, err
	}
	responseTime := time.Since(start)

	device := &DiscoveredDevice{
		IP:           ip,
		Port:         port,
		SNMPVersion:  version,
		Community:    community,
		DiscoveredAt: time.Now(),
		ResponseTime: responseTime,
	}

	for _, pdu := range result.Variables {
		val := pduToString(pdu)
		switch pdu.Name {
		case ".1.3.6.1.2.1.1.1.0":
			device.SysDescr = val
		case ".1.3.6.1.2.1.1.2.0":
			device.SysObjectID = val
		case ".1.3.6.1.2.1.1.3.0":
			device.SysUpTime = val
		case ".1.3.6.1.2.1.1.4.0":
			device.SysContact = val
		case ".1.3.6.1.2.1.1.5.0":
			device.SysName = val
		case ".1.3.6.1.2.1.1.6.0":
			device.SysLocation = val
		}
	}

	// Auto-detect vendor and type from sysDescr
	device.Vendor = detectVendor(device.SysDescr)
	device.DeviceType = detectDeviceType(device.SysDescr)

	// Try to get interface count (ifNumber)
	ifResult, err := snmp.Get([]string{"1.3.6.1.2.1.2.1.0"}) // ifNumber
	if err == nil && len(ifResult.Variables) > 0 {
		if v, ok := ifResult.Variables[0].Value.(int); ok {
			device.Interfaces = v
		}
	}

	return device, nil
}

// ── Helpers ──────────────────────────────────────────────────────────────────

// expandCIDR converts a CIDR string to a list of individual IPs.
// Excludes network and broadcast addresses for /24 and smaller.
func expandCIDR(cidr string) ([]net.IP, error) {
	ip, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	var ips []net.IP
	ones, bits := ipNet.Mask.Size()
	totalHosts := 1 << uint(bits-ones)

	// Safety: cap at /16 (65534 hosts)
	if totalHosts > 65536 {
		return nil, fmt.Errorf("subnet too large: %s (%d hosts), max /16", cidr, totalHosts)
	}

	for ipVal := ipToUint32(ip.Mask(ipNet.Mask)); totalHosts > 0; totalHosts-- {
		candidate := uint32ToIP(ipVal)
		if ipNet.Contains(candidate) {
			ips = append(ips, candidate)
		}
		ipVal++
	}

	// Remove network (.0) and broadcast (.255) for /24+
	if ones >= 24 && len(ips) > 2 {
		ips = ips[1 : len(ips)-1]
	}

	return ips, nil
}

func ipToUint32(ip net.IP) uint32 {
	ip = ip.To4()
	if ip == nil {
		return 0
	}
	return binary.BigEndian.Uint32(ip)
}

func uint32ToIP(val uint32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, val)
	return ip
}

func pduToString(pdu gosnmp.SnmpPDU) string {
	switch pdu.Type {
	case gosnmp.OctetString:
		return string(pdu.Value.([]byte))
	case gosnmp.ObjectIdentifier:
		return pdu.Value.(string)
	case gosnmp.TimeTicks:
		ticks := pdu.Value.(uint32)
		dur := time.Duration(ticks) * time.Millisecond * 10
		return dur.String()
	default:
		return fmt.Sprintf("%v", pdu.Value)
	}
}

// ── Vendor/Type Detection (reused from device package patterns) ──────────────

func detectVendor(descr string) string {
	d := strings.ToLower(descr)
	vendors := map[string][]string{
		"Cisco":    {"cisco", "ios", "nxos", "asa"},
		"Juniper":  {"juniper", "junos"},
		"HP":       {"hp", "hewlett", "procurve", "aruba"},
		"Huawei":   {"huawei", "vrp"},
		"MikroTik": {"mikrotik", "routeros"},
		"Fortinet": {"fortinet", "fortigate", "fortios"},
		"Palo Alto": {"palo alto", "pan-os"},
		"Linux":    {"linux", "ubuntu", "centos", "debian"},
		"Windows":  {"windows", "microsoft"},
		"VMware":   {"vmware", "esxi"},
		"Eltex":    {"eltex"},
		"D-Link":   {"d-link", "dlink", "des-", "dgs-"},
	}
	for vendor, keywords := range vendors {
		for _, kw := range keywords {
			if strings.Contains(d, kw) {
				return vendor
			}
		}
	}
	return "Unknown"
}

func detectDeviceType(descr string) string {
	d := strings.ToLower(descr)
	
	// Ordered slice to ensure priority (e.g., specific switch models before generic "ios " router match)
	types := []struct {
		name     string
		keywords []string
	}{
		{"firewall", []string{"firewall", "asa", "fortigate", "pan-os"}},
		{"switch", []string{"switch", "procurve", "catalyst", "nxos", "des-", "dgs-", "c2960"}},
		{"router", []string{"router", "ios ", "junos", "routeros"}},
		{"server", []string{"linux", "windows", "ubuntu", "centos", "esxi"}},
		{"ap", []string{"access point", " ap ", "aruba"}},
		{"printer", []string{"printer", "laserjet", "xerox"}},
	}
	
	for _, t := range types {
		for _, kw := range t.keywords {
			if strings.Contains(d, kw) {
				return t.name
			}
		}
	}
	return "unknown"
}

// ── Template Matching ────────────────────────────────────────────────────────

// TemplateMatch holds a template ID and matching confidence score.
type TemplateMatch struct {
	TemplateID string  `json:"template_id"`
	Score      float64 `json:"score"` // 0.0 - 1.0
}

// MatchTemplate tries to find the best template for a discovered device.
// This uses simple keyword matching on sysDescr and sysObjectID.
func MatchTemplate(device *DiscoveredDevice, templateIDs []string) *TemplateMatch {
	d := strings.ToLower(device.SysDescr + " " + device.SysObjectID)

	rules := map[string][]string{
		"network-switch":     {"switch", "catalyst", "procurve", "nxos", "des-", "dgs-"},
		"network-router":     {"router", "ios ", "junos", "routeros", "vrp"},
		"network-firewall":   {"firewall", "asa", "fortigate", "pan-os"},
		"linux-server":       {"linux", "ubuntu", "centos", "debian"},
		"windows-server":     {"windows", "microsoft"},
		"network-ap":         {"access point", "aruba", " ap "},
	}

	var bestMatch *TemplateMatch
	for tid, keywords := range rules {
		// Check if this template exists in available templates
		found := false
		for _, id := range templateIDs {
			if id == tid {
				found = true
				break
			}
		}

		score := 0.0
		for _, kw := range keywords {
			if strings.Contains(d, kw) {
				score += 0.25
			}
		}
		if score > 0 && (bestMatch == nil || score > bestMatch.Score) {
			if found {
				bestMatch = &TemplateMatch{TemplateID: tid, Score: score}
			} else if bestMatch == nil {
				bestMatch = &TemplateMatch{TemplateID: tid, Score: score}
			}
		}
	}
	return bestMatch
}

// SortByIP sorts discovered devices by IP address.
func SortByIP(devices []DiscoveredDevice) {
	sort.Slice(devices, func(i, j int) bool {
		a := net.ParseIP(devices[i].IP)
		b := net.ParseIP(devices[j].IP)
		if a == nil || b == nil {
			return devices[i].IP < devices[j].IP
		}
		return ipToUint32(a) < ipToUint32(b)
	})
}
