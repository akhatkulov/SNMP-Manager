package pipeline

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog"

	"github.com/me262/snmp-manager/internal/mib"
)

// Normalizer resolves OIDs to names, classifies events, computes MetricData,
// and assigns severity.
type Normalizer struct {
	resolver         *mib.Resolver
	log              zerolog.Logger
	resolveHostnames bool
	dnsCache         map[string]string
	dnsCacheMu       sync.RWMutex
}

func NewNormalizer(resolver *mib.Resolver, log zerolog.Logger, resolveHostnames bool) *Normalizer {
	return &Normalizer{
		resolver:         resolver,
		log:              log.With().Str("component", "normalizer").Logger(),
		resolveHostnames: resolveHostnames,
		dnsCache:         make(map[string]string),
	}
}

// Process normalises a raw SNMP event in-place.
func (n *Normalizer) Process(event *SNMPEvent) {
	n.resolveOIDs(event)
	n.resolveHostname(event)
	n.classifyCategory(event)
	n.classifySeverity(event)
	n.buildMetric(event)

	// Always populate ValueStr
	if event.ValueStr == "" && event.Value != nil {
		event.ValueStr = fmt.Sprintf("%v", event.Value)
	}
}

// ─── OID resolution ────────────────────────────────────────────────────────

func (n *Normalizer) resolveOIDs(event *SNMPEvent) {
	// Resolve main OID
	if event.OID != "" {
		if entry, ok := n.resolver.Resolve(event.OID); ok {
			setIfEmpty(&event.OIDName, entry.Name)
			setIfEmpty(&event.OIDModule, entry.Module)
			setIfEmpty(&event.OIDDescription, entry.Description)
			setIfEmpty(&event.OIDSyntax, entry.Syntax)
		} else if event.OIDName == "" {
			event.OIDName = event.OID
		}
	}

	// Resolve varbind OIDs
	for i := range event.Variables {
		v := &event.Variables[i]
		if v.OIDName == "" {
			if entry, ok := n.resolver.Resolve(v.OID); ok {
				v.OIDName = entry.Name
			}
		}
		if v.ValueStr == "" && v.Value != nil {
			v.ValueStr = fmt.Sprintf("%v", v.Value)
		}
	}

	// Resolve trap OID name (SNMPv2: varbind 1.3.6.1.6.3.1.1.4.1.0)
	if event.EventType == EventTypeTrap || event.EventType == EventTypeInform {
		for _, v := range event.Variables {
			if v.OID == "1.3.6.1.6.3.1.1.4.1.0" {
				oidStr := fmt.Sprintf("%v", v.Value)
				event.TrapOID = oidStr
				if entry, ok := n.resolver.Resolve(oidStr); ok {
					event.TrapOIDName = entry.Name
				}
				break
			}
		}
		// Prefer trapOID name as the event name
		if event.TrapOIDName != "" && event.OIDName == event.OID {
			event.OIDName = event.TrapOIDName
		}
	}

	// ValueStr fallback
	if event.ValueStr == "" && event.Value != nil {
		event.ValueStr = fmt.Sprintf("%v", event.Value)
	}
}

// ─── Hostname resolution ───────────────────────────────────────────────────

func (n *Normalizer) resolveHostname(event *SNMPEvent) {
	if n.resolveHostnames && event.DeviceHostname == "" && event.DeviceIP != "" {
		event.DeviceHostname = n.lookupHost(event.DeviceIP)
	}
}

// ─── Category classification ───────────────────────────────────────────────

type oidCategoryRule struct {
	prefix   string
	keywords []string
	category Category
}

var rulesOIDPrefix = []oidCategoryRule{
	{prefix: "1.3.6.1.6.3.1.1.5.1", category: CategoryAvailability}, // coldStart
	{prefix: "1.3.6.1.6.3.1.1.5.2", category: CategoryAvailability}, // warmStart
	{prefix: "1.3.6.1.6.3.1.1.5.3", category: CategoryNetwork},      // linkDown
	{prefix: "1.3.6.1.6.3.1.1.5.4", category: CategoryNetwork},      // linkUp
	{prefix: "1.3.6.1.6.3.1.1.5.5", category: CategorySecurity},     // authenticationFailure
	{prefix: "1.3.6.1.2.1.2.", category: CategoryNetwork},
	{prefix: "1.3.6.1.2.1.31.", category: CategoryNetwork},
	{prefix: "1.3.6.1.2.1.10.", category: CategoryNetwork},
	{prefix: "1.3.6.1.2.1.4.", category: CategoryNetwork},
	{prefix: "1.3.6.1.2.1.5.", category: CategoryNetwork},
	{prefix: "1.3.6.1.2.1.6.", category: CategoryNetwork},
	{prefix: "1.3.6.1.2.1.7.", category: CategoryNetwork},
	{prefix: "1.3.6.1.2.1.1.", category: CategorySystem},
	{prefix: "1.3.6.1.2.1.25.1.", category: CategorySystem},
	{prefix: "1.3.6.1.2.1.25.2.", category: CategoryStorage},
	{prefix: "1.3.6.1.2.1.25.3.", category: CategoryStorage},
	{prefix: "1.3.6.1.4.1.2021.10.", category: CategoryPerformance},
	{prefix: "1.3.6.1.4.1.2021.11.", category: CategoryPerformance},
	{prefix: "1.3.6.1.4.1.2021.4.", category: CategoryPerformance},
	{prefix: "1.3.6.1.4.1.9.9.13.", category: CategoryEnvironment},
	{prefix: "1.3.6.1.4.1.9.9.109.", category: CategoryPerformance},
	{prefix: "1.3.6.1.4.1.9.9.48.", category: CategoryPerformance},
	{prefix: "1.3.6.1.4.1.9.9.187.", category: CategoryBGP},
	{prefix: "1.3.6.1.4.1.9.9.272.", category: CategoryVPN},
	{prefix: "1.3.6.1.4.1.14988.1.1.3.", category: CategoryEnvironment},
	{prefix: "1.3.6.1.4.1.14988.1.1.7.", category: CategoryWireless},
	{prefix: "1.3.6.1.4.1.14988.1.1.2.", category: CategoryPerformance},
	{prefix: "1.3.6.1.4.1.2011.5.25.31.", category: CategoryEnvironment},
	{prefix: "1.3.6.1.4.1.2011.5.25.41.", category: CategoryPerformance},
	{prefix: "1.3.6.1.2.1.15.", category: CategoryBGP},
	{prefix: "1.3.6.1.2.1.14.", category: CategoryOSPF},
	{prefix: "1.3.6.1.2.1.17.", category: CategoryVLAN},
	{prefix: "1.3.6.1.2.1.105.", category: CategoryPoE},
	{prefix: "1.3.6.1.2.1.33.", category: CategoryUPS},
	{prefix: "1.3.6.1.2.1.43.", category: CategoryPrinter},
	{prefix: "1.3.6.1.2.1.25.3.5.", category: CategoryPrinter},
	{prefix: "1.2.840.10036.", category: CategoryWireless},
	{prefix: "1.0.8802.1.1.2.", category: CategoryNetwork},
}

var rulesKeyword = []oidCategoryRule{
	{keywords: []string{"temperature", "thermal", "heat", "fan", "voltage", "envmon", "sensor"}, category: CategoryEnvironment},
	{keywords: []string{"cpu", "processor", "load", "memory", "mem", "ram"}, category: CategoryPerformance},
	{keywords: []string{"storage", "disk", "flash", "partition", "filesystem", "hrstorage"}, category: CategoryStorage},
	{keywords: []string{"wireless", "wifi", "wlan", "ssid", "radio", "signal", "rssi", "noise"}, category: CategoryWireless},
	{keywords: []string{"vpn", "ipsec", "tunnel", "ikev", "l2tp"}, category: CategoryVPN},
	{keywords: []string{"bgp", "autonomous", "aspath", "prefix"}, category: CategoryBGP},
	{keywords: []string{"ospf", "neighbor", "lsa", "area"}, category: CategoryOSPF},
	{keywords: []string{"vlan", "dot1q", "dot1d", "bridge"}, category: CategoryVLAN},
	{keywords: []string{"poe", "pethpse", "powerport"}, category: CategoryPoE},
	{keywords: []string{"ups", "battery", "chargeremaining", "minutesremaining"}, category: CategoryUPS},
	{keywords: []string{"printer", "toner", "marker", "paper"}, category: CategoryPrinter},
	{keywords: []string{"voip", "voice", "sip", "rtp", "call"}, category: CategoryVoIP},
	{keywords: []string{"auth", "authentication", "security", "acl", "login", "password"}, category: CategorySecurity},
	{keywords: []string{"ifin", "ifout", "octets", "interface", "link", "port", "ethernet", "duplex", "speed", "ifoperstatus", "ifadminstatus", "ifstatus"}, category: CategoryNetwork},
	{keywords: []string{"uptime", "coldstart", "warmstart", "reachab", "avail"}, category: CategoryAvailability},
	{keywords: []string{"sys", "sysname", "sysdescr", "syscontact", "syslocation", "sysoid"}, category: CategorySystem},
}

func (n *Normalizer) classifyCategory(event *SNMPEvent) {
	if event.Category != "" {
		return
	}

	oid := event.OID
	name := strings.ToLower(event.OIDName)

	for _, rule := range rulesOIDPrefix {
		if strings.HasPrefix(oid, rule.prefix) {
			event.Category = rule.category
			return
		}
	}

	for _, rule := range rulesKeyword {
		for _, kw := range rule.keywords {
			if strings.Contains(name, kw) {
				event.Category = rule.category
				return
			}
		}
	}

	if event.EventType == EventTypeTrap || event.EventType == EventTypeInform {
		event.Category = CategoryTrap
		return
	}

	event.Category = CategoryGeneral
}

// ─── Severity classification ───────────────────────────────────────────────

type severityRule struct {
	trapOID  string
	keywords []string
	severity Severity
}

var severityRules = []severityRule{
	// Standard traps — matched by trapOID prefix
	{trapOID: "1.3.6.1.6.3.1.1.5.5", severity: SeverityHigh},
	{trapOID: "1.3.6.1.6.3.1.1.5.3", severity: SeverityHigh},
	{trapOID: "1.3.6.1.6.3.1.1.5.4", severity: SeverityInfo},
	{trapOID: "1.3.6.1.6.3.1.1.5.1", severity: SeverityMedium},
	{trapOID: "1.3.6.1.6.3.1.1.5.2", severity: SeverityLow},

	// OID name exact prefixes (checked before generic keywords)
	{keywords: []string{"coldstart"}, severity: SeverityMedium},
	{keywords: []string{"warmstart"}, severity: SeverityLow},
	{keywords: []string{"linkdown"}, severity: SeverityHigh},
	{keywords: []string{"linkup"}, severity: SeverityInfo},
	{keywords: []string{"authenticationfailure"}, severity: SeverityHigh},

	// Generic keyword rules
	{keywords: []string{"critical", "fail", "down", "error", "alarm", "alert", "exceed", "overtemp"}, severity: SeverityHigh},
	{keywords: []string{"warn", "high", "discard", "drop", "degrad", "half-duplex", "halfdup"}, severity: SeverityMedium},
	{keywords: []string{"up", "active", "ok", "normal", "recover", "restore", "clear"}, severity: SeverityInfo},
	{keywords: []string{"change", "changed", "modified", "new"}, severity: SeverityLow},
}

func (n *Normalizer) classifySeverity(event *SNMPEvent) {
	if event.Severity > 0 {
		return
	}

	if event.TrapOID != "" {
		for _, r := range severityRules {
			if r.trapOID != "" && strings.HasPrefix(event.TrapOID, r.trapOID) {
				event.Severity = r.severity
				event.SeverityLabel = r.severity.String()
				return
			}
		}
	}

	name := strings.ToLower(event.OIDName)
	for _, r := range severityRules {
		if len(r.keywords) == 0 {
			continue
		}
		for _, kw := range r.keywords {
			if strings.Contains(name, strings.ToLower(kw)) {
				event.Severity = r.severity
				event.SeverityLabel = r.severity.String()
				return
			}
		}
	}

	switch event.Category {
	case CategorySecurity:
		event.Severity = SeverityHigh
	case CategoryEnvironment:
		event.Severity = SeverityMedium
	case CategoryAvailability:
		event.Severity = SeverityMedium
	case CategoryNetwork, CategoryVPN, CategoryBGP, CategoryOSPF:
		event.Severity = SeverityLow
	default:
		event.Severity = SeverityInfo
	}

	event.SeverityLabel = event.Severity.String()
}

// ─── Metric building ───────────────────────────────────────────────────────

type oidMetricDef struct {
	prefix     string
	keywords   []string
	unit       string
	multiplier float64
	threshWarn float64
	threshCrit float64
	isRate     bool
}

var metricDefs = []oidMetricDef{
	// Temperature
	{prefix: "1.3.6.1.4.1.14988.1.1.3.10", unit: "°C", multiplier: 0.1, threshWarn: 65, threshCrit: 80},
	{prefix: "1.3.6.1.4.1.14988.1.1.3.11", unit: "°C", multiplier: 0.1, threshWarn: 65, threshCrit: 80},
	{prefix: "1.3.6.1.4.1.9.9.13.1.3.1.3", unit: "°C", threshWarn: 65, threshCrit: 80},
	{prefix: "1.3.6.1.4.1.2011.5.25.31.1.1.1.1.11", unit: "°C", threshWarn: 65, threshCrit: 80},
	{keywords: []string{"temperature", "thermal", "temp"}, unit: "°C", threshWarn: 65, threshCrit: 80},
	// Fan
	{keywords: []string{"fan", "rpm"}, unit: "RPM"},
	// Voltage
	{prefix: "1.3.6.1.4.1.14988.1.1.3.8", unit: "V", multiplier: 0.1},
	{keywords: []string{"voltage", "volt"}, unit: "V"},
	// CPU
	{prefix: "1.3.6.1.4.1.2021.11.9", unit: "%", threshWarn: 80, threshCrit: 95},
	{prefix: "1.3.6.1.4.1.9.9.109.1.1.1.1.3", unit: "%", threshWarn: 80, threshCrit: 95},
	{prefix: "1.3.6.1.2.1.25.3.3.1.2", unit: "%", threshWarn: 80, threshCrit: 95},
	{keywords: []string{"cpu", "cpuload", "processor"}, unit: "%", threshWarn: 80, threshCrit: 95},
	// Memory
	{prefix: "1.3.6.1.4.1.2021.4.5", unit: "KB"},
	{prefix: "1.3.6.1.4.1.2021.4.6", unit: "KB"},
	{keywords: []string{"memory", "memtotal", "memavail", "memfree"}, unit: "KB"},
	// Traffic (bps)
	{prefix: "1.3.6.1.2.1.2.2.1.10", unit: "bps", isRate: true},
	{prefix: "1.3.6.1.2.1.2.2.1.16", unit: "bps", isRate: true},
	{prefix: "1.3.6.1.2.1.31.1.1.1.6", unit: "bps", isRate: true},
	{prefix: "1.3.6.1.2.1.31.1.1.1.10", unit: "bps", isRate: true},
	{keywords: []string{"octets", "bytes", "traffic", "bps"}, unit: "bps", isRate: true},
	// Errors
	{prefix: "1.3.6.1.2.1.2.2.1.14", unit: "pps", isRate: true},
	{prefix: "1.3.6.1.2.1.2.2.1.20", unit: "pps", isRate: true},
	{keywords: []string{"error", "discard", "drop"}, unit: "pps", isRate: true},
	// Interface speed
	{prefix: "1.3.6.1.2.1.2.2.1.5", unit: "bps"},
	// Uptime
	{prefix: "1.3.6.1.2.1.1.3.0", unit: "s", multiplier: 0.01},
	{prefix: "1.3.6.1.2.1.25.1.1.0", unit: "s", multiplier: 0.01},
	{keywords: []string{"uptime"}, unit: "s", multiplier: 0.01},
	// UPS
	{prefix: "1.3.6.1.2.1.33.1.2.4", unit: "%", threshWarn: 30, threshCrit: 10},
	{prefix: "1.3.6.1.2.1.33.1.2.3", unit: "min", threshWarn: 15, threshCrit: 5},
	// PoE
	{prefix: "1.3.6.1.2.1.105.1.1.1.2", unit: "mW"},
	// Signal
	{keywords: []string{"rssi", "signal", "noise"}, unit: "dBm"},
	// Generic %
	{keywords: []string{"utilization", "util", "percent", "usage"}, unit: "%"},
}

func (n *Normalizer) buildMetric(event *SNMPEvent) {
	raw, ok := toFloat64(event.Value)
	if !ok {
		return
	}

	oid := event.OID
	name := strings.ToLower(event.OIDName)

	var matched *oidMetricDef

	for i := range metricDefs {
		d := &metricDefs[i]
		if d.prefix != "" && strings.HasPrefix(oid, d.prefix) {
			matched = d
			break
		}
	}
	if matched == nil {
		for i := range metricDefs {
			d := &metricDefs[i]
			for _, kw := range d.keywords {
				if strings.Contains(name, strings.ToLower(kw)) {
					matched = d
					break
				}
			}
			if matched != nil {
				break
			}
		}
	}

	processedValue := raw
	if matched != nil {
		event.MetricUnit = matched.unit
		event.MetricIsRate = matched.isRate

		if matched.multiplier != 0 {
			processedValue = raw * matched.multiplier
		}

		if matched.threshWarn != 0 {
			w := matched.threshWarn
			event.ThresholdWarn = &w
		}
		if matched.threshCrit != 0 {
			c := matched.threshCrit
			event.ThresholdCrit = &c
		}

		// Re-evaluate severity based on thresholds
		if event.ThresholdCrit != nil && processedValue >= *event.ThresholdCrit {
			if event.Severity < SeverityCritical {
				event.Severity = SeverityCritical
				event.SeverityLabel = event.Severity.String()
			}
		} else if event.ThresholdWarn != nil && processedValue >= *event.ThresholdWarn {
			if event.Severity < SeverityMedium {
				event.Severity = SeverityMedium
				event.SeverityLabel = event.Severity.String()
			}
		}

		event.ValueStr = fmt.Sprintf("%.2f %s", processedValue, event.MetricUnit)
	}

	event.MetricValue = &processedValue
	rawCopy := raw
	event.MetricRaw = &rawCopy
}

// ─── Helpers ──────────────────────────────────────────────────────────────

func toFloat64(v any) (float64, bool) {
	if v == nil {
		return 0, false
	}
	switch val := v.(type) {
	case float64:
		return val, true
	case float32:
		return float64(val), true
	case int:
		return float64(val), true
	case int32:
		return float64(val), true
	case int64:
		return float64(val), true
	case uint:
		return float64(val), true
	case uint32:
		return float64(val), true
	case uint64:
		return float64(val), true
	case string:
		if f, err := strconv.ParseFloat(val, 64); err == nil {
			return f, true
		}
	}
	return 0, false
}

func setIfEmpty(dst *string, src string) {
	if *dst == "" {
		*dst = src
	}
}

func containsAny(s string, substrs ...string) bool {
	for _, sub := range substrs {
		if strings.Contains(strings.ToLower(s), strings.ToLower(sub)) {
			return true
		}
	}
	return false
}

func toLower(s string) string {
	return strings.ToLower(s)
}

func (n *Normalizer) lookupHost(ip string) string {
	n.dnsCacheMu.RLock()
	if host, ok := n.dnsCache[ip]; ok {
		n.dnsCacheMu.RUnlock()
		return host
	}
	n.dnsCacheMu.RUnlock()

	host := ""
	names, err := net.LookupAddr(ip)
	if err == nil && len(names) > 0 {
		host = names[0]
	}

	n.dnsCacheMu.Lock()
	n.dnsCache[ip] = host
	n.dnsCacheMu.Unlock()

	return host
}

// Ensure time is imported (used by callers via ProcessedAt).
var _ = time.Now
