package template

import (
	"encoding/json"
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

// ─── Zabbix YAML top-level structure ─────────────────────────────────────────

type ZabbixExport struct {
	Version   string       `yaml:"version"`
	Templates []ZabbixTmpl `yaml:"templates"`
}

type ZabbixTmpl struct {
	UUID        string       `yaml:"uuid"`
	Template    string       `yaml:"template"`
	Name        string       `yaml:"name"`
	Description string       `yaml:"description"`
	Vendor      ZabbixVendor `yaml:"vendor"`
	Items       []ZabbixItem `yaml:"items"`
	Discovery   []ZabbixDisc `yaml:"discovery_rules"`
	Macros      []ZabbixMacro `yaml:"macros"`
}

type ZabbixVendor struct {
	Name    string `yaml:"name"`
	Version string `yaml:"version"`
}

type ZabbixItem struct {
	Name        string `yaml:"name"`
	Type        string `yaml:"type"`
	SNMPOid     string `yaml:"snmp_oid"`
	Key         string `yaml:"key"`
	ValueType   string `yaml:"value_type"`
	Description string `yaml:"description"`
}

type ZabbixDisc struct {
	Name           string       `yaml:"name"`
	Type           string       `yaml:"type"`
	SNMPOid        string       `yaml:"snmp_oid"`
	Key            string       `yaml:"key"`
	Description    string       `yaml:"description"`
	ItemPrototypes []ZabbixItem `yaml:"item_prototypes"`
}

type ZabbixMacro struct {
	Macro       string `yaml:"macro"`
	Value       string `yaml:"value"`
	Description string `yaml:"description"`
}

// ─── Import result ────────────────────────────────────────────────────────────

// ImportResult holds the outcome of a bulk import operation.
type ImportResult struct {
	Imported []string      `json:"imported"`
	Skipped  []string      `json:"skipped"`
	Errors   []ImportError `json:"errors"`
	Total    int           `json:"total"`
}

// ImportError describes a per-template failure.
type ImportError struct {
	TemplateID string `json:"template_id"`
	Name       string `json:"name"`
	Reason     string `json:"reason"`
}

// ImportMode controls conflict handling during bulk import.
type ImportMode string

const (
	ImportModeSkip      ImportMode = "skip"      // keep existing (default)
	ImportModeOverwrite ImportMode = "overwrite"  // replace existing
)

// ─── BulkAdd ──────────────────────────────────────────────────────────────────

// BulkAdd adds multiple templates at once.
func (s *Store) BulkAdd(templates []*Template, mode ImportMode) ImportResult {
	s.mu.Lock()
	defer s.mu.Unlock()

	result := ImportResult{
		Imported: make([]string, 0),
		Skipped:  make([]string, 0),
		Errors:   make([]ImportError, 0),
		Total:    len(templates),
	}

	changed := false

	for _, t := range templates {
		if t.ID == "" || t.Name == "" {
			result.Errors = append(result.Errors, ImportError{
				TemplateID: t.ID,
				Name:       t.Name,
				Reason:     "id and name are required",
			})
			continue
		}

		t.Builtin = false

		if existing, exists := s.templates[t.ID]; exists {
			if mode == ImportModeOverwrite {
				if existing.Builtin {
					result.Errors = append(result.Errors, ImportError{
						TemplateID: t.ID,
						Name:       t.Name,
						Reason:     "cannot overwrite built-in template",
					})
					continue
				}
				s.templates[t.ID] = t
				result.Imported = append(result.Imported, t.ID)
				changed = true
			} else {
				result.Skipped = append(result.Skipped, t.ID)
			}
			continue
		}

		s.templates[t.ID] = t
		result.Imported = append(result.Imported, t.ID)
		changed = true
	}

	if changed {
		_ = s.saveCustom()
	}

	return result
}

// ZabbixFile is the top-level wrapper for Zabbix YAML exports.
// All content is nested under the "zabbix_export" key.
type ZabbixFile struct {
	ZabbixExport ZabbixExport `yaml:"zabbix_export"`
}

// ─── Parser: Zabbix YAML ──────────────────────────────────────────────────────

// ParseZabbixYAML parses a Zabbix 6.x/7.x YAML export and converts all
// templates to our internal format.
func ParseZabbixYAML(data []byte) ([]*Template, error) {
	var file ZabbixFile
	if err := yaml.Unmarshal(data, &file); err != nil {
		return nil, fmt.Errorf("invalid YAML: %w", err)
	}
	export := file.ZabbixExport
	if len(export.Templates) == 0 {
		return nil, fmt.Errorf("no templates found in file (version: %s)", export.Version)
	}

	result := make([]*Template, 0, len(export.Templates))
	for _, zt := range export.Templates {
		result = append(result, convertZabbixTemplate(zt))
	}
	return result, nil
}


// ParseNativeJSON parses an array of our own Template JSON objects.
// This allows re-importing previously exported templates.
func ParseNativeJSON(data []byte) ([]*Template, error) {
	var templates []Template
	if err := json.Unmarshal(data, &templates); err != nil {
		return nil, fmt.Errorf("invalid JSON: %w", err)
	}
	if len(templates) == 0 {
		return nil, fmt.Errorf("no templates found in JSON")
	}
	ptrs := make([]*Template, len(templates))
	for i := range templates {
		ptrs[i] = &templates[i]
	}
	return ptrs, nil
}

// ─── Converter ────────────────────────────────────────────────────────────────

func convertZabbixTemplate(zt ZabbixTmpl) *Template {
	id := slugify(zt.Template)
	if id == "" {
		id = slugify(zt.Name)
	}

	t := &Template{
		ID:              id,
		Name:            zt.Name,
		Description:     cleanDesc(zt.Description),
		Category:        inferCategory(zt),
		Vendor:          inferVendor(zt),
		OIDGroups:       inferOIDGroups(zt),
		Items:           make([]TemplateItem, 0),
		DefaultTags:     map[string]string{},
		DefaultInterval: inferInterval(zt),
	}

	// Direct items (SNMP_AGENT type with explicit OID)
	for _, zi := range zt.Items {
		if item, ok := convertItem(zi); ok {
			t.Items = append(t.Items, item)
		}
	}

	// Discovery rule prototypes (LLD) → flatten as generic items
	for _, disc := range zt.Discovery {
		cat := inferDiscCategory(disc.Name)
		for _, proto := range disc.ItemPrototypes {
			oid := normalizeLLDOid(proto.SNMPOid)
			if oid == "" {
				continue
			}
			t.Items = append(t.Items, TemplateItem{
				OID:         oid,
				Name:        proto.Name,
				Description: proto.Description,
				Type:        mapZabbixValueType(proto.ValueType),
				Category:    cat,
			})
		}
	}

	// Vendor tag
	if t.Vendor != "" && t.Vendor != "Any" && t.Vendor != "Zabbix" {
		t.DefaultTags["vendor"] = strings.ToLower(t.Vendor)
	}

	return t
}

func convertItem(zi ZabbixItem) (TemplateItem, bool) {
	oid := extractOIDFromGet(zi.SNMPOid)
	if oid == "" || strings.HasPrefix(oid, "discovery[") {
		return TemplateItem{}, false
	}
	return TemplateItem{
		OID:         oid,
		Name:        zi.Name,
		Description: zi.Description,
		Type:        mapZabbixValueType(zi.ValueType),
		Category:    inferItemCategory(zi.Name, zi.Key),
	}, true
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

func extractOIDFromGet(s string) string {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "get[") && strings.HasSuffix(s, "]") {
		return s[4 : len(s)-1]
	}
	return s
}

func normalizeLLDOid(s string) string {
	s = extractOIDFromGet(s)
	s = strings.ReplaceAll(s, ".{#SNMPINDEX}", "")
	s = strings.ReplaceAll(s, "{#SNMPINDEX}", "")
	if !strings.HasPrefix(s, "1.") {
		return ""
	}
	return s
}

func slugify(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	var b strings.Builder
	prevDash := false
	for _, c := range s {
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') {
			b.WriteRune(c)
			prevDash = false
		} else if c == ' ' || c == '_' || c == '/' || c == '.' || c == '-' {
			if !prevDash && b.Len() > 0 {
				b.WriteRune('-')
				prevDash = true
			}
		}
	}
	return strings.TrimRight(b.String(), "-")
}

func cleanDesc(s string) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	out := make([]string, 0, len(lines))
	for _, l := range lines {
		if l = strings.TrimSpace(l); l != "" {
			out = append(out, l)
		}
	}
	return strings.Join(out, " ")
}

func inferCategory(zt ZabbixTmpl) string {
	name := strings.ToLower(zt.Name)
	switch {
	// Firewalls / security
	case zContains(name, "firewall", "utm", "checkpoint", "fortinet", "paloalto", "stormshield"):
		return "firewall"
	// Routers
	case zContains(name, "router", "routing", "cisco ios", "cisco asr", "mikrotik", "juniper mx", "juniper", "vyatta", "cradlepoint"):
		return "router"
	// Switches
	case zContains(name, "switch", "foundry", "brocade", "extreme", "arista", "hp enterprise", "hh3c", "dell force", "d-link", "netgear", "tp-link", "alcatel", "ciena", "qtech"):
		return "switch"
	// Load balancers / ADC
	case zContains(name, "big-ip", "f5", "load balanc"):
		return "generic"
	// Wireless
	case zContains(name, "wireless", "access point", "wifi", " ap ", "airos", "ubiquiti", "aruba", "meraki"):
		return "ap"
	// Printers
	case zContains(name, "printer"):
		return "printer"
	// Servers / OS
	case zContains(name, "windows", "linux", "unix", "freebsd", "openbsd", "solaris", "aix", "macos", "server"):
		return "server"
	default:
		return "generic"
	}
}

func inferVendor(zt ZabbixTmpl) string {
	if zt.Vendor.Name != "" && zt.Vendor.Name != "Zabbix" {
		return zt.Vendor.Name
	}
	name := strings.ToLower(zt.Name)
	vendors := []struct{ kw, label string }{
		{"cisco", "Cisco"}, {"mikrotik", "MikroTik"}, {"huawei", "Huawei"},
		{"juniper", "Juniper"}, {"aruba", "Aruba"}, {"ubiquiti", "Ubiquiti"},
		{"fortinet", "Fortinet"}, {"paloalto", "Palo Alto"},
		{"checkpoint", "Check Point"}, {"eltex", "Eltex"}, {"dlink", "D-Link"},
		{"zte", "ZTE"}, {"netgear", "Netgear"},
	}
	for _, v := range vendors {
		if strings.Contains(name, v.kw) {
			return v.label
		}
	}
	return "Any"
}

func inferOIDGroups(zt ZabbixTmpl) []string {
	all := strings.ToLower(zt.Name + " " + zt.Description)
	groups := map[string]bool{"system": true}
	if zContains(all, "interface", "traffic", "octets") {
		groups["interfaces"] = true
	}
	if zContains(all, "cpu", "processor", "load", "memory") {
		groups["cpu_memory"] = true
	}
	if zContains(all, "disk", "storage", "filesystem") {
		groups["storage"] = true
	}
	if zContains(all, "temperature", "fan", "voltage", "environment", "sensor") {
		groups["environment"] = true
	}
	if zContains(all, "vlan", "bridge") {
		groups["vlan"] = true
	}
	if zContains(all, "bgp") {
		groups["bgp"] = true
	}
	if zContains(all, "ospf") {
		groups["ospf"] = true
	}
	result := make([]string, 0, len(groups))
	for g := range groups {
		result = append(result, g)
	}
	return result
}

func inferInterval(zt ZabbixTmpl) string {
	for _, m := range zt.Macros {
		if zContains(m.Macro, "INTERVAL", "DELAY") && m.Value != "" {
			return m.Value
		}
	}
	return "60s"
}

func inferDiscCategory(name string) string {
	name = strings.ToLower(name)
	switch {
	case zContains(name, "interface", "etherlike"):
		return "interfaces"
	case zContains(name, "cpu"):
		return "cpu"
	case zContains(name, "memory", "mem"):
		return "memory"
	case zContains(name, "disk", "storage", "filesystem"):
		return "disk"
	case zContains(name, "temperature", "fan", "sensor", "environment"):
		return "environment"
	case zContains(name, "vlan"):
		return "vlan"
	default:
		return "general"
	}
}

func inferItemCategory(name, key string) string {
	s := strings.ToLower(name + " " + key)
	switch {
	case zContains(s, "cpu", "processor", "load"):
		return "cpu"
	case zContains(s, "memory", "mem", "ram"):
		return "memory"
	case zContains(s, "temperature", "thermal", "fan", "voltage"):
		return "environment"
	case zContains(s, "interface", "octets", "errors", "discards", "speed", "link"):
		return "interfaces"
	case zContains(s, "disk", "storage", "filesystem"):
		return "disk"
	case zContains(s, "uptime"):
		return "system"
	case zContains(s, "icmp", "ping"):
		return "availability"
	case zContains(s, "vlan"):
		return "vlan"
	default:
		return "system"
	}
}

func mapZabbixValueType(vt string) string {
	switch strings.ToUpper(vt) {
	case "FLOAT":
		return "Float"
	case "CHAR", "TEXT", "LOG":
		return "OctetString"
	case "UNSIGNED":
		return "Counter32"
	default:
		return "Integer"
	}
}

func zContains(s string, subs ...string) bool {
	for _, sub := range subs {
		if strings.Contains(s, strings.ToLower(sub)) {
			return true
		}
	}
	return false
}
