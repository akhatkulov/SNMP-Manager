package mib

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/sleepinggenius2/gosmi"
	"github.com/sleepinggenius2/gosmi/types"
)

// Standard MIB search paths
var defaultMIBPaths = []string{
	"/usr/share/snmp/mibs",
	"/usr/share/mibs",
	"/usr/local/share/snmp/mibs",
	"/usr/share/snmp/mibs/ietf",
	"/usr/share/snmp/mibs/iana",
}

// LoadSystemMIBs loads MIB files from the system MIB directories using gosmi.
// This provides thousands of OID translations from standard RFC MIBs.
func (r *Resolver) LoadSystemMIBs(extraPaths ...string) int {
	// Initialize gosmi
	gosmi.Init()

	// Add MIB search paths
	paths := append(defaultMIBPaths, extraPaths...)
	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			gosmi.AppendPath(p)
			r.log.Debug().Str("path", p).Msg("added MIB search path")
		}
	}

	// Load key MIB modules
	modules := []string{
		"SNMPv2-MIB",
		"IF-MIB",
		"IP-MIB",
		"TCP-MIB",
		"UDP-MIB",
		"HOST-RESOURCES-MIB",
		"BRIDGE-MIB",
		"ENTITY-MIB",
		"SNMP-FRAMEWORK-MIB",
		"IP-FORWARD-MIB",
		"EtherLike-MIB",
		"NOTIFICATION-LOG-MIB",
		"SNMP-TARGET-MIB",
	}

	loaded := 0
	for _, mod := range modules {
		moduleName, err := gosmi.LoadModule(mod)
		if err != nil {
			r.log.Debug().Str("module", mod).Err(err).Msg("could not load MIB module")
			continue
		}
		r.log.Debug().Str("module", moduleName).Msg("loaded MIB module")
		loaded++
	}

	// Also try loading all .txt MIB files found in paths
	for _, p := range paths {
		entries, err := os.ReadDir(p)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			name := entry.Name()
			ext := filepath.Ext(name)
			if ext == ".txt" || ext == "" {
				modName := strings.TrimSuffix(name, ext)
				_, err := gosmi.LoadModule(modName)
				if err == nil {
					loaded++
				}
			}
		}
	}

	if loaded == 0 {
		r.log.Warn().Msg("no system MIB files loaded, using built-in database only")
		return 0
	}

	// Walk the loaded MIB tree and extract all OID entries
	added := 0
	gosmiModules := gosmi.GetLoadedModules()
	for _, mod := range gosmiModules {
		nodes := mod.GetNodes()
		for _, node := range nodes {
			oid := node.Oid.String()
			if oid == "" || oid == "0" {
				continue
			}

			name := node.Name
			module := node.GetModule().Name

			// Determine category from module name
			category := categorizeModule(module)

			// Determine access
			access := ""
			switch node.Access {
			case types.AccessReadOnly:
				access = "read-only"
			case types.AccessReadWrite:
				access = "read-write"
			case types.AccessNotify:
				access = "notify"
			}

			entry := OIDEntry{
				OID:         oid,
				Name:        name,
				Module:      module,
				Description: node.Description,
				Access:      access,
				Category:    category,
			}

			// Determine syntax
			if node.Type != nil {
				entry.Syntax = node.Type.Name
			}

			r.mu.Lock()
			// Don't overwrite our curated entries (they have better categories)
			if _, exists := r.oidToName[oid]; !exists {
				r.oidToName[oid] = entry
				r.nameToOID[name] = oid
				added++
			}
			r.mu.Unlock()
		}
	}

	r.log.Info().
		Int("modules_loaded", loaded).
		Int("oids_added", added).
		Int("total_oids", r.Count()).
		Msg("system MIB files loaded via gosmi")

	return added
}

// categorizeModule maps MIB module names to our internal categories.
func categorizeModule(module string) string {
	modLower := strings.ToLower(module)
	switch {
	case strings.Contains(modLower, "snmpv2") && strings.Contains(modLower, "mib"):
		return "system"
	case strings.Contains(modLower, "if-mib") || strings.Contains(modLower, "ifmib"):
		return "interfaces"
	case strings.Contains(modLower, "ip-mib") || strings.Contains(modLower, "ipmib"):
		return "ip"
	case strings.Contains(modLower, "tcp"):
		return "tcp"
	case strings.Contains(modLower, "udp"):
		return "udp"
	case strings.Contains(modLower, "bridge"):
		return "bridge"
	case strings.Contains(modLower, "entity"):
		return "entity"
	case strings.Contains(modLower, "host"):
		return "host"
	case strings.Contains(modLower, "ether"):
		return "ethernet"
	case strings.Contains(modLower, "notification") || strings.Contains(modLower, "trap"):
		return "trap"
	case strings.Contains(modLower, "snmp"):
		return "snmp_engine"
	default:
		return modLower
	}
}
