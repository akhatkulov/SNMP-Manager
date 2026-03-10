package mib

import (
	"fmt"
	"strings"
	"sync"

	"github.com/rs/zerolog"
)

// Resolver handles OID to human-readable name resolution using built-in MIB data.
// It provides a fast in-memory lookup for the most common OIDs used in SIEM monitoring.
type Resolver struct {
	mu       sync.RWMutex
	oidToName map[string]OIDEntry
	nameToOID map[string]string
	log       zerolog.Logger
}

// OIDEntry represents a known OID with metadata.
type OIDEntry struct {
	OID         string `json:"oid"`
	Name        string `json:"name"`
	Module      string `json:"module"`
	Description string `json:"description"`
	Syntax      string `json:"syntax"`
	Access      string `json:"access"`
	Category    string `json:"category"`
}

// NewResolver creates a new MIB resolver with built-in OID database.
func NewResolver(log zerolog.Logger) *Resolver {
	r := &Resolver{
		oidToName: make(map[string]OIDEntry),
		nameToOID: make(map[string]string),
		log:       log.With().Str("component", "mib-resolver").Logger(),
	}
	r.loadBuiltinMIBs()
	return r
}

// Resolve converts an OID to its human-readable name.
// It tries exact match first, then walks up the OID tree.
func (r *Resolver) Resolve(oid string) (OIDEntry, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	// Normalize: remove leading dot
	oid = strings.TrimPrefix(oid, ".")

	// Try exact match
	if entry, ok := r.oidToName[oid]; ok {
		return entry, true
	}

	// Walk up the OID tree for table entries (e.g., ifOperStatus.3 → ifOperStatus)
	parts := strings.Split(oid, ".")
	for i := len(parts) - 1; i > 0; i-- {
		parent := strings.Join(parts[:i], ".")
		if entry, ok := r.oidToName[parent]; ok {
			// Return parent entry but with the full OID and instance suffix
			instance := strings.Join(parts[i:], ".")
			resolved := entry
			resolved.OID = oid
			resolved.Name = fmt.Sprintf("%s.%s", entry.Name, instance)
			return resolved, true
		}
	}

	return OIDEntry{OID: oid, Name: oid, Category: "unknown"}, false
}

// ResolveByName converts a name to its OID.
func (r *Resolver) ResolveByName(name string) (string, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	oid, ok := r.nameToOID[name]
	return oid, ok
}

// Register adds a custom OID entry.
func (r *Resolver) Register(entry OIDEntry) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.oidToName[entry.OID] = entry
	r.nameToOID[entry.Name] = entry.OID
}

// Count returns the number of known OIDs.
func (r *Resolver) Count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.oidToName)
}

// GetOIDsForGroup returns OIDs for a named group (e.g., "system", "interfaces").
func (r *Resolver) GetOIDsForGroup(group string) []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var oids []string
	for oid, entry := range r.oidToName {
		if strings.EqualFold(entry.Category, group) {
			oids = append(oids, oid)
		}
	}
	return oids
}

// ListGroups returns all available OID groups.
func (r *Resolver) ListGroups() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	groups := make(map[string]bool)
	for _, entry := range r.oidToName {
		if entry.Category != "" {
			groups[entry.Category] = true
		}
	}

	result := make([]string, 0, len(groups))
	for g := range groups {
		result = append(result, g)
	}
	return result
}

// loadBuiltinMIBs loads the essential MIB entries for SIEM monitoring.
func (r *Resolver) loadBuiltinMIBs() {
	entries := []OIDEntry{
		// ─── SNMPv2-MIB (System) ─────────────────────────────────────
		{OID: "1.3.6.1.2.1.1.1", Name: "sysDescr", Module: "SNMPv2-MIB", Description: "System description", Syntax: "DisplayString", Access: "read-only", Category: "system"},
		{OID: "1.3.6.1.2.1.1.2", Name: "sysObjectID", Module: "SNMPv2-MIB", Description: "System object identifier", Syntax: "OBJECT IDENTIFIER", Access: "read-only", Category: "system"},
		{OID: "1.3.6.1.2.1.1.3", Name: "sysUpTime", Module: "SNMPv2-MIB", Description: "System uptime in timeticks", Syntax: "TimeTicks", Access: "read-only", Category: "system"},
		{OID: "1.3.6.1.2.1.1.4", Name: "sysContact", Module: "SNMPv2-MIB", Description: "System contact person", Syntax: "DisplayString", Access: "read-write", Category: "system"},
		{OID: "1.3.6.1.2.1.1.5", Name: "sysName", Module: "SNMPv2-MIB", Description: "System hostname", Syntax: "DisplayString", Access: "read-write", Category: "system"},
		{OID: "1.3.6.1.2.1.1.6", Name: "sysLocation", Module: "SNMPv2-MIB", Description: "System physical location", Syntax: "DisplayString", Access: "read-write", Category: "system"},
		{OID: "1.3.6.1.2.1.1.7", Name: "sysServices", Module: "SNMPv2-MIB", Description: "System services", Syntax: "INTEGER", Access: "read-only", Category: "system"},

		// ─── IF-MIB (Interfaces) ─────────────────────────────────────
		{OID: "1.3.6.1.2.1.2.1", Name: "ifNumber", Module: "IF-MIB", Description: "Number of network interfaces", Syntax: "INTEGER", Access: "read-only", Category: "interfaces"},
		{OID: "1.3.6.1.2.1.2.2.1.1", Name: "ifIndex", Module: "IF-MIB", Description: "Interface index", Syntax: "InterfaceIndex", Access: "read-only", Category: "interfaces"},
		{OID: "1.3.6.1.2.1.2.2.1.2", Name: "ifDescr", Module: "IF-MIB", Description: "Interface description", Syntax: "DisplayString", Access: "read-only", Category: "interfaces"},
		{OID: "1.3.6.1.2.1.2.2.1.3", Name: "ifType", Module: "IF-MIB", Description: "Interface type", Syntax: "IANAifType", Access: "read-only", Category: "interfaces"},
		{OID: "1.3.6.1.2.1.2.2.1.5", Name: "ifSpeed", Module: "IF-MIB", Description: "Interface speed (bps)", Syntax: "Gauge32", Access: "read-only", Category: "interfaces"},
		{OID: "1.3.6.1.2.1.2.2.1.7", Name: "ifAdminStatus", Module: "IF-MIB", Description: "Interface admin status", Syntax: "INTEGER", Access: "read-write", Category: "interfaces"},
		{OID: "1.3.6.1.2.1.2.2.1.8", Name: "ifOperStatus", Module: "IF-MIB", Description: "Interface operational status", Syntax: "INTEGER", Access: "read-only", Category: "interfaces"},
		{OID: "1.3.6.1.2.1.2.2.1.10", Name: "ifInOctets", Module: "IF-MIB", Description: "Incoming octets", Syntax: "Counter32", Access: "read-only", Category: "interfaces"},
		{OID: "1.3.6.1.2.1.2.2.1.13", Name: "ifInDiscards", Module: "IF-MIB", Description: "Incoming discarded packets", Syntax: "Counter32", Access: "read-only", Category: "interfaces"},
		{OID: "1.3.6.1.2.1.2.2.1.14", Name: "ifInErrors", Module: "IF-MIB", Description: "Incoming error packets", Syntax: "Counter32", Access: "read-only", Category: "interfaces"},
		{OID: "1.3.6.1.2.1.2.2.1.16", Name: "ifOutOctets", Module: "IF-MIB", Description: "Outgoing octets", Syntax: "Counter32", Access: "read-only", Category: "interfaces"},
		{OID: "1.3.6.1.2.1.2.2.1.19", Name: "ifOutDiscards", Module: "IF-MIB", Description: "Outgoing discarded packets", Syntax: "Counter32", Access: "read-only", Category: "interfaces"},
		{OID: "1.3.6.1.2.1.2.2.1.20", Name: "ifOutErrors", Module: "IF-MIB", Description: "Outgoing error packets", Syntax: "Counter32", Access: "read-only", Category: "interfaces"},

		// IF-MIB (64-bit counters)
		{OID: "1.3.6.1.2.1.31.1.1.1.6", Name: "ifHCInOctets", Module: "IF-MIB", Description: "Incoming octets (64-bit)", Syntax: "Counter64", Access: "read-only", Category: "interfaces"},
		{OID: "1.3.6.1.2.1.31.1.1.1.10", Name: "ifHCOutOctets", Module: "IF-MIB", Description: "Outgoing octets (64-bit)", Syntax: "Counter64", Access: "read-only", Category: "interfaces"},
		{OID: "1.3.6.1.2.1.31.1.1.1.1", Name: "ifName", Module: "IF-MIB", Description: "Interface short name", Syntax: "DisplayString", Access: "read-only", Category: "interfaces"},
		{OID: "1.3.6.1.2.1.31.1.1.1.18", Name: "ifAlias", Module: "IF-MIB", Description: "Interface alias", Syntax: "DisplayString", Access: "read-write", Category: "interfaces"},

		// ─── HOST-RESOURCES-MIB (CPU, Memory, Storage) ───────────────
		{OID: "1.3.6.1.2.1.25.1.1", Name: "hrSystemUptime", Module: "HOST-RESOURCES-MIB", Description: "Host uptime", Syntax: "TimeTicks", Access: "read-only", Category: "host"},
		{OID: "1.3.6.1.2.1.25.1.6", Name: "hrSystemProcesses", Module: "HOST-RESOURCES-MIB", Description: "Number of processes", Syntax: "Gauge32", Access: "read-only", Category: "host"},
		{OID: "1.3.6.1.2.1.25.2.2", Name: "hrMemorySize", Module: "HOST-RESOURCES-MIB", Description: "Total memory (KB)", Syntax: "INTEGER", Access: "read-only", Category: "host"},
		{OID: "1.3.6.1.2.1.25.2.3.1.2", Name: "hrStorageType", Module: "HOST-RESOURCES-MIB", Description: "Storage type", Syntax: "OBJECT IDENTIFIER", Access: "read-only", Category: "host"},
		{OID: "1.3.6.1.2.1.25.2.3.1.3", Name: "hrStorageDescr", Module: "HOST-RESOURCES-MIB", Description: "Storage description", Syntax: "DisplayString", Access: "read-only", Category: "host"},
		{OID: "1.3.6.1.2.1.25.2.3.1.4", Name: "hrStorageAllocationUnits", Module: "HOST-RESOURCES-MIB", Description: "Storage allocation unit size", Syntax: "INTEGER", Access: "read-only", Category: "host"},
		{OID: "1.3.6.1.2.1.25.2.3.1.5", Name: "hrStorageSize", Module: "HOST-RESOURCES-MIB", Description: "Storage total size", Syntax: "INTEGER", Access: "read-only", Category: "host"},
		{OID: "1.3.6.1.2.1.25.2.3.1.6", Name: "hrStorageUsed", Module: "HOST-RESOURCES-MIB", Description: "Storage used space", Syntax: "INTEGER", Access: "read-only", Category: "host"},
		{OID: "1.3.6.1.2.1.25.3.3.1.2", Name: "hrProcessorLoad", Module: "HOST-RESOURCES-MIB", Description: "CPU load percentage", Syntax: "INTEGER", Access: "read-only", Category: "cpu_memory"},

		// ─── UCD-SNMP-MIB (Linux specific) ───────────────────────────
		{OID: "1.3.6.1.4.1.2021.4.3", Name: "memTotalSwap", Module: "UCD-SNMP-MIB", Description: "Total swap space (KB)", Syntax: "INTEGER", Access: "read-only", Category: "cpu_memory"},
		{OID: "1.3.6.1.4.1.2021.4.4", Name: "memAvailSwap", Module: "UCD-SNMP-MIB", Description: "Available swap space (KB)", Syntax: "INTEGER", Access: "read-only", Category: "cpu_memory"},
		{OID: "1.3.6.1.4.1.2021.4.5", Name: "memTotalReal", Module: "UCD-SNMP-MIB", Description: "Total real memory (KB)", Syntax: "INTEGER", Access: "read-only", Category: "cpu_memory"},
		{OID: "1.3.6.1.4.1.2021.4.6", Name: "memAvailReal", Module: "UCD-SNMP-MIB", Description: "Available real memory (KB)", Syntax: "INTEGER", Access: "read-only", Category: "cpu_memory"},
		{OID: "1.3.6.1.4.1.2021.4.11", Name: "memTotalFree", Module: "UCD-SNMP-MIB", Description: "Total free memory (KB)", Syntax: "INTEGER", Access: "read-only", Category: "cpu_memory"},
		{OID: "1.3.6.1.4.1.2021.4.14", Name: "memBuffer", Module: "UCD-SNMP-MIB", Description: "Buffer memory (KB)", Syntax: "INTEGER", Access: "read-only", Category: "cpu_memory"},
		{OID: "1.3.6.1.4.1.2021.4.15", Name: "memCached", Module: "UCD-SNMP-MIB", Description: "Cached memory (KB)", Syntax: "INTEGER", Access: "read-only", Category: "cpu_memory"},
		{OID: "1.3.6.1.4.1.2021.10.1.3.1", Name: "laLoad1", Module: "UCD-SNMP-MIB", Description: "1 minute load average", Syntax: "DisplayString", Access: "read-only", Category: "cpu_memory"},
		{OID: "1.3.6.1.4.1.2021.10.1.3.2", Name: "laLoad5", Module: "UCD-SNMP-MIB", Description: "5 minute load average", Syntax: "DisplayString", Access: "read-only", Category: "cpu_memory"},
		{OID: "1.3.6.1.4.1.2021.10.1.3.3", Name: "laLoad15", Module: "UCD-SNMP-MIB", Description: "15 minute load average", Syntax: "DisplayString", Access: "read-only", Category: "cpu_memory"},
		{OID: "1.3.6.1.4.1.2021.11.9", Name: "ssCpuUser", Module: "UCD-SNMP-MIB", Description: "CPU user time %", Syntax: "INTEGER", Access: "read-only", Category: "cpu_memory"},
		{OID: "1.3.6.1.4.1.2021.11.10", Name: "ssCpuSystem", Module: "UCD-SNMP-MIB", Description: "CPU system time %", Syntax: "INTEGER", Access: "read-only", Category: "cpu_memory"},
		{OID: "1.3.6.1.4.1.2021.11.11", Name: "ssCpuIdle", Module: "UCD-SNMP-MIB", Description: "CPU idle time %", Syntax: "INTEGER", Access: "read-only", Category: "cpu_memory"},

		// ─── IP-MIB ──────────────────────────────────────────────────
		{OID: "1.3.6.1.2.1.4.3", Name: "ipInReceives", Module: "IP-MIB", Description: "IP datagrams received", Syntax: "Counter32", Access: "read-only", Category: "ip"},
		{OID: "1.3.6.1.2.1.4.10", Name: "ipInDelivers", Module: "IP-MIB", Description: "IP datagrams delivered", Syntax: "Counter32", Access: "read-only", Category: "ip"},
		{OID: "1.3.6.1.2.1.4.20.1.1", Name: "ipAdEntAddr", Module: "IP-MIB", Description: "IP address entry", Syntax: "IpAddress", Access: "read-only", Category: "ip"},

		// ─── TCP/UDP ─────────────────────────────────────────────────
		{OID: "1.3.6.1.2.1.6.5", Name: "tcpActiveOpens", Module: "TCP-MIB", Description: "Active TCP connections opened", Syntax: "Counter32", Access: "read-only", Category: "tcp"},
		{OID: "1.3.6.1.2.1.6.9", Name: "tcpCurrEstab", Module: "TCP-MIB", Description: "Current TCP connections", Syntax: "Gauge32", Access: "read-only", Category: "tcp"},
		{OID: "1.3.6.1.2.1.7.1", Name: "udpInDatagrams", Module: "UDP-MIB", Description: "UDP datagrams received", Syntax: "Counter32", Access: "read-only", Category: "udp"},

		// ─── SNMP Traps (Standard) ───────────────────────────────────
		{OID: "1.3.6.1.6.3.1.1.5.1", Name: "coldStart", Module: "SNMPv2-MIB", Description: "Device cold start (full restart)", Syntax: "NOTIFICATION-TYPE", Category: "trap"},
		{OID: "1.3.6.1.6.3.1.1.5.2", Name: "warmStart", Module: "SNMPv2-MIB", Description: "Device warm start (software restart)", Syntax: "NOTIFICATION-TYPE", Category: "trap"},
		{OID: "1.3.6.1.6.3.1.1.5.3", Name: "linkDown", Module: "IF-MIB", Description: "Interface link down", Syntax: "NOTIFICATION-TYPE", Category: "trap"},
		{OID: "1.3.6.1.6.3.1.1.5.4", Name: "linkUp", Module: "IF-MIB", Description: "Interface link up", Syntax: "NOTIFICATION-TYPE", Category: "trap"},
		{OID: "1.3.6.1.6.3.1.1.5.5", Name: "authenticationFailure", Module: "SNMPv2-MIB", Description: "SNMP authentication failure", Syntax: "NOTIFICATION-TYPE", Category: "trap"},

		// ─── ENTITY-MIB (Hardware) ───────────────────────────────────
		{OID: "1.3.6.1.2.1.47.1.1.1.1.2", Name: "entPhysicalDescr", Module: "ENTITY-MIB", Description: "Physical entity description", Syntax: "DisplayString", Access: "read-only", Category: "entity"},
		{OID: "1.3.6.1.2.1.47.1.1.1.1.7", Name: "entPhysicalName", Module: "ENTITY-MIB", Description: "Physical entity name", Syntax: "DisplayString", Access: "read-only", Category: "entity"},
		{OID: "1.3.6.1.2.1.47.1.1.1.1.11", Name: "entPhysicalSerialNum", Module: "ENTITY-MIB", Description: "Physical entity serial number", Syntax: "DisplayString", Access: "read-write", Category: "entity"},
		{OID: "1.3.6.1.2.1.47.1.1.1.1.13", Name: "entPhysicalModelName", Module: "ENTITY-MIB", Description: "Physical entity model", Syntax: "DisplayString", Access: "read-only", Category: "entity"},

		// ─── SNMP Engine ─────────────────────────────────────────────
		{OID: "1.3.6.1.6.3.10.2.1.1", Name: "snmpEngineID", Module: "SNMP-FRAMEWORK-MIB", Description: "SNMP engine ID", Syntax: "OCTET STRING", Access: "read-only", Category: "snmp_engine"},
		{OID: "1.3.6.1.6.3.10.2.1.3", Name: "snmpEngineTime", Module: "SNMP-FRAMEWORK-MIB", Description: "SNMP engine uptime", Syntax: "INTEGER", Access: "read-only", Category: "snmp_engine"},
	}

	for _, entry := range entries {
		r.oidToName[entry.OID] = entry
		r.nameToOID[entry.Name] = entry.OID
	}

	r.log.Info().Int("oids", len(entries)).Msg("built-in MIB entries loaded")
}
