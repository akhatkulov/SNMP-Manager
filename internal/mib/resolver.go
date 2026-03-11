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

// loadBuiltinMIBs loads the comprehensive MIB database.
func (r *Resolver) loadBuiltinMIBs() {
	entries := GetExtendedMIBDatabase()

	for _, entry := range entries {
		r.oidToName[entry.OID] = entry
		r.nameToOID[entry.Name] = entry.OID
	}

	r.log.Info().Int("oids", len(entries)).Msg("MIB database loaded")
}
