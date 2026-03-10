package mib

import (
	"testing"

	"github.com/rs/zerolog"
)

func newTestResolver() *Resolver {
	return NewResolver(zerolog.Nop())
}

func TestResolverBuiltinCount(t *testing.T) {
	r := newTestResolver()
	count := r.Count()
	if count < 50 {
		t.Errorf("built-in OID count: want >= 50, got %d", count)
	}
}

func TestResolverExactMatch(t *testing.T) {
	r := newTestResolver()

	tests := []struct {
		oid      string
		wantName string
		wantMod  string
	}{
		{"1.3.6.1.2.1.1.1", "sysDescr", "SNMPv2-MIB"},
		{"1.3.6.1.2.1.1.3", "sysUpTime", "SNMPv2-MIB"},
		{"1.3.6.1.2.1.1.5", "sysName", "SNMPv2-MIB"},
		{"1.3.6.1.2.1.2.2.1.8", "ifOperStatus", "IF-MIB"},
		{"1.3.6.1.2.1.2.2.1.10", "ifInOctets", "IF-MIB"},
		{"1.3.6.1.2.1.25.3.3.1.2", "hrProcessorLoad", "HOST-RESOURCES-MIB"},
		{"1.3.6.1.4.1.2021.4.5", "memTotalReal", "UCD-SNMP-MIB"},
		{"1.3.6.1.6.3.1.1.5.3", "linkDown", "IF-MIB"},
		{"1.3.6.1.6.3.1.1.5.5", "authenticationFailure", "SNMPv2-MIB"},
	}

	for _, tt := range tests {
		t.Run(tt.wantName, func(t *testing.T) {
			entry, found := r.Resolve(tt.oid)
			if !found {
				t.Fatalf("OID %s not found", tt.oid)
			}
			if entry.Name != tt.wantName {
				t.Errorf("name: want %q, got %q", tt.wantName, entry.Name)
			}
			if entry.Module != tt.wantMod {
				t.Errorf("module: want %q, got %q", tt.wantMod, entry.Module)
			}
		})
	}
}

func TestResolverLeadingDot(t *testing.T) {
	r := newTestResolver()

	// Should work with leading dot
	entry, found := r.Resolve(".1.3.6.1.2.1.1.1")
	if !found {
		t.Fatal("resolve with leading dot failed")
	}
	if entry.Name != "sysDescr" {
		t.Errorf("name: want sysDescr, got %q", entry.Name)
	}
}

func TestResolverTableInstance(t *testing.T) {
	r := newTestResolver()

	// ifOperStatus.3 should resolve to ifOperStatus with instance suffix
	entry, found := r.Resolve("1.3.6.1.2.1.2.2.1.8.3")
	if !found {
		t.Fatal("table instance OID not resolved")
	}
	if entry.Name != "ifOperStatus.3" {
		t.Errorf("table instance name: want %q, got %q", "ifOperStatus.3", entry.Name)
	}

	// ifInOctets.1
	entry, found = r.Resolve("1.3.6.1.2.1.2.2.1.10.1")
	if !found {
		t.Fatal("ifInOctets.1 not resolved")
	}
	if entry.Name != "ifInOctets.1" {
		t.Errorf("name: want %q, got %q", "ifInOctets.1", entry.Name)
	}
}

func TestResolverUnknownOID(t *testing.T) {
	r := newTestResolver()

	entry, found := r.Resolve("1.3.6.1.99.99.99")
	if found {
		t.Error("expected not found for unknown OID")
	}
	// Should still return the OID as the name
	if entry.OID != "1.3.6.1.99.99.99" {
		t.Errorf("unknown OID: want oid echoed back, got %q", entry.OID)
	}
}

func TestResolverByName(t *testing.T) {
	r := newTestResolver()

	oid, found := r.ResolveByName("sysDescr")
	if !found {
		t.Fatal("sysDescr not found by name")
	}
	if oid != "1.3.6.1.2.1.1.1" {
		t.Errorf("sysDescr OID: want %q, got %q", "1.3.6.1.2.1.1.1", oid)
	}

	_, found = r.ResolveByName("nonexistent")
	if found {
		t.Error("expected not found for nonexistent name")
	}
}

func TestResolverRegisterCustom(t *testing.T) {
	r := newTestResolver()

	before := r.Count()
	r.Register(OIDEntry{
		OID:         "1.3.6.1.4.1.99999.1.1",
		Name:        "customMetric",
		Module:      "CUSTOM-MIB",
		Description: "A custom metric",
		Category:    "custom",
	})

	if r.Count() != before+1 {
		t.Errorf("count after register: want %d, got %d", before+1, r.Count())
	}

	entry, found := r.Resolve("1.3.6.1.4.1.99999.1.1")
	if !found {
		t.Fatal("custom OID not found after register")
	}
	if entry.Name != "customMetric" {
		t.Errorf("custom name: want %q, got %q", "customMetric", entry.Name)
	}
}

func TestResolverGetOIDsForGroup(t *testing.T) {
	r := newTestResolver()

	tests := []struct {
		group   string
		minOIDs int
	}{
		{"system", 5},
		{"interfaces", 10},
		{"cpu_memory", 5},
		{"trap", 4},
		{"host", 5},
	}

	for _, tt := range tests {
		t.Run(tt.group, func(t *testing.T) {
			oids := r.GetOIDsForGroup(tt.group)
			if len(oids) < tt.minOIDs {
				t.Errorf("group %q: want >= %d OIDs, got %d", tt.group, tt.minOIDs, len(oids))
			}
		})
	}
}

func TestResolverListGroups(t *testing.T) {
	r := newTestResolver()
	groups := r.ListGroups()

	expectedGroups := map[string]bool{
		"system": true, "interfaces": true, "cpu_memory": true,
		"trap": true, "host": true, "ip": true,
	}

	for expected := range expectedGroups {
		found := false
		for _, g := range groups {
			if g == expected {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected group %q not found", expected)
		}
	}
}

func TestResolverCategoryField(t *testing.T) {
	r := newTestResolver()

	entry, found := r.Resolve("1.3.6.1.2.1.1.1")
	if !found {
		t.Fatal("sysDescr not found")
	}
	if entry.Category != "system" {
		t.Errorf("sysDescr category: want %q, got %q", "system", entry.Category)
	}

	entry, found = r.Resolve("1.3.6.1.2.1.2.2.1.8")
	if !found {
		t.Fatal("ifOperStatus not found")
	}
	if entry.Category != "interfaces" {
		t.Errorf("ifOperStatus category: want %q, got %q", "interfaces", entry.Category)
	}
}
