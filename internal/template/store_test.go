package template

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadBuiltinTemplates(t *testing.T) {
	// Find the project root by looking for go.mod
	dir, _ := os.Getwd()
	for dir != "/" {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			break
		}
		dir = filepath.Dir(dir)
	}

	builtinPath := filepath.Join(dir, "configs", "templates", "builtin_templates.json")
	if _, err := os.Stat(builtinPath); os.IsNotExist(err) {
		t.Skip("builtin_templates.json not found at", builtinPath)
	}

	store, err := NewStore(builtinPath, "")
	if err != nil {
		t.Fatal("Failed to load templates:", err)
	}

	if store.Count() == 0 {
		t.Fatal("Expected templates, got 0")
	}

	t.Logf("Loaded %d templates:", store.Count())
	for _, tmpl := range store.List() {
		t.Logf("  [%s] %s (%s) - %d items, groups: %v", tmpl.ID, tmpl.Name, tmpl.Category, len(tmpl.Items), tmpl.OIDGroups)
	}

	// Test Get
	tmpl, ok := store.Get("generic-snmp")
	if !ok {
		t.Fatal("generic-snmp template not found")
	}
	if tmpl.Name != "Generic SNMP Device" {
		t.Errorf("expected 'Generic SNMP Device', got %q", tmpl.Name)
	}
	if len(tmpl.Items) != 12 {
		t.Errorf("expected 12 items, got %d", len(tmpl.Items))
	}
	if !tmpl.Builtin {
		t.Error("expected builtin=true")
	}

	// Test GetByCategory
	routers := store.GetByCategory("router")
	if len(routers) < 2 {
		t.Errorf("expected >= 2 router templates, got %d", len(routers))
	}

	// Test sorting (List should be sorted by ID)
	list := store.List()
	for i := 1; i < len(list); i++ {
		if list[i].ID < list[i-1].ID {
			t.Errorf("templates not sorted: %s came after %s", list[i].ID, list[i-1].ID)
		}
	}
}
