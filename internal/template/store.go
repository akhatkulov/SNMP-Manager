package template

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
)

// Template represents an SNMP monitoring template (Zabbix-style).
type Template struct {
	ID              string            `json:"id"`
	Name            string            `json:"name"`
	Description     string            `json:"description"`
	Category        string            `json:"category"` // router, switch, server, printer, firewall, ap, generic
	Vendor          string            `json:"vendor"`
	Builtin         bool              `json:"builtin"`
	OIDGroups       []string          `json:"oid_groups"`
	Items           []TemplateItem    `json:"items"`
	DefaultTags     map[string]string `json:"default_tags"`
	DefaultInterval string            `json:"default_interval"`
}

// TemplateItem represents a single monitorable OID within a template.
type TemplateItem struct {
	OID         string `json:"oid"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Type        string `json:"type"`     // OctetString, Integer, Counter32, etc.
	Category    string `json:"category"` // system, interfaces, cpu, memory, etc.
}

// Store manages SNMP templates in memory with JSON file persistence.
type Store struct {
	mu              sync.RWMutex
	templates       map[string]*Template
	customFile      string
}

// NewStore creates a template store, loading built-in and custom templates.
func NewStore(builtinPath, customPath string) (*Store, error) {
	s := &Store{
		templates:  make(map[string]*Template),
		customFile: customPath,
	}

	// Load built-in templates
	if builtinPath != "" {
		if err := s.loadFromFile(builtinPath, true); err != nil {
			return nil, fmt.Errorf("loading built-in templates: %w", err)
		}
	}

	// Load custom templates (if file exists)
	if customPath != "" {
		if _, err := os.Stat(customPath); err == nil {
			if err := s.loadFromFile(customPath, false); err != nil {
				return nil, fmt.Errorf("loading custom templates: %w", err)
			}
		}
	}

	return s, nil
}

// loadFromFile loads templates from a JSON file.
func (s *Store) loadFromFile(path string, builtin bool) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("reading %s: %w", path, err)
	}

	var templates []Template
	if err := json.Unmarshal(data, &templates); err != nil {
		return fmt.Errorf("parsing %s: %w", path, err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	for i := range templates {
		t := &templates[i]
		t.Builtin = builtin
		s.templates[t.ID] = t
	}

	return nil
}

// List returns all templates.
func (s *Store) List() []*Template {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]*Template, 0, len(s.templates))
	for _, t := range s.templates {
		result = append(result, t)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	return result
}

// Get returns a template by ID.
func (s *Store) Get(id string) (*Template, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	t, ok := s.templates[id]
	return t, ok
}

// Add adds a new custom template.
func (s *Store) Add(t *Template) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.templates[t.ID]; exists {
		return fmt.Errorf("template %q already exists", t.ID)
	}

	t.Builtin = false
	s.templates[t.ID] = t

	return s.saveCustom()
}

// Update updates an existing custom template.
func (s *Store) Update(id string, t *Template) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	existing, ok := s.templates[id]
	if !ok {
		return fmt.Errorf("template %q not found", id)
	}
	if existing.Builtin {
		return fmt.Errorf("cannot modify built-in template %q", id)
	}

	t.ID = id
	t.Builtin = false
	s.templates[id] = t

	return s.saveCustom()
}

// Delete removes a custom template.
func (s *Store) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	t, ok := s.templates[id]
	if !ok {
		return fmt.Errorf("template %q not found", id)
	}
	if t.Builtin {
		return fmt.Errorf("cannot delete built-in template %q", id)
	}

	delete(s.templates, id)
	return s.saveCustom()
}

// saveCustom persists all custom templates to the custom file.
func (s *Store) saveCustom() error {
	if s.customFile == "" {
		return nil
	}

	var custom []Template
	for _, t := range s.templates {
		if !t.Builtin {
			custom = append(custom, *t)
		}
	}

	// If no custom templates, remove the file
	if len(custom) == 0 {
		os.Remove(s.customFile)
		return nil
	}

	// Ensure directory exists
	dir := filepath.Dir(s.customFile)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("creating directory %s: %w", dir, err)
	}

	data, err := json.MarshalIndent(custom, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling custom templates: %w", err)
	}

	if err := os.WriteFile(s.customFile, data, 0644); err != nil {
		return fmt.Errorf("writing %s: %w", s.customFile, err)
	}

	return nil
}

// Count returns the number of templates.
func (s *Store) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.templates)
}

// GetByCategory returns all templates matching a specific category.
func (s *Store) GetByCategory(category string) []*Template {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var result []*Template
	for _, t := range s.templates {
		if t.Category == category {
			result = append(result, t)
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	return result
}
