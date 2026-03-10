package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadValidConfig(t *testing.T) {
	content := `
server:
  name: "test-manager"
  log_level: "debug"
  log_format: "json"

poller:
  workers: 20
  default_interval: 30s
  timeout: 3s
  retries: 3
  max_oids_per_request: 10

trap_receiver:
  enabled: true
  listen_address: "0.0.0.0:1620"

devices:
  - name: "test-device"
    ip: "192.168.1.1"
    port: 161
    snmp_version: "v2c"
    community: "public"
    poll_interval: 60s
    oid_groups:
      - "system"
    tags:
      location: "test-lab"

pipeline:
  buffer_size: 5000
  batch_size: 50
  flush_interval: 3s
  workers: 2

outputs:
  - type: "stdout"
    enabled: true

api:
  enabled: true
  listen_address: "0.0.0.0:9080"

metrics:
  enabled: true
  listen_address: "0.0.0.0:9191"
  path: "/metrics"
`
	path := writeTemp(t, "config-valid.yaml", content)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	// Server
	if cfg.Server.Name != "test-manager" {
		t.Errorf("server name: want %q, got %q", "test-manager", cfg.Server.Name)
	}
	if cfg.Server.LogLevel != "debug" {
		t.Errorf("log level: want %q, got %q", "debug", cfg.Server.LogLevel)
	}

	// Poller
	if cfg.Poller.Workers != 20 {
		t.Errorf("poller workers: want 20, got %d", cfg.Poller.Workers)
	}
	if cfg.Poller.DefaultInterval != 30*time.Second {
		t.Errorf("default interval: want 30s, got %v", cfg.Poller.DefaultInterval)
	}
	if cfg.Poller.Timeout != 3*time.Second {
		t.Errorf("timeout: want 3s, got %v", cfg.Poller.Timeout)
	}
	if cfg.Poller.Retries != 3 {
		t.Errorf("retries: want 3, got %d", cfg.Poller.Retries)
	}

	// Devices
	if len(cfg.Devices) != 1 {
		t.Fatalf("devices: want 1, got %d", len(cfg.Devices))
	}
	dev := cfg.Devices[0]
	if dev.Name != "test-device" {
		t.Errorf("device name: want %q, got %q", "test-device", dev.Name)
	}
	if dev.IP != "192.168.1.1" {
		t.Errorf("device ip: want %q, got %q", "192.168.1.1", dev.IP)
	}
	if dev.Port != 161 {
		t.Errorf("device port: want 161, got %d", dev.Port)
	}
	if dev.Community != "public" {
		t.Errorf("device community: want %q, got %q", "public", dev.Community)
	}
	if dev.Tags["location"] != "test-lab" {
		t.Errorf("device tag location: want %q, got %q", "test-lab", dev.Tags["location"])
	}

	// Pipeline
	if cfg.Pipeline.BufferSize != 5000 {
		t.Errorf("buffer size: want 5000, got %d", cfg.Pipeline.BufferSize)
	}

	// API
	if cfg.API.ListenAddress != "0.0.0.0:9080" {
		t.Errorf("api address: want %q, got %q", "0.0.0.0:9080", cfg.API.ListenAddress)
	}
}

func TestLoadDefaults(t *testing.T) {
	content := `
devices:
  - name: "minimal-device"
    ip: "10.0.0.1"
    community: "public"
`
	path := writeTemp(t, "config-defaults.yaml", content)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	// Check defaults
	if cfg.Server.LogLevel != "info" {
		t.Errorf("default log level: want %q, got %q", "info", cfg.Server.LogLevel)
	}
	if cfg.Poller.Workers != 50 {
		t.Errorf("default workers: want 50, got %d", cfg.Poller.Workers)
	}
	if cfg.Poller.DefaultInterval != 60*time.Second {
		t.Errorf("default interval: want 60s, got %v", cfg.Poller.DefaultInterval)
	}
	if cfg.Poller.Timeout != 5*time.Second {
		t.Errorf("default timeout: want 5s, got %v", cfg.Poller.Timeout)
	}
	if cfg.Pipeline.BufferSize != 10000 {
		t.Errorf("default buffer size: want 10000, got %d", cfg.Pipeline.BufferSize)
	}
	if cfg.API.ListenAddress != "0.0.0.0:8080" {
		t.Errorf("default api address: want %q, got %q", "0.0.0.0:8080", cfg.API.ListenAddress)
	}

	// Device defaults
	dev := cfg.Devices[0]
	if dev.Port != 161 {
		t.Errorf("default device port: want 161, got %d", dev.Port)
	}
	if dev.SNMPVersion != "v2c" {
		t.Errorf("default snmp version: want %q, got %q", "v2c", dev.SNMPVersion)
	}
	if dev.Enabled == nil || !*dev.Enabled {
		t.Error("default device enabled: want true")
	}
}

func TestLoadEnvExpansion(t *testing.T) {
	os.Setenv("TEST_SNMP_COMMUNITY", "secret-community")
	defer os.Unsetenv("TEST_SNMP_COMMUNITY")

	content := `
devices:
  - name: "env-device"
    ip: "10.0.0.1"
    community: "${TEST_SNMP_COMMUNITY}"
`
	path := writeTemp(t, "config-env.yaml", content)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if cfg.Devices[0].Community != "secret-community" {
		t.Errorf("env expansion: want %q, got %q", "secret-community", cfg.Devices[0].Community)
	}
}

func TestValidationErrors(t *testing.T) {
	tests := []struct {
		name    string
		content string
		wantErr string
	}{
		{
			name: "invalid log level",
			content: `
server:
  log_level: "verbose"
devices:
  - name: "d1"
    ip: "1.1.1.1"
    community: "pub"
`,
			wantErr: "invalid log_level",
		},
		{
			name: "device missing ip",
			content: `
devices:
  - name: "d1"
    community: "pub"
`,
			wantErr: "ip is required",
		},
		{
			name: "device missing name",
			content: `
devices:
  - ip: "1.1.1.1"
    community: "pub"
`,
			wantErr: "name is required",
		},
		{
			name: "v3 without credentials",
			content: `
devices:
  - name: "d1"
    ip: "1.1.1.1"
    snmp_version: "v3"
`,
			wantErr: "v3 requires credentials",
		},
		{
			name: "v2c without community",
			content: `
devices:
  - name: "d1"
    ip: "1.1.1.1"
    snmp_version: "v2c"
`,
			wantErr: "requires community string",
		},
		{
			name: "invalid snmp version",
			content: `
devices:
  - name: "d1"
    ip: "1.1.1.1"
    snmp_version: "v4"
    community: "pub"
`,
			wantErr: "invalid snmp_version",
		},
		{
			name: "too many workers",
			content: `
poller:
  workers: 999
devices:
  - name: "d1"
    ip: "1.1.1.1"
    community: "pub"
`,
			wantErr: "exceeds maximum",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := writeTemp(t, "config-err.yaml", tt.content)
			_, err := Load(path)
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tt.wantErr)
			}
			if !contains(err.Error(), tt.wantErr) {
				t.Errorf("error %q does not contain %q", err.Error(), tt.wantErr)
			}
		})
	}
}

func TestLoadFileNotFound(t *testing.T) {
	_, err := Load("/nonexistent/config.yaml")
	if err == nil {
		t.Fatal("expected error for nonexistent file")
	}
}

func TestLoadInvalidYAML(t *testing.T) {
	content := `
server:
  name: [invalid yaml
`
	path := writeTemp(t, "config-invalid.yaml", content)
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for invalid YAML")
	}
}

func TestExpandEnvVars(t *testing.T) {
	os.Setenv("MY_VAR", "hello")
	defer os.Unsetenv("MY_VAR")

	tests := []struct {
		input string
		want  string
	}{
		{"${MY_VAR}", "hello"},
		{"prefix-${MY_VAR}-suffix", "prefix-hello-suffix"},
		{"${UNDEFINED_VAR}", ""},
		{"no-vars", "no-vars"},
	}

	for _, tt := range tests {
		got := expandEnvVars(tt.input)
		if got != tt.want {
			t.Errorf("expandEnvVars(%q): want %q, got %q", tt.input, tt.want, got)
		}
	}
}

func TestV3DeviceConfig(t *testing.T) {
	content := `
devices:
  - name: "v3-device"
    ip: "10.0.0.1"
    snmp_version: "v3"
    credentials:
      username: "admin"
      auth_protocol: "SHA256"
      auth_passphrase: "authpass"
      priv_protocol: "AES256"
      priv_passphrase: "privpass"
      context_name: "ctx1"
    oid_groups:
      - "system"
      - "interfaces"
`
	path := writeTemp(t, "config-v3.yaml", content)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	dev := cfg.Devices[0]
	if dev.Credentials == nil {
		t.Fatal("credentials should not be nil")
	}
	if dev.Credentials.Username != "admin" {
		t.Errorf("username: want %q, got %q", "admin", dev.Credentials.Username)
	}
	if dev.Credentials.AuthProtocol != "SHA256" {
		t.Errorf("auth protocol: want %q, got %q", "SHA256", dev.Credentials.AuthProtocol)
	}
	if dev.Credentials.ContextName != "ctx1" {
		t.Errorf("context name: want %q, got %q", "ctx1", dev.Credentials.ContextName)
	}
	if len(dev.OIDGroups) != 2 {
		t.Errorf("oid groups: want 2, got %d", len(dev.OIDGroups))
	}
}

func TestMultipleOutputs(t *testing.T) {
	content := `
devices:
  - name: "d1"
    ip: "1.1.1.1"
    community: "pub"
outputs:
  - type: "stdout"
    enabled: true
  - type: "file"
    enabled: true
    path: "/tmp/test.log"
  - type: "syslog"
    enabled: false
    address: "siem:514"
    protocol: "tcp"
    format: "cef"
`
	path := writeTemp(t, "config-outputs.yaml", content)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if len(cfg.Outputs) != 3 {
		t.Fatalf("outputs: want 3, got %d", len(cfg.Outputs))
	}
	if cfg.Outputs[0].Type != "stdout" {
		t.Errorf("output 0 type: want stdout, got %s", cfg.Outputs[0].Type)
	}
	if cfg.Outputs[1].Path != "/tmp/test.log" {
		t.Errorf("output 1 path: want /tmp/test.log, got %s", cfg.Outputs[1].Path)
	}
	if cfg.Outputs[2].Enabled {
		t.Error("output 2 should be disabled")
	}
}

// ── helpers ──────────────────────────────────────────────────────

func writeTemp(t *testing.T, name, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("write temp file: %v", err)
	}
	return path
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && searchStr(s, substr)
}

func searchStr(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
