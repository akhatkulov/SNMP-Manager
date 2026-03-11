package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// ManagedOutputsFile returns the path to the managed outputs JSON file,
// derived from the main config file path.
func ManagedOutputsFile(configPath string) string {
	dir := filepath.Dir(configPath)
	return filepath.Join(dir, "managed-outputs.json")
}

// SaveOutputs persists the output configurations to a JSON file.
func SaveOutputs(configPath string, outputs []OutputConfig) error {
	path := ManagedOutputsFile(configPath)
	data, err := json.MarshalIndent(outputs, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling outputs: %w", err)
	}
	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("writing outputs file %s: %w", path, err)
	}
	return nil
}

// LoadManagedOutputs reads the managed outputs JSON file if it exists.
// Returns nil if the file does not exist.
func LoadManagedOutputs(configPath string) ([]OutputConfig, error) {
	path := ManagedOutputsFile(configPath)
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("reading outputs file %s: %w", path, err)
	}
	var outputs []OutputConfig
	if err := json.Unmarshal(data, &outputs); err != nil {
		return nil, fmt.Errorf("parsing outputs file %s: %w", path, err)
	}
	return outputs, nil
}

// Config is the root configuration structure for the SNMP Manager.
type Config struct {
	Server       ServerConfig       `yaml:"server"`
	Poller       PollerConfig       `yaml:"poller"`
	TrapReceiver TrapReceiverConfig `yaml:"trap_receiver"`
	Devices      []DeviceConfig     `yaml:"devices"`
	Pipeline     PipelineConfig     `yaml:"pipeline"`
	Outputs      []OutputConfig     `yaml:"outputs"`
	API          APIConfig          `yaml:"api"`
	Metrics      MetricsConfig      `yaml:"metrics"`
	MIB          MIBConfig          `yaml:"mib"`
}

// ServerConfig holds general server settings.
type ServerConfig struct {
	Name      string `yaml:"name"`
	LogLevel  string `yaml:"log_level"`
	LogFormat string `yaml:"log_format"`
}

// PollerConfig controls SNMP polling behavior.
type PollerConfig struct {
	Workers            int           `yaml:"workers"`
	DefaultInterval    time.Duration `yaml:"default_interval"`
	Timeout            time.Duration `yaml:"timeout"`
	Retries            int           `yaml:"retries"`
	MaxOIDsPerRequest  int           `yaml:"max_oids_per_request"`
}

// TrapReceiverConfig controls the SNMP trap listener.
type TrapReceiverConfig struct {
	Enabled       bool         `yaml:"enabled"`
	ListenAddress string       `yaml:"listen_address"`
	V3Users       []V3User     `yaml:"v3_users"`
}

// V3User represents an SNMPv3 user for trap authentication.
type V3User struct {
	Username       string `yaml:"username"`
	AuthProtocol   string `yaml:"auth_protocol"`
	AuthPassphrase string `yaml:"auth_passphrase"`
	PrivProtocol   string `yaml:"priv_protocol"`
	PrivPassphrase string `yaml:"priv_passphrase"`
}

// DeviceConfig defines a single SNMP-managed device.
type DeviceConfig struct {
	Name         string            `yaml:"name"`
	IP           string            `yaml:"ip"`
	Port         int               `yaml:"port"`
	SNMPVersion  string            `yaml:"snmp_version"`
	Community    string            `yaml:"community"`
	PollInterval time.Duration     `yaml:"poll_interval"`
	Credentials  *V3Credentials    `yaml:"credentials"`
	OIDGroups    []string          `yaml:"oid_groups"`
	Tags         map[string]string `yaml:"tags"`
	Enabled      *bool             `yaml:"enabled"`
}

// V3Credentials holds SNMPv3 authentication and privacy parameters.
type V3Credentials struct {
	Username       string `yaml:"username"`
	AuthProtocol   string `yaml:"auth_protocol"`
	AuthPassphrase string `yaml:"auth_passphrase"`
	PrivProtocol   string `yaml:"priv_protocol"`
	PrivPassphrase string `yaml:"priv_passphrase"`
	ContextName    string `yaml:"context_name"`
}

// PipelineConfig controls the event processing pipeline.
type PipelineConfig struct {
	BufferSize    int               `yaml:"buffer_size"`
	BatchSize     int               `yaml:"batch_size"`
	FlushInterval time.Duration     `yaml:"flush_interval"`
	Workers       int               `yaml:"workers"`
	Normalizer    NormalizerConfig  `yaml:"normalizer"`
	Enricher      EnricherConfig    `yaml:"enricher"`
	Filters       []FilterConfig    `yaml:"filters"`
}

// NormalizerConfig controls OID and hostname resolution.
type NormalizerConfig struct {
	ResolveOIDNames  bool `yaml:"resolve_oid_names"`
	ResolveHostnames bool `yaml:"resolve_hostnames"`
}

// EnricherConfig controls event enrichment sources.
type EnricherConfig struct {
	GeoIPDB string `yaml:"geoip_db"`
	AssetDB string `yaml:"asset_db"`
}

// FilterConfig defines a single event filter rule.
type FilterConfig struct {
	Type      string `yaml:"type"`
	Condition string `yaml:"condition"`
	MaxEvents int    `yaml:"max_events_per_minute,omitempty"`
}

// OutputConfig defines a single output destination.
type OutputConfig struct {
	Type     string            `yaml:"type"`
	Enabled  bool              `yaml:"enabled"`
	Address  string            `yaml:"address,omitempty"`
	Protocol string            `yaml:"protocol,omitempty"`
	Format   string            `yaml:"format,omitempty"`
	TLS      *TLSConfig        `yaml:"tls,omitempty"`
	Brokers  []string          `yaml:"brokers,omitempty"`
	Topic    string            `yaml:"topic,omitempty"`
	Path     string            `yaml:"path,omitempty"`
	MaxSizeMB int             `yaml:"max_size_mb,omitempty"`
	MaxBackups int            `yaml:"max_backups,omitempty"`
	Compress  bool            `yaml:"compress,omitempty"`
	Headers   map[string]string `yaml:"headers,omitempty"`

	// HTTP output (Logstash HTTP input, webhooks)
	URL           string `yaml:"url,omitempty"`
	TLSSkipVerify bool   `yaml:"tls_skip_verify,omitempty"`

	// Elasticsearch output
	Addresses []string `yaml:"addresses,omitempty"`
	Index     string   `yaml:"index,omitempty"`
	Username  string   `yaml:"username,omitempty"`
	Password  string   `yaml:"password,omitempty"`
}

// TLSConfig holds TLS certificate paths.
type TLSConfig struct {
	Enabled  bool   `yaml:"enabled"`
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`
	CAFile   string `yaml:"ca_file"`
}

// APIConfig controls the REST API server.
type APIConfig struct {
	Enabled       bool           `yaml:"enabled"`
	ListenAddress string         `yaml:"listen_address"`
	Auth          AuthConfig     `yaml:"auth"`
	AdminPanel    AdminPanelConfig `yaml:"admin_panel"`
}

// AuthConfig holds API authentication settings.
type AuthConfig struct {
	Type string   `yaml:"type"`
	Keys []string `yaml:"keys"`
}

// AdminPanelConfig holds admin panel login credentials.
type AdminPanelConfig struct {
	Username string `yaml:"username"`
	Password string `yaml:"password"`
}

// MetricsConfig controls Prometheus metrics exposure.
type MetricsConfig struct {
	Enabled       bool   `yaml:"enabled"`
	ListenAddress string `yaml:"listen_address"`
	Path          string `yaml:"path"`
}

// MIBConfig controls MIB file loading.
type MIBConfig struct {
	Directories    []string `yaml:"directories"`
	LoadSystemMIBs bool     `yaml:"load_system_mibs"`
}

// Load reads a YAML configuration file and returns a validated Config.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config file %s: %w", path, err)
	}

	// Expand environment variables in the config
	expanded := expandEnvVars(string(data))

	cfg := &Config{}
	if err := yaml.Unmarshal([]byte(expanded), cfg); err != nil {
		return nil, fmt.Errorf("parsing config file %s: %w", path, err)
	}

	applyDefaults(cfg)

	if err := validate(cfg); err != nil {
		return nil, fmt.Errorf("validating config: %w", err)
	}

	return cfg, nil
}

// expandEnvVars replaces ${VAR} and $VAR patterns with environment variable values.
func expandEnvVars(s string) string {
	return os.Expand(s, func(key string) string {
		if val, ok := os.LookupEnv(key); ok {
			return val
		}
		return ""
	})
}

// applyDefaults sets default values for unspecified configuration fields.
func applyDefaults(cfg *Config) {
	if cfg.Server.Name == "" {
		hostname, _ := os.Hostname()
		cfg.Server.Name = "snmp-manager-" + hostname
	}
	if cfg.Server.LogLevel == "" {
		cfg.Server.LogLevel = "info"
	}
	if cfg.Server.LogFormat == "" {
		cfg.Server.LogFormat = "json"
	}

	if cfg.Poller.Workers <= 0 {
		cfg.Poller.Workers = 50
	}
	if cfg.Poller.DefaultInterval <= 0 {
		cfg.Poller.DefaultInterval = 60 * time.Second
	}
	if cfg.Poller.Timeout <= 0 {
		cfg.Poller.Timeout = 5 * time.Second
	}
	if cfg.Poller.Retries <= 0 {
		cfg.Poller.Retries = 2
	}
	if cfg.Poller.MaxOIDsPerRequest <= 0 {
		cfg.Poller.MaxOIDsPerRequest = 20
	}

	if cfg.TrapReceiver.ListenAddress == "" {
		cfg.TrapReceiver.ListenAddress = "0.0.0.0:162"
	}

	if cfg.Pipeline.BufferSize <= 0 {
		cfg.Pipeline.BufferSize = 10000
	}
	if cfg.Pipeline.BatchSize <= 0 {
		cfg.Pipeline.BatchSize = 100
	}
	if cfg.Pipeline.FlushInterval <= 0 {
		cfg.Pipeline.FlushInterval = 5 * time.Second
	}
	if cfg.Pipeline.Workers <= 0 {
		cfg.Pipeline.Workers = 4
	}

	if cfg.API.ListenAddress == "" {
		cfg.API.ListenAddress = "0.0.0.0:8080"
	}
	if cfg.Metrics.ListenAddress == "" {
		cfg.Metrics.ListenAddress = "0.0.0.0:9090"
	}
	if cfg.Metrics.Path == "" {
		cfg.Metrics.Path = "/metrics"
	}

	// Set default port for devices
	for i := range cfg.Devices {
		if cfg.Devices[i].Port <= 0 {
			cfg.Devices[i].Port = 161
		}
		if cfg.Devices[i].PollInterval <= 0 {
			cfg.Devices[i].PollInterval = cfg.Poller.DefaultInterval
		}
		if cfg.Devices[i].Enabled == nil {
			enabled := true
			cfg.Devices[i].Enabled = &enabled
		}
		if cfg.Devices[i].SNMPVersion == "" {
			cfg.Devices[i].SNMPVersion = "v2c"
		}
	}

	if len(cfg.MIB.Directories) == 0 {
		cfg.MIB.Directories = []string{"/var/lib/snmp-manager/mibs", "./internal/mib/mibs"}
	}
}

// validate checks that the configuration is valid and complete.
func validate(cfg *Config) error {
	validLogLevels := map[string]bool{"debug": true, "info": true, "warn": true, "error": true}
	if !validLogLevels[strings.ToLower(cfg.Server.LogLevel)] {
		return fmt.Errorf("invalid log_level: %q (must be debug, info, warn, or error)", cfg.Server.LogLevel)
	}

	if cfg.Poller.Workers > 500 {
		return fmt.Errorf("poller workers %d exceeds maximum of 500", cfg.Poller.Workers)
	}

	for i, dev := range cfg.Devices {
		if dev.IP == "" {
			return fmt.Errorf("device #%d: ip is required", i+1)
		}
		if dev.Name == "" {
			return fmt.Errorf("device #%d (%s): name is required", i+1, dev.IP)
		}
		version := strings.ToLower(dev.SNMPVersion)
		if version != "v1" && version != "v2c" && version != "v3" {
			return fmt.Errorf("device %q: invalid snmp_version %q", dev.Name, dev.SNMPVersion)
		}
		if version == "v3" && dev.Credentials == nil {
			return fmt.Errorf("device %q: v3 requires credentials", dev.Name)
		}
		if (version == "v1" || version == "v2c") && dev.Community == "" {
			return fmt.Errorf("device %q: %s requires community string", dev.Name, version)
		}
	}

	for i, out := range cfg.Outputs {
		if !out.Enabled {
			continue
		}
		validTypes := map[string]bool{"syslog": true, "kafka": true, "http": true, "file": true, "stdout": true, "tcp": true, "elasticsearch": true}
		if !validTypes[out.Type] {
			return fmt.Errorf("output #%d: invalid type %q", i+1, out.Type)
		}
	}

	return nil
}
