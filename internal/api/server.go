package api

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/rs/zerolog"

	"github.com/me262/snmp-manager/internal/config"
	"github.com/me262/snmp-manager/internal/device"
	"github.com/me262/snmp-manager/internal/mib"
	"github.com/me262/snmp-manager/internal/pipeline"
	"github.com/me262/snmp-manager/internal/poller"
	"github.com/me262/snmp-manager/internal/trap"
)

// Server provides a REST API for managing and monitoring the SNMP Manager.
type Server struct {
	log           zerolog.Logger
	cfg           config.APIConfig
	registry      *device.Registry
	resolver      *mib.Resolver
	poller        *poller.Poller
	trap          *trap.Listener
	pipe          *pipeline.Pipeline
	server        *http.Server
	startTime     time.Time
	outputConfigs []config.OutputConfig
}

// NewServer creates a new API server.
func NewServer(
	log zerolog.Logger,
	cfg config.APIConfig,
	registry *device.Registry,
	resolver *mib.Resolver,
	poll *poller.Poller,
	trapListener *trap.Listener,
	pipe *pipeline.Pipeline,
	outputConfigs []config.OutputConfig,
) *Server {
	return &Server{
		log:           log.With().Str("component", "api").Logger(),
		cfg:           cfg,
		registry:      registry,
		resolver:      resolver,
		poller:        poll,
		trap:          trapListener,
		pipe:          pipe,
		startTime:     time.Now(),
		outputConfigs: outputConfigs,
	}
}

// Run starts the API server. Blocks until context is cancelled.
func (s *Server) Run(ctx context.Context) error {
	if !s.cfg.Enabled {
		s.log.Info().Msg("API server is disabled")
		return nil
	}

	mux := http.NewServeMux()

	// Register routes
	mux.HandleFunc("GET /api/v1/health", s.handleHealth)
	mux.HandleFunc("GET /api/v1/stats", s.withAuth(s.handleStats))
	mux.HandleFunc("GET /api/v1/devices", s.withAuth(s.handleListDevices))
	mux.HandleFunc("GET /api/v1/devices/{name}", s.withAuth(s.handleGetDevice))
	mux.HandleFunc("POST /api/v1/devices/{name}/poll", s.withAuth(s.handlePollDevice))
	mux.HandleFunc("POST /api/v1/devices", s.withAuth(s.handleAddDevice))
	mux.HandleFunc("PUT /api/v1/devices/{name}", s.withAuth(s.handleUpdateDevice))
	mux.HandleFunc("DELETE /api/v1/devices/{name}", s.withAuth(s.handleDeleteDevice))
	mux.HandleFunc("GET /api/v1/mibs/groups", s.withAuth(s.handleListMIBGroups))
	mux.HandleFunc("GET /api/v1/mibs/resolve/{oid}", s.withAuth(s.handleResolveOID))
	mux.HandleFunc("GET /api/v1/mibs/count", s.withAuth(s.handleMIBCount))
	mux.HandleFunc("GET /api/v1/pipeline/stats", s.withAuth(s.handlePipelineStats))
	mux.HandleFunc("GET /api/v1/poller/progress", s.withAuth(s.handlePollerProgress))
	mux.HandleFunc("GET /api/v1/logs/recent", s.withAuth(s.handleRecentLogs))
	mux.HandleFunc("GET /api/v1/config/outputs", s.withAuth(s.handleGetOutputs))

	// Admin panel auth (no API key required)
	mux.HandleFunc("POST /api/v1/auth/login", s.handleLogin)

	// Serve admin panel static files
	webDir := "./web"
	if _, err := os.Stat(webDir); err == nil {
		fs := http.FileServer(http.Dir(webDir))
		mux.Handle("/", fs)
		s.log.Info().Str("dir", webDir).Msg("admin panel enabled")
	} else {
		s.log.Warn().Msg("web/ directory not found, admin panel disabled")
	}

	// Wrap with logging middleware
	handler := s.loggingMiddleware(s.corsMiddleware(mux))

	s.server = &http.Server{
		Addr:         s.cfg.ListenAddress,
		Handler:      handler,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	s.log.Info().Str("address", s.cfg.ListenAddress).Msg("API server starting")

	errCh := make(chan error, 1)
	go func() {
		errCh <- s.server.ListenAndServe()
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		s.log.Info().Msg("API server shutting down")
		return s.server.Shutdown(shutdownCtx)
	case err := <-errCh:
		if err != http.ErrServerClosed {
			return fmt.Errorf("API server error: %w", err)
		}
		return nil
	}
}

// ── Handlers ──────────────────────────────────────────────────────────

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	stats := s.registry.Stats()
	status := "healthy"
	if stats.Total > 0 && stats.Up == 0 {
		status = "degraded"
	}

	s.writeJSON(w, http.StatusOK, map[string]any{
		"status":  status,
		"uptime":  time.Since(s.startTime).String(),
		"devices": stats,
	})
}

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	var pollerStats poller.PollerStats
	if s.poller != nil {
		pollerStats = s.poller.Stats()
	}
	var trapStats trap.TrapStats
	if s.trap != nil {
		trapStats = s.trap.Stats()
	}
	var pipeStats pipeline.PipelineStats
	if s.pipe != nil {
		pipeStats = s.pipe.Stats()
	}

	s.writeJSON(w, http.StatusOK, map[string]any{
		"uptime":   time.Since(s.startTime).String(),
		"devices":  s.registry.Stats(),
		"poller":   pollerStats,
		"traps":    trapStats,
		"pipeline": pipeStats,
	})
}

func (s *Server) handleListDevices(w http.ResponseWriter, r *http.Request) {
	devices := s.registry.List()

	type deviceSummary struct {
		Name       string        `json:"name"`
		IP         string        `json:"ip"`
		Version    string        `json:"snmp_version"`
		Status     device.Status `json:"status"`
		Enabled    bool          `json:"enabled"`
		DeviceType string        `json:"device_type,omitempty"`
		Vendor     string        `json:"vendor,omitempty"`
		LastPoll   time.Time     `json:"last_poll,omitempty"`
		PollCount  int64         `json:"poll_count"`
		TrapCount  int64         `json:"trap_count"`
		ErrorCount int64         `json:"error_count"`
	}

	summaries := make([]deviceSummary, 0, len(devices))
	for _, d := range devices {
		summaries = append(summaries, deviceSummary{
			Name:       d.Name,
			IP:         d.IP,
			Version:    d.SNMPVersion,
			Status:     d.GetStatus(),
			Enabled:    d.Enabled,
			DeviceType: d.DeviceType,
			Vendor:     d.Vendor,
			LastPoll:   d.LastPoll,
			PollCount:  d.PollCount,
			TrapCount:  d.TrapCount,
			ErrorCount: d.ErrorCount,
		})
	}

	s.writeJSON(w, http.StatusOK, map[string]any{
		"count":   len(summaries),
		"devices": summaries,
	})
}

func (s *Server) handleGetDevice(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	dev, ok := s.registry.Get(name)
	if !ok {
		s.writeJSON(w, http.StatusNotFound, map[string]string{"error": "device not found"})
		return
	}
	s.writeJSON(w, http.StatusOK, dev)
}

// addDeviceRequest represents the JSON body for adding a new device.
type addDeviceRequest struct {
	Name         string            `json:"name"`
	IP           string            `json:"ip"`
	Port         int               `json:"port"`
	SNMPVersion  string            `json:"snmp_version"`
	Community    string            `json:"community"`
	PollInterval string            `json:"poll_interval"`
	OIDGroups    []string          `json:"oid_groups"`
	Tags         map[string]string `json:"tags"`
	Enabled      *bool             `json:"enabled"`
	Credentials  *config.V3Credentials `json:"credentials,omitempty"`
}

func (s *Server) handleAddDevice(w http.ResponseWriter, r *http.Request) {
	var req addDeviceRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON: " + err.Error()})
		return
	}

	// Validate required fields
	if req.Name == "" {
		s.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "name is required"})
		return
	}
	if req.IP == "" {
		s.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "ip is required"})
		return
	}

	// Defaults
	if req.Port <= 0 {
		req.Port = 161
	}
	if req.SNMPVersion == "" {
		req.SNMPVersion = "v2c"
	}
	version := strings.ToLower(req.SNMPVersion)
	if version != "v1" && version != "v2c" && version != "v3" {
		s.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid snmp_version (must be v1, v2c, or v3)"})
		return
	}
	if (version == "v1" || version == "v2c") && req.Community == "" {
		s.writeJSON(w, http.StatusBadRequest, map[string]string{"error": version + " requires community string"})
		return
	}
	if version == "v3" && req.Credentials == nil {
		s.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "v3 requires credentials"})
		return
	}

	pollInterval := 60 * time.Second
	if req.PollInterval != "" {
		parsed, err := time.ParseDuration(req.PollInterval)
		if err != nil {
			s.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid poll_interval: " + err.Error()})
			return
		}
		pollInterval = parsed
	}

	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}

	oidGroups := req.OIDGroups
	if len(oidGroups) == 0 {
		oidGroups = []string{"system"}
	}

	dev := &device.Device{
		Name:         req.Name,
		IP:           req.IP,
		Port:         req.Port,
		SNMPVersion:  req.SNMPVersion,
		Community:    req.Community,
		Credentials:  req.Credentials,
		OIDGroups:    oidGroups,
		Tags:         req.Tags,
		Enabled:      enabled,
		PollInterval: pollInterval,
		Status:       device.StatusUnknown,
	}

	if err := s.registry.Add(dev); err != nil {
		s.writeJSON(w, http.StatusConflict, map[string]string{"error": err.Error()})
		return
	}

	s.log.Info().
		Str("name", dev.Name).
		Str("ip", dev.IP).
		Str("version", dev.SNMPVersion).
		Msg("device added via API")

	s.writeJSON(w, http.StatusCreated, map[string]any{
		"message": "device added successfully",
		"device":  dev.Name,
		"ip":      dev.IP,
	})
}

func (s *Server) handleUpdateDevice(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	existing, ok := s.registry.Get(name)
	if !ok {
		s.writeJSON(w, http.StatusNotFound, map[string]string{"error": "device not found"})
		return
	}

	var req addDeviceRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON: " + err.Error()})
		return
	}

	// Update fields if provided
	if req.IP != "" {
		existing.IP = req.IP
	}
	if req.Port > 0 {
		existing.Port = req.Port
	}
	if req.SNMPVersion != "" {
		existing.SNMPVersion = req.SNMPVersion
	}
	if req.Community != "" {
		existing.Community = req.Community
	}
	if req.PollInterval != "" {
		parsed, err := time.ParseDuration(req.PollInterval)
		if err != nil {
			s.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid poll_interval: " + err.Error()})
			return
		}
		existing.PollInterval = parsed
	}
	if len(req.OIDGroups) > 0 {
		existing.OIDGroups = req.OIDGroups
	}
	if req.Tags != nil {
		existing.Tags = req.Tags
	}
	if req.Enabled != nil {
		existing.Enabled = *req.Enabled
	}
	if req.Credentials != nil {
		existing.Credentials = req.Credentials
	}

	s.log.Info().Str("name", name).Msg("device updated via API")
	s.writeJSON(w, http.StatusOK, map[string]any{
		"message": "device updated successfully",
		"device":  name,
	})
}

func (s *Server) handleDeleteDevice(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if err := s.registry.Remove(name); err != nil {
		s.writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
		return
	}

	s.log.Info().Str("name", name).Msg("device removed via API")
	s.writeJSON(w, http.StatusOK, map[string]any{
		"message": "device removed successfully",
		"device":  name,
	})
}

func (s *Server) handlePollDevice(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	dev, ok := s.registry.Get(name)
	if !ok {
		s.writeJSON(w, http.StatusNotFound, map[string]string{"error": "device not found"})
		return
	}

	events, err := s.poller.PollDevice(r.Context(), dev)
	if err != nil {
		s.writeJSON(w, http.StatusInternalServerError, map[string]string{
			"error": err.Error(),
		})
		return
	}

	s.writeJSON(w, http.StatusOK, map[string]any{
		"device": dev.Name,
		"events": len(events),
		"data":   events,
	})
}

func (s *Server) handleListMIBGroups(w http.ResponseWriter, r *http.Request) {
	groups := s.resolver.ListGroups()
	result := make(map[string]int)
	for _, g := range groups {
		oids := s.resolver.GetOIDsForGroup(g)
		result[g] = len(oids)
	}
	s.writeJSON(w, http.StatusOK, map[string]any{
		"groups": result,
	})
}

func (s *Server) handleResolveOID(w http.ResponseWriter, r *http.Request) {
	oid := r.PathValue("oid")
	entry, found := s.resolver.Resolve(oid)
	if !found {
		s.writeJSON(w, http.StatusNotFound, map[string]string{
			"error": "OID not found in MIB database",
			"oid":   oid,
		})
		return
	}
	s.writeJSON(w, http.StatusOK, entry)
}

func (s *Server) handleMIBCount(w http.ResponseWriter, r *http.Request) {
	s.writeJSON(w, http.StatusOK, map[string]int{
		"total_oids": s.resolver.Count(),
	})
}

// ── Middleware ─────────────────────────────────────────────────────────

func (s *Server) withAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if len(s.cfg.Auth.Keys) == 0 {
			next(w, r)
			return
		}

		key := r.Header.Get("X-API-Key")
		if key == "" {
			key = r.URL.Query().Get("api_key")
		}

		for _, validKey := range s.cfg.Auth.Keys {
			if key == validKey {
				next(w, r)
				return
			}
		}

		s.writeJSON(w, http.StatusUnauthorized, map[string]string{
			"error": "invalid or missing API key",
		})
	}
}

func (s *Server) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		wrapped := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(wrapped, r)

		s.log.Info().
			Str("method", r.Method).
			Str("path", r.URL.Path).
			Int("status", wrapped.status).
			Dur("duration", time.Since(start)).
			Str("remote", r.RemoteAddr).
			Msg("api request")
	})
}

func (s *Server) corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, X-API-Key")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// ── Helpers ───────────────────────────────────────────────────────────

func (s *Server) writeJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		s.log.Error().Err(err).Msg("failed to write JSON response")
	}
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(status int) {
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

// Ensure statusWriter also satisfies http.Flusher if the underlying writer does.
func (w *statusWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Unused but keeps the import from erroring if strings is used elsewhere.
var _ = strings.TrimSpace

// handleLogin authenticates admin panel users.
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request"})
		return
	}

	cfgUser := s.cfg.AdminPanel.Username
	cfgPass := s.cfg.AdminPanel.Password

	if cfgUser == "" || cfgPass == "" {
		// No admin panel credentials configured — use API key auth
		s.writeJSON(w, http.StatusOK, map[string]interface{}{
			"mode": "api_key",
			"message": "no admin credentials configured, use API key",
		})
		return
	}

	if req.Username != cfgUser || req.Password != cfgPass {
		s.writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid credentials"})
		return
	}

	// Return a session token (the API key itself for simplicity)
	apiKey := ""
	if len(s.cfg.Auth.Keys) > 0 {
		apiKey = s.cfg.Auth.Keys[0]
	}

	s.writeJSON(w, http.StatusOK, map[string]interface{}{
		"token":   apiKey,
		"message": "login successful",
	})
}

// handlePipelineStats returns pipeline processing statistics.
func (s *Server) handlePipelineStats(w http.ResponseWriter, r *http.Request) {
	stats := s.pipe.Stats()
	s.writeJSON(w, http.StatusOK, stats)
}

// handlePollerProgress returns real-time poll progress for all devices.
func (s *Server) handlePollerProgress(w http.ResponseWriter, r *http.Request) {
	progress := s.poller.GetProgress()
	s.writeJSON(w, http.StatusOK, map[string]interface{}{
		"progress": progress,
	})
}

// handleRecentLogs returns the last N lines from the log file, enriched with
// human-readable OID translations from the MIB resolver.
func (s *Server) handleRecentLogs(w http.ResponseWriter, r *http.Request) {
	// Find log path from configured outputs
	logPath := "logs/snmp-events.log" // default fallback
	for _, o := range s.outputConfigs {
		if o.Type == "file" && o.Enabled && o.Path != "" {
			logPath = o.Path
			break
		}
	}
	limit := 50

	file, err := os.Open(logPath)
	if err != nil {
		s.writeJSON(w, http.StatusOK, map[string]interface{}{
			"logs":  []map[string]interface{}{},
			"total": 0,
			"error": "log file not found",
		})
		return
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024) // 1MB buffer per line
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}

	// Get last N lines
	start := 0
	if len(lines) > limit {
		start = len(lines) - limit
	}
	recent := lines[start:]

	// Reverse so newest first
	for i, j := 0, len(recent)-1; i < j; i, j = i+1, j-1 {
		recent[i], recent[j] = recent[j], recent[i]
	}

	// Parse each line and enrich with resolved OID info
	enriched := make([]map[string]interface{}, 0, len(recent))
	for _, line := range recent {
		var event map[string]interface{}
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			// If JSON parse fails, wrap the raw line
			enriched = append(enriched, map[string]interface{}{
				"raw": line,
			})
			continue
		}

		// Extract SNMP data and build the resolved OID display name
		if snmpData, ok := event["snmp"].(map[string]interface{}); ok {
			oid, _ := snmpData["oid"].(string)
			oidName, _ := snmpData["oid_name"].(string)
			oidModule, _ := snmpData["oid_module"].(string)

			// Use existing oid_name/oid_module from the log if available,
			// otherwise resolve from the MIB database
			if oidName != "" && oidModule != "" {
				// Already have resolved name with module — format as "MODULE::Name"
				snmpData["oid_resolved"] = oidModule + "::" + oidName
			} else if oidName != "" {
				snmpData["oid_resolved"] = oidName
			} else if oid != "" && s.resolver != nil {
				entry, found := s.resolver.Resolve(oid)
				if found {
					resolved := entry.Name
					if entry.Module != "" {
						resolved = entry.Module + "::" + entry.Name
					}
					snmpData["oid_resolved"] = resolved
					snmpData["oid_name"] = entry.Name
					snmpData["oid_module"] = entry.Module
				} else {
					snmpData["oid_resolved"] = oid
				}
			}

			// Always add description from the resolver if we have the OID
			if oid != "" && s.resolver != nil {
				entry, found := s.resolver.Resolve(oid)
				if found {
					snmpData["oid_description"] = entry.Description
					snmpData["oid_syntax"] = entry.Syntax
					snmpData["oid_category"] = entry.Category
				}
			}
		}

		enriched = append(enriched, event)
	}

	s.writeJSON(w, http.StatusOK, map[string]interface{}{
		"logs":  enriched,
		"total": len(lines),
	})
}

// handleGetOutputs returns the current output configuration (passwords masked).
func (s *Server) handleGetOutputs(w http.ResponseWriter, r *http.Request) {
	type outputInfo struct {
		Type    string `json:"type"`
		Enabled bool   `json:"enabled"`
		Target  string `json:"target"`
		Format  string `json:"format,omitempty"`
	}

	var outs []outputInfo
	for _, o := range s.outputConfigs {
		target := ""
		switch o.Type {
		case "file":
			target = o.Path
		case "syslog":
			target = o.Protocol + "://" + o.Address
		case "http":
			if o.URL != "" {
				target = o.URL
			} else {
				target = o.Address
			}
		case "tcp":
			target = "tcp://" + o.Address
		case "elasticsearch":
			if len(o.Addresses) > 0 {
				target = o.Addresses[0]
				if len(o.Addresses) > 1 {
					target += fmt.Sprintf(" (+%d)", len(o.Addresses)-1)
				}
				if o.Index != "" {
					target += "/" + o.Index
				}
			}
		case "stdout":
			target = "console"
		}

		outs = append(outs, outputInfo{
			Type:    o.Type,
			Enabled: o.Enabled,
			Target:  target,
			Format:  o.Format,
		})
	}

	s.writeJSON(w, http.StatusOK, map[string]interface{}{
		"outputs": outs,
		"total":   len(outs),
	})
}
