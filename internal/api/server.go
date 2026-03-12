package api

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/rs/zerolog"

	"github.com/me262/snmp-manager/internal/config"
	"github.com/me262/snmp-manager/internal/device"
	"github.com/me262/snmp-manager/internal/mib"
	"github.com/me262/snmp-manager/internal/pipeline"
	"github.com/me262/snmp-manager/internal/poller"
	"github.com/me262/snmp-manager/internal/store"
	"github.com/me262/snmp-manager/internal/trap"
)

// Server provides a REST API for managing and monitoring the SNMP Manager.
type Server struct {
	log             zerolog.Logger
	cfg             config.APIConfig
	fullConfig      *config.Config
	configPath      string
	registry        *device.Registry
	resolver        *mib.Resolver
	poller          *poller.Poller
	trap            *trap.Listener
	pipe            *pipeline.Pipeline
	server          *http.Server
	startTime       time.Time
	outputConfigs   []config.OutputConfig
	esStore         *store.ElasticsearchStore
	statsHistory    *store.StatsHistory
	outputInstances []pipeline.Output
}

// NewServer creates a new API server.
func NewServer(
	log zerolog.Logger,
	cfg config.APIConfig,
	fullCfg *config.Config,
	configPath string,
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
		fullConfig:    fullCfg,
		configPath:    configPath,
		registry:      registry,
		resolver:      resolver,
		poller:        poll,
		trap:          trapListener,
		pipe:          pipe,
		startTime:     time.Now(),
		outputConfigs: outputConfigs,
		statsHistory:  store.NewStatsHistory(360), // 360 points ≈ 1 hour at 10s intervals
	}
}

// SetESStore sets the Elasticsearch store for event querying.
func (s *Server) SetESStore(es *store.ElasticsearchStore) {
	s.esStore = es
}

// SetOutputInstances stores output references for buffer stats.
func (s *Server) SetOutputInstances(outputs []pipeline.Output) {
	s.outputInstances = outputs
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
	mux.HandleFunc("POST /api/v1/config/outputs", s.withAuth(s.handleAddOutput))
	mux.HandleFunc("PUT /api/v1/config/outputs/{idx}", s.withAuth(s.handleUpdateOutput))
	mux.HandleFunc("DELETE /api/v1/config/outputs/{idx}", s.withAuth(s.handleDeleteOutput))
	mux.HandleFunc("PATCH /api/v1/config/outputs/{idx}/toggle", s.withAuth(s.handleToggleOutput))
	mux.HandleFunc("GET /api/v1/config/server", s.withAuth(s.handleGetServerConfig))
	mux.HandleFunc("GET /api/v1/system/info", s.withAuth(s.handleSystemInfo))
	mux.HandleFunc("GET /api/v1/stats/history", s.withAuth(s.handleStatsHistory))
	mux.HandleFunc("GET /api/v1/events/search", s.withAuth(s.handleEventSearch))
	mux.HandleFunc("GET /api/v1/events/stats", s.withAuth(s.handleEventStats))
	mux.HandleFunc("GET /api/v1/events/timeseries", s.withAuth(s.handleEventTimeSeries))
	mux.HandleFunc("GET /api/v1/buffer/stats", s.withAuth(s.handleBufferStats))

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

	// Stats collector goroutine — snapshots every 10s for dashboard charts
	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				var ms runtime.MemStats
				runtime.ReadMemStats(&ms)
				devStats := s.registry.Stats()
				pipeStats := s.pipe.Stats()
				s.statsHistory.Push(store.StatsSnapshot{
					Timestamp:  time.Now(),
					EventsIn:   pipeStats.EventsIn,
					EventsOut:  pipeStats.EventsOut,
					Goroutines: runtime.NumGoroutine(),
					MemoryMB:   float64(ms.Alloc) / 1024 / 1024,
					DevicesUp:  devStats.Up,
					DevicesErr: devStats.Error,
				})
			}
		}
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
		Type       string            `json:"type"`
		Enabled    bool              `json:"enabled"`
		Target     string            `json:"target"`
		Format     string            `json:"format,omitempty"`
		Protocol   string            `json:"protocol,omitempty"`
		Path       string            `json:"path,omitempty"`
		MaxSizeMB  int               `json:"max_size_mb,omitempty"`
		MaxBackups int               `json:"max_backups,omitempty"`
		Compress   bool              `json:"compress,omitempty"`
		TLS        bool              `json:"tls,omitempty"`
		TLSSkip    bool              `json:"tls_skip_verify,omitempty"`
		Index      string            `json:"index,omitempty"`
		Addresses  []string          `json:"addresses,omitempty"`
		Username   string            `json:"username,omitempty"`
		Headers    map[string]string `json:"headers,omitempty"`
	}

	var outs []outputInfo
	for _, o := range s.outputConfigs {
		info := outputInfo{
			Type:     o.Type,
			Enabled:  o.Enabled,
			Format:   o.Format,
			Protocol: o.Protocol,
		}

		switch o.Type {
		case "file":
			info.Target = o.Path
			info.Path = o.Path
			info.MaxSizeMB = o.MaxSizeMB
			info.MaxBackups = o.MaxBackups
			info.Compress = o.Compress
		case "syslog":
			info.Target = o.Protocol + "://" + o.Address
			if o.TLS != nil && o.TLS.Enabled {
				info.TLS = true
			}
		case "http":
			if o.URL != "" {
				info.Target = o.URL
			} else {
				info.Target = o.Address
			}
			info.TLSSkip = o.TLSSkipVerify
			info.Headers = o.Headers
		case "tcp":
			info.Target = "tcp://" + o.Address
		case "elasticsearch":
			info.Addresses = o.Addresses
			info.Index = o.Index
			if o.Username != "" {
				info.Username = o.Username
			}
			if len(o.Addresses) > 0 {
				info.Target = o.Addresses[0]
				if len(o.Addresses) > 1 {
					info.Target += fmt.Sprintf(" (+%d)", len(o.Addresses)-1)
				}
				if o.Index != "" {
					info.Target += "/" + o.Index
				}
			}
			info.TLSSkip = o.TLSSkipVerify
		case "stdout":
			info.Target = "console"
		}

		outs = append(outs, info)
	}

	s.writeJSON(w, http.StatusOK, map[string]interface{}{
		"outputs": outs,
		"total":   len(outs),
	})
}

// handleSystemInfo returns runtime system information.
func (s *Server) handleSystemInfo(w http.ResponseWriter, r *http.Request) {
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)

	s.writeJSON(w, http.StatusOK, map[string]interface{}{
		"go_version":    runtime.Version(),
		"os":            runtime.GOOS,
		"arch":          runtime.GOARCH,
		"cpus":          runtime.NumCPU(),
		"goroutines":    runtime.NumGoroutine(),
		"memory": map[string]interface{}{
			"alloc_mb":       fmt.Sprintf("%.1f", float64(mem.Alloc)/1024/1024),
			"total_alloc_mb": fmt.Sprintf("%.1f", float64(mem.TotalAlloc)/1024/1024),
			"sys_mb":         fmt.Sprintf("%.1f", float64(mem.Sys)/1024/1024),
			"num_gc":         mem.NumGC,
			"heap_objects":   mem.HeapObjects,
		},
		"uptime":        time.Since(s.startTime).String(),
		"uptime_seconds": int(time.Since(s.startTime).Seconds()),
		"start_time":    s.startTime.Format(time.RFC3339),
		"device_count":  s.registry.Stats().Total,
	})
}

// handleGetServerConfig returns the sanitized server configuration.
func (s *Server) handleGetServerConfig(w http.ResponseWriter, r *http.Request) {
	if s.fullConfig == nil {
		s.writeJSON(w, http.StatusOK, map[string]interface{}{"error": "config not available"})
		return
	}
	cfg := s.fullConfig

	s.writeJSON(w, http.StatusOK, map[string]interface{}{
		"server": map[string]interface{}{
			"name":       cfg.Server.Name,
			"log_level":  cfg.Server.LogLevel,
			"log_format": cfg.Server.LogFormat,
		},
		"poller": map[string]interface{}{
			"workers":              cfg.Poller.Workers,
			"default_interval":     cfg.Poller.DefaultInterval.String(),
			"timeout":              cfg.Poller.Timeout.String(),
			"retries":              cfg.Poller.Retries,
			"max_oids_per_request": cfg.Poller.MaxOIDsPerRequest,
		},
		"pipeline": map[string]interface{}{
			"buffer_size":    cfg.Pipeline.BufferSize,
			"batch_size":     cfg.Pipeline.BatchSize,
			"flush_interval": cfg.Pipeline.FlushInterval.String(),
			"workers":        cfg.Pipeline.Workers,
			"normalizer": map[string]interface{}{
				"resolve_oid_names":  cfg.Pipeline.Normalizer.ResolveOIDNames,
				"resolve_hostnames":  cfg.Pipeline.Normalizer.ResolveHostnames,
			},
		},
		"trap_receiver": map[string]interface{}{
			"enabled":        cfg.TrapReceiver.Enabled,
			"listen_address": cfg.TrapReceiver.ListenAddress,
			"v3_users_count": len(cfg.TrapReceiver.V3Users),
		},
		"api": map[string]interface{}{
			"listen_address": cfg.API.ListenAddress,
			"auth_type":      cfg.API.Auth.Type,
			"api_keys_count": len(cfg.API.Auth.Keys),
		},
		"metrics": map[string]interface{}{
			"enabled":        cfg.Metrics.Enabled,
			"listen_address": cfg.Metrics.ListenAddress,
			"path":           cfg.Metrics.Path,
		},
		"mib": map[string]interface{}{
			"load_system_mibs": cfg.MIB.LoadSystemMIBs,
			"directories":      cfg.MIB.Directories,
		},
	})
}

// ── Output CRUD ──────────────────────────────────────────────────────

var validOutputTypes = map[string]bool{
	"stdout": true, "file": true, "syslog": true,
	"http": true, "tcp": true, "elasticsearch": true,
}

func (s *Server) handleAddOutput(w http.ResponseWriter, r *http.Request) {
	var out config.OutputConfig
	if err := json.NewDecoder(r.Body).Decode(&out); err != nil {
		s.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON: " + err.Error()})
		return
	}
	if !validOutputTypes[out.Type] {
		s.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid output type: " + out.Type})
		return
	}

	s.outputConfigs = append(s.outputConfigs, out)
	if s.fullConfig != nil {
		s.fullConfig.Outputs = s.outputConfigs
	}
	if err := config.SaveOutputs(s.configPath, s.outputConfigs); err != nil {
		s.log.Error().Err(err).Msg("failed to save outputs")
	}

	s.log.Info().Str("type", out.Type).Bool("enabled", out.Enabled).Msg("output added via API")
	s.writeJSON(w, http.StatusCreated, map[string]interface{}{
		"message": "Output added. Restart required to activate.",
		"total":   len(s.outputConfigs),
	})
}

func (s *Server) handleUpdateOutput(w http.ResponseWriter, r *http.Request) {
	idx, err := strconv.Atoi(r.PathValue("idx"))
	if err != nil || idx < 0 || idx >= len(s.outputConfigs) {
		s.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid output index"})
		return
	}

	var out config.OutputConfig
	if err := json.NewDecoder(r.Body).Decode(&out); err != nil {
		s.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON: " + err.Error()})
		return
	}
	if !validOutputTypes[out.Type] {
		s.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid output type: " + out.Type})
		return
	}

	s.outputConfigs[idx] = out
	if s.fullConfig != nil {
		s.fullConfig.Outputs = s.outputConfigs
	}
	if err := config.SaveOutputs(s.configPath, s.outputConfigs); err != nil {
		s.log.Error().Err(err).Msg("failed to save outputs")
	}

	s.log.Info().Int("index", idx).Str("type", out.Type).Msg("output updated via API")
	s.writeJSON(w, http.StatusOK, map[string]string{"message": "Output updated. Restart required to apply."})
}

func (s *Server) handleDeleteOutput(w http.ResponseWriter, r *http.Request) {
	idx, err := strconv.Atoi(r.PathValue("idx"))
	if err != nil || idx < 0 || idx >= len(s.outputConfigs) {
		s.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid output index"})
		return
	}

	removed := s.outputConfigs[idx]
	s.outputConfigs = append(s.outputConfigs[:idx], s.outputConfigs[idx+1:]...)
	if s.fullConfig != nil {
		s.fullConfig.Outputs = s.outputConfigs
	}
	if err := config.SaveOutputs(s.configPath, s.outputConfigs); err != nil {
		s.log.Error().Err(err).Msg("failed to save outputs")
	}

	s.log.Info().Int("index", idx).Str("type", removed.Type).Msg("output deleted via API")
	s.writeJSON(w, http.StatusOK, map[string]string{"message": "Output deleted. Restart required to apply."})
}

func (s *Server) handleToggleOutput(w http.ResponseWriter, r *http.Request) {
	idx, err := strconv.Atoi(r.PathValue("idx"))
	if err != nil || idx < 0 || idx >= len(s.outputConfigs) {
		s.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid output index"})
		return
	}

	s.outputConfigs[idx].Enabled = !s.outputConfigs[idx].Enabled
	if s.fullConfig != nil {
		s.fullConfig.Outputs = s.outputConfigs
	}
	if err := config.SaveOutputs(s.configPath, s.outputConfigs); err != nil {
		s.log.Error().Err(err).Msg("failed to save outputs")
	}

	status := "disabled"
	if s.outputConfigs[idx].Enabled {
		status = "enabled"
	}
	s.log.Info().Int("index", idx).Str("status", status).Msg("output toggled via API")
	s.writeJSON(w, http.StatusOK, map[string]interface{}{
		"message": "Output " + status + ". Restart required to apply.",
		"enabled": s.outputConfigs[idx].Enabled,
	})
}

// ── Charts & Events ──────────────────────────────────────────────────

func (s *Server) handleStatsHistory(w http.ResponseWriter, r *http.Request) {
	s.writeJSON(w, http.StatusOK, s.statsHistory.FormatForChart())
}

func (s *Server) handleEventSearch(w http.ResponseWriter, r *http.Request) {
	if s.esStore == nil {
		s.writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "Elasticsearch not configured"})
		return
	}

	params := store.SearchParams{
		Query:     r.URL.Query().Get("q"),
		Severity:  r.URL.Query().Get("severity"),
		DeviceIP:  r.URL.Query().Get("device_ip"),
		EventType: r.URL.Query().Get("event_type"),
		TimeFrom:  r.URL.Query().Get("time_from"),
		TimeTo:    r.URL.Query().Get("time_to"),
		SortField: r.URL.Query().Get("sort"),
		SortOrder: r.URL.Query().Get("order"),
	}
	if v := r.URL.Query().Get("from"); v != "" {
		fmt.Sscanf(v, "%d", &params.From)
	}
	if v := r.URL.Query().Get("size"); v != "" {
		fmt.Sscanf(v, "%d", &params.Size)
	}

	result, err := s.esStore.Search(r.Context(), params)
	if err != nil {
		s.writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	s.writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleEventStats(w http.ResponseWriter, r *http.Request) {
	if s.esStore == nil {
		s.writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "Elasticsearch not configured"})
		return
	}
	stats, err := s.esStore.EventStats(r.Context())
	if err != nil {
		s.writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	s.writeJSON(w, http.StatusOK, stats)
}

func (s *Server) handleEventTimeSeries(w http.ResponseWriter, r *http.Request) {
	if s.esStore == nil {
		s.writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "Elasticsearch not configured"})
		return
	}
	interval := r.URL.Query().Get("interval")
	if interval == "" {
		interval = "10m"
	}
	hours := 6
	if v := r.URL.Query().Get("hours"); v != "" {
		fmt.Sscanf(v, "%d", &hours)
	}

	points, err := s.esStore.GetTimeSeries(r.Context(), interval, hours)
	if err != nil {
		s.writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]interface{}{
		"interval": interval,
		"hours":    hours,
		"points":   points,
	})
}

func (s *Server) handleBufferStats(w http.ResponseWriter, r *http.Request) {
	type bufferInfo struct {
		Name        string      `json:"name"`
		CircuitOpen bool        `json:"circuit_open"`
		Sent        int64       `json:"sent"`
		Buffered    int64       `json:"buffered"`
		Flushed     int64       `json:"flushed"`
		Dropped     int64       `json:"dropped"`
		Errors      int64       `json:"errors"`
		SpoolBytes  int64       `json:"spool_bytes"`
		MemBufLen   int         `json:"mem_buf_len"`
		MemBufCap   int         `json:"mem_buf_cap"`
		Backoff     string      `json:"backoff"`
	}

	var buffers []bufferInfo
	for _, out := range s.outputInstances {
		// Check if output has a Stats() method (BufferedOutput)
		type statter interface {
			Stats() map[string]interface{}
		}
		if bo, ok := out.(statter); ok {
			stats := bo.Stats()
			buffers = append(buffers, bufferInfo{
				Name:        fmt.Sprintf("%v", stats["output"]),
				CircuitOpen: stats["circuit_open"].(bool),
				Sent:        stats["sent"].(int64),
				Buffered:    stats["buffered"].(int64),
				Flushed:     stats["flushed"].(int64),
				Dropped:     stats["dropped"].(int64),
				Errors:      stats["errors"].(int64),
				SpoolBytes:  stats["spool_bytes"].(int64),
				MemBufLen:   stats["mem_buf_len"].(int),
				MemBufCap:   stats["mem_buf_cap"].(int),
				Backoff:     fmt.Sprintf("%v", stats["backoff"]),
			})
		}
	}
	s.writeJSON(w, http.StatusOK, map[string]interface{}{
		"buffers": buffers,
		"total":   len(buffers),
	})
}
