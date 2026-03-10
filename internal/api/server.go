package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
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
	log      zerolog.Logger
	cfg      config.APIConfig
	registry *device.Registry
	resolver *mib.Resolver
	poller   *poller.Poller
	trap     *trap.Listener
	pipe     *pipeline.Pipeline
	server   *http.Server
	startTime time.Time
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
) *Server {
	return &Server{
		log:      log.With().Str("component", "api").Logger(),
		cfg:      cfg,
		registry: registry,
		resolver: resolver,
		poller:   poll,
		trap:     trapListener,
		pipe:     pipe,
		startTime: time.Now(),
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
	mux.HandleFunc("GET /api/v1/mibs/groups", s.withAuth(s.handleListMIBGroups))
	mux.HandleFunc("GET /api/v1/mibs/resolve/{oid}", s.withAuth(s.handleResolveOID))
	mux.HandleFunc("GET /api/v1/mibs/count", s.withAuth(s.handleMIBCount))

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
