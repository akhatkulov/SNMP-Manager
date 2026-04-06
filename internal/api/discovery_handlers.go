package api

// discovery_handlers.go — REST API handlers for Network Discovery & Topology.
//
// Endpoints:
//   POST /api/v1/discovery/scan        — Start a network scan
//   GET  /api/v1/discovery/status       — Get current scan status
//   GET  /api/v1/discovery/results      — Get scan results
//   POST /api/v1/discovery/cancel       — Cancel running scan
//   POST /api/v1/discovery/register     — Register discovered devices
//   GET  /api/v1/topology               — Get topology map
//   POST /api/v1/topology/refresh       — Rebuild topology

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/me262/snmp-manager/internal/config"
	"github.com/me262/snmp-manager/internal/device"
	"github.com/me262/snmp-manager/internal/discovery"
)

// ── Start Scan ───────────────────────────────────────────────────────────────

func (s *Server) handleDiscoveryScan(w http.ResponseWriter, r *http.Request) {
	if s.scanner == nil {
		s.writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "discovery module not available"})
		return
	}

	var req struct {
		Subnets     []string `json:"subnets"`
		Communities []string `json:"communities"`
		Versions    []string `json:"snmp_versions"`
		Concurrency int      `json:"concurrency"`
		Timeout     string   `json:"timeout"`
		Port        int      `json:"port"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	if len(req.Subnets) == 0 {
		s.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "at least one subnet is required (e.g. 10.0.0.0/24)"})
		return
	}

	cfg := discovery.DefaultScanConfig()
	cfg.Subnets = req.Subnets
	if len(req.Communities) > 0 {
		cfg.Communities = req.Communities
	}
	if len(req.Versions) > 0 {
		cfg.SNMPVersions = req.Versions
	}
	if req.Concurrency > 0 {
		cfg.Concurrency = req.Concurrency
	}
	if req.Port > 0 {
		cfg.Port = req.Port
	}
	if req.Timeout != "" {
		if d, err := time.ParseDuration(req.Timeout); err == nil {
			cfg.Timeout = d
		}
	}

	status, err := s.scanner.StartScan(r.Context(), cfg)
	if err != nil {
		s.writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	s.log.Info().Strs("subnets", cfg.Subnets).Int("concurrency", cfg.Concurrency).Msg("network discovery scan started")
	s.writeJSON(w, http.StatusOK, map[string]any{
		"message": "scan started",
		"scan_id": status.ID,
		"total_ips": status.TotalIPs,
	})
}

// ── Scan Status ──────────────────────────────────────────────────────────────

func (s *Server) handleDiscoveryStatus(w http.ResponseWriter, r *http.Request) {
	if s.scanner == nil {
		s.writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "discovery module not available"})
		return
	}

	status := s.scanner.GetStatus()
	if status == nil {
		s.writeJSON(w, http.StatusOK, map[string]string{"state": "idle", "message": "no scan has been run yet"})
		return
	}

	s.writeJSON(w, http.StatusOK, status)
}

// ── Scan Results ─────────────────────────────────────────────────────────────

func (s *Server) handleDiscoveryResults(w http.ResponseWriter, r *http.Request) {
	if s.scanner == nil {
		s.writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "discovery module not available"})
		return
	}

	results := s.scanner.GetResults()
	if results == nil {
		results = []discovery.DiscoveredDevice{}
	}

	// Mark devices that are already registered
	for i := range results {
		if _, ok := s.registry.GetByIP(results[i].IP); ok {
			results[i].Registered = true
		}
	}

	// Sort by IP
	discovery.SortByIP(results)

	s.writeJSON(w, http.StatusOK, map[string]any{
		"count":   len(results),
		"devices": results,
	})
}

// ── Cancel Scan ──────────────────────────────────────────────────────────────

func (s *Server) handleDiscoveryCancel(w http.ResponseWriter, r *http.Request) {
	if s.scanner == nil {
		s.writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "discovery module not available"})
		return
	}
	s.scanner.CancelScan()
	s.writeJSON(w, http.StatusOK, map[string]string{"message": "scan cancelled"})
}

// ── Register Discovered Devices ──────────────────────────────────────────────

func (s *Server) handleDiscoveryRegister(w http.ResponseWriter, r *http.Request) {
	var req struct {
		IPs []string `json:"ips"` // Specific IPs to register (empty = all)
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	if s.scanner == nil {
		s.writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "discovery module not available"})
		return
	}

	results := s.scanner.GetResults()
	if len(results) == 0 {
		s.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "no scan results available"})
		return
	}

	ipSet := make(map[string]bool)
	for _, ip := range req.IPs {
		ipSet[ip] = true
	}

	registered := 0
	skipped := 0
	var errors []string

	for _, dd := range results {
		// Filter by IPs if specified
		if len(ipSet) > 0 && !ipSet[dd.IP] {
			continue
		}
		// Skip already registered
		if _, exists := s.registry.GetByIP(dd.IP); exists {
			skipped++
			continue
		}

		// Generate a name from sysName or IP
		name := dd.SysName
		if name == "" {
			name = fmt.Sprintf("auto-%s", dd.IP)
		}
		// Ensure unique name
		if _, exists := s.registry.Get(name); exists {
			name = fmt.Sprintf("%s-%s", name, dd.IP)
		}

		// Create device
		enabled := true
		devCfg := config.DeviceConfig{
			Name:        name,
			IP:          dd.IP,
			Port:        dd.Port,
			SNMPVersion: dd.SNMPVersion,
			Community:   dd.Community,
			PollInterval: 60 * time.Second,
			Enabled:     &enabled,
			OIDGroups:   []string{"system", "interfaces"},
			Tags: map[string]string{
				"discovered":  "true",
				"vendor":      dd.Vendor,
				"device_type": dd.DeviceType,
			},
			TemplateID: dd.MatchedTemplate,
		}

		dev := device.NewDeviceFromConfig(devCfg)
		if err := s.registry.Add(dev); err != nil {
			errors = append(errors, fmt.Sprintf("%s: %v", dd.IP, err))
			continue
		}
		registered++
	}

	s.log.Info().Int("registered", registered).Int("skipped", skipped).Msg("discovery registration completed")
	result := map[string]any{
		"registered": registered,
		"skipped":    skipped,
		"message":    fmt.Sprintf("%d devices registered, %d already existed", registered, skipped),
	}
	if len(errors) > 0 {
		result["errors"] = errors
	}

	s.writeJSON(w, http.StatusOK, result)
}

// ── Topology ─────────────────────────────────────────────────────────────────

func (s *Server) handleTopology(w http.ResponseWriter, r *http.Request) {
	if s.topoBuilder == nil {
		s.writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "topology module not available"})
		return
	}

	// Use cached topology if available
	s.topoMu.RLock()
	topo := s.cachedTopology
	s.topoMu.RUnlock()

	if topo == nil {
		// Build on first request
		topo = s.buildTopologyMap()
	}

	s.writeJSON(w, http.StatusOK, topo)
}

func (s *Server) handleTopologyRefresh(w http.ResponseWriter, r *http.Request) {
	if s.topoBuilder == nil {
		s.writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "topology module not available"})
		return
	}

	topo := s.buildTopologyMap()
	s.writeJSON(w, http.StatusOK, map[string]any{
		"message":  "topology refreshed",
		"nodes":    len(topo.Nodes),
		"links":    len(topo.Links),
		"topology": topo,
	})
}

func (s *Server) buildTopologyMap() *discovery.TopologyMap {
	devices := s.registry.List()
	infos := make([]discovery.DeviceInfo, 0, len(devices))
	for _, d := range devices {
		clone := d.Clone()
		infos = append(infos, discovery.DeviceInfo{
			Name:        clone.Name,
			IP:          clone.IP,
			Port:        clone.Port,
			Community:   clone.Community,
			SNMPVersion: clone.SNMPVersion,
			Status:      string(clone.Status),
			Vendor:      clone.Vendor,
			DeviceType:  clone.DeviceType,
			SysName:     clone.SysName,
		})
	}

	topo := s.topoBuilder.BuildTopology(infos)

	s.topoMu.Lock()
	s.cachedTopology = topo
	s.topoMu.Unlock()

	return topo
}
