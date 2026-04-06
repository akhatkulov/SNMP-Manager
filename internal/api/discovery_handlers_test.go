package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/me262/snmp-manager/internal/config"
	"github.com/me262/snmp-manager/internal/device"
	"github.com/me262/snmp-manager/internal/discovery"
	"github.com/rs/zerolog"
)

// setupDiscoveryServer initializes a test API server with mock discovery components
func setupDiscoveryServer() *Server {
	log := zerolog.Nop()
	cfg := config.APIConfig{Enabled: true}
	fullCfg := &config.Config{}
	
	registry := device.NewRegistry(log)
	scanner := discovery.NewScanner(log)
	topoBuilder := discovery.NewTopologyBuilder(log)

	server := NewServer(log, cfg, fullCfg, "", registry, nil, nil, nil, nil, nil)
	server.SetScanner(scanner)
	server.SetTopologyBuilder(topoBuilder)
	// Add test auth middleware to bypass auth
	server.cfg.Enabled = true

	return server
}

func TestDiscoveryHandlers(t *testing.T) {
	s := setupDiscoveryServer()
	
	// Create an HTTP handler from the server's ServeMux
	// We have to register routes. Since Run() is blocking, we manually construct the mux
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/discovery/scan", s.handleDiscoveryScan)
	mux.HandleFunc("GET /api/v1/discovery/status", s.handleDiscoveryStatus)
	mux.HandleFunc("GET /api/v1/discovery/results", s.handleDiscoveryResults)
	mux.HandleFunc("POST /api/v1/discovery/cancel", s.handleDiscoveryCancel)

	// --- 1. Test starting a scan (Invalid Body) ---
	reqInvalid := httptest.NewRequest("POST", "/api/v1/discovery/scan", strings.NewReader(`"invalid"`))
	wInvalid := httptest.NewRecorder()
	mux.ServeHTTP(wInvalid, reqInvalid)
	if wInvalid.Code != http.StatusBadRequest {
		t.Errorf("Expected 400 Bad Request for invalid body, got %d", wInvalid.Code)
	}

	// --- 2. Test starting a scan (Valid Subnet) ---
	bodyBytes, _ := json.Marshal(map[string]interface{}{
		"subnets": []string{"192.168.99.0/30"}, // small subnet for faster fast evaluation
		"concurrency": 2,
		"timeout": "50ms",
	})
	reqValid := httptest.NewRequest("POST", "/api/v1/discovery/scan", bytes.NewReader(bodyBytes))
	wValid := httptest.NewRecorder()
	mux.ServeHTTP(wValid, reqValid)
	if wValid.Code != http.StatusOK {
		t.Fatalf("Expected 200 OK for starting scan, got %d %v", wValid.Code, wValid.Body.String())
	}
	
	var scanResp map[string]interface{}
	json.NewDecoder(wValid.Body).Decode(&scanResp)
	if scanResp["scan_id"] == nil {
		t.Errorf("Expected scan_id in response")
	}

	// Wait briefly for scan task to start working
	time.Sleep(50 * time.Millisecond)

	// --- 3. Test checking scan status ---
	reqStatus := httptest.NewRequest("GET", "/api/v1/discovery/status", nil)
	wStatus := httptest.NewRecorder()
	mux.ServeHTTP(wStatus, reqStatus)
	if wStatus.Code != http.StatusOK {
		t.Errorf("Expected 200 OK for status, got %d", wStatus.Code)
	}

	// --- 4. Test getting results (During or After scan) ---
	reqResults := httptest.NewRequest("GET", "/api/v1/discovery/results", nil)
	wResults := httptest.NewRecorder()
	mux.ServeHTTP(wResults, reqResults)
	if wResults.Code != http.StatusOK {
		t.Errorf("Expected 200 OK for results, got %d", wResults.Code)
	}
	var resResp map[string]interface{}
	json.NewDecoder(wResults.Body).Decode(&resResp)
	if _, ok := resResp["devices"]; !ok {
		t.Errorf("Expected devices array in results response")
	}

	// --- 5. Test cancelling scan ---
	reqCancel := httptest.NewRequest("POST", "/api/v1/discovery/cancel", nil)
	wCancel := httptest.NewRecorder()
	mux.ServeHTTP(wCancel, reqCancel)
	if wCancel.Code != http.StatusOK {
		t.Errorf("Expected 200 OK for cancel, got %d", wCancel.Code)
	}
}

func TestTopologyHandlers(t *testing.T) {
	s := setupDiscoveryServer()
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/topology", s.handleTopology)
	mux.HandleFunc("POST /api/v1/topology/refresh", s.handleTopologyRefresh)

	// -- 1. Test GET Topology --
	reqGet := httptest.NewRequest("GET", "/api/v1/topology", nil)
	wGet := httptest.NewRecorder()
	mux.ServeHTTP(wGet, reqGet)
	if wGet.Code != http.StatusOK {
		t.Errorf("Expected 200 OK for GET topology, got %d", wGet.Code)
	}
	
	// -- 2. Test POST Refresh Topology --
	reqRefresh := httptest.NewRequest("POST", "/api/v1/topology/refresh", nil)
	wRefresh := httptest.NewRecorder()
	mux.ServeHTTP(wRefresh, reqRefresh)
	if wRefresh.Code != http.StatusOK {
		t.Errorf("Expected 200 OK for Refresh topology, got %d", wRefresh.Code)
	}
}
