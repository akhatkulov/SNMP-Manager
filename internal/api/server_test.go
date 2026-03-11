package api

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog"

	"github.com/me262/snmp-manager/internal/config"
	"github.com/me262/snmp-manager/internal/device"
	"github.com/me262/snmp-manager/internal/mib"
)

func newTestServer() (*Server, *http.ServeMux) {
	log := zerolog.Nop()
	registry := device.NewRegistry(log)
	registry.Add(&device.Device{
		Name: "test-router", IP: "10.0.0.1", Port: 161,
		SNMPVersion: "v2c", Enabled: true, Status: device.StatusUp,
		Vendor: "Cisco", DeviceType: "router",
		PollCount: 42, TrapCount: 7,
		LastPoll: time.Now(),
	})
	registry.Add(&device.Device{
		Name: "test-switch", IP: "10.0.0.2", Port: 161,
		SNMPVersion: "v2c", Enabled: true, Status: device.StatusDown,
	})

	resolver := mib.NewResolver(log)

	s := &Server{
		log:       log,
		cfg:       config.APIConfig{Enabled: true, Auth: config.AuthConfig{Keys: []string{"test-key"}}},
		registry:  registry,
		resolver:  resolver,
		startTime: time.Now(),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/health", s.handleHealth)
	mux.HandleFunc("GET /api/v1/stats", s.withAuth(s.handleStats))
	mux.HandleFunc("GET /api/v1/devices", s.withAuth(s.handleListDevices))
	mux.HandleFunc("GET /api/v1/devices/{name}", s.withAuth(s.handleGetDevice))
	mux.HandleFunc("POST /api/v1/devices", s.withAuth(s.handleAddDevice))
	mux.HandleFunc("PUT /api/v1/devices/{name}", s.withAuth(s.handleUpdateDevice))
	mux.HandleFunc("DELETE /api/v1/devices/{name}", s.withAuth(s.handleDeleteDevice))
	mux.HandleFunc("GET /api/v1/mibs/groups", s.withAuth(s.handleListMIBGroups))
	mux.HandleFunc("GET /api/v1/mibs/resolve/{oid}", s.withAuth(s.handleResolveOID))
	mux.HandleFunc("GET /api/v1/mibs/count", s.withAuth(s.handleMIBCount))

	return s, mux
}

func doRequest(mux http.Handler, method, path, apiKey string) *httptest.ResponseRecorder {
	return doRequestWithBody(mux, method, path, apiKey, "")
}

func doRequestWithBody(mux http.Handler, method, path, apiKey, body string) *httptest.ResponseRecorder {
	var bodyReader io.Reader
	if body != "" {
		bodyReader = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, bodyReader)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if apiKey != "" {
		req.Header.Set("X-API-Key", apiKey)
	}
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	return w
}

func parseJSON(t *testing.T, r *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	body, _ := io.ReadAll(r.Body)
	var result map[string]any
	if err := json.Unmarshal(body, &result); err != nil {
		t.Fatalf("invalid JSON response: %v\nbody: %s", err, string(body))
	}
	return result
}

// ── Health Endpoint ─────────────────────────────────────────────────

func TestHealthEndpoint(t *testing.T) {
	_, mux := newTestServer()
	w := doRequest(mux, "GET", "/api/v1/health", "")

	if w.Code != http.StatusOK {
		t.Errorf("status: want 200, got %d", w.Code)
	}

	result := parseJSON(t, w)
	if result["status"] != "healthy" {
		t.Errorf("status: want %q, got %v", "healthy", result["status"])
	}

	devices, ok := result["devices"].(map[string]any)
	if !ok {
		t.Fatal("devices field should be a map")
	}
	if devices["total"].(float64) != 2 {
		t.Errorf("total devices: want 2, got %v", devices["total"])
	}
}

func TestHealthNoAuth(t *testing.T) {
	_, mux := newTestServer()
	// Health should NOT require auth
	w := doRequest(mux, "GET", "/api/v1/health", "")
	if w.Code != http.StatusOK {
		t.Errorf("health should not require auth, got status %d", w.Code)
	}
}

// ── Auth Middleware ──────────────────────────────────────────────────

func TestAuthRequired(t *testing.T) {
	_, mux := newTestServer()

	// Without API key
	w := doRequest(mux, "GET", "/api/v1/devices", "")
	if w.Code != http.StatusUnauthorized {
		t.Errorf("no auth: want 401, got %d", w.Code)
	}

	// With invalid API key
	w = doRequest(mux, "GET", "/api/v1/devices", "wrong-key")
	if w.Code != http.StatusUnauthorized {
		t.Errorf("wrong key: want 401, got %d", w.Code)
	}

	// With valid API key
	w = doRequest(mux, "GET", "/api/v1/devices", "test-key")
	if w.Code != http.StatusOK {
		t.Errorf("valid key: want 200, got %d", w.Code)
	}
}

func TestAuthQueryParam(t *testing.T) {
	_, mux := newTestServer()

	// API key in query parameter
	req := httptest.NewRequest("GET", "/api/v1/devices?api_key=test-key", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("query param auth: want 200, got %d", w.Code)
	}
}

// ── Devices Endpoints ───────────────────────────────────────────────

func TestListDevices(t *testing.T) {
	_, mux := newTestServer()
	w := doRequest(mux, "GET", "/api/v1/devices", "test-key")

	if w.Code != http.StatusOK {
		t.Fatalf("status: want 200, got %d", w.Code)
	}

	result := parseJSON(t, w)
	count := result["count"].(float64)
	if count != 2 {
		t.Errorf("count: want 2, got %v", count)
	}

	devices, ok := result["devices"].([]any)
	if !ok {
		t.Fatal("devices should be an array")
	}
	if len(devices) != 2 {
		t.Errorf("devices length: want 2, got %d", len(devices))
	}
}

func TestGetDevice(t *testing.T) {
	_, mux := newTestServer()
	w := doRequest(mux, "GET", "/api/v1/devices/test-router", "test-key")

	if w.Code != http.StatusOK {
		t.Fatalf("status: want 200, got %d", w.Code)
	}

	result := parseJSON(t, w)
	if result["name"] != "test-router" {
		t.Errorf("name: want %q, got %v", "test-router", result["name"])
	}
	if result["ip"] != "10.0.0.1" {
		t.Errorf("ip: want %q, got %v", "10.0.0.1", result["ip"])
	}
}

func TestGetDeviceNotFound(t *testing.T) {
	_, mux := newTestServer()
	w := doRequest(mux, "GET", "/api/v1/devices/nonexistent", "test-key")

	if w.Code != http.StatusNotFound {
		t.Errorf("status: want 404, got %d", w.Code)
	}

	result := parseJSON(t, w)
	if _, ok := result["error"]; !ok {
		t.Error("response should contain 'error' field")
	}
}

// ── MIB Endpoints ───────────────────────────────────────────────────

func TestListMIBGroups(t *testing.T) {
	_, mux := newTestServer()
	w := doRequest(mux, "GET", "/api/v1/mibs/groups", "test-key")

	if w.Code != http.StatusOK {
		t.Fatalf("status: want 200, got %d", w.Code)
	}

	result := parseJSON(t, w)
	groups, ok := result["groups"].(map[string]any)
	if !ok {
		t.Fatal("groups should be a map")
	}

	expectedGroups := []string{"system", "interfaces", "cpu_memory", "trap"}
	for _, g := range expectedGroups {
		if _, ok := groups[g]; !ok {
			t.Errorf("missing group: %q", g)
		}
	}
}

func TestResolveOID(t *testing.T) {
	_, mux := newTestServer()
	w := doRequest(mux, "GET", "/api/v1/mibs/resolve/1.3.6.1.2.1.1.1", "test-key")

	if w.Code != http.StatusOK {
		t.Fatalf("status: want 200, got %d", w.Code)
	}

	result := parseJSON(t, w)
	if result["name"] != "sysDescr" {
		t.Errorf("name: want %q, got %v", "sysDescr", result["name"])
	}
	if result["module"] != "SNMPv2-MIB" {
		t.Errorf("module: want %q, got %v", "SNMPv2-MIB", result["module"])
	}
}

func TestResolveOIDNotFound(t *testing.T) {
	_, mux := newTestServer()
	w := doRequest(mux, "GET", "/api/v1/mibs/resolve/1.3.6.1.99.99", "test-key")

	if w.Code != http.StatusNotFound {
		t.Errorf("status: want 404, got %d", w.Code)
	}
}

func TestMIBCount(t *testing.T) {
	_, mux := newTestServer()
	w := doRequest(mux, "GET", "/api/v1/mibs/count", "test-key")

	if w.Code != http.StatusOK {
		t.Fatalf("status: want 200, got %d", w.Code)
	}

	result := parseJSON(t, w)
	count := result["total_oids"].(float64)
	if count < 50 {
		t.Errorf("total OIDs: want >= 50, got %v", count)
	}
}

// ── Content Type ────────────────────────────────────────────────────

func TestContentTypeJSON(t *testing.T) {
	_, mux := newTestServer()
	w := doRequest(mux, "GET", "/api/v1/health", "")

	ct := w.Header().Get("Content-Type")
	if ct != "application/json" {
		t.Errorf("Content-Type: want %q, got %q", "application/json", ct)
	}
}

// ── CORS ────────────────────────────────────────────────────────────

func TestCORSHeaders(t *testing.T) {
	s, mux := newTestServer()
	handler := s.corsMiddleware(mux)

	req := httptest.NewRequest("OPTIONS", "/api/v1/health", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Header().Get("Access-Control-Allow-Origin") != "*" {
		t.Error("CORS Allow-Origin header missing")
	}
	if w.Header().Get("Access-Control-Allow-Methods") == "" {
		t.Error("CORS Allow-Methods header missing")
	}
	if w.Code != http.StatusOK {
		t.Errorf("OPTIONS status: want 200, got %d", w.Code)
	}
}

// ── Device Management (Add/Update/Delete) ──────────────────────────

func TestAddDevice(t *testing.T) {
	_, mux := newTestServer()

	body, _ := json.Marshal(map[string]any{
		"name":         "new-fw",
		"ip":           "192.168.1.100",
		"snmp_version": "v2c",
		"community":    "public",
		"poll_interval": "30s",
		"oid_groups":   []string{"system", "interfaces"},
		"tags": map[string]string{
			"location":    "DC-Tashkent",
			"criticality": "medium",
		},
	})

	w := doRequestWithBody(mux, "POST", "/api/v1/devices", "test-key", string(body))
	if w.Code != http.StatusCreated {
		t.Fatalf("status: want 201, got %d; body: %s", w.Code, w.Body.String())
	}

	result := parseJSON(t, w)
	if result["device"] != "new-fw" {
		t.Errorf("device: want %q, got %v", "new-fw", result["device"])
	}

	// Verify device appears in list
	w2 := doRequest(mux, "GET", "/api/v1/devices", "test-key")
	result2 := parseJSON(t, w2)
	if result2["count"].(float64) != 3 {
		t.Errorf("count after add: want 3, got %v", result2["count"])
	}
}

func TestAddDeviceDuplicate(t *testing.T) {
	_, mux := newTestServer()

	body, _ := json.Marshal(map[string]any{
		"name":      "test-router",
		"ip":        "10.0.0.99",
		"community": "public",
	})

	w := doRequestWithBody(mux, "POST", "/api/v1/devices", "test-key", string(body))
	if w.Code != http.StatusConflict {
		t.Errorf("duplicate: want 409, got %d", w.Code)
	}
}

func TestAddDeviceMissingFields(t *testing.T) {
	_, mux := newTestServer()

	tests := []struct {
		name string
		body string
	}{
		{"no name", `{"ip":"1.2.3.4","community":"x"}`},
		{"no ip", `{"name":"foo","community":"x"}`},
		{"v2c no community", `{"name":"foo","ip":"1.2.3.4","snmp_version":"v2c"}`},
		{"v3 no creds", `{"name":"foo","ip":"1.2.3.4","snmp_version":"v3"}`},
	}

	for _, tc := range tests {
		w := doRequestWithBody(mux, "POST", "/api/v1/devices", "test-key", tc.body)
		if w.Code != http.StatusBadRequest {
			t.Errorf("%s: want 400, got %d", tc.name, w.Code)
		}
	}
}

func TestUpdateDevice(t *testing.T) {
	_, mux := newTestServer()

	body, _ := json.Marshal(map[string]any{
		"community":    "new-community",
		"poll_interval": "120s",
	})

	w := doRequestWithBody(mux, "PUT", "/api/v1/devices/test-router", "test-key", string(body))
	if w.Code != http.StatusOK {
		t.Fatalf("status: want 200, got %d; body: %s", w.Code, w.Body.String())
	}

	result := parseJSON(t, w)
	if result["message"] != "device updated successfully" {
		t.Errorf("message: got %v", result["message"])
	}
}

func TestUpdateDeviceNotFound(t *testing.T) {
	_, mux := newTestServer()

	w := doRequestWithBody(mux, "PUT", "/api/v1/devices/nonexistent", "test-key", `{"community":"x"}`)
	if w.Code != http.StatusNotFound {
		t.Errorf("status: want 404, got %d", w.Code)
	}
}

func TestDeleteDevice(t *testing.T) {
	_, mux := newTestServer()

	w := doRequestWithBody(mux, "DELETE", "/api/v1/devices/test-switch", "test-key", "")
	if w.Code != http.StatusOK {
		t.Fatalf("status: want 200, got %d; body: %s", w.Code, w.Body.String())
	}

	// Verify device is gone
	w2 := doRequest(mux, "GET", "/api/v1/devices/test-switch", "test-key")
	if w2.Code != http.StatusNotFound {
		t.Errorf("after delete: want 404, got %d", w2.Code)
	}

	// Verify count
	w3 := doRequest(mux, "GET", "/api/v1/devices", "test-key")
	result := parseJSON(t, w3)
	if result["count"].(float64) != 1 {
		t.Errorf("count after delete: want 1, got %v", result["count"])
	}
}

func TestDeleteDeviceNotFound(t *testing.T) {
	_, mux := newTestServer()

	w := doRequestWithBody(mux, "DELETE", "/api/v1/devices/nonexistent", "test-key", "")
	if w.Code != http.StatusNotFound {
		t.Errorf("status: want 404, got %d", w.Code)
	}
}

// Ensure unused imports don't error
var _ = bytes.NewBuffer
