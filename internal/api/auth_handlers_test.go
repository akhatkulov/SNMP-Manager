package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/me262/snmp-manager/internal/auth"
	"github.com/me262/snmp-manager/internal/config"
	"github.com/rs/zerolog"
)

func setupAuthServer(t *testing.T) (*Server, func()) {
	log := zerolog.Nop()
	cfg := config.APIConfig{Enabled: true}
	fullCfg := &config.Config{}

	// Create temp user store path (don't create the file)
	tmpFile, err := os.CreateTemp("", "users_test_*.json")
	if err != nil {
		t.Fatal(err)
	}
	tmpFileName := tmpFile.Name()
	tmpFile.Close()
	os.Remove(tmpFileName) // ensure it does not exist so NewUserStore creates it

	userStore, err := auth.NewUserStore(tmpFileName)
	if err != nil {
		t.Fatal(err)
	}

	jwtCfg := auth.JWTConfig{Secret: "test-secret-key-12345"}
	
	server := NewServer(log, cfg, fullCfg, "", nil, nil, nil, nil, nil, nil)
	server.SetUserStore(userStore)
	server.SetJWTConfig(jwtCfg)

	cleanup := func() {
		os.Remove(tmpFileName)
	}

	return server, cleanup
}

func TestAuthLogin(t *testing.T) {
	s, cleanup := setupAuthServer(t)
	defer cleanup()

	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/auth/login", s.handleAuthLogin)

	// Since we use NewUserStore, it creates a default admin/admin123 user
	bodyBytes, _ := json.Marshal(map[string]interface{}{
		"username": "admin",
		"password": "admin123",
	})
	reqValid := httptest.NewRequest("POST", "/api/v1/auth/login", bytes.NewReader(bodyBytes))
	wValid := httptest.NewRecorder()
	mux.ServeHTTP(wValid, reqValid)

	if wValid.Code != http.StatusOK {
		t.Fatalf("Expected 200 OK for valid login, got %d. Body: %s", wValid.Code, wValid.Body.String())
	}

	var resp map[string]interface{}
	json.NewDecoder(wValid.Body).Decode(&resp)
	if resp["access_token"] == nil {
		t.Errorf("Expected 'access_token' in response")
	}

	// Test Invalid Login
	bodyBytesInvalid, _ := json.Marshal(map[string]interface{}{
		"username": "admin",
		"password": "wrongpassword",
	})
	reqInvalid := httptest.NewRequest("POST", "/api/v1/auth/login", bytes.NewReader(bodyBytesInvalid))
	wInvalid := httptest.NewRecorder()
	mux.ServeHTTP(wInvalid, reqInvalid)

	if wInvalid.Code != http.StatusUnauthorized {
		t.Fatalf("Expected 401 Unauthorized, got %d", wInvalid.Code)
	}

	// Test Malformed Request
	reqMalformed := httptest.NewRequest("POST", "/api/v1/auth/login", strings.NewReader(`"invalid"`))
	wMalformed := httptest.NewRecorder()
	mux.ServeHTTP(wMalformed, reqMalformed)
	if wMalformed.Code != http.StatusBadRequest {
		t.Fatalf("Expected 400 Bad Request, got %d", wMalformed.Code)
	}
}
