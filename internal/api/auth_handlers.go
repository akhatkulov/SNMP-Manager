package api

// auth_handlers.go — REST API handlers for authentication and user management.
//
// Endpoints:
//   POST /api/v1/auth/login       — Login with username/password, get JWT
//   POST /api/v1/auth/refresh     — Refresh an access token
//   GET  /api/v1/auth/me          — Get current user profile
//   PUT  /api/v1/auth/password    — Change own password
//   GET  /api/v1/users            — [admin] List all users
//   POST /api/v1/users            — [admin] Create a new user
//   PUT  /api/v1/users/{id}       — [admin] Update a user
//   DELETE /api/v1/users/{id}     — [admin] Delete a user

import (
	"encoding/json"
	"net/http"

	"github.com/me262/snmp-manager/internal/auth"
)

// ── Login ─────────────────────────────────────────────────────────────────────

func (s *Server) handleAuthLogin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	if req.Username == "" || req.Password == "" {
		s.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "username and password required"})
		return
	}

	// Try RBAC user store first
	if s.userStore != nil {
		user, err := s.userStore.Authenticate(req.Username, req.Password)
		if err == nil {
			// Generate JWT tokens
			accessToken, err := auth.GenerateToken(user, s.jwtConfig, "access")
			if err != nil {
				s.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "token generation failed"})
				return
			}
			refreshToken, err := auth.GenerateToken(user, s.jwtConfig, "refresh")
			if err != nil {
				s.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "token generation failed"})
				return
			}

			s.writeJSON(w, http.StatusOK, map[string]any{
				"access_token":  accessToken,
				"refresh_token": refreshToken,
				"token_type":    "Bearer",
				"expires_in":    int(s.jwtConfig.SessionTTL.Seconds()),
				"user":          user.Safe(),
			})
			return
		}
	}

	// Fallback: admin panel credentials (backward compat)
	if req.Username == s.cfg.AdminPanel.Username && req.Password == s.cfg.AdminPanel.Password {
		// Legacy login — create a temporary admin user for JWT
		tmpUser := &auth.User{
			ID:       "legacy-admin",
			Username: req.Username,
			Role:     auth.RoleAdmin,
		}
		accessToken, err := auth.GenerateToken(tmpUser, s.jwtConfig, "access")
		if err != nil {
			s.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "token generation failed"})
			return
		}

		s.writeJSON(w, http.StatusOK, map[string]any{
			"access_token": accessToken,
			"token_type":   "Bearer",
			"expires_in":   int(s.jwtConfig.SessionTTL.Seconds()),
			"user": map[string]any{
				"id":       "legacy-admin",
				"username": req.Username,
				"role":     "admin",
			},
		})
		return
	}

	s.writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid credentials"})
}

// ── Refresh Token ─────────────────────────────────────────────────────────────

func (s *Server) handleAuthRefresh(w http.ResponseWriter, r *http.Request) {
	var req struct {
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.RefreshToken == "" {
		s.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "refresh_token required"})
		return
	}

	claims, err := auth.ValidateToken(req.RefreshToken, s.jwtConfig.Secret)
	if err != nil {
		s.writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid refresh token: " + err.Error()})
		return
	}
	if claims.TokenType != "refresh" {
		s.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "not a refresh token"})
		return
	}

	// Get fresh user data
	if s.userStore != nil {
		user, ok := s.userStore.GetByID(claims.UserID)
		if !ok || !user.Enabled {
			s.writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "user not found or disabled"})
			return
		}
		accessToken, err := auth.GenerateToken(user, s.jwtConfig, "access")
		if err != nil {
			s.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "token generation failed"})
			return
		}

		s.writeJSON(w, http.StatusOK, map[string]any{
			"access_token": accessToken,
			"token_type":   "Bearer",
			"expires_in":   int(s.jwtConfig.SessionTTL.Seconds()),
		})
		return
	}

	s.writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "user store not available"})
}

// ── Current User ──────────────────────────────────────────────────────────────

func (s *Server) handleAuthMe(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.GetUserFromContext(r.Context())
	if !ok {
		s.writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}

	result := map[string]any{
		"id":       claims.UserID,
		"username": claims.Username,
		"role":     claims.Role,
	}
	if claims.TenantID != "" {
		result["tenant_id"] = claims.TenantID
	}

	// Get permissions for the role
	perms := []string{}
	for _, p := range []auth.Permission{
		auth.PermDevicesRead, auth.PermDevicesWrite, auth.PermDevicesPoll,
		auth.PermMonitoringRead, auth.PermConfigRead, auth.PermConfigWrite,
		auth.PermDiscoveryRead, auth.PermDiscoveryWrite,
		auth.PermUsersRead, auth.PermUsersWrite,
		auth.PermTemplatesRead, auth.PermTemplatesWrite,
		auth.PermEventsRead, auth.PermAlertsRead,
		auth.PermTopologyRead, auth.PermAPIDocsRead,
	} {
		if auth.HasPermission(claims.Role, p) {
			perms = append(perms, string(p))
		}
	}
	result["permissions"] = perms

	s.writeJSON(w, http.StatusOK, result)
}

// ── Change Password ───────────────────────────────────────────────────────────

func (s *Server) handleAuthPasswordChange(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.GetUserFromContext(r.Context())
	if !ok {
		s.writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}

	var req struct {
		OldPassword string `json:"old_password"`
		NewPassword string `json:"new_password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}
	if req.NewPassword == "" || len(req.NewPassword) < 6 {
		s.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "new password must be at least 6 characters"})
		return
	}

	if s.userStore == nil {
		s.writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "user store not available"})
		return
	}

	// Verify old password
	_, err := s.userStore.Authenticate(claims.Username, req.OldPassword)
	if err != nil {
		s.writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "current password is incorrect"})
		return
	}

	if err := s.userStore.UpdatePassword(claims.UserID, req.NewPassword); err != nil {
		s.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	s.writeJSON(w, http.StatusOK, map[string]string{"message": "password updated successfully"})
}

// ── List Users [admin] ────────────────────────────────────────────────────────

func (s *Server) handleListUsers(w http.ResponseWriter, r *http.Request) {
	if s.userStore == nil {
		s.writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "user store not available"})
		return
	}

	users := s.userStore.List()
	s.writeJSON(w, http.StatusOK, map[string]any{
		"count": len(users),
		"users": users,
	})
}

// ── Create User [admin] ──────────────────────────────────────────────────────

func (s *Server) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	if s.userStore == nil {
		s.writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "user store not available"})
		return
	}

	var req struct {
		Username string    `json:"username"`
		Password string    `json:"password"`
		Role     auth.Role `json:"role"`
		TenantID string    `json:"tenant_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}
	if req.Username == "" || req.Password == "" {
		s.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "username and password required"})
		return
	}
	if len(req.Password) < 6 {
		s.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "password must be at least 6 characters"})
		return
	}
	if req.Role == "" {
		req.Role = auth.RoleViewer
	}

	user, err := s.userStore.Create(req.Username, req.Password, req.Role, req.TenantID)
	if err != nil {
		s.writeJSON(w, http.StatusConflict, map[string]string{"error": err.Error()})
		return
	}

	s.log.Info().Str("username", user.Username).Str("role", string(user.Role)).Msg("user created")
	s.writeJSON(w, http.StatusCreated, map[string]any{
		"message": "user created",
		"user":    user.Safe(),
	})
}

// ── Update User [admin] ──────────────────────────────────────────────────────

func (s *Server) handleUpdateUser(w http.ResponseWriter, r *http.Request) {
	if s.userStore == nil {
		s.writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "user store not available"})
		return
	}

	id := r.PathValue("id")
	var req struct {
		Role     *auth.Role `json:"role,omitempty"`
		Enabled  *bool      `json:"enabled,omitempty"`
		TenantID *string    `json:"tenant_id,omitempty"`
		Password *string    `json:"password,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	// Update password if provided
	if req.Password != nil && *req.Password != "" {
		if len(*req.Password) < 6 {
			s.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "password must be at least 6 characters"})
			return
		}
		if err := s.userStore.UpdatePassword(id, *req.Password); err != nil {
			s.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
	}

	user, err := s.userStore.Update(id, req.Role, req.Enabled, req.TenantID)
	if err != nil {
		s.writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
		return
	}

	s.log.Info().Str("id", id).Str("role", string(user.Role)).Msg("user updated")
	s.writeJSON(w, http.StatusOK, map[string]any{
		"message": "user updated",
		"user":    user.Safe(),
	})
}

// ── Delete User [admin] ──────────────────────────────────────────────────────

func (s *Server) handleDeleteUser(w http.ResponseWriter, r *http.Request) {
	if s.userStore == nil {
		s.writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "user store not available"})
		return
	}

	id := r.PathValue("id")

	// Prevent deleting yourself
	claims, _ := auth.GetUserFromContext(r.Context())
	if claims != nil && claims.UserID == id {
		s.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "cannot delete your own account"})
		return
	}

	if err := s.userStore.Delete(id); err != nil {
		s.writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	s.log.Info().Str("id", id).Msg("user deleted")
	s.writeJSON(w, http.StatusOK, map[string]string{"message": "user deleted"})
}
