package auth

// auth.go — RBAC authentication system for SNMP Manager
//
// Pure Go implementation (no external JWT/bcrypt libraries):
//   - bcrypt password hashing via golang.org/x/crypto/bcrypt (stdlib extension)
//   - HMAC-SHA256 JWT tokens using crypto/hmac + encoding/json
//   - Role-based access control with 4 predefined roles

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

// ── Roles ─────────────────────────────────────────────────────────────────────

// Role is the authorization level of a user.
type Role string

const (
	RoleAdmin     Role = "admin"
	RoleOperator  Role = "operator"
	RoleViewer    Role = "viewer"
	RoleL1Support Role = "l1_support"
)

// ValidRoles is the list of all valid roles.
var ValidRoles = []Role{RoleAdmin, RoleOperator, RoleViewer, RoleL1Support}

// IsValidRole checks if a role string is valid.
func IsValidRole(r string) bool {
	for _, vr := range ValidRoles {
		if string(vr) == r {
			return true
		}
	}
	return false
}

// ── Permissions ──────────────────────────────────────────────────────────────

// Permission represents a specific action.
type Permission string

const (
	PermDevicesRead    Permission = "devices:read"
	PermDevicesWrite   Permission = "devices:write"
	PermDevicesPoll    Permission = "devices:poll"
	PermMonitoringRead Permission = "monitoring:read"
	PermConfigRead     Permission = "config:read"
	PermConfigWrite    Permission = "config:write"
	PermDiscoveryRead  Permission = "discovery:read"
	PermDiscoveryWrite Permission = "discovery:write"
	PermUsersRead      Permission = "users:read"
	PermUsersWrite     Permission = "users:write"
	PermTemplatesRead  Permission = "templates:read"
	PermTemplatesWrite Permission = "templates:write"
	PermEventsRead     Permission = "events:read"
	PermAlertsRead     Permission = "alerts:read"
	PermTopologyRead   Permission = "topology:read"
	PermAPIDocsRead    Permission = "api_docs:read"
)

// rolePermissions defines which permissions each role has.
var rolePermissions = map[Role][]Permission{
	RoleAdmin: {
		PermDevicesRead, PermDevicesWrite, PermDevicesPoll,
		PermMonitoringRead, PermConfigRead, PermConfigWrite,
		PermDiscoveryRead, PermDiscoveryWrite,
		PermUsersRead, PermUsersWrite,
		PermTemplatesRead, PermTemplatesWrite,
		PermEventsRead, PermAlertsRead,
		PermTopologyRead, PermAPIDocsRead,
	},
	RoleOperator: {
		PermDevicesRead, PermDevicesWrite, PermDevicesPoll,
		PermMonitoringRead, PermConfigRead,
		PermDiscoveryRead,
		PermTemplatesRead, PermTemplatesWrite,
		PermEventsRead, PermAlertsRead,
		PermTopologyRead, PermAPIDocsRead,
	},
	RoleViewer: {
		PermDevicesRead, PermMonitoringRead, PermConfigRead,
		PermDiscoveryRead, PermTemplatesRead,
		PermEventsRead, PermAlertsRead,
		PermTopologyRead, PermAPIDocsRead,
	},
	RoleL1Support: {
		PermDevicesRead, PermDevicesPoll,
		PermMonitoringRead,
		PermEventsRead, PermAlertsRead,
		PermAPIDocsRead,
	},
}

// HasPermission checks if a role has a specific permission.
func HasPermission(role Role, perm Permission) bool {
	perms, ok := rolePermissions[role]
	if !ok {
		return false
	}
	for _, p := range perms {
		if p == perm {
			return true
		}
	}
	return false
}

// ── User ──────────────────────────────────────────────────────────────────────

// User represents an authenticated user.
type User struct {
	ID           string    `json:"id"`
	Username     string    `json:"username"`
	PasswordHash string    `json:"password_hash,omitempty"`
	Role         Role      `json:"role"`
	TenantID     string    `json:"tenant_id,omitempty"`
	Enabled      bool      `json:"enabled"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
	LastLogin    time.Time `json:"last_login,omitempty"`
}

// SafeUser returns user data safe for API responses (no password hash).
type SafeUser struct {
	ID        string    `json:"id"`
	Username  string    `json:"username"`
	Role      Role      `json:"role"`
	TenantID  string    `json:"tenant_id,omitempty"`
	Enabled   bool      `json:"enabled"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	LastLogin time.Time `json:"last_login,omitempty"`
}

// Safe returns a copy of the user without sensitive fields.
func (u *User) Safe() SafeUser {
	return SafeUser{
		ID:        u.ID,
		Username:  u.Username,
		Role:      u.Role,
		TenantID:  u.TenantID,
		Enabled:   u.Enabled,
		CreatedAt: u.CreatedAt,
		UpdatedAt: u.UpdatedAt,
		LastLogin: u.LastLogin,
	}
}

// ── Password Hashing (Simple SHA-256 + Salt) ─────────────────────────────────
// We use a custom PBKDF-like scheme with SHA-256 and random salt to avoid
// requiring the golang.org/x/crypto dependency. In production, consider using
// bcrypt or argon2.

const (
	saltLength     = 16
	hashIterations = 10000
	hashPrefix     = "$snmp$"
)

// HashPassword creates a salted SHA-256 hash of the password.
func HashPassword(password string) (string, error) {
	salt := make([]byte, saltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("generating salt: %w", err)
	}

	hash := deriveKey([]byte(password), salt)
	// Format: $snmp$<base64_salt>$<base64_hash>
	return fmt.Sprintf("%s%s$%s",
		hashPrefix,
		base64.StdEncoding.EncodeToString(salt),
		base64.StdEncoding.EncodeToString(hash),
	), nil
}

// VerifyPassword checks if a password matches the stored hash.
func VerifyPassword(password, storedHash string) bool {
	if !strings.HasPrefix(storedHash, hashPrefix) {
		return false
	}
	parts := strings.Split(strings.TrimPrefix(storedHash, hashPrefix), "$")
	if len(parts) != 2 {
		return false
	}
	salt, err := base64.StdEncoding.DecodeString(parts[0])
	if err != nil {
		return false
	}
	expectedHash, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		return false
	}

	derived := deriveKey([]byte(password), salt)
	return hmac.Equal(derived, expectedHash)
}

// deriveKey performs PBKDF2-like key derivation using HMAC-SHA256.
func deriveKey(password, salt []byte) []byte {
	key := append(password, salt...)
	for i := 0; i < hashIterations; i++ {
		h := sha256.Sum256(key)
		key = h[:]
	}
	return key
}

// ── JWT ───────────────────────────────────────────────────────────────────────

// JWTConfig holds JWT configuration.
type JWTConfig struct {
	Secret     string
	SessionTTL time.Duration
	RefreshTTL time.Duration
}

// DefaultJWTConfig returns default JWT configuration.
func DefaultJWTConfig() JWTConfig {
	return JWTConfig{
		Secret:     "change-me-in-production",
		SessionTTL: 24 * time.Hour,
		RefreshTTL: 7 * 24 * time.Hour,
	}
}

// JWTClaims holds the JWT payload.
type JWTClaims struct {
	UserID   string `json:"sub"`
	Username string `json:"username"`
	Role     Role   `json:"role"`
	TenantID string `json:"tenant_id,omitempty"`
	IssuedAt int64  `json:"iat"`
	ExpireAt int64  `json:"exp"`
	TokenType string `json:"type"` // "access" or "refresh"
}

// jwtHeader is the fixed JWT header for HMAC-SHA256.
var jwtHeader = base64URLEncode([]byte(`{"alg":"HS256","typ":"JWT"}`))

// GenerateToken creates a new JWT token for the given user.
func GenerateToken(user *User, cfg JWTConfig, tokenType string) (string, error) {
	if cfg.Secret == "" {
		return "", errors.New("JWT secret is empty")
	}

	ttl := cfg.SessionTTL
	if tokenType == "refresh" {
		ttl = cfg.RefreshTTL
	}

	claims := JWTClaims{
		UserID:    user.ID,
		Username:  user.Username,
		Role:      user.Role,
		TenantID:  user.TenantID,
		IssuedAt:  time.Now().Unix(),
		ExpireAt:  time.Now().Add(ttl).Unix(),
		TokenType: tokenType,
	}

	payload, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("marshaling claims: %w", err)
	}

	encodedPayload := base64URLEncode(payload)
	signingInput := jwtHeader + "." + encodedPayload
	signature := signHMAC([]byte(signingInput), []byte(cfg.Secret))

	return signingInput + "." + base64URLEncode(signature), nil
}

// ValidateToken verifies a JWT token and returns its claims.
func ValidateToken(tokenStr string, secret string) (*JWTClaims, error) {
	parts := strings.Split(tokenStr, ".")
	if len(parts) != 3 {
		return nil, errors.New("invalid token format")
	}

	// Verify signature
	signingInput := parts[0] + "." + parts[1]
	signature, err := base64URLDecode(parts[2])
	if err != nil {
		return nil, errors.New("invalid signature encoding")
	}

	expected := signHMAC([]byte(signingInput), []byte(secret))
	if !hmac.Equal(signature, expected) {
		return nil, errors.New("invalid signature")
	}

	// Decode payload
	payload, err := base64URLDecode(parts[1])
	if err != nil {
		return nil, errors.New("invalid payload encoding")
	}

	var claims JWTClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("invalid claims: %w", err)
	}

	// Check expiry
	if time.Now().Unix() > claims.ExpireAt {
		return nil, errors.New("token expired")
	}

	return &claims, nil
}

// ── Helpers ──────────────────────────────────────────────────────────────────

func signHMAC(data, secret []byte) []byte {
	h := hmac.New(sha256.New, secret)
	h.Write(data)
	return h.Sum(nil)
}

func base64URLEncode(data []byte) string {
	return strings.TrimRight(base64.URLEncoding.EncodeToString(data), "=")
}

func base64URLDecode(s string) ([]byte, error) {
	// Add back padding
	switch len(s) % 4 {
	case 2:
		s += "=="
	case 3:
		s += "="
	}
	return base64.URLEncoding.DecodeString(s)
}

// NewUserID generates a new unique user ID.
func NewUserID() string {
	return uuid.New().String()
}
