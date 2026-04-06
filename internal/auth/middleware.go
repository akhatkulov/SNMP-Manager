package auth

// middleware.go — HTTP authentication middleware supporting both JWT and API key.

import (
	"context"
	"net/http"
	"strings"
)

// contextKey is a private type for context keys.
type contextKey string

const (
	// UserContextKey is the context key for the authenticated user claims.
	UserContextKey contextKey = "auth_user"
)

// GetUserFromContext extracts the JWT claims from the request context.
func GetUserFromContext(ctx context.Context) (*JWTClaims, bool) {
	claims, ok := ctx.Value(UserContextKey).(*JWTClaims)
	return claims, ok
}

// Middleware provides HTTP authentication middleware.
type Middleware struct {
	jwtSecret string
	apiKeys   map[string]bool
}

// NewMiddleware creates a new auth middleware.
func NewMiddleware(jwtSecret string, apiKeys []string) *Middleware {
	keyMap := make(map[string]bool, len(apiKeys))
	for _, k := range apiKeys {
		if k != "" {
			keyMap[k] = true
		}
	}
	return &Middleware{
		jwtSecret: jwtSecret,
		apiKeys:   keyMap,
	}
}

// Authenticate is the main auth middleware. It supports:
// 1. Bearer JWT token in Authorization header
// 2. API key in X-API-Key header (backward compatibility)
// If neither is provided, returns 401.
func (m *Middleware) Authenticate(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Try JWT first
		if authHeader := r.Header.Get("Authorization"); authHeader != "" {
			if strings.HasPrefix(authHeader, "Bearer ") {
				tokenStr := strings.TrimPrefix(authHeader, "Bearer ")
				claims, err := ValidateToken(tokenStr, m.jwtSecret)
				if err == nil {
					ctx := context.WithValue(r.Context(), UserContextKey, claims)
					next(w, r.WithContext(ctx))
					return
				}
				// Invalid JWT — fall through to API key check
			}
		}

		// Try API key
		if apiKey := r.Header.Get("X-API-Key"); apiKey != "" {
			if m.apiKeys[apiKey] {
				// API key auth → treat as admin role
				claims := &JWTClaims{
					UserID:   "api-key-user",
					Username: "api-key",
					Role:     RoleAdmin,
				}
				ctx := context.WithValue(r.Context(), UserContextKey, claims)
				next(w, r.WithContext(ctx))
				return
			}
		}

		// No valid auth
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
	}
}

// RequireRole wraps a handler and checks that the user has the required role permission.
func (m *Middleware) RequireRole(roles ...Role) func(http.HandlerFunc) http.HandlerFunc {
	roleSet := make(map[Role]bool, len(roles))
	for _, r := range roles {
		roleSet[r] = true
	}

	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			claims, ok := GetUserFromContext(r.Context())
			if !ok {
				http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
				return
			}
			if !roleSet[claims.Role] {
				http.Error(w, `{"error":"forbidden: insufficient permissions"}`, http.StatusForbidden)
				return
			}
			next(w, r)
		}
	}
}

// RequirePermission wraps a handler and checks that the user role has the required permission.
func (m *Middleware) RequirePermission(perm Permission) func(http.HandlerFunc) http.HandlerFunc {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			claims, ok := GetUserFromContext(r.Context())
			if !ok {
				http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
				return
			}
			if !HasPermission(claims.Role, perm) {
				http.Error(w, `{"error":"forbidden: insufficient permissions"}`, http.StatusForbidden)
				return
			}
			next(w, r)
		}
	}
}
