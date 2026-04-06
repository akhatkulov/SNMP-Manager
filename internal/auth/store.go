package auth

// store.go — JSON file-based user store with thread-safe CRUD operations.

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"
)

// UserStore manages users persisted in a JSON file.
type UserStore struct {
	mu       sync.RWMutex
	users    map[string]*User // key: user ID
	byName   map[string]*User // key: username (lowercase)
	filePath string
}

// NewUserStore creates a new UserStore. If the file doesn't exist,
// a default admin user is created.
func NewUserStore(filePath string) (*UserStore, error) {
	s := &UserStore{
		users:    make(map[string]*User),
		byName:   make(map[string]*User),
		filePath: filePath,
	}

	if err := s.load(); err != nil {
		if !os.IsNotExist(err) {
			return nil, fmt.Errorf("loading users file: %w", err)
		}
		// Create default admin user
		if err := s.createDefaultAdmin(); err != nil {
			return nil, fmt.Errorf("creating default admin: %w", err)
		}
	}

	return s, nil
}

// load reads users from the JSON file.
func (s *UserStore) load() error {
	data, err := os.ReadFile(s.filePath)
	if err != nil {
		return err
	}

	var users []*User
	if err := json.Unmarshal(data, &users); err != nil {
		return fmt.Errorf("parsing users file: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.users = make(map[string]*User, len(users))
	s.byName = make(map[string]*User, len(users))
	for _, u := range users {
		s.users[u.ID] = u
		s.byName[u.Username] = u
	}

	return nil
}

// save writes users to the JSON file.
func (s *UserStore) save() error {
	users := make([]*User, 0, len(s.users))
	for _, u := range s.users {
		users = append(users, u)
	}

	data, err := json.MarshalIndent(users, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling users: %w", err)
	}

	if err := os.WriteFile(s.filePath, data, 0600); err != nil {
		return fmt.Errorf("writing users file: %w", err)
	}

	return nil
}

// createDefaultAdmin creates the initial admin user.
func (s *UserStore) createDefaultAdmin() error {
	hash, err := HashPassword("admin123")
	if err != nil {
		return err
	}

	admin := &User{
		ID:           NewUserID(),
		Username:     "admin",
		PasswordHash: hash,
		Role:         RoleAdmin,
		Enabled:      true,
		CreatedAt:    time.Now().UTC(),
		UpdatedAt:    time.Now().UTC(),
	}

	s.mu.Lock()
	s.users[admin.ID] = admin
	s.byName[admin.Username] = admin
	s.mu.Unlock()

	return s.save()
}

// ── CRUD Operations ─────────────────────────────────────────────────────────

// Create adds a new user. Returns error if username exists.
func (s *UserStore) Create(username, password string, role Role, tenantID string) (*User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.byName[username]; exists {
		return nil, fmt.Errorf("username %q already exists", username)
	}

	if !IsValidRole(string(role)) {
		return nil, fmt.Errorf("invalid role: %q", role)
	}

	hash, err := HashPassword(password)
	if err != nil {
		return nil, fmt.Errorf("hashing password: %w", err)
	}

	user := &User{
		ID:           NewUserID(),
		Username:     username,
		PasswordHash: hash,
		Role:         role,
		TenantID:     tenantID,
		Enabled:      true,
		CreatedAt:    time.Now().UTC(),
		UpdatedAt:    time.Now().UTC(),
	}

	s.users[user.ID] = user
	s.byName[user.Username] = user

	if err := s.save(); err != nil {
		delete(s.users, user.ID)
		delete(s.byName, user.Username)
		return nil, err
	}

	return user, nil
}

// GetByUsername finds a user by username.
func (s *UserStore) GetByUsername(username string) (*User, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	u, ok := s.byName[username]
	return u, ok
}

// GetByID finds a user by ID.
func (s *UserStore) GetByID(id string) (*User, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	u, ok := s.users[id]
	return u, ok
}

// List returns all users (safe copies).
func (s *UserStore) List() []SafeUser {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]SafeUser, 0, len(s.users))
	for _, u := range s.users {
		result = append(result, u.Safe())
	}
	return result
}

// Update modifies a user's role, enabled status, or tenant.
func (s *UserStore) Update(id string, role *Role, enabled *bool, tenantID *string) (*User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	user, ok := s.users[id]
	if !ok {
		return nil, fmt.Errorf("user %q not found", id)
	}

	if role != nil {
		if !IsValidRole(string(*role)) {
			return nil, fmt.Errorf("invalid role: %q", *role)
		}
		user.Role = *role
	}
	if enabled != nil {
		user.Enabled = *enabled
	}
	if tenantID != nil {
		user.TenantID = *tenantID
	}
	user.UpdatedAt = time.Now().UTC()

	if err := s.save(); err != nil {
		return nil, err
	}

	return user, nil
}

// UpdatePassword changes a user's password.
func (s *UserStore) UpdatePassword(id, newPassword string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	user, ok := s.users[id]
	if !ok {
		return fmt.Errorf("user %q not found", id)
	}

	hash, err := HashPassword(newPassword)
	if err != nil {
		return err
	}
	user.PasswordHash = hash
	user.UpdatedAt = time.Now().UTC()

	return s.save()
}

// RecordLogin updates the last login time.
func (s *UserStore) RecordLogin(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if user, ok := s.users[id]; ok {
		user.LastLogin = time.Now().UTC()
		_ = s.save() // Best-effort
	}
}

// Delete removes a user. Cannot delete the last admin.
func (s *UserStore) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	user, ok := s.users[id]
	if !ok {
		return fmt.Errorf("user %q not found", id)
	}

	// Prevent deleting the last admin
	if user.Role == RoleAdmin {
		adminCount := 0
		for _, u := range s.users {
			if u.Role == RoleAdmin && u.Enabled {
				adminCount++
			}
		}
		if adminCount <= 1 {
			return fmt.Errorf("cannot delete the last admin user")
		}
	}

	delete(s.users, id)
	delete(s.byName, user.Username)

	return s.save()
}

// Count returns the number of users.
func (s *UserStore) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.users)
}

// Authenticate verifies credentials and returns the user if valid.
func (s *UserStore) Authenticate(username, password string) (*User, error) {
	user, ok := s.GetByUsername(username)
	if !ok {
		return nil, fmt.Errorf("invalid credentials")
	}

	if !user.Enabled {
		return nil, fmt.Errorf("account disabled")
	}

	if !VerifyPassword(password, user.PasswordHash) {
		return nil, fmt.Errorf("invalid credentials")
	}

	s.RecordLogin(user.ID)
	return user, nil
}
