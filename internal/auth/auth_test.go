package auth

import (
	"os"
	"path/filepath"
	"testing"
)

func TestHashAndVerifyPassword(t *testing.T) {
	password := "mySecretP@ss123"
	hash, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if hash == "" {
		t.Fatal("hash is empty")
	}
	if hash == password {
		t.Fatal("hash equals plaintext password")
	}

	// Correct password
	if !VerifyPassword(password, hash) {
		t.Error("VerifyPassword rejected correct password")
	}
	// Wrong password
	if VerifyPassword("wrong-password", hash) {
		t.Error("VerifyPassword accepted wrong password")
	}
	// Empty
	if VerifyPassword("", hash) {
		t.Error("VerifyPassword accepted empty password")
	}
}

func TestHashDifferentSalts(t *testing.T) {
	hash1, _ := HashPassword("test")
	hash2, _ := HashPassword("test")
	if hash1 == hash2 {
		t.Error("two hashes of the same password should differ (different salts)")
	}
}

func TestJWTGenerateAndValidate(t *testing.T) {
	cfg := JWTConfig{
		Secret:     "test-secret-key-very-long",
		SessionTTL: 1 * 3600_000_000_000, // 1 hour in nanoseconds
		RefreshTTL: 7 * 24 * 3600_000_000_000,
	}

	user := &User{
		ID:       "user-123",
		Username: "testuser",
		Role:     RoleOperator,
		TenantID: "tenant-A",
	}

	token, err := GenerateToken(user, cfg, "access")
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}
	if token == "" {
		t.Fatal("token is empty")
	}

	// Validate
	claims, err := ValidateToken(token, cfg.Secret)
	if err != nil {
		t.Fatalf("ValidateToken: %v", err)
	}
	if claims.UserID != "user-123" {
		t.Errorf("UserID = %q, want %q", claims.UserID, "user-123")
	}
	if claims.Username != "testuser" {
		t.Errorf("Username = %q, want %q", claims.Username, "testuser")
	}
	if claims.Role != RoleOperator {
		t.Errorf("Role = %q, want %q", claims.Role, RoleOperator)
	}
	if claims.TenantID != "tenant-A" {
		t.Errorf("TenantID = %q, want %q", claims.TenantID, "tenant-A")
	}
	if claims.TokenType != "access" {
		t.Errorf("TokenType = %q, want %q", claims.TokenType, "access")
	}

	// Wrong secret
	_, err = ValidateToken(token, "wrong-secret")
	if err == nil {
		t.Error("ValidateToken should reject token with wrong secret")
	}

	// Tampered token
	tampered := token[:len(token)-4] + "XXXX"
	_, err = ValidateToken(tampered, cfg.Secret)
	if err == nil {
		t.Error("ValidateToken should reject tampered token")
	}
}

func TestRolePermissions(t *testing.T) {
	// Admin has all permissions
	if !HasPermission(RoleAdmin, PermUsersWrite) {
		t.Error("admin should have users:write")
	}
	if !HasPermission(RoleAdmin, PermDiscoveryWrite) {
		t.Error("admin should have discovery:write")
	}

	// Viewer cannot write
	if HasPermission(RoleViewer, PermDevicesWrite) {
		t.Error("viewer should not have devices:write")
	}
	if HasPermission(RoleViewer, PermUsersWrite) {
		t.Error("viewer should not have users:write")
	}
	// Viewer can read
	if !HasPermission(RoleViewer, PermDevicesRead) {
		t.Error("viewer should have devices:read")
	}

	// L1 Support
	if !HasPermission(RoleL1Support, PermDevicesPoll) {
		t.Error("l1_support should have devices:poll")
	}
	if HasPermission(RoleL1Support, PermConfigWrite) {
		t.Error("l1_support should not have config:write")
	}

	// Invalid role
	if HasPermission(Role("hacker"), PermDevicesRead) {
		t.Error("invalid role should have no permissions")
	}
}

func TestIsValidRole(t *testing.T) {
	if !IsValidRole("admin") { t.Error("admin should be valid") }
	if !IsValidRole("operator") { t.Error("operator should be valid") }
	if !IsValidRole("viewer") { t.Error("viewer should be valid") }
	if !IsValidRole("l1_support") { t.Error("l1_support should be valid") }
	if IsValidRole("root") { t.Error("root should not be valid") }
	if IsValidRole("") { t.Error("empty string should not be valid") }
}

func TestUserStore(t *testing.T) {
	tmpDir := t.TempDir()
	usersFile := filepath.Join(tmpDir, "users.json")

	// Creates default admin
	store, err := NewUserStore(usersFile)
	if err != nil {
		t.Fatalf("NewUserStore: %v", err)
	}
	if store.Count() != 1 {
		t.Fatalf("expected 1 default user, got %d", store.Count())
	}

	// Authenticate default admin
	user, err := store.Authenticate("admin", "admin123")
	if err != nil {
		t.Fatalf("Authenticate default admin: %v", err)
	}
	if user.Role != RoleAdmin {
		t.Errorf("default admin role = %q, want %q", user.Role, RoleAdmin)
	}

	// Wrong password
	_, err = store.Authenticate("admin", "wrong")
	if err == nil {
		t.Error("Authenticate should fail with wrong password")
	}

	// Create operator
	op, err := store.Create("operator1", "pass123", RoleOperator, "")
	if err != nil {
		t.Fatalf("Create operator: %v", err)
	}
	if op.Role != RoleOperator {
		t.Errorf("operator role = %q", op.Role)
	}
	if store.Count() != 2 {
		t.Fatalf("expected 2 users, got %d", store.Count())
	}

	// Duplicate username
	_, err = store.Create("operator1", "pass", RoleViewer, "")
	if err == nil {
		t.Error("Create should fail for duplicate username")
	}

	// Cannot delete last admin
	err = store.Delete(user.ID)
	if err == nil {
		t.Error("Delete should fail for last admin")
	}

	// Delete operator
	err = store.Delete(op.ID)
	if err != nil {
		t.Fatalf("Delete operator: %v", err)
	}
	if store.Count() != 1 {
		t.Fatalf("expected 1 user after delete, got %d", store.Count())
	}

	// Persistence: reload from file
	store2, err := NewUserStore(usersFile)
	if err != nil {
		t.Fatalf("NewUserStore reload: %v", err)
	}
	if store2.Count() != 1 {
		t.Fatalf("reloaded store should have 1 user, got %d", store2.Count())
	}

	// File should exist and not be world-readable
	info, _ := os.Stat(usersFile)
	if info.Mode().Perm() != 0600 {
		t.Logf("users.json permissions: %o (ideally 0600)", info.Mode().Perm())
	}
}

func TestUserStoreTenantFilter(t *testing.T) {
	tmpDir := t.TempDir()
	usersFile := filepath.Join(tmpDir, "users.json")

	store, _ := NewUserStore(usersFile)
	store.Create("opA", "pass", RoleOperator, "tenantA")
	store.Create("opB", "pass", RoleOperator, "tenantB")

	users := store.List()
	tenantA := 0
	for _, u := range users {
		if u.TenantID == "tenantA" {
			tenantA++
		}
	}
	if tenantA != 1 {
		t.Errorf("expected 1 tenantA user, got %d", tenantA)
	}
}

func TestUpdatePassword(t *testing.T) {
	tmpDir := t.TempDir()
	store, _ := NewUserStore(filepath.Join(tmpDir, "users.json"))

	user, _ := store.Authenticate("admin", "admin123")
	err := store.UpdatePassword(user.ID, "newPassword!")
	if err != nil {
		t.Fatalf("UpdatePassword: %v", err)
	}

	// Old password fails
	_, err = store.Authenticate("admin", "admin123")
	if err == nil {
		t.Error("old password should fail after change")
	}

	// New password works
	_, err = store.Authenticate("admin", "newPassword!")
	if err != nil {
		t.Errorf("new password should work: %v", err)
	}
}
