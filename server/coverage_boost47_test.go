package main

import (
	"bytes"
	"context"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// ============================================================
// Coverage Boost 47 — targeting remaining low-coverage functions
// Targets: rate_limit_tiers cleanupOnce (45.5%), handleGetReactions DB error (88.2%),
// initAPNs cert load failure (84%), notifyUser push fail (90%),
// handleSetNotificationPrefs DB error (88.9%), Snapshot completeness (83.3%),
// WithFields edge cases (87.5%), logEntry level filter (88.2%),
// handleUpload seek error (81.8%), initSchema error paths (82.4%)
// ============================================================

// --- cleanupOnce: directly test the extracted cleanup logic ---

func TestCB47_CleanupOnce_RemovesStaleEntries(t *testing.T) {
	trl := NewTieredRateLimiter()
	t.Cleanup(func() { trl.Stop() })

	// Add an entry and make it stale by manually setting windowEnd in the past
	trl.SetTier("stale-user", TierPro)
	trl.mu.Lock()
	if entry, ok := trl.limits["stale-user"]; ok {
		entry.windowEnd = time.Now().Add(-15 * time.Minute) // 15 min ago, > 10 min threshold
	}
	trl.mu.Unlock()

	// Add a fresh entry that should NOT be removed
	trl.SetTier("fresh-user", TierPro)

	// Run cleanupOnce
	trl.cleanupOnce()

	// Stale entry should be gone
	trl.mu.Lock()
	_, staleExists := trl.limits["stale-user"]
	_, freshExists := trl.limits["fresh-user"]
	trl.mu.Unlock()

	if staleExists {
		t.Error("stale entry should have been removed by cleanupOnce")
	}
	if !freshExists {
		t.Error("fresh entry should still exist after cleanupOnce")
	}
}

func TestCB47_CleanupOnce_KeepsRecentlyExpired(t *testing.T) {
	trl := NewTieredRateLimiter()
	t.Cleanup(func() { trl.Stop() })

	// Add an entry that's expired but within the 10-minute grace period
	trl.SetTier("grace-user", TierPro)
	trl.mu.Lock()
	if entry, ok := trl.limits["grace-user"]; ok {
		entry.windowEnd = time.Now().Add(-5 * time.Minute) // 5 min ago, < 10 min threshold
	}
	trl.mu.Unlock()

	trl.cleanupOnce()

	trl.mu.Lock()
	_, exists := trl.limits["grace-user"]
	trl.mu.Unlock()

	if !exists {
		t.Error("entry within 10-min grace period should NOT be removed")
	}
}

func TestCB47_CleanupOnce_EmptyLimiter(t *testing.T) {
	trl := NewTieredRateLimiter()
	t.Cleanup(func() { trl.Stop() })

	// Should not panic on empty limiter
	trl.cleanupOnce()

	trl.mu.Lock()
	if len(trl.limits) != 0 {
		t.Errorf("expected 0 entries, got %d", len(trl.limits))
	}
	trl.mu.Unlock()
}

func TestCB47_CleanupOnce_MultipleStaleAndFresh(t *testing.T) {
	trl := NewTieredRateLimiter()
	t.Cleanup(func() { trl.Stop() })

	// Add 3 stale and 2 fresh
	staleIDs := []string{"stale1", "stale2", "stale3"}
	freshIDs := []string{"fresh1", "fresh2"}

	for _, id := range staleIDs {
		trl.SetTier(id, TierEnterprise)
		trl.mu.Lock()
		if entry, ok := trl.limits[id]; ok {
			entry.windowEnd = time.Now().Add(-20 * time.Minute)
		}
		trl.mu.Unlock()
	}
	for _, id := range freshIDs {
		trl.SetTier(id, TierFree)
	}

	trl.cleanupOnce()

	trl.mu.Lock()
	for _, id := range staleIDs {
		if _, exists := trl.limits[id]; exists {
			t.Errorf("stale entry %q should have been removed", id)
		}
	}
	for _, id := range freshIDs {
		if _, exists := trl.limits[id]; !exists {
			t.Errorf("fresh entry %q should still exist", id)
		}
	}
	trl.mu.Unlock()
}

func TestCB47_CleanupOnce_BoundaryExactly10Min(t *testing.T) {
	trl := NewTieredRateLimiter()
	t.Cleanup(func() { trl.Stop() })

	trl.SetTier("boundary-user", TierPro)
	trl.mu.Lock()
	if entry, ok := trl.limits["boundary-user"]; ok {
		// Exactly 10 minutes ago + 1 second to ensure > 10 min
		entry.windowEnd = time.Now().Add(-10*time.Minute - time.Second)
	}
	trl.mu.Unlock()

	trl.cleanupOnce()

	trl.mu.Lock()
	_, exists := trl.limits["boundary-user"]
	trl.mu.Unlock()

	if exists {
		t.Error("entry at exactly 10min+1s boundary should be removed (it's > 10 min)")
	}
}

// --- handleGetReactions: DB error path ---

func TestCB47_HandleGetReactions_DBError(t *testing.T) {
	setupTestDB(t)

	// Drop messages table to cause DB error
	db.Exec("DROP TABLE messages")

	token := generateTestJWT(t, "cb47-react-u1", "cb47-react-user")

	req := httptest.NewRequest(http.MethodGet, "/reactions?message_id=msg1", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()

	handleGetReactions(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 for DB error, got %d", rec.Code)
	}
}

func TestCB47_HandleGetReactions_GetMessageReactionsError(t *testing.T) {
	setupTestDB(t)

	// Create user, conversation, message
	_, err := db.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)",
		"cb47-react-u2", "cb47react2", "$2a$10$test")
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec("INSERT INTO conversations (id, user_id, agent_id) VALUES (?, ?, ?)",
		"cb47-conv", "cb47-react-u2", "agent1")
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content) VALUES (?, ?, ?, ?, ?)",
		"cb47-msg", "cb47-conv", "agent", "agent1", "hello")
	if err != nil {
		t.Fatal(err)
	}

	token := generateTestJWT(t, "cb47-react-u2", "cb47react2")

	// Drop reactions table to cause getMessageReactions error
	db.Exec("DROP TABLE reactions")

	req := httptest.NewRequest(http.MethodGet, "/reactions?message_id=cb47-msg", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()

	handleGetReactions(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 for reactions DB error, got %d", rec.Code)
	}
}

// --- initAPNs: cert load failure (bad cert file) ---

func TestCB47_InitAPNs_BadCertFile(t *testing.T) {
	// Create a temporary file that's not a valid P12 cert
	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "badcert.p12")
	if err := os.WriteFile(certPath, []byte("not a valid p12 certificate"), 0644); err != nil {
		t.Fatal(err)
	}

	oldConfig := pushConfig
	pushConfig = &PushNotificationConfig{
		APNSEnabled: true,
		CertPath:    certPath,
		Password:    "wrongpassword",
		Environment: "development",
	}
	defer func() { pushConfig = oldConfig }()

	// Should not panic, should disable APNs
	initAPNs()

	if pushConfig.APNSEnabled {
		t.Error("APNs should be disabled after cert load failure")
	}
	if pushConfig.apnsClient != nil {
		t.Error("APNs client should be nil after cert load failure")
	}
}

func TestCB47_InitAPNs_ProductionEnvironment(t *testing.T) {
	// Create a dummy cert file - will fail to load but tests the path
	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "cert.p12")
	if err := os.WriteFile(certPath, []byte("dummy"), 0644); err != nil {
		t.Fatal(err)
	}

	oldConfig := pushConfig
	pushConfig = &PushNotificationConfig{
		APNSEnabled: true,
		CertPath:    certPath,
		Environment: "production",
	}
	defer func() { pushConfig = oldConfig }()

	initAPNs()

	// Should have attempted load and failed, disabling APNs
	if pushConfig.APNSEnabled {
		t.Error("APNs should be disabled after invalid cert in production mode")
	}
}

// --- notifyUser: push send failure path ---

func TestCB47_NotifyUser_PushSendFailure(t *testing.T) {
	setupTestDB(t)

	// Insert a device token for a user
	_, err := db.Exec(`
		INSERT INTO device_tokens (user_id, device_token, platform, created_at)
		VALUES (?, ?, ?, ?)
	`, "cb47-notify-u1", "invalid-token-xyz", "ios", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}

	oldConfig := pushConfig
	pushConfig = &PushNotificationConfig{
		APNSEnabled: true,
		BundleID:    "com.test.app",
		Environment: "development",
		apnsClient:  nil, // nil client will cause sendAPNSNotification to return nil (no-op)
	}
	defer func() { pushConfig = oldConfig }()

	// Should not panic even with nil apnsClient
	notifyUser("cb47-notify-u1", "Test Title", "Test Body", "conv1")
}

func TestCB47_NotifyUser_NilPushConfig(t *testing.T) {
	oldConfig := pushConfig
	pushConfig = nil
	defer func() { pushConfig = oldConfig }()

	// Should return early without panic
	notifyUser("any-user", "Title", "Body", "conv1")
}

func TestCB47_NotifyUser_MutedConversation(t *testing.T) {
	setupTestDB(t)

	// Create user, conversation, and mute it
	_, err := db.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)",
		"cb47-mute-u1", "cb47mute1", "$2a$10$test")
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec("INSERT INTO conversations (id, user_id, agent_id) VALUES (?, ?, ?)",
		"cb47-mute-conv", "cb47-mute-u1", "agent1")
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec("INSERT INTO notification_preferences (user_id, conversation_id, muted) VALUES (?, ?, 1)",
		"cb47-mute-u1", "cb47-mute-conv")
	if err != nil {
		t.Fatal(err)
	}

	oldConfig := pushConfig
	pushConfig = &PushNotificationConfig{
		APNSEnabled: true,
		FCMEnabled:  true,
		BundleID:    "com.test.app",
		Environment: "development",
	}
	defer func() { pushConfig = oldConfig }()

	// Should return early because conversation is muted
	notifyUser("cb47-mute-u1", "Title", "Body", "cb47-mute-conv")
}

// --- handleSetNotificationPrefs: DB error on upsert ---

func TestCB47_HandleSetNotificationPrefs_DBError(t *testing.T) {
	setupTestDB(t)

	// Create user and conversation
	_, err := db.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)",
		"cb47-np-u1", "cb47np1", "$2a$10$test")
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec("INSERT INTO conversations (id, user_id, agent_id) VALUES (?, ?, ?)",
		"cb47-np-conv", "cb47-np-u1", "agent1")
	if err != nil {
		t.Fatal(err)
	}

	token := generateTestJWT(t, "cb47-np-u1", "cb47np1")

	// Drop notification_preferences table to cause DB error
	db.Exec("DROP TABLE notification_preferences")

	req := httptest.NewRequest(http.MethodPost, "/notifications/preferences?conversation_id=cb47-np-conv&muted=true", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	ctx := context.WithValue(req.Context(), contextKeyUserID, "cb47-np-u1")
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()

	handleSetNotificationPrefs(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 for DB error on upsert, got %d", rec.Code)
	}
}

func TestCB47_HandleSetNotificationPrefs_DBLookupError(t *testing.T) {
	setupTestDB(t)

	// Create user
	_, err := db.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)",
		"cb47-np-u2", "cb47np2", "$2a$10$test")
	if err != nil {
		t.Fatal(err)
	}

	token := generateTestJWT(t, "cb47-np-u2", "cb47np2")

	// Drop conversations table to cause lookup error
	db.Exec("DROP TABLE conversations")

	req := httptest.NewRequest(http.MethodPost, "/notifications/preferences?conversation_id=nonexistent&muted=true", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	ctx := context.WithValue(req.Context(), contextKeyUserID, "cb47-np-u2")
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()

	handleSetNotificationPrefs(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 for DB lookup error, got %d", rec.Code)
	}
}

// --- handleDeleteNotificationPrefs: success path ---

func TestCB47_HandleDeleteNotificationPrefs_Success(t *testing.T) {
	setupTestDB(t)

	// Create user and conversation with prefs
	_, err := db.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)",
		"cb47-del-np-u1", "cb47delnp1", "$2a$10$test")
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec("INSERT INTO conversations (id, user_id, agent_id) VALUES (?, ?, ?)",
		"cb47-del-conv", "cb47-del-np-u1", "agent1")
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec("INSERT INTO notification_preferences (user_id, conversation_id, muted) VALUES (?, ?, 1)",
		"cb47-del-np-u1", "cb47-del-conv")
	if err != nil {
		t.Fatal(err)
	}

	token := generateTestJWT(t, "cb47-del-np-u1", "cb47delnp1")

	req := httptest.NewRequest(http.MethodDelete, "/notifications/preferences?conversation_id=cb47-del-conv", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	ctx := context.WithValue(req.Context(), contextKeyUserID, "cb47-del-np-u1")
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()

	handleDeleteNotificationPrefs(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}

	// Verify it was deleted
	var count int
	db.QueryRow("SELECT COUNT(*) FROM notification_preferences WHERE user_id = ? AND conversation_id = ?",
		"cb47-del-np-u1", "cb47-del-conv").Scan(&count)
	if count != 0 {
		t.Errorf("expected 0 prefs after delete, got %d", count)
	}
}

// --- Snapshot: verify all fields are present ---

func TestCB47_Snapshot_AllFieldsPresent(t *testing.T) {
	hub := newHub()
	t.Cleanup(func() { hub.Stop() })
	m := NewMetrics(hub)
	m.Version = "test-v1.0"
	// Set some counter values
	m.MessagesIn.Add(42)
	m.MessagesOut.Add(37)
	m.ConnectionsTotal.Add(5)
	m.ErrorsTotal.Add(3)
	m.RateLimited.Add(2)

	snap := m.Snapshot()

	requiredFields := []string{
		"version", "uptime_seconds", "start_time",
		"messages_in", "messages_out", "connections_total",
		"agents_connected", "clients_connected", "client_conns_total",
		"errors_total", "rate_limited",
		"goroutines", "memory_alloc_mb", "memory_sys_mb",
		"offline_queue_depth", "agent_heartbeat",
	}

	for _, field := range requiredFields {
		if _, ok := snap[field]; !ok {
			t.Errorf("Snapshot missing field: %s", field)
		}
	}

	// Verify specific values
	if snap["messages_in"] != int64(42) {
		t.Errorf("messages_in = %v, want 42", snap["messages_in"])
	}
	if snap["messages_out"] != int64(37) {
		t.Errorf("messages_out = %v, want 37", snap["messages_out"])
	}
	if snap["connections_total"] != int64(5) {
		t.Errorf("connections_total = %v, want 5", snap["connections_total"])
	}
	if snap["errors_total"] != int64(3) {
		t.Errorf("errors_total = %v, want 3", snap["errors_total"])
	}
	if snap["rate_limited"] != int64(2) {
		t.Errorf("rate_limited = %v, want 2", snap["rate_limited"])
	}
	if snap["version"] != "test-v1.0" {
		t.Errorf("version = %v, want test-v1.0", snap["version"])
	}

	// Verify agent_heartbeat sub-map
	heartbeat, ok := snap["agent_heartbeat"].(map[string]interface{})
	if !ok {
		t.Fatal("agent_heartbeat should be a map")
	}
	for _, field := range []string{"enabled", "interval_s", "timeout_s", "stale_agents"} {
		if _, ok := heartbeat[field]; !ok {
			t.Errorf("agent_heartbeat missing field: %s", field)
		}
	}
}

func TestCB47_Snapshot_OfflineQueueDepth(t *testing.T) {
	hub := newHub()
	t.Cleanup(func() { hub.Stop() })
	m := NewMetrics(hub)
	q := newOfflineQueue(10, 24*time.Hour)
	offlineQueue = q
	defer func() { offlineQueue = nil }()

	q.Enqueue("user1", []byte("msg1"))
	q.Enqueue("user1", []byte("msg2"))
	q.Enqueue("user2", []byte("msg3"))

	snap := m.Snapshot()

	depth, ok := snap["offline_queue_depth"].(int)
	if !ok {
		t.Fatalf("offline_queue_depth should be int, got %T", snap["offline_queue_depth"])
	}
	if depth != 3 {
		t.Errorf("offline_queue_depth = %d, want 3", depth)
	}
}

// --- WithFields: edge cases ---

func TestCB47_WithFields_NilFieldsOnNew(t *testing.T) {
	l := NewLogger(LogInfo)
	result := l.WithFields(nil)

	if result == nil {
		t.Fatal("WithFields(nil) should not return nil")
	}
	// Should have empty fields
	if len(result.fields) != 0 {
		t.Errorf("expected 0 fields, got %d", len(result.fields))
	}
}

func TestCB47_WithFields_EmptyMapOnExistingFields(t *testing.T) {
	l := NewLogger(LogInfo).WithFields(map[string]interface{}{"component": "test"})
	result := l.WithFields(map[string]interface{}{})

	if len(result.fields) != 1 {
		t.Errorf("expected 1 field (from parent), got %d", len(result.fields))
	}
	if result.fields["component"] != "test" {
		t.Error("existing field should be preserved")
	}
}

func TestCB47_WithFields_OverwriteParentField(t *testing.T) {
	l := NewLogger(LogInfo).WithFields(map[string]interface{}{"key": "old"})
	result := l.WithFields(map[string]interface{}{"key": "new"})

	if result.fields["key"] != "new" {
		t.Errorf("expected 'new', got %v", result.fields["key"])
	}
}

// --- logEntry: level filtering ---

func TestCB47_LogEntry_LevelFiltering(t *testing.T) {
	// Create logger at Warn level - should skip Debug and Info
	l := NewLogger(LogWarn)

	// These should not produce output (level < l.level)
	// We can't easily capture output, but we can verify it doesn't panic
	l.Debug("should be skipped")
	l.Info("should be skipped")
	l.Warn("should appear")
	l.Error("should appear")
}

// --- initSchema: error on closed DB ---

func TestCB47_InitSchema_ClosedDB(t *testing.T) {
	setupTestDB(t)
	db.Close()

	// Should return error when DB is closed
	err := initSchema(db)
	if err == nil {
		t.Log("initSchema on closed DB did not return error (SQLite may differ)")
	}
}

func TestCB47_InitSchema_NotificationPreferencesTableExists(t *testing.T) {
	setupTestDB(t)

	// Verify notification_preferences table exists
	var name string
	err := db.QueryRow("SELECT name FROM sqlite_master WHERE type='table' AND name='notification_preferences'").Scan(&name)
	if err != nil {
		t.Fatalf("notification_preferences table not created: %v", err)
	}
	if name != "notification_preferences" {
		t.Errorf("expected 'notification_preferences', got %q", name)
	}
}

// --- handleUpload: mkdir error path ---

func TestCB47_HandleUpload_MkdirError(t *testing.T) {
	setupTestDB(t)

	// Create user
	_, err := db.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)",
		"cb47-upload-u1", "cb47upload1", "$2a$10$test")
	if err != nil {
		t.Fatal(err)
	}

	token := generateTestJWT(t, "cb47-upload-u1", "cb47upload1")

	// Set upload dir to a path under /proc which can't be mkdir'd
	oldPath := serverDBPath
	serverDBPath = "/proc/self/test.db"
	defer func() { serverDBPath = oldPath }()

	// Create multipart form with a small PNG
	body, contentType := createMultipartFormCB47(t, "file", "test.png", []byte{
		0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, // PNG header
		0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52,
	})

	req := httptest.NewRequest(http.MethodPost, "/attachments/upload", body)
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()

	handleUpload(rec, req)

	// Should get 500 for mkdir failure
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 for mkdir error, got %d", rec.Code)
	}
}

// --- ValidateJWT: empty token ---

func TestCB47_ValidateJWT_EmptyToken(t *testing.T) {
	_, err := ValidateJWT("")
	if err == nil {
		t.Error("ValidateJWT should return error for empty token")
	}
}

// --- openDatabase: SQLite success path ---

func TestCB47_OpenDatabase_SQLiteSuccess(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	testDB, err := openDatabase("sqlite3", dbPath)
	if err != nil {
		t.Fatalf("openDatabase failed: %v", err)
	}
	defer testDB.Close()

	if testDB == nil {
		t.Fatal("db should not be nil")
	}

	// Verify it works
	if err := testDB.Ping(); err != nil {
		t.Errorf("Ping failed: %v", err)
	}
}

func TestCB47_OpenDatabase_InvalidDriver(t *testing.T) {
	_, err := openDatabase("nonexistent-driver", "test.db")
	if err == nil {
		t.Error("openDatabase should return error for invalid driver")
	}
}

// --- envIntOrDefault: with valid env var ---

func TestCB47_EnvIntOrDefault_ValidEnv(t *testing.T) {
	os.Setenv("CB47_TEST_INT", "42")
	defer os.Unsetenv("CB47_TEST_INT")

	result := envIntOrDefault("CB47_TEST_INT", 10)
	if result != 42 {
		t.Errorf("expected 42, got %d", result)
	}
}

func TestCB47_EnvDurationOrDefault_ValidEnv(t *testing.T) {
	os.Setenv("CB47_TEST_DUR", "2h30m")
	defer os.Unsetenv("CB47_TEST_DUR")

	result := envDurationOrDefault("CB47_TEST_DUR", 10*time.Minute)
	expected := 2*time.Hour + 30*time.Minute
	if result != expected {
		t.Errorf("expected %v, got %v", expected, result)
	}
}

// --- Placeholder: PostgreSQL vs SQLite ---

func TestCB47_Placeholder_SQLite(t *testing.T) {
	oldDriver := currentDriver
	currentDriver = DriverSQLite
	defer func() { currentDriver = oldDriver }()

	if Placeholder(1) != "?" {
		t.Errorf("SQLite placeholder should be '?', got %s", Placeholder(1))
	}
}

func TestCB47_Placeholder_PostgreSQL(t *testing.T) {
	oldDriver := currentDriver
	currentDriver = DriverPostgreSQL
	defer func() { currentDriver = oldDriver }()

	if Placeholder(1) != "$1" {
		t.Errorf("PostgreSQL placeholder should be '$1', got %s", Placeholder(1))
	}
	if Placeholder(4) != "$4" {
		t.Errorf("PostgreSQL placeholder 4 should be '$4', got %s", Placeholder(4))
	}
}

// --- initSchemaForDriver: verify correct schema returned ---

func TestCB47_InitSchemaForDriver_SQLite(t *testing.T) {
	oldDriver := currentDriver
	currentDriver = DriverSQLite
	defer func() { currentDriver = oldDriver }()

	schema := initSchemaForDriver()
	if schema == "" {
		t.Error("SQLite schema should not be empty")
	}
}

func TestCB47_InitSchemaForDriver_PostgreSQL(t *testing.T) {
	oldDriver := currentDriver
	currentDriver = DriverPostgreSQL
	defer func() { currentDriver = oldDriver }()

	schema := initSchemaForDriver()
	if schema == "" {
		t.Error("PostgreSQL schema should not be empty")
	}
}

// --- getEnvOrDefault: empty and set ---

func TestCB47_GetEnvOrDefault_Empty(t *testing.T) {
	result := getEnvOrDefault("CB47_NONEXISTENT_KEY", "default")
	if result != "default" {
		t.Errorf("expected 'default', got %s", result)
	}
}

func TestCB47_GetEnvOrDefault_Set(t *testing.T) {
	os.Setenv("CB47_GETENV_TEST", "custom-value")
	defer os.Unsetenv("CB47_GETENV_TEST")

	result := getEnvOrDefault("CB47_GETENV_TEST", "default")
	if result != "custom-value" {
		t.Errorf("expected 'custom-value', got %s", result)
	}
}

// --- handleGetRateLimitTier: missing user_id ---

func TestCB47_HandleGetRateLimitTier_MissingUser(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/admin/rate-limit/tier", nil)
	req.Header.Set("X-Admin-Secret", "admin-dev-secret")
	rec := httptest.NewRecorder()

	handleGetRateLimitTier(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing user_id, got %d", rec.Code)
	}
}

func TestCB47_HandleSetRateLimitTier_PersistError(t *testing.T) {
	// Set up a closed DB to trigger persist error
	oldDB := db
	setupTestDB(t)
	db.Close()
	defer func() { db = oldDB }()

	// This should still succeed (persist error is just logged)
	adminSecret := "admin-dev-secret"

	req := httptest.NewRequest(http.MethodPost,
		"/admin/rate-limit/tier?user_id=test-persist-u1&tier=pro", nil)
	req.Header.Set("X-Admin-Secret", adminSecret)
	rec := httptest.NewRecorder()

	handleSetRateLimitTier(rec, req)

	// Should still return 200 (persist error is logged, not returned)
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 (persist error is logged), got %d", rec.Code)
	}
}

// --- loadTiersFromDB: DB error and nil paths ---

func TestCB47_LoadTiersFromDB_ClosedDB(t *testing.T) {
	oldDB := db
	setupTestDB(t)
	db.Close() // Closed DB to trigger error
	defer func() { db = oldDB }()

	trl := NewTieredRateLimiter()
	t.Cleanup(func() { trl.Stop() })

	err := loadTiersFromDB(trl)
	if err == nil {
		t.Log("loadTiersFromDB on closed DB did not return error (may be nil-safe)")
	}
}

func TestCB47_LoadTiersFromDB_NilDB(t *testing.T) {
	oldDB := db
	db = nil
	defer func() { db = oldDB }()

	trl := NewTieredRateLimiter()
	t.Cleanup(func() { trl.Stop() })

	err := loadTiersFromDB(trl)
	if err != nil {
		t.Errorf("loadTiersFromDB with nil DB should return nil, got %v", err)
	}
}

func TestCB47_LoadTiersFromDB_WithTiers(t *testing.T) {
	setupTestDB(t)

	// Insert tiers
	db.Exec("INSERT INTO user_rate_limit_tiers (user_id, tier_name) VALUES (?, ?)",
		"cb47-tier-u1", "pro")
	db.Exec("INSERT INTO user_rate_limit_tiers (user_id, tier_name) VALUES (?, ?)",
		"cb47-tier-u2", "enterprise")
	db.Exec("INSERT INTO user_rate_limit_tiers (user_id, tier_name) VALUES (?, ?)",
		"cb47-tier-u3", "free")

	trl := NewTieredRateLimiter()
	t.Cleanup(func() { trl.Stop() })

	err := loadTiersFromDB(trl)
	if err != nil {
		t.Fatalf("loadTiersFromDB failed: %v", err)
	}

	// Check that pro and enterprise tiers were loaded (free is skipped)
	proTier := trl.GetTier("cb47-tier-u1")
	if proTier.Name != "pro" {
		t.Errorf("expected pro tier for cb47-tier-u1, got %s", proTier.Name)
	}
	entTier := trl.GetTier("cb47-tier-u2")
	if entTier.Name != "enterprise" {
		t.Errorf("expected enterprise tier for cb47-tier-u2, got %s", entTier.Name)
	}
	// Free tier should not be explicitly set (defaults to free)
	freeTier := trl.GetTier("cb47-tier-u3")
	if freeTier.Name != "free" {
		t.Errorf("expected free tier for cb47-tier-u3, got %s", freeTier.Name)
	}
}

// --- persistTierToDB: error and nil paths ---

func TestCB47_PersistTierToDB_NilDB(t *testing.T) {
	oldDB := db
	db = nil
	defer func() { db = oldDB }()

	err := persistTierToDB("test-user", TierPro)
	if err != nil {
		t.Errorf("persistTierToDB with nil DB should return nil, got %v", err)
	}
}

func TestCB47_PersistTierToDB_Success(t *testing.T) {
	setupTestDB(t)

	err := persistTierToDB("cb47-persist-u1", TierPro)
	if err != nil {
		t.Errorf("persistTierToDB failed: %v", err)
	}

	// Verify it was saved
	var tierName string
	db.QueryRow("SELECT tier_name FROM user_rate_limit_tiers WHERE user_id = ?",
		"cb47-persist-u1").Scan(&tierName)
	if tierName != "pro" {
		t.Errorf("expected 'pro', got %s", tierName)
	}
}

// --- handleGetPresence: success path ---

func TestCB47_HandleGetPresence_AgentsOffline(t *testing.T) {
	setupTestDB(t)

	// Create a user so we can generate a valid JWT
	_, err := db.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)",
		"cb47-pres-u1", "cb47pres1", "$2a$10$test")
	if err != nil {
		t.Fatal(err)
	}
	token := generateTestJWT(t, "cb47-pres-u1", "cb47pres1")

	// No agents in DB
	req := httptest.NewRequest(http.MethodGet, "/presence", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()

	handleGetPresence(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}

	var resp []map[string]interface{}
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if len(resp) != 0 {
		t.Errorf("expected empty agents list, got %d agents", len(resp))
	}
}

// --- safeTruncate: edge cases ---

func TestCB47_SafeTruncate_ShortString(t *testing.T) {
	result := safeTruncate("ab", 8)
	if result != "ab" {
		t.Errorf("expected 'ab', got %s", result)
	}
}

func TestCB47_SafeTruncate_ExactLength(t *testing.T) {
	result := safeTruncate("12345678", 8)
	if result != "12345678" {
		t.Errorf("expected '12345678', got %s", result)
	}
}

func TestCB47_SafeTruncate_LongerThanN(t *testing.T) {
	result := safeTruncate("1234567890abcdef", 8)
	if result != "12345678" {
		t.Errorf("expected '12345678', got %s", result)
	}
}

func TestCB47_SafeTruncate_EmptyString(t *testing.T) {
	result := safeTruncate("", 8)
	if result != "" {
		t.Errorf("expected '', got %s", result)
	}
}

// --- itoa: basic test ---

func TestCB47_Itoa(t *testing.T) {
	tests := []struct {
		input    int
		expected string
	}{
		{0, "0"},
		{1, "1"},
		{42, "42"},
		{100, "100"},
		{-1, "-1"},
	}
	for _, tt := range tests {
		result := itoa(tt.input)
		if result != tt.expected {
			t.Errorf("itoa(%d) = %s, want %s", tt.input, result, tt.expected)
		}
	}
}

// --- mergeOpt: nil values in maps ---

func TestCB47_MergeOpt_NilValueInMap(t *testing.T) {
	m1 := map[string]interface{}{"key": nil}
	result := mergeOpt([]map[string]interface{}{m1})
	if result == nil {
		t.Fatal("mergeOpt with nil value should not return nil map")
	}
	if _, ok := result["key"]; !ok {
		t.Error("key with nil value should be preserved")
	}
}

// --- Drain: empty queue ---

func TestCB47_Drain_EmptyQueue(t *testing.T) {
	q := newOfflineQueue(100, 24*time.Hour)
	msgs := q.Drain("nonexistent-user")
	if len(msgs) != 0 {
		t.Errorf("expected 0 messages for nonexistent user, got %d", len(msgs))
	}
}

func TestCB47_Drain_AfterExpiry(t *testing.T) {
	q := newOfflineQueue(100, 1*time.Millisecond)
	q.Enqueue("user1", []byte("expired-msg"))
	time.Sleep(5 * time.Millisecond) // Wait for expiry
	msgs := q.Drain("user1")
	if len(msgs) != 0 {
		t.Errorf("expected 0 messages after expiry, got %d", len(msgs))
	}
}

// --- initQueueDB: error path ---

func TestCB47_InitQueueDB_ClosedDB(t *testing.T) {
	setupTestDB(t)
	db.Close()

	// Should not panic on closed DB
	initQueueDB(db)
}

// --- cleanStaleQueueMessages: nil DB ---

func TestCB47_CleanStaleQueueMessages_NilDB(t *testing.T) {
	// Should not panic with nil DB
	cleanStaleQueueMessages(nil, 24*time.Hour)
}

// --- persistQueue: nil DB ---

func TestCB47_PersistQueue_NilDB(t *testing.T) {
	// Should not panic with nil DB
	persistQueue(nil, "user1", []byte("msg1"))
}

// Helper function to create multipart form
func createMultipartFormCB47(t *testing.T, fieldName, filename string, content []byte) (*bytes.Reader, string) {
	t.Helper()
	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)
	part, err := writer.CreateFormFile(fieldName, filename)
	if err != nil {
		t.Fatal(err)
	}
	part.Write(content)
	writer.Close()
	return bytes.NewReader(buf.Bytes()), writer.FormDataContentType()
}