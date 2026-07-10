package main

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// --- Helpers ---

func setupTestDB_CB55(t *testing.T) *sql.DB {
	testDB, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("Failed to open test DB: %v", err)
	}
	if err := initSchema(testDB); err != nil {
		t.Fatalf("Failed to init schema: %v", err)
	}
	return testDB
}

func setupTestServer_CB55(t *testing.T) (*sql.DB, func()) {
	testDB := setupTestDB_CB55(t)
	oldDB := db
	db = testDB

	h := newHub()
	oldHub := hub
	hub = h

	cleanup := func() {
		db = oldDB
		hub = oldHub
		if h.done != nil {
			close(h.done)
		}
	}
	return testDB, cleanup
}

func cb55CreateUserAndGetToken(t *testing.T, testDB *sql.DB, username, password string) (string, string) {
	req := httptest.NewRequest(http.MethodPost, "/auth/register", strings.NewReader(
		"username="+username+"&password="+password))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handleRegisterUser(w, req)
	if w.Code != http.StatusCreated && w.Code != http.StatusOK && w.Code != http.StatusConflict {
		t.Fatalf("Failed to register user: %d - %s", w.Code, w.Body.String())
	}
	var regResp map[string]string
	json.NewDecoder(w.Body).Decode(&regResp)
	userID := regResp["user_id"]

	req = httptest.NewRequest(http.MethodPost, "/auth/login", strings.NewReader(
		"username="+username+"&password="+password))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w = httptest.NewRecorder()
	handleLogin(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("Failed to login: %d - %s", w.Code, w.Body.String())
	}
	var resp map[string]string
	json.NewDecoder(w.Body).Decode(&resp)
	return resp["token"], userID
}

// --- RegisterAgentOnConnect DB error paths ---

func TestCB55_RegisterAgentOnConnect_UpdateModelError(t *testing.T) {
	testDB := setupTestDB_CB55(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()
	defer testDB.Close()

	// Insert an agent first
	_, err := testDB.Exec("INSERT INTO agents (id, name, model, personality, specialty) VALUES (?, ?, ?, ?, ?)",
		"agent_test1", "TestAgent", "gpt-4", "friendly", "general")
	if err != nil {
		t.Fatalf("Failed to insert agent: %v", err)
	}

	// Close the DB to cause errors on UPDATE
	testDB.Close()

	// Reopen with a broken connection (closed DB)
	err = RegisterAgentOnConnect("agent_test1", "NewName", "newmodel", "newpersonality", "newspecialty")
	if err == nil {
		t.Error("Expected error updating model on closed DB, got nil")
	}
}

func TestCB55_RegisterAgentOnConnect_UpdatePersonalityError(t *testing.T) {
	testDB := setupTestDB_CB55(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()
	defer testDB.Close()

	_, err := testDB.Exec("INSERT INTO agents (id, name, model, personality, specialty) VALUES (?, ?, ?, ?, ?)",
		"agent_test2", "TestAgent2", "", "friendly", "general")
	if err != nil {
		t.Fatalf("Failed to insert agent: %v", err)
	}

	// Close DB to cause error
	testDB.Close()

	// This should hit the personality UPDATE error path
	// We need model to be empty so we reach personality update
	err = RegisterAgentOnConnect("agent_test2", "agent_test2", "", "newpersonality", "")
	if err == nil {
		t.Error("Expected error updating personality on closed DB, got nil")
	}
}

func TestCB55_RegisterAgentOnConnect_UpdateSpecialtyError(t *testing.T) {
	testDB := setupTestDB_CB55(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()
	defer testDB.Close()

	_, err := testDB.Exec("INSERT INTO agents (id, name, model, personality, specialty) VALUES (?, ?, ?, ?, ?)",
		"agent_test3", "TestAgent3", "", "", "general")
	if err != nil {
		t.Fatalf("Failed to insert agent: %v", err)
	}

	testDB.Close()

	// Empty model and personality, non-empty specialty → should reach specialty UPDATE
	err = RegisterAgentOnConnect("agent_test3", "agent_test3", "", "", "newspecialty")
	if err == nil {
		t.Error("Expected error updating specialty on closed DB, got nil")
	}
}

func TestCB55_RegisterAgentOnConnect_UpdateNameError(t *testing.T) {
	testDB := setupTestDB_CB55(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()
	defer testDB.Close()

	_, err := testDB.Exec("INSERT INTO agents (id, name, model, personality, specialty) VALUES (?, ?, ?, ?, ?)",
		"agent_test4", "TestAgent4", "", "", "")
	if err != nil {
		t.Fatalf("Failed to insert agent: %v", err)
	}

	testDB.Close()

	// Name different from agentID, empty model/personality/specialty → should reach name UPDATE
	err = RegisterAgentOnConnect("agent_test4", "DifferentName", "", "", "")
	if err == nil {
		t.Error("Expected error updating name on closed DB, got nil")
	}
}

func TestCB55_RegisterAgentOnConnect_QueryError(t *testing.T) {
	testDB := setupTestDB_CB55(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()
	defer testDB.Close()

	testDB.Close()

	// QueryRow on closed DB should return error (not sql.ErrNoRows)
	err := RegisterAgentOnConnect("nonexistent_agent", "name", "model", "p", "s")
	if err == nil {
		t.Error("Expected error on closed DB, got nil")
	}
	// The error should NOT be sql.ErrNoRows since the DB is closed
	if errors.Is(err, sql.ErrNoRows) {
		t.Error("Expected non-ErrNoRows error, got sql.ErrNoRows")
	}
}

// --- initAPNs coverage ---

func TestCB55_InitAPNs_NilPushConfig(t *testing.T) {
	oldPC := pushConfig
	pushConfig = nil
	defer func() { pushConfig = oldPC }()

	initAPNs()
	// Should not panic, should just log and return
	if pushConfig != nil && pushConfig.APNSEnabled {
		t.Error("Expected APNs to remain disabled with nil config")
	}
}

func TestCB55_InitAPNs_Disabled(t *testing.T) {
	oldPC := pushConfig
	pushConfig = &PushNotificationConfig{
		APNSEnabled: false,
	}
	defer func() { pushConfig = oldPC }()

	initAPNs()
	// Should not set up APNs client
	if pushConfig.apnsClient != nil {
		t.Error("Expected nil APNs client when disabled")
	}
}

func TestCB55_InitAPNs_NoCertPath(t *testing.T) {
	oldPC := pushConfig
	pushConfig = &PushNotificationConfig{
		APNSEnabled: true,
		CertPath:   "",
	}
	defer func() { pushConfig = oldPC }()

	initAPNs()
	// APNs should still be enabled (empty cert path just warns, doesn't disable)
	// But it won't have a client since there's no cert to load
	if pushConfig.apnsClient != nil {
		t.Error("Expected nil APNs client when no cert path")
	}
}

func TestCB55_InitAPNs_CertNotFound(t *testing.T) {
	oldPC := pushConfig
	pushConfig = &PushNotificationConfig{
		APNSEnabled: true,
		CertPath:   "/tmp/nonexistent_cert_path_12345.p12",
	}
	defer func() { pushConfig = oldPC }()

	initAPNs()
	if pushConfig.APNSEnabled {
		t.Error("Expected APNs to be disabled when cert not found")
	}
}

func TestCB55_InitAPNs_DirCreation(t *testing.T) {
	// Test that initAPNs creates parent directories for cert path
	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "subdir", "deep", "cert.p12")

	oldPC := pushConfig
	pushConfig = &PushNotificationConfig{
		APNSEnabled: true,
		CertPath:    certPath,
	}
	defer func() { pushConfig = oldPC }()

	initAPNs()

	// The directory should have been created
	dir := filepath.Dir(certPath)
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		t.Error("Expected cert parent directory to be created")
	}

	// APNs should be disabled since cert doesn't exist
	if pushConfig.APNSEnabled {
		t.Error("Expected APNs to be disabled when cert file doesn't exist")
	}
}

func TestCB55_InitAPNs_InvalidCertFile(t *testing.T) {
	// Create a temp file that is not a valid P12 cert
	tmpFile, err := os.CreateTemp("", "invalid_cert_*.p12")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	tmpFile.WriteString("this is not a valid P12 cert")
	tmpFile.Close()
	defer os.Remove(tmpFile.Name())

	oldPC := pushConfig
	pushConfig = &PushNotificationConfig{
		APNSEnabled:  true,
		CertPath:     tmpFile.Name(),
		Environment:  "development",
	}
	defer func() { pushConfig = oldPC }()

	initAPNs()
	// Should fail to load cert and disable APNs
	if pushConfig.APNSEnabled {
		t.Error("Expected APNs to be disabled with invalid cert")
	}
	if pushConfig.apnsClient != nil {
		t.Error("Expected nil APNs client with invalid cert")
	}
}

// --- initFCM coverage ---

func TestCB55_InitFCM_NilPushConfig(t *testing.T) {
	oldPC := pushConfig
	pushConfig = nil
	defer func() { pushConfig = oldPC }()

	initFCM()
	// Should not panic
}

func TestCB55_InitFCM_Disabled(t *testing.T) {
	oldPC := pushConfig
	pushConfig = &PushNotificationConfig{
		FCMEnabled: false,
	}
	defer func() { pushConfig = oldPC }()

	initFCM()
	if pushConfig.fcmClient != nil {
		t.Error("Expected nil FCM client when disabled")
	}
}

func TestCB55_InitFCM_NoCredsPath(t *testing.T) {
	oldPC := pushConfig
	pushConfig = &PushNotificationConfig{
		FCMEnabled:     true,
		FCMCredentials: "",
	}
	defer func() { pushConfig = oldPC }()

	initFCM()
	// Should log warning and return without setting up client
	if pushConfig.fcmClient != nil {
		t.Error("Expected nil FCM client when no creds path")
	}
}

func TestCB55_InitFCM_CredsNotFound(t *testing.T) {
	oldPC := pushConfig
	pushConfig = &PushNotificationConfig{
		FCMEnabled:      true,
		FCMCredentials:  "/tmp/nonexistent_fcm_creds_12345.json",
	}
	defer func() { pushConfig = oldPC }()

	initFCM()
	if pushConfig.fcmClient != nil {
		t.Error("Expected nil FCM client when creds not found")
	}
}

// --- Snapshot coverage ---

func TestCB55_Snapshot_NilOfflineQueue(t *testing.T) {
	oldOQ := offlineQueue
	offlineQueue = nil
	defer func() { offlineQueue = oldOQ }()

	m := &Metrics{
		StartTime:        time.Now(),
		Version:          "test-version",
		AgentsConnected:  func() int { return 3 },
		ClientsConnected: func() int { return 5 },
		ClientConnsTotal: func() int { return 7 },
		StaleAgentCount:  func() int64 { return 2 },
	}

	snap := m.Snapshot()

	if snap["version"] != "test-version" {
		t.Errorf("Expected version 'test-version', got %v", snap["version"])
	}
	if snap["agents_connected"] != 3 {
		t.Errorf("Expected agents_connected=3, got %v", snap["agents_connected"])
	}
	if snap["clients_connected"] != 5 {
		t.Errorf("Expected clients_connected=5, got %v", snap["clients_connected"])
	}
	if snap["client_conns_total"] != 7 {
		t.Errorf("Expected client_conns_total=7, got %v", snap["client_conns_total"])
	}
	if snap["offline_queue_depth"] != 0 {
		t.Errorf("Expected offline_queue_depth=0 with nil queue, got %v", snap["offline_queue_depth"])
	}
	hb, ok := snap["agent_heartbeat"].(map[string]interface{})
	if !ok {
		t.Fatal("Expected agent_heartbeat to be a map")
	}
	if hb["stale_agents"] != int64(2) {
		t.Errorf("Expected stale_agents=2, got %v", hb["stale_agents"])
	}
}

func TestCB55_Snapshot_WithOfflineQueue(t *testing.T) {
	oldOQ := offlineQueue
	offlineQueue = newOfflineQueue(100, 7*24*time.Hour)
	defer func() { offlineQueue = oldOQ }()

	// Add some messages
	offlineQueue.Enqueue("user1", []byte(`{"type":"chat","content":"hello"}`))
	offlineQueue.Enqueue("user1", []byte(`{"type":"chat","content":"world"}`))
	offlineQueue.Enqueue("user2", []byte(`{"type":"chat","content":"test"}`))

	m := &Metrics{
		StartTime:        time.Now(),
		Version:          "test-v2",
		AgentsConnected:  func() int { return 1 },
		ClientsConnected: func() int { return 0 },
		ClientConnsTotal: func() int { return 0 },
		StaleAgentCount:  func() int64 { return 0 },
	}

	snap := m.Snapshot()

	if snap["offline_queue_depth"] != 3 {
		t.Errorf("Expected offline_queue_depth=3, got %v", snap["offline_queue_depth"])
	}
}

func TestCB55_Snapshot_ZeroValues(t *testing.T) {
	m := &Metrics{
		StartTime:        time.Now(),
		Version:          "",
		AgentsConnected:  func() int { return 0 },
		ClientsConnected: func() int { return 0 },
		ClientConnsTotal: func() int { return 0 },
		StaleAgentCount:  func() int64 { return 0 },
	}

	snap := m.Snapshot()

	if snap["messages_in"] != int64(0) {
		t.Errorf("Expected messages_in=0, got %v", snap["messages_in"])
	}
	if snap["messages_out"] != int64(0) {
		t.Errorf("Expected messages_out=0, got %v", snap["messages_out"])
	}
	if snap["goroutines"] == nil {
		t.Error("Expected goroutines to be non-nil")
	}
	if snap["memory_alloc_mb"] == nil {
		t.Error("Expected memory_alloc_mb to be non-nil")
	}
}

// --- rate_limit_tiers cleanup ---

func TestCB55_TieredRateLimiter_CleanupStaleEntries(t *testing.T) {
	trl := NewTieredRateLimiter()
	defer trl.Stop()

	// Add some entries
	trl.Allow("user1")
	trl.Allow("user2")

	if remaining, _, _ := trl.Allow("user1"); !remaining {
		t.Error("Expected user1 to be allowed on second call within window")
	}

	// Force entries to be stale by manipulating windowEnd
	trl.mu.Lock()
	for id, entry := range trl.limits {
		trl.limits[id] = &userRateLimitState{
			count:     entry.count,
			windowEnd: time.Now().Add(-11 * time.Minute),
			tier:      entry.tier,
		}
	}
	trl.mu.Unlock()

	// Call cleanupOnce directly
	trl.cleanupOnce()

	// Both entries should be cleaned up
	remaining := trl.GetRemaining("user1")
	if remaining != 60 {
		t.Errorf("Expected user1 remaining=60 after cleanup, got %d (entry should be gone)", remaining)
	}
	remaining = trl.GetRemaining("user2")
	if remaining != 60 {
		t.Errorf("Expected user2 remaining=60 after cleanup, got %d (entry should be gone)", remaining)
	}
}

func TestCB55_TieredRateLimiter_CleanupPartialStale(t *testing.T) {
	trl := NewTieredRateLimiter()
	defer trl.Stop()

	trl.Allow("fresh_user")
	trl.Allow("stale_user")

	// Make only stale_user's entry expired
	trl.mu.Lock()
	trl.limits["stale_user"] = &userRateLimitState{
		count:     1,
		windowEnd: time.Now().Add(-11 * time.Minute),
		tier:      TierFree,
	}
	trl.mu.Unlock()

	trl.cleanupOnce()

	// fresh_user should still have their entry
	if trl.GetRemaining("fresh_user") != 59 {
		t.Errorf("Expected fresh_user remaining=59, got %d", trl.GetRemaining("fresh_user"))
	}
	// stale_user entry should be cleaned up
	if trl.GetRemaining("stale_user") != 60 {
		t.Errorf("Expected stale_user remaining=60 (cleaned up), got %d", trl.GetRemaining("stale_user"))
	}
}

// --- logEntry coverage ---

func TestCB55_LogEntry_DebugFiltered(t *testing.T) {
	// Set level to Info so Debug entries are filtered
	l := NewLogger(LogInfo)
	buf := &testBuffer{}
	l.SetOutput(buf)

	l.Debug("this should be filtered")
	if buf.Len() > 0 {
		t.Errorf("Expected no output for debug when level=info, got: %s", buf.String())
	}
}

func TestCB55_LogEntry_AllLevels(t *testing.T) {
	// Set level to Debug so all levels are written
	l := NewLogger(LogDebug)
	buf := &testBuffer{}
	l.SetOutput(buf)

	l.Debug("debug message")
	l.Info("info message")
	l.Warn("warn message")
	l.Error("error message")

	output := buf.String()
	for _, expected := range []string{"debug message", "info message", "warn message", "error message"} {
		if !strings.Contains(output, expected) {
			t.Errorf("Expected output to contain '%s', got: %s", expected, output)
		}
	}
}

func TestCB55_LogEntry_WithFields(t *testing.T) {
	l := NewLogger(LogDebug)
	buf := &testBuffer{}
	l.SetOutput(buf)

	l.Info("test msg", map[string]interface{}{"key1": "val1", "key2": 42})

	output := buf.String()
	if !strings.Contains(output, "test msg") {
		t.Errorf("Expected output to contain 'test msg', got: %s", output)
	}
	if !strings.Contains(output, "key1") {
		t.Errorf("Expected output to contain 'key1', got: %s", output)
	}
	if !strings.Contains(output, "val1") {
		t.Errorf("Expected output to contain 'val1', got: %s", output)
	}
}

func TestCB55_LogEntry_LevelFiltering(t *testing.T) {
	// Test Warn level filters Debug and Info
	l := NewLogger(LogWarn)
	buf := &testBuffer{}
	l.SetOutput(buf)

	l.Debug("should_not_appear_1")
	l.Info("should_not_appear_2")
	l.Warn("should_appear_1")
	l.Error("should_appear_2")

	output := buf.String()
	if strings.Contains(output, "should_not_appear_1") {
		t.Error("Debug should be filtered at Warn level")
	}
	if strings.Contains(output, "should_not_appear_2") {
		t.Error("Info should be filtered at Warn level")
	}
	if !strings.Contains(output, "should_appear_1") {
		t.Error("Warn should appear at Warn level")
	}
	if !strings.Contains(output, "should_appear_2") {
		t.Error("Error should appear at Warn level")
	}
}

func TestCB55_LogEntry_ErrorLevelFilter(t *testing.T) {
	// Test Error level filters Debug, Info, and Warn
	l := NewLogger(LogError)
	buf := &testBuffer{}
	l.SetOutput(buf)

	l.Debug("dbg_hidden")
	l.Info("info_hidden")
	l.Warn("warn_hidden")
	l.Error("err_visible")

	output := buf.String()
	if strings.Contains(output, "dbg_hidden") {
		t.Error("Debug should be filtered at Error level")
	}
	if strings.Contains(output, "info_hidden") {
		t.Error("Info should be filtered at Error level")
	}
	if strings.Contains(output, "warn_hidden") {
		t.Error("Warn should be filtered at Error level")
	}
	if !strings.Contains(output, "err_visible") {
		t.Error("Error should appear at Error level")
	}
}

// --- handleUpload coverage ---

func TestCB55_HandleUpload_HeaderSizeExceedsMax(t *testing.T) {
	testDB, cleanup := setupTestServer_CB55(t)
	defer cleanup()
	defer testDB.Close()

	token, _ := cb55CreateUserAndGetToken(t, testDB, "user_cb55a", "pass123")

	// Set maxUploadSize to a very small value
	oldMax := maxUploadSize
	maxUploadSize = 50 // 50 bytes
	defer func() { maxUploadSize = oldMax }()

	// Create a multipart form with a file larger than 50 bytes
	body := strings.NewReader("------boundary\r\n" +
		"Content-Disposition: form-data; name=\"file\"; filename=\"test.txt\"\r\n" +
		"Content-Type: text/plain\r\n\r\n" +
		"This is a test file that exceeds the max upload size limit of 50 bytes\r\n" +
		"------boundary--\r\n")

	req := httptest.NewRequest(http.MethodPost, "/attachments/upload", body)
	req.Header.Set("Content-Type", "multipart/form-data; boundary=----boundary")
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	handleUpload(w, req)

	// Should get 400 (file too large or invalid form data)
	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected 400 for file too large, got %d - %s", w.Code, w.Body.String())
	}
}

func TestCB55_HandleUpload_NoFileField(t *testing.T) {
	testDB, cleanup := setupTestServer_CB55(t)
	defer cleanup()
	defer testDB.Close()

	token, _ := cb55CreateUserAndGetToken(t, testDB, "user_cb55b", "pass123")

	body := strings.NewReader("------boundary\r\n" +
		"Content-Disposition: form-data; name=\"notfile\"\r\n\r\n" +
		"value\r\n" +
		"------boundary--\r\n")

	req := httptest.NewRequest(http.MethodPost, "/attachments/upload", body)
	req.Header.Set("Content-Type", "multipart/form-data; boundary=----boundary")
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	handleUpload(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected 400 for missing file field, got %d - %s", w.Code, w.Body.String())
	}
}

// --- handleListAttachments coverage ---

func TestCB55_HandleListAttachments_DBError(t *testing.T) {
	testDB, cleanup := setupTestServer_CB55(t)
	defer cleanup()

	token, userID := cb55CreateUserAndGetToken(t, testDB, "user_cb55c", "pass123")

	// Create conversation
	convID := generateID("conv")
	_, err := testDB.Exec("INSERT INTO conversations (id, user_id, agent_id, created_at) VALUES (?, ?, ?, datetime('now'))",
		convID, userID, "agent_test")
	if err != nil {
		t.Fatalf("Failed to create conversation: %v", err)
	}

	// Replace global db with a closed one to cause query error
	testDB.Close()

	// getConversation will fail on closed DB, returning nil conv → 404
	// This exercises the error path in getConversation → 404 response
	req := httptest.NewRequest(http.MethodGet, "/attachments?conversation_id="+convID, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleListAttachments(w, req)

	// With closed DB, getConversation returns error → 404 "conversation not found"
	if w.Code != http.StatusNotFound && w.Code != http.StatusInternalServerError {
		t.Errorf("Expected 404 or 500 for DB error, got %d - %s", w.Code, w.Body.String())
	}
}

func TestCB55_HandleListAttachments_ScanError(t *testing.T) {
	testDB, cleanup := setupTestServer_CB55(t)
	defer cleanup()
	defer testDB.Close()

	token, userID := cb55CreateUserAndGetToken(t, testDB, "user_cb55d", "pass123")

	// Create conversation
	convID := generateID("conv")
	_, err := testDB.Exec("INSERT INTO conversations (id, user_id, agent_id, created_at) VALUES (?, ?, ?, datetime('now'))",
		convID, userID, "agent_test")
	if err != nil {
		t.Fatalf("Failed to create conversation: %v", err)
	}

	// Create a message
	msgID := generateID("msg")
	_, err = testDB.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, created_at) VALUES (?, ?, ?, ?, ?, datetime('now'))",
		msgID, convID, "user", userID, "test message")
	if err != nil {
		t.Fatalf("Failed to create message: %v", err)
	}

	// Insert an attachment with non-integer size to cause scan error
	_, err = testDB.Exec(`INSERT INTO attachments (id, message_id, user_id, filename, content_type, size, sha256, storage_path, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		"att1", msgID, userID, "test.txt", "text/plain", "not_a_number", "abc123", "uploads/test.txt", "2025-01-01T00:00:00Z")
	if err != nil {
		t.Fatalf("Failed to insert attachment: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/attachments?conversation_id="+convID, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleListAttachments(w, req)

	// Should return 200 with empty list (scan error is silently continued)
	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d - %s", w.Code, w.Body.String())
	}
	var attachments []Attachment
	json.NewDecoder(w.Body).Decode(&attachments)
	if len(attachments) != 0 {
		t.Errorf("Expected 0 attachments (scan error skipped), got %d", len(attachments))
	}
}

// --- ValidateJWT additional coverage ---

func TestCB55_ValidateJWT_EmptyToken(t *testing.T) {
	_, err := ValidateJWT("")
	if err == nil {
		t.Error("Expected error for empty token, got nil")
	}
	if err.Error() != "empty token" {
		t.Errorf("Expected 'empty token' error, got: %v", err)
	}
}

func TestCB55_ValidateJWT_MalformedToken(t *testing.T) {
	// Test with a token that doesn't have 3 parts
	_, err := ValidateJWT("notajwt")
	if err == nil {
		t.Error("Expected error for malformed token, got nil")
	}
}

func TestCB55_ValidateJWT_GarbageToken(t *testing.T) {
	// Test with a properly formatted JWT but invalid signature
	_, err := ValidateJWT("header.payload.signature")
	if err == nil {
		t.Error("Expected error for garbage JWT, got nil")
	}
}

// --- initSchema coverage ---

func TestCB55_InitSchema_IdempotentMultipleCalls(t *testing.T) {
	testDB, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("Failed to open DB: %v", err)
	}
	defer testDB.Close()

	// First call
	if err := initSchema(testDB); err != nil {
		t.Fatalf("First initSchema failed: %v", err)
	}

	// Second call should be idempotent (IF NOT EXISTS on all CREATE TABLE)
	if err := initSchema(testDB); err != nil {
		t.Fatalf("Second initSchema failed: %v", err)
	}

	// Verify tables exist
	tables := []string{"users", "agents", "conversations", "messages", "schema_migrations",
		"reactions", "conversation_tags", "user_rate_limit_tiers", "notification_preferences"}
	for _, table := range tables {
		var name string
		err := testDB.QueryRow("SELECT name FROM sqlite_master WHERE type='table' AND name=?", table).Scan(&name)
		if err != nil {
			t.Errorf("Expected table '%s' to exist after initSchema, got error: %v", table, err)
		}
	}
}

func TestCB55_InitSchema_NotificationPreferencesTable(t *testing.T) {
	testDB, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("Failed to open DB: %v", err)
	}
	defer testDB.Close()

	if err := initSchema(testDB); err != nil {
		t.Fatalf("initSchema failed: %v", err)
	}

	// Verify notification_preferences table exists and is functional
	_, err = testDB.Exec("INSERT INTO notification_preferences (user_id, conversation_id, muted) VALUES (?, ?, ?)",
		"test_user", "test_conv", 1)
	if err != nil {
		t.Errorf("Failed to insert into notification_preferences: %v", err)
	}

	var muted int
	err = testDB.QueryRow("SELECT muted FROM notification_preferences WHERE user_id=? AND conversation_id=?",
		"test_user", "test_conv").Scan(&muted)
	if err != nil {
		t.Errorf("Failed to query notification_preferences: %v", err)
	}
	if muted != 1 {
		t.Errorf("Expected muted=1, got %d", muted)
	}
}

// --- safeTruncate additional tests ---

func TestCB55_SafeTruncate_ExactLength(t *testing.T) {
	s := "12345678"
	result := safeTruncate(s, 8)
	if result != "12345678" {
		t.Errorf("Expected '12345678', got '%s'", result)
	}
}

func TestCB55_SafeTruncate_LongerThanLength(t *testing.T) {
	s := "1234567890ABCDEF"
	result := safeTruncate(s, 8)
	if result != "12345678" {
		t.Errorf("Expected '12345678', got '%s'", result)
	}
}

func TestCB55_SafeTruncate_ShortString(t *testing.T) {
	s := "ab"
	result := safeTruncate(s, 8)
	if result != "ab" {
		t.Errorf("Expected 'ab', got '%s'", result)
	}
}

func TestCB55_SafeTruncate_EmptyString(t *testing.T) {
	result := safeTruncate("", 8)
	if result != "" {
		t.Errorf("Expected '', got '%s'", result)
	}
}

// --- testBuffer helper for logger tests ---

type testBuffer struct {
	data []byte
}

func (b *testBuffer) Write(p []byte) (int, error) {
	b.data = append(b.data, p...)
	return len(p), nil
}

func (b *testBuffer) String() string {
	return string(b.data)
}

func (b *testBuffer) Len() int {
	return len(b.data)
}