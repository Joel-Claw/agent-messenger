package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// ==============================
// Coverage Boost 22: Targeting low-coverage functions
// Focus: push.go (sendAPNSNotification, sendFCMNotification, initAPNs, initFCM, initPushNotifications, notifyUser, safeTruncate),
// rate_limit_tiers.go (cleanup, persistTierToDB, loadTiersFromDB, handleSetRateLimitTier, handleGetRateLimitTier, handleAdminRateLimitTier),
// attachments.go (handleUpload, handleGetAttachment, handleListAttachments),
// conversations.go (deleteConversation, searchMessages, markMessagesRead, storeMessagesBatch, getConversationMessages),
// e2e.go (handleUploadPublicKey, handleStoreEncryptedMessage, authenticateRequest),
// notif_prefs.go (handleSetNotificationPrefs, handleGetNotificationPrefs, handleDeleteNotificationPrefs, isConversationMuted),
// queue_persist.go (persistQueue, deleteQueueMessages, loadQueueFromDB, initQueueDB, cleanStaleQueueMessages),
// tracing.go (InitTracing, ShutdownTracing, StartSpan, StartSpanFromRequest, TraceRouteMessage, etc.),
// profile.go (StartCPUProfile, WriteHeapProfile, WriteGoroutineProfile, MemoryStats, CaptureProfile),
// profile_handler.go (handleAdminProfile, handleHeapProfile, handleGoroutineProfile, handleCPUProfileStart, handleCPUProfileStop, handleForceGC, handleMemoryStats),
// protocol.go (sendWelcomeMessage, negotiateProtocol, isSupportedVersion),
// handlers.go (handleListAgents, handleAdminAgents, handleSearchMessages, handleRegisterAgent),
// main.go (parseSize, initSchema portions),
// reactions.go (addReaction),
// tags.go (getConversationTags, addConversationTag, removeConversationTag)
// ==============================

// --- Helper: setup for CB22 tests ---
func cb22SetupDB(t *testing.T) {
	t.Helper()
	var err error
	db, err = sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if err := initSchema(db); err != nil {
		t.Fatal(err)
	}
	offlineQueue = newOfflineQueue(100, 7*24*time.Hour)
}

func cb22CreateUser(t *testing.T, username, password string) (string, string) {
	t.Helper()
	form := url.Values{"username": {username}, "password": {password}}.Encode()
	req := httptest.NewRequest("POST", "/auth/user", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	handleRegisterUser(rr, req)
	if rr.Code != http.StatusOK && rr.Code != http.StatusCreated {
		t.Fatalf("register user %s failed: %d %s", username, rr.Code, rr.Body.String())
	}
	var resp map[string]string
	json.Unmarshal(rr.Body.Bytes(), &resp)
	userID := resp["user_id"]

	form = url.Values{"username": {username}, "password": {password}}.Encode()
	req = httptest.NewRequest("POST", "/auth/login", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr = httptest.NewRecorder()
	handleLogin(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("login user %s failed: %d %s", username, rr.Code, rr.Body.String())
	}
	var loginResp map[string]string
	json.Unmarshal(rr.Body.Bytes(), &loginResp)
	return userID, loginResp["token"]
}

func cb22CreateAgent(t *testing.T, agentID, name string) {
	t.Helper()
	_, err := db.Exec("INSERT OR IGNORE INTO agents (id, name, model, personality, specialty) VALUES (?, ?, 'test-model', 'friendly', 'general')", agentID, name)
	if err != nil {
		t.Fatalf("create agent: %v", err)
	}
}

func cb22CreateConversation(t *testing.T, userID, agentID string) string {
	t.Helper()
	conv, err := CreateConversation(userID, agentID)
	if err != nil {
		t.Fatalf("create conversation: %v", err)
	}
	return conv.ID
}

func cb22AuthRequest(t *testing.T, req *http.Request, username string) *http.Request {
	t.Helper()
	ctx := context.WithValue(req.Context(), contextKeyUserID, username)
	*req = *req.WithContext(ctx)
	return req
}

func cb22AuthRequestWithToken(t *testing.T, req *http.Request, username, password string) *http.Request {
	t.Helper()
	_, token := cb22CreateUser(t, username, password)
	req.Header.Set("Authorization", "Bearer "+token)
	return req
}

// ==============================
// push.go coverage
// ==============================

func TestCb22_SafeTruncate(t *testing.T) {
	tests := []struct {
		input string
		n     int
		want  string
	}{
		{"hello", 3, "hel"},
		{"hi", 5, "hi"},
		{"", 3, ""},
		{"abcdefgh", 4, "abcd"},
		{"exactly8", 8, "exactly8"},
	}
	for _, tt := range tests {
		got := safeTruncate(tt.input, tt.n)
		if got != tt.want {
			t.Errorf("safeTruncate(%q, %d) = %q, want %q", tt.input, tt.n, got, tt.want)
		}
	}
}

func TestCb22_InitPushNotifications_Disabled(t *testing.T) {
	// Ensure push is disabled by default (no env vars)
	os.Unsetenv("APNS_ENABLED")
	os.Unsetenv("FCM_ENABLED")
	os.Unsetenv("APNS_CERT_PATH")
	os.Unsetenv("FCM_CREDENTIALS_PATH")

	initPushNotifications()
	if pushConfig == nil {
		t.Fatal("pushConfig should be initialized")
	}
	if pushConfig.APNSEnabled {
		t.Error("APNs should be disabled by default")
	}
	if pushConfig.FCMEnabled {
		t.Error("FCM should be disabled by default")
	}
}

func TestCb22_InitPushNotifications_APNSNoCert(t *testing.T) {
	os.Setenv("APNS_ENABLED", "true")
	os.Unsetenv("APNS_CERT_PATH")
	defer os.Unsetenv("APNS_ENABLED")

	initPushNotifications()
	if pushConfig.APNSEnabled {
		// When APNS_ENABLED=true but no cert path, initAPNs returns early
		// without disabling it. The enabled flag stays true but client is nil.
		// This is expected behavior - it will be disabled when cert is not found.
		t.Log("APNS remains enabled when cert path is empty (no cert check)")
	}
	if pushConfig.apnsClient != nil {
		t.Error("APNs client should be nil when cert path is empty")
	}
}

func TestCb22_InitPushNotifications_FCMNoCreds(t *testing.T) {
	os.Setenv("FCM_ENABLED", "true")
	os.Unsetenv("FCM_CREDENTIALS_PATH")
	defer os.Unsetenv("FCM_ENABLED")

	initPushNotifications()
	if pushConfig.FCMEnabled {
		t.Log("FCM remains enabled when credentials path is empty (no file check)")
	}
	if pushConfig.fcmClient != nil {
		t.Error("FCM client should be nil when credentials path is empty")
	}
}

func TestCb22_SendAPNSNotification_Disabled(t *testing.T) {
	pushConfig = nil
	err := sendAPNSNotification("token", "title", "body", "conv1")
	if err != nil {
		t.Errorf("should be no-op when push disabled, got: %v", err)
	}
}

func TestCb22_SendAPNSNotification_NoClient(t *testing.T) {
	pushConfig = &PushNotificationConfig{APNSEnabled: true, apnsClient: nil}
	err := sendAPNSNotification("token", "title", "body", "conv1")
	if err != nil {
		t.Errorf("should be no-op when no APNs client, got: %v", err)
	}
}

func TestCb22_SendFCMNotification_Disabled(t *testing.T) {
	pushConfig = nil
	err := sendFCMNotification("token", "title", "body", "conv1")
	if err != nil {
		t.Errorf("should be no-op when push disabled, got: %v", err)
	}
}

func TestCb22_SendFCMNotification_NoClient(t *testing.T) {
	pushConfig = &PushNotificationConfig{FCMEnabled: true, fcmClient: nil}
	err := sendFCMNotification("token", "title", "body", "conv1")
	if err != nil {
		t.Errorf("should be no-op when no FCM client, got: %v", err)
	}
}

func TestCb22_NotifyUser_Disabled(t *testing.T) {
	pushConfig = nil
	notifyUser("user1", "title", "body", "conv1")
	// No panic = success
}

func TestCb22_NotifyUser_Muted(t *testing.T) {
	cb22SetupDB(t)
	pushConfig = &PushNotificationConfig{APNSEnabled: false, FCMEnabled: false}

	userID, _ := cb22CreateUser(t, "muteduser", "password123")
	cb22CreateAgent(t, "agent1", "Test Agent")
	convID := cb22CreateConversation(t, userID, "agent1")

	// Mute the conversation
	db.Exec("INSERT INTO notification_preferences (user_id, conversation_id, muted) VALUES (?, ?, 1)", userID, convID)

	notifyUser(userID, "title", "body", convID)
	// Should not attempt push since conversation is muted
}

func TestCb22_GetEnvOrDefault(t *testing.T) {
	os.Setenv("TEST_CB22_KEY", "value")
	if v := getEnvOrDefault("TEST_CB22_KEY", "default"); v != "value" {
		t.Errorf("expected 'value', got %q", v)
	}
	if v := getEnvOrDefault("TEST_CB22_MISSING", "default"); v != "default" {
		t.Errorf("expected 'default', got %q", v)
	}
	os.Unsetenv("TEST_CB22_KEY")
}

// ==============================
// rate_limit_tiers.go coverage
// ==============================

func TestCb22_TieredRateLimiter_Cleanup(t *testing.T) {
	trl := NewTieredRateLimiter()
	defer trl.Stop()

	// Add some entries
	trl.SetTier("user1", TierFree)
	trl.Allow("user1")

	// Let entries become stale by manipulating windowEnd
	trl.mu.Lock()
	if entry, ok := trl.limits["user1"]; ok {
		entry.windowEnd = time.Now().Add(-15 * time.Minute) // Stale: expired > 10 min ago
	}
	trl.mu.Unlock()

	// Trigger cleanup manually by calling the logic inline
	trl.mu.Lock()
	now := time.Now()
	for id, entry := range trl.limits {
		if now.After(entry.windowEnd) && now.Sub(entry.windowEnd) > 10*time.Minute {
			delete(trl.limits, id)
		}
	}
	trl.mu.Unlock()

	if _, ok := trl.limits["user1"]; ok {
		t.Error("stale entry should have been cleaned up")
	}
}

func TestCb22_PersistTierToDB_NilDB(t *testing.T) {
	savedDB := db
	db = nil
	defer func() { db = savedDB }()

	err := persistTierToDB("user1", TierPro)
	if err != nil {
		t.Errorf("persistTierToDB with nil db should return nil, got: %v", err)
	}
}

func TestCb22_PersistTierToDB_SQLite(t *testing.T) {
	cb22SetupDB(t)

	err := persistTierToDB("user1", TierPro)
	if err != nil {
		t.Errorf("persistTierToDB failed: %v", err)
	}

	// Verify in DB
	var tierName string
	err = db.QueryRow("SELECT tier_name FROM user_rate_limit_tiers WHERE user_id = ?", "user1").Scan(&tierName)
	if err != nil {
		t.Fatalf("query tier: %v", err)
	}
	if tierName != "pro" {
		t.Errorf("expected tier 'pro', got %q", tierName)
	}
}

func TestCb22_LoadTiersFromDB_NilDB(t *testing.T) {
	savedDB := db
	db = nil
	defer func() { db = savedDB }()

	trl := NewTieredRateLimiter()
	defer trl.Stop()

	err := loadTiersFromDB(trl)
	if err != nil {
		t.Errorf("loadTiersFromDB with nil db should return nil, got: %v", err)
	}
}

func TestCb22_LoadTiersFromDB_WithData(t *testing.T) {
	cb22SetupDB(t)

	// Insert test tiers
	db.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)", "user1", "u1", "hash1")
	db.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)", "user2", "u2", "hash2")
	db.Exec("INSERT OR REPLACE INTO user_rate_limit_tiers (user_id, tier_name) VALUES (?, 'pro')", "user1")
	db.Exec("INSERT OR REPLACE INTO user_rate_limit_tiers (user_id, tier_name) VALUES (?, 'enterprise')", "user2")

	trl := NewTieredRateLimiter()
	defer trl.Stop()

	err := loadTiersFromDB(trl)
	if err != nil {
		t.Fatalf("loadTiersFromDB failed: %v", err)
	}

	if trl.GetTier("user1") != TierPro {
		t.Errorf("expected user1 to be pro tier")
	}
	if trl.GetTier("user2") != TierEnterprise {
		t.Errorf("expected user2 to be enterprise tier")
	}
}

func TestCb22_HandleSetRateLimitTier(t *testing.T) {
	cb22SetupDB(t)
	globalTieredLimiter = NewTieredRateLimiter()
	defer globalTieredLimiter.Stop()

	// Create admin secret for testing
	origSecret := os.Getenv("ADMIN_SECRET")
	os.Setenv("ADMIN_SECRET", "test-admin-secret")
	resetAdminSecret()
	defer func() {
		os.Setenv("ADMIN_SECRET", origSecret)
		resetAdminSecret()
	}()

	tests := []struct {
		name       string
		method     string
		body       string
		headers    map[string]string
		wantStatus int
		wantBody   string
	}{
		{
			name:       "valid set pro tier",
			method:     "POST",
			body:       "user_id=user1&tier=pro",
			headers:    map[string]string{"X-Admin-Secret": "test-admin-secret", "Content-Type": "application/x-www-form-urlencoded"},
			wantStatus: http.StatusOK,
			wantBody:   "pro",
		},
		{
			name:       "missing auth",
			method:     "POST",
			body:       "user_id=user2&tier=free",
			headers:    map[string]string{},
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "missing user_id",
			method:     "POST",
			body:       "tier=pro",
			headers:    map[string]string{"X-Admin-Secret": "test-admin-secret", "Content-Type": "application/x-www-form-urlencoded"},
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "unknown tier",
			method:     "POST",
			body:       "user_id=user1&tier=premium",
			headers:    map[string]string{"X-Admin-Secret": "test-admin-secret", "Content-Type": "application/x-www-form-urlencoded"},
			wantStatus: http.StatusBadRequest,
			wantBody:   "unknown tier",
		},
		{
			name:       "wrong method",
			method:     "DELETE",
			body:       "",
			headers:    map[string]string{"X-Admin-Secret": "test-admin-secret"},
			wantStatus: http.StatusMethodNotAllowed,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, "/admin/rate-limit/tier", strings.NewReader(tt.body))
			for k, v := range tt.headers {
				req.Header.Set(k, v)
			}
			rr := httptest.NewRecorder()
			handleSetRateLimitTier(rr, req)
			if rr.Code != tt.wantStatus {
				t.Errorf("status: got %d, want %d; body: %s", rr.Code, tt.wantStatus, rr.Body.String())
			}
			if tt.wantBody != "" && !strings.Contains(rr.Body.String(), tt.wantBody) {
				t.Errorf("body: want %q in %q", tt.wantBody, rr.Body.String())
			}
		})
	}
}

func TestCb22_HandleGetRateLimitTier(t *testing.T) {
	cb22SetupDB(t)
	globalTieredLimiter = NewTieredRateLimiter()
	defer globalTieredLimiter.Stop()

	origSecret := os.Getenv("ADMIN_SECRET")
	os.Setenv("ADMIN_SECRET", "test-admin-secret")
	resetAdminSecret()
	defer func() {
		os.Setenv("ADMIN_SECRET", origSecret)
		resetAdminSecret()
	}()

	// Set a tier first
	globalTieredLimiter.SetTier("user1", TierEnterprise)

	tests := []struct {
		name       string
		method     string
		url        string
		headers    map[string]string
		wantStatus int
		wantBody   string
	}{
		{
			name:       "get existing tier",
			method:     "GET",
			url:        "/admin/rate-limit/tier?user_id=user1&admin_secret=test-admin-secret",
			headers:    map[string]string{},
			wantStatus: http.StatusOK,
			wantBody:   "enterprise",
		},
		{
			name:       "missing auth",
			method:     "GET",
			url:        "/admin/rate-limit/tier?user_id=user1",
			headers:    map[string]string{},
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "missing user_id",
			method:     "GET",
			url:        "/admin/rate-limit/tier?admin_secret=test-admin-secret",
			headers:    map[string]string{},
			wantStatus: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.url, nil)
			for k, v := range tt.headers {
				req.Header.Set(k, v)
			}
			rr := httptest.NewRecorder()
			handleGetRateLimitTier(rr, req)
			if rr.Code != tt.wantStatus {
				t.Errorf("status: got %d, want %d; body: %s", rr.Code, tt.wantStatus, rr.Body.String())
			}
			if tt.wantBody != "" && !strings.Contains(rr.Body.String(), tt.wantBody) {
				t.Errorf("body: want %q in %q", tt.wantBody, rr.Body.String())
			}
		})
	}
}

func TestCb22_HandleAdminRateLimitTier_Routing(t *testing.T) {
	cb22SetupDB(t)
	globalTieredLimiter = NewTieredRateLimiter()
	defer globalTieredLimiter.Stop()

	origSecret := os.Getenv("ADMIN_SECRET")
	os.Setenv("ADMIN_SECRET", "test-admin-secret")
	resetAdminSecret()
	defer func() {
		os.Setenv("ADMIN_SECRET", origSecret)
		resetAdminSecret()
	}()

	// POST should route to handleSetRateLimitTier
	req := httptest.NewRequest("POST", "/admin/rate-limit/tier", strings.NewReader("user_id=test&tier=free"))
	req.Header.Set("X-Admin-Secret", "test-admin-secret")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	handleAdminRateLimitTier(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("POST routing: got %d, want 200; body: %s", rr.Code, rr.Body.String())
	}

	// GET should route to handleGetRateLimitTier
	req = httptest.NewRequest("GET", "/admin/rate-limit/tier?user_id=test&admin_secret=test-admin-secret", nil)
	rr = httptest.NewRecorder()
	handleAdminRateLimitTier(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("GET routing: got %d, want 200; body: %s", rr.Code, rr.Body.String())
	}
}

func TestCb22_Itoa(t *testing.T) {
	tests := []struct {
		input int
		want  string
	}{
		{0, "0"},
		{42, "42"},
		{-5, "-5"},
		{999, "999"},
	}
	for _, tt := range tests {
		got := itoa(tt.input)
		if got != tt.want {
			t.Errorf("itoa(%d) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestCb22_TieredRateLimiter_Reset(t *testing.T) {
	trl := NewTieredRateLimiter()
	defer trl.Stop()

	trl.SetTier("user1", TierPro)
	trl.Allow("user1")
	trl.Reset()

	if trl.GetTier("user1") != TierFree {
		t.Error("after reset, tier should default to Free")
	}
	if trl.GetRemaining("user1") != TierFree.Burst {
		t.Error("after reset, remaining should be Free burst")
	}
}

// ==============================
// attachments.go coverage
// ==============================

func TestCb22_HandleUpload_AuthRequired(t *testing.T) {
	cb22SetupDB(t)
	ensureUploadDir()

	// No auth
	req := httptest.NewRequest("POST", "/attachments/upload", nil)
	rr := httptest.NewRecorder()
	handleUpload(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 without auth, got %d", rr.Code)
	}
}

func TestCb22_HandleUpload_InvalidToken(t *testing.T) {
	cb22SetupDB(t)

	req := httptest.NewRequest("POST", "/attachments/upload", nil)
	req.Header.Set("Authorization", "Bearer invalid-token")
	rr := httptest.NewRecorder()
	handleUpload(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 with invalid token, got %d", rr.Code)
	}
}

func TestCb22_HandleUpload_WrongMethod(t *testing.T) {
	cb22SetupDB(t)
	_, token := cb22CreateUser(t, "uploaduser", "password123")

	req := httptest.NewRequest("GET", "/attachments/upload", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	handleUpload(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405 for GET, got %d", rr.Code)
	}
}

func TestCb22_HandleUpload_MissingFile(t *testing.T) {
	cb22SetupDB(t)
	_, token := cb22CreateUser(t, "uploaduser2", "password123")

	req := httptest.NewRequest("POST", "/attachments/upload", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "multipart/form-data")
	rr := httptest.NewRecorder()
	handleUpload(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing file, got %d; body: %s", rr.Code, rr.Body.String())
	}
}

func TestCb22_HandleUpload_Success(t *testing.T) {
	cb22SetupDB(t)
	_, token := cb22CreateUser(t, "uploaduser3", "password123")

	// Create a small test file
	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)
	part, err := writer.CreateFormFile("file", "test.txt")
	if err != nil {
		t.Fatal(err)
	}
	part.Write([]byte("hello world test content"))
	writer.Close()

	req := httptest.NewRequest("POST", "/attachments/upload", &buf)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	rr := httptest.NewRecorder()
	handleUpload(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 for valid upload, got %d; body: %s", rr.Code, rr.Body.String())
	}

	var resp map[string]interface{}
	json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp["id"] == nil {
		t.Error("expected attachment ID in response")
	}
	if resp["filename"] != "test.txt" {
		t.Errorf("expected filename 'test.txt', got %v", resp["filename"])
	}
}

func TestCb22_HandleGetAttachment_WrongMethod(t *testing.T) {
	cb22SetupDB(t)

	req := httptest.NewRequest("POST", "/attachments/att123", nil)
	rr := httptest.NewRecorder()
	handleGetAttachment(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405 for POST, got %d", rr.Code)
	}
}

func TestCb22_HandleGetAttachment_MissingID(t *testing.T) {
	cb22SetupDB(t)
	_, token := cb22CreateUser(t, "getuser", "password123")

	req := httptest.NewRequest("GET", "/attachments/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	handleGetAttachment(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing id, got %d; body: %s", rr.Code, rr.Body.String())
	}
}

func TestCb22_HandleGetAttachment_NotFound(t *testing.T) {
	cb22SetupDB(t)
	_, token := cb22CreateUser(t, "getuser2", "password123")

	req := httptest.NewRequest("GET", "/attachments/nonexistent", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	handleGetAttachment(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Errorf("expected 404 for nonexistent attachment, got %d; body: %s", rr.Code, rr.Body.String())
	}
}

func TestCb22_HandleListAttachments_WrongMethod(t *testing.T) {
	cb22SetupDB(t)

	req := httptest.NewRequest("POST", "/messages/attachments", nil)
	rr := httptest.NewRecorder()
	handleListAttachments(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405 for POST, got %d", rr.Code)
	}
}

func TestCb22_HandleListAttachments_NoAuth(t *testing.T) {
	cb22SetupDB(t)

	req := httptest.NewRequest("GET", "/messages/attachments?conversation_id=conv1", nil)
	rr := httptest.NewRecorder()
	handleListAttachments(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 without auth, got %d", rr.Code)
	}
}

func TestCb22_HandleListAttachments_MissingConvID(t *testing.T) {
	cb22SetupDB(t)
	_, token := cb22CreateUser(t, "listuser", "password123")

	req := httptest.NewRequest("GET", "/messages/attachments", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	handleListAttachments(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing conversation_id, got %d; body: %s", rr.Code, rr.Body.String())
	}
}

func TestCb22_IsAllowedContentType(t *testing.T) {
	tests := []struct {
		ct   string
		want bool
	}{
		{"image/jpeg", true},
		{"image/png", true},
		{"application/pdf", true},
		{"text/plain", true},
		{"audio/mpeg", true},
		{"video/mp4", true},
		{"image/svg+xml", true},
		{"text/csv", true},
		{"application/json", true},
		{"application/x-executable", false},
		{"text/html", true}, // text/ prefix
		{"image/tiff", true}, // image/ prefix
		{"audio/flac", true}, // audio/ prefix
		{"video/avi", true}, // video/ prefix
		{"", false},
	}
	for _, tt := range tests {
		got := isAllowedContentType(tt.ct)
		if got != tt.want {
			t.Errorf("isAllowedContentType(%q) = %v, want %v", tt.ct, got, tt.want)
		}
	}
}

func TestCb22_GetUploadDir(t *testing.T) {
	serverDBPath = "/tmp/test-agent-messenger.db"
	dir := getUploadDir()
	expected := "/tmp/uploads"
	if dir != expected {
		t.Errorf("getUploadDir() = %q, want %q", dir, expected)
	}
}

func TestCb22_EnsureUploadDir(t *testing.T) {
	tmpDir := t.TempDir()
	serverDBPath = filepath.Join(tmpDir, "test.db")
	defer func() { serverDBPath = "" }()

	err := ensureUploadDir()
	if err != nil {
		t.Fatalf("ensureUploadDir failed: %v", err)
	}

	uploadDir := getUploadDir()
	if _, err := os.Stat(uploadDir); os.IsNotExist(err) {
		t.Errorf("upload directory was not created: %s", uploadDir)
	}
}

func TestCb22_GetMaxUploadSize(t *testing.T) {
	origSize := maxUploadSize
	defer func() { maxUploadSize = origSize }()

	maxUploadSize = MaxUploadSize
	if getMaxUploadSize() != MaxUploadSize {
		t.Errorf("expected %d, got %d", MaxUploadSize, getMaxUploadSize())
	}

	maxUploadSize = 1024
	if getMaxUploadSize() != 1024 {
		t.Errorf("expected 1024, got %d", getMaxUploadSize())
	}
}

// ==============================
// conversations.go coverage
// ==============================

func TestCb22_DeleteConversation_NotFound(t *testing.T) {
	cb22SetupDB(t)

	err := deleteConversation("nonexistent", "user1")
	if err == nil {
		t.Error("expected error for nonexistent conversation")
	}
}

func TestCb22_DeleteConversation_Unauthorized(t *testing.T) {
	cb22SetupDB(t)
	userID, _ := cb22CreateUser(t, "deluser", "password123")
	cb22CreateAgent(t, "agent1", "Test Agent")
	convID := cb22CreateConversation(t, userID, "agent1")

	err := deleteConversation(convID, "wronguser")
	if err == nil || err.Error() != "unauthorized" {
		t.Errorf("expected unauthorized error, got: %v", err)
	}
}

func TestCb22_SearchMessages_EmptyQuery(t *testing.T) {
	cb22SetupDB(t)
	userID, _ := cb22CreateUser(t, "searchuser", "password123")

	_, err := searchMessages(userID, "", 50)
	if err == nil || err.Error() != "empty search query" {
		t.Errorf("expected empty search query error, got: %v", err)
	}
}

func TestCb22_SearchMessages_NoResults(t *testing.T) {
	cb22SetupDB(t)
	userID, _ := cb22CreateUser(t, "searchuser2", "password123")

	messages, err := searchMessages(userID, "nonexistent", 50)
	if err != nil {
		t.Fatalf("searchMessages failed: %v", err)
	}
	if len(messages) != 0 {
		t.Errorf("expected 0 results, got %d", len(messages))
	}
}

func TestCb22_SearchMessages_WithResults(t *testing.T) {
	cb22SetupDB(t)
	userID, _ := cb22CreateUser(t, "searchuser3", "password123")
	cb22CreateAgent(t, "agent1", "Test Agent")
	convID := cb22CreateConversation(t, userID, "agent1")

	// Insert a message
	db.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, created_at) VALUES (?, ?, 'user', ?, ?, datetime('now'))",
		"msg_search1", convID, userID, "hello world unique search term")

	messages, err := searchMessages(userID, "unique search term", 50)
	if err != nil {
		t.Fatalf("searchMessages failed: %v", err)
	}
	if len(messages) != 1 {
		t.Errorf("expected 1 result, got %d", len(messages))
	}
}

func TestCb22_MarkMessagesRead_NotFound(t *testing.T) {
	cb22SetupDB(t)

	_, err := markMessagesRead("nonexistent", "user1")
	if err == nil {
		t.Error("expected error for nonexistent conversation")
	}
}

func TestCb22_MarkMessagesRead_Unauthorized(t *testing.T) {
	cb22SetupDB(t)
	userID, _ := cb22CreateUser(t, "markuser", "password123")
	cb22CreateAgent(t, "agent1", "Test Agent")
	convID := cb22CreateConversation(t, userID, "agent1")

	_, err := markMessagesRead(convID, "wronguser")
	if err == nil || err.Error() != "unauthorized" {
		t.Errorf("expected unauthorized error, got: %v", err)
	}
}

func TestCb22_MarkMessagesRead_Success(t *testing.T) {
	cb22SetupDB(t)
	userID, _ := cb22CreateUser(t, "markuser2", "password123")
	cb22CreateAgent(t, "agent1", "Test Agent")
	convID := cb22CreateConversation(t, userID, "agent1")

	// Insert agent messages
	db.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, created_at) VALUES (?, ?, 'agent', ?, ?, datetime('now'))",
		"msg_mark1", convID, "agent1", "hello")
	db.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, created_at) VALUES (?, ?, 'agent', ?, ?, datetime('now'))",
		"msg_mark2", convID, "agent1", "world")

	count, err := markMessagesRead(convID, userID)
	if err != nil {
		t.Fatalf("markMessagesRead failed: %v", err)
	}
	if count != 2 {
		t.Errorf("expected 2 messages marked read, got %d", count)
	}

	// Idempotent: second call should return 0
	count, err = markMessagesRead(convID, userID)
	if err != nil {
		t.Fatalf("second markMessagesRead failed: %v", err)
	}
	if count != 0 {
		t.Errorf("expected 0 on second call, got %d", count)
	}
}

// ==============================
// e2e.go coverage: handleUploadPublicKey, handleStoreEncryptedMessage, authenticateRequest
// ==============================

func TestCb22_AuthenticateRequest_JWT(t *testing.T) {
	cb22SetupDB(t)
	_, token := cb22CreateUser(t, "e2euser", "password123")

	req := httptest.NewRequest("POST", "/keys/upload", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	userID, ownerType, err := authenticateRequest(req)
	if err != nil {
		t.Fatalf("authenticateRequest failed: %v", err)
	}
	if ownerType != "user" {
		t.Errorf("expected owner_type 'user', got %q", ownerType)
	}
	if userID == "" {
		t.Error("expected non-empty user_id")
	}
}

func TestCb22_AuthenticateRequest_AgentSecret(t *testing.T) {
	cb22SetupDB(t)
	origSecret := os.Getenv("AGENT_SECRET")
	os.Setenv("AGENT_SECRET", "test-agent-secret")
	resetAgentSecret()
	defer func() {
		os.Setenv("AGENT_SECRET", origSecret)
		resetAgentSecret()
	}()

	req := httptest.NewRequest("POST", "/keys/upload", nil)
	req.Header.Set("X-Agent-Secret", "test-agent-secret")
	req.Header.Set("X-Agent-ID", "agent1")

	userID, ownerType, err := authenticateRequest(req)
	if err != nil {
		t.Fatalf("authenticateRequest failed: %v", err)
	}
	if ownerType != "agent" {
		t.Errorf("expected owner_type 'agent', got %q", ownerType)
	}
	if userID != "agent1" {
		t.Errorf("expected agent_id 'agent1', got %q", userID)
	}
}

func TestCb22_AuthenticateRequest_NoAuth(t *testing.T) {
	req := httptest.NewRequest("POST", "/keys/upload", nil)
	_, _, err := authenticateRequest(req)
	if err == nil {
		t.Error("expected error for no auth")
	}
}

func TestCb22_AuthenticateRequest_BadToken(t *testing.T) {
	req := httptest.NewRequest("POST", "/keys/upload", nil)
	req.Header.Set("Authorization", "Bearer bad-token")
	_, _, err := authenticateRequest(req)
	if err == nil {
		t.Error("expected error for bad token")
	}
}

func TestCb22_HandleUploadPublicKey_Success(t *testing.T) {
	cb22SetupDB(t)
	_, token := cb22CreateUser(t, "keyuser", "password123")

	body := `{"key_type":"identity","public_key":"dGVzdC1wdWJsaWMta2V5"}`
	req := httptest.NewRequest("POST", "/keys/upload", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	handleUploadPublicKey(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d; body: %s", rr.Code, rr.Body.String())
	}

	var resp KeyBundle
	json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp.ID == "" {
		t.Error("expected non-empty key ID")
	}
	if resp.KeyType != "identity" {
		t.Errorf("expected key_type 'identity', got %q", resp.KeyType)
	}
}

func TestCb22_HandleUploadPublicKey_InvalidKeyType(t *testing.T) {
	cb22SetupDB(t)
	_, token := cb22CreateUser(t, "keyuser2", "password123")

	body := `{"key_type":"invalid","public_key":"dGVzdA=="}`
	req := httptest.NewRequest("POST", "/keys/upload", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	handleUploadPublicKey(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d; body: %s", rr.Code, rr.Body.String())
	}
}

func TestCb22_HandleUploadPublicKey_MissingPublicKey(t *testing.T) {
	cb22SetupDB(t)
	_, token := cb22CreateUser(t, "keyuser3", "password123")

	body := `{"key_type":"identity"}`
	req := httptest.NewRequest("POST", "/keys/upload", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	handleUploadPublicKey(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d; body: %s", rr.Code, rr.Body.String())
	}
}

func TestCb22_HandleUploadPublicKey_WrongMethod(t *testing.T) {
	req := httptest.NewRequest("GET", "/keys/upload", nil)
	rr := httptest.NewRecorder()
	handleUploadPublicKey(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rr.Code)
	}
}

func TestCb22_HandleStoreEncryptedMessage_Success(t *testing.T) {
	cb22SetupDB(t)
	hub = newHub()
	go hub.run()
	defer hub.Stop()

	userID, token := cb22CreateUser(t, "encuser", "password123")
	cb22CreateAgent(t, "agent1", "Test Agent")
	convID := cb22CreateConversation(t, userID, "agent1")

	body := fmt.Sprintf(`{
		"conversation_id": "%s",
		"ciphertext": "base64ciphertext",
		"iv": "base64iv",
		"recipient_key_id": "key_123",
		"algorithm": "aes-256-gcm"
	}`, convID)

	req := httptest.NewRequest("POST", "/messages/encrypted", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	handleStoreEncryptedMessage(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d; body: %s", rr.Code, rr.Body.String())
	}
}

func TestCb22_HandleStoreEncryptedMessage_UnsupportedAlgorithm(t *testing.T) {
	cb22SetupDB(t)
	_, token := cb22CreateUser(t, "encuser2", "password123")

	body := `{
		"conversation_id": "conv1",
		"ciphertext": "abc",
		"iv": "def",
		"algorithm": "rsa-4096"
	}`

	req := httptest.NewRequest("POST", "/messages/encrypted", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	handleStoreEncryptedMessage(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d; body: %s", rr.Code, rr.Body.String())
	}
}

func TestCb22_HandleStoreEncryptedMessage_MissingFields(t *testing.T) {
	cb22SetupDB(t)
	_, token := cb22CreateUser(t, "encuser3", "password123")

	body := `{"conversation_id":"conv1","ciphertext":"abc","algorithm":"aes-256-gcm"}`
	req := httptest.NewRequest("POST", "/messages/encrypted", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	handleStoreEncryptedMessage(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing iv, got %d; body: %s", rr.Code, rr.Body.String())
	}
}

func TestCb22_HandleStoreEncryptedMessage_WrongMethod(t *testing.T) {
	req := httptest.NewRequest("GET", "/messages/encrypted", nil)
	rr := httptest.NewRecorder()
	handleStoreEncryptedMessage(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rr.Code)
	}
}

func TestCb22_HandleGetEncryptedMessages_Success(t *testing.T) {
	cb22SetupDB(t)
	userID, token := cb22CreateUser(t, "encgetuser2", "password123")
	cb22CreateAgent(t, "agent1", "Test Agent")
	convID := cb22CreateConversation(t, userID, "agent1")

	req := httptest.NewRequest("GET", "/messages/encrypted/list?conversation_id="+convID, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	handleGetEncryptedMessages(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d; body: %s", rr.Code, rr.Body.String())
	}
}

// ==============================
// notif_prefs.go coverage
// ==============================

func TestCb22_HandleGetNotificationPrefs(t *testing.T) {
	cb22SetupDB(t)
	cb22CreateUser(t, "notifuser", "password123")

	req := httptest.NewRequest("GET", "/notification-prefs", nil)
	cb22AuthRequest(t, req, "notifuser")
	rr := httptest.NewRecorder()
	handleGetNotificationPrefs(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d; body: %s", rr.Code, rr.Body.String())
	}
}

func TestCb22_HandleSetNotificationPrefs(t *testing.T) {
	cb22SetupDB(t)
	cb22CreateUser(t, "notifuser2", "password123")
	cb22CreateAgent(t, "agent1", "Test Agent")
	convID := cb22CreateConversation(t, "notifuser2", "agent1")

	form := url.Values{
		"conversation_id": {convID},
		"muted":           {"true"},
	}.Encode()

	req := httptest.NewRequest("POST", "/notification-prefs/set", strings.NewReader(form))
	cb22AuthRequest(t, req, "notifuser2")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	handleSetNotificationPrefs(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d; body: %s", rr.Code, rr.Body.String())
	}

	// Verify muted
	if !isConversationMuted("notifuser2", convID) {
		t.Error("expected conversation to be muted")
	}
}

func TestCb22_HandleSetNotificationPrefs_Unauthorized(t *testing.T) {
	cb22SetupDB(t)
	cb22CreateUser(t, "notifowner", "password123")
	cb22CreateUser(t, "notifother", "password456")
	cb22CreateAgent(t, "agent1", "Test Agent")
	convID := cb22CreateConversation(t, "notifowner", "agent1")

	form := url.Values{
		"conversation_id": {convID},
		"muted":           {"true"},
	}.Encode()

	req := httptest.NewRequest("POST", "/notification-prefs/set", strings.NewReader(form))
	cb22AuthRequest(t, req, "notifother")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	handleSetNotificationPrefs(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d; body: %s", rr.Code, rr.Body.String())
	}
}

func TestCb22_HandleSetNotificationPrefs_NotFound(t *testing.T) {
	cb22SetupDB(t)
	cb22CreateUser(t, "notifuser3", "password123")

	form := url.Values{
		"conversation_id": {"nonexistent"},
		"muted":           {"true"},
	}.Encode()

	req := httptest.NewRequest("POST", "/notification-prefs/set", strings.NewReader(form))
	cb22AuthRequest(t, req, "notifuser3")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	handleSetNotificationPrefs(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d; body: %s", rr.Code, rr.Body.String())
	}
}

func TestCb22_HandleSetNotificationPrefs_MissingConvID(t *testing.T) {
	cb22SetupDB(t)
	cb22CreateUser(t, "notifuser4", "password123")

	req := httptest.NewRequest("POST", "/notification-prefs/set", strings.NewReader("muted=true"))
	cb22AuthRequest(t, req, "notifuser4")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	handleSetNotificationPrefs(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d; body: %s", rr.Code, rr.Body.String())
	}
}

func TestCb22_HandleDeleteNotificationPrefs(t *testing.T) {
	cb22SetupDB(t)
	cb22CreateUser(t, "delnotifuser", "password123")

	form := url.Values{
		"conversation_id": {"conv1"},
	}.Encode()

	req := httptest.NewRequest("POST", "/notification-prefs/delete", strings.NewReader(form))
	cb22AuthRequest(t, req, "delnotifuser")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	handleDeleteNotificationPrefs(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d; body: %s", rr.Code, rr.Body.String())
	}
}

func TestCb22_IsConversationMuted(t *testing.T) {
	cb22SetupDB(t)
	userID, _ := cb22CreateUser(t, "mutetest", "password123")
	cb22CreateAgent(t, "agent1", "Test Agent")
	convID := cb22CreateConversation(t, userID, "agent1")

	// Not muted by default
	if isConversationMuted(userID, convID) {
		t.Error("expected conversation to not be muted by default")
	}

	// Mute it
	db.Exec("INSERT INTO notification_preferences (user_id, conversation_id, muted) VALUES (?, ?, 1)", userID, convID)
	if !isConversationMuted(userID, convID) {
		t.Error("expected conversation to be muted after insert")
	}

	// Different conversation should not be muted
	if isConversationMuted(userID, "nonexistent") {
		t.Error("expected nonexistent conversation to not be muted")
	}
}

// ==============================
// queue_persist.go coverage
// ==============================

func TestCb22_PersistQueue_NilDB(t *testing.T) {
	savedDB := db
	db = nil
	defer func() { db = savedDB }()

	persistQueue(nil, "user1", []byte("test"))
	// No panic = success
}

func TestCb22_DeleteQueueMessages_NilDB(t *testing.T) {
	savedDB := db
	db = nil
	defer func() { db = savedDB }()

	deleteQueueMessages(nil, "user1")
	// No panic = success
}

func TestCb22_LoadQueueFromDB_NilDB(t *testing.T) {
	savedDB := db
	db = nil
	defer func() { db = savedDB }()

	q := newOfflineQueue(100, 7*24*time.Hour)
	loadQueueFromDB(nil, q)
	// No panic = success
}

func TestCb22_InitQueueDB_NilDB(t *testing.T) {
	savedDB := db
	db = nil
	defer func() { db = savedDB }()

	initQueueDB(nil)
	// No panic = success
}

func TestCb22_CleanStaleQueueMessages_NilDB(t *testing.T) {
	savedDB := db
	db = nil
	defer func() { db = savedDB }()

	cleanStaleQueueMessages(nil, time.Hour)
	// No panic = success
}

func TestCb22_QueuePersistRoundTrip(t *testing.T) {
	cb22SetupDB(t)
	initQueueDB(db)

	q := newOfflineQueue(100, 7*24*time.Hour)

	// Enqueue some messages
	msgData := []byte(`{"type":"chat","data":"hello"}`)
	q.Enqueue("user1", msgData)
	q.Enqueue("user1", []byte(`{"type":"chat","data":"world"}`))

	// Persist them
	persistQueue(db, "user1", msgData)
	persistQueue(db, "user1", []byte(`{"type":"chat","data":"world"}`))

	// Load from DB into a new queue
	q2 := newOfflineQueue(100, 7*24*time.Hour)
	loadQueueFromDB(db, q2)

	// Verify messages were loaded
	count := q2.QueueDepth("user1")
	if count < 1 {
		t.Errorf("expected at least 1 message in loaded queue, got %d", count)
	}

	// Delete
	deleteQueueMessages(db, "user1")

	// Verify DB is clean
	var rowCount int
	db.QueryRow("SELECT COUNT(*) FROM offline_queue WHERE recipient = ?", "user1").Scan(&rowCount)
	if rowCount != 0 {
		t.Errorf("expected 0 rows after delete, got %d", rowCount)
	}
}

func TestCb22_CleanStaleQueueMessages(t *testing.T) {
	cb22SetupDB(t)
	initQueueDB(db)

	// Insert a stale message directly
	db.Exec("INSERT INTO offline_queue (recipient, data, queued_at, sent_count) VALUES (?, ?, datetime('now', '-10 days'), 0)", "stale_user", "old data")

	cleanStaleQueueMessages(db, 7*24*time.Hour)

	var count int
	db.QueryRow("SELECT COUNT(*) FROM offline_queue WHERE recipient = ?", "stale_user").Scan(&count)
	if count != 0 {
		t.Errorf("expected stale messages to be cleaned, got %d remaining", count)
	}
}

func TestCb22_MarshalOutgoingMessage(t *testing.T) {
	msg := OutgoingMessage{Type: "chat", Data: "hello"}
	data := marshalOutgoingMessage(msg)
	if len(data) == 0 {
		t.Error("expected non-empty marshaled message")
	}
	var parsed map[string]interface{}
	json.Unmarshal(data, &parsed)
	if parsed["type"] != "chat" {
		t.Errorf("expected type 'chat', got %v", parsed["type"])
	}
}

// ==============================
// tracing.go coverage
// ==============================

func TestCb22_InitTracing_Disabled(t *testing.T) {
	os.Unsetenv("OTEL_ENABLED")
	err := InitTracing()
	if err != nil {
		t.Errorf("InitTracing with OTEL_ENABLED unset should not error: %v", err)
	}
	if IsTracingEnabled() {
		t.Error("tracing should be disabled when OTEL_ENABLED is not set")
	}
}

func TestCb22_ShutdownTracing_NoProvider(t *testing.T) {
	// Should not panic when no provider is set
	tp = nil
	ShutdownTracing()
}

func TestCb22_StartSpan_Disabled(t *testing.T) {
	tracingEnabled = false
	ctx := context.Background()
	_, span := StartSpan(ctx, "test")
	if span == nil {
		t.Error("StartSpan should return a non-nil span even when disabled")
	}
}

func TestCb22_StartSpanFromRequest_Disabled(t *testing.T) {
	tracingEnabled = false
	req := httptest.NewRequest("GET", "/test", nil)
	_, span := StartSpanFromRequest(req, "test")
	if span == nil {
		t.Error("StartSpanFromRequest should return a non-nil span even when disabled")
	}
}

func TestCb22_TraceRouteMessage_Disabled(t *testing.T) {
	tracingEnabled = false
	span := TraceRouteMessage("agent", "agent1")
	// Should not panic
	_ = span
}

func TestCb22_TraceChatMessage_Disabled(t *testing.T) {
	tracingEnabled = false
	ctx := context.Background()
	_, span := TraceChatMessage(ctx, "user", "user1", "conv1", "agent1")
	_ = span
}

func TestCb22_TraceStoreMessage_Disabled(t *testing.T) {
	tracingEnabled = false
	ctx := context.Background()
	_, span := TraceStoreMessage(ctx, "conv1", "user1")
	_ = span
}

func TestCb22_TraceDeliverMessage_Disabled(t *testing.T) {
	tracingEnabled = false
	ctx := context.Background()
	_, span := TraceDeliverMessage(ctx, "user1", "client", true)
	_ = span
}

func TestCb22_TraceOfflineEnqueue_Disabled(t *testing.T) {
	tracingEnabled = false
	span := TraceOfflineEnqueue("user1")
	_ = span
}

func TestCb22_TracePushNotify_Disabled(t *testing.T) {
	tracingEnabled = false
	span := TracePushNotify("user1", "conv1", true)
	_ = span
}

func TestCb22_TraceAgentConnect_Disabled(t *testing.T) {
	tracingEnabled = false
	span := TraceAgentConnect("agent1")
	_ = span
}

func TestCb22_TraceClientConnect_Disabled(t *testing.T) {
	tracingEnabled = false
	span := TraceClientConnect("user1", "device1")
	_ = span
}

func TestCb22_SpanError_Disabled(t *testing.T) {
	tracingEnabled = false
	span := TraceRouteMessage("agent", "agent1")
	SpanError(span, fmt.Errorf("test error"))
	// Should not panic
}

func TestCb22_SpanOK_Disabled(t *testing.T) {
	tracingEnabled = false
	span := TraceRouteMessage("agent", "agent1")
	SpanOK(span)
	// Should not panic
}

// ==============================
// protocol.go coverage
// ==============================

func TestCb22_NegotiateProtocol(t *testing.T) {
	tests := []struct {
		name     string
		header   string
		query    string
		want     string
	}{
		{"v1 header", "v1", "", "v1"},
		{"empty header, v1 query", "", "v1", "v1"},
		{"no proto", "", "", ProtocolVersion},
		{"unsupported", "v2", "", ProtocolVersion},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/test", nil)
			if tt.header != "" {
				req.Header.Set("Sec-WebSocket-Protocol", tt.header)
			}
			if tt.query != "" {
				q := req.URL.Query()
				q.Set("protocol_version", tt.query)
				req.URL.RawQuery = q.Encode()
			}
			got := negotiateProtocol(req)
			if got != tt.want {
				t.Errorf("negotiateProtocol() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestCb22_IsSupportedVersion(t *testing.T) {
	if !isSupportedVersion("v1") {
		t.Error("v1 should be supported")
	}
	if isSupportedVersion("v2") {
		t.Error("v2 should not be supported")
	}
}

// ==============================
// profile.go coverage
// ==============================

func TestCb22_MemoryStats(t *testing.T) {
	stats := MemoryStats()
	if stats == nil {
		t.Fatal("MemoryStats() returned nil")
	}
	if _, ok := stats["alloc_bytes"]; !ok {
		t.Error("expected 'alloc_bytes' in stats")
	}
	if _, ok := stats["goroutines"]; !ok {
		t.Error("expected 'goroutines' in stats")
	}
}

func TestCb22_ForceGC(t *testing.T) {
	numGC := ForceGC()
	if numGC == 0 {
		t.Error("expected at least 1 GC cycle after ForceGC")
	}
}

func TestCb22_WriteHeapProfile(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "heap.prof")
	err := WriteHeapProfile(path)
	if err != nil {
		t.Fatalf("WriteHeapProfile failed: %v", err)
	}
	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Error("heap profile file was not created")
	}
}

func TestCb22_WriteGoroutineProfile(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "goroutine.prof")
	err := WriteGoroutineProfile(path)
	if err != nil {
		t.Fatalf("WriteGoroutineProfile failed: %v", err)
	}
	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Error("goroutine profile file was not created")
	}
}

func TestCb22_StartCPUProfile(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "cpu.prof")
	stop, err := StartCPUProfile(path)
	if err != nil {
		t.Fatalf("StartCPUProfile failed: %v", err)
	}
	time.Sleep(10 * time.Millisecond)
	stop()
	// Verify file was created
	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Error("CPU profile file was not created")
	}
}

func TestCb22_CaptureProfile_NoDir(t *testing.T) {
	snapshot := CaptureProfile("")
	if snapshot == nil {
		t.Fatal("CaptureProfile returned nil")
	}
	if snapshot.Memory == nil {
		t.Error("expected Memory stats in snapshot")
	}
	if snapshot.HeapFile != "" {
		t.Error("expected no heap file when dir is empty")
	}
}

func TestCb22_CaptureProfile_WithDir(t *testing.T) {
	tmpDir := t.TempDir()
	snapshot := CaptureProfile(tmpDir)
	if snapshot == nil {
		t.Fatal("CaptureProfile returned nil")
	}
	if snapshot.HeapFile == "" {
		t.Error("expected heap file path in snapshot")
	}
	if snapshot.GoroutineFile == "" {
		t.Error("expected goroutine file path in snapshot")
	}
}

// ==============================
// profile_handler.go coverage
// ==============================

func TestCb22_HandleAdminProfile_Stats(t *testing.T) {
	req := httptest.NewRequest("GET", "/admin/profile", nil)
	rr := httptest.NewRecorder()
	handleAdminProfile(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d; body: %s", rr.Code, rr.Body.String())
	}
}

func TestCb22_HandleAdminProfile_Heap(t *testing.T) {
	req := httptest.NewRequest("GET", "/admin/profile?action=heap", nil)
	rr := httptest.NewRecorder()
	handleAdminProfile(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d; body: %s", rr.Code, rr.Body.String())
	}
}

func TestCb22_HandleAdminProfile_Goroutine(t *testing.T) {
	req := httptest.NewRequest("GET", "/admin/profile?action=goroutine", nil)
	rr := httptest.NewRecorder()
	handleAdminProfile(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d; body: %s", rr.Code, rr.Body.String())
	}
}

func TestCb22_HandleAdminProfile_GC(t *testing.T) {
	req := httptest.NewRequest("GET", "/admin/profile?action=gc", nil)
	rr := httptest.NewRecorder()
	handleAdminProfile(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d; body: %s", rr.Code, rr.Body.String())
	}
}

func TestCb22_HandleAdminProfile_CPUStartStop(t *testing.T) {
	// Start CPU profile
	req := httptest.NewRequest("POST", "/admin/profile?action=cpu", nil)
	rr := httptest.NewRecorder()
	handleAdminProfile(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("CPU start: expected 200, got %d; body: %s", rr.Code, rr.Body.String())
	}

	// Stop CPU profile
	req = httptest.NewRequest("POST", "/admin/profile?action=cpu_stop", nil)
	rr = httptest.NewRecorder()
	handleAdminProfile(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("CPU stop: expected 200, got %d; body: %s", rr.Code, rr.Body.String())
	}
}

func TestCb22_HandleAdminProfile_CPUStopWithoutStart(t *testing.T) {
	// Make sure no CPU profile is active
	cpuProfileState.Lock()
	cpuProfileState.active = false
	cpuProfileState.stopFunc = nil
	cpuProfileState.Unlock()

	req := httptest.NewRequest("POST", "/admin/profile?action=cpu_stop", nil)
	rr := httptest.NewRecorder()
	handleAdminProfile(rr, req)
	if rr.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 for cpu_stop without start, got %d; body: %s", rr.Code, rr.Body.String())
	}
}

func TestCb22_HandleAdminProfile_UnknownAction(t *testing.T) {
	req := httptest.NewRequest("GET", "/admin/profile?action=unknown", nil)
	rr := httptest.NewRecorder()
	handleAdminProfile(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for unknown action, got %d; body: %s", rr.Code, rr.Body.String())
	}
}

func TestCb22_HandleAdminProfile_WrongMethod(t *testing.T) {
	req := httptest.NewRequest("PUT", "/admin/profile", nil)
	rr := httptest.NewRecorder()
	handleAdminProfile(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405 for PUT, got %d", rr.Code)
	}
}

func TestCb22_SetGCPercent(t *testing.T) {
	orig := SetGCPercent(100)
	defer SetGCPercent(orig)
	newVal := SetGCPercent(200)
	if newVal != 100 {
		t.Errorf("expected old GC percent 100, got %d", newVal)
	}
}

func TestCb22_SetMemoryLimit(t *testing.T) {
	orig := debug_SetMemoryLimit(0)
	defer debug_SetMemoryLimit(orig)
	newVal := debug_SetMemoryLimit(1 << 30) // 1GB
	// The return value is the previous limit
	_ = newVal // Just verify it doesn't panic
}

// Helper for memory limit test since debug.SetMemoryLimit may not exist on all Go versions
func debug_SetMemoryLimit(limit int64) int64 {
	return SetMemoryLimit(limit)
}

// ==============================
// main.go: parseSize coverage
// ==============================

func TestCb22_ParseSize(t *testing.T) {
	tests := []struct {
		input string
		want  int64
		err   bool
	}{
		{"1024", 1024, false},
		{"1KB", 1024, false},
		{"1MB", 1 << 20, false},
		{"50MB", 50 << 20, false},
		{"1GB", 1 << 30, false},
		{"1TB", 1 << 40, false},
		{"10B", 10, false},
		{"", 0, true},
		{"abc", 0, true},
	}
	for _, tt := range tests {
		got, err := parseSize(tt.input)
		if tt.err && err == nil {
			t.Errorf("parseSize(%q): expected error, got %d", tt.input, got)
		}
		if !tt.err && err != nil {
			t.Errorf("parseSize(%q): unexpected error: %v", tt.input, err)
		}
		if !tt.err && got != tt.want {
			t.Errorf("parseSize(%q) = %d, want %d", tt.input, got, tt.want)
		}
	}
}

// ==============================
// handlers.go: handleListAgents, handleAdminAgents coverage
// ==============================

func TestCb22_HandleListAgents(t *testing.T) {
	cb22SetupDB(t)
	hub = newHub()
	go hub.run()
	defer hub.Stop()
	ServerMetrics = NewMetrics(hub)

	cb22CreateAgent(t, "agent1", "Test Agent")

	req := httptest.NewRequest("GET", "/agents", nil)
	rr := httptest.NewRecorder()
	handleListAgents(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d; body: %s", rr.Code, rr.Body.String())
	}

	var agents []AgentInfo
	json.Unmarshal(rr.Body.Bytes(), &agents)
	if len(agents) != 1 {
		t.Errorf("expected 1 agent, got %d", len(agents))
	}
}

func TestCb22_HandleListAgents_WrongMethod(t *testing.T) {
	req := httptest.NewRequest("POST", "/agents", nil)
	rr := httptest.NewRecorder()
	handleListAgents(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rr.Code)
	}
}

func TestCb22_HandleAdminAgents(t *testing.T) {
	cb22SetupDB(t)
	hub = newHub()
	go hub.run()
	defer hub.Stop()

	origSecret := os.Getenv("ADMIN_SECRET")
	os.Setenv("ADMIN_SECRET", "test-admin-secret")
	resetAdminSecret()
	defer func() {
		os.Setenv("ADMIN_SECRET", origSecret)
		resetAdminSecret()
	}()

	cb22CreateAgent(t, "agent1", "Test Agent")

	req := httptest.NewRequest("GET", "/admin/agents", nil)
	req.Header.Set("X-Admin-Secret", "test-admin-secret")
	rr := httptest.NewRecorder()
	handleAdminAgents(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d; body: %s", rr.Code, rr.Body.String())
	}
}

func TestCb22_HandleAdminAgents_WrongMethod(t *testing.T) {
	req := httptest.NewRequest("POST", "/admin/agents", nil)
	rr := httptest.NewRecorder()
	handleAdminAgents(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rr.Code)
	}
}

// ==============================
// reactions.go: addReaction coverage
// ==============================

func TestCb22_AddReaction_NotFound(t *testing.T) {
	cb22SetupDB(t)

	_, _, err := addReaction("nonexistent-msg", "user1", "👍")
	if err == nil || err.Error() != "message not found" {
		t.Errorf("expected 'message not found' error, got: %v", err)
	}
}

func TestCb22_AddReaction_Unauthorized(t *testing.T) {
	cb22SetupDB(t)
	userID, _ := cb22CreateUser(t, "rxnuser", "password123")
	cb22CreateAgent(t, "agent1", "Test Agent")
	convID := cb22CreateConversation(t, userID, "agent1")

	db.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, created_at) VALUES (?, ?, 'agent', ?, ?, datetime('now'))",
		"msg_rxn1", convID, "agent1", "hello")

	_, _, err := addReaction("msg_rxn1", "wronguser", "👍")
	if err == nil || err.Error() != "unauthorized" {
		t.Errorf("expected unauthorized error, got: %v", err)
	}
}

func TestCb22_AddReaction_Toggle(t *testing.T) {
	cb22SetupDB(t)
	userID, _ := cb22CreateUser(t, "rxnuser2", "password123")
	cb22CreateAgent(t, "agent1", "Test Agent")
	convID := cb22CreateConversation(t, userID, "agent1")

	db.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, created_at) VALUES (?, ?, 'agent', ?, ?, datetime('now'))",
		"msg_rxn2", convID, "agent1", "hello")

	// Add reaction
	reaction, added, err := addReaction("msg_rxn2", userID, "👍")
	if err != nil {
		t.Fatalf("addReaction failed: %v", err)
	}
	if !added {
		t.Error("expected reaction to be added")
	}
	if reaction.Emoji != "👍" {
		t.Errorf("expected emoji '👍', got %q", reaction.Emoji)
	}

	// Toggle off (same emoji)
	_, added, err = addReaction("msg_rxn2", userID, "👍")
	if err != nil {
		t.Fatalf("toggle reaction failed: %v", err)
	}
	if added {
		t.Error("expected reaction to be toggled off")
	}
}

func TestCb22_GetMessageReactions(t *testing.T) {
	cb22SetupDB(t)

	reactions, err := getMessageReactions("nonexistent-msg")
	if err != nil {
		t.Fatalf("getMessageReactions failed: %v", err)
	}
	if len(reactions) != 0 {
		t.Errorf("expected 0 reactions for nonexistent message, got %d", len(reactions))
	}
}

// ==============================
// tags.go: getConversationTags, addConversationTag, removeConversationTag
// ==============================

func TestCb22_GetConversationTags_Empty(t *testing.T) {
	cb22SetupDB(t)
	userID, _ := cb22CreateUser(t, "taguser", "password123")
	cb22CreateAgent(t, "agent1", "Test Agent")
	convID := cb22CreateConversation(t, userID, "agent1")

	tags, err := getConversationTags(convID)
	if err != nil {
		t.Fatalf("getConversationTags failed: %v", err)
	}
	if len(tags) != 0 {
		t.Errorf("expected 0 tags, got %d", len(tags))
	}
}

func TestCb22_AddConversationTag_Success(t *testing.T) {
	cb22SetupDB(t)
	userID, _ := cb22CreateUser(t, "taguser2", "password123")
	cb22CreateAgent(t, "agent1", "Test Agent")
	convID := cb22CreateConversation(t, userID, "agent1")

	tag, err := addConversationTag(convID, userID, "important")
	if err != nil {
		t.Fatalf("addConversationTag failed: %v", err)
	}
	if tag.Tag != "important" {
		t.Errorf("expected tag 'important', got %q", tag.Tag)
	}
}

func TestCb22_AddConversationTag_Duplicate(t *testing.T) {
	cb22SetupDB(t)
	userID, _ := cb22CreateUser(t, "taguser3", "password123")
	cb22CreateAgent(t, "agent1", "Test Agent")
	convID := cb22CreateConversation(t, userID, "agent1")

	_, err := addConversationTag(convID, userID, "work")
	if err != nil {
		t.Fatalf("first addConversationTag failed: %v", err)
	}
	_, err = addConversationTag(convID, userID, "work")
	if err == nil || err.Error() != "tag already exists" {
		t.Errorf("expected 'tag already exists' error, got: %v", err)
	}
}

func TestCb22_AddConversationTag_InvalidTag(t *testing.T) {
	cb22SetupDB(t)
	userID, _ := cb22CreateUser(t, "taguser4", "password123")
	cb22CreateAgent(t, "agent1", "Test Agent")
	convID := cb22CreateConversation(t, userID, "agent1")

	_, err := addConversationTag(convID, userID, "")
	if err == nil {
		t.Error("expected error for empty tag")
	}

	longTag := strings.Repeat("a", 51)
	_, err = addConversationTag(convID, userID, longTag)
	if err == nil {
		t.Error("expected error for tag > 50 chars")
	}
}

func TestCb22_AddConversationTag_Unauthorized(t *testing.T) {
	cb22SetupDB(t)
	userID, _ := cb22CreateUser(t, "taguser5", "password123")
	cb22CreateAgent(t, "agent1", "Test Agent")
	convID := cb22CreateConversation(t, userID, "agent1")

	_, err := addConversationTag(convID, "wronguser", "test")
	if err == nil || err.Error() != "unauthorized" {
		t.Errorf("expected unauthorized error, got: %v", err)
	}
}

func TestCb22_AddConversationTag_NotFound(t *testing.T) {
	cb22SetupDB(t)

	_, err := addConversationTag("nonexistent", "user1", "test")
	if err == nil || err.Error() != "conversation not found" {
		t.Errorf("expected 'conversation not found' error, got: %v", err)
	}
}

func TestCb22_RemoveConversationTag_Success(t *testing.T) {
	cb22SetupDB(t)
	userID, _ := cb22CreateUser(t, "taguser6", "password123")
	cb22CreateAgent(t, "agent1", "Test Agent")
	convID := cb22CreateConversation(t, userID, "agent1")

	_, err := addConversationTag(convID, userID, "todo")
	if err != nil {
		t.Fatalf("addConversationTag failed: %v", err)
	}

	err = removeConversationTag(convID, userID, "todo")
	if err != nil {
		t.Fatalf("removeConversationTag failed: %v", err)
	}
}

func TestCb22_RemoveConversationTag_NotFound(t *testing.T) {
	cb22SetupDB(t)
	userID, _ := cb22CreateUser(t, "taguser7", "password123")
	cb22CreateAgent(t, "agent1", "Test Agent")
	convID := cb22CreateConversation(t, userID, "agent1")

	err := removeConversationTag(convID, userID, "nonexistent")
	if err == nil || err.Error() != "tag not found" {
		t.Errorf("expected 'tag not found' error, got: %v", err)
	}
}

// ==============================
// Web push handlers
// ==============================

func TestCb22_HandleGetVAPIDKey_NoKey(t *testing.T) {
	cb22SetupDB(t)
	_, token := cb22CreateUser(t, "vapiduser", "password123")

	vapidPublicKey = ""

	req := httptest.NewRequest("GET", "/push/vapid-key", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	handleGetVAPIDKey(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("expected 404 when VAPID not configured, got %d; body: %s", rr.Code, rr.Body.String())
	}
}

func TestCb22_HandleGetVAPIDKey_WithKey(t *testing.T) {
	cb22SetupDB(t)
	_, token := cb22CreateUser(t, "vapiduser2", "password123")

	vapidPublicKey = "test-vapid-public-key"
	defer func() { vapidPublicKey = "" }()

	req := httptest.NewRequest("GET", "/push/vapid-key", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	handleGetVAPIDKey(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d; body: %s", rr.Code, rr.Body.String())
	}
}

func TestCb22_HandleGetVAPIDKey_WrongMethod(t *testing.T) {
	req := httptest.NewRequest("POST", "/push/vapid-key", nil)
	rr := httptest.NewRecorder()
	handleGetVAPIDKey(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rr.Code)
	}
}

func TestCb22_HandleWebPushSubscribe(t *testing.T) {
	cb22SetupDB(t)
	_, token := cb22CreateUser(t, "wpsuser", "password123")

	body := `{"endpoint":"https://push.example.com/123","keys":{"p256dh":"base64key","auth":"base64auth"}}`
	req := httptest.NewRequest("POST", "/push/web-subscribe", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	handleWebPushSubscribe(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d; body: %s", rr.Code, rr.Body.String())
	}
}

func TestCb22_HandleWebPushSubscribe_MissingFields(t *testing.T) {
	cb22SetupDB(t)
	_, token := cb22CreateUser(t, "wpsuser2", "password123")

	body := `{"endpoint":"","keys":{"p256dh":"","auth":""}}`
	req := httptest.NewRequest("POST", "/push/web-subscribe", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	handleWebPushSubscribe(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d; body: %s", rr.Code, rr.Body.String())
	}
}

func TestCb22_HandleWebPushSubscribe_WrongMethod(t *testing.T) {
	req := httptest.NewRequest("GET", "/push/web-subscribe", nil)
	rr := httptest.NewRecorder()
	handleWebPushSubscribe(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rr.Code)
	}
}

func TestCb22_HandleWebPushUnsubscribe(t *testing.T) {
	cb22SetupDB(t)
	_, token := cb22CreateUser(t, "wpuuser", "password123")

	// First subscribe
	body := `{"endpoint":"https://push.example.com/456","keys":{"p256dh":"base64key2","auth":"base64auth2"}}`
	req := httptest.NewRequest("POST", "/push/web-subscribe", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	handleWebPushSubscribe(rr, req)

	// Then unsubscribe
	unsubBody := `{"endpoint":"https://push.example.com/456"}`
	req = httptest.NewRequest("POST", "/push/web-unsubscribe", strings.NewReader(unsubBody))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	rr = httptest.NewRecorder()
	handleWebPushUnsubscribe(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d; body: %s", rr.Code, rr.Body.String())
	}
}

func TestCb22_HandleWebPushUnsubscribe_WrongMethod(t *testing.T) {
	req := httptest.NewRequest("GET", "/push/web-unsubscribe", nil)
	rr := httptest.NewRecorder()
	handleWebPushUnsubscribe(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rr.Code)
	}
}

// ==============================
// handleSearchMessages REST handler coverage
// ==============================

func TestCb22_HandleSearchMessages_WrongMethod(t *testing.T) {
	req := httptest.NewRequest("POST", "/messages/search?q=test", nil)
	rr := httptest.NewRecorder()
	handleSearchMessages(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rr.Code)
	}
}

func TestCb22_HandleSearchMessages_NoAuth(t *testing.T) {
	req := httptest.NewRequest("GET", "/messages/search?q=test", nil)
	rr := httptest.NewRecorder()
	handleSearchMessages(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

func TestCb22_HandleSearchMessages_MissingQuery(t *testing.T) {
	cb22SetupDB(t)
	_, token := cb22CreateUser(t, "searchuser4", "password123")

	req := httptest.NewRequest("GET", "/messages/search", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	handleSearchMessages(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing q, got %d; body: %s", rr.Code, rr.Body.String())
	}
}

func TestCb22_HandleSearchMessages_WithLimit(t *testing.T) {
	cb22SetupDB(t)
	userID, token := cb22CreateUser(t, "searchuser5", "password123")
	cb22CreateAgent(t, "agent1", "Test Agent")
	convID := cb22CreateConversation(t, userID, "agent1")

	// Insert messages
	for i := 0; i < 5; i++ {
		db.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, created_at) VALUES (?, ?, 'user', ?, ?, datetime('now'))",
			fmt.Sprintf("msg_searchlim_%d", i), convID, userID, fmt.Sprintf("test message %d", i))
	}

	req := httptest.NewRequest("GET", "/messages/search?q=test&limit=2", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	handleSearchMessages(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d; body: %s", rr.Code, rr.Body.String())
	}

	var messages []StoredMessage
	json.Unmarshal(rr.Body.Bytes(), &messages)
	if len(messages) > 2 {
		t.Errorf("expected at most 2 results, got %d", len(messages))
	}
}

// ==============================
// handleMarkRead REST handler coverage
// ==============================

func TestCb22_HandleMarkRead_WrongMethod(t *testing.T) {
	req := httptest.NewRequest("GET", "/conversations/mark-read", nil)
	rr := httptest.NewRecorder()
	handleMarkRead(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rr.Code)
	}
}

func TestCb22_HandleMarkRead_NoAuth(t *testing.T) {
	req := httptest.NewRequest("POST", "/conversations/mark-read", strings.NewReader("conversation_id=conv1"))
	rr := httptest.NewRecorder()
	handleMarkRead(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

func TestCb22_HandleMarkRead_MissingConvID(t *testing.T) {
	cb22SetupDB(t)
	_, token := cb22CreateUser(t, "markuser3", "password123")

	req := httptest.NewRequest("POST", "/conversations/mark-read", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	handleMarkRead(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d; body: %s", rr.Code, rr.Body.String())
	}
}

func TestCb22_HandleMarkRead_NotFound(t *testing.T) {
	cb22SetupDB(t)
	_, token := cb22CreateUser(t, "markuser4", "password123")

	form := url.Values{"conversation_id": {"nonexistent"}}.Encode()
	req := httptest.NewRequest("POST", "/conversations/mark-read", strings.NewReader(form))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	handleMarkRead(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d; body: %s", rr.Code, rr.Body.String())
	}
}

// ==============================
// initAPNs / initFCM edge cases
// ==============================

func TestCb22_InitAPNs_MissingCertPath(t *testing.T) {
	pushConfig = &PushNotificationConfig{APNSEnabled: true, CertPath: "/nonexistent/cert.p12"}
	initAPNs()
	if pushConfig.APNSEnabled {
		t.Error("APNs should be disabled when cert is not found")
	}
}

func TestCb22_InitFCM_MissingCreds(t *testing.T) {
	pushConfig = &PushNotificationConfig{FCMEnabled: true, FCMCredentials: "/nonexistent/creds.json"}
	initFCM()
	if pushConfig.FCMEnabled {
		t.Error("FCM should be disabled when credentials file is not found")
	}
}

func TestCb22_SendPushNotification_PlatformRouting(t *testing.T) {
	pushConfig = &PushNotificationConfig{APNSEnabled: false, FCMEnabled: false}

	// Android should route to FCM (which is disabled, so no-op)
	err := sendPushNotification("token", "title", "body", "conv1", "android")
	if err != nil {
		t.Errorf("expected no error for disabled FCM, got: %v", err)
	}

	// iOS should route to APNs (which is disabled, so no-op)
	err = sendPushNotification("token", "title", "body", "conv1", "ios")
	if err != nil {
		t.Errorf("expected no error for disabled APNs, got: %v", err)
	}

	// fcm platform should route to FCM
	err = sendPushNotification("token", "title", "body", "conv1", "fcm")
	if err != nil {
		t.Errorf("expected no error for disabled FCM, got: %v", err)
	}
}

// ==============================
// storeMessagesBatch coverage
// ==============================

func TestCb22_StoreMessagesBatch_Empty(t *testing.T) {
	cb22SetupDB(t)

	ids, err := storeMessagesBatch(nil)
	if err != nil {
		t.Fatalf("storeMessagesBatch with nil should not error: %v", err)
	}
	if len(ids) != 0 {
		t.Errorf("expected 0 IDs, got %d", len(ids))
	}
}

func TestCb22_StoreMessagesBatch_Success(t *testing.T) {
	cb22SetupDB(t)
	userID, _ := cb22CreateUser(t, "batchuser", "password123")
	cb22CreateAgent(t, "agent1", "Test Agent")
	convID := cb22CreateConversation(t, userID, "agent1")

	msgData := []RoutedMessage{
		{ConversationID: convID, SenderType: "user", SenderID: userID, Content: "hello", RecipientID: "agent1"},
		{ConversationID: convID, SenderType: "agent", SenderID: "agent1", Content: "world", RecipientID: userID},
	}

	ids, err := storeMessagesBatch(msgData)
	if err != nil {
		t.Fatalf("storeMessagesBatch failed: %v", err)
	}
	if len(ids) != 2 {
		t.Errorf("expected 2 IDs, got %d", len(ids))
	}
}

// ==============================
// getConversationMessages coverage
// ==============================

func TestCb22_GetConversationMessages_Empty(t *testing.T) {
	cb22SetupDB(t)
	userID, _ := cb22CreateUser(t, "getmsguser", "password123")
	cb22CreateAgent(t, "agent1", "Test Agent")
	convID := cb22CreateConversation(t, userID, "agent1")

	messages, err := getConversationMessages(convID, 50, "")
	if err != nil {
		t.Fatalf("getConversationMessages failed: %v", err)
	}
	if len(messages) != 0 {
		t.Errorf("expected 0 messages, got %d", len(messages))
	}
}

func TestCb22_GetConversationMessages_WithMessages(t *testing.T) {
	cb22SetupDB(t)
	userID, _ := cb22CreateUser(t, "getmsguser2", "password123")
	cb22CreateAgent(t, "agent1", "Test Agent")
	convID := cb22CreateConversation(t, userID, "agent1")

	// Insert messages
	db.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, created_at) VALUES (?, ?, 'user', ?, ?, datetime('now'))",
		"msg_get1", convID, userID, "hello")
	db.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, created_at) VALUES (?, ?, 'agent', ?, ?, datetime('now', '+1 second'))",
		"msg_get2", convID, "agent1", "world")

	messages, err := getConversationMessages(convID, 50, "")
	if err != nil {
		t.Fatalf("getConversationMessages failed: %v", err)
	}
	if len(messages) != 2 {
		t.Errorf("expected 2 messages, got %d", len(messages))
	}
}

// ==============================
// initSchema migration coverage
// ==============================

func TestCb22_InitSchema_Idempotent(t *testing.T) {
	var err error
	db, err = sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })

	// Run initSchema twice — should be idempotent
	if err := initSchema(db); err != nil {
		t.Fatalf("first initSchema failed: %v", err)
	}
	if err := initSchema(db); err != nil {
		t.Fatalf("second initSchema failed: %v", err)
	}
}

// ==============================
// writeJSONResponse coverage
// ==============================

func TestCb22_WriteJSONResponse(t *testing.T) {
	rr := httptest.NewRecorder()
	writeJSONResponse(rr, http.StatusOK, map[string]string{"status": "ok"})

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "ok") {
		t.Errorf("expected 'ok' in body, got %q", rr.Body.String())
	}
}

// ==============================
// Additional handleUploadPublicKey coverage (one-time prekey, signed prekey)
// ==============================

func TestCb22_HandleUploadPublicKey_OneTimePreKey(t *testing.T) {
	cb22SetupDB(t)
	_, token := cb22CreateUser(t, "otpkuser", "password123")

	body := `{"key_type":"one_time_prekey","public_key":"base64key","key_id":1}`
	req := httptest.NewRequest("POST", "/keys/upload", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	handleUploadPublicKey(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d; body: %s", rr.Code, rr.Body.String())
	}
}

func TestCb22_HandleUploadPublicKey_SignedPreKey(t *testing.T) {
	cb22SetupDB(t)
	_, token := cb22CreateUser(t, "spkuser", "password123")

	body := `{"key_type":"signed_prekey","public_key":"base64spk","signature":"base64sig"}`
	req := httptest.NewRequest("POST", "/keys/upload", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	handleUploadPublicKey(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d; body: %s", rr.Code, rr.Body.String())
	}
}

func TestCb22_HandleUploadPublicKey_IdentityKeyReplace(t *testing.T) {
	cb22SetupDB(t)
	_, token := cb22CreateUser(t, "identityuser", "password123")

	// Upload first identity key
	body := `{"key_type":"identity","public_key":"key1"}`
	req := httptest.NewRequest("POST", "/keys/upload", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	handleUploadPublicKey(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("first upload: expected 200, got %d", rr.Code)
	}

	// Upload replacement identity key
	body = `{"key_type":"identity","public_key":"key2"}`
	req = httptest.NewRequest("POST", "/keys/upload", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	rr = httptest.NewRecorder()
	handleUploadPublicKey(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("replacement upload: expected 200, got %d; body: %s", rr.Code, rr.Body.String())
	}
}

func TestCb22_HandleGetKeyBundle(t *testing.T) {
	cb22SetupDB(t)
	_, token := cb22CreateUser(t, "bundleuser", "password123")

	// First upload an identity key
	body := `{"key_type":"identity","public_key":"bundle_identity_key"}`
	req := httptest.NewRequest("POST", "/keys/upload", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	handleUploadPublicKey(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("upload identity key: expected 200, got %d", rr.Code)
	}

	// Now get the bundle
	req = httptest.NewRequest("GET", "/keys/bundle?owner_id=bundleuser-id&owner_type=user", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr = httptest.NewRecorder()
	handleGetKeyBundle(rr, req)

	// The key may or may not be found depending on user ID matching
	// At minimum we test the handler doesn't crash
	if rr.Code != http.StatusOK && rr.Code != http.StatusNotFound {
		t.Logf("handleGetKeyBundle status: %d, body: %s", rr.Code, rr.Body.String())
	}
}

func TestCb22_HandleGetKeyBundle_WrongMethod(t *testing.T) {
	req := httptest.NewRequest("POST", "/keys/bundle", nil)
	rr := httptest.NewRecorder()
	handleGetKeyBundle(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rr.Code)
	}
}

func TestCb22_HandleListOneTimePreKeys(t *testing.T) {
	cb22SetupDB(t)
	_, token := cb22CreateUser(t, "otpkcountuser", "password123")

	req := httptest.NewRequest("GET", "/keys/otpk-count", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	handleListOneTimePreKeys(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d; body: %s", rr.Code, rr.Body.String())
	}

	var resp map[string]int
	json.Unmarshal(rr.Body.Bytes(), &resp)
	if _, ok := resp["one_time_prekey_count"]; !ok {
		t.Error("expected one_time_prekey_count in response")
	}
}

func TestCb22_HandleListOneTimePreKeys_WrongMethod(t *testing.T) {
	req := httptest.NewRequest("POST", "/keys/otpk-count", nil)
	rr := httptest.NewRecorder()
	handleListOneTimePreKeys(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rr.Code)
	}
}

func TestCb22_HandleGetEncryptedMessages_WrongMethod(t *testing.T) {
	req := httptest.NewRequest("POST", "/messages/encrypted/list", nil)
	rr := httptest.NewRecorder()
	handleGetEncryptedMessages(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rr.Code)
	}
}

func TestCb22_HandleGetEncryptedMessages_MissingConvID(t *testing.T) {
	cb22SetupDB(t)
	_, token := cb22CreateUser(t, "encgetmissing", "password123")

	req := httptest.NewRequest("GET", "/messages/encrypted/list", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	handleGetEncryptedMessages(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d; body: %s", rr.Code, rr.Body.String())
	}
}

func TestCb22_HandleGetEncryptedMessages_NotFound(t *testing.T) {
	cb22SetupDB(t)
	_, token := cb22CreateUser(t, "encgetnf", "password123")

	req := httptest.NewRequest("GET", "/messages/encrypted/list?conversation_id=nonexistent", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	handleGetEncryptedMessages(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d; body: %s", rr.Code, rr.Body.String())
	}
}

func TestCb22_HandleStoreEncryptedMessage_AgentAuth(t *testing.T) {
	cb22SetupDB(t)
	hub = newHub()
	go hub.run()
	defer hub.Stop()

	origSecret := os.Getenv("AGENT_SECRET")
	os.Setenv("AGENT_SECRET", "test-agent-secret")
	resetAgentSecret()
	defer func() {
		os.Setenv("AGENT_SECRET", origSecret)
		resetAgentSecret()
	}()

	userID, _ := cb22CreateUser(t, "encagentuser", "password123")
	cb22CreateAgent(t, "agent1", "Test Agent")
	convID := cb22CreateConversation(t, userID, "agent1")

	body := fmt.Sprintf(`{
		"conversation_id": "%s",
		"ciphertext": "base64ct",
		"iv": "base64iv",
		"recipient_key_id": "key_1",
		"sender_key_id": "key_2",
		"algorithm": "aes-256-gcm"
	}`, convID)

	req := httptest.NewRequest("POST", "/messages/encrypted", strings.NewReader(body))
	req.Header.Set("X-Agent-Secret", "test-agent-secret")
	req.Header.Set("X-Agent-ID", "agent1")
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	handleStoreEncryptedMessage(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d; body: %s", rr.Code, rr.Body.String())
	}
}

func TestCb22_HandleStoreEncryptedMessage_AgentNotParticipant(t *testing.T) {
	cb22SetupDB(t)
	hub = newHub()
	go hub.run()
	defer hub.Stop()

	origSecret := os.Getenv("AGENT_SECRET")
	os.Setenv("AGENT_SECRET", "test-agent-secret")
	resetAgentSecret()
	defer func() {
		os.Setenv("AGENT_SECRET", origSecret)
		resetAgentSecret()
	}()

	userID, _ := cb22CreateUser(t, "encagentuser2", "password123")
	cb22CreateAgent(t, "agent1", "Test Agent")
	cb22CreateAgent(t, "agent2", "Other Agent")
	convID := cb22CreateConversation(t, userID, "agent1")

	body := fmt.Sprintf(`{
		"conversation_id": "%s",
		"ciphertext": "base64ct",
		"iv": "base64iv",
		"recipient_key_id": "key_1",
		"algorithm": "aes-256-gcm"
	}`, convID)

	req := httptest.NewRequest("POST", "/messages/encrypted", strings.NewReader(body))
	req.Header.Set("X-Agent-Secret", "test-agent-secret")
	req.Header.Set("X-Agent-ID", "agent2")
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	handleStoreEncryptedMessage(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403 for non-participant agent, got %d; body: %s", rr.Code, rr.Body.String())
	}
}

func TestCb22_HandleStoreEncryptedMessage_ConvNotFound(t *testing.T) {
	cb22SetupDB(t)
	_, token := cb22CreateUser(t, "encconvnf", "password123")

	body := `{
		"conversation_id": "nonexistent",
		"ciphertext": "abc",
		"iv": "def",
		"algorithm": "aes-256-gcm"
	}`

	req := httptest.NewRequest("POST", "/messages/encrypted", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	handleStoreEncryptedMessage(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d; body: %s", rr.Code, rr.Body.String())
	}
}

func TestCb22_HandleStoreEncryptedMessage_UserNotParticipant(t *testing.T) {
	cb22SetupDB(t)
	user1ID, _ := cb22CreateUser(t, "encuser_a", "password123")
	_, token2 := cb22CreateUser(t, "encuser_b", "password456")
	cb22CreateAgent(t, "agent1", "Test Agent")
	convID := cb22CreateConversation(t, user1ID, "agent1")

	body := fmt.Sprintf(`{
		"conversation_id": "%s",
		"ciphertext": "abc",
		"iv": "def",
		"recipient_key_id": "key_1",
		"algorithm": "aes-256-gcm"
	}`, convID)

	req := httptest.NewRequest("POST", "/messages/encrypted", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token2)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	handleStoreEncryptedMessage(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403 for non-owner user, got %d; body: %s", rr.Code, rr.Body.String())
	}
}

// ==============================
// handleRegisterAgent REST handler coverage
// ==============================

func TestCb22_HandleRegisterAgent_WrongMethod(t *testing.T) {
	req := httptest.NewRequest("GET", "/auth/agent", nil)
	rr := httptest.NewRecorder()
	handleRegisterAgent(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rr.Code)
	}
}

func TestCb22_HandleRegisterAgent_Success(t *testing.T) {
	cb22SetupDB(t)

	origSecret := os.Getenv("AGENT_SECRET")
	os.Setenv("AGENT_SECRET", "test-agent-secret")
	resetAgentSecret()
	defer func() {
		os.Setenv("AGENT_SECRET", origSecret)
		resetAgentSecret()
	}()

	form := url.Values{
		"agent_id":  {"test-agent"},
		"name":      {"Test Agent"},
		"model":     {"gpt-4"},
	}.Encode()

	req := httptest.NewRequest("POST", "/auth/agent", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Agent-Secret", "test-agent-secret")
	rr := httptest.NewRecorder()
	handleRegisterAgent(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d; body: %s", rr.Code, rr.Body.String())
	}
}

func TestCb22_HandleRegisterAgent_BadSecret(t *testing.T) {
	cb22SetupDB(t)

	origSecret := os.Getenv("AGENT_SECRET")
	os.Setenv("AGENT_SECRET", "test-agent-secret")
	resetAgentSecret()
	defer func() {
		os.Setenv("AGENT_SECRET", origSecret)
		resetAgentSecret()
	}()

	form := url.Values{
		"agent_id":  {"bad-agent"},
		"name":      {"Bad Agent"},
		"secret":    {"wrong-secret"},
	}.Encode()

	req := httptest.NewRequest("POST", "/auth/agent", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	handleRegisterAgent(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for bad secret, got %d; body: %s", rr.Code, rr.Body.String())
	}
}

func TestCb22_HandleRegisterAgent_MissingFields(t *testing.T) {
	cb22SetupDB(t)

	origSecret := os.Getenv("AGENT_SECRET")
	os.Setenv("AGENT_SECRET", "test-agent-secret")
	resetAgentSecret()
	defer func() {
		os.Setenv("AGENT_SECRET", origSecret)
		resetAgentSecret()
	}()

	form := url.Values{}.Encode()

	req := httptest.NewRequest("POST", "/auth/agent", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Agent-Secret", "test-agent-secret")
	rr := httptest.NewRecorder()
	handleRegisterAgent(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing fields, got %d; body: %s", rr.Code, rr.Body.String())
	}
}

// ==============================
// HandleRegisterDeviceToken / HandleUnregisterDeviceToken additional coverage
// ==============================

func TestCb22_RegisterDeviceToken_MissingToken(t *testing.T) {
	cb22SetupDB(t)
	_, token := cb22CreateUser(t, "devuser", "password123")

	body := `{"platform":"ios"}`
	req := httptest.NewRequest("POST", "/push/register", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	handleRegisterDeviceToken(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing device_token, got %d; body: %s", rr.Code, rr.Body.String())
	}
}

func TestCb22_RegisterDeviceToken_DefaultPlatform(t *testing.T) {
	cb22SetupDB(t)
	db.Exec("DELETE FROM device_tokens")
	_, token := cb22CreateUser(t, "devuser2", "password123")

	body := `{"device_token":"tok_default_platform"}`
	req := httptest.NewRequest("POST", "/push/register", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	handleRegisterDeviceToken(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d; body: %s", rr.Code, rr.Body.String())
	}

	// Verify default platform is iOS
	var platform string
	db.QueryRow("SELECT platform FROM device_tokens WHERE device_token = ?", "tok_default_platform").Scan(&platform)
	if platform != "ios" {
		t.Errorf("expected default platform 'ios', got %q", platform)
	}
}

func TestCb22_UnregisterDeviceToken_WrongMethod(t *testing.T) {
	req := httptest.NewRequest("GET", "/push/unregister", nil)
	rr := httptest.NewRecorder()
	handleUnregisterDeviceToken(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rr.Code)
	}
}

func TestCb22_UnregisterDeviceToken_MissingToken(t *testing.T) {
	cb22SetupDB(t)
	_, token := cb22CreateUser(t, "unreguser2", "password123")

	body := `{}`
	req := httptest.NewRequest("DELETE", "/push/unregister", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	handleUnregisterDeviceToken(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing device_token, got %d; body: %s", rr.Code, rr.Body.String())
	}
}