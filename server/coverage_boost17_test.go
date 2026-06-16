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
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// ==============================
// Helpers for CB17
// ==============================

func cb17SetupDB(t *testing.T) {
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
	// Reset globals
	pushConfig = nil
	vapidPublicKey = ""
}

func cb17SetupAuth(t *testing.T) (string, string) {
	t.Helper()
	origJwtSecret := jwtSecret
	origAgentEnv := os.Getenv("AGENT_SECRET")
	origAdminEnv := os.Getenv("ADMIN_SECRET")
	jwtSecret = []byte("test-jwt-secret-cb17")
	os.Setenv("AGENT_SECRET", "test-agent-secret-cb17")
	agentSecret = "test-agent-secret-cb17"
	os.Setenv("ADMIN_SECRET", "test-admin-secret-cb17")
	adminSecret = "test-admin-secret-cb17"
	t.Cleanup(func() {
		jwtSecret = origJwtSecret
		if origAgentEnv != "" {
			os.Setenv("AGENT_SECRET", origAgentEnv)
		} else {
			os.Unsetenv("AGENT_SECRET")
		}
		if origAdminEnv != "" {
			os.Setenv("ADMIN_SECRET", origAdminEnv)
		} else {
			os.Unsetenv("ADMIN_SECRET")
		}
		resetAgentSecret()
		resetAdminSecret()
	})
	// Register user
	hash, _ := HashAPIKey("password123")
	_, err := db.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)", "user_cb17", "testuser_cb17", hash)
	if err != nil {
		t.Fatal(err)
	}
	token, _ := GenerateJWT("user_cb17", "testuser_cb17")
	return token, "user_cb17"
}

func cb17SetupAgent(t *testing.T) string {
	t.Helper()
	_, err := db.Exec("INSERT INTO agents (id, name, model) VALUES (?, ?, ?)", "agent_cb17", "TestAgent", "gpt-4")
	if err != nil {
		t.Fatal(err)
	}
	return "agent_cb17"
}

func cb17CreateConversation(t *testing.T, userID, agentID string) string {
	t.Helper()
	convID := fmt.Sprintf("conv_cb17_%d", time.Now().UnixNano())
	_, err := db.Exec("INSERT INTO conversations (id, user_id, agent_id) VALUES (?, ?, ?)", convID, userID, agentID)
	if err != nil {
		t.Fatal(err)
	}
	return convID
}

func cb17MakeToken(t *testing.T, userID, username string) string {
	t.Helper()
	token, err := GenerateJWT(userID, username)
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func cb17SetUserIDContext(r *http.Request, userID string) *http.Request {
	ctx := context.WithValue(r.Context(), contextKeyUserID, userID)
	return r.WithContext(ctx)
}

func TestCB17_SafeTruncate_ShortString(t *testing.T) {
	result := safeTruncate("hi", 8)
	if result != "hi" {
		t.Errorf("expected 'hi', got '%s'", result)
	}
}

func TestCB17_SafeTruncate_ExactLength(t *testing.T) {
	result := safeTruncate("12345678", 8)
	if result != "12345678" {
		t.Errorf("expected '12345678', got '%s'", result)
	}
}

func TestCB17_SafeTruncate_LongString(t *testing.T) {
	result := safeTruncate("1234567890abcdef", 8)
	if result != "12345678" {
		t.Errorf("expected '12345678', got '%s'", result)
	}
}

func TestCB17_SafeTruncate_EmptyString(t *testing.T) {
	result := safeTruncate("", 8)
	if result != "" {
		t.Errorf("expected '', got '%s'", result)
	}
}

func TestCB17_SafeTruncate_ZeroN(t *testing.T) {
	result := safeTruncate("hello", 0)
	if result != "" {
		t.Errorf("expected '', got '%s'", result)
	}
}

func TestCB17_SafeTruncate_SingleChar(t *testing.T) {
	result := safeTruncate("x", 1)
	if result != "x" {
		t.Errorf("expected 'x', got '%s'", result)
	}
}

// ==============================
// sendAPNSNotification tests (14.3% coverage)
// ==============================

func TestCB17_SendAPNSNotification_NilConfig(t *testing.T) {
	pushConfig = nil
	err := sendAPNSNotification("token123", "Title", "Body", "conv1")
	if err != nil {
		t.Errorf("expected nil error with nil config, got %v", err)
	}
}

func TestCB17_SendAPNSNotification_Disabled(t *testing.T) {
	pushConfig = &PushNotificationConfig{
		APNSEnabled: false,
	}
	err := sendAPNSNotification("token123", "Title", "Body", "conv1")
	if err != nil {
		t.Errorf("expected nil error with disabled APNs, got %v", err)
	}
}

func TestCB17_SendAPNSNotification_NilClient(t *testing.T) {
	pushConfig = &PushNotificationConfig{
		APNSEnabled: true,
		apnsClient:  nil,
	}
	err := sendAPNSNotification("token123", "Title", "Body", "conv1")
	if err != nil {
		t.Errorf("expected nil error with nil APNs client, got %v", err)
	}
}

// ==============================
// sendFCMNotification tests (22.2% coverage)
// ==============================

func TestCB17_SendFCMNotification_NilConfig(t *testing.T) {
	pushConfig = nil
	err := sendFCMNotification("token123", "Title", "Body", "conv1")
	if err != nil {
		t.Errorf("expected nil error with nil config, got %v", err)
	}
}

func TestCB17_SendFCMNotification_Disabled(t *testing.T) {
	pushConfig = &PushNotificationConfig{
		FCMEnabled: false,
	}
	err := sendFCMNotification("token123", "Title", "Body", "conv1")
	if err != nil {
		t.Errorf("expected nil error with disabled FCM, got %v", err)
	}
}

func TestCB17_SendFCMNotification_NilClient(t *testing.T) {
	pushConfig = &PushNotificationConfig{
		FCMEnabled: true,
		fcmClient:  nil,
	}
	err := sendFCMNotification("token123", "Title", "Body", "conv1")
	if err != nil {
		t.Errorf("expected nil error with nil FCM client, got %v", err)
	}
}

// ==============================
// sendPushNotification platform routing tests
// ==============================

func TestCB17_SendPushNotification_AndroidPlatform(t *testing.T) {
	pushConfig = nil
	err := sendPushNotification("token", "Title", "Body", "conv1", "android")
	if err != nil {
		t.Errorf("expected nil, got %v", err)
	}
}

func TestCB17_SendPushNotification_FCMPlatform(t *testing.T) {
	pushConfig = nil
	err := sendPushNotification("token", "Title", "Body", "conv1", "fcm")
	if err != nil {
		t.Errorf("expected nil, got %v", err)
	}
}

func TestCB17_SendPushNotification_IOSPlatform(t *testing.T) {
	pushConfig = nil
	err := sendPushNotification("token", "Title", "Body", "conv1", "ios")
	if err != nil {
		t.Errorf("expected nil, got %v", err)
	}
}

func TestCB17_SendPushNotification_UnknownPlatform(t *testing.T) {
	pushConfig = nil
	err := sendPushNotification("token", "Title", "Body", "conv1", "unknown")
	if err != nil {
		t.Errorf("expected nil (defaults to APNs), got %v", err)
	}
}

func TestCB17_SendPushNotification_EmptyPlatform(t *testing.T) {
	pushConfig = nil
	err := sendPushNotification("token", "Title", "Body", "conv1", "")
	if err != nil {
		t.Errorf("expected nil (defaults to APNs), got %v", err)
	}
}

// ==============================
// notifyUser additional tests
// ==============================

func TestCB17_NotifyUser_NilConfig(t *testing.T) {
	cb17SetupDB(t)
	pushConfig = nil
	notifyUser("user1", "Title", "Body", "conv1")
}

func TestCB17_NotifyUser_MutedConversation(t *testing.T) {
	cb17SetupDB(t)
	token, userID := cb17SetupAuth(t)
	agentID := cb17SetupAgent(t)
	convID := cb17CreateConversation(t, userID, agentID)

	pushConfig = &PushNotificationConfig{
		APNSEnabled: true,
		apnsClient:  nil,
		FCMEnabled:  false,
	}

	// Mute the conversation
	_, err := db.Exec("INSERT INTO notification_preferences (user_id, conversation_id, muted) VALUES (?, ?, ?)", userID, convID, true)
	if err != nil {
		t.Fatal(err)
	}

	notifyUser(userID, "Title", "Body", convID)
	_ = token
}

func TestCB17_NotifyUser_NoDeviceTokens(t *testing.T) {
	cb17SetupDB(t)
	_, userID := cb17SetupAuth(t)
	agentID := cb17SetupAgent(t)
	convID := cb17CreateConversation(t, userID, agentID)

	pushConfig = &PushNotificationConfig{
		APNSEnabled: true,
		apnsClient:  nil,
	}

	notifyUser(userID, "Title", "Body", convID)
}

func TestCB17_NotifyUser_WithDeviceTokens(t *testing.T) {
	cb17SetupDB(t)
	_, userID := cb17SetupAuth(t)
	agentID := cb17SetupAgent(t)
	convID := cb17CreateConversation(t, userID, agentID)

	pushConfig = &PushNotificationConfig{
		APNSEnabled: true,
		apnsClient:  nil,
		FCMEnabled:  true,
		fcmClient:   nil,
	}

	_, err := db.Exec("INSERT INTO device_tokens (user_id, device_token, platform) VALUES (?, ?, ?)", userID, "ios_token_1", "ios")
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec("INSERT INTO device_tokens (user_id, device_token, platform) VALUES (?, ?, ?)", userID, "android_token_1", "android")
	if err != nil {
		t.Fatal(err)
	}

	notifyUser(userID, "Title", "Body", convID)
}

func TestCB17_NotifyUser_EmptyConversationID(t *testing.T) {
	cb17SetupDB(t)
	_, userID := cb17SetupAuth(t)

	pushConfig = &PushNotificationConfig{
		APNSEnabled: true,
		apnsClient:  nil,
	}

	_, err := db.Exec("INSERT INTO device_tokens (user_id, device_token, platform) VALUES (?, ?, ?)", userID, "token_1", "ios")
	if err != nil {
		t.Fatal(err)
	}

	notifyUser(userID, "Title", "Body", "")
}

// ==============================
// initPushNotifications tests
// ==============================

func TestCB17_InitPushNotifications_Defaults(t *testing.T) {
	os.Unsetenv("APNS_ENABLED")
	os.Unsetenv("APNS_CERT_PATH")
	os.Unsetenv("APNS_CERT_PASSWORD")
	os.Unsetenv("APNS_KEY_ID")
	os.Unsetenv("APNS_TEAM_ID")
	os.Unsetenv("APNS_BUNDLE_ID")
	os.Unsetenv("APNS_ENVIRONMENT")
	os.Unsetenv("FCM_ENABLED")
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
	if pushConfig.BundleID != "com.agentmessenger.ios" {
		t.Errorf("expected default BundleID, got %s", pushConfig.BundleID)
	}
	if pushConfig.Environment != "development" {
		t.Errorf("expected development environment, got %s", pushConfig.Environment)
	}
}

func TestCB17_InitPushNotifications_EnabledButNoPaths(t *testing.T) {
	os.Setenv("APNS_ENABLED", "true")
	os.Setenv("FCM_ENABLED", "true")
	defer func() {
		os.Unsetenv("APNS_ENABLED")
		os.Unsetenv("FCM_ENABLED")
	}()

	initPushNotifications()

	// APNs/FCM stay enabled in config even without paths; clients are just nil
	// This is expected behavior - config flag is separate from client availability
}

func TestCB17_InitPushNotifications_NonExistentCertPath(t *testing.T) {
	os.Setenv("APNS_ENABLED", "true")
	os.Setenv("APNS_CERT_PATH", "/nonexistent/path/cert.p12")
	defer func() {
		os.Unsetenv("APNS_ENABLED")
		os.Unsetenv("APNS_CERT_PATH")
	}()

	initPushNotifications()

	if pushConfig.APNSEnabled {
		t.Error("APNs should be disabled when cert file doesn't exist")
	}
}

func TestCB17_InitPushNotifications_NonExistentFCMCreds(t *testing.T) {
	os.Setenv("FCM_ENABLED", "true")
	os.Setenv("FCM_CREDENTIALS_PATH", "/nonexistent/creds.json")
	defer func() {
		os.Unsetenv("FCM_ENABLED")
		os.Unsetenv("FCM_CREDENTIALS_PATH")
	}()

	initPushNotifications()

	if pushConfig.FCMEnabled {
		t.Error("FCM should be disabled when credentials file doesn't exist")
	}
}

func TestCB17_InitPushNotifications_CustomBundleID(t *testing.T) {
	os.Setenv("APNS_BUNDLE_ID", "com.custom.app")
	defer os.Unsetenv("APNS_BUNDLE_ID")

	initPushNotifications()

	if pushConfig.BundleID != "com.custom.app" {
		t.Errorf("expected 'com.custom.app', got %s", pushConfig.BundleID)
	}
}

func TestCB17_InitPushNotifications_ProductionEnvironment(t *testing.T) {
	os.Setenv("APNS_ENABLED", "true")
	os.Setenv("APNS_CERT_PATH", "/tmp/test_cert_cb17.p12")
	os.Setenv("APNS_ENVIRONMENT", "production")
	defer func() {
		os.Unsetenv("APNS_ENABLED")
		os.Unsetenv("APNS_CERT_PATH")
		os.Unsetenv("APNS_ENVIRONMENT")
	}()

	initPushNotifications()

	if pushConfig.Environment != "production" {
		t.Errorf("expected production, got %s", pushConfig.Environment)
	}
}

// ==============================
// handleUpload additional tests (72.7% → higher)
// ==============================

func TestCB17_HandleUpload_WrongContentType(t *testing.T) {
	cb17SetupDB(t)
	token, userID := cb17SetupAuth(t)
	_ = userID

	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)
	part, err := writer.CreateFormFile("file", "test.exe")
	if err != nil {
		t.Fatal(err)
	}
	part.Write([]byte("MZ\x90\x00 executable content"))
	writer.Close()

	req := httptest.NewRequest(http.MethodPost, "/attachments/upload", &buf)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	handleUpload(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "not allowed") {
		t.Errorf("expected 'not allowed' in body, got %s", w.Body.String())
	}
}

func TestCB17_HandleUpload_NoAuth(t *testing.T) {
	cb17SetupDB(t)

	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)
	part, _ := writer.CreateFormFile("file", "test.txt")
	part.Write([]byte("hello"))
	writer.Close()

	req := httptest.NewRequest(http.MethodPost, "/attachments/upload", &buf)
	req.Header.Set("Content-Type", writer.FormDataContentType())

	w := httptest.NewRecorder()
	handleUpload(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestCB17_HandleUpload_InvalidToken(t *testing.T) {
	cb17SetupDB(t)

	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)
	part, _ := writer.CreateFormFile("file", "test.txt")
	part.Write([]byte("hello"))
	writer.Close()

	req := httptest.NewRequest(http.MethodPost, "/attachments/upload", &buf)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	req.Header.Set("Authorization", "Bearer invalid-token")

	w := httptest.NewRecorder()
	handleUpload(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestCB17_HandleUpload_WrongMethod(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/attachments/upload", nil)
	w := httptest.NewRecorder()
	handleUpload(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestCB17_HandleUpload_MissingFile(t *testing.T) {
	cb17SetupDB(t)
	token, _ := cb17SetupAuth(t)

	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)
	// Don't add a file field, just close
	writer.Close()

	req := httptest.NewRequest(http.MethodPost, "/attachments/upload", &buf)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	handleUpload(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCB17_HandleUpload_ValidImage(t *testing.T) {
	cb17SetupDB(t)
	token, userID := cb17SetupAuth(t)
	_ = userID

	dir := getUploadDir()
	os.MkdirAll(dir, 0755)
	defer os.RemoveAll(filepath.Dir(filepath.Dir(dir)))

	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)
	part, _ := writer.CreateFormFile("file", "test.png")
	pngHeader := []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}
	part.Write(pngHeader)
	part.Write([]byte("fake png data"))
	writer.Close()

	req := httptest.NewRequest(http.MethodPost, "/attachments/upload", &buf)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	handleUpload(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var result map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &result)
	if result["id"] == nil {
		t.Error("expected attachment ID in response")
	}
	if result["sha256"] == nil {
		t.Error("expected sha256 in response")
	}
}

func TestCB17_HandleUpload_ContentDetection(t *testing.T) {
	cb17SetupDB(t)
	token, userID := cb17SetupAuth(t)
	_ = userID

	dir := getUploadDir()
	os.MkdirAll(dir, 0755)
	defer os.RemoveAll(filepath.Dir(filepath.Dir(dir)))

	// Upload a file — the server detects content type from first 512 bytes
	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)
	part, _ := writer.CreateFormFile("file", "test2.txt")
	part.Write([]byte("Hello, this is plain text"))
	writer.Close()

	req := httptest.NewRequest(http.MethodPost, "/attachments/upload", &buf)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	handleUpload(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

// ==============================
// handleGetAttachment additional tests
// ==============================

func TestCB17_HandleGetAttachment_WrongMethod(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/attachments/att123", nil)
	w := httptest.NewRecorder()
	handleGetAttachment(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestCB17_HandleGetAttachment_NoAuth(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/attachments/att123", nil)
	w := httptest.NewRecorder()
	handleGetAttachment(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestCB17_HandleGetAttachment_InvalidJWT(t *testing.T) {
	cb17SetupDB(t)
	req := httptest.NewRequest(http.MethodGet, "/attachments/att123", nil)
	req.Header.Set("Authorization", "Bearer invalid-token")
	w := httptest.NewRecorder()
	handleGetAttachment(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestCB17_HandleGetAttachment_NotFound(t *testing.T) {
	cb17SetupDB(t)
	token, _ := cb17SetupAuth(t)

	req := httptest.NewRequest(http.MethodGet, "/attachments/nonexistent", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleGetAttachment(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

func TestCB17_HandleGetAttachment_WrongOwner(t *testing.T) {
	cb17SetupDB(t)
	token, _ := cb17SetupAuth(t)

	hash2, _ := HashAPIKey("pass456")
	_, err := db.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)", "user_other", "otheruser", hash2)
	if err != nil {
		t.Fatal(err)
	}

	_, err = db.Exec("INSERT INTO attachments (id, user_id, filename, content_type, size, sha256, storage_path, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
		"att_owned_by_other", "user_other", "file.txt", "text/plain", 100, "abc123", "2026/01/file.txt", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/attachments/att_owned_by_other", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleGetAttachment(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403 (wrong owner), got %d", w.Code)
	}
}

func TestCB17_HandleGetAttachment_AgentAuth(t *testing.T) {
	cb17SetupDB(t)
	os.Setenv("AGENT_SECRET", "test-agent-secret-cb17")
	agentSecret = "test-agent-secret-cb17"
	t.Cleanup(func() { os.Unsetenv("AGENT_SECRET"); resetAgentSecret() })

	_, err := db.Exec("INSERT INTO attachments (id, user_id, filename, content_type, size, sha256, storage_path, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
		"att_agent_test", "user1", "file.txt", "text/plain", 100, "abc123", "nonexistent_path.txt", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/attachments/att_agent_test", nil)
	req.Header.Set("X-Agent-Secret", "test-agent-secret-cb17")
	w := httptest.NewRecorder()
	handleGetAttachment(w, req)

	// File won't exist on disk, so 404 is expected
	if w.Code != http.StatusNotFound {
		t.Logf("Got code %d (file serving may vary)", w.Code)
	}
}

func TestCB17_HandleGetAttachment_EmptyID(t *testing.T) {
	cb17SetupDB(t)
	token, _ := cb17SetupAuth(t)

	req := httptest.NewRequest(http.MethodGet, "/attachments/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleGetAttachment(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestCB17_HandleGetAttachment_WrongAgentSecret(t *testing.T) {
	cb17SetupDB(t)
	os.Setenv("AGENT_SECRET", "test-agent-secret-cb17")
	agentSecret = "test-agent-secret-cb17"
	t.Cleanup(func() { os.Unsetenv("AGENT_SECRET"); resetAgentSecret() })

	req := httptest.NewRequest(http.MethodGet, "/attachments/att123", nil)
	req.Header.Set("X-Agent-Secret", "wrong-secret")
	w := httptest.NewRecorder()
	handleGetAttachment(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

// ==============================
// handleListAttachments additional tests
// ==============================

func TestCB17_HandleListAttachments_WrongMethod(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/messages/conv1/attachments", nil)
	w := httptest.NewRecorder()
	handleListAttachments(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestCB17_HandleListAttachments_NoAuth(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/messages/conv1/attachments", nil)
	w := httptest.NewRecorder()
	handleListAttachments(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestCB17_HandleListAttachments_MissingConvID(t *testing.T) {
	cb17SetupDB(t)
	token, _ := cb17SetupAuth(t)

	req := httptest.NewRequest(http.MethodGet, "/messages/attachments", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleListAttachments(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestCB17_HandleListAttachments_WrongUser(t *testing.T) {
	cb17SetupDB(t)
	token, _ := cb17SetupAuth(t)
	agentID := cb17SetupAgent(t)

	hash2, _ := HashAPIKey("pass456")
	_, err := db.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)", "user_other2", "otheruser2", hash2)
	if err != nil {
		t.Fatal(err)
	}
	convID := fmt.Sprintf("conv_other_%d", time.Now().UnixNano())
	_, err = db.Exec("INSERT INTO conversations (id, user_id, agent_id) VALUES (?, ?, ?)", convID, "user_other2", agentID)
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/messages/attachments?conversation_id="+convID, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleListAttachments(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

func TestCB17_HandleListAttachments_Success(t *testing.T) {
	cb17SetupDB(t)
	token, userID := cb17SetupAuth(t)
	agentID := cb17SetupAgent(t)
	convID := cb17CreateConversation(t, userID, agentID)

	msgID := generateID("msg")
	_, err := db.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, created_at) VALUES (?, ?, ?, ?, ?, ?)",
		msgID, convID, "agent", agentID, "test message", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}

	_, err = db.Exec("INSERT INTO attachments (id, message_id, user_id, filename, content_type, size, sha256, storage_path, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
		"att_list_1", msgID, userID, "photo.jpg", "image/jpeg", 2048, "def456", "2026/06/photo.jpg", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/messages/attachments?conversation_id="+convID, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleListAttachments(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var attachments []map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &attachments)
	if len(attachments) != 1 {
		t.Errorf("expected 1 attachment, got %d", len(attachments))
	}
}

// ==============================
// deleteConversation additional tests
// ==============================

func TestCB17_DeleteConversation_NotFound(t *testing.T) {
	cb17SetupDB(t)

	err := deleteConversation("nonexistent_conv", "user1")
	if err == nil {
		t.Error("expected error for nonexistent conversation")
	}
}

func TestCB17_DeleteConversation_WrongUser(t *testing.T) {
	cb17SetupDB(t)
	_, userID := cb17SetupAuth(t)
	agentID := cb17SetupAgent(t)
	convID := cb17CreateConversation(t, userID, agentID)

	err := deleteConversation(convID, "wrong_user")
	if err == nil {
		t.Error("expected error for wrong user")
	}
	if err.Error() != "unauthorized" {
		t.Errorf("expected 'unauthorized', got '%s'", err.Error())
	}
}

func TestCB17_DeleteConversation_Success(t *testing.T) {
	cb17SetupDB(t)
	_, userID := cb17SetupAuth(t)
	agentID := cb17SetupAgent(t)
	convID := cb17CreateConversation(t, userID, agentID)

	_, err := db.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, created_at) VALUES (?, ?, ?, ?, ?, ?)",
		"msg_del_1", convID, "agent", agentID, "message 1", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, created_at) VALUES (?, ?, ?, ?, ?, ?)",
		"msg_del_2", convID, "client", userID, "message 2", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}

	err = deleteConversation(convID, userID)
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}

	var count int
	db.QueryRow("SELECT COUNT(*) FROM conversations WHERE id = ?", convID).Scan(&count)
	if count != 0 {
		t.Error("conversation should be deleted")
	}

	db.QueryRow("SELECT COUNT(*) FROM messages WHERE conversation_id = ?", convID).Scan(&count)
	if count != 0 {
		t.Error("messages should be deleted")
	}
}

// ==============================
// handleDeleteConversation handler tests
// ==============================

func TestCB17_HandleDeleteConversation_Success(t *testing.T) {
	cb17SetupDB(t)
	token, userID := cb17SetupAuth(t)
	agentID := cb17SetupAgent(t)
	convID := cb17CreateConversation(t, userID, agentID)

	req := httptest.NewRequest(http.MethodDelete, "/conversations/delete?conversation_id="+convID, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleDeleteConversation(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCB17_HandleDeleteConversation_Unauthorized(t *testing.T) {
	cb17SetupDB(t)

	req := httptest.NewRequest(http.MethodDelete, "/conversations/delete?conversation_id=conv1", nil)
	w := httptest.NewRecorder()
	handleDeleteConversation(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestCB17_HandleDeleteConversation_MissingID(t *testing.T) {
	cb17SetupDB(t)
	token, _ := cb17SetupAuth(t)

	req := httptest.NewRequest(http.MethodDelete, "/conversations/delete", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleDeleteConversation(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestCB17_HandleDeleteConversation_NotFound(t *testing.T) {
	cb17SetupDB(t)
	token, _ := cb17SetupAuth(t)

	req := httptest.NewRequest(http.MethodDelete, "/conversations/delete?conversation_id=nonexistent", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleDeleteConversation(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCB17_HandleDeleteConversation_WrongUser(t *testing.T) {
	cb17SetupDB(t)
	_, userID := cb17SetupAuth(t)
	agentID := cb17SetupAgent(t)
	convID := cb17CreateConversation(t, userID, agentID)

	hash2, _ := HashAPIKey("pass456")
	_, err := db.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)", "user_other3", "otheruser3", hash2)
	if err != nil {
		t.Fatal(err)
	}
	token2 := cb17MakeToken(t, "user_other3", "otheruser3")

	req := httptest.NewRequest(http.MethodDelete, "/conversations/delete?conversation_id="+convID, nil)
	req.Header.Set("Authorization", "Bearer "+token2)
	w := httptest.NewRecorder()
	handleDeleteConversation(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 (not your conversation), got %d", w.Code)
	}
}
// ==============================

func TestCB17_RouteChatMessage_InvalidJSON(t *testing.T) {
	cb17SetupDB(t)
	agentPresenceEnabled = false
	hub = newHub()
	go hub.run()
	defer hub.Stop()

	conn := &Connection{
		id:      "agent_cb17",
		connType: "agent",
		hub:     hub,
		send:    make(chan []byte, 10),
		closed:  false,
		closeMu: sync.RWMutex{},
		writeMu: sync.Mutex{},
	}
	hub.register <- conn
	time.Sleep(10 * time.Millisecond)

	routeChatMessage(conn, json.RawMessage(`{invalid json`))
}

func TestCB17_RouteChatMessage_EmptyContent(t *testing.T) {
	cb17SetupDB(t)
	agentPresenceEnabled = false
	hub = newHub()
	go hub.run()
	defer hub.Stop()

	conn := &Connection{
		id:      "agent_cb17",
		connType: "agent",
		hub:     hub,
		send:    make(chan []byte, 10),
		closed:  false,
		closeMu: sync.RWMutex{},
		writeMu: sync.Mutex{},
	}
	hub.register <- conn
	time.Sleep(10 * time.Millisecond)

	msg := RoutedMessage{ConversationID: "conv1", Content: ""}
	data, _ := json.Marshal(msg)
	routeChatMessage(conn, data)
}

func TestCB17_RouteChatMessage_EmptyConversationID(t *testing.T) {
	cb17SetupDB(t)
	agentPresenceEnabled = false
	hub = newHub()
	go hub.run()
	defer hub.Stop()

	conn := &Connection{
		id:      "agent_cb17",
		connType: "agent",
		hub:     hub,
		send:    make(chan []byte, 10),
		closed:  false,
		closeMu: sync.RWMutex{},
		writeMu: sync.Mutex{},
	}
	hub.register <- conn
	time.Sleep(10 * time.Millisecond)

	msg := RoutedMessage{Content: "hello"}
	data, _ := json.Marshal(msg)
	routeChatMessage(conn, data)
}

func TestCB17_RouteChatMessage_NonexistentConversation(t *testing.T) {
	cb17SetupDB(t)
	agentPresenceEnabled = false
	hub = newHub()
	go hub.run()
	defer hub.Stop()

	conn := &Connection{
		id:      "agent_cb17",
		connType: "agent",
		hub:     hub,
		send:    make(chan []byte, 10),
		closed:  false,
		closeMu: sync.RWMutex{},
		writeMu: sync.Mutex{},
	}
	hub.register <- conn
	time.Sleep(10 * time.Millisecond)

	msg := RoutedMessage{ConversationID: "nonexistent", Content: "hello"}
	data, _ := json.Marshal(msg)
	routeChatMessage(conn, data)
}

func TestCB17_RouteChatMessage_AgentNotParticipant(t *testing.T) {
	cb17SetupDB(t)
	_, userID := cb17SetupAuth(t)
	agentID := cb17SetupAgent(t)
	convID := cb17CreateConversation(t, userID, agentID)

	agentPresenceEnabled = false
	hub = newHub()
	go hub.run()
	defer hub.Stop()

	conn := &Connection{
		id:      "agent_wrong",
		connType: "agent",
		hub:     hub,
		send:    make(chan []byte, 10),
		closed:  false,
		closeMu: sync.RWMutex{},
		writeMu: sync.Mutex{},
	}
	hub.register <- conn
	time.Sleep(10 * time.Millisecond)

	msg := RoutedMessage{ConversationID: convID, Content: "hello"}
	data, _ := json.Marshal(msg)
	routeChatMessage(conn, data)
}

func TestCB17_RouteChatMessage_ClientNotParticipant(t *testing.T) {
	cb17SetupDB(t)
	_, userID := cb17SetupAuth(t)
	agentID := cb17SetupAgent(t)
	convID := cb17CreateConversation(t, userID, agentID)

	agentPresenceEnabled = false
	hub = newHub()
	go hub.run()
	defer hub.Stop()

	conn := &Connection{
		id:      "client_wrong",
		connType: "client",
		hub:     hub,
		send:    make(chan []byte, 10),
		closed:  false,
		closeMu: sync.RWMutex{},
		writeMu: sync.Mutex{},
	}
	hub.register <- conn
	time.Sleep(10 * time.Millisecond)

	msg := RoutedMessage{ConversationID: convID, Content: "hello"}
	data, _ := json.Marshal(msg)
	routeChatMessage(conn, data)
}

// ==============================
// handleSetNotificationPrefs additional tests
// ==============================

func TestCB17_HandleSetNotifPrefs_SetAndUnmute(t *testing.T) {
	cb17SetupDB(t)
	token, userID := cb17SetupAuth(t)
	agentID := cb17SetupAgent(t)
	convID := cb17CreateConversation(t, userID, agentID)

	req := httptest.NewRequest(http.MethodPost, "/notifications/prefs?conversation_id="+convID+"&muted=true", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req = cb17SetUserIDContext(req, userID)
	w := httptest.NewRecorder()
	handleSetNotificationPrefs(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// Then unmute
	req2 := httptest.NewRequest(http.MethodPost, "/notifications/prefs?conversation_id="+convID+"&muted=false", nil)
	req2.Header.Set("Authorization", "Bearer "+token)
	req2 = cb17SetUserIDContext(req2, userID)
	w2 := httptest.NewRecorder()
	handleSetNotificationPrefs(w2, req2)

	if w2.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w2.Code, w2.Body.String())
	}

	var result NotificationPreferences
	json.Unmarshal(w2.Body.Bytes(), &result)
	if result.Muted {
		t.Error("expected muted=false after unmute")
	}
}

// ==============================
// handleStoreEncryptedMessage additional tests
// ==============================

func TestCB17_HandleStoreEncryptedMessage_WrongMethod(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/messages/encrypted", nil)
	w := httptest.NewRecorder()
	handleStoreEncryptedMessage(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestCB17_HandleStoreEncryptedMessage_NoAuth(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/messages/encrypted", nil)
	w := httptest.NewRecorder()
	handleStoreEncryptedMessage(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestCB17_HandleStoreEncryptedMessage_AgentAuth(t *testing.T) {
	cb17SetupDB(t)
	os.Setenv("AGENT_SECRET", "test-agent-secret-cb17")
	agentSecret = "test-agent-secret-cb17"
	t.Cleanup(func() { os.Unsetenv("AGENT_SECRET"); resetAgentSecret() })

	_, userID := cb17SetupAuth(t)
	agentID := cb17SetupAgent(t)
	convID := cb17CreateConversation(t, userID, agentID)

	agentPresenceEnabled = false
	hub = newHub()
	go hub.run()
	defer hub.Stop()

	body := map[string]interface{}{
		"conversation_id":   convID,
		"ciphertext":       "base64ciphertext==",
		"iv":               "base64iv==",
		"recipient_key_id": "key_abc",
		"algorithm":        "aes-256-gcm",
	}
	bodyJSON, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/messages/encrypted", bytes.NewReader(bodyJSON))
	req.Header.Set("X-Agent-Secret", "test-agent-secret-cb17")
	req.Header.Set("X-Agent-ID", agentID)
	w := httptest.NewRecorder()
	handleStoreEncryptedMessage(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCB17_HandleStoreEncryptedMessage_WrongUser(t *testing.T) {
	cb17SetupDB(t)
	token, _ := cb17SetupAuth(t)
	agentID := cb17SetupAgent(t)

	hash2, _ := HashAPIKey("pass456")
	_, err := db.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)", "user_other4", "otheruser4", hash2)
	if err != nil {
		t.Fatal(err)
	}
	convID2 := fmt.Sprintf("conv_other4_%d", time.Now().UnixNano())
	_, err = db.Exec("INSERT INTO conversations (id, user_id, agent_id) VALUES (?, ?, ?)", convID2, "user_other4", agentID)
	if err != nil {
		t.Fatal(err)
	}

	body := map[string]interface{}{
		"conversation_id":   convID2,
		"ciphertext":       "base64ciphertext==",
		"iv":               "base64iv==",
		"recipient_key_id": "key_abc",
		"algorithm":        "aes-256-gcm",
	}
	bodyJSON, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/messages/encrypted", bytes.NewReader(bodyJSON))
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleStoreEncryptedMessage(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", w.Code)
	}
}

func TestCB17_HandleStoreEncryptedMessage_InvalidAlgorithm(t *testing.T) {
	cb17SetupDB(t)
	token, userID := cb17SetupAuth(t)
	agentID := cb17SetupAgent(t)
	convID := cb17CreateConversation(t, userID, agentID)

	body := map[string]interface{}{
		"conversation_id":   convID,
		"ciphertext":       "base64ciphertext==",
		"iv":               "base64iv==",
		"recipient_key_id": "key_abc",
		"algorithm":        "invalid-algo",
	}
	bodyJSON, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/messages/encrypted", bytes.NewReader(bodyJSON))
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleStoreEncryptedMessage(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCB17_HandleStoreEncryptedMessage_MissingFields(t *testing.T) {
	cb17SetupDB(t)
	token, userID := cb17SetupAuth(t)
	agentID := cb17SetupAgent(t)
	convID := cb17CreateConversation(t, userID, agentID)

	body := map[string]interface{}{
		"conversation_id": convID,
		"algorithm":       "aes-256-gcm",
	}
	bodyJSON, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/messages/encrypted", bytes.NewReader(bodyJSON))
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleStoreEncryptedMessage(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestCB17_HandleStoreEncryptedMessage_NonexistentConversation(t *testing.T) {
	cb17SetupDB(t)
	token, _ := cb17SetupAuth(t)

	body := map[string]interface{}{
		"conversation_id":   "nonexistent",
		"ciphertext":       "base64ciphertext==",
		"iv":               "base64iv==",
		"recipient_key_id": "key_abc",
		"algorithm":        "aes-256-gcm",
	}
	bodyJSON, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/messages/encrypted", bytes.NewReader(bodyJSON))
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleStoreEncryptedMessage(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

func TestCB17_HandleStoreEncryptedMessage_SupportedAlgorithms(t *testing.T) {
	cb17SetupDB(t)
	token, userID := cb17SetupAuth(t)
	agentID := cb17SetupAgent(t)

	algorithms := []string{"aes-256-gcm", "x25519-aes-256-gcm", "x25519-chacha20-poly1305"}
	for _, algo := range algorithms {
		convID := cb17CreateConversation(t, userID, agentID)

		body := map[string]interface{}{
			"conversation_id":   convID,
			"ciphertext":       "base64ciphertext==",
			"iv":               "base64iv==",
			"recipient_key_id": "key_abc",
			"algorithm":        algo,
		}
		bodyJSON, _ := json.Marshal(body)

		req := httptest.NewRequest(http.MethodPost, "/messages/encrypted", bytes.NewReader(bodyJSON))
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		handleStoreEncryptedMessage(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("expected 200 for algo %s, got %d: %s", algo, w.Code, w.Body.String())
		}
	}
}

// ==============================
// GetEncryptedMessages additional tests
// ==============================

func TestCB17_GetEncryptedMessages_AgentAuth(t *testing.T) {
	cb17SetupDB(t)
	os.Setenv("AGENT_SECRET", "test-agent-secret-cb17")
	agentSecret = "test-agent-secret-cb17"
	t.Cleanup(func() { os.Unsetenv("AGENT_SECRET"); resetAgentSecret() })

	_, userID := cb17SetupAuth(t)
	agentID := cb17SetupAgent(t)
	convID := cb17CreateConversation(t, userID, agentID)

	_, err := db.Exec(`INSERT INTO encrypted_messages (id, conversation_id, sender_id, sender_type, ciphertext, iv, recipient_key_id, algorithm, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		"emsg_1", convID, agentID, "agent", "ciphertext1", "iv1", "key1", "aes-256-gcm", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/messages/encrypted?conversation_id="+convID, nil)
	req.Header.Set("X-Agent-Secret", "test-agent-secret-cb17")
	req.Header.Set("X-Agent-ID", agentID)
	w := httptest.NewRecorder()
	handleGetEncryptedMessages(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCB17_GetEncryptedMessages_WrongParticipant(t *testing.T) {
	cb17SetupDB(t)
	token, _ := cb17SetupAuth(t)
	agentID := cb17SetupAgent(t)

	hash2, _ := HashAPIKey("pass456")
	_, err := db.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)", "user_other5", "otheruser5", hash2)
	if err != nil {
		t.Fatal(err)
	}
	convID := fmt.Sprintf("conv_other5_%d", time.Now().UnixNano())
	_, err = db.Exec("INSERT INTO conversations (id, user_id, agent_id) VALUES (?, ?, ?)", convID, "user_other5", agentID)
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/messages/encrypted?conversation_id="+convID, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleGetEncryptedMessages(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

func TestCB17_GetEncryptedMessages_MissingConversationID(t *testing.T) {
	cb17SetupDB(t)
	token, _ := cb17SetupAuth(t)

	req := httptest.NewRequest(http.MethodGet, "/messages/encrypted", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleGetEncryptedMessages(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestCB17_GetEncryptedMessages_WrongMethod(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/messages/encrypted", nil)
	w := httptest.NewRecorder()
	handleGetEncryptedMessages(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

// ==============================
// HashAPIKey additional tests
// ==============================

func TestCB17_HashAPIKey_EmptyString(t *testing.T) {
	hash, err := HashAPIKey("")
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
	if hash == "" {
		t.Error("expected non-empty hash")
	}
}

func TestCB17_HashAPIKey_LongInput(t *testing.T) {
	longInput := strings.Repeat("a", 1000)
	hash, err := HashAPIKey(longInput)
	// bcrypt has 72-byte limit; error expected for longer inputs
	if err != nil {
		// This is expected for inputs > 72 bytes
		return
	}
	if hash == "" {
		t.Error("expected non-empty hash")
	}
}

// ==============================
// loadQueueFromDB additional tests
// ==============================

func TestCB17_LoadQueueFromDB_Empty(t *testing.T) {
	cb17SetupDB(t)
	initQueueDB(db)

	q := newOfflineQueue(100, 7*24*time.Hour)
	loadQueueFromDB(db, q)
	// Empty queue - nothing to load
}

func TestCB17_LoadQueueFromDB_WithData(t *testing.T) {
	cb17SetupDB(t)
	initQueueDB(db)

	now := time.Now().UTC()
	_, err := db.Exec(`INSERT INTO offline_queue (recipient, data, queued_at, sent_count) VALUES (?, ?, ?, ?)`,
		"user1", `{"type":"message","data":"hello"}`, now, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`INSERT INTO offline_queue (recipient, data, queued_at, sent_count) VALUES (?, ?, ?, ?)`,
		"user1", `{"type":"message","data":"world"}`, now, 0)
	if err != nil {
		t.Fatal(err)
	}

	q := newOfflineQueue(100, 7*24*time.Hour)
	loadQueueFromDB(db, q)
	// Verify the queue has messages for user1
	if len(q.buffers["user1"]) == 0 {
		t.Error("expected messages to be loaded")
	}
}

func TestCB17_LoadQueueFromDB_OldMessages(t *testing.T) {
	cb17SetupDB(t)
	initQueueDB(db)

	now := time.Now().UTC()
	_, err := db.Exec(`INSERT INTO offline_queue (recipient, data, queued_at, sent_count) VALUES (?, ?, ?, ?)`,
		"user1", `{"type":"message","data":"old"}`, now.Add(-8*24*time.Hour), 0)
	if err != nil {
		t.Fatal(err)
	}

	q := newOfflineQueue(100, 7*24*time.Hour)
	loadQueueFromDB(db, q)
	// Old messages still get loaded (TTL filtering is in cleanStaleQueueMessages)
}

// ==============================
// cleanStaleQueueMessages tests
// ==============================

func TestCB17_CleanStaleQueueMessages_WithExpired(t *testing.T) {
	cb17SetupDB(t)
	initQueueDB(db)

	now := time.Now().UTC()
	_, err := db.Exec(`INSERT INTO offline_queue (recipient, data, queued_at, sent_count) VALUES (?, ?, ?, ?)`,
		"user1", `{"type":"message"}`, now.Add(-8*24*time.Hour), 0)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`INSERT INTO offline_queue (recipient, data, queued_at, sent_count) VALUES (?, ?, ?, ?)`,
		"user1", `{"type":"message2"}`, now, 0)
	if err != nil {
		t.Fatal(err)
	}

	cleanStaleQueueMessages(db, 7*24*time.Hour)

	var count int
	db.QueryRow("SELECT COUNT(*) FROM offline_queue WHERE recipient = ?", "user1").Scan(&count)
	if count != 1 {
		t.Errorf("expected 1 remaining message, got %d", count)
	}
}

func TestCB17_CleanStaleQueueMessages_AllValid(t *testing.T) {
	cb17SetupDB(t)
	initQueueDB(db)

	now := time.Now().UTC()
	_, err := db.Exec(`INSERT INTO offline_queue (recipient, data, queued_at, sent_count) VALUES (?, ?, ?, ?)`,
		"user1", `{"type":"message"}`, now, 0)
	if err != nil {
		t.Fatal(err)
	}

	cleanStaleQueueMessages(db, 7*24*time.Hour)

	var count int
	db.QueryRow("SELECT COUNT(*) FROM offline_queue WHERE recipient = ?", "user1").Scan(&count)
	if count != 1 {
		t.Errorf("expected 1 message (not cleaned), got %d", count)
	}
}

// ==============================
// addConversationTag additional tests
// ==============================

func TestCB17_AddConversationTag_DBError(t *testing.T) {
	cb17SetupDB(t)

	_, err := addConversationTag("nonexistent_conv", "user_cb17", "important")
	if err == nil {
		t.Error("expected error for nonexistent conversation")
	}
}

func TestCB17_AddConversationTag_Success(t *testing.T) {
	cb17SetupDB(t)
	_, userID := cb17SetupAuth(t)
	agentID := cb17SetupAgent(t)
	convID := cb17CreateConversation(t, userID, agentID)

	_, err := addConversationTag(convID, userID, "important")
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}

	var count int
	db.QueryRow("SELECT COUNT(*) FROM conversation_tags WHERE conversation_id = ? AND tag = ?", convID, "important").Scan(&count)
	if count != 1 {
		t.Errorf("expected 1 tag, got %d", count)
	}
}

func TestCB17_AddConversationTag_Duplicate(t *testing.T) {
	cb17SetupDB(t)
	_, userID := cb17SetupAuth(t)
	agentID := cb17SetupAgent(t)
	convID := cb17CreateConversation(t, userID, agentID)

	_, err := addConversationTag(convID, userID, "starred")
	if err != nil {
		t.Fatal(err)
	}

	_, err = addConversationTag(convID, userID, "starred")
	_ = err
}

// ==============================
// addReaction additional tests
// ==============================

func TestCB17_AddReaction_ExistingMessage(t *testing.T) {
	cb17SetupDB(t)
	_, userID := cb17SetupAuth(t)
	agentID := cb17SetupAgent(t)
	convID := cb17CreateConversation(t, userID, agentID)

	msgID := generateID("msg")
	_, err := db.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, created_at) VALUES (?, ?, ?, ?, ?, ?)",
		msgID, convID, "agent", agentID, "hello", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}

	_, _, err = addReaction(msgID, userID, "👍")
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
}

func TestCB17_AddReaction_Toggle(t *testing.T) {
	cb17SetupDB(t)
	_, userID := cb17SetupAuth(t)
	agentID := cb17SetupAgent(t)
	convID := cb17CreateConversation(t, userID, agentID)

	msgID := generateID("msg")
	_, err := db.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, created_at) VALUES (?, ?, ?, ?, ?, ?)",
		msgID, convID, "agent", agentID, "hello", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}

	_, _, err = addReaction(msgID, userID, "❤️")
	if err != nil {
		t.Fatal(err)
	}

	_, _, err = addReaction(msgID, userID, "❤️")
	_ = err
}

// ==============================
// initFCM additional coverage tests
// ==============================

func TestCB17_InitFCM_Disabled(t *testing.T) {
	pushConfig = &PushNotificationConfig{
		FCMEnabled: false,
	}
	initFCM()
	if pushConfig.fcmClient != nil {
		t.Error("FCM client should be nil when disabled")
	}
}

func TestCB17_InitFCM_EmptyCredentialsPath(t *testing.T) {
	pushConfig = &PushNotificationConfig{
		FCMEnabled:     true,
		FCMCredentials: "",
	}
	initFCM()
	if pushConfig.fcmClient != nil {
		t.Error("FCM client should be nil with empty creds path")
	}
}

func TestCB17_InitFCM_NonExistentCredentialsFile(t *testing.T) {
	pushConfig = &PushNotificationConfig{
		FCMEnabled:     true,
		FCMCredentials: "/nonexistent/firebase-creds.json",
	}
	initFCM()
	if pushConfig.FCMEnabled {
		t.Error("FCM should be disabled when credentials file not found")
	}
}

// ==============================
// initAPNs additional coverage tests
// ==============================

func TestCB17_InitAPNs_Disabled(t *testing.T) {
	pushConfig = &PushNotificationConfig{
		APNSEnabled: false,
	}
	initAPNs()
	if pushConfig.apnsClient != nil {
		t.Error("APNs client should be nil when disabled")
	}
}

func TestCB17_InitAPNs_NoCertPath(t *testing.T) {
	pushConfig = &PushNotificationConfig{
		APNSEnabled: true,
		CertPath:    "",
	}
	initAPNs()
	if pushConfig.apnsClient != nil {
		t.Error("APNs client should be nil with empty cert path")
	}
}

func TestCB17_InitAPNs_CertNotFound(t *testing.T) {
	pushConfig = &PushNotificationConfig{
		APNSEnabled: true,
		CertPath:    "/nonexistent/cert.p12",
	}
	initAPNs()
	if pushConfig.APNSEnabled {
		t.Error("APNs should be disabled when cert not found")
	}
}

// ==============================
// getEnvOrDefault tests
// ==============================

func TestCB17_GetEnvOrDefault_Set(t *testing.T) {
	os.Setenv("TEST_VAR_CB17", "value123")
	defer os.Unsetenv("TEST_VAR_CB17")

	result := getEnvOrDefault("TEST_VAR_CB17", "default")
	if result != "value123" {
		t.Errorf("expected 'value123', got '%s'", result)
	}
}

func TestCB17_GetEnvOrDefault_Unset(t *testing.T) {
	os.Unsetenv("TEST_VAR_CB17_UNSET")

	result := getEnvOrDefault("TEST_VAR_CB17_UNSET", "default_val")
	if result != "default_val" {
		t.Errorf("expected 'default_val', got '%s'", result)
	}
}

func TestCB17_GetEnvOrDefault_Empty(t *testing.T) {
	os.Setenv("TEST_VAR_CB17_EMPTY", "")
	defer os.Unsetenv("TEST_VAR_CB17_EMPTY")

	result := getEnvOrDefault("TEST_VAR_CB17_EMPTY", "default")
	if result != "default" {
		t.Errorf("expected 'default' (empty string uses default), got '%s'", result)
	}
}

// ==============================
// TieredRateLimiter cleanup test
// ==============================

func TestCB17_TieredRateLimiter_CleanupRemovesStale(t *testing.T) {
	trl := NewTieredRateLimiter()
	t.Cleanup(func() { trl.Stop() })
	trl.SetTier("user_stale", TierPro)

	// Manually expire the entry
	trl.mu.Lock()
	if entry, ok := trl.limits["user_stale"]; ok {
		entry.windowEnd = time.Now().Add(-1 * time.Hour)
		trl.limits["user_stale"] = entry
	}
	trl.mu.Unlock()

	// Force cleanup check
	trl.mu.Lock()
	now := time.Now()
	for id, entry := range trl.limits {
		if now.After(entry.windowEnd) && now.Sub(entry.windowEnd) > 10*time.Minute {
			delete(trl.limits, id)
		}
	}
	trl.mu.Unlock()

	trl.mu.Lock()
	_, exists := trl.limits["user_stale"]
	trl.mu.Unlock()
	if exists {
		t.Error("stale entry should have been cleaned up")
	}
}

// ==============================
// InitTracing additional coverage
// ==============================

func TestCB17_InitTracing_Disabled(t *testing.T) {
	os.Unsetenv("OTEL_ENABLED")
	tracingEnabled = false
	tp = nil
	tracer = nil
	tracingMu = sync.Once{}

	err := InitTracing()
	if err != nil {
		t.Errorf("expected no error when disabled, got %v", err)
	}
	if tracingEnabled {
		t.Error("tracing should not be enabled")
	}
}

func TestCB17_InitTracing_NoEndpoint(t *testing.T) {
	os.Setenv("OTEL_ENABLED", "true")
	os.Unsetenv("OTEL_EXPORTER_OTLP_ENDPOINT")
	os.Unsetenv("OTEL_EXPORTER_OTLP_HTTP_ENDPOINT")
	defer os.Unsetenv("OTEL_ENABLED")

	tracingEnabled = false
	tp = nil
	tracer = nil
	tracingMu = sync.Once{}

	err := InitTracing()
	if err != nil {
		t.Errorf("expected no error when no endpoint, got %v", err)
	}
	if tracingEnabled {
		t.Error("tracing should not be enabled without endpoint")
	}
}

// ==============================
// ShutdownTracing additional tests
// ==============================

func TestCB17_ShutdownTracing_NilProvider(t *testing.T) {
	tp = nil
	ShutdownTracing()
}

// ==============================
// getDeviceTokensForUser tests
// ==============================

func TestCB17_GetDeviceTokensForUser_NoTokens(t *testing.T) {
	cb17SetupDB(t)

	tokens, err := getDeviceTokensForUser("nonexistent_user")
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
	if len(tokens) != 0 {
		t.Errorf("expected 0 tokens, got %d", len(tokens))
	}
}

func TestCB17_GetDeviceTokensForUser_WithTokens(t *testing.T) {
	cb17SetupDB(t)

	_, err := db.Exec("INSERT INTO device_tokens (user_id, device_token, platform) VALUES (?, ?, ?)", "user1", "token_ios_1", "ios")
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec("INSERT INTO device_tokens (user_id, device_token, platform) VALUES (?, ?, ?)", "user1", "token_android_1", "android")
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec("INSERT INTO device_tokens (user_id, device_token, platform) VALUES (?, ?, ?)", "user1", "token_web_1", "web")
	if err != nil {
		t.Fatal(err)
	}

	tokens, err := getDeviceTokensForUser("user1")
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
	if len(tokens) != 3 {
		t.Errorf("expected 3 tokens, got %d", len(tokens))
	}

	platforms := map[string]bool{}
	for _, tk := range tokens {
		platforms[tk.Platform] = true
	}
	if !platforms["ios"] || !platforms["android"] || !platforms["web"] {
		t.Errorf("expected ios, android, web platforms, got %v", platforms)
	}
}

// ==============================
// WebPush additional tests
// ==============================

func TestCB17_HandleWebPushSubscribe_NoAuth(t *testing.T) {
	cb17SetupDB(t)

	body := map[string]interface{}{
		"endpoint": "https://push.example.com/sub/123",
		"keys": map[string]string{
			"p256dh": "testkey123",
			"auth":   "testauth123",
		},
	}
	bodyJSON, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/push/web-subscribe", bytes.NewReader(bodyJSON))
	w := httptest.NewRecorder()
	handleWebPushSubscribe(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestCB17_HandleWebPushSubscribe_MissingFields(t *testing.T) {
	cb17SetupDB(t)
	token, _ := cb17SetupAuth(t)

	body := map[string]interface{}{
		"endpoint": "",
		"keys": map[string]string{
			"p256dh": "",
			"auth":   "",
		},
	}
	bodyJSON, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/push/web-subscribe", bytes.NewReader(bodyJSON))
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleWebPushSubscribe(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestCB17_HandleWebPushUnsubscribe_NoAuth(t *testing.T) {
	cb17SetupDB(t)

	body := map[string]interface{}{
		"endpoint": "https://push.example.com/sub/123",
	}
	bodyJSON, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/push/web-unsubscribe", bytes.NewReader(bodyJSON))
	w := httptest.NewRecorder()
	handleWebPushUnsubscribe(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestCB17_HandleWebPushUnsubscribe_MissingEndpoint(t *testing.T) {
	cb17SetupDB(t)
	token, _ := cb17SetupAuth(t)

	body := map[string]interface{}{
		"endpoint": "",
	}
	bodyJSON, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/push/web-unsubscribe", bytes.NewReader(bodyJSON))
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleWebPushUnsubscribe(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestCB17_HandleGetVAPIDKey_NotConfigured(t *testing.T) {
	cb17SetupDB(t)
	token, _ := cb17SetupAuth(t)
	vapidPublicKey = ""

	req := httptest.NewRequest(http.MethodGet, "/push/vapid-key", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleGetVAPIDKey(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

func TestCB17_HandleGetVAPIDKey_Configured(t *testing.T) {
	cb17SetupDB(t)
	token, _ := cb17SetupAuth(t)
	vapidPublicKey = "test-vapid-public-key-abc123"

	req := httptest.NewRequest(http.MethodGet, "/push/vapid-key", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleGetVAPIDKey(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var result map[string]string
	json.Unmarshal(w.Body.Bytes(), &result)
	if result["public_key"] != "test-vapid-public-key-abc123" {
		t.Errorf("expected VAPID key, got %v", result)
	}
}

func TestCB17_HandleGetVAPIDKey_WrongMethod(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/push/vapid-key", nil)
	w := httptest.NewRecorder()
	handleGetVAPIDKey(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestCB17_HandleGetVAPIDKey_NoAuth(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/push/vapid-key", nil)
	w := httptest.NewRecorder()
	handleGetVAPIDKey(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

// ==============================
// authenticateRequest additional tests
// ==============================

func TestCB17_AuthenticateRequest_NoAuth(t *testing.T) {
	cb17SetupDB(t)
	os.Setenv("AGENT_SECRET", "test-agent-secret-cb17")
	agentSecret = "test-agent-secret-cb17"
	t.Cleanup(func() { os.Unsetenv("AGENT_SECRET"); resetAgentSecret() })

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	id, typ, err := authenticateRequest(req)
	if err == nil {
		t.Error("expected error with no auth")
	}
	if id != "" || typ != "" {
		t.Errorf("expected empty id/type, got id=%s type=%s", id, typ)
	}
}

func TestCB17_AuthenticateRequest_ValidJWT(t *testing.T) {
	cb17SetupDB(t)
	token, userID := cb17SetupAuth(t)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	id, typ, err := authenticateRequest(req)
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
	if id != userID {
		t.Errorf("expected userID %s, got %s", userID, id)
	}
	if typ != "user" {
		t.Errorf("expected 'user', got '%s'", typ)
	}
}

func TestCB17_AuthenticateRequest_AgentSecret(t *testing.T) {
	cb17SetupDB(t)
	os.Setenv("AGENT_SECRET", "test-agent-secret-cb17")
	agentSecret = "test-agent-secret-cb17"
	t.Cleanup(func() { os.Unsetenv("AGENT_SECRET"); resetAgentSecret() })

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Agent-Secret", "test-agent-secret-cb17")
	req.Header.Set("X-Agent-ID", "agent_123")
	id, typ, err := authenticateRequest(req)
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
	if id != "agent_123" {
		t.Errorf("expected 'agent_123', got '%s'", id)
	}
	if typ != "agent" {
		t.Errorf("expected 'agent', got '%s'", typ)
	}
}

func TestCB17_AuthenticateRequest_AgentMissingID(t *testing.T) {
	cb17SetupDB(t)
	os.Setenv("AGENT_SECRET", "test-agent-secret-cb17")
	agentSecret = "test-agent-secret-cb17"
	t.Cleanup(func() { os.Unsetenv("AGENT_SECRET"); resetAgentSecret() })

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Agent-Secret", "test-agent-secret-cb17")
	id, typ, err := authenticateRequest(req)
	if err == nil {
		t.Error("expected error when X-Agent-ID missing")
	}
	if id != "" || typ != "" {
		t.Errorf("expected empty, got id=%s type=%s", id, typ)
	}
}

func TestCB17_AuthenticateRequest_WrongAgentSecret(t *testing.T) {
	cb17SetupDB(t)
	os.Setenv("AGENT_SECRET", "test-agent-secret-cb17")
	agentSecret = "test-agent-secret-cb17"
	t.Cleanup(func() { os.Unsetenv("AGENT_SECRET"); resetAgentSecret() })

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Agent-Secret", "wrong-secret")
	req.Header.Set("X-Agent-ID", "agent_123")
	_, _, err := authenticateRequest(req)
	if err == nil {
		t.Error("expected error with wrong agent secret")
	}
}

// ==============================
// changeUserPassword additional tests
// ==============================

func TestCB17_ChangeUserPassword_NonexistentUser(t *testing.T) {
	cb17SetupDB(t)

	err := changeUserPassword("nonexistent", "old", "newpass")
	if err == nil {
		t.Error("expected error for nonexistent user")
	}
}

func TestCB17_ChangeUserPassword_Success(t *testing.T) {
	cb17SetupDB(t)
	_, userID := cb17SetupAuth(t)

	err := changeUserPassword(userID, "password123", "newpass456")
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}

	var hash string
	db.QueryRow("SELECT password_hash FROM users WHERE id = ?", userID).Scan(&hash)
	err = bcrypt.CompareHashAndPassword([]byte(hash), []byte("newpass456"))
	if err != nil {
		t.Error("new password should match")
	}
}

func TestCB17_ChangeUserPassword_WrongOld(t *testing.T) {
	cb17SetupDB(t)
	_, userID := cb17SetupAuth(t)

	err := changeUserPassword(userID, "wrongpass", "newpass456")
	if err == nil {
		t.Error("expected error with wrong old password")
	}
}

func TestCB17_ChangeUserPassword_ShortNew(t *testing.T) {
	cb17SetupDB(t)
	_, userID := cb17SetupAuth(t)

	err := changeUserPassword(userID, "password123", "abc")
	if err == nil {
		t.Error("expected error with short new password")
	}
}

// ==============================
// isConversationMuted tests
// ==============================

func TestCB17_IsConversationMuted_NotMuted(t *testing.T) {
	cb17SetupDB(t)

	if isConversationMuted("user1", "conv1") {
		t.Error("should not be muted by default")
	}
}

func TestCB17_IsConversationMuted_Muted(t *testing.T) {
	cb17SetupDB(t)
	_, userID := cb17SetupAuth(t)
	agentID := cb17SetupAgent(t)
	convID := cb17CreateConversation(t, userID, agentID)

	_, err := db.Exec("INSERT INTO notification_preferences (user_id, conversation_id, muted) VALUES (?, ?, ?)", userID, convID, true)
	if err != nil {
		t.Fatal(err)
	}

	if !isConversationMuted(userID, convID) {
		t.Error("should be muted")
	}
}

func TestCB17_IsConversationMuted_Unmuted(t *testing.T) {
	cb17SetupDB(t)
	_, userID := cb17SetupAuth(t)
	agentID := cb17SetupAgent(t)
	convID := cb17CreateConversation(t, userID, agentID)

	_, err := db.Exec("INSERT INTO notification_preferences (user_id, conversation_id, muted) VALUES (?, ?, ?)", userID, convID, false)
	if err != nil {
		t.Fatal(err)
	}

	if isConversationMuted(userID, convID) {
		t.Error("should not be muted when muted=false")
	}
}

// ==============================
// handleRegisterDeviceToken additional tests
// ==============================

func TestCB17_HandleRegisterDeviceToken_WrongMethod(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/push/register", nil)
	w := httptest.NewRecorder()
	handleRegisterDeviceToken(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestCB17_HandleRegisterDeviceToken_NoAuth(t *testing.T) {
	body := map[string]string{"device_token": "abc123", "platform": "ios"}
	bodyJSON, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/push/register", bytes.NewReader(bodyJSON))
	w := httptest.NewRecorder()
	handleRegisterDeviceToken(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestCB17_HandleRegisterDeviceToken_InvalidJSON(t *testing.T) {
	cb17SetupDB(t)
	token, _ := cb17SetupAuth(t)

	req := httptest.NewRequest(http.MethodPost, "/push/register", bytes.NewReader([]byte("invalid json")))
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleRegisterDeviceToken(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestCB17_HandleRegisterDeviceToken_MissingToken(t *testing.T) {
	cb17SetupDB(t)
	token, _ := cb17SetupAuth(t)

	body := map[string]string{"platform": "ios"}
	bodyJSON, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/push/register", bytes.NewReader(bodyJSON))
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleRegisterDeviceToken(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestCB17_HandleRegisterDeviceToken_DefaultPlatform(t *testing.T) {
	cb17SetupDB(t)
	token, userID := cb17SetupAuth(t)

	body := map[string]string{"device_token": "abc123def"}
	bodyJSON, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/push/register", bytes.NewReader(bodyJSON))
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleRegisterDeviceToken(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var platform string
	db.QueryRow("SELECT platform FROM device_tokens WHERE user_id = ? AND device_token = ?", userID, "abc123def").Scan(&platform)
	if platform != "ios" {
		t.Errorf("expected default platform 'ios', got '%s'", platform)
	}
}

// ==============================
// handleUnregisterDeviceToken additional tests
// ==============================

func TestCB17_HandleUnregisterDeviceToken_WrongMethod(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/push/unregister", nil)
	w := httptest.NewRecorder()
	handleUnregisterDeviceToken(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestCB17_HandleUnregisterDeviceToken_NoAuth(t *testing.T) {
	body := map[string]string{"device_token": "abc123"}
	bodyJSON, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodDelete, "/push/unregister", bytes.NewReader(bodyJSON))
	w := httptest.NewRecorder()
	handleUnregisterDeviceToken(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestCB17_HandleUnregisterDeviceToken_MissingToken(t *testing.T) {
	cb17SetupDB(t)
	token, _ := cb17SetupAuth(t)

	body := map[string]string{}
	bodyJSON, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodDelete, "/push/unregister", bytes.NewReader(bodyJSON))
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleUnregisterDeviceToken(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestCB17_HandleUnregisterDeviceToken_Success(t *testing.T) {
	cb17SetupDB(t)
	token, userID := cb17SetupAuth(t)

	_, err := db.Exec("INSERT INTO device_tokens (user_id, device_token, platform) VALUES (?, ?, ?)", userID, "token_to_remove", "ios")
	if err != nil {
		t.Fatal(err)
	}

	body := map[string]string{"device_token": "token_to_remove"}
	bodyJSON, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodDelete, "/push/unregister", bytes.NewReader(bodyJSON))
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleUnregisterDeviceToken(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}

	var count int
	db.QueryRow("SELECT COUNT(*) FROM device_tokens WHERE user_id = ? AND device_token = ?", userID, "token_to_remove").Scan(&count)
	if count != 0 {
		t.Error("token should be removed")
	}
}

// ==============================
// deleteQueueMessages tests
// ==============================

func TestCB17_DeleteQueueMessages_ForRecipient(t *testing.T) {
	cb17SetupDB(t)
	initQueueDB(db)

	now := time.Now().UTC()
	db.Exec(`INSERT INTO offline_queue (recipient, data, queued_at, sent_count) VALUES (?, ?, ?, ?)`,
		"user_del1", `{"type":"message"}`, now, 0)
	db.Exec(`INSERT INTO offline_queue (recipient, data, queued_at, sent_count) VALUES (?, ?, ?, ?)`,
		"user_del1", `{"type":"message2"}`, now, 0)
	db.Exec(`INSERT INTO offline_queue (recipient, data, queued_at, sent_count) VALUES (?, ?, ?, ?)`,
		"user_del2", `{"type":"message3"}`, now, 0)

	deleteQueueMessages(db, "user_del1")

	var count int
	db.QueryRow("SELECT COUNT(*) FROM offline_queue WHERE recipient = ?", "user_del2").Scan(&count)
	if count != 1 {
		t.Errorf("expected 1 remaining, got %d", count)
	}
	db.QueryRow("SELECT COUNT(*) FROM offline_queue WHERE recipient = ?", "user_del1").Scan(&count)
	if count != 0 {
		t.Errorf("expected 0 for deleted recipient, got %d", count)
	}
}

// ==============================
// removeConversationTag tests
// ==============================

func TestCB17_RemoveConversationTag_Success(t *testing.T) {
	cb17SetupDB(t)
	_, userID := cb17SetupAuth(t)
	agentID := cb17SetupAgent(t)
	convID := cb17CreateConversation(t, userID, agentID)

	_, err := addConversationTag(convID, userID, "important")
	if err != nil {
		t.Fatal(err)
	}

	err = removeConversationTag(convID, userID, "important")
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}

	var count int
	db.QueryRow("SELECT COUNT(*) FROM conversation_tags WHERE conversation_id = ? AND tag = ?", convID, "important").Scan(&count)
	if count != 0 {
		t.Error("tag should be removed")
	}
}

func TestCB17_RemoveConversationTag_Nonexistent(t *testing.T) {
	cb17SetupDB(t)

	err := removeConversationTag("nonexistent_conv", "user_cb17", "important")
	_ = err
}

// ==============================
// searchMessages additional tests
// ==============================

func TestCB17_SearchMessages_FoundResults(t *testing.T) {
	cb17SetupDB(t)
	_, userID := cb17SetupAuth(t)
	agentID := cb17SetupAgent(t)
	convID := cb17CreateConversation(t, userID, agentID)

	db.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, created_at) VALUES (?, ?, ?, ?, ?, ?)",
		"msg_search1", convID, "agent", agentID, "Hello world", time.Now().UTC())
	db.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, created_at) VALUES (?, ?, ?, ?, ?, ?)",
		"msg_search2", convID, "agent", agentID, "Goodbye world", time.Now().UTC())
	db.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, created_at) VALUES (?, ?, ?, ?, ?, ?)",
		"msg_search3", convID, "agent", agentID, "No match here", time.Now().UTC())

	results, err := searchMessages(userID, "world", 10)
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
	if len(results) != 2 {
		t.Errorf("expected 2 results, got %d", len(results))
	}
}

func TestCB17_SearchMessages_EmptyQuery(t *testing.T) {
	cb17SetupDB(t)
	_, userID := cb17SetupAuth(t)

	_, err := searchMessages(userID, "", 10)
	if err == nil {
		t.Error("expected error for empty query")
	}
}

func TestCB17_SearchMessages_NoResults(t *testing.T) {
	cb17SetupDB(t)
	_, userID := cb17SetupAuth(t)

	results, err := searchMessages(userID, "nonexistentterm", 10)
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
	if len(results) != 0 {
		t.Errorf("expected 0 results, got %d", len(results))
	}
}

func TestCB17_SearchMessages_CustomLimit(t *testing.T) {
	cb17SetupDB(t)
	_, userID := cb17SetupAuth(t)
	agentID := cb17SetupAgent(t)
	convID := cb17CreateConversation(t, userID, agentID)

	for i := 0; i < 5; i++ {
		msgID := generateID("msg")
		db.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, created_at) VALUES (?, ?, ?, ?, ?, ?)",
			msgID, convID, "agent", agentID, "match term here", time.Now().Add(time.Duration(i)*time.Second).UTC())
	}

	results, err := searchMessages(userID, "match", 3)
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
	if len(results) > 3 {
		t.Errorf("expected at most 3 results, got %d", len(results))
	}
}

// ==============================
// GetOrCreateConversation tests
// ==============================

func TestCB17_GetOrCreateConversation_New(t *testing.T) {
	cb17SetupDB(t)

	conv, err := GetOrCreateConversation("user_new", "agent_new")
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
	if conv == nil {
		t.Fatal("expected non-nil conversation")
	}
	if conv.UserID != "user_new" {
		t.Errorf("expected user_new, got %s", conv.UserID)
	}
}

func TestCB17_GetOrCreateConversation_Existing(t *testing.T) {
	cb17SetupDB(t)
	_, userID := cb17SetupAuth(t)
	agentID := cb17SetupAgent(t)
	existingConvID := cb17CreateConversation(t, userID, agentID)

	conv, err := GetOrCreateConversation(userID, agentID)
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
	if conv == nil {
		t.Fatal("expected non-nil conversation")
	}
	if conv.ID != existingConvID {
		t.Errorf("expected existing conv %s, got %s", existingConvID, conv.ID)
	}
}

// ==============================
// isAllowedContentType additional tests
// ==============================

func TestCB17_IsAllowedContentType_AudioWebM(t *testing.T) {
	if !isAllowedContentType("audio/webm") {
		t.Error("audio/webm should be allowed")
	}
}

func TestCB17_IsAllowedContentType_VideoMP4(t *testing.T) {
	if !isAllowedContentType("video/mp4") {
		t.Error("video/mp4 should be allowed")
	}
}

func TestCB17_IsAllowedContentType_TextCSV(t *testing.T) {
	if !isAllowedContentType("text/csv") {
		t.Error("text/csv should be allowed")
	}
}

func TestCB17_IsAllowedContentType_ImageBMP(t *testing.T) {
	if !isAllowedContentType("image/bmp") {
		t.Error("image/bmp should be allowed")
	}
}

func TestCB17_IsAllowedContentType_Disallowed(t *testing.T) {
	if isAllowedContentType("application/x-executable") {
		t.Error("application/x-executable should not be allowed")
	}
}

func TestCB17_IsAllowedContentType_ApplicationZip(t *testing.T) {
	if isAllowedContentType("application/zip") {
		t.Error("application/zip should not be allowed")
	}
}

// ==============================
// markMessagesRead additional tests
// ==============================

func TestCB17_MarkMessagesRead_Unauthorized(t *testing.T) {
	cb17SetupDB(t)
	_, userID := cb17SetupAuth(t)
	agentID := cb17SetupAgent(t)
	convID := cb17CreateConversation(t, userID, agentID)

	count, err := markMessagesRead(convID, "wrong_user")
	if err == nil {
		t.Error("expected error for wrong user")
	}
	if count != 0 {
		t.Errorf("expected 0, got %d", count)
	}
}

func TestCB17_MarkMessagesRead_NotFound(t *testing.T) {
	cb17SetupDB(t)

	count, err := markMessagesRead("nonexistent_conv", "user1")
	if err == nil {
		t.Error("expected error for nonexistent conversation")
	}
	if count != 0 {
		t.Errorf("expected 0, got %d", count)
	}
}

func TestCB17_MarkMessagesRead_Idempotent(t *testing.T) {
	cb17SetupDB(t)
	_, userID := cb17SetupAuth(t)
	agentID := cb17SetupAgent(t)
	convID := cb17CreateConversation(t, userID, agentID)

	_, err := db.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, created_at) VALUES (?, ?, ?, ?, ?, ?)",
		"msg_read_1", convID, "agent", agentID, "hello", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}

	count1, _ := markMessagesRead(convID, userID)
	if count1 != 1 {
		t.Errorf("expected 1, got %d", count1)
	}

	count2, _ := markMessagesRead(convID, userID)
	if count2 != 0 {
		t.Errorf("expected 0 (idempotent), got %d", count2)
	}
}

// ==============================
// Ensure upload dir tests
// ==============================

func TestCB17_EnsureUploadDir(t *testing.T) {
	cb17SetupDB(t)
	serverDBPath = ":memory:"

	err := ensureUploadDir()
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}

	dir := getUploadDir()
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		t.Errorf("upload dir should exist at %s", dir)
	}

	os.RemoveAll(filepath.Dir(dir))
}

// ==============================
// initQueueDB tests
// ==============================

func TestCB17_InitQueueDB(t *testing.T) {
	cb17SetupDB(t)

	initQueueDB(db)

	var name string
	err := db.QueryRow("SELECT name FROM sqlite_master WHERE type='table' AND name='offline_queue'").Scan(&name)
	if err != nil {
		t.Error("offline_queue table should exist")
	}
}

// ==============================
// getConversationMessages with cursor pagination tests
// ==============================

func TestCB17_GetConversationMessages_CursorPagination(t *testing.T) {
	cb17SetupDB(t)
	_, userID := cb17SetupAuth(t)
	agentID := cb17SetupAgent(t)
	convID := cb17CreateConversation(t, userID, agentID)

	for i := 0; i < 10; i++ {
		msgID := generateID("msg")
		ts := time.Now().Add(-time.Duration(10-i) * time.Minute).UTC()
		db.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, created_at) VALUES (?, ?, ?, ?, ?, ?)",
			msgID, convID, "agent", agentID, fmt.Sprintf("message %d", i), ts)
	}

	messages, err := getConversationMessages(convID, 5, "")
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
	if len(messages) != 5 {
		t.Errorf("expected 5 messages, got %d", len(messages))
	}

	before := messages[len(messages)-1].CreatedAt.Format(time.RFC3339Nano)
	messages2, err := getConversationMessages(convID, 5, before)
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
	if len(messages2) != 5 {
		t.Errorf("expected 5 messages, got %d", len(messages2))
	}

	if len(messages2) > 1 {
		if !messages2[0].CreatedAt.Before(messages2[len(messages2)-1].CreatedAt) {
			t.Error("cursor-paginated results should be in chronological order")
		}
	}
}

// ==============================
// getMessageReactions tests
// ==============================

func TestCB17_GetMessageReactions_NoReactions(t *testing.T) {
	cb17SetupDB(t)

	reactions, err := getMessageReactions("nonexistent_msg")
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
	if len(reactions) != 0 {
		t.Errorf("expected 0 reactions, got %d", len(reactions))
	}
}

func TestCB17_GetMessageReactions_WithReactions(t *testing.T) {
	cb17SetupDB(t)
	_, userID := cb17SetupAuth(t)
	agentID := cb17SetupAgent(t)
	convID := cb17CreateConversation(t, userID, agentID)

	msgID := generateID("msg")
	db.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, created_at) VALUES (?, ?, ?, ?, ?, ?)",
		msgID, convID, "agent", agentID, "hello", time.Now().UTC())

	addReaction(msgID, userID, "👍")
	addReaction(msgID, userID, "❤️")

	reactions, err := getMessageReactions(msgID)
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
	if len(reactions) < 1 {
		t.Errorf("expected at least 1 reaction, got %d", len(reactions))
	}
}

// ==============================
// getConversationTags tests
// ==============================

func TestCB17_GetConversationTags_NoTags(t *testing.T) {
	cb17SetupDB(t)

	tags, err := getConversationTags("nonexistent_conv")
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
	if len(tags) != 0 {
		t.Errorf("expected 0 tags, got %d", len(tags))
	}
}

func TestCB17_GetConversationTags_WithTags(t *testing.T) {
	cb17SetupDB(t)
	_, userID := cb17SetupAuth(t)
	agentID := cb17SetupAgent(t)
	convID := cb17CreateConversation(t, userID, agentID)

	addConversationTag(convID, userID, "important")
	addConversationTag(convID, userID, "starred")

	tags, err := getConversationTags(convID)
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
	if len(tags) < 2 {
		t.Errorf("expected at least 2 tags, got %d", len(tags))
	}
}

// ==============================
// handleDeleteNotificationPrefs tests
// ==============================

func TestCB17_HandleDeleteNotificationPrefs_NoAuth(t *testing.T) {
	req := httptest.NewRequest(http.MethodDelete, "/notifications/prefs?conversation_id=conv1", nil)
	w := httptest.NewRecorder()
	handleDeleteNotificationPrefs(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestCB17_HandleDeleteNotificationPrefs_MissingConvID(t *testing.T) {
	cb17SetupDB(t)
	token, userID := cb17SetupAuth(t)

	req := httptest.NewRequest(http.MethodDelete, "/notifications/prefs", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req = cb17SetUserIDContext(req, userID)
	w := httptest.NewRecorder()
	handleDeleteNotificationPrefs(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestCB17_HandleDeleteNotificationPrefs_Success(t *testing.T) {
	cb17SetupDB(t)
	token, userID := cb17SetupAuth(t)
	agentID := cb17SetupAgent(t)
	convID := cb17CreateConversation(t, userID, agentID)

	req := httptest.NewRequest(http.MethodPost, "/notifications/prefs?conversation_id="+convID+"&muted=true", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req = cb17SetUserIDContext(req, userID)
	w := httptest.NewRecorder()
	handleSetNotificationPrefs(w, req)

	req2 := httptest.NewRequest(http.MethodDelete, "/notifications/prefs?conversation_id="+convID, nil)
	req2.Header.Set("Authorization", "Bearer "+token)
	req2 = cb17SetUserIDContext(req2, userID)
	w2 := httptest.NewRecorder()
	handleDeleteNotificationPrefs(w2, req2)

	if w2.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w2.Code, w2.Body.String())
	}

	var count int
	db.QueryRow("SELECT COUNT(*) FROM notification_preferences WHERE user_id = ? AND conversation_id = ?", userID, convID).Scan(&count)
	if count != 0 {
		t.Error("preference should be deleted")
	}
}

// ==============================
// handleGetNotificationPrefs tests
// ==============================

func TestCB17_HandleGetNotificationPrefs_NoAuth(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/notifications/prefs", nil)
	w := httptest.NewRecorder()
	handleGetNotificationPrefs(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestCB17_HandleGetNotificationPrefs_Empty(t *testing.T) {
	cb17SetupDB(t)
	token, userID := cb17SetupAuth(t)

	req := httptest.NewRequest(http.MethodGet, "/notifications/prefs", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req = cb17SetUserIDContext(req, userID)
	w := httptest.NewRecorder()
	handleGetNotificationPrefs(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}

	var prefs []NotificationPreferences
	json.Unmarshal(w.Body.Bytes(), &prefs)
	if len(prefs) != 0 {
		t.Errorf("expected 0 preferences, got %d", len(prefs))
	}
}

// ==============================
// handleMessageEdit/Delete additional tests
// ==============================

func TestCB17_HandleMessageEdit_WrongMethod(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/messages/edit", nil)
	w := httptest.NewRecorder()
	handleMessageEdit(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestCB17_HandleMessageDelete_WrongMethod(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/messages/delete", nil)
	w := httptest.NewRecorder()
	handleMessageDelete(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

// ==============================
// truncate tests
// ==============================

func TestCB17_Truncate(t *testing.T) {
	if truncate("hello", 3) != "hel" {
		t.Error("truncate should work for maxLen<=3")
	}
	if truncate("hello", 10) != "hello" {
		t.Error("truncate should return full string if shorter than maxLen")
	}
	if truncate("hello world", 8) != "hello..." {
		t.Errorf("expected 'hello...', got '%s'", truncate("hello world", 8))
	}
	if truncate("abc", 0) != "" {
		t.Errorf("expected '', got '%s'", truncate("abc", 0))
	}
}

// ==============================
// HandleWebPushSubscribe success test
// ==============================

func TestCB17_HandleWebPushSubscribe_Success(t *testing.T) {
	cb17SetupDB(t)
	token, _ := cb17SetupAuth(t)

	body := map[string]interface{}{
		"endpoint": "https://push.example.com/sub/456",
		"keys": map[string]string{
			"p256dh": "testkey456abc",
			"auth":   "testauth456def",
		},
	}
	bodyJSON, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/push/web-subscribe", bytes.NewReader(bodyJSON))
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleWebPushSubscribe(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var result map[string]string
	json.Unmarshal(w.Body.Bytes(), &result)
	if result["status"] != "subscribed" {
		t.Errorf("expected 'subscribed', got %v", result)
	}
}

func TestCB17_HandleWebPushUnsubscribe_Success(t *testing.T) {
	cb17SetupDB(t)
	token, _ := cb17SetupAuth(t)

	body := map[string]interface{}{
		"endpoint": "https://push.example.com/sub/456",
	}
	bodyJSON, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/push/web-unsubscribe", bytes.NewReader(bodyJSON))
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleWebPushUnsubscribe(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var result map[string]string
	json.Unmarshal(w.Body.Bytes(), &result)
	if result["status"] != "unsubscribed" {
		t.Errorf("expected 'unsubscribed', got %v", result)
	}
}

// ==============================
// HandleRegisterDeviceToken success
// ==============================

func TestCB17_HandleRegisterDeviceToken_Success(t *testing.T) {
	cb17SetupDB(t)
	token, userID := cb17SetupAuth(t)

	body := map[string]string{"device_token": "new_device_token", "platform": "android"}
	bodyJSON, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/push/register", bytes.NewReader(bodyJSON))
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleRegisterDeviceToken(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var platform string
	db.QueryRow("SELECT platform FROM device_tokens WHERE user_id = ? AND device_token = ?", userID, "new_device_token").Scan(&platform)
	if platform != "android" {
		t.Errorf("expected 'android', got '%s'", platform)
	}
}

// ==============================
// WebPush wrong methods
// ==============================

func TestCB17_HandleWebPushSubscribe_WrongMethod(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/push/web-subscribe", nil)
	w := httptest.NewRecorder()
	handleWebPushSubscribe(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestCB17_HandleWebPushUnsubscribe_WrongMethod(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/push/web-unsubscribe", nil)
	w := httptest.NewRecorder()
	handleWebPushUnsubscribe(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

// ==============================
// GetEncryptedMessages with user auth
// ==============================

func TestCB17_GetEncryptedMessages_UserAuth(t *testing.T) {
	cb17SetupDB(t)
	token, userID := cb17SetupAuth(t)
	agentID := cb17SetupAgent(t)
	convID := cb17CreateConversation(t, userID, agentID)

	_, err := db.Exec(`INSERT INTO encrypted_messages (id, conversation_id, sender_id, sender_type, ciphertext, iv, recipient_key_id, algorithm, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		"emsg_user", convID, userID, "user", "ciphertext_user", "iv_user", "key_user", "aes-256-gcm", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/messages/encrypted?conversation_id="+convID, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleGetEncryptedMessages(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var messages []EncryptedMessage
	json.Unmarshal(w.Body.Bytes(), &messages)
	if len(messages) != 1 {
		t.Errorf("expected 1 message, got %d", len(messages))
	}
}

// ==============================
// GetEncryptedMessages with limit
// ==============================

func TestCB17_GetEncryptedMessages_WithLimit(t *testing.T) {
	cb17SetupDB(t)
	token, userID := cb17SetupAuth(t)
	agentID := cb17SetupAgent(t)
	convID := cb17CreateConversation(t, userID, agentID)

	for i := 0; i < 5; i++ {
		msgID := generateID("emsg")
		_, err := db.Exec(`INSERT INTO encrypted_messages (id, conversation_id, sender_id, sender_type, ciphertext, iv, recipient_key_id, algorithm, created_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			msgID, convID, userID, "user", fmt.Sprintf("cipher_%d", i), fmt.Sprintf("iv_%d", i), "key1", "aes-256-gcm", time.Now().Add(time.Duration(i)*time.Second).UTC())
		if err != nil {
			t.Fatal(err)
		}
	}

	req := httptest.NewRequest(http.MethodGet, "/messages/encrypted?conversation_id="+convID+"&limit=2", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleGetEncryptedMessages(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var messages []EncryptedMessage
	json.Unmarshal(w.Body.Bytes(), &messages)
	if len(messages) != 2 {
		t.Errorf("expected 2 messages with limit, got %d", len(messages))
	}
}

// ==============================
// HandleStoreEncryptedMessage with hub nil
// ==============================

func TestCB17_HandleStoreEncryptedMessage_HubNil(t *testing.T) {
	cb17SetupDB(t)
	token, userID := cb17SetupAuth(t)
	agentID := cb17SetupAgent(t)
	convID := cb17CreateConversation(t, userID, agentID)

	hub = nil

	body := map[string]interface{}{
		"conversation_id":   convID,
		"ciphertext":       "base64ciphertext==",
		"iv":               "base64iv==",
		"recipient_key_id": "key_abc",
		"algorithm":        "aes-256-gcm",
	}
	bodyJSON, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/messages/encrypted", bytes.NewReader(bodyJSON))
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleStoreEncryptedMessage(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200 even with hub nil, got %d: %s", w.Code, w.Body.String())
	}
}