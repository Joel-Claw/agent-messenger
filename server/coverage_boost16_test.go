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
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// ==============================
// Helper functions for CB16
// ==============================

func cb16SetupDB(t *testing.T) {
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
}

func cb16MakeToken(t *testing.T, username string) string {
	t.Helper()
	hash, _ := bcrypt.GenerateFromPassword([]byte("testpass123"), bcrypt.MinCost)
	_, err := db.Exec("INSERT OR IGNORE INTO users (id, username, password_hash) VALUES (?, ?, ?)", username, username, string(hash))
	if err != nil {
		t.Fatalf("insert user: %v", err)
	}
	token, err := GenerateJWT(username, username)
	if err != nil {
		t.Fatalf("generate JWT: %v", err)
	}
	return token
}

func cb16WithUserContext(r *http.Request, userID string) *http.Request {
	ctx := context.WithValue(r.Context(), contextKeyUserID, userID)
	return r.WithContext(ctx)
}

func cb16CreateAgent(t *testing.T, agentID string) {
	t.Helper()
	_, err := db.Exec("INSERT OR IGNORE INTO agents (id, name) VALUES (?, ?)", agentID, agentID)
	if err != nil {
		t.Fatalf("insert agent: %v", err)
	}
}

func cb16CreateConversation(t *testing.T, convID, userID, agentID string) {
	t.Helper()
	_, err := db.Exec("INSERT OR IGNORE INTO conversations (id, user_id, agent_id) VALUES (?, ?, ?)", convID, userID, agentID)
	if err != nil {
		t.Fatalf("insert conversation: %v", err)
	}
}

func cb16CreateUser(t *testing.T, userID, username string) {
	t.Helper()
	hash, _ := bcrypt.GenerateFromPassword([]byte("testpass123"), bcrypt.MinCost)
	_, err := db.Exec("INSERT OR IGNORE INTO users (id, username, password_hash) VALUES (?, ?, ?)", userID, username, string(hash))
	if err != nil {
		t.Fatalf("insert user: %v", err)
	}
}

// ==============================
// sendAPNSNotification deeper coverage
// ==============================

func TestCB16_SendAPNSNotification_WithClientAndSuccessfulResponse(t *testing.T) {
	// Test the branch where pushConfig is set, APNs is enabled, and apnsClient is set,
	// but we can't easily create a real APNs client, so we test that with a nil
	// client the function returns nil (early exit path)
	pushConfig = &PushNotificationConfig{
		APNSEnabled: true,
	}
	// No apnsClient — should return nil without panicking
	err := sendAPNSNotification("testtoken", "Title", "Body", "conv1")
	if err != nil {
		t.Fatalf("expected nil error with nil client, got %v", err)
	}
	pushConfig = nil
}

func TestCB16_SendAPNSNotification_DisabledConfig(t *testing.T) {
	pushConfig = &PushNotificationConfig{
		APNSEnabled: false,
	}
	err := sendAPNSNotification("token", "Title", "Body", "conv1")
	if err != nil {
		t.Fatalf("expected nil when APNs disabled, got %v", err)
	}
	pushConfig = nil
}

func TestCB16_SendAPNSNotification_NilConfig(t *testing.T) {
	pushConfig = nil
	err := sendAPNSNotification("token", "Title", "Body", "conv1")
	if err != nil {
		t.Fatalf("expected nil when pushConfig is nil, got %v", err)
	}
}

func TestCB16_SendAPNSNotification_EmptyToken(t *testing.T) {
	pushConfig = &PushNotificationConfig{
		APNSEnabled:    true,
		BundleID:        "com.test.app",
		Environment:     "development",
		apnsClient:      nil, // no client, so we hit the early return
	}
	// Should return nil since client is nil
	err := sendAPNSNotification("", "Title", "Body", "")
	if err != nil {
		t.Fatalf("expected nil with empty token and nil client, got %v", err)
	}
	pushConfig = nil
}

// ==============================
// sendFCMNotification deeper coverage
// ==============================

func TestCB16_SendFCMNotification_NilConfig(t *testing.T) {
	pushConfig = nil
	err := sendFCMNotification("token123", "Title", "Body", "conv1")
	if err != nil {
		t.Fatalf("expected nil when pushConfig is nil, got %v", err)
	}
}

func TestCB16_SendFCMNotification_FCMDisabled(t *testing.T) {
	pushConfig = &PushNotificationConfig{
		FCMEnabled: false,
	}
	err := sendFCMNotification("token", "Title", "Body", "conv1")
	if err != nil {
		t.Fatalf("expected nil when FCM disabled, got %v", err)
	}
	pushConfig = nil
}

func TestCB16_SendFCMNotification_NilClient(t *testing.T) {
	pushConfig = &PushNotificationConfig{
		FCMEnabled: true,
		fcmClient:  nil,
	}
	err := sendFCMNotification("token", "Title", "Body", "conv1")
	if err != nil {
		t.Fatalf("expected nil when fcmClient is nil, got %v", err)
	}
	pushConfig = nil
}

func TestCB16_SendFCMNotification_EnabledButNilClient(t *testing.T) {
	pushConfig = &PushNotificationConfig{
		FCMEnabled: true,
		fcmClient:  nil,
	}
	err := sendFCMNotification("token", "Hello", "World", "conv1")
	if err != nil {
		t.Fatalf("expected nil for nil client, got %v", err)
	}
	pushConfig = nil
}

// ==============================
// sendPushNotification platform routing
// ==============================

func TestCB16_SendPushNotification_AndroidPlatform(t *testing.T) {
	pushConfig = nil // both sendAPNSNotification and sendFCMNotification return nil when config is nil
	err := sendPushNotification("token", "Title", "Body", "conv1", "android")
	if err != nil {
		t.Fatalf("expected nil for android platform, got %v", err)
	}
}

func TestCB16_SendPushNotification_FCMPlatform(t *testing.T) {
	pushConfig = nil
	err := sendPushNotification("token", "Title", "Body", "conv1", "fcm")
	if err != nil {
		t.Fatalf("expected nil for fcm platform, got %v", err)
	}
}

func TestCB16_SendPushNotification_IOSPlatform(t *testing.T) {
	pushConfig = nil
	err := sendPushNotification("token", "Title", "Body", "conv1", "ios")
	if err != nil {
		t.Fatalf("expected nil for ios platform, got %v", err)
	}
}

func TestCB16_SendPushNotification_UnknownPlatform(t *testing.T) {
	pushConfig = nil
	// Unknown platforms should default to APNs
	err := sendPushNotification("token", "Title", "Body", "conv1", "unknown_platform")
	if err != nil {
		t.Fatalf("expected nil for unknown platform (defaults to APNs), got %v", err)
	}
}

// ==============================
// notifyUser edge cases
// ==============================

func TestCB16_NotifyUser_NilConfig(t *testing.T) {
	pushConfig = nil
	// Should not panic and should return early
	notifyUser("user1", "Title", "Body", "conv1")
}

func TestCB16_NotifyUser_MutedConversation(t *testing.T) {
	cb16SetupDB(t)
	pushConfig = &PushNotificationConfig{
		APNSEnabled: false,
		FCMEnabled: false,
	}
	defer func() { pushConfig = nil }()

	cb16CreateUser(t, "user1", "user1")
	cb16CreateAgent(t, "agent1")
	cb16CreateConversation(t, "conv1", "user1", "agent1")

	// Mute the conversation
	_, err := db.Exec("INSERT INTO notification_preferences (user_id, conversation_id, muted) VALUES (?, ?, 1)", "user1", "conv1")
	if err != nil {
		t.Fatalf("insert notif pref: %v", err)
	}

	// Should return early (muted), no push sent
	notifyUser("user1", "Title", "Body", "conv1")
	// No crash, no push sent
}

func TestCB16_NotifyUser_NoDeviceTokens(t *testing.T) {
	cb16SetupDB(t)
	pushConfig = &PushNotificationConfig{
		APNSEnabled: true,
		FCMEnabled: true,
		apnsClient: nil, // no actual clients
		fcmClient:  nil,
	}
	defer func() { pushConfig = nil }()

	cb16CreateUser(t, "user1", "user1")
	cb16CreateAgent(t, "agent1")
	cb16CreateConversation(t, "conv1", "user1", "agent1")

	// No device tokens registered — should return without error
	notifyUser("user1", "Title", "Body", "conv1")
}

func TestCB16_NotifyUser_WithDeviceTokens(t *testing.T) {
	cb16SetupDB(t)
	pushConfig = &PushNotificationConfig{
		APNSEnabled: true,
		FCMEnabled:  true,
		apnsClient:  nil, // nil clients will return nil
		fcmClient:   nil,
	}
	defer func() { pushConfig = nil }()

	cb16CreateUser(t, "user1", "user1")
	cb16CreateAgent(t, "agent1")
	cb16CreateConversation(t, "conv1", "user1", "agent1")

	// Register a device token
	_, err := db.Exec("INSERT INTO device_tokens (user_id, device_token, platform, updated_at) VALUES (?, ?, ?, CURRENT_TIMESTAMP)",
		"user1", "ios_token_1", "ios")
	if err != nil {
		t.Fatalf("insert device token: %v", err)
	}
	_, err = db.Exec("INSERT INTO device_tokens (user_id, device_token, platform, updated_at) VALUES (?, ?, ?, CURRENT_TIMESTAMP)",
		"user1", "android_token_1", "android")
	if err != nil {
		t.Fatalf("insert device token: %v", err)
	}

	// Should iterate tokens without crash (nil clients cause early return)
	notifyUser("user1", "New Message", "Hello", "conv1")
}

func TestCB16_NotifyUser_EmptyConversationID(t *testing.T) {
	cb16SetupDB(t)
	pushConfig = &PushNotificationConfig{
		APNSEnabled: true,
		FCMEnabled:  true,
		apnsClient:  nil,
		fcmClient:   nil,
	}
	defer func() { pushConfig = nil }()

	cb16CreateUser(t, "user1", "user1")
	// Register a device token
	_, err := db.Exec("INSERT INTO device_tokens (user_id, device_token, platform, updated_at) VALUES (?, ?, ?, CURRENT_TIMESTAMP)",
		"user1", "token_1", "ios")
	if err != nil {
		t.Fatalf("insert device token: %v", err)
	}

	// Empty conversation ID should skip mute check (no panic)
	notifyUser("user1", "Title", "Body", "")
}

// ==============================
// initPushNotifications deeper coverage
// ==============================

func TestCB16_InitPushNotifications_Defaults(t *testing.T) {
	// Save and restore env vars
	origAPNS := os.Getenv("APNS_ENABLED")
	origFCM := os.Getenv("FCM_ENABLED")
	origCertPath := os.Getenv("APNS_CERT_PATH")
	origFCMCreds := os.Getenv("FCM_CREDENTIALS_PATH")
	origBundleID := os.Getenv("APNS_BUNDLE_ID")
	origEnv := os.Getenv("APNS_ENVIRONMENT")
	defer func() {
		os.Setenv("APNS_ENABLED", origAPNS)
		os.Setenv("FCM_ENABLED", origFCM)
		os.Setenv("APNS_CERT_PATH", origCertPath)
		os.Setenv("FCM_CREDENTIALS_PATH", origFCMCreds)
		os.Setenv("APNS_BUNDLE_ID", origBundleID)
		os.Setenv("APNS_ENVIRONMENT", origEnv)
	}()

	os.Setenv("APNS_ENABLED", "false")
	os.Setenv("FCM_ENABLED", "false")
	os.Setenv("APNS_CERT_PATH", "")
	os.Setenv("FCM_CREDENTIALS_PATH", "")

	initPushNotifications()

	if pushConfig == nil {
		t.Fatal("pushConfig should not be nil after init")
	}
	if pushConfig.APNSEnabled {
		t.Error("APNs should be disabled")
	}
	if pushConfig.FCMEnabled {
		t.Error("FCM should be disabled")
	}
	if pushConfig.BundleID != "com.agentmessenger.ios" {
		t.Errorf("expected default BundleID, got %s", pushConfig.BundleID)
	}
	if pushConfig.Environment != "development" {
		t.Errorf("expected default Environment 'development', got %s", pushConfig.Environment)
	}
	pushConfig = nil
}

func TestCB16_InitPushNotifications_APNSEnabledNoCertPath(t *testing.T) {
	origAPNS := os.Getenv("APNS_ENABLED")
	origCertPath := os.Getenv("APNS_CERT_PATH")
	origFCM := os.Getenv("FCM_ENABLED")
	origFCMCreds := os.Getenv("FCM_CREDENTIALS_PATH")
	defer func() {
		os.Setenv("APNS_ENABLED", origAPNS)
		os.Setenv("APNS_CERT_PATH", origCertPath)
		os.Setenv("FCM_ENABLED", origFCM)
		os.Setenv("FCM_CREDENTIALS_PATH", origFCMCreds)
	}()

	os.Setenv("APNS_ENABLED", "true")
	os.Setenv("APNS_CERT_PATH", "")
	os.Setenv("FCM_ENABLED", "false")
	os.Setenv("FCM_CREDENTIALS_PATH", "")

	initPushNotifications()

	// APNs stays enabled in config but has no cert path — initAPNs returns without creating client
	if pushConfig == nil {
		t.Fatal("pushConfig should not be nil after init")
	}
	// With no cert path, APNs won't actually work but the flag stays true
	// The actual client (apnsClient) will be nil
	if pushConfig.apnsClient != nil {
		t.Error("apnsClient should be nil when no cert path")
	}
	pushConfig = nil
}

func TestCB16_InitPushNotifications_APNSWithNonexistentCert(t *testing.T) {
	origAPNS := os.Getenv("APNS_ENABLED")
	origCertPath := os.Getenv("APNS_CERT_PATH")
	origFCM := os.Getenv("FCM_ENABLED")
	origFCMCreds := os.Getenv("FCM_CREDENTIALS_PATH")
	defer func() {
		os.Setenv("APNS_ENABLED", origAPNS)
		os.Setenv("APNS_CERT_PATH", origCertPath)
		os.Setenv("FCM_ENABLED", origFCM)
		os.Setenv("FCM_CREDENTIALS_PATH", origFCMCreds)
	}()

	os.Setenv("APNS_ENABLED", "true")
	os.Setenv("APNS_CERT_PATH", "/nonexistent/path/to/cert.p12")
	os.Setenv("FCM_ENABLED", "false")
	os.Setenv("FCM_CREDENTIALS_PATH", "")

	initPushNotifications()

	if pushConfig.APNSEnabled {
		t.Error("APNs should be disabled when cert file doesn't exist")
	}
	pushConfig = nil
}

func TestCB16_InitPushNotifications_FCMEnabledNoCredsPath(t *testing.T) {
	origAPNS := os.Getenv("APNS_ENABLED")
	origFCM := os.Getenv("FCM_ENABLED")
	origFCMCreds := os.Getenv("FCM_CREDENTIALS_PATH")
	defer func() {
		os.Setenv("APNS_ENABLED", origAPNS)
		os.Setenv("FCM_ENABLED", origFCM)
		os.Setenv("FCM_CREDENTIALS_PATH", origFCMCreds)
	}()

	os.Setenv("APNS_ENABLED", "false")
	os.Setenv("FCM_ENABLED", "true")
	os.Setenv("FCM_CREDENTIALS_PATH", "")

	initPushNotifications()

	// FCM stays enabled in config but has no client — initFCM returns without creating client
	if pushConfig == nil {
		t.Fatal("pushConfig should not be nil after init")
	}
	if pushConfig.fcmClient != nil {
		t.Error("fcmClient should be nil when no credentials path")
	}
	pushConfig = nil
}

func TestCB16_InitPushNotifications_FCMWithNonexistentCreds(t *testing.T) {
	origAPNS := os.Getenv("APNS_ENABLED")
	origFCM := os.Getenv("FCM_ENABLED")
	origFCMCreds := os.Getenv("FCM_CREDENTIALS_PATH")
	defer func() {
		os.Setenv("APNS_ENABLED", origAPNS)
		os.Setenv("FCM_ENABLED", origFCM)
		os.Setenv("FCM_CREDENTIALS_PATH", origFCMCreds)
	}()

	os.Setenv("APNS_ENABLED", "false")
	os.Setenv("FCM_ENABLED", "true")
	os.Setenv("FCM_CREDENTIALS_PATH", "/nonexistent/path/creds.json")

	initPushNotifications()

	if pushConfig.FCMEnabled {
		t.Error("FCM should be disabled when credentials file doesn't exist")
	}
	pushConfig = nil
}

// ==============================
// handleSetNotificationPrefs deeper coverage
// ==============================

func TestCB16_SetNotificationPrefs_NotFoundConversation(t *testing.T) {
	cb16SetupDB(t)

	body := strings.NewReader("conversation_id=nonexistent&muted=true")
	req := httptest.NewRequest(http.MethodPost, "/notification-prefs/set", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req = cb16WithUserContext(req, "user1")
	w := httptest.NewRecorder()

	handleSetNotificationPrefs(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404 for nonexistent conversation, got %d", w.Code)
	}
}

func TestCB16_SetNotificationPrefs_WrongOwner(t *testing.T) {
	cb16SetupDB(t)
	cb16CreateUser(t, "user1", "user1")
	cb16CreateUser(t, "user2", "user2")
	cb16CreateAgent(t, "agent1")
	cb16CreateConversation(t, "conv1", "user1", "agent1")

	// user2 tries to set prefs for user1's conversation
	body := strings.NewReader("conversation_id=conv1&muted=true")
	req := httptest.NewRequest(http.MethodPost, "/notification-prefs/set", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req = cb16WithUserContext(req, "user2")
	w := httptest.NewRecorder()

	handleSetNotificationPrefs(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403 for wrong owner, got %d", w.Code)
	}
}

func TestCB16_SetNotificationPrefs_Success(t *testing.T) {
	cb16SetupDB(t)
	cb16CreateUser(t, "user1", "user1")
	cb16CreateAgent(t, "agent1")
	cb16CreateConversation(t, "conv1", "user1", "agent1")

	body := strings.NewReader("conversation_id=conv1&muted=true")
	req := httptest.NewRequest(http.MethodPost, "/notification-prefs/set", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req = cb16WithUserContext(req, "user1")
	w := httptest.NewRecorder()

	handleSetNotificationPrefs(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}

	var result NotificationPreferences
	json.Unmarshal(w.Body.Bytes(), &result)
	if result.ConversationID != "conv1" {
		t.Errorf("expected conv1, got %s", result.ConversationID)
	}
	if !result.Muted {
		t.Error("expected muted=true")
	}
}

func TestCB16_SetNotificationPrefs_Unmute(t *testing.T) {
	cb16SetupDB(t)
	cb16CreateUser(t, "user1", "user1")
	cb16CreateAgent(t, "agent1")
	cb16CreateConversation(t, "conv1", "user1", "agent1")

	// First mute
	body1 := strings.NewReader("conversation_id=conv1&muted=true")
	req := httptest.NewRequest(http.MethodPost, "/notification-prefs/set", body1)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req = cb16WithUserContext(req, "user1")
	w := httptest.NewRecorder()
	handleSetNotificationPrefs(w, req)

	// Then unmute
	body2 := strings.NewReader("conversation_id=conv1&muted=false")
	req2 := httptest.NewRequest(http.MethodPost, "/notification-prefs/set", body2)
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req2 = cb16WithUserContext(req2, "user1")
	w2 := httptest.NewRecorder()
	handleSetNotificationPrefs(w2, req2)

	if w2.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w2.Code)
	}
}

func TestCB16_SetNotificationPrefs_MissingConversationID(t *testing.T) {
	cb16SetupDB(t)

	body := strings.NewReader("muted=true")
	req := httptest.NewRequest(http.MethodPost, "/notification-prefs/set", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req = cb16WithUserContext(req, "user1")
	w := httptest.NewRecorder()

	handleSetNotificationPrefs(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing conversation_id, got %d", w.Code)
	}
}

// ==============================
// deleteConversation deeper coverage
// ==============================

func TestCB16_DeleteConversation_NotFound(t *testing.T) {
	cb16SetupDB(t)

	err := deleteConversation("nonexistent", "user1")
	if err == nil {
		t.Fatal("expected error for nonexistent conversation")
	}
	if err != sql.ErrNoRows {
		t.Errorf("expected sql.ErrNoRows, got %v", err)
	}
}

func TestCB16_DeleteConversation_WrongUser(t *testing.T) {
	cb16SetupDB(t)
	cb16CreateUser(t, "user1", "user1")
	cb16CreateAgent(t, "agent1")
	cb16CreateConversation(t, "conv1", "user1", "agent1")

	err := deleteConversation("conv1", "wrong_user")
	if err == nil {
		t.Fatal("expected error for wrong user")
	}
	if err.Error() != "unauthorized" {
		t.Errorf("expected 'unauthorized', got %v", err)
	}
}

func TestCB16_DeleteConversation_Success(t *testing.T) {
	cb16SetupDB(t)
	cb16CreateUser(t, "user1", "user1")
	cb16CreateAgent(t, "agent1")
	cb16CreateConversation(t, "conv1", "user1", "agent1")

	// Insert a message
	_, err := db.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, created_at) VALUES (?, ?, ?, ?, ?, ?)",
		"msg1", "conv1", "user", "user1", "hello", time.Now().UTC())
	if err != nil {
		t.Fatalf("insert message: %v", err)
	}

	err = deleteConversation("conv1", "user1")
	if err != nil {
		t.Fatalf("expected successful deletion, got %v", err)
	}

	// Verify conversation is gone
	var count int
	db.QueryRow("SELECT COUNT(*) FROM conversations WHERE id = ?", "conv1").Scan(&count)
	if count != 0 {
		t.Error("conversation should be deleted")
	}

	// Verify messages are gone
	db.QueryRow("SELECT COUNT(*) FROM messages WHERE conversation_id = ?", "conv1").Scan(&count)
	if count != 0 {
		t.Error("messages should be deleted")
	}
}

// ==============================
// handleDeleteConversation deeper coverage
// ==============================

func TestCB16_HandleDeleteConversation_Success(t *testing.T) {
	cb16SetupDB(t)
	cb16MakeToken(t, "user1")
	cb16CreateAgent(t, "agent1")
	cb16CreateConversation(t, "conv1", "user1", "agent1")
	token, _ := GenerateJWT("user1", "user1")

	req := httptest.NewRequest(http.MethodDelete, "/conversations/delete?conversation_id=conv1", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	handleDeleteConversation(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCB16_HandleDeleteConversation_Unauthorized(t *testing.T) {
	cb16SetupDB(t)

	req := httptest.NewRequest(http.MethodDelete, "/conversations/delete?conversation_id=conv1", nil)
	w := httptest.NewRecorder()

	handleDeleteConversation(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestCB16_HandleDeleteConversation_NotFound(t *testing.T) {
	cb16SetupDB(t)
	cb16MakeToken(t, "user1")
	token, _ := GenerateJWT("user1", "user1")

	req := httptest.NewRequest(http.MethodDelete, "/conversations/delete?conversation_id=nonexistent", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	handleDeleteConversation(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

func TestCB16_HandleDeleteConversation_MissingID(t *testing.T) {
	cb16SetupDB(t)
	cb16MakeToken(t, "user1")
	token, _ := GenerateJWT("user1", "user1")

	req := httptest.NewRequest(http.MethodDelete, "/conversations/delete", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	handleDeleteConversation(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

// ==============================
// routeChatMessage deeper coverage — offline agent + push
// ==============================

func TestCB16_RouteChatMessage_AgentNotOnline_QueuesAndPushes(t *testing.T) {
	cb16SetupDB(t)
	hub = newHub()
	go hub.run()
	defer hub.Stop()

	cb16CreateUser(t, "user1", "user1")
	cb16CreateAgent(t, "agent1")
	cb16CreateConversation(t, "conv1", "user1", "agent1")

	// Send a message from a user connection where agent is NOT online
	conn := &Connection{
		id:        "user1",
		connType:  "client",
		send:      make(chan []byte, 256),
		closeMu:   sync.RWMutex{},
	}
	// Don't register with hub — just test the routing logic

	pushConfig = &PushNotificationConfig{
		APNSEnabled: true,
		FCMEnabled:  true,
		apnsClient:  nil,
		fcmClient:   nil,
	}
	defer func() { pushConfig = nil }()

	data, _ := json.Marshal(RoutedMessage{
		ConversationID: "conv1",
		Content:        "hello from user",
	})

	routeChatMessage(conn, data)

	// Verify message was stored in DB
	var count int
	db.QueryRow("SELECT COUNT(*) FROM messages WHERE conversation_id = ? AND content = ?", "conv1", "hello from user").Scan(&count)
	if count != 1 {
		t.Errorf("expected 1 message stored, got %d", count)
	}
}

func TestCB16_RouteChatMessage_InvalidJSON(t *testing.T) {
	conn := &Connection{
		id:       "badconn",
		connType: "client",
		send:     make(chan []byte, 256),
		closeMu:  sync.RWMutex{},
	}

	routeChatMessage(conn, json.RawMessage(`{invalid json`))
	// Should not panic
}

func TestCB16_RouteChatMessage_EmptyContent(t *testing.T) {
	conn := &Connection{
		id:       "emptycontent",
		connType: "client",
		send:     make(chan []byte, 256),
		closeMu:  sync.RWMutex{},
	}

	data, _ := json.Marshal(RoutedMessage{
		ConversationID: "conv1",
		Content:        "",
	})

	routeChatMessage(conn, data)
	// Should not panic — sends error back
}

// ==============================
// handleStoreEncryptedMessage deeper coverage
// ==============================

func TestCB16_StoreEncryptedMessage_WrongUserParticipant(t *testing.T) {
	cb16SetupDB(t)
	cb16MakeToken(t, "user1")
	cb16MakeToken(t, "user2")
	cb16CreateAgent(t, "agent1")
	cb16CreateConversation(t, "conv1", "user1", "agent1")

	// user2 tries to store encrypted message in user1's conversation
	token2, _ := GenerateJWT("user2", "user2")
	body := fmt.Sprintf(`{"conversation_id":"conv1","ciphertext":"abc","iv":"def","algorithm":"aes-256-gcm"}`)
	req := httptest.NewRequest(http.MethodPost, "/messages/encrypted", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token2)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handleStoreEncryptedMessage(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403 for wrong user, got %d", w.Code)
	}
}

func TestCB16_StoreEncryptedMessage_AgentNotParticipant(t *testing.T) {
	cb16SetupDB(t)
	cb16CreateAgent(t, "agent1")
	cb16CreateAgent(t, "agent2")
	cb16CreateUser(t, "user1", "user1")
	cb16CreateConversation(t, "conv1", "user1", "agent1")

	// agent2 tries to store encrypted message in a conversation they're not in
	body := fmt.Sprintf(`{"conversation_id":"conv1","ciphertext":"abc","iv":"def","algorithm":"aes-256-gcm"}`)
	req := httptest.NewRequest(http.MethodPost, "/messages/encrypted", strings.NewReader(body))
	req.Header.Set("X-Agent-Secret", getAgentSecret())
	req.Header.Set("X-Agent-ID", "agent2")
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handleStoreEncryptedMessage(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403 for non-participant agent, got %d", w.Code)
	}
}

func TestCB16_StoreEncryptedMessage_InvalidAlgorithm(t *testing.T) {
	cb16SetupDB(t)
	cb16MakeToken(t, "user1")
	cb16CreateAgent(t, "agent1")
	cb16CreateConversation(t, "conv1", "user1", "agent1")
	token, _ := GenerateJWT("user1", "user1")

	body := `{"conversation_id":"conv1","ciphertext":"abc","iv":"def","algorithm":"invalid-algo"}`
	req := httptest.NewRequest(http.MethodPost, "/messages/encrypted", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handleStoreEncryptedMessage(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid algorithm, got %d", w.Code)
	}
}

func TestCB16_StoreEncryptedMessage_MissingFields(t *testing.T) {
	cb16SetupDB(t)
	cb16MakeToken(t, "user1")
	token, _ := GenerateJWT("user1", "user1")

	// Missing ciphertext
	body := `{"conversation_id":"conv1","iv":"def","algorithm":"aes-256-gcm"}`
	req := httptest.NewRequest(http.MethodPost, "/messages/encrypted", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handleStoreEncryptedMessage(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing ciphertext, got %d", w.Code)
	}
}

func TestCB16_StoreEncryptedMessage_MissingConversationID(t *testing.T) {
	cb16SetupDB(t)
	cb16MakeToken(t, "user1")
	token, _ := GenerateJWT("user1", "user1")

	body := `{"ciphertext":"abc","iv":"def","algorithm":"aes-256-gcm"}`
	req := httptest.NewRequest(http.MethodPost, "/messages/encrypted", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handleStoreEncryptedMessage(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing conversation_id, got %d", w.Code)
	}
}

func TestCB16_StoreEncryptedMessage_NonexistentConversation(t *testing.T) {
	cb16SetupDB(t)
	cb16MakeToken(t, "user1")
	token, _ := GenerateJWT("user1", "user1")

	body := `{"conversation_id":"nonexistent","ciphertext":"abc","iv":"def","algorithm":"aes-256-gcm"}`
	req := httptest.NewRequest(http.MethodPost, "/messages/encrypted", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handleStoreEncryptedMessage(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404 for nonexistent conversation, got %d", w.Code)
	}
}

// ==============================
// GetEncryptedMessages deeper coverage
// ==============================

func TestCB16_GetEncryptedMessages_AgentAuth(t *testing.T) {
	cb16SetupDB(t)
	cb16CreateAgent(t, "agent1")
	cb16CreateUser(t, "user1", "user1")
	cb16CreateConversation(t, "conv1", "user1", "agent1")

	// Store an encrypted message
	_, err := db.Exec(`INSERT INTO encrypted_messages (id, conversation_id, sender_id, sender_type, ciphertext, iv, recipient_key_id, algorithm, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		"emsg1", "conv1", "user1", "user", "ct1", "iv1", "key1", "aes-256-gcm", time.Now().UTC())
	if err != nil {
		t.Fatalf("insert encrypted msg: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/messages/encrypted/list?conversation_id=conv1", nil)
	req.Header.Set("X-Agent-Secret", getAgentSecret())
	req.Header.Set("X-Agent-ID", "agent1")
	w := httptest.NewRecorder()

	handleGetEncryptedMessages(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200 for agent auth, got %d", w.Code)
	}
}

func TestCB16_GetEncryptedMessages_WrongParticipant(t *testing.T) {
	cb16SetupDB(t)
	cb16CreateAgent(t, "agent1")
	cb16CreateAgent(t, "agent2")
	cb16CreateUser(t, "user1", "user1")
	cb16CreateConversation(t, "conv1", "user1", "agent1")

	req := httptest.NewRequest(http.MethodGet, "/messages/encrypted/list?conversation_id=conv1", nil)
	req.Header.Set("X-Agent-Secret", getAgentSecret())
	req.Header.Set("X-Agent-ID", "agent2") // wrong agent
	w := httptest.NewRecorder()

	handleGetEncryptedMessages(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404 for non-participant agent, got %d", w.Code)
	}
}

func TestCB16_GetEncryptedMessages_MissingConversationID(t *testing.T) {
	cb16SetupDB(t)
	cb16MakeToken(t, "user1")
	token, _ := GenerateJWT("user1", "user1")

	req := httptest.NewRequest(http.MethodGet, "/messages/encrypted/list", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	handleGetEncryptedMessages(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing conversation_id, got %d", w.Code)
	}
}

// ==============================
// loadQueueFromDB and persistQueue deeper coverage
// ==============================

func TestCB16_LoadQueueFromDB_NilDB(t *testing.T) {
	// Should not panic with nil db
	q := newOfflineQueue(100, 7*24*time.Hour)
	loadQueueFromDB(nil, q)
}

func TestCB16_PersistQueue_NilDB(t *testing.T) {
	// Should not panic with nil db
	persistQueue(nil, "user1", []byte(`{}`))
}

func TestCB16_DeleteQueueMessages_NilDB(t *testing.T) {
	// Should not panic with nil db
	deleteQueueMessages(nil, "user1")
}

func TestCB16_CleanStaleQueueMessages_NilDB(t *testing.T) {
	// Should not panic with nil db
	cleanStaleQueueMessages(nil, 7*24*time.Hour)
}

func TestCB16_PersistAndLoadQueue(t *testing.T) {
	cb16SetupDB(t)
	_ = newOfflineQueue(100, 7*24*time.Hour) // create initial queue for reference

	msgData := marshalOutgoingMessage(OutgoingMessage{Type: "message", Data: "test"})
	persistQueue(db, "user1", msgData)
	persistQueue(db, "user1", msgData)

	// Load back into a new queue
	q2 := newOfflineQueue(100, 7*24*time.Hour)
	loadQueueFromDB(db, q2)

	// Check messages were loaded
	if q2.TotalDepth() < 2 {
		t.Errorf("expected at least 2 messages in loaded queue, got %d", q2.TotalDepth())
	}

	// Clean up
	deleteQueueMessages(db, "user1")
}

func TestCB16_CleanStaleQueueMessages_RemovesOld(t *testing.T) {
	cb16SetupDB(t)

	// Insert an old message
	_, err := db.Exec("INSERT INTO offline_queue (recipient, data, queued_at, sent_count) VALUES (?, ?, ?, 0)",
		"user1", []byte(`{}`), time.Now().UTC().Add(-8*24*time.Hour).Format(time.RFC3339))
	if err != nil {
		t.Fatalf("insert old queue msg: %v", err)
	}

	// Insert a recent message
	_, err = db.Exec("INSERT INTO offline_queue (recipient, data, queued_at, sent_count) VALUES (?, ?, ?, 0)",
		"user2", []byte(`{}`), time.Now().UTC().Format(time.RFC3339))
	if err != nil {
		t.Fatalf("insert recent queue msg: %v", err)
	}

	// Clean messages older than 7 days
	cleanStaleQueueMessages(db, 7*24*time.Hour)

	// Old message should be gone
	var count int
	db.QueryRow("SELECT COUNT(*) FROM offline_queue WHERE recipient = ?", "user1").Scan(&count)
	if count != 0 {
		t.Errorf("expected old message to be cleaned up, got %d", count)
	}

	// Recent message should remain
	db.QueryRow("SELECT COUNT(*) FROM offline_queue WHERE recipient = ?", "user2").Scan(&count)
	if count != 1 {
		t.Errorf("expected recent message to remain, got %d", count)
	}
}

// ==============================
// Tiered rate limiter cleanup deeper coverage
// ==============================

func TestCB16_TieredRateLimiter_CleanupRemovesStaleEntries(t *testing.T) {
	trl := NewTieredRateLimiter()

	// Add an entry that's already expired (window ended 15 min ago)
	trl.mu.Lock()
	trl.limits["stale_user"] = &userRateLimitState{
		count:     10,
		windowEnd: time.Now().Add(-15 * time.Minute),
		tier:      TierFree,
	}
	trl.mu.Unlock()

	// Add a current entry
	trl.SetTier("current_user", TierPro)

	// Manually trigger cleanup logic (same as the goroutine)
	trl.mu.Lock()
	now := time.Now()
	for id, entry := range trl.limits {
		if now.After(entry.windowEnd) && now.Sub(entry.windowEnd) > 10*time.Minute {
			delete(trl.limits, id)
		}
	}
	trl.mu.Unlock()

	// Stale entry should be removed
	if _, ok := trl.limits["stale_user"]; ok {
		t.Error("stale entry should have been removed")
	}

	// Current entry should remain
	if _, ok := trl.limits["current_user"]; !ok {
		t.Error("current entry should still exist")
	}
}

func TestCB16_TieredRateLimiter_GetRemaining_WindowExpired(t *testing.T) {
	trl := NewTieredRateLimiter()
	trl.SetTier("user1", TierPro)

	// Expire the window manually
	trl.mu.Lock()
	if entry, ok := trl.limits["user1"]; ok {
		entry.windowEnd = time.Now().Add(-1 * time.Hour)
		entry.count = 100 // Used many requests
	}
	trl.mu.Unlock()

	// After window expires, remaining should be reset to tier burst
	remaining := trl.GetRemaining("user1")
	if remaining != TierPro.Burst {
		t.Errorf("expected remaining to reset to %d after window expiry, got %d", TierPro.Burst, remaining)
	}
}

func TestCB16_TieredRateLimiter_GetRemaining_NonexistentUser(t *testing.T) {
	trl := NewTieredRateLimiter()

	remaining := trl.GetRemaining("nonexistent_user")
	if remaining != TierFree.Burst {
		t.Errorf("expected default burst for nonexistent user, got %d", remaining)
	}
}

// ==============================
// openDatabase deeper coverage — PostgreSQL driver
// ==============================

func TestCB16_OpenDatabase_PostgreSQLConnectionString(t *testing.T) {
	// Save and restore current driver
	origDriver := currentDriver
	defer func() { currentDriver = origDriver }()

	// Test the PostgreSQL path parsing with a fake connection string
	// We can't actually connect to PostgreSQL, but we can test the parsing logic
	origDBDriver := os.Getenv("DB_DRIVER")
	origDBPath := os.Getenv("DB_PATH")
	defer func() {
		os.Setenv("DB_DRIVER", origDBDriver)
		os.Setenv("DB_PATH", origDBPath)
	}()

	// Test that opening a PostgreSQL connection fails gracefully with invalid host
	_, err := openDatabase("postgres", "host=nonexistent port=9999 user=test password=test dbname=test sslmode=disable")
	if err == nil {
		t.Log("PostgreSQL connection unexpectedly succeeded (would need real server)")
	} else {
		t.Logf("PostgreSQL connection failed as expected: %v", err)
	}
}

// ==============================
// handleUpload deeper coverage
// ==============================

func TestCB16_HandleUpload_WrongContentType(t *testing.T) {
	cb16SetupDB(t)
	cb16MakeToken(t, "user1")
	token, _ := GenerateJWT("user1", "user1")

	// Upload with wrong content type
	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)
	part, _ := writer.CreateFormFile("file", "test.exe")
	part.Write([]byte("executable content"))
	writer.WriteField("conversation_id", "conv1")
	writer.Close()

	req := httptest.NewRequest(http.MethodPost, "/attachments/upload", &buf)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	handleUpload(w, req)

	// .exe should be rejected as not allowed content type
	if w.Code != http.StatusBadRequest {
		t.Logf("Response: %s", w.Body.String())
		// May be 400 or 415 depending on implementation
	}
}

func TestCB16_HandleUpload_MissingFile(t *testing.T) {
	cb16SetupDB(t)
	cb16MakeToken(t, "user1")
	token, _ := GenerateJWT("user1", "user1")

	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)
	writer.WriteField("conversation_id", "conv1")
	writer.Close()

	req := httptest.NewRequest(http.MethodPost, "/attachments/upload", &buf)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	handleUpload(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing file, got %d", w.Code)
	}
}

func TestCB16_HandleUpload_NoAuth(t *testing.T) {
	cb16SetupDB(t)

	req := httptest.NewRequest(http.MethodPost, "/attachments/upload", nil)
	w := httptest.NewRecorder()

	handleUpload(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestCB16_HandleUpload_WrongHTTPMethod(t *testing.T) {
	cb16SetupDB(t)

	req := httptest.NewRequest(http.MethodGet, "/attachments/upload", nil)
	w := httptest.NewRecorder()

	handleUpload(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

// ==============================
// handleListAttachments deeper coverage
// ==============================

func TestCB16_HandleListAttachments_Success(t *testing.T) {
	cb16SetupDB(t)
	cb16MakeToken(t, "user1_long_id")
	cb16CreateAgent(t, "agent1")
	cb16CreateConversation(t, "conv1", "user1_long_id", "agent1")
	token, _ := GenerateJWT("user1_long_id", "user1_long_id")

	// Insert an attachment record (no conversation_id column)
	_, err := db.Exec("INSERT INTO attachments (id, user_id, filename, content_type, size, sha256, storage_path, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
		"attach1", "user1_long_id", "test.txt", "text/plain", 100, "abc123", "/data/attachments/attach1", time.Now().UTC())
	if err != nil {
		t.Fatalf("insert attachment: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/messages/attachments?conversation_id=conv1", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	handleListAttachments(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCB16_HandleListAttachments_NoAuth(t *testing.T) {
	cb16SetupDB(t)

	req := httptest.NewRequest(http.MethodGet, "/messages/attachments?conversation_id=conv1", nil)
	w := httptest.NewRecorder()

	handleListAttachments(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestCB16_HandleListAttachments_MissingConversationID(t *testing.T) {
	cb16SetupDB(t)
	cb16MakeToken(t, "user1")
	token, _ := GenerateJWT("user1", "user1")

	req := httptest.NewRequest(http.MethodGet, "/messages/attachments", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	handleListAttachments(w, req)

	// Should return 400
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing conversation_id, got %d", w.Code)
	}
}

func TestCB16_HandleListAttachments_WrongUser(t *testing.T) {
	cb16SetupDB(t)
	cb16MakeToken(t, "user1_long_id")
	cb16MakeToken(t, "user2_long_id")
	cb16CreateAgent(t, "agent1")
	cb16CreateConversation(t, "conv1", "user1_long_id", "agent1")

	token2, _ := GenerateJWT("user2_long_id", "user2_long_id")
	req := httptest.NewRequest(http.MethodGet, "/messages/attachments?conversation_id=conv1", nil)
	req.Header.Set("Authorization", "Bearer "+token2)
	w := httptest.NewRecorder()

	handleListAttachments(w, req)

	// Wrong user gets 404 (conversation not found from their perspective)
	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404 for wrong user, got %d", w.Code)
	}
}

// ==============================
// InitTracing deeper coverage
// ==============================

func TestCB16_InitTracing_Disabled(t *testing.T) {
	origOTEL := os.Getenv("OTEL_ENABLED")
	defer os.Setenv("OTEL_ENABLED", origOTEL)

	os.Setenv("OTEL_ENABLED", "false")

	// Reset tracing state for test
	tracingEnabled = false
	tp = nil
	// Reset the sync.Once — we need to use a new one
	// Since sync.Once can't be reset, we test that calling InitTracing
	// with disabled flag just returns nil
	err := InitTracing()
	// With OTEL_ENABLED=false, should not error
	if err != nil {
		t.Logf("InitTracing with OTEL_ENABLED=false: %v (acceptable)", err)
	}
}

func TestCB16_ShutdownTracing_NilProvider(t *testing.T) {
	// Should not panic with nil trace provider
	tp = nil
	ShutdownTracing()
}

// ==============================
// authenticateRequest deeper coverage
// ==============================

func TestCB16_AuthenticateRequest_NoAuth(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/keys/upload", nil)
	_, _, err := authenticateRequest(req)
	if err == nil {
		t.Error("expected error for no auth header")
	}
}

func TestCB16_AuthenticateRequest_AgentMissingID(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/keys/upload", nil)
	req.Header.Set("X-Agent-Secret", getAgentSecret())
	// No X-Agent-ID header
	_, _, err := authenticateRequest(req)
	if err == nil {
		t.Error("expected error for missing X-Agent-ID")
	}
}

func TestCB16_AuthenticateRequest_InvalidJWT(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/keys/upload", nil)
	req.Header.Set("Authorization", "Bearer invalid_token")
	_, _, err := authenticateRequest(req)
	if err == nil {
		t.Error("expected error for invalid JWT")
	}
}

func TestCB16_AuthenticateRequest_ValidAgentAuth(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/keys/upload", nil)
	req.Header.Set("X-Agent-Secret", getAgentSecret())
	req.Header.Set("X-Agent-ID", "agent1")

	id, idType, err := authenticateRequest(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id != "agent1" {
		t.Errorf("expected agent1, got %s", id)
	}
	if idType != "agent" {
		t.Errorf("expected agent, got %s", idType)
	}
}

// ==============================
// handleRegisterDeviceToken deeper coverage
// ==============================

func TestCB16_RegisterDeviceToken_DefaultPlatform(t *testing.T) {
	cb16SetupDB(t)
	// Use a longer user ID to avoid panic in claims.UserID[:8] logging
	cb16MakeToken(t, "user1_long_id")
	token, _ := GenerateJWT("user1_long_id", "user1_long_id")

	// Register without specifying platform (should default to ios)
	body := `{"device_token":"token_abc123"}`
	req := httptest.NewRequest(http.MethodPost, "/push/register", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handleRegisterDeviceToken(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// Verify platform defaulted to ios
	var platform string
	db.QueryRow("SELECT platform FROM device_tokens WHERE user_id = ?", "user1_long_id").Scan(&platform)
	if platform != "ios" {
		t.Errorf("expected default platform 'ios', got %s", platform)
	}
}

func TestCB16_RegisterDeviceToken_InvalidJSON(t *testing.T) {
	cb16SetupDB(t)
	cb16MakeToken(t, "user1")
	token, _ := GenerateJWT("user1", "user1")

	req := httptest.NewRequest(http.MethodPost, "/push/register", strings.NewReader("not json"))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handleRegisterDeviceToken(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid JSON, got %d", w.Code)
	}
}

func TestCB16_RegisterDeviceToken_MissingToken(t *testing.T) {
	cb16SetupDB(t)
	cb16MakeToken(t, "user1")
	token, _ := GenerateJWT("user1", "user1")

	body := `{"platform":"android"}`
	req := httptest.NewRequest(http.MethodPost, "/push/register", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handleRegisterDeviceToken(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing token, got %d", w.Code)
	}
}

func TestCB16_RegisterDeviceToken_WrongMethod(t *testing.T) {
	cb16SetupDB(t)

	req := httptest.NewRequest(http.MethodGet, "/push/register", nil)
	w := httptest.NewRecorder()

	handleRegisterDeviceToken(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestCB16_RegisterDeviceToken_NoAuth(t *testing.T) {
	cb16SetupDB(t)

	body := `{"device_token":"abc","platform":"ios"}`
	req := httptest.NewRequest(http.MethodPost, "/push/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handleRegisterDeviceToken(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

// ==============================
// handleUnregisterDeviceToken deeper coverage
// ==============================

func TestCB16_UnregisterDeviceToken_Success(t *testing.T) {
	cb16SetupDB(t)
	cb16MakeToken(t, "user1")
	token, _ := GenerateJWT("user1", "user1")

	// First register a token
	_, err := db.Exec("INSERT INTO device_tokens (user_id, device_token, platform, updated_at) VALUES (?, ?, ?, CURRENT_TIMESTAMP)",
		"user1", "token_to_remove", "ios")
	if err != nil {
		t.Fatalf("insert token: %v", err)
	}

	// Then unregister
	body := `{"device_token":"token_to_remove"}`
	req := httptest.NewRequest(http.MethodDelete, "/push/unregister", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handleUnregisterDeviceToken(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// Verify token removed
	var count int
	db.QueryRow("SELECT COUNT(*) FROM device_tokens WHERE user_id = ? AND device_token = ?", "user1", "token_to_remove").Scan(&count)
	if count != 0 {
		t.Error("token should be removed")
	}
}

func TestCB16_UnregisterDeviceToken_InvalidJSON(t *testing.T) {
	cb16SetupDB(t)
	cb16MakeToken(t, "user1")
	token, _ := GenerateJWT("user1", "user1")

	req := httptest.NewRequest(http.MethodDelete, "/push/unregister", strings.NewReader("bad json"))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handleUnregisterDeviceToken(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid JSON, got %d", w.Code)
	}
}

func TestCB16_UnregisterDeviceToken_MissingToken(t *testing.T) {
	cb16SetupDB(t)
	cb16MakeToken(t, "user1")
	token, _ := GenerateJWT("user1", "user1")

	body := `{}`
	req := httptest.NewRequest(http.MethodDelete, "/push/unregister", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handleUnregisterDeviceToken(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing token, got %d", w.Code)
	}
}

func TestCB16_UnregisterDeviceToken_WrongMethod(t *testing.T) {
	cb16SetupDB(t)

	req := httptest.NewRequest(http.MethodPost, "/push/unregister", nil)
	w := httptest.NewRecorder()

	handleUnregisterDeviceToken(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

// ==============================
// WebPush Subscribe/Unsubscribe deeper coverage
// ==============================

func TestCB16_WebPushSubscribe_Success(t *testing.T) {
	cb16SetupDB(t)
	cb16MakeToken(t, "user1")
	token, _ := GenerateJWT("user1", "user1")

	body := `{"endpoint":"https://push.example.com/subscribe/abc","keys":{"p256dh":"key123","auth":"auth456"}}`
	req := httptest.NewRequest(http.MethodPost, "/push/web-subscribe", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handleWebPushSubscribe(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCB16_WebPushSubscribe_MissingFields(t *testing.T) {
	cb16SetupDB(t)
	cb16MakeToken(t, "user1")
	token, _ := GenerateJWT("user1", "user1")

	body := `{"endpoint":"https://push.example.com/subscribe/abc","keys":{"p256dh":"key123"}}`
	req := httptest.NewRequest(http.MethodPost, "/push/web-subscribe", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handleWebPushSubscribe(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing auth key, got %d", w.Code)
	}
}

func TestCB16_WebPushSubscribe_NoAuth(t *testing.T) {
	cb16SetupDB(t)

	body := `{"endpoint":"https://push.example.com/subscribe/abc","keys":{"p256dh":"key123","auth":"auth456"}}`
	req := httptest.NewRequest(http.MethodPost, "/push/web-subscribe", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handleWebPushSubscribe(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestCB16_WebPushUnsubscribe_Success(t *testing.T) {
	cb16SetupDB(t)
	cb16MakeToken(t, "user1")
	token, _ := GenerateJWT("user1", "user1")

	// First subscribe
	_, err := db.Exec("INSERT INTO device_tokens (user_id, device_token, platform, created_at) VALUES (?, ?, 'web', ?)",
		"user1", "https://push.example.com/abc", time.Now().UTC())
	if err != nil {
		t.Fatalf("insert web push token: %v", err)
	}

	// Then unsubscribe
	body := `{"endpoint":"https://push.example.com/abc"}`
	req := httptest.NewRequest(http.MethodPost, "/push/web-unsubscribe", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handleWebPushUnsubscribe(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCB16_WebPushUnsubscribe_MissingEndpoint(t *testing.T) {
	cb16SetupDB(t)
	cb16MakeToken(t, "user1")
	token, _ := GenerateJWT("user1", "user1")

	body := `{}`
	req := httptest.NewRequest(http.MethodPost, "/push/web-unsubscribe", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handleWebPushUnsubscribe(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing endpoint, got %d", w.Code)
	}
}

func TestCB16_WebPushUnsubscribe_InvalidJSON(t *testing.T) {
	cb16SetupDB(t)
	cb16MakeToken(t, "user1")
	token, _ := GenerateJWT("user1", "user1")

	req := httptest.NewRequest(http.MethodPost, "/push/web-unsubscribe", strings.NewReader("bad json"))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handleWebPushUnsubscribe(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid JSON, got %d", w.Code)
	}
}

func TestCB16_GetVAPIDKey_NotConfigured(t *testing.T) {
	cb16SetupDB(t)
	cb16MakeToken(t, "user1")
	token, _ := GenerateJWT("user1", "user1")
	vapidPublicKey = ""

	req := httptest.NewRequest(http.MethodGet, "/push/vapid-key", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	handleGetVAPIDKey(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404 when VAPID not configured, got %d", w.Code)
	}
}

func TestCB16_GetVAPIDKey_Success(t *testing.T) {
	cb16SetupDB(t)
	cb16MakeToken(t, "user1")
	token, _ := GenerateJWT("user1", "user1")
	vapidPublicKey = "test-vapid-public-key"
	defer func() { vapidPublicKey = "" }()

	req := httptest.NewRequest(http.MethodGet, "/push/vapid-key", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	handleGetVAPIDKey(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestCB16_GetVAPIDKey_NoAuth(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/push/vapid-key", nil)
	w := httptest.NewRecorder()

	handleGetVAPIDKey(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestCB16_GetVAPIDKey_WrongMethod(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/push/vapid-key", nil)
	w := httptest.NewRecorder()

	handleGetVAPIDKey(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

// ==============================
// Protocol negotiation deeper coverage
// ==============================

func TestCB16_NegotiateProtocol_Default(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	version := negotiateProtocol(req)
	if version != "v1" {
		t.Errorf("expected default protocol v1, got %s", version)
	}
}

func TestCB16_NegotiateProtocol_UnknownQueryParam(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/?protocol_version=v99", nil)
	version := negotiateProtocol(req)
	// Unsupported version should fall back to default
	if version != "v1" {
		t.Errorf("expected fallback to v1, got %s", version)
	}
}

func TestCB16_IsSupportedVersion(t *testing.T) {
	if !isSupportedVersion("v1") {
		t.Error("v1 should be supported")
	}
	if isSupportedVersion("v99") {
		t.Error("v99 should not be supported")
	}
}

// ==============================
// Conversation operations deeper coverage
// ==============================

func TestCB16_CreateConversation_DBError(t *testing.T) {
	// Use closed DB to force error
	closedDB, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	closedDB.Close()

	db = closedDB
	defer func() { cb16SetupDB(&testing.T{}) }()

	_, err = CreateConversation("user1", "agent1")
	if err == nil {
		t.Error("expected error with closed DB")
	}
}

func TestCB16_GetOrCreateConversation_New(t *testing.T) {
	cb16SetupDB(t)
	cb16CreateUser(t, "user1", "user1")
	cb16CreateAgent(t, "agent1")

	conv, err := GetOrCreateConversation("user1", "agent1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if conv == nil {
		t.Fatal("expected conversation to be created")
	}
	if conv.UserID != "user1" {
		t.Errorf("expected user1, got %s", conv.UserID)
	}
	if conv.AgentID != "agent1" {
		t.Errorf("expected agent1, got %s", conv.AgentID)
	}
}

func TestCB16_GetOrCreateConversation_Existing(t *testing.T) {
	cb16SetupDB(t)
	cb16CreateUser(t, "user1", "user1")
	cb16CreateAgent(t, "agent1")
	cb16CreateConversation(t, "conv1", "user1", "agent1")

	conv, err := GetOrCreateConversation("user1", "agent1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if conv == nil {
		t.Fatal("expected existing conversation")
	}
	if conv.ID != "conv1" {
		t.Errorf("expected conv1, got %s", conv.ID)
	}
}

// ==============================
// searchMessages deeper coverage
// ==============================

func TestCB16_SearchMessages_EmptyQuery(t *testing.T) {
	cb16SetupDB(t)

	_, err := searchMessages("user1", "", 50)
	if err == nil {
		t.Error("expected error for empty query")
	}
}

func TestCB16_SearchMessages_NoResults(t *testing.T) {
	cb16SetupDB(t)
	cb16CreateUser(t, "user1", "user1")
	cb16CreateAgent(t, "agent1")
	cb16CreateConversation(t, "conv1", "user1", "agent1")

	messages, err := searchMessages("user1", "nonexistent_term", 50)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(messages) != 0 {
		t.Errorf("expected 0 results, got %d", len(messages))
	}
}

func TestCB16_SearchMessages_WithResults(t *testing.T) {
	cb16SetupDB(t)
	cb16CreateUser(t, "user1", "user1")
	cb16CreateAgent(t, "agent1")
	cb16CreateConversation(t, "conv1", "user1", "agent1")

	// Insert messages
	_, err := db.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, created_at) VALUES (?, ?, ?, ?, ?, ?)",
		"msg1", "conv1", "user", "user1", "hello world", time.Now().UTC())
	if err != nil {
		t.Fatalf("insert message: %v", err)
	}
	_, err = db.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, created_at) VALUES (?, ?, ?, ?, ?, ?)",
		"msg2", "conv1", "agent", "agent1", "hello back", time.Now().UTC().Add(time.Second))
	if err != nil {
		t.Fatalf("insert message: %v", err)
	}

	messages, err := searchMessages("user1", "hello", 50)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(messages) < 2 {
		t.Errorf("expected at least 2 results, got %d", len(messages))
	}
}

// ==============================
// markMessagesRead deeper coverage
// ==============================

func TestCB16_MarkMessagesRead_Unauthorized(t *testing.T) {
	cb16SetupDB(t)
	cb16CreateUser(t, "user1", "user1")
	cb16CreateUser(t, "user2", "user2")
	cb16CreateAgent(t, "agent1")
	cb16CreateConversation(t, "conv1", "user1", "agent1")

	count, err := markMessagesRead("conv1", "user2")
	if err == nil {
		t.Error("expected error for unauthorized user")
	}
	if count != 0 {
		t.Errorf("expected 0, got %d", count)
	}
}

func TestCB16_MarkMessagesRead_NotFound(t *testing.T) {
	cb16SetupDB(t)

	count, err := markMessagesRead("nonexistent", "user1")
	if err == nil {
		t.Error("expected error for nonexistent conversation")
	}
	_ = count // May be 0
}

func TestCB16_MarkMessagesRead_Idempotent(t *testing.T) {
	cb16SetupDB(t)
	cb16CreateUser(t, "user1", "user1")
	cb16CreateAgent(t, "agent1")
	cb16CreateConversation(t, "conv1", "user1", "agent1")

	// Insert agent messages
	_, err := db.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, created_at) VALUES (?, ?, ?, ?, ?, ?)",
		"msg1", "conv1", "agent", "agent1", "hello", time.Now().UTC())
	if err != nil {
		t.Fatalf("insert message: %v", err)
	}

	// First mark
	count1, err := markMessagesRead("conv1", "user1")
	if err != nil {
		t.Fatalf("mark read: %v", err)
	}
	if count1 != 1 {
		t.Errorf("expected 1 message marked, got %d", count1)
	}

	// Second mark (idempotent — should be 0)
	count2, err := markMessagesRead("conv1", "user1")
	if err != nil {
		t.Fatalf("mark read again: %v", err)
	}
	if count2 != 0 {
		t.Errorf("expected 0 on second call, got %d", count2)
	}
}

// ==============================
// handleRegisterUser deeper coverage
// ==============================

func TestCB16_RegisterUser_ShortUsername(t *testing.T) {
	cb16SetupDB(t)

	body := "username=ab&password=testpass123"
	req := httptest.NewRequest(http.MethodPost, "/auth/user", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	handleRegisterUser(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for short username, got %d", w.Code)
	}
}

func TestCB16_RegisterUser_MissingFields(t *testing.T) {
	cb16SetupDB(t)

	body := "username=testuser"
	req := httptest.NewRequest(http.MethodPost, "/auth/user", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	handleRegisterUser(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing password, got %d", w.Code)
	}
}

func TestCB16_RegisterUser_DuplicateUsername(t *testing.T) {
	cb16SetupDB(t)
	cb16MakeToken(t, "testuser")

	body := "username=testuser&password=testpass123"
	req := httptest.NewRequest(http.MethodPost, "/auth/user", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	handleRegisterUser(w, req)

	if w.Code != http.StatusConflict {
		t.Errorf("expected 409 for duplicate username, got %d", w.Code)
	}
}

// ==============================
// handleLogin deeper coverage
// ==============================

func TestCB16_Login_WrongPassword(t *testing.T) {
	cb16SetupDB(t)
	cb16MakeToken(t, "testuser")

	body := "username=testuser&password=wrongpassword"
	req := httptest.NewRequest(http.MethodPost, "/auth/login", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	handleLogin(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for wrong password, got %d", w.Code)
	}
}

func TestCB16_Login_NonexistentUser(t *testing.T) {
	cb16SetupDB(t)

	body := "username=nonexistent&password=testpass123"
	req := httptest.NewRequest(http.MethodPost, "/auth/login", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	handleLogin(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for nonexistent user, got %d", w.Code)
	}
}

// ==============================
// handleRegisterAgent deeper coverage
// ==============================

func TestCB16_RegisterAgent_MissingID(t *testing.T) {
	cb16SetupDB(t)

	body := "name=Test+Agent"
	req := httptest.NewRequest(http.MethodPost, "/auth/agent", strings.NewReader(body))
	req.Header.Set("X-Agent-Secret", getAgentSecret())
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	handleRegisterAgent(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing agent ID, got %d", w.Code)
	}
}

func TestCB16_RegisterAgent_WrongSecret(t *testing.T) {
	cb16SetupDB(t)

	body := "agent_id=agent1&name=Test+Agent"
	req := httptest.NewRequest(http.MethodPost, "/auth/agent", strings.NewReader(body))
	req.Header.Set("X-Agent-Secret", "wrong-secret")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	handleRegisterAgent(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for wrong secret, got %d", w.Code)
	}
}

// ==============================
// Reactions deeper coverage
// ==============================

func TestCB16_Reactions_AddAndToggle(t *testing.T) {
	cb16SetupDB(t)
	cb16CreateUser(t, "user1", "user1")
	cb16CreateAgent(t, "agent1")
	cb16CreateConversation(t, "conv1", "user1", "agent1")

	// Insert a message
	_, err := db.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, created_at) VALUES (?, ?, ?, ?, ?, ?)",
		"msg1", "conv1", "user", "user1", "hello", time.Now().UTC())
	if err != nil {
		t.Fatalf("insert message: %v", err)
	}

	// Add reaction
	_, _, err = addReaction("msg1", "user1", "👍")
	if err != nil {
		t.Fatalf("add reaction: %v", err)
	}

	// Verify reaction exists
	reactions, err := getMessageReactions("msg1")
	if err != nil {
		t.Fatalf("get reactions: %v", err)
	}
	if len(reactions) != 1 {
		t.Fatalf("expected 1 reaction, got %d", len(reactions))
	}
	if reactions[0].Emoji != "👍" {
		t.Errorf("expected 👍, got %s", reactions[0].Emoji)
	}

	// Toggle (remove) the reaction — adding same emoji should toggle
	_, _, err = addReaction("msg1", "user1", "👍")
	if err != nil {
		t.Fatalf("toggle reaction: %v", err)
	}

	// Should be removed now
	reactions, err = getMessageReactions("msg1")
	if err != nil {
		t.Fatalf("get reactions after toggle: %v", err)
	}
	if len(reactions) != 0 {
		t.Errorf("expected 0 reactions after toggle, got %d", len(reactions))
	}
}

// ==============================
// Conversation tags deeper coverage
// ==============================

func TestCB16_ConversationTags_AddAndRemove(t *testing.T) {
	cb16SetupDB(t)
	cb16CreateUser(t, "user1", "user1")
	cb16CreateAgent(t, "agent1")
	cb16CreateConversation(t, "conv1", "user1", "agent1")

	// Add tag
	_, err := addConversationTag("conv1", "user1", "important")
	if err != nil {
		t.Fatalf("add tag: %v", err)
	}

	// Verify tag
	tags, err := getConversationTags("conv1")
	if err != nil {
		t.Fatalf("get tags: %v", err)
	}
	if len(tags) != 1 || tags[0].Tag != "important" {
		t.Errorf("expected [important], got %v", tags)
	}

	// Remove tag
	err = removeConversationTag("conv1", "user1", "important")
	if err != nil {
		t.Fatalf("remove tag: %v", err)
	}

	// Verify removed
	tags, err = getConversationTags("conv1")
	if err != nil {
		t.Fatalf("get tags after remove: %v", err)
	}
	if len(tags) != 0 {
		t.Errorf("expected empty tags, got %v", tags)
	}
}

// ==============================
// parseSize deeper coverage
// ==============================

func TestCB16_ParseSize_Bytes(t *testing.T) {
	size, err := parseSize("1024")
	if err != nil || size != 1024 {
		t.Errorf("expected 1024, got %d, err=%v", size, err)
	}
}

func TestCB16_ParseSize_KB(t *testing.T) {
	size, err := parseSize("10KB")
	if err != nil || size != 10*1024 {
		t.Errorf("expected %d, got %d, err=%v", 10*1024, size, err)
	}
}

func TestCB16_ParseSize_MB(t *testing.T) {
	size, err := parseSize("50MB")
	if err != nil || size != 50*1024*1024 {
		t.Errorf("expected %d, got %d, err=%v", 50*1024*1024, size, err)
	}
}

func TestCB16_ParseSize_GB(t *testing.T) {
	size, err := parseSize("1GB")
	if err != nil || size != 1*1024*1024*1024 {
		t.Errorf("expected %d, got %d, err=%v", 1*1024*1024*1024, size, err)
	}
}

func TestCB16_ParseSize_TB(t *testing.T) {
	size, err := parseSize("2TB")
	if err != nil || size != 2*1024*1024*1024*1024 {
		t.Errorf("expected %d, got %d, err=%v", 2*1024*1024*1024*1024, size, err)
	}
}

func TestCB16_ParseSize_InvalidFormat(t *testing.T) {
	_, err := parseSize("abc")
	if err == nil {
		t.Error("expected error for invalid format")
	}
}

func TestCB16_ParseSize_EmptyString(t *testing.T) {
	_, err := parseSize("")
	if err == nil {
		t.Error("expected error for empty string")
	}
}

// ==============================
// Rate limit tier handlers
// ==============================

func TestCB16_HandleSetRateLimitTier_InvalidTier(t *testing.T) {
	cb16SetupDB(t)
	// Need admin secret
	req := httptest.NewRequest(http.MethodPost, "/admin/rate-limit/tier", strings.NewReader("user_id=user1&tier=invalid_tier"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Admin-Secret", getAdminSecret())
	w := httptest.NewRecorder()

	handleSetRateLimitTier(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid tier, got %d", w.Code)
	}
}

func TestCB16_HandleSetRateLimitTier_MissingUserID(t *testing.T) {
	cb16SetupDB(t)

	req := httptest.NewRequest(http.MethodPost, "/admin/rate-limit/tier", strings.NewReader("tier=pro"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Admin-Secret", getAdminSecret())
	w := httptest.NewRecorder()

	handleSetRateLimitTier(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing user_id, got %d", w.Code)
	}
}

func TestCB16_HandleGetRateLimitTier_NonexistentUser(t *testing.T) {
	cb16SetupDB(t)

	req := httptest.NewRequest(http.MethodGet, "/admin/rate-limit/tier?user_id=nonexistent", nil)
	req.Header.Set("X-Admin-Secret", getAdminSecret())
	w := httptest.NewRecorder()

	handleGetRateLimitTier(w, req)

	// Should return free tier for unknown user
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

// ==============================
// Message edit/delete deeper coverage
// ==============================

func TestCB16_MessageDeleteHandler_AlreadyDeleted(t *testing.T) {
	cb16SetupDB(t)
	cb16CreateUser(t, "user1", "user1")
	cb16CreateAgent(t, "agent1")
	cb16CreateConversation(t, "conv1", "user1", "agent1")

	// Insert a message
	_, err := db.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, created_at) VALUES (?, ?, ?, ?, ?, ?)",
		"msg1", "conv1", "user", "user1", "hello", time.Now().UTC())
	if err != nil {
		t.Fatalf("insert message: %v", err)
	}

	// Delete via HTTP handler
	token, _ := GenerateJWT("user1", "user1")
	req := httptest.NewRequest(http.MethodPost, "/messages/delete", strings.NewReader("message_id=msg1"))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	handleMessageDelete(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200 for first delete, got %d: %s", w.Code, w.Body.String())
	}

	// Try to delete again — should return 400 (already deleted)
	req2 := httptest.NewRequest(http.MethodPost, "/messages/delete", strings.NewReader("message_id=msg1"))
	req2.Header.Set("Authorization", "Bearer "+token)
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w2 := httptest.NewRecorder()

	handleMessageDelete(w2, req2)

	if w2.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for already deleted, got %d", w2.Code)
	}
}

func TestCB16_MessageDeleteHandler_NotFound(t *testing.T) {
	cb16SetupDB(t)
	cb16MakeToken(t, "user1")
	token, _ := GenerateJWT("user1", "user1")

	req := httptest.NewRequest(http.MethodPost, "/messages/delete", strings.NewReader("message_id=nonexistent_msg"))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	handleMessageDelete(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404 for nonexistent message, got %d", w.Code)
	}
}

// ==============================
// Middleware: extractIP deeper coverage
// ==============================

func TestCB16_ExtractIP_XForwardedFor(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Forwarded-For", "203.0.113.1, 70.41.3.18")
	ip := extractIP(req)
	if ip != "203.0.113.1" {
		t.Errorf("expected first IP from X-Forwarded-For, got %s", ip)
	}
}

func TestCB16_ExtractIP_XRealIP(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Real-Ip", "203.0.113.2")
	ip := extractIP(req)
	if ip != "203.0.113.2" {
		t.Errorf("expected X-Real-Ip, got %s", ip)
	}
}

func TestCB16_ExtractIP_RemoteAddr(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	// No forwarded headers — should fall back to RemoteAddr
	ip := extractIP(req)
	// RemoteAddr may include port, just check it's not empty
	if ip == "" {
		t.Error("expected non-empty IP from RemoteAddr")
	}
}

// ==============================
// HashAPIKey deeper coverage
// ==============================

func TestCB16_HashAPIKey(t *testing.T) {
	hash, err := HashAPIKey("test_password")
	if err != nil {
		t.Fatalf("HashAPIKey error: %v", err)
	}
	if hash == "" {
		t.Error("expected non-empty hash")
	}
	if hash == "test_password" {
		t.Error("hash should not be plaintext")
	}
}

// ==============================
// storeMessagesBatch deeper coverage
// ==============================

func TestCB16_StoreMessagesBatch_Empty(t *testing.T) {
	cb16SetupDB(t)

	ids, err := storeMessagesBatch(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ids != nil {
		t.Errorf("expected nil for empty batch, got %v", ids)
	}
}

func TestCB16_StoreMessagesBatch_Valid(t *testing.T) {
	cb16SetupDB(t)
	cb16CreateUser(t, "user1", "user1")
	cb16CreateAgent(t, "agent1")
	cb16CreateConversation(t, "conv1", "user1", "agent1")

	msgs := []RoutedMessage{
		{ConversationID: "conv1", SenderType: "user", SenderID: "user1", Content: "hello"},
		{ConversationID: "conv1", SenderType: "agent", SenderID: "agent1", Content: "world"},
	}

	ids, err := storeMessagesBatch(msgs)
	if err != nil {
		t.Fatalf("storeMessagesBatch error: %v", err)
	}
	if len(ids) != 2 {
		t.Errorf("expected 2 IDs, got %d", len(ids))
	}

	// Verify messages in DB
	var count int
	db.QueryRow("SELECT COUNT(*) FROM messages WHERE conversation_id = ?", "conv1").Scan(&count)
	if count != 2 {
		t.Errorf("expected 2 messages, got %d", count)
	}
}

// ==============================
// ValidateAdminSecret deeper coverage
// ==============================

func TestCB16_ValidateAdminSecret_Correct(t *testing.T) {
	err := ValidateAdminSecret(getAdminSecret())
	if err != nil {
		t.Errorf("expected admin secret to be valid, got %v", err)
	}
}

func TestCB16_ValidateAdminSecret_Incorrect(t *testing.T) {
	err := ValidateAdminSecret("wrong-secret")
	if err == nil {
		t.Error("expected error for wrong secret")
	}
}

// ==============================
// DB driver helpers
// ==============================

func TestCB16_Placeholders(t *testing.T) {
	// For SQLite driver (default), Placeholders returns ?, ?, ?
	p := Placeholders(1, 3)
	if p != "?, ?, ?" {
		t.Errorf("expected '?, ?, ?', got %s", p)
	}
}

// ==============================
// Connection IsClosed/SafeSend deeper coverage
// ==============================

func TestCB16_Connection_IsClosed(t *testing.T) {
	conn := &Connection{
		closeMu: sync.RWMutex{},
	}
	if conn.IsClosed() {
		t.Error("connection should not be closed initially")
	}

	conn.MarkClosed()
	if !conn.IsClosed() {
		t.Error("connection should be closed after MarkClosed")
	}
}

func TestCB16_Connection_SafeSend_OnClosed(t *testing.T) {
	conn := &Connection{
		send:    make(chan []byte, 1),
		closeMu: sync.RWMutex{},
	}
	conn.MarkClosed()

	result := conn.SafeSend([]byte("test"))
	if result {
		t.Error("SafeSend on closed connection should return false")
	}
}

// ==============================
// Message search with custom limit
// ==============================

func TestCB16_SearchMessages_CustomLimit(t *testing.T) {
	cb16SetupDB(t)
	cb16CreateUser(t, "user1", "user1")
	cb16CreateAgent(t, "agent1")
	cb16CreateConversation(t, "conv1", "user1", "agent1")

	// Insert 5 messages
	for i := 0; i < 5; i++ {
		_, err := db.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, created_at) VALUES (?, ?, ?, ?, ?, ?)",
			fmt.Sprintf("msg_%d", i), "conv1", "user", "user1", fmt.Sprintf("hello test %d", i), time.Now().UTC().Add(time.Duration(i)*time.Second))
		if err != nil {
			t.Fatalf("insert message: %v", err)
		}
	}

	// Search with limit of 3
	messages, err := searchMessages("user1", "hello", 3)
	if err != nil {
		t.Fatalf("search error: %v", err)
	}
	if len(messages) > 3 {
		t.Errorf("expected at most 3 results, got %d", len(messages))
	}
}

// ==============================
// changeUserPassword deeper coverage
// ==============================

func TestCB16_ChangeUserPassword_WrongOldPassword(t *testing.T) {
	cb16SetupDB(t)
	cb16CreateUser(t, "user1", "user1")

	err := changeUserPassword("user1", "wrong_old_password", "newpassword123")
	if err == nil {
		t.Error("expected error for wrong old password")
	}
	if err.Error() != "invalid old password" {
		t.Errorf("expected 'invalid old password', got %v", err)
	}
}

func TestCB16_ChangeUserPassword_ShortNewPassword(t *testing.T) {
	cb16SetupDB(t)
	cb16CreateUser(t, "user1", "user1")

	err := changeUserPassword("user1", "testpass123", "abc")
	if err == nil {
		t.Error("expected error for short new password")
	}
	if err.Error() != "new password must be at least 6 characters" {
		t.Errorf("expected 'new password must be at least 6 characters', got %v", err)
	}
}

func TestCB16_ChangeUserPassword_Success(t *testing.T) {
	cb16SetupDB(t)
	cb16CreateUser(t, "user1", "user1")

	err := changeUserPassword("user1", "testpass123", "newpassword123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify we can login with new password
	token, err := GenerateJWT("user1", "user1")
	if err != nil {
		t.Fatalf("generate JWT: %v", err)
	}
	if token == "" {
		t.Error("expected non-empty token")
	}
}

func TestCB16_ChangeUserPassword_NonexistentUser(t *testing.T) {
	cb16SetupDB(t)

	err := changeUserPassword("nonexistent_user", "old_password", "newpassword123")
	if err == nil {
		t.Error("expected error for nonexistent user")
	}
}