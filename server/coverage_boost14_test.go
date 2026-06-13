package main

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// ==============================
// Helper functions for CB14
// ==============================

func cb14SetupDB(t *testing.T) {
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

func cb14MakeToken(t *testing.T, username string) string {
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

func cb14CreateConv(t *testing.T, username, agentID string) (string, string) {
	t.Helper()
	token := cb14MakeToken(t, username)
	_, err := db.Exec("INSERT OR IGNORE INTO agents (id, name) VALUES (?, ?)", agentID, agentID)
	if err != nil {
		t.Fatalf("insert agent: %v", err)
	}
	conv, err := GetOrCreateConversation(username, agentID)
	if err != nil {
		t.Fatalf("create conversation: %v", err)
	}
	return token, conv.ID
}

func cb14CreateAgent(t *testing.T, agentID string) {
	t.Helper()
	_, err := db.Exec("INSERT OR IGNORE INTO agents (id, name) VALUES (?, ?)", agentID, agentID)
	if err != nil {
		t.Fatalf("insert agent: %v", err)
	}
}

func cb14SetupHub(t *testing.T) {
	t.Helper()
	origPresence := agentPresenceEnabled
	agentPresenceEnabled = false
	t.Cleanup(func() { agentPresenceEnabled = origPresence })

	messageRateLimiter = NewRateLimiter(60, time.Minute)
	userRateLimiter = NewRateLimiter(120, time.Minute)
	globalTieredLimiter = NewTieredRateLimiter()
	ipRateLimiter = NewRateLimiter(300, time.Minute)
	authIPLimiter = NewRateLimiter(30, time.Minute)
	agentRateLimiter.Reset()

	hub = newHub()
	go hub.run()
	t.Cleanup(func() { hub.Stop() })
	ServerMetrics = NewMetrics(hub)
}

// ==============================
// sendAPNSNotification / sendFCMNotification coverage
// ==============================

func TestCB14_SendAPNSNotification_NilConfig(t *testing.T) {
	pushConfig = nil
	defer func() { pushConfig = nil }()

	err := sendAPNSNotification("token123", "Title", "Body", "conv1")
	if err != nil {
		t.Errorf("expected nil error for nil config, got %v", err)
	}
}

func TestCB14_SendAPNSNotification_Disabled(t *testing.T) {
	pushConfig = &PushNotificationConfig{APNSEnabled: false}
	defer func() { pushConfig = nil }()

	err := sendAPNSNotification("token123", "Title", "Body", "conv1")
	if err != nil {
		t.Errorf("expected nil error for disabled APNs, got %v", err)
	}
}

func TestCB14_SendAPNSNotification_NilClient(t *testing.T) {
	pushConfig = &PushNotificationConfig{APNSEnabled: true, apnsClient: nil}
	defer func() { pushConfig = nil }()

	err := sendAPNSNotification("token123", "Title", "Body", "conv1")
	if err != nil {
		t.Errorf("expected nil error for nil client, got %v", err)
	}
}

func TestCB14_SendFCMNotification_NilConfig(t *testing.T) {
	pushConfig = nil
	defer func() { pushConfig = nil }()

	err := sendFCMNotification("token123", "Title", "Body", "conv1")
	if err != nil {
		t.Errorf("expected nil error for nil config, got %v", err)
	}
}

func TestCB14_SendFCMNotification_Disabled(t *testing.T) {
	pushConfig = &PushNotificationConfig{FCMEnabled: false}
	defer func() { pushConfig = nil }()

	err := sendFCMNotification("token123", "Title", "Body", "conv1")
	if err != nil {
		t.Errorf("expected nil error for disabled FCM, got %v", err)
	}
}

func TestCB14_SendFCMNotification_NilClient(t *testing.T) {
	pushConfig = &PushNotificationConfig{FCMEnabled: true, fcmClient: nil}
	defer func() { pushConfig = nil }()

	err := sendFCMNotification("token123", "Title", "Body", "conv1")
	if err != nil {
		t.Errorf("expected nil error for nil client, got %v", err)
	}
}

func TestCB14_SendPushNotification_PlatformRouting(t *testing.T) {
	// Test that android routes to FCM
	pushConfig = &PushNotificationConfig{FCMEnabled: true, fcmClient: nil}
	defer func() { pushConfig = nil }()

	// All paths should return nil since clients are nil
	err := sendPushNotification("token", "Title", "Body", "conv1", "android")
	if err != nil {
		t.Errorf("expected nil for android with nil FCM client, got %v", err)
	}

	err = sendPushNotification("token", "Title", "Body", "conv1", "fcm")
	if err != nil {
		t.Errorf("expected nil for fcm with nil FCM client, got %v", err)
	}

	// iOS defaults to APNs
	err = sendPushNotification("token", "Title", "Body", "conv1", "ios")
	if err != nil {
		t.Errorf("expected nil for ios with nil APNs client, got %v", err)
	}

	// Unknown platform defaults to APNs
	err = sendPushNotification("token", "Title", "Body", "conv1", "unknown")
	if err != nil {
		t.Errorf("expected nil for unknown platform, got %v", err)
	}
}

// ==============================
// notifyUser coverage
// ==============================

func TestCB14_NotifyUser_NilConfig(t *testing.T) {
	pushConfig = nil
	// Should not panic with nil config
	notifyUser("user1", "Title", "Body", "conv1")
}

func TestCB14_NotifyUser_NoDeviceTokens(t *testing.T) {
	cb14SetupDB(t)
	pushConfig = &PushNotificationConfig{APNSEnabled: true, apnsClient: nil}
	defer func() { pushConfig = nil }()

	cb14MakeToken(t, "cb14_notok_u")
	cb14CreateAgent(t, "cb14_notok_a")
	cb14CreateConv(t, "cb14_notok_u", "cb14_notok_a")

	// User has no device tokens - should not panic
	notifyUser("cb14_notok_u", "Title", "Body", "conv1")
}

func TestCB14_NotifyUser_MutedConversation(t *testing.T) {
	cb14SetupDB(t)
	pushConfig = &PushNotificationConfig{APNSEnabled: true, apnsClient: nil}
	defer func() { pushConfig = nil }()

	_, convID := cb14CreateConv(t, "cb14_mute_u", "cb14_mute_a")

	// Mute the conversation
	db.Exec("INSERT INTO notification_preferences (user_id, conversation_id, muted) VALUES (?, ?, ?)",
		"cb14_mute_u", convID, true)

	// Should skip notification without error
	notifyUser("cb14_mute_u", "Title", "Body", convID)
}

// ==============================
// TieredRateLimiter cleanup coverage
// ==============================

func TestCB14_RateLimitCleanup_StaleEntries(t *testing.T) {
	trl := NewTieredRateLimiter()
	trl.mu.Lock()
	trl.limits["expired_user"] = &userRateLimitState{
		tier:      TierFree,
		count:     5,
		windowEnd: time.Now().Add(-15 * time.Minute),
	}
	trl.limits["recent_user"] = &userRateLimitState{
		tier:      TierPro,
		count:     3,
		windowEnd: time.Now().Add(30 * time.Minute),
	}
	trl.mu.Unlock()

	before := len(trl.limits)

	// Manually clean up expired entries (same logic as cleanup goroutine)
	now := time.Now()
	trl.mu.Lock()
	for id, entry := range trl.limits {
		if now.After(entry.windowEnd) && now.Sub(entry.windowEnd) > 10*time.Minute {
			delete(trl.limits, id)
		}
	}
	trl.mu.Unlock()

	after := len(trl.limits)
	if after >= before {
		t.Errorf("expected cleanup to remove expired entry: before=%d after=%d", before, after)
	}

	tier := trl.GetTier("recent_user")
	if tier.Name != "pro" {
		t.Errorf("expected recent user to still be pro, got %s", tier.Name)
	}
}

func TestCB14_RateLimitReset(t *testing.T) {
	trl := NewTieredRateLimiter()
	trl.Allow("user1")
	trl.Allow("user2")
	trl.SetTier("user3", TierEnterprise)

	trl.Reset()

	trl.mu.Lock()
	count := len(trl.limits)
	trl.mu.Unlock()

	if count != 0 {
		t.Errorf("expected 0 limits after reset, got %d", count)
	}
}

// ==============================
// initPushNotifications coverage
// ==============================

func TestCB14_InitPushNotifications_Defaults(t *testing.T) {
	os.Unsetenv("APNS_ENABLED")
	os.Unsetenv("FCM_ENABLED")
	os.Unsetenv("APNS_CERT_PATH")
	os.Unsetenv("FCM_CREDENTIALS_PATH")

	initPushNotifications()

	if pushConfig.APNSEnabled {
		t.Error("expected APNs to be disabled by default")
	}
	if pushConfig.FCMEnabled {
		t.Error("expected FCM to be disabled by default")
	}
	if pushConfig.BundleID != "com.agentmessenger.ios" {
		t.Errorf("expected default bundle ID, got %s", pushConfig.BundleID)
	}
	if pushConfig.Environment != "development" {
		t.Errorf("expected default environment development, got %s", pushConfig.Environment)
	}
}

func TestCB14_InitAPNs_EnabledNoCertPath(t *testing.T) {
	os.Setenv("APNS_ENABLED", "true")
	os.Unsetenv("APNS_CERT_PATH")
	defer func() {
		os.Unsetenv("APNS_ENABLED")
		pushConfig = nil
	}()

	pushConfig = &PushNotificationConfig{APNSEnabled: true}
	initAPNs()

	// initAPNs returns early when CertPath is empty, leaving APNSEnabled true
	// but no client is initialized - pushes just won't actually send
	if !pushConfig.APNSEnabled {
		t.Error("expected APNs to remain enabled (just no client) when no cert path")
	}
	if pushConfig.apnsClient != nil {
		t.Error("expected nil APNs client when no cert path")
	}
}

func TestCB14_InitAPNs_CertNotFound(t *testing.T) {
	os.Setenv("APNS_ENABLED", "true")
	os.Setenv("APNS_CERT_PATH", "/nonexistent/path/to/cert.p12")
	defer func() {
		os.Unsetenv("APNS_ENABLED")
		os.Unsetenv("APNS_CERT_PATH")
		pushConfig = nil
	}()

	pushConfig = &PushNotificationConfig{
		APNSEnabled: true,
		CertPath:    "/nonexistent/path/to/cert.p12",
	}
	initAPNs()

	if pushConfig.APNSEnabled {
		t.Error("expected APNs to be disabled when cert not found")
	}
}

func TestCB14_InitFCM_EnabledNoCredsPath(t *testing.T) {
	os.Setenv("FCM_ENABLED", "true")
	os.Unsetenv("FCM_CREDENTIALS_PATH")
	defer func() {
		os.Unsetenv("FCM_ENABLED")
		pushConfig = nil
	}()

	pushConfig = &PushNotificationConfig{FCMEnabled: true}
	initFCM()

	if pushConfig.fcmClient != nil {
		t.Error("expected nil FCM client when no credentials path")
	}
}

func TestCB14_InitFCM_CredsNotFound(t *testing.T) {
	pushConfig = &PushNotificationConfig{
		FCMEnabled:     true,
		FCMCredentials: "/nonexistent/path/to/creds.json",
	}
	defer func() { pushConfig = nil }()

	initFCM()

	if pushConfig.FCMEnabled {
		t.Error("expected FCM to be disabled when creds not found")
	}
}

// ==============================
// getDeviceTokensForUser coverage
// ==============================

func TestCB14_GetDeviceTokensForUser_NoTokens(t *testing.T) {
	cb14SetupDB(t)

	tokens, err := getDeviceTokensForUser("nonexistent_user")
	if err != nil {
		t.Errorf("expected nil error, got %v", err)
	}
	if len(tokens) != 0 {
		t.Errorf("expected 0 tokens, got %d", len(tokens))
	}
}

func TestCB14_GetDeviceTokensForUser_WithTokens(t *testing.T) {
	cb14SetupDB(t)

	userID := "cb14_tok_user"
	db.Exec("INSERT OR IGNORE INTO users (id, username, password_hash) VALUES (?, ?, ?)",
		userID, userID, "$2a$04$hash")
	db.Exec("INSERT INTO device_tokens (user_id, device_token, platform, created_at) VALUES (?, ?, ?, ?)",
		userID, "token_ios_1", "ios", time.Now().UTC())
	db.Exec("INSERT INTO device_tokens (user_id, device_token, platform, created_at) VALUES (?, ?, ?, ?)",
		userID, "token_android_1", "android", time.Now().UTC())

	tokens, err := getDeviceTokensForUser(userID)
	if err != nil {
		t.Errorf("expected nil error, got %v", err)
	}
	if len(tokens) != 2 {
		t.Errorf("expected 2 tokens, got %d", len(tokens))
	}
}

// ==============================
// deleteConversation edge cases
// ==============================

func TestCB14_DeleteConversation_NotFound(t *testing.T) {
	cb14SetupDB(t)

	err := deleteConversation("nonexistent_conv", "user1")
	if err == nil {
		t.Error("expected error for nonexistent conversation")
	}
}

func TestCB14_DeleteConversation_UnauthorizedUser(t *testing.T) {
	cb14SetupDB(t)
	cb14MakeToken(t, "cb14_del_u1")
	cb14CreateAgent(t, "cb14_del_a1")

	conv, _ := GetOrCreateConversation("cb14_del_u1", "cb14_del_a1")

	err := deleteConversation(conv.ID, "different_user")
	if err == nil {
		t.Error("expected error for unauthorized user")
	}
	if err.Error() != "unauthorized" {
		t.Errorf("expected 'unauthorized' error, got %v", err)
	}
}

func TestCB14_DeleteConversation_Valid(t *testing.T) {
	cb14SetupDB(t)
	cb14MakeToken(t, "cb14_del_u2")
	cb14CreateAgent(t, "cb14_del_a2")

	conv, _ := GetOrCreateConversation("cb14_del_u2", "cb14_del_a2")

	// Add a message to the conversation
	db.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, metadata, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
		"msg_del1", conv.ID, "client", "cb14_del_u2", "hello", "{}", time.Now().UTC())

	err := deleteConversation(conv.ID, "cb14_del_u2")
	if err != nil {
		t.Errorf("expected nil error, got %v", err)
	}

	// Verify conversation is gone
	var count int
	db.QueryRow("SELECT COUNT(*) FROM conversations WHERE id = ?", conv.ID).Scan(&count)
	if count != 0 {
		t.Errorf("expected conversation to be deleted, still found %d", count)
	}

	// Verify messages are gone
	db.QueryRow("SELECT COUNT(*) FROM messages WHERE conversation_id = ?", conv.ID).Scan(&count)
	if count != 0 {
		t.Errorf("expected messages to be deleted, still found %d", count)
	}
}

// ==============================
// changeUserPassword edge cases
// ==============================

func TestCB14_ChangePassword_NonexistentUser(t *testing.T) {
	cb14SetupDB(t)

	err := changeUserPassword("nonexistent_user", "oldpass", "newpass123")
	if err == nil {
		t.Error("expected error for nonexistent user")
	}
}

// ==============================
// searchMessages edge cases
// ==============================

func TestCB14_SearchMessages_EmptyQuery(t *testing.T) {
	cb14SetupDB(t)

	_, err := searchMessages("user1", "", 50)
	if err == nil {
		t.Error("expected error for empty query")
	}
	if err.Error() != "empty search query" {
		t.Errorf("expected 'empty search query' error, got %v", err)
	}
}

func TestCB14_SearchMessages_NoResults(t *testing.T) {
	cb14SetupDB(t)
	cb14MakeToken(t, "cb14_search_u")
	cb14CreateAgent(t, "cb14_search_a")
	conv, _ := GetOrCreateConversation("cb14_search_u", "cb14_search_a")

	// Add a message
	db.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, metadata, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
		"msg_search1", conv.ID, "client", "cb14_search_u", "hello world", "{}", time.Now().UTC())

	messages, err := searchMessages("cb14_search_u", "nonexistent", 50)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if len(messages) != 0 {
		t.Errorf("expected 0 results, got %d", len(messages))
	}
}

func TestCB14_SearchMessages_WithResults(t *testing.T) {
	cb14SetupDB(t)
	cb14MakeToken(t, "cb14_search_u2")
	cb14CreateAgent(t, "cb14_search_a2")
	conv, _ := GetOrCreateConversation("cb14_search_u2", "cb14_search_a2")

	// Add messages
	db.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, metadata, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
		"msg_search2", conv.ID, "client", "cb14_search_u2", "hello world", "{}", time.Now().UTC())
	db.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, metadata, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
		"msg_search3", conv.ID, "agent", "cb14_search_a2", "hello from agent", "{}", time.Now().UTC())

	messages, err := searchMessages("cb14_search_u2", "hello", 50)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if len(messages) != 2 {
		t.Errorf("expected 2 results, got %d", len(messages))
	}
}

// ==============================
// markMessagesRead edge cases
// ==============================

func TestCB14_MarkRead_NotFound(t *testing.T) {
	cb14SetupDB(t)

	_, err := markMessagesRead("nonexistent_conv", "user1")
	if err == nil {
		t.Error("expected error for nonexistent conversation")
	}
}

func TestCB14_MarkRead_UnauthorizedUser(t *testing.T) {
	cb14SetupDB(t)
	cb14MakeToken(t, "cb14_read_u1")
	cb14CreateAgent(t, "cb14_read_a1")
	conv, _ := GetOrCreateConversation("cb14_read_u1", "cb14_read_a1")

	_, err := markMessagesRead(conv.ID, "different_user")
	if err == nil {
		t.Error("expected error for unauthorized user")
	}
}

// ==============================
// Attachment upload full flow
// ==============================

func TestCB14_Upload_FullFlow(t *testing.T) {
	cb14SetupDB(t)
	token, _ := cb14CreateConv(t, "cb14_upload_u", "cb14_upload_a")

	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)
	part, _ := writer.CreateFormFile("file", "test.txt")
	part.Write([]byte("hello world test content"))
	writer.Close()

	req := httptest.NewRequest(http.MethodPost, "/attachments/upload", &buf)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleUpload(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200 for valid upload, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["id"] == nil {
		t.Error("expected id in response")
	}
	if resp["filename"] != "test.txt" {
		t.Errorf("expected filename test.txt, got %v", resp["filename"])
	}
}

func TestCB14_Upload_FileTooLarge(t *testing.T) {
	cb14SetupDB(t)
	token, _ := cb14CreateConv(t, "cb14_big_u", "cb14_big_a")

	origMax := maxUploadSize
	maxUploadSize = 100
	defer func() { maxUploadSize = origMax }()

	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)
	part, _ := writer.CreateFormFile("file", "big.txt")
	part.Write(make([]byte, 200))
	writer.Close()

	req := httptest.NewRequest(http.MethodPost, "/attachments/upload", &buf)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleUpload(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for file too large, got %d", w.Code)
	}
}

func TestCB14_Upload_InvalidAuth(t *testing.T) {
	cb14SetupDB(t)

	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)
	part, _ := writer.CreateFormFile("file", "agent.txt")
	part.Write([]byte("agent file content"))
	writer.Close()

	req := httptest.NewRequest(http.MethodPost, "/attachments/upload", &buf)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	req.Header.Set("Authorization", "Bearer invalid_token")
	w := httptest.NewRecorder()
	handleUpload(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for invalid token, got %d", w.Code)
	}
}

// ==============================
// handleUploadPublicKey more paths
// ==============================

func TestCB14_UploadPublicKey_IdentityReplace(t *testing.T) {
	cb14SetupDB(t)
	token := cb14MakeToken(t, "cb14_key_u1")

	// Upload identity key
	body := `{"key_type":"identity","public_key":"base64key1"}`
	req := httptest.NewRequest(http.MethodPost, "/keys/upload", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handleUploadPublicKey(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200 for first identity key, got %d: %s", w.Code, w.Body.String())
	}

	// Upload identity key again (should replace)
	body2 := `{"key_type":"identity","public_key":"base64key2_replaced"}`
	req2 := httptest.NewRequest(http.MethodPost, "/keys/upload", strings.NewReader(body2))
	req2.Header.Set("Authorization", "Bearer "+token)
	req2.Header.Set("Content-Type", "application/json")
	w2 := httptest.NewRecorder()
	handleUploadPublicKey(w2, req2)
	if w2.Code != http.StatusOK {
		t.Errorf("expected 200 for identity key replacement, got %d: %s", w2.Code, w2.Body.String())
	}

	// Verify only one identity key exists
	var count int
	db.QueryRow("SELECT COUNT(*) FROM key_bundles WHERE owner_id = ? AND owner_type = 'user' AND key_type = 'identity'", "cb14_key_u1").Scan(&count)
	if count != 1 {
		t.Errorf("expected 1 identity key after replacement, got %d", count)
	}
}

func TestCB14_UploadPublicKey_OTPK(t *testing.T) {
	cb14SetupDB(t)
	token := cb14MakeToken(t, "cb14_key_u2")

	body := `{"key_type":"one_time_prekey","public_key":"base64otpk1","key_id":1}`
	req := httptest.NewRequest(http.MethodPost, "/keys/upload", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handleUploadPublicKey(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200 for OTPK, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCB14_GetKeyBundle_Full(t *testing.T) {
	cb14SetupDB(t)
	token := cb14MakeToken(t, "cb14_bundle_u")
	cb14CreateAgent(t, "cb14_bundle_a")
	cb14CreateConv(t, "cb14_bundle_u", "cb14_bundle_a")

	// Upload identity key for the agent
	body := `{"key_type":"identity","public_key":"agent_identity_key"}`
	req := httptest.NewRequest(http.MethodPost, "/keys/upload", strings.NewReader(body))
	req.Header.Set("X-Agent-Secret", getAgentSecret())
	req.Header.Set("X-Agent-ID", "cb14_bundle_a")
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handleUploadPublicKey(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// Get bundle
	req2 := httptest.NewRequest(http.MethodGet, "/keys/bundle?owner_id=cb14_bundle_a&owner_type=agent", nil)
	req2.Header.Set("Authorization", "Bearer "+token)
	w2 := httptest.NewRecorder()
	handleGetKeyBundle(w2, req2)
	if w2.Code != http.StatusOK {
		t.Errorf("expected 200 for bundle, got %d: %s", w2.Code, w2.Body.String())
	}
}

// ==============================
// handleGetAttachment with user auth
// ==============================

func TestCB14_GetAttachment_WithUserAuth(t *testing.T) {
	cb14SetupDB(t)
	token, convID := cb14CreateConv(t, "cb14_att_u", "cb14_att_a")
	_ = convID

	// Upload a file first
	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)
	part, _ := writer.CreateFormFile("file", "download.txt")
	part.Write([]byte("download me"))
	writer.Close()

	req := httptest.NewRequest(http.MethodPost, "/attachments/upload", &buf)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleUpload(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("upload failed: %d %s", w.Code, w.Body.String())
	}

	var uploadResp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&uploadResp)
	attachID, _ := uploadResp["id"].(string)

	// Now get the attachment with user auth
	req2 := httptest.NewRequest(http.MethodGet, "/attachments/"+attachID, nil)
	req2.Header.Set("Authorization", "Bearer "+token)
	w2 := httptest.NewRecorder()
	handleGetAttachment(w2, req2)
	if w2.Code != http.StatusOK && w2.Code != http.StatusPartialContent {
		t.Errorf("expected 200 for get attachment, got %d", w2.Code)
	}
}

func TestCB14_GetAttachment_WrongUser(t *testing.T) {
	cb14SetupDB(t)
	token, _ := cb14CreateConv(t, "cb14_att_u2", "cb14_att_a2")
	token2 := cb14MakeToken(t, "cb14_att_u2b")
	_ = token2

	// Upload a file as user1
	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)
	part, _ := writer.CreateFormFile("file", "private.txt")
	part.Write([]byte("private content"))
	writer.Close()

	req := httptest.NewRequest(http.MethodPost, "/attachments/upload", &buf)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleUpload(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("upload failed: %d", w.Code)
	}

	var uploadResp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&uploadResp)
	attachID, _ := uploadResp["id"].(string)

	// Try to get the attachment as a different user
	req2 := httptest.NewRequest(http.MethodGet, "/attachments/"+attachID, nil)
	req2.Header.Set("Authorization", "Bearer "+token2)
	w2 := httptest.NewRecorder()
	handleGetAttachment(w2, req2)
	if w2.Code != http.StatusForbidden {
		t.Errorf("expected 403 for wrong user, got %d", w2.Code)
	}
}

// ==============================
// handleStoreEncryptedMessage agent not participant
// ==============================

func TestCB14_StoreEncrypted_AgentNotParticipant(t *testing.T) {
	cb14SetupDB(t)
	_, convID := cb14CreateConv(t, "cb14_e2e_u1", "cb14_e2e_a1")

	// Agent that's NOT in this conversation
	cb14CreateAgent(t, "cb14_e2e_wrong_agent")

	body := fmt.Sprintf(`{"conversation_id":"%s","ciphertext":"abc","iv":"def","algorithm":"aes-256-gcm","recipient_key_id":"key1"}`, convID)
	req := httptest.NewRequest(http.MethodPost, "/messages/encrypted", strings.NewReader(body))
	req.Header.Set("X-Agent-Secret", getAgentSecret())
	req.Header.Set("X-Agent-ID", "cb14_e2e_wrong_agent")
	w := httptest.NewRecorder()
	handleStoreEncryptedMessage(w, req)
	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403 for agent not in conversation, got %d", w.Code)
	}
}

// ==============================
// handleGetEncryptedMessages with agent auth
// ==============================

func TestCB14_GetEncrypted_AgentAuth(t *testing.T) {
	cb14SetupDB(t)
	_, convID := cb14CreateConv(t, "cb14_e2e_u2", "cb14_e2e_a2")

	// Store an encrypted message as agent
	body := fmt.Sprintf(`{"conversation_id":"%s","ciphertext":"abc","iv":"def","algorithm":"aes-256-gcm","recipient_key_id":"key1"}`, convID)
	req := httptest.NewRequest(http.MethodPost, "/messages/encrypted", strings.NewReader(body))
	req.Header.Set("X-Agent-Secret", getAgentSecret())
	req.Header.Set("X-Agent-ID", "cb14_e2e_a2")
	w := httptest.NewRecorder()
	handleStoreEncryptedMessage(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("store failed: %d %s", w.Code, w.Body.String())
	}

	// Get encrypted messages as the agent
	req2 := httptest.NewRequest(http.MethodGet, "/messages/encrypted?conversation_id="+convID, nil)
	req2.Header.Set("X-Agent-Secret", getAgentSecret())
	req2.Header.Set("X-Agent-ID", "cb14_e2e_a2")
	w2 := httptest.NewRecorder()
	handleGetEncryptedMessages(w2, req2)
	if w2.Code != http.StatusOK {
		t.Errorf("expected 200 for agent get encrypted, got %d: %s", w2.Code, w2.Body.String())
	}
}

// ==============================
// handleListAttachments valid flow
// ==============================

func TestCB14_ListAttachments_ValidFlow(t *testing.T) {
	cb14SetupDB(t)
	token, convID := cb14CreateConv(t, "cb14_list_u", "cb14_list_a")
	_ = convID

	// Upload a file
	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)
	part, _ := writer.CreateFormFile("file", "listme.txt")
	part.Write([]byte("list this file"))
	writer.Close()

	req := httptest.NewRequest(http.MethodPost, "/attachments/upload", &buf)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleUpload(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("upload failed: %d %s", w.Code, w.Body.String())
	}

	// List attachments
	req2 := httptest.NewRequest(http.MethodGet, "/messages/attachments?conversation_id="+convID, nil)
	req2.Header.Set("Authorization", "Bearer "+token)
	w2 := httptest.NewRecorder()
	handleListAttachments(w2, req2)
	if w2.Code != http.StatusOK {
		t.Errorf("expected 200 for list attachments, got %d: %s", w2.Code, w2.Body.String())
	}
}

// ==============================
// Notification preferences DB operations
// ==============================

func TestCB14_NotificationPrefs_MuteUnmute(t *testing.T) {
	cb14SetupDB(t)
	_, convID := cb14CreateConv(t, "cb14_notif_u", "cb14_notif_a")
	userID := "cb14_notif_u"

	// Mute conversation
	_, err := db.Exec(fmt.Sprintf(
		"INSERT INTO notification_preferences (user_id, conversation_id, muted) VALUES (%s, %s, %s) ON CONFLICT(user_id, conversation_id) DO UPDATE SET muted = %s",
		Placeholder(1), Placeholder(2), Placeholder(3), Placeholder(4)),
		userID, convID, true, true)
	if err != nil {
		t.Fatalf("insert notif pref: %v", err)
	}

	// Check mute status
	if !isConversationMuted(userID, convID) {
		t.Error("expected conversation to be muted")
	}

	// Unmute
	_, err = db.Exec("UPDATE notification_preferences SET muted = 0 WHERE user_id = ? AND conversation_id = ?",
		userID, convID)
	if err != nil {
		t.Fatalf("update notif pref: %v", err)
	}

	if isConversationMuted(userID, convID) {
		t.Error("expected conversation to NOT be muted after unmute")
	}
}

// ==============================
// Rate limit tier handlers
// ==============================

func TestCB14_SetRateLimitTier_InvalidTier(t *testing.T) {
	cb14SetupDB(t)
	origSecret := adminSecret
	adminSecret = "test_admin_secret"
	defer func() { adminSecret = origSecret }()

	form := url.Values{}
	form.Set("user_id", "test_user")
	form.Set("tier", "invalid_tier")
	form.Set("admin_secret", "test_admin_secret")

	req := httptest.NewRequest(http.MethodPost, "/admin/rate-limit/tier", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Admin-Secret", "test_admin_secret")
	w := httptest.NewRecorder()
	handleSetRateLimitTier(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid tier, got %d", w.Code)
	}
}

func TestCB14_GetRateLimitTier_MissingUserID(t *testing.T) {
	cb14SetupDB(t)
	origSecret := adminSecret
	adminSecret = "test_admin_secret"
	defer func() { adminSecret = origSecret }()

	req := httptest.NewRequest(http.MethodGet, "/admin/rate-limit/tier", nil)
	req.Header.Set("X-Admin-Secret", "test_admin_secret")
	w := httptest.NewRecorder()
	handleGetRateLimitTier(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing user_id, got %d", w.Code)
	}
}

func TestCB14_AdminRateLimitTier_Routing(t *testing.T) {
	cb14SetupDB(t)
	origSecret := adminSecret
	adminSecret = "test_admin_secret"
	defer func() { adminSecret = origSecret }()

	// Test POST routing
	form := url.Values{}
	form.Set("user_id", "route_test_user")
	form.Set("tier", "pro")

	req := httptest.NewRequest(http.MethodPost, "/admin/rate-limit/tier", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Admin-Secret", "test_admin_secret")
	w := httptest.NewRecorder()
	handleAdminRateLimitTier(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200 for POST set tier, got %d: %s", w.Code, w.Body.String())
	}

	// Test GET routing
	req2 := httptest.NewRequest(http.MethodGet, "/admin/rate-limit/tier?user_id=route_test_user&admin_secret=test_admin_secret", nil)
	w2 := httptest.NewRecorder()
	handleAdminRateLimitTier(w2, req2)

	if w2.Code != http.StatusOK {
		t.Errorf("expected 200 for GET tier, got %d: %s", w2.Code, w2.Body.String())
	}
}

// ==============================
// Web Push handlers
// ==============================

func TestCB14_WebPushSubscribe_MissingFields(t *testing.T) {
	cb14SetupDB(t)
	token := cb14MakeToken(t, "cb14_webpush_u")

	// Missing endpoint
	body := `{"keys":{"p256dh":"key1","auth":"auth1"}}`
	req := httptest.NewRequest(http.MethodPost, "/push/web-subscribe", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handleWebPushSubscribe(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing endpoint, got %d", w.Code)
	}

	// Missing p256dh
	body2 := `{"endpoint":"https://push.example.com/123","keys":{"auth":"auth1"}}`
	req2 := httptest.NewRequest(http.MethodPost, "/push/web-subscribe", strings.NewReader(body2))
	req2.Header.Set("Authorization", "Bearer "+token)
	req2.Header.Set("Content-Type", "application/json")
	w2 := httptest.NewRecorder()
	handleWebPushSubscribe(w2, req2)
	if w2.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing p256dh, got %d", w2.Code)
	}
}

func TestCB14_WebPushSubscribe_Valid(t *testing.T) {
	cb14SetupDB(t)
	token := cb14MakeToken(t, "cb14_webpush_u2")

	body := `{"endpoint":"https://push.example.com/sub/456","keys":{"p256dh":"base64p256dh","auth":"base64auth"}}`
	req := httptest.NewRequest(http.MethodPost, "/push/web-subscribe", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handleWebPushSubscribe(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200 for valid subscribe, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]string
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["status"] != "subscribed" {
		t.Errorf("expected status=subscribed, got %v", resp["status"])
	}
}

func TestCB14_WebPushUnsubscribe_MissingEndpoint(t *testing.T) {
	cb14SetupDB(t)
	token := cb14MakeToken(t, "cb14_webpush_u3")

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

func TestCB14_WebPushUnsubscribe_Valid(t *testing.T) {
	cb14SetupDB(t)
	token := cb14MakeToken(t, "cb14_webpush_u4")

	// First subscribe
	body := `{"endpoint":"https://push.example.com/sub/789","keys":{"p256dh":"key","auth":"auth"}}`
	req := httptest.NewRequest(http.MethodPost, "/push/web-subscribe", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handleWebPushSubscribe(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("subscribe failed: %d %s", w.Code, w.Body.String())
	}

	// Then unsubscribe
	body2 := `{"endpoint":"https://push.example.com/sub/789"}`
	req2 := httptest.NewRequest(http.MethodPost, "/push/web-unsubscribe", strings.NewReader(body2))
	req2.Header.Set("Authorization", "Bearer "+token)
	req2.Header.Set("Content-Type", "application/json")
	w2 := httptest.NewRecorder()
	handleWebPushUnsubscribe(w2, req2)
	if w2.Code != http.StatusOK {
		t.Errorf("expected 200 for unsubscribe, got %d: %s", w2.Code, w2.Body.String())
	}
}

// ==============================
// VAPID key handler
// ==============================

func TestCB14_VAPIDKey_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/push/vapid-key", nil)
	w := httptest.NewRecorder()
	handleGetVAPIDKey(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405 for POST, got %d", w.Code)
	}
}

func TestCB14_VAPIDKey_NotConfigured(t *testing.T) {
	origKey := vapidPublicKey
	vapidPublicKey = ""
	defer func() { vapidPublicKey = origKey }()

	req := httptest.NewRequest(http.MethodGet, "/push/vapid-key", nil)
	req.Header.Set("Authorization", "Bearer test_token")
	w := httptest.NewRecorder()
	handleGetVAPIDKey(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404 when VAPID not configured, got %d", w.Code)
	}
}

func TestCB14_VAPIDKey_Configured(t *testing.T) {
	origKey := vapidPublicKey
	vapidPublicKey = "test_vapid_public_key_base64"
	defer func() { vapidPublicKey = origKey }()

	req := httptest.NewRequest(http.MethodGet, "/push/vapid-key", nil)
	req.Header.Set("Authorization", "Bearer test_token")
	w := httptest.NewRecorder()
	handleGetVAPIDKey(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200 when VAPID configured, got %d", w.Code)
	}

	var resp map[string]string
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["public_key"] != "test_vapid_public_key_base64" {
		t.Errorf("expected VAPID key, got %v", resp["public_key"])
	}
}

// ==============================
// Device token register/unregister
// ==============================

func TestCB14_RegisterDeviceToken_DefaultPlatform(t *testing.T) {
	cb14SetupDB(t)
	token := cb14MakeToken(t, "cb14_device_u")

	body := `{"device_token":"ios_token_123"}`
	req := httptest.NewRequest(http.MethodPost, "/push/register", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handleRegisterDeviceToken(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200 for register with default platform, got %d: %s", w.Code, w.Body.String())
	}

	// Verify platform is "ios" (default)
	var platform string
	db.QueryRow("SELECT platform FROM device_tokens WHERE user_id = ? AND device_token = ?", "cb14_device_u", "ios_token_123").Scan(&platform)
	if platform != "ios" {
		t.Errorf("expected default platform ios, got %s", platform)
	}
}

func TestCB14_RegisterDeviceToken_InvalidJSON(t *testing.T) {
	cb14SetupDB(t)
	token := cb14MakeToken(t, "cb14_device_u2")

	req := httptest.NewRequest(http.MethodPost, "/push/register", strings.NewReader("not json"))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handleRegisterDeviceToken(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid JSON, got %d", w.Code)
	}
}

func TestCB14_RegisterDeviceToken_MissingToken(t *testing.T) {
	cb14SetupDB(t)
	token := cb14MakeToken(t, "cb14_device_u3")

	body := `{"platform":"android"}`
	req := httptest.NewRequest(http.MethodPost, "/push/register", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handleRegisterDeviceToken(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing device_token, got %d", w.Code)
	}
}

func TestCB14_UnregisterDeviceToken_Valid(t *testing.T) {
	cb14SetupDB(t)
	token := cb14MakeToken(t, "cb14_device_u4")

	// Register first
	db.Exec("INSERT INTO device_tokens (user_id, device_token, platform, created_at) VALUES (?, ?, ?, ?)",
		"cb14_device_u4", "token_to_remove", "ios", time.Now().UTC())

	// Then unregister
	body := `{"device_token":"token_to_remove"}`
	req := httptest.NewRequest(http.MethodDelete, "/push/unregister", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handleUnregisterDeviceToken(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200 for unregister, got %d: %s", w.Code, w.Body.String())
	}

	// Verify token removed
	var count int
	db.QueryRow("SELECT COUNT(*) FROM device_tokens WHERE device_token = ?", "token_to_remove").Scan(&count)
	if count != 0 {
		t.Errorf("expected 0 tokens after unregister, got %d", count)
	}
}

func TestCB14_UnregisterDeviceToken_InvalidJSON(t *testing.T) {
	cb14SetupDB(t)
	token := cb14MakeToken(t, "cb14_device_u5")

	req := httptest.NewRequest(http.MethodDelete, "/push/unregister", strings.NewReader("not json"))
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleUnregisterDeviceToken(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid JSON, got %d", w.Code)
	}
}

func TestCB14_UnregisterDeviceToken_MissingToken(t *testing.T) {
	cb14SetupDB(t)
	token := cb14MakeToken(t, "cb14_device_u6")

	body := `{}`
	req := httptest.NewRequest(http.MethodDelete, "/push/unregister", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handleUnregisterDeviceToken(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing device_token, got %d", w.Code)
	}
}

// ==============================
// handleRegisterAgent edge cases
// ==============================

func TestCB14_RegisterAgent_MissingID(t *testing.T) {
	cb14SetupDB(t)
	origEnv := os.Getenv("AGENT_SECRET")
	os.Setenv("AGENT_SECRET", "test_secret")
	agentSecret = "test_secret"
	defer func() {
		if origEnv != "" {
			os.Setenv("AGENT_SECRET", origEnv)
		} else {
			os.Unsetenv("AGENT_SECRET")
		}
		resetAgentSecret()
	}()

	form := url.Values{}
	form.Set("name", "Test Agent")
	req := httptest.NewRequest(http.MethodPost, "/auth/agent", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Agent-Secret", "test_secret")
	w := httptest.NewRecorder()
	handleRegisterAgent(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing agent_id, got %d", w.Code)
	}
}

func TestCB14_RegisterAgent_Valid(t *testing.T) {
	cb14SetupDB(t)
	origEnv := os.Getenv("AGENT_SECRET")
	os.Setenv("AGENT_SECRET", "test_secret")
	agentSecret = "test_secret"
	defer func() {
		if origEnv != "" {
			os.Setenv("AGENT_SECRET", origEnv)
		} else {
			os.Unsetenv("AGENT_SECRET")
		}
		resetAgentSecret()
	}()

	form := url.Values{}
	form.Set("agent_id", "test_agent_1")
	form.Set("name", "Test Agent")
	form.Set("model", "gpt-4")
	req := httptest.NewRequest(http.MethodPost, "/auth/agent", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Agent-Secret", "test_secret")
	w := httptest.NewRecorder()
	handleRegisterAgent(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200 for valid agent registration, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]string
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["status"] != "registered" {
		t.Errorf("expected status=registered, got %v", resp["status"])
	}
}

// ==============================
// handleRegisterUser edge cases
// ==============================

func TestCB14_RegisterUser_ShortUsername(t *testing.T) {
	cb14SetupDB(t)

	form := url.Values{}
	form.Set("username", "ab")
	form.Set("password", "password123")
	req := httptest.NewRequest(http.MethodPost, "/auth/user", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handleRegisterUser(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for short username, got %d", w.Code)
	}
}

func TestCB14_RegisterUser_InvalidChars(t *testing.T) {
	cb14SetupDB(t)

	form := url.Values{}
	form.Set("username", "user@name!")
	form.Set("password", "password123")
	req := httptest.NewRequest(http.MethodPost, "/auth/user", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handleRegisterUser(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid chars, got %d", w.Code)
	}
}

func TestCB14_RegisterUser_Duplicate(t *testing.T) {
	cb14SetupDB(t)

	form := url.Values{}
	form.Set("username", "cb14_dup_user")
	form.Set("password", "password123")

	req1 := httptest.NewRequest(http.MethodPost, "/auth/user", strings.NewReader(form.Encode()))
	req1.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w1 := httptest.NewRecorder()
	handleRegisterUser(w1, req1)
	if w1.Code != http.StatusOK {
		t.Fatalf("first registration should succeed: %d %s", w1.Code, w1.Body.String())
	}

	req2 := httptest.NewRequest(http.MethodPost, "/auth/user", strings.NewReader(form.Encode()))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w2 := httptest.NewRecorder()
	handleRegisterUser(w2, req2)
	if w2.Code != http.StatusConflict {
		t.Errorf("expected 409 for duplicate username, got %d", w2.Code)
	}
}

// ==============================
// Protocol negotiation tests
// ==============================

func TestCB14_NegotiateProtocol_Default(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	version := negotiateProtocol(req)
	if version != ProtocolVersion {
		t.Errorf("expected default protocol version %s, got %s", ProtocolVersion, version)
	}
}

func TestCB14_NegotiateProtocol_QueryParam(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/?protocol_version=v1", nil)
	version := negotiateProtocol(req)
	if version != "v1" {
		t.Errorf("expected v1 from query param, got %s", version)
	}
}

func TestCB14_NegotiateProtocol_UnsupportedQueryParam(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/?protocol_version=v99", nil)
	version := negotiateProtocol(req)
	if version != ProtocolVersion {
		t.Errorf("expected default for unsupported version, got %s", version)
	}
}

func TestCB14_NegotiateProtocol_Header(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Sec-WebSocket-Protocol", "v1")
	version := negotiateProtocol(req)
	if version != "v1" {
		t.Errorf("expected v1 from header, got %s", version)
	}
}

func TestCB14_NegotiateProtocol_MultipleProtocols(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Sec-WebSocket-Protocol", "other, v1")
	version := negotiateProtocol(req)
	if version != "v1" {
		t.Errorf("expected v1 from multiple protocols, got %s", version)
	}
}

func TestCB14_IsSupportedVersion(t *testing.T) {
	if !isSupportedVersion("v1") {
		t.Error("expected v1 to be supported")
	}
	if isSupportedVersion("v99") {
		t.Error("expected v99 to NOT be supported")
	}
}

// ==============================
// GetOrCreateConversation edge cases
// ==============================

func TestCB14_GetOrCreateConversation_MultipleCalls(t *testing.T) {
	cb14SetupDB(t)
	cb14CreateAgent(t, "cb14_conv_a")

	conv1, err := GetOrCreateConversation("cb14_conv_u", "cb14_conv_a")
	if err != nil {
		t.Fatalf("first call: %v", err)
	}
	conv2, err := GetOrCreateConversation("cb14_conv_u", "cb14_conv_a")
	if err != nil {
		t.Fatalf("second call: %v", err)
	}
	if conv1.ID != conv2.ID {
		t.Errorf("expected same conversation ID, got %s and %s", conv1.ID, conv2.ID)
	}
}

// ==============================
// Placeholder/Placeholders for PostgreSQL support
// ==============================

func TestCB14_Placeholder_SQLite(t *testing.T) {
	origDriver := currentDriver
	currentDriver = DriverSQLite
	defer func() { currentDriver = origDriver }()

	if Placeholder(1) != "?" {
		t.Errorf("expected ? for SQLite, got %s", Placeholder(1))
	}
	if Placeholder(5) != "?" {
		t.Errorf("expected ? for SQLite, got %s", Placeholder(5))
	}
}

func TestCB14_Placeholder_PostgreSQL(t *testing.T) {
	origDriver := currentDriver
	currentDriver = DriverPostgreSQL
	defer func() { currentDriver = origDriver }()

	if Placeholder(1) != "$1" {
		t.Errorf("expected $1 for PostgreSQL, got %s", Placeholder(1))
	}
	if Placeholder(3) != "$3" {
		t.Errorf("expected $3 for PostgreSQL, got %s", Placeholder(3))
	}
}

func TestCB14_Placeholders(t *testing.T) {
	origDriver := currentDriver
	currentDriver = DriverSQLite
	defer func() { currentDriver = origDriver }()

	result := Placeholders(1, 3)
	if result != "?, ?, ?" {
		t.Errorf("expected '?, ?, ?' for SQLite, got %s", result)
	}

	currentDriver = DriverPostgreSQL
	result = Placeholders(1, 3)
	if result != "$1, $2, $3" {
		t.Errorf("expected '$1, $2, $3' for PostgreSQL, got %s", result)
	}
}

// ==============================
// loadTiersFromDB edge cases
// ==============================

func TestCB14_LoadTiersFromDB_NilDB(t *testing.T) {
	origDB := db
	db = nil
	defer func() { db = origDB }()

	trl := NewTieredRateLimiter()
	loadTiersFromDB(trl)
	// Should not panic
}

func TestCB14_LoadTiersFromDB_ValidTiers(t *testing.T) {
	cb14SetupDB(t)

	// Insert tier data
	db.Exec("INSERT INTO user_rate_limit_tiers (user_id, tier_name, updated_at) VALUES (?, ?, datetime('now'))", "pro_user_1", "pro")
	db.Exec("INSERT INTO user_rate_limit_tiers (user_id, tier_name, updated_at) VALUES (?, ?, datetime('now'))", "ent_user_1", "enterprise")
	db.Exec("INSERT INTO user_rate_limit_tiers (user_id, tier_name, updated_at) VALUES (?, ?, datetime('now'))", "free_user_1", "free")

	trl := NewTieredRateLimiter()
	loadTiersFromDB(trl)

	// Pro user should have pro tier
	tier := trl.GetTier("pro_user_1")
	if tier.Name != "pro" {
		t.Errorf("expected pro tier for pro_user_1, got %s", tier.Name)
	}

	// Enterprise user should have enterprise tier
	tier = trl.GetTier("ent_user_1")
	if tier.Name != "enterprise" {
		t.Errorf("expected enterprise tier for ent_user_1, got %s", tier.Name)
	}

	// Unknown users default to free
	tier = trl.GetTier("unknown_user")
	if tier.Name != "free" {
		t.Errorf("expected free tier for unknown user, got %s", tier.Name)
	}
}

// ==============================
// persistTierToDB
// ==============================

func TestCB14_PersistTierToDB_NilDB(t *testing.T) {
	origDB := db
	db = nil
	defer func() { db = origDB }()

	err := persistTierToDB("user1", TierPro)
	if err != nil {
		t.Errorf("expected nil error for nil db, got %v", err)
	}
}

func TestCB14_PersistTierToDB_Valid(t *testing.T) {
	cb14SetupDB(t)

	err := persistTierToDB("cb14_persist_u", TierPro)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	var tierName string
	db.QueryRow("SELECT tier_name FROM user_rate_limit_tiers WHERE user_id = ?", "cb14_persist_u").Scan(&tierName)
	if tierName != "pro" {
		t.Errorf("expected pro tier, got %s", tierName)
	}
}

// ==============================
// Queue persist functions
// ==============================

func TestCB14_QueuePersist_InitAndStore(t *testing.T) {
	cb14SetupDB(t)
	initQueueDB(db)

	msgData := map[string]interface{}{
		"conversation_id": "conv1",
		"content":        "hello queued",
		"sender_type":     "agent",
		"sender_id":       "agent1",
	}
	data := marshalOutgoingMessage(OutgoingMessage{Type: "message", Data: msgData})
	persistQueue(db, "user1", data)

	// Verify message was stored
	var count int
	db.QueryRow("SELECT COUNT(*) FROM offline_queue WHERE recipient = ?", "user1").Scan(&count)
	if count != 1 {
		t.Errorf("expected 1 queued message, got %d", count)
	}
}

func TestCB14_DeleteQueueMessages(t *testing.T) {
	cb14SetupDB(t)
	initQueueDB(db)

	msgData := map[string]interface{}{
		"conversation_id": "conv_del1",
		"content":        "to be deleted",
		"sender_type":     "agent",
		"sender_id":       "agent_del1",
	}
	data := marshalOutgoingMessage(OutgoingMessage{Type: "message", Data: msgData})
	persistQueue(db, "user_del1", data)

	deleteQueueMessages(db, "user_del1")

	// Verify no messages remain
	var count int
	db.QueryRow("SELECT COUNT(*) FROM offline_queue WHERE recipient = ?", "user_del1").Scan(&count)
	if count != 0 {
		t.Errorf("expected 0 messages after delete, got %d", count)
	}
}

func TestCB14_CleanStaleQueueMessages(t *testing.T) {
	cb14SetupDB(t)
	initQueueDB(db)

	// Insert a stale message (old created_at)
	_, err := db.Exec("INSERT INTO offline_queue (recipient, data, queued_at, sent_count) VALUES (?, ?, ?, ?)",
		"user_stale", []byte("stale"), time.Now().UTC().Add(-8*24*time.Hour).Format(time.RFC3339), 0)
	if err != nil {
		t.Fatalf("insert stale message: %v", err)
	}

	cleanStaleQueueMessages(db, 7*24*time.Hour)

	// Verify stale message was removed
	var count int
	db.QueryRow("SELECT COUNT(*) FROM offline_queue WHERE recipient = ?", "user_stale").Scan(&count)
	if count != 0 {
		t.Errorf("expected 0 messages after stale cleanup, got %d", count)
	}
}

// ==============================
// isAllowedContentType more paths
// ==============================

func TestCB14_IsAllowedContentType_ImagePrefixes(t *testing.T) {
	types := []string{"image/tiff", "image/heic", "image/avif", "image/bmp"}
	for _, ct := range types {
		if !isAllowedContentType(ct) {
			t.Errorf("expected %s to be allowed (image prefix)", ct)
		}
	}
}

func TestCB14_IsAllowedContentType_AudioPrefixes(t *testing.T) {
	types := []string{"audio/flac", "audio/aac", "audio/midi"}
	for _, ct := range types {
		if !isAllowedContentType(ct) {
			t.Errorf("expected %s to be allowed (audio prefix)", ct)
		}
	}
}

func TestCB14_IsAllowedContentType_VideoPrefixes(t *testing.T) {
	types := []string{"video/avi", "video/quicktime"}
	for _, ct := range types {
		if !isAllowedContentType(ct) {
			t.Errorf("expected %s to be allowed (video prefix)", ct)
		}
	}
}

func TestCB14_IsAllowedContentType_DisallowedTypes(t *testing.T) {
	types := []string{"application/x-executable", "application/x-msdownload", "application/vnd.ms-excel"}
	for _, ct := range types {
		if isAllowedContentType(ct) {
			t.Errorf("expected %s to be disallowed", ct)
		}
	}
}

// ==============================
// itoa helper
// ==============================

func TestCB14_Itoa(t *testing.T) {
	tests := []struct {
		input    int
		expected string
	}{
		{0, "0"},
		{1, "1"},
		{42, "42"},
		{100, "100"},
		{-1, "-1"},
		{-99, "-99"},
	}
	for _, tt := range tests {
		result := itoa(tt.input)
		if result != tt.expected {
			t.Errorf("itoa(%d) = %q, expected %q", tt.input, result, tt.expected)
		}
	}
}

// ==============================
// getEnvOrDefault
// ==============================

func TestCB14_GetEnvOrDefault(t *testing.T) {
	key := "CB14_TEST_ENV_VAR_12345"
	os.Unsetenv(key)

	result := getEnvOrDefault(key, "default_val")
	if result != "default_val" {
		t.Errorf("expected default_val, got %s", result)
	}

	os.Setenv(key, "overridden")
	defer os.Unsetenv(key)

	result = getEnvOrDefault(key, "default_val")
	if result != "overridden" {
		t.Errorf("expected overridden, got %s", result)
	}
}

// ==============================
// authenticateRequest edge cases
// ==============================

func TestCB14_AuthenticateRequest_NoAuth(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/test", nil)
	_, _, err := authenticateRequest(req)
	if err == nil {
		t.Error("expected error for no auth")
	}
}

func TestCB14_AuthenticateRequest_InvalidJWT(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/test", nil)
	req.Header.Set("Authorization", "Bearer invalid_token_here")
	_, _, err := authenticateRequest(req)
	if err == nil {
		t.Error("expected error for invalid JWT")
	}
}

func TestCB14_AuthenticateRequest_AgentNoID(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/test", nil)
	req.Header.Set("X-Agent-Secret", getAgentSecret())
	// No X-Agent-ID header
	_, _, err := authenticateRequest(req)
	if err == nil {
		t.Error("expected error for agent auth without ID")
	}
}

func TestCB14_AuthenticateRequest_ValidAgent(t *testing.T) {
	cb14SetupDB(t)
	cb14CreateAgent(t, "cb14_auth_agent")

	req := httptest.NewRequest(http.MethodPost, "/test", nil)
	req.Header.Set("X-Agent-Secret", getAgentSecret())
	req.Header.Set("X-Agent-ID", "cb14_auth_agent")
	id, idType, err := authenticateRequest(req)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if id != "cb14_auth_agent" {
		t.Errorf("expected agent ID cb14_auth_agent, got %s", id)
	}
	if idType != "agent" {
		t.Errorf("expected type agent, got %s", idType)
	}
}

// ==============================
// HTTP method check tests
// ==============================

func TestCB14_ChangePassword_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/auth/change-password", nil)
	w := httptest.NewRecorder()
	handleChangePassword(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405 for GET, got %d", w.Code)
	}
}

func TestCB14_DeleteConversation_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/conversations/delete", nil)
	w := httptest.NewRecorder()
	handleDeleteConversation(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405 for POST to delete endpoint, got %d", w.Code)
	}
}

func TestCB14_SearchMessages_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/messages/search", nil)
	w := httptest.NewRecorder()
	handleSearchMessages(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405 for POST, got %d", w.Code)
	}
}

func TestCB14_MarkRead_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/conversations/mark-read", nil)
	w := httptest.NewRecorder()
	handleMarkRead(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405 for GET, got %d", w.Code)
	}
}

func TestCB14_CreateConversation_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/conversations/create", nil)
	w := httptest.NewRecorder()
	handleCreateConversation(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405 for GET, got %d", w.Code)
	}
}

func TestCB14_ListConversations_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/conversations/list", nil)
	w := httptest.NewRecorder()
	handleListConversations(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405 for POST, got %d", w.Code)
	}
}

func TestCB14_ListConversations_NoAuth(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/conversations/list", nil)
	w := httptest.NewRecorder()
	handleListConversations(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for no auth, got %d", w.Code)
	}
}

func TestCB14_ListConversations_InvalidToken(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/conversations/list", nil)
	req.Header.Set("Authorization", "Bearer invalid_token")
	w := httptest.NewRecorder()
	handleListConversations(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for invalid token, got %d", w.Code)
	}
}

func TestCB14_GetMessages_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/conversations/messages", nil)
	w := httptest.NewRecorder()
	handleGetMessages(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405 for POST, got %d", w.Code)
	}
}

func TestCB14_GetMessages_NoAuth(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/conversations/messages?conversation_id=conv1", nil)
	w := httptest.NewRecorder()
	handleGetMessages(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for no auth, got %d", w.Code)
	}
}

func TestCB14_GetMessages_MissingConvID(t *testing.T) {
	cb14SetupDB(t)
	token := cb14MakeToken(t, "cb14_msg_u")

	req := httptest.NewRequest(http.MethodGet, "/conversations/messages", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleGetMessages(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing conversation_id, got %d", w.Code)
	}
}

func TestCB14_GetMessages_NotFound(t *testing.T) {
	cb14SetupDB(t)
	token := cb14MakeToken(t, "cb14_msg_u2")

	req := httptest.NewRequest(http.MethodGet, "/conversations/messages?conversation_id=nonexistent", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleGetMessages(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404 for nonexistent conversation, got %d", w.Code)
	}
}

// ==============================
// handleLogin edge cases
// ==============================

func TestCB14_Login_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/auth/login", nil)
	w := httptest.NewRecorder()
	handleLogin(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405 for GET, got %d", w.Code)
	}
}

func TestCB14_Login_MissingFields(t *testing.T) {
	cb14SetupDB(t)

	form := url.Values{}
	form.Set("username", "")
	form.Set("password", "")
	req := httptest.NewRequest(http.MethodPost, "/auth/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handleLogin(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing fields, got %d", w.Code)
	}
}

// ==============================
// handleHealth coverage
// ==============================

func TestCB14_Health_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/health", nil)
	w := httptest.NewRecorder()
	handleHealth(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405 for POST, got %d", w.Code)
	}
}

// ==============================
// handleListAgents method check
// ==============================

func TestCB14_ListAgents_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/agents", nil)
	w := httptest.NewRecorder()
	handleListAgents(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405 for POST, got %d", w.Code)
	}
}

func TestCB14_ListAgents_Valid(t *testing.T) {
	cb14SetupDB(t)
	cb14SetupHub(t)
	cb14CreateAgent(t, "cb14_agent_list_1")
	cb14CreateAgent(t, "cb14_agent_list_2")

	req := httptest.NewRequest(http.MethodGet, "/agents", nil)
	w := httptest.NewRecorder()
	handleListAgents(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var agents []map[string]interface{}
	json.NewDecoder(w.Body).Decode(&agents)
	if len(agents) != 2 {
		t.Errorf("expected 2 agents, got %d", len(agents))
	}
}

// ==============================
// handleAdminAgents
// ==============================

func TestCB14_AdminAgents_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/admin/agents", nil)
	w := httptest.NewRecorder()
	handleAdminAgents(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405 for POST, got %d", w.Code)
	}
}

func TestCB14_AdminAgents_Valid(t *testing.T) {
	cb14SetupDB(t)
	cb14SetupHub(t)
	cb14CreateAgent(t, "cb14_admin_agent_1")

	req := httptest.NewRequest(http.MethodGet, "/admin/agents", nil)
	w := httptest.NewRecorder()
	handleAdminAgents(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var agents []map[string]interface{}
	json.NewDecoder(w.Body).Decode(&agents)
	if len(agents) != 1 {
		t.Errorf("expected 1 agent, got %d", len(agents))
	}
}

// ==============================
// Message edit/delete edge cases
// ==============================

func TestCB14_MessageEdit_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/messages/edit", nil)
	w := httptest.NewRecorder()
	handleMessageEdit(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405 for GET on edit, got %d", w.Code)
	}
}

func TestCB14_MessageDelete_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/messages/delete", nil)
	w := httptest.NewRecorder()
	handleMessageDelete(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405 for GET on delete, got %d", w.Code)
	}
}

func TestCB14_MessageDelete_Valid(t *testing.T) {
	cb14SetupDB(t)
	token, convID := cb14CreateConv(t, "cb14_del_u", "cb14_del_a")

	// Create a message
	db.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, metadata, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
		"msg_del_test", convID, "client", "cb14_del_u", "message to delete", "{}", time.Now().UTC())

	form := url.Values{}
	form.Set("message_id", "msg_del_test")
	req := httptest.NewRequest(http.MethodPost, "/messages/delete", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleMessageDelete(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200 for valid delete, got %d: %s", w.Code, w.Body.String())
	}

	// Verify message is soft-deleted
	var isDeleted bool
	db.QueryRow("SELECT COALESCE(is_deleted, 0) FROM messages WHERE id = ?", "msg_del_test").Scan(&isDeleted)
	if !isDeleted {
		t.Error("expected message to be soft-deleted")
	}
}

func TestCB14_MessageDelete_AlreadyDeleted(t *testing.T) {
	cb14SetupDB(t)
	token, convID := cb14CreateConv(t, "cb14_del_u2", "cb14_del_a2")

	// Create and soft-delete a message
	db.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, metadata, created_at, is_deleted) VALUES (?, ?, ?, ?, ?, ?, ?, 1)",
		"msg_del_already", convID, "client", "cb14_del_u2", "already deleted", "{}", time.Now().UTC())

	form := url.Values{}
	form.Set("message_id", "msg_del_already")
	req := httptest.NewRequest(http.MethodPost, "/messages/delete", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleMessageDelete(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for already deleted, got %d", w.Code)
	}
}

func TestCB14_MessageDelete_NotFound(t *testing.T) {
	cb14SetupDB(t)
	token := cb14MakeToken(t, "cb14_del_u3")

	form := url.Values{}
	form.Set("message_id", "nonexistent_msg")
	req := httptest.NewRequest(http.MethodPost, "/messages/delete", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleMessageDelete(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404 for nonexistent message, got %d", w.Code)
	}
}

// ==============================
// Reactions handlers
// ==============================

func TestCB14_AddReaction_DB(t *testing.T) {
	cb14SetupDB(t)
	_, convID := cb14CreateConv(t, "cb14_react_u", "cb14_react_a")

	// Create a message to react to
	db.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, metadata, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
		"msg_react1", convID, "agent", "cb14_react_a", "hello", "{}", time.Now().UTC())

	_, added, err := addReaction("msg_react1", "cb14_react_u", "👍")
	if err != nil {
		t.Errorf("unexpected error adding reaction: %v", err)
	}
	if !added {
		t.Error("expected reaction to be added (new)")
	}
}

func TestCB14_RemoveReaction_DB(t *testing.T) {
	cb14SetupDB(t)
	_, convID := cb14CreateConv(t, "cb14_react_u2", "cb14_react_a2")

	// Create a message
	db.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, metadata, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
		"msg_react2", convID, "agent", "cb14_react_a2", "hello", "{}", time.Now().UTC())

	// First add a reaction
	_, added, err := addReaction("msg_react2", "cb14_react_u2", "\U0001f44d")
	if err != nil {
		t.Fatalf("unexpected error adding reaction: %v", err)
	}
	if !added {
		t.Error("expected reaction to be added (new)")
	}

	// Toggle: same user+emoji removes the reaction
	_, added, err = addReaction("msg_react2", "cb14_react_u2", "\U0001f44d")
	if err != nil {
		t.Errorf("unexpected error toggling reaction: %v", err)
	}
	if added {
		t.Error("expected reaction to be removed (toggle off)")
	}

	// Verify reaction is gone
	reactions, err := getMessageReactions("msg_react2")
	if err != nil {
		t.Errorf("unexpected error getting reactions: %v", err)
	}
	if len(reactions) != 0 {
		t.Errorf("expected 0 reactions after toggle off, got %d", len(reactions))
	}
}

func TestCB14_GetReactions_DB(t *testing.T) {
	cb14SetupDB(t)
	_, convID := cb14CreateConv(t, "cb14_react_u3", "cb14_react_a3")

	// Create a message
	db.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, metadata, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
		"msg_react3", convID, "agent", "cb14_react_a3", "hello", "{}", time.Now().UTC())

	addReaction("msg_react3", "cb14_react_u3", "\U0001f44d")
	// Note: other_user is not a conversation participant, so addReaction will fail auth check
	addReaction("msg_react3", "cb14_react_a3", "\U0001f604")

	reactions, err := getMessageReactions("msg_react3")
	if err != nil {
		t.Errorf("unexpected error getting reactions: %v", err)
	}
	if len(reactions) < 1 {
		t.Errorf("expected at least 1 reaction, got %d", len(reactions))
	}
}

// ==============================
// Conversation tags
// ==============================

func TestCB14_AddConversationTag(t *testing.T) {
	cb14SetupDB(t)
	_, convID := cb14CreateConv(t, "cb14_tag_u", "cb14_tag_a")

	_, err := addConversationTag(convID, "cb14_tag_u", "important")
	if err != nil {
		t.Errorf("unexpected error adding tag: %v", err)
	}

	tags, err := getConversationTags(convID)
	if err != nil {
		t.Errorf("unexpected error getting tags: %v", err)
	}
	if len(tags) != 1 || tags[0].Tag != "important" {
		t.Errorf("expected 1 tag 'important', got %v", tags)
	}
}

func TestCB14_RemoveConversationTag(t *testing.T) {
	cb14SetupDB(t)
	_, convID := cb14CreateConv(t, "cb14_tag_u2", "cb14_tag_a2")

	addConversationTag(convID, "cb14_tag_u2", "todo")
	addConversationTag(convID, "cb14_tag_u2", "urgent")

	err := removeConversationTag(convID, "cb14_tag_u2", "todo")
	if err != nil {
		t.Errorf("unexpected error removing tag: %v", err)
	}

	tags, _ := getConversationTags(convID)
	if len(tags) != 1 || tags[0].Tag != "urgent" {
		t.Errorf("expected [urgent], got %v", tags)
	}
}

func TestCB14_GetConversationTags_Empty(t *testing.T) {
	cb14SetupDB(t)
	_, convID := cb14CreateConv(t, "cb14_tag_u3", "cb14_tag_a3")

	tags, err := getConversationTags(convID)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if len(tags) != 0 {
		t.Errorf("expected 0 tags for new conversation, got %d", len(tags))
	}
}

// ==============================
// StoreMessagesBatch
// ==============================

func TestCB14_StoreMessagesBatch_Empty(t *testing.T) {
	cb14SetupDB(t)

	ids, err := storeMessagesBatch(nil)
	if err != nil {
		t.Errorf("unexpected error for nil batch: %v", err)
	}
	if ids != nil {
		t.Errorf("expected nil for empty batch, got %v", ids)
	}
}

func TestCB14_StoreMessagesBatch_Valid(t *testing.T) {
	cb14SetupDB(t)
	_, convID := cb14CreateConv(t, "cb14_batch_u", "cb14_batch_a")

	msgs := []RoutedMessage{
		{
			Type:           "message",
			ConversationID: convID,
			Content:        "batch message 1",
			SenderType:     "client",
			SenderID:       "cb14_batch_u",
		},
		{
			Type:           "message",
			ConversationID: convID,
			Content:        "batch message 2",
			SenderType:     "agent",
			SenderID:       "cb14_batch_a",
		},
	}

	ids, err := storeMessagesBatch(msgs)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if len(ids) != 2 {
		t.Errorf("expected 2 IDs, got %d", len(ids))
	}

	// Verify messages are stored
	var count int
	db.QueryRow("SELECT COUNT(*) FROM messages WHERE conversation_id = ?", convID).Scan(&count)
	if count != 2 {
		t.Errorf("expected 2 messages, got %d", count)
	}
}

// ==============================
// Middleware tests
// ==============================

func TestCB14_ExtractIP(t *testing.T) {
	tests := []struct {
		name       string
		forwarded  string
		realIP     string
		remote     string
		expected   string
	}{
		{"X-Forwarded-For", "1.2.3.4, 5.6.7.8", "", "9.9.9.9:1234", "1.2.3.4"},
		{"X-Real-IP", "", "10.0.0.1", "9.9.9.9:1234", "10.0.0.1"},
		{"RemoteAddr only", "", "", "192.168.1.1:5678", "192.168.1.1"},
		{"X-Forwarded-For priority", "3.4.5.6", "7.8.9.0", "1.2.3.4:80", "3.4.5.6"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			if tt.forwarded != "" {
				req.Header.Set("X-Forwarded-For", tt.forwarded)
			}
			if tt.realIP != "" {
				req.Header.Set("X-Real-IP", tt.realIP)
			}
			req.RemoteAddr = tt.remote

			ip := extractIP(req)
			if ip != tt.expected {
				t.Errorf("expected %s, got %s", tt.expected, ip)
			}
		})
	}
}

func TestCB14_ValidateAdminSecret(t *testing.T) {
	origSecret := adminSecret
	adminSecret = "test_admin_123"
	defer func() { adminSecret = origSecret }()

	err := ValidateAdminSecret("test_admin_123")
	if err != nil {
		t.Errorf("expected nil error for valid secret, got %v", err)
	}

	err = ValidateAdminSecret("wrong_secret")
	if err == nil {
		t.Error("expected error for wrong secret")
	}

	err = ValidateAdminSecret("")
	if err == nil {
		t.Error("expected error for empty secret")
	}
}

// ==============================
// Context cancellation for tracing
// ==============================

func TestCB14_InitTracing_DisabledByDefault(t *testing.T) {
	os.Unsetenv("OTEL_ENABLED")
	os.Unsetenv("OTEL_EXPORTER_OTLP_ENDPOINT")

	InitTracing()

	if IsTracingEnabled() {
		t.Error("expected tracing to be disabled by default")
	}
}

func TestCB14_ShutdownTracing(t *testing.T) {
	// Should not panic even when tracing is not initialized
	ShutdownTracing()
}

// ==============================
// writeJSONResponse helper
// ==============================

func TestCB14_WriteJSONResponse(t *testing.T) {
	w := httptest.NewRecorder()
	writeJSONResponse(w, http.StatusOK, map[string]string{"status": "ok"})

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}

	var resp map[string]string
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["status"] != "ok" {
		t.Errorf("expected status=ok, got %v", resp["status"])
	}
}

// ==============================
// Connection struct tests
// ==============================

func TestCB14_Connection_IsClosed(t *testing.T) {
	c := &Connection{
		send: make(chan []byte, 256),
	}

	if c.IsClosed() {
		t.Error("expected connection to not be closed initially")
	}

	c.MarkClosed()
	if !c.IsClosed() {
		t.Error("expected connection to be closed after MarkClosed")
	}
}

func TestCB14_Connection_SafeSend(t *testing.T) {
	c := &Connection{
		send: make(chan []byte, 4),
	}

	result := c.SafeSend([]byte("test"))
	if !result {
		t.Error("expected SafeSend to succeed on open channel")
	}

	c.MarkClosed()
	close(c.send)
	result = c.SafeSend([]byte("test2"))
	if result {
		t.Error("expected SafeSend to fail on closed channel")
	}
}

// ==============================
// openDatabase with SQLite
// ==============================

func TestCB14_OpenDatabase_SQLite(t *testing.T) {
	db2, err := openDatabase("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("failed to open SQLite: %v", err)
	}
	defer db2.Close()

	// Verify it's functional
	if err := db2.Ping(); err != nil {
		t.Errorf("failed to ping: %v", err)
	}
}

// ==============================
// RoutedMessage struct
// ==============================

func TestCB14_RoutedMessage_Fields(t *testing.T) {
	msg := RoutedMessage{
		Type:           "message",
		ConversationID: "conv1",
		Content:        "hello",
		SenderType:     "client",
		SenderID:       "user1",
		RecipientID:    "agent1",
		AttachmentIDs:  []string{"att1", "att2"},
	}

	if msg.Type != "message" {
		t.Errorf("expected type message, got %s", msg.Type)
	}
	if len(msg.AttachmentIDs) != 2 {
		t.Errorf("expected 2 attachments, got %d", len(msg.AttachmentIDs))
	}
}

// ==============================
// Agent status test
// ==============================

func TestCB14_AgentStatus_Offline(t *testing.T) {
	cb14SetupDB(t)
	cb14SetupHub(t)
	testHub := newHub()

	status := testHub.AgentStatus("nonexistent_agent")
	if status != "offline" {
		t.Errorf("expected offline for nonexistent agent, got %s", status)
	}
}

// ==============================
// loadQueueFromDB edge cases
// ==============================

func TestCB14_LoadQueueFromDB_Empty(t *testing.T) {
	cb14SetupDB(t)
	initQueueDB(db)

	q := newOfflineQueue(100, 7*24*time.Hour)
	loadQueueFromDB(db, q)

	// Should not panic with empty DB
	if q.TotalDepth() != 0 {
		t.Errorf("expected 0 depth from empty DB, got %d", q.TotalDepth())
	}
}

func TestCB14_LoadQueueFromDB_WithMessages(t *testing.T) {
	cb14SetupDB(t)
	initQueueDB(db)

	// Insert a message directly
	msgData2 := map[string]interface{}{
		"conversation_id": "conv1",
		"content":        "test message",
		"sender_type":     "agent",
		"sender_id":       "agent1",
	}
	data := marshalOutgoingMessage(OutgoingMessage{Type: "message", Data: msgData2})
	persistQueue(db, "user_load1", data)

	q := newOfflineQueue(100, 7*24*time.Hour)
	loadQueueFromDB(db, q)

	// Should have loaded the message
	if q.TotalDepth() != 1 {
		t.Errorf("expected depth 1, got %d", q.TotalDepth())
	}
}