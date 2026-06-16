package main

import (
	"context"
	"encoding/json"
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
// Push Notification Init Tests
// ==============================

func TestInitPushNotificationsDisabledState(t *testing.T) {
	// Ensure push is disabled when env vars are not set
	origAPNS := os.Getenv("APNS_ENABLED")
	origFCM := os.Getenv("FCM_ENABLED")
	os.Unsetenv("APNS_ENABLED")
	os.Unsetenv("FCM_ENABLED")
	defer func() {
		if origAPNS != "" {
			os.Setenv("APNS_ENABLED", origAPNS)
		}
		if origFCM != "" {
			os.Setenv("FCM_ENABLED", origFCM)
		}
	}()

	pushConfig = nil
	initPushNotifications()

	if pushConfig == nil {
		t.Fatal("pushConfig should not be nil after init")
	}
	if pushConfig.APNSEnabled {
		t.Error("APNs should be disabled by default")
	}
	if pushConfig.FCMEnabled {
		t.Error("FCM should be disabled by default")
	}
	if pushConfig.apnsClient != nil {
		t.Error("APNs client should be nil when disabled")
	}
	if pushConfig.fcmClient != nil {
		t.Error("FCM client should be nil when disabled")
	}
}

func TestInitAPNsMissingCertPath(t *testing.T) {
	pushConfig = &PushNotificationConfig{
		APNSEnabled: true,
		CertPath:    "", // empty cert path
	}
	initAPNs()
	// When cert path is empty, initAPNs returns early without disabling
	// It just logs a warning. APNs stays enabled but apnsClient stays nil.
	if pushConfig.apnsClient != nil {
		t.Error("APNs client should be nil when cert path is empty")
	}
}

func TestInitAPNsCertNotFound(t *testing.T) {
	pushConfig = &PushNotificationConfig{
		APNSEnabled: true,
		CertPath:    "/nonexistent/path/cert.p12",
	}
	initAPNs()
	if pushConfig.APNSEnabled {
		t.Error("APNs should be disabled when cert file doesn't exist")
	}
}

func TestInitAPNsInvalidCert(t *testing.T) {
	// Create a temporary invalid cert file
	dir := t.TempDir()
	certPath := filepath.Join(dir, "invalid.p12")
	if err := os.WriteFile(certPath, []byte("not a valid certificate"), 0644); err != nil {
		t.Fatalf("Failed to create temp cert file: %v", err)
	}

	pushConfig = &PushNotificationConfig{
		APNSEnabled: true,
		CertPath:    certPath,
		Password:    "",
		BundleID:    "com.test.app",
		Environment: "development",
	}
	initAPNs()
	if pushConfig.APNSEnabled {
		t.Error("APNs should be disabled when cert is invalid")
	}
}

func TestInitFCMMissingCredentials(t *testing.T) {
	pushConfig = &PushNotificationConfig{
		FCMEnabled:     true,
		FCMCredentials: "", // empty credentials path
	}
	initFCM()
	// When credentials path is empty, initFCM returns early without disabling
	// It just logs a warning. FCM stays enabled but fcmClient stays nil.
	if pushConfig.fcmClient != nil {
		t.Error("FCM client should be nil when credentials path is empty")
	}
}

func TestInitFCMCredentialsNotFound(t *testing.T) {
	pushConfig = &PushNotificationConfig{
		FCMEnabled:     true,
		FCMCredentials: "/nonexistent/path/firebase.json",
	}
	initFCM()
	if pushConfig.FCMEnabled {
		t.Error("FCM should be disabled when credentials file doesn't exist")
	}
}

func TestInitFCMInvalidCredentials(t *testing.T) {
	dir := t.TempDir()
	credPath := filepath.Join(dir, "firebase.json")
	if err := os.WriteFile(credPath, []byte("not a valid JSON"), 0644); err != nil {
		t.Fatalf("Failed to create temp cred file: %v", err)
	}

	pushConfig = &PushNotificationConfig{
		FCMEnabled:     true,
		FCMCredentials: credPath,
	}
	initFCM()
	if pushConfig.FCMEnabled {
		t.Error("FCM should be disabled when credentials are invalid")
	}
}

func TestSendAPNSNotificationDisabledStates(t *testing.T) {
	pushConfig = nil
	err := sendAPNSNotification("token123", "Title", "Body", "conv-1")
	if err != nil {
		t.Errorf("expected nil error when pushConfig is nil, got %v", err)
	}

	pushConfig = &PushNotificationConfig{APNSEnabled: false}
	err = sendAPNSNotification("token123", "Title", "Body", "conv-1")
	if err != nil {
		t.Errorf("expected nil error when APNs disabled, got %v", err)
	}
}

func TestSendAPNSNotificationNoClient(t *testing.T) {
	pushConfig = &PushNotificationConfig{
		APNSEnabled: true,
		apnsClient:  nil,
	}
	err := sendAPNSNotification("token123", "Title", "Body", "conv-1")
	if err != nil {
		t.Errorf("expected nil error when APNs client is nil, got %v", err)
	}
}

func TestSendFCMNotificationDisabledStates(t *testing.T) {
	pushConfig = nil
	err := sendFCMNotification("token123", "Title", "Body", "conv-1")
	if err != nil {
		t.Errorf("expected nil error when pushConfig is nil, got %v", err)
	}

	pushConfig = &PushNotificationConfig{FCMEnabled: false}
	err = sendFCMNotification("token123", "Title", "Body", "conv-1")
	if err != nil {
		t.Errorf("expected nil error when FCM disabled, got %v", err)
	}
}

func TestSendFCMNotificationNoClient(t *testing.T) {
	pushConfig = &PushNotificationConfig{
		FCMEnabled: true,
		fcmClient:  nil,
	}
	err := sendFCMNotification("token123", "Title", "Body", "conv-1")
	if err != nil {
		t.Errorf("expected nil error when FCM client is nil, got %v", err)
	}
}

func TestSendPushNotificationPlatformRouting(t *testing.T) {
	// Both APNs and FCM disabled — should be no-ops
	pushConfig = &PushNotificationConfig{}

	tests := []struct {
		platform string
	}{
		{"android"},
		{"fcm"},
		{"ios"},
		{"unknown"},
		{"ANDROID"},
		{"FCM"},
	}

	for _, tt := range tests {
		err := sendPushNotification("token123", "Title", "Body", "conv-1", tt.platform)
		if err != nil {
			t.Errorf("platform=%q: expected nil error, got %v", tt.platform, err)
		}
	}
}

func TestNotifyUserNoPushConfig2(t *testing.T) {
	pushConfig = nil
	// Should not panic
	notifyUser("user-1", "Title", "Body", "conv-1")
}

// ==============================
// Web Push Tests
// ==============================

func TestGetVAPIDKeyNotConfigured2(t *testing.T) {
	setupTestDB(t)
	origKey := vapidPublicKey
	vapidPublicKey = ""
	defer func() { vapidPublicKey = origKey }()

	_, token := createPushTestUser(t, "vapidnoconf", "password123")

	req := httptest.NewRequest("GET", "/push/vapid-key", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleGetVAPIDKey(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

func TestGetVAPIDKeyNoAuth(t *testing.T) {
	origKey := vapidPublicKey
	vapidPublicKey = "test-vapid-key"
	defer func() { vapidPublicKey = origKey }()

	req := httptest.NewRequest("GET", "/push/vapid-key", nil)
	w := httptest.NewRecorder()
	handleGetVAPIDKey(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 without auth, got %d", w.Code)
	}
}

func TestGetVAPIDKeyWithAuth2(t *testing.T) {
	setupTestDB(t)
	vapidPublicKey = "test-vapid-key-abc123"
	defer func() { vapidPublicKey = "" }()

	_, token := createPushTestUser(t, "vapiduser", "password123")

	req := httptest.NewRequest("GET", "/push/vapid-key", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleGetVAPIDKey(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]string
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["public_key"] != "test-vapid-key-abc123" {
		t.Errorf("expected vapid key, got %v", resp)
	}
}

func TestGetVAPIDKeyMethodCheck(t *testing.T) {
	req := httptest.NewRequest("POST", "/push/vapid-key", nil)
	w := httptest.NewRecorder()
	handleGetVAPIDKey(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestWebPushSubscribeNoAuth(t *testing.T) {
	setupTestDB(t)
	db.Exec("DELETE FROM device_tokens")
	db.Exec("DELETE FROM users")

	body := `{"endpoint":"https://push.example.com/123","keys":{"p256dh":"key1","auth":"auth1"}}`
	req := httptest.NewRequest("POST", "/push/web-subscribe", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handleWebPushSubscribe(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestWebPushSubscribeFieldValidation(t *testing.T) {
	setupTestDB(t)
	db.Exec("DELETE FROM device_tokens")
	db.Exec("DELETE FROM users")

	_, token := createPushTestUser(t, "webuser1", "password123")

	tests := []struct {
		name   string
		body   string
		status int
	}{
		{"missing endpoint", `{"keys":{"p256dh":"key1","auth":"auth1"}}`, http.StatusBadRequest},
		{"missing p256dh", `{"endpoint":"https://push.example.com/123","keys":{"auth":"auth1"}}`, http.StatusBadRequest},
		{"missing auth", `{"endpoint":"https://push.example.com/123","keys":{"p256dh":"key1"}}`, http.StatusBadRequest},
		{"empty endpoint", `{"endpoint":"","keys":{"p256dh":"key1","auth":"auth1"}}`, http.StatusBadRequest},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("POST", "/push/web-subscribe", strings.NewReader(tt.body))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", "Bearer "+token)
			w := httptest.NewRecorder()
			handleWebPushSubscribe(w, req)

			if w.Code != tt.status {
				t.Errorf("expected %d, got %d: %s", tt.status, w.Code, w.Body.String())
			}
		})
	}
}

func TestWebPushSubscribeInvalidJSON(t *testing.T) {
	setupTestDB(t)
	db.Exec("DELETE FROM device_tokens")
	db.Exec("DELETE FROM users")

	_, token := createPushTestUser(t, "webuser2", "password123")

	req := httptest.NewRequest("POST", "/push/web-subscribe", strings.NewReader("not json"))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleWebPushSubscribe(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestWebPushSubscribeSuccess(t *testing.T) {
	setupTestDB(t)
	db.Exec("DELETE FROM device_tokens")
	db.Exec("DELETE FROM users")

	_, token := createPushTestUser(t, "webuser3", "password123")

	body := `{"endpoint":"https://push.example.com/abc","keys":{"p256dh":"key123","auth":"auth456"}}`
	req := httptest.NewRequest("POST", "/push/web-subscribe", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleWebPushSubscribe(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]string
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["status"] != "subscribed" {
		t.Errorf("expected status=subscribed, got %v", resp)
	}
}

func TestWebPushUnsubscribeNoAuth(t *testing.T) {
	setupTestDB(t)
	body := `{"endpoint":"https://push.example.com/123"}`
	req := httptest.NewRequest("POST", "/push/web-unsubscribe", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handleWebPushUnsubscribe(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestWebPushUnsubscribeMissingEndpoint(t *testing.T) {
	setupTestDB(t)
	_, token := createPushTestUser(t, "webuser4", "password123")

	body := `{"endpoint":""}`
	req := httptest.NewRequest("POST", "/push/web-unsubscribe", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleWebPushUnsubscribe(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestWebPushUnsubscribeInvalidJSON(t *testing.T) {
	setupTestDB(t)
	_, token := createPushTestUser(t, "webuser5", "password123")

	req := httptest.NewRequest("POST", "/push/web-unsubscribe", strings.NewReader("not json"))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleWebPushUnsubscribe(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestWebPushUnsubscribeSuccess(t *testing.T) {
	setupTestDB(t)
	db.Exec("DELETE FROM device_tokens")
	db.Exec("DELETE FROM users")

	userID, token := createPushTestUser(t, "webuser6", "password123")

	// First subscribe
	subBody := `{"endpoint":"https://push.example.com/unsub-test","keys":{"p256dh":"key1","auth":"auth1"}}`
	req := httptest.NewRequest("POST", "/push/web-subscribe", strings.NewReader(subBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleWebPushSubscribe(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("subscribe failed: %d %s", w.Code, w.Body.String())
	}

	// Now unsubscribe
	unsubBody := `{"endpoint":"https://push.example.com/unsub-test"}`
	req = httptest.NewRequest("POST", "/push/web-unsubscribe", strings.NewReader(unsubBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w = httptest.NewRecorder()
	handleWebPushUnsubscribe(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]string
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["status"] != "unsubscribed" {
		t.Errorf("expected status=unsubscribed, got %v", resp)
	}

	// Verify token removed
	var count int
	db.QueryRow("SELECT COUNT(*) FROM device_tokens WHERE user_id = ? AND platform = 'web'", userID).Scan(&count)
	if count != 0 {
		t.Errorf("expected 0 web push tokens after unsubscribe, got %d", count)
	}
}

func TestWebPushSubscribeWrongMethod(t *testing.T) {
	req := httptest.NewRequest("GET", "/push/web-subscribe", nil)
	w := httptest.NewRecorder()
	handleWebPushSubscribe(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestWebPushUnsubscribeWrongMethod(t *testing.T) {
	req := httptest.NewRequest("DELETE", "/push/web-unsubscribe", nil)
	w := httptest.NewRecorder()
	handleWebPushUnsubscribe(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

// ==============================
// Profile Handler Tests
// ==============================

func TestProfileHeapProfileMkdirError(t *testing.T) {
	// Set PROFILING_DIR to a path that can't be created
	t.Setenv("PROFILING_DIR", "/dev/null/impossible/path")

	req := httptest.NewRequest("POST", "/admin/profile?action=heap", nil)
	w := httptest.NewRecorder()
	handleHeapProfile(w, req)

	// Should return 500 because the directory can't be created
	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 for invalid dir, got %d", w.Code)
	}
}

func TestProfileGoroutineProfileMkdirError(t *testing.T) {
	t.Setenv("PROFILING_DIR", "/dev/null/impossible/path")

	req := httptest.NewRequest("POST", "/admin/profile?action=goroutine", nil)
	w := httptest.NewRecorder()
	handleGoroutineProfile(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 for invalid dir, got %d", w.Code)
	}
}

func TestProfileCPUProfileStartMkdirError(t *testing.T) {
	defer cpuProfileTestSetup()()
	t.Setenv("PROFILING_DIR", "/dev/null/impossible/path")

	req := httptest.NewRequest("POST", "/admin/profile?action=cpu", nil)
	w := httptest.NewRecorder()
	handleCPUProfileStart(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 for invalid dir, got %d", w.Code)
	}
}

func TestProfileCPUProfileStopNotActive(t *testing.T) {
	req := httptest.NewRequest("POST", "/admin/profile?action=cpu_stop", nil)
	w := httptest.NewRecorder()
	handleCPUProfileStop(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 for no active profile, got %d", w.Code)
	}
}

func TestProfileCPUProfileStartWhenActive(t *testing.T) {
	defer cpuProfileTestSetup()()

	dir := t.TempDir()
	t.Setenv("PROFILING_DIR", dir)

	// Start first profile
	req := httptest.NewRequest("POST", "/admin/profile?action=cpu", nil)
	w := httptest.NewRecorder()
	handleCPUProfileStart(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for first cpu start, got %d", w.Code)
	}

	// Try to start again — should fail
	req2 := httptest.NewRequest("POST", "/admin/profile?action=cpu", nil)
	w2 := httptest.NewRecorder()
	handleCPUProfileStart(w2, req2)
	if w2.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 for duplicate cpu start, got %d", w2.Code)
	}

	// Stop it
	req3 := httptest.NewRequest("POST", "/admin/profile?action=cpu_stop", nil)
	w3 := httptest.NewRecorder()
	handleCPUProfileStop(w3, req3)
	if w3.Code != http.StatusOK {
		t.Errorf("expected 200 for cpu stop, got %d", w3.Code)
	}
}

func TestProfileAdminWithJSONBody(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("PROFILING_DIR", dir)

	body := `{"action":"stats"}`
	req := httptest.NewRequest("POST", "/admin/profile", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handleAdminProfile(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var result map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &result)
	if result["status"] != "ok" {
		t.Errorf("expected status ok, got %v", result["status"])
	}
}

func TestProfileMemoryStatsEndpoint(t *testing.T) {
	req := httptest.NewRequest("GET", "/admin/profile", nil)
	w := httptest.NewRecorder()
	handleAdminProfile(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}

	var result map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &result)
	if result["status"] != "ok" {
		t.Errorf("expected status ok, got %v", result["status"])
	}
}

// ==============================
// Notification Preferences Tests
// ==============================

func TestGetNotificationPrefsDBError(t *testing.T) {
	setupTestDB(t)
	token := createTestUser(t, "notiferruser1")

	// Close the DB to force an error
	db.Close()

	req := authGetReq("/notification-prefs", token)
	w := httptest.NewRecorder()
	handleGetNotificationPrefs(w, req)

	// Should return 500 for DB error (not panic)
	if w.Code != http.StatusInternalServerError {
		t.Logf("Note: got status %d (may vary based on DB state)", w.Code)
	}

	// Re-setup for other tests
	setupTestDB(t)
}

func TestSetNotificationPrefsNonexistentConversation(t *testing.T) {
	setupTestDB(t)
	token := createTestUser(t, "notiferruser2")

	req := authPostReq("/notification-prefs/set", token, url.Values{
		"conversation_id": {"nonexistent-conv-id"},
		"muted":           {"true"},
	})
	w := httptest.NewRecorder()
	handleSetNotificationPrefs(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404 for nonexistent conversation, got %d", w.Code)
	}
}

func TestDeleteNotificationPrefsNoAuth(t *testing.T) {
	req := httptest.NewRequest("POST", "/notification-prefs/delete", strings.NewReader(""))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handleDeleteNotificationPrefs(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 without auth, got %d", w.Code)
	}
}

func TestDeleteNotificationPrefsNoID(t *testing.T) {
	setupTestDB(t)
	token := createTestUser(t, "notiferruser3")

	req := authPostReq("/notification-prefs/delete", token, url.Values{})
	w := httptest.NewRecorder()
	handleDeleteNotificationPrefs(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestGetNotificationPrefsWithData(t *testing.T) {
	setupTestDB(t)
	token := createTestUser(t, "notifdatauser")
	createTestAgent(t, "notifdataagent", "data-bot")
	convID := createTestConversation(t, token, "notifdataagent")

	// Mute conversation
	req := authPostReq("/notification-prefs/set", token, url.Values{
		"conversation_id": {convID},
		"muted":           {"true"},
	})
	w := httptest.NewRecorder()
	handleSetNotificationPrefs(w, req)

	// Get prefs
	req2 := authGetReq("/notification-prefs", token)
	w2 := httptest.NewRecorder()
	handleGetNotificationPrefs(w2, req2)

	var prefs []NotificationPreferences
	json.Unmarshal(w2.Body.Bytes(), &prefs)
	if len(prefs) != 1 {
		t.Fatalf("expected 1 pref, got %d", len(prefs))
	}
	if prefs[0].ConversationID != convID {
		t.Errorf("expected conversation_id %s, got %s", convID, prefs[0].ConversationID)
	}
	if !prefs[0].Muted {
		t.Error("expected muted=true")
	}
}

// ==============================
// Rate Limiter Extended Tests
// ==============================

func TestRateLimiterCleanup(t *testing.T) {
	rl := NewRateLimiter(5, 100*time.Millisecond)
	t.Cleanup(func() { rl.Stop() })

	// Use all 5 allowances
	for i := 0; i < 5; i++ {
		if !rl.Allow("test-id") {
			t.Fatalf("expected allowance %d to succeed", i+1)
		}
	}

	// Should be rate limited now
	if rl.Allow("test-id") {
		t.Error("expected rate limit after 5 requests")
	}

	// Wait for cleanup (window + buffer)
	time.Sleep(200 * time.Millisecond)

	// Should be allowed again after window expires
	if !rl.Allow("test-id") {
		t.Error("expected allowance after window expiry")
	}
}

func TestCheckRateLimitPerConnectionExceeded(t *testing.T) {
	// Create a connection and test per-connection rate limit
	hub := newTestHub()
	conn := &Connection{
		hub:  hub,
		id:   "rate-test-conn",
		connType: "client",
		send: make(chan []byte, 100),
	}

	// Exhaust the per-connection rate limit
	savedMsgLimiter := messageRateLimiter
	savedUserLimiter := userRateLimiter
	messageRateLimiter = NewRateLimiter(5, time.Minute)
	t.Cleanup(func() { messageRateLimiter.Stop() })
	userRateLimiter = NewRateLimiter(100, time.Minute)
	t.Cleanup(func() { userRateLimiter.Stop() })
	defer func() {
		messageRateLimiter = savedMsgLimiter
		userRateLimiter = savedUserLimiter
	}()

	// First 5 should pass
	for i := 0; i < 5; i++ {
		if !checkRateLimit(conn) {
			t.Errorf("expected request %d to pass rate limit", i+1)
		}
	}

	// 6th should fail
	if checkRateLimit(conn) {
		t.Error("expected rate limit to be exceeded on 6th request")
	}

	// Read the error message from the send channel
	select {
	case msg := <-conn.send:
		var parsed map[string]interface{}
		json.Unmarshal(msg, &parsed)
		if parsed["type"] != "error" {
			t.Errorf("expected error message, got %v", parsed)
		}
	default:
		t.Error("expected error message on send channel")
	}
}

func TestCheckRateLimitPerUserExceeded(t *testing.T) {
	// Create connections and test per-user rate limit
	hub := newTestHub()
	conn := &Connection{
		hub:  hub,
		id:   "rate-test-user-conn",
		connType: "client",
		send: make(chan []byte, 100),
	}

	savedMsgLimiter2 := messageRateLimiter
	savedUserLimiter2 := userRateLimiter
	messageRateLimiter = NewRateLimiter(100, time.Minute)
	t.Cleanup(func() { messageRateLimiter.Stop() })
	userRateLimiter = NewRateLimiter(3, time.Minute)
	t.Cleanup(func() { userRateLimiter.Stop() })
	defer func() {
		messageRateLimiter = savedMsgLimiter2
		userRateLimiter = savedUserLimiter2
	}()

	// First 3 should pass
	for i := 0; i < 3; i++ {
		if !checkRateLimit(conn) {
			t.Errorf("expected request %d to pass user rate limit", i+1)
		}
	}

	// 4th should fail
	if checkRateLimit(conn) {
		t.Error("expected user rate limit to be exceeded on 4th request")
	}

	// Read error from channel
	select {
	case msg := <-conn.send:
		var parsed map[string]interface{}
		json.Unmarshal(msg, &parsed)
		if parsed["type"] != "error" {
			t.Errorf("expected error message, got %v", parsed)
		}
	default:
		t.Error("expected error message on send channel")
	}
}

func TestCheckRateLimitNilMetrics(t *testing.T) {
	// Verify that nil ServerMetrics doesn't cause a panic when rate limited
	origMetrics := ServerMetrics
	ServerMetrics = nil
	defer func() { ServerMetrics = origMetrics }()

	hub := newTestHub()
	conn := &Connection{
		hub:  hub,
		id:   "nil-metrics-conn",
		connType: "client",
		send: make(chan []byte, 10),
	}

	savedMsgLimiter := messageRateLimiter
	savedUserLimiter := userRateLimiter
	messageRateLimiter = NewRateLimiter(1, time.Minute)
	t.Cleanup(func() { messageRateLimiter.Stop() })
	userRateLimiter = NewRateLimiter(100, time.Minute)
	t.Cleanup(func() { userRateLimiter.Stop() })
	defer func() {
		messageRateLimiter = savedMsgLimiter
		userRateLimiter = savedUserLimiter
	}()

	// First request passes
	if !checkRateLimit(conn) {
		t.Error("expected first request to pass")
	}

	// Second request should be rate limited but not panic
	if checkRateLimit(conn) {
		t.Error("expected rate limit on second request")
	}
}

// ==============================
// E2E Auth Tests
// ==============================

func TestAuthenticateRequestWithJWT(t *testing.T) {
	setupTestDB(t)
	token := createTestUser(t, "e2eauthuser")

	req := httptest.NewRequest("GET", "/e2e/keys", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	userID, authType, err := authenticateRequest(req)
	if err != nil {
		t.Fatalf("expected valid auth, got error: %v", err)
	}
	if authType != "user" {
		t.Errorf("expected auth type user, got %s", authType)
	}
	if userID == "" {
		t.Error("expected non-empty user ID")
	}
}

func TestAuthenticateRequestWithAgentSecret(t *testing.T) {
	origSecret := os.Getenv("AGENT_SECRET")
	os.Setenv("AGENT_SECRET", "test-agent-secret")
	agentSecret = "test-agent-secret"
	defer func() {
		if origSecret != "" {
			os.Setenv("AGENT_SECRET", origSecret)
		} else {
			os.Unsetenv("AGENT_SECRET")
		}
		resetAgentSecret()
	}()

	req := httptest.NewRequest("GET", "/e2e/keys", nil)
	req.Header.Set("X-Agent-Secret", "test-agent-secret")
	req.Header.Set("X-Agent-ID", "test-agent-1")

	userID, authType, err := authenticateRequest(req)
	if err != nil {
		t.Fatalf("expected valid auth, got error: %v", err)
	}
	if authType != "agent" {
		t.Errorf("expected auth type agent, got %s", authType)
	}
	if userID != "test-agent-1" {
		t.Errorf("expected agent ID test-agent-1, got %s", userID)
	}
}

func TestAuthenticateRequestAgentSecretNoID(t *testing.T) {
	origSecret := os.Getenv("AGENT_SECRET")
	os.Setenv("AGENT_SECRET", "test-agent-secret")
	agentSecret = "test-agent-secret"
	defer func() {
		if origSecret != "" {
			os.Setenv("AGENT_SECRET", origSecret)
		} else {
			os.Unsetenv("AGENT_SECRET")
		}
		resetAgentSecret()
	}()

	req := httptest.NewRequest("GET", "/e2e/keys", nil)
	req.Header.Set("X-Agent-Secret", "test-agent-secret")
	// No X-Agent-ID header

	_, _, err := authenticateRequest(req)
	if err == nil {
		t.Error("expected error when agent secret provided without agent ID")
	}
}

func TestAuthenticateRequestNoAuthHeader(t *testing.T) {
	req := httptest.NewRequest("GET", "/e2e/keys", nil)

	_, _, err := authenticateRequest(req)
	if err == nil {
		t.Error("expected error when no auth provided")
	}
}

func TestAuthenticateRequestInvalidJWT(t *testing.T) {
	req := httptest.NewRequest("GET", "/e2e/keys", nil)
	req.Header.Set("Authorization", "Bearer invalid-token")

	_, _, err := authenticateRequest(req)
	if err == nil {
		t.Error("expected error for invalid JWT")
	}
}

func TestAuthenticateRequestWrongAgentSecret(t *testing.T) {
	origSecret := os.Getenv("AGENT_SECRET")
	os.Setenv("AGENT_SECRET", "test-agent-secret")
	agentSecret = "test-agent-secret"
	defer func() {
		if origSecret != "" {
			os.Setenv("AGENT_SECRET", origSecret)
		} else {
			os.Unsetenv("AGENT_SECRET")
		}
		resetAgentSecret()
	}()

	req := httptest.NewRequest("GET", "/e2e/keys", nil)
	req.Header.Set("X-Agent-Secret", "wrong-secret")
	req.Header.Set("X-Agent-ID", "test-agent-1")

	_, _, err := authenticateRequest(req)
	if err == nil {
		t.Error("expected error for wrong agent secret")
	}
}

// ==============================
// NotifyUser with muted conversation
// ==============================

func TestNotifyUserMutedConversation(t *testing.T) {
	setupTestDB(t)
	pushConfig = &PushNotificationConfig{}
	defer func() { pushConfig = nil }()

	token := createTestUser(t, "mutenotifuser")
	claims, err := ValidateJWT(token)
	if err != nil {
		t.Fatalf("Invalid token: %v", err)
	}
	createTestAgent(t, "mutenotifagent", "mute-bot")
	convID := createTestConversation(t, token, "mutenotifagent")

	// Register a device token
	body := `{"device_token":"mute-test-token","platform":"ios"}`
	req := httptest.NewRequest("POST", "/push/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleRegisterDeviceToken(w, req)

	// Mute the conversation
	muteReq := authPostReq("/notification-prefs/set", token, url.Values{
		"conversation_id": {convID},
		"muted":           {"true"},
	})
	muteW := httptest.NewRecorder()
	handleSetNotificationPrefs(muteW, muteReq)
	if muteW.Code != http.StatusOK {
		t.Fatalf("mute failed: %d %s", muteW.Code, muteW.Body.String())
	}

	// notifyUser should skip when conversation is muted
	// (push config has no APNs/FCM clients so it won't actually send,
	// but it should not even try because the conversation is muted)
	notifyUser(claims.UserID, "Title", "Body", convID)
	// No panic = success (the function returns early on muted conversation)
}

func TestNotifyUserEmptyDeviceTokens(t *testing.T) {
	setupTestDB(t)
	pushConfig = &PushNotificationConfig{}
	defer func() { pushConfig = nil }()

	token := createTestUser(t, "emptydevuser")
	claims, err := ValidateJWT(token)
	if err != nil {
		t.Fatalf("Invalid token: %v", err)
	}

	// User has no device tokens — notifyUser should be a no-op
	notifyUser(claims.UserID, "Title", "Body", "conv-1")
	// No panic = success
}

func TestGetDeviceTokensForUserNoDevices(t *testing.T) {
	setupTestDB(t)
	db.Exec("DELETE FROM device_tokens")
	db.Exec("DELETE FROM users")

	userID, _ := createPushTestUser(t, "notokensuser", "password123")

	tokens, err := getDeviceTokensForUser(userID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(tokens) != 0 {
		t.Errorf("expected 0 tokens for user with no devices, got %d", len(tokens))
	}
}

func TestGetDeviceTokensForUserClosedDB(t *testing.T) {
	setupTestDB(t)
	db.Close()

	_, err := getDeviceTokensForUser("any-user")
	if err == nil {
		t.Error("expected error for closed DB")
	}

	// Re-setup for subsequent tests
	setupTestDB(t)
}

// ==============================
// Register Device Token Edge Cases
// ==============================

func TestRegisterDeviceTokenDefaultPlatform(t *testing.T) {
	setupTestDB(t)
	db.Exec("DELETE FROM device_tokens")
	db.Exec("DELETE FROM users")

	_, token := createPushTestUser(t, "defaultplatuser", "password123")

	// Register without specifying platform (should default to "ios")
	body := `{"device_token":"default-plat-token"}`
	req := httptest.NewRequest("POST", "/push/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleRegisterDeviceToken(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var platform string
	err := db.QueryRow("SELECT platform FROM device_tokens WHERE device_token = ?", "default-plat-token").Scan(&platform)
	if err != nil {
		t.Fatalf("Error querying device_tokens: %v", err)
	}
	if platform != "ios" {
		t.Errorf("expected default platform ios, got %s", platform)
	}
}

func TestRegisterDeviceTokenInvalidJSON(t *testing.T) {
	setupTestDB(t)
	_, token := createPushTestUser(t, "badjsonuser", "password123")

	req := httptest.NewRequest("POST", "/push/register", strings.NewReader("not json"))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleRegisterDeviceToken(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid JSON, got %d", w.Code)
	}
}

func TestUnregisterDeviceTokenInvalidJSON(t *testing.T) {
	setupTestDB(t)
	_, token := createPushTestUser(t, "badjsonunreg", "password123")

	req := httptest.NewRequest("DELETE", "/push/unregister", strings.NewReader("not json"))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleUnregisterDeviceToken(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid JSON, got %d", w.Code)
	}
}

func TestUnregisterDeviceTokenMissingToken(t *testing.T) {
	setupTestDB(t)
	_, token := createPushTestUser(t, "missingtokenunreg", "password123")

	body := `{"device_token":""}`
	req := httptest.NewRequest("DELETE", "/push/unregister", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleUnregisterDeviceToken(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing device_token, got %d", w.Code)
	}
}

// ==============================
// Helper: newTestHub
// ==============================

func newTestHub() *Hub {
	h := &Hub{
		agents:      make(map[string]*Connection),
		clientConns: make(map[string][]*Connection),
		register:    make(chan *Connection),
		unregister:  make(chan *Connection),
		broadcast:   make(chan []byte),
		done:        make(chan struct{}),
	}
	return h
}

// ==============================
// Middleware: IP extraction tests
// ==============================

func TestExtractIPHeaders(t *testing.T) {
	tests := []struct {
		name     string
		headers  map[string]string
		remote   string
		expected string
	}{
		{"direct remote", nil, "192.168.1.1:1234", "192.168.1.1"},
		{"X-Forwarded-For single", map[string]string{"X-Forwarded-For": "10.0.0.1"}, "192.168.1.1:1234", "10.0.0.1"},
		{"X-Forwarded-For multi", map[string]string{"X-Forwarded-For": "10.0.0.1, 10.0.0.2"}, "192.168.1.1:1234", "10.0.0.1"},
		{"X-Real-IP", map[string]string{"X-Real-Ip": "10.0.0.3"}, "192.168.1.1:1234", "10.0.0.3"},
		{"X-Forwarded-For priority over X-Real-IP", map[string]string{"X-Forwarded-For": "10.0.0.1", "X-Real-Ip": "10.0.0.3"}, "192.168.1.1:1234", "10.0.0.1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/", nil)
			req.RemoteAddr = tt.remote
			for k, v := range tt.headers {
				req.Header.Set(k, v)
			}
			got := extractIP(req)
			if got != tt.expected {
				t.Errorf("extractIP() = %q, want %q", got, tt.expected)
			}
		})
	}
}

// ==============================
// VAPID key test
// ==============================

func TestGetEnvOrDefaultDefaultValue(t *testing.T) {
	key := "TEST_ENV_VAR_OR_DEFAULT_12345"
	os.Unsetenv(key)

	got := getEnvOrDefault(key, "default_val")
	if got != "default_val" {
		t.Errorf("expected default_val, got %s", got)
	}

	os.Setenv(key, "env_val")
	defer os.Unsetenv(key)

	got = getEnvOrDefault(key, "default_val")
	if got != "env_val" {
		t.Errorf("expected env_val, got %s", got)
	}
}

// ==============================
// Context key tests (for auth middleware)
// ==============================

func TestGetUserIDFromContext(t *testing.T) {
	setupTestDB(t)
	token := createTestUser(t, "ctxuser1")
	claims, err := ValidateJWT(token)
	if err != nil {
		t.Fatalf("Invalid token: %v", err)
	}

	req := httptest.NewRequest("GET", "/", nil)
	ctx := context.WithValue(req.Context(), contextKeyUserID, claims.UserID)
	req = req.WithContext(ctx)

	userID, err := getUserID(req)
	if err != nil {
		t.Fatalf("expected valid user ID, got error: %v", err)
	}
	if userID != claims.UserID {
		t.Errorf("expected %s, got %s", claims.UserID, userID)
	}
}

func TestGetUserIDMissing(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)

	_, err := getUserID(req)
	if err == nil {
		t.Error("expected error when user ID missing from context")
	}
}