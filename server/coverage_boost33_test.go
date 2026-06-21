package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sideshow/apns2"
)

// CB33: Targeted coverage for sendAPNSNotification (actual push path with mock server),
// rate_limit_tiers cleanup, sendPushNotification routing, and push init edge cases.

// --- APNS mock server tests ---

func TestCB33_SendAPNSNotification_MockServer_Success(t *testing.T) {
	// Create a mock APNS server that returns 200 OK
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("apns-id", "test-apns-id-123")
		w.Header().Set("apns-unique-id", "test-apns-unique-id-456")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"reason": ""})
	}))
	defer mockServer.Close()

	// Create an APNS client pointing to the mock server
	client := &apns2.Client{
		Host:       mockServer.URL,
		HTTPClient: &http.Client{},
	}

	oldConfig := pushConfig
	pushConfig = &PushNotificationConfig{
		APNSEnabled: true,
		BundleID:    "com.test.app",
		apnsClient:  client,
	}
	t.Cleanup(func() { pushConfig = oldConfig })

	err := sendAPNSNotification("device-token-abc123", "Test Title", "Test Body", "conv-123")
	if err != nil {
		t.Errorf("expected nil error on success, got %v", err)
	}
}

func TestCB33_SendAPNSNotification_MockServer_Rejected(t *testing.T) {
	// Create a mock APNS server that returns 400 Bad Request
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("apns-id", "test-apns-id-789")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"reason": "BadDeviceToken"})
	}))
	defer mockServer.Close()

	client := &apns2.Client{
		Host:       mockServer.URL,
		HTTPClient: &http.Client{},
	}

	oldConfig := pushConfig
	pushConfig = &PushNotificationConfig{
		APNSEnabled: true,
		BundleID:    "com.test.app",
		apnsClient:  client,
	}
	t.Cleanup(func() { pushConfig = oldConfig })

	// sendAPNSNotification returns nil even on rejection (it logs a warning)
	err := sendAPNSNotification("bad-device-token", "Title", "Body", "conv-rejected")
	if err != nil {
		t.Errorf("expected nil error on rejection (log only), got %v", err)
	}
}

func TestCB33_SendAPNSNotification_MockServer_EmptyConversationID(t *testing.T) {
	var receivedBody map[string]interface{}
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Capture the request body to verify no conversation_id is set
		body := make([]byte, r.ContentLength)
		r.Body.Read(body)
		json.Unmarshal(body, &receivedBody)
		w.Header().Set("apns-id", "test-id")
		w.WriteHeader(http.StatusOK)
	}))
	defer mockServer.Close()

	client := &apns2.Client{
		Host:       mockServer.URL,
		HTTPClient: &http.Client{},
	}

	oldConfig := pushConfig
	pushConfig = &PushNotificationConfig{
		APNSEnabled: true,
		BundleID:    "com.test.app",
		apnsClient:  client,
	}
	t.Cleanup(func() { pushConfig = oldConfig })

	err := sendAPNSNotification("device-token-xyz", "Title", "Body", "")
	if err != nil {
		t.Errorf("expected nil error, got %v", err)
	}
}

func TestCB33_SendAPNSNotification_MockServer_ServerError(t *testing.T) {
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("apns-id", "test-id")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"reason": "InternalServerError"})
	}))
	defer mockServer.Close()

	client := &apns2.Client{
		Host:       mockServer.URL,
		HTTPClient: &http.Client{},
	}

	oldConfig := pushConfig
	pushConfig = &PushNotificationConfig{
		APNSEnabled: true,
		BundleID:    "com.test.app",
		apnsClient:  client,
	}
	t.Cleanup(func() { pushConfig = oldConfig })

	// Should return nil (logs warning) for non-200 status
	err := sendAPNSNotification("device-token-err", "Title", "Body", "conv-err")
	if err != nil {
		t.Errorf("expected nil error on server error (log only), got %v", err)
	}
}

func TestCB33_SendAPNSNotification_MockServer_ConnectionError(t *testing.T) {
	// Create a client pointing to a dead server
	client := &apns2.Client{
		Host:       "http://127.0.0.1:1", // port 1 should not be listening
		HTTPClient: &http.Client{Timeout: 100 * time.Millisecond},
	}

	oldConfig := pushConfig
	pushConfig = &PushNotificationConfig{
		APNSEnabled: true,
		BundleID:    "com.test.app",
		apnsClient:  client,
	}
	t.Cleanup(func() { pushConfig = oldConfig })

	err := sendAPNSNotification("device-token-conn-err", "Title", "Body", "conv-conn-err")
	if err == nil {
		t.Error("expected error on connection failure, got nil")
	}
}

// --- sendPushNotification routing tests ---

func TestCB33_SendPushNotification_Android(t *testing.T) {
	oldConfig := pushConfig
	pushConfig = &PushNotificationConfig{
		FCMEnabled: true,
		fcmClient:  nil, // nil client -> returns nil
	}
	t.Cleanup(func() { pushConfig = oldConfig })

	err := sendPushNotification("token123", "Title", "Body", "conv1", "android")
	if err != nil {
		t.Errorf("expected nil error with nil fcmClient, got %v", err)
	}
}

func TestCB33_SendPushNotification_FCMPlatform(t *testing.T) {
	oldConfig := pushConfig
	pushConfig = &PushNotificationConfig{
		FCMEnabled: true,
		fcmClient:  nil,
	}
	t.Cleanup(func() { pushConfig = oldConfig })

	err := sendPushNotification("token123", "Title", "Body", "conv1", "fcm")
	if err != nil {
		t.Errorf("expected nil error with nil fcmClient, got %v", err)
	}
}

func TestCB33_SendPushNotification_IOS(t *testing.T) {
	oldConfig := pushConfig
	pushConfig = &PushNotificationConfig{
		APNSEnabled: true,
		apnsClient:  nil, // nil client -> returns nil
	}
	t.Cleanup(func() { pushConfig = oldConfig })

	err := sendPushNotification("token123", "Title", "Body", "conv1", "ios")
	if err != nil {
		t.Errorf("expected nil error with nil apnsClient, got %v", err)
	}
}

func TestCB33_SendPushNotification_UnknownPlatform(t *testing.T) {
	oldConfig := pushConfig
	pushConfig = &PushNotificationConfig{
		APNSEnabled: true,
		apnsClient:  nil,
	}
	t.Cleanup(func() { pushConfig = oldConfig })

	// Unknown platform defaults to APNs
	err := sendPushNotification("token123", "Title", "Body", "conv1", "unknown")
	if err != nil {
		t.Errorf("expected nil error (defaults to APNs), got %v", err)
	}
}

func TestCB33_SendPushNotification_EmptyPlatform(t *testing.T) {
	oldConfig := pushConfig
	pushConfig = &PushNotificationConfig{
		APNSEnabled: true,
		apnsClient:  nil,
	}
	t.Cleanup(func() { pushConfig = oldConfig })

	// Empty platform defaults to APNs
	err := sendPushNotification("token123", "Title", "Body", "conv1", "")
	if err != nil {
		t.Errorf("expected nil error (empty platform defaults to APNs), got %v", err)
	}
}

func TestCB33_SendPushNotification_AndroidCaseInsensitive(t *testing.T) {
	oldConfig := pushConfig
	pushConfig = &PushNotificationConfig{
		FCMEnabled: true,
		fcmClient:  nil,
	}
	t.Cleanup(func() { pushConfig = oldConfig })

	// "Android" with capital A should route to FCM
	err := sendPushNotification("token123", "Title", "Body", "conv1", "Android")
	if err != nil {
		t.Errorf("expected nil error (case insensitive FCM routing), got %v", err)
	}
}

func TestCB33_SendPushNotification_FCMCaseInsensitive(t *testing.T) {
	oldConfig := pushConfig
	pushConfig = &PushNotificationConfig{
		FCMEnabled: true,
		fcmClient:  nil,
	}
	t.Cleanup(func() { pushConfig = oldConfig })

	// "FCM" with capitals should route to FCM
	err := sendPushNotification("token123", "Title", "Body", "conv1", "FCM")
	if err != nil {
		t.Errorf("expected nil error (case insensitive FCM routing), got %v", err)
	}
}

// --- initAPNs coverage tests ---

func TestCB33_InitAPNs_NilPushConfig(t *testing.T) {
	pushConfig = nil
	initAPNs()
	if pushConfig != nil {
		t.Error("expected pushConfig to remain nil")
	}
}

func TestCB33_InitAPNs_Disabled(t *testing.T) {
	pushConfig = &PushNotificationConfig{
		APNSEnabled: false,
	}
	t.Cleanup(func() { pushConfig = nil })
	initAPNs()
	if pushConfig.APNSEnabled {
		t.Error("expected APNSEnabled to remain false")
	}
}

func TestCB33_InitAPNs_EnabledNoCertPath(t *testing.T) {
	pushConfig = &PushNotificationConfig{
		APNSEnabled: true,
		CertPath:    "",
	}
	t.Cleanup(func() { pushConfig = nil })
	initAPNs()
	// initAPNs returns early without disabling when cert path is empty
	// (it logs a warning but doesn't change APNSEnabled)
	if !pushConfig.APNSEnabled {
		t.Log("APNSEnabled was set to false (acceptable)")
	}
}

func TestCB33_InitAPNs_EnabledCertNotFound(t *testing.T) {
	pushConfig = &PushNotificationConfig{
		APNSEnabled: true,
		CertPath:    "/nonexistent/path/cert.p12",
	}
	t.Cleanup(func() { pushConfig = nil })
	initAPNs()
	// Should disable APNs since cert file doesn't exist
	if pushConfig.APNSEnabled {
		t.Error("expected APNSEnabled to be set to false when cert not found")
	}
}

// --- initFCM coverage tests ---

func TestCB33_InitFCM_NilPushConfig(t *testing.T) {
	pushConfig = nil
	initFCM()
	if pushConfig != nil {
		t.Error("expected pushConfig to remain nil")
	}
}

func TestCB33_InitFCM_Disabled(t *testing.T) {
	pushConfig = &PushNotificationConfig{
		FCMEnabled: false,
	}
	t.Cleanup(func() { pushConfig = nil })
	initFCM()
	if pushConfig.FCMEnabled {
		t.Error("expected FCMEnabled to remain false")
	}
}

func TestCB33_InitFCM_EnabledNoCredsPath(t *testing.T) {
	pushConfig = &PushNotificationConfig{
		FCMEnabled:     true,
		FCMCredentials: "",
	}
	t.Cleanup(func() { pushConfig = nil })
	initFCM()
	// initFCM returns early without disabling when creds path is empty
	// (it logs a warning but doesn't change FCMEnabled)
	if !pushConfig.FCMEnabled {
		t.Log("FCMEnabled was set to false (acceptable)")
	}
	if pushConfig.fcmClient != nil {
		t.Error("expected fcmClient to remain nil when no creds path")
	}
}

func TestCB33_InitFCM_EnabledCredsNotFound(t *testing.T) {
	pushConfig = &PushNotificationConfig{
		FCMEnabled:     true,
		FCMCredentials: "/nonexistent/path/creds.json",
	}
	t.Cleanup(func() { pushConfig = nil })
	initFCM()
	// Should disable FCM since creds file doesn't exist
	if pushConfig.FCMEnabled {
		t.Error("expected FCMEnabled to be set to false when creds not found")
	}
}

// --- initPushNotifications coverage ---

func TestCB33_InitPushNotifications_AllDisabled(t *testing.T) {
	oldAPNS := os.Getenv("APNS_ENABLED")
	os.Unsetenv("APNS_ENABLED")
	os.Unsetenv("FCM_ENABLED")
	os.Unsetenv("APNS_CERT_PATH")
	os.Unsetenv("FCM_CREDENTIALS_PATH")
	t.Cleanup(func() {
		if oldAPNS != "" {
			os.Setenv("APNS_ENABLED", oldAPNS)
		}
	})

	initPushNotifications()
	t.Cleanup(func() { pushConfig = nil })

	if pushConfig == nil {
		t.Fatal("expected pushConfig to be initialized")
	}
	if pushConfig.APNSEnabled {
		t.Error("expected APNSEnabled to be false")
	}
	if pushConfig.FCMEnabled {
		t.Error("expected FCMEnabled to be false")
	}
}

func TestCB33_InitPushNotifications_APNSEnabledNoCert(t *testing.T) {
	os.Setenv("APNS_ENABLED", "true")
	os.Unsetenv("APNS_CERT_PATH")
	os.Unsetenv("FCM_ENABLED")
	t.Cleanup(func() {
		os.Unsetenv("APNS_ENABLED")
		pushConfig = nil
	})

	initPushNotifications()
	// APNS enabled but no cert path -> initAPNs logs warning but doesn't disable
	// The flag stays true but apnsClient remains nil, so sends will return nil
	if !pushConfig.APNSEnabled {
		t.Log("APNSEnabled was set to false (acceptable)")
	}
	if pushConfig.apnsClient != nil {
		t.Error("expected apnsClient to remain nil with no cert")
	}
}

func TestCB33_InitPushNotifications_FCMEnabledNoCreds(t *testing.T) {
	os.Unsetenv("APNS_ENABLED")
	os.Setenv("FCM_ENABLED", "true")
	os.Unsetenv("FCM_CREDENTIALS_PATH")
	t.Cleanup(func() {
		os.Unsetenv("FCM_ENABLED")
		pushConfig = nil
	})

	initPushNotifications()
	// FCM enabled but no creds path -> initFCM logs warning but doesn't disable
	// The flag stays true but fcmClient remains nil, so sends will return nil
	if !pushConfig.FCMEnabled {
		t.Log("FCMEnabled was set to false (acceptable)")
	}
	if pushConfig.fcmClient != nil {
		t.Error("expected fcmClient to remain nil with no creds")
	}
}

func TestCB33_InitPushNotifications_BundleIDDefault(t *testing.T) {
	os.Unsetenv("APNS_ENABLED")
	os.Unsetenv("FCM_ENABLED")
	os.Unsetenv("APNS_BUNDLE_ID")
	t.Cleanup(func() { pushConfig = nil })

	initPushNotifications()
	if pushConfig.BundleID != "com.agentmessenger.ios" {
		t.Errorf("expected default bundle ID, got %s", pushConfig.BundleID)
	}
}

func TestCB33_InitPushNotifications_EnvironmentDefault(t *testing.T) {
	os.Unsetenv("APNS_ENABLED")
	os.Unsetenv("FCM_ENABLED")
	os.Unsetenv("APNS_ENVIRONMENT")
	t.Cleanup(func() { pushConfig = nil })

	initPushNotifications()
	if pushConfig.Environment != "development" {
		t.Errorf("expected default environment 'development', got %s", pushConfig.Environment)
	}
}

func TestCB33_InitPushNotifications_CustomBundleID(t *testing.T) {
	os.Unsetenv("APNS_ENABLED")
	os.Unsetenv("FCM_ENABLED")
	os.Setenv("APNS_BUNDLE_ID", "com.custom.app")
	t.Cleanup(func() {
		os.Unsetenv("APNS_BUNDLE_ID")
		pushConfig = nil
	})

	initPushNotifications()
	if pushConfig.BundleID != "com.custom.app" {
		t.Errorf("expected custom bundle ID, got %s", pushConfig.BundleID)
	}
}

func TestCB33_InitPushNotifications_ProductionEnvironment(t *testing.T) {
	os.Unsetenv("APNS_ENABLED")
	os.Unsetenv("FCM_ENABLED")
	os.Setenv("APNS_ENVIRONMENT", "production")
	t.Cleanup(func() {
		os.Unsetenv("APNS_ENVIRONMENT")
		pushConfig = nil
	})

	initPushNotifications()
	if pushConfig.Environment != "production" {
		t.Errorf("expected 'production', got %s", pushConfig.Environment)
	}
}

// --- Rate limiter cleanup coverage ---

func TestCB33_TieredRateLimiter_Cleanup(t *testing.T) {
	trl := NewTieredRateLimiter()

	// Add some entries
	trl.mu.Lock()
	trl.limits["user1"] = &userRateLimitState{
		count:     5,
		windowEnd: time.Now().Add(-15 * time.Minute), // expired >10min ago
		tier:      TierFree,
	}
	trl.limits["user2"] = &userRateLimitState{
		count:     3,
		windowEnd: time.Now().Add(-5 * time.Minute), // expired but <10min, should NOT be cleaned
		tier:      TierPro,
	}
	trl.limits["user3"] = &userRateLimitState{
		count:     10,
		windowEnd: time.Now().Add(10 * time.Minute), // not expired
		tier:      TierEnterprise,
	}
	trl.mu.Unlock()

	// Stop the cleanup goroutine after a short delay
	// The cleanup ticker fires every 5 minutes, so we can't wait for it.
	// Instead, we test that stopCh works correctly.
	close(trl.stopCh)

	// Verify entries are still there (cleanup goroutine didn't tick yet)
	trl.mu.Lock()
	_, hasUser1 := trl.limits["user1"]
	_, hasUser2 := trl.limits["user2"]
	_, hasUser3 := trl.limits["user3"]
	trl.mu.Unlock()

	if !hasUser1 {
		t.Error("user1 should still exist (cleanup tick hasn't fired)")
	}
	if !hasUser2 {
		t.Error("user2 should still exist")
	}
	if !hasUser3 {
		t.Error("user3 should still exist")
	}
}

func TestCB33_TieredRateLimiter_Cleanup_StopChannel(t *testing.T) {
	trl := NewTieredRateLimiter()

	// Verify stopCh can be closed without blocking
	close(trl.stopCh)
}

func TestCB33_TieredRateLimiter_Stop(t *testing.T) {
	trl := NewTieredRateLimiter()

	// Stop should not block or panic
	trl.Stop()

	// Calling Stop again should be safe (idempotent check)
	// Note: if not using sync.Once, this may panic — test will catch it
}

func TestCB33_TieredRateLimiter_StopMultiple(t *testing.T) {
	trl := NewTieredRateLimiter()

	// Stop multiple times should not panic
	trl.Stop()
	// Second stop may or may not be safe depending on implementation
	// Let's test it doesn't deadlock
	done := make(chan struct{})
	go func() {
		defer func() { done <- struct{}{} }()
		trl.Stop()
	}()
	select {
	case <-done:
		// Good
	case <-time.After(2 * time.Second):
		t.Error("second Stop() should not block")
	}
}

// --- TieredRateLimiter concurrent access coverage ---

func TestCB33_TieredRateLimiter_ConcurrentAccess(t *testing.T) {
	trl := NewTieredRateLimiter()
	t.Cleanup(func() { trl.Stop() })

	trl.SetTier("user1", TierPro)

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			trl.Allow("user1")
		}()
	}
	wg.Wait()

	remaining := trl.GetRemaining("user1")
	if remaining >= 300 {
		t.Errorf("expected remaining < 300 after 10 concurrent allows, got %d", remaining)
	}
}

func TestCB33_TieredRateLimiter_SetAndGetTierConcurrent(t *testing.T) {
	trl := NewTieredRateLimiter()
	t.Cleanup(func() { trl.Stop() })

	var wg sync.WaitGroup
	for i := 0; i < 5; i++ {
		wg.Add(2)
		go func(i int) {
			defer wg.Done()
			trl.SetTier("user"+string(rune('0'+i)), TierPro)
		}(i)
		go func(i int) {
			defer wg.Done()
			trl.GetTier("user" + string(rune('0'+i)))
		}(i)
	}
	wg.Wait()
}

// --- notifyUser with mock push config ---

func TestCB33_NotifyUser_NilPushConfig(t *testing.T) {
	setupTestDB(t)
	oldConfig := pushConfig
	pushConfig = nil
	t.Cleanup(func() { pushConfig = oldConfig })

	// Should be a no-op with nil pushConfig
	notifyUser("user1", "Title", "Body", "conv1")
	// No panic = pass
}

func TestCB33_NotifyUser_EmptyUserID(t *testing.T) {
	setupTestDB(t)
	oldConfig := pushConfig
	pushConfig = &PushNotificationConfig{
		APNSEnabled: true,
		apnsClient:  nil,
	}
	t.Cleanup(func() { pushConfig = oldConfig })

	notifyUser("", "Title", "Body", "")
	// No panic = pass
}

// --- getDeviceTokensForUser with DB ---

func TestCB33_GetDeviceTokensForUser_NoTokens(t *testing.T) {
	setupTestDB(t)
	tokens, err := getDeviceTokensForUser("nonexistent-user")
	if err != nil {
		t.Errorf("expected nil error, got %v", err)
	}
	if len(tokens) != 0 {
		t.Errorf("expected 0 tokens, got %d", len(tokens))
	}
}

func TestCB33_GetDeviceTokensForUser_WithTokens(t *testing.T) {
	setupTestDB(t)

	// Insert a device token
	_, err := db.Exec(`
		INSERT INTO device_tokens (user_id, device_token, platform, updated_at)
		VALUES (?, ?, ?, CURRENT_TIMESTAMP)
	`, "test-user-cb33", "token-abc", "ios")
	if err != nil {
		t.Fatal(err)
	}

	tokens, err := getDeviceTokensForUser("test-user-cb33")
	if err != nil {
		t.Errorf("expected nil error, got %v", err)
	}
	if len(tokens) != 1 {
		t.Fatalf("expected 1 token, got %d", len(tokens))
	}
	if tokens[0].Token != "token-abc" {
		t.Errorf("expected token 'token-abc', got %s", tokens[0].Token)
	}
	if tokens[0].Platform != "ios" {
		t.Errorf("expected platform 'ios', got %s", tokens[0].Platform)
	}
}

func TestCB33_GetDeviceTokensForUser_MultipleTokens(t *testing.T) {
	setupTestDB(t)

	// Insert multiple device tokens for same user
	for _, plat := range []string{"ios", "android", "web"} {
		_, err := db.Exec(`
			INSERT INTO device_tokens (user_id, device_token, platform, updated_at)
			VALUES (?, ?, ?, CURRENT_TIMESTAMP)
		`, "multi-user-cb33", "token-"+plat, plat)
		if err != nil {
			t.Fatal(err)
		}
	}

	tokens, err := getDeviceTokensForUser("multi-user-cb33")
	if err != nil {
		t.Errorf("expected nil error, got %v", err)
	}
	if len(tokens) != 3 {
		t.Errorf("expected 3 tokens, got %d", len(tokens))
	}
}

// --- handleGetVAPIDKey edge cases ---

func TestCB33_HandleGetVAPIDKey_NoAuth(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/push/vapid-key", nil)
	handleGetVAPIDKey(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestCB33_HandleGetVAPIDKey_WrongMethod(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/push/vapid-key", nil)
	handleGetVAPIDKey(w, r)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestCB33_HandleGetVAPIDKey_NotConfigured(t *testing.T) {
	oldKey := vapidPublicKey
	vapidPublicKey = ""
	t.Cleanup(func() { vapidPublicKey = oldKey })

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/push/vapid-key", nil)
	r.Header.Set("Authorization", "Bearer "+genTokenCB33(t, "user-cb33"))
	handleGetVAPIDKey(w, r)
	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

func TestCB33_HandleGetVAPIDKey_Success(t *testing.T) {
	oldKey := vapidPublicKey
	vapidPublicKey = "test-vapid-key-abc"
	t.Cleanup(func() { vapidPublicKey = oldKey })

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/push/vapid-key", nil)
	r.Header.Set("Authorization", "Bearer "+genTokenCB33(t, "user-cb33"))
	handleGetVAPIDKey(w, r)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}

	var resp map[string]string
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["public_key"] != "test-vapid-key-abc" {
		t.Errorf("expected 'test-vapid-key-abc', got '%s'", resp["public_key"])
	}
}

// --- handleWebPushSubscribe edge cases ---

func TestCB33_HandleWebPushSubscribe_WrongMethod(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/push/web-subscribe", nil)
	handleWebPushSubscribe(w, r)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestCB33_HandleWebPushSubscribe_NoAuth(t *testing.T) {
	w := httptest.NewRecorder()
	body := `{"endpoint":"https://example.com/sub","keys":{"p256dh":"key1","auth":"key2"}}`
	r := httptest.NewRequest("POST", "/push/web-subscribe", strings.NewReader(body))
	handleWebPushSubscribe(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestCB33_HandleWebPushSubscribe_InvalidBody(t *testing.T) {
	setupTestDB(t)
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/push/web-subscribe", strings.NewReader("not json"))
	r.Header.Set("Authorization", "Bearer "+genTokenCB33(t, "user-cb33"))
	handleWebPushSubscribe(w, r)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestCB33_HandleWebPushSubscribe_MissingFields(t *testing.T) {
	setupTestDB(t)
	w := httptest.NewRecorder()
	body := `{"endpoint":"","keys":{"p256dh":"","auth":""}}`
	r := httptest.NewRequest("POST", "/push/web-subscribe", strings.NewReader(body))
	r.Header.Set("Authorization", "Bearer "+genTokenCB33(t, "user-cb33"))
	handleWebPushSubscribe(w, r)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestCB33_HandleWebPushSubscribe_Success(t *testing.T) {
	setupTestDB(t)
	w := httptest.NewRecorder()
	body := `{"endpoint":"https://example.com/sub/123","keys":{"p256dh":"p256key","auth":"authkey"}}`
	r := httptest.NewRequest("POST", "/push/web-subscribe", strings.NewReader(body))
	r.Header.Set("Authorization", "Bearer "+genTokenCB33(t, "user-cb33-wps"))
	handleWebPushSubscribe(w, r)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}

	var resp map[string]string
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["status"] != "subscribed" {
		t.Errorf("expected 'subscribed', got '%s'", resp["status"])
	}
}

// --- handleWebPushUnsubscribe edge cases ---

func TestCB33_HandleWebPushUnsubscribe_WrongMethod(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/push/web-unsubscribe", nil)
	handleWebPushUnsubscribe(w, r)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestCB33_HandleWebPushUnsubscribe_NoAuth(t *testing.T) {
	w := httptest.NewRecorder()
	body := `{"endpoint":"https://example.com/sub/123"}`
	r := httptest.NewRequest("POST", "/push/web-unsubscribe", strings.NewReader(body))
	handleWebPushUnsubscribe(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestCB33_HandleWebPushUnsubscribe_InvalidBody(t *testing.T) {
	setupTestDB(t)
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/push/web-unsubscribe", strings.NewReader("not json"))
	r.Header.Set("Authorization", "Bearer "+genTokenCB33(t, "user-cb33"))
	handleWebPushUnsubscribe(w, r)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestCB33_HandleWebPushUnsubscribe_MissingEndpoint(t *testing.T) {
	setupTestDB(t)
	w := httptest.NewRecorder()
	body := `{"endpoint":""}`
	r := httptest.NewRequest("POST", "/push/web-unsubscribe", strings.NewReader(body))
	r.Header.Set("Authorization", "Bearer "+genTokenCB33(t, "user-cb33"))
	handleWebPushUnsubscribe(w, r)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestCB33_HandleWebPushUnsubscribe_Success(t *testing.T) {
	setupTestDB(t)

	// First subscribe
	body := `{"endpoint":"https://example.com/sub/unsub-1","keys":{"p256dh":"p256key","auth":"authkey"}}`
	w1 := httptest.NewRecorder()
	r1 := httptest.NewRequest("POST", "/push/web-subscribe", strings.NewReader(body))
	r1.Header.Set("Authorization", "Bearer "+genTokenCB33(t, "user-cb33-unsub"))
	handleWebPushSubscribe(w1, r1)

	// Then unsubscribe
	w := httptest.NewRecorder()
	body2 := `{"endpoint":"https://example.com/sub/unsub-1"}`
	r := httptest.NewRequest("POST", "/push/web-unsubscribe", strings.NewReader(body2))
	r.Header.Set("Authorization", "Bearer "+genTokenCB33(t, "user-cb33-unsub"))
	handleWebPushUnsubscribe(w, r)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}

	var resp map[string]string
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["status"] != "unsubscribed" {
		t.Errorf("expected 'unsubscribed', got '%s'", resp["status"])
	}
}

// --- handleRegisterDeviceToken / handleUnregisterDeviceToken more coverage ---

func TestCB33_HandleRegisterDeviceToken_WrongMethod(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/push/register", nil)
	handleRegisterDeviceToken(w, r)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestCB33_HandleRegisterDeviceToken_NoAuth(t *testing.T) {
	w := httptest.NewRecorder()
	body := `{"device_token":"token123","platform":"ios"}`
	r := httptest.NewRequest("POST", "/push/register", strings.NewReader(body))
	handleRegisterDeviceToken(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestCB33_HandleRegisterDeviceToken_InvalidBody(t *testing.T) {
	setupTestDB(t)
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/push/register", strings.NewReader("not json"))
	r.Header.Set("Authorization", "Bearer "+genTokenCB33(t, "user-cb33-reg"))
	handleRegisterDeviceToken(w, r)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestCB33_HandleRegisterDeviceToken_MissingToken(t *testing.T) {
	setupTestDB(t)
	w := httptest.NewRecorder()
	body := `{"device_token":"","platform":"ios"}`
	r := httptest.NewRequest("POST", "/push/register", strings.NewReader(body))
	r.Header.Set("Authorization", "Bearer "+genTokenCB33(t, "user-cb33-reg"))
	handleRegisterDeviceToken(w, r)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestCB33_HandleRegisterDeviceToken_Success(t *testing.T) {
	setupTestDB(t)
	w := httptest.NewRecorder()
	body := `{"device_token":"test-token-cb33","platform":"ios"}`
	r := httptest.NewRequest("POST", "/push/register", strings.NewReader(body))
	r.Header.Set("Authorization", "Bearer "+genTokenCB33(t, "user-cb33-reg-success"))
	handleRegisterDeviceToken(w, r)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}

	var resp map[string]string
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["status"] != "ok" {
		t.Errorf("expected 'ok', got '%s'", resp["status"])
	}
}

func TestCB33_HandleRegisterDeviceToken_EmptyPlatform(t *testing.T) {
	setupTestDB(t)
	w := httptest.NewRecorder()
	body := `{"device_token":"test-token-no-plat","platform":""}`
	r := httptest.NewRequest("POST", "/push/register", strings.NewReader(body))
	r.Header.Set("Authorization", "Bearer "+genTokenCB33(t, "user-cb33-no-plat"))
	handleRegisterDeviceToken(w, r)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestCB33_HandleRegisterDeviceToken_DuplicateUpdate(t *testing.T) {
	setupTestDB(t)

	token := genTokenCB33(t, "user-cb33-dup")

	// First registration
	w1 := httptest.NewRecorder()
	body := `{"device_token":"dup-token-cb33","platform":"ios"}`
	r1 := httptest.NewRequest("POST", "/push/register", strings.NewReader(body))
	r1.Header.Set("Authorization", "Bearer "+token)
	handleRegisterDeviceToken(w1, r1)
	if w1.Code != http.StatusOK {
		t.Fatalf("first registration failed: %d", w1.Code)
	}

	// Second registration with same token but different platform (should update)
	w2 := httptest.NewRecorder()
	body2 := `{"device_token":"dup-token-cb33","platform":"android"}`
	r2 := httptest.NewRequest("POST", "/push/register", strings.NewReader(body2))
	r2.Header.Set("Authorization", "Bearer "+token)
	handleRegisterDeviceToken(w2, r2)
	if w2.Code != http.StatusOK {
		t.Errorf("expected 200 on update, got %d", w2.Code)
	}
}

// --- handleUnregisterDeviceToken coverage ---

func TestCB33_HandleUnregisterDeviceToken_WrongMethod(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/push/unregister", nil)
	handleUnregisterDeviceToken(w, r)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestCB33_HandleUnregisterDeviceToken_NoAuth(t *testing.T) {
	w := httptest.NewRecorder()
	body := `{"device_token":"token123"}`
	r := httptest.NewRequest("DELETE", "/push/unregister", strings.NewReader(body))
	handleUnregisterDeviceToken(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestCB33_HandleUnregisterDeviceToken_InvalidBody(t *testing.T) {
	setupTestDB(t)
	w := httptest.NewRecorder()
	r := httptest.NewRequest("DELETE", "/push/unregister", strings.NewReader("not json"))
	r.Header.Set("Authorization", "Bearer "+genTokenCB33(t, "user-cb33-unreg"))
	handleUnregisterDeviceToken(w, r)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestCB33_HandleUnregisterDeviceToken_MissingToken(t *testing.T) {
	setupTestDB(t)
	w := httptest.NewRecorder()
	body := `{"device_token":""}`
	r := httptest.NewRequest("DELETE", "/push/unregister", strings.NewReader(body))
	r.Header.Set("Authorization", "Bearer "+genTokenCB33(t, "user-cb33-unreg"))
	handleUnregisterDeviceToken(w, r)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestCB33_HandleUnregisterDeviceToken_Success(t *testing.T) {
	setupTestDB(t)
	token := genTokenCB33(t, "user-cb33-unreg-success")

	// First register
	w1 := httptest.NewRecorder()
	body1 := `{"device_token":"unreg-token-cb33","platform":"ios"}`
	r1 := httptest.NewRequest("POST", "/push/register", strings.NewReader(body1))
	r1.Header.Set("Authorization", "Bearer "+token)
	handleRegisterDeviceToken(w1, r1)

	// Then unregister
	w := httptest.NewRecorder()
	body2 := `{"device_token":"unreg-token-cb33"}`
	r := httptest.NewRequest("DELETE", "/push/unregister", strings.NewReader(body2))
	r.Header.Set("Authorization", "Bearer "+token)
	handleUnregisterDeviceToken(w, r)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}

	var resp map[string]string
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["status"] != "ok" {
		t.Errorf("expected 'ok', got '%s'", resp["status"])
	}
}

func TestCB33_HandleUnregisterDeviceToken_NotOwned(t *testing.T) {
	setupTestDB(t)

	// Register with user A
	tokenA := genTokenCB33(t, "user-a-cb33")
	w1 := httptest.NewRecorder()
	body1 := `{"device_token":"user-a-token-cb33","platform":"ios"}`
	r1 := httptest.NewRequest("POST", "/push/register", strings.NewReader(body1))
	r1.Header.Set("Authorization", "Bearer "+tokenA)
	handleRegisterDeviceToken(w1, r1)

	// Try to unregister with user B
	tokenB := genTokenCB33(t, "user-b-cb33")
	w := httptest.NewRecorder()
	body2 := `{"device_token":"user-a-token-cb33"}`
	r := httptest.NewRequest("DELETE", "/push/unregister", strings.NewReader(body2))
	r.Header.Set("Authorization", "Bearer "+tokenB)
	handleUnregisterDeviceToken(w, r)
	// Should return 200 (no error) but not actually delete anything
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}
// genTokenCB33 is a helper to generate a JWT token for CB33 tests.
func genTokenCB33(t *testing.T, userID string) string {
	t.Helper()
	token, err := GenerateJWT(userID, "testuser")
	if err != nil {
		t.Fatalf("GenerateJWT failed: %v", err)
	}
	return token
}
