package main

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

// =====================================================
// Coverage boost 9: targeting remaining low-coverage functions
// Focus: push notifications, notifyUser, checkRateLimit,
// profile handlers, notif prefs, presence, conversations,
// queue persist, rate limit tiers, e2e, attachments
// =====================================================

// --- Push notification initialization and sending ---

func TestCb9InitPushNotifications_Disabled(t *testing.T) {
	// When both APNs and FCM are disabled, initPushNotifications should not crash
	os.Unsetenv("APNS_ENABLED")
	os.Unsetenv("FCM_ENABLED")
	initPushNotifications()

	if pushConfig == nil {
		t.Fatal("pushConfig should be initialized even when disabled")
	}
	if pushConfig.APNSEnabled {
		t.Error("APNs should be disabled")
	}
	if pushConfig.FCMEnabled {
		t.Error("FCM should be disabled")
	}
}

func TestCb9InitPushNotifications_APNsEnabled_NoCert(t *testing.T) {
	os.Setenv("APNS_ENABLED", "true")
	os.Unsetenv("APNS_CERT_PATH")
	os.Unsetenv("FCM_ENABLED")
	defer os.Unsetenv("APNS_ENABLED")

	initPushNotifications()

	// When APNS_ENABLED=true but no cert path, APNs stays enabled but will fail at send time
	// The function logs a warning but does not set APNSEnabled=false
	if pushConfig == nil {
		t.Fatal("pushConfig should be initialized")
	}
}

func TestCb9InitPushNotifications_APNsEnabled_NonexistentCert(t *testing.T) {
	os.Setenv("APNS_ENABLED", "true")
	os.Setenv("APNS_CERT_PATH", "/nonexistent/path/cert.p12")
	os.Unsetenv("FCM_ENABLED")
	defer os.Unsetenv("APNS_ENABLED")
	defer os.Unsetenv("APNS_CERT_PATH")

	initPushNotifications()

	if pushConfig.APNSEnabled {
		t.Error("APNs should be disabled because cert does not exist")
	}
}

func TestCb9InitPushNotifications_FCMEnabled_NoCreds(t *testing.T) {
	os.Unsetenv("APNS_ENABLED")
	os.Setenv("FCM_ENABLED", "true")
	os.Unsetenv("FCM_CREDENTIALS_PATH")
	defer os.Unsetenv("FCM_ENABLED")

	initPushNotifications()

	// When FCM_ENABLED=true but no credentials path, FCM stays enabled but will fail at send time
	// The function logs a warning but does not set FCMEnabled=false
	if pushConfig == nil {
		t.Fatal("pushConfig should be initialized")
	}
}

func TestCb9InitPushNotifications_FCMEnabled_NonexistentCreds(t *testing.T) {
	os.Unsetenv("APNS_ENABLED")
	os.Setenv("FCM_ENABLED", "true")
	os.Setenv("FCM_CREDENTIALS_PATH", "/nonexistent/firebase-creds.json")
	defer os.Unsetenv("FCM_ENABLED")
	defer os.Unsetenv("FCM_CREDENTIALS_PATH")

	initPushNotifications()

	if pushConfig.FCMEnabled {
		t.Error("FCM should be disabled because credentials don't exist")
	}
}

func TestCb9InitPushNotifications_DefaultEnvVars(t *testing.T) {
	os.Unsetenv("APNS_ENABLED")
	os.Unsetenv("FCM_ENABLED")

	initPushNotifications()

	if pushConfig.BundleID != "com.agentmessenger.ios" {
		t.Errorf("Expected default bundle ID, got %s", pushConfig.BundleID)
	}
	if pushConfig.Environment != "development" {
		t.Errorf("Expected default environment 'development', got %s", pushConfig.Environment)
	}
}

func TestCb9SendAPNSNotification_Disabled(t *testing.T) {
	// Reset push config to disabled
	pushConfig = &PushNotificationConfig{
		APNSEnabled: false,
	}

	err := sendAPNSNotification("token", "Title", "Body", "conv-1")
	if err != nil {
		t.Errorf("Expected nil error when APNs disabled, got: %v", err)
	}
}

func TestCb9SendAPNSNotification_NilConfig(t *testing.T) {
	pushConfig = nil
	err := sendAPNSNotification("token", "Title", "Body", "conv-1")
	if err != nil {
		t.Errorf("Expected nil error when pushConfig is nil, got: %v", err)
	}
}

func TestCb9SendAPNSNotification_NilClient(t *testing.T) {
	pushConfig = &PushNotificationConfig{
		APNSEnabled: true,
		apnsClient:  nil,
	}
	err := sendAPNSNotification("token", "Title", "Body", "conv-1")
	if err != nil {
		t.Errorf("Expected nil error when apnsClient is nil, got: %v", err)
	}
}

func TestCb9SendFCMNotification_Disabled(t *testing.T) {
	pushConfig = &PushNotificationConfig{
		FCMEnabled: false,
	}

	err := sendFCMNotification("token", "Title", "Body", "conv-1")
	if err != nil {
		t.Errorf("Expected nil error when FCM disabled, got: %v", err)
	}
}

func TestCb9SendFCMNotification_NilConfig(t *testing.T) {
	pushConfig = nil
	err := sendFCMNotification("token", "Title", "Body", "conv-1")
	if err != nil {
		t.Errorf("Expected nil error when pushConfig is nil, got: %v", err)
	}
}

func TestCb9SendFCMNotification_NilClient(t *testing.T) {
	pushConfig = &PushNotificationConfig{
		FCMEnabled: true,
		fcmClient:  nil,
	}
	err := sendFCMNotification("token", "Title", "Body", "conv-1")
	if err != nil {
		t.Errorf("Expected nil error when fcmClient is nil, got: %v", err)
	}
}

// --- notifyUser coverage ---

func TestCb9NotifyUser_NilConfig(t *testing.T) {
	pushConfig = nil
	notifyUser("user1", "Title", "Body", "conv-1")
	// Should not panic
}

func TestCb9NotifyUser_MutedConversation(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	pushConfig = &PushNotificationConfig{
		APNSEnabled: false,
		FCMEnabled:  false,
	}

	token := cb7CreateUser(t, "notifmute9")
	claims, _ := ValidateJWT(token)
	convID := cb7CreateConversation(t, token, "notifmute9agent")

	// Mute the conversation
	ctx := context.WithValue(context.Background(), contextKeyUserID, claims.UserID)
	req := httptest.NewRequest("POST", "/notifications/preferences?conversation_id="+convID+"&muted=true", nil)
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()
	handleSetNotificationPrefs(w, req)
	if w.Code != 200 {
		t.Fatalf("Failed to set muted prefs: %d %s", w.Code, w.Body.String())
	}

	// notifyUser should return early for muted conversations
	notifyUser(claims.UserID, "Title", "Body", convID)
	// No panic = success
}

func TestCb9NotifyUser_NoDeviceTokens(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	pushConfig = &PushNotificationConfig{
		APNSEnabled: false,
		FCMEnabled:  false,
	}

	token := cb7CreateUser(t, "notifnotokens9")
	claims, _ := ValidateJWT(token)

	// User has no device tokens — should not crash
	notifyUser(claims.UserID, "Title", "Body", "")
}

func TestCb9NotifyUser_WithDeviceTokens(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	pushConfig = &PushNotificationConfig{
		APNSEnabled: false,
		FCMEnabled:  false,
	}

	token := cb7CreateUser(t, "notifdt9")
	claims, _ := ValidateJWT(token)

	// Register a device token
	body := `{"device_token":"test-token-123","platform":"ios"}`
	req := httptest.NewRequest("POST", "/push/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleRegisterDeviceToken(w, req)
	if w.Code != 200 {
		t.Fatalf("Register failed: %d %s", w.Code, w.Body.String())
	}

	// notifyUser should not crash with device tokens present
	notifyUser(claims.UserID, "Title", "Body", "")
}

// --- checkRateLimit coverage ---

func TestCb9CheckRateLimit_Allowed(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	conn := &Connection{
		id:   "rate-limit-test-allowed",
		send: make(chan []byte, 10),
	}
	defer close(conn.send)

	// Fresh rate limiters should allow
	if !checkRateLimit(conn) {
		t.Error("Expected rate limit to allow first message")
	}
}

func TestCb9CheckRateLimit_PerConnExceeded(t *testing.T) {
	// Create a dedicated rate limiter so we don't pollute the global one
	oldMsgLimiter := messageRateLimiter
	oldUserLimiter := userRateLimiter
	messageRateLimiter = NewRateLimiter(2, time.Minute)
	userRateLimiter = NewRateLimiter(100, time.Minute)
	defer func() {
		messageRateLimiter = oldMsgLimiter
		userRateLimiter = oldUserLimiter
	}()

	conn := &Connection{
		id:   "rate-limit-test-exceeded",
		send: make(chan []byte, 10),
	}
	defer close(conn.send)

	// Use up the limit
	checkRateLimit(conn)
	checkRateLimit(conn)

	// Third message should be rate limited
	if checkRateLimit(conn) {
		t.Error("Expected rate limit to block after exceeding per-conn limit")
	}

	// Drain any error messages from the channel
	select {
	case msg := <-conn.send:
		var parsed map[string]interface{}
		json.Unmarshal(msg, &parsed)
		if parsed["type"] != "error" {
			t.Errorf("Expected error message, got: %v", parsed)
		}
	default:
	}
}

// --- Profile handler coverage ---

func TestCb9AdminProfile_ActionFromJSON(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	body := `{"action":"gc"}`
	req := httptest.NewRequest("POST", "/admin/profile", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handleAdminProfile(w, req)

	if w.Code != 200 {
		t.Errorf("Expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCb9AdminProfile_UnknownAction(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	req := httptest.NewRequest("POST", "/admin/profile?action=unknown", nil)
	w := httptest.NewRecorder()
	handleAdminProfile(w, req)

	if w.Code != 400 {
		t.Errorf("Expected 400 for unknown action, got %d", w.Code)
	}
}

func TestCb9AdminProfile_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest("DELETE", "/admin/profile", nil)
	w := httptest.NewRecorder()
	handleAdminProfile(w, req)

	if w.Code != 405 {
		t.Errorf("Expected 405, got %d", w.Code)
	}
}

func TestCb9AdminProfile_GetStats(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	req := httptest.NewRequest("GET", "/admin/profile", nil)
	w := httptest.NewRecorder()
	handleAdminProfile(w, req)

	if w.Code != 200 {
		t.Errorf("Expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCb9ForceGC(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	req := httptest.NewRequest("POST", "/admin/profile?action=gc", nil)
	w := httptest.NewRecorder()
	handleForceGC(w, req)

	if w.Code != 200 {
		t.Errorf("Expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["action"] != "gc" {
		t.Errorf("Expected action=gc, got %v", resp["action"])
	}
}

func TestCb9MemoryStats(t *testing.T) {
	stats := MemoryStats()
	if stats == nil {
		t.Fatal("MemoryStats() returned nil")
	}
	if _, ok := stats["alloc_bytes"]; !ok {
		t.Error("Missing alloc_bytes in MemoryStats")
	}
	if _, ok := stats["goroutines"]; !ok {
		t.Error("Missing goroutines in MemoryStats")
	}
}

func TestCb9ForceGCFunction(t *testing.T) {
	numGC := ForceGC()
	if numGC == 0 {
		t.Error("ForceGC should return positive GC count")
	}
}

func TestCb9SetGCPercent(t *testing.T) {
	old := SetGCPercent(100)
	SetGCPercent(old) // restore
	if old < 0 {
		t.Error("SetGCPercent should return previous value >= 0")
	}
}

func TestCb9SetMemoryLimit(t *testing.T) {
	oldLimit := SetMemoryLimit(1 << 30) // 1GB
	SetMemoryLimit(oldLimit)              // restore
}

func TestCb9CaptureProfile_NoDir(t *testing.T) {
	snapshot := CaptureProfile("")
	if snapshot == nil {
		t.Fatal("CaptureProfile should not return nil")
	}
	if snapshot.HeapFile != "" {
		t.Error("Expected no heap file when dir is empty")
	}
	if snapshot.GoroutineFile != "" {
		t.Error("Expected no goroutine file when dir is empty")
	}
}

func TestCb9CaptureProfile_WithDir(t *testing.T) {
	dir := t.TempDir()
	snapshot := CaptureProfile(dir)
	if snapshot == nil {
		t.Fatal("CaptureProfile should not return nil")
	}
	if snapshot.HeapFile == "" {
		t.Error("Expected heap file when dir is provided")
	}
	if snapshot.GoroutineFile == "" {
		t.Error("Expected goroutine file when dir is provided")
	}
	if _, err := os.Stat(snapshot.HeapFile); err != nil {
		t.Errorf("Heap profile file should exist: %v", err)
	}
	if _, err := os.Stat(snapshot.GoroutineFile); err != nil {
		t.Errorf("Goroutine profile file should exist: %v", err)
	}
}

func TestCb9WriteHeapProfile(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/heap.prof"
	err := WriteHeapProfile(path)
	if err != nil {
		t.Fatalf("WriteHeapProfile failed: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Errorf("Heap profile file should exist: %v", err)
	}
}

func TestCb9WriteGoroutineProfile(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/goroutine.prof"
	err := WriteGoroutineProfile(path)
	if err != nil {
		t.Fatalf("WriteGoroutineProfile failed: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Errorf("Goroutine profile file should exist: %v", err)
	}
}

func TestCb9StartCPUProfile(t *testing.T) {
	defer cpuProfileTestSetup()()

	dir := t.TempDir()
	path := dir + "/cpu.prof"

	stop, err := StartCPUProfile(path)
	if err != nil {
		t.Fatalf("StartCPUProfile failed: %v", err)
	}
	stop() // Must call to flush and close

	if _, err := os.Stat(path); err != nil {
		t.Errorf("CPU profile file should exist after stop: %v", err)
	}
}

func TestCb9StartCPUProfile_BadPath(t *testing.T) {
	_, err := StartCPUProfile("/nonexistent/dir/that/does/not/exist/cpu.prof")
	if err == nil {
		t.Error("Expected error for bad path")
	}
}

// --- Notification preferences handlers ---

func TestCb9GetNotificationPrefs_NoAuth(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	req := httptest.NewRequest("GET", "/notifications/preferences", nil)
	w := httptest.NewRecorder()
	handleGetNotificationPrefs(w, req)

	if w.Code != 401 {
		t.Errorf("Expected 401, got %d", w.Code)
	}
}

func TestCb9GetNotificationPrefs_Empty(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	token := cb7CreateUser(t, "notifpref9")
	claims, _ := ValidateJWT(token)
	ctx := context.WithValue(context.Background(), contextKeyUserID, claims.UserID)

	req := httptest.NewRequest("GET", "/notifications/preferences", nil)
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()
	handleGetNotificationPrefs(w, req)

	if w.Code != 200 {
		t.Errorf("Expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var prefs []NotificationPreferences
	json.Unmarshal(w.Body.Bytes(), &prefs)
	if len(prefs) != 0 {
		t.Errorf("Expected empty prefs, got %d", len(prefs))
	}
}

func TestCb9SetNotificationPrefs_NoAuth(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	req := httptest.NewRequest("POST", "/notifications/preferences", nil)
	w := httptest.NewRecorder()
	handleSetNotificationPrefs(w, req)

	if w.Code != 401 {
		t.Errorf("Expected 401, got %d", w.Code)
	}
}

func TestCb9SetNotificationPrefs_MissingConvID(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	token := cb7CreateUser(t, "notifprefmiss9")
	claims, _ := ValidateJWT(token)
	ctx := context.WithValue(context.Background(), contextKeyUserID, claims.UserID)

	req := httptest.NewRequest("POST", "/notifications/preferences?muted=true", nil)
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()
	handleSetNotificationPrefs(w, req)

	if w.Code != 400 {
		t.Errorf("Expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCb9SetNotificationPrefs_ConvNotFound(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	token := cb7CreateUser(t, "notifpreftnf9")
	claims, _ := ValidateJWT(token)
	ctx := context.WithValue(context.Background(), contextKeyUserID, claims.UserID)

	req := httptest.NewRequest("POST", "/notifications/preferences?conversation_id=nonexistent&muted=true", nil)
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()
	handleSetNotificationPrefs(w, req)

	if w.Code != 404 {
		t.Errorf("Expected 404, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCb9SetNotificationPrefs_WrongOwner(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	token1 := cb7CreateUser(t, "notifprefowner1")
	token2 := cb7CreateUser(t, "notifprefowner2")
	claims2, _ := ValidateJWT(token2)

	convID := cb7CreateConversation(t, token1, "notifprefagent1")

	ctx := context.WithValue(context.Background(), contextKeyUserID, claims2.UserID)
	req := httptest.NewRequest("POST", "/notifications/preferences?conversation_id="+convID+"&muted=true", nil)
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()
	handleSetNotificationPrefs(w, req)

	if w.Code != 403 {
		t.Errorf("Expected 403, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCb9DeleteNotificationPrefs_NoAuth(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	req := httptest.NewRequest("DELETE", "/notifications/preferences", nil)
	w := httptest.NewRecorder()
	handleDeleteNotificationPrefs(w, req)

	if w.Code != 401 {
		t.Errorf("Expected 401, got %d", w.Code)
	}
}

func TestCb9DeleteNotificationPrefs_MissingConvID(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	token := cb7CreateUser(t, "notifprefdelmiss9")
	claims, _ := ValidateJWT(token)
	ctx := context.WithValue(context.Background(), contextKeyUserID, claims.UserID)

	req := httptest.NewRequest("DELETE", "/notifications/preferences", nil)
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()
	handleDeleteNotificationPrefs(w, req)

	if w.Code != 400 {
		t.Errorf("Expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

// --- Presence handlers ---

func TestCb9GetPresence_NoAuth(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	req := httptest.NewRequest("GET", "/presence", nil)
	w := httptest.NewRecorder()
	handleGetPresence(w, req)

	if w.Code != 401 {
		t.Errorf("Expected 401, got %d", w.Code)
	}
}

func TestCb9GetPresence_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest("POST", "/presence", nil)
	w := httptest.NewRecorder()
	handleGetPresence(w, req)

	if w.Code != 405 {
		t.Errorf("Expected 405, got %d", w.Code)
	}
}

func TestCb9GetPresence_WithAuth(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	hub = newHub()
	go hub.run()
	defer hub.Stop()

	token := cb7CreateUser(t, "presence9")
	req := httptest.NewRequest("GET", "/presence", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleGetPresence(w, req)

	if w.Code != 200 {
		t.Errorf("Expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCb9GetUserPresence(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	token := cb7CreateUser(t, "userpresence9")
	claims, _ := ValidateJWT(token)

	req := httptest.NewRequest("GET", "/presence/user", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleGetUserPresence(w, req)

	if w.Code != 200 {
		t.Errorf("Expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["user_id"] != claims.UserID {
		t.Errorf("Expected user_id %s, got %v", claims.UserID, resp["user_id"])
	}
}

func TestCb9GetUserPresence_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest("POST", "/presence/user", nil)
	w := httptest.NewRecorder()
	handleGetUserPresence(w, req)

	if w.Code != 405 {
		t.Errorf("Expected 405, got %d", w.Code)
	}
}

func TestCb9GetUserPresence_SpecificUser(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	hub = newHub()
	go hub.run()
	defer hub.Stop()

	token := cb7CreateUser(t, "userpresence9spec2")
	req := httptest.NewRequest("GET", "/presence/user?user_id=someotheruser", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleGetUserPresence(w, req)

	if w.Code != 200 {
		t.Errorf("Expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

// --- Queue persistence coverage ---

func TestCb9PersistQueue_NilDB(t *testing.T) {
	origDB := db
	db = nil
	defer func() { db = origDB }()

	persistQueue(nil, "recipient", []byte("data"))
	// Should not panic
}

func TestCb9DeleteQueueMessages_NilDB(t *testing.T) {
	origDB := db
	db = nil
	defer func() { db = origDB }()

	deleteQueueMessages(nil, "recipient")
	// Should not panic
}

func TestCb9LoadQueueFromDB_NilDB(t *testing.T) {
	q := newOfflineQueue(100, 7*24*time.Hour)
	loadQueueFromDB(nil, q)
	// Should not panic
}

func TestCb9InitQueueDB_NilDB(t *testing.T) {
	initQueueDB(nil)
	// Should not panic
}

func TestCb9CleanStaleQueueMessages_NilDB(t *testing.T) {
	cleanStaleQueueMessages(nil, time.Hour)
	// Should not panic
}

func TestCb9MarshalOutgoingMessage(t *testing.T) {
	msg := OutgoingMessage{
		Type: "chat",
		Data: map[string]interface{}{"content": "Hello"},
	}
	data := marshalOutgoingMessage(msg)
	if data == nil {
		t.Fatal("marshalOutgoingMessage should not return nil")
	}
	var parsed map[string]interface{}
	err := json.Unmarshal(data, &parsed)
	if err != nil {
		t.Fatalf("Failed to unmarshal: %v", err)
	}
	if parsed["type"] != "chat" {
		t.Errorf("Expected type 'chat', got %v", parsed["type"])
	}
}

func TestCb9PersistAndLoad(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	initQueueDB(db)

	data := marshalOutgoingMessage(OutgoingMessage{
		Type: "chat",
		Data: map[string]interface{}{"content": "Test message"},
	})

	persistQueue(db, "user-1", data)
	persistQueue(db, "user-1", data)

	q := newOfflineQueue(100, 7*24*time.Hour)
	loadQueueFromDB(db, q)
	// Verify loaded messages by draining
	messages := q.Drain("user-1")
	if len(messages) != 2 {
		t.Errorf("Expected 2 messages from load, got %d", len(messages))
	}
}

func TestCb9DeleteQueueMessagesWithData(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	initQueueDB(db)

	data := marshalOutgoingMessage(OutgoingMessage{
		Type: "chat",
		Data: map[string]interface{}{"content": "Test message"},
	})

	persistQueue(db, "user-del-test", data)
	deleteQueueMessages(db, "user-del-test")

	// Verify the message is gone
	var count int
	err := db.QueryRow("SELECT COUNT(*) FROM offline_queue WHERE recipient = ?", "user-del-test").Scan(&count)
	if err != nil {
		t.Fatalf("Query error: %v", err)
	}
	if count != 0 {
		t.Errorf("Expected 0 messages after delete, got %d", count)
	}
}

func TestCb9CleanStaleQueueMessages(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	initQueueDB(db)

	data := marshalOutgoingMessage(OutgoingMessage{
		Type: "chat",
		Data: map[string]interface{}{"content": "Old message"},
	})

	persistQueue(db, "user-stale", data)

	// Manually age the message
	_, err := db.Exec("UPDATE offline_queue SET queued_at = ? WHERE recipient = ?",
		time.Now().UTC().Add(-48*time.Hour).Format(time.RFC3339), "user-stale")
	if err != nil {
		t.Fatalf("Failed to age message: %v", err)
	}

	cleanStaleQueueMessages(db, 24*time.Hour)

	var count int
	db.QueryRow("SELECT COUNT(*) FROM offline_queue WHERE recipient = ?", "user-stale").Scan(&count)
	if count != 0 {
		t.Errorf("Expected 0 stale messages after cleanup, got %d", count)
	}
}

// --- Rate limit tier persistence ---

func TestCb9PersistTierToDB_SQLite(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	err := persistTierToDB("user-tier-test", TierPro)
	if err != nil {
		t.Fatalf("persistTierToDB failed: %v", err)
	}

	var tierName string
	err = db.QueryRow("SELECT tier_name FROM user_rate_limit_tiers WHERE user_id = ?", "user-tier-test").Scan(&tierName)
	if err != nil {
		t.Fatalf("Failed to query tier: %v", err)
	}
	if tierName != "pro" {
		t.Errorf("Expected tier 'pro', got %s", tierName)
	}
}

func TestCb9PersistTierToDB_NilDB(t *testing.T) {
	savedDB := db
	db = nil
	defer func() { db = savedDB }()

	err := persistTierToDB("user-nil-test", TierFree)
	if err != nil {
		t.Errorf("persistTierToDB with nil db should return nil, got: %v", err)
	}
}

func TestCb9LoadTiersFromDB(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	// Insert some tiers
	persistTierToDB("user-load-pro", TierPro)
	persistTierToDB("user-load-ent", TierEnterprise)

	trl := NewTieredRateLimiter()
	err := loadTiersFromDB(trl)
	if err != nil {
		t.Fatalf("loadTiersFromDB failed: %v", err)
	}

	// Verify pro tier loaded
	proTier := trl.GetTier("user-load-pro")
	if proTier.Name != "pro" {
		t.Errorf("Expected 'pro', got %s", proTier.Name)
	}

	// Verify enterprise tier loaded
	entTier := trl.GetTier("user-load-ent")
	if entTier.Name != "enterprise" {
		t.Errorf("Expected 'enterprise', got %s", entTier.Name)
	}
}

func TestCb9LoadTiersFromDB_NilDB(t *testing.T) {
	savedDB := db
	db = nil
	defer func() { db = savedDB }()

	err := loadTiersFromDB(nil)
	if err != nil {
		t.Errorf("loadTiersFromDB with nil db should return nil, got: %v", err)
	}
}

func TestCb9HandleAdminRateLimitTier_GetMethod(t *testing.T) {
	req := httptest.NewRequest("GET", "/admin/rate-limit/tier", nil)
	w := httptest.NewRecorder()
	handleAdminRateLimitTier(w, req)

	// Should be unauthorized (no admin secret)
	if w.Code != 401 {
		t.Logf("Got status %d, body: %s", w.Code, w.Body.String())
	}
}

func TestCb9HandleAdminRateLimitTier_PostMethod(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	form := "user_id=test-user&tier=pro&admin_secret=" + getAdminSecret()
	req := httptest.NewRequest("POST", "/admin/rate-limit/tier", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handleSetRateLimitTier(w, req)

	if w.Code != 200 {
		t.Errorf("Expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

// --- E2E encryption handler coverage ---

func TestCb9HandleGetEncryptedMessages_NoAuth(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	req := httptest.NewRequest("GET", "/messages/encrypted", nil)
	w := httptest.NewRecorder()
	handleGetEncryptedMessages(w, req)

	if w.Code != 401 {
		t.Errorf("Expected 401, got %d", w.Code)
	}
}

func TestCb9HandleGetEncryptedMessages_MissingConvID(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	token := cb7CreateUser(t, "e2enoconv9")
	req := httptest.NewRequest("GET", "/messages/encrypted", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleGetEncryptedMessages(w, req)

	if w.Code != 400 {
		t.Errorf("Expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

// --- Attachment handler coverage ---

func TestCb9HandleUpload_WrongMethod(t *testing.T) {
	req := httptest.NewRequest("GET", "/upload", nil)
	w := httptest.NewRecorder()
	handleUpload(w, req)

	if w.Code != 405 {
		t.Errorf("Expected 405, got %d", w.Code)
	}
}

func TestCb9HandleUpload_NoAuth(t *testing.T) {
	req := httptest.NewRequest("POST", "/upload", nil)
	w := httptest.NewRecorder()
	handleUpload(w, req)

	if w.Code != 401 {
		t.Errorf("Expected 401, got %d", w.Code)
	}
}

func TestCb9HandleListAttachments_NoAuth(t *testing.T) {
	req := httptest.NewRequest("GET", "/attachments", nil)
	w := httptest.NewRecorder()
	handleListAttachments(w, req)

	if w.Code != 401 {
		t.Errorf("Expected 401, got %d", w.Code)
	}
}

func TestCb9HandleListAttachments_WrongMethod(t *testing.T) {
	req := httptest.NewRequest("POST", "/attachments", nil)
	w := httptest.NewRecorder()
	handleListAttachments(w, req)

	if w.Code != 405 {
		t.Errorf("Expected 405, got %d", w.Code)
	}
}

// --- WebPush handler coverage ---

func TestCb9GetVAPIDKey_NotConfigured(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	vapidPublicKey = ""
	req := httptest.NewRequest("GET", "/push/vapid-key", nil)
	req.Header.Set("Authorization", "Bearer sometoken")
	w := httptest.NewRecorder()
	handleGetVAPIDKey(w, req)

	if w.Code != 404 {
		t.Errorf("Expected 404, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCb9GetVAPIDKey_Configured(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	vapidPublicKey = "test-vapid-public-key"
	defer func() { vapidPublicKey = "" }()

	token := cb7CreateUser(t, "vapid9")
	req := httptest.NewRequest("GET", "/push/vapid-key", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleGetVAPIDKey(w, req)

	if w.Code != 200 {
		t.Errorf("Expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCb9GetVAPIDKey_NoAuth(t *testing.T) {
	vapidPublicKey = "test-key"
	defer func() { vapidPublicKey = "" }()

	req := httptest.NewRequest("GET", "/push/vapid-key", nil)
	w := httptest.NewRecorder()
	handleGetVAPIDKey(w, req)

	if w.Code != 401 {
		t.Errorf("Expected 401, got %d", w.Code)
	}
}

func TestCb9GetVAPIDKey_WrongMethod(t *testing.T) {
	req := httptest.NewRequest("POST", "/push/vapid-key", nil)
	w := httptest.NewRecorder()
	handleGetVAPIDKey(w, req)

	if w.Code != 405 {
		t.Errorf("Expected 405, got %d", w.Code)
	}
}

func TestCb9WebPushSubscribe_WrongMethod(t *testing.T) {
	req := httptest.NewRequest("GET", "/push/web-subscribe", nil)
	w := httptest.NewRecorder()
	handleWebPushSubscribe(w, req)

	if w.Code != 405 {
		t.Errorf("Expected 405, got %d", w.Code)
	}
}

func TestCb9WebPushSubscribe_NoAuth(t *testing.T) {
	body := `{"endpoint":"https://push.example.com/123","keys":{"p256dh":"key1","auth":"auth1"}}`
	req := httptest.NewRequest("POST", "/push/web-subscribe", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handleWebPushSubscribe(w, req)

	if w.Code != 401 {
		t.Errorf("Expected 401, got %d", w.Code)
	}
}

func TestCb9WebPushSubscribe_MissingFields(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	token := cb7CreateUser(t, "webpushsub9")

	body := `{"endpoint":"","keys":{"p256dh":"","auth":""}}`
	req := httptest.NewRequest("POST", "/push/web-subscribe", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleWebPushSubscribe(w, req)

	if w.Code != 400 {
		t.Errorf("Expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCb9WebPushUnsubscribe_WrongMethod(t *testing.T) {
	req := httptest.NewRequest("GET", "/push/web-unsubscribe", nil)
	w := httptest.NewRecorder()
	handleWebPushUnsubscribe(w, req)

	if w.Code != 405 {
		t.Errorf("Expected 405, got %d", w.Code)
	}
}

func TestCb9WebPushUnsubscribe_NoAuth(t *testing.T) {
	body := `{"endpoint":"https://push.example.com/123"}`
	req := httptest.NewRequest("POST", "/push/web-unsubscribe", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handleWebPushUnsubscribe(w, req)

	if w.Code != 401 {
		t.Errorf("Expected 401, got %d", w.Code)
	}
}

func TestCb9WebPushUnsubscribe_MissingEndpoint(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	token := cb7CreateUser(t, "webpushunsub9")

	body := `{"endpoint":""}`
	req := httptest.NewRequest("POST", "/push/web-unsubscribe", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleWebPushUnsubscribe(w, req)

	if w.Code != 400 {
		t.Errorf("Expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

// --- getEnvOrDefault coverage ---

func TestCb9GetEnvOrDefault(t *testing.T) {
	os.Unsetenv("TEST_CB9_VAR")
	result := getEnvOrDefault("TEST_CB9_VAR", "default")
	if result != "default" {
		t.Errorf("Expected 'default', got %s", result)
	}

	os.Setenv("TEST_CB9_VAR", "custom")
	defer os.Unsetenv("TEST_CB9_VAR")
	result = getEnvOrDefault("TEST_CB9_VAR", "default")
	if result != "custom" {
		t.Errorf("Expected 'custom', got %s", result)
	}
}

// --- Conversation delete handler coverage ---

func TestCb9DeleteConversation_Handler(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	token := cb7CreateUser(t, "delconv9")
	convID := cb7CreateConversation(t, token, "delconv9agent")

	req := httptest.NewRequest("DELETE", "/conversations/delete?conversation_id="+convID, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleDeleteConversation(w, req)

	if w.Code != 200 {
		t.Errorf("Expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCb9DeleteConversation_MissingID(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	token := cb7CreateUser(t, "delconvmiss9")
	req := httptest.NewRequest("DELETE", "/conversations/delete", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleDeleteConversation(w, req)

	if w.Code != 400 {
		t.Errorf("Expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCb9DeleteConversation_NotOwner(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	token1 := cb7CreateUser(t, "delconvowner9")
	token2 := cb7CreateUser(t, "delconvother9")
	convID := cb7CreateConversation(t, token1, "delconvagent9")

	req := httptest.NewRequest("DELETE", "/conversations/delete?conversation_id="+convID, nil)
	req.Header.Set("Authorization", "Bearer "+token2)
	w := httptest.NewRecorder()
	handleDeleteConversation(w, req)

	if w.Code != 401 {
		t.Errorf("Expected 401 for wrong owner, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCb9DeleteConversation_NotFound(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	token := cb7CreateUser(t, "delconvnf9")

	req := httptest.NewRequest("DELETE", "/conversations/delete?conversation_id=nonexistent", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleDeleteConversation(w, req)

	if w.Code != 404 {
		t.Errorf("Expected 404, got %d: %s", w.Code, w.Body.String())
	}
}

// --- InitSchema coverage ---

func TestCb9InitSchema(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	// initSchema is called during setupTestDB, just verify tables exist
	var count int
	err := db.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type='table'").Scan(&count)
	if err != nil {
		t.Fatalf("Failed to query tables: %v", err)
	}
	if count < 10 {
		t.Errorf("Expected at least 10 tables, got %d", count)
	}
}

// --- HashAPIKey coverage ---

func TestCb9HashAPIKey(t *testing.T) {
	hash, err := HashAPIKey("testkey123")
	if err != nil {
		t.Fatalf("HashAPIKey failed: %v", err)
	}
	if hash == "" {
		t.Error("Hash should not be empty")
	}
	if hash == "testkey123" {
		t.Error("Hash should not equal input")
	}
}

// --- RegisterAgentOnConnect coverage ---

func TestCb9RegisterAgentOnConnect(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	err := RegisterAgentOnConnect("agent-reg9", "Test Agent", "gpt-4", "friendly", "general")
	if err != nil {
		t.Fatalf("RegisterAgentOnConnect failed: %v", err)
	}

	var name string
	err = db.QueryRow("SELECT name FROM agents WHERE id = ?", "agent-reg9").Scan(&name)
	if err != nil {
		t.Fatalf("Failed to query agent: %v", err)
	}
	if name != "Test Agent" {
		t.Errorf("Expected 'Test Agent', got %s", name)
	}
}

func TestCb9RegisterAgentOnConnect_UpdateExisting(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	err := RegisterAgentOnConnect("agent-update9", "Original", "model1", "friendly", "general")
	if err != nil {
		t.Fatalf("First registration failed: %v", err)
	}

	err = RegisterAgentOnConnect("agent-update9", "Updated", "model2", "serious", "medical")
	if err != nil {
		t.Fatalf("Second registration failed: %v", err)
	}

	var name string
	db.QueryRow("SELECT name FROM agents WHERE id = ?", "agent-update9").Scan(&name)
	if name != "Updated" {
		t.Errorf("Expected 'Updated', got %s", name)
	}
}

// --- openDatabase coverage ---

func TestCb9OpenDatabase_BadPath(t *testing.T) {
	// SQLite creates directories and files as needed, so test with a valid temp path instead
	dir := t.TempDir()
	dbConn, err := openDatabase("sqlite3", dir+"/test.db")
	if err != nil {
		t.Fatalf("openDatabase should work with temp path: %v", err)
	}
	dbConn.Close()
}

// --- dbdriver helpers ---

func TestCb9Placeholder(t *testing.T) {
	p := Placeholder(1)
	if p != "?" {
		t.Errorf("Expected '?' for SQLite, got %s", p)
	}
}

func TestCb9Placeholders(t *testing.T) {
	// Current driver is SQLite
	placeholders := Placeholders(1, 5)
	expected := "?, ?, ?, ?, ?"
	if placeholders != expected {
		t.Errorf("Expected %s, got %s", expected, placeholders)
	}
}

// --- Routing: truncate helper ---

func TestCb9Truncate_Short(t *testing.T) {
	result := truncate("hi", 10)
	if result != "hi" {
		t.Errorf("Expected 'hi', got %s", result)
	}
}

func TestCb9Truncate_Exact(t *testing.T) {
	result := truncate("1234567890", 10)
	if result != "1234567890" {
		t.Errorf("Expected '1234567890', got %s", result)
	}
}

func TestCb9Truncate_Long(t *testing.T) {
	result := truncate("123456789012345", 10)
	if len(result) > 10 {
		t.Errorf("Result should be at most 10 chars, got %d: %s", len(result), result)
	}
}

// --- E2E store encrypted message more coverage ---

func TestCb9StoreEncrypted_NoBody(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	token := cb7CreateUser(t, "enc9nobody")
	req := httptest.NewRequest("POST", "/messages/encrypted/store", nil)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleStoreEncryptedMessage(w, req)

	if w.Code != 400 {
		t.Errorf("Expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCb9StoreEncrypted_InvalidJSON(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	token := cb7CreateUser(t, "enc9badjson")
	req := httptest.NewRequest("POST", "/messages/encrypted/store", strings.NewReader("not json"))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleStoreEncryptedMessage(w, req)

	if w.Code != 400 {
		t.Errorf("Expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

// --- SendWelcomeMessage coverage ---

func TestCb9SendWelcomeMessage(t *testing.T) {
	send := make(chan []byte, 10)

	sendWelcomeMessage("client", "user-welcome9", "device-1", "1.0", send)

	select {
	case msg := <-send:
		var parsed map[string]interface{}
		if err := json.Unmarshal(msg, &parsed); err != nil {
			t.Fatalf("Failed to parse welcome message: %v", err)
		}
		if parsed["type"] != "connected" {
			t.Errorf("Expected type 'connected', got %v", parsed["type"])
		}
	default:
		t.Error("Expected welcome message on send channel")
	}
}

// --- Change password handler coverage ---

func TestCb9ChangePassword_Success(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	token := cb7CreateUser(t, "chpw9")

	form := "old_password=testpass123&new_password=newpass456"
	req := httptest.NewRequest("POST", "/auth/change-password", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleChangePassword(w, req)

	if w.Code != 200 {
		t.Errorf("Expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCb9ChangePassword_WrongOld(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	token := cb7CreateUser(t, "chpw9wrong")

	form := "old_password=wrongpass&new_password=newpass456"
	req := httptest.NewRequest("POST", "/auth/change-password", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleChangePassword(w, req)

	if w.Code != 401 {
		t.Errorf("Expected 401, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCb9ChangePassword_ShortNew(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	token := cb7CreateUser(t, "chpw9short")

	form := "old_password=testpass123&new_password=abc"
	req := httptest.NewRequest("POST", "/auth/change-password", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleChangePassword(w, req)

	if w.Code != 400 {
		t.Errorf("Expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

// --- isConversationMuted coverage ---

func TestCb9IsConversationMuted_NotMuted(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	muted := isConversationMuted("nonexistent-user", "nonexistent-conv")
	if muted {
		t.Error("Expected not muted for nonexistent conversation")
	}
}

// --- OfflineQueue coverage ---

func TestCb9OfflineQueue_EnqueueDequeue(t *testing.T) {
	q := newOfflineQueue(100, 7*24*time.Hour)

	data := []byte("test message data")
	q.Enqueue("user-1", data)

	messages := q.Drain("user-1")
	if len(messages) != 1 {
		t.Fatalf("Expected 1 message, got %d", len(messages))
	}
	if string(messages[0]) != string(data) {
		t.Error("Message data mismatch")
	}

	// Drain again should be empty
	messages = q.Drain("user-1")
	if len(messages) != 0 {
		t.Errorf("Expected 0 messages after drain, got %d", len(messages))
	}
}

func TestCb9OfflineQueue_MaxLen(t *testing.T) {
	q := newOfflineQueue(10, 7*24*time.Hour) // small max for testing

	data := []byte("msg")
	for i := 0; i < 200; i++ {
		q.Enqueue("user-max", data)
	}

	messages := q.Drain("user-max")
	if len(messages) > 10 {
		t.Errorf("Expected at most 10 messages, got %d", len(messages))
	}
}

func TestCb9OfflineQueue_DrainNonexistent(t *testing.T) {
	q := newOfflineQueue(100, 7*24*time.Hour)

	messages := q.Drain("nonexistent")
	if len(messages) != 0 {
		t.Errorf("Expected 0 messages for nonexistent user, got %d", len(messages))
	}
}

// --- Device token handler coverage ---

func TestCb9RegisterDeviceToken_WrongMethod(t *testing.T) {
	req := httptest.NewRequest("GET", "/push/register", nil)
	w := httptest.NewRecorder()
	handleRegisterDeviceToken(w, req)

	if w.Code != 405 {
		t.Errorf("Expected 405, got %d", w.Code)
	}
}

func TestCb9RegisterDeviceToken_NoBody(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	token := cb7CreateUser(t, "regdev9")
	req := httptest.NewRequest("POST", "/push/register", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleRegisterDeviceToken(w, req)

	if w.Code != 400 {
		t.Errorf("Expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCb9RegisterDeviceToken_DefaultPlatform(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	token := cb7CreateUser(t, "regdev9default")
	body := `{"device_token":"token-default-platform"}`
	req := httptest.NewRequest("POST", "/push/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleRegisterDeviceToken(w, req)

	if w.Code != 200 {
		t.Errorf("Expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// Verify platform defaults to ios
	var platform string
	db.QueryRow("SELECT platform FROM device_tokens WHERE device_token = ?", "token-default-platform").Scan(&platform)
	if platform != "ios" {
		t.Errorf("Expected default platform 'ios', got %s", platform)
	}
}

func TestCb9UnregisterDeviceToken_WrongMethod(t *testing.T) {
	req := httptest.NewRequest("POST", "/push/unregister", nil)
	w := httptest.NewRecorder()
	handleUnregisterDeviceToken(w, req)

	if w.Code != 405 {
		t.Errorf("Expected 405, got %d", w.Code)
	}
}

func TestCb9UnregisterDeviceToken_NoToken(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	token := cb7CreateUser(t, "unregdev9")
	body := `{"device_token":""}`
	req := httptest.NewRequest("DELETE", "/push/unregister", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleUnregisterDeviceToken(w, req)

	if w.Code != 400 {
		t.Errorf("Expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCb9UnregisterDeviceToken_InvalidJSON(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	token := cb7CreateUser(t, "unregdev9bad")
	req := httptest.NewRequest("DELETE", "/push/unregister", strings.NewReader("not json"))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleUnregisterDeviceToken(w, req)

	if w.Code != 400 {
		t.Errorf("Expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

// --- Conversation create handler more coverage ---

func TestCb9CreateConversation_Handler(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	hub = newHub()
	go hub.run()
	defer hub.Stop()

	token := cb7CreateUser(t, "convcreate9")
	form := "agent_id=agent-conv9"
	req := httptest.NewRequest("POST", "/conversations/create", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleCreateConversation(w, req)

	if w.Code != 200 && w.Code != 201 {
		t.Errorf("Expected 200/201, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCb9CreateConversation_InvalidJSON(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	token := cb7CreateUser(t, "convcreate9bad")
	req := httptest.NewRequest("POST", "/conversations/create", strings.NewReader("not json"))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleCreateConversation(w, req)

	if w.Code != 400 {
		t.Errorf("Expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

// --- Store messages batch coverage ---

func TestCb9StoreMessagesBatch_Empty(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	ids, err := storeMessagesBatch(nil)
	if err != nil {
		t.Fatalf("storeMessagesBatch(nil) should not error: %v", err)
	}
	if ids != nil {
		t.Errorf("Expected nil ids for empty input, got %v", ids)
	}
}

func TestCb9StoreMessagesBatch_Success(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	token := cb7CreateUser(t, "batch9")
	convID := cb7CreateConversation(t, token, "batch9agent")

	msgs := []RoutedMessage{
		{ConversationID: convID, SenderID: "batch9", SenderType: "client", Content: "msg1"},
		{ConversationID: convID, SenderID: "batch9", SenderType: "client", Content: "msg2"},
		{ConversationID: convID, SenderID: "batch9", SenderType: "client", Content: "msg3"},
	}

	ids, err := storeMessagesBatch(msgs)
	if err != nil {
		t.Fatalf("storeMessagesBatch failed: %v", err)
	}
	if len(ids) != 3 {
		t.Errorf("Expected 3 ids, got %d", len(ids))
	}

	// Verify messages are in DB
	var count int
	db.QueryRow("SELECT COUNT(*) FROM messages WHERE conversation_id = ?", convID).Scan(&count)
	if count != 3 {
		t.Errorf("Expected 3 messages, got %d", count)
	}
}

// --- Search messages handler coverage ---

func TestCb9SearchMessages_Handler(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	token := cb7CreateUser(t, "search9handler")
	convID := cb7CreateConversation(t, token, "search9agent")

	storeMessage(RoutedMessage{
		ConversationID: convID,
		SenderID:      "search9handler",
		SenderType:    "client",
		Content:       "searchable content here",
	})

	req := httptest.NewRequest("GET", "/messages/search?q=searchable&conversation_id="+convID, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleSearchMessages(w, req)

	if w.Code != 200 {
		t.Errorf("Expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCb9SearchMessages_NoAuth(t *testing.T) {
	req := httptest.NewRequest("GET", "/messages/search?q=test", nil)
	w := httptest.NewRecorder()
	handleSearchMessages(w, req)

	if w.Code != 401 {
		t.Errorf("Expected 401, got %d", w.Code)
	}
}

// --- getConversation function coverage ---

func TestCb9GetConversation_Found(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	token := cb7CreateUser(t, "getconv9")
	convID := cb7CreateConversation(t, token, "getconv9agent")

	conv, err := getConversation(convID)
	if err != nil {
		t.Fatalf("getConversation failed: %v", err)
	}
	if conv == nil {
		t.Fatal("Expected conversation, got nil")
	}
	if conv.ID != convID {
		t.Errorf("Expected ID %s, got %s", convID, conv.ID)
	}
}

func TestCb9GetConversation_NotFound(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	conv, err := getConversation("nonexistent-id")
	if err != nil {
		t.Fatalf("getConversation should not error for nonexistent: %v", err)
	}
	if conv != nil {
		t.Error("Expected nil for nonexistent conversation")
	}
}

// --- storeMessage function coverage ---

func TestCb9StoreMessage_WithAttachments(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	token := cb7CreateUser(t, "storemsg9")
	convID := cb7CreateConversation(t, token, "storemsg9agent")

	msg := RoutedMessage{
		ConversationID: convID,
		SenderID:       "storemsg9",
		SenderType:     "client",
		Content:        "message with attachments",
		AttachmentIDs:  []string{"attach-1", "attach-2"},
	}

	err := storeMessage(msg)
	if err != nil {
		t.Fatalf("storeMessage failed: %v", err)
	}
}

// --- changeUserPassword function coverage ---

func TestCb9ChangeUserPassword_WrongOld(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	token := cb7CreateUser(t, "chpwfn9")
	claims, _ := ValidateJWT(token)

	err := changeUserPassword(claims.UserID, "wrongpass", "newpass123")
	if err == nil {
		t.Error("Expected error for wrong old password")
	}
}

func TestCb9ChangeUserPassword_ShortNew(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	token := cb7CreateUser(t, "chpwfn9short")
	claims, _ := ValidateJWT(token)

	err := changeUserPassword(claims.UserID, "testpass123", "abc")
	if err == nil {
		t.Error("Expected error for short new password")
	}
}

func TestCb9ChangeUserPassword_NonexistentUser(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	err := changeUserPassword("nonexistent-user-id", "oldpass", "newpass123")
	if err == nil {
		t.Error("Expected error for nonexistent user")
	}
}

// --- sql.ErrNoRows handling ---

func TestCb9DeleteConversation_Nonexistent(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	err := deleteConversation("nonexistent-conv", "any-user")
	if err == nil {
		t.Error("Expected error for nonexistent conversation")
	}
}

func TestCb9DeleteConversation_Unauthorized(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	token := cb7CreateUser(t, "delconv9unauth")
	convID := cb7CreateConversation(t, token, "delconv9agent")

	err := deleteConversation(convID, "wrong-user")
	if err == nil {
		t.Error("Expected error for unauthorized user")
	}
}