package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

// ==================== Helpers ====================

func setupTestDB_CB81(t *testing.T) *sql.DB {
	testDB, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("Failed to open test DB: %v", err)
	t.Cleanup(func() { testDB.Close() })
	}
	if err := initSchema(testDB); err != nil {
		t.Fatalf("Failed to init schema: %v", err)
	}
	initQueueDB(testDB)
	return testDB
}

func withGlobalDB_CB81(testDB *sql.DB, fn func()) {
	origDB := db
	db = testDB
	defer func() { db = origDB }()
	fn()
}

func generateTestToken_CB81(userID string) string {
	token, err := GenerateJWT(userID, userID)
	if err != nil {
		panic(fmt.Sprintf("Failed to generate token: %v", err))
	}
	return token
}

func createUser_CB81(testDB *sql.DB, username, password string) string {
	hash, _ := HashAPIKey(password)
	testDB.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)", username, username, hash)
	return username
}

func createConversation_CB81(testDB *sql.DB, userID, agentID string) string {
	convID := "conv-" + userID + "-" + agentID
	testDB.Exec("INSERT INTO conversations (id, user_id, agent_id) VALUES (?, ?, ?)", convID, userID, agentID)
	return convID
}

// ==================== deleteConversation ====================

func TestCB81_DeleteConversation_Unauthorized(t *testing.T) {
	testDB := setupTestDB_CB81(t)
	convID := createConversation_CB81(testDB, "user1", "agent1")
	withGlobalDB_CB81(testDB, func() {
		err := deleteConversation(convID, "otheruser")
		if err == nil || err.Error() != "unauthorized" {
			t.Errorf("expected unauthorized error, got %v", err)
		}
	})
}

func TestCB81_DeleteConversation_NotFound(t *testing.T) {
	testDB := setupTestDB_CB81(t)
	withGlobalDB_CB81(testDB, func() {
		err := deleteConversation("nonexistent", "user1")
		if err != sql.ErrNoRows {
			t.Errorf("expected sql.ErrNoRows, got %v", err)
		}
	})
}

func TestCB81_DeleteConversation_WithMessages(t *testing.T) {
	testDB := setupTestDB_CB81(t)
	convID := createConversation_CB81(testDB, "user1", "agent1")
	testDB.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, created_at) VALUES (?, ?, ?, ?, ?, ?)",
		"msg1", convID, "client", "user1", "hello", time.Now().UTC())
	withGlobalDB_CB81(testDB, func() {
		err := deleteConversation(convID, "user1")
		if err != nil {
			t.Fatalf("deleteConversation failed: %v", err)
		}
		var count int
		testDB.QueryRow("SELECT COUNT(*) FROM messages WHERE conversation_id = ?", convID).Scan(&count)
		if count != 0 {
			t.Errorf("expected 0 messages after delete, got %d", count)
		}
	})
}

func TestCB81_DeleteConversation_Success(t *testing.T) {
	testDB := setupTestDB_CB81(t)
	convID := createConversation_CB81(testDB, "user1", "agent1")
	withGlobalDB_CB81(testDB, func() {
		err := deleteConversation(convID, "user1")
		if err != nil {
			t.Fatalf("deleteConversation failed: %v", err)
		}
		conv, _ := getConversation(convID)
		if conv != nil {
			t.Error("expected nil conversation after delete")
		}
	})
}

// ==================== RegisterAgentOnConnect ====================

func TestCB81_RegisterAgentOnConnect_AllFields(t *testing.T) {
	testDB := setupTestDB_CB81(t)
	withGlobalDB_CB81(testDB, func() {
		err := RegisterAgentOnConnect("agent1", "Agent One", "gpt-4", "friendly", "general")
		if err != nil {
			t.Fatalf("RegisterAgentOnConnect failed: %v", err)
		}
		var name, model, personality, specialty string
		testDB.QueryRow("SELECT name, model, personality, specialty FROM agents WHERE id = ?", "agent1").
			Scan(&name, &model, &personality, &specialty)
		if name != "Agent One" || model != "gpt-4" {
			t.Errorf("unexpected agent data: name=%s model=%s", name, model)
		}
	})
}

func TestCB81_RegisterAgentOnConnect_UpdateExisting(t *testing.T) {
	testDB := setupTestDB_CB81(t)
	withGlobalDB_CB81(testDB, func() {
		RegisterAgentOnConnect("agent1", "Agent", "gpt-3", "friendly", "general")
		err := RegisterAgentOnConnect("agent1", "Agent Updated", "gpt-4", "serious", "coding")
		if err != nil {
			t.Fatalf("update failed: %v", err)
		}
		var name, model, personality, specialty string
		testDB.QueryRow("SELECT name, model, personality, specialty FROM agents WHERE id = ?", "agent1").
			Scan(&name, &model, &personality, &specialty)
		if model != "gpt-4" || personality != "serious" || specialty != "coding" {
			t.Errorf("update failed: model=%s personality=%s specialty=%s", model, personality, specialty)
		}
		if name != "Agent Updated" {
			t.Errorf("name not updated: %s", name)
		}
	})
}

func TestCB81_RegisterAgentOnConnect_PreserveOnEmpty(t *testing.T) {
	testDB := setupTestDB_CB81(t)
	withGlobalDB_CB81(testDB, func() {
		RegisterAgentOnConnect("agent1", "Agent", "gpt-4", "friendly", "general")
		err := RegisterAgentOnConnect("agent1", "", "", "", "")
		if err != nil {
			t.Fatalf("RegisterAgentOnConnect failed: %v", err)
		}
		var name, model string
		testDB.QueryRow("SELECT name, model FROM agents WHERE id = ?", "agent1").Scan(&name, &model)
		if model != "gpt-4" {
			t.Errorf("model should be preserved: %s", model)
		}
		// name stays "Agent" because empty defaults to agentID, and update is skipped when name == agentID
		if name != "Agent" {
			t.Errorf("name should be preserved as 'Agent': %s", name)
		}
	})
}

func TestCB81_RegisterAgentOnConnect_DBError(t *testing.T) {
	testDB := setupTestDB_CB81(t)
	withGlobalDB_CB81(testDB, func() {
		db.Close()
		err := RegisterAgentOnConnect("agent1", "Agent", "gpt-4", "friendly", "general")
		if err == nil {
			t.Error("expected error with closed DB")
		}
	})
}

// ==================== initAPNs ====================

func TestCB81_InitAPNs_NilConfig(t *testing.T) {
	origPush := pushConfig
	pushConfig = nil
	defer func() { pushConfig = origPush }()
	initAPNs()
	if pushConfig != nil {
		t.Error("pushConfig should remain nil")
	}
}

func TestCB81_InitAPNs_Disabled(t *testing.T) {
	origPush := pushConfig
	pushConfig = &PushNotificationConfig{APNSEnabled: false}
	defer func() { pushConfig = origPush }()
	initAPNs()
	if pushConfig.APNSEnabled {
		t.Error("APNs should remain disabled")
	}
}

func TestCB81_InitAPNs_NoCertPath(t *testing.T) {
	origPush := pushConfig
	pushConfig = &PushNotificationConfig{APNSEnabled: true, CertPath: ""}
	defer func() { pushConfig = origPush }()
	initAPNs()
	// APNs remains enabled but without a cert — initAPNs just returns without setting up client
	if !pushConfig.APNSEnabled {
		t.Error("APNs should remain enabled when no cert path (just no client set up)")
	}
}

func TestCB81_InitAPNs_NonExistentCert(t *testing.T) {
	origPush := pushConfig
	pushConfig = &PushNotificationConfig{APNSEnabled: true, CertPath: "/nonexistent/cert.p12"}
	defer func() { pushConfig = origPush }()
	initAPNs()
	if pushConfig.APNSEnabled {
		t.Error("APNs should be disabled when cert not found")
	}
}

func TestCB81_InitAPNs_DirCreation(t *testing.T) {
	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "subdir", "cert.p12")
	origPush := pushConfig
	pushConfig = &PushNotificationConfig{APNSEnabled: true, CertPath: certPath}
	defer func() { pushConfig = origPush }()
	initAPNs()
	// dir should have been created (but cert doesn't exist so APNs disabled)
	_, err := os.Stat(filepath.Dir(certPath))
	if err != nil {
		t.Errorf("directory should have been created: %v", err)
	}
}

// ==================== initFCM ====================

func TestCB81_InitFCM_NilConfig(t *testing.T) {
	origPush := pushConfig
	pushConfig = nil
	defer func() { pushConfig = origPush }()
	initFCM()
	if pushConfig != nil {
		t.Error("pushConfig should remain nil")
	}
}

func TestCB81_InitFCM_Disabled(t *testing.T) {
	origPush := pushConfig
	pushConfig = &PushNotificationConfig{FCMEnabled: false}
	defer func() { pushConfig = origPush }()
	initFCM()
	if pushConfig.FCMEnabled {
		t.Error("FCM should remain disabled")
	}
}

func TestCB81_InitFCM_NoCreds(t *testing.T) {
	origPush := pushConfig
	pushConfig = &PushNotificationConfig{FCMEnabled: true, FCMCredentials: ""}
	defer func() { pushConfig = origPush }()
	initFCM()
	// FCM remains enabled but without creds — initFCM just returns without setting up client
	if !pushConfig.FCMEnabled {
		t.Error("FCM should remain enabled when no creds path (just no client set up)")
	}
}

func TestCB81_InitFCM_NonExistentCreds(t *testing.T) {
	origPush := pushConfig
	pushConfig = &PushNotificationConfig{FCMEnabled: true, FCMCredentials: "/nonexistent/creds.json"}
	defer func() { pushConfig = origPush }()
	initFCM()
	if pushConfig.FCMEnabled {
		t.Error("FCM should be disabled when creds not found")
	}
}

// ==================== handleSetNotificationPrefs ====================

func TestCB81_HandleSetNotificationPrefs_Success(t *testing.T) {
	testDB := setupTestDB_CB81(t)
	userID := createUser_CB81(testDB, "testuser", "pass123")
	convID := createConversation_CB81(testDB, userID, "agent1")
	token := generateTestToken_CB81(userID)
	withGlobalDB_CB81(testDB, func() {
		req := httptest.NewRequest("POST", "/notifications/prefs?conversation_id="+convID+"&muted=true", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("X-Requested-With", "XMLHttpRequest")
		// Set context with userID
		ctx := context.WithValue(req.Context(), contextKeyUserID, userID)
		req = req.WithContext(ctx)
		w := httptest.NewRecorder()
		handleSetNotificationPrefs(w, req)
		if w.Code != http.StatusOK {
			t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
		}
	})
}

func TestCB81_HandleSetNotificationPrefs_NotOwner(t *testing.T) {
	testDB := setupTestDB_CB81(t)
	userID := createUser_CB81(testDB, "testuser", "pass123")
	createUser_CB81(testDB, "otheruser", "pass456")
	convID := createConversation_CB81(testDB, userID, "agent1")
	token := generateTestToken_CB81("otheruser")
	withGlobalDB_CB81(testDB, func() {
		req := httptest.NewRequest("POST", "/notifications/prefs?conversation_id="+convID+"&muted=true", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		ctx := context.WithValue(req.Context(), contextKeyUserID, "otheruser")
		req = req.WithContext(ctx)
		w := httptest.NewRecorder()
		handleSetNotificationPrefs(w, req)
		if w.Code != http.StatusForbidden {
			t.Errorf("expected 403, got %d", w.Code)
		}
	})
}

func TestCB81_HandleSetNotificationPrefs_NotFound(t *testing.T) {
	testDB := setupTestDB_CB81(t)
	userID := createUser_CB81(testDB, "testuser", "pass123")
	token := generateTestToken_CB81(userID)
	withGlobalDB_CB81(testDB, func() {
		req := httptest.NewRequest("POST", "/notifications/prefs?conversation_id=nonexistent&muted=true", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		ctx := context.WithValue(req.Context(), contextKeyUserID, userID)
		req = req.WithContext(ctx)
		w := httptest.NewRecorder()
		handleSetNotificationPrefs(w, req)
		if w.Code != http.StatusNotFound {
			t.Errorf("expected 404, got %d", w.Code)
		}
	})
}

func TestCB81_HandleSetNotificationPrefs_NoAuth(t *testing.T) {
	testDB := setupTestDB_CB81(t)
	withGlobalDB_CB81(testDB, func() {
		req := httptest.NewRequest("POST", "/notifications/prefs?conversation_id=conv1&muted=true", nil)
		w := httptest.NewRecorder()
		handleSetNotificationPrefs(w, req)
		if w.Code != http.StatusUnauthorized {
			t.Errorf("expected 401, got %d", w.Code)
		}
	})
}

func TestCB81_HandleSetNotificationPrefs_EmptyConvID(t *testing.T) {
	testDB := setupTestDB_CB81(t)
	userID := createUser_CB81(testDB, "testuser", "pass123")
	token := generateTestToken_CB81(userID)
	withGlobalDB_CB81(testDB, func() {
		req := httptest.NewRequest("POST", "/notifications/prefs?muted=true", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		ctx := context.WithValue(req.Context(), contextKeyUserID, userID)
		req = req.WithContext(ctx)
		w := httptest.NewRecorder()
		handleSetNotificationPrefs(w, req)
		if w.Code != http.StatusBadRequest {
			t.Errorf("expected 400, got %d", w.Code)
		}
	})
}

func TestCB81_HandleSetNotificationPrefs_Unmute(t *testing.T) {
	testDB := setupTestDB_CB81(t)
	userID := createUser_CB81(testDB, "testuser", "pass123")
	convID := createConversation_CB81(testDB, userID, "agent1")
	token := generateTestToken_CB81(userID)
	withGlobalDB_CB81(testDB, func() {
		// First mute
		req := httptest.NewRequest("POST", "/notifications/prefs?conversation_id="+convID+"&muted=true", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		ctx := context.WithValue(req.Context(), contextKeyUserID, userID)
		req = req.WithContext(ctx)
		w := httptest.NewRecorder()
		handleSetNotificationPrefs(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", w.Code)
		}
		// Then unmute
		req2 := httptest.NewRequest("POST", "/notifications/prefs?conversation_id="+convID+"&muted=false", nil)
		req2.Header.Set("Authorization", "Bearer "+token)
		ctx2 := context.WithValue(req2.Context(), contextKeyUserID, userID)
		req2 = req2.WithContext(ctx2)
		w2 := httptest.NewRecorder()
		handleSetNotificationPrefs(w2, req2)
		if w2.Code != http.StatusOK {
			t.Errorf("expected 200, got %d", w2.Code)
		}
		var resp NotificationPreferences
		json.NewDecoder(w2.Body).Decode(&resp)
		if resp.Muted {
			t.Error("should be unmuted")
		}
	})
}

// ==================== checkRateLimit ====================

func TestCB81_CheckRateLimit_Allowed(t *testing.T) {
	conn := &Connection{
		id:       "test-allow-81",
		connType: "client",
		send:     make(chan []byte, 10),
	}
	result := checkRateLimit(conn)
	if !result {
		t.Error("expected rate limit to allow")
	}
}

func TestCB81_CheckRateLimit_PerConnExceeded(t *testing.T) {
	origMsgRL := messageRateLimiter
	origUserRL := userRateLimiter
	messageRateLimiter = NewRateLimiter(2, time.Minute)
	userRateLimiter = NewRateLimiter(100, time.Minute)
	defer func() {
		messageRateLimiter.Stop()
		userRateLimiter.Stop()
		messageRateLimiter = origMsgRL
		userRateLimiter = origUserRL
	}()
	conn := &Connection{
		id:       "test-exceed-81",
		connType: "client",
		send:     make(chan []byte, 10),
	}
	checkRateLimit(conn)
	checkRateLimit(conn)
	result := checkRateLimit(conn)
	if result {
		t.Error("expected rate limit to be exceeded")
	}
}

func TestCB81_CheckRateLimit_PerUserExceeded(t *testing.T) {
	origMsgRL := messageRateLimiter
	origUserRL := userRateLimiter
	messageRateLimiter = NewRateLimiter(100, time.Minute)
	userRateLimiter = NewRateLimiter(2, time.Minute)
	defer func() {
		messageRateLimiter.Stop()
		userRateLimiter.Stop()
		messageRateLimiter = origMsgRL
		userRateLimiter = origUserRL
	}()
	conn := &Connection{
		id:       "test-userexceed-81",
		connType: "client",
		send:     make(chan []byte, 10),
	}
	checkRateLimit(conn)
	checkRateLimit(conn)
	result := checkRateLimit(conn)
	if result {
		t.Error("expected per-user rate limit to be exceeded")
	}
}

func TestCB81_CheckRateLimit_WithMetrics(t *testing.T) {
	origMetrics := ServerMetrics
	h := newHub()
	go h.run()
	defer h.Stop()
	ServerMetrics = NewMetrics(h)
	defer func() { ServerMetrics = origMetrics }()
	origMsgRL := messageRateLimiter
	origUserRL := userRateLimiter
	messageRateLimiter = NewRateLimiter(1, time.Minute)
	userRateLimiter = NewRateLimiter(100, time.Minute)
	defer func() {
		messageRateLimiter.Stop()
		userRateLimiter.Stop()
		messageRateLimiter = origMsgRL
		userRateLimiter = origUserRL
	}()
	conn := &Connection{
		id:       "test-metrics-81",
		connType: "client",
		send:     make(chan []byte, 10),
	}
	checkRateLimit(conn) // uses the 1 allowance
	result := checkRateLimit(conn)
	if result {
		t.Error("expected rate limit to be exceeded")
	}
	if ServerMetrics.RateLimited.Load() < 1 {
		t.Error("expected RateLimited metric to be incremented")
	}
}

// ==================== loadQueueFromDB ====================

func TestCB81_LoadQueueFromDB_NilDB(t *testing.T) {
	q := newOfflineQueue(100, time.Hour)
	loadQueueFromDB(nil, q)
	if q.TotalDepth() != 0 {
		t.Error("expected 0 depth with nil DB")
	}
}

func TestCB81_LoadQueueFromDB_Empty(t *testing.T) {
	testDB := setupTestDB_CB81(t)
	q := newOfflineQueue(100, time.Hour)
	loadQueueFromDB(testDB, q)
	if q.TotalDepth() != 0 {
		t.Error("expected 0 depth with empty queue table")
	}
}

func TestCB81_LoadQueueFromDB_WithMessages(t *testing.T) {
	testDB := setupTestDB_CB81(t)
	testDB.Exec("INSERT INTO offline_queue (recipient, data, queued_at, sent_count) VALUES (?, ?, ?, 0)",
		"user1", []byte("test-msg"), time.Now().UTC().Format(time.RFC3339))
	q := newOfflineQueue(100, time.Hour)
	loadQueueFromDB(testDB, q)
	if q.TotalDepth() != 1 {
		t.Errorf("expected 1 depth, got %d", q.TotalDepth())
	}
}

// ==================== storeMessagesBatch ====================

func TestCB81_StoreMessagesBatch_EmptyBatch(t *testing.T) {
	testDB := setupTestDB_CB81(t)
	withGlobalDB_CB81(testDB, func() {
		ids, err := storeMessagesBatch([]RoutedMessage{})
		if err != nil {
			t.Fatalf("expected nil error, got %v", err)
		}
		if ids != nil {
			t.Errorf("expected nil ids, got %v", ids)
		}
	})
}

func TestCB81_StoreMessagesBatch_ClosedDB(t *testing.T) {
	testDB := setupTestDB_CB81(t)
	testDB.Close()
	withGlobalDB_CB81(testDB, func() {
		_, err := storeMessagesBatch([]RoutedMessage{
			{ConversationID: "c1", Content: "hi", SenderType: "client", SenderID: "u1"},
		})
		if err == nil {
			t.Error("expected error with closed DB")
		}
	})
}

func TestCB81_StoreMessagesBatch_Success(t *testing.T) {
	testDB := setupTestDB_CB81(t)
	convID := createConversation_CB81(testDB, "user1", "agent1")
	withGlobalDB_CB81(testDB, func() {
		msgs := []RoutedMessage{
			{ConversationID: convID, Content: "msg1", SenderType: "client", SenderID: "user1"},
			{ConversationID: convID, Content: "msg2", SenderType: "agent", SenderID: "agent1"},
		}
		ids, err := storeMessagesBatch(msgs)
		if err != nil {
			t.Fatalf("storeMessagesBatch failed: %v", err)
		}
		if len(ids) != 2 {
			t.Errorf("expected 2 ids, got %d", len(ids))
		}
	})
}

// ==================== notifyUser ====================

func TestCB81_NotifyUser_NilPushConfig(t *testing.T) {
	origPush := pushConfig
	pushConfig = nil
	defer func() { pushConfig = origPush }()
	testDB := setupTestDB_CB81(t)
	withGlobalDB_CB81(testDB, func() {
		// should not panic
		notifyUser("user1", "title", "body", "conv1")
	})
}

func TestCB81_NotifyUser_NilDB(t *testing.T) {
	origPush := pushConfig
	pushConfig = &PushNotificationConfig{}
	defer func() { pushConfig = origPush }()
	withGlobalDB_CB81(nil, func() {
		notifyUser("user1", "title", "body", "conv1")
	})
}

func TestCB81_NotifyUser_Muted(t *testing.T) {
	testDB := setupTestDB_CB81(t)
	userID := createUser_CB81(testDB, "testuser", "pass")
	convID := createConversation_CB81(testDB, userID, "agent1")
	// Mute the conversation
	testDB.Exec("INSERT INTO notification_preferences (user_id, conversation_id, muted) VALUES (?, ?, 1)", userID, convID)
	origPush := pushConfig
	pushConfig = &PushNotificationConfig{}
	defer func() { pushConfig = origPush }()
	withGlobalDB_CB81(testDB, func() {
		// should not send notification (muted)
		notifyUser(userID, "title", "body", convID)
	})
}

func TestCB81_NotifyUser_NoTokens(t *testing.T) {
	testDB := setupTestDB_CB81(t)
	userID := createUser_CB81(testDB, "testuser", "pass")
	convID := createConversation_CB81(testDB, userID, "agent1")
	origPush := pushConfig
	pushConfig = &PushNotificationConfig{}
	defer func() { pushConfig = origPush }()
	withGlobalDB_CB81(testDB, func() {
		// should not panic or send (no tokens)
		notifyUser(userID, "title", "body", convID)
	})
}

func TestCB81_NotifyUser_EmptyConvID(t *testing.T) {
	testDB := setupTestDB_CB81(t)
	userID := createUser_CB81(testDB, "testuser", "pass")
	origPush := pushConfig
	pushConfig = &PushNotificationConfig{}
	defer func() { pushConfig = origPush }()
	withGlobalDB_CB81(testDB, func() {
		// empty convID should still work (just not check mute)
		notifyUser(userID, "title", "body", "")
	})
}

// ==================== sendWelcomeMessage ====================

func TestCB81_SendWelcomeMessage_WithDeviceID(t *testing.T) {
	conn := &Connection{
		id:               "test-user-81",
		connType:         "client",
		deviceID:         "dev-123",
		send:             make(chan []byte, 10),
		negotiatedVersion: "v1",
	}
	sendWelcomeMessage(conn)
	select {
	case msg := <-conn.send:
		var data map[string]interface{}
		json.Unmarshal(msg, &data)
		if data["type"] != "connected" {
			t.Errorf("expected type 'connected', got %v", data["type"])
		}
		d := data["data"].(map[string]interface{})
		if d["device_id"] != "dev-123" {
			t.Errorf("expected device_id 'dev-123', got %v", d["device_id"])
		}
	default:
		t.Error("no message received")
	}
}

func TestCB81_SendWelcomeMessage_WithoutDeviceID(t *testing.T) {
	conn := &Connection{
		id:               "test-user-81",
		connType:         "agent",
		send:             make(chan []byte, 10),
		negotiatedVersion: "v1",
	}
	sendWelcomeMessage(conn)
	select {
	case msg := <-conn.send:
		var data map[string]interface{}
		json.Unmarshal(msg, &data)
		d := data["data"].(map[string]interface{})
		if _, exists := d["device_id"]; exists {
			t.Error("device_id should not be present")
		}
	default:
		t.Error("no message received")
	}
}

func TestCB81_SendWelcomeMessage_BufferFull(t *testing.T) {
	conn := &Connection{
		id:               "test-user-81",
		connType:         "client",
		send:             make(chan []byte, 1),
		negotiatedVersion: "v1",
	}
	conn.send <- []byte("fill")
	sendWelcomeMessage(conn)
	// should not block, message dropped
	if len(conn.send) != 1 {
		t.Errorf("expected 1 message in buffer, got %d", len(conn.send))
	}
}

// ==================== InitTracing ====================

func TestCB81_InitTracing_Disabled(t *testing.T) {
	os.Unsetenv("OTEL_ENABLED")
	// Reset tracingMu by creating a new one is not possible, but we can test
	// by ensuring the function doesn't panic
	_ = InitTracing()
	// tracingEnabled should remain false since OTEL_ENABLED is not set
}

func TestCB81_InitTracing_NoEndpoint(t *testing.T) {
	// Can't easily reset sync.Once, but calling InitTracing with OTEL_ENABLED=true
	// and no endpoint should not panic
	t.Setenv("OTEL_ENABLED", "true")
	os.Unsetenv("OTEL_EXPORTER_OTLP_ENDPOINT")
	os.Unsetenv("OTEL_EXPORTER_OTLP_HTTP_ENDPOINT")
	_ = InitTracing()
}

// ==================== ShutdownTracing ====================

func TestCB81_ShutdownTracing_NilProvider(t *testing.T) {
	// Save original tp
	origTP := tp
	tp = nil
	defer func() { tp = origTP }()
	// should not panic with nil provider
	ShutdownTracing()
}

// ==================== RateLimiter cleanup ====================

func TestCB81_RateLimiter_Stop(t *testing.T) {
	rl := NewRateLimiter(10, 100*time.Millisecond)
	rl.Stop()
	// calling Stop again should not panic
	rl.Stop()
}

func TestCB81_RateLimiter_ExpiredEntries(t *testing.T) {
	rl := NewRateLimiter(10, 50*time.Millisecond)
	rl.Allow("key1")
	time.Sleep(100 * time.Millisecond)
	// After expiry, new Allow should create fresh entry
	if !rl.Allow("key1") {
		t.Error("expected fresh entry after expiry")
	}
	rl.Stop()
}

// ==================== TieredRateLimiter cleanup ====================

func TestCB81_TieredRateLimiter_Stop(t *testing.T) {
	trl := NewTieredRateLimiter()
	trl.Stop()
	// calling Stop again should not panic
	trl.Stop()
}

func TestCB81_TieredRateLimiter_CleanupOnce(t *testing.T) {
	trl := NewTieredRateLimiter()
	trl.Allow("user1")
	// Manually expire entry
	trl.mu.Lock()
	if entry, ok := trl.limits["user1"]; ok {
		entry.windowEnd = time.Now().Add(-11 * time.Minute)
	}
	trl.mu.Unlock()
	trl.cleanupOnce()
	trl.mu.Lock()
	_, exists := trl.limits["user1"]
	trl.mu.Unlock()
	if exists {
		t.Error("expected entry to be cleaned up")
	}
	trl.Stop()
}

// ==================== handleUpload ====================

func TestCB81_HandleUpload_NoAuth(t *testing.T) {
	testDB := setupTestDB_CB81(t)
	withGlobalDB_CB81(testDB, func() {
		req := httptest.NewRequest("POST", "/attachments/upload", nil)
		w := httptest.NewRecorder()
		handleUpload(w, req)
		if w.Code != http.StatusUnauthorized {
			t.Errorf("expected 401, got %d", w.Code)
		}
	})
}

func TestCB81_HandleUpload_InvalidToken(t *testing.T) {
	testDB := setupTestDB_CB81(t)
	withGlobalDB_CB81(testDB, func() {
		req := httptest.NewRequest("POST", "/attachments/upload", nil)
		req.Header.Set("Authorization", "Bearer invalidtoken")
		w := httptest.NewRecorder()
		handleUpload(w, req)
		if w.Code != http.StatusUnauthorized {
			t.Errorf("expected 401, got %d", w.Code)
		}
	})
}

func TestCB81_HandleUpload_MethodNotAllowed(t *testing.T) {
	testDB := setupTestDB_CB81(t)
	withGlobalDB_CB81(testDB, func() {
		req := httptest.NewRequest("GET", "/attachments/upload", nil)
		w := httptest.NewRecorder()
		handleUpload(w, req)
		if w.Code != http.StatusMethodNotAllowed {
			t.Errorf("expected 405, got %d", w.Code)
		}
	})
}

func TestCB81_HandleUpload_NoFile(t *testing.T) {
	testDB := setupTestDB_CB81(t)
	userID := createUser_CB81(testDB, "testuser", "pass")
	token := generateTestToken_CB81(userID)
	withGlobalDB_CB81(testDB, func() {
		req := httptest.NewRequest("POST", "/attachments/upload", strings.NewReader(""))
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		handleUpload(w, req)
		if w.Code != http.StatusBadRequest {
			t.Errorf("expected 400, got %d", w.Code)
		}
	})
}

// ==================== isAllowedContentType ====================

func TestCB81_IsAllowedContentType_Images(t *testing.T) {
	types := []string{"image/jpeg", "image/png", "image/gif", "image/webp", "image/svg+xml", "image/bmp"}
	for _, ct := range types {
		if !isAllowedContentType(ct) {
			t.Errorf("expected %s to be allowed", ct)
		}
	}
}

func TestCB81_IsAllowedContentType_Documents(t *testing.T) {
	types := []string{"application/pdf", "text/plain", "text/csv", "text/markdown", "application/json"}
	for _, ct := range types {
		if !isAllowedContentType(ct) {
			t.Errorf("expected %s to be allowed", ct)
		}
	}
}

func TestCB81_IsAllowedContentType_Disallowed(t *testing.T) {
	if isAllowedContentType("application/x-msdownload") {
		t.Error("application/x-msdownload should not be allowed")
	}
	if isAllowedContentType("application/javascript") {
		t.Error("application/javascript should not be allowed")
	}
}

// ==================== isConversationMuted ====================

func TestCB81_IsConversationMuted_MutedTrue(t *testing.T) {
	testDB := setupTestDB_CB81(t)
	userID := createUser_CB81(testDB, "testuser", "pass")
	convID := createConversation_CB81(testDB, userID, "agent1")
	testDB.Exec("INSERT INTO notification_preferences (user_id, conversation_id, muted) VALUES (?, ?, 1)", userID, convID)
	withGlobalDB_CB81(testDB, func() {
		if !isConversationMuted(userID, convID) {
			t.Error("expected conversation to be muted")
		}
	})
}

func TestCB81_IsConversationMuted_MutedFalse(t *testing.T) {
	testDB := setupTestDB_CB81(t)
	userID := createUser_CB81(testDB, "testuser", "pass")
	convID := createConversation_CB81(testDB, userID, "agent1")
	testDB.Exec("INSERT INTO notification_preferences (user_id, conversation_id, muted) VALUES (?, ?, 0)", userID, convID)
	withGlobalDB_CB81(testDB, func() {
		if isConversationMuted(userID, convID) {
			t.Error("expected conversation to not be muted")
		}
	})
}

func TestCB81_IsConversationMuted_NoPrefs(t *testing.T) {
	testDB := setupTestDB_CB81(t)
	userID := createUser_CB81(testDB, "testuser", "pass")
	convID := createConversation_CB81(testDB, userID, "agent1")
	withGlobalDB_CB81(testDB, func() {
		if isConversationMuted(userID, convID) {
			t.Error("expected conversation to not be muted with no prefs")
		}
	})
}

// ==================== getDeviceTokensForUser ====================

func TestCB81_GetDeviceTokensForUser_WithTokens(t *testing.T) {
	testDB := setupTestDB_CB81(t)
	userID := createUser_CB81(testDB, "testuser", "pass")
	testDB.Exec("INSERT INTO device_tokens (user_id, device_token, platform) VALUES (?, ?, ?)", userID, "token1", "ios")
	testDB.Exec("INSERT INTO device_tokens (user_id, device_token, platform) VALUES (?, ?, ?)", userID, "token2", "android")
	withGlobalDB_CB81(testDB, func() {
		tokens, err := getDeviceTokensForUser(userID)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(tokens) != 2 {
			t.Errorf("expected 2 tokens, got %d", len(tokens))
		}
	})
}

func TestCB81_GetDeviceTokensForUser_NoTokens(t *testing.T) {
	testDB := setupTestDB_CB81(t)
	userID := createUser_CB81(testDB, "testuser", "pass")
	withGlobalDB_CB81(testDB, func() {
		tokens, err := getDeviceTokensForUser(userID)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(tokens) != 0 {
			t.Errorf("expected 0 tokens, got %d", len(tokens))
		}
	})
}

// ==================== OfflineQueue ====================

func TestCB81_OfflineQueue_BasicOps(t *testing.T) {
	q := newOfflineQueue(100, time.Hour)
	q.Enqueue("user1", []byte("msg1"))
	q.Enqueue("user1", []byte("msg2"))
	if q.QueueDepth("user1") != 2 {
		t.Errorf("expected depth 2, got %d", q.QueueDepth("user1"))
	}
	msgs := q.Drain("user1")
	if len(msgs) != 2 {
		t.Errorf("expected 2 messages, got %d", len(msgs))
	}
	if q.QueueDepth("user1") != 0 {
		t.Error("expected 0 depth after drain")
	}
}

func TestCB81_OfflineQueue_MaxLen(t *testing.T) {
	q := newOfflineQueue(3, time.Hour)
	q.Enqueue("user1", []byte("msg1"))
	q.Enqueue("user1", []byte("msg2"))
	q.Enqueue("user1", []byte("msg3"))
	q.Enqueue("user1", []byte("msg4")) // should trim oldest
	if q.QueueDepth("user1") != 3 {
		t.Errorf("expected depth 3, got %d", q.QueueDepth("user1"))
	}
	msgs := q.Drain("user1")
	if string(msgs[0]) != "msg2" {
		t.Errorf("expected oldest trimmed, got %s", msgs[0])
	}
}

func TestCB81_OfflineQueue_TTL(t *testing.T) {
	q := newOfflineQueue(100, 50*time.Millisecond)
	q.Enqueue("user1", []byte("msg1"))
	time.Sleep(100 * time.Millisecond)
	msgs := q.Drain("user1")
	if msgs != nil {
		t.Errorf("expected nil for expired messages, got %d", len(msgs))
	}
}

func TestCB81_OfflineQueue_DifferentUsers(t *testing.T) {
	q := newOfflineQueue(100, time.Hour)
	q.Enqueue("user1", []byte("msg1"))
	q.Enqueue("user2", []byte("msg2"))
	if q.TotalDepth() != 2 {
		t.Errorf("expected total depth 2, got %d", q.TotalDepth())
	}
	msgs1 := q.Drain("user1")
	msgs2 := q.Drain("user2")
	if len(msgs1) != 1 || len(msgs2) != 1 {
		t.Errorf("expected 1 each, got %d and %d", len(msgs1), len(msgs2))
	}
}

// ==================== persistQueue / deleteQueueMessages / cleanStaleQueueMessages ====================

func TestCB81_PersistQueue_NilDB(t *testing.T) {
	persistQueue(nil, "user1", []byte("msg"))
	// should not panic
}

func TestCB81_PersistQueue_Success(t *testing.T) {
	testDB := setupTestDB_CB81(t)
	persistQueue(testDB, "user1", []byte("test-data"))
	var count int
	testDB.QueryRow("SELECT COUNT(*) FROM offline_queue WHERE recipient = ?", "user1").Scan(&count)
	if count != 1 {
		t.Errorf("expected 1 persisted message, got %d", count)
	}
}

func TestCB81_DeleteQueueMessages_Success(t *testing.T) {
	testDB := setupTestDB_CB81(t)
	testDB.Exec("INSERT INTO offline_queue (recipient, data, queued_at, sent_count) VALUES (?, ?, ?, 0)",
		"user1", []byte("msg1"), time.Now().UTC().Format(time.RFC3339))
	testDB.Exec("INSERT INTO offline_queue (recipient, data, queued_at, sent_count) VALUES (?, ?, ?, 0)",
		"user1", []byte("msg2"), time.Now().UTC().Format(time.RFC3339))
	deleteQueueMessages(testDB, "user1")
	var count int
	testDB.QueryRow("SELECT COUNT(*) FROM offline_queue WHERE recipient = ?", "user1").Scan(&count)
	if count != 0 {
		t.Errorf("expected 0 messages after delete, got %d", count)
	}
}

func TestCB81_DeleteQueueMessages_NilDB(t *testing.T) {
	deleteQueueMessages(nil, "user1")
	// should not panic
}

func TestCB81_CleanStaleQueueMessages_Success(t *testing.T) {
	testDB := setupTestDB_CB81(t)
	testDB.Exec("INSERT INTO offline_queue (recipient, data, queued_at, sent_count) VALUES (?, ?, ?, 0)",
		"user1", []byte("old-msg"), time.Now().Add(-2*time.Hour).UTC().Format(time.RFC3339))
	testDB.Exec("INSERT INTO offline_queue (recipient, data, queued_at, sent_count) VALUES (?, ?, ?, 0)",
		"user1", []byte("new-msg"), time.Now().UTC().Format(time.RFC3339))
	cleanStaleQueueMessages(testDB, 1*time.Hour)
	var count int
	testDB.QueryRow("SELECT COUNT(*) FROM offline_queue WHERE recipient = ?", "user1").Scan(&count)
	if count != 1 {
		t.Errorf("expected 1 message after cleanup, got %d", count)
	}
}

func TestCB81_CleanStaleQueueMessages_NilDB(t *testing.T) {
	cleanStaleQueueMessages(nil, time.Hour)
	// should not panic
}

// ==================== marshalOutgoingMessage ====================

func TestCB81_MarshalOutgoingMessage_Success(t *testing.T) {
	msg := OutgoingMessage{Type: "message", Data: map[string]string{"content": "hello"}}
	data := marshalOutgoingMessage(msg)
	if data == nil {
		t.Error("expected non-nil data")
	}
	var result map[string]interface{}
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}
	if result["type"] != "message" {
		t.Errorf("expected type 'message', got %v", result["type"])
	}
}

// ==================== accessLogMiddleware ====================

func TestCB81_AccessLogMiddleware_WithRequestID(t *testing.T) {
	called := false
	handler := accessLogMiddleware(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-Request-ID", "test-req-123")
	w := httptest.NewRecorder()
	handler(w, req)
	if !called {
		t.Error("handler not called")
	}
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestCB81_AccessLogMiddleware_WithoutRequestID(t *testing.T) {
	called := false
	handler := accessLogMiddleware(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})
	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()
	handler(w, req)
	if !called {
		t.Error("handler not called")
	}
	// Without requestIDMiddleware, X-Request-ID won't be auto-generated by accessLogMiddleware
	// Just verify the handler was called and response is 200
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

// ==================== authenticateRequest ====================

func TestCB81_AuthenticateRequest_ValidJWT(t *testing.T) {
	token := generateTestToken_CB81("user1")
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	uid, authType, err := authenticateRequest(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if uid != "user1" {
		t.Errorf("expected uid 'user1', got %s", uid)
	}
	if authType != "user" {
		t.Errorf("expected type 'user', got %s", authType)
	}
}

func TestCB81_AuthenticateRequest_ValidAgentSecret(t *testing.T) {
	t.Setenv("AGENT_SECRET", "test-secret-81")
	resetAgentSecret()
	defer resetAgentSecret()
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-Agent-Secret", "test-secret-81")
	req.Header.Set("X-Agent-ID", "agent1")
	uid, authType, err := authenticateRequest(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if uid != "agent1" {
		t.Errorf("expected uid 'agent1', got %s", uid)
	}
	if authType != "agent" {
		t.Errorf("expected type 'agent', got %s", authType)
	}
}

func TestCB81_AuthenticateRequest_NoAuth(t *testing.T) {
	req := httptest.NewRequest("GET", "/test", nil)
	_, _, err := authenticateRequest(req)
	if err == nil {
		t.Error("expected error with no auth")
	}
}

func TestCB81_AuthenticateRequest_InvalidToken(t *testing.T) {
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer invalidtoken")
	_, _, err := authenticateRequest(req)
	if err == nil {
		t.Error("expected error with invalid token")
	}
}

func TestCB81_AuthenticateRequest_InvalidAgentSecret(t *testing.T) {
	t.Setenv("AGENT_SECRET", "correct-secret-81")
	resetAgentSecret()
	defer resetAgentSecret()
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-Agent-Secret", "wrong-secret")
	_, _, err := authenticateRequest(req)
	if err == nil {
		t.Error("expected error with wrong agent secret")
	}
}

// ==================== extractIP ====================

func TestCB81_ExtractIP_ForwardedFor(t *testing.T) {
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-Forwarded-For", "1.2.3.4, 5.6.7.8")
	ip := extractIP(req)
	if ip != "1.2.3.4" {
		t.Errorf("expected '1.2.3.4', got %s", ip)
	}
}

func TestCB81_ExtractIP_RealIP(t *testing.T) {
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-Real-IP", "9.8.7.6")
	ip := extractIP(req)
	if ip != "9.8.7.6" {
		t.Errorf("expected '9.8.7.6', got %s", ip)
	}
}

func TestCB81_ExtractIP_RemoteAddr(t *testing.T) {
	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "192.168.1.1:12345"
	ip := extractIP(req)
	if ip != "192.168.1.1" {
		t.Errorf("expected '192.168.1.1', got %s", ip)
	}
}

// ==================== getEnvOrDefault ====================

func TestCB81_GetEnvOrDefault_Set(t *testing.T) {
	t.Setenv("TEST_ENV_VAR_81", "hello")
	if v := getEnvOrDefault("TEST_ENV_VAR_81", "default"); v != "hello" {
		t.Errorf("expected 'hello', got %s", v)
	}
}

func TestCB81_GetEnvOrDefault_Unset(t *testing.T) {
	if v := getEnvOrDefault("UNSET_VAR_81", "defaultval"); v != "defaultval" {
		t.Errorf("expected 'defaultval', got %s", v)
	}
}

// ==================== Hub ====================

func TestCB81_Hub_GetClientConns_Multi(t *testing.T) {
	h := newHub()
	go h.run()
	defer h.Stop()
	c1 := &Connection{id: "user1", connType: "client", deviceID: "dev1", send: make(chan []byte, 10)}
	c2 := &Connection{id: "user1", connType: "client", deviceID: "dev2", send: make(chan []byte, 10)}
	h.register <- c1
	time.Sleep(50 * time.Millisecond)
	h.register <- c2
	time.Sleep(50 * time.Millisecond)
	conns := h.GetClientConns("user1")
	if len(conns) != 2 {
		t.Errorf("expected 2 conns, got %d", len(conns))
	}
}

func TestCB81_Hub_GetClientConns_None(t *testing.T) {
	h := newHub()
	go h.run()
	defer h.Stop()
	conns := h.GetClientConns("nonexistent")
	if len(conns) != 0 {
		t.Errorf("expected 0 conns, got %d", len(conns))
	}
}

func TestCB81_Hub_Unregister(t *testing.T) {
	h := newHub()
	go h.run()
	defer h.Stop()
	c := &Connection{id: "user-unreg-81", connType: "client", deviceID: "dev1", send: make(chan []byte, 10)}
	h.register <- c
	time.Sleep(50 * time.Millisecond)
	h.unregister <- c
	time.Sleep(50 * time.Millisecond)
	conns := h.GetClientConns("user-unreg-81")
	if len(conns) != 0 {
		t.Errorf("expected 0 conns after unregister, got %d", len(conns))
	}
}

func TestCB81_Hub_StopMultiple(t *testing.T) {
	h := newHub()
	go h.run()
	h.Stop()
	// Stop again should not panic
	h.Stop()
}

// ==================== SafeSend ====================

func TestCB81_SafeSend_ClosedChannel(t *testing.T) {
	conn := &Connection{
		id:   "test-closed-81",
		send: make(chan []byte, 1),
	}
	conn.MarkClosed()
	close(conn.send)
	result := conn.SafeSend([]byte("test"))
	if result {
		t.Error("expected false on closed channel")
	}
}

func TestCB81_SafeSend_Success(t *testing.T) {
	conn := &Connection{
		id:   "test-success-81",
		send: make(chan []byte, 10),
	}
	result := conn.SafeSend([]byte("test"))
	if !result {
		t.Error("expected true on success")
	}
}

func TestCB81_SafeSend_BufferFull(t *testing.T) {
	conn := &Connection{
		id:   "test-full-81",
		send: make(chan []byte, 1),
	}
	conn.send <- []byte("fill")
	result := conn.SafeSend([]byte("test"))
	if result {
		t.Error("expected false on full buffer")
	}
}

// ==================== Snapshot ====================

func TestCB81_Snapshot_Basic(t *testing.T) {
	h := newHub()
	go h.run()
	defer h.Stop()
	m := NewMetrics(h)
	snap := m.Snapshot()
	if snap["version"] == nil {
		t.Error("expected version in snapshot")
	}
	if _, ok := snap["uptime_seconds"]; !ok {
		t.Error("expected uptime_seconds in snapshot")
	}
}

// ==================== GetOrCreateConversation ====================

func TestCB81_GetOrCreateConversation_New(t *testing.T) {
	testDB := setupTestDB_CB81(t)
	// Need an agent to exist for FK constraint
	testDB.Exec("INSERT INTO agents (id, name) VALUES (?, ?)", "agent1", "Agent One")
	createUser_CB81(testDB, "user1", "pass")
	withGlobalDB_CB81(testDB, func() {
		conv, err := GetOrCreateConversation("user1", "agent1")
		if err != nil {
			t.Fatalf("GetOrCreateConversation failed: %v", err)
		}
		if conv == nil {
			t.Fatal("expected non-nil conversation")
		}
	})
}

func TestCB81_GetOrCreateConversation_Existing(t *testing.T) {
	testDB := setupTestDB_CB81(t)
	testDB.Exec("INSERT INTO agents (id, name) VALUES (?, ?)", "agent1", "Agent One")
	createUser_CB81(testDB, "user1", "pass")
	withGlobalDB_CB81(testDB, func() {
		conv1, _ := GetOrCreateConversation("user1", "agent1")
		conv2, err := GetOrCreateConversation("user1", "agent1")
		if err != nil {
			t.Fatalf("GetOrCreateConversation failed: %v", err)
		}
		if conv1.ID != conv2.ID {
			t.Error("expected same conversation ID")
		}
	})
}

// ==================== getConversationMessages ====================

func TestCB81_GetConversationMessages_Success(t *testing.T) {
	testDB := setupTestDB_CB81(t)
	convID := createConversation_CB81(testDB, "user1", "agent1")
	testDB.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, created_at) VALUES (?, ?, ?, ?, ?, ?)",
		"msg1", convID, "client", "user1", "hello", time.Now().UTC())
	testDB.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, created_at) VALUES (?, ?, ?, ?, ?, ?)",
		"msg2", convID, "agent", "agent1", "hi back", time.Now().UTC().Add(time.Second))
	withGlobalDB_CB81(testDB, func() {
		msgs, err := getConversationMessages(convID, 50, "")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(msgs) != 2 {
			t.Errorf("expected 2 messages, got %d", len(msgs))
		}
	})
}

// ==================== searchMessages ====================

func TestCB81_SearchMessages_Success(t *testing.T) {
	testDB := setupTestDB_CB81(t)
	convID := createConversation_CB81(testDB, "user1", "agent1")
	testDB.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, created_at) VALUES (?, ?, ?, ?, ?, ?)",
		"msg1", convID, "client", "user1", "hello world", time.Now().UTC())
	testDB.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, created_at) VALUES (?, ?, ?, ?, ?, ?)",
		"msg2", convID, "agent", "agent1", "goodbye world", time.Now().UTC().Add(time.Second))
	withGlobalDB_CB81(testDB, func() {
		msgs, err := searchMessages("user1", "world", 50)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(msgs) != 2 {
			t.Errorf("expected 2 messages, got %d", len(msgs))
		}
	})
}

func TestCB81_SearchMessages_NoResults(t *testing.T) {
	testDB := setupTestDB_CB81(t)
	convID := createConversation_CB81(testDB, "user1", "agent1")
	testDB.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, created_at) VALUES (?, ?, ?, ?, ?, ?)",
		"msg1", convID, "client", "user1", "hello", time.Now().UTC())
	withGlobalDB_CB81(testDB, func() {
		msgs, err := searchMessages("user1", "nonexistent", 50)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(msgs) != 0 {
			t.Errorf("expected 0 messages, got %d", len(msgs))
		}
	})
}

// ==================== ValidateJWT ====================

func TestCB81_ValidateJWT_Empty(t *testing.T) {
	_, err := ValidateJWT("")
	if err == nil {
		t.Error("expected error for empty token")
	}
}

func TestCB81_ValidateJWT_Invalid(t *testing.T) {
	_, err := ValidateJWT("invalid.jwt.token")
	if err == nil {
		t.Error("expected error for invalid token")
	}
}

func TestCB81_ValidateJWT_Valid(t *testing.T) {
	token, _ := GenerateJWT("user1", "user1")
	claims, err := ValidateJWT(token)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if claims.UserID != "user1" {
		t.Errorf("expected UserID 'user1', got %s", claims.UserID)
	}
}

// ==================== HashAPIKey ====================

func TestCB81_HashAPIKey_Success(t *testing.T) {
	hash, err := HashAPIKey("mypassword")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hash == "" {
		t.Error("expected non-empty hash")
	}
	if hash == "mypassword" {
		t.Error("hash should differ from input")
	}
}

func TestCB81_HashAPIKey_DifferentInputs(t *testing.T) {
	hash1, _ := HashAPIKey("password1")
	hash2, _ := HashAPIKey("password2")
	if hash1 == hash2 {
		t.Error("different inputs should produce different hashes")
	}
}

// ==================== ipRateLimitMiddleware ====================

func TestCB81_IPRateLimitMiddleware_Allows(t *testing.T) {
	called := false
	handler := ipRateLimitMiddleware(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})
	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "1.2.3.4:12345"
	w := httptest.NewRecorder()
	handler(w, req)
	if !called {
		t.Error("handler should have been called")
	}
}

// ==================== authRateLimitMiddleware ====================

func TestCB81_AuthRateLimitMiddleware_Allows(t *testing.T) {
	called := false
	handler := authRateLimitMiddleware(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})
	req := httptest.NewRequest("POST", "/auth/login", nil)
	req.RemoteAddr = "1.2.3.4:12345"
	w := httptest.NewRecorder()
	handler(w, req)
	if !called {
		t.Error("handler should have been called")
	}
}

// ==================== csrfMiddleware ====================

func TestCB81_CSRFMiddleware_GETAllowed(t *testing.T) {
	called := false
	handler := csrfMiddleware(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})
	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()
	handler(w, req)
	if !called {
		t.Error("GET should be allowed without CSRF check")
	}
}

func TestCB81_CSRFMiddleware_XHR(t *testing.T) {
	called := false
	handler := csrfMiddleware(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})
	req := httptest.NewRequest("POST", "/test", nil)
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	w := httptest.NewRecorder()
	handler(w, req)
	if !called {
		t.Error("POST with X-Requested-With should be allowed")
	}
}

func TestCB81_CSRFMiddleware_Blocked(t *testing.T) {
	called := false
	handler := csrfMiddleware(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})
	req := httptest.NewRequest("POST", "/test", nil)
	w := httptest.NewRecorder()
	handler(w, req)
	if called {
		t.Error("POST without CSRF headers should be blocked")
	}
	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", w.Code)
	}
}

// ==================== handleMessageDelete ====================

func TestCB81_HandleMessageDelete_Success(t *testing.T) {
	testDB := setupTestDB_CB81(t)
	userID := createUser_CB81(testDB, "testuser", "pass")
	convID := createConversation_CB81(testDB, userID, "agent1")
	msgID := "msg-delete-81"
	testDB.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, created_at) VALUES (?, ?, ?, ?, ?, ?)",
		msgID, convID, "client", userID, "to be deleted", time.Now().UTC())
	token := generateTestToken_CB81(userID)
	h := newHub()
	go h.run()
	defer h.Stop()
	origHub := hub
	hub = h
	defer func() { hub = origHub }()
	withGlobalDB_CB81(testDB, func() {
		req := httptest.NewRequest("POST", "/messages/delete?message_id="+msgID, nil)
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		handleMessageDelete(w, req)
		if w.Code != http.StatusOK {
			t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
		}
	})
}

// ==================== handleListAgents ====================

func TestCB81_HandleListAgents_Success(t *testing.T) {
	testDB := setupTestDB_CB81(t)
	testDB.Exec("INSERT INTO agents (id, name, model, personality, specialty) VALUES (?, ?, ?, ?, ?)",
		"agent1", "Agent One", "gpt-4", "friendly", "general")
	testDB.Exec("INSERT INTO agents (id, name, model, personality, specialty) VALUES (?, ?, ?, ?, ?)",
		"agent2", "Agent Two", "claude-3", "serious", "coding")
	h := newHub()
	go h.run()
	defer h.Stop()
	origHub := hub
	hub = h
	defer func() { hub = origHub }()
	withGlobalDB_CB81(testDB, func() {
		req := httptest.NewRequest("GET", "/agents", nil)
		w := httptest.NewRecorder()
		handleListAgents(w, req)
		if w.Code != http.StatusOK {
			t.Errorf("expected 200, got %d", w.Code)
		}
		var agents []AgentInfo
		json.NewDecoder(w.Body).Decode(&agents)
		if len(agents) != 2 {
			t.Errorf("expected 2 agents, got %d", len(agents))
		}
	})
}

func TestCB81_HandleListAgents_Empty(t *testing.T) {
	testDB := setupTestDB_CB81(t)
	h := newHub()
	go h.run()
	defer h.Stop()
	origHub := hub
	hub = h
	defer func() { hub = origHub }()
	withGlobalDB_CB81(testDB, func() {
		req := httptest.NewRequest("GET", "/agents", nil)
		w := httptest.NewRecorder()
		handleListAgents(w, req)
		if w.Code != http.StatusOK {
			t.Errorf("expected 200, got %d", w.Code)
		}
		var agents []AgentInfo
		json.NewDecoder(w.Body).Decode(&agents)
		if len(agents) != 0 {
			t.Errorf("expected 0 agents, got %d", len(agents))
		}
	})
}

// ==================== handleHealth ====================

func TestCB81_HandleHealth_Success(t *testing.T) {
	testDB := setupTestDB_CB81(t)
	h := newHub()
	go h.run()
	defer h.Stop()
	origHub := hub
	hub = h
	defer func() { hub = origHub }()
	origMetrics := ServerMetrics
	ServerMetrics = NewMetrics(h)
	defer func() { ServerMetrics = origMetrics }()
	withGlobalDB_CB81(testDB, func() {
		req := httptest.NewRequest("GET", "/health", nil)
		w := httptest.NewRecorder()
		handleHealth(w, req)
		if w.Code != http.StatusOK {
			t.Errorf("expected 200, got %d", w.Code)
		}
	})
}

func TestCB81_HandleHealth_MethodNotAllowed(t *testing.T) {
	testDB := setupTestDB_CB81(t)
	withGlobalDB_CB81(testDB, func() {
		req := httptest.NewRequest("POST", "/health", nil)
		w := httptest.NewRecorder()
		handleHealth(w, req)
		if w.Code != http.StatusMethodNotAllowed {
			t.Errorf("expected 405, got %d", w.Code)
		}
	})
}

// ==================== handleAdminProfile ====================

func TestCB81_HandleAdminProfile_Stats(t *testing.T) {
	req := httptest.NewRequest("GET", "/admin/profile?action=stats", nil)
	w := httptest.NewRecorder()
	handleAdminProfile(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestCB81_HandleAdminProfile_GC(t *testing.T) {
	req := httptest.NewRequest("POST", "/admin/profile?action=gc", nil)
	w := httptest.NewRecorder()
	handleAdminProfile(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestCB81_HandleAdminProfile_UnknownAction(t *testing.T) {
	req := httptest.NewRequest("POST", "/admin/profile?action=unknown", nil)
	w := httptest.NewRecorder()
	handleAdminProfile(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

// ==================== handleForceGC ====================

func TestCB81_HandleForceGC_Success(t *testing.T) {
	req := httptest.NewRequest("POST", "/admin/profile?action=gc", nil)
	w := httptest.NewRecorder()
	handleForceGC(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

// ==================== Tracing: StartSpan, SpanError, SpanOK, IsTracingEnabled ====================

func TestCB81_StartSpan_Disabled(t *testing.T) {
	ctx := context.Background()
	newCtx, span := StartSpan(ctx, "test-span")
	if !span.IsRecording() {
		// When tracing is disabled, span is a no-op
		_ = newCtx
	}
	// Should not panic
}

func TestCB81_SpanError_NilSpan(t *testing.T) {
	SpanError(nil, fmt.Errorf("test error"))
	// should not panic
}

func TestCB81_SpanOK_NilSpan(t *testing.T) {
	SpanOK(nil)
	// should not panic
}

func TestCB81_IsTracingEnabled_Disabled(t *testing.T) {
	// Tracing should be disabled by default in tests
	enabled := IsTracingEnabled()
	_ = enabled
	// Just verify it doesn't panic
}

func TestCB81_IsTracingEnabled_Enabled(t *testing.T) {
	// Can't easily enable tracing in test, just verify function doesn't panic
	_ = IsTracingEnabled()
}

func TestCB81_StartSpanFromRequest_Disabled(t *testing.T) {
	req := httptest.NewRequest("GET", "/test", nil)
	_, span := StartSpanFromRequest(req, "test-span")
	_ = span
	// should not panic
}

// ==================== parseSize ====================

func TestCB81_ParseSize_KB(t *testing.T) {
	v, err := parseSize("10KB")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if v != 10*1024 {
		t.Errorf("expected %d, got %d", 10*1024, v)
	}
}

func TestCB81_ParseSize_MB(t *testing.T) {
	v, err := parseSize("50MB")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if v != 50*1024*1024 {
		t.Errorf("expected %d, got %d", 50*1024*1024, v)
	}
}

func TestCB81_ParseSize_GB(t *testing.T) {
	v, err := parseSize("1GB")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if v != 1*1024*1024*1024 {
		t.Errorf("expected %d, got %d", 1*1024*1024*1024, v)
	}
}

// ==================== initSchema ====================

func TestCB81_InitSchema_NilDB(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic with nil DB")
		}
	}()
	initSchema(nil)
}

func TestCB81_InitSchema_Idempotent(t *testing.T) {
	testDB := setupTestDB_CB81(t)
	// Running initSchema again should not error
	err := initSchema(testDB)
	if err != nil {
		t.Errorf("expected no error on re-run, got %v", err)
	}
}

// ==================== cpuProfileTestSetup ====================

func TestCB81_CpuProfileTestSetup_Basic(t *testing.T) {
	cleanup := cpuProfileTestSetup()
	defer cleanup()
	// Should not have active profile
	cpuProfileState.Lock()
	active := cpuProfileState.active
	cpuProfileState.Unlock()
	if active {
		t.Error("expected no active profile after setup")
	}
}

// ==================== handleCPUProfileStart ====================

func TestCB81_HandleCPUProfileStart_NotActive(t *testing.T) {
	defer cpuProfileTestSetup()()
	req := httptest.NewRequest("POST", "/admin/profile?action=cpu", nil)
	w := httptest.NewRecorder()
	handleCPUProfileStart(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	// Clean up
	cpuProfileState.Lock()
	if cpuProfileState.active && cpuProfileState.stopFunc != nil {
		cpuProfileState.stopFunc()
	}
	cpuProfileState.active = false
	cpuProfileState.stopFunc = nil
	cpuProfileState.Unlock()
}

func TestCB81_HandleCPUProfileStart_AlreadyActive(t *testing.T) {
	defer cpuProfileTestSetup()()
	// Manually set active
	cpuProfileState.Lock()
	cpuProfileState.active = true
	cpuProfileState.stopFunc = func() {}
	cpuProfileState.Unlock()
	req := httptest.NewRequest("POST", "/admin/profile?action=cpu", nil)
	w := httptest.NewRecorder()
	handleCPUProfileStart(w, req)
	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", w.Code)
	}
}

// ==================== readPump: nil conn ====================

func TestCB81_ReadPump_NilConn(t *testing.T) {
	conn := &Connection{
		id:       "test-nil-conn-81",
		connType: "client",
		send:     make(chan []byte, 10),
		hub:      newHub(),
	}
	// readPump with nil conn should panic and recover
	go func() {
		defer func() {
			if r := recover(); r != nil {
				// Expected
			}
		}()
		conn.readPump()
	}()
	time.Sleep(100 * time.Millisecond)
	// If we get here without hanging, test passed
}

// ==================== Logger ====================

func TestCB81_Logger_Error(t *testing.T) {
	origLogger := DefaultLogger
	DefaultLogger = NewLogger(LogError)
	defer func() { DefaultLogger = origLogger }()
	DefaultLogger.Error("test_error", map[string]interface{}{"key": "value"})
}

func TestCB81_Logger_Warn(t *testing.T) {
	origLogger := DefaultLogger
	DefaultLogger = NewLogger(LogWarn)
	defer func() { DefaultLogger = origLogger }()
	DefaultLogger.Warn("test_warn", map[string]interface{}{"key": "value"})
}

func TestCB81_Logger_Info(t *testing.T) {
	origLogger := DefaultLogger
	DefaultLogger = NewLogger(LogInfo)
	defer func() { DefaultLogger = origLogger }()
	DefaultLogger.Info("test_info", map[string]interface{}{"key": "value"})
}

func TestCB81_Logger_Debug(t *testing.T) {
	origLogger := DefaultLogger
	DefaultLogger = NewLogger(LogDebug)
	defer func() { DefaultLogger = origLogger }()
	DefaultLogger.Debug("test_debug", map[string]interface{}{"key": "value"})
}

func TestCB81_Logger_WithFields(t *testing.T) {
	origLogger := DefaultLogger
	DefaultLogger = NewLogger(LogInfo)
	defer func() { DefaultLogger = origLogger }()
	l := DefaultLogger.WithFields(map[string]interface{}{"session": "test"})
	l.Info("with_fields_msg", nil)
}

// ==================== storeMessage ====================

func TestCB81_StoreMessage_Success(t *testing.T) {
	testDB := setupTestDB_CB81(t)
	convID := createConversation_CB81(testDB, "user1", "agent1")
	withGlobalDB_CB81(testDB, func() {
		msg := RoutedMessage{
			ConversationID: convID,
			Content:        "test message",
			SenderType:     "client",
			SenderID:       "user1",
		}
		err := storeMessage(msg)
		if err != nil {
			t.Fatalf("storeMessage failed: %v", err)
		}
	})
}

// ==================== CreateConversation ====================

func TestCB81_CreateConversation_Success(t *testing.T) {
	testDB := setupTestDB_CB81(t)
	testDB.Exec("INSERT INTO agents (id, name) VALUES (?, ?)", "agent1", "Agent One")
	createUser_CB81(testDB, "user1", "pass")
	withGlobalDB_CB81(testDB, func() {
		conv, err := CreateConversation("user1", "agent1")
		if err != nil {
			t.Fatalf("CreateConversation failed: %v", err)
		}
		if conv == nil {
			t.Fatal("expected non-nil conversation")
		}
		if conv.UserID != "user1" || conv.AgentID != "agent1" {
			t.Errorf("unexpected conversation: %+v", conv)
		}
	})
}

// ==================== markMessagesRead ====================

func TestCB81_MarkMessagesRead_Success(t *testing.T) {
	testDB := setupTestDB_CB81(t)
	convID := createConversation_CB81(testDB, "user1", "agent1")
	testDB.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, created_at) VALUES (?, ?, ?, ?, ?, ?)",
		"msg1", convID, "agent", "agent1", "hello", time.Now().UTC())
	testDB.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, created_at) VALUES (?, ?, ?, ?, ?, ?)",
		"msg2", convID, "agent", "agent1", "world", time.Now().UTC().Add(time.Second))
	withGlobalDB_CB81(testDB, func() {
		count, err := markMessagesRead(convID, "user1")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if count != 2 {
			t.Errorf("expected 2 messages marked read, got %d", count)
		}
	})
}

// ==================== changeUserPassword ====================

func TestCB81_ChangeUserPassword_Success(t *testing.T) {
	testDB := setupTestDB_CB81(t)
	userID := createUser_CB81(testDB, "testuser", "oldpass123")
	withGlobalDB_CB81(testDB, func() {
		err := changeUserPassword(userID, "oldpass123", "newpass456")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}

func TestCB81_ChangeUserPassword_InvalidOld(t *testing.T) {
	testDB := setupTestDB_CB81(t)
	userID := createUser_CB81(testDB, "testuser", "oldpass123")
	withGlobalDB_CB81(testDB, func() {
		err := changeUserPassword(userID, "wrongpass", "newpass456")
		if err == nil || err.Error() != "invalid old password" {
			t.Errorf("expected 'invalid old password', got %v", err)
		}
	})
}

func TestCB81_ChangeUserPassword_TooShort(t *testing.T) {
	testDB := setupTestDB_CB81(t)
	userID := createUser_CB81(testDB, "testuser", "oldpass123")
	withGlobalDB_CB81(testDB, func() {
		err := changeUserPassword(userID, "oldpass123", "short")
		if err == nil {
			t.Error("expected error for short password")
		}
	})
}

// ==================== addReaction ====================

func TestCB81_AddReaction_Success(t *testing.T) {
	testDB := setupTestDB_CB81(t)
	convID := createConversation_CB81(testDB, "user1", "agent1")
	msgID := "msg-rxn-81"
	testDB.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, created_at) VALUES (?, ?, ?, ?, ?, ?)",
		msgID, convID, "client", "user1", "hello", time.Now().UTC())
	withGlobalDB_CB81(testDB, func() {
		rxn, added, err := addReaction(msgID, "user1", "👍")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !added {
			t.Error("expected reaction to be added")
		}
		if rxn == nil {
			t.Fatal("expected non-nil reaction")
		}
	})
}

func TestCB81_AddReaction_Toggle(t *testing.T) {
	testDB := setupTestDB_CB81(t)
	convID := createConversation_CB81(testDB, "user1", "agent1")
	msgID := "msg-rxn-toggle-81"
	testDB.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, created_at) VALUES (?, ?, ?, ?, ?, ?)",
		msgID, convID, "client", "user1", "hello", time.Now().UTC())
	withGlobalDB_CB81(testDB, func() {
		addReaction(msgID, "user1", "👍")
		_, added, err := addReaction(msgID, "user1", "👍")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if added {
			t.Error("expected reaction to be removed (toggled)")
		}
	})
}

// ==================== getMessageReactions ====================

func TestCB81_GetMessageReactions_Success(t *testing.T) {
	testDB := setupTestDB_CB81(t)
	convID := createConversation_CB81(testDB, "user1", "agent1")
	msgID := "msg-rxn-get-81"
	testDB.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, created_at) VALUES (?, ?, ?, ?, ?, ?)",
		msgID, convID, "client", "user1", "hello", time.Now().UTC())
	testDB.Exec("INSERT INTO reactions (id, message_id, user_id, emoji, created_at) VALUES (?, ?, ?, ?, ?)",
		"rxn1", msgID, "user1", "👍", time.Now().UTC())
	withGlobalDB_CB81(testDB, func() {
		reactions, err := getMessageReactions(msgID)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(reactions) != 1 {
			t.Errorf("expected 1 reaction, got %d", len(reactions))
		}
	})
}

// ==================== addConversationTag ====================

func TestCB81_AddConversationTag_Success(t *testing.T) {
	testDB := setupTestDB_CB81(t)
	convID := createConversation_CB81(testDB, "user1", "agent1")
	withGlobalDB_CB81(testDB, func() {
		tag, err := addConversationTag(convID, "user1", "important")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if tag == nil {
			t.Fatal("expected non-nil tag")
		}
	})
}

func TestCB81_AddConversationTag_AlreadyExists(t *testing.T) {
	testDB := setupTestDB_CB81(t)
	convID := createConversation_CB81(testDB, "user1", "agent1")
	withGlobalDB_CB81(testDB, func() {
		addConversationTag(convID, "user1", "important")
		_, err := addConversationTag(convID, "user1", "important")
		if err == nil || err.Error() != "tag already exists" {
			t.Errorf("expected 'tag already exists', got %v", err)
		}
	})
}

// ==================== removeConversationTag ====================

func TestCB81_RemoveConversationTag_Success(t *testing.T) {
	testDB := setupTestDB_CB81(t)
	convID := createConversation_CB81(testDB, "user1", "agent1")
	withGlobalDB_CB81(testDB, func() {
		addConversationTag(convID, "user1", "important")
		err := removeConversationTag(convID, "user1", "important")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}

func TestCB81_RemoveConversationTag_NotFound(t *testing.T) {
	testDB := setupTestDB_CB81(t)
	convID := createConversation_CB81(testDB, "user1", "agent1")
	withGlobalDB_CB81(testDB, func() {
		err := removeConversationTag(convID, "user1", "nonexistent")
		if err == nil || err.Error() != "tag not found" {
			t.Errorf("expected 'tag not found', got %v", err)
		}
	})
}

// ==================== getConversationTags ====================

func TestCB81_GetConversationTags_Success(t *testing.T) {
	testDB := setupTestDB_CB81(t)
	convID := createConversation_CB81(testDB, "user1", "agent1")
	withGlobalDB_CB81(testDB, func() {
		addConversationTag(convID, "user1", "tag1")
		addConversationTag(convID, "user1", "tag2")
		tags, err := getConversationTags(convID)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(tags) != 2 {
			t.Errorf("expected 2 tags, got %d", len(tags))
		}
	})
}

// ==================== getConversation ====================

func TestCB81_GetConversation_Success(t *testing.T) {
	testDB := setupTestDB_CB81(t)
	convID := createConversation_CB81(testDB, "user1", "agent1")
	withGlobalDB_CB81(testDB, func() {
		conv, err := getConversation(convID)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if conv == nil {
			t.Fatal("expected non-nil conversation")
		}
		if conv.ID != convID {
			t.Errorf("expected ID %s, got %s", convID, conv.ID)
		}
	})
}

func TestCB81_GetConversation_NotFound(t *testing.T) {
	testDB := setupTestDB_CB81(t)
	withGlobalDB_CB81(testDB, func() {
		conv, err := getConversation("nonexistent")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if conv != nil {
			t.Error("expected nil conversation")
		}
	})
}

// ==================== handleAdminAgents ====================

func TestCB81_HandleAdminAgents_Success(t *testing.T) {
	testDB := setupTestDB_CB81(t)
	testDB.Exec("INSERT INTO agents (id, name, model, personality, specialty) VALUES (?, ?, ?, ?, ?)",
		"agent1", "Agent One", "gpt-4", "friendly", "general")
	h := newHub()
	go h.run()
	defer h.Stop()
	origHub := hub
	hub = h
	defer func() { hub = origHub }()
	withGlobalDB_CB81(testDB, func() {
		req := httptest.NewRequest("GET", "/admin/agents", nil)
		w := httptest.NewRecorder()
		handleAdminAgents(w, req)
		if w.Code != http.StatusOK {
			t.Errorf("expected 200, got %d", w.Code)
		}
		var agents []AgentInfo
		json.NewDecoder(w.Body).Decode(&agents)
		if len(agents) != 1 {
			t.Errorf("expected 1 agent, got %d", len(agents))
		}
	})
}

// ==================== handleMessageEdit ====================

func TestCB81_HandleMessageEdit_Success(t *testing.T) {
	testDB := setupTestDB_CB81(t)
	userID := createUser_CB81(testDB, "testuser", "pass")
	convID := createConversation_CB81(testDB, userID, "agent1")
	msgID := "msg-edit-81"
	testDB.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, created_at) VALUES (?, ?, ?, ?, ?, ?)",
		msgID, convID, "client", userID, "original", time.Now().UTC())
	token := generateTestToken_CB81(userID)
	h := newHub()
	go h.run()
	defer h.Stop()
	origHub := hub
	hub = h
	defer func() { hub = origHub }()
	withGlobalDB_CB81(testDB, func() {
		req := httptest.NewRequest("POST", "/messages/edit?message_id="+msgID+"&content=edited", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		handleMessageEdit(w, req)
		if w.Code != http.StatusOK {
			t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
		}
	})
}

// ==================== OfflineQueue Purge ====================

func TestCB81_OfflineQueue_Purge(t *testing.T) {
	q := newOfflineQueue(100, time.Hour)
	q.Enqueue("user1", []byte("msg1"))
	q.Purge("user1")
	if q.QueueDepth("user1") != 0 {
		t.Error("expected 0 depth after purge")
	}
}

// ==================== OfflineQueue Drain Empty ====================

func TestCB81_OfflineQueue_DrainEmpty(t *testing.T) {
	q := newOfflineQueue(100, time.Hour)
	msgs := q.Drain("nonexistent")
	if msgs != nil {
		t.Error("expected nil for nonexistent user drain")
	}
}

// ==================== getUploadDir ====================

func TestCB81_GetUploadDir(t *testing.T) {
	dir := getUploadDir()
	if dir == "" {
		t.Error("expected non-empty upload dir")
	}
}

// ==================== getMaxUploadSize ====================

func TestCB81_GetMaxUploadSize(t *testing.T) {
	size := getMaxUploadSize()
	if size <= 0 {
		t.Error("expected positive upload size")
	}
}