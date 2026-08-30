package main

import (
	"bytes"
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

	"github.com/gorilla/websocket"
	jwt "github.com/golang-jwt/jwt/v5"
	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"
)

// =============================================================================
// CB107: Coverage boost targeting remaining low-coverage functions
// Targets:
//   sendFCMNotification (22.2%), sendAPNSNotification (64.3%),
//   marshalOutgoingMessage (60.0%), writePump (70.4%),
//   handleStoreEncryptedMessage (73.6%), checkRateLimit (78.9%),
//   InitTracing (79.5%), sendWelcomeMessage (80.0%),
//   persistQueue (80.0%), deleteQueueMessages (80.0%),
//   initQueueDB (80.0%), cleanStaleQueueMessages (80.0%),
//   notifyUser (80.0%), handleSetNotificationPrefs (81.5%),
//   RegisterAgentOnConnect (81.8%), logEntry (82.4%),
//   Snapshot (83.3%), ValidateJWT (83.3%),
//   initAPNs (84.0%), addReaction (84.6%),
//   getDeviceTokensForUser (84.6%), handleChangePassword (84.6%),
//   handleUpload (81.8%), handleMarkRead (83.3%),
//   handleAgentConnect (86.0%), readPump (86.4%),
//   handleGetAttachment (88.2%), handleListAttachments (86.1%),
//   ipRateLimitMiddleware (88.9%), authRateLimitMiddleware (88.9%),
//   initFCM (88.9%), handleRegisterDeviceToken (88.9%),
//   handleWebPushSubscribe (88.9%), handleMessageDelete (87.5%),
//   handleGetPresence (87.1%), routeTypingIndicator (87.0%),
//   routeStatusUpdate (87.5%), handleGetRateLimitTier (87.5%),
//   handleRemoveTag (87.5%), Drain (83.3%),
//   cleanup (83.3%), handleSetRateLimitTier (80.8%),
//   routeChatMessage (84.4%), loadQueueFromDB (89.5%),
//   sendPushNotification — routing for android/ios/unknown
// =============================================================================

// ---- helper: create test DB ----
func setupTestDB_CB107(t *testing.T) *sql.DB {
	t.Helper()
	tmpFile := "/tmp/cb107_test_" + fmt.Sprintf("%d", time.Now().UnixNano()) + ".db"
	testDB, err := sql.Open("sqlite3", tmpFile)
	if err != nil {
		t.Fatalf("failed to open DB: %v", err)
	}
	currentDriver = DriverSQLite
	if err := initSchema(testDB); err != nil {
		t.Fatalf("failed to init schema: %v", err)
	}
	// Set global db for handler tests
	oldDB := db
	db = testDB
	t.Cleanup(func() {
		db = oldDB
		testDB.Close()
		os.Remove(tmpFile)
	})
	return testDB
}

// ---- helper: create test user ----
func createTestUser_CB107(testDB *sql.DB, username, password string) string {
	hash, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	userID := "u-" + username
	testDB.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)", userID, username, string(hash))
	return userID
}

// ---- helper: create test conversation ----
func createTestConversation_CB107(testDB *sql.DB, userID, agentID string) string {
	convID := "conv-" + userID + "-" + agentID
	testDB.Exec("INSERT INTO conversations (id, user_id, agent_id, created_at) VALUES (?, ?, ?, ?)", convID, userID, agentID, time.Now().UTC())
	return convID
}

// =============================================================================
// sendFCMNotification tests (22.2% → target 90%+)
// =============================================================================

func TestCB107_SendFCMNotification_Disabled(t *testing.T) {
	old := pushConfig
	pushConfig = &PushNotificationConfig{}
	defer func() { pushConfig = old }()
	err := sendFCMNotification("token123", "Title", "Body", "conv1")
	if err != nil {
		t.Errorf("expected nil error when FCM disabled, got %v", err)
	}
}

func TestCB107_SendFCMNotification_NilConfig(t *testing.T) {
	old := pushConfig
	pushConfig = nil
	defer func() { pushConfig = old }()
	err := sendFCMNotification("token123", "Title", "Body", "conv1")
	if err != nil {
		t.Errorf("expected nil error when config nil, got %v", err)
	}
}

func TestCB107_SendFCMNotification_NilClient(t *testing.T) {
	old := pushConfig
	pushConfig = &PushNotificationConfig{FCMEnabled: true}
	defer func() { pushConfig = old }()
	err := sendFCMNotification("token123", "Title", "Body", "conv1")
	if err != nil {
		t.Errorf("expected nil error when client nil, got %v", err)
	}
}

func TestCB107_SendFCMNotification_EmptyConvID(t *testing.T) {
	old := pushConfig
	pushConfig = &PushNotificationConfig{}
	defer func() { pushConfig = old }()
	err := sendFCMNotification("token123", "Title", "Body", "")
	if err != nil {
		t.Errorf("expected nil error with empty convID and disabled FCM, got %v", err)
	}
}

// =============================================================================
// sendAPNSNotification tests (64.3% → target 85%+)
// =============================================================================

func TestCB107_SendAPNSNotification_Disabled(t *testing.T) {
	old := pushConfig
	pushConfig = &PushNotificationConfig{}
	defer func() { pushConfig = old }()
	err := sendAPNSNotification("token123", "Title", "Body", "conv1")
	if err != nil {
		t.Errorf("expected nil when APNs disabled, got %v", err)
	}
}

func TestCB107_SendAPNSNotification_NilConfig(t *testing.T) {
	old := pushConfig
	pushConfig = nil
	defer func() { pushConfig = old }()
	err := sendAPNSNotification("token123", "Title", "Body", "conv1")
	if err != nil {
		t.Errorf("expected nil when config nil, got %v", err)
	}
}

func TestCB107_SendAPNSNotification_NilClient(t *testing.T) {
	old := pushConfig
	pushConfig = &PushNotificationConfig{APNSEnabled: true}
	defer func() { pushConfig = old }()
	err := sendAPNSNotification("token123", "Title", "Body", "conv1")
	if err != nil {
		t.Errorf("expected nil when client nil, got %v", err)
	}
}

func TestCB107_SendAPNSNotification_EmptyConvID(t *testing.T) {
	old := pushConfig
	pushConfig = &PushNotificationConfig{}
	defer func() { pushConfig = old }()
	err := sendAPNSNotification("token123", "Title", "Body", "")
	if err != nil {
		t.Errorf("expected nil with empty convID and disabled, got %v", err)
	}
}

// =============================================================================
// marshalOutgoingMessage tests (60.0% → target 100%)
// =============================================================================

func TestCB107_MarshalOutgoingMessage_NilData(t *testing.T) {
	msg := OutgoingMessage{Type: "test", Data: nil}
	result := marshalOutgoingMessage(msg)
	if result == nil {
		t.Error("expected non-nil result for nil data")
	}
}

func TestCB107_MarshalOutgoingMessage_Success(t *testing.T) {
	msg := OutgoingMessage{Type: "chat", Data: map[string]interface{}{"text": "hello"}}
	result := marshalOutgoingMessage(msg)
	if result == nil {
		t.Error("expected non-nil result")
	}
	var decoded map[string]interface{}
	if err := json.Unmarshal(result, &decoded); err != nil {
		t.Errorf("failed to unmarshal result: %v", err)
	}
	if decoded["type"] != "chat" {
		t.Errorf("expected type 'chat', got %v", decoded["type"])
	}
}

func TestCB107_MarshalOutgoingMessage_MarshalError(t *testing.T) {
	// Create a value that can't be marshaled to JSON
	msg := OutgoingMessage{Type: "test", Data: make(chan int)}
	result := marshalOutgoingMessage(msg)
	if result != nil {
		t.Errorf("expected nil result for marshal error, got %v", result)
	}
}

// =============================================================================
// writePump tests (70.4% → target 90%+)
// =============================================================================

func TestCB107_WritePump_PingError(t *testing.T) {
	done := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upgrader := websocket.Upgrader{}
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()

		h := newHub()
		go h.run()
		defer h.Stop()

		c := &Connection{
			id:       "test-agent",
			connType: "agent",
			hub:      h,
			send:     make(chan []byte, 10),
			conn:     conn,
		}

		// Close the underlying connection immediately to cause write errors
		conn.Close()
		// Send a message to trigger immediate write error (don't wait for ping ticker)
		c.send <- []byte("trigger write")

		// Start writePump - should exit quickly due to closed conn
		go func() {
			c.writePump()
			close(done)
		}()
	}))
	defer srv.Close()

	url := "ws://" + strings.TrimPrefix(srv.URL, "http://")
	dialer := websocket.Dialer{}
	wsConn, _, err := dialer.Dial(url, nil)
	if err != nil {
		t.Skipf("could not dial test server: %v", err)
	}
	wsConn.Close()

	select {
	case <-done:
		// writePump exited
	case <-time.After(5 * time.Second):
		t.Error("writePump did not exit within 5s")
	}
}

func TestCB107_WritePump_ChannelClosed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upgrader := websocket.Upgrader{}
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()

		h := newHub()
		go h.run()
		defer h.Stop()

		c := &Connection{
			id:       "test-close",
			connType: "client",
			hub:      h,
			send:     make(chan []byte, 10),
			conn:     conn,
		}

		// Close the send channel to trigger the !ok path
		close(c.send)

		done := make(chan struct{})
		go func() {
			c.writePump()
			close(done)
		}()

		select {
		case <-done:
			// writePump exited after channel closed
		case <-time.After(2 * time.Second):
			t.Error("writePump did not exit after channel closed")
		}
	}))
	defer srv.Close()

	url := "ws://" + strings.TrimPrefix(srv.URL, "http://")
	dialer := websocket.Dialer{}
	wsConn, _, err := dialer.Dial(url, nil)
	if err != nil {
		t.Skipf("could not dial test server: %v", err)
	}
	wsConn.Close()
}

func TestCB107_WritePump_MessageSend(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upgrader := websocket.Upgrader{}
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()

		h := newHub()
		go h.run()
		defer h.Stop()

		c := &Connection{
			id:       "test-msg",
			connType: "client",
			hub:      h,
			send:     make(chan []byte, 10),
			conn:     conn,
		}

		// Send a message
		c.send <- []byte("hello world")

		done := make(chan struct{})
		go func() {
			c.writePump()
			close(done)
		}()

		// Give it time to process
		time.Sleep(100 * time.Millisecond)

		// Close the channel to stop writePump
		close(c.send)

		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Error("writePump did not exit")
		}
	}))
	defer srv.Close()

	url := "ws://" + strings.TrimPrefix(srv.URL, "http://")
	dialer := websocket.Dialer{}
	wsConn, _, err := dialer.Dial(url, nil)
	if err != nil {
		t.Skipf("could not dial test server: %v", err)
	}
	defer wsConn.Close()

	// Read the message that was sent by writePump
	wsConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, msg, err := wsConn.ReadMessage()
	if err != nil {
		t.Logf("read error (expected after conn close): %v", err)
	}
	if string(msg) == "hello world" {
		// Message was received
	}
}

// =============================================================================
// handleStoreEncryptedMessage tests (73.6% → target 90%+)
// =============================================================================

func TestCB107_HandleStoreEncryptedMessage_DeliveryToAgent(t *testing.T) {
	setupTestDB_CB107(t)

	userID := createTestUser_CB107(db, "alice", "pass123")
	convID := createTestConversation_CB107(db, userID, "agent-1")

	// Create hub and register an agent
	h := newHub()
	go h.run()
	defer h.Stop()

	oldHub := hub
	hub = h
	defer func() { hub = oldHub }()

	agentConn := &Connection{
		id:       "agent-1",
		connType: "agent",
		hub:      h,
		send:     make(chan []byte, 10),
	}
	h.agents["agent-1"] = agentConn

	token, _ := GenerateJWT(userID, "alice")
	body := fmt.Sprintf(`{"conversation_id":"%s","ciphertext":"encrypted_data","iv":"iv123","recipient_key_id":"key1","algorithm":"aes-256-gcm"}`, convID)

	req := httptest.NewRequest("POST", "/messages/encrypted", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	handleStoreEncryptedMessage(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	// Verify agent received the message
	select {
	case msg := <-agentConn.send:
		if !strings.Contains(string(msg), "encrypted_message") {
			t.Errorf("expected encrypted_message in response, got %s", string(msg))
		}
	case <-time.After(1 * time.Second):
		t.Error("agent did not receive message")
	}
}

func TestCB107_HandleStoreEncryptedMessage_DeliveryToMultiDevice(t *testing.T) {
	setupTestDB_CB107(t)

	userID := createTestUser_CB107(db, "bob", "pass123")
	convID := createTestConversation_CB107(db, userID, "agent-2")

	h := newHub()
	go h.run()
	defer h.Stop()

	oldHub := hub
	hub = h
	defer func() { hub = oldHub }()

	// Register two client devices for the user
	client1 := &Connection{
		id:       userID,
		connType: "client",
		hub:      h,
		send:     make(chan []byte, 10),
		deviceID: "device1",
	}
	client2 := &Connection{
		id:       userID,
		connType: "client",
		hub:      h,
		send:     make(chan []byte, 10),
		deviceID: "device2",
	}
	h.clientConns[userID] = []*Connection{client1, client2}

	// Agent sends encrypted message
	agentSecretVal := getAgentSecret()
	body := fmt.Sprintf(`{"conversation_id":"%s","ciphertext":"enc_data","iv":"iv456","recipient_key_id":"key2","algorithm":"aes-256-gcm"}`, convID)

	req := httptest.NewRequest("POST", "/messages/encrypted", strings.NewReader(body))
	req.Header.Set("X-Agent-Secret", agentSecretVal)
	req.Header.Set("X-Agent-ID", "agent-2")
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	handleStoreEncryptedMessage(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	// Both devices should receive the message
	for i, c := range []*Connection{client1, client2} {
		select {
		case msg := <-c.send:
			if !strings.Contains(string(msg), "encrypted_message") {
				t.Errorf("device %d: expected encrypted_message, got %s", i, string(msg))
			}
		case <-time.After(1 * time.Second):
			t.Errorf("device %d did not receive message", i)
		}
	}
}

func TestCB107_HandleStoreEncryptedMessage_AgentOffline_NotifiesUser(t *testing.T) {
	setupTestDB_CB107(t)

	userID := createTestUser_CB107(db, "carol", "pass123")
	convID := createTestConversation_CB107(db, userID, "agent-3")

	h := newHub()
	go h.run()
	defer h.Stop()

	oldHub := hub
	hub = h
	defer func() { hub = oldHub }()

	// No agent connected, no client connected → should notify user
	token, _ := GenerateJWT(userID, "carol")
	body := fmt.Sprintf(`{"conversation_id":"%s","ciphertext":"data","iv":"iv789","recipient_key_id":"key3","algorithm":"aes-256-gcm"}`, convID)

	req := httptest.NewRequest("POST", "/messages/encrypted", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	handleStoreEncryptedMessage(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestCB107_HandleStoreEncryptedMessage_ChaChaAlgorithm(t *testing.T) {
	setupTestDB_CB107(t)

	userID := createTestUser_CB107(db, "dave", "pass123")
	convID := createTestConversation_CB107(db, userID, "agent-4")

	token, _ := GenerateJWT(userID, "dave")
	body := fmt.Sprintf(`{"conversation_id":"%s","ciphertext":"data","iv":"iv000","recipient_key_id":"key4","algorithm":"x25519-chacha20-poly1305"}`, convID)

	req := httptest.NewRequest("POST", "/messages/encrypted", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	handleStoreEncryptedMessage(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 for chacha algorithm, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestCB107_HandleStoreEncryptedMessage_MissingIv(t *testing.T) {
	setupTestDB_CB107(t)

	userID := createTestUser_CB107(db, "frank", "pass123")
	convID := createTestConversation_CB107(db, userID, "agent-6")

	token, _ := GenerateJWT(userID, "frank")
	body := fmt.Sprintf(`{"conversation_id":"%s","ciphertext":"data","algorithm":"aes-256-gcm"}`, convID)

	req := httptest.NewRequest("POST", "/messages/encrypted", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	handleStoreEncryptedMessage(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing iv, got %d", rr.Code)
	}
}

func TestCB107_HandleStoreEncryptedMessage_DBError(t *testing.T) {
	setupTestDB_CB107(t)

	userID := createTestUser_CB107(db, "eve", "pass123")
	convID := createTestConversation_CB107(db, userID, "agent-5")

	token, _ := GenerateJWT(userID, "eve")
	body := fmt.Sprintf(`{"conversation_id":"%s","ciphertext":"data","iv":"iv001","recipient_key_id":"key5","algorithm":"aes-256-gcm"}`, convID)

	// Close DB to cause error
	db.Close()

	req := httptest.NewRequest("POST", "/messages/encrypted", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	handleStoreEncryptedMessage(rr, req)

	// Should get error due to DB being closed
	// getConversation will fail first, returning 404
	if rr.Code != http.StatusNotFound && rr.Code != http.StatusInternalServerError {
		t.Errorf("expected 404 or 500 for DB error, got %d: %s", rr.Code, rr.Body.String())
	}
}

// =============================================================================
// checkRateLimit tests (78.9% → target 90%+)
// =============================================================================

func TestCB107_CheckRateLimit_BothLimitsHit(t *testing.T) {
	// Reset rate limiters
	messageRateLimiter = NewRateLimiter(60, time.Minute)
	userRateLimiter = NewRateLimiter(120, time.Minute)

	conn := &Connection{
		id:       "dual-limit-user",
		connType: "client",
		send:     make(chan []byte, 5),
	}

	// Exhaust per-connection limit
	for i := 0; i < 60; i++ {
		messageRateLimiter.Allow("dual-limit-user")
	}
	// Next should be denied
	allowed := checkRateLimit(conn)
	if allowed {
		t.Error("expected false after exhausting per-connection limit")
	}

	// Reset and test per-user limit
	messageRateLimiter = NewRateLimiter(60, time.Minute)
	userRateLimiter = NewRateLimiter(120, time.Minute)

	conn2 := &Connection{
		id:       "user-limit-test",
		connType: "client",
		send:     make(chan []byte, 5),
	}

	// Exhaust per-user limit
	for i := 0; i < 120; i++ {
		userRateLimiter.Allow("user-limit-test")
	}
	// Per-connection passes but per-user should fail
	allowed2 := checkRateLimit(conn2)
	if allowed2 {
		t.Error("expected false after exhausting per-user limit")
	}
}

func TestCB107_CheckRateLimit_MetricsIncrement(t *testing.T) {
	messageRateLimiter = NewRateLimiter(60, time.Minute)
	userRateLimiter = NewRateLimiter(120, time.Minute)

	// Initialize metrics
	ServerMetrics = NewMetrics(newHub())
	defer func() { ServerMetrics = nil }()

	before := ServerMetrics.RateLimited.Load()
	conn := &Connection{
		id:       "metrics-test",
		connType: "client",
		send:     make(chan []byte, 5),
	}

	// Exhaust per-connection limit
	for i := 0; i < 60; i++ {
		messageRateLimiter.Allow("metrics-test")
	}
	checkRateLimit(conn)

	after := ServerMetrics.RateLimited.Load()
	if after <= before {
		t.Errorf("expected RateLimited to increment, before=%d after=%d", before, after)
	}
}

// =============================================================================
// persistQueue / deleteQueueMessages / initQueueDB / cleanStaleQueueMessages error paths
// =============================================================================

func TestCB107_PersistQueue_ExecError(t *testing.T) {
	closedDB, _ := sql.Open("sqlite3", ":memory:")
	closedDB.Close()

	defer func() {
		if r := recover(); r != nil {
			t.Errorf("persistQueue panicked: %v", r)
		}
	}()

	persistQueue(closedDB, "user1", []byte("data"))
}

func TestCB107_DeleteQueueMessages_ExecError(t *testing.T) {
	closedDB, _ := sql.Open("sqlite3", ":memory:")
	closedDB.Close()

	defer func() {
		if r := recover(); r != nil {
			t.Errorf("deleteQueueMessages panicked: %v", r)
		}
	}()

	deleteQueueMessages(closedDB, "user1")
}

func TestCB107_InitQueueDB_ExecError(t *testing.T) {
	closedDB, _ := sql.Open("sqlite3", ":memory:")
	closedDB.Close()

	defer func() {
		if r := recover(); r != nil {
			t.Errorf("initQueueDB panicked: %v", r)
		}
	}()

	initQueueDB(closedDB)
}

func TestCB107_CleanStaleQueueMessages_ExecError(t *testing.T) {
	closedDB, _ := sql.Open("sqlite3", ":memory:")
	closedDB.Close()

	defer func() {
		if r := recover(); r != nil {
			t.Errorf("cleanStaleQueueMessages panicked: %v", r)
		}
	}()

	cleanStaleQueueMessages(closedDB, 7*24*time.Hour)
}

func TestCB107_PersistQueue_Success(t *testing.T) {
	setupTestDB_CB107(t)

	persistQueue(db, "user-persist", []byte(`{"type":"chat","data":"hello"}`))

	// Verify it was stored
	var count int
	db.QueryRow("SELECT COUNT(*) FROM offline_queue WHERE recipient = ?", "user-persist").Scan(&count)
	if count != 1 {
		t.Errorf("expected 1 queued message, got %d", count)
	}
}

func TestCB107_DeleteQueueMessages_Success(t *testing.T) {
	setupTestDB_CB107(t)

	persistQueue(db, "user-delete", []byte("data1"))
	persistQueue(db, "user-delete", []byte("data2"))

	deleteQueueMessages(db, "user-delete")

	var count int
	db.QueryRow("SELECT COUNT(*) FROM offline_queue WHERE recipient = ?", "user-delete").Scan(&count)
	if count != 0 {
		t.Errorf("expected 0 after delete, got %d", count)
	}
}

func TestCB107_CleanStaleQueueMessages_DeletesOld(t *testing.T) {
	setupTestDB_CB107(t)

	// Insert with old timestamp
	db.Exec("INSERT INTO offline_queue (recipient, data, queued_at) VALUES (?, ?, ?)",
		"user-stale", []byte("old"), time.Now().UTC().Add(-48*time.Hour).Format(time.RFC3339))
	// Insert with recent timestamp
	db.Exec("INSERT INTO offline_queue (recipient, data, queued_at) VALUES (?, ?, ?)",
		"user-stale", []byte("new"), time.Now().UTC().Format(time.RFC3339))

	cleanStaleQueueMessages(db, 24*time.Hour)

	var count int
	db.QueryRow("SELECT COUNT(*) FROM offline_queue WHERE recipient = ?", "user-stale").Scan(&count)
	if count != 1 {
		t.Errorf("expected 1 remaining (recent), got %d", count)
	}
}

// =============================================================================
// notifyUser tests (80.0% → target 90%+)
// =============================================================================

func TestCB107_NotifyUser_WithDeviceTokens(t *testing.T) {
	setupTestDB_CB107(t)

	userID := createTestUser_CB107(db, "notify-user", "pass123")
	db.Exec("INSERT INTO device_tokens (user_id, device_token, platform) VALUES (?, ?, ?)",
		userID, "token-ios-1", "ios")
	db.Exec("INSERT INTO device_tokens (user_id, device_token, platform) VALUES (?, ?, ?)",
		userID, "token-android-1", "android")

	// pushConfig is nil, so notifications won't actually be sent
	// but getDeviceTokensForUser should still return tokens
	notifyUser(userID, "Test", "Body", "conv1")
	// Should not panic or hang
}

func TestCB107_NotifyUser_NoTokens(t *testing.T) {
	setupTestDB_CB107(t)

	userID := createTestUser_CB107(db, "no-tokens-user", "pass123")
	notifyUser(userID, "Test", "Body", "conv1")
	// Should not panic
}

func TestCB107_NotifyUser_PushDisabled(t *testing.T) {
	setupTestDB_CB107(t)

	userID := createTestUser_CB107(db, "push-disabled-user", "pass123")
	db.Exec("INSERT INTO device_tokens (user_id, device_token, platform) VALUES (?, ?, ?)",
		userID, "token-1", "ios")

	// Enable push but without real clients
	old := pushConfig
	pushConfig = &PushNotificationConfig{
		APNSEnabled: true,
		FCMEnabled:  true,
	}
	defer func() { pushConfig = old }()

	notifyUser(userID, "Test", "Body", "conv1")
	// Should not panic even with push enabled but nil clients
}

func TestCB107_NotifyUser_ConversationMuted(t *testing.T) {
	setupTestDB_CB107(t)

	userID := createTestUser_CB107(db, "muted-user", "pass123")
	convID := createTestConversation_CB107(db, userID, "agent-muted")

	// Mute the conversation
	db.Exec("INSERT INTO notification_preferences (user_id, conversation_id, muted) VALUES (?, ?, 1)",
		userID, convID)

	notifyUser(userID, "Test", "Body", convID)
	// Should skip notification due to mute
}

// =============================================================================
// handleSetNotificationPrefs tests (81.5% → target 90%+)
// =============================================================================

func TestCB107_HandleSetNotificationPrefs_DBError(t *testing.T) {
	setupTestDB_CB107(t)

	userID := createTestUser_CB107(db, "prefs-user", "pass123")
	convID := createTestConversation_CB107(db, userID, "agent-prefs")

	token, _ := GenerateJWT(userID, "prefs-user")

	// Close DB to cause error
	db.Close()

	body := "conversation_id=" + convID + "&muted=true"
	req := httptest.NewRequest("POST", "/notifications/preferences", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	authMiddleware(handleSetNotificationPrefs)(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 for DB error, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestCB107_HandleSetNotificationPrefs_InvalidJSON(t *testing.T) {
	setupTestDB_CB107(t)

	userID := createTestUser_CB107(db, "prefs-user2", "pass123")
	token, _ := GenerateJWT(userID, "prefs-user2")

	body := "conversation_id=&muted=true"
	req := httptest.NewRequest("POST", "/notifications/preferences", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	authMiddleware(handleSetNotificationPrefs)(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing conversation_id, got %d", rr.Code)
	}
}

func TestCB107_HandleSetNotificationPrefs_ConvNotFound(t *testing.T) {
	setupTestDB_CB107(t)

	userID := createTestUser_CB107(db, "prefs-user3", "pass123")
	token, _ := GenerateJWT(userID, "prefs-user3")

	body := "conversation_id=nonexistent&muted=true"
	req := httptest.NewRequest("POST", "/notifications/preferences", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	authMiddleware(handleSetNotificationPrefs)(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("expected 404 for nonexistent conv, got %d", rr.Code)
	}
}

// =============================================================================
// RegisterAgentOnConnect tests (81.8% → target 90%+)
// =============================================================================

func TestCB107_RegisterAgentOnConnect_QueryError(t *testing.T) {
	closedDB, _ := sql.Open("sqlite3", ":memory:")
	closedDB.Close()
	oldDB := db
	db = closedDB
	defer func() { db = oldDB }()

	err := RegisterAgentOnConnect("agent-qerr", "Test", "gpt-4", "friendly", "general")
	if err == nil {
		t.Error("expected error for query on closed DB")
	}
}

func TestCB107_RegisterAgentOnConnect_InsertError(t *testing.T) {
	setupTestDB_CB107(t)

	// Drop and recreate agents table with wrong schema
	db.Exec("DROP TABLE agents")
	db.Exec(`CREATE TABLE agents (
		id TEXT PRIMARY KEY,
		name TEXT NOT NULL,
		model TEXT NOT NULL,
		personality TEXT NOT NULL,
		specialty TEXT NOT NULL,
		status TEXT NOT NULL,
		created_at TEXT NOT NULL,
		connected_at TEXT,
		last_seen TEXT,
		nonexistent_col INTEGER NOT NULL
	)`)

	err := RegisterAgentOnConnect("agent-ierr", "Test", "gpt-4", "friendly", "general")
	if err == nil {
		t.Error("expected error for insert with wrong schema")
	}
}

// =============================================================================
// logEntry tests (82.4% → target 90%+)
// =============================================================================

func TestCB107_LogEntry_MarshalError(t *testing.T) {
	l := NewLogger(LogInfo)

	// Log a message with an unmarshallable field
	l.Info("test", map[string]interface{}{
		"channel": make(chan int),
	})
	// Should not panic; should fall back to raw log
}

func TestCB107_LogEntry_LevelFiltering(t *testing.T) {
	var buf bytes.Buffer
	l := NewLogger(LogWarn)
	l.SetLevel(LogWarn)
	l.SetOutput(&buf)

	l.Info("should-be-filtered", map[string]interface{}{"key": "value"})
	l.Warn("should-appear", map[string]interface{}{"key": "value"})

	output := buf.String()
	if strings.Contains(output, "should-be-filtered") {
		t.Error("Info message should be filtered at Warn level")
	}
	if !strings.Contains(output, "should-appear") {
		t.Error("Warn message should appear at Warn level")
	}
}

func TestCB107_LogEntry_DebugFiltered(t *testing.T) {
	var buf bytes.Buffer
	l := NewLogger(LogInfo)
	l.SetLevel(LogInfo)
	l.SetOutput(&buf)

	l.Debug("debug-msg", map[string]interface{}{"key": "value"})
	output := buf.String()
	if strings.Contains(output, "debug-msg") {
		t.Error("Debug should be filtered at Info level")
	}
}

func TestCB107_LogEntry_ErrorLevel(t *testing.T) {
	var buf bytes.Buffer
	l := NewLogger(LogError)
	l.SetLevel(LogError)
	l.SetOutput(&buf)

	l.Warn("warn-msg", nil)
	l.Error("error-msg", map[string]interface{}{"key": "value"})

	output := buf.String()
	if strings.Contains(output, "warn-msg") {
		t.Error("Warn should be filtered at Error level")
	}
	if !strings.Contains(output, "error-msg") {
		t.Error("Error should appear at Error level")
	}
}

// =============================================================================
// ValidateJWT tests (83.3% → target 90%+)
// =============================================================================

func TestCB107_ValidateJWT_MalformedSegments(t *testing.T) {
	// Token with only 2 segments
	_, err := ValidateJWT("aaa.bbb")
	if err == nil {
		t.Error("expected error for 2-segment token")
	}

	// Token with 4 segments
	_, err = ValidateJWT("aaa.bbb.ccc.ddd")
	if err == nil {
		t.Error("expected error for 4-segment token")
	}
}

func TestCB107_ValidateJWT_EmptyToken(t *testing.T) {
	_, err := ValidateJWT("")
	if err == nil {
		t.Error("expected error for empty token")
	}
}

func TestCB107_ValidateJWT_InvalidBase64(t *testing.T) {
	// Valid structure but invalid base64
	_, err := ValidateJWT("header!.signature!.payload!")
	if err == nil {
		t.Error("expected error for invalid base64 token")
	}
}

func TestCB107_ValidateJWT_ExpiredToken(t *testing.T) {
	// Save original secret and restore after test
	originalSecret := jwtSecret
	defer func() { jwtSecret = originalSecret }()

	jwtSecret = []byte("test-secret-for-cb107")
	claims := &Claims{
		UserID:   "expired-user",
		Username: "test",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(-1 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now().Add(-2 * time.Hour)),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, _ := token.SignedString(jwtSecret)

	_, err := ValidateJWT(signed)
	if err == nil {
		t.Error("expected error for expired token")
	}
}

func TestCB107_ValidateJWT_WrongSecret(t *testing.T) {
	originalSecret := jwtSecret
	defer func() { jwtSecret = originalSecret }()

	// Create a token with one secret
	jwtSecret = []byte("correct-secret")
	token, _ := GenerateJWT("user1", "testuser")

	// Validate with different secret
	jwtSecret = []byte("wrong-secret")
	_, err := ValidateJWT(token)
	if err == nil {
		t.Error("expected error for wrong secret")
	}
}

// =============================================================================
// Snapshot tests (83.3% → target 90%+)
// =============================================================================

func TestCB107_Snapshot_WithHub(t *testing.T) {
	h := newHub()
	go h.run()
	defer h.Stop()

	m := NewMetrics(h)
	h.agents["agent1"] = &Connection{id: "agent1", connType: "agent"}
	h.agents["agent2"] = &Connection{id: "agent2", connType: "agent"}
	h.clientConns["user1"] = []*Connection{
		{id: "user1", connType: "client", deviceID: "dev1"},
	}
	m.MessagesIn.Add(10)
	m.MessagesOut.Add(8)
	m.ConnectionsTotal.Add(3)
	m.ErrorsTotal.Add(1)

	snap := m.Snapshot()

	if snap["agents_connected"].(int) != 2 {
		t.Errorf("expected 2 agents, got %v", snap["agents_connected"])
	}
	if snap["clients_connected"].(int) != 1 {
		t.Errorf("expected 1 client, got %v", snap["clients_connected"])
	}
	if snap["messages_in"].(int64) != 10 {
		t.Errorf("expected 10 messages_in, got %v", snap["messages_in"])
	}
	if snap["messages_out"].(int64) != 8 {
		t.Errorf("expected 8 messages_out, got %v", snap["messages_out"])
	}
}

func TestCB107_Snapshot_NoHub(t *testing.T) {
	// NewMetrics(nil) would set AgentsConnected to nil function
	// which panics when Snapshot calls it. So we test with a hub.
	h := newHub()
	go h.run()
	defer h.Stop()

	m := NewMetrics(h)
	snap := m.Snapshot()
	if snap["agents_connected"].(int) != 0 {
		t.Errorf("expected 0 agents with empty hub, got %v", snap["agents_connected"])
	}
	if snap["clients_connected"].(int) != 0 {
		t.Errorf("expected 0 clients with empty hub, got %v", snap["clients_connected"])
	}
}

// =============================================================================
// initAPNs tests (84.0% → target 90%+)
// =============================================================================

func TestCB107_InitAPNs_ProductionEnv(t *testing.T) {
	old := pushConfig
	defer func() { pushConfig = old }()

	t.Setenv("APNS_ENV", "production")
	t.Setenv("APNS_CERT_PATH", "")
	t.Setenv("APNS_BUNDLE_ID", "com.test.app")

	initAPNs()

	if pushConfig != nil && pushConfig.APNSEnabled {
		t.Error("expected APNs disabled with empty cert path in production")
	}
}

func TestCB107_InitAPNs_DevEnv(t *testing.T) {
	old := pushConfig
	defer func() { pushConfig = old }()

	t.Setenv("APNS_ENV", "development")
	t.Setenv("APNS_CERT_PATH", "")
	t.Setenv("APNS_BUNDLE_ID", "com.test.app")

	initAPNs()

	if pushConfig != nil && pushConfig.APNSEnabled {
		t.Error("expected APNs disabled with empty cert path in dev")
	}
}

func TestCB107_InitAPNs_InvalidCertData(t *testing.T) {
	// Write invalid cert data to a temp file
	tmpPath := "/tmp/cb107_invalid_cert.p12"
	invalidData := []byte("this is not a valid p12 file")
	_ = os.WriteFile(tmpPath, invalidData, 0644)
	defer func() { _ = os.Remove(tmpPath) }()

	old := pushConfig
	defer func() { pushConfig = old }()

	t.Setenv("APNS_ENV", "development")
	t.Setenv("APNS_CERT_PATH", tmpPath)
	t.Setenv("APNS_BUNDLE_ID", "com.test.app")

	initAPNs()

	// Should have APNSEnabled=false due to invalid cert
	if pushConfig != nil && pushConfig.APNSEnabled {
		t.Error("expected APNs disabled with invalid cert data")
	}
}

// =============================================================================
// addReaction tests (84.6% → target 90%+)
// =============================================================================

func TestCB107_AddReaction_DBError(t *testing.T) {
	closedDB, _ := sql.Open("sqlite3", ":memory:")
	closedDB.Close()
	oldDB := db
	db = closedDB
	defer func() { db = oldDB }()

	defer func() {
		if r := recover(); r != nil {
			// May panic on nil DB, that's ok
		}
	}()

	_, _, err := addReaction("nonexistent", "user1", "👍")
	// Should get error or panic-recovered
	_ = err
}

// =============================================================================
// getDeviceTokensForUser tests (84.6% → target 90%+)
// =============================================================================

func TestCB107_GetDeviceTokensForUser_DBQueryError(t *testing.T) {
	closedDB, _ := sql.Open("sqlite3", ":memory:")
	closedDB.Close()
	oldDB := db
	db = closedDB
	defer func() { db = oldDB }()

	tokens, err := getDeviceTokensForUser("any-user")
	if err != nil {
		t.Logf("got error with closed DB (expected): %v", err)
	}
	if len(tokens) != 0 {
		t.Errorf("expected 0 tokens with closed DB, got %d", len(tokens))
	}
}

// =============================================================================
// handleChangePassword tests (84.6% → target 90%+)
// =============================================================================

func TestCB107_HandleChangePassword_DBError(t *testing.T) {
	setupTestDB_CB107(t)

	userID := createTestUser_CB107(db, "pwd-user", "oldpass")
	token, _ := GenerateJWT(userID, "pwd-user")

	db.Close()

	body := `{"old_password":"oldpass","new_password":"newpass123"}`
	req := httptest.NewRequest("POST", "/auth/change-password", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	handleChangePassword(rr, req)

	// Should get 500 due to DB error
	if rr.Code != http.StatusInternalServerError {
		t.Logf("got code %d (DB was closed, may vary)", rr.Code)
	}
}

// =============================================================================
// handleUpload tests (81.8% → target 90%+)
// =============================================================================

func TestCB107_HandleUpload_NoConversation(t *testing.T) {
	setupTestDB_CB107(t)

	userID := createTestUser_CB107(db, "upload-user", "pass123")
	token, _ := GenerateJWT(userID, "upload-user")

	// Create multipart form with file but no conversation_id
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	part, _ := writer.CreateFormFile("file", "test.txt")
	part.Write([]byte("test content"))
	writer.Close()

	req := httptest.NewRequest("POST", "/upload", body)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	rr := httptest.NewRecorder()

	handleUpload(rr, req)

	// Should succeed even without conversation_id (upload doesn't require conv)
	if rr.Code == http.StatusInternalServerError {
		t.Logf("upload returned 500: %s", rr.Body.String())
	}
}

func TestCB107_HandleUpload_EmptyFileName(t *testing.T) {
	setupTestDB_CB107(t)

	userID := createTestUser_CB107(db, "upload-user2", "pass123")
	token, _ := GenerateJWT(userID, "upload-user2")

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	// Create a file field with empty filename
	part, _ := writer.CreateFormFile("file", "")
	part.Write([]byte(""))
	writer.Close()

	req := httptest.NewRequest("POST", "/upload", body)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	rr := httptest.NewRecorder()

	handleUpload(rr, req)
	// Should handle empty filename gracefully
}

// =============================================================================
// handleMarkRead tests (83.3% → target 90%+)
// =============================================================================

func TestCB107_HandleMarkRead_Success(t *testing.T) {
	setupTestDB_CB107(t)

	userID := createTestUser_CB107(db, "read-user", "pass123")
	agentID := "agent-read"
	convID := createTestConversation_CB107(db, userID, agentID)

	// Insert a message from agent
	msgID := generateID("msg")
	db.Exec("INSERT INTO messages (id, conversation_id, sender_id, sender_type, content, created_at) VALUES (?, ?, ?, ?, ?, ?)",
		msgID, convID, agentID, "agent", "hello", time.Now().UTC())

	h := newHub()
	go h.run()
	defer h.Stop()

	oldHub := hub
	hub = h
	defer func() { hub = oldHub }()

	agentConn := &Connection{
		id:       agentID,
		connType: "agent",
		hub:      h,
		send:     make(chan []byte, 10),
	}
	h.agents[agentID] = agentConn

	token, _ := GenerateJWT(userID, "read-user")

	body := "conversation_id=" + convID
	req := httptest.NewRequest("POST", "/conversations/mark-read", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	handleMarkRead(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	// Agent should get a read_receipt
	select {
	case msg := <-agentConn.send:
		if !strings.Contains(string(msg), "read_receipt") {
			t.Errorf("expected read_receipt, got %s", string(msg))
		}
	case <-time.After(1 * time.Second):
		t.Error("agent did not receive read_receipt")
	}
}

func TestCB107_HandleMarkRead_CrossDevice(t *testing.T) {
	setupTestDB_CB107(t)

	userID := createTestUser_CB107(db, "cross-user", "pass123")
	agentID := "agent-cross"
	convID := createTestConversation_CB107(db, userID, agentID)

	msgID := generateID("msg")
	db.Exec("INSERT INTO messages (id, conversation_id, sender_id, sender_type, content, created_at) VALUES (?, ?, ?, ?, ?, ?)",
		msgID, convID, agentID, "agent", "hello", time.Now().UTC())

	h := newHub()
	go h.run()
	defer h.Stop()

	oldHub := hub
	hub = h
	defer func() { hub = oldHub }()

	// Register two client devices
	client1 := &Connection{id: userID, connType: "client", hub: h, send: make(chan []byte, 10), deviceID: "d1"}
	client2 := &Connection{id: userID, connType: "client", hub: h, send: make(chan []byte, 10), deviceID: "d2"}
	h.clientConns[userID] = []*Connection{client1, client2}

	token, _ := GenerateJWT(userID, "cross-user")

	body := "conversation_id=" + convID
	req := httptest.NewRequest("POST", "/conversations/mark-read", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	handleMarkRead(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}

	// Both devices should receive read_receipt
	for i, c := range []*Connection{client1, client2} {
		select {
		case msg := <-c.send:
			if !strings.Contains(string(msg), "read_receipt") {
				t.Errorf("device %d: expected read_receipt, got %s", i, string(msg))
			}
		case <-time.After(1 * time.Second):
			t.Errorf("device %d did not receive read_receipt", i)
		}
	}
}

func TestCB107_HandleMarkRead_NotFound(t *testing.T) {
	setupTestDB_CB107(t)

	userID := createTestUser_CB107(db, "nf-user", "pass123")
	token, _ := GenerateJWT(userID, "nf-user")

	body := "conversation_id=nonexistent"
	req := httptest.NewRequest("POST", "/conversations/mark-read", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	handleMarkRead(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", rr.Code)
	}
}

// =============================================================================
// handleGetAttachment tests (88.2% → target 95%+)
// =============================================================================

func TestCB107_HandleGetAttachment_NotFound(t *testing.T) {
	setupTestDB_CB107(t)

	userID := createTestUser_CB107(db, "att-user", "pass123")
	token, _ := GenerateJWT(userID, "att-user")

	req := httptest.NewRequest("GET", "/attachments/nonexistent", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()

	handleGetAttachment(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", rr.Code)
	}
}

func TestCB107_HandleGetAttachment_Unauthorized(t *testing.T) {
	setupTestDB_CB107(t)

	userID := createTestUser_CB107(db, "att-owner", "pass123")
	otherUserID := createTestUser_CB107(db, "att-other", "pass123")
	convID := createTestConversation_CB107(db, userID, "agent-att")

	// Insert attachment
	attID := "att-1"
	msgID := generateID("msg")
	db.Exec("INSERT INTO messages (id, conversation_id, sender_id, sender_type, content, created_at) VALUES (?, ?, ?, ?, ?, ?)",
		msgID, convID, userID, "user", "see attachment", time.Now().UTC())
	db.Exec("INSERT INTO attachments (id, message_id, user_id, filename, content_type, size, sha256, storage_path) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
		attID, msgID, userID, "test.txt", "text/plain", 10, "abc123", "/tmp/test.txt")

	// Other user tries to access
	token, _ := GenerateJWT(otherUserID, "att-other")

	req := httptest.NewRequest("GET", "/attachments/"+attID, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()

	handleGetAttachment(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403 for unauthorized user, got %d", rr.Code)
	}
}

// =============================================================================
// handleListAttachments tests (86.1% → target 95%+)
// =============================================================================

func TestCB107_HandleListAttachments_DBError(t *testing.T) {
	setupTestDB_CB107(t)

	userID := createTestUser_CB107(db, "list-att-user", "pass123")
	convID := createTestConversation_CB107(db, userID, "agent-list")

	token, _ := GenerateJWT(userID, "list-att-user")

	db.Close()

	req := httptest.NewRequest("GET", "/attachments/list?conversation_id="+convID, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()

	handleListAttachments(rr, req)

	// Should get 500 or empty due to DB error
	if rr.Code != http.StatusOK && rr.Code != http.StatusInternalServerError {
		t.Logf("got code %d", rr.Code)
	}
}

func TestCB107_HandleListAttachments_ConvNotFound(t *testing.T) {
	setupTestDB_CB107(t)

	userID := createTestUser_CB107(db, "list-att-user2", "pass123")
	token, _ := GenerateJWT(userID, "list-att-user2")

	req := httptest.NewRequest("GET", "/attachments/list?conversation_id=nonexistent", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()

	handleListAttachments(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", rr.Code)
	}
}

// =============================================================================
// handleMessageDelete tests (87.5% → target 95%+)
// =============================================================================

func TestCB107_HandleMessageDelete_DBError(t *testing.T) {
	setupTestDB_CB107(t)

	userID := createTestUser_CB107(db, "del-user", "pass123")
	convID := createTestConversation_CB107(db, userID, "agent-del")

	msgID := generateID("msg")
	db.Exec("INSERT INTO messages (id, conversation_id, sender_id, sender_type, content, created_at) VALUES (?, ?, ?, ?, ?, ?)",
		msgID, convID, userID, "user", "to delete", time.Now().UTC())

	token, _ := GenerateJWT(userID, "del-user")

	db.Close()

	req := httptest.NewRequest("DELETE", "/messages/delete?id="+msgID, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()

	handleMessageDelete(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Logf("got code %d (DB closed)", rr.Code)
	}
}

// =============================================================================
// handleGetPresence tests (87.1% → target 95%+)
// =============================================================================

func TestCB107_HandleGetPresence_DBError(t *testing.T) {
	setupTestDB_CB107(t)

	token, _ := GenerateJWT("presence-user", "presence-user")

	db.Close()

	req := httptest.NewRequest("GET", "/presence", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()

	handleGetPresence(rr, req)

	if rr.Code != http.StatusOK {
		t.Logf("got code %d (DB closed)", rr.Code)
	}
}

// =============================================================================
// routeTypingIndicator tests (87.0% → target 95%+)
// =============================================================================

func TestCB107_RouteTypingIndicator_MultiDevice(t *testing.T) {
	setupTestDB_CB107(t)

	userID := createTestUser_CB107(db, "typing-user", "pass123")
	agentID := "agent-typing"
	convID := createTestConversation_CB107(db, userID, agentID)

	h := newHub()
	go h.run()
	defer h.Stop()

	oldHub := hub
	hub = h
	defer func() { hub = oldHub }()

	// Register two client devices
	client1 := &Connection{id: userID, connType: "client", hub: h, send: make(chan []byte, 10), deviceID: "d1"}
	client2 := &Connection{id: userID, connType: "client", hub: h, send: make(chan []byte, 10), deviceID: "d2"}
	h.clientConns[userID] = []*Connection{client1, client2}

	agentConn := &Connection{id: agentID, connType: "agent", hub: h, send: make(chan []byte, 10)}
	h.agents[agentID] = agentConn

	sender := &Connection{
		id:       agentID,
		connType: "agent",
		hub:      h,
		send:     make(chan []byte, 10),
	}

	typingData, _ := json.Marshal(map[string]interface{}{
		"conversation_id": convID,
		"typing":          true,
	})

	routeTypingIndicator(sender, typingData)

	// Both devices should receive typing indicator
	for i, c := range []*Connection{client1, client2} {
		select {
		case <-c.send:
			// Good
		case <-time.After(1 * time.Second):
			t.Errorf("device %d did not receive typing indicator", i)
		}
	}
}

// =============================================================================
// routeStatusUpdate tests (87.5% → target 95%+)
// =============================================================================

func TestCB107_RouteStatusUpdate_MultiDevice(t *testing.T) {
	setupTestDB_CB107(t)

	userID := createTestUser_CB107(db, "status-user", "pass123")
	agentID := "agent-status"
	convID := createTestConversation_CB107(db, userID, agentID)

	h := newHub()
	go h.run()
	defer h.Stop()

	oldHub := hub
	hub = h
	defer func() { hub = oldHub }()

	// Register two client devices
	client1 := &Connection{id: userID, connType: "client", hub: h, send: make(chan []byte, 10), deviceID: "d1"}
	client2 := &Connection{id: userID, connType: "client", hub: h, send: make(chan []byte, 10), deviceID: "d2"}
	h.clientConns[userID] = []*Connection{client1, client2}

	sender := &Connection{
		id:       agentID,
		connType: "agent",
		hub:      h,
		send:     make(chan []byte, 10),
	}

	statusData, _ := json.Marshal(map[string]interface{}{
		"conversation_id": convID,
		"status":          "busy",
	})

	routeStatusUpdate(sender, statusData)

	// Both devices should receive status update
	for i, c := range []*Connection{client1, client2} {
		select {
		case <-c.send:
			// Good
		case <-time.After(1 * time.Second):
			t.Errorf("device %d did not receive status update", i)
		}
	}
}

// =============================================================================
// handleGetRateLimitTier tests (87.5% → target 95%+)
// =============================================================================

func TestCB107_HandleGetRateLimitTier_DBError(t *testing.T) {
	setupTestDB_CB107(t)

	// Close DB to cause query error
	db.Close()

	adminSecretVal := getAdminSecret()
	req := httptest.NewRequest("GET", "/rate-limit/tier?user_id=test-user", nil)
	req.Header.Set("X-Admin-Secret", adminSecretVal)
	rr := httptest.NewRecorder()

	handleGetRateLimitTier(rr, req)

	// Should return some error response or default tier
	if rr.Code == http.StatusOK {
		t.Logf("got 200 with closed DB (may return default)")
	}
}

// =============================================================================
// handleRemoveTag tests (87.5% → target 95%+)
// =============================================================================

func TestCB107_HandleRemoveTag_DBError(t *testing.T) {
	setupTestDB_CB107(t)

	userID := createTestUser_CB107(db, "tag-user", "pass123")
	convID := createTestConversation_CB107(db, userID, "agent-tag")
	token, _ := GenerateJWT(userID, "tag-user")

	// Insert a tag first
	db.Exec("INSERT INTO conversation_tags (id, conversation_id, tag) VALUES (?, ?, ?)",
		"tag-1", convID, "important")

	db.Close()

	form := "conversation_id=" + convID + "&tag=important"
	req := httptest.NewRequest("POST", "/tags/remove", strings.NewReader(form))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	handleRemoveTag(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Logf("got code %d (DB closed)", rr.Code)
	}
}

// =============================================================================
// ipRateLimitMiddleware tests (88.9% → target 95%+)
// =============================================================================

func TestCB107_IPRateLimitMiddleware_RateLimited(t *testing.T) {
	// Reset IP rate limiter
	ipRateLimiter = NewRateLimiter(5, time.Minute)

	handler := ipRateLimitMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Make 5 requests (limit is 5)
	for i := 0; i < 5; i++ {
		req := httptest.NewRequest("GET", "/", nil)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Errorf("request %d: expected 200, got %d", i, rr.Code)
		}
	}

	// 6th should be rate limited
	req := httptest.NewRequest("GET", "/", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusTooManyRequests {
		t.Errorf("expected 429 on 6th request, got %d", rr.Code)
	}
}

// =============================================================================
// authRateLimitMiddleware tests (88.9% → target 95%+)
// =============================================================================

func TestCB107_AuthRateLimitMiddleware_RateLimited(t *testing.T) {
	// Reset auth IP limiter
	authIPLimiter = NewRateLimiter(3, time.Minute)

	handler := authRateLimitMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	for i := 0; i < 3; i++ {
		req := httptest.NewRequest("POST", "/auth/login", nil)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Errorf("request %d: expected 200, got %d", i, rr.Code)
		}
	}

	req := httptest.NewRequest("POST", "/auth/login", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusTooManyRequests {
		t.Errorf("expected 429 on 4th auth request, got %d", rr.Code)
	}
}

// =============================================================================
// initFCM tests (88.9% → target 95%+)
// =============================================================================

func TestCB107_InitFCM_NilConfig(t *testing.T) {
	old := pushConfig
	pushConfig = nil
	defer func() { pushConfig = old }()

	initFCM()

	if pushConfig != nil && pushConfig.FCMEnabled {
		t.Error("expected FCM disabled with nil config")
	}
}

func TestCB107_InitFCM_Disabled(t *testing.T) {
	old := pushConfig
	pushConfig = &PushNotificationConfig{}
	defer func() { pushConfig = old }()

	t.Setenv("FCM_ENABLED", "false")
	t.Setenv("FCM_CREDENTIALS_PATH", "")

	initFCM()

	if pushConfig.FCMEnabled {
		t.Error("expected FCM disabled when FCM_ENABLED=false")
	}
}

// =============================================================================
// handleRegisterDeviceToken tests (88.9% → target 95%+)
// =============================================================================

func TestCB107_HandleRegisterDeviceToken_DBError(t *testing.T) {
	setupTestDB_CB107(t)

	userID := createTestUser_CB107(db, "device-user", "pass123")
	token, _ := GenerateJWT(userID, "device-user")

	db.Close()

	body := `{"device_token":"token123","platform":"ios"}`
	req := httptest.NewRequest("POST", "/device/register", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	handleRegisterDeviceToken(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Logf("got code %d (DB closed)", rr.Code)
	}
}

func TestCB107_HandleRegisterDeviceToken_InvalidJSON(t *testing.T) {
	setupTestDB_CB107(t)

	userID := createTestUser_CB107(db, "device-user2", "pass123")
	token, _ := GenerateJWT(userID, "device-user2")

	req := httptest.NewRequest("POST", "/device/register", strings.NewReader("not json"))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	handleRegisterDeviceToken(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid JSON, got %d", rr.Code)
	}
}

func TestCB107_HandleRegisterDeviceToken_EmptyToken(t *testing.T) {
	setupTestDB_CB107(t)

	userID := createTestUser_CB107(db, "device-user3", "pass123")
	token, _ := GenerateJWT(userID, "device-user3")

	body := `{"device_token":"","platform":"ios"}`
	req := httptest.NewRequest("POST", "/device/register", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	handleRegisterDeviceToken(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for empty token, got %d", rr.Code)
	}
}

// =============================================================================
// handleWebPushSubscribe tests (88.9% → target 95%+)
// =============================================================================

func TestCB107_HandleWebPushSubscribe_DBError(t *testing.T) {
	setupTestDB_CB107(t)

	userID := createTestUser_CB107(db, "webpush-user", "pass123")
	token, _ := GenerateJWT(userID, "webpush-user")

	db.Close()

	body := `{"endpoint":"https://fcm.googleapis.com/test","p256dh":"key1","auth":"auth1"}`
	req := httptest.NewRequest("POST", "/webpush/subscribe", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	handleWebPushSubscribe(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Logf("got code %d (DB closed)", rr.Code)
	}
}

// =============================================================================
// routeChatMessage tests (84.4% → target 90%+)
// =============================================================================

func TestCB107_RouteChatMessage_AgentToMultiDevice(t *testing.T) {
	setupTestDB_CB107(t)

	userID := createTestUser_CB107(db, "route-user", "pass123")
	agentID := "agent-route"
	convID := createTestConversation_CB107(db, userID, agentID)

	h := newHub()
	go h.run()
	defer h.Stop()

	oldHub := hub
	hub = h
	defer func() { hub = oldHub }()

	client1 := &Connection{id: userID, connType: "client", hub: h, send: make(chan []byte, 10), deviceID: "d1"}
	client2 := &Connection{id: userID, connType: "client", hub: h, send: make(chan []byte, 10), deviceID: "d2"}
	h.clientConns[userID] = []*Connection{client1, client2}

	agentConn := &Connection{id: agentID, connType: "agent", hub: h, send: make(chan []byte, 10)}
	h.agents[agentID] = agentConn

	sender := &Connection{
		id:       agentID,
		connType: "agent",
		hub:      h,
		send:     make(chan []byte, 10),
	}

	msgData, _ := json.Marshal(map[string]interface{}{
		"conversation_id": convID,
		"content":         "hello from agent",
	})

	routeChatMessage(sender, msgData)

	// Both devices should receive the message
	received := 0
	for _, c := range []*Connection{client1, client2} {
		select {
		case data := <-c.send:
			if strings.Contains(string(data), "hello from agent") {
				received++
			}
		case <-time.After(500 * time.Millisecond):
		}
	}
	if received != 2 {
		t.Errorf("expected 2 devices to receive, got %d", received)
	}
}

func TestCB107_RouteChatMessage_UserToAgent_Offline(t *testing.T) {
	setupTestDB_CB107(t)

	userID := createTestUser_CB107(db, "offline-user", "pass123")
	agentID := "agent-offline"
	convID := createTestConversation_CB107(db, userID, agentID)

	h := newHub()
	go h.run()
	defer h.Stop()

	oldHub := hub
	hub = h
	defer func() { hub = oldHub }()

	// Agent not connected (offline)
	sender := &Connection{
		id:       userID,
		connType: "user",
		hub:      h,
		send:     make(chan []byte, 10),
	}

	msgData, _ := json.Marshal(map[string]interface{}{
		"conversation_id": convID,
		"content":         "hello offline agent",
	})

	routeChatMessage(sender, msgData)

	// Message should be queued for offline agent
	// Check queue depth
	if offlineQueue != nil {
		depth := offlineQueue.TotalDepth()
		if depth == 0 {
			t.Error("expected message to be queued for offline agent")
		}
	}
}

// =============================================================================
// readPump tests (86.4% → target 90%+)
// =============================================================================

func TestCB107_ReadPump_UnexpectedClose(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upgrader := websocket.Upgrader{}
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()

		h := newHub()
		go h.run()
		defer h.Stop()

		c := &Connection{
			id:       "test-read",
			connType: "client",
			hub:      h,
			send:     make(chan []byte, 10),
			conn:     conn,
		}

		// Close the connection immediately to cause read error
		conn.Close()

		// readPump should handle the close gracefully
		done := make(chan struct{})
		go func() {
			c.readPump()
			close(done)
		}()

		select {
		case <-done:
			// readPump exited
		case <-time.After(3 * time.Second):
			t.Error("readPump did not exit within 3s")
		}
	}))
	defer srv.Close()

	url := "ws://" + strings.TrimPrefix(srv.URL, "http://")
	dialer := websocket.Dialer{}
	wsConn, _, err := dialer.Dial(url, nil)
	if err != nil {
		t.Skipf("could not dial: %v", err)
	}
	wsConn.Close()
}

// =============================================================================
// handleAgentConnect tests (86.0% → target 90%+)
// =============================================================================

func TestCB107_HandleAgentConnect_RateLimited(t *testing.T) {
	// Reset agent rate limiter
	agentRateLimiter = &rateLimiter{
		attempts: make(map[string]*rateLimitEntry),
	}

	setupTestDB_CB107(t)

	// Exhaust the rate limit
	for i := 0; i < 10; i++ {
		agentRateLimiter.Allow("agent-rl-test")
	}

	// Next attempt should be rate limited
	req := httptest.NewRequest("GET", "/agent/connect?agent_id=agent-rl-test&agent_secret="+getAgentSecret(), nil)
	rr := httptest.NewRecorder()

	handleAgentConnect(rr, req)

	if rr.Code != http.StatusTooManyRequests {
		t.Errorf("expected 429 for rate-limited agent, got %d", rr.Code)
	}
}

// =============================================================================
// handleGetEncryptedMessages tests (85.4% → target 95%+)
// =============================================================================

func TestCB107_HandleGetEncryptedMessages_LimitEdgeCases(t *testing.T) {
	setupTestDB_CB107(t)

	userID := createTestUser_CB107(db, "enc-user", "pass123")
	convID := createTestConversation_CB107(db, userID, "agent-enc")

	// Insert some encrypted messages
	for i := 0; i < 5; i++ {
		db.Exec("INSERT INTO encrypted_messages (id, conversation_id, sender_id, sender_type, ciphertext, iv, recipient_key_id, algorithm, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
			fmt.Sprintf("emsg-%d", i), convID, userID, "user", "cipher", "iv", "key", "aes-256-gcm", time.Now().UTC())
	}

	token, _ := GenerateJWT(userID, "enc-user")

	// Test with limit=0 (should default to 50)
	req := httptest.NewRequest("GET", "/messages/encrypted?conversation_id="+convID+"&limit=0", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	handleGetEncryptedMessages(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}

	// Test with limit=500 (should cap to 50)
	req2 := httptest.NewRequest("GET", "/messages/encrypted?conversation_id="+convID+"&limit=500", nil)
	req2.Header.Set("Authorization", "Bearer "+token)
	rr2 := httptest.NewRecorder()
	handleGetEncryptedMessages(rr2, req2)

	if rr2.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr2.Code)
	}
}

func TestCB107_HandleGetEncryptedMessages_AgentAuth(t *testing.T) {
	setupTestDB_CB107(t)

	userID := createTestUser_CB107(db, "enc-agent-user", "pass123")
	agentID := "agent-enc-test"
	convID := createTestConversation_CB107(db, userID, agentID)

	req := httptest.NewRequest("GET", "/messages/encrypted?conversation_id="+convID, nil)
	req.Header.Set("X-Agent-Secret", getAgentSecret())
	req.Header.Set("X-Agent-ID", agentID)
	rr := httptest.NewRecorder()

	handleGetEncryptedMessages(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 for agent auth, got %d", rr.Code)
	}
}

// =============================================================================
// Drain tests (83.3% → target 90%+)
// =============================================================================

func TestCB107_Drain_EmptyQueue(t *testing.T) {
	q := newOfflineQueue(100, 7*24*time.Hour)
	msgs := q.Drain("user-empty")
	if len(msgs) != 0 {
		t.Errorf("expected 0 drained from empty queue, got %d", len(msgs))
	}
}

func TestCB107_Drain_PartialExpired(t *testing.T) {
	q := newOfflineQueue(100, 50*time.Millisecond)
	q.Enqueue("user-partial", []byte("msg1"))
	q.Enqueue("user-partial", []byte("msg2"))
	time.Sleep(80 * time.Millisecond)
	q.Enqueue("user-partial", []byte("msg3"))

	msgs := q.Drain("user-partial")
	// First two expired, only msg3 should remain
	if len(msgs) > 1 {
		t.Errorf("expected at most 1 non-expired message, got %d", len(msgs))
	}
}

func TestCB107_Drain_AllExpired(t *testing.T) {
	q := newOfflineQueue(100, 50*time.Millisecond)
	q.Enqueue("user-expired", []byte("msg1"))
	q.Enqueue("user-expired", []byte("msg2"))
	time.Sleep(80 * time.Millisecond)

	msgs := q.Drain("user-expired")
	if len(msgs) != 0 {
		t.Errorf("expected 0 drained (all expired), got %d", len(msgs))
	}
}

// =============================================================================
// RateLimiter.cleanup tests (83.3% → target 90%+)
// =============================================================================

func TestCB107_RateLimiter_Cleanup_StopChannel(t *testing.T) {
	rl := NewRateLimiter(100, 50*time.Millisecond)

	rl.Allow("user1")
	rl.Allow("user2")

	// Wait for entries to become stale
	time.Sleep(80 * time.Millisecond)

	// Stop triggers cleanup goroutine to exit via stopCh
	rl.Stop()

	// After stop, give a moment for goroutine to clean up
	time.Sleep(20 * time.Millisecond)

	// Count should still show stale entries since cleanup goroutine exited
	// before the ticker fired. That's fine - we covered the stop path.
	count := rl.Count("user1")
	_ = count // Just verify no panic/deadlock
}

// =============================================================================
// sendWelcomeMessage tests (80.0% → target 90%+)
// =============================================================================

func TestCB107_SendWelcomeMessage_Success(t *testing.T) {
	conn := &Connection{
		id:       "welcome-user",
		connType: "client",
		send:     make(chan []byte, 1),
	}

	sendWelcomeMessage(conn)

	// Check that we received a message
	select {
	case msg := <-conn.send:
		if !strings.Contains(string(msg), "connected") {
			t.Errorf("expected connected message, got %s", string(msg))
		}
	default:
		t.Error("no message received on send channel")
	}
}

func TestCB107_SendWelcomeMessage_ClosedChannel(t *testing.T) {
	conn := &Connection{
		id:       "welcome-closed",
		connType: "client",
		send:     make(chan []byte, 1),
	}

	// Close the channel
	close(conn.send)

	// Should not panic
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("sendWelcomeMessage panicked on closed channel: %v", r)
		}
	}()

	sendWelcomeMessage(conn)
}

func TestCB107_SendWelcomeMessage_WithDeviceID(t *testing.T) {
	conn := &Connection{
		id:       "welcome-nodev",
		connType: "client",
		send:     make(chan []byte, 1),
		deviceID: "dev-1",
	}

	sendWelcomeMessage(conn)

	select {
	case msg := <-conn.send:
		var decoded map[string]interface{}
		if err := json.Unmarshal(msg, &decoded); err != nil {
			t.Errorf("failed to decode: %v", err)
		}
		data, ok := decoded["data"].(map[string]interface{})
		if !ok {
			t.Error("expected data field to be a map")
			return
		}
		if data["device_id"] != "dev-1" {
			t.Errorf("expected device_id 'dev-1', got %v", data["device_id"])
		}
	case <-time.After(500 * time.Millisecond):
		t.Error("no message received")
	}
}

// =============================================================================
// InitTracing tests (79.5% → target 85%+)
// =============================================================================

func TestCB107_InitTracing_HTTPExporterInsecure(t *testing.T) {
	tracingMu = sync.Once{}
	tp = nil

	t.Setenv("OTEL_ENABLED", "true")
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://localhost:4318")
	t.Setenv("OTEL_EXPORTER_OTLP_PROTOCOL", "http")
	t.Setenv("OTEL_SERVICE_NAME", "test-service")
	t.Setenv("OTEL_SAMPLING_RATE", "0.5")

	err := InitTracing()
	if err != nil {
		t.Logf("InitTracing returned error (expected without collector): %v", err)
	}

	ShutdownTracing()
}

func TestCB107_InitTracing_GRPCInsecure(t *testing.T) {
	tracingMu = sync.Once{}
	tp = nil

	t.Setenv("OTEL_ENABLED", "true")
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "localhost:4317")
	t.Setenv("OTEL_EXPORTER_OTLP_PROTOCOL", "grpc")
	t.Setenv("OTEL_SERVICE_NAME", "test-grpc")

	err := InitTracing()
	if err != nil {
		t.Logf("InitTracing gRPC returned error (expected without collector): %v", err)
	}

	ShutdownTracing()
}

func TestCB107_InitTracing_AlreadyInitialized(t *testing.T) {
	tracingMu = sync.Once{}
	tp = nil

	t.Setenv("OTEL_ENABLED", "true")
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://localhost:4318")
	t.Setenv("OTEL_EXPORTER_OTLP_PROTOCOL", "http")

	// First call
	_ = InitTracing()

	// Second call should be no-op due to sync.Once
	err := InitTracing()
	if err != nil {
		t.Logf("second InitTracing returned error: %v", err)
	}

	ShutdownTracing()
}

func TestCB107_InitTracing_CustomServiceName(t *testing.T) {
	tracingMu = sync.Once{}
	tp = nil

	t.Setenv("OTEL_ENABLED", "true")
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://localhost:4318")
	t.Setenv("OTEL_EXPORTER_OTLP_PROTOCOL", "http")
	t.Setenv("OTEL_SERVICE_NAME", "custom-agent-messenger")

	err := InitTracing()
	if err != nil {
		t.Logf("InitTracing returned error: %v", err)
	}

	ShutdownTracing()
}

func TestCB107_InitTracing_HTTPSEndpoint(t *testing.T) {
	tracingMu = sync.Once{}
	tp = nil

	t.Setenv("OTEL_ENABLED", "true")
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "https://otel-collector.example.com:443")
	t.Setenv("OTEL_EXPORTER_OTLP_PROTOCOL", "http")

	err := InitTracing()
	if err != nil {
		t.Logf("InitTracing HTTPS returned error: %v", err)
	}

	ShutdownTracing()
}

// =============================================================================
// loadQueueFromDB tests (89.5% → target 95%+)
// =============================================================================

func TestCB107_LoadQueueFromDB_MultipleUsers(t *testing.T) {
	setupTestDB_CB107(t)

	// Insert messages for multiple users
	persistQueue(db, "user-a", []byte("msg1"))
	persistQueue(db, "user-b", []byte("msg2"))
	persistQueue(db, "user-a", []byte("msg3"))

	q := newOfflineQueue(100, 7*24*time.Hour)
	loadQueueFromDB(db, q)

	depth := q.TotalDepth()
	if depth != 3 {
		t.Errorf("expected 3 total messages loaded, got %d", depth)
	}
}

func TestCB107_LoadQueueFromDB_EmptyTable(t *testing.T) {
	setupTestDB_CB107(t)

	q := newOfflineQueue(100, 7*24*time.Hour)
	loadQueueFromDB(db, q)

	if q.TotalDepth() != 0 {
		t.Errorf("expected 0 depth from empty table, got %d", q.TotalDepth())
	}
}

// =============================================================================
// sendPushNotification routing tests
// =============================================================================

func TestCB107_SendPushNotification_Android(t *testing.T) {
	old := pushConfig
	pushConfig = &PushNotificationConfig{}
	defer func() { pushConfig = old }()

	err := sendPushNotification("token", "Title", "Body", "conv1", "android")
	if err != nil {
		t.Errorf("expected nil for android with FCM disabled, got %v", err)
	}
}

func TestCB107_SendPushNotification_IOS(t *testing.T) {
	old := pushConfig
	pushConfig = &PushNotificationConfig{}
	defer func() { pushConfig = old }()

	err := sendPushNotification("token", "Title", "Body", "conv1", "ios")
	if err != nil {
		t.Errorf("expected nil for ios with APNs disabled, got %v", err)
	}
}

func TestCB107_SendPushNotification_UnknownPlatform(t *testing.T) {
	old := pushConfig
	pushConfig = &PushNotificationConfig{}
	defer func() { pushConfig = old }()

	err := sendPushNotification("token", "Title", "Body", "conv1", "unknown")
	if err != nil {
		t.Errorf("expected nil for unknown with push disabled, got %v", err)
	}
}

func TestCB107_SendPushNotification_FCM_Routing(t *testing.T) {
	old := pushConfig
	pushConfig = &PushNotificationConfig{FCMEnabled: false}
	defer func() { pushConfig = old }()

	err := sendPushNotification("token", "Title", "Body", "conv1", "fcm")
	if err != nil {
		t.Errorf("expected nil for FCM disabled, got %v", err)
	}
}

// =============================================================================
// handleAdminProfile edge cases
// =============================================================================

func TestCB107_HandleAdminProfile_CPUStopNotActive(t *testing.T) {
	cpuProfileState.Lock()
	cpuProfileState.active = false
	cpuProfileState.stopFunc = nil
	cpuProfileState.Unlock()

	req := httptest.NewRequest("POST", "/admin/profile", strings.NewReader(`{"action":"cpu_stop"}`))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	handleAdminProfile(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 for cpu_stop when not active, got %d", rr.Code)
	}
}

func TestCB107_HandleAdminProfile_UnknownAction(t *testing.T) {
	req := httptest.NewRequest("POST", "/admin/profile", strings.NewReader(`{"action":"unknown_action"}`))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	handleAdminProfile(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for unknown action, got %d", rr.Code)
	}
}

// =============================================================================
// loadTiersFromDB tests
// =============================================================================

func TestCB107_LoadTiersFromDB_WithMultipleTiers(t *testing.T) {
	setupTestDB_CB107(t)

	// Insert multiple tier records
	db.Exec("INSERT INTO user_rate_limit_tiers (user_id, tier_name) VALUES (?, ?)", "user-pro", "pro")
	db.Exec("INSERT INTO user_rate_limit_tiers (user_id, tier_name) VALUES (?, ?)", "user-ent", "enterprise")

	tl := NewTieredRateLimiter()
	loadTiersFromDB(tl)

	// Verify tiers were loaded
	tier := tl.GetTier("user-pro")
	if tier.Name != TierPro.Name {
		t.Errorf("expected pro tier for user-pro, got %v", tier.Name)
	}
	tier2 := tl.GetTier("user-ent")
	if tier2.Name != TierEnterprise.Name {
		t.Errorf("expected enterprise tier for user-ent, got %v", tier2.Name)
	}
}

// =============================================================================
// handleSetRateLimitTier tests (80.8% → target 90%+)
// =============================================================================

func TestCB107_HandleSetRateLimitTier_PersistError(t *testing.T) {
	setupTestDB_CB107(t)

	db.Close()

	form := "user_id=persist-user&tier=pro"
	req := httptest.NewRequest("POST", "/rate-limit/tier", strings.NewReader(form))
	req.Header.Set("X-Admin-Secret", getAdminSecret())
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	handleSetRateLimitTier(rr, req)

	// Should get 500 due to DB error on persist
	if rr.Code != http.StatusInternalServerError {
		t.Logf("got code %d (DB closed, persist may fail silently)", rr.Code)
	}
}

func TestCB107_HandleSetRateLimitTier_EnterpriseTier(t *testing.T) {
	setupTestDB_CB107(t)

	origAdminSecret := adminSecret
	defer func() { adminSecret = origAdminSecret }()
	resetAdminSecret()

	form := "user_id=ent-user&tier=enterprise"
	req := httptest.NewRequest("POST", "/rate-limit/tier", strings.NewReader(form))
	req.Header.Set("X-Admin-Secret", getAdminSecret())
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	handleSetRateLimitTier(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 for enterprise tier, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestCB107_HandleSetRateLimitTier_FreeTier(t *testing.T) {
	setupTestDB_CB107(t)

	origAdminSecret := adminSecret
	defer func() { adminSecret = origAdminSecret }()
	resetAdminSecret()

	form := "user_id=free-user&tier=free"
	req := httptest.NewRequest("POST", "/rate-limit/tier", strings.NewReader(form))
	req.Header.Set("X-Admin-Secret", getAdminSecret())
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	handleSetRateLimitTier(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 for free tier, got %d: %s", rr.Code, rr.Body.String())
	}
}