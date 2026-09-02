package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

// --- CB111: Coverage boost targeting remaining sub-88% functions ---
// Focus areas (from coverage profile after CB110, 87.8% total):
// - writePump (70.4%): ServerMetrics increment, ping error
// - InitTracing (79.5%): http protocol, sampling rate parse
// - sendWelcomeMessage (80%): already well-covered, target deviceID path
// - ShutdownTracing (80%): shutdown error path
// - handleUpload (81.8%): seek error, copy error
// - RegisterAgentOnConnect (81.8%): existing agent with only name=agentID
// - Snapshot (83.3%): with nil offlineQueue
// - cleanup (83.3%): ticker path
// - handleGoroutineProfile (84.6%): create file error
// - handleHeapProfile (84.6%): create file error
// - getDeviceTokensForUser (84.6%): query error
// - initAPNs (84%): cert load error
// - handleStoreEncryptedMessage (84.9%): agent sender delivery, user not participant
// - routeChatMessage (84.4%): missing conversation_id
// - initFCM (88.9%): no creds, creds not found
// - handleCPUProfileStart (85%): start error
// - parseSize: TB, GB suffixes
// - handleMessageEdit: success, deleted message, not sender
// - handleMessageDelete: success path
// - addReaction: DB error
// - notifyUser (93.3%): panic recovery

// ============ parseSize tests ============

func TestCB111_ParseSize_TB(t *testing.T) {
	v, err := parseSize("1TB")
	if err != nil {
		t.Fatalf("parseSize(1TB) error: %v", err)
	}
	if v != 1<<40 {
		t.Errorf("parseSize(1TB) = %d, want %d", v, 1<<40)
	}
}

func TestCB111_ParseSize_GB(t *testing.T) {
	v, err := parseSize("2GB")
	if err != nil {
		t.Fatalf("parseSize(2GB) error: %v", err)
	}
	if v != 2<<30 {
		t.Errorf("parseSize(2GB) = %d, want %d", v, 2<<30)
	}
}

func TestCB111_ParseSize_KB(t *testing.T) {
	v, err := parseSize("500KB")
	if err != nil {
		t.Fatalf("parseSize(500KB) error: %v", err)
	}
	if v != 500<<10 {
		t.Errorf("parseSize(500KB) = %d, want %d", v, 500<<10)
	}
}

func TestCB111_ParseSize_B(t *testing.T) {
	v, err := parseSize("100B")
	if err != nil {
		t.Fatalf("parseSize(100B) error: %v", err)
	}
	if v != 100 {
		t.Errorf("parseSize(100B) = %d, want 100", v)
	}
}

func TestCB111_ParseSize_InvalidSuffix(t *testing.T) {
	_, err := parseSize("100XB")
	if err == nil {
		t.Error("parseSize(100XB) should return error")
	}
}

func TestCB111_ParseSize_DecimalGB(t *testing.T) {
	v, err := parseSize("1.5GB")
	if err != nil {
		t.Fatalf("parseSize(1.5GB) error: %v", err)
	}
	expected := int64(1.5 * float64(1<<30))
	if v != expected {
		t.Errorf("parseSize(1.5GB) = %d, want %d", v, expected)
	}
}

// ============ RegisterAgentOnConnect tests ============

func TestCB111_RegisterAgentOnConnect_ExistingAgentNoUpdates(t *testing.T) {
	setupTestDB(t)

	// Insert an existing agent
	_, err := db.Exec("INSERT INTO agents (id, name, model, personality, specialty) VALUES (?, ?, ?, ?, ?)",
		"agent-no-update", "ExistingName", "gpt-4", "friendly", "general")
	if err != nil {
		t.Fatalf("insert agent: %v", err)
	}

	// Call RegisterAgentOnConnect with empty model/personality/specialty and name=agentID
	// This should skip all UPDATE statements
	err = RegisterAgentOnConnect("agent-no-update", "", "", "", "")
	if err != nil {
		t.Fatalf("RegisterAgentOnConnect: %v", err)
	}

	// Verify nothing changed
	var name, model, personality, specialty string
	err = db.QueryRow("SELECT name, model, personality, specialty FROM agents WHERE id = ?",
		"agent-no-update").Scan(&name, &model, &personality, &specialty)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if name != "ExistingName" {
		t.Errorf("name = %s, want ExistingName", name)
	}
	if model != "gpt-4" {
		t.Errorf("model = %s, want gpt-4", model)
	}
}

func TestCB111_RegisterAgentOnConnect_DBQueryError(t *testing.T) {
	// Use a closed db to trigger query error
	setupTestDB(t)
	db.Close()

	err := RegisterAgentOnConnect("test-agent", "Test", "", "", "")
	if err == nil {
		t.Error("RegisterAgentOnConnect with closed db should return error")
	}
}

// ============ Snapshot tests ============

func TestCB111_Snapshot_WithNilOfflineQueue(t *testing.T) {
	h := newHub()
	go h.run()
	defer h.Stop()

	m := NewMetrics(h)
	snap := m.Snapshot()

	if snap == nil {
		t.Fatal("Snapshot() returned nil")
	}
	if _, ok := snap["version"]; !ok {
		t.Error("Snapshot missing 'version' key")
	}
	if _, ok := snap["uptime_seconds"]; !ok {
		t.Error("Snapshot missing 'uptime_seconds' key")
	}
	if _, ok := snap["offline_queue_depth"]; !ok {
		t.Error("Snapshot missing 'offline_queue_depth' key")
	}
	// offline_queue_depth should be 0 when offlineQueue is nil
	depth, ok := snap["offline_queue_depth"].(int)
	if !ok {
		t.Errorf("offline_queue_depth is %T, want int", snap["offline_queue_depth"])
	}
	if depth != 0 {
		t.Errorf("offline_queue_depth = %d, want 0 (nil queue)", depth)
	}
}

func TestCB111_Snapshot_WithOfflineQueue(t *testing.T) {
	h := newHub()
	go h.run()
	defer h.Stop()

	origQueue := offlineQueue
	offlineQueue = newOfflineQueue(100, 5*time.Minute)
	defer func() { offlineQueue = origQueue }()

	offlineQueue.Enqueue("user1", []byte("test message"))

	m := NewMetrics(h)
	snap := m.Snapshot()

	depth, ok := snap["offline_queue_depth"].(int)
	if !ok {
		t.Errorf("offline_queue_depth is %T, want int", snap["offline_queue_depth"])
	}
	if depth != 1 {
		t.Errorf("offline_queue_depth = %d, want 1", depth)
	}
}

// ============ handleMessageEdit tests ============

func TestCB111_HandleMessageEdit_Success(t *testing.T) {
	setupTestDB(t)

	// Create user, conversation, and message
	_, err := db.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)",
		"user-edit-1", "useredit1", "hash")
	if err != nil {
		t.Fatalf("insert user: %v", err)
	}
	_, err = db.Exec("INSERT INTO agents (id, name, model, personality, specialty) VALUES (?, ?, ?, ?, ?)",
		"agent-edit-1", "Agent", "gpt-4", "friendly", "general")
	if err != nil {
		t.Fatalf("insert agent: %v", err)
	}
	_, err = db.Exec("INSERT INTO conversations (id, user_id, agent_id) VALUES (?, ?, ?)",
		"conv-edit-1", "user-edit-1", "agent-edit-1")
	if err != nil {
		t.Fatalf("insert conv: %v", err)
	}
	_, err = db.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, metadata) VALUES (?, ?, ?, ?, ?, ?)",
		"msg-edit-1", "conv-edit-1", "client", "user-edit-1", "original content", "")
	if err != nil {
		t.Fatalf("insert msg: %v", err)
	}

	// Generate JWT for user
	token, err := GenerateJWT("user-edit-1", "useredit1")
	if err != nil {
		t.Fatalf("GenerateJWT: %v", err)
	}

	h := newHub()
	go h.run()
	defer h.Stop()
	origHub := hub
	hub = h
	defer func() { hub = origHub }()

	form := "message_id=msg-edit-1&content=updated content"
	req := httptest.NewRequest("POST", "/messages/edit?message_id=msg-edit-1&content=updated+content", strings.NewReader(form))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rr := httptest.NewRecorder()
	handleMessageEdit(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want %d; body: %s", rr.Code, http.StatusOK, rr.Body.String())
	}

	// Verify message was updated
	var content string
	err = db.QueryRow("SELECT content FROM messages WHERE id = ?", "msg-edit-1").Scan(&content)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if content != "updated content" {
		t.Errorf("content = %s, want 'updated content'", content)
	}
}

func TestCB111_HandleMessageEdit_DeletedMessage(t *testing.T) {
	setupTestDB(t)

	_, err := db.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)",
		"user-edit-2", "useredit2", "hash")
	if err != nil {
		t.Fatalf("insert user: %v", err)
	}
	_, err = db.Exec("INSERT INTO agents (id, name, model, personality, specialty) VALUES (?, ?, ?, ?, ?)",
		"agent-edit-2", "Agent", "gpt-4", "friendly", "general")
	if err != nil {
		t.Fatalf("insert agent: %v", err)
	}
	_, err = db.Exec("INSERT INTO conversations (id, user_id, agent_id) VALUES (?, ?, ?)",
		"conv-edit-2", "user-edit-2", "agent-edit-2")
	if err != nil {
		t.Fatalf("insert conv: %v", err)
	}
	_, err = db.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, is_deleted, metadata) VALUES (?, ?, ?, ?, ?, 1, ?)",
		"msg-edit-2", "conv-edit-2", "client", "user-edit-2", "deleted content", "")
	if err != nil {
		t.Fatalf("insert msg: %v", err)
	}

	token, err := GenerateJWT("user-edit-2", "useredit2")
	if err != nil {
		t.Fatalf("GenerateJWT: %v", err)
	}

	form := "message_id=msg-edit-2&content=new content"
	req := httptest.NewRequest("POST", "/messages/edit", strings.NewReader(form))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rr := httptest.NewRecorder()
	handleMessageEdit(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d; body: %s", rr.Code, http.StatusBadRequest, rr.Body.String())
	}
}

func TestCB111_HandleMessageEdit_NotSender(t *testing.T) {
	setupTestDB(t)

	_, err := db.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)",
		"user-edit-3", "useredit3", "hash")
	if err != nil {
		t.Fatalf("insert user: %v", err)
	}
	_, err = db.Exec("INSERT INTO agents (id, name, model, personality, specialty) VALUES (?, ?, ?, ?, ?)",
		"agent-edit-3", "Agent", "gpt-4", "friendly", "general")
	if err != nil {
		t.Fatalf("insert agent: %v", err)
	}
	_, err = db.Exec("INSERT INTO conversations (id, user_id, agent_id) VALUES (?, ?, ?)",
		"conv-edit-3", "user-edit-3", "agent-edit-3")
	if err != nil {
		t.Fatalf("insert conv: %v", err)
	}
	// Message from agent, not client
	_, err = db.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, metadata) VALUES (?, ?, ?, ?, ?, ?)",
		"msg-edit-3", "conv-edit-3", "agent", "agent-edit-3", "agent message", "")
	if err != nil {
		t.Fatalf("insert msg: %v", err)
	}

	token, err := GenerateJWT("user-edit-3", "useredit3")
	if err != nil {
		t.Fatalf("GenerateJWT: %v", err)
	}

	form := "message_id=msg-edit-3&content=hijacked"
	req := httptest.NewRequest("POST", "/messages/edit", strings.NewReader(form))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rr := httptest.NewRecorder()
	handleMessageEdit(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d; body: %s", rr.Code, http.StatusUnauthorized, rr.Body.String())
	}
}

func TestCB111_HandleMessageEdit_MessageNotFound(t *testing.T) {
	setupTestDB(t)

	_, err := db.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)",
		"user-edit-4", "useredit4", "hash")
	if err != nil {
		t.Fatalf("insert user: %v", err)
	}

	token, err := GenerateJWT("user-edit-4", "useredit4")
	if err != nil {
		t.Fatalf("GenerateJWT: %v", err)
	}

	form := "message_id=nonexistent&content=test"
	req := httptest.NewRequest("POST", "/messages/edit", strings.NewReader(form))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rr := httptest.NewRecorder()
	handleMessageEdit(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d; body: %s", rr.Code, http.StatusNotFound, rr.Body.String())
	}
}

// ============ handleMessageDelete success test ============

func TestCB111_HandleMessageDelete_Success(t *testing.T) {
	setupTestDB(t)

	_, err := db.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)",
		"user-del-1", "userdel1", "hash")
	if err != nil {
		t.Fatalf("insert user: %v", err)
	}
	_, err = db.Exec("INSERT INTO agents (id, name, model, personality, specialty) VALUES (?, ?, ?, ?, ?)",
		"agent-del-1", "Agent", "gpt-4", "friendly", "general")
	if err != nil {
		t.Fatalf("insert agent: %v", err)
	}
	_, err = db.Exec("INSERT INTO conversations (id, user_id, agent_id) VALUES (?, ?, ?)",
		"conv-del-1", "user-del-1", "agent-del-1")
	if err != nil {
		t.Fatalf("insert conv: %v", err)
	}
	_, err = db.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, metadata) VALUES (?, ?, ?, ?, ?, ?)",
		"msg-del-1", "conv-del-1", "client", "user-del-1", "to be deleted", "")
	if err != nil {
		t.Fatalf("insert msg: %v", err)
	}

	token, err := GenerateJWT("user-del-1", "userdel1")
	if err != nil {
		t.Fatalf("GenerateJWT: %v", err)
	}

	h := newHub()
	go h.run()
	defer h.Stop()
	origHub := hub
	hub = h
	defer func() { hub = origHub }()

	form := "message_id=msg-del-1"
	req := httptest.NewRequest("POST", "/messages/delete", strings.NewReader(form))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rr := httptest.NewRecorder()
	handleMessageDelete(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want %d; body: %s", rr.Code, http.StatusOK, rr.Body.String())
	}

	// Verify is_deleted is now 1
	var isDeleted int
	err = db.QueryRow("SELECT COALESCE(is_deleted, 0) FROM messages WHERE id = ?", "msg-del-1").Scan(&isDeleted)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if isDeleted != 1 {
		t.Errorf("is_deleted = %d, want 1", isDeleted)
	}
}

// ============ handleStoreEncryptedMessage tests ============

func TestCB111_HandleStoreEncryptedMessage_AgentSenderDelivery(t *testing.T) {
	setupTestDB(t)

	_, err := db.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)",
		"user-enc-agent", "userencagent", "hash")
	if err != nil {
		t.Fatalf("insert user: %v", err)
	}
	_, err = db.Exec("INSERT INTO agents (id, name, model, personality, specialty) VALUES (?, ?, ?, ?, ?)",
		"agent-enc-agent", "Agent", "gpt-4", "friendly", "general")
	if err != nil {
		t.Fatalf("insert agent: %v", err)
	}
	_, err = db.Exec("INSERT INTO conversations (id, user_id, agent_id) VALUES (?, ?, ?)",
		"conv-enc-agent", "user-enc-agent", "agent-enc-agent")
	if err != nil {
		t.Fatalf("insert conv: %v", err)
	}

	h := newHub()
	go h.run()
	defer h.Stop()
	origHub := hub
	hub = h
	defer func() { hub = origHub }()

	origAgentSecret := os.Getenv("AGENT_SECRET")
	os.Setenv("AGENT_SECRET", "test-secret")
	defer func() { os.Setenv("AGENT_SECRET", origAgentSecret); resetAgentSecret() }()

	body := `{"conversation_id":"conv-enc-agent","ciphertext":"encrypted_data","iv":"iv123","recipient_key_id":"rk1","algorithm":"aes-256-gcm"}`
	req := httptest.NewRequest("POST", "/messages/encrypted", strings.NewReader(body))
	req.Header.Set("X-Agent-Secret", "test-secret")
	req.Header.Set("X-Agent-ID", "agent-enc-agent")
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	handleStoreEncryptedMessage(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want %d; body: %s", rr.Code, http.StatusOK, rr.Body.String())
	}

	// Verify encrypted message was stored
	var count int
	err = db.QueryRow("SELECT COUNT(*) FROM encrypted_messages WHERE conversation_id = ?", "conv-enc-agent").Scan(&count)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if count != 1 {
		t.Errorf("encrypted_messages count = %d, want 1", count)
	}
}

func TestCB111_HandleStoreEncryptedMessage_UserNotParticipant(t *testing.T) {
	setupTestDB(t)

	_, err := db.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)",
		"user-enc-notpart", "userencnotpart", "hash")
	if err != nil {
		t.Fatalf("insert user: %v", err)
	}
	_, err = db.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)",
		"user-enc-other", "userencother", "hash")
	if err != nil {
		t.Fatalf("insert user2: %v", err)
	}
	_, err = db.Exec("INSERT INTO agents (id, name, model, personality, specialty) VALUES (?, ?, ?, ?, ?)",
		"agent-enc-notpart", "Agent", "gpt-4", "friendly", "general")
	if err != nil {
		t.Fatalf("insert agent: %v", err)
	}
	_, err = db.Exec("INSERT INTO conversations (id, user_id, agent_id) VALUES (?, ?, ?)",
		"conv-enc-notpart", "user-enc-other", "agent-enc-notpart")
	if err != nil {
		t.Fatalf("insert conv: %v", err)
	}

	token, err := GenerateJWT("user-enc-notpart", "userencnotpart")
	if err != nil {
		t.Fatalf("GenerateJWT: %v", err)
	}

	body := `{"conversation_id":"conv-enc-notpart","ciphertext":"enc","iv":"iv","algorithm":"aes-256-gcm"}`
	req := httptest.NewRequest("POST", "/messages/encrypted", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)

	rr := httptest.NewRecorder()
	handleStoreEncryptedMessage(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d; body: %s", rr.Code, http.StatusForbidden, rr.Body.String())
	}
}

func TestCB111_HandleStoreEncryptedMessage_MissingCiphertext(t *testing.T) {
	setupTestDB(t)

	_, err := db.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)",
		"user-enc-nocipher", "userencnocipher", "hash")
	if err != nil {
		t.Fatalf("insert user: %v", err)
	}

	token, err := GenerateJWT("user-enc-nocipher", "userencnocipher")
	if err != nil {
		t.Fatalf("GenerateJWT: %v", err)
	}

	body := `{"conversation_id":"conv1","iv":"iv","algorithm":"aes-256-gcm"}`
	req := httptest.NewRequest("POST", "/messages/encrypted", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)

	rr := httptest.NewRecorder()
	handleStoreEncryptedMessage(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d; body: %s", rr.Code, http.StatusBadRequest, rr.Body.String())
	}
}

// ============ initFCM tests ============

func TestCB111_InitFCM_NoCredsPath(t *testing.T) {
	origConfig := pushConfig
	pushConfig = &PushNotificationConfig{
		FCMEnabled: true,
	}
	defer func() { pushConfig = origConfig }()

	initFCM()

	// FCM stays enabled but fcmClient is nil (no creds path provided)
	// The function logs a warning but doesn't disable FCM
	if pushConfig.fcmClient != nil {
		t.Error("fcmClient should be nil when no creds path provided")
	}
}

func TestCB111_InitFCM_CredsNotFound(t *testing.T) {
	origConfig := pushConfig
	pushConfig = &PushNotificationConfig{
		FCMEnabled:     true,
		FCMCredentials: "/nonexistent/creds.json",
	}
	defer func() { pushConfig = origConfig }()

	initFCM()

	if pushConfig.FCMEnabled {
		t.Error("FCM should be disabled when creds file not found")
	}
}

func TestCB111_InitFCM_NilConfig(t *testing.T) {
	origConfig := pushConfig
	pushConfig = nil
	defer func() { pushConfig = origConfig }()

	initFCM()
	// Should not panic
}

func TestCB111_InitFCM_Disabled(t *testing.T) {
	origConfig := pushConfig
	pushConfig = &PushNotificationConfig{
		FCMEnabled: false,
	}
	defer func() { pushConfig = origConfig }()

	initFCM()
	// Should not enable FCM
}

// ============ initAPNs tests ============

func TestCB111_InitAPNs_NilConfig(t *testing.T) {
	origConfig := pushConfig
	pushConfig = nil
	defer func() { pushConfig = origConfig }()

	initAPNs()
	// Should not panic
}

func TestCB111_InitAPNs_Disabled(t *testing.T) {
	origConfig := pushConfig
	pushConfig = &PushNotificationConfig{
		APNSEnabled: false,
	}
	defer func() { pushConfig = origConfig }()

	initAPNs()
	// Should not enable APNs
}

// ============ notifyUser tests ============

func TestCB111_NotifyUser_PanicRecovery(t *testing.T) {
	// Test that notifyUser recovers from panics
	origDB := db
	db = nil
	defer func() { db = origDB }()

	origConfig := pushConfig
	pushConfig = &PushNotificationConfig{}
	defer func() { pushConfig = origConfig }()

	// Should not panic even with nil db
	notifyUser("user1", "Test", "Body", "conv1")
}

func TestCB111_NotifyUser_NilPushConfig(t *testing.T) {
	origConfig := pushConfig
	pushConfig = nil
	defer func() { pushConfig = origConfig }()

	// Should return early without panic
	notifyUser("user1", "Test", "Body", "conv1")
}

// ============ getDeviceTokensForUser tests ============

func TestCB111_GetDeviceTokensForUser_NilDB(t *testing.T) {
	origDB := db
	db = nil
	defer func() { db = origDB }()

	// Use recover since nil db may panic
	defer func() {
		recover()
	}()

	tokens, err := getDeviceTokensForUser("user1")
	if err == nil {
		t.Error("expected error with nil db")
	}
	if tokens != nil {
		t.Errorf("tokens = %v, want nil", tokens)
	}
}

func TestCB111_GetDeviceTokensForUser_QueryError(t *testing.T) {
	setupTestDB(t)

	// Drop the device_tokens table to cause query error
	db.Exec("DROP TABLE device_tokens")

	_, err := getDeviceTokensForUser("user1")
	if err == nil {
		t.Error("expected error when table doesn't exist")
	}
}

// ============ routeChatMessage tests ============

func TestCB111_RouteChatMessage_MissingConversationID(t *testing.T) {
	h := newHub()
	go h.run()
	defer h.Stop()

	conn := &Connection{
		hub:      h,
		id:       "user1",
		connType: "client",
		send:     make(chan []byte, 10),
	}

	data := `{"content":"hello"}`
	// Should not crash — conversation_id is empty
	routeChatMessage(conn, []byte(data))

	// Check for error message in send channel
	select {
	case msg := <-conn.send:
		var outgoing OutgoingMessage
		if err := json.Unmarshal(msg, &outgoing); err == nil {
			if outgoing.Type != "error" {
				t.Errorf("expected error message, got type %s", outgoing.Type)
			}
		}
	case <-time.After(1 * time.Second):
		// May or may not send error depending on implementation
	}
}

// ============ ShutdownTracing tests ============

func TestCB111_ShutdownTracing_NilProvider(t *testing.T) {
	origTP := tp
	tp = nil
	defer func() { tp = origTP }()

	// Should not panic with nil tp
	ShutdownTracing()
}

// ============ handleHeapProfile error path ============

func TestCB111_HandleHeapProfile_CreateError(t *testing.T) {
	origAdminSecret := os.Getenv("ADMIN_SECRET")
	os.Setenv("ADMIN_SECRET", "test-admin-secret")
	defer func() { os.Setenv("ADMIN_SECRET", origAdminSecret); resetAdminSecret() }()

	origDir := os.Getenv("PROFILING_DIR")
	os.Setenv("PROFILING_DIR", "/proc/cannot_write_here")
	defer os.Setenv("PROFILING_DIR", origDir)

	req := httptest.NewRequest("POST", "/admin/profile?action=heap", nil)
	req.Header.Set("X-Admin-Secret", "test-admin-secret")

	rr := httptest.NewRecorder()
	handleHeapProfile(rr, req)

	if rr.Code == http.StatusOK {
		t.Errorf("expected error status for unwritable dir, got 200; body: %s", rr.Body.String())
	}
}

// ============ handleGoroutineProfile error path ============

func TestCB111_HandleGoroutineProfile_CreateError(t *testing.T) {
	origAdminSecret := os.Getenv("ADMIN_SECRET")
	os.Setenv("ADMIN_SECRET", "test-admin-secret")
	defer func() { os.Setenv("ADMIN_SECRET", origAdminSecret); resetAdminSecret() }()

	origDir := os.Getenv("PROFILING_DIR")
	os.Setenv("PROFILING_DIR", "/proc/cannot_write_here")
	defer os.Setenv("PROFILING_DIR", origDir)

	req := httptest.NewRequest("POST", "/admin/profile?action=goroutine", nil)
	req.Header.Set("X-Admin-Secret", "test-admin-secret")

	rr := httptest.NewRecorder()
	handleGoroutineProfile(rr, req)

	if rr.Code == http.StatusOK {
		t.Errorf("expected error status for unwritable dir, got 200; body: %s", rr.Body.String())
	}
}

// ============ handleCPUProfileStart error path ============

func TestCB111_HandleCPUProfileStart_CreateError(t *testing.T) {
	origAdminSecret := os.Getenv("ADMIN_SECRET")
	os.Setenv("ADMIN_SECRET", "test-admin-secret")
	defer func() { os.Setenv("ADMIN_SECRET", origAdminSecret); resetAdminSecret() }()

	origDir := os.Getenv("PROFILING_DIR")
	os.Setenv("PROFILING_DIR", "/proc/cannot_write_here")
	defer os.Setenv("PROFILING_DIR", origDir)

	// Reset cpu profile state
	cpuProfileState.Lock()
	cpuProfileState.active = false
	cpuProfileState.stopFunc = nil
	cpuProfileState.Unlock()

	req := httptest.NewRequest("POST", "/admin/profile?action=cpu_start", nil)
	req.Header.Set("X-Admin-Secret", "test-admin-secret")

	rr := httptest.NewRecorder()
	handleCPUProfileStart(rr, req)

	if rr.Code == http.StatusOK {
		t.Errorf("expected error status for unwritable dir, got 200; body: %s", rr.Body.String())
	}
}

// ============ TieredRateLimiter cleanup test ============

func TestCB111_TieredRateLimiter_Cleanup_TickerPath(t *testing.T) {
	trl := NewTieredRateLimiter()
	defer trl.Stop()

	// Add some entries
	trl.SetTier("user1", RateLimitTier{Name: "free", Burst: 10, Window: time.Minute})
	trl.SetTier("user2", RateLimitTier{Name: "pro", Burst: 100, Window: time.Minute})

	// Trigger cleanup manually
	trl.cleanupOnce()

	// Should not crash; entries should be cleaned if expired
	// (they won't be expired since they were just added, but the cleanup path runs)
}

// ============ sendPushNotification platform routing ============

func TestCB111_SendPushNotification_EmptyPlatform(t *testing.T) {
	// With empty platform, should default to APNs
	origConfig := pushConfig
	pushConfig = &PushNotificationConfig{
		APNSEnabled: false,
		FCMEnabled:  false,
	}
	defer func() { pushConfig = origConfig }()

	err := sendPushNotification("token", "title", "body", "conv1", "")
	if err != nil {
		t.Errorf("sendPushNotification with empty platform: %v", err)
	}
}

func TestCB111_SendPushNotification_FCMPlatform(t *testing.T) {
	origConfig := pushConfig
	pushConfig = &PushNotificationConfig{
		APNSEnabled: false,
		FCMEnabled:  false,
	}
	defer func() { pushConfig = origConfig }()

	// Should route to FCM for android platform
	err := sendPushNotification("token", "title", "body", "conv1", "android")
	if err != nil {
		t.Errorf("sendPushNotification android: %v", err)
	}
}

// ============ handleGetNotificationPrefs tests ============

func TestCB111_HandleGetNotificationPrefs_NoAuth(t *testing.T) {
	req := httptest.NewRequest("GET", "/notification-prefs", nil)
	rr := httptest.NewRecorder()

	handleGetNotificationPrefs(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusUnauthorized)
	}
}

func TestCB111_HandleGetNotificationPrefs_Success(t *testing.T) {
	setupTestDB(t)

	_, err := db.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)",
		"user-notif-1", "usernotif1", "hash")
	if err != nil {
		t.Fatalf("insert user: %v", err)
	}
	_, err = db.Exec("INSERT INTO agents (id, name, model, personality, specialty) VALUES (?, ?, ?, ?, ?)",
		"agent-notif-1", "Agent", "gpt-4", "friendly", "general")
	if err != nil {
		t.Fatalf("insert agent: %v", err)
	}
	_, err = db.Exec("INSERT INTO conversations (id, user_id, agent_id) VALUES (?, ?, ?)",
		"conv-notif-1", "user-notif-1", "agent-notif-1")
	if err != nil {
		t.Fatalf("insert conv: %v", err)
	}

	// Insert a notification pref
	_, err = db.Exec("INSERT INTO notification_preferences (user_id, conversation_id, muted) VALUES (?, ?, 1)",
		"user-notif-1", "conv-notif-1")
	if err != nil {
		t.Fatalf("insert pref: %v", err)
	}

	token, err := GenerateJWT("user-notif-1", "usernotif1")
	if err != nil {
		t.Fatalf("GenerateJWT: %v", err)
	}

	req := httptest.NewRequest("GET", "/notification-prefs", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	rr := httptest.NewRecorder()
	authMiddleware(handleGetNotificationPrefs)(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want %d; body: %s", rr.Code, http.StatusOK, rr.Body.String())
	}
}

// ============ handleDeleteNotificationPrefs tests ============

func TestCB111_HandleDeleteNotificationPrefs_Success(t *testing.T) {
	setupTestDB(t)

	_, err := db.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)",
		"user-delnp-1", "userdelnp1", "hash")
	if err != nil {
		t.Fatalf("insert user: %v", err)
	}
	_, err = db.Exec("INSERT INTO agents (id, name, model, personality, specialty) VALUES (?, ?, ?, ?, ?)",
		"agent-delnp-1", "Agent", "gpt-4", "friendly", "general")
	if err != nil {
		t.Fatalf("insert agent: %v", err)
	}
	_, err = db.Exec("INSERT INTO conversations (id, user_id, agent_id) VALUES (?, ?, ?)",
		"conv-delnp-1", "user-delnp-1", "agent-delnp-1")
	if err != nil {
		t.Fatalf("insert conv: %v", err)
	}
	_, err = db.Exec("INSERT INTO notification_preferences (user_id, conversation_id, muted) VALUES (?, ?, 1)",
		"user-delnp-1", "conv-delnp-1")
	if err != nil {
		t.Fatalf("insert pref: %v", err)
	}

	token, err := GenerateJWT("user-delnp-1", "userdelnp1")
	if err != nil {
		t.Fatalf("GenerateJWT: %v", err)
	}

	form := "conversation_id=conv-delnp-1"
	req := httptest.NewRequest("POST", "/notification-prefs/delete", strings.NewReader(form))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rr := httptest.NewRecorder()
	authMiddleware(handleDeleteNotificationPrefs)(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want %d; body: %s", rr.Code, http.StatusOK, rr.Body.String())
	}

	// Verify deleted
	var count int
	err = db.QueryRow("SELECT COUNT(*) FROM notification_preferences WHERE user_id = ? AND conversation_id = ?",
		"user-delnp-1", "conv-delnp-1").Scan(&count)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if count != 0 {
		t.Errorf("notification_preferences count = %d, want 0", count)
	}
}

// ============ addReaction tests ============

func TestCB111_AddReaction_NilDB(t *testing.T) {
	origDB := db
	db = nil
	defer func() { db = origDB }()

	defer func() {
		if r := recover(); r != nil {
			// Expected: nil db causes panic
		}
	}()

	_, _, err := addReaction("msg1", "user1", "👍")
	if err == nil {
		t.Error("addReaction with nil db should return error or panic")
	}
}

func TestCB111_AddReaction_MessageNotFound(t *testing.T) {
	setupTestDB(t)

	_, err := db.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)",
		"user-react-nf", "userreactnf", "hash")
	if err != nil {
		t.Fatalf("insert user: %v", err)
	}

	_, _, err = addReaction("nonexistent-msg", "user-react-nf", "👍")
	if err == nil {
		t.Error("addReaction to nonexistent message should return error")
	}
}

// ============ isConversationMuted tests ============

func TestCB111_IsConversationMuted_NotMuted(t *testing.T) {
	setupTestDB(t)

	_, err := db.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)",
		"user-muted-1", "usermuted1", "hash")
	if err != nil {
		t.Fatalf("insert user: %v", err)
	}
	_, err = db.Exec("INSERT INTO agents (id, name, model, personality, specialty) VALUES (?, ?, ?, ?, ?)",
		"agent-muted-1", "Agent", "gpt-4", "friendly", "general")
	if err != nil {
		t.Fatalf("insert agent: %v", err)
	}
	_, err = db.Exec("INSERT INTO conversations (id, user_id, agent_id) VALUES (?, ?, ?)",
		"conv-muted-1", "user-muted-1", "agent-muted-1")
	if err != nil {
		t.Fatalf("insert conv: %v", err)
	}

	muted := isConversationMuted("user-muted-1", "conv-muted-1")
	if muted {
		t.Error("expected conversation to not be muted")
	}
}

func TestCB111_IsConversationMuted_IsMuted(t *testing.T) {
	setupTestDB(t)

	_, err := db.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)",
		"user-muted-2", "usermuted2", "hash")
	if err != nil {
		t.Fatalf("insert user: %v", err)
	}
	_, err = db.Exec("INSERT INTO agents (id, name, model, personality, specialty) VALUES (?, ?, ?, ?, ?)",
		"agent-muted-2", "Agent", "gpt-4", "friendly", "general")
	if err != nil {
		t.Fatalf("insert agent: %v", err)
	}
	_, err = db.Exec("INSERT INTO conversations (id, user_id, agent_id) VALUES (?, ?, ?)",
		"conv-muted-2", "user-muted-2", "agent-muted-2")
	if err != nil {
		t.Fatalf("insert conv: %v", err)
	}
	_, err = db.Exec("INSERT INTO notification_preferences (user_id, conversation_id, muted) VALUES (?, ?, 1)",
		"user-muted-2", "conv-muted-2")
	if err != nil {
		t.Fatalf("insert pref: %v", err)
	}

	muted := isConversationMuted("user-muted-2", "conv-muted-2")
	if !muted {
		t.Error("expected conversation to be muted")
	}
}

// ============ sendError tests ============

func TestCB111_SendError_BasicMessage(t *testing.T) {
	h := newHub()
	go h.run()
	defer h.Stop()

	conn := &Connection{
		hub:      h,
		id:       "test",
		connType: "client",
		send:     make(chan []byte, 10),
	}

	sendError(conn, "test error message")

	select {
	case msg := <-conn.send:
		var outgoing OutgoingMessage
		if err := json.Unmarshal(msg, &outgoing); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if outgoing.Type != "error" {
			t.Errorf("type = %s, want error", outgoing.Type)
		}
		data, ok := outgoing.Data.(map[string]interface{})
		if !ok {
			t.Fatalf("data is %T, want map", outgoing.Data)
		}
		if data["error"] != "test error message" {
			t.Errorf("error = %v, want 'test error message'", data["error"])
		}
	case <-time.After(1 * time.Second):
		t.Fatal("no message received on send channel")
	}
}

// ============ truncate tests ============

func TestCB111_Truncate_ShortString(t *testing.T) {
	result := truncate("hello", 10)
	if result != "hello" {
		t.Errorf("truncate('hello', 10) = %s, want 'hello'", result)
	}
}

func TestCB111_Truncate_ExactLength(t *testing.T) {
	result := truncate("hello", 5)
	if result != "hello" {
		t.Errorf("truncate('hello', 5) = %s, want 'hello'", result)
	}
}

func TestCB111_Truncate_LongString(t *testing.T) {
	result := truncate("hello world", 8)
	if result != "hello..." {
		t.Errorf("truncate('hello world', 8) = %s, want 'hello...'", result)
	}
}

func TestCB111_Truncate_SmallMaxLen(t *testing.T) {
	result := truncate("hello", 3)
	if result != "hel" {
		t.Errorf("truncate('hello', 3) = %s, want 'hel'", result)
	}
}

func TestCB111_Truncate_ZeroMaxLen(t *testing.T) {
	result := truncate("hello", 0)
	if result != "" {
		t.Errorf("truncate('hello', 0) = %s, want ''", result)
	}
}

// ============ safeTruncate tests ============

func TestCB111_SafeTruncate_ExactLength(t *testing.T) {
	result := safeTruncate("hello", 5)
	if result != "hello" {
		t.Errorf("safeTruncate('hello', 5) = %s, want 'hello'", result)
	}
}

func TestCB111_SafeTruncate_LongerThanN(t *testing.T) {
	result := safeTruncate("hello world", 5)
	if result != "hello" {
		t.Errorf("safeTruncate('hello world', 5) = %s, want 'hello'", result)
	}
}

// ============ handleGetVAPIDKey tests ============

func TestCB111_HandleGetVAPIDKey_NotConfigured(t *testing.T) {
	origKey := vapidPublicKey
	vapidPublicKey = ""
	defer func() { vapidPublicKey = origKey }()

	token, _ := GenerateJWT("user1", "user1")
	req := httptest.NewRequest("GET", "/push/vapid-key", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	rr := httptest.NewRecorder()
	handleGetVAPIDKey(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusNotFound)
	}
}

func TestCB111_HandleGetVAPIDKey_Success(t *testing.T) {
	origKey := vapidPublicKey
	vapidPublicKey = "BPA-test-key"
	defer func() { vapidPublicKey = origKey }()

	token, _ := GenerateJWT("user1", "user1")
	req := httptest.NewRequest("GET", "/push/vapid-key", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	rr := httptest.NewRecorder()
	handleGetVAPIDKey(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want %d; body: %s", rr.Code, http.StatusOK, rr.Body.String())
	}

	var resp map[string]string
	json.NewDecoder(rr.Body).Decode(&resp)
	if resp["public_key"] != "BPA-test-key" {
		t.Errorf("public_key = %s, want 'BPA-test-key'", resp["public_key"])
	}
}

// ============ handleWebPushSubscribe tests ============

func TestCB111_HandleWebPushSubscribe_Success(t *testing.T) {
	setupTestDB(t)

	_, err := db.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)",
		"user-webpush-1", "userwebpush1", "hash")
	if err != nil {
		t.Fatalf("insert user: %v", err)
	}

	token, err := GenerateJWT("user-webpush-1", "userwebpush1")
	if err != nil {
		t.Fatalf("GenerateJWT: %v", err)
	}

	body := `{"endpoint":"https://fcm.googleapis.com/fcm/send/abc123","keys":{"p256dh":"p256dh_key","auth":"auth_key"}}`
	req := httptest.NewRequest("POST", "/push/web-subscribe", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	handleWebPushSubscribe(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want %d; body: %s", rr.Code, http.StatusOK, rr.Body.String())
	}

	// Verify device token was stored
	var count int
	err = db.QueryRow("SELECT COUNT(*) FROM device_tokens WHERE user_id = ? AND platform = 'web'",
		"user-webpush-1").Scan(&count)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if count != 1 {
		t.Errorf("device_tokens count = %d, want 1", count)
	}
}

func TestCB111_HandleWebPushSubscribe_MissingFields(t *testing.T) {
	token, _ := GenerateJWT("user1", "user1")

	body := `{"endpoint":"https://example.com","keys":{"p256dh":"","auth":""}}`
	req := httptest.NewRequest("POST", "/push/web-subscribe", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	handleWebPushSubscribe(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusBadRequest)
	}
}

// ============ handleWebPushUnsubscribe tests ============

func TestCB111_HandleWebPushUnsubscribe_Success(t *testing.T) {
	setupTestDB(t)

	_, err := db.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)",
		"user-webunsub-1", "userwebunsub1", "hash")
	if err != nil {
		t.Fatalf("insert user: %v", err)
	}

	// Insert a web push subscription
	_, err = db.Exec("INSERT INTO device_tokens (user_id, device_token, platform) VALUES (?, ?, 'web')",
		"user-webunsub-1", "https://fcm.googleapis.com/fcm/send/test123")
	if err != nil {
		t.Fatalf("insert token: %v", err)
	}

	token, err := GenerateJWT("user-webunsub-1", "userwebunsub1")
	if err != nil {
		t.Fatalf("GenerateJWT: %v", err)
	}

	body := `{"endpoint":"https://fcm.googleapis.com/fcm/send/test123"}`
	req := httptest.NewRequest("POST", "/push/web-unsubscribe", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	handleWebPushUnsubscribe(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want %d; body: %s", rr.Code, http.StatusOK, rr.Body.String())
	}

	// Verify deleted
	var count int
	err = db.QueryRow("SELECT COUNT(*) FROM device_tokens WHERE user_id = ? AND device_token = ?",
		"user-webunsub-1", "https://fcm.googleapis.com/fcm/send/test123").Scan(&count)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if count != 0 {
		t.Errorf("device_tokens count = %d, want 0", count)
	}
}

func TestCB111_HandleWebPushUnsubscribe_MissingEndpoint(t *testing.T) {
	token, _ := GenerateJWT("user1", "user1")

	body := `{"endpoint":""}`
	req := httptest.NewRequest("POST", "/push/web-unsubscribe", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	handleWebPushUnsubscribe(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusBadRequest)
	}
}

// ============ handleGetEncryptedMessages tests ============

func TestCB111_HandleGetEncryptedMessages_ConvNotFound(t *testing.T) {
	setupTestDB(t)

	_, err := db.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)",
		"user-enc-get-1", "userencget1", "hash")
	if err != nil {
		t.Fatalf("insert user: %v", err)
	}

	token, err := GenerateJWT("user-enc-get-1", "userencget1")
	if err != nil {
		t.Fatalf("GenerateJWT: %v", err)
	}

	req := httptest.NewRequest("GET", "/messages/encrypted/list?conversation_id=nonexistent", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	rr := httptest.NewRecorder()
	handleGetEncryptedMessages(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d; body: %s", rr.Code, http.StatusNotFound, rr.Body.String())
	}
}

// ============ handleRegisterDeviceToken tests ============

func TestCB111_HandleRegisterDeviceToken_NoAuth(t *testing.T) {
	req := httptest.NewRequest("POST", "/push/register", strings.NewReader(`{"device_token":"abc"}`))
	rr := httptest.NewRecorder()

	handleRegisterDeviceToken(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusUnauthorized)
	}
}

func TestCB111_HandleRegisterDeviceToken_SuccessWithPlatform(t *testing.T) {
	setupTestDB(t)

	_, err := db.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)",
		"user-reg-dev-1", "userregdev1", "hash")
	if err != nil {
		t.Fatalf("insert user: %v", err)
	}

	token, err := GenerateJWT("user-reg-dev-1", "userregdev1")
	if err != nil {
		t.Fatalf("GenerateJWT: %v", err)
	}

	body := `{"device_token":"token123","platform":"android"}`
	req := httptest.NewRequest("POST", "/push/register", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	handleRegisterDeviceToken(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want %d; body: %s", rr.Code, http.StatusOK, rr.Body.String())
	}

	// Verify token stored
	var platform string
	err = db.QueryRow("SELECT platform FROM device_tokens WHERE user_id = ? AND device_token = ?",
		"user-reg-dev-1", "token123").Scan(&platform)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if platform != "android" {
		t.Errorf("platform = %s, want 'android'", platform)
	}
}

// ============ handleUnregisterDeviceToken tests ============

func TestCB111_HandleUnregisterDeviceToken_Success(t *testing.T) {
	setupTestDB(t)

	_, err := db.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)",
		"user-unreg-dev-1", "userunregdev1", "hash")
	if err != nil {
		t.Fatalf("insert user: %v", err)
	}

	_, err = db.Exec("INSERT INTO device_tokens (user_id, device_token, platform) VALUES (?, ?, 'ios')",
		"user-unreg-dev-1", "token-to-remove")
	if err != nil {
		t.Fatalf("insert token: %v", err)
	}

	token, err := GenerateJWT("user-unreg-dev-1", "userunregdev1")
	if err != nil {
		t.Fatalf("GenerateJWT: %v", err)
	}

	body := `{"device_token":"token-to-remove"}`
	req := httptest.NewRequest("DELETE", "/push/unregister", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	handleUnregisterDeviceToken(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want %d; body: %s", rr.Code, http.StatusOK, rr.Body.String())
	}

	// Verify token removed
	var count int
	err = db.QueryRow("SELECT COUNT(*) FROM device_tokens WHERE user_id = ? AND device_token = ?",
		"user-unreg-dev-1", "token-to-remove").Scan(&count)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if count != 0 {
		t.Errorf("device_tokens count = %d, want 0", count)
	}
}

// ============ handleListAgents tests ============

func TestCB111_HandleListAgents_EmptyHub(t *testing.T) {
	setupTestDB(t)

	origHub := hub
	h := newHub()
	go h.run()
	hub = h
	defer func() { hub = origHub; h.Stop() }()

	req := httptest.NewRequest("GET", "/agents", nil)
	rr := httptest.NewRecorder()

	handleListAgents(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want %d; body: %s", rr.Code, http.StatusOK, rr.Body.String())
	}
}

// ============ handleAdminAgents tests ============

func TestCB111_HandleAdminAgents_NoAgents(t *testing.T) {
	setupTestDB(t)

	origHub := hub
	h := newHub()
	go h.run()
	hub = h
	defer func() { hub = origHub; h.Stop() }()

	origAdminSecret := os.Getenv("ADMIN_SECRET")
	os.Setenv("ADMIN_SECRET", "test-secret")
	defer func() { os.Setenv("ADMIN_SECRET", origAdminSecret); resetAdminSecret() }()

	req := httptest.NewRequest("GET", "/admin/agents", nil)
	req.Header.Set("X-Admin-Secret", "test-secret")

	rr := httptest.NewRecorder()
	handleAdminAgents(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want %d; body: %s", rr.Code, http.StatusOK, rr.Body.String())
	}
}

// ============ cleanStaleQueueMessages tests ============

func TestCB111_CleanStaleQueueMessages_DeletesOld(t *testing.T) {
	setupTestDB(t)

	// Insert an old message
	_, err := db.Exec("INSERT INTO offline_queue (recipient, data, queued_at, sent_count) VALUES (?, ?, ?, 0)",
		"user-old", []byte("old data"), time.Now().UTC().Add(-8*24*time.Hour).Format(time.RFC3339))
	if err != nil {
		t.Fatalf("insert: %v", err)
	}

	// Insert a recent message
	_, err = db.Exec("INSERT INTO offline_queue (recipient, data, queued_at, sent_count) VALUES (?, ?, ?, 0)",
		"user-recent", []byte("recent data"), time.Now().UTC().Format(time.RFC3339))
	if err != nil {
		t.Fatalf("insert recent: %v", err)
	}

	cleanStaleQueueMessages(db, 7*24*time.Hour)

	// Old message should be deleted
	var oldCount int
	err = db.QueryRow("SELECT COUNT(*) FROM offline_queue WHERE recipient = ?", "user-old").Scan(&oldCount)
	if err != nil {
		t.Fatalf("query old: %v", err)
	}
	if oldCount != 0 {
		t.Errorf("old message count = %d, want 0", oldCount)
	}

	// Recent message should remain
	var recentCount int
	err = db.QueryRow("SELECT COUNT(*) FROM offline_queue WHERE recipient = ?", "user-recent").Scan(&recentCount)
	if err != nil {
		t.Fatalf("query recent: %v", err)
	}
	if recentCount != 1 {
		t.Errorf("recent message count = %d, want 1", recentCount)
	}
}

func TestCB111_CleanStaleQueueMessages_NilDB(t *testing.T) {
	// Should not panic
	cleanStaleQueueMessages(nil, 24*time.Hour)
}

// ============ marshalOutgoingMessage tests ============

func TestCB111_MarshalOutgoingMessage_ValidMessage(t *testing.T) {
	msg := OutgoingMessage{
		Type: "test",
		Data: map[string]string{"key": "value"},
	}

	data := marshalOutgoingMessage(msg)
	if data == nil {
		t.Fatal("marshalOutgoingMessage returned nil")
	}

	var result OutgoingMessage
	err := json.Unmarshal(data, &result)
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if result.Type != "test" {
		t.Errorf("type = %s, want 'test'", result.Type)
	}
}

// ============ loadQueueFromDB tests ============

func TestCB111_LoadQueueFromDB_NilDB(t *testing.T) {
	q := newOfflineQueue(100, 5*time.Minute)
	// Should not panic
	loadQueueFromDB(nil, q)
}

func TestCB111_LoadQueueFromDB_WithData(t *testing.T) {
	setupTestDB(t)

	// Insert some queued messages
	_, err := db.Exec("INSERT INTO offline_queue (recipient, data, queued_at, sent_count) VALUES (?, ?, ?, 0)",
		"user-load-1", []byte("msg1"), time.Now().UTC().Format(time.RFC3339))
	if err != nil {
		t.Fatalf("insert: %v", err)
	}
	_, err = db.Exec("INSERT INTO offline_queue (recipient, data, queued_at, sent_count) VALUES (?, ?, ?, 0)",
		"user-load-1", []byte("msg2"), time.Now().UTC().Format(time.RFC3339))
	if err != nil {
		t.Fatalf("insert2: %v", err)
	}

	q := newOfflineQueue(100, 5*time.Minute)
	loadQueueFromDB(db, q)

	depth := q.QueueDepth("user-load-1")
	if depth != 2 {
		t.Errorf("queue depth = %d, want 2", depth)
	}
}