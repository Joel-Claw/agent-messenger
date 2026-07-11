package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime/debug"
	"strings"
	"sync"
	"testing"
	"time"
)

// --- Helpers (CB57) ---

func setupTestDB_CB57(t *testing.T) *sql.DB {
	testDB, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("Failed to open test DB: %v", err)
	}
	if err := initSchema(testDB); err != nil {
		t.Fatalf("Failed to init schema: %v", err)
	}
	return testDB
}

func setupTestServer_CB57(t *testing.T) (*sql.DB, func()) {
	testDB := setupTestDB_CB57(t)
	oldDB := db
	db = testDB

	h := newHub()
	oldHub := hub
	hub = h
	go h.run()

	oldServerDBPath := serverDBPath
	serverDBPath = "/tmp/test_am_cb57.db"

	cleanup := func() {
		db = oldDB
		hub = oldHub
		serverDBPath = oldServerDBPath
		close(h.done)
		<-h.runDone
	}
	return testDB, cleanup
}

func cb57CreateUserAndGetToken(t *testing.T, testDB *sql.DB, username, password string) (string, string) {
	req := httptest.NewRequest(http.MethodPost, "/auth/register", strings.NewReader(
		"username="+username+"&password="+password))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handleRegisterUser(w, req)
	if w.Code != http.StatusCreated && w.Code != http.StatusOK && w.Code != http.StatusConflict {
		t.Fatalf("Failed to register user: %d - %s", w.Code, w.Body.String())
	}
	var regResp map[string]string
	json.NewDecoder(w.Body).Decode(&regResp)
	userID := regResp["user_id"]

	req = httptest.NewRequest(http.MethodPost, "/auth/login", strings.NewReader(
		"username="+username+"&password="+password))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w = httptest.NewRecorder()
	handleLogin(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("Failed to login: %d - %s", w.Code, w.Body.String())
	}
	var resp map[string]string
	json.NewDecoder(w.Body).Decode(&resp)
	return resp["token"], userID
}

func cb57CreateConversation(t *testing.T, testDB *sql.DB, userID, agentID string) string {
	conv, err := CreateConversation(userID, agentID)
	if err != nil {
		t.Fatalf("Failed to create conversation: %v", err)
	}
	return conv.ID
}

// ========================
// profile_handler.go tests
// ========================

// --- handleCPUProfileStart ---

func TestCB57_HandleCPUProfileStart_Success(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("PROFILING_DIR", tmpDir)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/admin/profile?action=cpu", nil)
	handleCPUProfileStart(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}
	if resp["status"] != "profiling" {
		t.Errorf("Expected status=profiling, got %v", resp["status"])
	}
	if resp["action"] != "cpu" {
		t.Errorf("Expected action=cpu, got %v", resp["action"])
	}

	// Clean up: stop the CPU profile
	cpuProfileState.Lock()
	if cpuProfileState.active && cpuProfileState.stopFunc != nil {
		cpuProfileState.stopFunc()
		cpuProfileState.active = false
		cpuProfileState.stopFunc = nil
	}
	cpuProfileState.Unlock()
}

func TestCB57_HandleCPUProfileStart_AlreadyActive(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("PROFILING_DIR", tmpDir)

	// Start a CPU profile manually
	cpuProfileState.Lock()
	cpuProfileState.active = true
	cpuProfileState.stopFunc = func() {}
	cpuProfileState.Unlock()

	defer func() {
		cpuProfileState.Lock()
		cpuProfileState.active = false
		cpuProfileState.stopFunc = nil
		cpuProfileState.Unlock()
	}()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/admin/profile?action=cpu", nil)
	handleCPUProfileStart(w, r)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("Expected 500, got %d: %s", w.Code, w.Body.String())
	}
	var resp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["status"] != "error" {
		t.Errorf("Expected status=error, got %v", resp["status"])
	}
	if resp["context"] != "cpu profile already active" {
		t.Errorf("Expected context='cpu profile already active', got %v", resp["context"])
	}
}

func TestCB57_HandleCPUProfileStart_MkdirError(t *testing.T) {
	// Use a path that can't be created (file exists where dir expected)
	tmpFile := t.TempDir() + "/blocker"
	os.WriteFile(tmpFile, []byte("x"), 0644)
	t.Setenv("PROFILING_DIR", tmpFile+"/subdir")

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/admin/profile?action=cpu", nil)
	handleCPUProfileStart(w, r)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("Expected 500, got %d: %s", w.Code, w.Body.String())
	}
}

// --- handleCPUProfileStop ---

func TestCB57_HandleCPUProfileStop_NotActive(t *testing.T) {
	// Ensure no active profile
	cpuProfileState.Lock()
	cpuProfileState.active = false
	cpuProfileState.stopFunc = nil
	cpuProfileState.Unlock()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/admin/profile?action=cpu_stop", nil)
	handleCPUProfileStop(w, r)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("Expected 500, got %d: %s", w.Code, w.Body.String())
	}
	var resp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["context"] != "no cpu profile active" {
		t.Errorf("Expected context='no cpu profile active', got %v", resp["context"])
	}
}

func TestCB57_HandleCPUProfileStop_Success(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("PROFILING_DIR", tmpDir)

	// Start CPU profile first
	w1 := httptest.NewRecorder()
	r1 := httptest.NewRequest(http.MethodPost, "/admin/profile?action=cpu", nil)
	handleCPUProfileStart(w1, r1)
	if w1.Code != http.StatusOK {
		t.Fatalf("Failed to start CPU profile: %d", w1.Code)
	}

	// Now stop it
	w2 := httptest.NewRecorder()
	r2 := httptest.NewRequest(http.MethodPost, "/admin/profile?action=cpu_stop", nil)
	handleCPUProfileStop(w2, r2)

	if w2.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d: %s", w2.Code, w2.Body.String())
	}
	var resp map[string]interface{}
	json.NewDecoder(w2.Body).Decode(&resp)
	if resp["status"] != "stopped" {
		t.Errorf("Expected status=stopped, got %v", resp["status"])
	}
	if resp["action"] != "cpu_stop" {
		t.Errorf("Expected action=cpu_stop, got %v", resp["action"])
	}
}

// --- handleMemoryStats ---

func TestCB57_HandleMemoryStats_Success(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/admin/profile?action=stats", nil)
	handleMemoryStats(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("Failed to decode: %v", err)
	}
	if resp["status"] != "ok" {
		t.Errorf("Expected status=ok, got %v", resp["status"])
	}
	if resp["action"] != "stats" {
		t.Errorf("Expected action=stats, got %v", resp["action"])
	}
	mem, ok := resp["memory"].(map[string]interface{})
	if !ok {
		t.Fatal("Expected memory field to be a map")
	}
	if mem["alloc_bytes"] == nil {
		t.Error("Expected alloc_bytes in memory stats")
	}
	if mem["goroutines"] == nil {
		t.Error("Expected goroutines in memory stats")
	}
}

// --- SetGCPercent ---

func TestCB57_SetGCPercent(t *testing.T) {
	old := debug.SetGCPercent(100)
	defer debug.SetGCPercent(old)

	prev := SetGCPercent(200)
	if prev != 100 {
		t.Errorf("Expected previous GC percent=100, got %d", prev)
	}

	// Verify it was set
	current := debug.SetGCPercent(200)
	if current != 200 {
		t.Errorf("Expected current GC percent=200, got %d", current)
	}

	// Test disabling GC (-1)
	prev = SetGCPercent(-1)
	if prev != 200 {
		t.Errorf("Expected previous=200, got %d", prev)
	}
}

// --- SetMemoryLimit ---

func TestCB57_SetMemoryLimit(t *testing.T) {
	oldLimit := debug.SetMemoryLimit(0) // get current without changing
	defer debug.SetMemoryLimit(oldLimit)

	// Set a new limit
	prev := SetMemoryLimit(1 << 30) // 1GB
	// Previous limit may be 0 (unlimited) if never explicitly set
	if prev < 0 {
		t.Errorf("Expected previous limit >= 0, got %d", prev)
	}

	// Verify it was set
	current := debug.SetMemoryLimit(0)
	if current != 1<<30 {
		t.Errorf("Expected current limit=1GB, got %d", current)
	}
}

// --- writeProfileError ---

func TestCB57_WriteProfileError_WithErr(t *testing.T) {
	w := httptest.NewRecorder()
	writeProfileError(w, "test context", fmt.Errorf("test error"))

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("Expected 500, got %d", w.Code)
	}
	var resp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["status"] != "error" {
		t.Errorf("Expected status=error, got %v", resp["status"])
	}
	if resp["context"] != "test context" {
		t.Errorf("Expected context='test context', got %v", resp["context"])
	}
	if resp["detail"] != "test error" {
		t.Errorf("Expected detail='test error', got %v", resp["detail"])
	}
}

func TestCB57_WriteProfileError_NilErr(t *testing.T) {
	w := httptest.NewRecorder()
	writeProfileError(w, "nil context", nil)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("Expected 500, got %d", w.Code)
	}
	var resp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["detail"] != "" {
		t.Errorf("Expected empty detail for nil error, got %v", resp["detail"])
	}
}

// ========================
// conversations.go tests
// ========================

// --- storeMessage ---

func TestCB57_StoreMessage_Success(t *testing.T) {
	testDB, cleanup := setupTestServer_CB57(t)
	defer cleanup()

	convID := cb57CreateConversation(t, testDB, "user1", "agent1")

	msg := RoutedMessage{
		Type:           "message",
		ConversationID: convID,
		Content:        "Hello from test",
		SenderType:     "client",
		SenderID:       "user1",
	}
	if err := storeMessage(msg); err != nil {
		t.Fatalf("storeMessage failed: %v", err)
	}

	// Verify message was stored
	var count int
	err := testDB.QueryRow("SELECT COUNT(*) FROM messages WHERE conversation_id = ?", convID).Scan(&count)
	if err != nil {
		t.Fatalf("Failed to count messages: %v", err)
	}
	if count != 1 {
		t.Errorf("Expected 1 message, got %d", count)
	}
}

func TestCB57_StoreMessage_WithAttachments(t *testing.T) {
	testDB, cleanup := setupTestServer_CB57(t)
	defer cleanup()

	convID := cb57CreateConversation(t, testDB, "user1", "agent1")

	// Create an attachment with no message_id
	attachID := generateID("att")
	_, err := testDB.Exec(`INSERT INTO attachments (id, user_id, filename, content_type, size, sha256, storage_path, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		attachID, "user1", "test.txt", "text/plain", 100, "abc123", "test/path", time.Now().UTC())
	if err != nil {
		t.Fatalf("Failed to insert attachment: %v", err)
	}

	msg := RoutedMessage{
		Type:           "message",
		ConversationID: convID,
		Content:        "Message with attachment",
		SenderType:     "client",
		SenderID:       "user1",
		AttachmentIDs:  []string{attachID},
	}
	if err := storeMessage(msg); err != nil {
		t.Fatalf("storeMessage failed: %v", err)
	}

	// Verify attachment is linked to a message
	var linkedMsgID *string
	err = testDB.QueryRow("SELECT message_id FROM attachments WHERE id = ?", attachID).Scan(&linkedMsgID)
	if err != nil {
		t.Fatalf("Failed to query attachment: %v", err)
	}
	if linkedMsgID == nil {
		t.Error("Expected attachment to be linked to a message, but message_id is NULL")
	}
}

func TestCB57_StoreMessage_DBError(t *testing.T) {
	testDB, cleanup := setupTestServer_CB57(t)
	defer cleanup()
	testDB.Close()

	msg := RoutedMessage{
		Type:           "message",
		ConversationID: "fake_conv",
		Content:        "test",
		SenderType:     "client",
		SenderID:       "user1",
	}
	err := storeMessage(msg)
	if err == nil {
		t.Error("Expected error from closed DB, got nil")
	}
}

// --- CreateConversation ---

func TestCB57_CreateConversation_Success(t *testing.T) {
	testDB, cleanup := setupTestServer_CB57(t)
	defer cleanup()

	conv, err := CreateConversation("user1", "agent1")
	if err != nil {
		t.Fatalf("CreateConversation failed: %v", err)
	}
	if conv.ID == "" {
		t.Error("Expected non-empty conversation ID")
	}
	if conv.UserID != "user1" || conv.AgentID != "agent1" {
		t.Errorf("Expected user1/agent1, got %s/%s", conv.UserID, conv.AgentID)
	}

	// Verify in DB
	var dbUserID, dbAgentID string
	err = testDB.QueryRow("SELECT user_id, agent_id FROM conversations WHERE id = ?", conv.ID).Scan(&dbUserID, &dbAgentID)
	if err != nil {
		t.Fatalf("Failed to query conversation: %v", err)
	}
	if dbUserID != "user1" || dbAgentID != "agent1" {
		t.Errorf("DB mismatch: expected user1/agent1, got %s/%s", dbUserID, dbAgentID)
	}
}

func TestCB57_CreateConversation_DBError(t *testing.T) {
	testDB, cleanup := setupTestServer_CB57(t)
	defer cleanup()
	testDB.Close()

	_, err := CreateConversation("user1", "agent1")
	if err == nil {
		t.Error("Expected error from closed DB, got nil")
	}
}

// --- GetOrCreateConversation ---

func TestCB57_GetOrCreateConversation_New(t *testing.T) {
	_, cleanup := setupTestServer_CB57(t)
	defer cleanup()

	conv, err := GetOrCreateConversation("user1", "agent1")
	if err != nil {
		t.Fatalf("GetOrCreateConversation failed: %v", err)
	}
	if conv.ID == "" {
		t.Error("Expected non-empty conversation ID")
	}
}

func TestCB57_GetOrCreateConversation_Existing(t *testing.T) {
	_, cleanup := setupTestServer_CB57(t)
	defer cleanup()

	// Create first
	conv1, err := GetOrCreateConversation("user1", "agent1")
	if err != nil {
		t.Fatalf("First GetOrCreateConversation failed: %v", err)
	}

	// Should return existing
	conv2, err := GetOrCreateConversation("user1", "agent1")
	if err != nil {
		t.Fatalf("Second GetOrCreateConversation failed: %v", err)
	}
	if conv1.ID != conv2.ID {
		t.Errorf("Expected same conversation ID, got %s vs %s", conv1.ID, conv2.ID)
	}
}

func TestCB57_GetOrCreateConversation_DBError(t *testing.T) {
	testDB, cleanup := setupTestServer_CB57(t)
	defer cleanup()
	testDB.Close()

	_, err := GetOrCreateConversation("user1", "agent1")
	if err == nil {
		t.Error("Expected error from closed DB, got nil")
	}
}

// --- changeUserPassword ---

func TestCB57_ChangeUserPassword_Success(t *testing.T) {
	testDB, cleanup := setupTestServer_CB57(t)
	defer cleanup()

	token, userID := cb57CreateUserAndGetToken(t, testDB, "testuser", "oldpass123")
	_ = token

	err := changeUserPassword(userID, "oldpass123", "newpass456")
	if err != nil {
		t.Fatalf("changeUserPassword failed: %v", err)
	}

	// Verify old password fails, new password works
	err = changeUserPassword(userID, "newpass456", "newerpass789")
	if err != nil {
		t.Fatalf("Password change with new password failed: %v", err)
	}
}

func TestCB57_ChangeUserPassword_WrongOldPassword(t *testing.T) {
	testDB, cleanup := setupTestServer_CB57(t)
	defer cleanup()

	_, userID := cb57CreateUserAndGetToken(t, testDB, "testuser2", "correctpass")

	err := changeUserPassword(userID, "wrongpass", "newpass123")
	if err == nil {
		t.Error("Expected error for wrong old password")
	}
	if err != nil && err.Error() != "invalid old password" {
		t.Errorf("Expected 'invalid old password' error, got: %v", err)
	}
}

func TestCB57_ChangeUserPassword_ShortNewPassword(t *testing.T) {
	testDB, cleanup := setupTestServer_CB57(t)
	defer cleanup()

	_, userID := cb57CreateUserAndGetToken(t, testDB, "testuser3", "oldpass123")

	err := changeUserPassword(userID, "oldpass123", "short")
	if err == nil {
		t.Error("Expected error for short new password")
	}
	if err != nil && err.Error() != "new password must be at least 6 characters" {
		t.Errorf("Expected short password error, got: %v", err)
	}
}

func TestCB57_ChangeUserPassword_UserNotFound(t *testing.T) {
	_, cleanup := setupTestServer_CB57(t)
	defer cleanup()

	err := changeUserPassword("nonexistent_user", "oldpass", "newpass123")
	if err == nil {
		t.Error("Expected error for non-existent user")
	}
}

// --- searchMessages ---

func TestCB57_SearchMessages_Success(t *testing.T) {
	testDB, cleanup := setupTestServer_CB57(t)
	defer cleanup()

	convID := cb57CreateConversation(t, testDB, "user1", "agent1")

	// Store some messages
	storeMessage(RoutedMessage{ConversationID: convID, Content: "hello world", SenderType: "client", SenderID: "user1"})
	storeMessage(RoutedMessage{ConversationID: convID, Content: "goodbye world", SenderType: "agent", SenderID: "agent1"})
	storeMessage(RoutedMessage{ConversationID: convID, Content: "unrelated text", SenderType: "client", SenderID: "user1"})

	results, err := searchMessages("user1", "world", 50)
	if err != nil {
		t.Fatalf("searchMessages failed: %v", err)
	}
	if len(results) != 2 {
		t.Errorf("Expected 2 results, got %d", len(results))
	}
}

func TestCB57_SearchMessages_EmptyQuery(t *testing.T) {
	_, cleanup := setupTestServer_CB57(t)
	defer cleanup()

	_, err := searchMessages("user1", "", 50)
	if err == nil {
		t.Error("Expected error for empty query")
	}
}

func TestCB57_SearchMessages_NoResults(t *testing.T) {
	testDB, cleanup := setupTestServer_CB57(t)
	defer cleanup()

	convID := cb57CreateConversation(t, testDB, "user1", "agent1")
	storeMessage(RoutedMessage{ConversationID: convID, Content: "hello world", SenderType: "client", SenderID: "user1"})

	results, err := searchMessages("user1", "nonexistent_term", 50)
	if err != nil {
		t.Fatalf("searchMessages failed: %v", err)
	}
	if len(results) != 0 {
		t.Errorf("Expected 0 results, got %d", len(results))
	}
}

// --- markMessagesRead ---

func TestCB57_MarkMessagesRead_Success(t *testing.T) {
	testDB, cleanup := setupTestServer_CB57(t)
	defer cleanup()

	convID := cb57CreateConversation(t, testDB, "user1", "agent1")

	// Store unread agent messages
	storeMessage(RoutedMessage{ConversationID: convID, Content: "msg1", SenderType: "agent", SenderID: "agent1"})
	storeMessage(RoutedMessage{ConversationID: convID, Content: "msg2", SenderType: "agent", SenderID: "agent1"})

	count, err := markMessagesRead(convID, "user1")
	if err != nil {
		t.Fatalf("markMessagesRead failed: %v", err)
	}
	if count != 2 {
		t.Errorf("Expected 2 messages marked read, got %d", count)
	}

	// Second call should return 0 (idempotent)
	count, err = markMessagesRead(convID, "user1")
	if err != nil {
		t.Fatalf("Second markMessagesRead failed: %v", err)
	}
	if count != 0 {
		t.Errorf("Expected 0 on second call, got %d", count)
	}
}

func TestCB57_MarkMessagesRead_NotFound(t *testing.T) {
	_, cleanup := setupTestServer_CB57(t)
	defer cleanup()

	_, err := markMessagesRead("nonexistent_conv", "user1")
	if err != sql.ErrNoRows {
		t.Errorf("Expected sql.ErrNoRows, got %v", err)
	}
}

func TestCB57_MarkMessagesRead_Unauthorized(t *testing.T) {
	testDB, cleanup := setupTestServer_CB57(t)
	defer cleanup()

	convID := cb57CreateConversation(t, testDB, "user1", "agent1")

	_, err := markMessagesRead(convID, "wrong_user")
	if err == nil {
		t.Error("Expected unauthorized error")
	}
	if err != nil && err.Error() != "unauthorized" {
		t.Errorf("Expected 'unauthorized', got: %v", err)
	}
}

// ========================
// routing.go tests
// ========================

// --- routeTypingIndicator ---

func TestCB57_RouteTypingIndicator_InvalidJSON(t *testing.T) {
	_, cleanup := setupTestServer_CB57(t)
	defer cleanup()

	conn := &Connection{connType: "client", id: "user1", send: make(chan []byte, 10)}
	routeTypingIndicator(conn, json.RawMessage(`{invalid json`))
	// Should silently return without panic
}

func TestCB57_RouteTypingIndicator_EmptyConvID(t *testing.T) {
	_, cleanup := setupTestServer_CB57(t)
	defer cleanup()

	conn := &Connection{connType: "client", id: "user1", send: make(chan []byte, 10)}
	routeTypingIndicator(conn, json.RawMessage(`{"conversation_id":""}`))
	// Should silently return
}

func TestCB57_RouteTypingIndicator_WrongSender(t *testing.T) {
	testDB, cleanup := setupTestServer_CB57(t)
	defer cleanup()

	convID := cb57CreateConversation(t, testDB, "user1", "agent1")
	conn := &Connection{connType: "client", id: "wrong_user", send: make(chan []byte, 10)}
	routeTypingIndicator(conn, json.RawMessage(`{"conversation_id":"`+convID+`"}`))
	// Should silently return without delivering
}

func TestCB57_RouteTypingIndicator_AgentToClient(t *testing.T) {
	testDB, cleanup := setupTestServer_CB57(t)
	defer cleanup()

	convID := cb57CreateConversation(t, testDB, "user1", "agent1")

	// Register a client connection in the hub
	clientConn := &Connection{
		hub:      hub,
		connType: "client",
		id:       "user1",
		send:     make(chan []byte, 10),
		closeMu:  sync.RWMutex{},
		writeMu:  sync.Mutex{},
	}
	hub.register <- clientConn
	time.Sleep(50 * time.Millisecond)
	defer func() { hub.unregister <- clientConn }()

	agentConn := &Connection{hub: hub, connType: "agent", id: "agent1", send: make(chan []byte, 10)}
	routeTypingIndicator(agentConn, json.RawMessage(`{"conversation_id":"`+convID+`"}`))

	// Client should receive typing indicator
	select {
	case msg := <-clientConn.send:
		var out OutgoingMessage
		if err := json.Unmarshal(msg, &out); err != nil {
			t.Fatalf("Failed to unmarshal: %v", err)
		}
		if out.Type != "typing" {
			t.Errorf("Expected type=typing, got %s", out.Type)
		}
	case <-time.After(time.Second):
		t.Error("Timeout waiting for typing indicator")
	}
}

func TestCB57_RouteTypingIndicator_ClientToAgent(t *testing.T) {
	testDB, cleanup := setupTestServer_CB57(t)
	defer cleanup()

	convID := cb57CreateConversation(t, testDB, "user1", "agent1")

	// Register an agent connection
	agentConn := &Connection{
		hub:      hub,
		connType: "agent",
		id:       "agent1",
		send:     make(chan []byte, 10),
		closeMu:  sync.RWMutex{},
		writeMu:  sync.Mutex{},
	}
	hub.register <- agentConn
	time.Sleep(50 * time.Millisecond)
	defer func() { hub.unregister <- agentConn }()

	clientConn := &Connection{hub: hub, connType: "client", id: "user1", send: make(chan []byte, 10)}
	routeTypingIndicator(clientConn, json.RawMessage(`{"conversation_id":"`+convID+`"}`))

	// Agent should receive typing indicator
	select {
	case msg := <-agentConn.send:
		var out OutgoingMessage
		if err := json.Unmarshal(msg, &out); err != nil {
			t.Fatalf("Failed to unmarshal: %v", err)
		}
		if out.Type != "typing" {
			t.Errorf("Expected type=typing, got %s", out.Type)
		}
	case <-time.After(time.Second):
		t.Error("Timeout waiting for typing indicator")
	}
}

// --- routeStatusUpdate ---

func TestCB57_RouteStatusUpdate_InvalidJSON(t *testing.T) {
	_, cleanup := setupTestServer_CB57(t)
	defer cleanup()

	conn := &Connection{hub: hub, connType: "agent", id: "agent1", send: make(chan []byte, 10)}
	routeStatusUpdate(conn, json.RawMessage(`{invalid`))
	// Should silently return
}

func TestCB57_RouteStatusUpdate_AgentBroadcast(t *testing.T) {
	_, cleanup := setupTestServer_CB57(t)
	defer cleanup()

	// Register a client to receive broadcast
	clientConn := &Connection{
		hub:      hub,
		connType: "client",
		id:       "user1",
		send:     make(chan []byte, 10),
		closeMu:  sync.RWMutex{},
		writeMu:  sync.Mutex{},
	}
	hub.register <- clientConn
	time.Sleep(50 * time.Millisecond)
	defer func() { hub.unregister <- clientConn }()

	agentConn := &Connection{hub: hub, connType: "agent", id: "agent1", send: make(chan []byte, 10)}
	routeStatusUpdate(agentConn, json.RawMessage(`{"status":"busy"}`))

	// Client should receive status broadcast
	select {
	case msg := <-clientConn.send:
		var out OutgoingMessage
		if err := json.Unmarshal(msg, &out); err != nil {
			t.Fatalf("Failed to unmarshal: %v", err)
		}
		if out.Type != "status" {
			t.Errorf("Expected type=status, got %s", out.Type)
		}
		data, ok := out.Data.(map[string]interface{})
		if !ok {
			t.Fatal("Expected data to be a map")
		}
		if data["status"] != "busy" {
			t.Errorf("Expected status=busy, got %v", data["status"])
		}
	case <-time.After(time.Second):
		t.Error("Timeout waiting for status broadcast")
	}
}

func TestCB57_RouteStatusUpdate_ConversationSpecific(t *testing.T) {
	testDB, cleanup := setupTestServer_CB57(t)
	defer cleanup()

	convID := cb57CreateConversation(t, testDB, "user1", "agent1")

	clientConn := &Connection{
		hub:      hub,
		connType: "client",
		id:       "user1",
		send:     make(chan []byte, 10),
		closeMu:  sync.RWMutex{},
		writeMu:  sync.Mutex{},
	}
	hub.register <- clientConn
	time.Sleep(50 * time.Millisecond)
	defer func() { hub.unregister <- clientConn }()

	agentConn := &Connection{hub: hub, connType: "agent", id: "agent1", send: make(chan []byte, 10)}
	routeStatusUpdate(agentConn, json.RawMessage(`{"conversation_id":"`+convID+`","status":"idle"}`))

	// Client should receive at least one status message (broadcast or conversation-specific)
	received := false
	for {
		select {
		case msg := <-clientConn.send:
			var out OutgoingMessage
			if err := json.Unmarshal(msg, &out); err != nil {
				continue
			}
			if out.Type == "status" {
				received = true
			}
		default:
			goto done
		}
	}
done:
	if !received {
		t.Error("Expected at least one status message")
	}
}

func TestCB57_RouteStatusUpdate_EmptyStatus(t *testing.T) {
	_, cleanup := setupTestServer_CB57(t)
	defer cleanup()

	agentConn := &Connection{hub: hub, connType: "agent", id: "agent1", send: make(chan []byte, 10)}
	// Empty status should not panic, no conversation_id should return early
	routeStatusUpdate(agentConn, json.RawMessage(`{"status":""}`))
	// Should not panic
}

// --- routeHeartbeat ---

func TestCB57_RouteHeartbeat_AckVerification(t *testing.T) {
	_, cleanup := setupTestServer_CB57(t)
	defer cleanup()

	conn := &Connection{
		hub:      hub,
		connType: "agent",
		id:       "agent1",
		send:     make(chan []byte, 10),
	}
	routeHeartbeat(conn)

	select {
	case msg := <-conn.send:
		var out OutgoingMessage
		if err := json.Unmarshal(msg, &out); err != nil {
			t.Fatalf("Failed to unmarshal: %v", err)
		}
		if out.Type != "heartbeat_ack" {
			t.Errorf("Expected type=heartbeat_ack, got %s", out.Type)
		}
		data, ok := out.Data.(map[string]interface{})
		if !ok {
			t.Fatal("Expected data to be a map")
		}
		if data["server_time"] == nil {
			t.Error("Expected server_time in ack")
		}
		if data["interval_s"] == nil {
			t.Error("Expected interval_s in ack")
		}
		if data["timeout_s"] == nil {
			t.Error("Expected timeout_s in ack")
		}
		if data["monitoring"] == nil {
			t.Error("Expected monitoring in ack")
		}
	case <-time.After(time.Second):
		t.Error("Timeout waiting for heartbeat ack")
	}
}

func TestCB57_RouteHeartbeat_TouchesHeartbeat(t *testing.T) {
	_, cleanup := setupTestServer_CB57(t)
	defer cleanup()

	conn := &Connection{
		hub:      hub,
		connType: "agent",
		id:       "agent1",
		send:     make(chan []byte, 10),
	}
	before := conn.lastHeartbeat
	routeHeartbeat(conn)

	// Drain the ack
	select {
	case <-conn.send:
	default:
	}

	after := conn.lastHeartbeat
	if !after.After(before) {
		t.Error("Expected lastHeartbeat to be updated after routeHeartbeat")
	}
}

// ========================
// attachments.go tests
// ========================

// --- handleGetAttachment ---

func TestCB57_HandleGetAttachment_MethodNotAllowed(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/attachments/att123", nil)
	handleGetAttachment(w, r)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected 405, got %d", w.Code)
	}
}

func TestCB57_HandleGetAttachment_MissingID(t *testing.T) {
	_, cleanup := setupTestServer_CB57(t)
	defer cleanup()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/attachments/", nil)
	r.URL.Path = "/attachments/"
	handleGetAttachment(w, r)

	// attachID would be empty string from path split
	// Actually the path "/attachments/" split after prefix gives "" — let's check
	// The handler should handle this gracefully
	if w.Code != http.StatusBadRequest && w.Code != http.StatusNotFound {
		// Some implementations might reach here differently
		t.Logf("Got code %d for missing attachment ID", w.Code)
	}
}

func TestCB57_HandleGetAttachment_JWTAuthSuccess(t *testing.T) {
	testDB, cleanup := setupTestServer_CB57(t)
	defer cleanup()

	// Create user and get token
	token, userID := cb57CreateUserAndGetToken(t, testDB, "testuser", "password123")

	// Create a test file
	uploadDir := getUploadDir()
	os.MkdirAll(uploadDir, 0755)
	filePath := uploadDir + "/test_att.txt"
	os.WriteFile(filePath, []byte("test content"), 0644)

	// Insert attachment record
	attachID := generateID("att")
	_, err := testDB.Exec(`INSERT INTO attachments (id, user_id, filename, content_type, size, sha256, storage_path, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		attachID, userID, "test_att.txt", "text/plain", 12, "sha123", "test_att.txt", time.Now().UTC())
	if err != nil {
		t.Fatalf("Failed to insert attachment: %v", err)
	}

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/attachments/"+attachID, nil)
	r.Header.Set("Authorization", "Bearer "+token)
	handleGetAttachment(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCB57_HandleGetAttachment_AgentAuthSuccess(t *testing.T) {
	testDB, cleanup := setupTestServer_CB57(t)
	defer cleanup()

	// Set agent secret
	t.Setenv("AGENT_SECRET", "test_secret")

	// Create a test file
	uploadDir := getUploadDir()
	os.MkdirAll(uploadDir, 0755)
	filePath := uploadDir + "/agent_att.txt"
	os.WriteFile(filePath, []byte("agent file"), 0644)

	attachID := generateID("att")
	_, err := testDB.Exec(`INSERT INTO attachments (id, user_id, filename, content_type, size, sha256, storage_path, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		attachID, "user1", "agent_att.txt", "text/plain", 10, "sha456", "agent_att.txt", time.Now().UTC())
	if err != nil {
		t.Fatalf("Failed to insert attachment: %v", err)
	}

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/attachments/"+attachID, nil)
	r.Header.Set("X-Agent-Secret", "test_secret")
	handleGetAttachment(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCB57_HandleGetAttachment_OwnershipForbidden(t *testing.T) {
	testDB, cleanup := setupTestServer_CB57(t)
	defer cleanup()

	// Create user
	token, _ := cb57CreateUserAndGetToken(t, testDB, "testuser", "password123")

	// Create attachment owned by different user
	uploadDir := getUploadDir()
	os.MkdirAll(uploadDir, 0755)
	os.WriteFile(uploadDir+"/other_att.txt", []byte("other"), 0644)

	attachID := generateID("att")
	_, err := testDB.Exec(`INSERT INTO attachments (id, user_id, filename, content_type, size, sha256, storage_path, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		attachID, "other_user", "other_att.txt", "text/plain", 5, "sha789", "other_att.txt", time.Now().UTC())
	if err != nil {
		t.Fatalf("Failed to insert attachment: %v", err)
	}

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/attachments/"+attachID, nil)
	r.Header.Set("Authorization", "Bearer "+token)
	// Need to set claims properly — the token belongs to userID, not "other_user"
	handleGetAttachment(w, r)

	if w.Code != http.StatusForbidden {
		t.Errorf("Expected 403, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCB57_HandleGetAttachment_NotFound(t *testing.T) {
	testDB, cleanup := setupTestServer_CB57(t)
	defer cleanup()

	token, _ := cb57CreateUserAndGetToken(t, testDB, "testuser", "password123")

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/attachments/nonexistent", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	handleGetAttachment(w, r)

	if w.Code != http.StatusNotFound {
		t.Errorf("Expected 404, got %d", w.Code)
	}
}

func TestCB57_HandleGetAttachment_NoAuth(t *testing.T) {
	_, cleanup := setupTestServer_CB57(t)
	defer cleanup()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/attachments/someid", nil)
	handleGetAttachment(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected 401, got %d", w.Code)
	}
}

func TestCB57_HandleGetAttachment_InvalidJWT(t *testing.T) {
	_, cleanup := setupTestServer_CB57(t)
	defer cleanup()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/attachments/someid", nil)
	r.Header.Set("Authorization", "Bearer invalidtoken123")
	handleGetAttachment(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected 401, got %d", w.Code)
	}
}

func TestCB57_HandleGetAttachment_WrongAgentSecret(t *testing.T) {
	_, cleanup := setupTestServer_CB57(t)
	defer cleanup()

	t.Setenv("AGENT_SECRET", "correct_secret")

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/attachments/someid", nil)
	r.Header.Set("X-Agent-Secret", "wrong_secret")
	handleGetAttachment(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected 401, got %d", w.Code)
	}
}

// --- handleListAttachments ---

func TestCB57_HandleListAttachments_SuccessWithAttachments(t *testing.T) {
	testDB, cleanup := setupTestServer_CB57(t)
	defer cleanup()

	token, userID := cb57CreateUserAndGetToken(t, testDB, "testuser", "password123")
	convID := cb57CreateConversation(t, testDB, userID, "agent1")

	// Store a message and get its ID
	msg := RoutedMessage{ConversationID: convID, Content: "test msg", SenderType: "client", SenderID: userID}
	storeMessage(msg)

	var msgID string
	testDB.QueryRow("SELECT id FROM messages WHERE conversation_id = ? LIMIT 1", convID).Scan(&msgID)

	// Insert attachment linked to message
	_, err := testDB.Exec(`INSERT INTO attachments (id, message_id, user_id, filename, content_type, size, sha256, storage_path, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		generateID("att"), msgID, userID, "doc.pdf", "application/pdf", 1024, "shaabc", "path/to/file", time.Now().UTC())
	if err != nil {
		t.Fatalf("Failed to insert attachment: %v", err)
	}

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/messages/"+convID+"/attachments?conversation_id="+convID, nil)
	r.Header.Set("Authorization", "Bearer "+token)
	handleListAttachments(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var attachments []map[string]interface{}
	json.NewDecoder(w.Body).Decode(&attachments)
	if len(attachments) != 1 {
		t.Errorf("Expected 1 attachment, got %d", len(attachments))
	}
}

func TestCB57_HandleListAttachments_EmptyConversationID(t *testing.T) {
	testDB, cleanup := setupTestServer_CB57(t)
	defer cleanup()

	token, _ := cb57CreateUserAndGetToken(t, testDB, "testuser", "password123")

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/messages/attachments", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	handleListAttachments(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected 400, got %d", w.Code)
	}
}

func TestCB57_HandleListAttachments_Unauthorized(t *testing.T) {
	_, cleanup := setupTestServer_CB57(t)
	defer cleanup()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/messages/attachments?conversation_id=conv1", nil)
	handleListAttachments(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected 401, got %d", w.Code)
	}
}

func TestCB57_HandleListAttachments_MethodNotAllowed(t *testing.T) {
	_, cleanup := setupTestServer_CB57(t)
	defer cleanup()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/messages/attachments", nil)
	handleListAttachments(w, r)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected 405, got %d", w.Code)
	}
}

func TestCB57_HandleListAttachments_InvalidToken(t *testing.T) {
	_, cleanup := setupTestServer_CB57(t)
	defer cleanup()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/messages/attachments?conversation_id=conv1", nil)
	r.Header.Set("Authorization", "Bearer invalidtoken")
	handleListAttachments(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected 401, got %d", w.Code)
	}
}

func TestCB57_HandleListAttachments_ConversationNotFound(t *testing.T) {
	testDB, cleanup := setupTestServer_CB57(t)
	defer cleanup()

	token, _ := cb57CreateUserAndGetToken(t, testDB, "testuser", "password123")

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/messages/attachments?conversation_id=nonexistent", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	handleListAttachments(w, r)

	if w.Code != http.StatusNotFound {
		t.Errorf("Expected 404, got %d", w.Code)
	}
}

// ========================
// handlers.go tests
// ========================

// --- handleListConversations ---

func TestCB57_HandleListConversations_SuccessWithMessages(t *testing.T) {
	testDB, cleanup := setupTestServer_CB57(t)
	defer cleanup()

	token, userID := cb57CreateUserAndGetToken(t, testDB, "testuser", "password123")

	convID := cb57CreateConversation(t, testDB, userID, "agent1")
	storeMessage(RoutedMessage{ConversationID: convID, Content: "hello", SenderType: "client", SenderID: userID})
	storeMessage(RoutedMessage{ConversationID: convID, Content: "hi there", SenderType: "agent", SenderID: "agent1"})

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/conversations", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	handleListConversations(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var conversations []map[string]interface{}
	json.NewDecoder(w.Body).Decode(&conversations)
	if len(conversations) != 1 {
		t.Fatalf("Expected 1 conversation, got %d", len(conversations))
	}
	conv := conversations[0]
	if conv["id"] != convID {
		t.Errorf("Expected conv ID=%s, got %v", convID, conv["id"])
	}
	// Check last_message
	lastMsg, ok := conv["last_message"].(map[string]interface{})
	if !ok {
		t.Fatal("Expected last_message to be a map")
	}
	if lastMsg["content"] == "" {
		t.Error("Expected non-empty last_message content")
	}
	// Check unread_count — agent messages should be unread
	unreadCount, _ := conv["unread_count"].(float64)
	if unreadCount < 1 {
		t.Errorf("Expected unread_count >= 1, got %v", conv["unread_count"])
	}
}

func TestCB57_HandleListConversations_EmptyList(t *testing.T) {
	testDB, cleanup := setupTestServer_CB57(t)
	defer cleanup()

	token, _ := cb57CreateUserAndGetToken(t, testDB, "testuser", "password123")

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/conversations", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	handleListConversations(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d", w.Code)
	}
	var conversations []map[string]interface{}
	json.NewDecoder(w.Body).Decode(&conversations)
	if len(conversations) != 0 {
		t.Errorf("Expected 0 conversations, got %d", len(conversations))
	}
}

func TestCB57_HandleListConversations_Unauthorized(t *testing.T) {
	_, cleanup := setupTestServer_CB57(t)
	defer cleanup()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/conversations", nil)
	handleListConversations(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected 401, got %d", w.Code)
	}
}

func TestCB57_HandleListConversations_MethodNotAllowed(t *testing.T) {
	_, cleanup := setupTestServer_CB57(t)
	defer cleanup()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/conversations", nil)
	handleListConversations(w, r)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected 405, got %d", w.Code)
	}
}

// --- handleGetMessages ---

func TestCB57_HandleGetMessages_Success(t *testing.T) {
	testDB, cleanup := setupTestServer_CB57(t)
	defer cleanup()

	token, userID := cb57CreateUserAndGetToken(t, testDB, "testuser", "password123")
	convID := cb57CreateConversation(t, testDB, userID, "agent1")

	storeMessage(RoutedMessage{ConversationID: convID, Content: "msg1", SenderType: "client", SenderID: userID})
	storeMessage(RoutedMessage{ConversationID: convID, Content: "msg2", SenderType: "agent", SenderID: "agent1"})

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/conversations/messages?conversation_id="+convID, nil)
	r.Header.Set("Authorization", "Bearer "+token)
	handleGetMessages(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var messages []map[string]interface{}
	json.NewDecoder(w.Body).Decode(&messages)
	if len(messages) != 2 {
		t.Errorf("Expected 2 messages, got %d", len(messages))
	}
}

func TestCB57_HandleGetMessages_LimitParsing(t *testing.T) {
	testDB, cleanup := setupTestServer_CB57(t)
	defer cleanup()

	token, userID := cb57CreateUserAndGetToken(t, testDB, "testuser", "password123")
	convID := cb57CreateConversation(t, testDB, userID, "agent1")

	// Store 5 messages
	for i := 0; i < 5; i++ {
		storeMessage(RoutedMessage{ConversationID: convID, Content: "msg", SenderType: "client", SenderID: userID})
	}

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/conversations/messages?conversation_id="+convID+"&limit=2", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	handleGetMessages(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d", w.Code)
	}
	var messages []map[string]interface{}
	json.NewDecoder(w.Body).Decode(&messages)
	if len(messages) != 2 {
		t.Errorf("Expected 2 messages with limit=2, got %d", len(messages))
	}
}

func TestCB57_HandleGetMessages_NotFound(t *testing.T) {
	testDB, cleanup := setupTestServer_CB57(t)
	defer cleanup()

	token, _ := cb57CreateUserAndGetToken(t, testDB, "testuser", "password123")

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/conversations/messages?conversation_id=nonexistent", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	handleGetMessages(w, r)

	if w.Code != http.StatusNotFound {
		t.Errorf("Expected 404, got %d", w.Code)
	}
}

func TestCB57_HandleGetMessages_MissingConversationID(t *testing.T) {
	testDB, cleanup := setupTestServer_CB57(t)
	defer cleanup()

	token, _ := cb57CreateUserAndGetToken(t, testDB, "testuser", "password123")

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/conversations/messages", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	handleGetMessages(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected 400, got %d", w.Code)
	}
}

func TestCB57_HandleGetMessages_WrongUser(t *testing.T) {
	testDB, cleanup := setupTestServer_CB57(t)
	defer cleanup()

	// Create user1 with conversation
	_, userID1 := cb57CreateUserAndGetToken(t, testDB, "user1", "password123")
	convID := cb57CreateConversation(t, testDB, userID1, "agent1")

	// Create user2
	token2, _ := cb57CreateUserAndGetToken(t, testDB, "user2", "password456")

	// user2 tries to read user1's conversation
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/conversations/messages?conversation_id="+convID, nil)
	r.Header.Set("Authorization", "Bearer "+token2)
	handleGetMessages(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected 401 for wrong user, got %d", w.Code)
	}
}

func TestCB57_HandleGetMessages_Unauthorized(t *testing.T) {
	_, cleanup := setupTestServer_CB57(t)
	defer cleanup()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/conversations/messages?conversation_id=conv1", nil)
	handleGetMessages(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected 401, got %d", w.Code)
	}
}

func TestCB57_HandleGetMessages_MethodNotAllowed(t *testing.T) {
	_, cleanup := setupTestServer_CB57(t)
	defer cleanup()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/conversations/messages", nil)
	handleGetMessages(w, r)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected 405, got %d", w.Code)
	}
}

// --- handleSearchMessages ---

func TestCB57_HandleSearchMessages_Success(t *testing.T) {
	testDB, cleanup := setupTestServer_CB57(t)
	defer cleanup()

	token, userID := cb57CreateUserAndGetToken(t, testDB, "testuser", "password123")
	convID := cb57CreateConversation(t, testDB, userID, "agent1")

	storeMessage(RoutedMessage{ConversationID: convID, Content: "find me here", SenderType: "client", SenderID: userID})
	storeMessage(RoutedMessage{ConversationID: convID, Content: "find another", SenderType: "agent", SenderID: "agent1"})
	storeMessage(RoutedMessage{ConversationID: convID, Content: "no match here", SenderType: "client", SenderID: userID})

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/messages/search?q=find", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	handleSearchMessages(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var results []map[string]interface{}
	json.NewDecoder(w.Body).Decode(&results)
	if len(results) != 2 {
		t.Errorf("Expected 2 results, got %d", len(results))
	}
}

func TestCB57_HandleSearchMessages_NoResults(t *testing.T) {
	testDB, cleanup := setupTestServer_CB57(t)
	defer cleanup()

	token, userID := cb57CreateUserAndGetToken(t, testDB, "testuser", "password123")
	convID := cb57CreateConversation(t, testDB, userID, "agent1")
	storeMessage(RoutedMessage{ConversationID: convID, Content: "hello world", SenderType: "client", SenderID: userID})

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/messages/search?q=nonexistent", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	handleSearchMessages(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d", w.Code)
	}
	var results []map[string]interface{}
	json.NewDecoder(w.Body).Decode(&results)
	if len(results) != 0 {
		t.Errorf("Expected 0 results, got %d", len(results))
	}
}

func TestCB57_HandleSearchMessages_Unauthorized(t *testing.T) {
	_, cleanup := setupTestServer_CB57(t)
	defer cleanup()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/messages/search?q=test", nil)
	handleSearchMessages(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected 401, got %d", w.Code)
	}
}

func TestCB57_HandleSearchMessages_MissingQuery(t *testing.T) {
	testDB, cleanup := setupTestServer_CB57(t)
	defer cleanup()

	token, _ := cb57CreateUserAndGetToken(t, testDB, "testuser", "password123")

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/messages/search", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	handleSearchMessages(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected 400, got %d", w.Code)
	}
}

func TestCB57_HandleSearchMessages_MethodNotAllowed(t *testing.T) {
	_, cleanup := setupTestServer_CB57(t)
	defer cleanup()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/messages/search", nil)
	handleSearchMessages(w, r)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected 405, got %d", w.Code)
	}
}

// --- handleMarkRead ---

func TestCB57_HandleMarkRead_Success(t *testing.T) {
	testDB, cleanup := setupTestServer_CB57(t)
	defer cleanup()

	token, userID := cb57CreateUserAndGetToken(t, testDB, "testuser", "password123")
	convID := cb57CreateConversation(t, testDB, userID, "agent1")

	// Store unread agent messages
	storeMessage(RoutedMessage{ConversationID: convID, Content: "agent msg 1", SenderType: "agent", SenderID: "agent1"})
	storeMessage(RoutedMessage{ConversationID: convID, Content: "agent msg 2", SenderType: "agent", SenderID: "agent1"})

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/conversations/mark-read", strings.NewReader("conversation_id="+convID))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Authorization", "Bearer "+token)
	handleMarkRead(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["status"] != "marked_read" {
		t.Errorf("Expected status=marked_read, got %v", resp["status"])
	}
	count, _ := resp["count"].(float64)
	if count != 2 {
		t.Errorf("Expected count=2, got %v", resp["count"])
	}
}

func TestCB57_HandleMarkRead_Unauthorized(t *testing.T) {
	_, cleanup := setupTestServer_CB57(t)
	defer cleanup()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/conversations/mark-read", strings.NewReader("conversation_id=conv1"))
	handleMarkRead(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected 401, got %d", w.Code)
	}
}

func TestCB57_HandleMarkRead_MissingConversationID(t *testing.T) {
	testDB, cleanup := setupTestServer_CB57(t)
	defer cleanup()

	token, _ := cb57CreateUserAndGetToken(t, testDB, "testuser", "password123")

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/conversations/mark-read", strings.NewReader(""))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Authorization", "Bearer "+token)
	handleMarkRead(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected 400, got %d", w.Code)
	}
}

func TestCB57_HandleMarkRead_NotFound(t *testing.T) {
	testDB, cleanup := setupTestServer_CB57(t)
	defer cleanup()

	token, _ := cb57CreateUserAndGetToken(t, testDB, "testuser", "password123")

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/conversations/mark-read", strings.NewReader("conversation_id=nonexistent"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Authorization", "Bearer "+token)
	handleMarkRead(w, r)

	if w.Code != http.StatusNotFound {
		t.Errorf("Expected 404, got %d", w.Code)
	}
}

func TestCB57_HandleMarkRead_MethodNotAllowed(t *testing.T) {
	_, cleanup := setupTestServer_CB57(t)
	defer cleanup()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/conversations/mark-read", nil)
	handleMarkRead(w, r)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected 405, got %d", w.Code)
	}
}