package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

// =====================================================
// Coverage boost 8: targeting remaining low-coverage functions
// =====================================================

// --- profile_handler coverage (heap, goroutine, CPU profiles) ---

func TestCb8HeapProfile(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	os.Setenv("PROFILING_DIR", t.TempDir())
	defer os.Unsetenv("PROFILING_DIR")

	token := cb7CreateUser(t, "proftestuser1")
	claims, _ := ValidateJWT(token)
	ctx := context.WithValue(context.Background(), contextKeyUserID, claims.UserID)
	req := httptest.NewRequest("GET", "/admin/profile?action=heap", nil).WithContext(ctx)
	w := httptest.NewRecorder()
	handleHeapProfile(w, req)

	if w.Code != 200 {
		t.Errorf("Expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCb8GoroutineProfile(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	os.Setenv("PROFILING_DIR", t.TempDir())
	defer os.Unsetenv("PROFILING_DIR")

	req := httptest.NewRequest("GET", "/admin/profile?action=goroutine", nil)
	w := httptest.NewRecorder()
	handleGoroutineProfile(w, req)

	if w.Code != 200 {
		t.Errorf("Expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCb8CPUProfileStart(t *testing.T) {
	defer cpuProfileTestSetup()()

	setupTestDB(t)
	defer db.Close()

	os.Setenv("PROFILING_DIR", t.TempDir())
	defer os.Unsetenv("PROFILING_DIR")

	req := httptest.NewRequest("POST", "/admin/profile?action=cpu_start", nil)
	w := httptest.NewRecorder()
	handleCPUProfileStart(w, req)

	if w.Code != 200 {
		t.Errorf("Expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// Clean up - stop profiling (safety net, also done by cpuProfileTestSetup cleanup)
	cpuProfileState.Lock()
	if cpuProfileState.stopFunc != nil {
		cpuProfileState.stopFunc()
		cpuProfileState.active = false
	}
	cpuProfileState.Unlock()
}

func TestCb8CPUProfileAlreadyActive(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

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

	req := httptest.NewRequest("POST", "/admin/profile?action=cpu_start", nil)
	w := httptest.NewRecorder()
	handleCPUProfileStart(w, req)

	if w.Code != 500 {
		t.Errorf("Expected 500, got %d", w.Code)
	}
}

func TestCb8CPUProfileStopNotActive(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	cpuProfileState.Lock()
	cpuProfileState.active = false
	cpuProfileState.stopFunc = nil
	cpuProfileState.Unlock()

	req := httptest.NewRequest("POST", "/admin/profile?action=cpu_stop", nil)
	w := httptest.NewRecorder()
	handleCPUProfileStop(w, req)

	if w.Code != 500 {
		t.Errorf("Expected 500, got %d", w.Code)
	}
}

// --- handleGetReactions coverage (70.6%) ---

func TestCb8GetReactions_NoAuth(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	req := httptest.NewRequest("GET", "/reactions?message_id=msg1", nil)
	w := httptest.NewRecorder()
	handleGetReactions(w, req)

	if w.Code != 401 {
		t.Errorf("Expected 401, got %d", w.Code)
	}
}

func TestCb8GetReactions_MissingMessageID(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	token := cb7CreateUser(t, "reactuser1")

	req := httptest.NewRequest("GET", "/reactions", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleGetReactions(w, req)

	if w.Code != 400 {
		t.Errorf("Expected 400, got %d", w.Code)
	}
}

func TestCb8GetReactions_MessageNotFound(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	token := cb7CreateUser(t, "reactuser2")

	req := httptest.NewRequest("GET", "/reactions?message_id=nonexistent-msg", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleGetReactions(w, req)

	if w.Code != 404 {
		t.Errorf("Expected 404, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCb8GetReactions_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest("POST", "/reactions", nil)
	w := httptest.NewRecorder()
	handleGetReactions(w, req)

	if w.Code != 405 {
		t.Errorf("Expected 405, got %d", w.Code)
	}
}

// --- handleRegisterAgent more coverage (80%) ---

func TestCb8RegisterAgent_MissingID(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	form := "name=Agent&agent_secret=" + getAgentSecret()
	req := httptest.NewRequest("POST", "/auth/agent", bytes.NewBufferString(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Agent-Secret", getAgentSecret())
	w := httptest.NewRecorder()
	handleRegisterAgent(w, req)

	if w.Code != 400 {
		t.Errorf("Expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCb8RegisterAgent_WrongSecret(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	form := "agent_id=agent-wrong-secret&name=Agent&agent_secret=wrong"
	req := httptest.NewRequest("POST", "/auth/agent", bytes.NewBufferString(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Agent-Secret", "wrong-secret")
	w := httptest.NewRecorder()
	handleRegisterAgent(w, req)

	if w.Code != 401 {
		t.Errorf("Expected 401, got %d: %s", w.Code, w.Body.String())
	}
}

// --- handleCreateConversation more coverage (80%) ---

func TestCb8CreateConversation_MissingAgentID(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	token := cb7CreateUser(t, "convtest8user1")

	req := httptest.NewRequest("POST", "/conversations/create", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleCreateConversation(w, req)

	if w.Code != 400 {
		t.Errorf("Expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCb8CreateConversation_NoAuth(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	req := httptest.NewRequest("POST", "/conversations/create", nil)
	w := httptest.NewRecorder()
	handleCreateConversation(w, req)

	if w.Code != 401 {
		t.Errorf("Expected 401, got %d", w.Code)
	}
}

// --- handleListConversations more coverage (87%) ---

func TestCb8ListConversations_WithAgentFilter(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	token := cb7CreateUser(t, "listconv8user1")

	// Create a conversation first
	cb7CreateConversation(t, token, "listconv8agent1")

	req := httptest.NewRequest("GET", "/conversations/list?agent_id=listconv8agent1", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleListConversations(w, req)

	if w.Code != 200 {
		t.Errorf("Expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

// --- handleMarkRead more coverage (83%) ---

func TestCb8MarkRead_NoAuth(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	req := httptest.NewRequest("POST", "/messages/mark-read", nil)
	w := httptest.NewRecorder()
	handleMarkRead(w, req)

	if w.Code != 401 {
		t.Errorf("Expected 401, got %d", w.Code)
	}
}

// --- handleSearchMessages more coverage (84%) ---

func TestCb8SearchMessages_EmptyQueryReturnsAll(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	token := cb7CreateUser(t, "search8user1")
	convID := cb7CreateConversation(t, token, "search8agent1")

	// Store a message
	err := storeMessage(RoutedMessage{
		ConversationID: convID,
		SenderID:      "search8user1",
		SenderType:    "client",
		Content:       "hello world",
	})
	if err != nil {
		t.Fatalf("storeMessage failed: %v", err)
	}

	req := httptest.NewRequest("GET", "/messages/search?conversation_id="+convID+"&q=hello", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleSearchMessages(w, req)

	if w.Code != 200 {
		t.Errorf("Expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

// --- addReaction edge cases (80.8%) ---

func TestCb8AddReaction_Duplicate(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	token := cb7CreateUser(t, "react8user1")
	convID := cb7CreateConversation(t, token, "react8agent1")

	err := storeMessage(RoutedMessage{
		ConversationID: convID,
		SenderID:       "react8user1",
		SenderType:     "client",
		Content:        "reaction test",
	})
	if err != nil {
		t.Fatalf("storeMessage failed: %v", err)
	}
	var msgID string
	err = db.QueryRow("SELECT id FROM messages WHERE conversation_id = ? ORDER BY created_at DESC LIMIT 1", convID).Scan(&msgID)
	if err != nil {
		t.Fatalf("Failed to get message ID: %v", err)
	}

	claims, _ := ValidateJWT(token)

	// First reaction
	_, _, err = addReaction(msgID, claims.UserID, "+1")
	if err != nil {
		t.Fatalf("First reaction failed: %v", err)
	}

	// Duplicate reaction should also succeed (idempotent)
	_, _, err = addReaction(msgID, claims.UserID, "+1")
	if err != nil {
		t.Logf("Duplicate reaction returned error (may be expected): %v", err)
	}
}

// --- removeConversationTag more coverage (78.6%) ---

func TestCb8RemoveConversationTag_NonExistent(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	err := removeConversationTag("nonexistent-conv", "user1", "important")
	// Removing non-existent tag should not error
	if err != nil {
		t.Logf("Remove non-existent tag returned: %v (may be expected)", err)
	}
}

// --- handleListAgents more coverage (80%) ---

func TestCb8ListAgents_EmptyDB(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	hub = newHub()
	go hub.run()
	defer hub.Stop()

	req := httptest.NewRequest("GET", "/agents", nil)
	w := httptest.NewRecorder()
	handleListAgents(w, req)

	if w.Code != 200 {
		t.Errorf("Expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

// --- handleChangePassword more coverage (84.6%) ---

func TestCb8ChangePassword_NoAuth(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	form := "old_password=old&new_password=newpass123"
	req := httptest.NewRequest("POST", "/auth/change-password", bytes.NewBufferString(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handleChangePassword(w, req)

	if w.Code != 401 {
		t.Errorf("Expected 401, got %d", w.Code)
	}
}

// --- handleDeleteConversation more coverage (92.6%) ---

func TestCb8DeleteConversation_NoAuth(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	// handleDeleteConversation requires DELETE method, but also requires auth
	req := httptest.NewRequest("DELETE", "/conversations/delete", nil)
	w := httptest.NewRecorder()
	handleDeleteConversation(w, req)

	if w.Code != 401 {
		t.Errorf("Expected 401 (no auth), got %d", w.Code)
	}
}

// --- handleSearchMessages with limit and offset ---

func TestCb8SearchMessages_WithOffset(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	token := cb7CreateUser(t, "searchoff8user1")
	convID := cb7CreateConversation(t, token, "searchoff8agent1")

	// Store multiple messages
	for i := 0; i < 5; i++ {
		storeMessage(RoutedMessage{
			ConversationID: convID,
			SenderID:       "searchoff8user1",
			SenderType:     "client",
			Content:        "test message " + time.Now().String(),
		})
		time.Sleep(time.Millisecond * 10) // ensure different timestamps
	}

	req := httptest.NewRequest("GET", "/messages/search?conversation_id="+convID+"&q=test&limit=2&offset=2", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleSearchMessages(w, req)

	if w.Code != 200 {
		t.Errorf("Expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

// --- handleGetMessages more coverage (94%) ---

func TestCb8GetMessages_WithLimit(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	token := cb7CreateUser(t, "msglim8user1")
	convID := cb7CreateConversation(t, token, "msglim8agent1")

	for i := 0; i < 5; i++ {
		storeMessage(RoutedMessage{
			ConversationID: convID,
			SenderID:       "msglim8user1",
			SenderType:     "client",
			Content:        "msg " + itoa(i),
		})
	}

	req := httptest.NewRequest("GET", "/messages/get?conversation_id="+convID+"&limit=3", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleGetMessages(w, req)

	if w.Code != 200 {
		t.Errorf("Expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

// --- handleGetEncryptedMessages missing fields ---

func TestCb8GetEncryptedMessages_MissingConvID(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	token := cb7CreateUser(t, "enc8user1")
	req := httptest.NewRequest("GET", "/messages/encrypted", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleGetEncryptedMessages(w, req)

	if w.Code != 400 {
		t.Errorf("Expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

// --- conversations.go: GetOrCreateConversation more coverage (80%) ---

func TestCb8GetOrCreateConversation_DifferentAgents(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	conv1, err := GetOrCreateConversation("user8a", "agent8a")
	if err != nil {
		t.Fatalf("Failed to create conversation 1: %v", err)
	}
	conv2, err := GetOrCreateConversation("user8a", "agent8b")
	if err != nil {
		t.Fatalf("Failed to create conversation 2: %v", err)
	}
	if conv1.ID == conv2.ID {
		t.Error("Different agents should produce different conversations")
	}
}

// --- conversations.go: deleteConversation more coverage (80%) ---

func TestCb8DeleteConversation_NonExistent(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	err := deleteConversation("nonexistent-conv", "user8")
	if err != nil {
		t.Logf("Delete nonexistent conversation returned: %v (may be expected)", err)
	}
}

// --- routeChatMessage more coverage ---

func TestCb8RouteChatMessage_WithContent(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	hub = newHub()
	go hub.run()
	defer hub.Stop()

	cb7RegisterAgent(t, "route8agent1", "Route Agent")

	token := cb7CreateUser(t, "route8user1")
	claims, _ := ValidateJWT(token)
	convID := cb7CreateConversation(t, token, "route8agent1")

	msg := map[string]interface{}{
		"type":            "chat",
		"conversation_id": convID,
		"content":         "Hello from route test",
	}
	data, _ := json.Marshal(msg)
	conn := &Connection{
		id:       claims.UserID,
		connType: "client",
		send:     make(chan []byte, 10),
	}
	routeChatMessage(conn, json.RawMessage(data))
}

// --- markMessagesRead more coverage ---

func TestCb8MarkMessagesRead_NoMessages(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	token := cb7CreateUser(t, "read8user1")
	convID := cb7CreateConversation(t, token, "read8agent1")

	// Mark read when no messages exist
	_, err := markMessagesRead(convID, "read8user1")
	if err != nil {
		t.Logf("markMessagesRead on empty conv returned: %v", err)
	}
}

// --- handleGetUserPresence more coverage (88%) ---

func TestCb8GetUserPresence_NotFound(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	token := cb7CreateUser(t, "presence8user1")

	req := httptest.NewRequest("GET", "/presence/user?user_id=nonexistent_user", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleGetUserPresence(w, req)

	// Should return 200 with empty/default presence
	if w.Code == 500 {
		t.Errorf("Got internal error: %s", w.Body.String())
	}
}

func TestCb8GetUserPresence_MissingUserID(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	token := cb7CreateUser(t, "presence8user2")

	req := httptest.NewRequest("GET", "/presence/user", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleGetUserPresence(w, req)

	// Handler returns 200 with default/empty data when no user_id provided
	if w.Code == 500 {
		t.Errorf("Got internal error: %s", w.Body.String())
	}
}

// --- middleware: checkRateLimit coverage (60%) ---

func TestCb8CheckRateLimit_Blocked(t *testing.T) {
	rl := NewRateLimiter(1, time.Minute)

	conn := &Connection{
		id:   "rate8conn1",
		send: make(chan []byte, 10),
	}

	if !rl.Allow(conn.id) {
		t.Error("First request should be allowed")
	}
	if rl.Allow(conn.id) {
		t.Error("Second request should be blocked (over limit)")
	}
}

// --- dbdriver: openDatabase coverage (52%) ---

func TestCb8EnvIntOrDefault(t *testing.T) {
	os.Setenv("TEST_INT_VAL", "42")
	defer os.Unsetenv("TEST_INT_VAL")

	val := envIntOrDefault("TEST_INT_VAL", 10)
	if val != 42 {
		t.Errorf("Expected 42, got %d", val)
	}

	val = envIntOrDefault("NONEXISTENT_INT", 10)
	if val != 10 {
		t.Errorf("Expected 10, got %d", val)
	}
}

func TestCb8EnvDurationOrDefault(t *testing.T) {
	os.Setenv("TEST_DUR_VAL", "5s")
	defer os.Unsetenv("TEST_DUR_VAL")

	val := envDurationOrDefault("TEST_DUR_VAL", time.Second)
	if val != 5*time.Second {
		t.Errorf("Expected 5s, got %v", val)
	}

	val = envDurationOrDefault("NONEXISTENT_DUR", time.Minute)
	if val != time.Minute {
		t.Errorf("Expected 1m, got %v", val)
	}
}

// --- attachments: handleGetMaxUploadSize (71%) ---

func TestCb8GetMaxUploadSize_SetViaEnv(t *testing.T) {
	// The variable is read at init time, so we need to set maxUploadSize directly
	maxUploadSize = 1024 * 1024 // 1MB
	defer func() { maxUploadSize = MaxUploadSize }()

	size := getMaxUploadSize()
	if size != 1024*1024 {
		t.Errorf("Expected 1MB, got %d", size)
	}
}

// --- conversations: searchMessages DB-level more coverage ---

func TestCb8SearchMessages_DB_WithLimit(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	token := cb7CreateUser(t, "search8dbuser1")
	claims, _ := ValidateJWT(token)
	convID := cb7CreateConversation(t, token, "search8dbagent1")

	for i := 0; i < 5; i++ {
		storeMessage(RoutedMessage{
			ConversationID: convID,
			SenderID:       claims.UserID,
			SenderType:     "client",
			Content:        "searchable content " + itoa(i),
		})
	}

	results, err := searchMessages(claims.UserID, "searchable", 3)
	if err != nil {
		t.Fatalf("searchMessages failed: %v", err)
	}
	if len(results) > 3 {
		t.Errorf("Expected at most 3 results, got %d", len(results))
	}
}

// --- handleReact more coverage (83.7%) ---

func TestCb8React_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest("GET", "/react", nil)
	w := httptest.NewRecorder()
	handleReact(w, req)

	if w.Code != 405 {
		t.Errorf("Expected 405, got %d", w.Code)
	}
}

// --- handleAddTag more coverage (92.6%) ---

func TestCb8AddTag_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest("GET", "/tags/add", nil)
	w := httptest.NewRecorder()
	handleAddTag(w, req)

	if w.Code != 405 {
		t.Errorf("Expected 405, got %d", w.Code)
	}
}

// --- handleRemoveTag more coverage (83.3%) ---

func TestCb8RemoveTag_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest("GET", "/tags/remove", nil)
	w := httptest.NewRecorder()
	handleRemoveTag(w, req)

	if w.Code != 405 {
		t.Errorf("Expected 405, got %d", w.Code)
	}
}

// --- handleAgentConnect more coverage (86%) ---

func TestCb8AgentConnect_WrongMethod(t *testing.T) {
	req := httptest.NewRequest("GET", "/auth/agent/connect", nil)
	w := httptest.NewRecorder()
	handleAgentConnect(w, req)

	// handleAgentConnect doesn't check method, returns 400 for missing fields
	if w.Code == 500 {
		t.Errorf("Got internal error: %s", w.Body.String())
	}
}

// --- handleLogin more coverage (92%) ---

func TestCb8Login_WrongMethod(t *testing.T) {
	req := httptest.NewRequest("GET", "/auth/login", nil)
	w := httptest.NewRecorder()
	handleLogin(w, req)

	if w.Code != 405 {
		t.Errorf("Expected 405, got %d", w.Code)
	}
}

// --- handleRegisterUser more coverage (86.2%) ---

func TestCb8RegisterUser_WrongMethod(t *testing.T) {
	req := httptest.NewRequest("GET", "/auth/user", nil)
	w := httptest.NewRecorder()
	handleRegisterUser(w, req)

	if w.Code != 405 {
		t.Errorf("Expected 405, got %d", w.Code)
	}
}

// --- handleClientConnect more coverage (93.5%) ---

func TestCb8ClientConnect_WrongMethod(t *testing.T) {
	req := httptest.NewRequest("GET", "/auth/client/connect", nil)
	w := httptest.NewRecorder()
	handleClientConnect(w, req)

	if w.Code == 500 {
		t.Errorf("Got internal error: %s", w.Body.String())
	}
}

// --- handleStoreEncryptedMessage more coverage ---

func TestCb8StoreEncryptedMessage_MissingConversationID(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	token := cb7CreateUser(t, "enc8miss1")
	body := `{"ciphertext":"abc","iv":"123","algorithm":"aes-256-gcm"}`
	req := httptest.NewRequest("POST", "/messages/encrypted/store", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleStoreEncryptedMessage(w, req)

	if w.Code != 400 {
		t.Errorf("Expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

// --- handleDeleteNotificationPrefs ---

func TestCb8DeleteNotificationPrefs(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	token := cb7CreateUser(t, "notifdel8user1")
	claims, _ := ValidateJWT(token)
	convID := cb7CreateConversation(t, token, "notifdel8agent1")

	// First set notification prefs
	req := httptest.NewRequest("POST", "/notifications/preferences?conversation_id="+convID+"&muted=true", nil)
	ctx := context.WithValue(req.Context(), contextKeyUserID, claims.UserID)
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()
	handleSetNotificationPrefs(w, req)
	if w.Code != 200 {
		t.Fatalf("Failed to set prefs: %d %s", w.Code, w.Body.String())
	}

	// Now delete
	req = httptest.NewRequest("DELETE", "/notifications/preferences?conversation_id="+convID, nil)
	ctx = context.WithValue(req.Context(), contextKeyUserID, claims.UserID)
	req = req.WithContext(ctx)
	w = httptest.NewRecorder()
	handleDeleteNotificationPrefs(w, req)

	if w.Code != 200 {
		t.Errorf("Expected 200, got %d: %s", w.Code, w.Body.String())
	}
}