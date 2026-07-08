package main

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

// --- Helper ---
func setupTestDB_CB53(t *testing.T) *sql.DB {
	testDB, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("Failed to open test DB: %v", err)
	}
	if err := initSchema(testDB); err != nil {
		t.Fatalf("Failed to init schema: %v", err)
	}
	return testDB
}

// =========================================================================
// handleWebPushSubscribe (push.go:410)
// =========================================================================

func TestCB53_HandleWebPushSubscribe_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/push/web-subscribe", nil)
	w := httptest.NewRecorder()
	handleWebPushSubscribe(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected 405, got %d", w.Code)
	}
}

func TestCB53_HandleWebPushSubscribe_Unauthorized(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/push/web-subscribe", strings.NewReader("{}"))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handleWebPushSubscribe(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected 401, got %d", w.Code)
	}
}

func TestCB53_HandleWebPushSubscribe_InvalidJSON(t *testing.T) {
	token := generateTestToken(t, "user-53a")
	req := httptest.NewRequest(http.MethodPost, "/push/web-subscribe", strings.NewReader("not json"))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleWebPushSubscribe(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected 400, got %d", w.Code)
	}
}

func TestCB53_HandleWebPushSubscribe_MissingFields(t *testing.T) {
	oldDB := db
	testDB := setupTestDB_CB53(t)
	db = testDB
	defer func() {
		db = oldDB
		testDB.Close()
	}()

	token := generateTestToken(t, "user-53a")
	body := `{"endpoint":"","keys":{"p256dh":"","auth":""}}`
	req := httptest.NewRequest(http.MethodPost, "/push/web-subscribe", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleWebPushSubscribe(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected 400, got %d", w.Code)
	}
}

func TestCB53_HandleWebPushSubscribe_Success(t *testing.T) {
	oldDB := db
	testDB := setupTestDB_CB53(t)
	db = testDB
	defer func() {
		db = oldDB
		testDB.Close()
	}()

	token := generateTestToken(t, "user-53b")
	body := `{"endpoint":"https://push.example.com/subscribe/abc123","keys":{"p256dh":"p256dh-key-53b","auth":"auth-key-53b"}}`
	req := httptest.NewRequest(http.MethodPost, "/push/web-subscribe", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleWebPushSubscribe(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w.Code)
	}

	// Verify device token stored
	var count int
	testDB.QueryRow("SELECT COUNT(*) FROM device_tokens WHERE user_id = ? AND platform = 'web'", "user-53b").Scan(&count)
	if count != 1 {
		t.Errorf("Expected 1 web token, got %d", count)
	}
}

func TestCB53_HandleWebPushSubscribe_DBError(t *testing.T) {
	oldDB := db
	testDB := setupTestDB_CB53(t)
	db = testDB
	defer func() {
		db = oldDB
	}()

	token := generateTestToken(t, "user-53c")
	body := `{"endpoint":"https://push.example.com/subscribe/err","keys":{"p256dh":"p256dh-key","auth":"auth-key"}}`
	req := httptest.NewRequest(http.MethodPost, "/push/web-subscribe", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	testDB.Close()
	handleWebPushSubscribe(w, req)
	if w.Code != http.StatusInternalServerError {
		t.Errorf("Expected 500, got %d", w.Code)
	}
}

// =========================================================================
// handleWebPushUnsubscribe (push.go:480)
// =========================================================================

func TestCB53_HandleWebPushUnsubscribe_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/push/web-unsubscribe", nil)
	w := httptest.NewRecorder()
	handleWebPushUnsubscribe(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected 405, got %d", w.Code)
	}
}

func TestCB53_HandleWebPushUnsubscribe_Unauthorized(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/push/web-unsubscribe", strings.NewReader("{}"))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handleWebPushUnsubscribe(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected 401, got %d", w.Code)
	}
}

func TestCB53_HandleWebPushUnsubscribe_InvalidJSON(t *testing.T) {
	token := generateTestToken(t, "user-53d")
	req := httptest.NewRequest(http.MethodPost, "/push/web-unsubscribe", strings.NewReader("bad json"))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleWebPushUnsubscribe(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected 400, got %d", w.Code)
	}
}

func TestCB53_HandleWebPushUnsubscribe_MissingEndpoint(t *testing.T) {
	token := generateTestToken(t, "user-53e")
	body := `{"endpoint":""}`
	req := httptest.NewRequest(http.MethodPost, "/push/web-unsubscribe", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleWebPushUnsubscribe(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected 400, got %d", w.Code)
	}
}

func TestCB53_HandleWebPushUnsubscribe_Success(t *testing.T) {
	oldDB := db
	testDB := setupTestDB_CB53(t)
	db = testDB
	defer func() {
		db = oldDB
		testDB.Close()
	}()

	// Insert a web push subscription first
	_, err := testDB.Exec("INSERT INTO device_tokens (user_id, device_token, platform, created_at) VALUES (?, ?, 'web', ?)",
		"user-53f", "https://push.example.com/subscribe/53f", time.Now())
	if err != nil {
		t.Fatalf("Failed to insert token: %v", err)
	}

	token := generateTestToken(t, "user-53f")
	body := `{"endpoint":"https://push.example.com/subscribe/53f"}`
	req := httptest.NewRequest(http.MethodPost, "/push/web-unsubscribe", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleWebPushUnsubscribe(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w.Code)
	}

	// Verify token removed
	var count int
	testDB.QueryRow("SELECT COUNT(*) FROM device_tokens WHERE user_id = ? AND platform = 'web'", "user-53f").Scan(&count)
	if count != 0 {
		t.Errorf("Expected 0 web tokens, got %d", count)
	}
}

// =========================================================================
// handleSearchMessages (handlers.go:544)
// =========================================================================

func TestCB53_HandleSearchMessages_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/messages/search?q=test", nil)
	w := httptest.NewRecorder()
	handleSearchMessages(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected 405, got %d", w.Code)
	}
}

func TestCB53_HandleSearchMessages_Unauthorized(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/messages/search?q=test", nil)
	w := httptest.NewRecorder()
	handleSearchMessages(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected 401, got %d", w.Code)
	}
}

func TestCB53_HandleSearchMessages_MissingQuery(t *testing.T) {
	token := generateTestToken(t, "user-53g")
	req := httptest.NewRequest(http.MethodGet, "/messages/search", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleSearchMessages(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected 400, got %d", w.Code)
	}
}

func TestCB53_HandleSearchMessages_Success(t *testing.T) {
	oldDB := db
	testDB := setupTestDB_CB53(t)
	db = testDB
	defer func() {
		db = oldDB
		testDB.Close()
	}()

	// Create conversation and a message
	_, err := testDB.Exec("INSERT INTO conversations (id, user_id, agent_id, created_at) VALUES (?, ?, ?, ?)",
		"conv-53s", "user-53s", "agent-53s", time.Now())
	if err != nil {
		t.Fatalf("Failed to insert conversation: %v", err)
	}
	_, err = testDB.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, created_at) VALUES (?, ?, 'user', 'user-53s', 'hello world test', ?)",
		"msg-53s", "conv-53s", time.Now())
	if err != nil {
		t.Fatalf("Failed to insert message: %v", err)
	}

	token := generateTestToken(t, "user-53s")
	req := httptest.NewRequest(http.MethodGet, "/messages/search?q=hello", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleSearchMessages(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w.Code)
	}

	var messages []StoredMessage
	json.NewDecoder(w.Body).Decode(&messages)
	if len(messages) != 1 {
		t.Errorf("Expected 1 message, got %d", len(messages))
	}
}

func TestCB53_HandleSearchMessages_WithLimit(t *testing.T) {
	oldDB := db
	testDB := setupTestDB_CB53(t)
	db = testDB
	defer func() {
		db = oldDB
		testDB.Close()
	}()

	// Create conversation and multiple messages
	_, err := testDB.Exec("INSERT INTO conversations (id, user_id, agent_id, created_at) VALUES (?, ?, ?, ?)",
		"conv-53sl", "user-53sl", "agent-53sl", time.Now())
	if err != nil {
		t.Fatalf("Failed to insert conversation: %v", err)
	}
	for i := 0; i < 5; i++ {
		_, err = testDB.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, created_at) VALUES (?, ?, 'user', 'user-53sl', 'test match', ?)",
			"msg-53sl-"+string(rune('a'+i)), "conv-53sl", time.Now().Add(time.Duration(i)*time.Second))
		if err != nil {
			t.Fatalf("Failed to insert message: %v", err)
		}
	}

	token := generateTestToken(t, "user-53sl")
	req := httptest.NewRequest(http.MethodGet, "/messages/search?q=test&limit=2", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleSearchMessages(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w.Code)
	}

	var messages []StoredMessage
	json.NewDecoder(w.Body).Decode(&messages)
	if len(messages) > 2 {
		t.Errorf("Expected at most 2 messages with limit, got %d", len(messages))
	}
}

func TestCB53_HandleSearchMessages_DBError(t *testing.T) {
	oldDB := db
	testDB := setupTestDB_CB53(t)
	db = testDB
	defer func() {
		db = oldDB
	}()

	token := generateTestToken(t, "user-53sde")
	req := httptest.NewRequest(http.MethodGet, "/messages/search?q=test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	testDB.Close()
	handleSearchMessages(w, req)
	if w.Code != http.StatusInternalServerError {
		t.Errorf("Expected 500, got %d", w.Code)
	}
}

// =========================================================================
// handleMarkRead (handlers.go:595)

// =========================================================================
// handleMarkRead (handlers.go:595)
// =========================================================================

func TestCB53_HandleMarkRead_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/conversations/mark-read", nil)
	w := httptest.NewRecorder()
	handleMarkRead(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected 405, got %d", w.Code)
	}
}

func TestCB53_HandleMarkRead_Unauthorized(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/conversations/mark-read", strings.NewReader("conversation_id=conv1"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handleMarkRead(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected 401, got %d", w.Code)
	}
}

func TestCB53_HandleMarkRead_MissingConvID(t *testing.T) {
	token := generateTestToken(t, "user-53h")
	req := httptest.NewRequest(http.MethodPost, "/conversations/mark-read", strings.NewReader(""))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleMarkRead(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected 400, got %d", w.Code)
	}
}

func TestCB53_HandleMarkRead_NotFound(t *testing.T) {
	oldDB := db
	testDB := setupTestDB_CB53(t)
	db = testDB
	defer func() {
		db = oldDB
		testDB.Close()
	}()

	token := generateTestToken(t, "user-53i")
	req := httptest.NewRequest(http.MethodPost, "/conversations/mark-read", strings.NewReader("conversation_id=nonexistent"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleMarkRead(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("Expected 404, got %d", w.Code)
	}
}

func TestCB53_HandleMarkRead_Success(t *testing.T) {
	oldDB := db
	oldHub := hub
	testDB := setupTestDB_CB53(t)
	db = testDB
	hub = newHub()
	defer func() {
		db = oldDB
		hub = oldHub
		testDB.Close()
	}()

	// Create conversation with an unread agent message
	_, err := testDB.Exec("INSERT INTO conversations (id, user_id, agent_id, created_at) VALUES (?, ?, ?, ?)",
		"conv-53mr", "user-53mr", "agent-53mr", time.Now())
	if err != nil {
		t.Fatalf("Failed to insert conversation: %v", err)
	}
	_, err = testDB.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, created_at) VALUES (?, ?, 'agent', 'agent-53mr', 'unread message', ?)",
		"msg-53mr", "conv-53mr", time.Now())
	if err != nil {
		t.Fatalf("Failed to insert message: %v", err)
	}

	token := generateTestToken(t, "user-53mr")
	req := httptest.NewRequest(http.MethodPost, "/conversations/mark-read", strings.NewReader("conversation_id=conv-53mr"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleMarkRead(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w.Code)
	}
}

func TestCB53_HandleMarkRead_DBError(t *testing.T) {
	oldDB := db
	testDB := setupTestDB_CB53(t)
	db = testDB
	defer func() {
		db = oldDB
	}()

	token := generateTestToken(t, "user-53mr-err")
	req := httptest.NewRequest(http.MethodPost, "/conversations/mark-read", strings.NewReader("conversation_id=conv-53mr-err"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	testDB.Close()
	handleMarkRead(w, req)
	if w.Code != http.StatusInternalServerError {
		t.Errorf("Expected 500, got %d", w.Code)
	}
}

// =========================================================================
// handleCreateConversation (handlers.go:671)
// =========================================================================

func TestCB53_HandleCreateConversation_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/conversations/create", nil)
	w := httptest.NewRecorder()
	handleCreateConversation(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected 405, got %d", w.Code)
	}
}

func TestCB53_HandleCreateConversation_Unauthorized(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/conversations/create", strings.NewReader("agent_id=agent1"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handleCreateConversation(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected 401, got %d", w.Code)
	}
}

func TestCB53_HandleCreateConversation_MissingAgentID(t *testing.T) {
	token := generateTestToken(t, "user-53j")
	req := httptest.NewRequest(http.MethodPost, "/conversations/create", strings.NewReader(""))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleCreateConversation(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected 400, got %d", w.Code)
	}
}

func TestCB53_HandleCreateConversation_Success(t *testing.T) {
	oldDB := db
	testDB := setupTestDB_CB53(t)
	db = testDB
	defer func() {
		db = oldDB
		testDB.Close()
	}()

	token := generateTestToken(t, "user-53k")
	req := httptest.NewRequest(http.MethodPost, "/conversations/create", strings.NewReader("agent_id=agent-53k"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleCreateConversation(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w.Code)
	}

	var result map[string]string
	json.NewDecoder(w.Body).Decode(&result)
	if result["conversation_id"] == "" {
		t.Error("Expected non-empty conversation_id")
	}
}

func TestCB53_HandleCreateConversation_DBError(t *testing.T) {
	oldDB := db
	testDB := setupTestDB_CB53(t)
	db = testDB
	defer func() {
		db = oldDB
	}()

	token := generateTestToken(t, "user-53k-err")
	req := httptest.NewRequest(http.MethodPost, "/conversations/create", strings.NewReader("agent_id=agent-53k-err"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	testDB.Close()
	handleCreateConversation(w, req)
	if w.Code != http.StatusInternalServerError {
		t.Errorf("Expected 500, got %d", w.Code)
	}
}

// =========================================================================
// handleListConversations (handlers.go:708)
// =========================================================================

func TestCB53_HandleListConversations_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/conversations/list", nil)
	w := httptest.NewRecorder()
	handleListConversations(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected 405, got %d", w.Code)
	}
}

func TestCB53_HandleListConversations_Unauthorized(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/conversations/list", nil)
	w := httptest.NewRecorder()
	handleListConversations(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected 401, got %d", w.Code)
	}
}

func TestCB53_HandleListConversations_Success(t *testing.T) {
	oldDB := db
	testDB := setupTestDB_CB53(t)
	db = testDB
	defer func() {
		db = oldDB
		testDB.Close()
	}()

	// Create conversations
	_, err := testDB.Exec("INSERT INTO conversations (id, user_id, agent_id, created_at) VALUES (?, ?, ?, ?)",
		"conv-53l1", "user-53l", "agent-53l1", time.Now())
	if err != nil {
		t.Fatalf("Failed to insert conversation: %v", err)
	}
	_, err = testDB.Exec("INSERT INTO conversations (id, user_id, agent_id, created_at) VALUES (?, ?, ?, ?)",
		"conv-53l2", "user-53l", "agent-53l2", time.Now().Add(time.Second))
	if err != nil {
		t.Fatalf("Failed to insert conversation: %v", err)
	}

	token := generateTestToken(t, "user-53l")
	req := httptest.NewRequest(http.MethodGet, "/conversations/list", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleListConversations(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w.Code)
	}

	var result []map[string]interface{}
	json.NewDecoder(w.Body).Decode(&result)
	if len(result) != 2 {
		t.Errorf("Expected 2 conversations, got %d", len(result))
	}
}

func TestCB53_HandleListConversations_DBError(t *testing.T) {
	oldDB := db
	testDB := setupTestDB_CB53(t)
	db = testDB
	defer func() {
		db = oldDB
	}()

	token := generateTestToken(t, "user-53l-err")
	req := httptest.NewRequest(http.MethodGet, "/conversations/list", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	testDB.Close()
	handleListConversations(w, req)
	if w.Code != http.StatusInternalServerError {
		t.Errorf("Expected 500, got %d", w.Code)
	}
}

// =========================================================================
// handleGetMessages (handlers.go:791)
// =========================================================================

func TestCB53_HandleGetMessages_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/conversations/messages", nil)
	w := httptest.NewRecorder()
	handleGetMessages(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected 405, got %d", w.Code)
	}
}

func TestCB53_HandleGetMessages_Unauthorized(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/conversations/messages?conversation_id=conv1", nil)
	w := httptest.NewRecorder()
	handleGetMessages(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected 401, got %d", w.Code)
	}
}

func TestCB53_HandleGetMessages_MissingConvID(t *testing.T) {
	token := generateTestToken(t, "user-53m")
	req := httptest.NewRequest(http.MethodGet, "/conversations/messages", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleGetMessages(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected 400, got %d", w.Code)
	}
}

func TestCB53_HandleGetMessages_NotFound(t *testing.T) {
	oldDB := db
	testDB := setupTestDB_CB53(t)
	db = testDB
	defer func() {
		db = oldDB
		testDB.Close()
	}()

	token := generateTestToken(t, "user-53m")
	req := httptest.NewRequest(http.MethodGet, "/conversations/messages?conversation_id=nonexistent", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleGetMessages(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("Expected 404, got %d", w.Code)
	}
}

func TestCB53_HandleGetMessages_Success(t *testing.T) {
	oldDB := db
	testDB := setupTestDB_CB53(t)
	db = testDB
	defer func() {
		db = oldDB
		testDB.Close()
	}()

	// Create conversation and messages
	_, err := testDB.Exec("INSERT INTO conversations (id, user_id, agent_id, created_at) VALUES (?, ?, ?, ?)",
		"conv-53gm", "user-53gm", "agent-53gm", time.Now())
	if err != nil {
		t.Fatalf("Failed to insert conversation: %v", err)
	}
	_, err = testDB.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, created_at) VALUES (?, ?, 'user', 'user-53gm', 'hello', ?)",
		"msg-53gm1", "conv-53gm", time.Now())
	if err != nil {
		t.Fatalf("Failed to insert message: %v", err)
	}
	_, err = testDB.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, created_at) VALUES (?, ?, 'agent', 'agent-53gm', 'hi back', ?)",
		"msg-53gm2", "conv-53gm", time.Now().Add(time.Second))
	if err != nil {
		t.Fatalf("Failed to insert message: %v", err)
	}

	token := generateTestToken(t, "user-53gm")
	req := httptest.NewRequest(http.MethodGet, "/conversations/messages?conversation_id=conv-53gm", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleGetMessages(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w.Code)
	}

	var messages []StoredMessage
	json.NewDecoder(w.Body).Decode(&messages)
	if len(messages) != 2 {
		t.Errorf("Expected 2 messages, got %d", len(messages))
	}
}

func TestCB53_HandleGetMessages_UnauthorizedUser(t *testing.T) {
	oldDB := db
	testDB := setupTestDB_CB53(t)
	db = testDB
	defer func() {
		db = oldDB
		testDB.Close()
	}()

	_, err := testDB.Exec("INSERT INTO conversations (id, user_id, agent_id, created_at) VALUES (?, ?, ?, ?)",
		"conv-53gu", "user-53-owner", "agent-53gu", time.Now())
	if err != nil {
		t.Fatalf("Failed to insert conversation: %v", err)
	}

	token := generateTestToken(t, "user-53-wrong")
	req := httptest.NewRequest(http.MethodGet, "/conversations/messages?conversation_id=conv-53gu", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleGetMessages(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected 401, got %d", w.Code)
	}
}

// =========================================================================
// handleReact (reactions.go:102)
// =========================================================================

func TestCB53_HandleReact_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/messages/react", nil)
	w := httptest.NewRecorder()
	handleReact(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected 405, got %d", w.Code)
	}
}

func TestCB53_HandleReact_Unauthorized(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/messages/react", strings.NewReader("message_id=msg1&emoji=👍"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handleReact(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected 401, got %d", w.Code)
	}
}

func TestCB53_HandleReact_MissingFields(t *testing.T) {
	token := generateTestToken(t, "user-53n")
	req := httptest.NewRequest(http.MethodPost, "/messages/react", strings.NewReader(""))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleReact(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected 400, got %d", w.Code)
	}
}

func TestCB53_HandleReact_EmojiTooLong(t *testing.T) {
	token := generateTestToken(t, "user-53n")
	req := httptest.NewRequest(http.MethodPost, "/messages/react", strings.NewReader("message_id=msg1&emoji=verylongemoji"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleReact(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected 400, got %d", w.Code)
	}
}

func TestCB53_HandleReact_MessageNotFound(t *testing.T) {
	oldDB := db
	testDB := setupTestDB_CB53(t)
	db = testDB
	defer func() {
		db = oldDB
		testDB.Close()
	}()

	token := generateTestToken(t, "user-53o")
	req := httptest.NewRequest(http.MethodPost, "/messages/react", strings.NewReader("message_id=nonexistent&emoji=👍"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleReact(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("Expected 404, got %d", w.Code)
	}
}

func TestCB53_HandleReact_Success(t *testing.T) {
	oldDB := db
	oldHub := hub
	testDB := setupTestDB_CB53(t)
	db = testDB
	hub = newHub()
	defer func() {
		db = oldDB
		hub = oldHub
		testDB.Close()
	}()

	// Create conversation and message
	_, err := testDB.Exec("INSERT INTO conversations (id, user_id, agent_id, created_at) VALUES (?, ?, ?, ?)",
		"conv-53r", "user-53r", "agent-53r", time.Now())
	if err != nil {
		t.Fatalf("Failed to insert conversation: %v", err)
	}
	_, err = testDB.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, created_at) VALUES (?, ?, 'user', 'user-53r', 'react to me', ?)",
		"msg-53r", "conv-53r", time.Now())
	if err != nil {
		t.Fatalf("Failed to insert message: %v", err)
	}

	token := generateTestToken(t, "user-53r")
	req := httptest.NewRequest(http.MethodPost, "/messages/react", strings.NewReader("message_id=msg-53r&emoji=👍"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleReact(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w.Code)
	}

	var result map[string]interface{}
	json.NewDecoder(w.Body).Decode(&result)
	if result["status"] != "reaction_added" {
		t.Errorf("Expected reaction_added, got %v", result["status"])
	}
}

func TestCB53_HandleReact_ToggleOff(t *testing.T) {
	oldDB := db
	oldHub := hub
	testDB := setupTestDB_CB53(t)
	db = testDB
	hub = newHub()
	defer func() {
		db = oldDB
		hub = oldHub
		testDB.Close()
	}()

	_, err := testDB.Exec("INSERT INTO conversations (id, user_id, agent_id, created_at) VALUES (?, ?, ?, ?)",
		"conv-53rt", "user-53rt", "agent-53rt", time.Now())
	if err != nil {
		t.Fatalf("Failed to insert conversation: %v", err)
	}
	_, err = testDB.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, created_at) VALUES (?, ?, 'user', 'user-53rt', 'toggle me', ?)",
		"msg-53rt", "conv-53rt", time.Now())
	if err != nil {
		t.Fatalf("Failed to insert message: %v", err)
	}
	// Pre-insert a reaction
	_, err = testDB.Exec("INSERT INTO reactions (id, message_id, user_id, emoji, created_at) VALUES (?, ?, ?, ?, ?)",
		"rxn-53rt", "msg-53rt", "user-53rt", "👍", time.Now())
	if err != nil {
		t.Fatalf("Failed to insert reaction: %v", err)
	}

	token := generateTestToken(t, "user-53rt")
	req := httptest.NewRequest(http.MethodPost, "/messages/react", strings.NewReader("message_id=msg-53rt&emoji=👍"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleReact(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w.Code)
	}

	var result map[string]interface{}
	json.NewDecoder(w.Body).Decode(&result)
	if result["status"] != "reaction_removed" {
		t.Errorf("Expected reaction_removed, got %v", result["status"])
	}
}

func TestCB53_HandleReact_DBError(t *testing.T) {
	oldDB := db
	testDB := setupTestDB_CB53(t)
	db = testDB
	defer func() {
		db = oldDB
	}()

	token := generateTestToken(t, "user-53r-err")
	req := httptest.NewRequest(http.MethodPost, "/messages/react", strings.NewReader("message_id=msg-err&emoji=👍"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	testDB.Close()
	handleReact(w, req)
	if w.Code != http.StatusInternalServerError {
		t.Errorf("Expected 500, got %d", w.Code)
	}
}

// =========================================================================
// handleGetReactions (reactions.go:200)
// =========================================================================

func TestCB53_HandleGetReactions_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/messages/reactions", nil)
	w := httptest.NewRecorder()
	handleGetReactions(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected 405, got %d", w.Code)
	}
}

func TestCB53_HandleGetReactions_Unauthorized(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/messages/reactions?message_id=msg1", nil)
	w := httptest.NewRecorder()
	handleGetReactions(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected 401, got %d", w.Code)
	}
}

func TestCB53_HandleGetReactions_MissingMessageID(t *testing.T) {
	token := generateTestToken(t, "user-53p")
	req := httptest.NewRequest(http.MethodGet, "/messages/reactions", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleGetReactions(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected 400, got %d", w.Code)
	}
}

func TestCB53_HandleGetReactions_MessageNotFound(t *testing.T) {
	oldDB := db
	testDB := setupTestDB_CB53(t)
	db = testDB
	defer func() {
		db = oldDB
		testDB.Close()
	}()

	token := generateTestToken(t, "user-53p")
	req := httptest.NewRequest(http.MethodGet, "/messages/reactions?message_id=nonexistent", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleGetReactions(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("Expected 404, got %d", w.Code)
	}
}

func TestCB53_HandleGetReactions_Success(t *testing.T) {
	oldDB := db
	testDB := setupTestDB_CB53(t)
	db = testDB
	defer func() {
		db = oldDB
		testDB.Close()
	}()

	// Create conversation, message, and reaction
	_, err := testDB.Exec("INSERT INTO conversations (id, user_id, agent_id, created_at) VALUES (?, ?, ?, ?)",
		"conv-53gr", "user-53gr", "agent-53gr", time.Now())
	if err != nil {
		t.Fatalf("Failed to insert conversation: %v", err)
	}
	_, err = testDB.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, created_at) VALUES (?, ?, 'user', 'user-53gr', 'msg', ?)",
		"msg-53gr", "conv-53gr", time.Now())
	if err != nil {
		t.Fatalf("Failed to insert message: %v", err)
	}
	_, err = testDB.Exec("INSERT INTO reactions (id, message_id, user_id, emoji, created_at) VALUES (?, ?, ?, ?, ?)",
		"rxn-53gr", "msg-53gr", "user-53gr", "👍", time.Now())
	if err != nil {
		t.Fatalf("Failed to insert reaction: %v", err)
	}

	token := generateTestToken(t, "user-53gr")
	req := httptest.NewRequest(http.MethodGet, "/messages/reactions?message_id=msg-53gr", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleGetReactions(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w.Code)
	}

	var reactions []MessageReaction
	json.NewDecoder(w.Body).Decode(&reactions)
	if len(reactions) != 1 {
		t.Errorf("Expected 1 reaction, got %d", len(reactions))
	}
}

func TestCB53_HandleGetReactions_DBError(t *testing.T) {
	oldDB := db
	testDB := setupTestDB_CB53(t)
	db = testDB
	defer func() {
		db = oldDB
	}()

	token := generateTestToken(t, "user-53gr-err")
	req := httptest.NewRequest(http.MethodGet, "/messages/reactions?message_id=msg-err", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	testDB.Close()
	handleGetReactions(w, req)
	if w.Code != http.StatusInternalServerError {
		t.Errorf("Expected 500, got %d", w.Code)
	}
}

// =========================================================================
// handleAddTag (tags.go:117)
// =========================================================================

func TestCB53_HandleAddTag_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/conversations/tags/add", nil)
	w := httptest.NewRecorder()
	handleAddTag(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected 405, got %d", w.Code)
	}
}

func TestCB53_HandleAddTag_Unauthorized(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/conversations/tags/add", strings.NewReader("conversation_id=conv1&tag=test"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handleAddTag(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected 401, got %d", w.Code)
	}
}

func TestCB53_HandleAddTag_MissingFields(t *testing.T) {
	token := generateTestToken(t, "user-53t")
	req := httptest.NewRequest(http.MethodPost, "/conversations/tags/add", strings.NewReader(""))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleAddTag(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected 400, got %d", w.Code)
	}
}

func TestCB53_HandleAddTag_ConversationNotFound(t *testing.T) {
	oldDB := db
	testDB := setupTestDB_CB53(t)
	db = testDB
	defer func() {
		db = oldDB
		testDB.Close()
	}()

	token := generateTestToken(t, "user-53t")
	req := httptest.NewRequest(http.MethodPost, "/conversations/tags/add", strings.NewReader("conversation_id=nonexistent&tag=important"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleAddTag(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("Expected 404, got %d", w.Code)
	}
}

func TestCB53_HandleAddTag_Success(t *testing.T) {
	oldDB := db
	testDB := setupTestDB_CB53(t)
	db = testDB
	defer func() {
		db = oldDB
		testDB.Close()
	}()

	_, err := testDB.Exec("INSERT INTO conversations (id, user_id, agent_id, created_at) VALUES (?, ?, ?, ?)",
		"conv-53at", "user-53at", "agent-53at", time.Now())
	if err != nil {
		t.Fatalf("Failed to insert conversation: %v", err)
	}

	token := generateTestToken(t, "user-53at")
	req := httptest.NewRequest(http.MethodPost, "/conversations/tags/add", strings.NewReader("conversation_id=conv-53at&tag=important"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleAddTag(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w.Code)
	}

	// Verify tag stored
	var count int
	testDB.QueryRow("SELECT COUNT(*) FROM conversation_tags WHERE conversation_id = ? AND tag = ?", "conv-53at", "important").Scan(&count)
	if count != 1 {
		t.Errorf("Expected 1 tag, got %d", count)
	}
}

func TestCB53_HandleAddTag_Duplicate(t *testing.T) {
	oldDB := db
	testDB := setupTestDB_CB53(t)
	db = testDB
	defer func() {
		db = oldDB
		testDB.Close()
	}()

	_, err := testDB.Exec("INSERT INTO conversations (id, user_id, agent_id, created_at) VALUES (?, ?, ?, ?)",
		"conv-53dup", "user-53dup", "agent-53dup", time.Now())
	if err != nil {
		t.Fatalf("Failed to insert conversation: %v", err)
	}
	_, err = testDB.Exec("INSERT INTO conversation_tags (id, conversation_id, tag, created_at) VALUES (?, ?, ?, ?)",
		"tag-53dup", "conv-53dup", "important", time.Now())
	if err != nil {
		t.Fatalf("Failed to insert tag: %v", err)
	}

	token := generateTestToken(t, "user-53dup")
	req := httptest.NewRequest(http.MethodPost, "/conversations/tags/add", strings.NewReader("conversation_id=conv-53dup&tag=important"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleAddTag(w, req)
	if w.Code != http.StatusConflict {
		t.Errorf("Expected 409, got %d", w.Code)
	}
}

func TestCB53_HandleAddTag_UnauthorizedUser(t *testing.T) {
	oldDB := db
	testDB := setupTestDB_CB53(t)
	db = testDB
	defer func() {
		db = oldDB
		testDB.Close()
	}()

	_, err := testDB.Exec("INSERT INTO conversations (id, user_id, agent_id, created_at) VALUES (?, ?, ?, ?)",
		"conv-53au", "user-53-owner", "agent-53au", time.Now())
	if err != nil {
		t.Fatalf("Failed to insert conversation: %v", err)
	}

	token := generateTestToken(t, "user-53-wrong")
	req := httptest.NewRequest(http.MethodPost, "/conversations/tags/add", strings.NewReader("conversation_id=conv-53au&tag=test"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleAddTag(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected 401, got %d", w.Code)
	}
}

func TestCB53_HandleAddTag_DBError(t *testing.T) {
	oldDB := db
	testDB := setupTestDB_CB53(t)
	db = testDB
	defer func() {
		db = oldDB
	}()

	token := generateTestToken(t, "user-53at-err")
	req := httptest.NewRequest(http.MethodPost, "/conversations/tags/add", strings.NewReader("conversation_id=conv-err&tag=test"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	testDB.Close()
	handleAddTag(w, req)
	if w.Code != http.StatusInternalServerError {
		t.Errorf("Expected 500, got %d", w.Code)
	}
}

// =========================================================================
// handleRemoveTag (tags.go:167)
// =========================================================================

func TestCB53_HandleRemoveTag_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/conversations/tags/remove", nil)
	w := httptest.NewRecorder()
	handleRemoveTag(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected 405, got %d", w.Code)
	}
}

func TestCB53_HandleRemoveTag_Unauthorized(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/conversations/tags/remove", strings.NewReader("conversation_id=conv1&tag=test"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handleRemoveTag(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected 401, got %d", w.Code)
	}
}

func TestCB53_HandleRemoveTag_MissingFields(t *testing.T) {
	token := generateTestToken(t, "user-53u")
	req := httptest.NewRequest(http.MethodPost, "/conversations/tags/remove", strings.NewReader(""))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleRemoveTag(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected 400, got %d", w.Code)
	}
}

func TestCB53_HandleRemoveTag_ConversationNotFound(t *testing.T) {
	oldDB := db
	testDB := setupTestDB_CB53(t)
	db = testDB
	defer func() {
		db = oldDB
		testDB.Close()
	}()

	token := generateTestToken(t, "user-53u")
	req := httptest.NewRequest(http.MethodPost, "/conversations/tags/remove", strings.NewReader("conversation_id=nonexistent&tag=test"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleRemoveTag(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("Expected 404, got %d", w.Code)
	}
}

func TestCB53_HandleRemoveTag_TagNotFound(t *testing.T) {
	oldDB := db
	testDB := setupTestDB_CB53(t)
	db = testDB
	defer func() {
		db = oldDB
		testDB.Close()
	}()

	_, err := testDB.Exec("INSERT INTO conversations (id, user_id, agent_id, created_at) VALUES (?, ?, ?, ?)",
		"conv-53rt2", "user-53rt2", "agent-53rt2", time.Now())
	if err != nil {
		t.Fatalf("Failed to insert conversation: %v", err)
	}

	token := generateTestToken(t, "user-53rt2")
	req := httptest.NewRequest(http.MethodPost, "/conversations/tags/remove", strings.NewReader("conversation_id=conv-53rt2&tag=nonexistent"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleRemoveTag(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("Expected 404, got %d", w.Code)
	}
}

func TestCB53_HandleRemoveTag_Success(t *testing.T) {
	oldDB := db
	testDB := setupTestDB_CB53(t)
	db = testDB
	defer func() {
		db = oldDB
		testDB.Close()
	}()

	_, err := testDB.Exec("INSERT INTO conversations (id, user_id, agent_id, created_at) VALUES (?, ?, ?, ?)",
		"conv-53rm", "user-53rm", "agent-53rm", time.Now())
	if err != nil {
		t.Fatalf("Failed to insert conversation: %v", err)
	}
	_, err = testDB.Exec("INSERT INTO conversation_tags (id, conversation_id, tag, created_at) VALUES (?, ?, ?, ?)",
		"tag-53rm", "conv-53rm", "important", time.Now())
	if err != nil {
		t.Fatalf("Failed to insert tag: %v", err)
	}

	token := generateTestToken(t, "user-53rm")
	req := httptest.NewRequest(http.MethodPost, "/conversations/tags/remove", strings.NewReader("conversation_id=conv-53rm&tag=important"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleRemoveTag(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w.Code)
	}

	// Verify tag removed
	var count int
	testDB.QueryRow("SELECT COUNT(*) FROM conversation_tags WHERE conversation_id = ?", "conv-53rm").Scan(&count)
	if count != 0 {
		t.Errorf("Expected 0 tags after remove, got %d", count)
	}
}

func TestCB53_HandleRemoveTag_DBError(t *testing.T) {
	oldDB := db
	testDB := setupTestDB_CB53(t)
	db = testDB
	defer func() {
		db = oldDB
	}()

	token := generateTestToken(t, "user-53rm-err")
	req := httptest.NewRequest(http.MethodPost, "/conversations/tags/remove", strings.NewReader("conversation_id=conv-err&tag=test"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	testDB.Close()
	handleRemoveTag(w, req)
	if w.Code != http.StatusInternalServerError {
		t.Errorf("Expected 500, got %d", w.Code)
	}
}

// =========================================================================
// handleGetTags (tags.go:212)
// =========================================================================

func TestCB53_HandleGetTags_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/conversations/tags", nil)
	w := httptest.NewRecorder()
	handleGetTags(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected 405, got %d", w.Code)
	}
}

func TestCB53_HandleGetTags_Unauthorized(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/conversations/tags?conversation_id=conv1", nil)
	w := httptest.NewRecorder()
	handleGetTags(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected 401, got %d", w.Code)
	}
}

func TestCB53_HandleGetTags_MissingConvID(t *testing.T) {
	token := generateTestToken(t, "user-53v")
	req := httptest.NewRequest(http.MethodGet, "/conversations/tags", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleGetTags(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected 400, got %d", w.Code)
	}
}

func TestCB53_HandleGetTags_NotFound(t *testing.T) {
	oldDB := db
	testDB := setupTestDB_CB53(t)
	db = testDB
	defer func() {
		db = oldDB
		testDB.Close()
	}()

	token := generateTestToken(t, "user-53v")
	req := httptest.NewRequest(http.MethodGet, "/conversations/tags?conversation_id=nonexistent", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleGetTags(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected 401 (conv not found → unauthorized), got %d", w.Code)
	}
}

func TestCB53_HandleGetTags_Success(t *testing.T) {
	oldDB := db
	testDB := setupTestDB_CB53(t)
	db = testDB
	defer func() {
		db = oldDB
		testDB.Close()
	}()

	_, err := testDB.Exec("INSERT INTO conversations (id, user_id, agent_id, created_at) VALUES (?, ?, ?, ?)",
		"conv-53gt", "user-53gt", "agent-53gt", time.Now())
	if err != nil {
		t.Fatalf("Failed to insert conversation: %v", err)
	}
	_, err = testDB.Exec("INSERT INTO conversation_tags (id, conversation_id, tag, created_at) VALUES (?, ?, ?, ?)",
		"tag-53gt1", "conv-53gt", "important", time.Now())
	if err != nil {
		t.Fatalf("Failed to insert tag: %v", err)
	}
	_, err = testDB.Exec("INSERT INTO conversation_tags (id, conversation_id, tag, created_at) VALUES (?, ?, ?, ?)",
		"tag-53gt2", "conv-53gt", "work", time.Now().Add(time.Second))
	if err != nil {
		t.Fatalf("Failed to insert tag: %v", err)
	}

	token := generateTestToken(t, "user-53gt")
	req := httptest.NewRequest(http.MethodGet, "/conversations/tags?conversation_id=conv-53gt", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleGetTags(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w.Code)
	}

	var tags []ConversationTag
	json.NewDecoder(w.Body).Decode(&tags)
	if len(tags) != 2 {
		t.Errorf("Expected 2 tags, got %d", len(tags))
	}
}

func TestCB53_HandleGetTags_DBError(t *testing.T) {
	oldDB := db
	testDB := setupTestDB_CB53(t)
	db = testDB
	defer func() {
		db = oldDB
	}()

	token := generateTestToken(t, "user-53gt-err")
	req := httptest.NewRequest(http.MethodGet, "/conversations/tags?conversation_id=conv-err", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	testDB.Close()
	handleGetTags(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected 401 (db closed → conv nil → unauthorized), got %d", w.Code)
	}
}

// =========================================================================
// handleAdminProfile (profile_handler.go:22) - admin auth via middleware
// =========================================================================

func TestCB53_HandleAdminProfile_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodPut, "/admin/profile", nil)
	w := httptest.NewRecorder()
	handleAdminProfile(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected 405, got %d", w.Code)
	}
}

func TestCB53_HandleAdminProfile_DefaultStats(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/admin/profile", nil)
	w := httptest.NewRecorder()
	handleAdminProfile(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w.Code)
	}
}

func TestCB53_HandleAdminProfile_MemoryStats(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/admin/profile?action=stats", nil)
	w := httptest.NewRecorder()
	handleAdminProfile(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w.Code)
	}
}

func TestCB53_HandleAdminProfile_UnknownAction(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/admin/profile?action=unknown", nil)
	w := httptest.NewRecorder()
	handleAdminProfile(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected 400, got %d", w.Code)
	}
}

func TestCB53_HandleAdminProfile_PostWithJSON(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/admin/profile", strings.NewReader(`{"action":"stats"}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handleAdminProfile(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w.Code)
	}
}

// =========================================================================
// handleHeapProfile (profile_handler.go:57)
// =========================================================================

func TestCB53_HandleHeapProfile_Success(t *testing.T) {
	oldDir := os.Getenv("PROFILING_DIR")
	dir, _ := os.MkdirTemp("", "cb53-heap-*")
	os.Setenv("PROFILING_DIR", dir)
	defer func() {
		os.Setenv("PROFILING_DIR", oldDir)
		os.RemoveAll(dir)
	}()

	req := httptest.NewRequest(http.MethodPost, "/admin/profile?action=heap", nil)
	w := httptest.NewRecorder()
	handleHeapProfile(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w.Code)
	}
}

// =========================================================================
// handleGoroutineProfile (profile_handler.go:86)
// =========================================================================

func TestCB53_HandleGoroutineProfile_Success(t *testing.T) {
	oldDir := os.Getenv("PROFILING_DIR")
	dir, _ := os.MkdirTemp("", "cb53-goroutine-*")
	os.Setenv("PROFILING_DIR", dir)
	defer func() {
		os.Setenv("PROFILING_DIR", oldDir)
		os.RemoveAll(dir)
	}()

	req := httptest.NewRequest(http.MethodPost, "/admin/profile?action=goroutine", nil)
	w := httptest.NewRecorder()
	handleGoroutineProfile(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w.Code)
	}
}

// =========================================================================
// handleCPUProfileStart (profile_handler.go:122)
// =========================================================================

func TestCB53_HandleCPUProfileStart_Success(t *testing.T) {
	oldDir := os.Getenv("PROFILING_DIR")
	dir, _ := os.MkdirTemp("", "cb53-cpu-*")
	os.Setenv("PROFILING_DIR", dir)
	defer func() {
		os.Setenv("PROFILING_DIR", oldDir)
		os.RemoveAll(dir)
	}()

	// Reset CPU profile state
	cpuProfileState.Lock()
	cpuProfileState.active = false
	cpuProfileState.stopFunc = nil
	cpuProfileState.Unlock()

	req := httptest.NewRequest(http.MethodPost, "/admin/profile?action=cpu", nil)
	w := httptest.NewRecorder()
	handleCPUProfileStart(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w.Code)
	}

	// Stop profiling to clean up
	cpuProfileState.Lock()
	if cpuProfileState.active && cpuProfileState.stopFunc != nil {
		cpuProfileState.stopFunc()
		cpuProfileState.active = false
		cpuProfileState.stopFunc = nil
	}
	cpuProfileState.Unlock()
}

func TestCB53_HandleCPUProfileStart_AlreadyActive(t *testing.T) {
	// Reset and set active
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

	req := httptest.NewRequest(http.MethodPost, "/admin/profile?action=cpu", nil)
	w := httptest.NewRecorder()
	handleCPUProfileStart(w, req)
	if w.Code != http.StatusInternalServerError {
		t.Errorf("Expected 500, got %d", w.Code)
	}
}

// =========================================================================
// handleCPUProfileStop (profile_handler.go:162)
// =========================================================================

func TestCB53_HandleCPUProfileStop_NotActive(t *testing.T) {
	cpuProfileState.Lock()
	cpuProfileState.active = false
	cpuProfileState.stopFunc = nil
	cpuProfileState.Unlock()

	req := httptest.NewRequest(http.MethodPost, "/admin/profile?action=cpu_stop", nil)
	w := httptest.NewRecorder()
	handleCPUProfileStop(w, req)
	if w.Code != http.StatusInternalServerError {
		t.Errorf("Expected 500, got %d", w.Code)
	}
}

// =========================================================================
// handleForceGC (profile_handler.go:184)
// =========================================================================

func TestCB53_HandleForceGC_Success(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/admin/profile?action=gc", nil)
	w := httptest.NewRecorder()
	handleForceGC(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w.Code)
	}

	var result map[string]interface{}
	json.NewDecoder(w.Body).Decode(&result)
	if result["action"] != "gc" {
		t.Errorf("Expected action gc, got %v", result["action"])
	}
}

// =========================================================================
// handleMemoryStats (profile_handler.go:200)
// =========================================================================

func TestCB53_HandleMemoryStats_Success(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/admin/profile?action=stats", nil)
	w := httptest.NewRecorder()
	handleMemoryStats(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w.Code)
	}

	var result map[string]interface{}
	json.NewDecoder(w.Body).Decode(&result)
	if result["memory"] == nil {
		t.Error("Expected memory in response")
	}
}

// =========================================================================
// handleAdminRateLimitTier (rate_limit_tiers.go:422)
// =========================================================================

func TestCB53_HandleAdminRateLimitTier_Unauthorized(t *testing.T) {
	os.Setenv("ADMIN_SECRET", "test-admin-secret-53")
	defer os.Unsetenv("ADMIN_SECRET")
	resetAdminSecret()

	// POST without admin secret
	req := httptest.NewRequest(http.MethodPost, "/admin/rate-limit/tier", strings.NewReader("user_id=user1&tier=pro"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handleAdminRateLimitTier(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected 401, got %d", w.Code)
	}

	// GET without admin secret
	req2 := httptest.NewRequest(http.MethodGet, "/admin/rate-limit/tier?user_id=user1", nil)
	w2 := httptest.NewRecorder()
	handleAdminRateLimitTier(w2, req2)
	if w2.Code != http.StatusUnauthorized {
		t.Errorf("Expected 401, got %d", w2.Code)
	}
}

func TestCB53_HandleAdminRateLimitTier_PostSuccess(t *testing.T) {
	oldDB := db
	testDB := setupTestDB_CB53(t)
	db = testDB
	defer func() {
		db = oldDB
		testDB.Close()
	}()

	os.Setenv("ADMIN_SECRET", "test-admin-secret-53")
	defer os.Unsetenv("ADMIN_SECRET")
	resetAdminSecret()

	req := httptest.NewRequest(http.MethodPost, "/admin/rate-limit/tier", strings.NewReader("user_id=user-53rl&tier=pro"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Admin-Secret", "test-admin-secret-53")
	w := httptest.NewRecorder()
	handleAdminRateLimitTier(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w.Code)
	}

	var result map[string]string
	json.NewDecoder(w.Body).Decode(&result)
	if result["tier"] != "pro" {
		t.Errorf("Expected tier pro, got %v", result["tier"])
	}
}

func TestCB53_HandleAdminRateLimitTier_PostMissingFields(t *testing.T) {
	os.Setenv("ADMIN_SECRET", "test-admin-secret-53")
	defer os.Unsetenv("ADMIN_SECRET")
	resetAdminSecret()

	req := httptest.NewRequest(http.MethodPost, "/admin/rate-limit/tier", strings.NewReader(""))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Admin-Secret", "test-admin-secret-53")
	w := httptest.NewRecorder()
	handleAdminRateLimitTier(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected 400, got %d", w.Code)
	}
}

func TestCB53_HandleAdminRateLimitTier_PostUnknownTier(t *testing.T) {
	os.Setenv("ADMIN_SECRET", "test-admin-secret-53")
	defer os.Unsetenv("ADMIN_SECRET")
	resetAdminSecret()

	req := httptest.NewRequest(http.MethodPost, "/admin/rate-limit/tier", strings.NewReader("user_id=user1&tier=platinum"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Admin-Secret", "test-admin-secret-53")
	w := httptest.NewRecorder()
	handleAdminRateLimitTier(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected 400, got %d", w.Code)
	}
}

func TestCB53_HandleAdminRateLimitTier_GetSuccess(t *testing.T) {
	os.Setenv("ADMIN_SECRET", "test-admin-secret-53")
	defer os.Unsetenv("ADMIN_SECRET")
	resetAdminSecret()

	req := httptest.NewRequest(http.MethodGet, "/admin/rate-limit/tier?user_id=user-53rl-get", nil)
	req.Header.Set("X-Admin-Secret", "test-admin-secret-53")
	w := httptest.NewRecorder()
	handleAdminRateLimitTier(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w.Code)
	}

	var result map[string]interface{}
	json.NewDecoder(w.Body).Decode(&result)
	if result["tier"] == nil {
		t.Error("Expected tier in response")
	}
}

func TestCB53_HandleAdminRateLimitTier_GetMissingUserID(t *testing.T) {
	os.Setenv("ADMIN_SECRET", "test-admin-secret-53")
	defer os.Unsetenv("ADMIN_SECRET")
	resetAdminSecret()

	req := httptest.NewRequest(http.MethodGet, "/admin/rate-limit/tier", nil)
	req.Header.Set("X-Admin-Secret", "test-admin-secret-53")
	w := httptest.NewRecorder()
	handleAdminRateLimitTier(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected 400, got %d", w.Code)
	}
}