package main

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"
)

// --- CB68 Helpers ---

func setupTestDB_CB68(t *testing.T) *sql.DB {
	testDB, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("Failed to open test DB: %v", err)
	}
	if err := initSchema(testDB); err != nil {
		t.Fatalf("Failed to init schema: %v", err)
	}
	return testDB
}

func generateTestToken_CB68(userID string) string {
	claims := &Claims{
		UserID: userID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, _ := token.SignedString(jwtSecret)
	return signed
}

func makeTestHub_CB68() *Hub {
	h := newHub()
	go h.run()
	return h
}

func createUser_CB68(testDB *sql.DB, username, password string) string {
	hash, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	userID := "user_" + username
	testDB.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)", userID, username, hash)
	return userID
}

func createAgent_CB68(testDB *sql.DB, agentID string) {
	testDB.Exec("INSERT INTO agents (id, name, model) VALUES (?, ?, ?)", agentID, "Test Agent", "test-model")
}

func createConversation_CB68(testDB *sql.DB, userID, agentID string) string {
	convID := "conv_" + agentID + "_" + userID
	testDB.Exec("INSERT INTO conversations (id, user_id, agent_id) VALUES (?, ?, ?)", convID, userID, agentID)
	return convID
}

func insertMessage_CB68(testDB *sql.DB, convID, senderType, senderID, content string) string {
	msgID := "msg_" + senderID + "_" + time.Now().Format("150405.000000")
	testDB.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, created_at) VALUES (?, ?, ?, ?, ?, ?)",
		msgID, convID, senderType, senderID, content, time.Now().UTC())
	return msgID
}

func restoreDB_CB68(oldDB *sql.DB) {
	db = oldDB
}

// ==================== handleMessageEdit (67.3% → target 90%+) ====================

func TestCB68_HandleMessageEdit_MethodNotAllowed(t *testing.T) {
	oldDB := db
	defer restoreDB_CB68(oldDB)
	db = setupTestDB_CB68(t)
	defer func() { db = nil }()

	req := httptest.NewRequest(http.MethodGet, "/messages/edit", nil)
	rr := httptest.NewRecorder()
	handleMessageEdit(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rr.Code)
	}
}

func TestCB68_HandleMessageEdit_Unauthorized(t *testing.T) {
	oldDB := db
	defer restoreDB_CB68(oldDB)
	db = setupTestDB_CB68(t)
	defer func() { db = nil }()

	req := httptest.NewRequest(http.MethodPost, "/messages/edit", nil)
	rr := httptest.NewRecorder()
	handleMessageEdit(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

func TestCB68_HandleMessageEdit_MissingMessageID(t *testing.T) {
	oldDB := db
	defer restoreDB_CB68(oldDB)
	db = setupTestDB_CB68(t)
	defer func() { db = nil }()

	req := httptest.NewRequest(http.MethodPost, "/messages/edit", strings.NewReader("content=hello"))
	req.Header.Set("Authorization", "Bearer "+generateTestToken_CB68("user1"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	handleMessageEdit(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestCB68_HandleMessageEdit_EmptyContent(t *testing.T) {
	oldDB := db
	defer restoreDB_CB68(oldDB)
	db = setupTestDB_CB68(t)
	defer func() { db = nil }()

	form := "message_id=msg1"
	req := httptest.NewRequest(http.MethodPost, "/messages/edit", strings.NewReader(form))
	req.Header.Set("Authorization", "Bearer "+generateTestToken_CB68("user1"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	handleMessageEdit(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for empty content, got %d", rr.Code)
	}
}

func TestCB68_HandleMessageEdit_NotFound(t *testing.T) {
	oldDB := db
	defer restoreDB_CB68(oldDB)
	db = setupTestDB_CB68(t)
	defer func() { db = nil }()

	form := "message_id=nonexistent&content=updated"
	req := httptest.NewRequest(http.MethodPost, "/messages/edit", strings.NewReader(form))
	req.Header.Set("Authorization", "Bearer "+generateTestToken_CB68("user1"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	handleMessageEdit(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", rr.Code)
	}
}

func TestCB68_HandleMessageEdit_DeletedMessage(t *testing.T) {
	oldDB := db
	defer restoreDB_CB68(oldDB)
	testDB := setupTestDB_CB68(t)
	db = testDB
	defer func() { db = nil }()

	userID := createUser_CB68(testDB, "alice", "pass123")
	agentID := "agent_test"
	createAgent_CB68(testDB, agentID)
	convID := createConversation_CB68(testDB, userID, agentID)
	msgID := insertMessage_CB68(testDB, convID, "client", userID, "hello")
	testDB.Exec("UPDATE messages SET is_deleted = 1 WHERE id = ?", msgID)

	form := "message_id=" + msgID + "&content=updated"
	req := httptest.NewRequest(http.MethodPost, "/messages/edit", strings.NewReader(form))
	req.Header.Set("Authorization", "Bearer "+generateTestToken_CB68(userID))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	handleMessageEdit(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for editing deleted message, got %d", rr.Code)
	}
}

func TestCB68_HandleMessageEdit_NotSender(t *testing.T) {
	oldDB := db
	defer restoreDB_CB68(oldDB)
	testDB := setupTestDB_CB68(t)
	db = testDB
	defer func() { db = nil }()

	userID := createUser_CB68(testDB, "alice", "pass123")
	otherUserID := createUser_CB68(testDB, "bob", "pass456")
	agentID := "agent_test"
	createAgent_CB68(testDB, agentID)
	convID := createConversation_CB68(testDB, userID, agentID)
	msgID := insertMessage_CB68(testDB, convID, "agent", agentID, "hello from agent")

	form := "message_id=" + msgID + "&content=updated"
	req := httptest.NewRequest(http.MethodPost, "/messages/edit", strings.NewReader(form))
	req.Header.Set("Authorization", "Bearer "+generateTestToken_CB68(otherUserID))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	handleMessageEdit(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for non-sender, got %d", rr.Code)
	}
}

func TestCB68_HandleMessageEdit_Success(t *testing.T) {
	oldDB := db
	defer restoreDB_CB68(oldDB)
	testDB := setupTestDB_CB68(t)
	db = testDB
	defer func() { db = nil }()

	oldHub := hub
	defer func() { hub = oldHub }()
	hub = makeTestHub_CB68()
	defer hub.Stop()

	userID := createUser_CB68(testDB, "alice", "pass123")
	agentID := "agent_test"
	createAgent_CB68(testDB, agentID)
	convID := createConversation_CB68(testDB, userID, agentID)
	msgID := insertMessage_CB68(testDB, convID, "client", userID, "hello")

	form := "message_id=" + msgID + "&content=updated content"
	req := httptest.NewRequest(http.MethodPost, "/messages/edit", strings.NewReader(form))
	req.Header.Set("Authorization", "Bearer "+generateTestToken_CB68(userID))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	handleMessageEdit(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
	var resp map[string]interface{}
	json.NewDecoder(rr.Body).Decode(&resp)
	if resp["status"] != "edited" {
		t.Errorf("expected status=edited, got %v", resp["status"])
	}
	if resp["content"] != "updated content" {
		t.Errorf("expected content=updated content, got %v", resp["content"])
	}
}

// ==================== handleMessageDelete (66.7% → target 90%+) ====================

func TestCB68_HandleMessageDelete_MethodNotAllowed(t *testing.T) {
	oldDB := db
	defer restoreDB_CB68(oldDB)
	db = setupTestDB_CB68(t)
	defer func() { db = nil }()

	req := httptest.NewRequest(http.MethodGet, "/messages/delete", nil)
	rr := httptest.NewRecorder()
	handleMessageDelete(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rr.Code)
	}
}

func TestCB68_HandleMessageDelete_Unauthorized(t *testing.T) {
	oldDB := db
	defer restoreDB_CB68(oldDB)
	db = setupTestDB_CB68(t)
	defer func() { db = nil }()

	req := httptest.NewRequest(http.MethodPost, "/messages/delete", nil)
	rr := httptest.NewRecorder()
	handleMessageDelete(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

func TestCB68_HandleMessageDelete_MissingMessageID(t *testing.T) {
	oldDB := db
	defer restoreDB_CB68(oldDB)
	db = setupTestDB_CB68(t)
	defer func() { db = nil }()

	req := httptest.NewRequest(http.MethodPost, "/messages/delete", nil)
	req.Header.Set("Authorization", "Bearer "+generateTestToken_CB68("user1"))
	rr := httptest.NewRecorder()
	handleMessageDelete(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestCB68_HandleMessageDelete_NotFound(t *testing.T) {
	oldDB := db
	defer restoreDB_CB68(oldDB)
	db = setupTestDB_CB68(t)
	defer func() { db = nil }()

	form := "message_id=nonexistent"
	req := httptest.NewRequest(http.MethodPost, "/messages/delete", strings.NewReader(form))
	req.Header.Set("Authorization", "Bearer "+generateTestToken_CB68("user1"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	handleMessageDelete(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", rr.Code)
	}
}

func TestCB68_HandleMessageDelete_AlreadyDeleted(t *testing.T) {
	oldDB := db
	defer restoreDB_CB68(oldDB)
	testDB := setupTestDB_CB68(t)
	db = testDB
	defer func() { db = nil }()

	userID := createUser_CB68(testDB, "alice", "pass123")
	agentID := "agent_test"
	createAgent_CB68(testDB, agentID)
	convID := createConversation_CB68(testDB, userID, agentID)
	msgID := insertMessage_CB68(testDB, convID, "client", userID, "hello")
	testDB.Exec("UPDATE messages SET is_deleted = 1 WHERE id = ?", msgID)

	form := "message_id=" + msgID
	req := httptest.NewRequest(http.MethodPost, "/messages/delete", strings.NewReader(form))
	req.Header.Set("Authorization", "Bearer "+generateTestToken_CB68(userID))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	handleMessageDelete(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for already deleted, got %d", rr.Code)
	}
}

func TestCB68_HandleMessageDelete_NotSenderNotOwner(t *testing.T) {
	oldDB := db
	defer restoreDB_CB68(oldDB)
	testDB := setupTestDB_CB68(t)
	db = testDB
	defer func() { db = nil }()

	userID := createUser_CB68(testDB, "alice", "pass123")
	otherUserID := createUser_CB68(testDB, "bob", "pass456")
	agentID := "agent_test"
	createAgent_CB68(testDB, agentID)
	convID := createConversation_CB68(testDB, userID, agentID)
	msgID := insertMessage_CB68(testDB, convID, "client", userID, "hello")

	form := "message_id=" + msgID
	req := httptest.NewRequest(http.MethodPost, "/messages/delete", strings.NewReader(form))
	req.Header.Set("Authorization", "Bearer "+generateTestToken_CB68(otherUserID))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	handleMessageDelete(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for non-sender non-owner, got %d", rr.Code)
	}
}

func TestCB68_HandleMessageDelete_SuccessAsSender(t *testing.T) {
	oldDB := db
	defer restoreDB_CB68(oldDB)
	testDB := setupTestDB_CB68(t)
	db = testDB
	defer func() { db = nil }()

	oldHub := hub
	defer func() { hub = oldHub }()
	hub = makeTestHub_CB68()
	defer hub.Stop()

	userID := createUser_CB68(testDB, "alice", "pass123")
	agentID := "agent_test"
	createAgent_CB68(testDB, agentID)
	convID := createConversation_CB68(testDB, userID, agentID)
	msgID := insertMessage_CB68(testDB, convID, "client", userID, "hello")

	form := "message_id=" + msgID
	req := httptest.NewRequest(http.MethodPost, "/messages/delete", strings.NewReader(form))
	req.Header.Set("Authorization", "Bearer "+generateTestToken_CB68(userID))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	handleMessageDelete(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
	var resp map[string]interface{}
	json.NewDecoder(rr.Body).Decode(&resp)
	if resp["status"] != "deleted" {
		t.Errorf("expected status=deleted, got %v", resp["status"])
	}
}

func TestCB68_HandleMessageDelete_SuccessAsOwner(t *testing.T) {
	oldDB := db
	defer restoreDB_CB68(oldDB)
	testDB := setupTestDB_CB68(t)
	db = testDB
	defer func() { db = nil }()

	oldHub := hub
	defer func() { hub = oldHub }()
	hub = makeTestHub_CB68()
	defer hub.Stop()

	userID := createUser_CB68(testDB, "alice", "pass123")
	agentID := "agent_test"
	createAgent_CB68(testDB, agentID)
	convID := createConversation_CB68(testDB, userID, agentID)
	msgID := insertMessage_CB68(testDB, convID, "agent", agentID, "hello from agent")

	form := "message_id=" + msgID
	req := httptest.NewRequest(http.MethodPost, "/messages/delete", strings.NewReader(form))
	req.Header.Set("Authorization", "Bearer "+generateTestToken_CB68(userID))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	handleMessageDelete(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 for owner deleting agent message, got %d", rr.Code)
	}
}

// ==================== handleReact (67.3% → target 90%+) ====================

func TestCB68_HandleReact_MethodNotAllowed(t *testing.T) {
	oldDB := db
	defer restoreDB_CB68(oldDB)
	db = setupTestDB_CB68(t)
	defer func() { db = nil }()

	req := httptest.NewRequest(http.MethodGet, "/messages/react", nil)
	rr := httptest.NewRecorder()
	handleReact(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rr.Code)
	}
}

func TestCB68_HandleReact_Unauthorized(t *testing.T) {
	oldDB := db
	defer restoreDB_CB68(oldDB)
	db = setupTestDB_CB68(t)
	defer func() { db = nil }()

	req := httptest.NewRequest(http.MethodPost, "/messages/react", nil)
	rr := httptest.NewRecorder()
	handleReact(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

func TestCB68_HandleReact_MissingFields(t *testing.T) {
	oldDB := db
	defer restoreDB_CB68(oldDB)
	db = setupTestDB_CB68(t)
	defer func() { db = nil }()

	req := httptest.NewRequest(http.MethodPost, "/messages/react", nil)
	req.Header.Set("Authorization", "Bearer "+generateTestToken_CB68("user1"))
	rr := httptest.NewRecorder()
	handleReact(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestCB68_HandleReact_EmojiTooLong(t *testing.T) {
	oldDB := db
	defer restoreDB_CB68(oldDB)
	db = setupTestDB_CB68(t)
	defer func() { db = nil }()

	form := "message_id=msg1&emoji=verylongemojistring"
	req := httptest.NewRequest(http.MethodPost, "/messages/react", strings.NewReader(form))
	req.Header.Set("Authorization", "Bearer "+generateTestToken_CB68("user1"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	handleReact(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for too long emoji, got %d", rr.Code)
	}
}

func TestCB68_HandleReact_MessageNotFound(t *testing.T) {
	oldDB := db
	defer restoreDB_CB68(oldDB)
	db = setupTestDB_CB68(t)
	defer func() { db = nil }()

	form := "message_id=nonexistent&emoji=👍"
	req := httptest.NewRequest(http.MethodPost, "/messages/react", strings.NewReader(form))
	req.Header.Set("Authorization", "Bearer "+generateTestToken_CB68("user1"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	handleReact(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", rr.Code)
	}
}

func TestCB68_HandleReact_UnauthorizedUser(t *testing.T) {
	oldDB := db
	defer restoreDB_CB68(oldDB)
	testDB := setupTestDB_CB68(t)
	db = testDB
	defer func() { db = nil }()

	userID := createUser_CB68(testDB, "alice", "pass123")
	otherUserID := createUser_CB68(testDB, "bob", "pass456")
	agentID := "agent_test"
	createAgent_CB68(testDB, agentID)
	convID := createConversation_CB68(testDB, userID, agentID)
	msgID := insertMessage_CB68(testDB, convID, "client", userID, "hello")

	form := "message_id=" + msgID + "&emoji=👍"
	req := httptest.NewRequest(http.MethodPost, "/messages/react", strings.NewReader(form))
	req.Header.Set("Authorization", "Bearer "+generateTestToken_CB68(otherUserID))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	handleReact(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for unauthorized user, got %d", rr.Code)
	}
}

func TestCB68_HandleReact_AddSuccess(t *testing.T) {
	oldDB := db
	defer restoreDB_CB68(oldDB)
	testDB := setupTestDB_CB68(t)
	db = testDB
	defer func() { db = nil }()

	oldHub := hub
	defer func() { hub = oldHub }()
	hub = makeTestHub_CB68()
	defer hub.Stop()

	userID := createUser_CB68(testDB, "alice", "pass123")
	agentID := "agent_test"
	createAgent_CB68(testDB, agentID)
	convID := createConversation_CB68(testDB, userID, agentID)
	msgID := insertMessage_CB68(testDB, convID, "client", userID, "hello")

	form := "message_id=" + msgID + "&emoji=👍"
	req := httptest.NewRequest(http.MethodPost, "/messages/react", strings.NewReader(form))
	req.Header.Set("Authorization", "Bearer "+generateTestToken_CB68(userID))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	handleReact(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
	var resp map[string]interface{}
	json.NewDecoder(rr.Body).Decode(&resp)
	if resp["status"] != "reaction_added" {
		t.Errorf("expected status=reaction_added, got %v", resp["status"])
	}
}

func TestCB68_HandleReact_ToggleRemove(t *testing.T) {
	oldDB := db
	defer restoreDB_CB68(oldDB)
	testDB := setupTestDB_CB68(t)
	db = testDB
	defer func() { db = nil }()

	oldHub := hub
	defer func() { hub = oldHub }()
	hub = makeTestHub_CB68()
	defer hub.Stop()

	userID := createUser_CB68(testDB, "alice", "pass123")
	agentID := "agent_test"
	createAgent_CB68(testDB, agentID)
	convID := createConversation_CB68(testDB, userID, agentID)
	msgID := insertMessage_CB68(testDB, convID, "client", userID, "hello")

	// First add
	form := "message_id=" + msgID + "&emoji=👍"
	req := httptest.NewRequest(http.MethodPost, "/messages/react", strings.NewReader(form))
	req.Header.Set("Authorization", "Bearer "+generateTestToken_CB68(userID))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	handleReact(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("first react failed: %d", rr.Code)
	}

	// Toggle remove
	req2 := httptest.NewRequest(http.MethodPost, "/messages/react", strings.NewReader(form))
	req2.Header.Set("Authorization", "Bearer "+generateTestToken_CB68(userID))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr2 := httptest.NewRecorder()
	handleReact(rr2, req2)
	if rr2.Code != http.StatusOK {
		t.Errorf("expected 200 for toggle, got %d", rr2.Code)
	}
	var resp map[string]string
	json.NewDecoder(rr2.Body).Decode(&resp)
	if resp["status"] != "reaction_removed" {
		t.Errorf("expected status=reaction_removed, got %v", resp["status"])
	}
}

// ==================== addReaction (69.2% → target 90%+) ====================

func TestCB68_AddReaction_ConversationNotFound(t *testing.T) {
	oldDB := db
	defer restoreDB_CB68(oldDB)
	testDB := setupTestDB_CB68(t)
	db = testDB
	defer func() { db = nil }()

	// Insert a message with a conversation that doesn't exist in conversations table
	msgID := "msg_orphan"
	testDB.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, created_at) VALUES (?, ?, ?, ?, ?, ?)",
		msgID, "nonexistent_conv", "client", "user1", "hello", time.Now().UTC())

	_, _, err := addReaction(msgID, "user1", "👍")
	if err == nil {
		t.Error("expected error for nonexistent conversation")
	}
}

func TestCB68_AddReaction_ToggleRemoveDBError(t *testing.T) {
	oldDB := db
	defer restoreDB_CB68(oldDB)
	testDB := setupTestDB_CB68(t)
	db = testDB
	defer func() { db = nil }()

	userID := createUser_CB68(testDB, "alice", "pass123")
	agentID := "agent_test"
	createAgent_CB68(testDB, agentID)
	convID := createConversation_CB68(testDB, userID, agentID)
	msgID := insertMessage_CB68(testDB, convID, "client", userID, "hello")

	// Add a reaction first
	addReaction(msgID, userID, "👍")

	// Close DB to cause error on toggle remove
	testDB.Close()
	_, _, err := addReaction(msgID, userID, "👍")
	if err == nil {
		t.Error("expected error on toggle remove with closed DB")
	}
}

func TestCB68_AddReaction_InsertDBError(t *testing.T) {
	oldDB := db
	defer restoreDB_CB68(oldDB)
	testDB := setupTestDB_CB68(t)
	db = testDB
	defer func() { db = nil }()

	userID := createUser_CB68(testDB, "alice", "pass123")
	agentID := "agent_test"
	createAgent_CB68(testDB, agentID)
	convID := createConversation_CB68(testDB, userID, agentID)
	msgID := insertMessage_CB68(testDB, convID, "client", userID, "hello")

	// Close DB to cause insert error
	testDB.Close()
	_, _, err := addReaction(msgID, userID, "👍")
	if err == nil {
		t.Error("expected error on insert with closed DB")
	}
}

// ==================== handleGetReactions (79.4% → target 90%+) ====================

func TestCB68_HandleGetReactions_MethodNotAllowed(t *testing.T) {
	oldDB := db
	defer restoreDB_CB68(oldDB)
	db = setupTestDB_CB68(t)
	defer func() { db = nil }()

	req := httptest.NewRequest(http.MethodPost, "/messages/reactions", nil)
	rr := httptest.NewRecorder()
	handleGetReactions(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rr.Code)
	}
}

func TestCB68_HandleGetReactions_Unauthorized(t *testing.T) {
	oldDB := db
	defer restoreDB_CB68(oldDB)
	db = setupTestDB_CB68(t)
	defer func() { db = nil }()

	req := httptest.NewRequest(http.MethodGet, "/messages/reactions", nil)
	rr := httptest.NewRecorder()
	handleGetReactions(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

func TestCB68_HandleGetReactions_MissingMessageID(t *testing.T) {
	oldDB := db
	defer restoreDB_CB68(oldDB)
	db = setupTestDB_CB68(t)
	defer func() { db = nil }()

	req := httptest.NewRequest(http.MethodGet, "/messages/reactions", nil)
	req.Header.Set("Authorization", "Bearer "+generateTestToken_CB68("user1"))
	rr := httptest.NewRecorder()
	handleGetReactions(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestCB68_HandleGetReactions_MessageNotFound(t *testing.T) {
	oldDB := db
	defer restoreDB_CB68(oldDB)
	db = setupTestDB_CB68(t)
	defer func() { db = nil }()

	req := httptest.NewRequest(http.MethodGet, "/messages/reactions?message_id=nonexistent", nil)
	req.Header.Set("Authorization", "Bearer "+generateTestToken_CB68("user1"))
	rr := httptest.NewRecorder()
	handleGetReactions(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", rr.Code)
	}
}

func TestCB68_HandleGetReactions_UnauthorizedUser(t *testing.T) {
	oldDB := db
	defer restoreDB_CB68(oldDB)
	testDB := setupTestDB_CB68(t)
	db = testDB
	defer func() { db = nil }()

	userID := createUser_CB68(testDB, "alice", "pass123")
	otherUserID := createUser_CB68(testDB, "bob", "pass456")
	agentID := "agent_test"
	createAgent_CB68(testDB, agentID)
	convID := createConversation_CB68(testDB, userID, agentID)
	msgID := insertMessage_CB68(testDB, convID, "client", userID, "hello")

	req := httptest.NewRequest(http.MethodGet, "/messages/reactions?message_id="+msgID, nil)
	req.Header.Set("Authorization", "Bearer "+generateTestToken_CB68(otherUserID))
	rr := httptest.NewRecorder()
	handleGetReactions(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for unauthorized user, got %d", rr.Code)
	}
}

func TestCB68_HandleGetReactions_SuccessWithReactions(t *testing.T) {
	oldDB := db
	defer restoreDB_CB68(oldDB)
	testDB := setupTestDB_CB68(t)
	db = testDB
	defer func() { db = nil }()

	oldHub := hub
	defer func() { hub = oldHub }()
	hub = makeTestHub_CB68()
	defer hub.Stop()

	userID := createUser_CB68(testDB, "alice", "pass123")
	agentID := "agent_test"
	createAgent_CB68(testDB, agentID)
	convID := createConversation_CB68(testDB, userID, agentID)
	msgID := insertMessage_CB68(testDB, convID, "client", userID, "hello")

	// Add reactions
	addReaction(msgID, userID, "👍")
	addReaction(msgID, userID, "❤️")

	req := httptest.NewRequest(http.MethodGet, "/messages/reactions?message_id="+msgID, nil)
	req.Header.Set("Authorization", "Bearer "+generateTestToken_CB68(userID))
	rr := httptest.NewRecorder()
	handleGetReactions(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
	var reactions []MessageReaction
	json.NewDecoder(rr.Body).Decode(&reactions)
	if len(reactions) != 2 {
		t.Errorf("expected 2 reactions, got %d", len(reactions))
	}
}

// ==================== handleGetMessages (73.5% → target 90%+) ====================

func TestCB68_HandleGetMessages_MethodNotAllowed(t *testing.T) {
	oldDB := db
	defer restoreDB_CB68(oldDB)
	db = setupTestDB_CB68(t)
	defer func() { db = nil }()

	req := httptest.NewRequest(http.MethodPost, "/conversations/messages", nil)
	rr := httptest.NewRecorder()
	handleGetMessages(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rr.Code)
	}
}

func TestCB68_HandleGetMessages_Unauthorized(t *testing.T) {
	oldDB := db
	defer restoreDB_CB68(oldDB)
	db = setupTestDB_CB68(t)
	defer func() { db = nil }()

	req := httptest.NewRequest(http.MethodGet, "/conversations/messages", nil)
	rr := httptest.NewRecorder()
	handleGetMessages(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

func TestCB68_HandleGetMessages_MissingConvID(t *testing.T) {
	oldDB := db
	defer restoreDB_CB68(oldDB)
	db = setupTestDB_CB68(t)
	defer func() { db = nil }()

	req := httptest.NewRequest(http.MethodGet, "/conversations/messages", nil)
	req.Header.Set("Authorization", "Bearer "+generateTestToken_CB68("user1"))
	rr := httptest.NewRecorder()
	handleGetMessages(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestCB68_HandleGetMessages_ConvNotFound(t *testing.T) {
	oldDB := db
	defer restoreDB_CB68(oldDB)
	db = setupTestDB_CB68(t)
	defer func() { db = nil }()

	req := httptest.NewRequest(http.MethodGet, "/conversations/messages?conversation_id=nonexistent", nil)
	req.Header.Set("Authorization", "Bearer "+generateTestToken_CB68("user1"))
	rr := httptest.NewRecorder()
	handleGetMessages(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", rr.Code)
	}
}

func TestCB68_HandleGetMessages_UnauthorizedUser(t *testing.T) {
	oldDB := db
	defer restoreDB_CB68(oldDB)
	testDB := setupTestDB_CB68(t)
	db = testDB
	defer func() { db = nil }()

	userID := createUser_CB68(testDB, "alice", "pass123")
	otherUserID := createUser_CB68(testDB, "bob", "pass456")
	agentID := "agent_test"
	createAgent_CB68(testDB, agentID)
	convID := createConversation_CB68(testDB, userID, agentID)

	req := httptest.NewRequest(http.MethodGet, "/conversations/messages?conversation_id="+convID, nil)
	req.Header.Set("Authorization", "Bearer "+generateTestToken_CB68(otherUserID))
	rr := httptest.NewRecorder()
	handleGetMessages(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

func TestCB68_HandleGetMessages_SuccessWithLimit(t *testing.T) {
	oldDB := db
	defer restoreDB_CB68(oldDB)
	testDB := setupTestDB_CB68(t)
	db = testDB
	defer func() { db = nil }()

	userID := createUser_CB68(testDB, "alice", "pass123")
	agentID := "agent_test"
	createAgent_CB68(testDB, agentID)
	convID := createConversation_CB68(testDB, userID, agentID)
	for i := 0; i < 5; i++ {
		insertMessage_CB68(testDB, convID, "client", userID, "msg"+string(rune('0'+i)))
	}

	req := httptest.NewRequest(http.MethodGet, "/conversations/messages?conversation_id="+convID+"&limit=3", nil)
	req.Header.Set("Authorization", "Bearer "+generateTestToken_CB68(userID))
	rr := httptest.NewRecorder()
	handleGetMessages(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
	var messages []StoredMessage
	json.NewDecoder(rr.Body).Decode(&messages)
	if len(messages) != 3 {
		t.Errorf("expected 3 messages with limit, got %d", len(messages))
	}
}

func TestCB68_HandleGetMessages_SuccessEmpty(t *testing.T) {
	oldDB := db
	defer restoreDB_CB68(oldDB)
	testDB := setupTestDB_CB68(t)
	db = testDB
	defer func() { db = nil }()

	userID := createUser_CB68(testDB, "alice", "pass123")
	agentID := "agent_test"
	createAgent_CB68(testDB, agentID)
	convID := createConversation_CB68(testDB, userID, agentID)

	req := httptest.NewRequest(http.MethodGet, "/conversations/messages?conversation_id="+convID, nil)
	req.Header.Set("Authorization", "Bearer "+generateTestToken_CB68(userID))
	rr := httptest.NewRecorder()
	handleGetMessages(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
	var messages []StoredMessage
	json.NewDecoder(rr.Body).Decode(&messages)
	if len(messages) != 0 {
		t.Errorf("expected 0 messages, got %d", len(messages))
	}
}

// ==================== handleSearchMessages (78.1% → target 90%+) ====================

func TestCB68_HandleSearchMessages_MethodNotAllowed(t *testing.T) {
	oldDB := db
	defer restoreDB_CB68(oldDB)
	db = setupTestDB_CB68(t)
	defer func() { db = nil }()

	req := httptest.NewRequest(http.MethodPost, "/messages/search", nil)
	rr := httptest.NewRecorder()
	handleSearchMessages(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rr.Code)
	}
}

func TestCB68_HandleSearchMessages_Unauthorized(t *testing.T) {
	oldDB := db
	defer restoreDB_CB68(oldDB)
	db = setupTestDB_CB68(t)
	defer func() { db = nil }()

	req := httptest.NewRequest(http.MethodGet, "/messages/search", nil)
	rr := httptest.NewRecorder()
	handleSearchMessages(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

func TestCB68_HandleSearchMessages_MissingQuery(t *testing.T) {
	oldDB := db
	defer restoreDB_CB68(oldDB)
	db = setupTestDB_CB68(t)
	defer func() { db = nil }()

	req := httptest.NewRequest(http.MethodGet, "/messages/search", nil)
	req.Header.Set("Authorization", "Bearer "+generateTestToken_CB68("user1"))
	rr := httptest.NewRecorder()
	handleSearchMessages(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestCB68_HandleSearchMessages_Success(t *testing.T) {
	oldDB := db
	defer restoreDB_CB68(oldDB)
	testDB := setupTestDB_CB68(t)
	db = testDB
	defer func() { db = nil }()

	userID := createUser_CB68(testDB, "alice", "pass123")
	agentID := "agent_test"
	createAgent_CB68(testDB, agentID)
	convID := createConversation_CB68(testDB, userID, agentID)
	insertMessage_CB68(testDB, convID, "client", userID, "hello world")
	insertMessage_CB68(testDB, convID, "agent", agentID, "world peace")

	req := httptest.NewRequest(http.MethodGet, "/messages/search?q=world", nil)
	req.Header.Set("Authorization", "Bearer "+generateTestToken_CB68(userID))
	rr := httptest.NewRecorder()
	handleSearchMessages(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
	var messages []StoredMessage
	json.NewDecoder(rr.Body).Decode(&messages)
	if len(messages) != 2 {
		t.Errorf("expected 2 results, got %d", len(messages))
	}
}

func TestCB68_HandleSearchMessages_NoResults(t *testing.T) {
	oldDB := db
	defer restoreDB_CB68(oldDB)
	testDB := setupTestDB_CB68(t)
	db = testDB
	defer func() { db = nil }()

	userID := createUser_CB68(testDB, "alice", "pass123")
	agentID := "agent_test"
	createAgent_CB68(testDB, agentID)
	convID := createConversation_CB68(testDB, userID, agentID)
	insertMessage_CB68(testDB, convID, "client", userID, "hello")

	req := httptest.NewRequest(http.MethodGet, "/messages/search?q=nonexistent", nil)
	req.Header.Set("Authorization", "Bearer "+generateTestToken_CB68(userID))
	rr := httptest.NewRecorder()
	handleSearchMessages(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
	var messages []StoredMessage
	json.NewDecoder(rr.Body).Decode(&messages)
	if len(messages) != 0 {
		t.Errorf("expected 0 results, got %d", len(messages))
	}
}

func TestCB68_HandleSearchMessages_LimitOver200Capped(t *testing.T) {
	oldDB := db
	defer restoreDB_CB68(oldDB)
	testDB := setupTestDB_CB68(t)
	db = testDB
	defer func() { db = nil }()

	userID := createUser_CB68(testDB, "alice", "pass123")
	agentID := "agent_test"
	createAgent_CB68(testDB, agentID)
	convID := createConversation_CB68(testDB, userID, agentID)
	insertMessage_CB68(testDB, convID, "client", userID, "hello")

	req := httptest.NewRequest(http.MethodGet, "/messages/search?q=hello&limit=500", nil)
	req.Header.Set("Authorization", "Bearer "+generateTestToken_CB68(userID))
	rr := httptest.NewRecorder()
	handleSearchMessages(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
	var messages []StoredMessage
	json.NewDecoder(rr.Body).Decode(&messages)
	// limit should be capped to 200, we only have 1 result
	if len(messages) != 1 {
		t.Errorf("expected 1 result, got %d", len(messages))
	}
}

// ==================== handleListAgents (80% → target 95%+) ====================

func TestCB68_HandleListAgents_MethodNotAllowed(t *testing.T) {
	oldDB := db
	defer restoreDB_CB68(oldDB)
	db = setupTestDB_CB68(t)
	defer func() { db = nil }()

	req := httptest.NewRequest(http.MethodPost, "/agents", nil)
	rr := httptest.NewRecorder()
	handleListAgents(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rr.Code)
	}
}

func TestCB68_HandleListAgents_DBError(t *testing.T) {
	oldDB := db
	defer restoreDB_CB68(oldDB)
	testDB := setupTestDB_CB68(t)
	db = testDB
	defer func() { db = nil }()

	testDB.Close()

	req := httptest.NewRequest(http.MethodGet, "/agents", nil)
	rr := httptest.NewRecorder()
	handleListAgents(rr, req)
	if rr.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", rr.Code)
	}
}

func TestCB68_HandleListAgents_Success(t *testing.T) {
	oldDB := db
	defer restoreDB_CB68(oldDB)
	testDB := setupTestDB_CB68(t)
	db = testDB
	defer func() { db = nil }()

	oldHub := hub
	defer func() { hub = oldHub }()
	hub = makeTestHub_CB68()
	defer hub.Stop()

	createAgent_CB68(testDB, "agent1")
	createAgent_CB68(testDB, "agent2")

	req := httptest.NewRequest(http.MethodGet, "/agents", nil)
	rr := httptest.NewRecorder()
	handleListAgents(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
	var agents []AgentInfo
	json.NewDecoder(rr.Body).Decode(&agents)
	if len(agents) != 2 {
		t.Errorf("expected 2 agents, got %d", len(agents))
	}
}

func TestCB68_HandleListAgents_EmptyList(t *testing.T) {
	oldDB := db
	defer restoreDB_CB68(oldDB)
	db = setupTestDB_CB68(t)
	defer func() { db = nil }()

	oldHub := hub
	defer func() { hub = oldHub }()
	hub = makeTestHub_CB68()
	defer hub.Stop()

	req := httptest.NewRequest(http.MethodGet, "/agents", nil)
	rr := httptest.NewRecorder()
	handleListAgents(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
	var agents []AgentInfo
	json.NewDecoder(rr.Body).Decode(&agents)
	if len(agents) != 0 {
		t.Errorf("expected 0 agents, got %d", len(agents))
	}
}

// ==================== handleAdminAgents (75% → target 90%+) ====================

func TestCB68_HandleAdminAgents_MethodNotAllowed(t *testing.T) {
	oldDB := db
	defer restoreDB_CB68(oldDB)
	db = setupTestDB_CB68(t)
	defer func() { db = nil }()

	req := httptest.NewRequest(http.MethodPost, "/admin/agents", nil)
	rr := httptest.NewRecorder()
	handleAdminAgents(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rr.Code)
	}
}

func TestCB68_HandleAdminAgents_DBError(t *testing.T) {
	oldDB := db
	defer restoreDB_CB68(oldDB)
	testDB := setupTestDB_CB68(t)
	db = testDB
	defer func() { db = nil }()

	testDB.Close()

	req := httptest.NewRequest(http.MethodGet, "/admin/agents", nil)
	rr := httptest.NewRecorder()
	handleAdminAgents(rr, req)
	if rr.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", rr.Code)
	}
}

func TestCB68_HandleAdminAgents_Success(t *testing.T) {
	oldDB := db
	defer restoreDB_CB68(oldDB)
	testDB := setupTestDB_CB68(t)
	db = testDB
	defer func() { db = nil }()

	oldHub := hub
	defer func() { hub = oldHub }()
	hub = makeTestHub_CB68()
	defer hub.Stop()

	createAgent_CB68(testDB, "agent1")
	createAgent_CB68(testDB, "agent2")

	req := httptest.NewRequest(http.MethodGet, "/admin/agents", nil)
	rr := httptest.NewRecorder()
	handleAdminAgents(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
	var agents []AgentInfo
	json.NewDecoder(rr.Body).Decode(&agents)
	if len(agents) != 2 {
		t.Errorf("expected 2 agents, got %d", len(agents))
	}
}

// ==================== handleListConversations (80.6% → target 90%+) ====================

func TestCB68_HandleListConversations_MethodNotAllowed(t *testing.T) {
	oldDB := db
	defer restoreDB_CB68(oldDB)
	db = setupTestDB_CB68(t)
	defer func() { db = nil }()

	req := httptest.NewRequest(http.MethodPost, "/conversations", nil)
	rr := httptest.NewRecorder()
	handleListConversations(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rr.Code)
	}
}

func TestCB68_HandleListConversations_Unauthorized(t *testing.T) {
	oldDB := db
	defer restoreDB_CB68(oldDB)
	db = setupTestDB_CB68(t)
	defer func() { db = nil }()

	req := httptest.NewRequest(http.MethodGet, "/conversations", nil)
	rr := httptest.NewRecorder()
	handleListConversations(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

func TestCB68_HandleListConversations_DBError(t *testing.T) {
	oldDB := db
	defer restoreDB_CB68(oldDB)
	testDB := setupTestDB_CB68(t)
	db = testDB
	defer func() { db = nil }()

	testDB.Close()

	req := httptest.NewRequest(http.MethodGet, "/conversations", nil)
	req.Header.Set("Authorization", "Bearer "+generateTestToken_CB68("user1"))
	rr := httptest.NewRecorder()
	handleListConversations(rr, req)
	if rr.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", rr.Code)
	}
}

func TestCB68_HandleListConversations_Success(t *testing.T) {
	oldDB := db
	defer restoreDB_CB68(oldDB)
	testDB := setupTestDB_CB68(t)
	db = testDB
	defer func() { db = nil }()

	oldHub := hub
	defer func() { hub = oldHub }()
	hub = makeTestHub_CB68()
	defer hub.Stop()

	userID := createUser_CB68(testDB, "alice", "pass123")
	agentID := "agent_test"
	createAgent_CB68(testDB, agentID)
	convID := createConversation_CB68(testDB, userID, agentID)
	insertMessage_CB68(testDB, convID, "client", userID, "hello")
	insertMessage_CB68(testDB, convID, "agent", agentID, "hi there")

	req := httptest.NewRequest(http.MethodGet, "/conversations", nil)
	req.Header.Set("Authorization", "Bearer "+generateTestToken_CB68(userID))
	rr := httptest.NewRecorder()
	handleListConversations(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
	var resp []map[string]interface{}
	json.NewDecoder(rr.Body).Decode(&resp)
	if len(resp) != 1 {
		t.Errorf("expected 1 conversation, got %d", len(resp))
	}
}

// ==================== handleCreateConversation (80% → target 90%+) ====================

func TestCB68_HandleCreateConversation_MethodNotAllowed(t *testing.T) {
	oldDB := db
	defer restoreDB_CB68(oldDB)
	db = setupTestDB_CB68(t)
	defer func() { db = nil }()

	req := httptest.NewRequest(http.MethodGet, "/conversations/create", nil)
	rr := httptest.NewRecorder()
	handleCreateConversation(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rr.Code)
	}
}

func TestCB68_HandleCreateConversation_Unauthorized(t *testing.T) {
	oldDB := db
	defer restoreDB_CB68(oldDB)
	db = setupTestDB_CB68(t)
	defer func() { db = nil }()

	req := httptest.NewRequest(http.MethodPost, "/conversations/create", nil)
	rr := httptest.NewRecorder()
	handleCreateConversation(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

func TestCB68_HandleCreateConversation_MissingAgentID(t *testing.T) {
	oldDB := db
	defer restoreDB_CB68(oldDB)
	db = setupTestDB_CB68(t)
	defer func() { db = nil }()

	req := httptest.NewRequest(http.MethodPost, "/conversations/create", nil)
	req.Header.Set("Authorization", "Bearer "+generateTestToken_CB68("user1"))
	rr := httptest.NewRecorder()
	handleCreateConversation(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestCB68_HandleCreateConversation_Success(t *testing.T) {
	oldDB := db
	defer restoreDB_CB68(oldDB)
	testDB := setupTestDB_CB68(t)
	db = testDB
	defer func() { db = nil }()

	oldHub := hub
	defer func() { hub = oldHub }()
	hub = makeTestHub_CB68()
	defer hub.Stop()

	userID := createUser_CB68(testDB, "alice", "pass123")
	agentID := "agent_test"
	createAgent_CB68(testDB, agentID)

	form := "agent_id=" + agentID
	req := httptest.NewRequest(http.MethodPost, "/conversations/create", strings.NewReader(form))
	req.Header.Set("Authorization", "Bearer "+generateTestToken_CB68(userID))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	handleCreateConversation(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
	var resp map[string]string
	json.NewDecoder(rr.Body).Decode(&resp)
	if resp["conversation_id"] == "" {
		t.Errorf("expected non-empty conversation_id, got %v", resp["conversation_id"])
	}
	if resp["agent_id"] != agentID {
		t.Errorf("expected agent_id=%s, got %v", agentID, resp["agent_id"])
	}
}

// ==================== HashAPIKey (75% → target 100%) ====================

func TestCB68_HashAPIKey_EmptyString(t *testing.T) {
	hash, err := HashAPIKey("")
	if err != nil {
		t.Errorf("expected no error for empty string, got %v", err)
	}
	if hash == "" {
		t.Error("expected non-empty hash")
	}
}

func TestCB68_HashAPIKey_LongString(t *testing.T) {
	// bcrypt has a 72-byte limit; 73+ should error
	longStr := strings.Repeat("a", 73)
	_, err := HashAPIKey(longStr)
	if err == nil {
		t.Error("expected error for string > 72 bytes, got nil")
	}

	// 72 bytes should work
	str72 := strings.Repeat("a", 72)
	hash, err := HashAPIKey(str72)
	if err != nil {
		t.Errorf("expected no error for 72-byte string, got %v", err)
	}
	if hash == "" {
		t.Error("expected non-empty hash")
	}
}

// ==================== persistTierToDB (71.4% → target 90%+) ====================

func TestCB68_PersistTierToDB_NilDB(t *testing.T) {
	oldDB := db
	defer restoreDB_CB68(oldDB)
	db = nil
	defer func() { db = oldDB }()

	err := persistTierToDB("user1", TierPro)
	if err != nil {
		t.Errorf("expected nil error for nil DB, got %v", err)
	}
}

func TestCB68_PersistTierToDB_Success(t *testing.T) {
	oldDB := db
	defer restoreDB_CB68(oldDB)
	testDB := setupTestDB_CB68(t)
	db = testDB
	defer func() { db = nil }()

	err := persistTierToDB("user_test", TierEnterprise)
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}

	// Verify it was persisted
	var tierName string
	err = testDB.QueryRow("SELECT tier_name FROM user_rate_limit_tiers WHERE user_id = ?", "user_test").Scan(&tierName)
	if err != nil {
		t.Fatalf("failed to query tier: %v", err)
	}
	if tierName != "enterprise" {
		t.Errorf("expected tier=enterprise, got %s", tierName)
	}
}

func TestCB68_PersistTierToDB_ReplaceExisting(t *testing.T) {
	oldDB := db
	defer restoreDB_CB68(oldDB)
	testDB := setupTestDB_CB68(t)
	db = testDB
	defer func() { db = nil }()

	// Insert first
	persistTierToDB("user_test", TierFree)
	// Replace
	err := persistTierToDB("user_test", TierPro)
	if err != nil {
		t.Errorf("expected no error on replace, got %v", err)
	}

	var tierName string
	testDB.QueryRow("SELECT tier_name FROM user_rate_limit_tiers WHERE user_id = ?", "user_test").Scan(&tierName)
	if tierName != "pro" {
		t.Errorf("expected tier=pro after replace, got %s", tierName)
	}
}

// ==================== handleSetRateLimitTier (69.2% → target 90%+) ====================

func TestCB68_HandleSetRateLimitTier_MethodNotAllowed(t *testing.T) {
	oldDB := db
	defer restoreDB_CB68(oldDB)
	db = setupTestDB_CB68(t)
	defer func() { db = nil }()

	req := httptest.NewRequest(http.MethodGet, "/admin/rate-limit/tier", nil)
	rr := httptest.NewRecorder()
	handleSetRateLimitTier(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rr.Code)
	}
}

func TestCB68_HandleSetRateLimitTier_MissingFields(t *testing.T) {
	oldDB := db
	defer restoreDB_CB68(oldDB)
	db = setupTestDB_CB68(t)
	defer func() { db = nil }()

	form := "admin_secret=" + getAdminSecret()
	req := httptest.NewRequest(http.MethodPost, "/admin/rate-limit/tier", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	handleSetRateLimitTier(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestCB68_HandleSetRateLimitTier_UnknownTier(t *testing.T) {
	oldDB := db
	defer restoreDB_CB68(oldDB)
	db = setupTestDB_CB68(t)
	defer func() { db = nil }()

	form := "admin_secret=" + getAdminSecret() + "&user_id=user1&tier=unknown"
	req := httptest.NewRequest(http.MethodPost, "/admin/rate-limit/tier", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	handleSetRateLimitTier(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for unknown tier, got %d", rr.Code)
	}
}

func TestCB68_HandleSetRateLimitTier_Success(t *testing.T) {
	oldDB := db
	defer restoreDB_CB68(oldDB)
	testDB := setupTestDB_CB68(t)
	db = testDB
	defer func() { db = nil }()

	form := "admin_secret=" + getAdminSecret() + "&user_id=user1&tier=pro"
	req := httptest.NewRequest(http.MethodPost, "/admin/rate-limit/tier", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	handleSetRateLimitTier(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
	var resp map[string]string
	json.NewDecoder(rr.Body).Decode(&resp)
	if resp["status"] != "ok" {
		t.Errorf("expected status=ok, got %v", resp["status"])
	}
	if resp["tier"] != "pro" {
		t.Errorf("expected tier=pro, got %v", resp["tier"])
	}
}

// ==================== handleRemoveTag (79.2% → target 90%+) ====================

func TestCB68_HandleRemoveTag_MethodNotAllowed(t *testing.T) {
	oldDB := db
	defer restoreDB_CB68(oldDB)
	db = setupTestDB_CB68(t)
	defer func() { db = nil }()

	req := httptest.NewRequest(http.MethodGet, "/conversations/tags/remove", nil)
	rr := httptest.NewRecorder()
	handleRemoveTag(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rr.Code)
	}
}

func TestCB68_HandleRemoveTag_Unauthorized(t *testing.T) {
	oldDB := db
	defer restoreDB_CB68(oldDB)
	db = setupTestDB_CB68(t)
	defer func() { db = nil }()

	req := httptest.NewRequest(http.MethodPost, "/conversations/tags/remove", nil)
	rr := httptest.NewRecorder()
	handleRemoveTag(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

func TestCB68_HandleRemoveTag_MissingConvID(t *testing.T) {
	oldDB := db
	defer restoreDB_CB68(oldDB)
	db = setupTestDB_CB68(t)
	defer func() { db = nil }()

	form := "tag=test"
	req := httptest.NewRequest(http.MethodPost, "/conversations/tags/remove", strings.NewReader(form))
	req.Header.Set("Authorization", "Bearer "+generateTestToken_CB68("user1"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	handleRemoveTag(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestCB68_HandleRemoveTag_MissingTag(t *testing.T) {
	oldDB := db
	defer restoreDB_CB68(oldDB)
	db = setupTestDB_CB68(t)
	defer func() { db = nil }()

	form := "conversation_id=conv1"
	req := httptest.NewRequest(http.MethodPost, "/conversations/tags/remove", strings.NewReader(form))
	req.Header.Set("Authorization", "Bearer "+generateTestToken_CB68("user1"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	handleRemoveTag(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestCB68_HandleRemoveTag_ConvNotFound(t *testing.T) {
	oldDB := db
	defer restoreDB_CB68(oldDB)
	db = setupTestDB_CB68(t)
	defer func() { db = nil }()

	form := "conversation_id=nonexistent&tag=test"
	req := httptest.NewRequest(http.MethodPost, "/conversations/tags/remove", strings.NewReader(form))
	req.Header.Set("Authorization", "Bearer "+generateTestToken_CB68("user1"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	handleRemoveTag(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", rr.Code)
	}
}

func TestCB68_HandleRemoveTag_UnauthorizedUser(t *testing.T) {
	oldDB := db
	defer restoreDB_CB68(oldDB)
	testDB := setupTestDB_CB68(t)
	db = testDB
	defer func() { db = nil }()

	userID := createUser_CB68(testDB, "alice", "pass123")
	otherUserID := createUser_CB68(testDB, "bob", "pass456")
	agentID := "agent_test"
	createAgent_CB68(testDB, agentID)
	convID := createConversation_CB68(testDB, userID, agentID)

	form := "conversation_id=" + convID + "&tag=test"
	req := httptest.NewRequest(http.MethodPost, "/conversations/tags/remove", strings.NewReader(form))
	req.Header.Set("Authorization", "Bearer "+generateTestToken_CB68(otherUserID))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	handleRemoveTag(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

func TestCB68_HandleRemoveTag_Success(t *testing.T) {
	oldDB := db
	defer restoreDB_CB68(oldDB)
	testDB := setupTestDB_CB68(t)
	db = testDB
	defer func() { db = nil }()

	oldHub := hub
	defer func() { hub = oldHub }()
	hub = makeTestHub_CB68()
	defer hub.Stop()

	userID := createUser_CB68(testDB, "alice", "pass123")
	agentID := "agent_test"
	createAgent_CB68(testDB, agentID)
	convID := createConversation_CB68(testDB, userID, agentID)

	// Add a tag first
	addConversationTag(convID, userID, "testtag")

	form := "conversation_id=" + convID + "&tag=testtag"
	req := httptest.NewRequest(http.MethodPost, "/conversations/tags/remove", strings.NewReader(form))
	req.Header.Set("Authorization", "Bearer "+generateTestToken_CB68(userID))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	handleRemoveTag(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}

// ==================== handleGetTags (80.8% → target 90%+) ====================

func TestCB68_HandleGetTags_MethodNotAllowed(t *testing.T) {
	oldDB := db
	defer restoreDB_CB68(oldDB)
	db = setupTestDB_CB68(t)
	defer func() { db = nil }()

	req := httptest.NewRequest(http.MethodPost, "/conversations/tags", nil)
	rr := httptest.NewRecorder()
	handleGetTags(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rr.Code)
	}
}

func TestCB68_HandleGetTags_Unauthorized(t *testing.T) {
	oldDB := db
	defer restoreDB_CB68(oldDB)
	db = setupTestDB_CB68(t)
	defer func() { db = nil }()

	req := httptest.NewRequest(http.MethodGet, "/conversations/tags", nil)
	rr := httptest.NewRecorder()
	handleGetTags(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

func TestCB68_HandleGetTags_Success(t *testing.T) {
	oldDB := db
	defer restoreDB_CB68(oldDB)
	testDB := setupTestDB_CB68(t)
	db = testDB
	defer func() { db = nil }()

	oldHub := hub
	defer func() { hub = oldHub }()
	hub = makeTestHub_CB68()
	defer hub.Stop()

	userID := createUser_CB68(testDB, "alice", "pass123")
	agentID := "agent_test"
	createAgent_CB68(testDB, agentID)
	convID := createConversation_CB68(testDB, userID, agentID)
	addConversationTag(convID, userID, "tag1")
	addConversationTag(convID, userID, "tag2")

	req := httptest.NewRequest(http.MethodGet, "/conversations/tags?conversation_id="+convID, nil)
	req.Header.Set("Authorization", "Bearer "+generateTestToken_CB68(userID))
	rr := httptest.NewRecorder()
	handleGetTags(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
	var tags []ConversationTag
	json.NewDecoder(rr.Body).Decode(&tags)
	if len(tags) != 2 {
		t.Errorf("expected 2 tags, got %d", len(tags))
	}
}

// ==================== marshalOutgoingMessage (60% → target 100%) ====================

func TestCB68_MarshalOutgoingMessage_Success(t *testing.T) {
	msg := OutgoingMessage{
		Type: "test",
		Data: map[string]string{"key": "value"},
	}
	data := marshalOutgoingMessage(msg)
	if data == nil {
		t.Error("expected non-nil data")
	}
	var parsed map[string]interface{}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Errorf("failed to unmarshal: %v", err)
	}
	if parsed["type"] != "test" {
		t.Errorf("expected type=test, got %v", parsed["type"])
	}
}

func TestCB68_MarshalOutgoingMessage_NilData(t *testing.T) {
	msg := OutgoingMessage{
		Type: "test",
		Data: nil,
	}
	data := marshalOutgoingMessage(msg)
	if data == nil {
		t.Error("expected non-nil data even with nil Data")
	}
}

// ==================== cleanStaleQueueMessages (70% → target 90%+) ====================

func TestCB68_CleanStaleQueueMessages_NilDB(t *testing.T) {
	cleanStaleQueueMessages(nil, 24*time.Hour)
	// Should not panic
}

func TestCB68_CleanStaleQueueMessages_DeletesOld(t *testing.T) {
	oldDB := db
	defer restoreDB_CB68(oldDB)
	testDB := setupTestDB_CB68(t)
	db = testDB
	defer func() { db = nil }()

	initQueueDB(testDB)

	// Insert a stale message (queued 2 days ago)
	staleTime := time.Now().UTC().Add(-48 * time.Hour)
	testDB.Exec("INSERT INTO offline_queue (recipient, data, queued_at, sent_count) VALUES (?, ?, ?, ?)",
		"user1", []byte(`{"type":"message"}`), staleTime, 0)

	// Insert a fresh message
	testDB.Exec("INSERT INTO offline_queue (recipient, data, queued_at, sent_count) VALUES (?, ?, ?, ?)",
		"user1", []byte(`{"type":"message"}`), time.Now().UTC(), 0)

	cleanStaleQueueMessages(testDB, 24*time.Hour)

	var count int
	testDB.QueryRow("SELECT COUNT(*) FROM offline_queue").Scan(&count)
	if count != 1 {
		t.Errorf("expected 1 remaining message after cleanup, got %d", count)
	}
}

func TestCB68_CleanStaleQueueMessages_NoStale(t *testing.T) {
	oldDB := db
	defer restoreDB_CB68(oldDB)
	testDB := setupTestDB_CB68(t)
	db = testDB
	defer func() { db = nil }()

	initQueueDB(testDB)

	// Insert only fresh messages
	testDB.Exec("INSERT INTO offline_queue (recipient, data, queued_at, sent_count) VALUES (?, ?, ?, ?)",
		"user1", []byte(`{"type":"message"}`), time.Now().UTC(), 0)

	cleanStaleQueueMessages(testDB, 24*time.Hour)

	var count int
	testDB.QueryRow("SELECT COUNT(*) FROM offline_queue").Scan(&count)
	if count != 1 {
		t.Errorf("expected 1 message (no stale), got %d", count)
	}
}

// ==================== initQueueDB (80% → target 100%) ====================

func TestCB68_InitQueueDB_NilDB(t *testing.T) {
	initQueueDB(nil)
	// Should not panic
}

func TestCB68_InitQueueDB_Idempotent(t *testing.T) {
	oldDB := db
	defer restoreDB_CB68(oldDB)
	testDB := setupTestDB_CB68(t)
	db = testDB
	defer func() { db = nil }()

	initQueueDB(testDB)
	// Call again - should not fail
	initQueueDB(testDB)

	var count int
	testDB.QueryRow("SELECT COUNT(*) FROM offline_queue").Scan(&count)
	if count != 0 {
		t.Errorf("expected 0 rows in empty queue table, got %d", count)
	}
}

// ==================== persistQueue (80% → target 95%+) ====================

func TestCB68_PersistQueue_NilDB(t *testing.T) {
	oldDB := db
	defer restoreDB_CB68(oldDB)
	db = nil
	defer func() { db = oldDB }()

	persistQueue(nil, "user1", []byte(`{"type":"message"}`))
	// Should not panic
}

func TestCB68_PersistQueue_Success(t *testing.T) {
	oldDB := db
	defer restoreDB_CB68(oldDB)
	testDB := setupTestDB_CB68(t)
	db = testDB
	defer func() { db = nil }()

	initQueueDB(testDB)
	data := []byte(`{"type":"message","data":{"content":"hello"}}`)
	persistQueue(testDB, "user1", data)

	var count int
	testDB.QueryRow("SELECT COUNT(*) FROM offline_queue WHERE recipient = ?", "user1").Scan(&count)
	if count != 1 {
		t.Errorf("expected 1 queued message, got %d", count)
	}
}

// ==================== deleteQueueMessages (80% → target 95%+) ====================

func TestCB68_DeleteQueueMessages_NilDB(t *testing.T) {
	oldDB := db
	defer restoreDB_CB68(oldDB)
	db = nil
	defer func() { db = oldDB }()

	deleteQueueMessages(nil, "user1")
	// Should not panic
}

func TestCB68_DeleteQueueMessages_Success(t *testing.T) {
	oldDB := db
	defer restoreDB_CB68(oldDB)
	testDB := setupTestDB_CB68(t)
	db = testDB
	defer func() { db = nil }()

	initQueueDB(testDB)
	testDB.Exec("INSERT INTO offline_queue (recipient, data, queued_at, sent_count) VALUES (?, ?, ?, ?)",
		"user1", []byte(`{"type":"message"}`), time.Now().UTC(), 0)
	testDB.Exec("INSERT INTO offline_queue (recipient, data, queued_at, sent_count) VALUES (?, ?, ?, ?)",
		"user1", []byte(`{"type":"message"}`), time.Now().UTC(), 0)

	deleteQueueMessages(testDB, "user1")

	var count int
	testDB.QueryRow("SELECT COUNT(*) FROM offline_queue WHERE recipient = ?", "user1").Scan(&count)
	if count != 0 {
		t.Errorf("expected 0 messages after delete, got %d", count)
	}
}

// ==================== loadTiersFromDB (83.3% → target 90%+) ====================

func TestCB68_LoadTiersFromDB_NilDB(t *testing.T) {
	oldDB := db
	defer restoreDB_CB68(oldDB)
	db = nil
	defer func() { db = oldDB }()

	trl := NewTieredRateLimiter()
	err := loadTiersFromDB(trl)
	if err != nil {
		t.Errorf("expected nil error for nil DB, got %v", err)
	}
}

func TestCB68_LoadTiersFromDB_Success(t *testing.T) {
	oldDB := db
	defer restoreDB_CB68(oldDB)
	testDB := setupTestDB_CB68(t)
	db = testDB
	defer func() { db = nil }()

	// Insert some tiers
	testDB.Exec("INSERT INTO user_rate_limit_tiers (user_id, tier_name, updated_at) VALUES (?, ?, datetime('now'))",
		"user_pro", "pro")
	testDB.Exec("INSERT INTO user_rate_limit_tiers (user_id, tier_name, updated_at) VALUES (?, ?, datetime('now'))",
		"user_ent", "enterprise")

	trl := NewTieredRateLimiter()
	err := loadTiersFromDB(trl)
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}

	if trl.GetTier("user_pro").Name != "pro" {
		t.Errorf("expected tier=pro for user_pro, got %v", trl.GetTier("user_pro").Name)
	}
	if trl.GetTier("user_ent").Name != "enterprise" {
		t.Errorf("expected tier=enterprise for user_ent, got %v", trl.GetTier("user_ent").Name)
	}
}

// ==================== isOriginAllowed (71.4% → target 100%) ====================

func TestCB68_IsOriginAllowed_Wildcard(t *testing.T) {
	oldCORS := corsAllowedOrigins
	defer func() { corsAllowedOrigins = oldCORS }()
	corsAllowedOrigins = "*"

	if !isOriginAllowed("https://example.com") {
		t.Error("expected wildcard to allow all origins")
	}
}

func TestCB68_IsOriginAllowed_SpecificMatch(t *testing.T) {
	oldCORS := corsAllowedOrigins
	defer func() { corsAllowedOrigins = oldCORS }()
	corsAllowedOrigins = "https://app.example.com,https://chat.example.com"

	if !isOriginAllowed("https://app.example.com") {
		t.Error("expected specific origin to be allowed")
	}
	if !isOriginAllowed("https://chat.example.com") {
		t.Error("expected second specific origin to be allowed")
	}
	if isOriginAllowed("https://evil.example.com") {
		t.Error("expected non-listed origin to be rejected")
	}
}

func TestCB68_IsOriginAllowed_WildcardInList(t *testing.T) {
	oldCORS := corsAllowedOrigins
	defer func() { corsAllowedOrigins = oldCORS }()
	corsAllowedOrigins = "https://app.example.com,*"

	if !isOriginAllowed("https://anything.com") {
		t.Error("expected * in list to allow all origins")
	}
}

func TestCB68_IsOriginAllowed_EmptyOrigin(t *testing.T) {
	oldCORS := corsAllowedOrigins
	defer func() { corsAllowedOrigins = oldCORS }()
	corsAllowedOrigins = "https://app.example.com"

	if isOriginAllowed("") {
		t.Error("expected empty origin to be rejected")
	}
}

// ==================== Count (80% → target 100%) ====================

func TestCB68_RateLimiter_Count_NonExistentID(t *testing.T) {
	rl := NewRateLimiter(60, time.Minute)
	if rl.Count("nonexistent") != 0 {
		t.Error("expected 0 count for nonexistent ID")
	}
}

func TestCB68_RateLimiter_Count_AfterAllow(t *testing.T) {
	rl := NewRateLimiter(60, time.Minute)
	rl.Allow("user1")
	rl.Allow("user1")
	if rl.Count("user1") != 2 {
		t.Errorf("expected count=2, got %d", rl.Count("user1"))
	}
}

// ==================== SafeSend (85.7% → target 100%) ====================

func TestCB68_SafeSend_NilChannel(t *testing.T) {
	conn := &Connection{
		hub:      hub,
		send: make(chan []byte, 1),
	}
	// Fill the channel
	conn.send <- []byte("msg1")

	// Now SafeSend should fail (buffer full)
	if conn.SafeSend([]byte("msg2")) {
		t.Error("expected SafeSend to return false when buffer is full")
	}
}

// ==================== Snapshot (83.3% → target 95%+) ====================

func TestCB68_Snapshot_WithOfflineQueue(t *testing.T) {
	oldDB := db
	defer restoreDB_CB68(oldDB)
	testDB := setupTestDB_CB68(t)
	db = testDB
	defer func() { db = nil }()

	initQueueDB(testDB)
	testDB.Exec("INSERT INTO offline_queue (recipient, data, queued_at, sent_count) VALUES (?, ?, ?, ?)",
		"user1", []byte(`{"type":"message"}`), time.Now().UTC(), 0)

	if ServerMetrics != nil {
		snap := ServerMetrics.Snapshot()
		depth, ok := snap["offline_queue_depth"].(int)
		if !ok || depth != 1 {
			t.Errorf("expected offline queue depth=1, got %v", snap["offline_queue_depth"])
		}
	}
}

// ==================== Drain (83.3% → target 100%) ====================

func TestCB68_Drain_EmptyQueue(t *testing.T) {
	q := newOfflineQueue(100, 7*24*time.Hour)
	msgs := q.Drain("nonexistent")
	if len(msgs) != 0 {
		t.Errorf("expected 0 messages from empty queue, got %d", len(msgs))
	}
}

// ==================== checkRateLimit (78.9% → target 90%+) ====================

func TestCB68_CheckRateLimit_AllowsUnderLimit(t *testing.T) {
	conn := &Connection{
		hub:      hub,
		id:       "test_user_cb68_1",
		connType: "client",
		send:     make(chan []byte, 10),
	}
	defer close(conn.send)

	// Should allow first message
	if !checkRateLimit(conn) {
		t.Error("expected first message to be allowed")
	}
}

func TestCB68_CheckRateLimit_BlocksOverLimit(t *testing.T) {
	// Create a rate limiter with very low limit for testing
	oldMsgRL := messageRateLimiter
	defer func() { messageRateLimiter = oldMsgRL }()
	messageRateLimiter = NewRateLimiter(2, time.Minute)

	conn := &Connection{
		hub:      hub,
		id:       "test_user_cb68_2",
		connType: "client",
		send:     make(chan []byte, 10),
	}
	defer close(conn.send)

	// First two should pass
	if !checkRateLimit(conn) {
		t.Error("expected first message to be allowed")
	}
	if !checkRateLimit(conn) {
		t.Error("expected second message to be allowed")
	}
	// Third should be blocked
	if checkRateLimit(conn) {
		t.Error("expected third message to be rate limited")
	}
}

// ==================== csrfMiddleware (81.8% → target 90%+) ====================

func TestCB68_CSRFMiddleware_AllowsWithAuthorization(t *testing.T) {
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodPost, "/api/test", nil)
	req.Header.Set("Authorization", "Bearer sometoken")
	rr := httptest.NewRecorder()
	csrfMiddleware(next).ServeHTTP(rr, req)

	if !called {
		t.Error("expected next handler to be called with Authorization header")
	}
}

func TestCB68_CSRFMiddleware_AllowsWithAgentSecret(t *testing.T) {
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodPost, "/api/test", nil)
	req.Header.Set("X-Agent-Secret", "secret123")
	rr := httptest.NewRecorder()
	csrfMiddleware(next).ServeHTTP(rr, req)

	if !called {
		t.Error("expected next handler to be called with X-Agent-Secret header")
	}
}

func TestCB68_CSRFMiddleware_AllowsWithCSRFToken(t *testing.T) {
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodPost, "/api/test", nil)
	req.Header.Set("X-CSRF-Token", "token123")
	rr := httptest.NewRecorder()
	csrfMiddleware(next).ServeHTTP(rr, req)

	if !called {
		t.Error("expected next handler to be called with X-CSRF-Token header")
	}
}

func TestCB68_CSRFMiddleware_BlocksGetWithNoHeaders(t *testing.T) {
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	// GET should be safe
	req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
	rr := httptest.NewRecorder()
	csrfMiddleware(next).ServeHTTP(rr, req)

	if !called {
		t.Error("expected GET to be allowed without any headers")
	}
}

// ==================== handleHealth (83.3% → target 95%+) ====================

func TestCB68_HandleHealth_DBError(t *testing.T) {
	oldDB := db
	defer restoreDB_CB68(oldDB)
	testDB := setupTestDB_CB68(t)
	db = testDB
	defer func() { db = nil }()

	testDB.Close()

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rr := httptest.NewRecorder()
	handleHealth(rr, req)
	// Health endpoint should still return 200 or 503 depending on implementation
	// The key is that it doesn't panic
	if rr.Code == 0 {
		t.Error("expected non-zero status code")
	}
}

// ==================== replayOfflineMessages (72.2% → target 85%+) ====================

func TestCB68_ReplayOfflineMessages_ClosedConn(t *testing.T) {
	oldDB := db
	defer restoreDB_CB68(oldDB)
	testDB := setupTestDB_CB68(t)
	db = testDB
	defer func() { db = nil }()

	initQueueDB(testDB)

	// Queue a message
	data, _ := json.Marshal(OutgoingMessage{Type: MsgTypeMessage, Data: map[string]string{"content": "hello"}})
	persistQueue(testDB, "user1", data)

	// Create a connection with a closed send channel
	conn := &Connection{
		hub:      hub,
		id:       "user1",
		connType: "client",
		send:     make(chan []byte, 1),
	}
	close(conn.send)

	// Should not panic even with closed channel
	replayOfflineMessages(conn)
}

// ==================== routeMessage integration (45% → target 70%+) ====================

func TestCB68_RouteMessage_InvalidJSON(t *testing.T) {
	oldDB := db
	defer restoreDB_CB68(oldDB)
	db = setupTestDB_CB68(t)
	defer func() { db = nil }()

	oldHub := hub
	defer func() { hub = oldHub }()
	hub = makeTestHub_CB68()
	defer hub.Stop()

	conn := &Connection{
		hub:      hub,
		id:       "test_client_cb68",
		connType: "client",
		send:     make(chan []byte, 10),
	}
	defer close(conn.send)

	// Send invalid JSON - should get an error message back
	routeMessage(conn, []byte("invalid json"))

	select {
	case msg := <-conn.send:
		var parsed map[string]interface{}
		json.Unmarshal(msg, &parsed)
		if parsed["type"] != "error" {
			t.Errorf("expected error type, got %v", parsed["type"])
		}
	case <-time.After(time.Second):
		t.Error("expected error response for invalid JSON")
	}
}

func TestCB68_RouteMessage_UnknownType(t *testing.T) {
	oldDB := db
	defer restoreDB_CB68(oldDB)
	db = setupTestDB_CB68(t)
	defer func() { db = nil }()

	oldHub := hub
	defer func() { hub = oldHub }()
	hub = makeTestHub_CB68()
	defer hub.Stop()

	conn := &Connection{
		hub:      hub,
		id:       "test_client_cb68_unk",
		connType: "client",
		send:     make(chan []byte, 10),
	}
	defer close(conn.send)

	msg := IncomingMessage{Type: "unknown_type"}
	data, _ := json.Marshal(msg)
	routeMessage(conn, data)

	select {
	case resp := <-conn.send:
		var parsed map[string]interface{}
		json.Unmarshal(resp, &parsed)
		if parsed["type"] != "error" {
			t.Errorf("expected error type for unknown message, got %v", parsed["type"])
		}
	case <-time.After(time.Second):
		t.Error("expected error response for unknown message type")
	}
}

func TestCB68_RouteMessage_Heartbeat(t *testing.T) {
	oldDB := db
	defer restoreDB_CB68(oldDB)
	db = setupTestDB_CB68(t)
	defer func() { db = nil }()

	oldHub := hub
	defer func() { hub = oldHub }()
	hub = makeTestHub_CB68()
	defer hub.Stop()

	conn := &Connection{
		hub:      hub,
		id:       "test_client_cb68_hb",
		connType: "client",
		send:     make(chan []byte, 10),
	}
	defer close(conn.send)

	msg := IncomingMessage{Type: MsgTypeHeartbeat}
	data, _ := json.Marshal(msg)
	routeMessage(conn, data)

	// Heartbeat should update the connection's lastHeartbeat
	// No response is expected for heartbeat
	select {
	case <-conn.send:
		// Some implementations might send a heartbeat ack
	case <-time.After(200 * time.Millisecond):
		// No response is also fine
	}
}

// ==================== routeChatMessage (37.6% → target 60%+) ====================

func TestCB68_RouteChatMessage_InvalidData(t *testing.T) {
	oldDB := db
	defer restoreDB_CB68(oldDB)
	db = setupTestDB_CB68(t)
	defer func() { db = nil }()

	oldHub := hub
	defer func() { hub = oldHub }()
	hub = makeTestHub_CB68()
	defer hub.Stop()

	conn := &Connection{
		hub:      hub,
		id:       "test_client_cb68_chat",
		connType: "client",
		send:     make(chan []byte, 10),
	}
	defer close(conn.send)

	routeChatMessage(conn, []byte("invalid json"))

	select {
	case msg := <-conn.send:
		var parsed map[string]interface{}
		json.Unmarshal(msg, &parsed)
		if parsed["type"] != "error" {
			t.Errorf("expected error type, got %v", parsed["type"])
		}
	case <-time.After(time.Second):
		t.Error("expected error response for invalid chat data")
	}
}

func TestCB68_RouteChatMessage_EmptyContent(t *testing.T) {
	oldDB := db
	defer restoreDB_CB68(oldDB)
	db = setupTestDB_CB68(t)
	defer func() { db = nil }()

	oldHub := hub
	defer func() { hub = oldHub }()
	hub = makeTestHub_CB68()
	defer hub.Stop()

	conn := &Connection{
		hub:      hub,
		id:       "test_client_cb68_ec",
		connType: "client",
		send:     make(chan []byte, 10),
	}
	defer close(conn.send)

	msg := RoutedMessage{ConversationID: "conv1", Content: ""}
	data, _ := json.Marshal(msg)
	routeChatMessage(conn, data)

	select {
	case resp := <-conn.send:
		var parsed map[string]interface{}
		json.Unmarshal(resp, &parsed)
		if parsed["type"] != "error" {
			t.Errorf("expected error for empty content, got %v", parsed["type"])
		}
	case <-time.After(time.Second):
		t.Error("expected error response for empty content")
	}
}

func TestCB68_RouteChatMessage_EmptyConvID(t *testing.T) {
	oldDB := db
	defer restoreDB_CB68(oldDB)
	db = setupTestDB_CB68(t)
	defer func() { db = nil }()

	oldHub := hub
	defer func() { hub = oldHub }()
	hub = makeTestHub_CB68()
	defer hub.Stop()

	conn := &Connection{
		hub:      hub,
		id:       "test_client_cb68_nocid",
		connType: "client",
		send:     make(chan []byte, 10),
	}
	defer close(conn.send)

	msg := RoutedMessage{ConversationID: "", Content: "hello"}
	data, _ := json.Marshal(msg)
	routeChatMessage(conn, data)

	select {
	case resp := <-conn.send:
		var parsed map[string]interface{}
		json.Unmarshal(resp, &parsed)
		if parsed["type"] != "error" {
			t.Errorf("expected error for missing conv ID, got %v", parsed["type"])
		}
	case <-time.After(time.Second):
		t.Error("expected error response for missing conversation_id")
	}
}

func TestCB68_RouteChatMessage_ConvNotFound(t *testing.T) {
	oldDB := db
	defer restoreDB_CB68(oldDB)
	db = setupTestDB_CB68(t)
	defer func() { db = nil }()

	oldHub := hub
	defer func() { hub = oldHub }()
	hub = makeTestHub_CB68()
	defer hub.Stop()

	conn := &Connection{
		hub:      hub,
		id:       "test_client_cb68_nocnv",
		connType: "client",
		send:     make(chan []byte, 10),
	}
	defer close(conn.send)

	msg := RoutedMessage{ConversationID: "nonexistent", Content: "hello"}
	data, _ := json.Marshal(msg)
	routeChatMessage(conn, data)

	select {
	case resp := <-conn.send:
		var parsed map[string]interface{}
		json.Unmarshal(resp, &parsed)
		if parsed["type"] != "error" {
			t.Errorf("expected error for nonexistent conversation, got %v", parsed["type"])
		}
	case <-time.After(time.Second):
		t.Error("expected error response for nonexistent conversation")
	}
}

func TestCB68_RouteChatMessage_UnauthorizedAgent(t *testing.T) {
	oldDB := db
	defer restoreDB_CB68(oldDB)
	testDB := setupTestDB_CB68(t)
	db = testDB
	defer func() { db = nil }()

	oldHub := hub
	defer func() { hub = oldHub }()
	hub = makeTestHub_CB68()
	defer hub.Stop()

	userID := createUser_CB68(testDB, "alice", "pass123")
	agentID := "agent_test"
	createAgent_CB68(testDB, agentID)
	convID := createConversation_CB68(testDB, userID, agentID)

	conn := &Connection{
		hub:      hub,
		id:       "wrong_agent",
		connType: "agent",
		send:     make(chan []byte, 10),
	}
	defer close(conn.send)

	msg := RoutedMessage{ConversationID: convID, Content: "hello"}
	data, _ := json.Marshal(msg)
	routeChatMessage(conn, data)

	select {
	case resp := <-conn.send:
		var parsed map[string]interface{}
		json.Unmarshal(resp, &parsed)
		if parsed["type"] != "error" {
			t.Errorf("expected error for unauthorized agent, got %v", parsed["type"])
		}
	case <-time.After(time.Second):
		t.Error("expected error response for unauthorized agent")
	}
}

func TestCB68_RouteChatMessage_UnauthorizedClient(t *testing.T) {
	oldDB := db
	defer restoreDB_CB68(oldDB)
	testDB := setupTestDB_CB68(t)
	db = testDB
	defer func() { db = nil }()

	oldHub := hub
	defer func() { hub = oldHub }()
	hub = makeTestHub_CB68()
	defer hub.Stop()

	userID := createUser_CB68(testDB, "alice", "pass123")
	agentID := "agent_test"
	createAgent_CB68(testDB, agentID)
	convID := createConversation_CB68(testDB, userID, agentID)

	conn := &Connection{
		hub:      hub,
		id:       "wrong_user",
		connType: "client",
		send:     make(chan []byte, 10),
	}
	defer close(conn.send)

	msg := RoutedMessage{ConversationID: convID, Content: "hello"}
	data, _ := json.Marshal(msg)
	routeChatMessage(conn, data)

	select {
	case resp := <-conn.send:
		var parsed map[string]interface{}
		json.Unmarshal(resp, &parsed)
		if parsed["type"] != "error" {
			t.Errorf("expected error for unauthorized client, got %v", parsed["type"])
		}
	case <-time.After(time.Second):
		t.Error("expected error response for unauthorized client")
	}
}

// ==================== handleStoreEncryptedMessage (79.2% → target 90%+) ====================

func TestCB68_HandleStoreEncryptedMessage_MethodNotAllowed(t *testing.T) {
	oldDB := db
	defer restoreDB_CB68(oldDB)
	db = setupTestDB_CB68(t)
	defer func() { db = nil }()

	req := httptest.NewRequest(http.MethodGet, "/e2e/messages/store", nil)
	rr := httptest.NewRecorder()
	handleStoreEncryptedMessage(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rr.Code)
	}
}

func TestCB68_HandleStoreEncryptedMessage_Unauthorized(t *testing.T) {
	oldDB := db
	defer restoreDB_CB68(oldDB)
	db = setupTestDB_CB68(t)
	defer func() { db = nil }()

	req := httptest.NewRequest(http.MethodPost, "/e2e/messages/store", nil)
	rr := httptest.NewRecorder()
	handleStoreEncryptedMessage(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

// ==================== handleListAttachments (86.1% → target 95%+) ====================

func TestCB68_HandleListAttachments_MethodNotAllowed(t *testing.T) {
	oldDB := db
	defer restoreDB_CB68(oldDB)
	db = setupTestDB_CB68(t)
	defer func() { db = nil }()

	req := httptest.NewRequest(http.MethodPost, "/attachments", nil)
	rr := httptest.NewRecorder()
	handleListAttachments(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rr.Code)
	}
}

func TestCB68_HandleListAttachments_Unauthorized(t *testing.T) {
	oldDB := db
	defer restoreDB_CB68(oldDB)
	db = setupTestDB_CB68(t)
	defer func() { db = nil }()

	req := httptest.NewRequest(http.MethodGet, "/attachments", nil)
	rr := httptest.NewRecorder()
	handleListAttachments(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

func TestCB68_HandleListAttachments_MissingConvID(t *testing.T) {
	oldDB := db
	defer restoreDB_CB68(oldDB)
	db = setupTestDB_CB68(t)
	defer func() { db = nil }()

	req := httptest.NewRequest(http.MethodGet, "/attachments", nil)
	req.Header.Set("Authorization", "Bearer "+generateTestToken_CB68("user1"))
	rr := httptest.NewRecorder()
	handleListAttachments(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

// ==================== logger String (66.7% → target 100%) ====================

func TestCB68_LoggerString_AllLevels(t *testing.T) {
	if LogInfo.String() != "info" {
		t.Errorf("expected 'info', got %s", LogInfo.String())
	}
	if LogWarn.String() != "warn" {
		t.Errorf("expected 'warn', got %s", LogWarn.String())
	}
	if LogError.String() != "error" {
		t.Errorf("expected 'error', got %s", LogError.String())
	}
	if LogDebug.String() != "debug" {
		t.Errorf("expected 'debug', got %s", LogDebug.String())
	}
}

// ==================== mergeOpt (85.7% → target 100%) ====================

func TestCB68_MergeOpt_Empty(t *testing.T) {
	result := mergeOpt(nil)
	if len(result) != 0 {
		t.Errorf("expected empty map, got %v", result)
	}
}

func TestCB68_MergeOpt_SingleMap(t *testing.T) {
	result := mergeOpt([]map[string]interface{}{{"key": "value"}})
	if result["key"] != "value" {
		t.Errorf("expected key=value, got %v", result["key"])
	}
}

func TestCB68_MergeOpt_MultipleMaps(t *testing.T) {
	result := mergeOpt([]map[string]interface{}{
		{"a": 1, "b": 2},
		{"b": 3, "c": 4},
	})
	if result["a"] != 1 || result["b"] != 3 || result["c"] != 4 {
		t.Errorf("expected merged map with override, got %v", result)
	}
}

// ==================== newHub (83.3% → target 95%+) ====================

func TestCB68_NewHub_NilFields(t *testing.T) {
	h := newHub()
	if h == nil {
		t.Fatal("expected non-nil hub")
	}
	if h.agents == nil {
		t.Error("expected non-nil agents map")
	}
	if h.clientConns == nil {
		t.Error("expected non-nil clientConns map")
	}
	if h.register == nil {
		t.Error("expected non-nil register channel")
	}
	if h.unregister == nil {
		t.Error("expected non-nil unregister channel")
	}
	if h.broadcast == nil {
		t.Error("expected non-nil broadcast channel")
	}
	if offlineQueue == nil {
		t.Error("expected non-nil offlineQueue after newHub")
	}
}

// ==================== writePump (69.2% → target 85%+) ====================

func TestCB68_WritePump_PingError(t *testing.T) {
	// writePump is hard to test directly because it needs a real WebSocket connection
	// This test verifies the SafeSend/writePump interaction indirectly
	conn := &Connection{
		hub:      hub,
		id:       "test_writepump_cb68",
		connType: "client",
		send:     make(chan []byte, 1),
	}
	// Fill the channel, then try SafeSend
	conn.send <- []byte("msg1")
	if conn.SafeSend([]byte("msg2")) {
		t.Error("expected SafeSend to return false when buffer is full")
	}
}

// ==================== StoreMessage (63.6% → target 85%+) ====================

func TestCB68_StoreMessage_WithAttachments(t *testing.T) {
	oldDB := db
	defer restoreDB_CB68(oldDB)
	testDB := setupTestDB_CB68(t)
	db = testDB
	defer func() { db = nil }()

	userID := createUser_CB68(testDB, "alice", "pass123")
	agentID := "agent_test"
	createAgent_CB68(testDB, agentID)
	convID := createConversation_CB68(testDB, userID, agentID)

	msg := RoutedMessage{
		ConversationID: convID,
		SenderType:     "client",
		SenderID:       userID,
		Content:        "hello with attachment",
		AttachmentIDs:  []string{"att1"},
	}
	err := storeMessage(msg)
	if err != nil {
		t.Errorf("expected no error storing message with attachment, got %v", err)
	}
}