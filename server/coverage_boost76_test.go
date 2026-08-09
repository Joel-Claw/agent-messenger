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

	"github.com/golang-jwt/jwt/v5"
	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"
)

// ==================== CB76 Helpers ====================

func setupTestDB_CB76(t *testing.T) *sql.DB {
	testDB, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("Failed to open test DB: %v", err)
	}
	if err := initSchema(testDB); err != nil {
		t.Fatalf("Failed to init schema: %v", err)
	}
	t.Cleanup(func() { testDB.Close() })

	return testDB
}

func generateTestToken_CB76(userID string) string {
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

func createUser_CB76(testDB *sql.DB, username, password string) string {
	hash, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	userID := "user_" + username
	testDB.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)", userID, username, hash)
	return userID
}

func createAgent_CB76(testDB *sql.DB, agentID string) {
	testDB.Exec("INSERT INTO agents (id, name, model) VALUES (?, ?, ?)", agentID, "Test Agent", "test-model")
}

func createConversation_CB76(testDB *sql.DB, userID, agentID string) string {
	convID := "conv_" + agentID + "_" + userID
	testDB.Exec("INSERT INTO conversations (id, user_id, agent_id) VALUES (?, ?, ?)", convID, userID, agentID)
	return convID
}

func createMessage_CB76(testDB *sql.DB, msgID, convID, senderType, senderID, content string) {
	testDB.Exec(
		"INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, created_at) VALUES (?, ?, ?, ?, ?, ?)",
		msgID, convID, senderType, senderID, content, time.Now().UTC().Format(time.RFC3339),
	)
}

func setupHub_CB76() *Hub {
	oldHub := hub
	hub = newHub()
	return oldHub
}

func restoreHub_CB76(oldHub *Hub) {
	if oldHub != nil {
		hub = oldHub
	}
}

// ==================== Tags: addConversationTag ====================

func TestCB76_AddConversationTag_Success(t *testing.T) {
	testDB := setupTestDB_CB76(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	userID := "user1"
	agentID := "agent1"
	createUser_CB76(testDB, "user1", "pass")
	createAgent_CB76(testDB, agentID)
	convID := createConversation_CB76(testDB, userID, agentID)

	tag, err := addConversationTag(convID, userID, "important")
	if err != nil {
		t.Fatalf("addConversationTag failed: %v", err)
	}
	if tag.Tag != "important" {
		t.Errorf("expected tag 'important', got '%s'", tag.Tag)
	}
	if tag.ID == "" {
		t.Error("expected non-empty tag ID")
	}
}

func TestCB76_AddConversationTag_NotFound(t *testing.T) {
	testDB := setupTestDB_CB76(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	_, err := addConversationTag("nonexistent", "user1", "tag1")
	if err == nil || err.Error() != "conversation not found" {
		t.Errorf("expected 'conversation not found', got %v", err)
	}
}

func TestCB76_AddConversationTag_Unauthorized(t *testing.T) {
	testDB := setupTestDB_CB76(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	userID := "user1"
	agentID := "agent1"
	createUser_CB76(testDB, "user1", "pass")
	createAgent_CB76(testDB, agentID)
	convID := createConversation_CB76(testDB, userID, agentID)

	_, err := addConversationTag(convID, "wronguser", "tag1")
	if err == nil || err.Error() != "unauthorized" {
		t.Errorf("expected 'unauthorized', got %v", err)
	}
}

func TestCB76_AddConversationTag_Duplicate(t *testing.T) {
	testDB := setupTestDB_CB76(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	userID := "user1"
	agentID := "agent1"
	createUser_CB76(testDB, "user1", "pass")
	createAgent_CB76(testDB, agentID)
	convID := createConversation_CB76(testDB, userID, agentID)

	_, _ = addConversationTag(convID, userID, "important")
	_, err := addConversationTag(convID, userID, "important")
	if err == nil || err.Error() != "tag already exists" {
		t.Errorf("expected 'tag already exists', got %v", err)
	}
}

func TestCB76_AddConversationTag_EmptyTag(t *testing.T) {
	testDB := setupTestDB_CB76(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	userID := "user1"
	agentID := "agent1"
	createUser_CB76(testDB, "user1", "pass")
	createAgent_CB76(testDB, agentID)
	convID := createConversation_CB76(testDB, userID, agentID)

	_, err := addConversationTag(convID, userID, "")
	if err == nil || err.Error() != "tag must be 1-50 characters" {
		t.Errorf("expected 'tag must be 1-50 characters', got %v", err)
	}
}

func TestCB76_AddConversationTag_LongTag(t *testing.T) {
	testDB := setupTestDB_CB76(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	userID := "user1"
	agentID := "agent1"
	createUser_CB76(testDB, "user1", "pass")
	createAgent_CB76(testDB, agentID)
	convID := createConversation_CB76(testDB, userID, agentID)

	longTag := strings.Repeat("a", 51)
	_, err := addConversationTag(convID, userID, longTag)
	if err == nil || err.Error() != "tag must be 1-50 characters" {
		t.Errorf("expected 'tag must be 1-50 characters', got %v", err)
	}
}

// ==================== Tags: removeConversationTag ====================

func TestCB76_RemoveConversationTag_Success(t *testing.T) {
	testDB := setupTestDB_CB76(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	userID := "user1"
	agentID := "agent1"
	createUser_CB76(testDB, "user1", "pass")
	createAgent_CB76(testDB, agentID)
	convID := createConversation_CB76(testDB, userID, agentID)

	_, _ = addConversationTag(convID, userID, "important")
	err := removeConversationTag(convID, userID, "important")
	if err != nil {
		t.Errorf("removeConversationTag failed: %v", err)
	}
}

func TestCB76_RemoveConversationTag_NotFound(t *testing.T) {
	testDB := setupTestDB_CB76(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	err := removeConversationTag("nonexistent", "user1", "tag1")
	if err == nil || err.Error() != "conversation not found" {
		t.Errorf("expected 'conversation not found', got %v", err)
	}
}

func TestCB76_RemoveConversationTag_Unauthorized(t *testing.T) {
	testDB := setupTestDB_CB76(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	userID := "user1"
	agentID := "agent1"
	createUser_CB76(testDB, "user1", "pass")
	createAgent_CB76(testDB, agentID)
	convID := createConversation_CB76(testDB, userID, agentID)

	_, _ = addConversationTag(convID, userID, "important")
	err := removeConversationTag(convID, "wronguser", "important")
	if err == nil || err.Error() != "unauthorized" {
		t.Errorf("expected 'unauthorized', got %v", err)
	}
}

func TestCB76_RemoveConversationTag_TagNotFound(t *testing.T) {
	testDB := setupTestDB_CB76(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	userID := "user1"
	agentID := "agent1"
	createUser_CB76(testDB, "user1", "pass")
	createAgent_CB76(testDB, agentID)
	convID := createConversation_CB76(testDB, userID, agentID)

	err := removeConversationTag(convID, userID, "nonexistent_tag")
	if err == nil || err.Error() != "tag not found" {
		t.Errorf("expected 'tag not found', got %v", err)
	}
}

func TestCB76_RemoveConversationTag_DBError(t *testing.T) {
	testDB := setupTestDB_CB76(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	userID := "user1"
	agentID := "agent1"
	createUser_CB76(testDB, "user1", "pass")
	createAgent_CB76(testDB, agentID)
	convID := createConversation_CB76(testDB, userID, agentID)

	testDB.Close()
	err := removeConversationTag(convID, userID, "tag1")
	if err == nil {
		t.Error("expected error on closed DB")
	}
}

// ==================== Tags: handleAddTag ====================

func TestCB76_HandleAddTag_Success(t *testing.T) {
	testDB := setupTestDB_CB76(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	userID := createUser_CB76(testDB, "user1", "pass")
	agentID := "agent1"
	createAgent_CB76(testDB, agentID)
	convID := createConversation_CB76(testDB, userID, agentID)

	token := generateTestToken_CB76(userID)
	form := "conversation_id=" + convID + "&tag=important"
	req := httptest.NewRequest("POST", "/conversations/tags/add", strings.NewReader(form))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handleAddTag(w, req)

	if w.Code != 200 {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCB76_HandleAddTag_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest("GET", "/conversations/tags/add", nil)
	w := httptest.NewRecorder()
	handleAddTag(w, req)

	if w.Code != 405 {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestCB76_HandleAddTag_Unauthorized(t *testing.T) {
	req := httptest.NewRequest("POST", "/conversations/tags/add", nil)
	w := httptest.NewRecorder()
	handleAddTag(w, req)

	if w.Code != 401 {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestCB76_HandleAddTag_MissingFields(t *testing.T) {
	testDB := setupTestDB_CB76(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	userID := createUser_CB76(testDB, "user1", "pass")
	token := generateTestToken_CB76(userID)

	req := httptest.NewRequest("POST", "/conversations/tags/add", strings.NewReader(""))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handleAddTag(w, req)

	if w.Code != 400 {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestCB76_HandleAddTag_ConvNotFound(t *testing.T) {
	testDB := setupTestDB_CB76(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	userID := createUser_CB76(testDB, "user1", "pass")
	token := generateTestToken_CB76(userID)

	form := "conversation_id=nonexistent&tag=test"
	req := httptest.NewRequest("POST", "/conversations/tags/add", strings.NewReader(form))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handleAddTag(w, req)

	if w.Code != 404 {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

func TestCB76_HandleAddTag_UnauthorizedUser(t *testing.T) {
	testDB := setupTestDB_CB76(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	userID := createUser_CB76(testDB, "user1", "pass")
	otherUserID := createUser_CB76(testDB, "user2", "pass")
	agentID := "agent1"
	createAgent_CB76(testDB, agentID)
	convID := createConversation_CB76(testDB, userID, agentID)

	token := generateTestToken_CB76(otherUserID)
	form := "conversation_id=" + convID + "&tag=test"
	req := httptest.NewRequest("POST", "/conversations/tags/add", strings.NewReader(form))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handleAddTag(w, req)

	if w.Code != 401 {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestCB76_HandleAddTag_Duplicate(t *testing.T) {
	testDB := setupTestDB_CB76(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	userID := createUser_CB76(testDB, "user1", "pass")
	agentID := "agent1"
	createAgent_CB76(testDB, agentID)
	convID := createConversation_CB76(testDB, userID, agentID)

	_, _ = addConversationTag(convID, userID, "important")

	token := generateTestToken_CB76(userID)
	form := "conversation_id=" + convID + "&tag=important"
	req := httptest.NewRequest("POST", "/conversations/tags/add", strings.NewReader(form))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handleAddTag(w, req)

	if w.Code != 409 {
		t.Errorf("expected 409, got %d", w.Code)
	}
}

func TestCB76_HandleAddTag_TagTooLong(t *testing.T) {
	testDB := setupTestDB_CB76(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	userID := createUser_CB76(testDB, "user1", "pass")
	agentID := "agent1"
	createAgent_CB76(testDB, agentID)
	convID := createConversation_CB76(testDB, userID, agentID)

	token := generateTestToken_CB76(userID)
	longTag := strings.Repeat("a", 51)
	form := "conversation_id=" + convID + "&tag=" + longTag
	req := httptest.NewRequest("POST", "/conversations/tags/add", strings.NewReader(form))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handleAddTag(w, req)

	if w.Code != 400 {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

// ==================== Tags: handleRemoveTag ====================

func TestCB76_HandleRemoveTag_Success(t *testing.T) {
	testDB := setupTestDB_CB76(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	userID := createUser_CB76(testDB, "user1", "pass")
	agentID := "agent1"
	createAgent_CB76(testDB, agentID)
	convID := createConversation_CB76(testDB, userID, agentID)

	_, _ = addConversationTag(convID, userID, "important")

	token := generateTestToken_CB76(userID)
	form := "conversation_id=" + convID + "&tag=important"
	req := httptest.NewRequest("POST", "/conversations/tags/remove", strings.NewReader(form))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handleRemoveTag(w, req)

	if w.Code != 200 {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestCB76_HandleRemoveTag_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest("GET", "/conversations/tags/remove", nil)
	w := httptest.NewRecorder()
	handleRemoveTag(w, req)

	if w.Code != 405 {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestCB76_HandleRemoveTag_Unauthorized(t *testing.T) {
	req := httptest.NewRequest("POST", "/conversations/tags/remove", nil)
	w := httptest.NewRecorder()
	handleRemoveTag(w, req)

	if w.Code != 401 {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestCB76_HandleRemoveTag_MissingFields(t *testing.T) {
	testDB := setupTestDB_CB76(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	userID := createUser_CB76(testDB, "user1", "pass")
	token := generateTestToken_CB76(userID)

	req := httptest.NewRequest("POST", "/conversations/tags/remove", strings.NewReader(""))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handleRemoveTag(w, req)

	if w.Code != 400 {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestCB76_HandleRemoveTag_ConvNotFound(t *testing.T) {
	testDB := setupTestDB_CB76(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	userID := createUser_CB76(testDB, "user1", "pass")
	token := generateTestToken_CB76(userID)

	form := "conversation_id=nonexistent&tag=test"
	req := httptest.NewRequest("POST", "/conversations/tags/remove", strings.NewReader(form))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handleRemoveTag(w, req)

	if w.Code != 404 {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

func TestCB76_HandleRemoveTag_TagNotFound(t *testing.T) {
	testDB := setupTestDB_CB76(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	userID := createUser_CB76(testDB, "user1", "pass")
	agentID := "agent1"
	createAgent_CB76(testDB, agentID)
	convID := createConversation_CB76(testDB, userID, agentID)

	token := generateTestToken_CB76(userID)
	form := "conversation_id=" + convID + "&tag=nonexistent"
	req := httptest.NewRequest("POST", "/conversations/tags/remove", strings.NewReader(form))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handleRemoveTag(w, req)

	if w.Code != 404 {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

func TestCB76_HandleRemoveTag_UnauthorizedUser(t *testing.T) {
	testDB := setupTestDB_CB76(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	userID := createUser_CB76(testDB, "user1", "pass")
	otherUserID := createUser_CB76(testDB, "user2", "pass")
	agentID := "agent1"
	createAgent_CB76(testDB, agentID)
	convID := createConversation_CB76(testDB, userID, agentID)

	token := generateTestToken_CB76(otherUserID)
	form := "conversation_id=" + convID + "&tag=test"
	req := httptest.NewRequest("POST", "/conversations/tags/remove", strings.NewReader(form))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handleRemoveTag(w, req)

	if w.Code != 401 {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

// ==================== Tags: getConversationTags ====================

func TestCB76_GetConversationTags_WithTags(t *testing.T) {
	testDB := setupTestDB_CB76(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	userID := "user1"
	agentID := "agent1"
	createUser_CB76(testDB, "user1", "pass")
	createAgent_CB76(testDB, agentID)
	convID := createConversation_CB76(testDB, userID, agentID)

	_, _ = addConversationTag(convID, userID, "alpha")
	_, _ = addConversationTag(convID, userID, "beta")

	tags, err := getConversationTags(convID)
	if err != nil {
		t.Fatalf("getConversationTags failed: %v", err)
	}
	if len(tags) != 2 {
		t.Errorf("expected 2 tags, got %d", len(tags))
	}
	// Should be ordered alphabetically
	if tags[0].Tag != "alpha" {
		t.Errorf("expected first tag 'alpha', got '%s'", tags[0].Tag)
	}
}

func TestCB76_GetConversationTags_Empty(t *testing.T) {
	testDB := setupTestDB_CB76(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	userID := "user1"
	agentID := "agent1"
	createUser_CB76(testDB, "user1", "pass")
	createAgent_CB76(testDB, agentID)
	convID := createConversation_CB76(testDB, userID, agentID)

	tags, err := getConversationTags(convID)
	if err != nil {
		t.Fatalf("getConversationTags failed: %v", err)
	}
	if len(tags) != 0 {
		t.Errorf("expected 0 tags, got %d", len(tags))
	}
}

func TestCB76_GetConversationTags_DBError(t *testing.T) {
	testDB := setupTestDB_CB76(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	testDB.Close()
	_, err := getConversationTags("someconv")
	if err == nil {
		t.Error("expected error on closed DB")
	}
}

// ==================== Reactions: addReaction ====================

func TestCB76_AddReaction_Success(t *testing.T) {
	testDB := setupTestDB_CB76(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	userID := "user1"
	agentID := "agent1"
	createUser_CB76(testDB, "user1", "pass")
	createAgent_CB76(testDB, agentID)
	convID := createConversation_CB76(testDB, userID, agentID)
	msgID := "msg1"
	createMessage_CB76(testDB, msgID, convID, "client", userID, "hello")

	reaction, added, err := addReaction(msgID, userID, "👍")
	if err != nil {
		t.Fatalf("addReaction failed: %v", err)
	}
	if !added {
		t.Error("expected added=true")
	}
	if reaction == nil {
		t.Error("expected non-nil reaction")
	}
	if reaction.Emoji != "👍" {
		t.Errorf("expected emoji '👍', got '%s'", reaction.Emoji)
	}
}

func TestCB76_AddReaction_MessageNotFound(t *testing.T) {
	testDB := setupTestDB_CB76(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	_, _, err := addReaction("nonexistent", "user1", "👍")
	if err == nil || err.Error() != "message not found" {
		t.Errorf("expected 'message not found', got %v", err)
	}
}

func TestCB76_AddReaction_ConvNotFound(t *testing.T) {
	testDB := setupTestDB_CB76(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	// Insert a message with a conversation_id that doesn't exist in conversations table
	testDB.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, created_at) VALUES (?, ?, ?, ?, ?, ?)",
		"msg1", "nonexistent_conv", "client", "user1", "hello", time.Now().UTC().Format(time.RFC3339))

	_, _, err := addReaction("msg1", "user1", "👍")
	if err == nil || err.Error() != "conversation not found" {
		t.Errorf("expected 'conversation not found', got %v", err)
	}
}

func TestCB76_AddReaction_Unauthorized(t *testing.T) {
	testDB := setupTestDB_CB76(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	userID := "user1"
	agentID := "agent1"
	createUser_CB76(testDB, "user1", "pass")
	createAgent_CB76(testDB, agentID)
	convID := createConversation_CB76(testDB, userID, agentID)
	msgID := "msg1"
	createMessage_CB76(testDB, msgID, convID, "client", userID, "hello")

	_, _, err := addReaction(msgID, "wronguser", "👍")
	if err == nil || err.Error() != "unauthorized" {
		t.Errorf("expected 'unauthorized', got %v", err)
	}
}

func TestCB76_AddReaction_ToggleRemove(t *testing.T) {
	testDB := setupTestDB_CB76(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	userID := "user1"
	agentID := "agent1"
	createUser_CB76(testDB, "user1", "pass")
	createAgent_CB76(testDB, agentID)
	convID := createConversation_CB76(testDB, userID, agentID)
	msgID := "msg1"
	createMessage_CB76(testDB, msgID, convID, "client", userID, "hello")

	// Add reaction
	_, added, err := addReaction(msgID, userID, "👍")
	if err != nil || !added {
		t.Fatalf("first addReaction failed: %v, added=%v", err, added)
	}

	// Toggle remove
	_, added2, err2 := addReaction(msgID, userID, "👍")
	if err2 != nil {
		t.Fatalf("toggle remove failed: %v", err2)
	}
	if added2 {
		t.Error("expected added=false on toggle remove")
	}
}

func TestCB76_AddReaction_AgentCanReact(t *testing.T) {
	testDB := setupTestDB_CB76(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	userID := "user1"
	agentID := "agent1"
	createUser_CB76(testDB, "user1", "pass")
	createAgent_CB76(testDB, agentID)
	convID := createConversation_CB76(testDB, userID, agentID)
	msgID := "msg1"
	createMessage_CB76(testDB, msgID, convID, "agent", agentID, "hi there")

	reaction, added, err := addReaction(msgID, agentID, "❤️")
	if err != nil {
		t.Fatalf("addReaction failed: %v", err)
	}
	if !added || reaction == nil {
		t.Error("expected reaction added")
	}
}

func TestCB76_AddReaction_DBError(t *testing.T) {
	testDB := setupTestDB_CB76(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	testDB.Close()
	_, _, err := addReaction("msg1", "user1", "👍")
	if err == nil {
		t.Error("expected error on closed DB")
	}
}

// ==================== Reactions: getMessageReactions ====================

func TestCB76_GetMessageReactions_WithReactions(t *testing.T) {
	testDB := setupTestDB_CB76(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	userID := "user1"
	agentID := "agent1"
	createUser_CB76(testDB, "user1", "pass")
	createAgent_CB76(testDB, agentID)
	convID := createConversation_CB76(testDB, userID, agentID)
	msgID := "msg1"
	createMessage_CB76(testDB, msgID, convID, "client", userID, "hello")

	_, _, _ = addReaction(msgID, userID, "👍")
	_, _, _ = addReaction(msgID, agentID, "❤️")

	reactions, err := getMessageReactions(msgID)
	if err != nil {
		t.Fatalf("getMessageReactions failed: %v", err)
	}
	if len(reactions) != 2 {
		t.Errorf("expected 2 reactions, got %d", len(reactions))
	}
}

func TestCB76_GetMessageReactions_Empty(t *testing.T) {
	testDB := setupTestDB_CB76(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	reactions, err := getMessageReactions("msg_no_reactions")
	if err != nil {
		t.Fatalf("getMessageReactions failed: %v", err)
	}
	if len(reactions) != 0 {
		t.Errorf("expected 0 reactions, got %d", len(reactions))
	}
}

func TestCB76_GetMessageReactions_DBError(t *testing.T) {
	testDB := setupTestDB_CB76(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	testDB.Close()
	_, err := getMessageReactions("msg1")
	if err == nil {
		t.Error("expected error on closed DB")
	}
}

// ==================== Reactions: handleReact ====================

func TestCB76_HandleReact_Success(t *testing.T) {
	testDB := setupTestDB_CB76(t)
	oldDB := db
	db = testDB
	oldHub := setupHub_CB76()
	defer func() { db = oldDB; restoreHub_CB76(oldHub) }()

	userID := createUser_CB76(testDB, "user1", "pass")
	agentID := "agent1"
	createAgent_CB76(testDB, agentID)
	convID := createConversation_CB76(testDB, userID, agentID)
	msgID := "msg1"
	createMessage_CB76(testDB, msgID, convID, "client", userID, "hello")

	token := generateTestToken_CB76(userID)
	form := "message_id=" + msgID + "&emoji=👍"
	req := httptest.NewRequest("POST", "/messages/react", strings.NewReader(form))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handleReact(w, req)

	if w.Code != 200 {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["status"] != "reaction_added" {
		t.Errorf("expected status 'reaction_added', got %v", resp["status"])
	}
}

func TestCB76_HandleReact_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest("GET", "/messages/react", nil)
	w := httptest.NewRecorder()
	handleReact(w, req)

	if w.Code != 405 {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestCB76_HandleReact_Unauthorized(t *testing.T) {
	req := httptest.NewRequest("POST", "/messages/react", nil)
	w := httptest.NewRecorder()
	handleReact(w, req)

	if w.Code != 401 {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestCB76_HandleReact_MissingFields(t *testing.T) {
	testDB := setupTestDB_CB76(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	userID := createUser_CB76(testDB, "user1", "pass")
	token := generateTestToken_CB76(userID)

	req := httptest.NewRequest("POST", "/messages/react", strings.NewReader(""))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handleReact(w, req)

	if w.Code != 400 {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestCB76_HandleReact_EmojiTooLong(t *testing.T) {
	testDB := setupTestDB_CB76(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	userID := createUser_CB76(testDB, "user1", "pass")
	token := generateTestToken_CB76(userID)

	form := "message_id=msg1&emoji=" + strings.Repeat("a", 11)
	req := httptest.NewRequest("POST", "/messages/react", strings.NewReader(form))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handleReact(w, req)

	if w.Code != 400 {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestCB76_HandleReact_MessageNotFound(t *testing.T) {
	testDB := setupTestDB_CB76(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	userID := createUser_CB76(testDB, "user1", "pass")
	token := generateTestToken_CB76(userID)

	form := "message_id=nonexistent&emoji=👍"
	req := httptest.NewRequest("POST", "/messages/react", strings.NewReader(form))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handleReact(w, req)

	if w.Code != 404 {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

func TestCB76_HandleReact_ToggleRemove(t *testing.T) {
	testDB := setupTestDB_CB76(t)
	oldDB := db
	db = testDB
	oldHub := setupHub_CB76()
	defer func() { db = oldDB; restoreHub_CB76(oldHub) }()

	userID := createUser_CB76(testDB, "user1", "pass")
	agentID := "agent1"
	createAgent_CB76(testDB, agentID)
	convID := createConversation_CB76(testDB, userID, agentID)
	msgID := "msg1"
	createMessage_CB76(testDB, msgID, convID, "client", userID, "hello")

	// First add
	_, _, _ = addReaction(msgID, userID, "👍")

	token := generateTestToken_CB76(userID)
	form := "message_id=" + msgID + "&emoji=👍"
	req := httptest.NewRequest("POST", "/messages/react", strings.NewReader(form))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handleReact(w, req)

	if w.Code != 200 {
		t.Errorf("expected 200, got %d", w.Code)
	}
	var resp map[string]string
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["status"] != "reaction_removed" {
		t.Errorf("expected status 'reaction_removed', got %v", resp["status"])
	}
}

// ==================== Reactions: handleGetReactions ====================

func TestCB76_HandleGetReactions_Success(t *testing.T) {
	testDB := setupTestDB_CB76(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	userID := createUser_CB76(testDB, "user1", "pass")
	agentID := "agent1"
	createAgent_CB76(testDB, agentID)
	convID := createConversation_CB76(testDB, userID, agentID)
	msgID := "msg1"
	createMessage_CB76(testDB, msgID, convID, "client", userID, "hello")
	_, _, _ = addReaction(msgID, userID, "👍")

	token := generateTestToken_CB76(userID)
	req := httptest.NewRequest("GET", "/messages/reactions?message_id="+msgID, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleGetReactions(w, req)

	if w.Code != 200 {
		t.Errorf("expected 200, got %d", w.Code)
	}
	var reactions []MessageReaction
	json.Unmarshal(w.Body.Bytes(), &reactions)
	if len(reactions) != 1 {
		t.Errorf("expected 1 reaction, got %d", len(reactions))
	}
}

func TestCB76_HandleGetReactions_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest("POST", "/messages/reactions", nil)
	w := httptest.NewRecorder()
	handleGetReactions(w, req)

	if w.Code != 405 {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestCB76_HandleGetReactions_Unauthorized(t *testing.T) {
	req := httptest.NewRequest("GET", "/messages/reactions?message_id=msg1", nil)
	w := httptest.NewRecorder()
	handleGetReactions(w, req)

	if w.Code != 401 {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestCB76_HandleGetReactions_MissingMessageID(t *testing.T) {
	testDB := setupTestDB_CB76(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	userID := createUser_CB76(testDB, "user1", "pass")
	token := generateTestToken_CB76(userID)

	req := httptest.NewRequest("GET", "/messages/reactions", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleGetReactions(w, req)

	if w.Code != 400 {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestCB76_HandleGetReactions_MessageNotFound(t *testing.T) {
	testDB := setupTestDB_CB76(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	userID := createUser_CB76(testDB, "user1", "pass")
	token := generateTestToken_CB76(userID)

	req := httptest.NewRequest("GET", "/messages/reactions?message_id=nonexistent", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleGetReactions(w, req)

	if w.Code != 404 {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

func TestCB76_HandleGetReactions_NotAuthorized(t *testing.T) {
	testDB := setupTestDB_CB76(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	userID := createUser_CB76(testDB, "user1", "pass")
	otherUserID := createUser_CB76(testDB, "user2", "pass")
	agentID := "agent1"
	createAgent_CB76(testDB, agentID)
	convID := createConversation_CB76(testDB, userID, agentID)
	msgID := "msg1"
	createMessage_CB76(testDB, msgID, convID, "client", userID, "hello")

	token := generateTestToken_CB76(otherUserID)
	req := httptest.NewRequest("GET", "/messages/reactions?message_id="+msgID, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleGetReactions(w, req)

	if w.Code != 401 {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestCB76_HandleGetReactions_Empty(t *testing.T) {
	testDB := setupTestDB_CB76(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	userID := createUser_CB76(testDB, "user1", "pass")
	agentID := "agent1"
	createAgent_CB76(testDB, agentID)
	convID := createConversation_CB76(testDB, userID, agentID)
	msgID := "msg1"
	createMessage_CB76(testDB, msgID, convID, "client", userID, "hello")

	token := generateTestToken_CB76(userID)
	req := httptest.NewRequest("GET", "/messages/reactions?message_id="+msgID, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleGetReactions(w, req)

	if w.Code != 200 {
		t.Errorf("expected 200, got %d", w.Code)
	}
	// Should return empty array, not null
	body := w.Body.String()
	if !strings.Contains(body, "[") {
		t.Errorf("expected JSON array, got: %s", body)
	}
}

// ==================== Message Edit: handleMessageEdit ====================

func TestCB76_HandleMessageEdit_Success(t *testing.T) {
	testDB := setupTestDB_CB76(t)
	oldDB := db
	db = testDB
	oldHub := setupHub_CB76()
	defer func() { db = oldDB; restoreHub_CB76(oldHub) }()

	userID := createUser_CB76(testDB, "user1", "pass")
	agentID := "agent1"
	createAgent_CB76(testDB, agentID)
	convID := createConversation_CB76(testDB, userID, agentID)
	msgID := "msg1"
	createMessage_CB76(testDB, msgID, convID, "client", userID, "original")

	token := generateTestToken_CB76(userID)
	form := "message_id=" + msgID + "&content=edited+content"
	req := httptest.NewRequest("POST", "/messages/edit", strings.NewReader(form))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handleMessageEdit(w, req)

	if w.Code != 200 {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["status"] != "edited" {
		t.Errorf("expected status 'edited', got %v", resp["status"])
	}
	if resp["content"] != "edited content" {
		t.Errorf("expected content 'edited content', got %v", resp["content"])
	}
}

func TestCB76_HandleMessageEdit_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest("GET", "/messages/edit", nil)
	w := httptest.NewRecorder()
	handleMessageEdit(w, req)

	if w.Code != 405 {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestCB76_HandleMessageEdit_Unauthorized(t *testing.T) {
	req := httptest.NewRequest("POST", "/messages/edit", nil)
	w := httptest.NewRecorder()
	handleMessageEdit(w, req)

	if w.Code != 401 {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestCB76_HandleMessageEdit_MissingMessageID(t *testing.T) {
	testDB := setupTestDB_CB76(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	userID := createUser_CB76(testDB, "user1", "pass")
	token := generateTestToken_CB76(userID)

	form := "content=test"
	req := httptest.NewRequest("POST", "/messages/edit", strings.NewReader(form))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handleMessageEdit(w, req)

	if w.Code != 400 {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestCB76_HandleMessageEdit_EmptyContent(t *testing.T) {
	testDB := setupTestDB_CB76(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	userID := createUser_CB76(testDB, "user1", "pass")
	token := generateTestToken_CB76(userID)

	form := "message_id=msg1"
	req := httptest.NewRequest("POST", "/messages/edit", strings.NewReader(form))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handleMessageEdit(w, req)

	if w.Code != 400 {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestCB76_HandleMessageEdit_NotFound(t *testing.T) {
	testDB := setupTestDB_CB76(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	userID := createUser_CB76(testDB, "user1", "pass")
	token := generateTestToken_CB76(userID)

	form := "message_id=nonexistent&content=edited"
	req := httptest.NewRequest("POST", "/messages/edit", strings.NewReader(form))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handleMessageEdit(w, req)

	if w.Code != 404 {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

func TestCB76_HandleMessageEdit_DeletedMessage(t *testing.T) {
	testDB := setupTestDB_CB76(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	userID := createUser_CB76(testDB, "user1", "pass")
	agentID := "agent1"
	createAgent_CB76(testDB, agentID)
	convID := createConversation_CB76(testDB, userID, agentID)
	msgID := "msg1"
	createMessage_CB76(testDB, msgID, convID, "client", userID, "original")
	testDB.Exec("UPDATE messages SET is_deleted = 1 WHERE id = ?", msgID)

	token := generateTestToken_CB76(userID)
	form := "message_id=" + msgID + "&content=edited"
	req := httptest.NewRequest("POST", "/messages/edit", strings.NewReader(form))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handleMessageEdit(w, req)

	if w.Code != 400 {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestCB76_HandleMessageEdit_NotSender(t *testing.T) {
	testDB := setupTestDB_CB76(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	userID := createUser_CB76(testDB, "user1", "pass")
	otherUserID := createUser_CB76(testDB, "user2", "pass")
	agentID := "agent1"
	createAgent_CB76(testDB, agentID)
	convID := createConversation_CB76(testDB, userID, agentID)
	msgID := "msg1"
	createMessage_CB76(testDB, msgID, convID, "client", userID, "original")

	token := generateTestToken_CB76(otherUserID)
	form := "message_id=" + msgID + "&content=edited"
	req := httptest.NewRequest("POST", "/messages/edit", strings.NewReader(form))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handleMessageEdit(w, req)

	if w.Code != 401 {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestCB76_HandleMessageEdit_AgentMessageNotEditable(t *testing.T) {
	testDB := setupTestDB_CB76(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	userID := createUser_CB76(testDB, "user1", "pass")
	agentID := "agent1"
	createAgent_CB76(testDB, agentID)
	convID := createConversation_CB76(testDB, userID, agentID)
	msgID := "msg1"
	createMessage_CB76(testDB, msgID, convID, "agent", agentID, "agent reply")

	token := generateTestToken_CB76(userID)
	form := "message_id=" + msgID + "&content=edited"
	req := httptest.NewRequest("POST", "/messages/edit", strings.NewReader(form))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handleMessageEdit(w, req)

	if w.Code != 401 {
		t.Errorf("expected 401 (can only edit your own messages), got %d", w.Code)
	}
}

func TestCB76_HandleMessageEdit_DBError(t *testing.T) {
	testDB := setupTestDB_CB76(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	userID := createUser_CB76(testDB, "user1", "pass")
	token := generateTestToken_CB76(userID)

	testDB.Close()
	form := "message_id=msg1&content=edited"
	req := httptest.NewRequest("POST", "/messages/edit", strings.NewReader(form))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handleMessageEdit(w, req)

	if w.Code != 500 {
		t.Errorf("expected 500, got %d", w.Code)
	}
}

// ==================== Push: handleUnregisterDeviceToken ====================

func TestCB76_HandleUnregisterDeviceToken_Success(t *testing.T) {
	testDB := setupTestDB_CB76(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	userID := createUser_CB76(testDB, "user1", "pass")
	testDB.Exec("INSERT INTO device_tokens (user_id, device_token, platform, created_at) VALUES (?, ?, 'ios', ?)",
		userID, "token123", time.Now().UTC())

	token := generateTestToken_CB76(userID)
	body := `{"device_token":"token123"}`
	req := httptest.NewRequest("DELETE", "/push/device-token", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleUnregisterDeviceToken(w, req)

	if w.Code != 200 {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestCB76_HandleUnregisterDeviceToken_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest("GET", "/push/device-token", nil)
	w := httptest.NewRecorder()
	handleUnregisterDeviceToken(w, req)

	if w.Code != 405 {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestCB76_HandleUnregisterDeviceToken_Unauthorized(t *testing.T) {
	req := httptest.NewRequest("DELETE", "/push/device-token", nil)
	w := httptest.NewRecorder()
	handleUnregisterDeviceToken(w, req)

	if w.Code != 401 {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestCB76_HandleUnregisterDeviceToken_InvalidBody(t *testing.T) {
	testDB := setupTestDB_CB76(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	userID := createUser_CB76(testDB, "user1", "pass")
	token := generateTestToken_CB76(userID)

	req := httptest.NewRequest("DELETE", "/push/device-token", strings.NewReader("invalid json"))
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleUnregisterDeviceToken(w, req)

	if w.Code != 400 {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestCB76_HandleUnregisterDeviceToken_EmptyToken(t *testing.T) {
	testDB := setupTestDB_CB76(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	userID := createUser_CB76(testDB, "user1", "pass")
	token := generateTestToken_CB76(userID)

	body := `{"device_token":""}`
	req := httptest.NewRequest("DELETE", "/push/device-token", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleUnregisterDeviceToken(w, req)

	if w.Code != 400 {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestCB76_HandleUnregisterDeviceToken_DBError(t *testing.T) {
	testDB := setupTestDB_CB76(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	userID := createUser_CB76(testDB, "user1", "pass")
	token := generateTestToken_CB76(userID)

	testDB.Close()
	body := `{"device_token":"token123"}`
	req := httptest.NewRequest("DELETE", "/push/device-token", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleUnregisterDeviceToken(w, req)

	if w.Code != 500 {
		t.Errorf("expected 500, got %d", w.Code)
	}
}

// ==================== Push: handleGetVAPIDKey ====================

func TestCB76_HandleGetVAPIDKey_Success(t *testing.T) {
	oldKey := vapidPublicKey
	vapidPublicKey = "test-vapid-key"
	defer func() { vapidPublicKey = oldKey }()

	req := httptest.NewRequest("GET", "/push/vapid-key", nil)
	req.Header.Set("Authorization", "Bearer "+generateTestToken_CB76("user1"))
	w := httptest.NewRecorder()
	handleGetVAPIDKey(w, req)

	if w.Code != 200 {
		t.Errorf("expected 200, got %d", w.Code)
	}
	var resp map[string]string
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["public_key"] != "test-vapid-key" {
		t.Errorf("expected 'test-vapid-key', got '%s'", resp["public_key"])
	}
}

func TestCB76_HandleGetVAPIDKey_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest("POST", "/push/vapid-key", nil)
	w := httptest.NewRecorder()
	handleGetVAPIDKey(w, req)

	if w.Code != 405 {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestCB76_HandleGetVAPIDKey_Unauthorized(t *testing.T) {
	req := httptest.NewRequest("GET", "/push/vapid-key", nil)
	w := httptest.NewRecorder()
	handleGetVAPIDKey(w, req)

	if w.Code != 401 {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestCB76_HandleGetVAPIDKey_NotConfigured(t *testing.T) {
	oldKey := vapidPublicKey
	vapidPublicKey = ""
	defer func() { vapidPublicKey = oldKey }()

	req := httptest.NewRequest("GET", "/push/vapid-key", nil)
	req.Header.Set("Authorization", "Bearer "+generateTestToken_CB76("user1"))
	w := httptest.NewRecorder()
	handleGetVAPIDKey(w, req)

	if w.Code != 404 {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

// ==================== Push: handleWebPushUnsubscribe ====================

func TestCB76_HandleWebPushUnsubscribe_Success(t *testing.T) {
	testDB := setupTestDB_CB76(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	userID := createUser_CB76(testDB, "user1", "pass")
	testDB.Exec("INSERT INTO device_tokens (user_id, device_token, platform, created_at) VALUES (?, ?, 'web', ?)",
		userID, "https://endpoint.example.com/push", time.Now().UTC())

	token := generateTestToken_CB76(userID)
	body := `{"endpoint":"https://endpoint.example.com/push"}`
	req := httptest.NewRequest("POST", "/push/web-unsubscribe", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleWebPushUnsubscribe(w, req)

	if w.Code != 200 {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestCB76_HandleWebPushUnsubscribe_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest("GET", "/push/web-unsubscribe", nil)
	w := httptest.NewRecorder()
	handleWebPushUnsubscribe(w, req)

	if w.Code != 405 {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestCB76_HandleWebPushUnsubscribe_Unauthorized(t *testing.T) {
	req := httptest.NewRequest("POST", "/push/web-unsubscribe", nil)
	w := httptest.NewRecorder()
	handleWebPushUnsubscribe(w, req)

	if w.Code != 401 {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestCB76_HandleWebPushUnsubscribe_InvalidBody(t *testing.T) {
	testDB := setupTestDB_CB76(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	userID := createUser_CB76(testDB, "user1", "pass")
	token := generateTestToken_CB76(userID)

	req := httptest.NewRequest("POST", "/push/web-unsubscribe", strings.NewReader("invalid"))
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleWebPushUnsubscribe(w, req)

	if w.Code != 400 {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestCB76_HandleWebPushUnsubscribe_EmptyEndpoint(t *testing.T) {
	testDB := setupTestDB_CB76(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	userID := createUser_CB76(testDB, "user1", "pass")
	token := generateTestToken_CB76(userID)

	body := `{"endpoint":""}`
	req := httptest.NewRequest("POST", "/push/web-unsubscribe", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleWebPushUnsubscribe(w, req)

	if w.Code != 400 {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

// ==================== Attachments: handleListAttachments ====================

func TestCB76_HandleListAttachments_Success(t *testing.T) {
	testDB := setupTestDB_CB76(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	userID := createUser_CB76(testDB, "user1", "pass")
	agentID := "agent1"
	createAgent_CB76(testDB, agentID)
	convID := createConversation_CB76(testDB, userID, agentID)
	msgID := "msg1"
	createMessage_CB76(testDB, msgID, convID, "client", userID, "see this file")

	// Insert attachment
	testDB.Exec(`INSERT INTO attachments (id, message_id, user_id, filename, content_type, size, sha256, storage_path, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		"att1", msgID, userID, "test.pdf", "application/pdf", int64(1024), "abc123", "/uploads/att1", time.Now().UTC().Format(time.RFC3339))

	token := generateTestToken_CB76(userID)
	req := httptest.NewRequest("GET", "/attachments?conversation_id="+convID, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleListAttachments(w, req)

	if w.Code != 200 {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var attachments []Attachment
	json.Unmarshal(w.Body.Bytes(), &attachments)
	if len(attachments) != 1 {
		t.Errorf("expected 1 attachment, got %d", len(attachments))
	}
	if attachments[0].Filename != "test.pdf" {
		t.Errorf("expected filename 'test.pdf', got '%s'", attachments[0].Filename)
	}
}

func TestCB76_HandleListAttachments_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest("POST", "/attachments", nil)
	w := httptest.NewRecorder()
	handleListAttachments(w, req)

	if w.Code != 405 {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestCB76_HandleListAttachments_Unauthorized(t *testing.T) {
	req := httptest.NewRequest("GET", "/attachments?conversation_id=conv1", nil)
	w := httptest.NewRecorder()
	handleListAttachments(w, req)

	if w.Code != 401 {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestCB76_HandleListAttachments_MissingConvID(t *testing.T) {
	testDB := setupTestDB_CB76(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	userID := createUser_CB76(testDB, "user1", "pass")
	token := generateTestToken_CB76(userID)

	req := httptest.NewRequest("GET", "/attachments", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleListAttachments(w, req)

	if w.Code != 400 {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestCB76_HandleListAttachments_ConvNotFound(t *testing.T) {
	testDB := setupTestDB_CB76(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	userID := createUser_CB76(testDB, "user1", "pass")
	token := generateTestToken_CB76(userID)

	req := httptest.NewRequest("GET", "/attachments?conversation_id=nonexistent", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleListAttachments(w, req)

	if w.Code != 404 {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

func TestCB76_HandleListAttachments_NotOwner(t *testing.T) {
	testDB := setupTestDB_CB76(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	userID := createUser_CB76(testDB, "user1", "pass")
	otherUserID := createUser_CB76(testDB, "user2", "pass")
	agentID := "agent1"
	createAgent_CB76(testDB, agentID)
	convID := createConversation_CB76(testDB, userID, agentID)

	token := generateTestToken_CB76(otherUserID)
	req := httptest.NewRequest("GET", "/attachments?conversation_id="+convID, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleListAttachments(w, req)

	if w.Code != 404 {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

// ==================== Utility: truncate ====================

func TestCB76_Truncate_ShortString(t *testing.T) {
	result := truncate("hello", 10)
	if result != "hello" {
		t.Errorf("expected 'hello', got '%s'", result)
	}
}

func TestCB76_Truncate_ExactLength(t *testing.T) {
	result := truncate("hello", 5)
	if result != "hello" {
		t.Errorf("expected 'hello', got '%s'", result)
	}
}

func TestCB76_Truncate_LongString(t *testing.T) {
	result := truncate("hello world", 8)
	if result != "hello..." {
		t.Errorf("expected 'hello...', got '%s'", result)
	}
}

func TestCB76_Truncate_TinyMaxLen(t *testing.T) {
	result := truncate("hello", 3)
	if result != "hel" {
		t.Errorf("expected 'hel', got '%s'", result)
	}
}

func TestCB76_Truncate_MaxLenZero(t *testing.T) {
	result := truncate("hello", 0)
	if result != "" {
		t.Errorf("expected '', got '%s'", result)
	}
}

// ==================== Utility: isUniqueViolation ====================

func TestCB76_IsUniqueViolation_True(t *testing.T) {
	err := &sqlError{msg: "UNIQUE constraint failed: users.username"}
	if !isUniqueViolation(err) {
		t.Error("expected isUniqueViolation=true for UNIQUE constraint error")
	}
}

func TestCB76_IsUniqueViolation_False(t *testing.T) {
	err := &sqlError{msg: "some other error"}
	if isUniqueViolation(err) {
		t.Error("expected isUniqueViolation=false for non-UNIQUE error")
	}
}

func TestCB76_IsUniqueViolation_Nil(t *testing.T) {
	if isUniqueViolation(nil) {
		t.Error("expected isUniqueViolation=false for nil error")
	}
}

// sqlError is a simple test error
type sqlError struct{ msg string }

func (e *sqlError) Error() string { return e.msg }

// ==================== Auth: rateLimiter ====================

func TestCB76_RateLimiter_Allow(t *testing.T) {
	rl := &rateLimiter{attempts: make(map[string]*rateLimitEntry)}
	// Should allow up to maxAgentAttempts
	for i := 0; i < maxAgentAttempts; i++ {
		if !rl.Allow("agent1") {
			t.Errorf("expected Allow to return true on attempt %d", i+1)
		}
	}
	// Should block the next attempt
	if rl.Allow("agent1") {
		t.Error("expected Allow to return false after max attempts")
	}
}

func TestCB76_RateLimiter_Clean(t *testing.T) {
	rl := &rateLimiter{attempts: make(map[string]*rateLimitEntry)}
	rl.Allow("agent1")
	rl.Allow("agent2")

	// Manually set firstSeen to past time to simulate expiry
	rl.mu.Lock()
	for _, entry := range rl.attempts {
		entry.firstSeen = time.Now().Add(-2 * time.Minute)
	}
	rl.mu.Unlock()

	rl.Clean()

	rl.mu.Lock()
	count := len(rl.attempts)
	rl.mu.Unlock()
	if count != 0 {
		t.Errorf("expected 0 entries after clean, got %d", count)
	}
}

func TestCB76_RateLimiter_Reset(t *testing.T) {
	rl := &rateLimiter{attempts: make(map[string]*rateLimitEntry)}
	rl.Allow("agent1")
	rl.Allow("agent2")

	rl.Reset()

	rl.mu.Lock()
	count := len(rl.attempts)
	rl.mu.Unlock()
	if count != 0 {
		t.Errorf("expected 0 entries after reset, got %d", count)
	}
}

func TestCB76_RateLimiter_DifferentAgents(t *testing.T) {
	rl := &rateLimiter{attempts: make(map[string]*rateLimitEntry)}
	// Exhaust agent1
	for i := 0; i < maxAgentAttempts; i++ {
		rl.Allow("agent1")
	}
	// agent2 should still be allowed
	if !rl.Allow("agent2") {
		t.Error("expected agent2 to be allowed when agent1 is rate limited")
	}
}

func TestCB76_RateLimiter_WindowReset(t *testing.T) {
	rl := &rateLimiter{attempts: make(map[string]*rateLimitEntry)}
	// Exhaust agent1
	for i := 0; i < maxAgentAttempts; i++ {
		rl.Allow("agent1")
	}
	// Manually set firstSeen to past time to simulate window reset
	rl.mu.Lock()
	rl.attempts["agent1"].firstSeen = time.Now().Add(-2 * time.Minute)
	rl.mu.Unlock()
	// Should allow again (new window)
	if !rl.Allow("agent1") {
		t.Error("expected agent1 to be allowed after window expired")
	}
}

// ==================== Auth: ValidateAgentSecret ====================

func TestCB76_ValidateAgentSecret_EmptySecret(t *testing.T) {
	err := ValidateAgentSecret("agent1", "")
	if err == nil || err.Error() != "missing agent secret" {
		t.Errorf("expected 'missing agent secret', got %v", err)
	}
}

func TestCB76_ValidateAgentSecret_InvalidSecret(t *testing.T) {
	oldSecret := agentSecret
	agentSecret = "correct-secret"
	defer func() { agentSecret = oldSecret }()

	err := ValidateAgentSecret("agent1", "wrong-secret")
	if err == nil || err.Error() != "invalid agent secret" {
		t.Errorf("expected 'invalid agent secret', got %v", err)
	}
}

func TestCB76_ValidateAgentSecret_ValidSecret(t *testing.T) {
	oldSecret := agentSecret
	agentSecret = "correct-secret"
	// Reset rate limiter to avoid interference
	if agentRateLimiter != nil {
		agentRateLimiter.Reset()
	}
	defer func() { agentSecret = oldSecret }()

	err := ValidateAgentSecret("agent1", "correct-secret")
	if err != nil {
		t.Errorf("expected nil error, got %v", err)
	}
}

func TestCB76_ValidateAgentSecret_RateLimited(t *testing.T) {
	oldSecret := agentSecret
	agentSecret = "correct-secret"
	// Reset rate limiter
	if agentRateLimiter != nil {
		agentRateLimiter.Reset()
	}
	defer func() { agentSecret = oldSecret }()

	// Exhaust rate limit
	for i := 0; i < maxAgentAttempts; i++ {
		ValidateAgentSecret("agent_rl_test", "wrong")
	}

	err := ValidateAgentSecret("agent_rl_test", "correct-secret")
	if err == nil || err.Error() != "rate limited: too many connection attempts" {
		t.Errorf("expected 'rate limited', got %v", err)
	}
}

// ==================== Auth: GenerateJWT and HashAPIKey ====================

func TestCB76_GenerateJWT_Success(t *testing.T) {
	oldSecret := jwtSecret
	jwtSecret = []byte("test-secret-key")
	defer func() { jwtSecret = oldSecret }()

	token, err := GenerateJWT("user123", "testuser")
	if err != nil {
		t.Fatalf("GenerateJWT failed: %v", err)
	}
	if token == "" {
		t.Error("expected non-empty token")
	}
}

func TestCB76_HashAPIKey_Success(t *testing.T) {
	hash, err := HashAPIKey("mysecret")
	if err != nil {
		t.Fatalf("HashAPIKey failed: %v", err)
	}
	if hash == "" {
		t.Error("expected non-empty hash")
	}
	if hash == "mysecret" {
		t.Error("expected hashed output, not plaintext")
	}
}

func TestCB76_HashAPIKey_EmptyInput(t *testing.T) {
	hash, err := HashAPIKey("")
	if err != nil {
		t.Fatalf("HashAPIKey failed on empty input: %v", err)
	}
	if hash == "" {
		t.Error("expected non-empty hash even for empty input")
	}
}

// ==================== Conversations: getConversationMessages ====================

func TestCB76_GetConversationMessages_Success(t *testing.T) {
	testDB := setupTestDB_CB76(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	userID := "user1"
	agentID := "agent1"
	createUser_CB76(testDB, "user1", "pass")
	createAgent_CB76(testDB, agentID)
	convID := createConversation_CB76(testDB, userID, agentID)

	createMessage_CB76(testDB, "msg1", convID, "client", userID, "hello")
	time.Sleep(time.Millisecond)
	createMessage_CB76(testDB, "msg2", convID, "agent", agentID, "hi back")

	msgs, err := getConversationMessages(convID, 50, "")
	if err != nil {
		t.Fatalf("getConversationMessages failed: %v", err)
	}
	if len(msgs) != 2 {
		t.Errorf("expected 2 messages, got %d", len(msgs))
	}
}

func TestCB76_GetConversationMessages_WithLimit(t *testing.T) {
	testDB := setupTestDB_CB76(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	userID := "user1"
	agentID := "agent1"
	createUser_CB76(testDB, "user1", "pass")
	createAgent_CB76(testDB, agentID)
	convID := createConversation_CB76(testDB, userID, agentID)

	for i := 0; i < 5; i++ {
		createMessage_CB76(testDB, "msg"+string(rune('1'+i)), convID, "client", userID, "msg")
		time.Sleep(time.Millisecond)
	}

	msgs, err := getConversationMessages(convID, 2, "")
	if err != nil {
		t.Fatalf("getConversationMessages failed: %v", err)
	}
	if len(msgs) != 2 {
		t.Errorf("expected 2 messages with limit, got %d", len(msgs))
	}
}

func TestCB76_GetConversationMessages_DefaultLimit(t *testing.T) {
	testDB := setupTestDB_CB76(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	userID := "user1"
	agentID := "agent1"
	createUser_CB76(testDB, "user1", "pass")
	createAgent_CB76(testDB, agentID)
	convID := createConversation_CB76(testDB, userID, agentID)
	createMessage_CB76(testDB, "msg1", convID, "client", userID, "hello")

	msgs, err := getConversationMessages(convID, 0, "")
	if err != nil {
		t.Fatalf("getConversationMessages failed: %v", err)
	}
	if len(msgs) != 1 {
		t.Errorf("expected 1 message with default limit, got %d", len(msgs))
	}
}

func TestCB76_GetConversationMessages_Empty(t *testing.T) {
	testDB := setupTestDB_CB76(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	userID := "user1"
	agentID := "agent1"
	createUser_CB76(testDB, "user1", "pass")
	createAgent_CB76(testDB, agentID)
	convID := createConversation_CB76(testDB, userID, agentID)

	msgs, err := getConversationMessages(convID, 50, "")
	if err != nil {
		t.Fatalf("getConversationMessages failed: %v", err)
	}
	if len(msgs) != 0 {
		t.Errorf("expected 0 messages, got %d", len(msgs))
	}
}

func TestCB76_GetConversationMessages_DBError(t *testing.T) {
	testDB := setupTestDB_CB76(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	testDB.Close()
	_, err := getConversationMessages("someconv", 50, "")
	if err == nil {
		t.Error("expected error on closed DB")
	}
}

// ==================== Conversations: changeUserPassword ====================

func TestCB76_ChangeUserPassword_Success(t *testing.T) {
	testDB := setupTestDB_CB76(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	userID := createUser_CB76(testDB, "user1", "oldpass")

	err := changeUserPassword(userID, "oldpass", "newpass123")
	if err != nil {
		t.Fatalf("changeUserPassword failed: %v", err)
	}

	// Verify new password works
	var hash string
	testDB.QueryRow("SELECT password_hash FROM users WHERE id = ?", userID).Scan(&hash)
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte("newpass123")); err != nil {
		t.Error("new password hash doesn't match 'newpass123'")
	}
}

func TestCB76_ChangeUserPassword_WrongOldPassword(t *testing.T) {
	testDB := setupTestDB_CB76(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	userID := createUser_CB76(testDB, "user1", "oldpass")

	err := changeUserPassword(userID, "wrongold", "newpass123")
	if err == nil || err.Error() != "invalid old password" {
		t.Errorf("expected 'invalid old password', got %v", err)
	}
}

func TestCB76_ChangeUserPassword_ShortNewPassword(t *testing.T) {
	testDB := setupTestDB_CB76(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	userID := createUser_CB76(testDB, "user1", "oldpass")

	err := changeUserPassword(userID, "oldpass", "short")
	if err == nil || err.Error() != "new password must be at least 6 characters" {
		t.Errorf("expected 'new password must be at least 6 characters', got %v", err)
	}
}

func TestCB76_ChangeUserPassword_UserNotFound(t *testing.T) {
	testDB := setupTestDB_CB76(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	err := changeUserPassword("nonexistent", "old", "newpass123")
	if err == nil {
		t.Error("expected error for non-existent user")
	}
}

func TestCB76_ChangeUserPassword_DBError(t *testing.T) {
	testDB := setupTestDB_CB76(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	testDB.Close()
	err := changeUserPassword("user1", "old", "newpass123")
	if err == nil {
		t.Error("expected error on closed DB")
	}
}

// ==================== Conversations: searchMessages ====================

func TestCB76_SearchMessages_Success(t *testing.T) {
	testDB := setupTestDB_CB76(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	userID := "user1"
	agentID := "agent1"
	createUser_CB76(testDB, "user1", "pass")
	createAgent_CB76(testDB, agentID)
	convID := createConversation_CB76(testDB, userID, agentID)

	createMessage_CB76(testDB, "msg1", convID, "client", userID, "hello world")
	createMessage_CB76(testDB, "msg2", convID, "agent", agentID, "world hello")

	msgs, err := searchMessages(userID, "world", 50)
	if err != nil {
		t.Fatalf("searchMessages failed: %v", err)
	}
	if len(msgs) != 2 {
		t.Errorf("expected 2 results, got %d", len(msgs))
	}
}

func TestCB76_SearchMessages_EmptyQuery(t *testing.T) {
	testDB := setupTestDB_CB76(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	userID := "user1"
	_, _, _, _ = userID, testDB, oldDB, setupTestDB_CB76
	createUser_CB76(testDB, "user1", "pass")

	_, err := searchMessages(userID, "", 50)
	if err == nil || err.Error() != "empty search query" {
		t.Errorf("expected 'empty search query', got %v", err)
	}
}

func TestCB76_SearchMessages_NoResults(t *testing.T) {
	testDB := setupTestDB_CB76(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	userID := "user1"
	agentID := "agent1"
	createUser_CB76(testDB, "user1", "pass")
	createAgent_CB76(testDB, agentID)
	convID := createConversation_CB76(testDB, userID, agentID)
	createMessage_CB76(testDB, "msg1", convID, "client", userID, "hello")

	msgs, err := searchMessages(userID, "nonexistent", 50)
	if err != nil {
		t.Fatalf("searchMessages failed: %v", err)
	}
	if len(msgs) != 0 {
		t.Errorf("expected 0 results, got %d", len(msgs))
	}
}

func TestCB76_SearchMessages_DefaultLimit(t *testing.T) {
	testDB := setupTestDB_CB76(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	userID := "user1"
	agentID := "agent1"
	createUser_CB76(testDB, "user1", "pass")
	createAgent_CB76(testDB, agentID)
	convID := createConversation_CB76(testDB, userID, agentID)
	createMessage_CB76(testDB, "msg1", convID, "client", userID, "test content")

	msgs, err := searchMessages(userID, "test", 0)
	if err != nil {
		t.Fatalf("searchMessages failed: %v", err)
	}
	if len(msgs) != 1 {
		t.Errorf("expected 1 result with default limit, got %d", len(msgs))
	}
}

func TestCB76_SearchMessages_DBError(t *testing.T) {
	testDB := setupTestDB_CB76(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	testDB.Close()
	_, err := searchMessages("user1", "test", 50)
	if err == nil {
		t.Error("expected error on closed DB")
	}
}

// ==================== Conversations: markMessagesRead ====================

func TestCB76_MarkMessagesRead_Success(t *testing.T) {
	testDB := setupTestDB_CB76(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	userID := "user1"
	agentID := "agent1"
	createUser_CB76(testDB, "user1", "pass")
	createAgent_CB76(testDB, agentID)
	convID := createConversation_CB76(testDB, userID, agentID)

	// Create agent messages (unread)
	createMessage_CB76(testDB, "msg1", convID, "agent", agentID, "response 1")
	createMessage_CB76(testDB, "msg2", convID, "agent", agentID, "response 2")

	count, err := markMessagesRead(convID, userID)
	if err != nil {
		t.Fatalf("markMessagesRead failed: %v", err)
	}
	if count != 2 {
		t.Errorf("expected 2 messages marked read, got %d", count)
	}
}

func TestCB76_MarkMessagesRead_Idempotent(t *testing.T) {
	testDB := setupTestDB_CB76(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	userID := "user1"
	agentID := "agent1"
	createUser_CB76(testDB, "user1", "pass")
	createAgent_CB76(testDB, agentID)
	convID := createConversation_CB76(testDB, userID, agentID)
	createMessage_CB76(testDB, "msg1", convID, "agent", agentID, "response")

	// First call marks as read
	_, _ = markMessagesRead(convID, userID)
	// Second call should return 0
	count, err := markMessagesRead(convID, userID)
	if err != nil {
		t.Fatalf("markMessagesRead failed: %v", err)
	}
	if count != 0 {
		t.Errorf("expected 0 on idempotent call, got %d", count)
	}
}

func TestCB76_MarkMessagesRead_ConvNotFound(t *testing.T) {
	testDB := setupTestDB_CB76(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	_, err := markMessagesRead("nonexistent", "user1")
	if err == nil {
		t.Error("expected error for non-existent conversation")
	}
}

func TestCB76_MarkMessagesRead_Unauthorized(t *testing.T) {
	testDB := setupTestDB_CB76(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	userID := "user1"
	agentID := "agent1"
	createUser_CB76(testDB, "user1", "pass")
	createAgent_CB76(testDB, agentID)
	convID := createConversation_CB76(testDB, userID, agentID)

	_, err := markMessagesRead(convID, "wronguser")
	if err == nil || err.Error() != "unauthorized" {
		t.Errorf("expected 'unauthorized', got %v", err)
	}
}

func TestCB76_MarkMessagesRead_DBError(t *testing.T) {
	testDB := setupTestDB_CB76(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	testDB.Close()
	_, err := markMessagesRead("conv1", "user1")
	if err == nil {
		t.Error("expected error on closed DB")
	}
}

// ==================== Conversations: CreateConversation ====================

func TestCB76_CreateConversation_Success(t *testing.T) {
	testDB := setupTestDB_CB76(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	userID := "user1"
	agentID := "agent1"
	createUser_CB76(testDB, "user1", "pass")
	createAgent_CB76(testDB, agentID)

	conv, err := CreateConversation(userID, agentID)
	if err != nil {
		t.Fatalf("CreateConversation failed: %v", err)
	}
	if conv == nil {
		t.Fatal("expected non-nil conversation")
	}
	if conv.UserID != userID || conv.AgentID != agentID {
		t.Errorf("unexpected conversation: %+v", conv)
	}
	if conv.ID == "" {
		t.Error("expected non-empty conversation ID")
	}
}

func TestCB76_CreateConversation_DBError(t *testing.T) {
	testDB := setupTestDB_CB76(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	testDB.Close()
	_, err := CreateConversation("user1", "agent1")
	if err == nil {
		t.Error("expected error on closed DB")
	}
}

// ==================== Conversations: GetOrCreateConversation ====================

func TestCB76_GetOrCreateConversation_CreateNew(t *testing.T) {
	testDB := setupTestDB_CB76(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	userID := "user1"
	agentID := "agent1"
	createUser_CB76(testDB, "user1", "pass")
	createAgent_CB76(testDB, agentID)

	conv, err := GetOrCreateConversation(userID, agentID)
	if err != nil {
		t.Fatalf("GetOrCreateConversation failed: %v", err)
	}
	if conv == nil {
		t.Fatal("expected non-nil conversation")
	}
}

func TestCB76_GetOrCreateConversation_ReturnsExisting(t *testing.T) {
	testDB := setupTestDB_CB76(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	userID := "user1"
	agentID := "agent1"
	createUser_CB76(testDB, "user1", "pass")
	createAgent_CB76(testDB, agentID)

	// Create first conversation
	conv1, _ := GetOrCreateConversation(userID, agentID)

	// Should return the existing one
	conv2, err := GetOrCreateConversation(userID, agentID)
	if err != nil {
		t.Fatalf("GetOrCreateConversation failed: %v", err)
	}
	if conv1.ID != conv2.ID {
		t.Errorf("expected same conversation ID, got %s vs %s", conv1.ID, conv2.ID)
	}
}

func TestCB76_GetOrCreateConversation_DBError(t *testing.T) {
	testDB := setupTestDB_CB76(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	testDB.Close()
	_, err := GetOrCreateConversation("user1", "agent1")
	if err == nil {
		t.Error("expected error on closed DB")
	}
}

// ==================== Hub: utility methods ====================

func TestCB76_Hub_StaleAgentCount(t *testing.T) {
	h := newHub()
	if h.StaleAgentCount() != 0 {
		t.Errorf("expected 0 stale agents, got %d", h.StaleAgentCount())
	}
	h.staleAgents.Add(5)
	if h.StaleAgentCount() != 5 {
		t.Errorf("expected 5 stale agents, got %d", h.StaleAgentCount())
	}
}

func TestCB76_Hub_GetClient_Empty(t *testing.T) {
	h := newHub()
	if c := h.GetClient("nonexistent"); c != nil {
		t.Error("expected nil for nonexistent client")
	}
}

func TestCB76_Hub_AgentCount_Empty(t *testing.T) {
	h := newHub()
	if h.AgentCount() != 0 {
		t.Errorf("expected 0 agents, got %d", h.AgentCount())
	}
}

func TestCB76_Hub_ClientCount_Empty(t *testing.T) {
	h := newHub()
	if h.ClientCount() != 0 {
		t.Errorf("expected 0 clients, got %d", h.ClientCount())
	}
}

func TestCB76_Hub_ClientConnCount_Empty(t *testing.T) {
	h := newHub()
	if h.ClientConnCount() != 0 {
		t.Errorf("expected 0 client connections, got %d", h.ClientConnCount())
	}
}

func TestCB76_Hub_GetAgentConns_Empty(t *testing.T) {
	h := newHub()
	if a := h.GetAgent("nonexistent"); a != nil {
		t.Error("expected nil for nonexistent agent")
	}
}

func TestCB76_Hub_GetClientConns_Empty(t *testing.T) {
	h := newHub()
	conns := h.GetClientConns("nonexistent")
	if len(conns) != 0 {
		t.Errorf("expected 0 conns, got %d", len(conns))
	}
}

func TestCB76_Hub_SetAgentStatus_NotConnected(t *testing.T) {
	h := newHub()
	// Should not panic for non-existent agent
	h.SetAgentStatus("nonexistent", "busy")
}

func TestCB76_Hub_AgentStatus_Offline(t *testing.T) {
	h := newHub()
	if status := h.AgentStatus("nonexistent"); status != "offline" {
		t.Errorf("expected 'offline', got '%s'", status)
	}
}

func TestCB76_Hub_BroadcastToAllClients_Empty(t *testing.T) {
	h := newHub()
	// Should not panic with no clients
	h.BroadcastToAllClients([]byte("test"))
}

// ==================== Metrics: Uptime and Snapshot ====================

func TestCB76_Metrics_Uptime(t *testing.T) {
	m := &Metrics{StartTime: time.Now().Add(-5 * time.Second)}
	uptime := m.Uptime()
	if uptime < 4*time.Second || uptime > 10*time.Second {
		t.Errorf("expected ~5s uptime, got %v", uptime)
	}
}

func TestCB76_Metrics_Snapshot(t *testing.T) {
	h := newHub()
	m := NewMetrics(h)
	m.MessagesIn.Add(10)
	m.MessagesOut.Add(5)
	m.ConnectionsTotal.Add(3)
	m.ErrorsTotal.Add(1)
	m.RateLimited.Add(2)

	snap := m.Snapshot()

	if snap["messages_in"].(int64) != 10 {
		t.Errorf("expected messages_in=10, got %v", snap["messages_in"])
	}
	if snap["messages_out"].(int64) != 5 {
		t.Errorf("expected messages_out=5, got %v", snap["messages_out"])
	}
	if snap["connections_total"].(int64) != 3 {
		t.Errorf("expected connections_total=3, got %v", snap["connections_total"])
	}
	if snap["errors_total"].(int64) != 1 {
		t.Errorf("expected errors_total=1, got %v", snap["errors_total"])
	}
	if snap["rate_limited"].(int64) != 2 {
		t.Errorf("expected rate_limited=2, got %v", snap["rate_limited"])
	}
	if snap["version"] != "0.2.0" {
		t.Errorf("expected version '0.2.0', got %v", snap["version"])
	}
	if snap["uptime_seconds"].(int) < 0 {
		t.Error("expected non-negative uptime")
	}
	if snap["goroutines"].(int) < 1 {
		t.Error("expected at least 1 goroutine")
	}
}

// ==================== Middleware: isOriginAllowed ====================

func TestCB76_IsOriginAllowed_Wildcard(t *testing.T) {
	oldCors := corsAllowedOrigins
	corsAllowedOrigins = "*"
	defer func() { corsAllowedOrigins = oldCors }()

	if !isOriginAllowed("https://example.com") {
		t.Error("expected wildcard to allow all origins")
	}
}

func TestCB76_IsOriginAllowed_SpecificMatch(t *testing.T) {
	oldCors := corsAllowedOrigins
	corsAllowedOrigins = "https://example.com,https://app.example.com"
	defer func() { corsAllowedOrigins = oldCors }()

	if !isOriginAllowed("https://example.com") {
		t.Error("expected example.com to be allowed")
	}
	if !isOriginAllowed("https://app.example.com") {
		t.Error("expected app.example.com to be allowed")
	}
	if isOriginAllowed("https://evil.com") {
		t.Error("expected evil.com to be rejected")
	}
}

func TestCB76_IsOriginAllowed_WildcardInList(t *testing.T) {
	oldCors := corsAllowedOrigins
	corsAllowedOrigins = "https://example.com,*"
	defer func() { corsAllowedOrigins = oldCors }()

	if !isOriginAllowed("https://anything.com") {
		t.Error("expected wildcard in list to allow all")
	}
}

// ==================== Middleware: securityHeadersMiddleware ====================

func TestCB76_SecurityHeadersMiddleware_AddsHeaders(t *testing.T) {
	handler := securityHeadersMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	})

	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()
	handler(w, req)

	if w.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Error("missing X-Content-Type-Options header")
	}
	if w.Header().Get("X-Frame-Options") != "DENY" {
		t.Error("missing X-Frame-Options header")
	}
	if w.Header().Get("X-XSS-Protection") != "1; mode=block" {
		t.Error("missing X-XSS-Protection header")
	}
	if w.Header().Get("Referrer-Policy") != "strict-origin-when-cross-origin" {
		t.Error("missing Referrer-Policy header")
	}
	if w.Header().Get("Permissions-Policy") == "" {
		t.Error("missing Permissions-Policy header")
	}
	if w.Header().Get("Content-Security-Policy") == "" {
		t.Error("missing Content-Security-Policy header")
	}
}

// ==================== Middleware: corsMiddleware ====================

func TestCB76_CorsMiddleware_Wildcard(t *testing.T) {
	oldCors := corsAllowedOrigins
	corsAllowedOrigins = "*"
	defer func() { corsAllowedOrigins = oldCors }()

	handler := corsMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	})

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Origin", "https://example.com")
	w := httptest.NewRecorder()
	handler(w, req)

	if w.Header().Get("Access-Control-Allow-Origin") != "*" {
		t.Errorf("expected '*', got '%s'", w.Header().Get("Access-Control-Allow-Origin"))
	}
}

func TestCB76_CorsMiddleware_SpecificOrigin(t *testing.T) {
	oldCors := corsAllowedOrigins
	corsAllowedOrigins = "https://example.com"
	defer func() { corsAllowedOrigins = oldCors }()

	handler := corsMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	})

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Origin", "https://example.com")
	w := httptest.NewRecorder()
	handler(w, req)

	if w.Header().Get("Access-Control-Allow-Origin") != "https://example.com" {
		t.Errorf("expected 'https://example.com', got '%s'", w.Header().Get("Access-Control-Allow-Origin"))
	}
}

func TestCB76_CorsMiddleware_NoOrigin(t *testing.T) {
	handler := corsMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	})

	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()
	handler(w, req)

	// Should not set CORS headers when no Origin header
	if w.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Error("expected no CORS header without Origin")
	}
}

func TestCB76_CorsMiddleware_DisallowedOrigin(t *testing.T) {
	oldCors := corsAllowedOrigins
	corsAllowedOrigins = "https://allowed.com"
	defer func() { corsAllowedOrigins = oldCors }()

	handler := corsMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	})

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Origin", "https://evil.com")
	w := httptest.NewRecorder()
	handler(w, req)

	if w.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Error("expected no CORS header for disallowed origin")
	}
}

// ==================== Middleware: csrfMiddleware ====================

func TestCB76_CsrfMiddleware_SafeMethod(t *testing.T) {
	called := false
	handler := csrfMiddleware(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(200)
	})

	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()
	handler(w, req)

	if !called {
		t.Error("expected handler to be called for GET")
	}
}

func TestCB76_CsrfMiddleware_XRequestedWith(t *testing.T) {
	called := false
	handler := csrfMiddleware(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(200)
	})

	req := httptest.NewRequest("POST", "/test", nil)
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	w := httptest.NewRecorder()
	handler(w, req)

	if !called {
		t.Error("expected handler to be called with X-Requested-With header")
	}
}

func TestCB76_CsrfMiddleware_CSRFToken(t *testing.T) {
	called := false
	handler := csrfMiddleware(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(200)
	})

	req := httptest.NewRequest("POST", "/test", nil)
	req.Header.Set("X-CSRF-Token", "some-token")
	w := httptest.NewRecorder()
	handler(w, req)

	if !called {
		t.Error("expected handler to be called with X-CSRF-Token header")
	}
}

func TestCB76_CsrfMiddleware_AuthorizationHeader(t *testing.T) {
	called := false
	handler := csrfMiddleware(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(200)
	})

	req := httptest.NewRequest("POST", "/test", nil)
	req.Header.Set("Authorization", "Bearer token")
	w := httptest.NewRecorder()
	handler(w, req)

	if !called {
		t.Error("expected handler to be called with Authorization header")
	}
}

func TestCB76_CsrfMiddleware_AgentSecretHeader(t *testing.T) {
	called := false
	handler := csrfMiddleware(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(200)
	})

	req := httptest.NewRequest("POST", "/test", nil)
	req.Header.Set("X-Agent-Secret", "secret")
	w := httptest.NewRecorder()
	handler(w, req)

	if !called {
		t.Error("expected handler to be called with X-Agent-Secret header")
	}
}

func TestCB76_CsrfMiddleware_AllowedOrigin(t *testing.T) {
	oldCors := corsAllowedOrigins
	corsAllowedOrigins = "https://example.com"
	defer func() { corsAllowedOrigins = oldCors }()

	called := false
	handler := csrfMiddleware(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(200)
	})

	req := httptest.NewRequest("POST", "/test", nil)
	req.Header.Set("Origin", "https://example.com")
	w := httptest.NewRecorder()
	handler(w, req)

	if !called {
		t.Error("expected handler to be called with allowed Origin")
	}
}

func TestCB76_CsrfMiddleware_Blocked(t *testing.T) {
	called := false
	handler := csrfMiddleware(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(200)
	})

	req := httptest.NewRequest("POST", "/test", nil)
	w := httptest.NewRecorder()
	handler(w, req)

	if called {
		t.Error("expected handler NOT to be called without any CSRF headers")
	}
	if w.Code != 403 {
		t.Errorf("expected 403, got %d", w.Code)
	}
}

// ==================== E2E: handleUploadPublicKey ====================

func TestCB76_HandleUploadPublicKey_Success(t *testing.T) {
	testDB := setupTestDB_CB76(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	userID := createUser_CB76(testDB, "user1", "pass")
	token := generateTestToken_CB76(userID)

	body := `{"key_type":"identity","public_key":"base64key","signature":"sig"}`
	req := httptest.NewRequest("POST", "/keys/upload", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleUploadPublicKey(w, req)

	if w.Code != 200 {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCB76_HandleUploadPublicKey_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest("GET", "/keys/upload", nil)
	w := httptest.NewRecorder()
	handleUploadPublicKey(w, req)

	if w.Code != 405 {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestCB76_HandleUploadPublicKey_Unauthorized(t *testing.T) {
	req := httptest.NewRequest("POST", "/keys/upload", nil)
	w := httptest.NewRecorder()
	handleUploadPublicKey(w, req)

	if w.Code != 401 {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestCB76_HandleUploadPublicKey_InvalidJSON(t *testing.T) {
	testDB := setupTestDB_CB76(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	userID := createUser_CB76(testDB, "user1", "pass")
	token := generateTestToken_CB76(userID)

	req := httptest.NewRequest("POST", "/keys/upload", strings.NewReader("invalid json"))
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleUploadPublicKey(w, req)

	if w.Code != 400 {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestCB76_HandleUploadPublicKey_MissingPublicKey(t *testing.T) {
	testDB := setupTestDB_CB76(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	userID := createUser_CB76(testDB, "user1", "pass")
	token := generateTestToken_CB76(userID)

	body := `{"key_type":"identity","public_key":""}`
	req := httptest.NewRequest("POST", "/keys/upload", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleUploadPublicKey(w, req)

	if w.Code != 400 {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestCB76_HandleUploadPublicKey_InvalidKeyType(t *testing.T) {
	testDB := setupTestDB_CB76(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	userID := createUser_CB76(testDB, "user1", "pass")
	token := generateTestToken_CB76(userID)

	body := `{"key_type":"invalid_type","public_key":"somekey"}`
	req := httptest.NewRequest("POST", "/keys/upload", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleUploadPublicKey(w, req)

	if w.Code != 400 {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestCB76_HandleUploadPublicKey_ReplaceIdentityKey(t *testing.T) {
	testDB := setupTestDB_CB76(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	userID := createUser_CB76(testDB, "user1", "pass")
	token := generateTestToken_CB76(userID)

	// Upload first identity key
	body1 := `{"key_type":"identity","public_key":"key1"}`
	req1 := httptest.NewRequest("POST", "/keys/upload", strings.NewReader(body1))
	req1.Header.Set("Authorization", "Bearer "+token)
	w1 := httptest.NewRecorder()
	handleUploadPublicKey(w1, req1)
	if w1.Code != 200 {
		t.Fatalf("first upload failed: %d", w1.Code)
	}

	// Replace with new identity key
	body2 := `{"key_type":"identity","public_key":"key2"}`
	req2 := httptest.NewRequest("POST", "/keys/upload", strings.NewReader(body2))
	req2.Header.Set("Authorization", "Bearer "+token)
	w2 := httptest.NewRecorder()
	handleUploadPublicKey(w2, req2)
	if w2.Code != 200 {
		t.Errorf("expected 200 on replace, got %d", w2.Code)
	}
}

func TestCB76_HandleUploadPublicKey_SignedPreKey(t *testing.T) {
	testDB := setupTestDB_CB76(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	userID := createUser_CB76(testDB, "user1", "pass")
	token := generateTestToken_CB76(userID)

	body := `{"key_type":"signed_prekey","public_key":"spk1","signature":"sig1"}`
	req := httptest.NewRequest("POST", "/keys/upload", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleUploadPublicKey(w, req)

	if w.Code != 200 {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCB76_HandleUploadPublicKey_OneTimePreKey(t *testing.T) {
	testDB := setupTestDB_CB76(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	userID := createUser_CB76(testDB, "user1", "pass")
	token := generateTestToken_CB76(userID)

	body := `{"key_type":"one_time_prekey","public_key":"otpk1","key_id":1}`
	req := httptest.NewRequest("POST", "/keys/upload", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleUploadPublicKey(w, req)

	if w.Code != 200 {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

// ==================== E2E: handleGetKeyBundle ====================

func TestCB76_HandleGetKeyBundle_Success(t *testing.T) {
	testDB := setupTestDB_CB76(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	userID := createUser_CB76(testDB, "user1", "pass")
	token := generateTestToken_CB76(userID)

	// Upload identity key
	body := `{"key_type":"identity","public_key":"identity_key_1"}`
	req1 := httptest.NewRequest("POST", "/keys/upload", strings.NewReader(body))
	req1.Header.Set("Authorization", "Bearer "+token)
	w1 := httptest.NewRecorder()
	handleUploadPublicKey(w1, req1)

	// Get key bundle
	req := httptest.NewRequest("GET", "/keys/bundle?owner_id="+userID+"&owner_type=user", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleGetKeyBundle(w, req)

	if w.Code != 200 {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCB76_HandleGetKeyBundle_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest("POST", "/keys/bundle", nil)
	w := httptest.NewRecorder()
	handleGetKeyBundle(w, req)

	if w.Code != 405 {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestCB76_HandleGetKeyBundle_Unauthorized(t *testing.T) {
	req := httptest.NewRequest("GET", "/keys/bundle", nil)
	w := httptest.NewRecorder()
	handleGetKeyBundle(w, req)

	if w.Code != 401 {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestCB76_HandleGetKeyBundle_MissingOwnerID(t *testing.T) {
	testDB := setupTestDB_CB76(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	userID := createUser_CB76(testDB, "user1", "pass")
	token := generateTestToken_CB76(userID)

	req := httptest.NewRequest("GET", "/keys/bundle", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleGetKeyBundle(w, req)

	if w.Code != 400 {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestCB76_HandleGetKeyBundle_NotFound(t *testing.T) {
	testDB := setupTestDB_CB76(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	userID := createUser_CB76(testDB, "user1", "pass")
	token := generateTestToken_CB76(userID)

	req := httptest.NewRequest("GET", "/keys/bundle?owner_id=nonexistent&owner_type=user", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleGetKeyBundle(w, req)

	if w.Code != 404 {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

func TestCB76_HandleGetKeyBundle_DefaultOwnerType(t *testing.T) {
	testDB := setupTestDB_CB76(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	userID := createUser_CB76(testDB, "user1", "pass")
	token := generateTestToken_CB76(userID)

	// Upload identity key
	body := `{"key_type":"identity","public_key":"identity_key_1"}`
	req1 := httptest.NewRequest("POST", "/keys/upload", strings.NewReader(body))
	req1.Header.Set("Authorization", "Bearer "+token)
	w1 := httptest.NewRecorder()
	handleUploadPublicKey(w1, req1)

	// Get key bundle without owner_type (should default to "user")
	req := httptest.NewRequest("GET", "/keys/bundle?owner_id="+userID, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleGetKeyBundle(w, req)

	if w.Code != 200 {
		t.Errorf("expected 200 with default owner_type, got %d", w.Code)
	}
}

// ==================== E2E: handleListOneTimePreKeys ====================

func TestCB76_HandleListOneTimePreKeys_Success(t *testing.T) {
	testDB := setupTestDB_CB76(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	userID := createUser_CB76(testDB, "user1", "pass")
	token := generateTestToken_CB76(userID)

	// Upload some one-time pre-keys
	for i := 1; i <= 3; i++ {
		body := `{"key_type":"one_time_prekey","public_key":"otpk_` + string(rune('0'+i)) + `","key_id":` + string(rune('0'+i)) + `}`
		req := httptest.NewRequest("POST", "/keys/upload", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		handleUploadPublicKey(w, req)
	}

	// List them - uses authenticated user, no owner_id needed
	req := httptest.NewRequest("GET", "/keys/one-time-prekeys", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleListOneTimePreKeys(w, req)

	if w.Code != 200 {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp map[string]int
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["one_time_prekey_count"] != 3 {
		t.Errorf("expected 3 one-time prekeys, got %d", resp["one_time_prekey_count"])
	}
}

func TestCB76_HandleListOneTimePreKeys_NoKeys(t *testing.T) {
	testDB := setupTestDB_CB76(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	userID := createUser_CB76(testDB, "user1", "pass")
	token := generateTestToken_CB76(userID)

	req := httptest.NewRequest("GET", "/keys/one-time-prekeys", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleListOneTimePreKeys(w, req)

	if w.Code != 200 {
		t.Errorf("expected 200, got %d", w.Code)
	}
	var resp map[string]int
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["one_time_prekey_count"] != 0 {
		t.Errorf("expected 0 one-time prekeys, got %d", resp["one_time_prekey_count"])
	}
}

func TestCB76_HandleListOneTimePreKeys_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest("POST", "/keys/one-time-prekeys", nil)
	w := httptest.NewRecorder()
	handleListOneTimePreKeys(w, req)

	if w.Code != 405 {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestCB76_HandleListOneTimePreKeys_Unauthorized(t *testing.T) {
	req := httptest.NewRequest("GET", "/keys/one-time-prekeys", nil)
	w := httptest.NewRecorder()
	handleListOneTimePreKeys(w, req)

	if w.Code != 401 {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

// ==================== E2E: handleGetEncryptedMessages ====================

func TestCB76_HandleGetEncryptedMessages_Success(t *testing.T) {
	testDB := setupTestDB_CB76(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	userID := createUser_CB76(testDB, "user1", "pass")
	agentID := "agent1"
	createAgent_CB76(testDB, agentID)
	convID := createConversation_CB76(testDB, userID, agentID)

	// Insert an encrypted message
	testDB.Exec(`INSERT INTO encrypted_messages (id, conversation_id, sender_id, ciphertext, nonce, ephemeral_key, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		"enc1", convID, userID, "ciphertext_data", "nonce123", "ephemeral_key_data", time.Now().UTC().Format(time.RFC3339))

	token := generateTestToken_CB76(userID)
	req := httptest.NewRequest("GET", "/messages/encrypted?conversation_id="+convID, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleGetEncryptedMessages(w, req)

	if w.Code != 200 {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCB76_HandleGetEncryptedMessages_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest("POST", "/messages/encrypted", nil)
	w := httptest.NewRecorder()
	handleGetEncryptedMessages(w, req)

	if w.Code != 405 {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestCB76_HandleGetEncryptedMessages_Unauthorized(t *testing.T) {
	req := httptest.NewRequest("GET", "/messages/encrypted?conversation_id=conv1", nil)
	w := httptest.NewRecorder()
	handleGetEncryptedMessages(w, req)

	if w.Code != 401 {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestCB76_HandleGetEncryptedMessages_MissingConvID(t *testing.T) {
	testDB := setupTestDB_CB76(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	userID := createUser_CB76(testDB, "user1", "pass")
	token := generateTestToken_CB76(userID)

	req := httptest.NewRequest("GET", "/messages/encrypted", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleGetEncryptedMessages(w, req)

	if w.Code != 400 {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestCB76_HandleGetEncryptedMessages_NotOwner(t *testing.T) {
	testDB := setupTestDB_CB76(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	userID := createUser_CB76(testDB, "user1", "pass")
	otherUserID := createUser_CB76(testDB, "user2", "pass")
	agentID := "agent1"
	createAgent_CB76(testDB, agentID)
	convID := createConversation_CB76(testDB, userID, agentID)

	token := generateTestToken_CB76(otherUserID)
	req := httptest.NewRequest("GET", "/messages/encrypted?conversation_id="+convID, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleGetEncryptedMessages(w, req)

	if w.Code != 404 {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

// ==================== Push: handleRegisterDeviceToken edge cases ====================

func TestCB76_HandleRegisterDeviceToken_EmptyToken(t *testing.T) {
	testDB := setupTestDB_CB76(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	userID := createUser_CB76(testDB, "user1", "pass")
	token := generateTestToken_CB76(userID)

	body := `{"device_token":"","platform":"ios"}`
	req := httptest.NewRequest("POST", "/push/device-token", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleRegisterDeviceToken(w, req)

	if w.Code != 400 {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestCB76_HandleRegisterDeviceToken_DBError(t *testing.T) {
	testDB := setupTestDB_CB76(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	userID := createUser_CB76(testDB, "user1", "pass")
	token := generateTestToken_CB76(userID)

	testDB.Close()
	body := `{"device_token":"token123","platform":"ios"}`
	req := httptest.NewRequest("POST", "/push/device-token", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleRegisterDeviceToken(w, req)

	if w.Code != 500 {
		t.Errorf("expected 500, got %d", w.Code)
	}
}

// ==================== Push: handleWebPushSubscribe edge cases ====================

func TestCB76_HandleWebPushSubscribe_DBError(t *testing.T) {
	testDB := setupTestDB_CB76(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	userID := createUser_CB76(testDB, "user1", "pass")
	token := generateTestToken_CB76(userID)

	testDB.Close()
	body := `{"endpoint":"https://push.example.com/sub","keys":{"p256dh":"key1","auth":"auth1"}}`
	req := httptest.NewRequest("POST", "/push/web-subscribe", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleWebPushSubscribe(w, req)

	if w.Code != 500 {
		t.Errorf("expected 500, got %d", w.Code)
	}
}

// ==================== Presence: handleGetUserPresence ====================

func TestCB76_HandleGetUserPresence_Online(t *testing.T) {
	testDB := setupTestDB_CB76(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	userID := createUser_CB76(testDB, "user1", "pass")
	token := generateTestToken_CB76(userID)

	// Insert a presence record
	testDB.Exec("INSERT INTO user_presence (user_id, last_seen) VALUES (?, ?)",
		userID, time.Now().UTC().Format(time.RFC3339))

	req := httptest.NewRequest("GET", "/presence/user?user_id="+userID, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleGetUserPresence(w, req)

	if w.Code != 200 {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCB76_HandleGetUserPresence_DefaultUserID(t *testing.T) {
	testDB := setupTestDB_CB76(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	userID := createUser_CB76(testDB, "user1", "pass")
	token := generateTestToken_CB76(userID)

	// No user_id param — should use the JWT user
	req := httptest.NewRequest("GET", "/presence/user", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleGetUserPresence(w, req)

	if w.Code != 200 {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestCB76_HandleGetUserPresence_DBError(t *testing.T) {
	testDB := setupTestDB_CB76(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	userID := createUser_CB76(testDB, "user1", "pass")
	token := generateTestToken_CB76(userID)

	testDB.Close()
	req := httptest.NewRequest("GET", "/presence/user?user_id="+userID, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleGetUserPresence(w, req)

	// With closed DB, should handle gracefully
	if w.Code != 200 && w.Code != 500 {
		t.Errorf("expected 200 or 500, got %d", w.Code)
	}
}

// ==================== Queue: newOfflineQueue ====================

func TestCB76_NewOfflineQueue_Defaults(t *testing.T) {
	q := newOfflineQueue(0, 0)
	if q == nil {
		t.Fatal("expected non-nil queue")
	}
	if q.buffers == nil {
		t.Error("expected non-nil buffers map")
	}
	if q.maxLen != 100 {
		t.Errorf("expected maxLen=100, got %d", q.maxLen)
	}
	if q.ttl != 7*24*time.Hour {
		t.Errorf("expected 7d TTL, got %v", q.ttl)
	}
}

// ==================== Queue: Purge ====================

func TestCB76_QueuePurge_Success(t *testing.T) {
	q := newOfflineQueue(0, 0)
	q.Enqueue("user1", []byte("msg1"))
	q.Enqueue("user1", []byte("msg2"))
	q.Enqueue("user2", []byte("msg3"))

	q.Purge("user1")

	if depth := q.TotalDepth(); depth != 1 {
		t.Errorf("expected depth=1 after purge, got %d", depth)
	}
}

func TestCB76_QueuePurge_NonExistentUser(t *testing.T) {
	q := newOfflineQueue(0, 0)
	q.Purge("nonexistent")
	// Should not panic
}

// ==================== Rate Limit Tiers: SetTier ====================

func TestCB76_SetTier_NewUser(t *testing.T) {
	rl := NewTieredRateLimiter()
	defer rl.Stop()
	rl.SetTier("user1", TierPro)
	if tier := rl.GetTier("user1"); tier != TierPro {
		t.Errorf("expected Pro tier, got %v", tier)
	}
}

func TestCB76_SetTier_UpgradeFromFree(t *testing.T) {
	rl := NewTieredRateLimiter()
	defer rl.Stop()
	// Default is Free
	rl.SetTier("user1", TierEnterprise)
	if tier := rl.GetTier("user1"); tier != TierEnterprise {
		t.Errorf("expected Enterprise tier, got %v", tier)
	}
}

func TestCB76_SetTier_ReplaceExisting(t *testing.T) {
	rl := NewTieredRateLimiter()
	defer rl.Stop()
	rl.SetTier("user1", TierPro)
	rl.SetTier("user1", TierFree)
	if tier := rl.GetTier("user1"); tier != TierFree {
		t.Errorf("expected Free tier after replace, got %v", tier)
	}
}

func TestCB76_SetTier_ReinitializeWindow(t *testing.T) {
	rl := NewTieredRateLimiter()
	// Set tier and use some allowance
	rl.Allow("user1")
	rl.Allow("user1")
	// Setting a new tier should reinitialize the window
	rl.SetTier("user1", TierPro)
	remaining := rl.GetRemaining("user1")
	// After SetTier, window should be fresh
	if remaining <= 0 {
		t.Errorf("expected positive remaining after SetTier, got %d", remaining)
	}
}

// ==================== Rate Limit Tiers: Allow and GetRemaining ====================

func TestCB76_TieredRateLimiter_AllowFreeTier(t *testing.T) {
	rl := NewTieredRateLimiter()
	defer rl.Stop()
	// Free tier: 60/min
	for i := 0; i < 60; i++ {
		ok, _, _ := rl.Allow("user1")
		if !ok {
			t.Errorf("expected Allow=true for attempt %d in free tier", i+1)
		}
	}
	// 61st should be blocked
	ok, _, _ := rl.Allow("user1")
	if ok {
		t.Error("expected Allow=false after 60 requests in free tier")
	}
}

func TestCB76_TieredRateLimiter_AllowProTier(t *testing.T) {
	rl := NewTieredRateLimiter()
	defer rl.Stop()
	rl.SetTier("user1", TierPro)
	for i := 0; i < 300; i++ {
		ok, _, _ := rl.Allow("user1")
		if !ok {
			t.Errorf("expected Allow=true for attempt %d in pro tier", i+1)
		}
	}
	ok, _, _ := rl.Allow("user1")
	if ok {
		t.Error("expected Allow=false after 300 requests in pro tier")
	}
}

func TestCB76_TieredRateLimiter_AllowEnterpriseTier(t *testing.T) {
	rl := NewTieredRateLimiter()
	defer rl.Stop()
	rl.SetTier("user1", TierEnterprise)
	for i := 0; i < 1500; i++ {
		ok, _, _ := rl.Allow("user1")
		if !ok {
			t.Errorf("expected Allow=true for attempt %d in enterprise tier", i+1)
		}
	}
	ok, _, _ := rl.Allow("user1")
	if ok {
		t.Error("expected Allow=false after 1500 requests in enterprise tier")
	}
}

func TestCB76_TieredRateLimiter_GetRemaining_Free(t *testing.T) {
	rl := NewTieredRateLimiter()
	defer rl.Stop()
	remaining := rl.GetRemaining("user1")
	if remaining != 60 {
		t.Errorf("expected 60 remaining for free tier, got %d", remaining)
	}
}

func TestCB76_TieredRateLimiter_GetRemaining_AfterUse(t *testing.T) {
	rl := NewTieredRateLimiter()
	defer rl.Stop()
	rl.Allow("user1")
	rl.Allow("user1")
	remaining := rl.GetRemaining("user1")
	if remaining != 58 {
		t.Errorf("expected 58 remaining after 2 uses, got %d", remaining)
	}
}

func TestCB76_TieredRateLimiter_GetRemaining_ProTier(t *testing.T) {
	rl := NewTieredRateLimiter()
	defer rl.Stop()
	rl.SetTier("user1", TierPro)
	remaining := rl.GetRemaining("user1")
	if remaining != 300 {
		t.Errorf("expected 300 remaining for pro tier, got %d", remaining)
	}
}

// ==================== Presence: handleGetPresence edge cases ====================

func TestCB76_HandleGetPresence_WithAgents(t *testing.T) {
	testDB := setupTestDB_CB76(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	userID := createUser_CB76(testDB, "user1", "pass")
	token := generateTestToken_CB76(userID)
	createAgent_CB76(testDB, "agent1")
	createAgent_CB76(testDB, "agent2")

	req := httptest.NewRequest("GET", "/presence/agents", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleGetPresence(w, req)

	if w.Code != 200 {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

// ==================== ensureUploadDir ====================

func TestCB76_EnsureUploadDir_Success(t *testing.T) {
	oldPath := serverDBPath
	serverDBPath = "/tmp/am_test_uploads_76"
	defer func() {
		serverDBPath = oldPath
	}()

	err := ensureUploadDir()
	if err != nil {
		t.Fatalf("ensureUploadDir failed: %v", err)
	}
}

// ==================== metrics_handler: boolToInt ====================

func TestCB76_BoolToInt_True(t *testing.T) {
	if boolToInt(true) != 1 {
		t.Error("expected boolToInt(true)=1")
	}
}

func TestCB76_BoolToInt_False(t *testing.T) {
	if boolToInt(false) != 0 {
		t.Error("expected boolToInt(false)=0")
	}
}

// ==================== Logger: SetLevel and SetOutput ====================

func TestCB76_Logger_SetLevel(t *testing.T) {
	oldLogger := DefaultLogger
	defer func() { DefaultLogger = oldLogger }()

	l := NewLogger(LogDebug)
	l.SetLevel(LogError)
	// Should not panic
	if l.level != LogError {
		t.Errorf("expected level LogError, got %v", l.level)
	}
}

func TestCB76_Logger_SetOutput(t *testing.T) {
	l := NewLogger(LogDebug)
	var buf strings.Builder
	l.SetOutput(&buf)
	l.Info("test_message", nil)
	if !strings.Contains(buf.String(), "test_message") {
		t.Error("expected 'test_message' in output")
	}
}

// ==================== resetAgentSecret / resetAdminSecret ====================

func TestCB76_ResetAgentSecret(t *testing.T) {
	oldSecret := agentSecret
	oldEnv := os.Getenv("AGENT_SECRET")
	os.Unsetenv("AGENT_SECRET")
	defer func() {
		agentSecret = oldSecret
		if oldEnv != "" {
			os.Setenv("AGENT_SECRET", oldEnv)
		}
	}()

	resetAgentSecret()
	if agentSecret != "dev-agent-secret-change-me" {
		t.Errorf("expected dev default secret after reset, got '%s'", agentSecret)
	}
}

func TestCB76_ResetAdminSecret(t *testing.T) {
	oldSecret := adminSecret
	oldEnv := os.Getenv("ADMIN_SECRET")
	os.Unsetenv("ADMIN_SECRET")
	defer func() {
		adminSecret = oldSecret
		if oldEnv != "" {
			os.Setenv("ADMIN_SECRET", oldEnv)
		}
	}()

	resetAdminSecret()
	if adminSecret != "admin-dev-secret" {
		t.Errorf("expected dev default admin secret after reset, got '%s'", adminSecret)
	}
}