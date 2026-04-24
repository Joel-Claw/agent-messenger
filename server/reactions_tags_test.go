package main

import (
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestAddReaction(t *testing.T) {
	setupTestDB(t)
	hub = newHub()
	go hub.run()

	token := registerUserAndGetToken(t, "reactuser", "pass123")
	userID := getUserIDFromToken(t, token)
	createTestAgent(t, "react-agent", "React Bot")
	convID := createTestConversation(t, token, "react-agent")

	// Store a message
	msg := RoutedMessage{
		Type:           MsgTypeMessage,
		ConversationID: convID,
		Content:        "React to this!",
		SenderType:     "agent",
		SenderID:       "react-agent",
	}
	storeMessage(msg)

	var msgID string
	db.QueryRow("SELECT id FROM messages WHERE conversation_id = ? ORDER BY created_at DESC LIMIT 1", convID).Scan(&msgID)

	// Add a reaction
	form := url.Values{
		"message_id": {msgID},
		"emoji":      {"👍"},
	}
	req := httptest.NewRequest("POST", "/messages/react", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleReact(w, req)

	if w.Code != 200 {
		t.Fatalf("Expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var count int
	db.QueryRow("SELECT COUNT(*) FROM reactions WHERE message_id = ? AND emoji = ?", msgID, "👍").Scan(&count)
	if count != 1 {
		t.Errorf("Expected 1 reaction, got %d", count)
	}

	// Toggle: same reaction should remove it
	req2 := httptest.NewRequest("POST", "/messages/react", strings.NewReader(form.Encode()))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req2.Header.Set("Authorization", "Bearer "+token)
	w2 := httptest.NewRecorder()
	handleReact(w2, req2)

	if w2.Code != 200 {
		t.Errorf("Expected 200 on toggle, got %d: %s", w2.Code, w2.Body.String())
	}

	db.QueryRow("SELECT COUNT(*) FROM reactions WHERE message_id = ? AND emoji = ?", msgID, "👍").Scan(&count)
	if count != 0 {
		t.Errorf("Expected 0 reactions after toggle, got %d", count)
	}

	_ = userID // used implicitly through token
}

func TestAddReactionUnauthorized(t *testing.T) {
	setupTestDB(t)
	hub = newHub()
	go hub.run()

	token := registerUserAndGetToken(t, "authuser", "pass123")
	otherToken := registerUserAndGetToken(t, "otheruser", "pass123")
	createTestAgent(t, "auth-agent", "Auth Bot")
	convID := createTestConversation(t, token, "auth-agent")

	msg := RoutedMessage{
		Type:           MsgTypeMessage,
		ConversationID: convID,
		Content:        "Secret message",
		SenderType:     "agent",
		SenderID:       "auth-agent",
	}
	storeMessage(msg)

	var msgID string
	db.QueryRow("SELECT id FROM messages WHERE conversation_id = ? LIMIT 1", convID).Scan(&msgID)

	form := url.Values{
		"message_id": {msgID},
		"emoji":      {"❤️"},
	}
	req := httptest.NewRequest("POST", "/messages/react", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+otherToken)
	w := httptest.NewRecorder()
	handleReact(w, req)

	if w.Code != 401 {
		t.Errorf("Expected 401, got %d", w.Code)
	}
}

func TestGetReactions(t *testing.T) {
	setupTestDB(t)
	hub = newHub()
	go hub.run()

	token := registerUserAndGetToken(t, "getrxnuser", "pass123")
	userID := getUserIDFromToken(t, token)
	createTestAgent(t, "getrxn-agent", "Bot")
	convID := createTestConversation(t, token, "getrxn-agent")

	msg := RoutedMessage{
		Type:           MsgTypeMessage,
		ConversationID: convID,
		Content:        "Get my reactions",
		SenderType:     "agent",
		SenderID:       "getrxn-agent",
	}
	storeMessage(msg)

	var msgID string
	db.QueryRow("SELECT id FROM messages WHERE conversation_id = ? LIMIT 1", convID).Scan(&msgID)

	addReaction(msgID, userID, "👍")
	addReaction(msgID, userID, "❤️")

	req := httptest.NewRequest("GET", "/messages/reactions?message_id="+msgID, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleGetReactions(w, req)

	if w.Code != 200 {
		t.Fatalf("Expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var reactions []MessageReaction
	json.Unmarshal(w.Body.Bytes(), &reactions)
	if len(reactions) != 2 {
		t.Errorf("Expected 2 reactions, got %d", len(reactions))
	}
}

func TestReactionMessageNotFound(t *testing.T) {
	setupTestDB(t)
	hub = newHub()
	go hub.run()

	token := registerUserAndGetToken(t, "nfounduser", "pass123")

	form := url.Values{
		"message_id": {"msg_nonexistent"},
		"emoji":      {"👍"},
	}
	req := httptest.NewRequest("POST", "/messages/react", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleReact(w, req)

	if w.Code != 404 {
		t.Errorf("Expected 404, got %d", w.Code)
	}
}

func TestReactionMissingFields(t *testing.T) {
	setupTestDB(t)
	hub = newHub()
	go hub.run()

	token := registerUserAndGetToken(t, "missrxnuser", "pass123")

	form := url.Values{
		"message_id": {"msg_1"},
	}
	req := httptest.NewRequest("POST", "/messages/react", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleReact(w, req)

	if w.Code != 400 {
		t.Errorf("Expected 400, got %d", w.Code)
	}
}

// Conversation Tag tests

func TestAddConversationTag(t *testing.T) {
	setupTestDB(t)
	hub = newHub()
	go hub.run()

	token := registerUserAndGetToken(t, "taguser", "pass123")
	createTestAgent(t, "tag-agent", "Tag Bot")
	convID := createTestConversation(t, token, "tag-agent")

	form := url.Values{
		"conversation_id": {convID},
		"tag":             {"important"},
	}
	req := httptest.NewRequest("POST", "/conversations/tags/add", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleAddTag(w, req)

	if w.Code != 200 {
		t.Fatalf("Expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var count int
	db.QueryRow("SELECT COUNT(*) FROM conversation_tags WHERE conversation_id = ? AND tag = ?", convID, "important").Scan(&count)
	if count != 1 {
		t.Errorf("Expected 1 tag, got %d", count)
	}
}

func TestAddDuplicateTag(t *testing.T) {
	setupTestDB(t)
	hub = newHub()
	go hub.run()

	token := registerUserAndGetToken(t, "duptaguser", "pass123")
	createTestAgent(t, "duptag-agent", "Bot")
	convID := createTestConversation(t, token, "duptag-agent")

	form := url.Values{
		"conversation_id": {convID},
		"tag":             {"work"},
	}
	req1 := httptest.NewRequest("POST", "/conversations/tags/add", strings.NewReader(form.Encode()))
	req1.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req1.Header.Set("Authorization", "Bearer "+token)
	w1 := httptest.NewRecorder()
	handleAddTag(w1, req1)

	req2 := httptest.NewRequest("POST", "/conversations/tags/add", strings.NewReader(form.Encode()))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req2.Header.Set("Authorization", "Bearer "+token)
	w2 := httptest.NewRecorder()
	handleAddTag(w2, req2)

	if w2.Code != 409 {
		t.Errorf("Expected 409 for duplicate tag, got %d", w2.Code)
	}
}

func TestRemoveConversationTag(t *testing.T) {
	setupTestDB(t)
	hub = newHub()
	go hub.run()

	token := registerUserAndGetToken(t, "rmtaguser", "pass123")
	userID := getUserIDFromToken(t, token)
	createTestAgent(t, "rmtag-agent", "Bot")
	convID := createTestConversation(t, token, "rmtag-agent")

	addConversationTag(convID, userID, "todo")

	form := url.Values{
		"conversation_id": {convID},
		"tag":             {"todo"},
	}
	req := httptest.NewRequest("POST", "/conversations/tags/remove", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleRemoveTag(w, req)

	if w.Code != 200 {
		t.Fatalf("Expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var count int
	db.QueryRow("SELECT COUNT(*) FROM conversation_tags WHERE conversation_id = ?", convID).Scan(&count)
	if count != 0 {
		t.Errorf("Expected 0 tags after removal, got %d", count)
	}
}

func TestRemoveNonexistentTag(t *testing.T) {
	setupTestDB(t)
	hub = newHub()
	go hub.run()

	token := registerUserAndGetToken(t, "rmtag2user", "pass123")
	createTestAgent(t, "rmtag2-agent", "Bot")
	convID := createTestConversation(t, token, "rmtag2-agent")

	form := url.Values{
		"conversation_id": {convID},
		"tag":             {"nonexistent"},
	}
	req := httptest.NewRequest("POST", "/conversations/tags/remove", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleRemoveTag(w, req)

	if w.Code != 404 {
		t.Errorf("Expected 404 for nonexistent tag, got %d", w.Code)
	}
}

func TestGetConversationTags(t *testing.T) {
	setupTestDB(t)
	hub = newHub()
	go hub.run()

	token := registerUserAndGetToken(t, "gettaguser", "pass123")
	userID := getUserIDFromToken(t, token)
	createTestAgent(t, "gettag-agent", "Bot")
	convID := createTestConversation(t, token, "gettag-agent")

	addConversationTag(convID, userID, "alpha")
	addConversationTag(convID, userID, "beta")

	req := httptest.NewRequest("GET", "/conversations/tags?conversation_id="+convID, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleGetTags(w, req)

	if w.Code != 200 {
		t.Fatalf("Expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var tags []ConversationTag
	json.Unmarshal(w.Body.Bytes(), &tags)
	if len(tags) != 2 {
		t.Errorf("Expected 2 tags, got %d", len(tags))
	}
}

func TestTagUnauthorized(t *testing.T) {
	setupTestDB(t)
	hub = newHub()
	go hub.run()

	token := registerUserAndGetToken(t, "tagauthuser", "pass123")
	otherToken := registerUserAndGetToken(t, "tagotheruser", "pass123")
	createTestAgent(t, "tagauth-agent", "Bot")
	convID := createTestConversation(t, token, "tagauth-agent")

	form := url.Values{
		"conversation_id": {convID},
		"tag":             {"hacked"},
	}
	req := httptest.NewRequest("POST", "/conversations/tags/add", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+otherToken)
	w := httptest.NewRecorder()
	handleAddTag(w, req)

	if w.Code != 401 {
		t.Errorf("Expected 401, got %d", w.Code)
	}
}

// Helper: extract user ID from JWT token
func getUserIDFromToken(t *testing.T, token string) string {
	t.Helper()
	claims, err := ValidateJWT(token)
	if err != nil {
		t.Fatalf("Invalid token: %v", err)
	}
	return claims.UserID
}

// Helper functions for tests

func createTestAgent(t *testing.T, agentID, name string) {
	t.Helper()
	_, err := db.Exec("INSERT OR IGNORE INTO agents (id, name) VALUES (?, ?)", agentID, name)
	if err != nil {
		t.Fatalf("Failed to create test agent: %v", err)
	}
}

func createTestConversation(t *testing.T, token, agentID string) string {
	t.Helper()
	claims, err := ValidateJWT(token)
	if err != nil {
		t.Fatalf("Invalid token: %v", err)
	}
	conv, err := GetOrCreateConversation(claims.UserID, agentID)
	if err != nil {
		t.Fatalf("Failed to create conversation: %v", err)
	}
	return conv.ID
}