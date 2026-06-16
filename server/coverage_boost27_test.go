package main

// Coverage boost 27: Deep integration tests for handler functions with real DB
// Targeting:
// - handleMessageEdit: success path, deleted message, not your message, message not found
// - handleMessageDelete: success path, not your message but owns conversation, already deleted
// - handleReact: add reaction, toggle off, emoji too long, missing fields
// - handleGetReactions: success, message not found, unauthorized
// - handleAddTag: success, duplicate tag, tag too long, unauthorized, conv not found
// - handleRemoveTag: success, tag not found, unauthorized
// - handleGetTags: success, empty tags, unauthorized
// - handleSetNotificationPrefs: success, not your conversation, conv not found
// - handleGetNotificationPrefs: success, empty
// - handleDeleteNotificationPrefs: success
// - handleGetPresence: with online agents, empty agents
// - handleGetUserPresence: online user, offline user, missing user_id param
// - handleUploadPublicKey: identity key replace, signed prekey, invalid key type, missing public key
// - handleGetKeyBundle: full bundle, missing owner_id
// - handleStoreEncryptedMessage: success, unsupported algorithm, not participant
// - handleGetEncryptedMessages: success, missing conversation_id
// - conversations: GetOrCreateConversation, searchMessages with real DB

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// cb27SetupDB initializes an in-memory SQLite DB with schema for testing
func cb27SetupDB(t *testing.T) {
	t.Helper()
	var err error
	db, err = sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if err := initSchema(db); err != nil {
		t.Fatal(err)
	}
}

// cb27SetupHub initializes hub with heartbeat monitoring off
func cb27SetupHub(t *testing.T) {
	t.Helper()
	origPresence := agentPresenceEnabled
	agentPresenceEnabled = false
	t.Cleanup(func() { agentPresenceEnabled = origPresence })

	messageRateLimiter = NewRateLimiter(60, time.Minute)
	t.Cleanup(func() { messageRateLimiter.Stop() })
	userRateLimiter = NewRateLimiter(120, time.Minute)
	t.Cleanup(func() { userRateLimiter.Stop() })
	globalTieredLimiter = NewTieredRateLimiter()
	t.Cleanup(func() { globalTieredLimiter.Stop() })
	ipRateLimiter = NewRateLimiter(300, time.Minute)
	t.Cleanup(func() { ipRateLimiter.Stop() })
	authIPLimiter = NewRateLimiter(30, time.Minute)
	t.Cleanup(func() { authIPLimiter.Stop() })
	agentRateLimiter.Reset()

	hub = newHub()
	go hub.run()
	t.Cleanup(func() { hub.Stop() })

	ServerMetrics = NewMetrics(hub)
}

// cb27MakeJWT creates a valid JWT for testing
func cb27MakeJWT(t *testing.T, userID, username string) string {
	t.Helper()
	token, err := GenerateJWT(userID, username)
	if err != nil {
		t.Fatal(err)
	}
	return token
}

// cb27RegisterUser creates a user in the DB and returns their JWT
func cb27RegisterUser(t *testing.T, username, password string) (string, string) {
	t.Helper()
	userID := generateID("user")
	hash, err := HashAPIKey(password)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)", userID, username, hash)
	if err != nil {
		t.Fatal(err)
	}
	return userID, cb27MakeJWT(t, userID, username)
}

// cb27RegisterAgent creates an agent in the DB
func cb27RegisterAgent(t *testing.T, agentID, name string) {
	t.Helper()
	_, err := db.Exec("INSERT INTO agents (id, name) VALUES (?, ?)", agentID, name)
	if err != nil {
		t.Fatal(err)
	}
}

// cb27CreateConversation creates a conversation and returns its ID
func cb27CreateConversation(t *testing.T, userID, agentID string) string {
	t.Helper()
	convID := generateID("conv")
	_, err := db.Exec("INSERT INTO conversations (id, user_id, agent_id, created_at) VALUES (?, ?, ?, ?)",
		convID, userID, agentID, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	return convID
}

// cb27StoreMessage inserts a message into the DB
func cb27StoreMessage(t *testing.T, convID, senderType, senderID, content string) string {
	t.Helper()
	msgID := generateID("msg")
	_, err := db.Exec(`
		INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, metadata, created_at)
		VALUES (?, ?, ?, ?, ?, '', ?)`,
		msgID, convID, senderType, senderID, content, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	return msgID
}

// ==============================
// Message Edit Tests
// ==============================

func TestCB27_HandleMessageEdit_Success(t *testing.T) {
	cb27SetupDB(t)
	cb27SetupHub(t)

	userID, token := cb27RegisterUser(t, "edituser", "pass123")
	agentID := "agent-edit"
	cb27RegisterAgent(t, agentID, "EditBot")
	convID := cb27CreateConversation(t, userID, agentID)
	msgID := cb27StoreMessage(t, convID, "client", userID, "original content")

	form := url.Values{}
	form.Set("message_id", msgID)
	form.Set("content", "edited content")

	req := httptest.NewRequest(http.MethodPost, "/messages/edit", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	handleMessageEdit(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp["status"] != "edited" {
		t.Errorf("expected status=edited, got %v", resp["status"])
	}
	if resp["content"] != "edited content" {
		t.Errorf("expected content=edited content, got %v", resp["content"])
	}
}

func TestCB27_HandleMessageEdit_DeletedMessage(t *testing.T) {
	cb27SetupDB(t)
	cb27SetupHub(t)

	userID, token := cb27RegisterUser(t, "editdel", "pass123")
	agentID := "agent-editdel"
	cb27RegisterAgent(t, agentID, "EditDelBot")
	convID := cb27CreateConversation(t, userID, agentID)
	msgID := cb27StoreMessage(t, convID, "client", userID, "deleted msg")

	// Mark message as deleted
	_, err := db.Exec("UPDATE messages SET is_deleted = 1, content = '[deleted]' WHERE id = ?", msgID)
	if err != nil {
		t.Fatal(err)
	}

	form := url.Values{}
	form.Set("message_id", msgID)
	form.Set("content", "try edit")

	req := httptest.NewRequest(http.MethodPost, "/messages/edit", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	handleMessageEdit(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestCB27_HandleMessageEdit_NotYourMessage(t *testing.T) {
	cb27SetupDB(t)
	cb27SetupHub(t)

	userID, token := cb27RegisterUser(t, "editother", "pass123")
	agentID := "agent-editother"
	cb27RegisterAgent(t, agentID, "EditOtherBot")
	convID := cb27CreateConversation(t, userID, agentID)
	// Message sent by agent, not client
	msgID := cb27StoreMessage(t, convID, "agent", agentID, "agent message")

	form := url.Values{}
	form.Set("message_id", msgID)
	form.Set("content", "try edit agent msg")

	req := httptest.NewRequest(http.MethodPost, "/messages/edit", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	handleMessageEdit(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestCB27_HandleMessageEdit_MessageNotFound(t *testing.T) {
	cb27SetupDB(t)
	cb27SetupHub(t)

	_, token := cb27RegisterUser(t, "editnf", "pass123")

	form := url.Values{}
	form.Set("message_id", "nonexistent-id")
	form.Set("content", "some content")

	req := httptest.NewRequest(http.MethodPost, "/messages/edit", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	handleMessageEdit(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}

func TestCB27_HandleMessageEdit_MissingMessageID(t *testing.T) {
	cb27SetupDB(t)
	cb27SetupHub(t)

	_, token := cb27RegisterUser(t, "editmiss", "pass123")

	form := url.Values{}
	form.Set("content", "some content")

	req := httptest.NewRequest(http.MethodPost, "/messages/edit", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	handleMessageEdit(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestCB27_HandleMessageEdit_EmptyContent(t *testing.T) {
	cb27SetupDB(t)
	cb27SetupHub(t)

	_, token := cb27RegisterUser(t, "editempty", "pass123")

	form := url.Values{}
	form.Set("message_id", "some-id")
	form.Set("content", "")

	req := httptest.NewRequest(http.MethodPost, "/messages/edit", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	handleMessageEdit(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestCB27_HandleMessageEdit_NoAuth(t *testing.T) {
	cb27SetupDB(t)

	req := httptest.NewRequest(http.MethodPost, "/messages/edit", nil)
	w := httptest.NewRecorder()
	handleMessageEdit(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestCB27_HandleMessageEdit_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/messages/edit", nil)
	w := httptest.NewRecorder()
	handleMessageEdit(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", w.Code)
	}
}

// ==============================
// Message Delete Tests
// ==============================

func TestCB27_HandleMessageDelete_Success(t *testing.T) {
	cb27SetupDB(t)
	cb27SetupHub(t)

	userID, token := cb27RegisterUser(t, "deluser", "pass123")
	agentID := "agent-del"
	cb27RegisterAgent(t, agentID, "DelBot")
	convID := cb27CreateConversation(t, userID, agentID)
	msgID := cb27StoreMessage(t, convID, "client", userID, "message to delete")

	form := url.Values{}
	form.Set("message_id", msgID)

	req := httptest.NewRequest(http.MethodPost, "/messages/delete", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	handleMessageDelete(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp["status"] != "deleted" {
		t.Errorf("expected status=deleted, got %v", resp["status"])
	}
}

func TestCB27_HandleMessageDelete_AlreadyDeleted(t *testing.T) {
	cb27SetupDB(t)
	cb27SetupHub(t)

	userID, token := cb27RegisterUser(t, "delalready", "pass123")
	agentID := "agent-delalready"
	cb27RegisterAgent(t, agentID, "DelAlreadyBot")
	convID := cb27CreateConversation(t, userID, agentID)
	msgID := cb27StoreMessage(t, convID, "client", userID, "already deleted")

	_, err := db.Exec("UPDATE messages SET is_deleted = 1, content = '[deleted]' WHERE id = ?", msgID)
	if err != nil {
		t.Fatal(err)
	}

	form := url.Values{}
	form.Set("message_id", msgID)

	req := httptest.NewRequest(http.MethodPost, "/messages/delete", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	handleMessageDelete(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestCB27_HandleMessageDelete_OwnerCanDeleteAgentMessage(t *testing.T) {
	cb27SetupDB(t)
	cb27SetupHub(t)

	userID, token := cb27RegisterUser(t, "delowner", "pass123")
	agentID := "agent-delowner"
	cb27RegisterAgent(t, agentID, "DelOwnerBot")
	convID := cb27CreateConversation(t, userID, agentID)
	// Message sent by agent, but user owns conversation
	msgID := cb27StoreMessage(t, convID, "agent", agentID, "agent message to delete")

	form := url.Values{}
	form.Set("message_id", msgID)

	req := httptest.NewRequest(http.MethodPost, "/messages/delete", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	handleMessageDelete(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 (owner can delete), got %d: %s", w.Code, w.Body.String())
	}
}

func TestCB27_HandleMessageDelete_NotParticipant(t *testing.T) {
	cb27SetupDB(t)
	cb27SetupHub(t)

	userID1, _ := cb27RegisterUser(t, "delnotpart1", "pass123")
	_, token2 := cb27RegisterUser(t, "delnotpart2", "pass123")
	agentID := "agent-delnotpart"
	cb27RegisterAgent(t, agentID, "DelNotPartBot")
	convID := cb27CreateConversation(t, userID1, agentID)
	msgID := cb27StoreMessage(t, convID, "client", userID1, "someone else's message")

	form := url.Values{}
	form.Set("message_id", msgID)

	req := httptest.NewRequest(http.MethodPost, "/messages/delete", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token2)

	w := httptest.NewRecorder()
	handleMessageDelete(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestCB27_HandleMessageDelete_MessageNotFound(t *testing.T) {
	cb27SetupDB(t)
	cb27SetupHub(t)

	_, token := cb27RegisterUser(t, "delnf", "pass123")

	form := url.Values{}
	form.Set("message_id", "nonexistent-id")

	req := httptest.NewRequest(http.MethodPost, "/messages/delete", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	handleMessageDelete(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}

func TestCB27_HandleMessageDelete_MissingMessageID(t *testing.T) {
	cb27SetupDB(t)
	cb27SetupHub(t)

	_, token := cb27RegisterUser(t, "delmiss", "pass123")

	req := httptest.NewRequest(http.MethodPost, "/messages/delete", strings.NewReader(""))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	handleMessageDelete(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestCB27_HandleMessageDelete_NoAuth(t *testing.T) {
	cb27SetupDB(t)

	req := httptest.NewRequest(http.MethodPost, "/messages/delete", nil)
	w := httptest.NewRecorder()
	handleMessageDelete(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestCB27_HandleMessageDelete_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/messages/delete", nil)
	w := httptest.NewRecorder()
	handleMessageDelete(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", w.Code)
	}
}

// ==============================
// Reactions Tests
// ==============================

func TestCB27_HandleReact_AddReaction(t *testing.T) {
	cb27SetupDB(t)
	cb27SetupHub(t)

	userID, token := cb27RegisterUser(t, "reactuser", "pass123")
	agentID := "agent-react"
	cb27RegisterAgent(t, agentID, "ReactBot")
	convID := cb27CreateConversation(t, userID, agentID)
	msgID := cb27StoreMessage(t, convID, "client", userID, "react to this")

	form := url.Values{}
	form.Set("message_id", msgID)
	form.Set("emoji", "👍")

	req := httptest.NewRequest(http.MethodPost, "/messages/react", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	handleReact(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp["status"] != "reaction_added" {
		t.Errorf("expected status=reaction_added, got %v", resp["status"])
	}
}

func TestCB27_HandleReact_ToggleOff(t *testing.T) {
	cb27SetupDB(t)
	cb27SetupHub(t)

	userID, token := cb27RegisterUser(t, "reacttoggle", "pass123")
	agentID := "agent-reacttoggle"
	cb27RegisterAgent(t, agentID, "ReactToggleBot")
	convID := cb27CreateConversation(t, userID, agentID)
	msgID := cb27StoreMessage(t, convID, "client", userID, "toggle reaction")

	// First add
	form := url.Values{}
	form.Set("message_id", msgID)
	form.Set("emoji", "❤️")

	req := httptest.NewRequest(http.MethodPost, "/messages/react", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleReact(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 on first react, got %d", w.Code)
	}

	// Toggle off (same emoji)
	req2 := httptest.NewRequest(http.MethodPost, "/messages/react", strings.NewReader(form.Encode()))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req2.Header.Set("Authorization", "Bearer "+token)
	w2 := httptest.NewRecorder()
	handleReact(w2, req2)

	if w2.Code != http.StatusOK {
		t.Fatalf("expected 200 on toggle, got %d", w2.Code)
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(w2.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp["status"] != "reaction_removed" {
		t.Errorf("expected status=reaction_removed, got %v", resp["status"])
	}
}

func TestCB27_HandleReact_EmojiTooLong(t *testing.T) {
	cb27SetupDB(t)
	cb27SetupHub(t)

	_, token := cb27RegisterUser(t, "reactlong", "pass123")

	form := url.Values{}
	form.Set("message_id", "some-msg")
	form.Set("emoji", strings.Repeat("a", 15))

	req := httptest.NewRequest(http.MethodPost, "/messages/react", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	handleReact(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestCB27_HandleReact_MissingFields(t *testing.T) {
	cb27SetupDB(t)
	cb27SetupHub(t)

	_, token := cb27RegisterUser(t, "reactmiss", "pass123")

	form := url.Values{}
	form.Set("message_id", "some-msg")
	// No emoji

	req := httptest.NewRequest(http.MethodPost, "/messages/react", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	handleReact(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestCB27_HandleReact_MessageNotFound(t *testing.T) {
	cb27SetupDB(t)
	cb27SetupHub(t)

	_, token := cb27RegisterUser(t, "reactnf", "pass123")

	form := url.Values{}
	form.Set("message_id", "nonexistent-msg")
	form.Set("emoji", "👍")

	req := httptest.NewRequest(http.MethodPost, "/messages/react", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	handleReact(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}

func TestCB27_HandleReact_NoAuth(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/messages/react", nil)
	w := httptest.NewRecorder()
	handleReact(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestCB27_HandleGetReactions_Success(t *testing.T) {
	cb27SetupDB(t)
	cb27SetupHub(t)

	userID, token := cb27RegisterUser(t, "getreactuser", "pass123")
	agentID := "agent-getreact"
	cb27RegisterAgent(t, agentID, "GetReactBot")
	convID := cb27CreateConversation(t, userID, agentID)
	msgID := cb27StoreMessage(t, convID, "client", userID, "get reactions")

	// Add a reaction first
	addReaction(msgID, userID, "🔥")

	req := httptest.NewRequest(http.MethodGet, "/messages/reactions?message_id="+msgID, nil)
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	handleGetReactions(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var reactions []MessageReaction
	if err := json.Unmarshal(w.Body.Bytes(), &reactions); err != nil {
		t.Fatal(err)
	}
	if len(reactions) != 1 {
		t.Errorf("expected 1 reaction, got %d", len(reactions))
	}
}

func TestCB27_HandleGetReactions_MessageNotFound(t *testing.T) {
	cb27SetupDB(t)
	cb27SetupHub(t)

	_, token := cb27RegisterUser(t, "getreactnf", "pass123")

	req := httptest.NewRequest(http.MethodGet, "/messages/reactions?message_id=nonexistent", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	handleGetReactions(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}

func TestCB27_HandleGetReactions_MissingMessageID(t *testing.T) {
	cb27SetupDB(t)
	cb27SetupHub(t)

	_, token := cb27RegisterUser(t, "getreactmiss", "pass123")

	req := httptest.NewRequest(http.MethodGet, "/messages/reactions", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	handleGetReactions(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

// ==============================
// Tags Tests
// ==============================

func TestCB27_HandleAddTag_Success(t *testing.T) {
	cb27SetupDB(t)
	cb27SetupHub(t)

	userID, token := cb27RegisterUser(t, "taguser", "pass123")
	agentID := "agent-tag"
	cb27RegisterAgent(t, agentID, "TagBot")
	convID := cb27CreateConversation(t, userID, agentID)

	form := url.Values{}
	form.Set("conversation_id", convID)
	form.Set("tag", "important")

	req := httptest.NewRequest(http.MethodPost, "/conversations/tags/add", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	handleAddTag(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp["status"] != "tag_added" {
		t.Errorf("expected status=tag_added, got %v", resp["status"])
	}
}

func TestCB27_HandleAddTag_Duplicate(t *testing.T) {
	cb27SetupDB(t)
	cb27SetupHub(t)

	userID, token := cb27RegisterUser(t, "tagdup", "pass123")
	agentID := "agent-tagdup"
	cb27RegisterAgent(t, agentID, "TagDupBot")
	convID := cb27CreateConversation(t, userID, agentID)

	// Add tag first
	addConversationTag(convID, userID, "important")

	form := url.Values{}
	form.Set("conversation_id", convID)
	form.Set("tag", "important")

	req := httptest.NewRequest(http.MethodPost, "/conversations/tags/add", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	handleAddTag(w, req)

	if w.Code != http.StatusConflict {
		t.Fatalf("expected 409, got %d", w.Code)
	}
}

func TestCB27_HandleAddTag_TagTooLong(t *testing.T) {
	cb27SetupDB(t)
	cb27SetupHub(t)

	userID, token := cb27RegisterUser(t, "taglong", "pass123")
	agentID := "agent-taglong"
	cb27RegisterAgent(t, agentID, "TagLongBot")
	convID := cb27CreateConversation(t, userID, agentID)

	form := url.Values{}
	form.Set("conversation_id", convID)
	form.Set("tag", strings.Repeat("a", 51))

	req := httptest.NewRequest(http.MethodPost, "/conversations/tags/add", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	handleAddTag(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestCB27_HandleAddTag_ConversationNotFound(t *testing.T) {
	cb27SetupDB(t)
	cb27SetupHub(t)

	_, token := cb27RegisterUser(t, "tagnf", "pass123")

	form := url.Values{}
	form.Set("conversation_id", "nonexistent-conv")
	form.Set("tag", "test")

	req := httptest.NewRequest(http.MethodPost, "/conversations/tags/add", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	handleAddTag(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}

func TestCB27_HandleAddTag_Unauthorized(t *testing.T) {
	cb27SetupDB(t)
	cb27SetupHub(t)

	userID1, _ := cb27RegisterUser(t, "tagownernf", "pass123")
	_, token2 := cb27RegisterUser(t, "tagnonowner", "pass123")
	agentID := "agent-tagauth"
	cb27RegisterAgent(t, agentID, "TagAuthBot")
	convID := cb27CreateConversation(t, userID1, agentID)

	form := url.Values{}
	form.Set("conversation_id", convID)
	form.Set("tag", "test")

	req := httptest.NewRequest(http.MethodPost, "/conversations/tags/add", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token2)

	w := httptest.NewRecorder()
	handleAddTag(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestCB27_HandleRemoveTag_Success(t *testing.T) {
	cb27SetupDB(t)
	cb27SetupHub(t)

	userID, token := cb27RegisterUser(t, "tagrmuser", "pass123")
	agentID := "agent-tagrm"
	cb27RegisterAgent(t, agentID, "TagRmBot")
	convID := cb27CreateConversation(t, userID, agentID)

	// Add tag first
	addConversationTag(convID, userID, "toremove")

	form := url.Values{}
	form.Set("conversation_id", convID)
	form.Set("tag", "toremove")

	req := httptest.NewRequest(http.MethodPost, "/conversations/tags/remove", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	handleRemoveTag(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCB27_HandleRemoveTag_NotFound(t *testing.T) {
	cb27SetupDB(t)
	cb27SetupHub(t)

	userID, token := cb27RegisterUser(t, "tagrmnf", "pass123")
	agentID := "agent-tagrmnf"
	cb27RegisterAgent(t, agentID, "TagRmNfBot")
	convID := cb27CreateConversation(t, userID, agentID)

	form := url.Values{}
	form.Set("conversation_id", convID)
	form.Set("tag", "nonexistent")

	req := httptest.NewRequest(http.MethodPost, "/conversations/tags/remove", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	handleRemoveTag(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}

func TestCB27_HandleGetTags_Success(t *testing.T) {
	cb27SetupDB(t)
	cb27SetupHub(t)

	userID, token := cb27RegisterUser(t, "taggetuser", "pass123")
	agentID := "agent-tagget"
	cb27RegisterAgent(t, agentID, "TagGetBot")
	convID := cb27CreateConversation(t, userID, agentID)

	// Add some tags
	addConversationTag(convID, userID, "bug")
	addConversationTag(convID, userID, "feature")

	req := httptest.NewRequest(http.MethodGet, "/conversations/tags?conversation_id="+convID, nil)
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	handleGetTags(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var tags []ConversationTag
	if err := json.Unmarshal(w.Body.Bytes(), &tags); err != nil {
		t.Fatal(err)
	}
	if len(tags) != 2 {
		t.Errorf("expected 2 tags, got %d", len(tags))
	}
}

func TestCB27_HandleGetTags_Empty(t *testing.T) {
	cb27SetupDB(t)
	cb27SetupHub(t)

	userID, token := cb27RegisterUser(t, "tagempty", "pass123")
	agentID := "agent-tagempty"
	cb27RegisterAgent(t, agentID, "TagEmptyBot")
	convID := cb27CreateConversation(t, userID, agentID)

	req := httptest.NewRequest(http.MethodGet, "/conversations/tags?conversation_id="+convID, nil)
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	handleGetTags(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var tags []ConversationTag
	if err := json.Unmarshal(w.Body.Bytes(), &tags); err != nil {
		t.Fatal(err)
	}
	if len(tags) != 0 {
		t.Errorf("expected 0 tags, got %d", len(tags))
	}
}

func TestCB27_HandleGetTags_Unauthorized(t *testing.T) {
	cb27SetupDB(t)
	cb27SetupHub(t)

	userID1, _ := cb27RegisterUser(t, "taggetown", "pass123")
	_, token2 := cb27RegisterUser(t, "taggetother", "pass123")
	agentID := "agent-taggetauth"
	cb27RegisterAgent(t, agentID, "TagGetAuthBot")
	convID := cb27CreateConversation(t, userID1, agentID)

	req := httptest.NewRequest(http.MethodGet, "/conversations/tags?conversation_id="+convID, nil)
	req.Header.Set("Authorization", "Bearer "+token2)

	w := httptest.NewRecorder()
	handleGetTags(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

// ==============================
// Notification Preferences Tests
// ==============================

func TestCB27_HandleSetNotificationPrefs_Success(t *testing.T) {
	cb27SetupDB(t)
	cb27SetupHub(t)

	userID, token := cb27RegisterUser(t, "notifuser", "pass123")
	agentID := "agent-notif"
	cb27RegisterAgent(t, agentID, "NotifBot")
	convID := cb27CreateConversation(t, userID, agentID)

	form := url.Values{}
	form.Set("conversation_id", convID)
	form.Set("muted", "true")

	req := httptest.NewRequest(http.MethodPost, "/notifications/prefs", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)
	// Set context for getUserID which reads from context, not the header
	claims, _ := ValidateJWT(token)
	ctx := context.WithValue(req.Context(), contextKeyUserID, claims.UserID)
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()
	handleSetNotificationPrefs(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp NotificationPreferences
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if !resp.Muted {
		t.Error("expected muted=true")
	}
}

func TestCB27_HandleSetNotificationPrefs_NotYourConversation(t *testing.T) {
	cb27SetupDB(t)
	cb27SetupHub(t)

	userID1, _ := cb27RegisterUser(t, "notifowner", "pass123")
	_, token2 := cb27RegisterUser(t, "notifother", "pass123")
	agentID := "agent-notifauth"
	cb27RegisterAgent(t, agentID, "NotifAuthBot")
	convID := cb27CreateConversation(t, userID1, agentID)

	form := url.Values{}
	form.Set("conversation_id", convID)
	form.Set("muted", "true")

	req := httptest.NewRequest(http.MethodPost, "/notifications/prefs", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token2)
	claims, _ := ValidateJWT(token2)
	ctx := context.WithValue(req.Context(), contextKeyUserID, claims.UserID)
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()
	handleSetNotificationPrefs(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", w.Code)
	}
}

func TestCB27_HandleSetNotificationPrefs_ConversationNotFound(t *testing.T) {
	cb27SetupDB(t)
	cb27SetupHub(t)

	_, token := cb27RegisterUser(t, "notifnf", "pass123")

	form := url.Values{}
	form.Set("conversation_id", "nonexistent-conv")
	form.Set("muted", "true")

	req := httptest.NewRequest(http.MethodPost, "/notifications/prefs", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)
	claims, _ := ValidateJWT(token)
	ctx := context.WithValue(req.Context(), contextKeyUserID, claims.UserID)
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()
	handleSetNotificationPrefs(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}

func TestCB27_HandleSetNotificationPrefs_MissingConvID(t *testing.T) {
	cb27SetupDB(t)
	cb27SetupHub(t)

	_, token := cb27RegisterUser(t, "notifmiss", "pass123")

	form := url.Values{}
	form.Set("muted", "true")

	req := httptest.NewRequest(http.MethodPost, "/notifications/prefs", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)
	claims, _ := ValidateJWT(token)
	ctx := context.WithValue(req.Context(), contextKeyUserID, claims.UserID)
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()
	handleSetNotificationPrefs(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestCB27_HandleGetNotificationPrefs_Success(t *testing.T) {
	cb27SetupDB(t)
	cb27SetupHub(t)

	userID, token := cb27RegisterUser(t, "notifgetuser", "pass123")
	agentID := "agent-notifget"
	cb27RegisterAgent(t, agentID, "NotifGetBot")
	convID := cb27CreateConversation(t, userID, agentID)

	// Set a pref first
	_, err := db.Exec("INSERT INTO notification_preferences (user_id, conversation_id, muted) VALUES (?, ?, ?)",
		userID, convID, true)
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/notifications/prefs", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	claims, _ := ValidateJWT(token)
	ctx := context.WithValue(req.Context(), contextKeyUserID, claims.UserID)
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()
	handleGetNotificationPrefs(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var prefs []NotificationPreferences
	if err := json.Unmarshal(w.Body.Bytes(), &prefs); err != nil {
		t.Fatal(err)
	}
	if len(prefs) != 1 {
		t.Errorf("expected 1 pref, got %d", len(prefs))
	}
}

func TestCB27_HandleGetNotificationPrefs_Empty(t *testing.T) {
	cb27SetupDB(t)
	cb27SetupHub(t)

	_, token := cb27RegisterUser(t, "notifempty", "pass123")

	req := httptest.NewRequest(http.MethodGet, "/notifications/prefs", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	claims, _ := ValidateJWT(token)
	ctx := context.WithValue(req.Context(), contextKeyUserID, claims.UserID)
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()
	handleGetNotificationPrefs(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var prefs []NotificationPreferences
	if err := json.Unmarshal(w.Body.Bytes(), &prefs); err != nil {
		t.Fatal(err)
	}
	if len(prefs) != 0 {
		t.Errorf("expected 0 prefs, got %d", len(prefs))
	}
}

func TestCB27_HandleDeleteNotificationPrefs_Success(t *testing.T) {
	cb27SetupDB(t)
	cb27SetupHub(t)

	userID, token := cb27RegisterUser(t, "notifdeluser", "pass123")
	agentID := "agent-notifdel"
	cb27RegisterAgent(t, agentID, "NotifDelBot")
	convID := cb27CreateConversation(t, userID, agentID)

	// Set a pref first
	_, err := db.Exec("INSERT INTO notification_preferences (user_id, conversation_id, muted) VALUES (?, ?, ?)",
		userID, convID, true)
	if err != nil {
		t.Fatal(err)
	}

	form := url.Values{}
	form.Set("conversation_id", convID)

	req := httptest.NewRequest(http.MethodPost, "/notifications/prefs/delete", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)
	claims, _ := ValidateJWT(token)
	ctx := context.WithValue(req.Context(), contextKeyUserID, claims.UserID)
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()
	handleDeleteNotificationPrefs(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCB27_IsConversationMuted_True(t *testing.T) {
	cb27SetupDB(t)

	userID := generateID("user")
	agentID := "agent-muted"
	cb27RegisterAgent(t, agentID, "MutedBot")
	convID := cb27CreateConversation(t, userID, agentID)

	_, err := db.Exec("INSERT INTO notification_preferences (user_id, conversation_id, muted) VALUES (?, ?, ?)",
		userID, convID, true)
	if err != nil {
		t.Fatal(err)
	}

	if !isConversationMuted(userID, convID) {
		t.Error("expected conversation to be muted")
	}
}

func TestCB27_IsConversationMuted_False(t *testing.T) {
	cb27SetupDB(t)

	if isConversationMuted("nonexistent-user", "nonexistent-conv") {
		t.Error("expected conversation not to be muted")
	}
}

// ==============================
// Presence Tests
// ==============================

func TestCB27_HandleGetPresence_WithAgents(t *testing.T) {
	cb27SetupDB(t)
	cb27SetupHub(t)

	_, token := cb27RegisterUser(t, "presuser", "pass123")
	cb27RegisterAgent(t, "agent-pres1", "PresBot1")
	cb27RegisterAgent(t, "agent-pres2", "PresBot2")

	req := httptest.NewRequest(http.MethodGet, "/presence", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	handleGetPresence(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var agents []struct {
		ID     string `json:"id"`
		Online bool   `json:"online"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &agents); err != nil {
		t.Fatal(err)
	}
	if len(agents) != 2 {
		t.Errorf("expected 2 agents, got %d", len(agents))
	}
	// All agents should be offline (not connected via WebSocket)
	for _, a := range agents {
		if a.Online {
			t.Errorf("expected agent %s to be offline", a.ID)
		}
	}
}

func TestCB27_HandleGetPresence_NoAuth(t *testing.T) {
	cb27SetupDB(t)

	req := httptest.NewRequest(http.MethodGet, "/presence", nil)
	w := httptest.NewRecorder()
	handleGetPresence(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestCB27_HandleGetUserPresence_Online(t *testing.T) {
	cb27SetupDB(t)
	cb27SetupHub(t)

	userID, token := cb27RegisterUser(t, "presonline", "pass123")

	// Simulate a connected client
	conn := &Connection{
		hub:      hub,
		connType: "client",
		id:       userID,
		deviceID: "device-1",
		send:     make(chan []byte, 256),
	}
	hub.register <- conn
	// Give hub time to process registration
	time.Sleep(50 * time.Millisecond)

	req := httptest.NewRequest(http.MethodGet, "/presence/user?user_id="+userID, nil)
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	handleGetUserPresence(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp["online"] != true {
		t.Errorf("expected online=true, got %v", resp["online"])
	}
}

func TestCB27_HandleGetUserPresence_OfflineUser(t *testing.T) {
	cb27SetupDB(t)
	cb27SetupHub(t)

	_, token := cb27RegisterUser(t, "presoffline", "pass123")

	req := httptest.NewRequest(http.MethodGet, "/presence/user", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	handleGetUserPresence(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp["online"] != false {
		t.Errorf("expected online=false, got %v", resp["online"])
	}
}

func TestCB27_HandleGetUserPresence_NoAuth(t *testing.T) {
	cb27SetupDB(t)

	req := httptest.NewRequest(http.MethodGet, "/presence/user", nil)
	w := httptest.NewRecorder()
	handleGetUserPresence(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

// ==============================
// E2E Encryption Tests
// ==============================

func TestCB27_HandleUploadPublicKey_IdentityReplace(t *testing.T) {
	cb27SetupDB(t)
	cb27SetupHub(t)

	userID, token := cb27RegisterUser(t, "keyuser", "pass123")

	// Upload first identity key
	body1 := `{"key_type":"identity","public_key":"base64key1"}`
	req1 := httptest.NewRequest(http.MethodPost, "/keys/upload", strings.NewReader(body1))
	req1.Header.Set("Content-Type", "application/json")
	req1.Header.Set("Authorization", "Bearer "+token)
	w1 := httptest.NewRecorder()
	handleUploadPublicKey(w1, req1)

	if w1.Code != http.StatusOK {
		t.Fatalf("expected 200 on first upload, got %d: %s", w1.Code, w1.Body.String())
	}

	// Upload replacement identity key
	body2 := `{"key_type":"identity","public_key":"base64key2"}`
	req2 := httptest.NewRequest(http.MethodPost, "/keys/upload", strings.NewReader(body2))
	req2.Header.Set("Content-Type", "application/json")
	req2.Header.Set("Authorization", "Bearer "+token)
	w2 := httptest.NewRecorder()
	handleUploadPublicKey(w2, req2)

	if w2.Code != http.StatusOK {
		t.Fatalf("expected 200 on replace, got %d: %s", w2.Code, w2.Body.String())
	}

	// Verify only one identity key exists
	var count int
	db.QueryRow("SELECT COUNT(*) FROM key_bundles WHERE owner_id = ? AND key_type = 'identity'", userID).Scan(&count)
	if count != 1 {
		t.Errorf("expected 1 identity key after replacement, got %d", count)
	}
}

func TestCB27_HandleUploadPublicKey_SignedPreKey(t *testing.T) {
	cb27SetupDB(t)
	cb27SetupHub(t)

	_, token := cb27RegisterUser(t, "spkuser", "pass123")

	body := `{"key_type":"signed_prekey","public_key":"base64spk","signature":"base64sig"}`
	req := httptest.NewRequest(http.MethodPost, "/keys/upload", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	handleUploadPublicKey(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCB27_HandleUploadPublicKey_InvalidKeyType(t *testing.T) {
	cb27SetupDB(t)
	cb27SetupHub(t)

	_, token := cb27RegisterUser(t, "invkeyuser", "pass123")

	body := `{"key_type":"invalid_type","public_key":"base64key"}`
	req := httptest.NewRequest(http.MethodPost, "/keys/upload", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	handleUploadPublicKey(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestCB27_HandleUploadPublicKey_MissingPublicKey(t *testing.T) {
	cb27SetupDB(t)
	cb27SetupHub(t)

	_, token := cb27RegisterUser(t, "nopubkeyuser", "pass123")

	body := `{"key_type":"identity","public_key":""}`
	req := httptest.NewRequest(http.MethodPost, "/keys/upload", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	handleUploadPublicKey(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestCB27_HandleUploadPublicKey_InvalidJSON(t *testing.T) {
	cb27SetupDB(t)
	cb27SetupHub(t)

	_, token := cb27RegisterUser(t, "badjsonuser", "pass123")

	req := httptest.NewRequest(http.MethodPost, "/keys/upload", strings.NewReader("not json"))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	handleUploadPublicKey(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestCB27_HandleGetKeyBundle_FullBundle(t *testing.T) {
	cb27SetupDB(t)
	cb27SetupHub(t)

	userID, token := cb27RegisterUser(t, "bundleuser", "pass123")

	// Upload all key types
	for _, body := range []string{
		`{"key_type":"identity","public_key":"base64id"}`,
		`{"key_type":"signed_prekey","public_key":"base64spk","signature":"base64sig"}`,
		`{"key_type":"one_time_prekey","public_key":"base64otpk","key_id":1}`,
	} {
		req := httptest.NewRequest(http.MethodPost, "/keys/upload", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		handleUploadPublicKey(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("key upload failed: %d %s", w.Code, w.Body.String())
		}
	}

	// Fetch bundle
	req := httptest.NewRequest(http.MethodGet, "/keys/bundle?owner_id="+userID+"&owner_type=user", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	handleGetKeyBundle(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var bundle map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &bundle); err != nil {
		t.Fatal(err)
	}
	if _, ok := bundle["identity_key"]; !ok {
		t.Error("expected identity_key in bundle")
	}
	if _, ok := bundle["signed_prekey"]; !ok {
		t.Error("expected signed_prekey in bundle")
	}
	if _, ok := bundle["one_time_prekey"]; !ok {
		t.Error("expected one_time_prekey in bundle")
	}

	// OTPK should be consumed - second request should not have one_time_prekey
	req2 := httptest.NewRequest(http.MethodGet, "/keys/bundle?owner_id="+userID+"&owner_type=user", nil)
	req2.Header.Set("Authorization", "Bearer "+token)
	w2 := httptest.NewRecorder()
	handleGetKeyBundle(w2, req2)

	var bundle2 map[string]interface{}
	if err := json.Unmarshal(w2.Body.Bytes(), &bundle2); err != nil {
		t.Fatal(err)
	}
	if _, ok := bundle2["one_time_prekey"]; ok {
		t.Error("expected one_time_prekey to be consumed (not in second bundle)")
	}
}

func TestCB27_HandleGetKeyBundle_MissingOwnerID(t *testing.T) {
	cb27SetupDB(t)
	cb27SetupHub(t)

	_, token := cb27RegisterUser(t, "bundlenf", "pass123")

	req := httptest.NewRequest(http.MethodGet, "/keys/bundle", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	handleGetKeyBundle(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestCB27_HandleGetKeyBundle_NoIdentityKey(t *testing.T) {
	cb27SetupDB(t)
	cb27SetupHub(t)

	_, token := cb27RegisterUser(t, "bundleempty", "pass123")

	req := httptest.NewRequest(http.MethodGet, "/keys/bundle?owner_id=nonexistent&owner_type=user", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	handleGetKeyBundle(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}

func TestCB27_HandleStoreEncryptedMessage_Success(t *testing.T) {
	cb27SetupDB(t)
	cb27SetupHub(t)

	userID, token := cb27RegisterUser(t, "encmsguser", "pass123")
	agentID := "agent-encmsg"
	cb27RegisterAgent(t, agentID, "EncMsgBot")
	convID := cb27CreateConversation(t, userID, agentID)

	body := fmt.Sprintf(`{
		"conversation_id": "%s",
		"ciphertext": "base64ciphertext",
		"iv": "base64iv",
		"recipient_key_id": "key-1",
		"algorithm": "aes-256-gcm"
	}`, convID)

	req := httptest.NewRequest(http.MethodPost, "/messages/encrypted", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	handleStoreEncryptedMessage(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp["status"] != "stored" {
		t.Errorf("expected status=stored, got %v", resp["status"])
	}
}

func TestCB27_HandleStoreEncryptedMessage_UnsupportedAlgorithm(t *testing.T) {
	cb27SetupDB(t)
	cb27SetupHub(t)

	userID, token := cb27RegisterUser(t, "encalgo", "pass123")
	agentID := "agent-encalgo"
	cb27RegisterAgent(t, agentID, "EncAlgoBot")
	convID := cb27CreateConversation(t, userID, agentID)

	body := fmt.Sprintf(`{
		"conversation_id": "%s",
		"ciphertext": "base64ciphertext",
		"iv": "base64iv",
		"recipient_key_id": "key-1",
		"algorithm": "rsa-4096"
	}`, convID)

	req := httptest.NewRequest(http.MethodPost, "/messages/encrypted", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	handleStoreEncryptedMessage(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestCB27_HandleStoreEncryptedMessage_NotParticipant(t *testing.T) {
	cb27SetupDB(t)
	cb27SetupHub(t)

	userID1, _ := cb27RegisterUser(t, "encpart1", "pass123")
	_, token2 := cb27RegisterUser(t, "encpart2", "pass123")
	agentID := "agent-encpart"
	cb27RegisterAgent(t, agentID, "EncPartBot")
	convID := cb27CreateConversation(t, userID1, agentID)

	body := fmt.Sprintf(`{
		"conversation_id": "%s",
		"ciphertext": "base64ciphertext",
		"iv": "base64iv",
		"recipient_key_id": "key-1",
		"algorithm": "aes-256-gcm"
	}`, convID)

	req := httptest.NewRequest(http.MethodPost, "/messages/encrypted", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token2)

	w := httptest.NewRecorder()
	handleStoreEncryptedMessage(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", w.Code)
	}
}

func TestCB27_HandleStoreEncryptedMessage_MissingFields(t *testing.T) {
	cb27SetupDB(t)
	cb27SetupHub(t)

	_, token := cb27RegisterUser(t, "encmiss", "pass123")

	body := `{"conversation_id": "conv-1", "ciphertext": "data"}`

	req := httptest.NewRequest(http.MethodPost, "/messages/encrypted", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	handleStoreEncryptedMessage(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestCB27_HandleGetEncryptedMessages_Success(t *testing.T) {
	cb27SetupDB(t)
	cb27SetupHub(t)

	userID, token := cb27RegisterUser(t, "encgetuser", "pass123")
	agentID := "agent-encget"
	cb27RegisterAgent(t, agentID, "EncGetBot")
	convID := cb27CreateConversation(t, userID, agentID)

	// Store an encrypted message first
	_, err := db.Exec(`
		INSERT INTO encrypted_messages (id, conversation_id, sender_id, sender_type, ciphertext, iv, recipient_key_id, sender_key_id, algorithm, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		generateID("emsg"), convID, userID, "user", "ciphertext1", "iv1", "key1", "skey1", "aes-256-gcm", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/messages/encrypted?conversation_id="+convID, nil)
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	handleGetEncryptedMessages(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var messages []EncryptedMessage
	if err := json.Unmarshal(w.Body.Bytes(), &messages); err != nil {
		t.Fatal(err)
	}
	if len(messages) != 1 {
		t.Errorf("expected 1 message, got %d", len(messages))
	}
}

func TestCB27_HandleGetEncryptedMessages_MissingConversationID(t *testing.T) {
	cb27SetupDB(t)
	cb27SetupHub(t)

	_, token := cb27RegisterUser(t, "encgetmiss", "pass123")

	req := httptest.NewRequest(http.MethodGet, "/messages/encrypted", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	handleGetEncryptedMessages(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestCB27_HandleGetEncryptedMessages_NotParticipant(t *testing.T) {
	cb27SetupDB(t)
	cb27SetupHub(t)

	userID1, _ := cb27RegisterUser(t, "encgetpart1", "pass123")
	_, token2 := cb27RegisterUser(t, "encgetpart2", "pass123")
	agentID := "agent-encgetpart"
	cb27RegisterAgent(t, agentID, "EncGetPartBot")
	convID := cb27CreateConversation(t, userID1, agentID)

	req := httptest.NewRequest(http.MethodGet, "/messages/encrypted?conversation_id="+convID, nil)
	req.Header.Set("Authorization", "Bearer "+token2)

	w := httptest.NewRecorder()
	handleGetEncryptedMessages(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}

// ==============================
// E2E: Agent auth with X-Agent-Secret
// ==============================

func TestCB27_AuthenticateRequest_AgentAuth(t *testing.T) {
	cb27SetupDB(t)

	origSecret := os.Getenv("AGENT_SECRET")
	os.Setenv("AGENT_SECRET", "test-agent-secret")
	t.Cleanup(func() {
		if origSecret != "" {
			os.Setenv("AGENT_SECRET", origSecret)
		} else {
			os.Unsetenv("AGENT_SECRET")
		}
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("X-Agent-Secret", "test-agent-secret")
	req.Header.Set("X-Agent-ID", "agent-1")

	id, ownerType, err := authenticateRequest(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id != "agent-1" {
		t.Errorf("expected id=agent-1, got %s", id)
	}
	if ownerType != "agent" {
		t.Errorf("expected ownerType=agent, got %s", ownerType)
	}
}

func TestCB27_AuthenticateRequest_AgentAuthMissingID(t *testing.T) {
	cb27SetupDB(t)

	origSecret := os.Getenv("AGENT_SECRET")
	os.Setenv("AGENT_SECRET", "test-agent-secret")
	t.Cleanup(func() {
		if origSecret != "" {
			os.Setenv("AGENT_SECRET", origSecret)
		} else {
			os.Unsetenv("AGENT_SECRET")
		}
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("X-Agent-Secret", "test-agent-secret")
	// Missing X-Agent-ID

	_, _, err := authenticateRequest(req)
	if err == nil {
		t.Error("expected error for missing X-Agent-ID")
	}
}

func TestCB27_AuthenticateRequest_NoAuth(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	_, _, err := authenticateRequest(req)
	if err == nil {
		t.Error("expected error for no auth")
	}
}

// ==============================
// Conversation deep tests
// ==============================

func TestCB27_GetOrCreateConversation_New(t *testing.T) {
	cb27SetupDB(t)

	userID := generateID("user")
	agentID := "agent-getorcreate"
	cb27RegisterAgent(t, agentID, "GetOrCreateBot")
	convID := cb27CreateConversation(t, userID, agentID)

	conv, err := GetOrCreateConversation(userID, agentID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Should return existing conversation
	if conv.ID != convID {
		t.Errorf("expected existing conv ID %s, got %s", convID, conv.ID)
	}
}

func TestCB27_SearchMessages_WithRealDB(t *testing.T) {
	cb27SetupDB(t)

	userID := generateID("user")
	agentID := "agent-search"
	cb27RegisterAgent(t, agentID, "SearchBot")
	convID := cb27CreateConversation(t, userID, agentID)

	// Store messages
	cb27StoreMessage(t, convID, "client", userID, "hello world")
	cb27StoreMessage(t, convID, "agent", agentID, "world peace")
	cb27StoreMessage(t, convID, "client", userID, "goodbye moon")

	// Search
	results, err := searchMessages(userID, "world", 50)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 2 {
		t.Errorf("expected 2 results for 'world', got %d", len(results))
	}
}

func TestCB27_ChangeUserPassword_Success(t *testing.T) {
	cb27SetupDB(t)

	userID := generateID("user")
	hash, err := HashAPIKey("oldpass")
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)", userID, "pwuser", hash)
	if err != nil {
		t.Fatal(err)
	}

	err = changeUserPassword(userID, "oldpass", "newpass")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify new password works
	var newHash string
	db.QueryRow("SELECT password_hash FROM users WHERE id = ?", userID).Scan(&newHash)
	if err := bcrypt.CompareHashAndPassword([]byte(newHash), []byte("newpass")); err != nil {
		t.Error("new password should work")
	}
	_ = bcrypt.CompareHashAndPassword
}

func TestCB27_ChangeUserPassword_WrongOldPassword(t *testing.T) {
	cb27SetupDB(t)

	userID := generateID("user")
	hash, err := HashAPIKey("correctpass")
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)", userID, "pwuser2", hash)
	if err != nil {
		t.Fatal(err)
	}

	err = changeUserPassword(userID, "wrongpass", "newpass")
	if err == nil || err.Error() != "invalid old password" {
		t.Errorf("expected 'invalid old password' error, got %v", err)
	}
}

func TestCB27_MarkMessagesRead_Success(t *testing.T) {
	cb27SetupDB(t)

	userID := generateID("user")
	agentID := "agent-markread"
	cb27RegisterAgent(t, agentID, "MarkReadBot")
	convID := cb27CreateConversation(t, userID, agentID)
	cb27StoreMessage(t, convID, "agent", agentID, "unread message")

	count, err := markMessagesRead(convID, userID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if count != 1 {
		t.Errorf("expected 1 message marked read, got %d", count)
	}
}

// ==============================
// Handler: handleLogin success path
// ==============================

func TestCB27_HandleLogin_Success(t *testing.T) {
	cb27SetupDB(t)
	cb27SetupHub(t)

	// Register user
	hash, err := HashAPIKey("testpass123")
	if err != nil {
		t.Fatal(err)
	}
	userID := generateID("user")
	_, err = db.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)", userID, "loginuser", hash)
	if err != nil {
		t.Fatal(err)
	}

	form := url.Values{}
	form.Set("username", "loginuser")
	form.Set("password", "testpass123")

	req := httptest.NewRequest(http.MethodPost, "/auth/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	w := httptest.NewRecorder()
	handleLogin(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp["token"] == "" {
		t.Error("expected token in response")
	}
	if resp["user_id"] != userID {
		t.Errorf("expected user_id=%s, got %s", userID, resp["user_id"])
	}
}

func TestCB27_HandleLogin_InvalidCredentials(t *testing.T) {
	cb27SetupDB(t)
	cb27SetupHub(t)

	form := url.Values{}
	form.Set("username", "nonexistent")
	form.Set("password", "wrong")

	req := httptest.NewRequest(http.MethodPost, "/auth/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	w := httptest.NewRecorder()
	handleLogin(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

// ==============================
// Handler: handleRegisterUser
// ==============================

func TestCB27_HandleRegisterUser_Success(t *testing.T) {
	cb27SetupDB(t)
	cb27SetupHub(t)

	form := url.Values{}
	form.Set("username", "newuser")
	form.Set("password", "password123")

	req := httptest.NewRequest(http.MethodPost, "/auth/user", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	w := httptest.NewRecorder()
	handleRegisterUser(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp["status"] != "registered" {
		t.Errorf("expected status=registered, got %v", resp["status"])
	}
}

func TestCB27_HandleRegisterUser_DuplicateUsername(t *testing.T) {
	cb27SetupDB(t)
	cb27SetupHub(t)

	form := url.Values{}
	form.Set("username", "duplicate")
	form.Set("password", "password123")

	// First registration
	req1 := httptest.NewRequest(http.MethodPost, "/auth/user", strings.NewReader(form.Encode()))
	req1.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w1 := httptest.NewRecorder()
	handleRegisterUser(w1, req1)

	if w1.Code != http.StatusOK {
		t.Fatalf("expected 200 on first, got %d", w1.Code)
	}

	// Duplicate registration
	req2 := httptest.NewRequest(http.MethodPost, "/auth/user", strings.NewReader(form.Encode()))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w2 := httptest.NewRecorder()
	handleRegisterUser(w2, req2)

	if w2.Code != http.StatusConflict {
		t.Fatalf("expected 409, got %d", w2.Code)
	}
}

func TestCB27_HandleRegisterUser_InvalidUsername(t *testing.T) {
	cb27SetupDB(t)
	cb27SetupHub(t)

	form := url.Values{}
	form.Set("username", "ab") // too short
	form.Set("password", "password123")

	req := httptest.NewRequest(http.MethodPost, "/auth/user", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	w := httptest.NewRecorder()
	handleRegisterUser(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestCB27_HandleRegisterUser_InvalidChars(t *testing.T) {
	cb27SetupDB(t)
	cb27SetupHub(t)

	form := url.Values{}
	form.Set("username", "user@name") // @ not allowed
	form.Set("password", "password123")

	req := httptest.NewRequest(http.MethodPost, "/auth/user", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	w := httptest.NewRecorder()
	handleRegisterUser(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

// ==============================
// Handler: handleRegisterAgent
// ==============================

func TestCB27_HandleRegisterAgent_Success(t *testing.T) {
	cb27SetupDB(t)
	cb27SetupHub(t)

	origSecret := agentSecret
	agentSecret = "test-secret"
	t.Cleanup(func() { agentSecret = origSecret })

	form := url.Values{}
	form.Set("agent_id", "test-agent")
	form.Set("name", "Test Agent")
	form.Set("model", "gpt-4")

	req := httptest.NewRequest(http.MethodPost, "/auth/agent", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Agent-Secret", "test-secret")

	w := httptest.NewRecorder()
	handleRegisterAgent(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCB27_HandleRegisterAgent_InvalidSecret(t *testing.T) {
	cb27SetupDB(t)
	cb27SetupHub(t)

	origSecret := agentSecret
	agentSecret = "correct-secret"
	t.Cleanup(func() { agentSecret = origSecret })

	form := url.Values{}
	form.Set("agent_id", "test-agent")
	form.Set("name", "Test Agent")

	req := httptest.NewRequest(http.MethodPost, "/auth/agent", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Agent-Secret", "wrong-secret")

	w := httptest.NewRecorder()
	handleRegisterAgent(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestCB27_HandleRegisterAgent_MissingAgentID(t *testing.T) {
	cb27SetupDB(t)
	cb27SetupHub(t)

	origSecret := agentSecret
	agentSecret = "test-secret"
	t.Cleanup(func() { agentSecret = origSecret })

	form := url.Values{}
	form.Set("name", "Test Agent")

	req := httptest.NewRequest(http.MethodPost, "/auth/agent", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Agent-Secret", "test-secret")

	w := httptest.NewRecorder()
	handleRegisterAgent(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

// ==============================
// OfflineQueue edge cases
// ==============================

func TestCB27_OfflineQueue_EnqueueAndDrain(t *testing.T) {
	q := newOfflineQueue(10, time.Hour)

	data1 := []byte("message1")
	data2 := []byte("message2")

	q.Enqueue("user1", data1)
	q.Enqueue("user1", data2)

	if q.QueueDepth("user1") != 2 {
		t.Errorf("expected depth 2, got %d", q.QueueDepth("user1"))
	}

	messages := q.Drain("user1")
	if len(messages) != 2 {
		t.Errorf("expected 2 messages, got %d", len(messages))
	}
	if q.QueueDepth("user1") != 0 {
		t.Errorf("expected depth 0 after drain, got %d", q.QueueDepth("user1"))
	}
}

func TestCB27_OfflineQueue_MaxLen(t *testing.T) {
	q := newOfflineQueue(3, time.Hour)

	for i := 0; i < 5; i++ {
		q.Enqueue("user1", []byte(fmt.Sprintf("msg%d", i)))
	}

	if q.QueueDepth("user1") != 3 {
		t.Errorf("expected depth 3 (maxLen), got %d", q.QueueDepth("user1"))
	}

	messages := q.Drain("user1")
	// Should have last 3 messages (oldest trimmed)
	if len(messages) != 3 {
		t.Errorf("expected 3 messages, got %d", len(messages))
	}
}

func TestCB27_OfflineQueue_ExpiredMessages(t *testing.T) {
	q := newOfflineQueue(10, 1*time.Nanosecond) // very short TTL

	q.Enqueue("user1", []byte("expired"))
	time.Sleep(10 * time.Millisecond) // wait for expiry

	messages := q.Drain("user1")
	if len(messages) != 0 {
		t.Errorf("expected 0 messages (all expired), got %d", len(messages))
	}
}

func TestCB27_OfflineQueue_Purge(t *testing.T) {
	q := newOfflineQueue(10, time.Hour)

	q.Enqueue("user1", []byte("msg1"))
	q.Enqueue("user1", []byte("msg2"))
	q.Enqueue("user2", []byte("msg3"))

	q.Purge("user1")

	if q.QueueDepth("user1") != 0 {
		t.Errorf("expected depth 0 after purge, got %d", q.QueueDepth("user1"))
	}
	if q.QueueDepth("user2") != 1 {
		t.Errorf("expected depth 1 for user2, got %d", q.QueueDepth("user2"))
	}
}

func TestCB27_OfflineQueue_TotalDepth(t *testing.T) {
	q := newOfflineQueue(10, time.Hour)

	q.Enqueue("user1", []byte("msg1"))
	q.Enqueue("user1", []byte("msg2"))
	q.Enqueue("user2", []byte("msg3"))

	if q.TotalDepth() != 3 {
		t.Errorf("expected total depth 3, got %d", q.TotalDepth())
	}
}

// ==============================
// Queue persistence with real DB
// ==============================

func TestCB27_QueuePersistAndLoad(t *testing.T) {
	cb27SetupDB(t)
	initQueueDB(db)

	q := newOfflineQueue(100, time.Hour)

	// Persist some messages
	msg := OutgoingMessage{Type: "message", Data: map[string]string{"content": "hello"}}
	data, _ := json.Marshal(msg)

	persistQueue(db, "user1", data)
	persistQueue(db, "user1", data)

	// Load from DB
	loadQueueFromDB(db, q)

	if q.QueueDepth("user1") != 2 {
		t.Errorf("expected depth 2 after load, got %d", q.QueueDepth("user1"))
	}

	// Delete
	deleteQueueMessages(db, "user1")

	// Verify deleted
	q2 := newOfflineQueue(100, time.Hour)
	loadQueueFromDB(db, q2)
	if q2.QueueDepth("user1") != 0 {
		t.Errorf("expected depth 0 after delete, got %d", q2.QueueDepth("user1"))
	}
}

func TestCB27_CleanStaleQueueMessages_WithDB(t *testing.T) {
	cb27SetupDB(t)
	initQueueDB(db)

	// Insert a stale message directly
	_, err := db.Exec(
		"INSERT INTO offline_queue (recipient, data, queued_at, sent_count) VALUES (?, ?, ?, 0)",
		"user1", []byte("old message"), time.Now().UTC().Add(-48*time.Hour).Format(time.RFC3339),
	)
	if err != nil {
		t.Fatal(err)
	}

	// Insert a fresh message
	_, err = db.Exec(
		"INSERT INTO offline_queue (recipient, data, queued_at, sent_count) VALUES (?, ?, ?, 0)",
		"user1", []byte("fresh message"), time.Now().UTC().Format(time.RFC3339),
	)
	if err != nil {
		t.Fatal(err)
	}

	// Clean messages older than 24 hours
	cleanStaleQueueMessages(db, 24*time.Hour)

	// Verify only fresh message remains
	var count int
	db.QueryRow("SELECT COUNT(*) FROM offline_queue WHERE recipient = 'user1'").Scan(&count)
	if count != 1 {
		t.Errorf("expected 1 message remaining, got %d", count)
	}
}

// ==============================
// HandleRegisterUser via FormValue for agent_secret
// ==============================

func TestCB27_HandleRegisterAgent_FormValueSecret(t *testing.T) {
	cb27SetupDB(t)
	cb27SetupHub(t)

	origSecret := agentSecret
	agentSecret = "form-secret"
	t.Cleanup(func() { agentSecret = origSecret })

	form := url.Values{}
	form.Set("agent_id", "form-agent")
	form.Set("name", "Form Agent")
	form.Set("agent_secret", "form-secret")

	req := httptest.NewRequest(http.MethodPost, "/auth/agent", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	// No X-Agent-Secret header - use form value

	w := httptest.NewRecorder()
	handleRegisterAgent(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 with form secret, got %d: %s", w.Code, w.Body.String())
	}
}

// ==============================
// handleListAgents
// ==============================

func TestCB27_HandleListAgents_Success(t *testing.T) {
	cb27SetupDB(t)
	cb27SetupHub(t)

	cb27RegisterAgent(t, "agent-list1", "ListBot1")
	cb27RegisterAgent(t, "agent-list2", "ListBot2")

	token := cb27MakeJWT(t, "user-1", "testuser")

	req := httptest.NewRequest(http.MethodGet, "/agents", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	handleListAgents(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var agents []AgentInfo
	if err := json.Unmarshal(w.Body.Bytes(), &agents); err != nil {
		t.Fatal(err)
	}
	if len(agents) != 2 {
		t.Errorf("expected 2 agents, got %d", len(agents))
	}
}

func TestCB27_HandleListAgents_Empty(t *testing.T) {
	cb27SetupDB(t)
	cb27SetupHub(t)

	token := cb27MakeJWT(t, "user-1", "testuser")

	req := httptest.NewRequest(http.MethodGet, "/agents", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	handleListAgents(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var agents []AgentInfo
	if err := json.Unmarshal(w.Body.Bytes(), &agents); err != nil {
		t.Fatal(err)
	}
	if len(agents) != 0 {
		t.Errorf("expected 0 agents, got %d", len(agents))
	}
}

// ==============================
// handleAdminAgents
// ==============================

func TestCB27_HandleAdminAgents_Success(t *testing.T) {
	cb27SetupDB(t)
	cb27SetupHub(t)

	cb27RegisterAgent(t, "agent-admin1", "AdminBot1")

	token := cb27MakeJWT(t, "admin-1", "admin")

	req := httptest.NewRequest(http.MethodGet, "/admin/agents", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	handleAdminAgents(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var agents []AgentInfo
	if err := json.Unmarshal(w.Body.Bytes(), &agents); err != nil {
		t.Fatal(err)
	}
	if len(agents) != 1 {
		t.Errorf("expected 1 agent, got %d", len(agents))
	}
}

// ==============================
// getUserID helper
// ==============================

func TestCB27_GetUserID_ValidToken(t *testing.T) {
	token := cb27MakeJWT(t, "user-123", "testuser")

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	claims, _ := ValidateJWT(token)
	ctx := context.WithValue(req.Context(), contextKeyUserID, claims.UserID)
	req = req.WithContext(ctx)

	userID, err := getUserID(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if userID != "user-123" {
		t.Errorf("expected user-123, got %s", userID)
	}
}

func TestCB27_GetUserID_InvalidToken(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer invalid-token")

	_, err := getUserID(req)
	if err == nil {
		t.Error("expected error for invalid token")
	}
}

func TestCB27_GetUserID_NoHeader(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/test", nil)

	_, err := getUserID(req)
	if err == nil {
		t.Error("expected error for missing auth header")
	}
}

// ==============================
// dbdriver: Placeholder/Placeholders with different drivers
// ==============================

func TestCB27_Placeholder_SQLiteDriver(t *testing.T) {
	origDriver := currentDriver
	currentDriver = DriverSQLite
	t.Cleanup(func() { currentDriver = origDriver })

	if Placeholder(1) != "?" {
		t.Errorf("expected ?, got %s", Placeholder(1))
	}
}

func TestCB27_Placeholders_SQLiteDriver(t *testing.T) {
	origDriver := currentDriver
	currentDriver = DriverSQLite
	t.Cleanup(func() { currentDriver = origDriver })

	result := Placeholders(1, 3)
	if result != "?, ?, ?" {
		t.Errorf("expected '?, ?, ?', got %s", result)
	}
}

func TestCB27_Placeholder_PostgresDriver(t *testing.T) {
	origDriver := currentDriver
	currentDriver = DriverPostgreSQL
	t.Cleanup(func() { currentDriver = origDriver })

	if Placeholder(1) != "$1" {
		t.Errorf("expected $1, got %s", Placeholder(1))
	}
	if Placeholder(3) != "$3" {
		t.Errorf("expected $3, got %s", Placeholder(3))
	}
}

func TestCB27_Placeholders_PostgresDriver(t *testing.T) {
	origDriver := currentDriver
	currentDriver = DriverPostgreSQL
	t.Cleanup(func() { currentDriver = origDriver })

	result := Placeholders(1, 3)
	if result != "$1, $2, $3" {
		t.Errorf("expected '$1, $2, $3', got %s", result)
	}
}

// ==============================
// Tracing no-op tests
// ==============================

func TestCB27_Tracing_NoOpSpans(t *testing.T) {
	// These should work without panic when tracing is disabled
	span := TraceRouteMessage("client", "user1")
	span.End()

	_, span2 := TraceChatMessage(context.Background(), "client", "user1", "conv1", "msg1")
	span2.End()

	_, span3 := TraceStoreMessage(context.Background(), "conv1", "user1")
	span3.End()

	_, span4 := TraceDeliverMessage(context.Background(), "user1", "client", true)
	span4.End()

	span5 := TraceOfflineEnqueue("user1")
	span5.End()

	span6 := TracePushNotify("user1", "conv1", true)
	span6.End()

	span7 := TraceAgentConnect("agent1")
	span7.End()

	span8 := TraceClientConnect("user1", "device1")
	span8.End()
}

// ==============================
// Protocol version tests
// ==============================

func TestCB27_UpgradeWithProtocol(t *testing.T) {
	// Just test the helper function logic
	if !isSupportedVersion("v1") {
		t.Error("v1 should be supported")
	}
}

// ==============================
// Push notification edge cases
// ==============================

func TestCB27_GetEnvOrDefault(t *testing.T) {
	// Test with env var set
	os.Setenv("TEST_PUSH_VAR", "fromenv")
	defer os.Unsetenv("TEST_PUSH_VAR")
	if getEnvOrDefault("TEST_PUSH_VAR", "default") != "fromenv" {
		t.Error("expected env var value")
	}

	// Test with env var not set
	if getEnvOrDefault("NONEXISTENT_VAR", "default") != "default" {
		t.Error("expected default value")
	}
}

func TestCB27_SafeTruncate_EdgeCases(t *testing.T) {
	tests := []struct {
		input   string
		maxLen  int
		want    string
	}{
		{"hello", 10, "hello"},
		{"hello world", 8, "hello wo"},
		{"hi", 3, "hi"},
		{"a", 0, ""},
		{"abc", 3, "abc"},
	}
	for _, tt := range tests {
		got := safeTruncate(tt.input, tt.maxLen)
		if got != tt.want {
			t.Errorf("safeTruncate(%q, %d) = %q, want %q", tt.input, tt.maxLen, got, tt.want)
		}
	}
}

// ==============================
// handleMarkRead with agent notification
// ==============================

func TestCB27_HandleMarkRead_Success(t *testing.T) {
	cb27SetupDB(t)
	cb27SetupHub(t)

	userID, token := cb27RegisterUser(t, "markreaduser", "pass123")
	agentID := "agent-markread2"
	cb27RegisterAgent(t, agentID, "MarkReadBot2")
	_ = userID
	convID := cb27CreateConversation(t, userID, agentID)
	cb27StoreMessage(t, convID, "client", userID, "message to mark")

	form := url.Values{}
	form.Set("conversation_id", convID)

	req := httptest.NewRequest(http.MethodPost, "/conversations/mark-read", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	handleMarkRead(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp["status"] != "marked_read" {
		t.Errorf("expected status=marked_read, got %v", resp["status"])
	}
}

func TestCB27_HandleMarkRead_MissingConvID(t *testing.T) {
	cb27SetupDB(t)
	cb27SetupHub(t)

	_, token := cb27RegisterUser(t, "markreadmiss", "pass123")

	req := httptest.NewRequest(http.MethodPost, "/conversations/mark-read", strings.NewReader(""))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	handleMarkRead(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestCB27_HandleMarkRead_Unauthorized(t *testing.T) {
	cb27SetupDB(t)
	cb27SetupHub(t)

	userID1, _ := cb27RegisterUser(t, "markreadown", "pass123")
	_, token2 := cb27RegisterUser(t, "markreadother", "pass123")
	agentID := "agent-markread3"
	cb27RegisterAgent(t, agentID, "MarkReadBot3")
	convID := cb27CreateConversation(t, userID1, agentID)

	form := url.Values{}
	form.Set("conversation_id", convID)

	req := httptest.NewRequest(http.MethodPost, "/conversations/mark-read", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token2)

	w := httptest.NewRecorder()
	handleMarkRead(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

// ==============================
// handleChangePassword
// ==============================

func TestCB27_HandleChangePassword_Success(t *testing.T) {
	cb27SetupDB(t)
	cb27SetupHub(t)

	_, token := cb27RegisterUser(t, "chpwuser", "oldpass")

	form := url.Values{}
	form.Set("old_password", "oldpass")
	form.Set("new_password", "newpass123")

	req := httptest.NewRequest(http.MethodPost, "/auth/change-password", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	handleChangePassword(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCB27_HandleChangePassword_WrongOld(t *testing.T) {
	cb27SetupDB(t)
	cb27SetupHub(t)

	_, token := cb27RegisterUser(t, "chpwwrong", "correctpass")

	form := url.Values{}
	form.Set("old_password", "wrongpass")
	form.Set("new_password", "newpass123")

	req := httptest.NewRequest(http.MethodPost, "/auth/change-password", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	handleChangePassword(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestCB27_HandleChangePassword_MissingFields(t *testing.T) {
	cb27SetupDB(t)
	cb27SetupHub(t)

	_, token := cb27RegisterUser(t, "chpwmiss", "pass123")

	form := url.Values{}
	form.Set("old_password", "pass123")
	// Missing new_password

	req := httptest.NewRequest(http.MethodPost, "/auth/change-password", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	handleChangePassword(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestCB27_HandleChangePassword_NoAuth(t *testing.T) {
	cb27SetupDB(t)

	req := httptest.NewRequest(http.MethodPost, "/auth/change-password", nil)
	w := httptest.NewRecorder()
	handleChangePassword(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

// ==============================
// handleDeleteConversation
// ==============================

func TestCB27_HandleDeleteConversation_Success(t *testing.T) {
	cb27SetupDB(t)
	cb27SetupHub(t)

	userID, token := cb27RegisterUser(t, "delconvuser", "pass123")
	agentID := "agent-delconv"
	cb27RegisterAgent(t, agentID, "DelConvBot")
	convID := cb27CreateConversation(t, userID, agentID)

	req := httptest.NewRequest(http.MethodDelete, "/conversations/delete?conversation_id="+convID, nil)
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	handleDeleteConversation(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCB27_HandleDeleteConversation_NotYours(t *testing.T) {
	cb27SetupDB(t)
	cb27SetupHub(t)

	userID1, _ := cb27RegisterUser(t, "delconvown", "pass123")
	_, token2 := cb27RegisterUser(t, "delconvother", "pass123")
	agentID := "agent-delconv2"
	cb27RegisterAgent(t, agentID, "DelConvBot2")
	convID := cb27CreateConversation(t, userID1, agentID)

	req := httptest.NewRequest(http.MethodDelete, "/conversations/delete?conversation_id="+convID, nil)
	req.Header.Set("Authorization", "Bearer "+token2)

	w := httptest.NewRecorder()
	handleDeleteConversation(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestCB27_HandleDeleteConversation_MissingConvID(t *testing.T) {
	cb27SetupDB(t)
	cb27SetupHub(t)

	_, token := cb27RegisterUser(t, "delconvmiss", "pass123")

	req := httptest.NewRequest(http.MethodDelete, "/conversations/delete", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	handleDeleteConversation(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

// ==============================
// handleSearchMessages
// ==============================

func TestCB27_HandleSearchMessages_Success(t *testing.T) {
	cb27SetupDB(t)
	cb27SetupHub(t)

	userID, token := cb27RegisterUser(t, "searchmsguser", "pass123")
	agentID := "agent-searchmsg"
	cb27RegisterAgent(t, agentID, "SearchMsgBot")
	convID := cb27CreateConversation(t, userID, agentID)
	cb27StoreMessage(t, convID, "client", userID, "find this keyword")
	cb27StoreMessage(t, convID, "agent", agentID, "another keyword here")

	req := httptest.NewRequest(http.MethodGet, "/messages/search?q=keyword", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	handleSearchMessages(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCB27_HandleSearchMessages_MissingQuery(t *testing.T) {
	cb27SetupDB(t)
	cb27SetupHub(t)

	_, token := cb27RegisterUser(t, "searchmiss", "pass123")

	req := httptest.NewRequest(http.MethodGet, "/messages/search", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	handleSearchMessages(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

// ==============================
// handleCreateConversation
// ==============================

func TestCB27_HandleCreateConversation_Success(t *testing.T) {
	cb27SetupDB(t)
	cb27SetupHub(t)

	_, token := cb27RegisterUser(t, "createconvuser", "pass123")
	agentID := "agent-createconv"
	cb27RegisterAgent(t, agentID, "CreateConvBot")

	form := url.Values{}
	form.Set("agent_id", agentID)

	req := httptest.NewRequest(http.MethodPost, "/conversations/create", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	handleCreateConversation(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp["conversation_id"] == "" {
		t.Error("expected conversation_id in response")
	}
}

func TestCB27_HandleCreateConversation_MissingAgentID(t *testing.T) {
	cb27SetupDB(t)
	cb27SetupHub(t)

	_, token := cb27RegisterUser(t, "createconvmiss", "pass123")

	form := url.Values{}

	req := httptest.NewRequest(http.MethodPost, "/conversations/create", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	handleCreateConversation(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

// ==============================
// handleGetMessages
// ==============================

func TestCB27_HandleGetMessages_Success(t *testing.T) {
	cb27SetupDB(t)
	cb27SetupHub(t)

	userID, token := cb27RegisterUser(t, "getmsguser", "pass123")
	agentID := "agent-getmsg"
	cb27RegisterAgent(t, agentID, "GetMsgBot")
	convID := cb27CreateConversation(t, userID, agentID)
	cb27StoreMessage(t, convID, "client", userID, "message 1")
	cb27StoreMessage(t, convID, "agent", agentID, "message 2")

	req := httptest.NewRequest(http.MethodGet, "/conversations/messages?conversation_id="+convID, nil)
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	handleGetMessages(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCB27_HandleGetMessages_ConversationNotFound(t *testing.T) {
	cb27SetupDB(t)
	cb27SetupHub(t)

	_, token := cb27RegisterUser(t, "getmsgnf", "pass123")

	req := httptest.NewRequest(http.MethodGet, "/conversations/messages?conversation_id=nonexistent", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	handleGetMessages(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}

func TestCB27_HandleGetMessages_WithPagination(t *testing.T) {
	cb27SetupDB(t)
	cb27SetupHub(t)

	userID, token := cb27RegisterUser(t, "getmsgpag", "pass123")
	agentID := "agent-getmsgpag"
	cb27RegisterAgent(t, agentID, "GetMsgPagBot")
	convID := cb27CreateConversation(t, userID, agentID)
	cb27StoreMessage(t, convID, "client", userID, "message 1")
	cb27StoreMessage(t, convID, "client", userID, "message 2")

	req := httptest.NewRequest(http.MethodGet, "/conversations/messages?conversation_id="+convID+"&limit=1", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	handleGetMessages(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var messages []StoredMessage
	if err := json.Unmarshal(w.Body.Bytes(), &messages); err != nil {
		t.Fatal(err)
	}
	if len(messages) != 1 {
		t.Errorf("expected 1 message with limit=1, got %d", len(messages))
	}
}

// ==============================
// Route chat message with real DB
// ==============================

func TestCB27_RouteChatMessage_Success(t *testing.T) {
	cb27SetupDB(t)
	cb27SetupHub(t)

	userID := generateID("user")
	agentID := "agent-routechat"
	cb27RegisterAgent(t, agentID, "RouteChatBot")
	convID := cb27CreateConversation(t, userID, agentID)

	// Set up the rate limiter to allow
	messageRateLimiter = NewRateLimiter(1000, time.Minute)
	t.Cleanup(func() { messageRateLimiter.Stop() })

	sender := &Connection{
		hub:      hub,
		connType: "client",
		id:       userID,
		deviceID: "device-1",
		send:     make(chan []byte, 256),
	}

	data := json.RawMessage(fmt.Sprintf(`{
		"conversation_id": "%s",
		"content": "hello from route test"
	}`, convID))

	routeChatMessage(sender, data)

	// Verify message was stored
	var count int
	db.QueryRow("SELECT COUNT(*) FROM messages WHERE conversation_id = ?", convID).Scan(&count)
	if count != 1 {
		t.Errorf("expected 1 message stored, got %d", count)
	}
}

func TestCB27_RouteChatMessage_NotAuthorized(t *testing.T) {
	cb27SetupDB(t)
	cb27SetupHub(t)

	userID := generateID("user")
	agentID := "agent-routechat2"
	cb27RegisterAgent(t, agentID, "RouteChatBot2")
	convID := cb27CreateConversation(t, userID, agentID)

	messageRateLimiter = NewRateLimiter(1000, time.Minute)
	t.Cleanup(func() { messageRateLimiter.Stop() })

	// Different user trying to send
	sender := &Connection{
		hub:      hub,
		connType: "client",
		id:       "other-user",
		deviceID: "device-1",
		send:     make(chan []byte, 256),
	}

	data := json.RawMessage(fmt.Sprintf(`{
		"conversation_id": "%s",
		"content": "unauthorized message"
	}`, convID))

	routeChatMessage(sender, data)

	// Verify message was NOT stored
	var count int
	db.QueryRow("SELECT COUNT(*) FROM messages WHERE conversation_id = ?", convID).Scan(&count)
	if count != 0 {
		t.Errorf("expected 0 messages stored (unauthorized), got %d", count)
	}
}

// ==============================
// handleHealth with nil db
// ==============================

func TestCB27_HandleHealth_NilDB(t *testing.T) {
	origDB := db
	db = nil
	t.Cleanup(func() { db = origDB })

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()
	handleHealth(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp["db"] != "not initialized" {
		t.Errorf("expected db=not initialized, got %v", resp["db"])
	}
}

// ==============================
// Metrics handler full output test
// ==============================

func TestCB27_HandleMetrics_Success(t *testing.T) {
	cb27SetupDB(t)
	cb27SetupHub(t)

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	w := httptest.NewRecorder()
	handleMetrics(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

// ==============================
// Logger edge cases
// ==============================

func TestCB27_Logger_NilDefaultLogger(t *testing.T) {
	orig := DefaultLogger
	DefaultLogger = NewLogger(LogInfo)
	t.Cleanup(func() { DefaultLogger = orig })

	// These should not panic
	DefaultLogger.Debug("test_debug", map[string]interface{}{"key": "value"})
	DefaultLogger.Info("test_info", map[string]interface{}{"key": "value"})
	DefaultLogger.Warn("test_warn", map[string]interface{}{"key": "value"})
	DefaultLogger.Error("test_error", map[string]interface{}{"key": "value"})
}

func TestCB27_MarshalOutgoingMessage_NilData(t *testing.T) {
	msg := OutgoingMessage{Type: "test", Data: nil}
	data := marshalOutgoingMessage(msg)
	if data == nil {
		t.Error("expected non-nil data")
	}
}

// ==============================
// bcrypt import check (used in changeUserPassword)
// ==============================

func TestCB27_ChangeUserPassword_NonexistentUser(t *testing.T) {
	cb27SetupDB(t)

	err := changeUserPassword("nonexistent-user", "oldpass", "newpass")
	if err != sql.ErrNoRows {
		t.Errorf("expected sql.ErrNoRows, got %v", err)
	}
}

// ==============================
// initQueueDB nil db
// ==============================

func TestCB27_InitQueueDB_NilDB(t *testing.T) {
	initQueueDB(nil) // should not panic
}

func TestCB27_PersistQueue_NilDB(t *testing.T) {
	persistQueue(nil, "user1", []byte("msg")) // should not panic
}

func TestCB27_DeleteQueueMessages_NilDB(t *testing.T) {
	deleteQueueMessages(nil, "user1") // should not panic
}

func TestCB27_LoadQueueFromDB_NilDB(t *testing.T) {
	q := newOfflineQueue(10, time.Hour)
	loadQueueFromDB(nil, q) // should not panic
}

func TestCB27_CleanStaleQueueMessages_NilDB(t *testing.T) {
	cleanStaleQueueMessages(nil, time.Hour) // should not panic
}