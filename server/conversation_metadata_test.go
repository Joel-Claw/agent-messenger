package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// TestConversationMetadata tests that list conversations includes last_message and unread_count
func TestConversationMetadata(t *testing.T) {
	setupTestDB(t)
	hub = newHub()
	go hub.run()
	ServerMetrics = NewMetrics(hub)

	token := registerUserAndGetToken(t, "metauser", "password123")
	userID := getUserIDFromToken(t, token)

	// Create agent
	_, err := db.Exec("INSERT OR IGNORE INTO agents (id, name) VALUES (?, ?)", "meta-agent", "Meta Agent")
	if err != nil {
		t.Fatal(err)
	}

	// Create conversation via API
	form := url.Values{}
	form.Set("agent_id", "meta-agent")
	req := httptest.NewRequest(http.MethodPost, "/conversations/create", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleCreateConversation(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("create conversation failed: %d %s", w.Code, w.Body.String())
	}

	var createResp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &createResp)
	convID := createResp["conversation_id"].(string)

	// Insert some messages
	_, err = db.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, created_at) VALUES (?, ?, ?, ?, ?, ?)",
		"meta-msg-1", convID, "client", userID, "Hello from user", time.Now().UTC().Add(-2*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, created_at) VALUES (?, ?, ?, ?, ?, ?)",
		"meta-msg-2", convID, "agent", "meta-agent", "Hello from agent", time.Now().UTC().Add(-1*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	// Third message is unread (no read_at)
	_, err = db.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, created_at) VALUES (?, ?, ?, ?, ?, ?)",
		"meta-msg-3", convID, "agent", "meta-agent", "Unread message", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}

	// Mark first two as read
	_, err = db.Exec("UPDATE messages SET read_at = ? WHERE id IN (?, ?)", time.Now().UTC(), "meta-msg-1", "meta-msg-2")
	if err != nil {
		t.Fatal(err)
	}

	// List conversations
	req = httptest.NewRequest(http.MethodGet, "/conversations", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w = httptest.NewRecorder()
	handleListConversations(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("list conversations failed: %d %s", w.Code, w.Body.String())
	}

	var convs []map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &convs)
	if len(convs) == 0 {
		t.Fatal("expected at least one conversation")
	}

	conv := convs[0]

	// Check last_message
	lastMsg, ok := conv["last_message"].(map[string]interface{})
	if !ok || lastMsg == nil {
		t.Fatal("expected last_message to be present")
	}
	if lastMsg["content"] != "Unread message" {
		t.Fatalf("expected last_message content 'Unread message', got %v", lastMsg["content"])
	}
	if lastMsg["sender_type"] != "agent" {
		t.Fatalf("expected last_message sender_type 'agent', got %v", lastMsg["sender_type"])
	}

	// Check unread_count
	unreadCount := int(conv["unread_count"].(float64))
	if unreadCount != 1 {
		t.Fatalf("expected unread_count 1, got %d", unreadCount)
	}
}

// TestConversationMetadataEmpty tests metadata for a conversation with no messages
func TestConversationMetadataEmpty(t *testing.T) {
	setupTestDB(t)
	hub = newHub()
	go hub.run()
	ServerMetrics = NewMetrics(hub)

	token := registerUserAndGetToken(t, "emptyuser", "password123")

	_, err := db.Exec("INSERT OR IGNORE INTO agents (id, name) VALUES (?, ?)", "empty-agent", "Empty Agent")
	if err != nil {
		t.Fatal(err)
	}

	form := url.Values{}
	form.Set("agent_id", "empty-agent")
	req := httptest.NewRequest(http.MethodPost, "/conversations/create", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleCreateConversation(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("create conversation failed: %d %s", w.Code, w.Body.String())
	}

	// List conversations
	req = httptest.NewRequest(http.MethodGet, "/conversations", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w = httptest.NewRecorder()
	handleListConversations(w, req)

	var convs []map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &convs)
	if len(convs) == 0 {
		t.Fatal("expected at least one conversation")
	}

	conv := convs[0]

	// Empty conversation should have no last_message
	if conv["last_message"] != nil {
		t.Fatalf("expected last_message nil for empty conversation, got %v", conv["last_message"])
	}

	unreadCount := int(conv["unread_count"].(float64))
	if unreadCount != 0 {
		t.Fatalf("expected unread_count 0 for empty conversation, got %d", unreadCount)
	}
}

// TestConversationMetadataDeletedExcluded tests that deleted messages are excluded from last_message
func TestConversationMetadataDeletedExcluded(t *testing.T) {
	setupTestDB(t)
	hub = newHub()
	go hub.run()
	ServerMetrics = NewMetrics(hub)

	token := registerUserAndGetToken(t, "delmetauser", "password123")
	userID := getUserIDFromToken(t, token)

	_, err := db.Exec("INSERT OR IGNORE INTO agents (id, name) VALUES (?, ?)", "delmeta-agent", "DelMeta Agent")
	if err != nil {
		t.Fatal(err)
	}

	form := url.Values{}
	form.Set("agent_id", "delmeta-agent")
	req := httptest.NewRequest(http.MethodPost, "/conversations/create", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleCreateConversation(w, req)

	var createResp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &createResp)
	convID := createResp["conversation_id"].(string)

	// Insert a regular message
	_, err = db.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, created_at) VALUES (?, ?, ?, ?, ?, ?)",
		"delmeta-msg-1", convID, "client", userID, "Visible message", time.Now().UTC().Add(-1*time.Hour))
	if err != nil {
		t.Fatal(err)
	}

	// Insert a deleted message (should be excluded from last_message)
	_, err = db.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, created_at, is_deleted) VALUES (?, ?, ?, ?, ?, ?, 1)",
		"delmeta-msg-2", convID, "agent", "delmeta-agent", "[deleted]", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}

	// List conversations
	req = httptest.NewRequest(http.MethodGet, "/conversations", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w = httptest.NewRecorder()
	handleListConversations(w, req)

	var convs []map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &convs)
	conv := convs[0]

	lastMsg := conv["last_message"].(map[string]interface{})
	if lastMsg["content"] != "Visible message" {
		t.Fatalf("expected last_message to be 'Visible message' (not the deleted one), got %v", lastMsg["content"])
	}
}