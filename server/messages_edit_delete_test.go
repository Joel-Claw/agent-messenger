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

// TestMessageEdit tests editing a message's content
func TestMessageEdit(t *testing.T) {
	setupTestDB(t)
	hub = newHub()
	go hub.run()
	ServerMetrics = NewMetrics(hub)

	// Register user and get token + user ID
	token := registerUserAndGetToken(t, "edituser", "password123")
	userID := getUserIDFromToken(t, token)

	// Create agent
	agent := &Connection{
		hub:         hub,
		connType:    "agent",
		id:          "edit-agent",
		send:        make(chan []byte, 256),
		connectedAt: time.Now(),
	}
	hub.register <- agent
	time.Sleep(10 * time.Millisecond)

	// Create conversation
	_, err := db.Exec("INSERT INTO conversations (id, user_id, agent_id, created_at) VALUES (?, ?, ?, datetime('now'))",
		"edit-conv-1", userID, "edit-agent")
	if err != nil {
		t.Fatal(err)
	}

	// Insert a message
	_, err = db.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, created_at) VALUES (?, ?, ?, ?, ?, ?)",
		"msg-to-edit", "edit-conv-1", "client", userID, "Original message", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}

	// Edit the message
	form := url.Values{}
	form.Set("message_id", "msg-to-edit")
	form.Set("content", "Edited message")

	req := httptest.NewRequest(http.MethodPost, "/messages/edit", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleMessageEdit(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["status"] != "edited" {
		t.Fatalf("expected status 'edited', got %v", resp["status"])
	}
	if resp["content"] != "Edited message" {
		t.Fatalf("expected content 'Edited message', got %v", resp["content"])
	}
	if resp["edited_at"] == nil {
		t.Fatal("expected edited_at to be set")
	}

	// Verify in DB
	var content string
	var editedAt *string
	err = db.QueryRow("SELECT content, edited_at FROM messages WHERE id = ?", "msg-to-edit").Scan(&content, &editedAt)
	if err != nil {
		t.Fatal(err)
	}
	if content != "Edited message" {
		t.Fatalf("expected DB content 'Edited message', got %q", content)
	}
	if editedAt == nil {
		t.Fatal("expected edited_at to be set in DB")
	}

	// Verify agent received message_edited event
	select {
	case data := <-agent.send:
		var outMsg OutgoingMessage
		json.Unmarshal(data, &outMsg)
		if outMsg.Type != "message_edited" {
			t.Fatalf("expected message_edited event, got %s", outMsg.Type)
		}
	case <-time.After(time.Second):
		t.Fatal("agent should have received message_edited event")
	}
}

// TestMessageEditUnauthorized tests that a user cannot edit another user's message
func TestMessageEditUnauthorized(t *testing.T) {
	setupTestDB(t)
	hub = newHub()
	go hub.run()
	ServerMetrics = NewMetrics(hub)

	token1 := registerUserAndGetToken(t, "owner", "password123")
	userID1 := getUserIDFromToken(t, token1)
	token2 := registerUserAndGetToken(t, "notowner", "password456")

	// Create conversation and message for user1
	_, err := db.Exec("INSERT INTO conversations (id, user_id, agent_id, created_at) VALUES (?, ?, ?, datetime('now'))",
		"edit-unauth-conv", userID1, "edit-agent-u")
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, created_at) VALUES (?, ?, ?, ?, ?, ?)",
		"msg-unauth", "edit-unauth-conv", "client", userID1, "Original", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}

	// Try to edit with user2's token
	form := url.Values{}
	form.Set("message_id", "msg-unauth")
	form.Set("content", "Hacked!")

	req := httptest.NewRequest(http.MethodPost, "/messages/edit", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token2)
	w := httptest.NewRecorder()
	handleMessageEdit(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

// TestMessageEditNotFound tests editing a nonexistent message
func TestMessageEditNotFound(t *testing.T) {
	setupTestDB(t)
	hub = newHub()
	go hub.run()
	ServerMetrics = NewMetrics(hub)

	token := registerUserAndGetToken(t, "editnfuser", "password123")

	form := url.Values{}
	form.Set("message_id", "nonexistent-msg")
	form.Set("content", "New content")

	req := httptest.NewRequest(http.MethodPost, "/messages/edit", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleMessageEdit(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}

// TestMessageDelete tests soft-deleting a message
func TestMessageDelete(t *testing.T) {
	setupTestDB(t)
	hub = newHub()
	go hub.run()
	ServerMetrics = NewMetrics(hub)

	token := registerUserAndGetToken(t, "deluser", "password123")
	userID := getUserIDFromToken(t, token)

	agent := &Connection{
		hub:         hub,
		connType:    "agent",
		id:          "del-agent",
		send:        make(chan []byte, 256),
		connectedAt: time.Now(),
	}
	hub.register <- agent
	time.Sleep(10 * time.Millisecond)

	// Create conversation and message
	_, err := db.Exec("INSERT INTO conversations (id, user_id, agent_id, created_at) VALUES (?, ?, ?, datetime('now'))",
		"del-conv-1", userID, "del-agent")
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, created_at) VALUES (?, ?, ?, ?, ?, ?)",
		"msg-to-del", "del-conv-1", "client", userID, "Delete me", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}

	// Delete the message
	form := url.Values{}
	form.Set("message_id", "msg-to-del")

	req := httptest.NewRequest(http.MethodPost, "/messages/delete", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleMessageDelete(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["status"] != "deleted" {
		t.Fatalf("expected status 'deleted', got %v", resp["status"])
	}

	// Verify in DB: content replaced, is_deleted = true
	var content string
	var isDeleted bool
	err = db.QueryRow("SELECT content, COALESCE(is_deleted, 0) FROM messages WHERE id = ?", "msg-to-del").Scan(&content, &isDeleted)
	if err != nil {
		t.Fatal(err)
	}
	if !isDeleted {
		t.Fatal("expected is_deleted = true")
	}
	if content != "[deleted]" {
		t.Fatalf("expected content '[deleted]', got %q", content)
	}

	// Verify agent received message_deleted event
	select {
	case data := <-agent.send:
		var outMsg OutgoingMessage
		json.Unmarshal(data, &outMsg)
		if outMsg.Type != "message_deleted" {
			t.Fatalf("expected message_deleted event, got %s", outMsg.Type)
		}
	case <-time.After(time.Second):
		t.Fatal("agent should have received message_deleted event")
	}
}

// TestMessageDeleteByConversationOwner tests that a conversation owner can delete any message in their conversation
func TestMessageDeleteByConversationOwner(t *testing.T) {
	setupTestDB(t)
	hub = newHub()
	go hub.run()
	ServerMetrics = NewMetrics(hub)

	token := registerUserAndGetToken(t, "convowner", "password123")
	userID := getUserIDFromToken(t, token)

	_, err := db.Exec("INSERT INTO conversations (id, user_id, agent_id, created_at) VALUES (?, ?, ?, datetime('now'))",
		"owner-del-conv", userID, "owner-del-agent")
	if err != nil {
		t.Fatal(err)
	}
	// Agent's message in the conversation
	_, err = db.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, created_at) VALUES (?, ?, ?, ?, ?, ?)",
		"agent-msg-del", "owner-del-conv", "agent", "owner-del-agent", "Agent message", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}

	// User deletes the agent's message (as conversation owner)
	form := url.Values{}
	form.Set("message_id", "agent-msg-del")

	req := httptest.NewRequest(http.MethodPost, "/messages/delete", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleMessageDelete(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 (owner can delete), got %d", w.Code)
	}
}

// TestMessageDeleteAlreadyDeleted tests deleting an already-deleted message
func TestMessageDeleteAlreadyDeleted(t *testing.T) {
	setupTestDB(t)
	hub = newHub()
	go hub.run()
	ServerMetrics = NewMetrics(hub)

	token := registerUserAndGetToken(t, "deldupuser", "password123")
	userID := getUserIDFromToken(t, token)

	_, err := db.Exec("INSERT INTO conversations (id, user_id, agent_id, created_at) VALUES (?, ?, ?, datetime('now'))",
		"deldup-conv", userID, "deldup-agent")
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, created_at, is_deleted) VALUES (?, ?, ?, ?, ?, ?, 1)",
		"msg-already-del", "deldup-conv", "client", userID, "[deleted]", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}

	form := url.Values{}
	form.Set("message_id", "msg-already-del")

	req := httptest.NewRequest(http.MethodPost, "/messages/delete", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleMessageDelete(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for already-deleted message, got %d", w.Code)
	}
}

// TestEditDeletedMessage tests that a deleted message cannot be edited
func TestEditDeletedMessage(t *testing.T) {
	setupTestDB(t)
	hub = newHub()
	go hub.run()
	ServerMetrics = NewMetrics(hub)

	token := registerUserAndGetToken(t, "editdeluser", "password123")
	userID := getUserIDFromToken(t, token)

	_, err := db.Exec("INSERT INTO conversations (id, user_id, agent_id, created_at) VALUES (?, ?, ?, datetime('now'))",
		"editdel-conv", userID, "editdel-agent")
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, created_at, is_deleted) VALUES (?, ?, ?, ?, ?, ?, 1)",
		"msg-edit-del", "editdel-conv", "client", userID, "[deleted]", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}

	form := url.Values{}
	form.Set("message_id", "msg-edit-del")
	form.Set("content", "Trying to edit deleted")

	req := httptest.NewRequest(http.MethodPost, "/messages/edit", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleMessageEdit(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for editing deleted message, got %d", w.Code)
	}
}

// TestMessageEditMissingFields tests validation for missing fields
func TestMessageEditMissingFields(t *testing.T) {
	setupTestDB(t)
	hub = newHub()
	go hub.run()
	ServerMetrics = NewMetrics(hub)

	token := registerUserAndGetToken(t, "editmfuser", "password123")

	// Missing message_id
	form := url.Values{}
	form.Set("content", "New content")
	req := httptest.NewRequest(http.MethodPost, "/messages/edit", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleMessageEdit(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for missing message_id, got %d", w.Code)
	}

	// Missing content
	form = url.Values{}
	form.Set("message_id", "some-msg")
	req = httptest.NewRequest(http.MethodPost, "/messages/edit", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)
	w = httptest.NewRecorder()
	handleMessageEdit(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for missing content, got %d", w.Code)
	}
}

// TestMessageDeleteMissingMessageID tests validation for missing message_id
func TestMessageDeleteMissingMessageID(t *testing.T) {
	setupTestDB(t)
	hub = newHub()
	go hub.run()
	ServerMetrics = NewMetrics(hub)

	token := registerUserAndGetToken(t, "delmfuser", "password123")

	form := url.Values{}
	req := httptest.NewRequest(http.MethodPost, "/messages/delete", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleMessageDelete(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for missing message_id, got %d", w.Code)
	}
}