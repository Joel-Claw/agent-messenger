package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// --- Password Change Tests ---

func TestChangePassword(t *testing.T) {
	setupTestDB(t)
	hub = newHub()
	go hub.run()

	token := registerUserAndGetToken(t, "pwuser", "oldpass123")

	// Change password
	form := url.Values{}
	form.Set("old_password", "oldpass123")
	form.Set("new_password", "newpass456")
	req := httptest.NewRequest(http.MethodPost, "/auth/change-password", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleChangePassword(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]string
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["status"] != "password_changed" {
		t.Fatalf("expected status=password_changed, got %s", resp["status"])
	}

	// Verify old password no longer works
	form2 := url.Values{}
	form2.Set("username", "pwuser")
	form2.Set("password", "oldpass123")
	req2 := httptest.NewRequest(http.MethodPost, "/auth/login", strings.NewReader(form2.Encode()))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w2 := httptest.NewRecorder()
	handleLogin(w2, req2)

	if w2.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for old password after change, got %d", w2.Code)
	}

	// Verify new password works
	form3 := url.Values{}
	form3.Set("username", "pwuser")
	form3.Set("password", "newpass456")
	req3 := httptest.NewRequest(http.MethodPost, "/auth/login", strings.NewReader(form3.Encode()))
	req3.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w3 := httptest.NewRecorder()
	handleLogin(w3, req3)

	if w3.Code != http.StatusOK {
		t.Fatalf("expected 200 for new password, got %d", w3.Code)
	}
}

func TestChangePasswordWrongOld(t *testing.T) {
	setupTestDB(t)
	hub = newHub()
	go hub.run()

	token := registerUserAndGetToken(t, "pwuser2", "correct123")

	form := url.Values{}
	form.Set("old_password", "wrongold")
	form.Set("new_password", "newpass456")
	req := httptest.NewRequest(http.MethodPost, "/auth/change-password", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleChangePassword(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for wrong old password, got %d", w.Code)
	}
}

func TestChangePasswordMissingFields(t *testing.T) {
	setupTestDB(t)
	hub = newHub()
	go hub.run()

	token := registerUserAndGetToken(t, "pwuser3", "pass123")

	req := httptest.NewRequest(http.MethodPost, "/auth/change-password", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleChangePassword(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for missing fields, got %d", w.Code)
	}
}

func TestChangePasswordShortNew(t *testing.T) {
	setupTestDB(t)
	hub = newHub()
	go hub.run()

	token := registerUserAndGetToken(t, "pwuser4", "oldpass123")

	form := url.Values{}
	form.Set("old_password", "oldpass123")
	form.Set("new_password", "short")
	req := httptest.NewRequest(http.MethodPost, "/auth/change-password", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleChangePassword(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for short new password, got %d: %s", w.Code, w.Body.String())
	}
}

func TestChangePasswordUnauthorized(t *testing.T) {
	setupTestDB(t)

	req := httptest.NewRequest(http.MethodPost, "/auth/change-password", nil)
	w := httptest.NewRecorder()
	handleChangePassword(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for no auth, got %d", w.Code)
	}
}

// --- Conversation Deletion Tests ---

func TestDeleteConversation(t *testing.T) {
	_, cleanup := setupTestServerForRouting(t)
	defer cleanup()

	token := registerUserAndGetToken(t, "deluser", "password123")

	// Create a conversation
	form := url.Values{}
	form.Set("agent_id", "del-agent")
	req := httptest.NewRequest(http.MethodPost, "/conversations/create", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleCreateConversation(w, req)

	var createResp map[string]string
	json.Unmarshal(w.Body.Bytes(), &createResp)
	convID := createResp["conversation_id"]

	// Store a message
	msg := RoutedMessage{
		Type:           "message",
		ConversationID: convID,
		Content:        "test message to delete",
		SenderType:     "agent",
		SenderID:       "del-agent",
		RecipientID:    createResp["user_id"],
	}
	if err := storeMessage(msg); err != nil {
		t.Fatal(err)
	}

	// Delete the conversation
	req2 := httptest.NewRequest(http.MethodDelete, "/conversations/delete?conversation_id="+convID, nil)
	req2.Header.Set("Authorization", "Bearer "+token)
	w2 := httptest.NewRecorder()
	handleDeleteConversation(w2, req2)

	if w2.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w2.Code, w2.Body.String())
	}

	var delResp map[string]string
	json.Unmarshal(w2.Body.Bytes(), &delResp)
	if delResp["status"] != "deleted" {
		t.Fatalf("expected status=deleted, got %s", delResp["status"])
	}
	if delResp["conversation_id"] != convID {
		t.Fatalf("expected conversation_id=%s, got %s", convID, delResp["conversation_id"])
	}

	// Verify conversation is gone
	req3 := httptest.NewRequest(http.MethodGet, "/conversations/messages?conversation_id="+convID, nil)
	req3.Header.Set("Authorization", "Bearer "+token)
	w3 := httptest.NewRecorder()
	handleGetMessages(w3, req3)

	if w3.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for deleted conversation, got %d", w3.Code)
	}
}

func TestDeleteConversationUnauthorized(t *testing.T) {
	setupTestDB(t)
	hub = newHub()
	go hub.run()

	// User A creates a conversation
	tokenA := registerUserAndGetToken(t, "owner_user", "password123")
	form := url.Values{}
	form.Set("agent_id", "shared-agent")
	req := httptest.NewRequest(http.MethodPost, "/conversations/create", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+tokenA)
	w := httptest.NewRecorder()
	handleCreateConversation(w, req)

	var createResp map[string]string
	json.Unmarshal(w.Body.Bytes(), &createResp)
	convID := createResp["conversation_id"]

	// User B tries to delete User A's conversation
	tokenB := registerUserAndGetToken(t, "other_user", "password456")
	req2 := httptest.NewRequest(http.MethodDelete, "/conversations/delete?conversation_id="+convID, nil)
	req2.Header.Set("Authorization", "Bearer "+tokenB)
	w2 := httptest.NewRecorder()
	handleDeleteConversation(w2, req2)

	if w2.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for unauthorized delete, got %d", w2.Code)
	}
}

func TestDeleteConversationNotFound(t *testing.T) {
	setupTestDB(t)
	hub = newHub()
	go hub.run()

	token := registerUserAndGetToken(t, "nofound_user", "password123")
	req := httptest.NewRequest(http.MethodDelete, "/conversations/delete?conversation_id=conv_nonexistent", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleDeleteConversation(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}

func TestDeleteConversationMissingID(t *testing.T) {
	setupTestDB(t)
	hub = newHub()
	go hub.run()

	token := registerUserAndGetToken(t, "noid_user", "password123")
	req := httptest.NewRequest(http.MethodDelete, "/conversations/delete", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleDeleteConversation(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for missing conversation_id, got %d", w.Code)
	}
}

// --- Message Search Tests ---

func TestSearchMessages(t *testing.T) {
	setupTestDB(t)
	hub = newHub()
	go hub.run()

	token := registerUserAndGetToken(t, "searchuser", "password123")

	// Create a conversation
	form := url.Values{}
	form.Set("agent_id", "search-agent")
	req := httptest.NewRequest(http.MethodPost, "/conversations/create", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleCreateConversation(w, req)

	var createResp map[string]string
	json.Unmarshal(w.Body.Bytes(), &createResp)
	convID := createResp["conversation_id"]
	userID := createResp["user_id"]

	// Store several messages
	messages := []RoutedMessage{
		{Type: "message", ConversationID: convID, Content: "Hello from the agent", SenderType: "agent", SenderID: "search-agent", RecipientID: userID},
		{Type: "message", ConversationID: convID, Content: "Hi there from the user", SenderType: "client", SenderID: userID, RecipientID: "search-agent"},
		{Type: "message", ConversationID: convID, Content: "How is the weather today?", SenderType: "client", SenderID: userID, RecipientID: "search-agent"},
		{Type: "message", ConversationID: convID, Content: "The weather is sunny", SenderType: "agent", SenderID: "search-agent", RecipientID: userID},
	}
	for _, m := range messages {
		if err := storeMessage(m); err != nil {
			t.Fatal(err)
		}
	}

	// Search for "weather"
	req2 := httptest.NewRequest(http.MethodGet, "/messages/search?q=weather", nil)
	req2.Header.Set("Authorization", "Bearer "+token)
	w2 := httptest.NewRecorder()
	handleSearchMessages(w2, req2)

	if w2.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w2.Code, w2.Body.String())
	}

	var results []StoredMessage
	json.Unmarshal(w2.Body.Bytes(), &results)
	if len(results) != 2 {
		t.Fatalf("expected 2 results for 'weather', got %d", len(results))
	}
}

func TestSearchMessagesEmptyQuery(t *testing.T) {
	setupTestDB(t)
	hub = newHub()
	go hub.run()

	token := registerUserAndGetToken(t, "searchempty", "password123")

	req := httptest.NewRequest(http.MethodGet, "/messages/search?q=", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleSearchMessages(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for empty query, got %d", w.Code)
	}
}

func TestSearchMessagesUnauthorized(t *testing.T) {
	setupTestDB(t)

	req := httptest.NewRequest(http.MethodGet, "/messages/search?q=test", nil)
	w := httptest.NewRecorder()
	handleSearchMessages(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for no auth, got %d", w.Code)
	}
}

func TestSearchMessagesNoResults(t *testing.T) {
	setupTestDB(t)
	hub = newHub()
	go hub.run()

	token := registerUserAndGetToken(t, "searchnone", "password123")

	req := httptest.NewRequest(http.MethodGet, "/messages/search?q=nonexistent_term_xyz", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleSearchMessages(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var results []StoredMessage
	json.Unmarshal(w.Body.Bytes(), &results)
	if len(results) != 0 {
		t.Fatalf("expected 0 results, got %d", len(results))
	}
}

// --- Read Receipts Tests ---

func TestMarkMessagesRead(t *testing.T) {
	setupTestDB(t)
	hub = newHub()
	go hub.run()

	token := registerUserAndGetToken(t, "readuser", "password123")

	// Create a conversation
	form := url.Values{}
	form.Set("agent_id", "read-agent")
	req := httptest.NewRequest(http.MethodPost, "/conversations/create", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleCreateConversation(w, req)

	var createResp map[string]string
	json.Unmarshal(w.Body.Bytes(), &createResp)
	convID := createResp["conversation_id"]
	userID := createResp["user_id"]

	// Store some agent messages
	for i := 0; i < 3; i++ {
		msg := RoutedMessage{
			Type:           "message",
			ConversationID: convID,
			Content:        "agent message",
			SenderType:     "agent",
			SenderID:       "read-agent",
			RecipientID:    userID,
		}
		if err := storeMessage(msg); err != nil {
			t.Fatal(err)
		}
	}

	// Mark as read
	form2 := url.Values{}
	form2.Set("conversation_id", convID)
	req2 := httptest.NewRequest(http.MethodPost, "/conversations/mark-read", strings.NewReader(form2.Encode()))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req2.Header.Set("Authorization", "Bearer "+token)
	w2 := httptest.NewRecorder()
	handleMarkRead(w2, req2)

	if w2.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w2.Code, w2.Body.String())
	}

	var readResp map[string]interface{}
	json.Unmarshal(w2.Body.Bytes(), &readResp)
	if readResp["status"] != "marked_read" {
		t.Fatalf("expected status=marked_read, got %v", readResp["status"])
	}
	// 3 agent messages should be marked
	count := int(readResp["count"].(float64))
	if count != 3 {
		t.Fatalf("expected count=3, got %d", count)
	}

	// Verify messages now have read_at set
	messages, err := getConversationMessages(convID, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range messages {
		if m.SenderType == "agent" && m.ReadAt == nil {
			t.Fatalf("expected agent message %s to have read_at set", m.ID)
		}
	}
}

func TestMarkReadUnauthorized(t *testing.T) {
	setupTestDB(t)
	hub = newHub()
	go hub.run()

	// User A creates conversation
	tokenA := registerUserAndGetToken(t, "readowner", "password123")
	form := url.Values{}
	form.Set("agent_id", "readshared-agent")
	req := httptest.NewRequest(http.MethodPost, "/conversations/create", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+tokenA)
	w := httptest.NewRecorder()
	handleCreateConversation(w, req)

	var createResp map[string]string
	json.Unmarshal(w.Body.Bytes(), &createResp)
	convID := createResp["conversation_id"]

	// User B tries to mark User A's messages as read
	tokenB := registerUserAndGetToken(t, "readother", "password456")
	form2 := url.Values{}
	form2.Set("conversation_id", convID)
	req2 := httptest.NewRequest(http.MethodPost, "/conversations/mark-read", strings.NewReader(form2.Encode()))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req2.Header.Set("Authorization", "Bearer "+tokenB)
	w2 := httptest.NewRecorder()
	handleMarkRead(w2, req2)

	if w2.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for unauthorized mark-read, got %d", w2.Code)
	}
}

func TestMarkReadMissingConversationID(t *testing.T) {
	setupTestDB(t)
	hub = newHub()
	go hub.run()

	token := registerUserAndGetToken(t, "readmiss", "password123")
	req := httptest.NewRequest(http.MethodPost, "/conversations/mark-read", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleMarkRead(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for missing conversation_id, got %d", w.Code)
	}
}

func TestMarkReadNonexistentConversation(t *testing.T) {
	setupTestDB(t)
	hub = newHub()
	go hub.run()

	token := registerUserAndGetToken(t, "readnone", "password123")
	form := url.Values{}
	form.Set("conversation_id", "conv_nonexistent")
	req := httptest.NewRequest(http.MethodPost, "/conversations/mark-read", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleMarkRead(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}

func TestMarkReadIdempotent(t *testing.T) {
	setupTestDB(t)
	hub = newHub()
	go hub.run()

	token := registerUserAndGetToken(t, "readidem", "password123")

	// Create conversation + agent messages
	form := url.Values{}
	form.Set("agent_id", "idem-agent")
	req := httptest.NewRequest(http.MethodPost, "/conversations/create", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleCreateConversation(w, req)

	var createResp map[string]string
	json.Unmarshal(w.Body.Bytes(), &createResp)
	convID := createResp["conversation_id"]

	msg := RoutedMessage{
		Type:           "message",
		ConversationID: convID,
		Content:        "hello",
		SenderType:     "agent",
		SenderID:       "idem-agent",
		RecipientID:    createResp["user_id"],
	}
	storeMessage(msg)

	// Mark read first time
	form2 := url.Values{}
	form2.Set("conversation_id", convID)
	req2 := httptest.NewRequest(http.MethodPost, "/conversations/mark-read", strings.NewReader(form2.Encode()))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req2.Header.Set("Authorization", "Bearer "+token)
	w2 := httptest.NewRecorder()
	handleMarkRead(w2, req2)

	// Mark read second time (should return count=0, no error)
	req3 := httptest.NewRequest(http.MethodPost, "/conversations/mark-read", strings.NewReader(form2.Encode()))
	req3.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req3.Header.Set("Authorization", "Bearer "+token)
	w3 := httptest.NewRecorder()
	handleMarkRead(w3, req3)

	if w3.Code != http.StatusOK {
		t.Fatalf("expected 200 on second mark-read, got %d", w3.Code)
	}

	var resp map[string]interface{}
	json.Unmarshal(w3.Body.Bytes(), &resp)
	count := int(resp["count"].(float64))
	if count != 0 {
		t.Fatalf("expected count=0 on second call (already read), got %d", count)
	}
}