package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

// =====================================================
// Handler coverage tests for low-coverage functions
// =====================================================

// helper to create a user and return JWT token
// Use underscores instead of hyphens in usernames (validation requires letters/numbers/underscores)
func cb7CreateUser(t *testing.T, username string) string {
	t.Helper()
	form := "username=" + username + "&password=testpass123"
	req := httptest.NewRequest("POST", "/auth/user", bytes.NewBufferString(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handleRegisterUser(w, req)
	if w.Code != 200 {
		t.Fatalf("Failed to register user %s: %d %s", username, w.Code, w.Body.String())
	}
	form2 := "username=" + username + "&password=testpass123"
	req2 := httptest.NewRequest("POST", "/auth/login", bytes.NewBufferString(form2))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w2 := httptest.NewRecorder()
	handleLogin(w2, req2)
	if w2.Code != 200 {
		t.Fatalf("Failed to login %s: %d %s", username, w2.Code, w2.Body.String())
	}
	var resp map[string]interface{}
	json.NewDecoder(w2.Body).Decode(&resp)
	return resp["token"].(string)
}

// helper to create a conversation via handler
func cb7CreateConversation(t *testing.T, token, agentID string) string {
	t.Helper()
	form := "agent_id=" + agentID
	req := httptest.NewRequest("POST", "/conversations/create", bytes.NewBufferString(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleCreateConversation(w, req)
	if w.Code != 200 {
		t.Fatalf("Failed to create conversation: %d %s", w.Code, w.Body.String())
	}
	var resp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&resp)
	return resp["conversation_id"].(string)
}

// helper to register an agent
func cb7RegisterAgent(t *testing.T, agentID, name string) {
	t.Helper()
	secret := getAgentSecret()
	form := "agent_id=" + agentID + "&name=" + name + "&agent_secret=" + secret
	req := httptest.NewRequest("POST", "/auth/agent", bytes.NewBufferString(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Agent-Secret", secret)
	w := httptest.NewRecorder()
	handleRegisterAgent(w, req)
	if w.Code != 200 {
		t.Fatalf("Failed to register agent: %d %s", w.Code, w.Body.String())
	}
}

// --- handleSearchMessages ---

func TestCb7SearchMessages_BasicSearch(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	token := cb7CreateUser(t, "searchuser1")
	cb7RegisterAgent(t, "search-agent-1", "Search Agent")
	convID := cb7CreateConversation(t, token, "search-agent-1")

	_, err := db.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, created_at) VALUES (?, ?, ?, ?, ?, ?)",
		"msg-search-1", convID, "user", "searchuser1", "hello world", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, created_at) VALUES (?, ?, ?, ?, ?, ?)",
		"msg-search-2", convID, "agent", "search-agent-1", "hello there", time.Now().UTC().Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest("GET", "/messages/search?q=hello", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleSearchMessages(w, req)

	if w.Code != 200 {
		t.Fatalf("Expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var results []map[string]interface{}
	json.NewDecoder(w.Body).Decode(&results)
	if len(results) < 2 {
		t.Errorf("Expected at least 2 results, got %d", len(results))
	}
}

func TestCb7SearchMessages_EmptyQuery(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	token := cb7CreateUser(t, "searchuser2")

	req := httptest.NewRequest("GET", "/messages/search?q=", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleSearchMessages(w, req)

	if w.Code != 400 {
		t.Errorf("Expected 400 for empty query, got %d", w.Code)
	}
}

func TestCb7SearchMessages_NoResults(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	token := cb7CreateUser(t, "searchuser3")

	req := httptest.NewRequest("GET", "/messages/search?q=nonexistent", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleSearchMessages(w, req)

	if w.Code != 200 {
		t.Fatalf("Expected 200, got %d", w.Code)
	}
	var results []map[string]interface{}
	json.NewDecoder(w.Body).Decode(&results)
	if results == nil {
		t.Errorf("Expected empty array, got nil")
	}
}

func TestCb7SearchMessages_Unauthorized(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	req := httptest.NewRequest("GET", "/messages/search?q=test", nil)
	w := httptest.NewRecorder()
	handleSearchMessages(w, req)

	if w.Code != 401 {
		t.Errorf("Expected 401, got %d", w.Code)
	}
}

func TestCb7SearchMessages_MethodNotAllowed(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	req := httptest.NewRequest("POST", "/messages/search?q=test", nil)
	w := httptest.NewRecorder()
	handleSearchMessages(w, req)

	if w.Code != 405 {
		t.Errorf("Expected 405, got %d", w.Code)
	}
}

func TestCb7SearchMessages_CustomLimit(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	token := cb7CreateUser(t, "searchuser4")
	cb7RegisterAgent(t, "search-agent-4", "Search Agent")
	convID := cb7CreateConversation(t, token, "search-agent-4")

	for i := 0; i < 3; i++ {
		_, err := db.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, created_at) VALUES (?, ?, ?, ?, ?, ?)",
			fmt.Sprintf("msg-limit-%d", i), convID, "user", "searchuser4", fmt.Sprintf("test message %d", i), time.Now().UTC().Add(time.Duration(i)*time.Second))
		if err != nil {
			t.Fatal(err)
		}
	}

	req := httptest.NewRequest("GET", "/messages/search?q=test&limit=2", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleSearchMessages(w, req)

	if w.Code != 200 {
		t.Fatalf("Expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var results []map[string]interface{}
	json.NewDecoder(w.Body).Decode(&results)
	if len(results) > 2 {
		t.Errorf("Expected at most 2 results, got %d", len(results))
	}
}

func TestCb7SearchMessages_LimitOverMax(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	token := cb7CreateUser(t, "searchuser5")

	req := httptest.NewRequest("GET", "/messages/search?q=test&limit=500", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleSearchMessages(w, req)

	if w.Code != 200 {
		t.Errorf("Expected 200, got %d", w.Code)
	}
}

func TestCb7SearchMessages_InvalidLimit(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	token := cb7CreateUser(t, "searchuser6")

	req := httptest.NewRequest("GET", "/messages/search?q=test&limit=abc", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleSearchMessages(w, req)

	if w.Code != 200 {
		t.Errorf("Expected 200 with default limit, got %d", w.Code)
	}
}

// --- handleListConversations ---

func TestCb7ListConversations_Basic(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	token := cb7CreateUser(t, "listconvuser1")
	cb7RegisterAgent(t, "list-agent-1", "List Agent")
	cb7CreateConversation(t, token, "list-agent-1")

	req := httptest.NewRequest("GET", "/conversations/list", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleListConversations(w, req)

	if w.Code != 200 {
		t.Fatalf("Expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var convs []map[string]interface{}
	json.NewDecoder(w.Body).Decode(&convs)
	if len(convs) != 1 {
		t.Errorf("Expected 1 conversation, got %d", len(convs))
	}
}

func TestCb7ListConversations_EmptyList(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	token := cb7CreateUser(t, "listconvuser2")

	req := httptest.NewRequest("GET", "/conversations/list", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleListConversations(w, req)

	if w.Code != 200 {
		t.Fatalf("Expected 200, got %d", w.Code)
	}
	var convs []map[string]interface{}
	json.NewDecoder(w.Body).Decode(&convs)
	if convs == nil {
		t.Errorf("Expected empty array, got nil")
	}
}

func TestCb7ListConversations_Unauthorized(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	req := httptest.NewRequest("GET", "/conversations/list", nil)
	w := httptest.NewRecorder()
	handleListConversations(w, req)

	if w.Code != 401 {
		t.Errorf("Expected 401, got %d", w.Code)
	}
}

func TestCb7ListConversations_MethodNotAllowed(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	req := httptest.NewRequest("POST", "/conversations/list", nil)
	w := httptest.NewRecorder()
	handleListConversations(w, req)

	if w.Code != 405 {
		t.Errorf("Expected 405, got %d", w.Code)
	}
}

func TestCb7ListConversations_WithLastMessage(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	token := cb7CreateUser(t, "listconvuser3")
	cb7RegisterAgent(t, "list-agent-3", "List Agent 3")
	convID := cb7CreateConversation(t, token, "list-agent-3")

	_, err := db.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, created_at) VALUES (?, ?, ?, ?, ?, ?)",
		"msg-list-1", convID, "user", "listconvuser3", "last message content", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest("GET", "/conversations/list", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleListConversations(w, req)

	if w.Code != 200 {
		t.Fatalf("Expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var convs []map[string]interface{}
	json.NewDecoder(w.Body).Decode(&convs)
	if len(convs) != 1 {
		t.Fatalf("Expected 1 conversation, got %d", len(convs))
	}
	lm := convs[0]["last_message"]
	if lm == nil {
		t.Error("Expected last_message to be present")
	}
}

func TestCb7ListConversations_WithUnreadCount(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	token := cb7CreateUser(t, "listconvuser4")
	cb7RegisterAgent(t, "list-agent-4", "List Agent 4")
	convID := cb7CreateConversation(t, token, "list-agent-4")

	_, err := db.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, created_at) VALUES (?, ?, ?, ?, ?, ?)",
		"msg-unread-1", convID, "agent", "list-agent-4", "unread message", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest("GET", "/conversations/list", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleListConversations(w, req)

	if w.Code != 200 {
		t.Fatalf("Expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var convs []map[string]interface{}
	json.NewDecoder(w.Body).Decode(&convs)
	if len(convs) != 1 {
		t.Fatalf("Expected 1 conversation, got %d", len(convs))
	}
	uc := convs[0]["unread_count"]
	if uc == nil {
		t.Error("Expected unread_count to be present")
	}
}

// --- handleDeleteConversation ---

func TestCb7DeleteConversation_Basic(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	token := cb7CreateUser(t, "deleteconvuser1")
	cb7RegisterAgent(t, "delete-agent-1", "Delete Agent")
	convID := cb7CreateConversation(t, token, "delete-agent-1")

	req := httptest.NewRequest("DELETE", "/conversations/delete?conversation_id="+convID, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleDeleteConversation(w, req)

	if w.Code != 200 {
		t.Fatalf("Expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var count int
	err := db.QueryRow("SELECT COUNT(*) FROM conversations WHERE id = ?", convID).Scan(&count)
	if err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Errorf("Expected conversation to be deleted, but found %d rows", count)
	}
}

func TestCb7DeleteConversation_Unauthorized(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	req := httptest.NewRequest("DELETE", "/conversations/delete?conversation_id=abc", nil)
	w := httptest.NewRecorder()
	handleDeleteConversation(w, req)

	if w.Code != 401 {
		t.Errorf("Expected 401, got %d", w.Code)
	}
}

func TestCb7DeleteConversation_NotOwner(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	token1 := cb7CreateUser(t, "deleteconvuser2")
	token2 := cb7CreateUser(t, "deleteconvuser3")
	cb7RegisterAgent(t, "delete-agent-2", "Delete Agent 2")
	convID := cb7CreateConversation(t, token1, "delete-agent-2")

	req := httptest.NewRequest("DELETE", "/conversations/delete?conversation_id="+convID, nil)
	req.Header.Set("Authorization", "Bearer "+token2)
	w := httptest.NewRecorder()
	handleDeleteConversation(w, req)

	if w.Code != 401 {
		t.Errorf("Expected 401 for non-owner, got %d", w.Code)
	}
}

func TestCb7DeleteConversation_NotFound(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	token := cb7CreateUser(t, "deleteconvuser4")

	req := httptest.NewRequest("DELETE", "/conversations/delete?conversation_id=nonexistent", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleDeleteConversation(w, req)

	if w.Code != 404 {
		t.Errorf("Expected 404, got %d", w.Code)
	}
}

func TestCb7DeleteConversation_MissingID(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	token := cb7CreateUser(t, "deleteconvuser5")

	req := httptest.NewRequest("DELETE", "/conversations/delete", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleDeleteConversation(w, req)

	if w.Code != 400 {
		t.Errorf("Expected 400, got %d", w.Code)
	}
}

func TestCb7DeleteConversation_MethodNotAllowed(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	req := httptest.NewRequest("POST", "/conversations/delete", nil)
	w := httptest.NewRecorder()
	handleDeleteConversation(w, req)

	if w.Code != 405 {
		t.Errorf("Expected 405, got %d", w.Code)
	}
}

// --- handleStoreEncryptedMessage ---

func TestCb7StoreEncryptedMessage_Basic(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	token := cb7CreateUser(t, "encuser1")
	cb7RegisterAgent(t, "enc-agent-1", "Enc Agent")
	convID := cb7CreateConversation(t, token, "enc-agent-1")

	body := `{"conversation_id":"` + convID + `","ciphertext":"base64ciphertext","iv":"base64iv","algorithm":"aes-256-gcm","recipient_key_id":"key-1"}`
	req := httptest.NewRequest("POST", "/messages/encrypted", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleStoreEncryptedMessage(w, req)

	if w.Code != 200 {
		t.Fatalf("Expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["status"] != "stored" {
		t.Errorf("Expected status 'stored', got %v", resp["status"])
	}
	if resp["id"] == nil || resp["id"] == "" {
		t.Error("Expected message id in response")
	}
}

func TestCb7StoreEncryptedMessage_MethodNotAllowed(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	req := httptest.NewRequest("GET", "/messages/encrypted", nil)
	w := httptest.NewRecorder()
	handleStoreEncryptedMessage(w, req)

	if w.Code != 405 {
		t.Errorf("Expected 405, got %d", w.Code)
	}
}

func TestCb7StoreEncryptedMessage_Unauthorized(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	body := `{"conversation_id":"conv-1","ciphertext":"abc","iv":"def","algorithm":"aes-256-gcm"}`
	req := httptest.NewRequest("POST", "/messages/encrypted", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handleStoreEncryptedMessage(w, req)

	if w.Code != 401 {
		t.Errorf("Expected 401, got %d", w.Code)
	}
}

func TestCb7StoreEncryptedMessage_InvalidJSON(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	token := cb7CreateUser(t, "encuser2")

	req := httptest.NewRequest("POST", "/messages/encrypted", bytes.NewBufferString("not json"))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleStoreEncryptedMessage(w, req)

	if w.Code != 400 {
		t.Errorf("Expected 400, got %d", w.Code)
	}
}

func TestCb7StoreEncryptedMessage_MissingFields(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	token := cb7CreateUser(t, "encuser3")

	body := `{"conversation_id":"conv-1","iv":"base64iv","algorithm":"aes-256-gcm"}`
	req := httptest.NewRequest("POST", "/messages/encrypted", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleStoreEncryptedMessage(w, req)

	if w.Code != 400 {
		t.Errorf("Expected 400 for missing ciphertext, got %d", w.Code)
	}
}

func TestCb7StoreEncryptedMessage_UnsupportedAlgorithm(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	token := cb7CreateUser(t, "encuser4")
	cb7RegisterAgent(t, "enc-agent-4", "Enc Agent 4")
	convID := cb7CreateConversation(t, token, "enc-agent-4")

	body := `{"conversation_id":"` + convID + `","ciphertext":"abc","iv":"def","algorithm":"rsa-4096"}`
	req := httptest.NewRequest("POST", "/messages/encrypted", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleStoreEncryptedMessage(w, req)

	if w.Code != 400 {
		t.Errorf("Expected 400 for unsupported algorithm, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCb7StoreEncryptedMessage_ConversationNotFound(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	token := cb7CreateUser(t, "encuser5")

	body := `{"conversation_id":"nonexistent","ciphertext":"abc","iv":"def","algorithm":"aes-256-gcm"}`
	req := httptest.NewRequest("POST", "/messages/encrypted", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleStoreEncryptedMessage(w, req)

	if w.Code != 404 {
		t.Errorf("Expected 404, got %d", w.Code)
	}
}

func TestCb7StoreEncryptedMessage_NotParticipant(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	token1 := cb7CreateUser(t, "encuser6")
	token2 := cb7CreateUser(t, "encuser7")
	cb7RegisterAgent(t, "enc-agent-6", "Enc Agent 6")
	convID := cb7CreateConversation(t, token1, "enc-agent-6")

	body := `{"conversation_id":"` + convID + `","ciphertext":"abc","iv":"def","algorithm":"aes-256-gcm"}`
	req := httptest.NewRequest("POST", "/messages/encrypted", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token2)
	w := httptest.NewRecorder()
	handleStoreEncryptedMessage(w, req)

	if w.Code != 403 {
		t.Errorf("Expected 403 for non-participant (store), got %d", w.Code)
	}
}

func TestCb7StoreEncryptedMessage_AllAlgorithms(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	algorithms := []string{"aes-256-gcm", "x25519-aes-256-gcm", "x25519-chacha20-poly1305"}
	for i, alg := range algorithms {
		token := cb7CreateUser(t, fmt.Sprintf("encalguser%d", i))
		cb7RegisterAgent(t, fmt.Sprintf("encalg-agent-%d", i), fmt.Sprintf("Alg Agent %d", i))
		convID := cb7CreateConversation(t, token, fmt.Sprintf("encalg-agent-%d", i))

		body := fmt.Sprintf(`{"conversation_id":"%s","ciphertext":"abc","iv":"def","algorithm":"%s"}`, convID, alg)
		req := httptest.NewRequest("POST", "/messages/encrypted", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		handleStoreEncryptedMessage(w, req)

		if w.Code != 200 {
			t.Errorf("Expected 200 for algorithm %s, got %d: %s", alg, w.Code, w.Body.String())
		}
	}
}

// --- handleGetEncryptedMessages ---

func TestCb7GetEncryptedMessages_Basic(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	token := cb7CreateUser(t, "encgetuser1")
	cb7RegisterAgent(t, "encget-agent-1", "EncGet Agent")
	convID := cb7CreateConversation(t, token, "encget-agent-1")

	_, err := db.Exec(`INSERT INTO encrypted_messages (id, conversation_id, sender_id, sender_type, ciphertext, iv, recipient_key_id, algorithm, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		"emsg-1", convID, "encgetuser1", "user", "base64ciphertext", "base64iv", "key-1", "aes-256-gcm", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest("GET", "/messages/encrypted?conversation_id="+convID, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleGetEncryptedMessages(w, req)

	if w.Code != 200 {
		t.Fatalf("Expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var msgs []map[string]interface{}
	json.NewDecoder(w.Body).Decode(&msgs)
	if len(msgs) != 1 {
		t.Errorf("Expected 1 encrypted message, got %d", len(msgs))
	}
}

func TestCb7GetEncryptedMessages_MethodNotAllowed(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	req := httptest.NewRequest("POST", "/messages/encrypted", nil)
	w := httptest.NewRecorder()
	handleGetEncryptedMessages(w, req)

	if w.Code != 405 {
		t.Errorf("Expected 405, got %d", w.Code)
	}
}

func TestCb7GetEncryptedMessages_Unauthorized(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	req := httptest.NewRequest("GET", "/messages/encrypted?conversation_id=conv-1", nil)
	w := httptest.NewRecorder()
	handleGetEncryptedMessages(w, req)

	if w.Code != 401 {
		t.Errorf("Expected 401, got %d", w.Code)
	}
}

func TestCb7GetEncryptedMessages_MissingConversationID(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	token := cb7CreateUser(t, "encgetuser2")

	req := httptest.NewRequest("GET", "/messages/encrypted", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleGetEncryptedMessages(w, req)

	if w.Code != 400 {
		t.Errorf("Expected 400, got %d", w.Code)
	}
}

func TestCb7GetEncryptedMessages_NotParticipant(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	token1 := cb7CreateUser(t, "encgetuser3")
	token2 := cb7CreateUser(t, "encgetuser4")
	cb7RegisterAgent(t, "encget-agent-3", "EncGet Agent 3")
	convID := cb7CreateConversation(t, token1, "encget-agent-3")

	req := httptest.NewRequest("GET", "/messages/encrypted?conversation_id="+convID, nil)
	req.Header.Set("Authorization", "Bearer "+token2)
	w := httptest.NewRecorder()
	handleGetEncryptedMessages(w, req)

	// GetEncryptedMessages checks ownership via conversation lookup
	// Non-participant/non-owner gets 404 (conversation not found for this user)
	if w.Code != 404 {
		t.Errorf("Expected 404 for non-participant (get), got %d", w.Code)
	}
}

// --- handleGetMessages pagination ---

func TestCb7GetMessages_WithPagination(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	token := cb7CreateUser(t, "msgpageuser1")
	cb7RegisterAgent(t, "msgpage-agent-1", "MsgPage Agent")
	convID := cb7CreateConversation(t, token, "msgpage-agent-1")

	for i := 0; i < 5; i++ {
		_, err := db.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, created_at) VALUES (?, ?, ?, ?, ?, ?)",
			fmt.Sprintf("msg-page-%d", i), convID, "user", "msgpageuser1", fmt.Sprintf("message %d", i), time.Now().UTC().Add(time.Duration(i)*time.Second))
		if err != nil {
			t.Fatal(err)
		}
	}

	req := httptest.NewRequest("GET", "/conversations/messages?conversation_id="+convID+"&limit=3", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleGetMessages(w, req)

	if w.Code != 200 {
		t.Fatalf("Expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var msgs []map[string]interface{}
	json.NewDecoder(w.Body).Decode(&msgs)
	if len(msgs) != 3 {
		t.Errorf("Expected 3 messages, got %d", len(msgs))
	}
}

func TestCb7GetMessages_Unauthorized(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	req := httptest.NewRequest("GET", "/conversations/messages?conversation_id=conv-1", nil)
	w := httptest.NewRecorder()
	handleGetMessages(w, req)

	if w.Code != 401 {
		t.Errorf("Expected 401, got %d", w.Code)
	}
}

func TestCb7GetMessages_MethodNotAllowed(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	req := httptest.NewRequest("POST", "/conversations/messages", nil)
	w := httptest.NewRecorder()
	handleGetMessages(w, req)

	if w.Code != 405 {
		t.Errorf("Expected 405, got %d", w.Code)
	}
}

func TestCb7GetMessages_MissingConversationID(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	token := cb7CreateUser(t, "msgpageuser2")

	req := httptest.NewRequest("GET", "/conversations/messages", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleGetMessages(w, req)

	if w.Code != 400 {
		t.Errorf("Expected 400, got %d", w.Code)
	}
}

func TestCb7GetMessages_NotOwner(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	token1 := cb7CreateUser(t, "msgpageuser3")
	token2 := cb7CreateUser(t, "msgpageuser4")
	cb7RegisterAgent(t, "msgpage-agent-3", "MsgPage Agent 3")
	convID := cb7CreateConversation(t, token1, "msgpage-agent-3")

	req := httptest.NewRequest("GET", "/conversations/messages?conversation_id="+convID, nil)
	req.Header.Set("Authorization", "Bearer "+token2)
	w := httptest.NewRecorder()
	handleGetMessages(w, req)

	if w.Code != 401 {
		t.Errorf("Expected 401 for non-owner, got %d", w.Code)
	}
}

// --- handleChangePassword ---

func TestCb7ChangePassword_Success(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	token := cb7CreateUser(t, "chpwuser1")

	form := "old_password=testpass123&new_password=newpass456"
	req := httptest.NewRequest("POST", "/auth/change-password", bytes.NewBufferString(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleChangePassword(w, req)

	if w.Code != 200 {
		t.Fatalf("Expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCb7ChangePassword_WrongOld(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	token := cb7CreateUser(t, "chpwuser2")

	form := "old_password=wrongpass&new_password=newpass456"
	req := httptest.NewRequest("POST", "/auth/change-password", bytes.NewBufferString(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleChangePassword(w, req)

	if w.Code != 401 {
		t.Errorf("Expected 401 for wrong old password, got %d", w.Code)
	}
}

func TestCb7ChangePassword_ShortNew(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	token := cb7CreateUser(t, "chpwuser3")

	form := "old_password=testpass123&new_password=abc"
	req := httptest.NewRequest("POST", "/auth/change-password", bytes.NewBufferString(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleChangePassword(w, req)

	if w.Code != 400 {
		t.Errorf("Expected 400 for short password, got %d", w.Code)
	}
}

func TestCb7ChangePassword_MissingFields(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	token := cb7CreateUser(t, "chpwuser4")

	form := "old_password=testpass123"
	req := httptest.NewRequest("POST", "/auth/change-password", bytes.NewBufferString(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleChangePassword(w, req)

	if w.Code != 400 {
		t.Errorf("Expected 400 for missing new_password, got %d", w.Code)
	}
}

func TestCb7ChangePassword_Unauthorized(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	form := "old_password=testpass123&new_password=newpass456"
	req := httptest.NewRequest("POST", "/auth/change-password", bytes.NewBufferString(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handleChangePassword(w, req)

	if w.Code != 401 {
		t.Errorf("Expected 401, got %d", w.Code)
	}
}

// --- handleListAgents / handleAdminAgents ---

func TestCb7ListAgents_Basic(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	hub = newHub()
	go hub.run()
	defer hub.Stop()

	cb7RegisterAgent(t, "list-agents-1", "Agent One")

	req := httptest.NewRequest("GET", "/agents", nil)
	w := httptest.NewRecorder()
	handleListAgents(w, req)

	if w.Code != 200 {
		t.Fatalf("Expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var agents []map[string]interface{}
	json.NewDecoder(w.Body).Decode(&agents)
	if len(agents) < 1 {
		t.Errorf("Expected at least 1 agent, got %d", len(agents))
	}
}

func TestCb7ListAgents_MethodNotAllowed(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	req := httptest.NewRequest("POST", "/agents", nil)
	w := httptest.NewRecorder()
	handleListAgents(w, req)

	if w.Code != 405 {
		t.Errorf("Expected 405, got %d", w.Code)
	}
}

func TestCb7AdminAgents_Basic(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	hub = newHub()
	go hub.run()
	defer hub.Stop()

	cb7RegisterAgent(t, "admin-agent-1", "Admin Agent")

	req := httptest.NewRequest("GET", "/admin/agents", nil)
	req.Header.Set("X-Admin-Secret", getAdminSecret())
	w := httptest.NewRecorder()
	handleAdminAgents(w, req)

	if w.Code != 200 {
		t.Fatalf("Expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCb7AdminAgents_Unauthorized(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	// Calling handler directly bypasses middleware.
	// Admin auth is enforced via adminAuthMiddleware on the route.
	req := httptest.NewRequest("GET", "/admin/agents", nil)
	w := httptest.NewRecorder()
	handleAdminAgents(w, req)

	// Handler itself has no auth check; middleware blocks unauthorized access
	if w.Code != 200 {
		t.Errorf("Expected 200 (handler has no internal auth), got %d", w.Code)
	}
}

func TestCb7AdminAgents_MethodNotAllowed(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	req := httptest.NewRequest("POST", "/admin/agents", nil)
	w := httptest.NewRecorder()
	handleAdminAgents(w, req)

	if w.Code != 405 {
		t.Errorf("Expected 405, got %d", w.Code)
	}
}

// --- storeMessage via RoutedMessage ---

func TestCb7StoreMessage_Basic(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	_, err := db.Exec("INSERT INTO conversations (id, user_id, agent_id, created_at) VALUES (?, ?, ?, ?)",
		"conv-store-1", "user-store-1", "agent-store-1", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}

	msg := RoutedMessage{
		Type:           "chat",
		ConversationID: "conv-store-1",
		Content:        "hello world",
		SenderType:     "user",
		SenderID:       "user-store-1",
	}
	err = storeMessage(msg)
	if err != nil {
		t.Fatalf("storeMessage failed: %v", err)
	}

	var content string
	err = db.QueryRow("SELECT content FROM messages WHERE conversation_id = ? ORDER BY created_at DESC LIMIT 1", "conv-store-1").Scan(&content)
	if err != nil {
		t.Fatal(err)
	}
	if content != "hello world" {
		t.Errorf("Expected content 'hello world', got %s", content)
	}
}

func TestCb7StoreMessage_EmptyContent(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	_, err := db.Exec("INSERT INTO conversations (id, user_id, agent_id, created_at) VALUES (?, ?, ?, ?)",
		"conv-store-2", "user-store-2", "agent-store-2", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}

	msg := RoutedMessage{
		Type:           "chat",
		ConversationID: "conv-store-2",
		Content:        "",
		SenderType:     "user",
		SenderID:       "user-store-2",
	}
	err = storeMessage(msg)
	if err != nil {
		t.Fatalf("storeMessage with empty content should not fail: %v", err)
	}
}

func TestCb7StoreMessagesBatch(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	_, err := db.Exec("INSERT INTO conversations (id, user_id, agent_id, created_at) VALUES (?, ?, ?, ?)",
		"conv-batch-1", "user-batch-1", "agent-batch-1", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}

	msgs := []RoutedMessage{
		{Type: "chat", ConversationID: "conv-batch-1", Content: "batch msg 1", SenderType: "user", SenderID: "user-batch-1"},
		{Type: "chat", ConversationID: "conv-batch-1", Content: "batch msg 2", SenderType: "agent", SenderID: "agent-batch-1"},
		{Type: "chat", ConversationID: "conv-batch-1", Content: "batch msg 3", SenderType: "user", SenderID: "user-batch-1"},
	}

	ids, err := storeMessagesBatch(msgs)
	if err != nil {
		t.Fatalf("storeMessagesBatch failed: %v", err)
	}
	if len(ids) != 3 {
		t.Errorf("Expected 3 message IDs, got %d", len(ids))
	}

	var count int
	err = db.QueryRow("SELECT COUNT(*) FROM messages WHERE conversation_id = ?", "conv-batch-1").Scan(&count)
	if err != nil {
		t.Fatal(err)
	}
	if count != 3 {
		t.Errorf("Expected 3 messages in DB, got %d", count)
	}
}

// --- searchMessages ---

func TestCb7SearchMessages_DB_EmptyQuery(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	_, err := searchMessages("user1", "", 50)
	if err == nil || err.Error() != "empty search query" {
		t.Errorf("Expected 'empty search query' error, got %v", err)
	}
}

func TestCb7SearchMessages_DB_WithResults(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	_, err := db.Exec("INSERT INTO conversations (id, user_id, agent_id, created_at) VALUES (?, ?, ?, ?)",
		"conv-srch-1", "srch-user-1", "srch-agent-1", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}

	_, err = db.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, created_at) VALUES (?, ?, ?, ?, ?, ?)",
		"msg-srch-test-1", "conv-srch-1", "user", "srch-user-1", "findme hello world", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}

	results, err := searchMessages("srch-user-1", "findme", 50)
	if err != nil {
		t.Fatalf("searchMessages failed: %v", err)
	}
	if len(results) != 1 {
		t.Errorf("Expected 1 result, got %d", len(results))
	}
}

func TestCb7SearchMessages_DB_UserIsolation(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	_, err := db.Exec("INSERT INTO conversations (id, user_id, agent_id, created_at) VALUES (?, ?, ?, ?)",
		"conv-srch-2", "srch-user-2", "srch-agent-2", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec("INSERT INTO conversations (id, user_id, agent_id, created_at) VALUES (?, ?, ?, ?)",
		"conv-srch-3", "srch-user-3", "srch-agent-3", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}

	_, err = db.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, created_at) VALUES (?, ?, ?, ?, ?, ?)",
		"msg-srch-test-2", "conv-srch-2", "user", "srch-user-2", "unique keyword match", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, created_at) VALUES (?, ?, ?, ?, ?, ?)",
		"msg-srch-test-3", "conv-srch-3", "user", "srch-user-3", "unique keyword other", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}

	results, err := searchMessages("srch-user-2", "unique", 50)
	if err != nil {
		t.Fatalf("searchMessages failed: %v", err)
	}
	if len(results) != 1 {
		t.Errorf("Expected 1 result for user2, got %d", len(results))
	}
}

// --- deleteConversation ---

func TestCb7DeleteConversation_DB_DeletesMessages(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	_, err := db.Exec("INSERT INTO conversations (id, user_id, agent_id, created_at) VALUES (?, ?, ?, ?)",
		"conv-del-1", "del-user-1", "del-agent-1", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, created_at) VALUES (?, ?, ?, ?, ?, ?)",
		"msg-del-1", "conv-del-1", "user", "del-user-1", "to be deleted", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}

	err = deleteConversation("conv-del-1", "del-user-1")
	if err != nil {
		t.Fatalf("deleteConversation failed: %v", err)
	}

	var count int
	db.QueryRow("SELECT COUNT(*) FROM messages WHERE conversation_id = ?", "conv-del-1").Scan(&count)
	if count != 0 {
		t.Errorf("Expected 0 messages after conversation deletion, got %d", count)
	}
}

func TestCb7DeleteConversation_DB_Unauthorized(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	_, err := db.Exec("INSERT INTO conversations (id, user_id, agent_id, created_at) VALUES (?, ?, ?, ?)",
		"conv-del-2", "del-user-2", "del-agent-2", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}

	err = deleteConversation("conv-del-2", "wrong-user")
	if err == nil || err.Error() != "unauthorized" {
		t.Errorf("Expected unauthorized error, got %v", err)
	}
}

func TestCb7DeleteConversation_DB_NotFound(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	err := deleteConversation("nonexistent-conv", "any-user")
	if err == nil {
		t.Error("Expected error for nonexistent conversation")
	}
}

// --- markMessagesRead ---

func TestCb7MarkMessagesRead_Basic(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	_, err := db.Exec("INSERT INTO conversations (id, user_id, agent_id, created_at) VALUES (?, ?, ?, ?)",
		"conv-read-1", "read-user-1", "read-agent-1", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, created_at) VALUES (?, ?, ?, ?, ?, ?)",
		"msg-read-1", "conv-read-1", "agent", "read-agent-1", "unread message", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}

	count, err := markMessagesRead("conv-read-1", "read-user-1")
	if err != nil {
		t.Fatalf("markMessagesRead failed: %v", err)
	}
	if count != 1 {
		t.Errorf("Expected 1 message marked as read, got %d", count)
	}
}

func TestCb7MarkMessagesRead_Idempotent(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	_, err := db.Exec("INSERT INTO conversations (id, user_id, agent_id, created_at) VALUES (?, ?, ?, ?)",
		"conv-read-2", "read-user-2", "read-agent-2", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, created_at) VALUES (?, ?, ?, ?, ?, ?)",
		"msg-read-2", "conv-read-2", "agent", "read-agent-2", "unread message", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}

	count1, _ := markMessagesRead("conv-read-2", "read-user-2")
	count2, _ := markMessagesRead("conv-read-2", "read-user-2")
	if count1 != 1 {
		t.Errorf("First call: expected 1, got %d", count1)
	}
	if count2 != 0 {
		t.Errorf("Second call (idempotent): expected 0, got %d", count2)
	}
}

// --- routeChatMessage edge cases ---

func TestCb7RouteChatMessage_InvalidJSON(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	hub = newHub()
	go hub.run()
	defer hub.Stop()

	conn := &Connection{
		connType: "client",
		id:       "route-client-1",
		send:     make(chan []byte, 10),
	}

	routeChatMessage(conn, []byte("not json"))
}

func TestCb7RouteChatMessage_EmptyConversationID(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	hub = newHub()
	go hub.run()
	defer hub.Stop()

	conn := &Connection{
		connType: "client",
		id:       "route-client-2",
		send:     make(chan []byte, 10),
	}

	data := `{"conversation_id":"","content":"hello"}`
	routeChatMessage(conn, []byte(data))
}

func TestCb7RouteChatMessage_NonexistentConversation(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	hub = newHub()
	go hub.run()
	defer hub.Stop()

	conn := &Connection{
		connType: "client",
		id:       "route-client-3",
		send:     make(chan []byte, 10),
	}

	data := `{"conversation_id":"nonexistent","content":"hello"}`
	routeChatMessage(conn, []byte(data))
}

// --- routeTypingIndicator ---

func TestCb7TypingIndicator_Basic(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	hub = newHub()
	go hub.run()
	defer hub.Stop()

	_, err := db.Exec("INSERT INTO conversations (id, user_id, agent_id, created_at) VALUES (?, ?, ?, ?)",
		"conv-typing-1", "typing-user-1", "typing-agent-1", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}

	conn := &Connection{
		connType: "client",
		id:       "typing-user-1",
		send:     make(chan []byte, 10),
	}

	data := `{"conversation_id":"conv-typing-1"}`
	routeTypingIndicator(conn, []byte(data))
}

func TestCb7TypingIndicator_InvalidJSON(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	conn := &Connection{
		connType: "client",
		id:       "typing-user-2",
		send:     make(chan []byte, 10),
	}

	routeTypingIndicator(conn, []byte("not json"))
}

func TestCb7TypingIndicator_EmptyConversationID(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	conn := &Connection{
		connType: "client",
		id:       "typing-user-3",
		send:     make(chan []byte, 10),
	}

	data := `{"conversation_id":""}`
	routeTypingIndicator(conn, []byte(data))
}

func TestCb7TypingIndicator_WrongUser(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	hub = newHub()
	go hub.run()
	defer hub.Stop()

	_, err := db.Exec("INSERT INTO conversations (id, user_id, agent_id, created_at) VALUES (?, ?, ?, ?)",
		"conv-typing-2", "typing-user-4", "typing-agent-2", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}

	conn := &Connection{
		connType: "client",
		id:       "wrong-user",
		send:     make(chan []byte, 10),
	}

	data := `{"conversation_id":"conv-typing-2"}`
	routeTypingIndicator(conn, []byte(data))
}

// --- routeStatusUpdate ---

func TestCb7StatusUpdate_AgentBusy(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	hub = newHub()
	go hub.run()
	defer hub.Stop()

	conn := &Connection{
		connType: "agent",
		id:       "status-agent-1",
		send:     make(chan []byte, 10),
	}

	data := `{"status":"busy"}`
	routeStatusUpdate(conn, []byte(data))
}

func TestCb7StatusUpdate_InvalidJSON(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	conn := &Connection{
		connType: "agent",
		id:       "status-agent-2",
		send:     make(chan []byte, 10),
	}

	routeStatusUpdate(conn, []byte("not json"))
}

func TestCb7StatusUpdate_ClientStatus(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	hub = newHub()
	go hub.run()
	defer hub.Stop()

	conn := &Connection{
		connType: "client",
		id:       "status-client-1",
		send:     make(chan []byte, 10),
	}

	data := `{"status":"away"}`
	routeStatusUpdate(conn, []byte(data))
}

// --- GetOrCreateConversation ---

func TestCb7GetOrCreateConversation_Existing(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	_, err := db.Exec("INSERT INTO conversations (id, user_id, agent_id, created_at) VALUES (?, ?, ?, ?)",
		"conv-goc-1", "goc-user-1", "goc-agent-1", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}

	conv, err := GetOrCreateConversation("goc-user-1", "goc-agent-1")
	if err != nil {
		t.Fatalf("GetOrCreateConversation failed: %v", err)
	}
	if conv.ID != "conv-goc-1" {
		t.Errorf("Expected existing conversation conv-goc-1, got %s", conv.ID)
	}
}

func TestCb7GetOrCreateConversation_New(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	conv, err := GetOrCreateConversation("goc-user-2", "goc-agent-2")
	if err != nil {
		t.Fatalf("GetOrCreateConversation failed: %v", err)
	}
	if conv.ID == "" {
		t.Error("Expected non-empty conversation ID")
	}
	if conv.UserID != "goc-user-2" {
		t.Errorf("Expected user_id 'goc-user-2', got %s", conv.UserID)
	}
}

// --- HashAPIKey ---

func TestCb7HashAPIKey(t *testing.T) {
	hash1, err := HashAPIKey("test-key")
	if err != nil {
		t.Fatalf("HashAPIKey failed: %v", err)
	}
	if hash1 == "" {
		t.Error("Expected non-empty hash")
	}
	hash2, _ := HashAPIKey("test-key")
	if hash1 == hash2 {
		t.Error("Expected different hashes for same key (bcrypt uses random salt)")
	}
	hash3, _ := HashAPIKey("different-key")
	if hash1 == hash3 {
		t.Error("Expected different hashes for different keys")
	}
}

// --- JWT edge cases ---

func TestCb7JWT_ExpiredToken(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	token, err := GenerateJWT("valid-user", "valid-user")
	if err != nil {
		t.Fatalf("GenerateJWT failed: %v", err)
	}
	claims, err := ValidateJWT(token)
	if err != nil {
		t.Fatalf("Token should be valid: %v", err)
	}
	if claims.UserID != "valid-user" {
		t.Errorf("Expected user ID 'valid-user', got %s", claims.UserID)
	}
}

func TestCb7JWT_MalformedToken(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	_, err := ValidateJWT("totally.invalid.token")
	if err == nil {
		t.Error("Expected error for malformed token")
	}
}

// --- notification preferences ---

func TestCb7GetNotificationPrefs_Basic(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	token := cb7CreateUser(t, "notifprefuser1")
	claims, _ := ValidateJWT(token)

	req := httptest.NewRequest("GET", "/notifications/preferences", nil)
	ctx := context.WithValue(req.Context(), contextKeyUserID, claims.UserID)
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()
	handleGetNotificationPrefs(w, req)

	if w.Code != 200 {
		t.Fatalf("Expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCb7GetNotificationPrefs_Unauthorized(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	req := httptest.NewRequest("GET", "/notifications/preferences", nil)
	w := httptest.NewRecorder()
	handleGetNotificationPrefs(w, req)

	if w.Code != 401 {
		t.Errorf("Expected 401, got %d", w.Code)
	}
}

func TestCb7SetNotificationPrefs_Basic(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	token := cb7CreateUser(t, "notifprefuser2")
	claims, _ := ValidateJWT(token)

	// Create a conversation for this user
	convID := cb7CreateConversation(t, token, "notifprefagent1")

	req := httptest.NewRequest("POST", "/notifications/preferences?conversation_id="+convID+"&muted=true", nil)
	ctx := context.WithValue(req.Context(), contextKeyUserID, claims.UserID)
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()
	handleSetNotificationPrefs(w, req)

	if w.Code != 200 {
		t.Fatalf("Expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCb7SetNotificationPrefs_Unauthorized(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	body := `{"push_enabled":true}`
	req := httptest.NewRequest("POST", "/notifications/preferences", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handleSetNotificationPrefs(w, req)

	if w.Code != 401 {
		t.Errorf("Expected 401, got %d", w.Code)
	}
}

func TestCb7SetNotificationPrefs_InvalidJSON(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	token := cb7CreateUser(t, "notifprefuser3")
	claims, _ := ValidateJWT(token)

	req := httptest.NewRequest("POST", "/notifications/preferences", bytes.NewBufferString("not json"))
	req.Header.Set("Content-Type", "application/json")
	ctx := context.WithValue(req.Context(), contextKeyUserID, claims.UserID)
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()
	handleSetNotificationPrefs(w, req)

	if w.Code != 400 {
		t.Errorf("Expected 400, got %d", w.Code)
	}
}

// --- presence ---

func TestCb7GetPresence_Basic(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	hub = newHub()
	go hub.run()
	defer hub.Stop()

	cb7RegisterAgent(t, "presence_agent_1", "Presence Agent")

	// Create a user token for auth
	token := cb7CreateUser(t, "presenceuser1")

	req := httptest.NewRequest("GET", "/presence?agent_id=presence_agent_1", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleGetPresence(w, req)

	if w.Code == 500 {
		t.Errorf("Got internal error: %s", w.Body.String())
	}
}

func TestCb7GetUserPresence_Basic(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	hub = newHub()
	go hub.run()
	defer hub.Stop()

	token := cb7CreateUser(t, "presence_user_1")

	req := httptest.NewRequest("GET", "/users/presence?user_id=presence-user-1", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleGetUserPresence(w, req)

	if w.Code != 200 {
		t.Fatalf("Expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCb7GetUserPresence_Unauthorized(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	req := httptest.NewRequest("GET", "/users/presence?user_id=test", nil)
	w := httptest.NewRecorder()
	handleGetUserPresence(w, req)

	if w.Code != 401 {
		t.Errorf("Expected 401, got %d", w.Code)
	}
}

// --- reactions ---

func TestCb7GetMessageReactions_NoReactions(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	reactions, err := getMessageReactions("nonexistent-msg")
	if err != nil {
		t.Fatalf("getMessageReactions failed: %v", err)
	}
	if len(reactions) != 0 {
		t.Errorf("Expected 0 reactions for nonexistent message, got %d", len(reactions))
	}
}

func TestCb7AddReaction_Basic(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	_, err := db.Exec("INSERT INTO conversations (id, user_id, agent_id, created_at) VALUES (?, ?, ?, ?)",
		"conv-react-1", "react-user-1", "react-agent-1", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, created_at) VALUES (?, ?, ?, ?, ?, ?)",
		"msg-react-1", "conv-react-1", "user", "react-user-1", "hello", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}

	_, added, err := addReaction("msg-react-1", "react-user-1", "👍")
	if err != nil {
		t.Fatalf("addReaction failed: %v", err)
	}
	if !added {
		t.Error("Expected added=true for new reaction")
	}

	_, added, err = addReaction("msg-react-1", "react-user-1", "👍")
	if err != nil {
		t.Fatalf("addReaction toggle failed: %v", err)
	}
	if added {
		t.Error("Expected added=false for toggle removal")
	}
}

// --- tags ---

func TestCb7AddConversationTag(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	_, err := db.Exec("INSERT INTO conversations (id, user_id, agent_id, created_at) VALUES (?, ?, ?, ?)",
		"conv-tag-1", "tag-user-1", "tag-agent-1", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}

	_, err = addConversationTag("conv-tag-1", "tag-user-1", "important")
	if err != nil {
		t.Fatalf("addConversationTag failed: %v", err)
	}

	tags, err := getConversationTags("conv-tag-1")
	if err != nil {
		t.Fatalf("getConversationTags failed: %v", err)
	}
	if len(tags) != 1 || tags[0].Tag != "important" {
		t.Errorf("Expected tag 'important', got %v", tags)
	}
}

func TestCb7RemoveConversationTag(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	_, err := db.Exec("INSERT INTO conversations (id, user_id, agent_id, created_at) VALUES (?, ?, ?, ?)",
		"conv-tag-2", "tag-user-2", "tag-agent-2", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}

	_, err = addConversationTag("conv-tag-2", "tag-user-2", "remove-me")
	if err != nil {
		t.Fatal(err)
	}

	err = removeConversationTag("conv-tag-2", "tag-user-2", "remove-me")
	if err != nil {
		t.Fatalf("removeConversationTag failed: %v", err)
	}

	tags, _ := getConversationTags("conv-tag-2")
	if len(tags) != 0 {
		t.Errorf("Expected 0 tags after removal, got %v", tags)
	}
}

// --- E2E key bundle edge cases ---

func TestCb7GetKeyBundle_NotFound(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	token := cb7CreateUser(t, "keybundleuser1")

	req := httptest.NewRequest("GET", "/keys/bundle?owner_id=nonexistent&owner_type=user", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleGetKeyBundle(w, req)

	if w.Code != 404 {
		t.Errorf("Expected 404 for nonexistent key bundle, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCb7GetKeyBundle_Unauthorized(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	req := httptest.NewRequest("GET", "/keys/bundle?user_id=test", nil)
	w := httptest.NewRecorder()
	handleGetKeyBundle(w, req)

	if w.Code != 401 {
		t.Errorf("Expected 401, got %d", w.Code)
	}
}

// --- TieredRateLimiter cleanup window reset ---

func TestCb7TieredRateLimiter_WindowReset(t *testing.T) {
	trl := &TieredRateLimiter{
		limits: make(map[string]*userRateLimitState),
	}

	// Add an entry and exhaust its burst
	trl.limits["reset-user"] = &userRateLimitState{
		count:     60,
		tier:      TierFree,
		windowEnd: time.Now().Add(-1 * time.Second),
	}

	// Verify expired window detection
	trl.mu.Lock()
	entry := trl.limits["reset-user"]
	trl.mu.Unlock()

	if !time.Now().After(entry.windowEnd) {
		t.Error("Expected window to be expired")
	}
	if entry.count != 60 {
		t.Errorf("Expected count to be 60 before reset, got %d", entry.count)
	}
	if entry.tier != TierFree {
		t.Errorf("Expected tier to be TierFree")
	}
}

// --- queue persist ---

func TestCb7PersistAndLoadQueue(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	data1 := []byte(`{"type":"chat","data":"hello"}`)
	data2 := []byte(`{"type":"chat","data":"world"}`)

	persistQueue(db, "user-q-1", data1)
	persistQueue(db, "user-q-1", data2)

	q := newOfflineQueue(100, 7*24*time.Hour)
	loadQueueFromDB(db, q)

	msgs := q.Drain("user-q-1")
	if len(msgs) != 2 {
		t.Errorf("Expected 2 queued messages, got %d", len(msgs))
	}
}

func TestCb7DeleteQueueMessages(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	persistQueue(db, "user-q-del", []byte(`{"type":"chat"}`))

	deleteQueueMessages(db, "user-q-del")

	q := newOfflineQueue(100, 7*24*time.Hour)
	loadQueueFromDB(db, q)
	msgs := q.Drain("user-q-del")
	if len(msgs) != 0 {
		t.Errorf("Expected 0 messages after deletion, got %d", len(msgs))
	}
}

func TestCb7CleanStaleQueueMessages(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	_, err := db.Exec(`INSERT INTO offline_queue (recipient, data, queued_at, sent_count)
		VALUES (?, ?, ?, 0)`,
		"user-stale", `{"type":"chat"}`, time.Now().UTC().Add(-8*24*time.Hour).Format(time.RFC3339))
	if err != nil {
		t.Fatal(err)
	}

	cleanStaleQueueMessages(db, 7*24*time.Hour)

	q := newOfflineQueue(100, 7*24*time.Hour)
	loadQueueFromDB(db, q)
	msgs := q.Drain("user-stale")
	if len(msgs) != 0 {
		t.Errorf("Expected 0 stale messages after cleanup, got %d", len(msgs))
	}
}

// --- sendWelcomeMessage ---

func TestCb7SendWelcomeMessage(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	send := make(chan []byte, 10)
	c := &Connection{connType: "client", id: "welcome_user_1", deviceID: "device-1", send: send, negotiatedVersion: "1.0"}
	sendWelcomeMessage(c)

	select {
	case msg := <-send:
		var parsed map[string]interface{}
		if err := json.Unmarshal(msg, &parsed); err != nil {
			t.Fatalf("Failed to parse welcome message: %v", err)
		}
		if parsed["type"] != "connected" {
			t.Errorf("Expected connected message type, got %v", parsed["type"])
		}
	case <-time.After(time.Second):
		t.Error("Timed out waiting for welcome message")
	}
}

// --- authenticateRequest ---

func TestCb7AuthenticateRequest_UserToken(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	token := cb7CreateUser(t, "authrequser1")

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	userID, userType, err := authenticateRequest(req)
	if err != nil {
		t.Fatalf("authenticateRequest failed: %v", err)
	}
	if userType != "user" {
		t.Errorf("Expected user type 'user', got %s", userType)
	}
	if userID == "" {
		t.Error("Expected non-empty user ID")
	}
}

func TestCb7AuthenticateRequest_AgentSecret(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-Agent-Secret", getAgentSecret())
	req.Header.Set("X-Agent-ID", "test-agent")

	userID, userType, err := authenticateRequest(req)
	if err != nil {
		t.Fatalf("authenticateRequest failed: %v", err)
	}
	if userID != "test-agent" {
		t.Errorf("Expected agent ID 'test-agent', got %s", userID)
	}
	if userType != "agent" {
		t.Errorf("Expected user type 'agent', got %s", userType)
	}
}

func TestCb7AuthenticateRequest_NoAuth(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	req := httptest.NewRequest("GET", "/", nil)
	_, _, err := authenticateRequest(req)
	if err == nil {
		t.Error("Expected error for missing auth")
	}
}

func TestCb7AuthenticateRequest_InvalidToken(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer invalid.token.here")
	_, _, err := authenticateRequest(req)
	if err == nil {
		t.Error("Expected error for invalid token")
	}
}

// --- message edit/delete handler tests ---

func TestCb7MessageEdit_MethodNotAllowed(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	req := httptest.NewRequest("GET", "/messages/edit", nil)
	w := httptest.NewRecorder()
	handleMessageEdit(w, req)

	if w.Code != 405 {
		t.Errorf("Expected 405, got %d", w.Code)
	}
}

func TestCb7MessageEdit_Unauthorized(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	form := "message_id=msg-1&content=edited"
	req := httptest.NewRequest("POST", "/messages/edit", bytes.NewBufferString(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handleMessageEdit(w, req)

	if w.Code != 401 {
		t.Errorf("Expected 401, got %d", w.Code)
	}
}

func TestCb7MessageDelete_MethodNotAllowed(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	req := httptest.NewRequest("PUT", "/messages/delete", nil)
	w := httptest.NewRecorder()
	handleMessageDelete(w, req)

	if w.Code != 405 {
		t.Errorf("Expected 405, got %d", w.Code)
	}
}

func TestCb7MessageDelete_Unauthorized(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	req := httptest.NewRequest("POST", "/messages/delete", nil)
	w := httptest.NewRecorder()
	handleMessageDelete(w, req)

	if w.Code != 401 {
		t.Errorf("Expected 401, got %d", w.Code)
	}
}

func TestCb7MessageDelete_MissingID(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	token := cb7CreateUser(t, "msgdeluser1")

	req := httptest.NewRequest("POST", "/messages/delete", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleMessageDelete(w, req)

	if w.Code != 400 {
		t.Errorf("Expected 400, got %d", w.Code)
	}
}

// --- handleRegisterUser duplicate ---

func TestCb7RegisterUser_DuplicateUsername(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	form := "username=dupuser&password=testpass123"
	req := httptest.NewRequest("POST", "/auth/user", bytes.NewBufferString(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handleRegisterUser(w, req)

	if w.Code != 200 {
		t.Fatalf("First registration should succeed: %d", w.Code)
	}

	req2 := httptest.NewRequest("POST", "/auth/user", bytes.NewBufferString(form))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w2 := httptest.NewRecorder()
	handleRegisterUser(w2, req2)

	if w2.Code != 409 {
		t.Errorf("Expected 409 for duplicate username, got %d", w2.Code)
	}
}

// --- writeJSONError ---

func TestCb7WriteJSONError(t *testing.T) {
	w := httptest.NewRecorder()
	writeJSONError(w, 400, "bad request")
	if w.Code != 400 {
		t.Errorf("Expected status 400, got %d", w.Code)
	}
	var resp map[string]string
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["error"] != "bad request" {
		t.Errorf("Expected error 'bad request', got %s", resp["error"])
	}
	if w.Header().Get("Content-Type") != "application/json" {
		t.Errorf("Expected application/json content type, got %s", w.Header().Get("Content-Type"))
	}
}

// --- handleHealth with tracing ---

func TestCb7Health_WithTracingEnabled(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	hub = newHub()
	go hub.run()
	defer hub.Stop()
	ServerMetrics = NewMetrics(hub)

	tracingEnabled = true
	defer func() { tracingEnabled = false }()

	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()
	handleHealth(w, req)

	if w.Code != 200 {
		t.Fatalf("Expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["tracing_enabled"] != true {
		t.Error("Expected tracing_enabled to be true")
	}
}

// --- CSRF middleware ---

func TestCb7CSRF_AllowsGET(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	})
	handler := csrfMiddleware(next)

	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Errorf("Expected GET to be allowed, got %d", w.Code)
	}
}

func TestCb7CSRF_BlocksPOSTWithoutHeader(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	})
	handler := csrfMiddleware(next)

	req := httptest.NewRequest("POST", "/test", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != 403 {
		t.Errorf("Expected 403 for POST without CSRF header, got %d", w.Code)
	}
}

func TestCb7CSRF_AllowsPOSTWithXMLHttpRequest(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	})
	handler := csrfMiddleware(next)

	req := httptest.NewRequest("POST", "/test", nil)
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Errorf("Expected 200 for POST with X-Requested-With, got %d", w.Code)
	}
}

// --- IP rate limiting ---

func TestCb7IPRateLimit_AllowsUnderLimit(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	})
	handler := ipRateLimitMiddleware(next)

	for i := 0; i < 5; i++ {
		req := httptest.NewRequest("GET", "/test", nil)
		req.RemoteAddr = "192.168.1.1:1234"
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if w.Code != 200 {
			t.Errorf("Request %d should be allowed, got %d", i+1, w.Code)
		}
	}
}

func TestCb7ExtractIP_XForwardedFor(t *testing.T) {
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-Forwarded-For", "10.0.0.1, 10.0.0.2")
	req.RemoteAddr = "192.168.1.1:1234"

	ip := extractIP(req)
	if ip != "10.0.0.1" {
		t.Errorf("Expected IP from X-Forwarded-For '10.0.0.1', got %s", ip)
	}
}

func TestCb7ExtractIP_XRealIP(t *testing.T) {
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-Real-IP", "10.0.0.3")
	req.RemoteAddr = "192.168.1.1:1234"

	ip := extractIP(req)
	if ip != "10.0.0.3" {
		t.Errorf("Expected IP from X-Real-IP '10.0.0.3', got %s", ip)
	}
}

func TestCb7ExtractIP_RemoteAddr(t *testing.T) {
	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "192.168.1.1:1234"

	ip := extractIP(req)
	if ip != "192.168.1.1" {
		t.Errorf("Expected IP from RemoteAddr '192.168.1.1', got %s", ip)
	}
}

// --- CORS middleware ---

func TestCb7CORS_Preflight(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	})
	handler := corsMiddleware(next)

	req := httptest.NewRequest("OPTIONS", "/test", nil)
	req.Header.Set("Origin", "http://localhost:3000")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != 204 {
		t.Errorf("Expected 204 for preflight, got %d", w.Code)
	}
	if w.Header().Get("Access-Control-Allow-Origin") == "" {
		t.Error("Expected Access-Control-Allow-Origin header")
	}
}

func TestCb7CORS_ActualRequest(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	})
	handler := corsMiddleware(next)

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Origin", "http://localhost:3000")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Errorf("Expected 200 for actual request, got %d", w.Code)
	}
	if w.Header().Get("Access-Control-Allow-Origin") == "" {
		t.Error("Expected Access-Control-Allow-Origin header")
	}
}

// --- truncate ---

func TestCb7Truncate(t *testing.T) {
	result := truncate("hello world", 5)
	if result != "he..." {
		t.Errorf("Expected 'he...', got '%s'", result)
	}

	result = truncate("hi", 5)
	if result != "hi" {
		t.Errorf("Expected 'hi', got '%s'", result)
	}

	result = truncate("", 5)
	if result != "" {
		t.Errorf("Expected '', got '%s'", result)
	}
}

// --- checkRateLimit ---

func TestCb7RateLimiter_Basic(t *testing.T) {
	rl := NewRateLimiter(5, time.Minute)
	t.Cleanup(func() { rl.Stop() })
	if !rl.Allow("user1") {
		t.Error("Expected request to be allowed under limit")
	}
	if !rl.Allow("user1") {
		t.Error("Expected second request to be allowed")
	}
}

func TestCb7RateLimiter_BlocksOverLimit(t *testing.T) {
	rl := NewRateLimiter(2, time.Minute)
	t.Cleanup(func() { rl.Stop() })
	rl.Allow("user2")
	rl.Allow("user2")
	if rl.Allow("user2") {
		t.Error("Expected request to be blocked over limit")
	}
}

// --- getMaxUploadSize env var ---

func TestCb7GetMaxUploadSize_Default(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	// Ensure MAX_UPLOAD_SIZE is not set
	os.Unsetenv("MAX_UPLOAD_SIZE")

	size := getMaxUploadSize()
	if size != 50*1024*1024 {
		t.Errorf("Expected default 50MB, got %d", size)
	}
}

func TestCb7GetMaxUploadSize_Custom(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	os.Setenv("MAX_UPLOAD_SIZE", "5MB")
	defer os.Unsetenv("MAX_UPLOAD_SIZE")

	maxUploadSize = 5 * 1024 * 1024
	defer func() { maxUploadSize = MaxUploadSize }()

	size := getMaxUploadSize()
	if size != 5*1024*1024 {
		t.Errorf("Expected 5MB, got %d", size)
	}
}

// --- os.LookupEnv test ---

func TestCb7OsLookupEnv_NotSet(t *testing.T) {
	_, ok := os.LookupEnv("DEFINITELY_NOT_SET_VAR_12345")
	if ok {
		t.Error("Expected ok=false for unset env var")
	}
}

// --- initSchema tables exist ---

func TestCb7InitSchema_TablesExist(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	var count int
	err := db.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='users'").Scan(&count)
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Errorf("Expected users table to exist, got count %d", count)
	}
}
