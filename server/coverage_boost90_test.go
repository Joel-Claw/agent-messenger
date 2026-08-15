package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
	_ "github.com/mattn/go-sqlite3"
)

// ============================================================
// CB90: Coverage boost targeting remaining low-coverage functions
// Focus: handleRegisterUser (65.5%), handleGetMessages (64.7%),
// handleSearchMessages (62.5%), handleMarkRead (55.6%),
// handleChangePassword (50%), handleCreateConversation,
// handleListConversations, handleListAgents, handleAdminAgents,
// handleDeleteConversation, handleGetNotificationPrefs,
// handleDeleteNotificationPrefs, openDatabase (52.2%),
// handleSetNotificationPrefs (88.9%), checkRateLimit (89.5%),
// loadQueueFromDB (89.5%), storeMessagesBatch (88.9%),
// monitorAgentHeartbeats (88.9%), initFCM (88.9%),
// readPump (86.4%), notifyUser (86.7%), handleUpload (85.7%),
// initSchema (85.3%), initAPNs (84%)
// ============================================================

// --- Helpers ---

func withTestDB_CB90(t *testing.T, fn func(testDB *sql.DB)) {
	t.Helper()
	oldDB := db
	oldDriver := currentDriver
	currentDriver = DriverSQLite
	defer func() { db = oldDB; currentDriver = oldDriver }()
	testDB, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("Failed to open test DB: %v", err)
	}
	defer testDB.Close()
	if err := initSchema(testDB); err != nil {
		t.Fatalf("Failed to init schema: %v", err)
	}
	db = testDB
	fn(testDB)
}

func makeJWT_CB90(userID, username string) string {
	token, err := GenerateJWT(userID, username)
	if err != nil {
		panic("failed to generate JWT: " + err.Error())
	}
	return token
}

func setupHub_CB90() *Hub {
	oldHub := hub
	h := newHub()
	hub = h
	go h.run()
	// Restore in cleanup by caller
	_ = oldHub
	return h
}

func teardownHub_CB90(h *Hub) {
	h.Stop()
}

func setupUserAndConv_CB90(t *testing.T, testDB *sql.DB) (string, string, string) {
	t.Helper()
	userID := "cb90-user1"
	agentID := "cb90-agent1"
	convID := "cb90-conv1"

	hash, _ := bcrypt.GenerateFromPassword([]byte("testpass"), bcrypt.DefaultCost)
	_, err := testDB.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)",
		userID, "cb90testuser", string(hash))
	if err != nil {
		t.Fatalf("Failed to insert user: %v", err)
	}

	_, err = testDB.Exec("INSERT INTO agents (id, name, model, personality, specialty) VALUES (?, ?, ?, ?, ?)",
		agentID, "TestAgent", "gpt-4", "friendly", "general")
	if err != nil {
		t.Fatalf("Failed to insert agent: %v", err)
	}

	_, err = testDB.Exec("INSERT INTO conversations (id, user_id, agent_id) VALUES (?, ?, ?)",
		convID, userID, agentID)
	if err != nil {
		t.Fatalf("Failed to insert conversation: %v", err)
	}

	return userID, agentID, convID
}

func insertMessage_CB90(testDB *sql.DB, id, convID, senderType, senderID, content string) {
	_, err := testDB.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, created_at) VALUES (?, ?, ?, ?, ?, ?)",
		id, convID, senderType, senderID, content, time.Now().UTC().Format(time.RFC3339))
	if err != nil {
		panic(fmt.Sprintf("Failed to insert message: %v", err))
	}
}

// ============================================================
// handleRegisterUser tests
// ============================================================

func TestCB90_HandleRegisterUser_MethodNotAllowed(t *testing.T) {
	withTestDB_CB90(t, func(testDB *sql.DB) {
		req := httptest.NewRequest(http.MethodGet, "/auth/register", nil)
		w := httptest.NewRecorder()
		handleRegisterUser(w, req)
		if w.Code != http.StatusMethodNotAllowed {
			t.Errorf("expected 405, got %d", w.Code)
		}
	})
}

func TestCB90_HandleRegisterUser_MissingFields(t *testing.T) {
	withTestDB_CB90(t, func(testDB *sql.DB) {
		req := httptest.NewRequest(http.MethodPost, "/auth/register", strings.NewReader(""))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		handleRegisterUser(w, req)
		if w.Code != http.StatusBadRequest {
			t.Errorf("expected 400, got %d", w.Code)
		}
	})
}

func TestCB90_HandleRegisterUser_ShortUsername(t *testing.T) {
	withTestDB_CB90(t, func(testDB *sql.DB) {
		form := "username=ab&password=test123"
		req := httptest.NewRequest(http.MethodPost, "/auth/register", strings.NewReader(form))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		handleRegisterUser(w, req)
		if w.Code != http.StatusBadRequest {
			t.Errorf("expected 400 for short username, got %d", w.Code)
		}
	})
}

func TestCB90_HandleRegisterUser_LongUsername(t *testing.T) {
	withTestDB_CB90(t, func(testDB *sql.DB) {
		longName := strings.Repeat("a", 51)
		form := "username=" + longName + "&password=test123"
		req := httptest.NewRequest(http.MethodPost, "/auth/register", strings.NewReader(form))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		handleRegisterUser(w, req)
		if w.Code != http.StatusBadRequest {
			t.Errorf("expected 400 for long username, got %d", w.Code)
		}
	})
}

func TestCB90_HandleRegisterUser_InvalidChars(t *testing.T) {
	withTestDB_CB90(t, func(testDB *sql.DB) {
		form := "username=test@user&password=test123"
		req := httptest.NewRequest(http.MethodPost, "/auth/register", strings.NewReader(form))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		handleRegisterUser(w, req)
		if w.Code != http.StatusBadRequest {
			t.Errorf("expected 400 for invalid chars, got %d", w.Code)
		}
	})
}

func TestCB90_HandleRegisterUser_DuplicateUsername(t *testing.T) {
	withTestDB_CB90(t, func(testDB *sql.DB) {
		// First registration
		form := "username=cb90dup&password=test123"
		req := httptest.NewRequest(http.MethodPost, "/auth/register", strings.NewReader(form))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		handleRegisterUser(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("first registration failed: %d", w.Code)
		}
		// Duplicate
		req2 := httptest.NewRequest(http.MethodPost, "/auth/register", strings.NewReader(form))
		req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w2 := httptest.NewRecorder()
		handleRegisterUser(w2, req2)
		if w2.Code != http.StatusConflict {
			t.Errorf("expected 409 for duplicate, got %d", w2.Code)
		}
	})
}

func TestCB90_HandleRegisterUser_Success(t *testing.T) {
	withTestDB_CB90(t, func(testDB *sql.DB) {
		form := "username=cb90new&password=test123"
		req := httptest.NewRequest(http.MethodPost, "/auth/register", strings.NewReader(form))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		handleRegisterUser(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", w.Code)
		}
		var resp map[string]string
		json.NewDecoder(w.Body).Decode(&resp)
		if resp["status"] != "registered" {
			t.Errorf("expected status=registered, got %s", resp["status"])
		}
		if resp["username"] != "cb90new" {
			t.Errorf("expected username=cb90new, got %s", resp["username"])
		}
		if resp["user_id"] == "" {
			t.Error("expected non-empty user_id")
		}
	})
}

func TestCB90_HandleRegisterUser_MinLengthUsername(t *testing.T) {
	withTestDB_CB90(t, func(testDB *sql.DB) {
		form := "username=abc&password=test123"
		req := httptest.NewRequest(http.MethodPost, "/auth/register", strings.NewReader(form))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		handleRegisterUser(w, req)
		if w.Code != http.StatusOK {
			t.Errorf("expected 200 for min length username, got %d", w.Code)
		}
	})
}

func TestCB90_HandleRegisterUser_MaxLengthUsername(t *testing.T) {
	withTestDB_CB90(t, func(testDB *sql.DB) {
		name := strings.Repeat("a", 50)
		form := "username=" + name + "&password=test123"
		req := httptest.NewRequest(http.MethodPost, "/auth/register", strings.NewReader(form))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		handleRegisterUser(w, req)
		if w.Code != http.StatusOK {
			t.Errorf("expected 200 for max length username, got %d", w.Code)
		}
	})
}

func TestCB90_HandleRegisterUser_UnderscoreAllowed(t *testing.T) {
	withTestDB_CB90(t, func(testDB *sql.DB) {
		form := "username=cb90_user&password=test123"
		req := httptest.NewRequest(http.MethodPost, "/auth/register", strings.NewReader(form))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		handleRegisterUser(w, req)
		if w.Code != http.StatusOK {
			t.Errorf("expected 200 for underscore username, got %d", w.Code)
		}
	})
}

// ============================================================
// handleChangePassword tests
// ============================================================

func TestCB90_HandleChangePassword_MethodNotAllowed(t *testing.T) {
	withTestDB_CB90(t, func(testDB *sql.DB) {
		req := httptest.NewRequest(http.MethodGet, "/auth/change-password", nil)
		w := httptest.NewRecorder()
		handleChangePassword(w, req)
		if w.Code != http.StatusMethodNotAllowed {
			t.Errorf("expected 405, got %d", w.Code)
		}
	})
}

func TestCB90_HandleChangePassword_NoAuth(t *testing.T) {
	withTestDB_CB90(t, func(testDB *sql.DB) {
		form := "old_password=old&new_password=newpass123"
		req := httptest.NewRequest(http.MethodPost, "/auth/change-password", strings.NewReader(form))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		handleChangePassword(w, req)
		if w.Code != http.StatusUnauthorized {
			t.Errorf("expected 401, got %d", w.Code)
		}
	})
}

func TestCB90_HandleChangePassword_MissingFields(t *testing.T) {
	withTestDB_CB90(t, func(testDB *sql.DB) {
		userID, _, _ := setupUserAndConv_CB90(t, testDB)
		token := makeJWT_CB90(userID, "cb90testuser")
		req := httptest.NewRequest(http.MethodPost, "/auth/change-password", strings.NewReader(""))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		handleChangePassword(w, req)
		if w.Code != http.StatusBadRequest {
			t.Errorf("expected 400, got %d", w.Code)
		}
	})
}

func TestCB90_HandleChangePassword_WrongOldPassword(t *testing.T) {
	withTestDB_CB90(t, func(testDB *sql.DB) {
		userID, _, _ := setupUserAndConv_CB90(t, testDB)
		token := makeJWT_CB90(userID, "cb90testuser")
		form := "old_password=wrongpass&new_password=newpass123"
		req := httptest.NewRequest(http.MethodPost, "/auth/change-password", strings.NewReader(form))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		handleChangePassword(w, req)
		if w.Code != http.StatusUnauthorized {
			t.Errorf("expected 401 for wrong old password, got %d", w.Code)
		}
	})
}

func TestCB90_HandleChangePassword_Success(t *testing.T) {
	withTestDB_CB90(t, func(testDB *sql.DB) {
		userID, _, _ := setupUserAndConv_CB90(t, testDB)
		token := makeJWT_CB90(userID, "cb90testuser")
		form := "old_password=testpass&new_password=newpass123"
		req := httptest.NewRequest(http.MethodPost, "/auth/change-password", strings.NewReader(form))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		handleChangePassword(w, req)
		if w.Code != http.StatusOK {
			t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
		}
		var resp map[string]string
		json.NewDecoder(w.Body).Decode(&resp)
		if resp["status"] != "password_changed" {
			t.Errorf("expected status=password_changed, got %s", resp["status"])
		}
	})
}

func TestCB90_HandleChangePassword_ShortNewPassword(t *testing.T) {
	withTestDB_CB90(t, func(testDB *sql.DB) {
		userID, _, _ := setupUserAndConv_CB90(t, testDB)
		token := makeJWT_CB90(userID, "cb90testuser")
		form := "old_password=testpass&new_password=abc"
		req := httptest.NewRequest(http.MethodPost, "/auth/change-password", strings.NewReader(form))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		handleChangePassword(w, req)
		if w.Code != http.StatusBadRequest {
			t.Errorf("expected 400 for short new password, got %d", w.Code)
		}
	})
}

func TestCB90_HandleChangePassword_InvalidToken(t *testing.T) {
	withTestDB_CB90(t, func(testDB *sql.DB) {
		form := "old_password=old&new_password=newpass123"
		req := httptest.NewRequest(http.MethodPost, "/auth/change-password", strings.NewReader(form))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Authorization", "Bearer invalidtoken")
		w := httptest.NewRecorder()
		handleChangePassword(w, req)
		if w.Code != http.StatusUnauthorized {
			t.Errorf("expected 401 for invalid token, got %d", w.Code)
		}
	})
}

func TestCB90_HandleChangePassword_UserNotFound(t *testing.T) {
	withTestDB_CB90(t, func(testDB *sql.DB) {
		token := makeJWT_CB90("nonexistent-user", "ghost")
		form := "old_password=testpass&new_password=newpass123"
		req := httptest.NewRequest(http.MethodPost, "/auth/change-password", strings.NewReader(form))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		handleChangePassword(w, req)
		if w.Code != http.StatusNotFound {
			t.Errorf("expected 404 for non-existent user, got %d: %s", w.Code, w.Body.String())
		}
	})
}

// ============================================================
// handleGetMessages tests
// ============================================================

func TestCB90_HandleGetMessages_MethodNotAllowed(t *testing.T) {
	withTestDB_CB90(t, func(testDB *sql.DB) {
		req := httptest.NewRequest(http.MethodPost, "/conversations/messages", nil)
		w := httptest.NewRecorder()
		handleGetMessages(w, req)
		if w.Code != http.StatusMethodNotAllowed {
			t.Errorf("expected 405, got %d", w.Code)
		}
	})
}

func TestCB90_HandleGetMessages_NoAuth(t *testing.T) {
	withTestDB_CB90(t, func(testDB *sql.DB) {
		req := httptest.NewRequest(http.MethodGet, "/conversations/messages?conversation_id=conv1", nil)
		w := httptest.NewRecorder()
		handleGetMessages(w, req)
		if w.Code != http.StatusUnauthorized {
			t.Errorf("expected 401, got %d", w.Code)
		}
	})
}

func TestCB90_HandleGetMessages_MissingConvID(t *testing.T) {
	withTestDB_CB90(t, func(testDB *sql.DB) {
		userID, _, _ := setupUserAndConv_CB90(t, testDB)
		token := makeJWT_CB90(userID, "cb90testuser")
		req := httptest.NewRequest(http.MethodGet, "/conversations/messages", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		handleGetMessages(w, req)
		if w.Code != http.StatusBadRequest {
			t.Errorf("expected 400 for missing conv ID, got %d", w.Code)
		}
	})
}

func TestCB90_HandleGetMessages_NotFound(t *testing.T) {
	withTestDB_CB90(t, func(testDB *sql.DB) {
		userID, _, _ := setupUserAndConv_CB90(t, testDB)
		token := makeJWT_CB90(userID, "cb90testuser")
		req := httptest.NewRequest(http.MethodGet, "/conversations/messages?conversation_id=nonexistent", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		handleGetMessages(w, req)
		if w.Code != http.StatusNotFound {
			t.Errorf("expected 404, got %d", w.Code)
		}
	})
}

func TestCB90_HandleGetMessages_Unauthorized(t *testing.T) {
	withTestDB_CB90(t, func(testDB *sql.DB) {
		_, _, convID := setupUserAndConv_CB90(t, testDB)
		// Create a second user
		token2 := makeJWT_CB90("cb90-user2", "cb90other")
		req := httptest.NewRequest(http.MethodGet, "/conversations/messages?conversation_id="+convID, nil)
		req.Header.Set("Authorization", "Bearer "+token2)
		w := httptest.NewRecorder()
		handleGetMessages(w, req)
		if w.Code != http.StatusUnauthorized {
			t.Errorf("expected 401 for unauthorized user, got %d", w.Code)
		}
	})
}

func TestCB90_HandleGetMessages_Success(t *testing.T) {
	withTestDB_CB90(t, func(testDB *sql.DB) {
		userID, _, convID := setupUserAndConv_CB90(t, testDB)
		insertMessage_CB90(testDB, "msg1", convID, "agent", "cb90-agent1", "Hello")
		insertMessage_CB90(testDB, "msg2", convID, "client", userID, "Hi back")
		token := makeJWT_CB90(userID, "cb90testuser")
		req := httptest.NewRequest(http.MethodGet, "/conversations/messages?conversation_id="+convID, nil)
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		handleGetMessages(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", w.Code)
		}
		var msgs []map[string]interface{}
		json.NewDecoder(w.Body).Decode(&msgs)
		if len(msgs) != 2 {
			t.Errorf("expected 2 messages, got %d", len(msgs))
		}
	})
}

func TestCB90_HandleGetMessages_EmptyResult(t *testing.T) {
	withTestDB_CB90(t, func(testDB *sql.DB) {
		userID, _, convID := setupUserAndConv_CB90(t, testDB)
		token := makeJWT_CB90(userID, "cb90testuser")
		req := httptest.NewRequest(http.MethodGet, "/conversations/messages?conversation_id="+convID, nil)
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		handleGetMessages(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", w.Code)
		}
		var msgs []map[string]interface{}
		json.NewDecoder(w.Body).Decode(&msgs)
		if len(msgs) != 0 {
			t.Errorf("expected 0 messages, got %d", len(msgs))
		}
	})
}

func TestCB90_HandleGetMessages_WithLimit(t *testing.T) {
	withTestDB_CB90(t, func(testDB *sql.DB) {
		userID, _, convID := setupUserAndConv_CB90(t, testDB)
		for i := 0; i < 5; i++ {
			insertMessage_CB90(testDB, fmt.Sprintf("msg%d", i), convID, "client", userID, fmt.Sprintf("msg %d", i))
		}
		token := makeJWT_CB90(userID, "cb90testuser")
		req := httptest.NewRequest(http.MethodGet, "/conversations/messages?conversation_id="+convID+"&limit=2", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		handleGetMessages(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", w.Code)
		}
		var msgs []map[string]interface{}
		json.NewDecoder(w.Body).Decode(&msgs)
		if len(msgs) != 2 {
			t.Errorf("expected 2 messages with limit, got %d", len(msgs))
		}
	})
}

func TestCB90_HandleGetMessages_InvalidLimit(t *testing.T) {
	withTestDB_CB90(t, func(testDB *sql.DB) {
		userID, _, convID := setupUserAndConv_CB90(t, testDB)
		insertMessage_CB90(testDB, "msg1", convID, "agent", "cb90-agent1", "Hello")
		token := makeJWT_CB90(userID, "cb90testuser")
		req := httptest.NewRequest(http.MethodGet, "/conversations/messages?conversation_id="+convID+"&limit=abc", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		handleGetMessages(w, req)
		if w.Code != http.StatusOK {
			t.Errorf("expected 200 with invalid limit (defaults to 50), got %d", w.Code)
		}
	})
}

func TestCB90_HandleGetMessages_OverMaxLimit(t *testing.T) {
	withTestDB_CB90(t, func(testDB *sql.DB) {
		userID, _, convID := setupUserAndConv_CB90(t, testDB)
		insertMessage_CB90(testDB, "msg1", convID, "agent", "cb90-agent1", "Hello")
		token := makeJWT_CB90(userID, "cb90testuser")
		req := httptest.NewRequest(http.MethodGet, "/conversations/messages?conversation_id="+convID+"&limit=500", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		handleGetMessages(w, req)
		if w.Code != http.StatusOK {
			t.Errorf("expected 200 with over-max limit (capped at 200), got %d", w.Code)
		}
	})
}

func TestCB90_HandleGetMessages_WithBefore(t *testing.T) {
	withTestDB_CB90(t, func(testDB *sql.DB) {
		userID, _, convID := setupUserAndConv_CB90(t, testDB)
		// Insert messages with different timestamps
		_, err := testDB.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, created_at) VALUES (?, ?, ?, ?, ?, ?)",
			"msg1", convID, "agent", "cb90-agent1", "First", "2026-01-01T00:00:00Z")
		if err != nil {
			t.Fatal(err)
		}
		_, err = testDB.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, created_at) VALUES (?, ?, ?, ?, ?, ?)",
			"msg2", convID, "agent", "cb90-agent1", "Second", "2026-01-02T00:00:00Z")
		if err != nil {
			t.Fatal(err)
		}
		token := makeJWT_CB90(userID, "cb90testuser")
		req := httptest.NewRequest(http.MethodGet, "/conversations/messages?conversation_id="+convID+"&before=msg2", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		handleGetMessages(w, req)
		if w.Code != http.StatusOK {
			t.Errorf("expected 200, got %d", w.Code)
		}
	})
}

// ============================================================
// handleSearchMessages tests
// ============================================================

func TestCB90_HandleSearchMessages_MethodNotAllowed(t *testing.T) {
	withTestDB_CB90(t, func(testDB *sql.DB) {
		req := httptest.NewRequest(http.MethodPost, "/messages/search", nil)
		w := httptest.NewRecorder()
		handleSearchMessages(w, req)
		if w.Code != http.StatusMethodNotAllowed {
			t.Errorf("expected 405, got %d", w.Code)
		}
	})
}

func TestCB90_HandleSearchMessages_NoAuth(t *testing.T) {
	withTestDB_CB90(t, func(testDB *sql.DB) {
		req := httptest.NewRequest(http.MethodGet, "/messages/search?q=hello", nil)
		w := httptest.NewRecorder()
		handleSearchMessages(w, req)
		if w.Code != http.StatusUnauthorized {
			t.Errorf("expected 401, got %d", w.Code)
		}
	})
}

func TestCB90_HandleSearchMessages_MissingQuery(t *testing.T) {
	withTestDB_CB90(t, func(testDB *sql.DB) {
		userID, _, _ := setupUserAndConv_CB90(t, testDB)
		token := makeJWT_CB90(userID, "cb90testuser")
		req := httptest.NewRequest(http.MethodGet, "/messages/search", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		handleSearchMessages(w, req)
		if w.Code != http.StatusBadRequest {
			t.Errorf("expected 400 for missing query, got %d", w.Code)
		}
	})
}

func TestCB90_HandleSearchMessages_Success(t *testing.T) {
	withTestDB_CB90(t, func(testDB *sql.DB) {
		userID, _, convID := setupUserAndConv_CB90(t, testDB)
		insertMessage_CB90(testDB, "msg1", convID, "agent", "cb90-agent1", "hello world")
		insertMessage_CB90(testDB, "msg2", convID, "client", userID, "goodbye world")
		token := makeJWT_CB90(userID, "cb90testuser")
		req := httptest.NewRequest(http.MethodGet, "/messages/search?q=hello", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		handleSearchMessages(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", w.Code)
		}
		var msgs []map[string]interface{}
		json.NewDecoder(w.Body).Decode(&msgs)
		if len(msgs) != 1 {
			t.Errorf("expected 1 result, got %d", len(msgs))
		}
	})
}

func TestCB90_HandleSearchMessages_NoResults(t *testing.T) {
	withTestDB_CB90(t, func(testDB *sql.DB) {
		userID, _, _ := setupUserAndConv_CB90(t, testDB)
		token := makeJWT_CB90(userID, "cb90testuser")
		req := httptest.NewRequest(http.MethodGet, "/messages/search?q=nonexistentterm", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		handleSearchMessages(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", w.Code)
		}
		var msgs []map[string]interface{}
		json.NewDecoder(w.Body).Decode(&msgs)
		if len(msgs) != 0 {
			t.Errorf("expected 0 results, got %d", len(msgs))
		}
	})
}

func TestCB90_HandleSearchMessages_WithLimit(t *testing.T) {
	withTestDB_CB90(t, func(testDB *sql.DB) {
		userID, _, convID := setupUserAndConv_CB90(t, testDB)
		for i := 0; i < 5; i++ {
			insertMessage_CB90(testDB, fmt.Sprintf("msg%d", i), convID, "client", userID, fmt.Sprintf("searchterm %d", i))
		}
		token := makeJWT_CB90(userID, "cb90testuser")
		req := httptest.NewRequest(http.MethodGet, "/messages/search?q=searchterm&limit=2", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		handleSearchMessages(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", w.Code)
		}
		var msgs []map[string]interface{}
		json.NewDecoder(w.Body).Decode(&msgs)
		if len(msgs) != 2 {
			t.Errorf("expected 2 results with limit, got %d", len(msgs))
		}
	})
}

func TestCB90_HandleSearchMessages_OverMaxLimit(t *testing.T) {
	withTestDB_CB90(t, func(testDB *sql.DB) {
		userID, _, convID := setupUserAndConv_CB90(t, testDB)
		insertMessage_CB90(testDB, "msg1", convID, "client", userID, "searchterm test")
		token := makeJWT_CB90(userID, "cb90testuser")
		req := httptest.NewRequest(http.MethodGet, "/messages/search?q=searchterm&limit=500", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		handleSearchMessages(w, req)
		if w.Code != http.StatusOK {
			t.Errorf("expected 200 with over-max limit (capped at 200), got %d", w.Code)
		}
	})
}

func TestCB90_HandleSearchMessages_InvalidLimit(t *testing.T) {
	withTestDB_CB90(t, func(testDB *sql.DB) {
		userID, _, convID := setupUserAndConv_CB90(t, testDB)
		insertMessage_CB90(testDB, "msg1", convID, "client", userID, "searchterm test")
		token := makeJWT_CB90(userID, "cb90testuser")
		req := httptest.NewRequest(http.MethodGet, "/messages/search?q=searchterm&limit=abc", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		handleSearchMessages(w, req)
		if w.Code != http.StatusOK {
			t.Errorf("expected 200 with invalid limit (defaults to 50), got %d", w.Code)
		}
	})
}

func TestCB90_HandleSearchMessages_InvalidToken(t *testing.T) {
	withTestDB_CB90(t, func(testDB *sql.DB) {
		req := httptest.NewRequest(http.MethodGet, "/messages/search?q=hello", nil)
		req.Header.Set("Authorization", "Bearer invalidtoken")
		w := httptest.NewRecorder()
		handleSearchMessages(w, req)
		if w.Code != http.StatusUnauthorized {
			t.Errorf("expected 401 for invalid token, got %d", w.Code)
		}
	})
}

// ============================================================
// handleMarkRead tests
// ============================================================

func TestCB90_HandleMarkRead_MethodNotAllowed(t *testing.T) {
	withTestDB_CB90(t, func(testDB *sql.DB) {
		req := httptest.NewRequest(http.MethodGet, "/conversations/mark-read", nil)
		w := httptest.NewRecorder()
		handleMarkRead(w, req)
		if w.Code != http.StatusMethodNotAllowed {
			t.Errorf("expected 405, got %d", w.Code)
		}
	})
}

func TestCB90_HandleMarkRead_NoAuth(t *testing.T) {
	withTestDB_CB90(t, func(testDB *sql.DB) {
		form := "conversation_id=conv1"
		req := httptest.NewRequest(http.MethodPost, "/conversations/mark-read", strings.NewReader(form))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		handleMarkRead(w, req)
		if w.Code != http.StatusUnauthorized {
			t.Errorf("expected 401, got %d", w.Code)
		}
	})
}

func TestCB90_HandleMarkRead_MissingConvID(t *testing.T) {
	withTestDB_CB90(t, func(testDB *sql.DB) {
		userID, _, _ := setupUserAndConv_CB90(t, testDB)
		token := makeJWT_CB90(userID, "cb90testuser")
		req := httptest.NewRequest(http.MethodPost, "/conversations/mark-read", strings.NewReader(""))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		handleMarkRead(w, req)
		if w.Code != http.StatusBadRequest {
			t.Errorf("expected 400 for missing conv ID, got %d", w.Code)
		}
	})
}

func TestCB90_HandleMarkRead_NotFound(t *testing.T) {
	withTestDB_CB90(t, func(testDB *sql.DB) {
		userID, _, _ := setupUserAndConv_CB90(t, testDB)
		token := makeJWT_CB90(userID, "cb90testuser")
		form := "conversation_id=nonexistent"
		req := httptest.NewRequest(http.MethodPost, "/conversations/mark-read", strings.NewReader(form))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		handleMarkRead(w, req)
		if w.Code != http.StatusNotFound {
			t.Errorf("expected 404, got %d", w.Code)
		}
	})
}

func TestCB90_HandleMarkRead_Unauthorized(t *testing.T) {
	withTestDB_CB90(t, func(testDB *sql.DB) {
		_, _, convID := setupUserAndConv_CB90(t, testDB)
		token2 := makeJWT_CB90("cb90-user2", "cb90other")
		form := "conversation_id=" + convID
		req := httptest.NewRequest(http.MethodPost, "/conversations/mark-read", strings.NewReader(form))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Authorization", "Bearer "+token2)
		w := httptest.NewRecorder()
		handleMarkRead(w, req)
		if w.Code != http.StatusUnauthorized {
			t.Errorf("expected 401 for unauthorized user, got %d", w.Code)
		}
	})
}

func TestCB90_HandleMarkRead_Success(t *testing.T) {
	withTestDB_CB90(t, func(testDB *sql.DB) {
		h := setupHub_CB90()
		defer teardownHub_CB90(h)
		userID, _, convID := setupUserAndConv_CB90(t, testDB)
		insertMessage_CB90(testDB, "msg1", convID, "agent", "cb90-agent1", "Hello")
		insertMessage_CB90(testDB, "msg2", convID, "agent", "cb90-agent1", "World")
		token := makeJWT_CB90(userID, "cb90testuser")
		form := "conversation_id=" + convID
		req := httptest.NewRequest(http.MethodPost, "/conversations/mark-read", strings.NewReader(form))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		handleMarkRead(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
		}
		var resp map[string]interface{}
		json.NewDecoder(w.Body).Decode(&resp)
		if resp["status"] != "marked_read" {
			t.Errorf("expected status=marked_read, got %v", resp["status"])
		}
	})
}

func TestCB90_HandleMarkRead_Idempotent(t *testing.T) {
	withTestDB_CB90(t, func(testDB *sql.DB) {
		h := setupHub_CB90()
		defer teardownHub_CB90(h)
		userID, _, convID := setupUserAndConv_CB90(t, testDB)
		insertMessage_CB90(testDB, "msg1", convID, "agent", "cb90-agent1", "Hello")
		token := makeJWT_CB90(userID, "cb90testuser")
		form := "conversation_id=" + convID
		// First call
		req1 := httptest.NewRequest(http.MethodPost, "/conversations/mark-read", strings.NewReader(form))
		req1.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req1.Header.Set("Authorization", "Bearer "+token)
		w1 := httptest.NewRecorder()
		handleMarkRead(w1, req1)
		if w1.Code != http.StatusOK {
			t.Fatalf("first call failed: %d", w1.Code)
		}
		// Second call should return count=0
		req2 := httptest.NewRequest(http.MethodPost, "/conversations/mark-read", strings.NewReader(form))
		req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req2.Header.Set("Authorization", "Bearer "+token)
		w2 := httptest.NewRecorder()
		handleMarkRead(w2, req2)
		if w2.Code != http.StatusOK {
			t.Fatalf("second call failed: %d", w2.Code)
		}
		var resp map[string]interface{}
		json.NewDecoder(w2.Body).Decode(&resp)
		count, _ := resp["count"].(float64)
		if count != 0 {
			t.Errorf("expected count=0 on second call, got %v", resp["count"])
		}
	})
}

func TestCB90_HandleMarkRead_InvalidToken(t *testing.T) {
	withTestDB_CB90(t, func(testDB *sql.DB) {
		form := "conversation_id=conv1"
		req := httptest.NewRequest(http.MethodPost, "/conversations/mark-read", strings.NewReader(form))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Authorization", "Bearer badtoken")
		w := httptest.NewRecorder()
		handleMarkRead(w, req)
		if w.Code != http.StatusUnauthorized {
			t.Errorf("expected 401 for invalid token, got %d", w.Code)
		}
	})
}

// ============================================================
// handleCreateConversation tests
// ============================================================

func TestCB90_HandleCreateConversation_MethodNotAllowed(t *testing.T) {
	withTestDB_CB90(t, func(testDB *sql.DB) {
		req := httptest.NewRequest(http.MethodGet, "/conversations/create", nil)
		w := httptest.NewRecorder()
		handleCreateConversation(w, req)
		if w.Code != http.StatusMethodNotAllowed {
			t.Errorf("expected 405, got %d", w.Code)
		}
	})
}

func TestCB90_HandleCreateConversation_NoAuth(t *testing.T) {
	withTestDB_CB90(t, func(testDB *sql.DB) {
		form := "agent_id=agent1"
		req := httptest.NewRequest(http.MethodPost, "/conversations/create", strings.NewReader(form))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		handleCreateConversation(w, req)
		if w.Code != http.StatusUnauthorized {
			t.Errorf("expected 401, got %d", w.Code)
		}
	})
}

func TestCB90_HandleCreateConversation_MissingAgentID(t *testing.T) {
	withTestDB_CB90(t, func(testDB *sql.DB) {
		userID, _, _ := setupUserAndConv_CB90(t, testDB)
		token := makeJWT_CB90(userID, "cb90testuser")
		req := httptest.NewRequest(http.MethodPost, "/conversations/create", strings.NewReader(""))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		handleCreateConversation(w, req)
		if w.Code != http.StatusBadRequest {
			t.Errorf("expected 400 for missing agent_id, got %d", w.Code)
		}
	})
}

func TestCB90_HandleCreateConversation_Success(t *testing.T) {
	withTestDB_CB90(t, func(testDB *sql.DB) {
		userID, agentID, _ := setupUserAndConv_CB90(t, testDB)
		token := makeJWT_CB90(userID, "cb90testuser")
		form := "agent_id=" + agentID
		req := httptest.NewRequest(http.MethodPost, "/conversations/create", strings.NewReader(form))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		handleCreateConversation(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
		}
		var resp map[string]string
		json.NewDecoder(w.Body).Decode(&resp)
		if resp["agent_id"] != agentID {
			t.Errorf("expected agent_id=%s, got %s", agentID, resp["agent_id"])
		}
		if resp["user_id"] != userID {
			t.Errorf("expected user_id=%s, got %s", userID, resp["user_id"])
		}
		if resp["conversation_id"] == "" {
			t.Error("expected non-empty conversation_id")
		}
	})
}

func TestCB90_HandleCreateConversation_InvalidToken(t *testing.T) {
	withTestDB_CB90(t, func(testDB *sql.DB) {
		form := "agent_id=agent1"
		req := httptest.NewRequest(http.MethodPost, "/conversations/create", strings.NewReader(form))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Authorization", "Bearer invalid")
		w := httptest.NewRecorder()
		handleCreateConversation(w, req)
		if w.Code != http.StatusUnauthorized {
			t.Errorf("expected 401, got %d", w.Code)
		}
	})
}

// ============================================================
// handleListConversations tests
// ============================================================

func TestCB90_HandleListConversations_MethodNotAllowed(t *testing.T) {
	withTestDB_CB90(t, func(testDB *sql.DB) {
		req := httptest.NewRequest(http.MethodPost, "/conversations/list", nil)
		w := httptest.NewRecorder()
		handleListConversations(w, req)
		if w.Code != http.StatusMethodNotAllowed {
			t.Errorf("expected 405, got %d", w.Code)
		}
	})
}

func TestCB90_HandleListConversations_NoAuth(t *testing.T) {
	withTestDB_CB90(t, func(testDB *sql.DB) {
		req := httptest.NewRequest(http.MethodGet, "/conversations/list", nil)
		w := httptest.NewRecorder()
		handleListConversations(w, req)
		if w.Code != http.StatusUnauthorized {
			t.Errorf("expected 401, got %d", w.Code)
		}
	})
}

func TestCB90_HandleListConversations_Empty(t *testing.T) {
	withTestDB_CB90(t, func(testDB *sql.DB) {
		// Create user but no conversations
		hash, _ := bcrypt.GenerateFromPassword([]byte("pass"), bcrypt.DefaultCost)
		testDB.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)",
			"cb90-empty-user", "cb90empty", string(hash))
		token := makeJWT_CB90("cb90-empty-user", "cb90empty")
		req := httptest.NewRequest(http.MethodGet, "/conversations/list", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		handleListConversations(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", w.Code)
		}
		var resp []map[string]interface{}
		json.NewDecoder(w.Body).Decode(&resp)
		if len(resp) != 0 {
			t.Errorf("expected 0 conversations, got %d", len(resp))
		}
	})
}

func TestCB90_HandleListConversations_WithData(t *testing.T) {
	withTestDB_CB90(t, func(testDB *sql.DB) {
		userID, agentID, convID := setupUserAndConv_CB90(t, testDB)
		insertMessage_CB90(testDB, "msg1", convID, "agent", agentID, "Hello")
		token := makeJWT_CB90(userID, "cb90testuser")
		req := httptest.NewRequest(http.MethodGet, "/conversations/list", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		handleListConversations(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", w.Code)
		}
		var resp []map[string]interface{}
		json.NewDecoder(w.Body).Decode(&resp)
		if len(resp) != 1 {
			t.Errorf("expected 1 conversation, got %d", len(resp))
		}
	})
}

func TestCB90_HandleListConversations_InvalidToken(t *testing.T) {
	withTestDB_CB90(t, func(testDB *sql.DB) {
		req := httptest.NewRequest(http.MethodGet, "/conversations/list", nil)
		req.Header.Set("Authorization", "Bearer badtoken")
		w := httptest.NewRecorder()
		handleListConversations(w, req)
		if w.Code != http.StatusUnauthorized {
			t.Errorf("expected 401, got %d", w.Code)
		}
	})
}

// ============================================================
// handleListAgents tests
// ============================================================

func TestCB90_HandleListAgents_MethodNotAllowed(t *testing.T) {
	withTestDB_CB90(t, func(testDB *sql.DB) {
		req := httptest.NewRequest(http.MethodPost, "/agents", nil)
		w := httptest.NewRecorder()
		handleListAgents(w, req)
		if w.Code != http.StatusMethodNotAllowed {
			t.Errorf("expected 405, got %d", w.Code)
		}
	})
}

func TestCB90_HandleListAgents_Empty(t *testing.T) {
	withTestDB_CB90(t, func(testDB *sql.DB) {
		req := httptest.NewRequest(http.MethodGet, "/agents", nil)
		w := httptest.NewRecorder()
		handleListAgents(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", w.Code)
		}
		var resp []map[string]interface{}
		json.NewDecoder(w.Body).Decode(&resp)
		if len(resp) != 0 {
			t.Errorf("expected 0 agents, got %d", len(resp))
		}
	})
}

func TestCB90_HandleListAgents_WithData(t *testing.T) {
	withTestDB_CB90(t, func(testDB *sql.DB) {
		_, agentID, _ := setupUserAndConv_CB90(t, testDB)
		req := httptest.NewRequest(http.MethodGet, "/agents", nil)
		w := httptest.NewRecorder()
		handleListAgents(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", w.Code)
		}
		var resp []map[string]interface{}
		json.NewDecoder(w.Body).Decode(&resp)
		if len(resp) != 1 {
			t.Errorf("expected 1 agent, got %d", len(resp))
		}
		if resp[0]["id"] != agentID {
			t.Errorf("expected agent id=%s, got %v", agentID, resp[0]["id"])
		}
	})
}

// ============================================================
// handleAdminAgents tests
// ============================================================

func TestCB90_HandleAdminAgents_MethodNotAllowed(t *testing.T) {
	withTestDB_CB90(t, func(testDB *sql.DB) {
		req := httptest.NewRequest(http.MethodPost, "/admin/agents", nil)
		w := httptest.NewRecorder()
		handleAdminAgents(w, req)
		if w.Code != http.StatusMethodNotAllowed {
			t.Errorf("expected 405, got %d", w.Code)
		}
	})
}

func TestCB90_HandleAdminAgents_WithData(t *testing.T) {
	withTestDB_CB90(t, func(testDB *sql.DB) {
		_, agentID, _ := setupUserAndConv_CB90(t, testDB)
		req := httptest.NewRequest(http.MethodGet, "/admin/agents", nil)
		w := httptest.NewRecorder()
		handleAdminAgents(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", w.Code)
		}
		var resp []map[string]interface{}
		json.NewDecoder(w.Body).Decode(&resp)
		if len(resp) != 1 {
			t.Errorf("expected 1 agent, got %d", len(resp))
		}
		if resp[0]["id"] != agentID {
			t.Errorf("expected agent id=%s, got %v", agentID, resp[0]["id"])
		}
	})
}

func TestCB90_HandleAdminAgents_Empty(t *testing.T) {
	withTestDB_CB90(t, func(testDB *sql.DB) {
		req := httptest.NewRequest(http.MethodGet, "/admin/agents", nil)
		w := httptest.NewRecorder()
		handleAdminAgents(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", w.Code)
		}
		var resp []map[string]interface{}
		json.NewDecoder(w.Body).Decode(&resp)
		if len(resp) != 0 {
			t.Errorf("expected 0 agents, got %d", len(resp))
		}
	})
}

// ============================================================
// handleDeleteConversation tests
// ============================================================

func TestCB90_HandleDeleteConversation_MethodNotAllowed(t *testing.T) {
	withTestDB_CB90(t, func(testDB *sql.DB) {
		req := httptest.NewRequest(http.MethodGet, "/conversations/delete", nil)
		w := httptest.NewRecorder()
		handleDeleteConversation(w, req)
		if w.Code != http.StatusMethodNotAllowed {
			t.Errorf("expected 405, got %d", w.Code)
		}
	})
}

func TestCB90_HandleDeleteConversation_NoAuth(t *testing.T) {
	withTestDB_CB90(t, func(testDB *sql.DB) {
		req := httptest.NewRequest(http.MethodDelete, "/conversations/delete?conversation_id=conv1", nil)
		w := httptest.NewRecorder()
		handleDeleteConversation(w, req)
		if w.Code != http.StatusUnauthorized {
			t.Errorf("expected 401, got %d", w.Code)
		}
	})
}

func TestCB90_HandleDeleteConversation_MissingID(t *testing.T) {
	withTestDB_CB90(t, func(testDB *sql.DB) {
		userID, _, _ := setupUserAndConv_CB90(t, testDB)
		token := makeJWT_CB90(userID, "cb90testuser")
		req := httptest.NewRequest(http.MethodDelete, "/conversations/delete", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		handleDeleteConversation(w, req)
		if w.Code != http.StatusBadRequest {
			t.Errorf("expected 400 for missing ID, got %d", w.Code)
		}
	})
}

func TestCB90_HandleDeleteConversation_NotFound(t *testing.T) {
	withTestDB_CB90(t, func(testDB *sql.DB) {
		userID, _, _ := setupUserAndConv_CB90(t, testDB)
		token := makeJWT_CB90(userID, "cb90testuser")
		req := httptest.NewRequest(http.MethodDelete, "/conversations/delete?conversation_id=nonexistent", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		handleDeleteConversation(w, req)
		if w.Code != http.StatusNotFound {
			t.Errorf("expected 404, got %d", w.Code)
		}
	})
}

func TestCB90_HandleDeleteConversation_Unauthorized(t *testing.T) {
	withTestDB_CB90(t, func(testDB *sql.DB) {
		_, _, convID := setupUserAndConv_CB90(t, testDB)
		token2 := makeJWT_CB90("cb90-user2", "cb90other")
		req := httptest.NewRequest(http.MethodDelete, "/conversations/delete?conversation_id="+convID, nil)
		req.Header.Set("Authorization", "Bearer "+token2)
		w := httptest.NewRecorder()
		handleDeleteConversation(w, req)
		if w.Code != http.StatusUnauthorized {
			t.Errorf("expected 401 for unauthorized user, got %d", w.Code)
		}
	})
}

func TestCB90_HandleDeleteConversation_Success(t *testing.T) {
	withTestDB_CB90(t, func(testDB *sql.DB) {
		userID, _, convID := setupUserAndConv_CB90(t, testDB)
		insertMessage_CB90(testDB, "msg1", convID, "agent", "cb90-agent1", "Hello")
		token := makeJWT_CB90(userID, "cb90testuser")
		req := httptest.NewRequest(http.MethodDelete, "/conversations/delete?conversation_id="+convID, nil)
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		handleDeleteConversation(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
		}
		// Verify conversation is gone
		var count int
		testDB.QueryRow("SELECT COUNT(*) FROM conversations WHERE id = ?", convID).Scan(&count)
		if count != 0 {
			t.Errorf("conversation still exists after delete")
		}
		// Verify messages are gone
		testDB.QueryRow("SELECT COUNT(*) FROM messages WHERE conversation_id = ?", convID).Scan(&count)
		if count != 0 {
			t.Errorf("messages still exist after delete")
		}
	})
}

// ============================================================
// handleGetNotificationPrefs tests
// ============================================================

func TestCB90_HandleGetNotificationPrefs_NoAuth(t *testing.T) {
	withTestDB_CB90(t, func(testDB *sql.DB) {
		req := httptest.NewRequest(http.MethodGet, "/notifications/preferences", nil)
		w := httptest.NewRecorder()
		handleGetNotificationPrefs(w, req)
		if w.Code != http.StatusUnauthorized {
			t.Errorf("expected 401, got %d", w.Code)
		}
	})
}

func TestCB90_HandleGetNotificationPrefs_Empty(t *testing.T) {
	withTestDB_CB90(t, func(testDB *sql.DB) {
		userID, _, _ := setupUserAndConv_CB90(t, testDB)
		token := makeJWT_CB90(userID, "cb90testuser")
		req := httptest.NewRequest(http.MethodGet, "/notifications/preferences", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		req = req.WithContext(context.WithValue(req.Context(), contextKeyUserID, userID))
		w := httptest.NewRecorder()
		handleGetNotificationPrefs(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", w.Code)
		}
		var resp []NotificationPreferences
		json.NewDecoder(w.Body).Decode(&resp)
		if len(resp) != 0 {
			t.Errorf("expected 0 prefs, got %d", len(resp))
		}
	})
}

func TestCB90_HandleGetNotificationPrefs_WithData(t *testing.T) {
	withTestDB_CB90(t, func(testDB *sql.DB) {
		userID, _, convID := setupUserAndConv_CB90(t, testDB)
		_, err := testDB.Exec("INSERT INTO notification_preferences (user_id, conversation_id, muted) VALUES (?, ?, ?)",
			userID, convID, true)
		if err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequest(http.MethodGet, "/notifications/preferences", nil)
		req = req.WithContext(context.WithValue(req.Context(), contextKeyUserID, userID))
		w := httptest.NewRecorder()
		handleGetNotificationPrefs(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", w.Code)
		}
		var resp []NotificationPreferences
		json.NewDecoder(w.Body).Decode(&resp)
		if len(resp) != 1 {
			t.Errorf("expected 1 pref, got %d", len(resp))
		}
		if !resp[0].Muted {
			t.Error("expected muted=true")
		}
	})
}

func TestCB90_HandleGetNotificationPrefs_DBError(t *testing.T) {
	oldDB := db
	defer func() { db = oldDB }()
	db, _ = sql.Open("sqlite3", ":memory:")
	defer db.Close()
	// Don't init schema — query will fail
	userID := "cb90-err-user"
	req := httptest.NewRequest(http.MethodGet, "/notifications/preferences", nil)
	req = req.WithContext(context.WithValue(req.Context(), contextKeyUserID, userID))
	w := httptest.NewRecorder()
	handleGetNotificationPrefs(w, req)
	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 for DB error, got %d", w.Code)
	}
}

// ============================================================
// handleDeleteNotificationPrefs tests
// ============================================================

func TestCB90_HandleDeleteNotificationPrefs_NoAuth(t *testing.T) {
	withTestDB_CB90(t, func(testDB *sql.DB) {
		req := httptest.NewRequest(http.MethodPost, "/notifications/preferences/delete", nil)
		w := httptest.NewRecorder()
		handleDeleteNotificationPrefs(w, req)
		if w.Code != http.StatusUnauthorized {
			t.Errorf("expected 401, got %d", w.Code)
		}
	})
}

func TestCB90_HandleDeleteNotificationPrefs_MissingID(t *testing.T) {
	withTestDB_CB90(t, func(testDB *sql.DB) {
		userID, _, _ := setupUserAndConv_CB90(t, testDB)
		req := httptest.NewRequest(http.MethodPost, "/notifications/preferences/delete", strings.NewReader(""))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req = req.WithContext(context.WithValue(req.Context(), contextKeyUserID, userID))
		w := httptest.NewRecorder()
		handleDeleteNotificationPrefs(w, req)
		if w.Code != http.StatusBadRequest {
			t.Errorf("expected 400 for missing conv ID, got %d", w.Code)
		}
	})
}

func TestCB90_HandleDeleteNotificationPrefs_Success(t *testing.T) {
	withTestDB_CB90(t, func(testDB *sql.DB) {
		userID, _, convID := setupUserAndConv_CB90(t, testDB)
		testDB.Exec("INSERT INTO notification_preferences (user_id, conversation_id, muted) VALUES (?, ?, ?)",
			userID, convID, true)
		form := "conversation_id=" + convID
		req := httptest.NewRequest(http.MethodPost, "/notifications/preferences/delete", strings.NewReader(form))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req = req.WithContext(context.WithValue(req.Context(), contextKeyUserID, userID))
		w := httptest.NewRecorder()
		handleDeleteNotificationPrefs(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", w.Code)
		}
		// Verify deleted
		var count int
		testDB.QueryRow("SELECT COUNT(*) FROM notification_preferences WHERE user_id = ? AND conversation_id = ?",
			userID, convID).Scan(&count)
		if count != 0 {
			t.Error("preference still exists after delete")
		}
	})
}

// ============================================================
// handleSetNotificationPrefs additional tests
// ============================================================

func TestCB90_HandleSetNotificationPrefs_DBError(t *testing.T) {
	oldDB := db
	defer func() { db = oldDB }()
	db, _ = sql.Open("sqlite3", ":memory:")
	defer db.Close()
	// Don't init schema — query will fail
	userID := "cb90-err-user"
	req := httptest.NewRequest(http.MethodPost, "/notifications/preferences", strings.NewReader("conversation_id=conv1&muted=true"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req = req.WithContext(context.WithValue(req.Context(), contextKeyUserID, userID))
	w := httptest.NewRecorder()
	handleSetNotificationPrefs(w, req)
	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 for DB error, got %d", w.Code)
	}
}

func TestCB90_HandleSetNotificationPrefs_Success(t *testing.T) {
	withTestDB_CB90(t, func(testDB *sql.DB) {
		userID, _, convID := setupUserAndConv_CB90(t, testDB)
		form := "conversation_id=" + convID + "&muted=true"
		req := httptest.NewRequest(http.MethodPost, "/notifications/preferences", strings.NewReader(form))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req = req.WithContext(context.WithValue(req.Context(), contextKeyUserID, userID))
		w := httptest.NewRecorder()
		handleSetNotificationPrefs(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
		}
		var resp NotificationPreferences
		json.NewDecoder(w.Body).Decode(&resp)
		if !resp.Muted {
			t.Error("expected muted=true")
		}
		if resp.ConversationID != convID {
			t.Errorf("expected conv_id=%s, got %s", convID, resp.ConversationID)
		}
	})
}

func TestCB90_HandleSetNotificationPrefs_Unmute(t *testing.T) {
	withTestDB_CB90(t, func(testDB *sql.DB) {
		userID, _, convID := setupUserAndConv_CB90(t, testDB)
		// First mute
		testDB.Exec("INSERT INTO notification_preferences (user_id, conversation_id, muted) VALUES (?, ?, ?)",
			userID, convID, true)
		// Now unmute
		form := "conversation_id=" + convID + "&muted=false"
		req := httptest.NewRequest(http.MethodPost, "/notifications/preferences", strings.NewReader(form))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req = req.WithContext(context.WithValue(req.Context(), contextKeyUserID, userID))
		w := httptest.NewRecorder()
		handleSetNotificationPrefs(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", w.Code)
		}
		var resp NotificationPreferences
		json.NewDecoder(w.Body).Decode(&resp)
		if resp.Muted {
			t.Error("expected muted=false after unmute")
		}
	})
}

func TestCB90_HandleSetNotificationPrefs_NotFound(t *testing.T) {
	withTestDB_CB90(t, func(testDB *sql.DB) {
		userID, _, _ := setupUserAndConv_CB90(t, testDB)
		form := "conversation_id=nonexistent&muted=true"
		req := httptest.NewRequest(http.MethodPost, "/notifications/preferences", strings.NewReader(form))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req = req.WithContext(context.WithValue(req.Context(), contextKeyUserID, userID))
		w := httptest.NewRecorder()
		handleSetNotificationPrefs(w, req)
		if w.Code != http.StatusNotFound {
			t.Errorf("expected 404, got %d", w.Code)
		}
	})
}

func TestCB90_HandleSetNotificationPrefs_NotOwner(t *testing.T) {
	withTestDB_CB90(t, func(testDB *sql.DB) {
		_, _, convID := setupUserAndConv_CB90(t, testDB)
		form := "conversation_id=" + convID + "&muted=true"
		req := httptest.NewRequest(http.MethodPost, "/notifications/preferences", strings.NewReader(form))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req = req.WithContext(context.WithValue(req.Context(), contextKeyUserID, "cb90-other-user"))
		w := httptest.NewRecorder()
		handleSetNotificationPrefs(w, req)
		if w.Code != http.StatusForbidden {
			t.Errorf("expected 403, got %d", w.Code)
		}
	})
}

// ============================================================
// openDatabase tests
// ============================================================

func TestCB90_OpenDatabase_SQLite(t *testing.T) {
	dbPath := "/tmp/cb90_test_open.db"
	defer os.Remove(dbPath)
	database, err := openDatabase(DriverSQLite, dbPath)
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}
	defer database.Close()
	if database == nil {
		t.Fatal("expected non-nil db")
	}
}

func TestCB90_OpenDatabase_InvalidDriver(t *testing.T) {
	_, err := openDatabase("unsupported_driver", "dsn")
	if err == nil {
		t.Error("expected error for unsupported driver")
	}
}

func TestCB90_OpenDatabase_EmptyDSN(t *testing.T) {
	// sql.Open is lazy — empty DSN doesn't error on open, only on ping.
	// For SQLite, empty DSN opens a temporary in-memory database.
	database, err := openDatabase(DriverSQLite, "")
	if err != nil {
		t.Errorf("expected success for empty DSN (lazy open), got %v", err)
	}
	if database != nil {
		database.Close()
	}
}

func TestCB90_OpenDatabase_PostgreSQL_PingFail(t *testing.T) {
	// PostgreSQL driver will fail to ping with non-existent host
	_, err := openDatabase(DriverPostgreSQL, "host=nonexistent port=9999 user=test password=test dbname=test sslmode=disable")
	if err == nil {
		t.Error("expected error for unreachable PostgreSQL")
	}
}

func TestCB90_OpenDatabase_PostgreSQL_WithEnv(t *testing.T) {
	// Set env vars for pool configuration — still fails on ping but exercises env parsing
	os.Setenv("DB_MAX_OPEN_CONNS", "10")
	os.Setenv("DB_MAX_IDLE_CONNS", "3")
	os.Setenv("DB_CONN_MAX_LIFETIME", "10m")
	os.Setenv("DB_CONN_MAX_IDLE_TIME", "2m")
	defer os.Unsetenv("DB_MAX_OPEN_CONNS")
	defer os.Unsetenv("DB_MAX_IDLE_CONNS")
	defer os.Unsetenv("DB_CONN_MAX_LIFETIME")
	defer os.Unsetenv("DB_CONN_MAX_IDLE_TIME")

	_, err := openDatabase(DriverPostgreSQL, "host=nonexistent port=9999 user=test password=test dbname=test sslmode=disable")
	if err == nil {
		t.Error("expected ping error for unreachable PostgreSQL")
	}
}

// ============================================================
// checkRateLimit tests
// ============================================================

func TestCB90_CheckRateLimit_Allowed(t *testing.T) {
	oldMsgRL := messageRateLimiter
	oldUserRL := userRateLimiter
	defer func() {
		messageRateLimiter = oldMsgRL
		userRateLimiter = oldUserRL
	}()
	messageRateLimiter = NewRateLimiter(60, time.Minute)
	userRateLimiter = NewRateLimiter(120, time.Minute)
	defer messageRateLimiter.Stop()
	defer userRateLimiter.Stop()

	conn := &Connection{id: "cb90-rl-user", connType: "client", send: make(chan []byte, 10)}
	result := checkRateLimit(conn)
	if !result {
		t.Error("expected rate limit to allow")
	}
}

func TestCB90_CheckRateLimit_PerConnExceeded(t *testing.T) {
	oldMsgRL := messageRateLimiter
	oldUserRL := userRateLimiter
	defer func() {
		messageRateLimiter = oldMsgRL
		userRateLimiter = oldUserRL
	}()
	messageRateLimiter = NewRateLimiter(2, time.Minute)
	userRateLimiter = NewRateLimiter(120, time.Minute)
	defer messageRateLimiter.Stop()
	defer userRateLimiter.Stop()

	conn := &Connection{id: "cb90-rl-exceed", connType: "client", send: make(chan []byte, 10)}
	checkRateLimit(conn)
	checkRateLimit(conn)
	result := checkRateLimit(conn)
	if result {
		t.Error("expected rate limit to deny on 3rd message")
	}
}

func TestCB90_CheckRateLimit_PerUserExceeded(t *testing.T) {
	oldMsgRL := messageRateLimiter
	oldUserRL := userRateLimiter
	defer func() {
		messageRateLimiter = oldMsgRL
		userRateLimiter = oldUserRL
	}()
	messageRateLimiter = NewRateLimiter(60, time.Minute)
	userRateLimiter = NewRateLimiter(2, time.Minute)
	defer messageRateLimiter.Stop()
	defer userRateLimiter.Stop()

	conn := &Connection{id: "cb90-rl-user-exceed", connType: "client", send: make(chan []byte, 10)}
	checkRateLimit(conn)
	checkRateLimit(conn)
	result := checkRateLimit(conn)
	if result {
		t.Error("expected user rate limit to deny on 3rd message")
	}
}

// ============================================================
// loadQueueFromDB tests
// ============================================================

func TestCB90_LoadQueueFromDB_Success(t *testing.T) {
	withTestDB_CB90(t, func(testDB *sql.DB) {
		q := newOfflineQueue(100, 7*24*time.Hour)
		// Insert a queue entry
		data := []byte(`{"type":"message","data":{"content":"hello"}}`)
		_, err := testDB.Exec("INSERT INTO offline_queue (recipient, data, queued_at, sent_count) VALUES (?, ?, ?, 0)",
			"cb90-recipient", data, time.Now().UTC().Format(time.RFC3339))
		if err != nil {
			t.Fatal(err)
		}
		loadQueueFromDB(testDB, q)
		if q.TotalDepth() != 1 {
			t.Errorf("expected 1 queued message, got %d", q.TotalDepth())
		}
	})
}

func TestCB90_LoadQueueFromDB_Empty(t *testing.T) {
	withTestDB_CB90(t, func(testDB *sql.DB) {
		q := newOfflineQueue(100, 7*24*time.Hour)
		loadQueueFromDB(testDB, q)
		if q.TotalDepth() != 0 {
			t.Errorf("expected 0 messages, got %d", q.TotalDepth())
		}
	})
}

func TestCB90_LoadQueueFromDB_NilDB(t *testing.T) {
	q := newOfflineQueue(100, 7*24*time.Hour)
	loadQueueFromDB(nil, q)
	if q.TotalDepth() != 0 {
		t.Errorf("expected 0 messages with nil DB, got %d", q.TotalDepth())
	}
}

func TestCB90_LoadQueueFromDB_MultipleEntries(t *testing.T) {
	withTestDB_CB90(t, func(testDB *sql.DB) {
		q := newOfflineQueue(100, 7*24*time.Hour)
		data := []byte(`{"type":"message"}`)
		for i := 0; i < 3; i++ {
			_, err := testDB.Exec("INSERT INTO offline_queue (recipient, data, queued_at, sent_count) VALUES (?, ?, ?, 0)",
				"cb90-multi", data, time.Now().Add(time.Duration(i)*time.Second).UTC().Format(time.RFC3339))
			if err != nil {
				t.Fatal(err)
			}
		}
		loadQueueFromDB(testDB, q)
		if q.TotalDepth() != 3 {
			t.Errorf("expected 3 messages, got %d", q.TotalDepth())
		}
	})
}

// ============================================================
// storeMessagesBatch tests
// ============================================================

func TestCB90_StoreMessagesBatch_Success(t *testing.T) {
	withTestDB_CB90(t, func(testDB *sql.DB) {
		_, _, convID := setupUserAndConv_CB90(t, testDB)
		msgs := []RoutedMessage{
			{ConversationID: convID, SenderType: "client", SenderID: "cb90-user1", Content: "msg1", Type: MsgTypeMessage},
			{ConversationID: convID, SenderType: "client", SenderID: "cb90-user1", Content: "msg2", Type: MsgTypeMessage},
		}
		ids, err := storeMessagesBatch(msgs)
		if err != nil {
			t.Fatalf("expected success, got %v", err)
		}
		if len(ids) != 2 {
			t.Errorf("expected 2 ids, got %d", len(ids))
		}
	})
}

func TestCB90_StoreMessagesBatch_Empty(t *testing.T) {
	withTestDB_CB90(t, func(testDB *sql.DB) {
		ids, err := storeMessagesBatch([]RoutedMessage{})
		if err != nil {
			t.Errorf("expected no error for empty batch, got %v", err)
		}
		if len(ids) != 0 {
			t.Errorf("expected 0 ids, got %d", len(ids))
		}
	})
}

func TestCB90_StoreMessagesBatch_WithMetadata(t *testing.T) {
	withTestDB_CB90(t, func(testDB *sql.DB) {
		_, _, convID := setupUserAndConv_CB90(t, testDB)
		msgs := []RoutedMessage{
			{
				ConversationID: convID, SenderType: "agent", SenderID: "cb90-agent1",
				Content: "msg with meta", Type: MsgTypeMessage,
				AttachmentIDs: []string{"attach1"},
			},
		}
		ids, err := storeMessagesBatch(msgs)
		if err != nil {
			t.Fatalf("expected success, got %v", err)
		}
		if len(ids) != 1 {
			t.Errorf("expected 1 id, got %d", len(ids))
		}
	})
}

// ============================================================
// isConversationMuted tests
// ============================================================

func TestCB90_IsConversationMuted_NotMuted(t *testing.T) {
	withTestDB_CB90(t, func(testDB *sql.DB) {
		userID, _, convID := setupUserAndConv_CB90(t, testDB)
		muted := isConversationMuted(userID, convID)
		if muted {
			t.Error("expected not muted")
		}
	})
}

func TestCB90_IsConversationMuted_Muted(t *testing.T) {
	withTestDB_CB90(t, func(testDB *sql.DB) {
		userID, _, convID := setupUserAndConv_CB90(t, testDB)
		testDB.Exec("INSERT INTO notification_preferences (user_id, conversation_id, muted) VALUES (?, ?, ?)",
			userID, convID, true)
		muted := isConversationMuted(userID, convID)
		if !muted {
			t.Error("expected muted")
		}
	})
}

func TestCB90_IsConversationMuted_NilDB(t *testing.T) {
	oldDB := db
	defer func() { db = oldDB }()
	db = nil
	muted := isConversationMuted("user1", "conv1")
	if muted {
		t.Error("expected not muted with nil DB")
	}
}

func TestCB90_IsConversationMuted_EmptyConvID(t *testing.T) {
	withTestDB_CB90(t, func(testDB *sql.DB) {
		muted := isConversationMuted("user1", "")
		if muted {
			t.Error("expected not muted for empty conv ID")
		}
	})
}

// ============================================================
// changeUserPassword tests (direct function)
// ============================================================

func TestCB90_ChangeUserPassword_Success(t *testing.T) {
	withTestDB_CB90(t, func(testDB *sql.DB) {
		userID, _, _ := setupUserAndConv_CB90(t, testDB)
		err := changeUserPassword(userID, "testpass", "newpass123")
		if err != nil {
			t.Errorf("expected success, got %v", err)
		}
		// Verify new password works
		var hash string
		testDB.QueryRow("SELECT password_hash FROM users WHERE id = ?", userID).Scan(&hash)
		err = bcrypt.CompareHashAndPassword([]byte(hash), []byte("newpass123"))
		if err != nil {
			t.Error("new password does not match")
		}
	})
}

func TestCB90_ChangeUserPassword_WrongOldPassword(t *testing.T) {
	withTestDB_CB90(t, func(testDB *sql.DB) {
		userID, _, _ := setupUserAndConv_CB90(t, testDB)
		err := changeUserPassword(userID, "wrongpass", "newpass123")
		if err == nil || err.Error() != "invalid old password" {
			t.Errorf("expected 'invalid old password', got %v", err)
		}
	})
}

func TestCB90_ChangeUserPassword_ShortNew(t *testing.T) {
	withTestDB_CB90(t, func(testDB *sql.DB) {
		userID, _, _ := setupUserAndConv_CB90(t, testDB)
		err := changeUserPassword(userID, "testpass", "abc")
		if err == nil || err.Error() != "new password must be at least 6 characters" {
			t.Errorf("expected 'new password must be at least 6 characters', got %v", err)
		}
	})
}

func TestCB90_ChangeUserPassword_UserNotFound(t *testing.T) {
	withTestDB_CB90(t, func(testDB *sql.DB) {
		err := changeUserPassword("nonexistent", "oldpass", "newpass123")
		if err == nil {
			t.Error("expected error for non-existent user")
		}
	})
}

// ============================================================
// searchMessages tests (direct function)
// ============================================================

func TestCB90_SearchMessages_Success(t *testing.T) {
	withTestDB_CB90(t, func(testDB *sql.DB) {
		userID, _, convID := setupUserAndConv_CB90(t, testDB)
		insertMessage_CB90(testDB, "msg1", convID, "agent", "cb90-agent1", "hello world")
		insertMessage_CB90(testDB, "msg2", convID, "client", userID, "goodbye world")
		results, err := searchMessages(userID, "hello", 50)
		if err != nil {
			t.Fatalf("expected success, got %v", err)
		}
		if len(results) != 1 {
			t.Errorf("expected 1 result, got %d", len(results))
		}
	})
}

func TestCB90_SearchMessages_EmptyQuery(t *testing.T) {
	withTestDB_CB90(t, func(testDB *sql.DB) {
		userID, _, _ := setupUserAndConv_CB90(t, testDB)
		_, err := searchMessages(userID, "", 50)
		if err == nil || err.Error() != "empty search query" {
			t.Errorf("expected 'empty search query', got %v", err)
		}
	})
}

func TestCB90_SearchMessages_NoResults(t *testing.T) {
	withTestDB_CB90(t, func(testDB *sql.DB) {
		userID, _, _ := setupUserAndConv_CB90(t, testDB)
		results, err := searchMessages(userID, "nonexistent", 50)
		if err != nil {
			t.Errorf("expected success, got %v", err)
		}
		if len(results) != 0 {
			t.Errorf("expected 0 results, got %d", len(results))
		}
	})
}

func TestCB90_SearchMessages_NegativeLimit(t *testing.T) {
	withTestDB_CB90(t, func(testDB *sql.DB) {
		userID, _, convID := setupUserAndConv_CB90(t, testDB)
		insertMessage_CB90(testDB, "msg1", convID, "agent", "cb90-agent1", "test content")
		results, err := searchMessages(userID, "test", -5)
		if err != nil {
			t.Errorf("expected success, got %v", err)
		}
		// Negative limit should default to 50
		if len(results) != 1 {
			t.Errorf("expected 1 result (limit defaults to 50), got %d", len(results))
		}
	})
}

// ============================================================
// markMessagesRead tests (direct function)
// ============================================================

func TestCB90_MarkMessagesRead_Success(t *testing.T) {
	withTestDB_CB90(t, func(testDB *sql.DB) {
		userID, _, convID := setupUserAndConv_CB90(t, testDB)
		insertMessage_CB90(testDB, "msg1", convID, "agent", "cb90-agent1", "Hello")
		insertMessage_CB90(testDB, "msg2", convID, "agent", "cb90-agent1", "World")
		count, err := markMessagesRead(convID, userID)
		if err != nil {
			t.Fatalf("expected success, got %v", err)
		}
		if count != 2 {
			t.Errorf("expected 2 messages marked, got %d", count)
		}
	})
}

func TestCB90_MarkMessagesRead_NotFound(t *testing.T) {
	withTestDB_CB90(t, func(testDB *sql.DB) {
		count, err := markMessagesRead("nonexistent", "user1")
		if err != sql.ErrNoRows {
			t.Errorf("expected sql.ErrNoRows, got %v", err)
		}
		if count != 0 {
			t.Errorf("expected 0 count, got %d", count)
		}
	})
}

func TestCB90_MarkMessagesRead_Unauthorized(t *testing.T) {
	withTestDB_CB90(t, func(testDB *sql.DB) {
		_, _, convID := setupUserAndConv_CB90(t, testDB)
		count, err := markMessagesRead(convID, "wrong-user")
		if err == nil || err.Error() != "unauthorized" {
			t.Errorf("expected 'unauthorized', got %v", err)
		}
		if count != 0 {
			t.Errorf("expected 0 count, got %d", count)
		}
	})
}

func TestCB90_MarkMessagesRead_Idempotent(t *testing.T) {
	withTestDB_CB90(t, func(testDB *sql.DB) {
		userID, _, convID := setupUserAndConv_CB90(t, testDB)
		insertMessage_CB90(testDB, "msg1", convID, "agent", "cb90-agent1", "Hello")
		// First call
		count1, _ := markMessagesRead(convID, userID)
		if count1 != 1 {
			t.Fatalf("expected 1 on first call, got %d", count1)
		}
		// Second call — already read
		count2, _ := markMessagesRead(convID, userID)
		if count2 != 0 {
			t.Errorf("expected 0 on second call, got %d", count2)
		}
	})
}

// ============================================================
// GetOrCreateConversation tests
// ============================================================

func TestCB90_GetOrCreateConversation_New(t *testing.T) {
	withTestDB_CB90(t, func(testDB *sql.DB) {
		_, agentID, _ := setupUserAndConv_CB90(t, testDB)
		conv, err := GetOrCreateConversation("cb90-new-user", agentID)
		if err != nil {
			t.Fatalf("expected success, got %v", err)
		}
		if conv == nil {
			t.Fatal("expected non-nil conversation")
		}
		if conv.AgentID != agentID {
			t.Errorf("expected agent_id=%s, got %s", agentID, conv.AgentID)
		}
	})
}

func TestCB90_GetOrCreateConversation_Existing(t *testing.T) {
	withTestDB_CB90(t, func(testDB *sql.DB) {
		userID, agentID, convID := setupUserAndConv_CB90(t, testDB)
		conv, err := GetOrCreateConversation(userID, agentID)
		if err != nil {
			t.Fatalf("expected success, got %v", err)
		}
		if conv.ID != convID {
			t.Errorf("expected existing conv ID=%s, got %s", convID, conv.ID)
		}
	})
}

// ============================================================
// generateID tests
// ============================================================

func TestCB90_GenerateID(t *testing.T) {
	id1 := generateID("test")
	id2 := generateID("test")
	if !strings.HasPrefix(id1, "test_") {
		t.Errorf("expected prefix 'test_', got %s", id1)
	}
	if id1 == id2 {
		t.Error("expected unique IDs (unlikely to be equal)")
	}
}

func TestCB90_GenerateID_DifferentPrefixes(t *testing.T) {
	id1 := generateID("user")
	id2 := generateID("agent")
	if !strings.HasPrefix(id1, "user_") {
		t.Errorf("expected prefix 'user_', got %s", id1)
	}
	if !strings.HasPrefix(id2, "agent_") {
		t.Errorf("expected prefix 'agent_', got %s", id2)
	}
}

// ============================================================
// GetOrCreateConversation error path
// ============================================================

func TestCB90_CreateConversation_Error(t *testing.T) {
	oldDB := db
	defer func() { db = oldDB }()
	db, _ = sql.Open("sqlite3", ":memory:")
	defer db.Close()
	// Don't init schema — insert will fail
	_, err := CreateConversation("user1", "agent1")
	if err == nil {
		t.Error("expected error without schema")
	}
}

// ============================================================
// isUniqueViolation tests
// ============================================================

func TestCB90_IsUniqueViolation_True(t *testing.T) {
	err := fmt.Errorf("UNIQUE constraint failed: users.username")
	if !isUniqueViolation(err) {
		t.Error("expected true for UNIQUE constraint error")
	}
}

func TestCB90_IsUniqueViolation_False(t *testing.T) {
	err := fmt.Errorf("some other error")
	if isUniqueViolation(err) {
		t.Error("expected false for non-unique error")
	}
}

func TestCB90_IsUniqueViolation_Nil(t *testing.T) {
	if isUniqueViolation(nil) {
		t.Error("expected false for nil error")
	}
}

// ============================================================
// writeJSON / writeJSONError tests
// ============================================================

func TestCB90_WriteJSON(t *testing.T) {
	w := httptest.NewRecorder()
	writeJSON(w, http.StatusOK, map[string]string{"key": "value"})
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	if w.Header().Get("Content-Type") != "application/json" {
		t.Errorf("expected application/json content type, got %s", w.Header().Get("Content-Type"))
	}
	var resp map[string]string
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["key"] != "value" {
		t.Errorf("expected key=value, got %s", resp["key"])
	}
}

func TestCB90_WriteJSONError(t *testing.T) {
	w := httptest.NewRecorder()
	writeJSONError(w, http.StatusBadRequest, "test error")
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
	var resp map[string]string
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["error"] != "test error" {
		t.Errorf("expected error='test error', got %s", resp["error"])
	}
}

// ============================================================
// getUserID tests
// ============================================================

func TestCB90_GetUserID_Success(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req = req.WithContext(context.WithValue(req.Context(), contextKeyUserID, "cb90-user"))
	userID, err := getUserID(req)
	if err != nil {
		t.Errorf("expected success, got %v", err)
	}
	if userID != "cb90-user" {
		t.Errorf("expected cb90-user, got %s", userID)
	}
}

func TestCB90_GetUserID_NoContext(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	_, err := getUserID(req)
	if err == nil {
		t.Error("expected error for missing context")
	}
}

func TestCB90_GetUserID_EmptyUserID(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req = req.WithContext(context.WithValue(req.Context(), contextKeyUserID, ""))
	_, err := getUserID(req)
	if err == nil {
		t.Error("expected error for empty userID")
	}
}

// ============================================================
// deleteConversation tests (direct function)
// ============================================================

func TestCB90_DeleteConversation_Success(t *testing.T) {
	withTestDB_CB90(t, func(testDB *sql.DB) {
		userID, _, convID := setupUserAndConv_CB90(t, testDB)
		insertMessage_CB90(testDB, "msg1", convID, "agent", "cb90-agent1", "Hello")
		err := deleteConversation(convID, userID)
		if err != nil {
			t.Fatalf("expected success, got %v", err)
		}
		var count int
		testDB.QueryRow("SELECT COUNT(*) FROM conversations WHERE id = ?", convID).Scan(&count)
		if count != 0 {
			t.Error("conversation still exists")
		}
	})
}

func TestCB90_DeleteConversation_NotFound(t *testing.T) {
	withTestDB_CB90(t, func(testDB *sql.DB) {
		err := deleteConversation("nonexistent", "user1")
		if err == nil {
			t.Error("expected error for non-existent conversation")
		}
	})
}

func TestCB90_DeleteConversation_Unauthorized(t *testing.T) {
	withTestDB_CB90(t, func(testDB *sql.DB) {
		_, _, convID := setupUserAndConv_CB90(t, testDB)
		err := deleteConversation(convID, "wrong-user")
		if err == nil {
			t.Error("expected error for unauthorized user")
		}
	})
}

// ============================================================
// getConversation tests
// ============================================================

func TestCB90_GetConversation_Success(t *testing.T) {
	withTestDB_CB90(t, func(testDB *sql.DB) {
		userID, agentID, convID := setupUserAndConv_CB90(t, testDB)
		conv, err := getConversation(convID)
		if err != nil {
			t.Fatalf("expected success, got %v", err)
		}
		if conv == nil {
			t.Fatal("expected non-nil conversation")
		}
		if conv.UserID != userID {
			t.Errorf("expected user_id=%s, got %s", userID, conv.UserID)
		}
		if conv.AgentID != agentID {
			t.Errorf("expected agent_id=%s, got %s", agentID, conv.AgentID)
		}
	})
}

func TestCB90_GetConversation_NotFound(t *testing.T) {
	withTestDB_CB90(t, func(testDB *sql.DB) {
		conv, err := getConversation("nonexistent")
		if err != nil {
			t.Errorf("expected no error for not found, got %v", err)
		}
		if conv != nil {
			t.Error("expected nil conversation")
		}
	})
}

// ============================================================
// getDeviceTokensForUser tests
// ============================================================

func TestCB90_GetDeviceTokensForUser_Success(t *testing.T) {
	withTestDB_CB90(t, func(testDB *sql.DB) {
		userID, _, _ := setupUserAndConv_CB90(t, testDB)
		_, err := testDB.Exec("INSERT INTO device_tokens (user_id, device_token, platform) VALUES (?, ?, ?)",
			userID, "token123", "ios")
		if err != nil {
			t.Fatal(err)
		}
		tokens, err := getDeviceTokensForUser(userID)
		if err != nil {
			t.Fatalf("expected success, got %v", err)
		}
		if len(tokens) != 1 {
			t.Errorf("expected 1 token, got %d", len(tokens))
		}
	})
}

func TestCB90_GetDeviceTokensForUser_NoTokens(t *testing.T) {
	withTestDB_CB90(t, func(testDB *sql.DB) {
		userID, _, _ := setupUserAndConv_CB90(t, testDB)
		tokens, err := getDeviceTokensForUser(userID)
		if err != nil {
			t.Errorf("expected success, got %v", err)
		}
		if len(tokens) != 0 {
			t.Errorf("expected 0 tokens, got %d", len(tokens))
		}
	})
}

func TestCB90_GetDeviceTokensForUser_NilDB(t *testing.T) {
	oldDB := db
	defer func() { db = oldDB }()
	db = nil
	tokens, err := getDeviceTokensForUser("user1")
	if err == nil {
		t.Error("expected error for nil DB")
	}
	if len(tokens) != 0 {
		t.Errorf("expected 0 tokens, got %d", len(tokens))
	}
}