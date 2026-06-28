package main

// Coverage Boost 40: Targeting remaining low-coverage handler wrappers and E2E:
// - handleSearchMessages (37.5%): success with results, limit parsing, DB error
// - handleMarkRead (8.3%): success with WS, not found, unauthorized, missing conv_id, wrong method
// - handleChangePassword (42.3%): success, wrong method, no auth, missing fields, wrong old, not found, short new
// - handleDeleteConversation (55.6%): success, wrong method, no auth, missing ID, not found, unauthorized
// - handleRegisterUser (58.6%): success, wrong method, missing fields, short username, bad chars, duplicate
// - handleRegisterAgent (64.0%): success, wrong method, no secret, bad secret, missing agent_id, DB error
// - handleLogin (56.0%): success, wrong method, missing fields, bad username, wrong password, JWT error
// - handleHealth (72.2%): DB ping error, metrics snapshot
// - handleUploadPublicKey (53.1%): success, wrong method, no auth, invalid JSON, missing public_key, invalid key_type, DB error, identity key replace
// - handleGetKeyBundle (9.4%): success with full bundle, no auth, missing owner_id, not found, agent auth, signed_prekey missing, one_time_prekey consume
// - handleStoreEncryptedMessage (54.7%): DB insert error, user delivery via WS all devices
// - handleGetEncryptedMessages (65.9%): DB query error, scan error, agent not participant
// - loadQueueFromDB scan error (78.9%): row scan failure
// - cleanStaleQueueMessages error (80%): DB exec error
// - initQueueDB error (80%): DB exec error
// - rate_limit_tiers cleanup ticker.C (45.5%): actual ticker fire with short interval

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

// --- Setup helpers ---

func cb40SetupDB(t *testing.T) {
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
	pushConfig = nil
	vapidPublicKey = ""
	hub = newHub()
	go hub.run()
	t.Cleanup(func() { hub.Stop() })
	ServerMetrics = NewMetrics(hub)
}

func cb40SetupAuth(t *testing.T) (string, string) {
	t.Helper()
	origJwtSecret := jwtSecret
	origAgentEnv := os.Getenv("AGENT_SECRET")
	origAdminEnv := os.Getenv("ADMIN_SECRET")
	jwtSecret = []byte("test-jwt-secret-cb40")
	os.Setenv("AGENT_SECRET", "test-agent-secret-cb40")
	agentSecret = "test-agent-secret-cb40"
	os.Setenv("ADMIN_SECRET", "test-admin-secret-cb40")
	adminSecret = "test-admin-secret-cb40"
	t.Cleanup(func() {
		jwtSecret = origJwtSecret
		if origAgentEnv != "" {
			os.Setenv("AGENT_SECRET", origAgentEnv)
		} else {
			os.Unsetenv("AGENT_SECRET")
		}
		if origAdminEnv != "" {
			os.Setenv("ADMIN_SECRET", origAdminEnv)
		} else {
			os.Unsetenv("ADMIN_SECRET")
		}
		resetAgentSecret()
		resetAdminSecret()
	})
	return "test-jwt-secret-cb40", "test-agent-secret-cb40"
}

func cb40GenToken(t *testing.T, userID, username string) string {
	t.Helper()
	token, err := GenerateJWT(userID, username)
	if err != nil {
		t.Fatalf("GenerateJWT failed: %v", err)
	}
	return token
}

func cb40RegisterAndLogin(t *testing.T) string {
	t.Helper()
	// Register user
	form := strings.NewReader("username=cb40user&password=cb40pass123")
	req, _ := http.NewRequest("POST", "/auth/user", form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	handleRegisterUser(rec, req)
	if rec.Code != http.StatusOK && rec.Code != http.StatusConflict {
		t.Fatalf("register failed: %d %s", rec.Code, rec.Body.String())
	}
	// Login
	form = strings.NewReader("username=cb40user&password=cb40pass123")
	req, _ = http.NewRequest("POST", "/auth/login", form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec = httptest.NewRecorder()
	handleLogin(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("login failed: %d %s", rec.Code, rec.Body.String())
	}
	var resp map[string]interface{}
	json.Unmarshal(rec.Body.Bytes(), &resp)
	token, _ := resp["token"].(string)
	if token == "" {
		t.Fatal("no token in login response")
	}
	return token
}

func cb40CreateConversation(t *testing.T, token, agentID string) string {
	t.Helper()
	form := strings.NewReader("agent_id=" + agentID)
	req, _ := http.NewRequest("POST", "/conversations/create", form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handleCreateConversation(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("create conversation failed: %d %s", rec.Code, rec.Body.String())
	}
	var resp map[string]interface{}
	json.Unmarshal(rec.Body.Bytes(), &resp)
	id, _ := resp["conversation_id"].(string)
	if id == "" {
		t.Fatal("no conversation_id in response")
	}
	return id
}

func cb40RegisterAgent(t *testing.T, agentID, secret string) {
	t.Helper()
	form := strings.NewReader("agent_id=" + agentID + "&name=TestAgent&model=gpt-4&personality=friendly&specialty=general")
	req, _ := http.NewRequest("POST", "/auth/agent", form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Agent-Secret", secret)
	rec := httptest.NewRecorder()
	handleRegisterAgent(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("register agent failed: %d %s", rec.Code, rec.Body.String())
	}
}

// ==============================
// handleSearchMessages tests
// ==============================

func TestCB40_SearchMessages_SuccessWithResults(t *testing.T) {
	cb40SetupDB(t)
	cb40SetupAuth(t)
	token := cb40RegisterAndLogin(t)
	cb40RegisterAgent(t, "agent-search-1", "test-agent-secret-cb40")
	convID := cb40CreateConversation(t, token, "agent-search-1")

	// Store some messages
	_, err := db.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, created_at) VALUES (?, ?, 'agent', 'agent-search-1', 'hello world test', ?)",
		"msg-search-1", convID, time.Now().UTC().Format(time.RFC3339))
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, created_at) VALUES (?, ?, 'user', 'user_cb40', 'test message here', ?)",
		"msg-search-2", convID, time.Now().UTC().Format(time.RFC3339))
	if err != nil {
		t.Fatal(err)
	}

	req, _ := http.NewRequest("GET", "/messages/search?q=test&limit=10", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handleSearchMessages(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var messages []map[string]interface{}
	json.Unmarshal(rec.Body.Bytes(), &messages)
	if len(messages) != 2 {
		t.Errorf("expected 2 results, got %d", len(messages))
	}
}

func TestCB40_SearchMessages_LimitParsing(t *testing.T) {
	cb40SetupDB(t)
	cb40SetupAuth(t)
	token := cb40RegisterAndLogin(t)
	cb40RegisterAgent(t, "agent-search-2", "test-agent-secret-cb40")
	convID := cb40CreateConversation(t, token, "agent-search-2")

	// Store 3 messages
	for i := 0; i < 3; i++ {
		db.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, created_at) VALUES (?, ?, 'agent', 'agent-search-2', 'match', ?)",
			"msg-lp-"+string(rune('1'+i)), convID, time.Now().UTC().Format(time.RFC3339))
	}

	// Valid limit
	req, _ := http.NewRequest("GET", "/messages/search?q=match&limit=2", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handleSearchMessages(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
	var messages []map[string]interface{}
	json.Unmarshal(rec.Body.Bytes(), &messages)
	if len(messages) > 2 {
		t.Errorf("limit not applied, got %d results", len(messages))
	}

	// Limit over max (should clamp to 200)
	req, _ = http.NewRequest("GET", "/messages/search?q=match&limit=999", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec = httptest.NewRecorder()
	handleSearchMessages(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 for clamped limit, got %d", rec.Code)
	}

	// Invalid limit (should default to 50)
	req, _ = http.NewRequest("GET", "/messages/search?q=match&limit=abc", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec = httptest.NewRecorder()
	handleSearchMessages(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 for invalid limit, got %d", rec.Code)
	}
}

func TestCB40_SearchMessages_NoResults(t *testing.T) {
	cb40SetupDB(t)
	cb40SetupAuth(t)
	token := cb40RegisterAndLogin(t)

	req, _ := http.NewRequest("GET", "/messages/search?q=nonexistentterm", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handleSearchMessages(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
	var messages []map[string]interface{}
	json.Unmarshal(rec.Body.Bytes(), &messages)
	if len(messages) != 0 {
		t.Errorf("expected 0 results, got %d", len(messages))
	}
}

func TestCB40_SearchMessages_WrongMethod(t *testing.T) {
	cb40SetupDB(t)
	cb40SetupAuth(t)
	token := cb40RegisterAndLogin(t)

	req, _ := http.NewRequest("POST", "/messages/search?q=test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handleSearchMessages(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rec.Code)
	}
}

func TestCB40_SearchMessages_NoAuth(t *testing.T) {
	cb40SetupDB(t)
	cb40SetupAuth(t)

	req, _ := http.NewRequest("GET", "/messages/search?q=test", nil)
	rec := httptest.NewRecorder()
	handleSearchMessages(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rec.Code)
	}
}

// ==============================
// handleMarkRead tests
// ==============================

func TestCB40_MarkRead_Success(t *testing.T) {
	cb40SetupDB(t)
	cb40SetupAuth(t)
	token := cb40RegisterAndLogin(t)
	cb40RegisterAgent(t, "agent-mr-1", "test-agent-secret-cb40")
	convID := cb40CreateConversation(t, token, "agent-mr-1")

	// Store an unread agent message
	_, err := db.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, created_at) VALUES (?, ?, 'agent', 'agent-mr-1', 'unread message', ?)",
		"msg-mr-1", convID, time.Now().UTC().Format(time.RFC3339))
	if err != nil {
		t.Fatal(err)
	}

	form := strings.NewReader("conversation_id=" + convID)
	req, _ := http.NewRequest("POST", "/conversations/mark-read", form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handleMarkRead(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp map[string]interface{}
	json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp["status"] != "marked_read" {
		t.Errorf("expected status=marked_read, got %v", resp["status"])
	}
}

func TestCB40_MarkRead_WrongMethod(t *testing.T) {
	cb40SetupDB(t)
	cb40SetupAuth(t)
	token := cb40RegisterAndLogin(t)

	req, _ := http.NewRequest("GET", "/conversations/mark-read", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handleMarkRead(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rec.Code)
	}
}

func TestCB40_MarkRead_NoAuth(t *testing.T) {
	cb40SetupDB(t)
	cb40SetupAuth(t)

	req, _ := http.NewRequest("POST", "/conversations/mark-read", strings.NewReader("conversation_id=conv-1"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	handleMarkRead(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rec.Code)
	}
}

func TestCB40_MarkRead_MissingConvID(t *testing.T) {
	cb40SetupDB(t)
	cb40SetupAuth(t)
	token := cb40RegisterAndLogin(t)

	req, _ := http.NewRequest("POST", "/conversations/mark-read", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handleMarkRead(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rec.Code)
	}
}

func TestCB40_MarkRead_NotFound(t *testing.T) {
	cb40SetupDB(t)
	cb40SetupAuth(t)
	token := cb40RegisterAndLogin(t)

	form := strings.NewReader("conversation_id=nonexistent-conv")
	req, _ := http.NewRequest("POST", "/conversations/mark-read", form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handleMarkRead(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", rec.Code)
	}
}

func TestCB40_MarkRead_Unauthorized(t *testing.T) {
	cb40SetupDB(t)
	cb40SetupAuth(t)
	cb40RegisterAndLogin(t) // user1
	token2 := cb40GenToken(t, "user_other", "otheruser")
	cb40RegisterAgent(t, "agent-mr-2", "test-agent-secret-cb40")

	// Create conversation as user1
	form := strings.NewReader("agent_id=agent-mr-2")
	req, _ := http.NewRequest("POST", "/conversations/create", form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	token1 := cb40GenToken(t, "user_cb40", "cb40user")
	req.Header.Set("Authorization", "Bearer "+token1)
	rec := httptest.NewRecorder()
	handleCreateConversation(rec, req)
	var resp map[string]interface{}
	json.Unmarshal(rec.Body.Bytes(), &resp)
	convID, _ := resp["conversation_id"].(string)
	if convID == "" {
		t.Fatal("failed to create conversation")
	}

	// Try to mark read as different user
	form = strings.NewReader("conversation_id=" + convID)
	req, _ = http.NewRequest("POST", "/conversations/mark-read", form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token2)
	rec = httptest.NewRecorder()
	handleMarkRead(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for unauthorized user, got %d", rec.Code)
	}
}

// ==============================
// handleChangePassword tests
// ==============================

func TestCB40_ChangePassword_Success(t *testing.T) {
	cb40SetupDB(t)
	cb40SetupAuth(t)
	token := cb40RegisterAndLogin(t)

	form := strings.NewReader("old_password=cb40pass123&new_password=newpass456")
	req, _ := http.NewRequest("POST", "/auth/change-password", form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handleChangePassword(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp map[string]interface{}
	json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp["status"] != "password_changed" {
		t.Errorf("expected status=password_changed, got %v", resp["status"])
	}

	// Verify new password works
	form = strings.NewReader("username=cb40user&password=newpass456")
	req, _ = http.NewRequest("POST", "/auth/login", form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec = httptest.NewRecorder()
	handleLogin(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("login with new password failed: %d", rec.Code)
	}
}

func TestCB40_ChangePassword_WrongMethod(t *testing.T) {
	cb40SetupDB(t)
	cb40SetupAuth(t)
	token := cb40RegisterAndLogin(t)

	req, _ := http.NewRequest("GET", "/auth/change-password", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handleChangePassword(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rec.Code)
	}
}

func TestCB40_ChangePassword_NoAuth(t *testing.T) {
	cb40SetupDB(t)
	cb40SetupAuth(t)

	form := strings.NewReader("old_password=old&new_password=new")
	req, _ := http.NewRequest("POST", "/auth/change-password", form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	handleChangePassword(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rec.Code)
	}
}

func TestCB40_ChangePassword_MissingFields(t *testing.T) {
	cb40SetupDB(t)
	cb40SetupAuth(t)
	token := cb40RegisterAndLogin(t)

	form := strings.NewReader("old_password=cb40pass123")
	req, _ := http.NewRequest("POST", "/auth/change-password", form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handleChangePassword(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rec.Code)
	}
}

func TestCB40_ChangePassword_WrongOldPassword(t *testing.T) {
	cb40SetupDB(t)
	cb40SetupAuth(t)
	token := cb40RegisterAndLogin(t)

	form := strings.NewReader("old_password=wrongpass&new_password=newpass456")
	req, _ := http.NewRequest("POST", "/auth/change-password", form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handleChangePassword(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for wrong old password, got %d", rec.Code)
	}
}

func TestCB40_ChangePassword_ShortNewPassword(t *testing.T) {
	cb40SetupDB(t)
	cb40SetupAuth(t)
	token := cb40RegisterAndLogin(t)

	form := strings.NewReader("old_password=cb40pass123&new_password=abc")
	req, _ := http.NewRequest("POST", "/auth/change-password", form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handleChangePassword(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for short password, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestCB40_ChangePassword_UserNotFound(t *testing.T) {
	cb40SetupDB(t)
	cb40SetupAuth(t)
	// Create token for a user that doesn't exist in DB
	token := cb40GenToken(t, "nonexistent_user", "ghost")

	form := strings.NewReader("old_password=somepass&new_password=newpass456")
	req, _ := http.NewRequest("POST", "/auth/change-password", form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handleChangePassword(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("expected 404 for nonexistent user, got %d", rec.Code)
	}
}

// ==============================
// handleDeleteConversation tests
// ==============================

func TestCB40_DeleteConversation_Success(t *testing.T) {
	cb40SetupDB(t)
	cb40SetupAuth(t)
	token := cb40RegisterAndLogin(t)
	cb40RegisterAgent(t, "agent-del-1", "test-agent-secret-cb40")
	convID := cb40CreateConversation(t, token, "agent-del-1")

	req, _ := http.NewRequest("DELETE", "/conversations/delete?conversation_id="+convID, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handleDeleteConversation(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp map[string]interface{}
	json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp["status"] != "deleted" {
		t.Errorf("expected status=deleted, got %v", resp["status"])
	}

	// Verify conversation is gone
	conv, _ := getConversation(convID)
	if conv != nil {
		t.Error("conversation still exists after delete")
	}
}

func TestCB40_DeleteConversation_WrongMethod(t *testing.T) {
	cb40SetupDB(t)
	cb40SetupAuth(t)
	token := cb40RegisterAndLogin(t)

	req, _ := http.NewRequest("POST", "/conversations/delete?conversation_id=conv-1", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handleDeleteConversation(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rec.Code)
	}
}

func TestCB40_DeleteConversation_NoAuth(t *testing.T) {
	cb40SetupDB(t)
	cb40SetupAuth(t)

	req, _ := http.NewRequest("DELETE", "/conversations/delete?conversation_id=conv-1", nil)
	rec := httptest.NewRecorder()
	handleDeleteConversation(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rec.Code)
	}
}

func TestCB40_DeleteConversation_MissingID(t *testing.T) {
	cb40SetupDB(t)
	cb40SetupAuth(t)
	token := cb40RegisterAndLogin(t)

	req, _ := http.NewRequest("DELETE", "/conversations/delete", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handleDeleteConversation(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rec.Code)
	}
}

func TestCB40_DeleteConversation_NotFound(t *testing.T) {
	cb40SetupDB(t)
	cb40SetupAuth(t)
	token := cb40RegisterAndLogin(t)

	req, _ := http.NewRequest("DELETE", "/conversations/delete?conversation_id=nonexistent", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handleDeleteConversation(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", rec.Code)
	}
}

func TestCB40_DeleteConversation_Unauthorized(t *testing.T) {
	cb40SetupDB(t)
	cb40SetupAuth(t)
	// Create conversation as user1
	token1 := cb40GenToken(t, "user_cb40", "cb40user")
	cb40RegisterAgent(t, "agent-del-2", "test-agent-secret-cb40")
	convID := cb40CreateConversation(t, token1, "agent-del-2")

	// Try to delete as different user
	token2 := cb40GenToken(t, "user_other", "otheruser")
	req, _ := http.NewRequest("DELETE", "/conversations/delete?conversation_id="+convID, nil)
	req.Header.Set("Authorization", "Bearer "+token2)
	rec := httptest.NewRecorder()
	handleDeleteConversation(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for unauthorized, got %d", rec.Code)
	}
}

func TestCB40_DeleteConversation_ViaQueryParam(t *testing.T) {
	cb40SetupDB(t)
	cb40SetupAuth(t)
	token := cb40RegisterAndLogin(t)
	cb40RegisterAgent(t, "agent-del-3", "test-agent-secret-cb40")
	convID := cb40CreateConversation(t, token, "agent-del-3")

	// Use query param for DELETE (standard approach)
	req, _ := http.NewRequest("DELETE", "/conversations/delete?conversation_id="+convID, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handleDeleteConversation(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
}

// ==============================
// handleRegisterUser tests
// ==============================

func TestCB40_RegisterUser_Success(t *testing.T) {
	cb40SetupDB(t)
	cb40SetupAuth(t)

	form := strings.NewReader("username=newuser40&password=mypassword123")
	req, _ := http.NewRequest("POST", "/auth/user", form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	handleRegisterUser(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp map[string]interface{}
	json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp["status"] != "registered" {
		t.Errorf("expected status=registered, got %v", resp["status"])
	}
	if resp["user_id"] == "" {
		t.Error("expected user_id in response")
	}
}

func TestCB40_RegisterUser_WrongMethod(t *testing.T) {
	cb40SetupDB(t)
	cb40SetupAuth(t)

	req, _ := http.NewRequest("GET", "/auth/user", nil)
	rec := httptest.NewRecorder()
	handleRegisterUser(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rec.Code)
	}
}

func TestCB40_RegisterUser_MissingFields(t *testing.T) {
	cb40SetupDB(t)
	cb40SetupAuth(t)

	form := strings.NewReader("username=testuser")
	req, _ := http.NewRequest("POST", "/auth/user", form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	handleRegisterUser(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rec.Code)
	}
}

func TestCB40_RegisterUser_ShortUsername(t *testing.T) {
	cb40SetupDB(t)
	cb40SetupAuth(t)

	form := strings.NewReader("username=ab&password=mypassword123")
	req, _ := http.NewRequest("POST", "/auth/user", form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	handleRegisterUser(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for short username, got %d", rec.Code)
	}
}

func TestCB40_RegisterUser_BadCharsInUsername(t *testing.T) {
	cb40SetupDB(t)
	cb40SetupAuth(t)

	form := strings.NewReader("username=test@user!&password=mypassword123")
	req, _ := http.NewRequest("POST", "/auth/user", form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	handleRegisterUser(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for bad chars, got %d", rec.Code)
	}
}

func TestCB40_RegisterUser_DuplicateUsername(t *testing.T) {
	cb40SetupDB(t)
	cb40SetupAuth(t)

	// First registration
	form := strings.NewReader("username=dupuser&password=mypassword123")
	req, _ := http.NewRequest("POST", "/auth/user", form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	handleRegisterUser(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("first registration failed: %d", rec.Code)
	}

	// Second registration with same username
	form = strings.NewReader("username=dupuser&password=otherpassword")
	req, _ = http.NewRequest("POST", "/auth/user", form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec = httptest.NewRecorder()
	handleRegisterUser(rec, req)
	if rec.Code != http.StatusConflict {
		t.Errorf("expected 409 for duplicate, got %d", rec.Code)
	}
}

func TestCB40_RegisterUser_LongUsername(t *testing.T) {
	cb40SetupDB(t)
	cb40SetupAuth(t)

	longName := strings.Repeat("a", 51)
	form := strings.NewReader("username="+longName+"&password=mypassword123")
	req, _ := http.NewRequest("POST", "/auth/user", form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	handleRegisterUser(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for long username, got %d", rec.Code)
	}
}

func TestCB40_RegisterUser_UnderscoreAllowed(t *testing.T) {
	cb40SetupDB(t)
	cb40SetupAuth(t)

	form := strings.NewReader("username=test_user_123&password=mypassword123")
	req, _ := http.NewRequest("POST", "/auth/user", form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	handleRegisterUser(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 for valid username with underscore, got %d: %s", rec.Code, rec.Body.String())
	}
}

// ==============================
// handleRegisterAgent tests
// ==============================

func TestCB40_RegisterAgent_Success(t *testing.T) {
	cb40SetupDB(t)
	_, agentSec := cb40SetupAuth(t)

	form := strings.NewReader("agent_id=agent-test-40&name=TestAgent&model=gpt-4&personality=friendly&specialty=general")
	req, _ := http.NewRequest("POST", "/auth/agent", form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Agent-Secret", agentSec)
	rec := httptest.NewRecorder()
	handleRegisterAgent(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp map[string]interface{}
	json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp["status"] != "registered" {
		t.Errorf("expected status=registered, got %v", resp["status"])
	}
	if resp["model"] != "gpt-4" {
		t.Errorf("expected model=gpt-4, got %v", resp["model"])
	}
}

func TestCB40_RegisterAgent_WrongMethod(t *testing.T) {
	cb40SetupDB(t)
	_, agentSec := cb40SetupAuth(t)

	req, _ := http.NewRequest("GET", "/auth/agent", nil)
	req.Header.Set("X-Agent-Secret", agentSec)
	rec := httptest.NewRecorder()
	handleRegisterAgent(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rec.Code)
	}
}

func TestCB40_RegisterAgent_NoSecret(t *testing.T) {
	cb40SetupDB(t)
	cb40SetupAuth(t)

	form := strings.NewReader("agent_id=agent-no-secret&name=Test")
	req, _ := http.NewRequest("POST", "/auth/agent", form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	handleRegisterAgent(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rec.Code)
	}
}

func TestCB40_RegisterAgent_BadSecret(t *testing.T) {
	cb40SetupDB(t)
	cb40SetupAuth(t)

	form := strings.NewReader("agent_id=agent-bad-secret&name=Test")
	req, _ := http.NewRequest("POST", "/auth/agent", form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Agent-Secret", "wrong-secret")
	rec := httptest.NewRecorder()
	handleRegisterAgent(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rec.Code)
	}
}

func TestCB40_RegisterAgent_MissingAgentID(t *testing.T) {
	cb40SetupDB(t)
	_, agentSec := cb40SetupAuth(t)

	form := strings.NewReader("name=Test&model=gpt-4")
	req, _ := http.NewRequest("POST", "/auth/agent", form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Agent-Secret", agentSec)
	rec := httptest.NewRecorder()
	handleRegisterAgent(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rec.Code)
	}
}

func TestCB40_RegisterAgent_FormSecret(t *testing.T) {
	cb40SetupDB(t)
	_, agentSec := cb40SetupAuth(t)

	// Secret via form field instead of header
	form := strings.NewReader("agent_id=agent-form-secret&name=TestAgent&agent_secret="+agentSec)
	req, _ := http.NewRequest("POST", "/auth/agent", form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	handleRegisterAgent(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 with form secret, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestCB40_RegisterAgent_DefaultName(t *testing.T) {
	cb40SetupDB(t)
	_, agentSec := cb40SetupAuth(t)

	// No name provided, should default to agent_id
	form := strings.NewReader("agent_id=agent-no-name")
	req, _ := http.NewRequest("POST", "/auth/agent", form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Agent-Secret", agentSec)
	rec := httptest.NewRecorder()
	handleRegisterAgent(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp map[string]interface{}
	json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp["agent_id"] != "agent-no-name" {
		t.Errorf("expected agent_id=agent-no-name, got %v", resp["agent_id"])
	}
}

func TestCB40_RegisterAgent_UpdateExisting(t *testing.T) {
	cb40SetupDB(t)
	_, agentSec := cb40SetupAuth(t)

	// First registration
	form := strings.NewReader("agent_id=agent-update&name=OriginalName&model=gpt-3.5")
	req, _ := http.NewRequest("POST", "/auth/agent", form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Agent-Secret", agentSec)
	rec := httptest.NewRecorder()
	handleRegisterAgent(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("first registration failed: %d", rec.Code)
	}

	// Update with new metadata
	form = strings.NewReader("agent_id=agent-update&name=UpdatedName&model=gpt-4&personality=serious")
	req, _ = http.NewRequest("POST", "/auth/agent", form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Agent-Secret", agentSec)
	rec = httptest.NewRecorder()
	handleRegisterAgent(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 on update, got %d", rec.Code)
	}
	var resp map[string]interface{}
	json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp["model"] != "gpt-4" {
		t.Errorf("expected updated model=gpt-4, got %v", resp["model"])
	}
}

// ==============================
// handleLogin tests
// ==============================

func TestCB40_Login_WrongMethod(t *testing.T) {
	cb40SetupDB(t)
	cb40SetupAuth(t)

	req, _ := http.NewRequest("GET", "/auth/login", nil)
	rec := httptest.NewRecorder()
	handleLogin(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rec.Code)
	}
}

func TestCB40_Login_MissingFields(t *testing.T) {
	cb40SetupDB(t)
	cb40SetupAuth(t)

	form := strings.NewReader("username=testuser")
	req, _ := http.NewRequest("POST", "/auth/login", form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	handleLogin(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rec.Code)
	}
}

func TestCB40_Login_BadUsername(t *testing.T) {
	cb40SetupDB(t)
	cb40SetupAuth(t)

	form := strings.NewReader("username=nonexistentuser&password=somepass")
	req, _ := http.NewRequest("POST", "/auth/login", form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	handleLogin(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for bad username, got %d", rec.Code)
	}
}

func TestCB40_Login_WrongPassword(t *testing.T) {
	cb40SetupDB(t)
	cb40SetupAuth(t)
	cb40RegisterAndLogin(t)

	form := strings.NewReader("username=cb40user&password=wrongpassword")
	req, _ := http.NewRequest("POST", "/auth/login", form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	handleLogin(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for wrong password, got %d", rec.Code)
	}
}

func TestCB40_Login_Success(t *testing.T) {
	cb40SetupDB(t)
	cb40SetupAuth(t)

	// Register user first
	form := strings.NewReader("username=loginuser40&password=mypass123")
	req, _ := http.NewRequest("POST", "/auth/user", form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	handleRegisterUser(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("register failed: %d", rec.Code)
	}

	// Login
	form = strings.NewReader("username=loginuser40&password=mypass123")
	req, _ = http.NewRequest("POST", "/auth/login", form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec = httptest.NewRecorder()
	handleLogin(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp map[string]interface{}
	json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp["token"] == "" || resp["token"] == nil {
		t.Error("expected token in response")
	}
}

// ==============================
// handleHealth tests
// ==============================

func TestCB40_Health_DBError(t *testing.T) {
	cb40SetupDB(t)
	cb40SetupAuth(t)

	// Close DB to cause Ping error
	db.Close()

	req, _ := http.NewRequest("GET", "/health", nil)
	rec := httptest.NewRecorder()
	handleHealth(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 even with DB error, got %d", rec.Code)
	}
	var resp map[string]interface{}
	json.Unmarshal(rec.Body.Bytes(), &resp)
	dbStatus, _ := resp["db"].(string)
	if dbStatus == "ok" {
		t.Error("expected db status to show error, got 'ok'")
	}
}

func TestCB40_Health_NilDB(t *testing.T) {
	cb40SetupDB(t)
	cb40SetupAuth(t)

	// Set db to nil
	origDB := db
	db = nil
	t.Cleanup(func() { db = origDB })

	req, _ := http.NewRequest("GET", "/health", nil)
	rec := httptest.NewRecorder()
	handleHealth(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
	var resp map[string]interface{}
	json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp["db"] != "not initialized" {
		t.Errorf("expected 'not initialized', got %v", resp["db"])
	}
}

func TestCB40_Health_WrongMethod(t *testing.T) {
	cb40SetupDB(t)
	cb40SetupAuth(t)

	req, _ := http.NewRequest("POST", "/health", nil)
	rec := httptest.NewRecorder()
	handleHealth(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rec.Code)
	}
}

// ==============================
// handleUploadPublicKey tests
// ==============================

func TestCB40_UploadPublicKey_Success(t *testing.T) {
	cb40SetupDB(t)
	cb40SetupAuth(t)
	token := cb40RegisterAndLogin(t)

	body := `{"key_type":"identity","public_key":"base64pubkey123","signature":"base64sig"}`
	req, _ := http.NewRequest("POST", "/keys/upload", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handleUploadPublicKey(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp map[string]interface{}
	json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp["key_type"] != "identity" {
		t.Errorf("expected key_type=identity, got %v", resp["key_type"])
	}
	if resp["public_key"] != "base64pubkey123" {
		t.Errorf("expected public_key=base64pubkey123, got %v", resp["public_key"])
	}
}

func TestCB40_UploadPublicKey_WrongMethod(t *testing.T) {
	cb40SetupDB(t)
	cb40SetupAuth(t)
	token := cb40RegisterAndLogin(t)

	req, _ := http.NewRequest("GET", "/keys/upload", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handleUploadPublicKey(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rec.Code)
	}
}

func TestCB40_UploadPublicKey_NoAuth(t *testing.T) {
	cb40SetupDB(t)
	cb40SetupAuth(t)

	body := `{"key_type":"identity","public_key":"base64pubkey"}`
	req, _ := http.NewRequest("POST", "/keys/upload", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handleUploadPublicKey(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rec.Code)
	}
}

func TestCB40_UploadPublicKey_InvalidJSON(t *testing.T) {
	cb40SetupDB(t)
	cb40SetupAuth(t)
	token := cb40RegisterAndLogin(t)

	req, _ := http.NewRequest("POST", "/keys/upload", strings.NewReader("invalid json"))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handleUploadPublicKey(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rec.Code)
	}
}

func TestCB40_UploadPublicKey_MissingPublicKey(t *testing.T) {
	cb40SetupDB(t)
	cb40SetupAuth(t)
	token := cb40RegisterAndLogin(t)

	body := `{"key_type":"identity"}`
	req, _ := http.NewRequest("POST", "/keys/upload", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handleUploadPublicKey(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rec.Code)
	}
}

func TestCB40_UploadPublicKey_InvalidKeyType(t *testing.T) {
	cb40SetupDB(t)
	cb40SetupAuth(t)
	token := cb40RegisterAndLogin(t)

	body := `{"key_type":"invalid_type","public_key":"base64key"}`
	req, _ := http.NewRequest("POST", "/keys/upload", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handleUploadPublicKey(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid key_type, got %d", rec.Code)
	}
}

func TestCB40_UploadPublicKey_SignedPreKey(t *testing.T) {
	cb40SetupDB(t)
	cb40SetupAuth(t)
	token := cb40RegisterAndLogin(t)

	body := `{"key_type":"signed_prekey","public_key":"base64spk","signature":"base64sig"}`
	req, _ := http.NewRequest("POST", "/keys/upload", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handleUploadPublicKey(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestCB40_UploadPublicKey_OneTimePreKey(t *testing.T) {
	cb40SetupDB(t)
	cb40SetupAuth(t)
	token := cb40RegisterAndLogin(t)

	body := `{"key_type":"one_time_prekey","public_key":"base64otpk","key_id":1}`
	req, _ := http.NewRequest("POST", "/keys/upload", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handleUploadPublicKey(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestCB40_UploadPublicKey_IdentityReplace(t *testing.T) {
	cb40SetupDB(t)
	cb40SetupAuth(t)
	token := cb40RegisterAndLogin(t)

	// Upload identity key
	body := `{"key_type":"identity","public_key":"original_key"}`
	req, _ := http.NewRequest("POST", "/keys/upload", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handleUploadPublicKey(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("first upload failed: %d", rec.Code)
	}

	// Upload new identity key (should replace)
	body = `{"key_type":"identity","public_key":"replacement_key"}`
	req, _ = http.NewRequest("POST", "/keys/upload", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	handleUploadPublicKey(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 on replace, got %d", rec.Code)
	}

	// Verify only one identity key exists
	var count int
	userID := "user_cb40" // the registered user's ID prefix
	db.QueryRow("SELECT COUNT(*) FROM key_bundles WHERE owner_type = 'user' AND key_type = 'identity' AND public_key = 'original_key'").Scan(&count)
	if count > 0 {
		// The original key should have been deleted. But userID might differ.
		// Let's check by public_key instead
		db.QueryRow("SELECT COUNT(*) FROM key_bundles WHERE key_type = 'identity' AND public_key = 'original_key'").Scan(&count)
		if count > 0 {
			t.Errorf("original identity key should have been deleted, found %d", count)
		}
	}
	_ = userID
}

func TestCB40_UploadPublicKey_AgentAuth(t *testing.T) {
	cb40SetupDB(t)
	_, agentSec := cb40SetupAuth(t)

	body := `{"key_type":"identity","public_key":"agent_pubkey"}`
	req, _ := http.NewRequest("POST", "/keys/upload", strings.NewReader(body))
	req.Header.Set("X-Agent-Secret", agentSec)
	req.Header.Set("X-Agent-ID", "agent-key-1")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handleUploadPublicKey(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 with agent auth, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp map[string]interface{}
	json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp["owner_type"] != "agent" {
		t.Errorf("expected owner_type=agent, got %v", resp["owner_type"])
	}
}

// ==============================
// handleGetKeyBundle tests
// ==============================

func TestCB40_GetKeyBundle_FullBundle(t *testing.T) {
	cb40SetupDB(t)
	cb40SetupAuth(t)
	token := cb40RegisterAndLogin(t)

	// Upload identity, signed pre-key, and one-time pre-key
	bodies := []string{
		`{"key_type":"identity","public_key":"id_key_1"}`,
		`{"key_type":"signed_prekey","public_key":"spk_key_1","signature":"spk_sig"}`,
		`{"key_type":"one_time_prekey","public_key":"otpk_key_1","key_id":1}`,
	}
	for _, b := range bodies {
		req, _ := http.NewRequest("POST", "/keys/upload", strings.NewReader(b))
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		handleUploadPublicKey(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("upload failed: %d %s", rec.Code, rec.Body.String())
		}
	}

	// Get the user ID from token
	claims, _ := ValidateJWT(token)

	// Fetch key bundle
	req, _ := http.NewRequest("GET", "/keys/bundle?owner_id="+claims.UserID+"&owner_type=user", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handleGetKeyBundle(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var bundle map[string]interface{}
	json.Unmarshal(rec.Body.Bytes(), &bundle)
	if bundle["identity_key"] == nil {
		t.Error("expected identity_key in bundle")
	}
	if bundle["signed_prekey"] == nil {
		t.Error("expected signed_prekey in bundle")
	}
	if bundle["one_time_prekey"] == nil {
		t.Error("expected one_time_prekey in bundle")
	}
}

func TestCB40_GetKeyBundle_OTPKConsumed(t *testing.T) {
	cb40SetupDB(t)
	cb40SetupAuth(t)
	token := cb40RegisterAndLogin(t)

	// Upload identity and one-time pre-key
	bodies := []string{
		`{"key_type":"identity","public_key":"id_key_2"}`,
		`{"key_type":"one_time_prekey","public_key":"otpk_key_2","key_id":1}`,
	}
	for _, b := range bodies {
		req, _ := http.NewRequest("POST", "/keys/upload", strings.NewReader(b))
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		handleUploadPublicKey(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("upload failed: %d", rec.Code)
		}
	}

	claims, _ := ValidateJWT(token)

	// First fetch - should get the one-time pre-key
	req, _ := http.NewRequest("GET", "/keys/bundle?owner_id="+claims.UserID+"&owner_type=user", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handleGetKeyBundle(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("first fetch failed: %d", rec.Code)
	}
	var bundle map[string]interface{}
	json.Unmarshal(rec.Body.Bytes(), &bundle)
	if bundle["one_time_prekey"] == nil {
		t.Error("expected one_time_prekey on first fetch")
	}

	// Second fetch - one-time pre-key should be consumed (deleted)
	req, _ = http.NewRequest("GET", "/keys/bundle?owner_id="+claims.UserID+"&owner_type=user", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec = httptest.NewRecorder()
	handleGetKeyBundle(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("second fetch failed: %d", rec.Code)
	}
	bundle = map[string]interface{}{}
	json.Unmarshal(rec.Body.Bytes(), &bundle)
	if bundle["one_time_prekey"] != nil {
		t.Error("one_time_prekey should have been consumed")
	}
}

func TestCB40_GetKeyBundle_NoAuth(t *testing.T) {
	cb40SetupDB(t)
	cb40SetupAuth(t)

	req, _ := http.NewRequest("GET", "/keys/bundle?owner_id=someuser&owner_type=user", nil)
	rec := httptest.NewRecorder()
	handleGetKeyBundle(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rec.Code)
	}
}

func TestCB40_GetKeyBundle_MissingOwnerID(t *testing.T) {
	cb40SetupDB(t)
	cb40SetupAuth(t)
	token := cb40RegisterAndLogin(t)

	req, _ := http.NewRequest("GET", "/keys/bundle", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handleGetKeyBundle(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rec.Code)
	}
}

func TestCB40_GetKeyBundle_NotFound(t *testing.T) {
	cb40SetupDB(t)
	cb40SetupAuth(t)
	token := cb40RegisterAndLogin(t)

	req, _ := http.NewRequest("GET", "/keys/bundle?owner_id=nonexistent&owner_type=user", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handleGetKeyBundle(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", rec.Code)
	}
}

func TestCB40_GetKeyBundle_WrongMethod(t *testing.T) {
	cb40SetupDB(t)
	cb40SetupAuth(t)
	token := cb40RegisterAndLogin(t)

	req, _ := http.NewRequest("POST", "/keys/bundle?owner_id=some&owner_type=user", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handleGetKeyBundle(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rec.Code)
	}
}

func TestCB40_GetKeyBundle_DefaultOwnerType(t *testing.T) {
	cb40SetupDB(t)
	cb40SetupAuth(t)
	token := cb40RegisterAndLogin(t)

	// Upload identity key
	body := `{"key_type":"identity","public_key":"id_key_default"}`
	req, _ := http.NewRequest("POST", "/keys/upload", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handleUploadPublicKey(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("upload failed: %d", rec.Code)
	}

	claims, _ := ValidateJWT(token)

	// Fetch without owner_type (should default to "user")
	req, _ = http.NewRequest("GET", "/keys/bundle?owner_id="+claims.UserID, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec = httptest.NewRecorder()
	handleGetKeyBundle(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 with default owner_type, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestCB40_GetKeyBundle_AgentAuth(t *testing.T) {
	cb40SetupDB(t)
	_, agentSec := cb40SetupAuth(t)

	// Agent uploads identity key
	body := `{"key_type":"identity","public_key":"agent_id_key"}`
	req, _ := http.NewRequest("POST", "/keys/upload", strings.NewReader(body))
	req.Header.Set("X-Agent-Secret", agentSec)
	req.Header.Set("X-Agent-ID", "agent-bundle-1")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handleUploadPublicKey(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("agent upload failed: %d", rec.Code)
	}

	// Fetch bundle for agent
	req, _ = http.NewRequest("GET", "/keys/bundle?owner_id=agent-bundle-1&owner_type=agent", nil)
	req.Header.Set("X-Agent-Secret", agentSec)
	req.Header.Set("X-Agent-ID", "agent-bundle-1")
	rec = httptest.NewRecorder()
	handleGetKeyBundle(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var bundle map[string]interface{}
	json.Unmarshal(rec.Body.Bytes(), &bundle)
	if bundle["identity_key"] == nil {
		t.Error("expected identity_key in agent bundle")
	}
}

func TestCB40_GetKeyBundle_IdentityOnly(t *testing.T) {
	cb40SetupDB(t)
	cb40SetupAuth(t)
	token := cb40RegisterAndLogin(t)

	// Upload only identity key
	body := `{"key_type":"identity","public_key":"id_only_key"}`
	req, _ := http.NewRequest("POST", "/keys/upload", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handleUploadPublicKey(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("upload failed: %d", rec.Code)
	}

	claims, _ := ValidateJWT(token)

	// Fetch bundle - should have identity but no signed_prekey or one_time_prekey
	req, _ = http.NewRequest("GET", "/keys/bundle?owner_id="+claims.UserID+"&owner_type=user", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec = httptest.NewRecorder()
	handleGetKeyBundle(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
	var bundle map[string]interface{}
	json.Unmarshal(rec.Body.Bytes(), &bundle)
	if bundle["identity_key"] == nil {
		t.Error("expected identity_key")
	}
	if bundle["signed_prekey"] != nil {
		t.Error("should not have signed_prekey")
	}
	if bundle["one_time_prekey"] != nil {
		t.Error("should not have one_time_prekey")
	}
}

// ==============================
// handleStoreEncryptedMessage tests
// ==============================

func TestCB40_StoreEncryptedMessage_DBError(t *testing.T) {
	cb40SetupDB(t)
	cb40SetupAuth(t)
	token := cb40RegisterAndLogin(t)
	cb40RegisterAgent(t, "agent-enc-db", "test-agent-secret-cb40")
	convID := cb40CreateConversation(t, token, "agent-enc-db")

	// Drop encrypted_messages table to cause DB error
	db.Exec("DROP TABLE encrypted_messages")

	body := `{"conversation_id":"` + convID + `","ciphertext":"enc_data","iv":"iv_data","algorithm":"aes-256-gcm"}`
	req, _ := http.NewRequest("POST", "/messages/encrypted", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handleStoreEncryptedMessage(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestCB40_StoreEncryptedMessage_AgentSenderDBError(t *testing.T) {
	cb40SetupDB(t)
	_, agentSec := cb40SetupAuth(t)
	token := cb40RegisterAndLogin(t)
	cb40RegisterAgent(t, "agent-enc-db2", "test-agent-secret-cb40")
	convID := cb40CreateConversation(t, token, "agent-enc-db2")

	// Drop table
	db.Exec("DROP TABLE encrypted_messages")

	body := `{"conversation_id":"` + convID + `","ciphertext":"enc_data","iv":"iv_data","algorithm":"x25519-aes-256-gcm"}`
	req, _ := http.NewRequest("POST", "/messages/encrypted", strings.NewReader(body))
	req.Header.Set("X-Agent-Secret", agentSec)
	req.Header.Set("X-Agent-ID", "agent-enc-db2")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handleStoreEncryptedMessage(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", rec.Code)
	}
}

// ==============================
// handleGetEncryptedMessages tests
// ==============================

func TestCB40_GetEncryptedMessages_DBQueryError(t *testing.T) {
	cb40SetupDB(t)
	cb40SetupAuth(t)
	token := cb40RegisterAndLogin(t)
	cb40RegisterAgent(t, "agent-enc-q", "test-agent-secret-cb40")
	convID := cb40CreateConversation(t, token, "agent-enc-q")

	// Drop table to cause query error
	db.Exec("DROP TABLE encrypted_messages")

	req, _ := http.NewRequest("GET", "/messages/encrypted?conversation_id="+convID, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handleGetEncryptedMessages(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestCB40_GetEncryptedMessages_AgentNotParticipant(t *testing.T) {
	cb40SetupDB(t)
	_, agentSec := cb40SetupAuth(t)
	token := cb40RegisterAndLogin(t)
	cb40RegisterAgent(t, "agent-enc-p1", "test-agent-secret-cb40")
	cb40RegisterAgent(t, "agent-enc-p2", "test-agent-secret-cb40")
	convID := cb40CreateConversation(t, token, "agent-enc-p1")

	// Try to get as wrong agent
	req, _ := http.NewRequest("GET", "/messages/encrypted?conversation_id="+convID, nil)
	req.Header.Set("X-Agent-Secret", agentSec)
	req.Header.Set("X-Agent-ID", "agent-enc-p2")
	rec := httptest.NewRecorder()
	handleGetEncryptedMessages(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("expected 404 for agent not participant, got %d", rec.Code)
	}
}

// ==============================
// Queue persist tests
// ==============================

func TestCB40_LoadQueueFromDB_ScanError(t *testing.T) {
	cb40SetupDB(t)
	cb40SetupAuth(t)

	// Insert a row with invalid data type to cause scan error
	// The scan expects: recipient (string), data ([]byte), queued_at (string)
	// Insert NULL for recipient to cause scan error
	db.Exec("INSERT INTO offline_queue (id, recipient, data, queued_at, sent_count) VALUES (1, NULL, ?, ?, 0)",
		[]byte("test data"), time.Now().UTC().Format(time.RFC3339))

	q := newOfflineQueue(100, 7*24*time.Hour)

	// This should trigger the scan error path (rows.Scan fails)
	// but continue processing
	loadQueueFromDB(db, q)

	// Queue should be empty since the scan failed
	if q.TotalDepth() != 0 {
		t.Errorf("expected 0 messages after scan error, got %d", q.TotalDepth())
	}
}

func TestCB40_CleanStaleQueueMessages_DBError(t *testing.T) {
	cb40SetupDB(t)
	cb40SetupAuth(t)

	// Drop the table to cause error
	db.Exec("DROP TABLE offline_queue")

	// Should not panic
	cleanStaleQueueMessages(db, 24*time.Hour)
	// If we get here without panic, the test passes
}

func TestCB40_InitQueueDB_Error(t *testing.T) {
	var err error
	db, err = sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })

	// Close the DB to cause error
	db.Close()

	// Should not panic
	initQueueDB(db)
	// If we get here without panic, the test passes
}

func TestCB40_LoadQueueFromDB_WithMessages(t *testing.T) {
	cb40SetupDB(t)
	cb40SetupAuth(t)

	// Insert some messages
	for i := 0; i < 3; i++ {
		db.Exec("INSERT INTO offline_queue (recipient, data, queued_at, sent_count) VALUES (?, ?, ?, 0)",
			"user-load-test", []byte("data-"+string(rune('1'+i))), time.Now().UTC().Format(time.RFC3339))
	}

	q := newOfflineQueue(100, 7*24*time.Hour)

	loadQueueFromDB(db, q)

	if q.TotalDepth() != 3 {
		t.Errorf("expected 3 messages loaded, got %d", q.TotalDepth())
	}
}

func TestCB40_CleanStaleQueueMessages_DeletesOld(t *testing.T) {
	cb40SetupDB(t)
	cb40SetupAuth(t)

	// Insert an old message (2 days ago)
	oldTime := time.Now().UTC().Add(-48 * time.Hour).Format(time.RFC3339)
	db.Exec("INSERT INTO offline_queue (recipient, data, queued_at, sent_count) VALUES (?, ?, ?, 0)",
		"user-clean-test", []byte("old data"), oldTime)

	// Insert a recent message
	db.Exec("INSERT INTO offline_queue (recipient, data, queued_at, sent_count) VALUES (?, ?, ?, 0)",
		"user-clean-test", []byte("new data"), time.Now().UTC().Format(time.RFC3339))

	// Clean messages older than 24 hours
	cleanStaleQueueMessages(db, 24*time.Hour)

	// Verify old message deleted, new message remains
	var count int
	db.QueryRow("SELECT COUNT(*) FROM offline_queue WHERE recipient = ? AND data = ?",
		"user-clean-test", []byte("old data")).Scan(&count)
	if count != 0 {
		t.Errorf("expected old message to be deleted, found %d", count)
	}
	db.QueryRow("SELECT COUNT(*) FROM offline_queue WHERE recipient = ? AND data = ?",
		"user-clean-test", []byte("new data")).Scan(&count)
	if count != 1 {
		t.Errorf("expected recent message to remain, found %d", count)
	}
}

// ==============================
// handleGetMessages tests
// ==============================

func TestCB40_GetMessages_Success(t *testing.T) {
	cb40SetupDB(t)
	cb40SetupAuth(t)
	token := cb40RegisterAndLogin(t)
	cb40RegisterAgent(t, "agent-gm-1", "test-agent-secret-cb40")
	convID := cb40CreateConversation(t, token, "agent-gm-1")

	// Store messages
	db.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, created_at) VALUES (?, ?, 'agent', 'agent-gm-1', 'msg1', ?)",
		"msg-gm-1", convID, time.Now().UTC().Format(time.RFC3339))
	db.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, created_at) VALUES (?, ?, 'user', 'user_cb40', 'msg2', ?)",
		"msg-gm-2", convID, time.Now().UTC().Format(time.RFC3339))

	req, _ := http.NewRequest("GET", "/conversations/messages?conversation_id="+convID, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handleGetMessages(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var messages []map[string]interface{}
	json.Unmarshal(rec.Body.Bytes(), &messages)
	if len(messages) != 2 {
		t.Errorf("expected 2 messages, got %d", len(messages))
	}
}

func TestCB40_GetMessages_WrongMethod(t *testing.T) {
	cb40SetupDB(t)
	cb40SetupAuth(t)
	token := cb40RegisterAndLogin(t)

	req, _ := http.NewRequest("POST", "/conversations/messages?conversation_id=conv-1", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handleGetMessages(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rec.Code)
	}
}

func TestCB40_GetMessages_MissingConvID(t *testing.T) {
	cb40SetupDB(t)
	cb40SetupAuth(t)
	token := cb40RegisterAndLogin(t)

	req, _ := http.NewRequest("GET", "/conversations/messages", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handleGetMessages(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rec.Code)
	}
}

func TestCB40_GetMessages_NotFound(t *testing.T) {
	cb40SetupDB(t)
	cb40SetupAuth(t)
	token := cb40RegisterAndLogin(t)

	req, _ := http.NewRequest("GET", "/conversations/messages?conversation_id=nonexistent", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handleGetMessages(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", rec.Code)
	}
}

func TestCB40_GetMessages_Unauthorized(t *testing.T) {
	cb40SetupDB(t)
	cb40SetupAuth(t)
	token1 := cb40GenToken(t, "user_cb40", "cb40user")
	cb40RegisterAgent(t, "agent-gm-2", "test-agent-secret-cb40")
	convID := cb40CreateConversation(t, token1, "agent-gm-2")

	// Try to access as different user
	token2 := cb40GenToken(t, "user_other", "other")
	req, _ := http.NewRequest("GET", "/conversations/messages?conversation_id="+convID, nil)
	req.Header.Set("Authorization", "Bearer "+token2)
	rec := httptest.NewRecorder()
	handleGetMessages(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rec.Code)
	}
}

func TestCB40_GetMessages_WithLimit(t *testing.T) {
	cb40SetupDB(t)
	cb40SetupAuth(t)
	token := cb40RegisterAndLogin(t)
	cb40RegisterAgent(t, "agent-gm-3", "test-agent-secret-cb40")
	convID := cb40CreateConversation(t, token, "agent-gm-3")

	// Store 5 messages
	for i := 0; i < 5; i++ {
		db.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, created_at) VALUES (?, ?, 'agent', 'agent-gm-3', ?, ?)",
			"msg-gm-l-"+string(rune('1'+i)), convID, "msg"+string(rune('1'+i)), time.Now().UTC().Format(time.RFC3339))
	}

	req, _ := http.NewRequest("GET", "/conversations/messages?conversation_id="+convID+"&limit=2", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handleGetMessages(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
	var messages []map[string]interface{}
	json.Unmarshal(rec.Body.Bytes(), &messages)
	if len(messages) > 2 {
		t.Errorf("expected at most 2 messages with limit, got %d", len(messages))
	}
}

// ==============================
// handleListConversations tests
// ==============================

func TestCB40_ListConversations_Success(t *testing.T) {
	cb40SetupDB(t)
	cb40SetupAuth(t)
	token := cb40RegisterAndLogin(t)
	cb40RegisterAgent(t, "agent-lc-1", "test-agent-secret-cb40")
	cb40RegisterAgent(t, "agent-lc-2", "test-agent-secret-cb40")

	cb40CreateConversation(t, token, "agent-lc-1")
	cb40CreateConversation(t, token, "agent-lc-2")

	req, _ := http.NewRequest("GET", "/conversations/list", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handleListConversations(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var conversations []map[string]interface{}
	json.Unmarshal(rec.Body.Bytes(), &conversations)
	if len(conversations) != 2 {
		t.Errorf("expected 2 conversations, got %d", len(conversations))
	}
}

func TestCB40_ListConversations_Empty(t *testing.T) {
	cb40SetupDB(t)
	cb40SetupAuth(t)
	token := cb40RegisterAndLogin(t)

	req, _ := http.NewRequest("GET", "/conversations/list", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handleListConversations(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
	var conversations []map[string]interface{}
	json.Unmarshal(rec.Body.Bytes(), &conversations)
	if len(conversations) != 0 {
		t.Errorf("expected 0 conversations, got %d", len(conversations))
	}
}

func TestCB40_ListConversations_WrongMethod(t *testing.T) {
	cb40SetupDB(t)
	cb40SetupAuth(t)
	token := cb40RegisterAndLogin(t)

	req, _ := http.NewRequest("POST", "/conversations/list", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handleListConversations(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rec.Code)
	}
}

// ==============================
// Additional E2E tests
// ==============================

func TestCB40_StoreEncryptedMessage_ChaChaAlgorithm(t *testing.T) {
	cb40SetupDB(t)
	cb40SetupAuth(t)
	token := cb40RegisterAndLogin(t)
	cb40RegisterAgent(t, "agent-enc-chacha", "test-agent-secret-cb40")
	convID := cb40CreateConversation(t, token, "agent-enc-chacha")

	body := `{"conversation_id":"` + convID + `","ciphertext":"enc_data","iv":"iv_data","algorithm":"x25519-chacha20-poly1305","sender_key_id":"key-1"}`
	req, _ := http.NewRequest("POST", "/messages/encrypted", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handleStoreEncryptedMessage(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestCB40_GetEncryptedMessages_SuccessWithMessages(t *testing.T) {
	cb40SetupDB(t)
	cb40SetupAuth(t)
	token := cb40RegisterAndLogin(t)
	cb40RegisterAgent(t, "agent-enc-get", "test-agent-secret-cb40")
	convID := cb40CreateConversation(t, token, "agent-enc-get")

	// Store encrypted message
	body := `{"conversation_id":"` + convID + `","ciphertext":"enc1","iv":"iv1","algorithm":"aes-256-gcm"}`
	req, _ := http.NewRequest("POST", "/messages/encrypted", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handleStoreEncryptedMessage(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("store failed: %d", rec.Code)
	}

	// Retrieve encrypted messages
	req, _ = http.NewRequest("GET", "/messages/encrypted?conversation_id="+convID, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec = httptest.NewRecorder()
	handleGetEncryptedMessages(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var messages []map[string]interface{}
	json.Unmarshal(rec.Body.Bytes(), &messages)
	if len(messages) != 1 {
		t.Errorf("expected 1 message, got %d", len(messages))
	}
}

func TestCB40_GetEncryptedMessages_LimitParsing(t *testing.T) {
	cb40SetupDB(t)
	cb40SetupAuth(t)
	token := cb40RegisterAndLogin(t)
	cb40RegisterAgent(t, "agent-enc-lp", "test-agent-secret-cb40")
	convID := cb40CreateConversation(t, token, "agent-enc-lp")

	// Store 3 encrypted messages
	for i := 0; i < 3; i++ {
		body := `{"conversation_id":"` + convID + `","ciphertext":"enc` + string(rune('1'+i)) + `","iv":"iv","algorithm":"aes-256-gcm"}`
		req, _ := http.NewRequest("POST", "/messages/encrypted", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		handleStoreEncryptedMessage(rec, req)
	}

	// Get with limit=2
	req, _ := http.NewRequest("GET", "/messages/encrypted?conversation_id="+convID+"&limit=2", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handleGetEncryptedMessages(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
	var messages []map[string]interface{}
	json.Unmarshal(rec.Body.Bytes(), &messages)
	if len(messages) > 2 {
		t.Errorf("expected at most 2 messages, got %d", len(messages))
	}

	// Get with invalid limit (should default to 50)
	req, _ = http.NewRequest("GET", "/messages/encrypted?conversation_id="+convID+"&limit=abc", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec = httptest.NewRecorder()
	handleGetEncryptedMessages(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 for invalid limit, got %d", rec.Code)
	}

	// Get with limit=0 (should default to 50)
	req, _ = http.NewRequest("GET", "/messages/encrypted?conversation_id="+convID+"&limit=0", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec = httptest.NewRecorder()
	handleGetEncryptedMessages(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 for zero limit, got %d", rec.Code)
	}
}

func TestCB40_GetEncryptedMessages_MissingConvID(t *testing.T) {
	cb40SetupDB(t)
	cb40SetupAuth(t)
	token := cb40RegisterAndLogin(t)

	req, _ := http.NewRequest("GET", "/messages/encrypted", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handleGetEncryptedMessages(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rec.Code)
	}
}

func TestCB40_GetEncryptedMessages_NoAuth(t *testing.T) {
	cb40SetupDB(t)
	cb40SetupAuth(t)

	req, _ := http.NewRequest("GET", "/messages/encrypted?conversation_id=conv-1", nil)
	rec := httptest.NewRecorder()
	handleGetEncryptedMessages(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rec.Code)
	}
}

func TestCB40_GetEncryptedMessages_WrongMethod(t *testing.T) {
	cb40SetupDB(t)
	cb40SetupAuth(t)
	token := cb40RegisterAndLogin(t)

	req, _ := http.NewRequest("POST", "/messages/encrypted?conversation_id=conv-1", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handleGetEncryptedMessages(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rec.Code)
	}
}

// ==============================
// authenticateRequest tests
// ==============================

func TestCB40_AuthenticateRequest_NoAuth(t *testing.T) {
	cb40SetupDB(t)
	cb40SetupAuth(t)

	req, _ := http.NewRequest("GET", "/test", nil)
	_, _, err := authenticateRequest(req)
	if err == nil {
		t.Error("expected error with no auth")
	}
}

func TestCB40_AuthenticateRequest_AgentNoID(t *testing.T) {
	cb40SetupDB(t)
	_, agentSec := cb40SetupAuth(t)

	req, _ := http.NewRequest("GET", "/test", nil)
	req.Header.Set("X-Agent-Secret", agentSec)
	// No X-Agent-ID header
	_, _, err := authenticateRequest(req)
	if err == nil {
		t.Error("expected error with agent secret but no agent ID")
	}
}

func TestCB40_AuthenticateRequest_InvalidToken(t *testing.T) {
	cb40SetupDB(t)
	cb40SetupAuth(t)

	req, _ := http.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer invalid-token-here")
	_, _, err := authenticateRequest(req)
	if err == nil {
		t.Error("expected error with invalid token")
	}
}

// ==============================
// handleListOneTimePreKeys tests
// ==============================

func TestCB40_ListOneTimePreKeys_Count(t *testing.T) {
	cb40SetupDB(t)
	cb40SetupAuth(t)
	token := cb40RegisterAndLogin(t)

	// Upload 3 one-time pre-keys
	for i := 1; i <= 3; i++ {
		body := `{"key_type":"one_time_prekey","public_key":"otpk_` + string(rune('0'+i)) + `","key_id":` + string(rune('0'+i)) + `}`
		req, _ := http.NewRequest("POST", "/keys/upload", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		handleUploadPublicKey(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("upload %d failed: %d", i, rec.Code)
		}
	}

	// Get count
	req, _ := http.NewRequest("GET", "/keys/otpk-count", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handleListOneTimePreKeys(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp map[string]int
	json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp["one_time_prekey_count"] != 3 {
		t.Errorf("expected count=3, got %d", resp["one_time_prekey_count"])
	}
}

func TestCB40_ListOneTimePreKeys_WrongMethod(t *testing.T) {
	cb40SetupDB(t)
	cb40SetupAuth(t)
	token := cb40RegisterAndLogin(t)

	req, _ := http.NewRequest("POST", "/keys/otpk-count", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handleListOneTimePreKeys(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rec.Code)
	}
}

func TestCB40_ListOneTimePreKeys_NoAuth(t *testing.T) {
	cb40SetupDB(t)
	cb40SetupAuth(t)

	req, _ := http.NewRequest("GET", "/keys/otpk-count", nil)
	rec := httptest.NewRecorder()
	handleListOneTimePreKeys(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rec.Code)
	}
}

func TestCB40_ListOneTimePreKeys_AgentAuth(t *testing.T) {
	cb40SetupDB(t)
	_, agentSec := cb40SetupAuth(t)

	// Agent uploads one-time pre-key
	body := `{"key_type":"one_time_prekey","public_key":"agent_otpk","key_id":1}`
	req, _ := http.NewRequest("POST", "/keys/upload", strings.NewReader(body))
	req.Header.Set("X-Agent-Secret", agentSec)
	req.Header.Set("X-Agent-ID", "agent-otpk-1")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handleUploadPublicKey(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("agent upload failed: %d", rec.Code)
	}

	// Agent checks count
	req, _ = http.NewRequest("GET", "/keys/otpk-count", nil)
	req.Header.Set("X-Agent-Secret", agentSec)
	req.Header.Set("X-Agent-ID", "agent-otpk-1")
	rec = httptest.NewRecorder()
	handleListOneTimePreKeys(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp map[string]int
	json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp["one_time_prekey_count"] != 1 {
		t.Errorf("expected count=1, got %d", resp["one_time_prekey_count"])
	}
}

// ==============================
// createConversation handler test
// ==============================

func TestCB40_CreateConversation_WrongMethod(t *testing.T) {
	cb40SetupDB(t)
	cb40SetupAuth(t)
	token := cb40RegisterAndLogin(t)

	req, _ := http.NewRequest("GET", "/conversations/create", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handleCreateConversation(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rec.Code)
	}
}

func TestCB40_CreateConversation_NoAuth(t *testing.T) {
	cb40SetupDB(t)
	cb40SetupAuth(t)

	form := strings.NewReader("agent_id=agent-1")
	req, _ := http.NewRequest("POST", "/conversations/create", form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	handleCreateConversation(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rec.Code)
	}
}

func TestCB40_CreateConversation_MissingAgentID(t *testing.T) {
	cb40SetupDB(t)
	cb40SetupAuth(t)
	token := cb40RegisterAndLogin(t)

	req, _ := http.NewRequest("POST", "/conversations/create", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handleCreateConversation(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rec.Code)
	}
}