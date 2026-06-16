package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

// ==============================
// Coverage Boost 20: Additional coverage for handlers, E2E, presence, notif prefs
// Focus: handleGetNotificationPrefs, handleDeleteNotificationPrefs,
// handleGetPresence, handleCreateConversation, handleListConversations,
// handleChangePassword, handleMessageEdit, handleMessageDelete,
// E2E key upload/get/list, push token register/unregister,
// handleGetAttachment, handleListAttachments
// ==============================

func cb20SetupDB(t *testing.T) {
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

func cb20SetupAuth(t *testing.T) (string, string) {
	t.Helper()
	origAgentEnv := os.Getenv("AGENT_SECRET")
	origAdminEnv := os.Getenv("ADMIN_SECRET")
	os.Setenv("AGENT_SECRET", "test-agent-secret-cb20")
	agentSecret = "test-agent-secret-cb20"
	os.Setenv("ADMIN_SECRET", "test-admin-secret-cb20")
	adminSecret = "test-admin-secret-cb20"
	t.Cleanup(func() {
		if origAgentEnv != "" {
			os.Setenv("AGENT_SECRET", origAgentEnv)
		} else {
			os.Unsetenv("AGENT_SECRET")
		}
		agentSecret = getAgentSecret()
		if origAdminEnv != "" {
			os.Setenv("ADMIN_SECRET", origAdminEnv)
		} else {
			os.Unsetenv("ADMIN_SECRET")
		}
		adminSecret = getAdminSecret()
	})
	return "test-agent-secret-cb20", "test-admin-secret-cb20"
}

func cb20MakeToken(t *testing.T, username string) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id": username,
		"exp":     time.Now().Add(24 * time.Hour).Unix(),
	})
	s, err := token.SignedString(jwtSecret)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// cb20AuthRequest sets the user_id in the request context (like auth middleware does)
func cb20AuthRequest(t *testing.T, req *http.Request, username string) {
	t.Helper()
	ctx := context.WithValue(req.Context(), contextKeyUserID, username)
	*req = *req.WithContext(ctx)
}

func cb20CreateUser(t *testing.T, username, password string) string {
	t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec("INSERT INTO users (username, password_hash) VALUES (?, ?)", username, string(hash))
	if err != nil {
		t.Fatalf("create user %s: %v", username, err)
	}
	return username
}

func cb20CreateConv(t *testing.T, userID, agentID string) string {
	t.Helper()
	// Ensure agent exists
	db.Exec("INSERT OR IGNORE INTO agents (id, name) VALUES (?, ?)", agentID, agentID+"-name")
	id := fmt.Sprintf("conv-cb20-%s-%s", userID, agentID)
	_, err := db.Exec("INSERT INTO conversations (id, user_id, agent_id) VALUES (?, ?, ?)", id, userID, agentID)
	if err != nil {
		t.Fatalf("create conversation: %v", err)
	}
	return id
}

// --- handleGetNotificationPrefs tests ---

func TestCb20_GetNotificationPrefs_NoAuth(t *testing.T) {
	cb20SetupDB(t)
	req := httptest.NewRequest(http.MethodGet, "/notification-prefs", nil)
	w := httptest.NewRecorder()
	handleGetNotificationPrefs(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestCb20_GetNotificationPrefs_Valid(t *testing.T) {
	cb20SetupDB(t)
	hub = newHub()
	go hub.run()
	defer hub.Stop()

	cb20CreateUser(t, "notifprefuser1", "pass")
	convID := cb20CreateConv(t, "notifprefuser1", "agent1")
	token := cb20MakeToken(t, "notifprefuser1")

	// Set muted preference first
	form := url.Values{"conversation_id": {convID}, "muted": {"true"}}
	req := httptest.NewRequest(http.MethodPost, "/notification-prefs/set", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)
	cb20AuthRequest(t, req, "notifprefuser1")
	w := httptest.NewRecorder()
	handleSetNotificationPrefs(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("set prefs: expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// Get preferences
	req2 := httptest.NewRequest(http.MethodGet, "/notification-prefs", nil)
	req2.Header.Set("Authorization", "Bearer "+token)
	cb20AuthRequest(t, req2, "notifprefuser1")
	w2 := httptest.NewRecorder()
	handleGetNotificationPrefs(w2, req2)
	if w2.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w2.Code, w2.Body.String())
	}
}

// --- handleDeleteNotificationPrefs tests ---

func TestCb20_DeleteNotificationPrefs_NoAuth(t *testing.T) {
	cb20SetupDB(t)
	req := httptest.NewRequest(http.MethodPost, "/notification-prefs/delete", nil)
	w := httptest.NewRecorder()
	handleDeleteNotificationPrefs(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestCb20_DeleteNotificationPrefs_MissingID(t *testing.T) {
	cb20SetupDB(t)
	token := cb20MakeToken(t, "delprefuser1")
	req := httptest.NewRequest(http.MethodDelete, "/notification-prefs/delete", strings.NewReader(``))
	req.Header.Set("Authorization", "Bearer "+token)
	cb20AuthRequest(t, req, "delprefuser1")
	w := httptest.NewRecorder()
	handleDeleteNotificationPrefs(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

// --- handleChangePassword tests ---

func TestCb20_ChangePassword_NoAuth(t *testing.T) {
	cb20SetupDB(t)
	req := httptest.NewRequest(http.MethodPost, "/auth/change-password", nil)
	w := httptest.NewRecorder()
	handleChangePassword(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestCb20_ChangePassword_Success(t *testing.T) {
	cb20SetupDB(t)
	// handleRegisterUser creates the user, then login with the same credentials
	form := url.Values{"username": {"chpwuser1"}, "password": {"oldpass"}}
	req := httptest.NewRequest(http.MethodPost, "/auth/user", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handleRegisterUser(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("register: expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// Now login to get a JWT with proper user_id
	loginForm := url.Values{"username": {"chpwuser1"}, "password": {"oldpass"}}
	loginReq := httptest.NewRequest(http.MethodPost, "/auth/login", strings.NewReader(loginForm.Encode()))
	loginReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	loginW := httptest.NewRecorder()
	handleLogin(loginW, loginReq)
	if loginW.Code != http.StatusOK {
		t.Fatalf("login: expected 200, got %d: %s", loginW.Code, loginW.Body.String())
	}
	var loginResult map[string]interface{}
	json.Unmarshal(loginW.Body.Bytes(), &loginResult)
	token, _ := loginResult["token"].(string)

	changeForm := url.Values{
		"old_password": {"oldpass"},
		"new_password": {"newpass123"},
	}
	changeReq := httptest.NewRequest(http.MethodPost, "/auth/change-password", strings.NewReader(changeForm.Encode()))
	changeReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	changeReq.Header.Set("Authorization", "Bearer "+token)
	cb20AuthRequest(t, changeReq, "chpwuser1")
	changeW := httptest.NewRecorder()
	handleChangePassword(changeW, changeReq)
	if changeW.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", changeW.Code, changeW.Body.String())
	}
}

func TestCb20_ChangePassword_WrongOld(t *testing.T) {
	cb20SetupDB(t)
	// Register user
	form := url.Values{"username": {"chpwuser2"}, "password": {"correctpass"}}
	req := httptest.NewRequest(http.MethodPost, "/auth/user", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handleRegisterUser(w, req)

	// Login
	loginForm := url.Values{"username": {"chpwuser2"}, "password": {"correctpass"}}
	loginReq := httptest.NewRequest(http.MethodPost, "/auth/login", strings.NewReader(loginForm.Encode()))
	loginReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	loginW := httptest.NewRecorder()
	handleLogin(loginW, loginReq)
	var loginResult map[string]interface{}
	json.Unmarshal(loginW.Body.Bytes(), &loginResult)
	token, _ := loginResult["token"].(string)

	changeForm := url.Values{
		"old_password": {"wrongpass"},
		"new_password": {"newpass123"},
	}
	changeReq := httptest.NewRequest(http.MethodPost, "/auth/change-password", strings.NewReader(changeForm.Encode()))
	changeReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	changeReq.Header.Set("Authorization", "Bearer "+token)
	cb20AuthRequest(t, changeReq, "chpwuser2")
	changeW := httptest.NewRecorder()
	handleChangePassword(changeW, changeReq)
	if changeW.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d: %s", changeW.Code, changeW.Body.String())
	}
}

func TestCb20_ChangePassword_ShortNew(t *testing.T) {
	cb20SetupDB(t)
	// Register user
	form := url.Values{"username": {"chpwuser3"}, "password": {"oldpass"}}
	req := httptest.NewRequest(http.MethodPost, "/auth/user", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handleRegisterUser(w, req)

	// Login
	loginForm := url.Values{"username": {"chpwuser3"}, "password": {"oldpass"}}
	loginReq := httptest.NewRequest(http.MethodPost, "/auth/login", strings.NewReader(loginForm.Encode()))
	loginReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	loginW := httptest.NewRecorder()
	handleLogin(loginW, loginReq)
	var loginResult map[string]interface{}
	json.Unmarshal(loginW.Body.Bytes(), &loginResult)
	token, _ := loginResult["token"].(string)

	changeForm := url.Values{
		"old_password": {"oldpass"},
		"new_password": {"abc"},
	}
	changeReq := httptest.NewRequest(http.MethodPost, "/auth/change-password", strings.NewReader(changeForm.Encode()))
	changeReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	changeReq.Header.Set("Authorization", "Bearer "+token)
	cb20AuthRequest(t, changeReq, "chpwuser3")
	changeW := httptest.NewRecorder()
	handleChangePassword(changeW, changeReq)
	if changeW.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d: %s", changeW.Code, changeW.Body.String())
	}
}

// --- handleCreateConversation tests ---

func TestCb20_CreateConversation_NoAuth(t *testing.T) {
	cb20SetupDB(t)
	req := httptest.NewRequest(http.MethodPost, "/conversations/create", nil)
	w := httptest.NewRecorder()
	handleCreateConversation(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestCb20_CreateConversation_MissingAgentID(t *testing.T) {
	cb20SetupDB(t)
	token := cb20MakeToken(t, "convuser1")
	form := url.Values{}
	req := httptest.NewRequest(http.MethodPost, "/conversations/create", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)
	cb20AuthRequest(t, req, "convuser1")
	w := httptest.NewRecorder()
	handleCreateConversation(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCb20_CreateConversation_Success(t *testing.T) {
	cb20SetupDB(t)
	hub = newHub()
	go hub.run()
	defer hub.Stop()

	cb20CreateUser(t, "convuser2", "pass")
	db.Exec("INSERT OR IGNORE INTO agents (id, name) VALUES (?, ?)", "convagent1", "Conv Agent")
	token := cb20MakeToken(t, "convuser2")

	form := url.Values{"agent_id": {"convagent1"}}
	req := httptest.NewRequest(http.MethodPost, "/conversations/create", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)
	cb20AuthRequest(t, req, "convuser2")
	w := httptest.NewRecorder()
	handleCreateConversation(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

// --- handleListConversations tests ---

func TestCb20_ListConversations_NoAuth(t *testing.T) {
	cb20SetupDB(t)
	req := httptest.NewRequest(http.MethodGet, "/conversations", nil)
	w := httptest.NewRecorder()
	handleListConversations(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestCb20_ListConversations_Empty(t *testing.T) {
	cb20SetupDB(t)
	cb20CreateUser(t, "listconvuser1", "pass")
	token := cb20MakeToken(t, "listconvuser1")

	req := httptest.NewRequest(http.MethodGet, "/conversations", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	cb20AuthRequest(t, req, "listconvuser1")
	w := httptest.NewRecorder()
	handleListConversations(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var result []interface{}
	json.Unmarshal(w.Body.Bytes(), &result)
	if len(result) != 0 {
		t.Errorf("expected empty list, got %d items", len(result))
	}
}

func TestCb20_ListConversations_WithData(t *testing.T) {
	cb20SetupDB(t)
	hub = newHub()
	go hub.run()
	defer hub.Stop()

	cb20CreateUser(t, "listconvuser2", "pass")
	cb20CreateConv(t, "listconvuser2", "agent-lc2")
	token := cb20MakeToken(t, "listconvuser2")

	req := httptest.NewRequest(http.MethodGet, "/conversations", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	cb20AuthRequest(t, req, "listconvuser2")
	w := httptest.NewRecorder()
	handleListConversations(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var result []interface{}
	json.Unmarshal(w.Body.Bytes(), &result)
	if len(result) != 1 {
		t.Errorf("expected 1 conversation, got %d", len(result))
	}
}

// --- handleMessageEdit tests ---

func TestCb20_MessageEdit_NoAuth(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/messages/edit", nil)
	w := httptest.NewRecorder()
	handleMessageEdit(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestCb20_MessageEdit_MissingFields(t *testing.T) {
	cb20SetupDB(t)
	token := cb20MakeToken(t, "edituser1")
	form := url.Values{"message_id": {"msg1"}}
	req := httptest.NewRequest(http.MethodPost, "/messages/edit", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)
	cb20AuthRequest(t, req, "edituser1")
	w := httptest.NewRecorder()
	handleMessageEdit(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

// --- handleMessageDelete tests ---

func TestCb20_MessageDelete_NoAuth(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/messages/delete", nil)
	w := httptest.NewRecorder()
	handleMessageDelete(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestCb20_MessageDelete_MissingID(t *testing.T) {
	cb20SetupDB(t)
	token := cb20MakeToken(t, "delmsguser1")
	req := httptest.NewRequest(http.MethodPost, "/messages/delete", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	cb20AuthRequest(t, req, "delmsguser1")
	w := httptest.NewRecorder()
	handleMessageDelete(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

// --- handleGetPresence tests ---

func TestCb20_GetPresence_NoAuth(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/presence", nil)
	w := httptest.NewRecorder()
	handleGetPresence(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

// --- handleRegisterDeviceToken tests ---

func TestCb20_RegisterDeviceToken_NoAuth(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/push/register", nil)
	w := httptest.NewRecorder()
	handleRegisterDeviceToken(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestCb20_RegisterDeviceToken_Success(t *testing.T) {
	cb20SetupDB(t)
	hub = newHub()
	go hub.run()
	defer hub.Stop()

	cb20CreateUser(t, "devtokenuser1", "pass")
	token := cb20MakeToken(t, "devtokenuser1")

	body := `{"device_token": "test-token-abc123", "platform": "ios"}`
	req := httptest.NewRequest(http.MethodPost, "/push/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	cb20AuthRequest(t, req, "devtokenuser1")
	w := httptest.NewRecorder()
	handleRegisterDeviceToken(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCb20_RegisterDeviceToken_MissingToken(t *testing.T) {
	cb20SetupDB(t)
	token := cb20MakeToken(t, "devtokenuser2")
	body := `{"platform": "ios"}`
	req := httptest.NewRequest(http.MethodPost, "/push/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	cb20AuthRequest(t, req, "devtokenuser2")
	w := httptest.NewRecorder()
	handleRegisterDeviceToken(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

// --- handleUnregisterDeviceToken tests ---

func TestCb20_UnregisterDeviceToken_NoAuth(t *testing.T) {
	req := httptest.NewRequest(http.MethodDelete, "/push/unregister", nil)
	w := httptest.NewRecorder()
	handleUnregisterDeviceToken(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

// --- handleGetAttachment tests ---

func TestCb20_GetAttachment_NoAuth(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/attachments/att_123", nil)
	w := httptest.NewRecorder()
	handleGetAttachment(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

// --- handleListAttachments tests ---

func TestCb20_ListAttachments_NoAuth(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/attachments?conversation_id=conv1", nil)
	w := httptest.NewRecorder()
	handleListAttachments(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

// --- E2E key management tests ---

func TestCb20_UploadPublicKey_NoAuth(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/e2e/upload-public-key", nil)
	w := httptest.NewRecorder()
	handleUploadPublicKey(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestCb20_GetKeyBundle_NoAuth(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/e2e/key-bundle/user1", nil)
	w := httptest.NewRecorder()
	handleGetKeyBundle(w, req)
	// No auth required for key bundle lookup (public key)
	// Just verify it doesn't crash
}

func TestCb20_StoreEncrypted_NoAuth(t *testing.T) {
	cb20SetupDB(t)
	req := httptest.NewRequest(http.MethodPost, "/e2e/store", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handleStoreEncryptedMessage(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestCb20_GetEncrypted_NoAuth(t *testing.T) {
	cb20SetupDB(t)
	req := httptest.NewRequest(http.MethodGet, "/e2e/messages", nil)
	w := httptest.NewRecorder()
	handleGetEncryptedMessages(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

// --- handleSearchMessages tests ---

func TestCb20_SearchMessages_ValidQuery(t *testing.T) {
	cb20SetupDB(t)
	hub = newHub()
	go hub.run()
	defer hub.Stop()

	cb20CreateUser(t, "searchuser1", "pass")
	convID := cb20CreateConv(t, "searchuser1", "agent-search1")
	db.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, created_at) VALUES (?, ?, 'user', 'searchuser1', 'hello world', datetime('now'))",
		"msg-search1", convID)

	token := cb20MakeToken(t, "searchuser1")
	req := httptest.NewRequest(http.MethodGet, "/messages/search?q=hello", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	cb20AuthRequest(t, req, "searchuser1")
	w := httptest.NewRecorder()
	handleSearchMessages(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

// --- handleGetMessages tests ---

func TestCb20_GetMessages_WithConversationID(t *testing.T) {
	cb20SetupDB(t)
	hub = newHub()
	go hub.run()
	defer hub.Stop()

	cb20CreateUser(t, "msguser1", "pass")
	convID := cb20CreateConv(t, "msguser1", "agent-msg1")
	db.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, created_at) VALUES (?, ?, 'user', 'msguser1', 'hi', datetime('now'))",
		"msg-get1", convID)

	token := cb20MakeToken(t, "msguser1")
	req := httptest.NewRequest(http.MethodGet, "/conversations/messages?conversation_id="+convID, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	cb20AuthRequest(t, req, "msguser1")
	w := httptest.NewRecorder()
	handleGetMessages(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

// --- RateLimiter.Stop test ---

func TestCb20_RateLimiter_Stop(t *testing.T) {
	rl := NewRateLimiter(10, time.Minute)
	t.Cleanup(func() { rl.Stop() })
	rl.Allow("test1")
	rl.Stop()
	// Verify Stop is idempotent
	rl.Stop()
}

func TestCb20_TieredRateLimiter_Stop(t *testing.T) {
	trl := NewTieredRateLimiter()
	t.Cleanup(func() { trl.Stop() })
	trl.Allow("test1")
	trl.Stop()
	// Verify Stop is idempotent
	trl.Stop()
}

// --- initAPNs/initFCM nil guard tests ---

func TestCb20_InitFCM_NoConfig(t *testing.T) {
	origPushConfig := pushConfig
	pushConfig = nil
	defer func() { pushConfig = origPushConfig }()

	// Should not panic when pushConfig is nil
	initFCM()
}

// --- SafeSend tests ---

func TestCb20_SafeSend_OpenChannel(t *testing.T) {
	ch := make(chan []byte, 1)
	conn := &Connection{send: ch, closeMu: sync.RWMutex{}}
	result := safeSendToConn(conn, []byte("test"))
	if !result {
		t.Error("expected true for open channel")
	}
}

func TestCb20_SafeSend_ClosedChannel(t *testing.T) {
	ch := make(chan []byte, 1)
	close(ch)
	conn := &Connection{send: ch, closeMu: sync.RWMutex{}}
	result := safeSendToConn(conn, []byte("test"))
	if result {
		t.Error("expected false for closed channel")
	}
}

// --- Connection.IsClosed tests ---

func TestCb20_Connection_IsClosed_Initially(t *testing.T) {
	conn := &Connection{
		closeMu: sync.RWMutex{},
	}
	if conn.IsClosed() {
		t.Error("expected connection to not be closed initially")
	}
}

func TestCb20_Connection_MarkClosed(t *testing.T) {
	conn := &Connection{
		closeMu: sync.RWMutex{},
	}
	conn.MarkClosed()
	if !conn.IsClosed() {
		t.Error("expected connection to be closed after MarkClosed")
	}
}

// --- handleUpload with auth ---

func TestCb20_HandleUpload_Success(t *testing.T) {
	cb20SetupDB(t)
	hub = newHub()
	go hub.run()
	defer hub.Stop()

	cb20CreateUser(t, "uploaduser1", "pass")
	token := cb20MakeToken(t, "uploaduser1")

	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)
	part, _ := writer.CreateFormFile("file", "test.txt")
	part.Write([]byte("hello world"))
	writer.Close()

	req := httptest.NewRequest(http.MethodPost, "/attachments/upload", &buf)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	req.Header.Set("Authorization", "Bearer "+token)
	cb20AuthRequest(t, req, "uploaduser1")
	w := httptest.NewRecorder()
	handleUpload(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var result map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &result)
	if result["id"] == nil {
		t.Error("expected id in response")
	}
}

// --- handleReact with auth ---

func TestCb20_React_Success(t *testing.T) {
	cb20SetupDB(t)
	hub = newHub()
	go hub.run()
	defer hub.Stop()

	cb20CreateUser(t, "reactuser1", "pass")
	convID := cb20CreateConv(t, "reactuser1", "agent-react1")
	db.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, created_at) VALUES (?, ?, 'user', 'reactuser1', 'hello', datetime('now'))",
		"msg-react1", convID)

	token := cb20MakeToken(t, "reactuser1")
	form := url.Values{
		"message_id": {"msg-react1"},
		"emoji":      {"👍"},
	}
	req := httptest.NewRequest(http.MethodPost, "/messages/react", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)
	cb20AuthRequest(t, req, "reactuser1")
	w := httptest.NewRecorder()
	handleReact(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

// --- handleRemoveTag / handleAddTag with auth ---

func TestCb20_RemoveTag_NoAuth(t *testing.T) {
	cb20SetupDB(t)
	req := httptest.NewRequest(http.MethodPost, "/tags/remove", nil)
	w := httptest.NewRecorder()
	handleRemoveTag(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestCb20_AddTag_NoAuth(t *testing.T) {
	cb20SetupDB(t)
	req := httptest.NewRequest(http.MethodPost, "/tags/add", nil)
	w := httptest.NewRecorder()
	handleAddTag(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestCb20_AddTag_Success(t *testing.T) {
	cb20SetupDB(t)
	hub = newHub()
	go hub.run()
	defer hub.Stop()

	cb20CreateUser(t, "taguser1", "pass")
	convID := cb20CreateConv(t, "taguser1", "agent-tag1")
	token := cb20MakeToken(t, "taguser1")

	form := url.Values{
		"conversation_id": {convID},
		"tag":             {"important"},
	}
	req := httptest.NewRequest(http.MethodPost, "/tags/add", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)
	cb20AuthRequest(t, req, "taguser1")
	w := httptest.NewRecorder()
	handleAddTag(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

// --- handleLogin success ---

func TestCb20_Login_Success(t *testing.T) {
	cb20SetupDB(t)
	// Register user first
	form := url.Values{"username": {"loginuser1"}, "password": {"goodpass"}}
	req := httptest.NewRequest(http.MethodPost, "/auth/user", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handleRegisterUser(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("register: expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// Now login
	loginForm := url.Values{"username": {"loginuser1"}, "password": {"goodpass"}}
	loginReq := httptest.NewRequest(http.MethodPost, "/auth/login", strings.NewReader(loginForm.Encode()))
	loginReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	loginW := httptest.NewRecorder()
	handleLogin(loginW, loginReq)
	if loginW.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", loginW.Code, loginW.Body.String())
	}
	var result map[string]interface{}
	json.Unmarshal(loginW.Body.Bytes(), &result)
	if result["token"] == nil {
		t.Error("expected token in response")
	}
}

// --- handleRegisterUser success ---

func TestCb20_RegisterUser_Success(t *testing.T) {
	cb20SetupDB(t)
	form := url.Values{"username": {"newuser1"}, "password": {"password123"}}
	req := httptest.NewRequest(http.MethodPost, "/auth/user", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handleRegisterUser(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

// --- handleGetMessages with limit ---

func TestCb20_GetMessages_Limit(t *testing.T) {
	cb20SetupDB(t)
	hub = newHub()
	go hub.run()
	defer hub.Stop()

	cb20CreateUser(t, "msguser2", "pass")
	convID := cb20CreateConv(t, "msguser2", "agent-msg2")

	// Insert 5 messages
	for i := 0; i < 5; i++ {
		db.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, created_at) VALUES (?, ?, 'user', 'msguser2', ?, datetime('now'))",
			fmt.Sprintf("msg-limit-%d", i), convID, fmt.Sprintf("message %d", i))
	}

	token := cb20MakeToken(t, "msguser2")
	req := httptest.NewRequest(http.MethodGet, "/conversations/messages?conversation_id="+convID+"&limit=3", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	cb20AuthRequest(t, req, "msguser2")
	w := httptest.NewRecorder()
	handleGetMessages(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

// --- handleAdminProfile test ---

func TestCb20_AdminProfile_NoAuth(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/admin/profile", nil)
	w := httptest.NewRecorder()
	handleAdminProfile(w, req)
	// No auth check in handler itself, returns memory stats
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCb20_AdminProfile_StatsAction(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/admin/profile?action=stats", nil)
	w := httptest.NewRecorder()
	handleAdminProfile(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCb20_AdminProfile_GCAction(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/admin/profile?action=gc", nil)
	w := httptest.NewRecorder()
	handleAdminProfile(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}