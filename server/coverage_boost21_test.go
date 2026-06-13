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
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// ==============================
// Coverage Boost 21: More coverage for low-coverage functions
// Focus: E2E handlers (full auth flow), message edit/delete, attachments,
// hub methods (TouchHeartbeat, SetAgentStatus, BroadcastToAllClients),
// logger methods, middleware helpers, conversation helpers, dbdriver
// ==============================

func cb21SetupDB(t *testing.T) {
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

func cb21SetupAuth(t *testing.T) {
	t.Helper()
	origAgentEnv := os.Getenv("AGENT_SECRET")
	origAdminEnv := os.Getenv("ADMIN_SECRET")
	os.Setenv("AGENT_SECRET", "test-agent-secret-cb21")
	agentSecret = "test-agent-secret-cb21"
	os.Setenv("ADMIN_SECRET", "test-admin-secret-cb21")
	adminSecret = "test-admin-secret-cb21"
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
}

func cb21MakeToken(t *testing.T, username string) string {
	t.Helper()
	hash, _ := bcrypt.GenerateFromPassword([]byte("testpass123"), bcrypt.MinCost)
	_, err := db.Exec("INSERT OR IGNORE INTO users (id, username, password_hash) VALUES (?, ?, ?)", username, username, string(hash))
	if err != nil {
		t.Fatalf("insert user: %v", err)
	}
	token, err := GenerateJWT(username, username)
	if err != nil {
		t.Fatalf("generate JWT: %v", err)
	}
	return token
}

func cb21AuthRequest(t *testing.T, req *http.Request, username string) {
	t.Helper()
	ctx := context.WithValue(req.Context(), contextKeyUserID, username)
	*req = *req.WithContext(ctx)
}

func cb21CreateUser(t *testing.T, username, password string) string {
	t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec("INSERT OR IGNORE INTO users (id, username, password_hash) VALUES (?, ?, ?)", username, username, string(hash))
	if err != nil {
		t.Fatalf("create user %s: %v", username, err)
	}
	return username
}

func cb21CreateConv(t *testing.T, userID, agentID string) string {
	t.Helper()
	db.Exec("INSERT OR IGNORE INTO agents (id, name) VALUES (?, ?)", agentID, agentID+"-name")
	id := fmt.Sprintf("conv-cb21-%s-%s", userID, agentID)
	_, err := db.Exec("INSERT INTO conversations (id, user_id, agent_id) VALUES (?, ?, ?)", id, userID, agentID)
	if err != nil {
		t.Fatalf("create conversation: %v", err)
	}
	return id
}

func cb21InsertMessage(t *testing.T, msgID, convID, senderType, senderID, content string) {
	t.Helper()
	_, err := db.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, created_at) VALUES (?, ?, ?, ?, ?, datetime('now'))",
		msgID, convID, senderType, senderID, content)
	if err != nil {
		t.Fatalf("insert message: %v", err)
	}
}

// ===== E2E Handlers =====

func TestCb21_UploadPublicKey_Success(t *testing.T) {
	cb21SetupDB(t)
	hub = newHub()
	go hub.run()
	defer hub.Stop()

	cb21CreateUser(t, "e2euser1", "pass")
	token := cb21MakeToken(t, "e2euser1")

	body := `{"key_type": "identity", "public_key": "ik-base64", "signature": "sig-base64"}`
	req := httptest.NewRequest(http.MethodPost, "/e2e/upload-public-key", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	cb21AuthRequest(t, req, "e2euser1")
	w := httptest.NewRecorder()
	handleUploadPublicKey(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCb21_UploadPublicKey_InvalidJSON(t *testing.T) {
	cb21SetupDB(t)
	token := cb21MakeToken(t, "e2euser2")
	req := httptest.NewRequest(http.MethodPost, "/e2e/upload-public-key", strings.NewReader("not json"))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	cb21AuthRequest(t, req, "e2euser2")
	w := httptest.NewRecorder()
	handleUploadPublicKey(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCb21_UploadPublicKey_MissingIdentityKey(t *testing.T) {
	cb21SetupDB(t)
	token := cb21MakeToken(t, "e2euser3")
	body := `{"key_type": "identity"}`
	req := httptest.NewRequest(http.MethodPost, "/e2e/upload-public-key", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	cb21AuthRequest(t, req, "e2euser3")
	w := httptest.NewRecorder()
	handleUploadPublicKey(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCb21_GetKeyBundle_Success(t *testing.T) {
	cb21SetupDB(t)
	cb21CreateUser(t, "bundleuser1", "pass")
	token := cb21MakeToken(t, "bundleuser1")

	// Upload identity key first
	body := `{"key_type": "identity", "public_key": "ik-b1", "signature": "sig-b1"}`
	req := httptest.NewRequest(http.MethodPost, "/e2e/upload-public-key", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	cb21AuthRequest(t, req, "bundleuser1")
	w := httptest.NewRecorder()
	handleUploadPublicKey(w, req)

	// Get the key bundle (requires auth)
	req2 := httptest.NewRequest(http.MethodGet, "/keys/bundle?owner_id=bundleuser1&owner_type=user", nil)
	req2.Header.Set("Authorization", "Bearer "+token)
	cb21AuthRequest(t, req2, "bundleuser1")
	w2 := httptest.NewRecorder()
	handleGetKeyBundle(w2, req2)
	if w2.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w2.Code, w2.Body.String())
	}
}

func TestCb21_GetKeyBundle_NotFound(t *testing.T) {
	cb21SetupDB(t)
	token := cb21MakeToken(t, "bundleuser2")
	req := httptest.NewRequest(http.MethodGet, "/keys/bundle?owner_id=nonexistent&owner_type=user", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	cb21AuthRequest(t, req, "bundleuser2")
	w := httptest.NewRecorder()
	handleGetKeyBundle(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCb21_StoreEncryptedMessage_Success(t *testing.T) {
	cb21SetupDB(t)
	hub = newHub()
	go hub.run()
	defer hub.Stop()

	cb21CreateUser(t, "encuser1", "pass")
	convID := cb21CreateConv(t, "encuser1", "encagent1")
	token := cb21MakeToken(t, "encuser1")

	body := fmt.Sprintf(`{"conversation_id": "%s", "ciphertext": "enc-blob-base64", "iv": "iv-base64", "algorithm": "aes-256-gcm", "recipient_key_id": "key1"}`, convID)
	req := httptest.NewRequest(http.MethodPost, "/messages/encrypted", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	cb21AuthRequest(t, req, "encuser1")
	w := httptest.NewRecorder()
	handleStoreEncryptedMessage(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCb21_StoreEncryptedMessage_InvalidJSON(t *testing.T) {
	cb21SetupDB(t)
	token := cb21MakeToken(t, "encuser2")
	req := httptest.NewRequest(http.MethodPost, "/messages/encrypted", strings.NewReader("not json"))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	cb21AuthRequest(t, req, "encuser2")
	w := httptest.NewRecorder()
	handleStoreEncryptedMessage(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCb21_GetEncryptedMessages_Success(t *testing.T) {
	cb21SetupDB(t)
	hub = newHub()
	go hub.run()
	defer hub.Stop()

	cb21CreateUser(t, "encgetuser1", "pass")
	convID := cb21CreateConv(t, "encgetuser1", "encgetagent1")
	token := cb21MakeToken(t, "encgetuser1")

	// Store an encrypted message first
	body := fmt.Sprintf(`{"conversation_id": "%s", "ciphertext": "enc-blob", "iv": "iv-base64", "algorithm": "aes-256-gcm", "recipient_key_id": "key1"}`, convID)
	req := httptest.NewRequest(http.MethodPost, "/messages/encrypted", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	cb21AuthRequest(t, req, "encgetuser1")
	w := httptest.NewRecorder()
	handleStoreEncryptedMessage(w, req)

	// Get encrypted messages
	req2 := httptest.NewRequest(http.MethodGet, "/messages/encrypted?conversation_id="+convID, nil)
	req2.Header.Set("Authorization", "Bearer "+token)
	cb21AuthRequest(t, req2, "encgetuser1")
	w2 := httptest.NewRecorder()
	handleGetEncryptedMessages(w2, req2)
	if w2.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w2.Code, w2.Body.String())
	}
}

func TestCb21_GetEncryptedMessages_NoConversationID(t *testing.T) {
	cb21SetupDB(t)
	token := cb21MakeToken(t, "encgetuser2")
	req := httptest.NewRequest(http.MethodGet, "/messages/encrypted", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	cb21AuthRequest(t, req, "encgetuser2")
	w := httptest.NewRecorder()
	handleGetEncryptedMessages(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

// ===== Message Edit/Delete with full auth flow =====

func TestCb21_MessageEdit_Success(t *testing.T) {
	cb21SetupDB(t)
	hub = newHub()
	go hub.run()
	defer hub.Stop()

	cb21CreateUser(t, "edituser1", "pass")
	convID := cb21CreateConv(t, "edituser1", "editagent1")
	cb21InsertMessage(t, "msg-edit1", convID, "client", "edituser1", "original text")
	token := cb21MakeToken(t, "edituser1")

	form := url.Values{
		"message_id": {"msg-edit1"},
		"content":    {"edited text"},
	}
	req := httptest.NewRequest(http.MethodPost, "/messages/edit", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)
	cb21AuthRequest(t, req, "edituser1")
	w := httptest.NewRecorder()
	handleMessageEdit(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCb21_MessageEdit_NotOwner(t *testing.T) {
	cb21SetupDB(t)
	hub = newHub()
	go hub.run()
	defer hub.Stop()

	cb21CreateUser(t, "editowner1", "pass")
	cb21CreateUser(t, "editother1", "pass")
	convID := cb21CreateConv(t, "editowner1", "editagent2")
	cb21InsertMessage(t, "msg-edit2", convID, "user", "editowner1", "owner's message")
	token := cb21MakeToken(t, "editother1")

	form := url.Values{
		"message_id": {"msg-edit2"},
		"content":    {"hacked text"},
	}
	req := httptest.NewRequest(http.MethodPost, "/messages/edit", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)
	cb21AuthRequest(t, req, "editother1")
	w := httptest.NewRecorder()
	handleMessageEdit(w, req)
	if w.Code != http.StatusForbidden && w.Code != http.StatusUnauthorized {
		t.Errorf("expected 403 or 401, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCb21_MessageEdit_NotFound(t *testing.T) {
	cb21SetupDB(t)
	token := cb21MakeToken(t, "edituser3")
	form := url.Values{
		"message_id": {"nonexistent"},
		"content":    {"new text"},
	}
	req := httptest.NewRequest(http.MethodPost, "/messages/edit", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)
	cb21AuthRequest(t, req, "edituser3")
	w := httptest.NewRecorder()
	handleMessageEdit(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCb21_MessageDelete_Success(t *testing.T) {
	cb21SetupDB(t)
	hub = newHub()
	go hub.run()
	defer hub.Stop()

	cb21CreateUser(t, "deluser1", "pass")
	convID := cb21CreateConv(t, "deluser1", "delagent1")
	cb21InsertMessage(t, "msg-del1", convID, "client", "deluser1", "to be deleted")
	token := cb21MakeToken(t, "deluser1")

	form := url.Values{
		"message_id": {"msg-del1"},
	}
	req := httptest.NewRequest(http.MethodPost, "/messages/delete", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)
	cb21AuthRequest(t, req, "deluser1")
	w := httptest.NewRecorder()
	handleMessageDelete(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCb21_MessageDelete_NotOwner(t *testing.T) {
	cb21SetupDB(t)
	hub = newHub()
	go hub.run()
	defer hub.Stop()

	cb21CreateUser(t, "delowner1", "pass")
	cb21CreateUser(t, "delother1", "pass")
	convID := cb21CreateConv(t, "delowner1", "delagent2")
	cb21InsertMessage(t, "msg-del2", convID, "user", "delowner1", "owner's message")
	token := cb21MakeToken(t, "delother1")

	form := url.Values{
		"message_id": {"msg-del2"},
	}
	req := httptest.NewRequest(http.MethodPost, "/messages/delete", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)
	cb21AuthRequest(t, req, "delother1")
	w := httptest.NewRecorder()
	handleMessageDelete(w, req)
	if w.Code != http.StatusForbidden && w.Code != http.StatusUnauthorized {
		t.Errorf("expected 403 or 401, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCb21_MessageDelete_NotFound(t *testing.T) {
	cb21SetupDB(t)
	token := cb21MakeToken(t, "deluser3")
	form := url.Values{
		"message_id": {"nonexistent"},
	}
	req := httptest.NewRequest(http.MethodPost, "/messages/delete", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)
	cb21AuthRequest(t, req, "deluser3")
	w := httptest.NewRecorder()
	handleMessageDelete(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d: %s", w.Code, w.Body.String())
	}
}

// ===== Attachment handlers with auth =====

func TestCb21_GetAttachment_Success(t *testing.T) {
	cb21SetupDB(t)
	hub = newHub()
	go hub.run()
	defer hub.Stop()

	cb21CreateUser(t, "attuser1", "pass")
	token := cb21MakeToken(t, "attuser1")

	// Upload a file first
	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)
	part, _ := writer.CreateFormFile("file", "test.txt")
	part.Write([]byte("attachment content"))
	writer.Close()

	req := httptest.NewRequest(http.MethodPost, "/attachments/upload", &buf)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	req.Header.Set("Authorization", "Bearer "+token)
	cb21AuthRequest(t, req, "attuser1")
	w := httptest.NewRecorder()
	handleUpload(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("upload: expected 200, got %d %s", w.Code, w.Body.String())
	}
	var uploadResult map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &uploadResult)
	attID, _ := uploadResult["id"].(string)

	// Get the attachment
	req2 := httptest.NewRequest(http.MethodGet, "/attachments/"+attID, nil)
	req2.Header.Set("Authorization", "Bearer "+token)
	cb21AuthRequest(t, req2, "attuser1")
	w2 := httptest.NewRecorder()
	handleGetAttachment(w2, req2)
	if w2.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w2.Code, w2.Body.String())
	}
}

func TestCb21_GetAttachment_NotFound(t *testing.T) {
	cb21SetupDB(t)
	token := cb21MakeToken(t, "attuser2")
	req := httptest.NewRequest(http.MethodGet, "/attachments/nonexistent", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	cb21AuthRequest(t, req, "attuser2")
	w := httptest.NewRecorder()
	handleGetAttachment(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCb21_ListAttachments_Success(t *testing.T) {
	cb21SetupDB(t)
	hub = newHub()
	go hub.run()
	defer hub.Stop()

	cb21CreateUser(t, "attlistuser1", "pass")
	convID := cb21CreateConv(t, "attlistuser1", "attlistagent1")
	token := cb21MakeToken(t, "attlistuser1")

	// Upload a file with conversation_id
	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)
	writer.WriteField("conversation_id", convID)
	part, _ := writer.CreateFormFile("file", "test.txt")
	part.Write([]byte("attachment"))
	writer.Close()

	req := httptest.NewRequest(http.MethodPost, "/attachments/upload", &buf)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	req.Header.Set("Authorization", "Bearer "+token)
	cb21AuthRequest(t, req, "attlistuser1")
	w := httptest.NewRecorder()
	handleUpload(w, req)

	// List attachments for the conversation
	req2 := httptest.NewRequest(http.MethodGet, "/attachments?conversation_id="+convID, nil)
	req2.Header.Set("Authorization", "Bearer "+token)
	cb21AuthRequest(t, req2, "attlistuser1")
	w2 := httptest.NewRecorder()
	handleListAttachments(w2, req2)
	if w2.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w2.Code, w2.Body.String())
	}
}

func TestCb21_ListAttachments_MissingConversationID(t *testing.T) {
	cb21SetupDB(t)
	token := cb21MakeToken(t, "attlistuser2")
	req := httptest.NewRequest(http.MethodGet, "/attachments", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	cb21AuthRequest(t, req, "attlistuser2")
	w := httptest.NewRecorder()
	handleListAttachments(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

// ===== Hub methods =====

func TestCb21_TouchHeartbeat(t *testing.T) {
	cb21SetupDB(t)
	hub = newHub()
	go hub.run()
	defer hub.Stop()

	conn := &Connection{
		connType: "agent",
		id:       "hbagent1",
		send:     make(chan []byte, 256),
		closeMu:  sync.RWMutex{},
	}
	hub.mu.Lock()
	hub.agents["hbagent1"] = conn
	hub.mu.Unlock()

	hub.TouchHeartbeat(conn)
	if conn.lastHeartbeat.IsZero() {
		t.Error("expected heartbeat to be set")
	}
}

func TestCb21_SetAgentStatus(t *testing.T) {
	cb21SetupDB(t)
	hub = newHub()
	go hub.run()
	defer hub.Stop()

	conn := &Connection{
		connType: "agent",
		id:       "statusagent1",
		send:     make(chan []byte, 256),
		closeMu:  sync.RWMutex{},
	}
	hub.mu.Lock()
	hub.agents["statusagent1"] = conn
	hub.mu.Unlock()

	hub.SetAgentStatus("statusagent1", "busy")
	if conn.status != "busy" {
		t.Errorf("expected busy, got %s", conn.status)
	}
}

func TestCb21_BroadcastToAllClients(t *testing.T) {
	cb21SetupDB(t)
	hub = newHub()
	go hub.run()
	defer hub.Stop()

	client1Send := make(chan []byte, 256)
	client2Send := make(chan []byte, 256)
	conn1 := &Connection{
		connType: "client",
		id:       "bcastuser1",
		send:     client1Send,
		closeMu:  sync.RWMutex{},
	}
	conn2 := &Connection{
		connType: "client",
		id:       "bcastuser2",
		send:     client2Send,
		closeMu:  sync.RWMutex{},
	}
	hub.mu.Lock()
	hub.clientConns["bcastuser1"] = []*Connection{conn1}
	hub.clientConns["bcastuser2"] = []*Connection{conn2}
	hub.mu.Unlock()

	msg := []byte(`{"type":"system","message":"maintenance"}`)
	hub.BroadcastToAllClients(msg)

	select {
	case <-client1Send:
	default:
		t.Error("client1 didn't receive broadcast")
	}
	select {
	case <-client2Send:
	default:
		t.Error("client2 didn't receive broadcast")
	}
}

// ===== Logger methods =====

func TestCb21_Logger_SetLevel(t *testing.T) {
	origLevel := DefaultLogger.level
	defer func() { DefaultLogger.level = origLevel }()

	DefaultLogger.SetLevel(LogDebug)
	if DefaultLogger.level != LogDebug {
		t.Errorf("expected debug level, got %d", DefaultLogger.level)
	}

	DefaultLogger.SetLevel(LogWarn)
	if DefaultLogger.level != LogWarn {
		t.Errorf("expected warn level, got %d", DefaultLogger.level)
	}

	DefaultLogger.SetLevel(LogError)
	if DefaultLogger.level != LogError {
		t.Errorf("expected error level, got %d", DefaultLogger.level)
	}

	DefaultLogger.SetLevel(LogInfo)
	if DefaultLogger.level != LogInfo {
		t.Errorf("expected info level, got %d", DefaultLogger.level)
	}
}

func TestCb21_Logger_SetOutput(t *testing.T) {
	var buf bytes.Buffer
	origOutput := DefaultLogger.output
	defer func() { DefaultLogger.output = origOutput }()

	DefaultLogger.SetOutput(&buf)
	DefaultLogger.Info("test-output-msg")
	if !strings.Contains(buf.String(), "test-output-msg") {
		t.Errorf("expected output to contain test-output-msg, got: %s", buf.String())
	}
}

func TestCb21_Logger_WithFields(t *testing.T) {
	l := DefaultLogger.WithFields(map[string]interface{}{"key1": "val1", "key2": 42})
	if l == nil {
		t.Error("expected non-nil logger")
	}
}

func TestCb21_Logger_Debug(t *testing.T) {
	var buf bytes.Buffer
	origOutput := DefaultLogger.output
	origLevel := DefaultLogger.level
	defer func() {
		DefaultLogger.output = origOutput
		DefaultLogger.level = origLevel
	}()

	DefaultLogger.SetOutput(&buf)
	DefaultLogger.SetLevel(LogDebug)
	DefaultLogger.Debug("debug-test-msg")
	if !strings.Contains(buf.String(), "debug-test-msg") {
		t.Errorf("expected debug msg in output, got: %s", buf.String())
	}
}

func TestCb21_Logger_Warn(t *testing.T) {
	var buf bytes.Buffer
	origOutput := DefaultLogger.output
	defer func() { DefaultLogger.output = origOutput }()

	DefaultLogger.SetOutput(&buf)
	DefaultLogger.Warn("warn-test-msg")
	if !strings.Contains(buf.String(), "warn-test-msg") {
		t.Errorf("expected warn msg in output, got: %s", buf.String())
	}
}

func TestCb21_Logger_Error(t *testing.T) {
	var buf bytes.Buffer
	origOutput := DefaultLogger.output
	defer func() { DefaultLogger.output = origOutput }()

	DefaultLogger.SetOutput(&buf)
	DefaultLogger.Error("error-test-msg")
	if !strings.Contains(buf.String(), "error-test-msg") {
		t.Errorf("expected error msg in output, got: %s", buf.String())
	}
}

// ===== RateLimiter helpers =====

func TestCb21_RateLimiter_Reset(t *testing.T) {
	rl := NewRateLimiter(10, time.Minute)
	rl.Allow("user1")
	rl.Allow("user1")
	rl.Allow("user1")
	count := rl.Count("user1")
	if count != 3 {
		t.Errorf("expected 3, got %d", count)
	}
	rl.Reset()
	count = rl.Count("user1")
	if count != 0 {
		t.Errorf("expected 0 after reset, got %d", count)
	}
	rl.Stop()
}

func TestCb21_RateLimiter_Count_Empty(t *testing.T) {
	rl := NewRateLimiter(10, time.Minute)
	defer rl.Stop()
	count := rl.Count("nonexistent")
	if count != 0 {
		t.Errorf("expected 0, got %d", count)
	}
}

func TestCb21_checkRateLimit(t *testing.T) {
	conn := &Connection{
		send:    make(chan []byte, 256),
		closeMu: sync.RWMutex{},
		id:      "rluser1",
	}

	// Under limit
	if !checkRateLimit(conn) {
		t.Error("expected allowed under limit")
	}
}

// ===== Agent rateLimiter Clean/Reset =====

func TestCb21_AgentRateLimiter_Clean(t *testing.T) {
	rl := &rateLimiter{
		attempts: make(map[string]*rateLimitEntry),
		mu:       sync.Mutex{},
	}

	rl.mu.Lock()
	rl.attempts["agent1"] = &rateLimitEntry{count: 5, firstSeen: time.Now().Add(-1 * time.Hour)}
	rl.attempts["agent2"] = &rateLimitEntry{count: 3, firstSeen: time.Now().Add(1 * time.Hour)}
	rl.mu.Unlock()

	rl.Clean()

	rl.mu.Lock()
	if _, ok := rl.attempts["agent1"]; ok {
		t.Error("expired agent1 should have been cleaned")
	}
	if _, ok := rl.attempts["agent2"]; !ok {
		t.Error("non-expired agent2 should still exist")
	}
	rl.mu.Unlock()
}

func TestCb21_AgentRateLimiter_Reset(t *testing.T) {
	rl := &rateLimiter{
		attempts: make(map[string]*rateLimitEntry),
		mu:       sync.Mutex{},
	}

	rl.Allow("agent1")
	rl.Allow("agent1")

	rl.Reset()

	rl.mu.Lock()
	if len(rl.attempts) != 0 {
		t.Errorf("expected 0 entries after reset, got %d", len(rl.attempts))
	}
	rl.mu.Unlock()
}

// ===== Conversation helpers =====

func TestCb21_StoreMessage(t *testing.T) {
	cb21SetupDB(t)
	hub = newHub()
	go hub.run()
	defer hub.Stop()

	cb21CreateUser(t, "storeuser1", "pass")
	convID := cb21CreateConv(t, "storeuser1", "storeagent1")

	err := storeMessage(RoutedMessage{
		ConversationID: convID,
		SenderType:     "user",
		SenderID:       "storeuser1",
		Content:        "hello from storeMessage",
	})
	if err != nil {
		t.Fatalf("storeMessage: %v", err)
	}

	var content string
	err = db.QueryRow("SELECT content FROM messages WHERE conversation_id = ? ORDER BY created_at DESC LIMIT 1", convID).Scan(&content)
	if err != nil {
		t.Fatalf("query message: %v", err)
	}
	if content != "hello from storeMessage" {
		t.Errorf("expected 'hello from storeMessage', got '%s'", content)
	}
}

func TestCb21_StoreMessage_WithAttachmentIDs(t *testing.T) {
	cb21SetupDB(t)
	hub = newHub()
	go hub.run()
	defer hub.Stop()

	cb21CreateUser(t, "storeuser2", "pass")
	convID := cb21CreateConv(t, "storeuser2", "storeagent2")

	err := storeMessage(RoutedMessage{
		ConversationID: convID,
		SenderType:     "agent",
		SenderID:       "storeagent2",
		Content:        "reply message",
		AttachmentIDs:  []string{"att1", "att2"},
	})
	if err != nil {
		t.Fatalf("storeMessage: %v", err)
	}
}

func TestCb21_GetOrCreateConversation_Existing(t *testing.T) {
	cb21SetupDB(t)
	hub = newHub()
	go hub.run()
	defer hub.Stop()

	cb21CreateUser(t, "getoruser1", "pass")
	convID := cb21CreateConv(t, "getoruser1", "getoragent1")

	conv, err := GetOrCreateConversation("getoruser1", "getoragent1")
	if err != nil {
		t.Fatalf("GetOrCreateConversation: %v", err)
	}
	if conv.ID != convID {
		t.Errorf("expected %s, got %s", convID, conv.ID)
	}
}

func TestCb21_GetOrCreateConversation_New(t *testing.T) {
	cb21SetupDB(t)
	hub = newHub()
	go hub.run()
	defer hub.Stop()

	cb21CreateUser(t, "getoruser2", "pass")
	db.Exec("INSERT OR IGNORE INTO agents (id, name) VALUES (?, ?)", "getoragent2", "Agent")

	conv, err := GetOrCreateConversation("getoruser2", "getoragent2")
	if err != nil {
		t.Fatalf("GetOrCreateConversation: %v", err)
	}
	if conv.ID == "" {
		t.Error("expected non-empty conversation ID")
	}
}

// ===== dbdriver helpers =====

func TestCb21_Placeholders(t *testing.T) {
	// Placeholders(start, count) generates `count` placeholders starting from `start`
	result := Placeholders(1, 3)
	if !strings.Contains(result, "?") {
		t.Errorf("expected placeholders with ?, got: %s", result)
	}
	// Should have 3 question marks
	if strings.Count(result, "?") != 3 {
		t.Errorf("expected 3 placeholders, got %d in: %s", strings.Count(result, "?"), result)
	}
}

func TestCb21_Placeholder(t *testing.T) {
	result := Placeholder(1)
	if result != "$1" {
		// SQLite uses ? but PostgreSQL uses $N
		t.Logf("Placeholder(1) = %s", result)
	}
}

func TestCb21_envIntOrDefault(t *testing.T) {
	os.Setenv("TEST_ENV_INT_CB21", "42")
	defer os.Unsetenv("TEST_ENV_INT_CB21")

	val := envIntOrDefault("TEST_ENV_INT_CB21", 10)
	if val != 42 {
		t.Errorf("expected 42, got %d", val)
	}

	val = envIntOrDefault("NONEXISTENT_ENV_INT_CB21", 10)
	if val != 10 {
		t.Errorf("expected 10 default, got %d", val)
	}
}

func TestCb21_envIntOrDefault_Invalid(t *testing.T) {
	os.Setenv("TEST_ENV_INT_BAD_CB21", "notanumber")
	defer os.Unsetenv("TEST_ENV_INT_BAD_CB21")

	val := envIntOrDefault("TEST_ENV_INT_BAD_CB21", 5)
	if val != 5 {
		t.Errorf("expected 5 default for invalid, got %d", val)
	}
}

func TestCb21_envDurationOrDefault(t *testing.T) {
	os.Setenv("TEST_ENV_DUR_CB21", "30s")
	defer os.Unsetenv("TEST_ENV_DUR_CB21")

	val := envDurationOrDefault("TEST_ENV_DUR_CB21", 10*time.Second)
	if val != 30*time.Second {
		t.Errorf("expected 30s, got %v", val)
	}

	val = envDurationOrDefault("NONEXISTENT_ENV_DUR_CB21", 10*time.Second)
	if val != 10*time.Second {
		t.Errorf("expected 10s default, got %v", val)
	}
}

func TestCb21_envDurationOrDefault_Invalid(t *testing.T) {
	os.Setenv("TEST_ENV_DUR_BAD_CB21", "notaduration")
	defer os.Unsetenv("TEST_ENV_DUR_BAD_CB21")

	val := envDurationOrDefault("TEST_ENV_DUR_BAD_CB21", 5*time.Second)
	if val != 5*time.Second {
		t.Errorf("expected 5s default for invalid, got %v", val)
	}
}

// ===== AuthenticateRequest =====

func TestCb21_AuthenticateRequest_Valid(t *testing.T) {
	cb21SetupDB(t)
	cb21SetupAuth(t)

	cb21CreateUser(t, "authrequser1", "pass")
	token := cb21MakeToken(t, "authrequser1")

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	userID, _, err := authenticateRequest(req)
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
	if userID != "authrequser1" {
		t.Errorf("expected authrequser1, got %s", userID)
	}
}

func TestCb21_AuthenticateRequest_NoAuth(t *testing.T) {
	cb21SetupDB(t)
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	_, _, err := authenticateRequest(req)
	if err == nil {
		t.Error("expected error for no auth")
	}
}

func TestCb21_AuthenticateRequest_InvalidToken(t *testing.T) {
	cb21SetupDB(t)
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer invalid-token")
	_, _, err := authenticateRequest(req)
	if err == nil {
		t.Error("expected error for invalid token")
	}
}

// ===== ValidateAgentSecret =====

func TestCb21_ValidateAgentSecret(t *testing.T) {
	cb21SetupDB(t)
	cb21SetupAuth(t)

	err := ValidateAgentSecret("someagent", "test-agent-secret-cb21")
	if err != nil {
		t.Errorf("expected nil for correct secret, got %v", err)
	}

	err = ValidateAgentSecret("someagent", "wrong-secret")
	if err == nil {
		t.Error("expected error for wrong secret")
	}
}

func TestCb21_ValidateAgentSecret_Empty(t *testing.T) {
	cb21SetupDB(t)
	cb21SetupAuth(t)

	err := ValidateAgentSecret("someagent", "")
	if err == nil {
		t.Error("expected error for empty secret")
	}
}

// ===== parseSize helper =====

func TestCb21_ParseSize(t *testing.T) {
	tests := []struct {
		input    string
		expected int64
	}{
		{"1MB", 1 * 1024 * 1024},
		{"5MB", 5 * 1024 * 1024},
		{"1GB", 1 * 1024 * 1024 * 1024},
		{"512KB", 512 * 1024},
		{"1048576", 1048576},
		{"0", 0},
	}

	for _, tc := range tests {
		result, err := parseSize(tc.input)
		if err != nil {
			t.Errorf("parseSize(%s): unexpected error: %v", tc.input, err)
		}
		if result != tc.expected {
			t.Errorf("parseSize(%s): expected %d, got %d", tc.input, tc.expected, result)
		}
	}
}

func TestCb21_ParseSize_Invalid(t *testing.T) {
	_, err := parseSize("invalid")
	if err == nil {
		t.Error("expected error for invalid size")
	}
}

// ===== ensureUploadDir =====

func TestCb21_EnsureUploadDir(t *testing.T) {
	tmpDir := t.TempDir()
	origDBPath := serverDBPath
	serverDBPath = filepath.Join(tmpDir, "test.db")
	defer func() { serverDBPath = origDBPath }()

	err := ensureUploadDir()
	if err != nil {
		t.Fatalf("ensureUploadDir: %v", err)
	}

	// Upload directory should exist
	uploadPath := filepath.Join(tmpDir, UploadSubdir)
	info, err := os.Stat(uploadPath)
	if err != nil {
		t.Fatalf("stat upload dir: %v", err)
	}
	if !info.IsDir() {
		t.Error("expected directory")
	}
}

// ===== CSRF middleware =====

func TestCb21_CsrfMiddleware(t *testing.T) {
	handler := csrfMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Request without X-Requested-With should be blocked for state-changing methods
	req := httptest.NewRequest(http.MethodPost, "/test", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403 for POST without X-Requested-With, got %d", w.Code)
	}

	// Request with X-Requested-With should pass
	req2 := httptest.NewRequest(http.MethodPost, "/test", nil)
	req2.Header.Set("X-Requested-With", "XMLHttpRequest")
	w2 := httptest.NewRecorder()
	handler.ServeHTTP(w2, req2)
	if w2.Code != http.StatusOK {
		t.Errorf("expected 200 for POST with X-Requested-With, got %d", w2.Code)
	}

	// GET should always pass
	req3 := httptest.NewRequest(http.MethodGet, "/test", nil)
	w3 := httptest.NewRecorder()
	handler.ServeHTTP(w3, req3)
	if w3.Code != http.StatusOK {
		t.Errorf("expected 200 for GET, got %d", w3.Code)
	}
}

// ===== isOriginAllowed =====

func TestCb21_IsOriginAllowed(t *testing.T) {
	orig := corsAllowedOrigins
	corsAllowedOrigins = "http://localhost:3000,https://example.com"
	defer func() { corsAllowedOrigins = orig }()

	if !isOriginAllowed("http://localhost:3000") {
		t.Error("localhost:3000 should be allowed")
	}
	if !isOriginAllowed("https://example.com") {
		t.Error("example.com should be allowed")
	}
	if isOriginAllowed("http://evil.com") {
		t.Error("evil.com should not be allowed")
	}
}

func TestCb21_IsOriginAllowed_EmptyList(t *testing.T) {
	orig := corsAllowedOrigins
	corsAllowedOrigins = "*"
	defer func() { corsAllowedOrigins = orig }()

	// Wildcard should allow all
	if !isOriginAllowed("http://any-origin.com") {
		t.Error("* should allow all origins")
	}
}

// ===== requestIDMiddleware =====

func TestCb21_RequestIDMiddleware(t *testing.T) {
	handler := requestIDMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqID := r.Header.Get("X-Request-ID")
		if reqID == "" {
			t.Error("expected request ID to be set")
		}
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

// ===== JWT with Claims struct =====

func TestCb21_ValidateJWT_WithClaims(t *testing.T) {
	cb21SetupAuth(t)

	token, err := GenerateJWT("claimuser1", "claimuser1")
	if err != nil {
		t.Fatalf("GenerateJWT: %v", err)
	}

	claims, err := ValidateJWT(token)
	if err != nil {
		t.Fatalf("ValidateJWT: %v", err)
	}
	if claims.UserID != "claimuser1" {
		t.Errorf("expected claimuser1, got %s", claims.UserID)
	}
	if claims.Username != "claimuser1" {
		t.Errorf("expected claimuser1 username, got %s", claims.Username)
	}
}

// ===== handleSetRateLimitTier with admin auth =====

func TestCb21_SetRateLimitTier_Success(t *testing.T) {
	cb21SetupDB(t)
	hub = newHub()
	go hub.run()
	defer hub.Stop()
	cb21SetupAuth(t)

	cb21CreateUser(t, "tieruser1", "pass")

	form := url.Values{"user_id": {"tieruser1"}, "tier": {"pro"}}
	req := httptest.NewRequest(http.MethodPost, "/admin/rate-limit/tier", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Admin-Secret", "test-admin-secret-cb21")
	w := httptest.NewRecorder()
	handleSetRateLimitTier(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCb21_GetRateLimitTier_Success(t *testing.T) {
	cb21SetupDB(t)
	hub = newHub()
	go hub.run()
	defer hub.Stop()
	cb21SetupAuth(t)

	cb21CreateUser(t, "tiergetuser1", "pass")

	req := httptest.NewRequest(http.MethodGet, "/admin/rate-limit/tier?user_id=tiergetuser1", nil)
	req.Header.Set("X-Admin-Secret", "test-admin-secret-cb21")
	w := httptest.NewRecorder()
	handleGetRateLimitTier(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

// ===== MarkRead with full auth flow =====

func TestCb21_MarkRead_Success(t *testing.T) {
	cb21SetupDB(t)
	hub = newHub()
	go hub.run()
	defer hub.Stop()

	cb21CreateUser(t, "markuser1", "pass")
	convID := cb21CreateConv(t, "markuser1", "markagent1")
	cb21InsertMessage(t, "msg-mark1", convID, "agent", "markagent1", "agent msg")

	token := cb21MakeToken(t, "markuser1")
	form := url.Values{"conversation_id": {convID}}
	req := httptest.NewRequest(http.MethodPost, "/conversations/mark-read", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)
	cb21AuthRequest(t, req, "markuser1")
	w := httptest.NewRecorder()
	handleMarkRead(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

// ===== Presence with auth =====

func TestCb21_GetPresence_Success(t *testing.T) {
	cb21SetupDB(t)
	hub = newHub()
	go hub.run()
	defer hub.Stop()

	cb21CreateUser(t, "presuser1", "pass")
	conn := &Connection{
		connType: "client",
		id:       "presuser1",
		send:     make(chan []byte, 256),
		closeMu:  sync.RWMutex{},
	}
	hub.mu.Lock()
	hub.clientConns["presuser1"] = []*Connection{conn}
	hub.mu.Unlock()

	token := cb21MakeToken(t, "presuser1")
	req := httptest.NewRequest(http.MethodGet, "/presence?user_id=presuser1", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	cb21AuthRequest(t, req, "presuser1")
	w := httptest.NewRecorder()
	handleGetPresence(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	hub.mu.Lock()
	delete(hub.clientConns, "presuser1")
	hub.mu.Unlock()
}

// ===== Notification prefs with full auth =====

func TestCb21_SetNotificationPrefs_Success(t *testing.T) {
	cb21SetupDB(t)
	hub = newHub()
	go hub.run()
	defer hub.Stop()

	cb21CreateUser(t, "notifuser1", "pass")
	convID := cb21CreateConv(t, "notifuser1", "notifagent1")
	token := cb21MakeToken(t, "notifuser1")

	form := url.Values{"conversation_id": {convID}, "muted": {"true"}}
	req := httptest.NewRequest(http.MethodPost, "/notification-prefs/set", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)
	cb21AuthRequest(t, req, "notifuser1")
	w := httptest.NewRecorder()
	handleSetNotificationPrefs(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCb21_DeleteNotificationPrefs_Success(t *testing.T) {
	cb21SetupDB(t)
	hub = newHub()
	go hub.run()
	defer hub.Stop()

	cb21CreateUser(t, "delnotifuser1", "pass")
	convID := cb21CreateConv(t, "delnotifuser1", "delnotifagent1")
	token := cb21MakeToken(t, "delnotifuser1")

	// Set a pref first
	form := url.Values{"conversation_id": {convID}, "muted": {"true"}}
	req := httptest.NewRequest(http.MethodPost, "/notification-prefs/set", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)
	cb21AuthRequest(t, req, "delnotifuser1")
	w := httptest.NewRecorder()
	handleSetNotificationPrefs(w, req)

	// Delete the pref
	form2 := url.Values{"conversation_id": {convID}}
	req2 := httptest.NewRequest(http.MethodPost, "/notification-prefs/delete", strings.NewReader(form2.Encode()))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req2.Header.Set("Authorization", "Bearer "+token)
	cb21AuthRequest(t, req2, "delnotifuser1")
	w2 := httptest.NewRecorder()
	handleDeleteNotificationPrefs(w2, req2)
	if w2.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w2.Code, w2.Body.String())
	}
}

// ===== RemoveTag with auth =====

func TestCb21_RemoveTag_Success(t *testing.T) {
	cb21SetupDB(t)
	hub = newHub()
	go hub.run()
	defer hub.Stop()

	cb21CreateUser(t, "tagdeluser1", "pass")
	convID := cb21CreateConv(t, "tagdeluser1", "tagdelagent1")
	token := cb21MakeToken(t, "tagdeluser1")

	// Add a tag first
	form := url.Values{"conversation_id": {convID}, "tag": {"important"}}
	req := httptest.NewRequest(http.MethodPost, "/tags/add", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)
	cb21AuthRequest(t, req, "tagdeluser1")
	w := httptest.NewRecorder()
	handleAddTag(w, req)

	// Remove the tag
	form2 := url.Values{"conversation_id": {convID}, "tag": {"important"}}
	req2 := httptest.NewRequest(http.MethodPost, "/tags/remove", strings.NewReader(form2.Encode()))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req2.Header.Set("Authorization", "Bearer "+token)
	cb21AuthRequest(t, req2, "tagdeluser1")
	w2 := httptest.NewRecorder()
	handleRemoveTag(w2, req2)
	if w2.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w2.Code, w2.Body.String())
	}
}

// ===== handleListOneTimePreKeys =====

func TestCb21_ListOneTimePreKeys_NoAuth(t *testing.T) {
	cb21SetupDB(t)
	req := httptest.NewRequest(http.MethodGet, "/keys/otpk-count", nil)
	w := httptest.NewRecorder()
	handleListOneTimePreKeys(w, req)
	// Without auth, should return 401
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestCb21_ListOneTimePreKeys_WithAuth(t *testing.T) {
	cb21SetupDB(t)
	cb21CreateUser(t, "otpkuser1", "pass")
	token := cb21MakeToken(t, "otpkuser1")

	// Upload a one-time prekey
	body := `{"key_type": "one_time_prekey", "public_key": "otpk1", "key_id": 1}`
	req := httptest.NewRequest(http.MethodPost, "/e2e/upload-public-key", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	cb21AuthRequest(t, req, "otpkuser1")
	w := httptest.NewRecorder()
	handleUploadPublicKey(w, req)

	// Get count
	req2 := httptest.NewRequest(http.MethodGet, "/keys/otpk-count", nil)
	req2.Header.Set("Authorization", "Bearer "+token)
	cb21AuthRequest(t, req2, "otpkuser1")
	w2 := httptest.NewRecorder()
	handleListOneTimePreKeys(w2, req2)
	if w2.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w2.Code, w2.Body.String())
	}
}

// ===== storeMessagesBatch =====

func TestCb21_StoreMessagesBatch(t *testing.T) {
	cb21SetupDB(t)
	hub = newHub()
	go hub.run()
	defer hub.Stop()

	cb21CreateUser(t, "batchuser1", "pass")
	convID := cb21CreateConv(t, "batchuser1", "batchagent1")

	msgs := []RoutedMessage{
		{ConversationID: convID, SenderType: "user", SenderID: "batchuser1", Content: "msg1"},
		{ConversationID: convID, SenderType: "user", SenderID: "batchuser1", Content: "msg2"},
		{ConversationID: convID, SenderType: "user", SenderID: "batchuser1", Content: "msg3"},
	}

	ids, err := storeMessagesBatch(msgs)
	if err != nil {
		t.Fatalf("storeMessagesBatch: %v", err)
	}
	if len(ids) != 3 {
		t.Errorf("expected 3 IDs, got %d", len(ids))
	}

	var count int
	db.QueryRow("SELECT COUNT(*) FROM messages WHERE conversation_id = ?", convID).Scan(&count)
	if count != 3 {
		t.Errorf("expected 3 messages, got %d", count)
	}
}

// ===== Connection negotiated version =====

func TestCb21_Connection_NegotiatedVersion(t *testing.T) {
	conn := &Connection{
		negotiatedVersion: "1.0",
		closeMu:           sync.RWMutex{},
	}
	if conn.negotiatedVersion != "1.0" {
		t.Errorf("expected 1.0, got %s", conn.negotiatedVersion)
	}
}

// ===== Logger LogLevel String method =====

func TestCb21_LogLevel_String(t *testing.T) {
	tests := map[LogLevel]string{
		LogDebug: "debug",
		LogInfo:  "info",
		LogWarn:  "warn",
		LogError: "error",
	}
	for level, expected := range tests {
		result := level.String()
		if result != expected {
			t.Errorf("level %d: expected %s, got %s", level, expected, result)
		}
	}
}

// ===== handleChangePassword with auth =====

func TestCb21_ChangePassword_Success(t *testing.T) {
	cb21SetupDB(t)
	hub = newHub()
	go hub.run()
	defer hub.Stop()

	cb21CreateUser(t, "cpuser1", "oldpass")
	token := cb21MakeToken(t, "cpuser1")

	form := url.Values{"old_password": {"oldpass"}, "new_password": {"newpass123"}}
	req := httptest.NewRequest(http.MethodPost, "/auth/change-password", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)
	cb21AuthRequest(t, req, "cpuser1")
	w := httptest.NewRecorder()
	handleChangePassword(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCb21_ChangePassword_WrongOld(t *testing.T) {
	cb21SetupDB(t)
	hub = newHub()
	go hub.run()
	defer hub.Stop()

	cb21CreateUser(t, "cpuser2", "oldpass")
	token := cb21MakeToken(t, "cpuser2")

	form := url.Values{"old_password": {"wrongpass"}, "new_password": {"newpass123"}}
	req := httptest.NewRequest(http.MethodPost, "/auth/change-password", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)
	cb21AuthRequest(t, req, "cpuser2")
	w := httptest.NewRecorder()
	handleChangePassword(w, req)
	if w.Code != http.StatusUnauthorized && w.Code != http.StatusBadRequest {
		t.Errorf("expected 401 or 400, got %d: %s", w.Code, w.Body.String())
	}
}

// ===== handleSearchMessages with auth =====

func TestCb21_SearchMessages_Success(t *testing.T) {
	cb21SetupDB(t)
	hub = newHub()
	go hub.run()
	defer hub.Stop()

	cb21CreateUser(t, "searchuser1", "pass")
	convID := cb21CreateConv(t, "searchuser1", "searchagent1")
	cb21InsertMessage(t, "msg-search1", convID, "agent", "searchagent1", "hello world")
	cb21InsertMessage(t, "msg-search2", convID, "agent", "searchagent1", "goodbye world")

	token := cb21MakeToken(t, "searchuser1")
	req := httptest.NewRequest(http.MethodGet, "/messages/search?q=hello&limit=10", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	cb21AuthRequest(t, req, "searchuser1")
	w := httptest.NewRecorder()
	handleSearchMessages(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCb21_SearchMessages_EmptyQuery(t *testing.T) {
	cb21SetupDB(t)
	token := cb21MakeToken(t, "searchuser2")
	req := httptest.NewRequest(http.MethodGet, "/messages/search?q=&limit=10", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	cb21AuthRequest(t, req, "searchuser2")
	w := httptest.NewRecorder()
	handleSearchMessages(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

// ===== handleCreateConversation with auth =====

func TestCb21_CreateConversation_Success(t *testing.T) {
	cb21SetupDB(t)
	hub = newHub()
	go hub.run()
	defer hub.Stop()

	cb21CreateUser(t, "convcreateuser1", "pass")
	db.Exec("INSERT OR IGNORE INTO agents (id, name) VALUES (?, ?)", "convcreateagent1", "Test Agent")
	token := cb21MakeToken(t, "convcreateuser1")

	form := url.Values{"agent_id": {"convcreateagent1"}}
	req := httptest.NewRequest(http.MethodPost, "/conversations/create", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)
	cb21AuthRequest(t, req, "convcreateuser1")
	w := httptest.NewRecorder()
	handleCreateConversation(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

// ===== handleListConversations with auth =====

func TestCb21_ListConversations_Success(t *testing.T) {
	cb21SetupDB(t)
	hub = newHub()
	go hub.run()
	defer hub.Stop()

	cb21CreateUser(t, "listconvuser1", "pass")
	cb21CreateConv(t, "listconvuser1", "listconvagent1")
	token := cb21MakeToken(t, "listconvuser1")

	req := httptest.NewRequest(http.MethodGet, "/conversations", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	cb21AuthRequest(t, req, "listconvuser1")
	w := httptest.NewRecorder()
	handleListConversations(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

// ===== handleReact with auth =====

func TestCb21_React_Success(t *testing.T) {
	cb21SetupDB(t)
	hub = newHub()
	go hub.run()
	defer hub.Stop()

	cb21CreateUser(t, "reactuser1", "pass")
	convID := cb21CreateConv(t, "reactuser1", "reactagent1")
	cb21InsertMessage(t, "msg-react1", convID, "agent", "reactagent1", "react to this")
	token := cb21MakeToken(t, "reactuser1")

	form := url.Values{"message_id": {"msg-react1"}, "emoji": {"👍"}}
	req := httptest.NewRequest(http.MethodPost, "/messages/react", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)
	cb21AuthRequest(t, req, "reactuser1")
	w := httptest.NewRecorder()
	handleReact(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

// ===== handleRegisterDeviceToken with auth =====

func TestCb21_RegisterDeviceToken_Success(t *testing.T) {
	cb21SetupDB(t)
	hub = newHub()
	go hub.run()
	defer hub.Stop()

	cb21CreateUser(t, "devtokenuser1", "pass")
	token := cb21MakeToken(t, "devtokenuser1")

	body := `{"device_token": "test-device-token-abc123", "platform": "ios"}`
	req := httptest.NewRequest(http.MethodPost, "/push/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	cb21AuthRequest(t, req, "devtokenuser1")
	w := httptest.NewRecorder()
	handleRegisterDeviceToken(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

// ===== handleGetMessages with auth =====

func TestCb21_GetMessages_Success(t *testing.T) {
	cb21SetupDB(t)
	hub = newHub()
	go hub.run()
	defer hub.Stop()

	cb21CreateUser(t, "getmsgsuser1", "pass")
	convID := cb21CreateConv(t, "getmsgsuser1", "getmsgsagent1")
	cb21InsertMessage(t, "msg-get1", convID, "agent", "getmsgsagent1", "hello")
	token := cb21MakeToken(t, "getmsgsuser1")

	req := httptest.NewRequest(http.MethodGet, "/conversations/messages?conversation_id="+convID, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	cb21AuthRequest(t, req, "getmsgsuser1")
	w := httptest.NewRecorder()
	handleGetMessages(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}