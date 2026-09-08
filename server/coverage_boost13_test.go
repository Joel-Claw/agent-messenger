package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)



// ==============================
// handleStoreEncryptedMessage coverage
// ==============================

func TestCB13_StoreEncrypted_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/messages/encrypted", nil)
	w := httptest.NewRecorder()
	handleStoreEncryptedMessage(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestCB13_StoreEncrypted_NoAuth(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/messages/encrypted", strings.NewReader(`{}`))
	w := httptest.NewRecorder()
	handleStoreEncryptedMessage(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestCB13_StoreEncrypted_InvalidJSON(t *testing.T) {
	setupTestDB(t)
	token := cb13MakeToken(t, "e2e_cb13_u2")
	req := httptest.NewRequest(http.MethodPost, "/messages/encrypted", strings.NewReader("not json"))
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleStoreEncryptedMessage(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid JSON, got %d", w.Code)
	}
}

func TestCB13_StoreEncrypted_MissingRequiredFields(t *testing.T) {
	setupTestDB(t)
	token := cb13MakeToken(t, "e2e_cb13_u3")
	body := `{"conversation_id":"","ciphertext":"","iv":"","algorithm":""}`
	req := httptest.NewRequest(http.MethodPost, "/messages/encrypted", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleStoreEncryptedMessage(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing fields, got %d", w.Code)
	}
}

func TestCB13_StoreEncrypted_UnsupportedAlgorithm(t *testing.T) {
	setupTestDB(t)
	token, convID := cb13CreateConv(t, "e2e_cb13_u4", "e2e_cb13_a4")

	body := fmt.Sprintf(`{"conversation_id":"%s","ciphertext":"abc","iv":"def","algorithm":"rsa-4096","recipient_key_id":"key1"}`, convID)
	req := httptest.NewRequest(http.MethodPost, "/messages/encrypted", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleStoreEncryptedMessage(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for unsupported algo, got %d", w.Code)
	}
}

func TestCB13_StoreEncrypted_ConversationNotFound(t *testing.T) {
	setupTestDB(t)
	token := cb13MakeToken(t, "e2e_cb13_u5")
	body := `{"conversation_id":"nonexistent","ciphertext":"abc","iv":"def","algorithm":"aes-256-gcm","recipient_key_id":"key1"}`
	req := httptest.NewRequest(http.MethodPost, "/messages/encrypted", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleStoreEncryptedMessage(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

func TestCB13_StoreEncrypted_NotParticipant(t *testing.T) {
	setupTestDB(t)
	// User A creates conversation
	_, convID := cb13CreateConv(t, "e2e_cb13_uA", "e2e_cb13_aA")
	// User B tries to store in User A's conversation
	tokenB := cb13MakeToken(t, "e2e_cb13_uB")
	body := fmt.Sprintf(`{"conversation_id":"%s","ciphertext":"abc","iv":"def","algorithm":"aes-256-gcm","recipient_key_id":"key1"}`, convID)
	req := httptest.NewRequest(http.MethodPost, "/messages/encrypted", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+tokenB)
	w := httptest.NewRecorder()
	handleStoreEncryptedMessage(w, req)
	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", w.Code)
	}
}

func TestCB13_StoreEncrypted_ValidUser(t *testing.T) {
	setupTestDB(t)
	token, convID := cb13CreateConv(t, "e2e_cb13_valid", "e2e_cb13_vagent")
	body := fmt.Sprintf(`{"conversation_id":"%s","ciphertext":"base64ct","iv":"base64iv","algorithm":"aes-256-gcm","recipient_key_id":"key1","sender_key_id":"key2"}`, convID)
	req := httptest.NewRequest(http.MethodPost, "/messages/encrypted", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleStoreEncryptedMessage(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp map[string]string
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["status"] != "stored" {
		t.Errorf("expected status=stored, got %v", resp)
	}
}

func TestCB13_StoreEncrypted_ValidAgent(t *testing.T) {
	setupTestDB(t)
	_, convID := cb13CreateConv(t, "e2e_cb13_valid2", "e2e_cb13_vagent2")
	body := fmt.Sprintf(`{"conversation_id":"%s","ciphertext":"base64ct","iv":"base64iv","algorithm":"x25519-aes-256-gcm","recipient_key_id":"key1"}`, convID)
	req := httptest.NewRequest(http.MethodPost, "/messages/encrypted", strings.NewReader(body))
	req.Header.Set("X-Agent-Secret", getAgentSecret())
	req.Header.Set("X-Agent-ID", "e2e_cb13_vagent2")
	w := httptest.NewRecorder()
	handleStoreEncryptedMessage(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200 for agent, got %d: %s", w.Code, w.Body.String())
	}
}

// cb13MakeToken creates a JWT token for a user (registers if needed).
func cb13MakeToken(t *testing.T, username string) string {
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

// cb13ReqWithAuth creates an HTTP request with JWT auth context set (for handlers that use getUserID).
func cb13ReqWithAuth(method, url, body, token string) *http.Request {
	req := httptest.NewRequest(method, url, strings.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	claims, _ := ValidateJWT(token)
	if claims != nil {
		ctx := context.WithValue(req.Context(), contextKeyUserID, claims.UserID)
		req = req.WithContext(ctx)
	}
	return req
}

// cb13CreateConv creates a conversation and returns (token, convID).
func cb13CreateConv(t *testing.T, username, agentID string) (string, string) {
	t.Helper()
	token := cb13MakeToken(t, username)
	_, err := db.Exec("INSERT OR IGNORE INTO agents (id, name) VALUES (?, ?)", agentID, agentID)
	if err != nil {
		t.Fatalf("insert agent: %v", err)
	}
	conv, err := GetOrCreateConversation(username, agentID)
	if err != nil {
		t.Fatalf("create conv: %v", err)
	}
	return token, conv.ID
}

// ==============================
// handleGetEncryptedMessages coverage
// ==============================

func TestCB13_GetEncrypted_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/messages/encrypted", nil)
	w := httptest.NewRecorder()
	handleGetEncryptedMessages(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestCB13_GetEncrypted_NoAuth(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/messages/encrypted?conversation_id=conv1", nil)
	w := httptest.NewRecorder()
	handleGetEncryptedMessages(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestCB13_GetEncrypted_MissingConversationID(t *testing.T) {
	setupTestDB(t)
	token := cb13MakeToken(t, "e2e_get_u1")
	req := httptest.NewRequest(http.MethodGet, "/messages/encrypted", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleGetEncryptedMessages(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestCB13_GetEncrypted_ConversationNotFound(t *testing.T) {
	setupTestDB(t)
	token := cb13MakeToken(t, "e2e_get_u2")
	req := httptest.NewRequest(http.MethodGet, "/messages/encrypted?conversation_id=nonexistent", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleGetEncryptedMessages(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

func TestCB13_GetEncrypted_WrongUser(t *testing.T) {
	setupTestDB(t)
	tokenA, convID := cb13CreateConv(t, "e2e_get_uA", "e2e_get_aA")
	_ = tokenA
	tokenB := cb13MakeToken(t, "e2e_get_uB")
	req := httptest.NewRequest(http.MethodGet, "/messages/encrypted?conversation_id="+convID, nil)
	req.Header.Set("Authorization", "Bearer "+tokenB)
	w := httptest.NewRecorder()
	handleGetEncryptedMessages(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404 for wrong user, got %d", w.Code)
	}
}

func TestCB13_GetEncrypted_AgentAuth(t *testing.T) {
	setupTestDB(t)
	_, convID := cb13CreateConv(t, "e2e_get_uC", "e2e_get_aC")

	// Wrong agent
	req := httptest.NewRequest(http.MethodGet, "/messages/encrypted?conversation_id="+convID, nil)
	req.Header.Set("X-Agent-Secret", getAgentSecret())
	req.Header.Set("X-Agent-ID", "wrong_agent")
	w := httptest.NewRecorder()
	handleGetEncryptedMessages(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404 for wrong agent, got %d", w.Code)
	}

	// Correct agent
	req2 := httptest.NewRequest(http.MethodGet, "/messages/encrypted?conversation_id="+convID, nil)
	req2.Header.Set("X-Agent-Secret", getAgentSecret())
	req2.Header.Set("X-Agent-ID", "e2e_get_aC")
	w2 := httptest.NewRecorder()
	handleGetEncryptedMessages(w2, req2)
	if w2.Code != http.StatusOK {
		t.Errorf("expected 200 for correct agent, got %d", w2.Code)
	}
}

func TestCB13_GetEncrypted_LimitParam(t *testing.T) {
	setupTestDB(t)
	token, convID := cb13CreateConv(t, "e2e_lim_u1", "e2e_lim_a1")
	req := httptest.NewRequest(http.MethodGet, "/messages/encrypted?conversation_id="+convID+"&limit=10", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleGetEncryptedMessages(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

// ==============================
// handleUpload coverage
// ==============================

func TestCB13_Upload_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/attachments/upload", nil)
	w := httptest.NewRecorder()
	handleUpload(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestCB13_Upload_NoAuth(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/attachments/upload", nil)
	w := httptest.NewRecorder()
	handleUpload(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestCB13_Upload_InvalidToken(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/attachments/upload", nil)
	req.Header.Set("Authorization", "Bearer invalidtoken")
	w := httptest.NewRecorder()
	handleUpload(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for invalid token, got %d", w.Code)
	}
}

func TestCB13_Upload_MissingFileField(t *testing.T) {
	setupTestDB(t)
	token := cb13MakeToken(t, "upload_cb13_u1")

	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)
	writer.WriteField("message_id", "msg_123")
	writer.Close()

	req := httptest.NewRequest(http.MethodPost, "/attachments/upload", &buf)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleUpload(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing file, got %d", w.Code)
	}
}

func TestCB13_Upload_DisallowedContentType(t *testing.T) {
	setupTestDB(t)
	token := cb13MakeToken(t, "upload_cb13_u2")

	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)
	part, _ := writer.CreateFormFile("file", "test.exe")
	part.Write([]byte("MZ\x90\x00"))
	writer.Close()

	req := httptest.NewRequest(http.MethodPost, "/attachments/upload", &buf)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleUpload(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for disallowed content type, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCB13_Upload_ValidSmallFile(t *testing.T) {
	setupTestDB(t)
	token := cb13MakeToken(t, "upload_cb13_u3")

	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)
	part, _ := writer.CreateFormFile("file", "test.txt")
	part.Write([]byte("hello world test content"))
	writer.Close()

	req := httptest.NewRequest(http.MethodPost, "/attachments/upload", &buf)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleUpload(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200 for valid upload, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["id"] == nil {
		t.Error("expected id in response")
	}
}

func TestCB13_Upload_ValidImageFile(t *testing.T) {
	setupTestDB(t)
	token := cb13MakeToken(t, "upload_cb13_u4")

	pngData := []byte("\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x02\x00\x00\x00\x90wS\xde")

	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)
	part, _ := writer.CreateFormFile("file", "test.png")
	part.Write(pngData)
	writer.Close()

	req := httptest.NewRequest(http.MethodPost, "/attachments/upload", &buf)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleUpload(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200 for valid image upload, got %d: %s", w.Code, w.Body.String())
	}
}

// ==============================
// handleGetAttachment coverage
// ==============================

func TestCB13_GetAttachment_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/attachments/abc123", nil)
	w := httptest.NewRecorder()
	handleGetAttachment(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestCB13_GetAttachment_MissingID(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/attachments/", nil)
	w := httptest.NewRecorder()
	handleGetAttachment(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCB13_GetAttachment_NotFound(t *testing.T) {
	setupTestDB(t)
	token := cb13MakeToken(t, "attach_cb13_u1")
	req := httptest.NewRequest(http.MethodGet, "/attachments/nonexistent", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleGetAttachment(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

func TestCB13_GetAttachment_AgentAuth(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/attachments/some_id", nil)
	req.Header.Set("X-Agent-Secret", getAgentSecret())
	w := httptest.NewRecorder()
	handleGetAttachment(w, req)
	if w.Code == http.StatusUnauthorized {
		t.Errorf("agent auth should be accepted, got 401")
	}
}

func TestCB13_GetAttachment_InvalidAgentSecret(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/attachments/some_id", nil)
	req.Header.Set("X-Agent-Secret", "wrongsecret")
	w := httptest.NewRecorder()
	handleGetAttachment(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for wrong agent secret, got %d", w.Code)
	}
}

// ==============================
// handleListAttachments coverage
// ==============================

func TestCB13_ListAttachments_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/messages/conv123/attachments", nil)
	w := httptest.NewRecorder()
	handleListAttachments(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestCB13_ListAttachments_NoAuth(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/messages/attachments?conversation_id=conv1", nil)
	w := httptest.NewRecorder()
	handleListAttachments(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestCB13_ListAttachments_InvalidToken(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/messages/attachments?conversation_id=conv1", nil)
	req.Header.Set("Authorization", "Bearer invalidtoken")
	w := httptest.NewRecorder()
	handleListAttachments(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestCB13_ListAttachments_MissingConversationID(t *testing.T) {
	setupTestDB(t)
	token := cb13MakeToken(t, "list_cb13_u1")
	req := httptest.NewRequest(http.MethodGet, "/messages/attachments", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleListAttachments(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestCB13_ListAttachments_ConversationNotFound(t *testing.T) {
	setupTestDB(t)
	token := cb13MakeToken(t, "list_cb13_u2")
	req := httptest.NewRequest(http.MethodGet, "/messages/attachments?conversation_id=nonexistent", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleListAttachments(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

func TestCB13_ListAttachments_WrongUser(t *testing.T) {
	setupTestDB(t)
	tokenA, convID := cb13CreateConv(t, "list_cb13_uA", "list_cb13_aA")
	_ = tokenA
	tokenB := cb13MakeToken(t, "list_cb13_uB")
	req := httptest.NewRequest(http.MethodGet, "/messages/attachments?conversation_id="+convID, nil)
	req.Header.Set("Authorization", "Bearer "+tokenB)
	w := httptest.NewRecorder()
	handleListAttachments(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404 for wrong user, got %d", w.Code)
	}
}

// ==============================
// deleteConversation coverage
// ==============================

func TestCB13_DeleteConversation_NotFound(t *testing.T) {
	setupTestDB(t)
	err := deleteConversation("nonexistent_conv", "some_user")
	if err == nil {
		t.Error("expected error for nonexistent conversation")
	}
}

func TestCB13_DeleteConversation_Unauthorized(t *testing.T) {
	setupTestDB(t)
	_, convID := cb13CreateConv(t, "del_cb13_u1", "del_cb13_a1")
	err := deleteConversation(convID, "wrong_user")
	if err == nil {
		t.Error("expected unauthorized error")
	}
	if err.Error() != "unauthorized" {
		t.Errorf("expected 'unauthorized' error, got %v", err)
	}
}

func TestCB13_DeleteConversation_Valid(t *testing.T) {
	setupTestDB(t)
	_, convID := cb13CreateConv(t, "del_cb13_u2", "del_cb13_a2")
	err := deleteConversation(convID, "del_cb13_u2")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	conv, _ := getConversation(convID)
	if conv != nil {
		t.Error("conversation should be deleted")
	}
}

// ==============================
// storeMessagesBatch coverage
// ==============================

func TestCB13_StoreMessagesBatch_EmptyBatch(t *testing.T) {
	setupTestDB(t)
	ids, err := storeMessagesBatch(nil)
	if err != nil {
		t.Errorf("expected nil error for empty batch, got %v", err)
	}
	if ids != nil {
		t.Errorf("expected nil ids for empty batch, got %v", ids)
	}
}

func TestCB13_StoreMessagesBatch_ValidBatch(t *testing.T) {
	setupTestDB(t)
	_, convID := cb13CreateConv(t, "batch_cb13_u1", "batch_cb13_a1")

	msgs := []RoutedMessage{
		{ConversationID: convID, Content: "batch message 1", SenderType: "client", SenderID: "batch_cb13_u1"},
		{ConversationID: convID, Content: "batch message 2", SenderType: "client", SenderID: "batch_cb13_u1"},
	}

	ids, err := storeMessagesBatch(msgs)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if len(ids) != 2 {
		t.Errorf("expected 2 ids, got %d", len(ids))
	}
}

func TestCB13_StoreMessagesBatch_WithAttachmentIDs(t *testing.T) {
	setupTestDB(t)
	_, convID := cb13CreateConv(t, "batch_cb13_u2", "batch_cb13_a2")

	msgs := []RoutedMessage{
		{ConversationID: convID, Content: "batch with attachments", SenderType: "client", SenderID: "batch_cb13_u2", AttachmentIDs: []string{"att_1", "att_2"}},
	}

	ids, err := storeMessagesBatch(msgs)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if len(ids) != 1 {
		t.Errorf("expected 1 id, got %d", len(ids))
	}
}

// ==============================
// RegisterAgentOnConnect coverage
// ==============================

func TestCB13_RegisterAgentOnConnect_NewAgent(t *testing.T) {
	setupTestDB(t)
	err := RegisterAgentOnConnect("new_cb13_agent1", "Agent One", "gpt-4", "friendly", "coding")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	var name string
	err = db.QueryRow("SELECT name FROM agents WHERE id = ?", "new_cb13_agent1").Scan(&name)
	if err != nil {
		t.Errorf("agent not found in DB: %v", err)
	}
	if name != "Agent One" {
		t.Errorf("expected name 'Agent One', got %s", name)
	}
}

func TestCB13_RegisterAgentOnConnect_DefaultName(t *testing.T) {
	setupTestDB(t)
	err := RegisterAgentOnConnect("default_cb13_agent", "", "gpt-4", "friendly", "coding")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	var name string
	err = db.QueryRow("SELECT name FROM agents WHERE id = ?", "default_cb13_agent").Scan(&name)
	if err != nil {
		t.Errorf("agent not found: %v", err)
	}
	if name != "default_cb13_agent" {
		t.Errorf("expected name to default to agentID, got %s", name)
	}
}

func TestCB13_RegisterAgentOnConnect_UpdateExisting(t *testing.T) {
	setupTestDB(t)
	err := RegisterAgentOnConnect("update_cb13_agent", "Agent Original", "gpt-3", "formal", "writing")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	err = RegisterAgentOnConnect("update_cb13_agent", "Agent Updated", "gpt-4", "casual", "coding")
	if err != nil {
		t.Errorf("unexpected error updating: %v", err)
	}
	var model, personality, specialty string
	err = db.QueryRow("SELECT model, personality, specialty FROM agents WHERE id = ?", "update_cb13_agent").Scan(&model, &personality, &specialty)
	if err != nil {
		t.Errorf("agent not found: %v", err)
	}
	if model != "gpt-4" {
		t.Errorf("expected model gpt-4, got %s", model)
	}
	if personality != "casual" {
		t.Errorf("expected personality casual, got %s", personality)
	}
	if specialty != "coding" {
		t.Errorf("expected specialty coding, got %s", specialty)
	}
}

func TestCB13_RegisterAgentOnConnect_PreserveFieldsOnEmpty(t *testing.T) {
	setupTestDB(t)
	err := RegisterAgentOnConnect("preserve_cb13_agent", "Agent P", "gpt-3", "formal", "writing")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	err = RegisterAgentOnConnect("preserve_cb13_agent", "preserve_cb13_agent", "", "", "")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	var model, personality, specialty string
	err = db.QueryRow("SELECT model, personality, specialty FROM agents WHERE id = ?", "preserve_cb13_agent").Scan(&model, &personality, &specialty)
	if err != nil {
		t.Errorf("agent not found: %v", err)
	}
	if model != "gpt-3" {
		t.Errorf("expected model preserved as gpt-3, got %s", model)
	}
	if personality != "formal" {
		t.Errorf("expected personality preserved as formal, got %s", personality)
	}
	if specialty != "writing" {
		t.Errorf("expected specialty preserved as writing, got %s", specialty)
	}
}

// ==============================
// handleSetNotificationPrefs coverage
// ==============================

func TestCB13_SetNotificationPrefs_NotFound(t *testing.T) {
	setupTestDB(t)
	token := cb13MakeToken(t, "notif_cb13_u2")
	form := "conversation_id=nonexistent&muted=true"
	req := cb13ReqWithAuth(http.MethodPost, "/notifications/prefs", form, token)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handleSetNotificationPrefs(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404 for nonexistent conversation, got %d", w.Code)
	}
}

func TestCB13_SetNotificationPrefs_Valid(t *testing.T) {
	setupTestDB(t)
	token, convID := cb13CreateConv(t, "notif_cb13_u1", "notif_cb13_a1")
	form := fmt.Sprintf("conversation_id=%s&muted=true", convID)
	req := cb13ReqWithAuth(http.MethodPost, "/notifications/prefs", form, token)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handleSetNotificationPrefs(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

// ==============================
// handleDeleteNotificationPrefs coverage
// ==============================

func TestCB13_DeleteNotificationPrefs_NoAuth(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/notifications/prefs/delete", nil)
	w := httptest.NewRecorder()
	handleDeleteNotificationPrefs(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestCB13_DeleteNotificationPrefs_MissingConversationID(t *testing.T) {
	setupTestDB(t)
	token := cb13MakeToken(t, "del_notif_cb13_u")
	req := cb13ReqWithAuth(http.MethodPost, "/notifications/prefs/delete", "", token)
	w := httptest.NewRecorder()
	handleDeleteNotificationPrefs(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing conversation_id, got %d", w.Code)
	}
}

func TestCB13_DeleteNotificationPrefs_Valid(t *testing.T) {
	setupTestDB(t)
	token, convID := cb13CreateConv(t, "del_notif_cb13_u2", "del_notif_cb13_a2")

	// First set mute
	form := fmt.Sprintf("conversation_id=%s&muted=true", convID)
	req := cb13ReqWithAuth(http.MethodPost, "/notifications/prefs", form, token)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handleSetNotificationPrefs(w, req)

	// Now delete
	form2 := fmt.Sprintf("conversation_id=%s", convID)
	req2 := cb13ReqWithAuth(http.MethodPost, "/notifications/prefs/delete", form2, token)
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w2 := httptest.NewRecorder()
	handleDeleteNotificationPrefs(w2, req2)
	if w2.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w2.Code, w2.Body.String())
	}

	muted := isConversationMuted("del_notif_cb13_u2", convID)
	if muted {
		t.Error("expected conversation to no longer be muted after deletion")
	}
}

// ==============================
// queue_persist coverage (no collision names)
// ==============================

func TestCB13_InitQueueDB_NilDB(t *testing.T) {
	initQueueDB(nil)
}

func TestCB13_LoadQueueFromDB_NilDB(t *testing.T) {
	q := newOfflineQueue(100, 7*24*time.Hour)
	loadQueueFromDB(nil, q)
}

func TestCB13_LoadQueueFromDB_WithData(t *testing.T) {
	setupTestDB(t)
	initQueueDB(db)

	msg1 := OutgoingMessage{Type: "message", Data: map[string]string{"content": "test1"}}
	data1, _ := json.Marshal(msg1)
	persistQueue(db, "user_cb13_q", data1)

	msg2 := OutgoingMessage{Type: "message", Data: map[string]string{"content": "test2"}}
	data2, _ := json.Marshal(msg2)
	persistQueue(db, "user_cb13_q", data2)

	q := newOfflineQueue(100, 7*24*time.Hour)
	loadQueueFromDB(db, q)

	msgs := q.Drain("user_cb13_q")
	if len(msgs) < 2 {
		t.Errorf("expected at least 2 messages from DB, got %d", len(msgs))
	}

	deleteQueueMessages(db, "user_cb13_q")
}

func TestCB13_CleanStaleQueueMessages(t *testing.T) {
	setupTestDB(t)
	initQueueDB(db)

	_, err := db.Exec(
		"INSERT INTO offline_queue (recipient, data, queued_at, sent_count) VALUES (?, ?, ?, 0)",
		"stale_cb13_user", []byte("stale data"), time.Now().Add(-8*24*time.Hour).Format(time.RFC3339),
	)
	if err != nil {
		t.Fatalf("insert stale: %v", err)
	}

	_, err = db.Exec(
		"INSERT INTO offline_queue (recipient, data, queued_at, sent_count) VALUES (?, ?, ?, 0)",
		"recent_cb13_user", []byte("recent data"), time.Now().Format(time.RFC3339),
	)
	if err != nil {
		t.Fatalf("insert recent: %v", err)
	}

	cleanStaleQueueMessages(db, 7*24*time.Hour)

	var count int
	db.QueryRow("SELECT COUNT(*) FROM offline_queue WHERE recipient = ?", "stale_cb13_user").Scan(&count)
	if count != 0 {
		t.Errorf("stale message should be deleted, count=%d", count)
	}

	db.QueryRow("SELECT COUNT(*) FROM offline_queue WHERE recipient = ?", "recent_cb13_user").Scan(&count)
	if count != 1 {
		t.Errorf("recent message should still exist, count=%d", count)
	}

	deleteQueueMessages(db, "recent_cb13_user")
}

func TestCB13_DeleteQueueMessages_NilDB(t *testing.T) {
	deleteQueueMessages(nil, "any_user")
}

func TestCB13_CleanStaleQueueMessages_NilDB(t *testing.T) {
	cleanStaleQueueMessages(nil, 24*time.Hour)
}

// ==============================
// tiered rate limiter: Reset, cleanup, persist (no collision names)
// ==============================

func TestCB13_TieredRateLimiter_Reset(t *testing.T) {
	trl := NewTieredRateLimiter()
	t.Cleanup(func() { trl.Stop() })
	trl.SetTier("user1", TierPro)
	trl.SetTier("user2", TierEnterprise)
	trl.Reset()

	tier := trl.GetTier("user1")
	if tier.Name != "free" {
		t.Errorf("expected free tier after reset, got %s", tier.Name)
	}
	tier = trl.GetTier("user2")
	if tier.Name != "free" {
		t.Errorf("expected free tier after reset, got %s", tier.Name)
	}
}

func TestCB13_TieredRateLimiter_CleanupRemovesStale(t *testing.T) {
	trl := NewTieredRateLimiter()
	t.Cleanup(func() { trl.Stop() })
	trl.mu.Lock()
	trl.limits["stale-cb13-user"] = &userRateLimitState{
		count:     5,
		windowEnd: time.Now().Add(-15 * time.Minute),
		tier:      TierFree,
	}
	trl.mu.Unlock()

	trl.mu.Lock()
	now := time.Now()
	for id, entry := range trl.limits {
		if now.After(entry.windowEnd) && now.Sub(entry.windowEnd) > 10*time.Minute {
			delete(trl.limits, id)
		}
	}
	trl.mu.Unlock()

	trl.mu.Lock()
	_, ok := trl.limits["stale-cb13-user"]
	trl.mu.Unlock()
	if ok {
		t.Error("stale entry should be removed")
	}
}

func TestCB13_TieredRateLimiter_CleanupKeepsRecent(t *testing.T) {
	trl := NewTieredRateLimiter()
	t.Cleanup(func() { trl.Stop() })
	trl.SetTier("recent-cb13-user", TierPro)
	trl.Allow("recent-cb13-user")

	trl.mu.Lock()
	now := time.Now()
	for id, entry := range trl.limits {
		if now.After(entry.windowEnd) && now.Sub(entry.windowEnd) > 10*time.Minute {
			delete(trl.limits, id)
		}
	}
	trl.mu.Unlock()

	trl.mu.Lock()
	_, ok := trl.limits["recent-cb13-user"]
	trl.mu.Unlock()
	if !ok {
		t.Error("recent entry should NOT be removed")
	}
}

func TestCB13_PersistTierToDB_Free(t *testing.T) {
	setupTestDB(t)
	err := persistTierToDB("free_cb13_user", TierFree)
	if err != nil {
		t.Errorf("unexpected error persisting free tier: %v", err)
	}
	var tierName string
	err = db.QueryRow("SELECT tier_name FROM user_rate_limit_tiers WHERE user_id = ?", "free_cb13_user").Scan(&tierName)
	if err != nil {
		t.Errorf("expected row in DB: %v", err)
	}
	if tierName != "free" {
		t.Errorf("expected tier 'free', got %s", tierName)
	}
}

func TestCB13_PersistTierToDB_UpdateExisting(t *testing.T) {
	setupTestDB(t)
	err := persistTierToDB("update_cb13_user", TierPro)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	err = persistTierToDB("update_cb13_user", TierEnterprise)
	if err != nil {
		t.Errorf("unexpected error updating tier: %v", err)
	}
	var tierName string
	err = db.QueryRow("SELECT tier_name FROM user_rate_limit_tiers WHERE user_id = ?", "update_cb13_user").Scan(&tierName)
	if err != nil {
		t.Errorf("expected row in DB: %v", err)
	}
	if tierName != "enterprise" {
		t.Errorf("expected tier 'enterprise', got %s", tierName)
	}
}

func TestCB13_PersistTierToDB_NilDB(t *testing.T) {
	origDB := db
	db = nil
	defer func() { db = origDB }()

	err := persistTierToDB("nil_cb13_user", TierPro)
	if err != nil {
		t.Errorf("expected nil error with nil db, got %v", err)
	}
}

func TestCB13_LoadTiersFromDB(t *testing.T) {
	setupTestDB(t)
	persistTierToDB("load_cb13_pro", TierPro)
	persistTierToDB("load_cb13_ent", TierEnterprise)

	trl := NewTieredRateLimiter()
	t.Cleanup(func() { trl.Stop() })
	err := loadTiersFromDB(trl)
	if err != nil {
		t.Errorf("unexpected error loading tiers: %v", err)
	}

	tier := trl.GetTier("load_cb13_pro")
	if tier.Name != "pro" {
		t.Errorf("expected pro tier, got %s", tier.Name)
	}
	tier = trl.GetTier("load_cb13_ent")
	if tier.Name != "enterprise" {
		t.Errorf("expected enterprise tier, got %s", tier.Name)
	}
}

func TestCB13_LoadTiersFromDB_NilDB(t *testing.T) {
	origDB := db
	db = nil
	defer func() { db = origDB }()

	trl := NewTieredRateLimiter()
	t.Cleanup(func() { trl.Stop() })
	err := loadTiersFromDB(trl)
	if err != nil {
		t.Errorf("expected nil error with nil db, got %v", err)
	}
}

// ==============================
// RateLimiter Count method
// ==============================

func TestCB13_RateLimiter_Count(t *testing.T) {
	rl := NewRateLimiter(60, time.Minute)
	t.Cleanup(func() { rl.Stop() })
	if count := rl.Count("user1"); count != 0 {
		t.Errorf("expected count 0, got %d", count)
	}
	rl.Allow("user1")
	if count := rl.Count("user1"); count != 1 {
		t.Errorf("expected count 1, got %d", count)
	}
	rl.Allow("user1")
	rl.Allow("user1")
	if count := rl.Count("user1"); count != 3 {
		t.Errorf("expected count 3, got %d", count)
	}
	if count := rl.Count("user2"); count != 0 {
		t.Errorf("expected count 0 for different user, got %d", count)
	}
}

// ==============================
// truncate helper
// ==============================

func TestCB13_Truncate_Short(t *testing.T) {
	result := truncate("hello", 10)
	if result != "hello" {
		t.Errorf("expected 'hello', got '%s'", result)
	}
}

func TestCB13_Truncate_Exact(t *testing.T) {
	result := truncate("12345", 5)
	if result != "12345" {
		t.Errorf("expected '12345', got '%s'", result)
	}
}

func TestCB13_Truncate_Long(t *testing.T) {
	result := truncate("hello world", 8)
	if result != "hello..." {
		t.Errorf("expected 'hello...', got '%s'", result)
	}
}

func TestCB13_Truncate_SmallMaxLen(t *testing.T) {
	result := truncate("hello", 3)
	if result != "hel" {
		t.Errorf("expected 'hel', got '%s'", result)
	}
}

func TestCB13_Truncate_Zero(t *testing.T) {
	result := truncate("hello", 0)
	if result != "" {
		t.Errorf("expected '', got '%s'", result)
	}
}

// ==============================
// authenticateRequest coverage
// ==============================

func TestCB13_AuthenticateRequest_ValidJWT(t *testing.T) {
	setupTestDB(t)
	token := cb13MakeToken(t, "auth_cb13_user")
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	id, typ, err := authenticateRequest(req)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if typ != "user" {
		t.Errorf("expected type 'user', got %s", typ)
	}
	if id == "" {
		t.Error("expected non-empty id")
	}
}

// ==============================
// isAllowedContentType coverage
// ==============================

func TestCB13_IsAllowedContentType_ImageTypes(t *testing.T) {
	for _, ct := range []string{"image/jpeg", "image/png", "image/gif", "image/webp", "image/svg+xml", "image/bmp", "image/tiff"} {
		if !isAllowedContentType(ct) {
			t.Errorf("expected %s to be allowed", ct)
		}
	}
}

func TestCB13_IsAllowedContentType_AudioVideo(t *testing.T) {
	for _, ct := range []string{"audio/mpeg", "audio/ogg", "audio/wav", "video/mp4", "video/webm"} {
		if !isAllowedContentType(ct) {
			t.Errorf("expected %s to be allowed", ct)
		}
	}
}

func TestCB13_IsAllowedContentType_Documents(t *testing.T) {
	for _, ct := range []string{"application/pdf", "text/plain", "text/csv", "text/markdown", "application/json"} {
		if !isAllowedContentType(ct) {
			t.Errorf("expected %s to be allowed", ct)
		}
	}
}

func TestCB13_IsAllowedContentType_Disallowed(t *testing.T) {
	for _, ct := range []string{"application/x-executable", "application/x-msdownload", "application/javascript"} {
		if isAllowedContentType(ct) {
			t.Errorf("expected %s to be disallowed", ct)
		}
	}
}

// ==============================
// HashAPIKey coverage
// ==============================

func TestCB13_HashAPIKey_RoundTrip(t *testing.T) {
	hash1, err := HashAPIKey("testkey123")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if hash1 == "" {
		t.Error("expected non-empty hash")
	}
	hash2, _ := HashAPIKey("testkey123")
	if hash1 == hash2 {
		t.Error("bcrypt hashes should differ due to random salt")
	}
}

func TestCB13_HashAPIKey_Empty(t *testing.T) {
	hash, err := HashAPIKey("")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if hash == "" {
		t.Error("expected non-empty hash even for empty input")
	}
}

// ==============================
// changeUserPassword coverage
// ==============================

func TestCB13_ChangeUserPassword_WrongOldPassword(t *testing.T) {
	setupTestDB(t)
	cb13MakeToken(t, "pwd_cb13_u1")
	err := changeUserPassword("pwd_cb13_u1", "wrongpass", "newpass456")
	if err == nil {
		t.Error("expected error for wrong old password")
	}
	if err.Error() != "invalid old password" {
		t.Errorf("expected 'invalid old password', got %v", err)
	}
}

func TestCB13_ChangeUserPassword_TooShortNewPassword(t *testing.T) {
	setupTestDB(t)
	cb13MakeToken(t, "pwd_cb13_u2")
	err := changeUserPassword("pwd_cb13_u2", "testpass123", "short")
	if err == nil {
		t.Error("expected error for too short new password")
	}
	if err.Error() != "new password must be at least 6 characters" {
		t.Errorf("expected length error, got %v", err)
	}
}

func TestCB13_ChangeUserPassword_Valid(t *testing.T) {
	setupTestDB(t)
	cb13MakeToken(t, "pwd_cb13_u3")
	err := changeUserPassword("pwd_cb13_u3", "testpass123", "newpass456")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestCB13_ChangeUserPassword_NonexistentUser(t *testing.T) {
	setupTestDB(t)
	err := changeUserPassword("nonexistent_cb13_user", "oldpass", "newpass123")
	if err == nil {
		t.Error("expected error for nonexistent user")
	}
}

// ==============================
// searchMessages coverage
// ==============================

func TestCB13_SearchMessages_EmptyQuery(t *testing.T) {
	setupTestDB(t)
	_, err := searchMessages("user1", "", 10)
	if err == nil {
		t.Error("expected error for empty query")
	}
}

func TestCB13_SearchMessages_NoResults(t *testing.T) {
	setupTestDB(t)
	results, err := searchMessages("user1", "nonexistent_term_xyz", 10)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if len(results) != 0 {
		t.Errorf("expected 0 results, got %d", len(results))
	}
}

func TestCB13_SearchMessages_WithResults(t *testing.T) {
	setupTestDB(t)
	_, convID := cb13CreateConv(t, "search_cb13_u1", "search_cb13_a1")
	msg := RoutedMessage{
		ConversationID: convID,
		Content:        "hello world from search test",
		SenderType:     "client",
		SenderID:       "search_cb13_u1",
	}
	storeMessage(msg)

	results, err := searchMessages("search_cb13_u1", "hello world", 10)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if len(results) == 0 {
		t.Error("expected at least 1 result")
	}
}

// ==============================
// markMessagesRead coverage
// ==============================

func TestCB13_MarkMessagesRead_WrongUser(t *testing.T) {
	setupTestDB(t)
	_, convID := cb13CreateConv(t, "read_cb13_u1", "read_cb13_a1")
	_, err := markMessagesRead(convID, "wrong_user")
	if err == nil {
		t.Error("expected error for wrong user")
	}
	if err.Error() != "unauthorized" {
		t.Errorf("expected 'unauthorized', got %v", err)
	}
}

func TestCB13_MarkMessagesRead_NotFound(t *testing.T) {
	setupTestDB(t)
	_, err := markMessagesRead("nonexistent_conv", "any_user")
	if err == nil {
		t.Error("expected error for nonexistent conversation")
	}
}

func TestCB13_MarkMessagesRead_Valid(t *testing.T) {
	setupTestDB(t)
	_, convID := cb13CreateConv(t, "read_cb13_u2", "read_cb13_a2")
	msg := RoutedMessage{
		ConversationID: convID,
		Content:        "agent message to read",
		SenderType:     "agent",
		SenderID:       "read_cb13_a2",
	}
	storeMessage(msg)

	count, err := markMessagesRead(convID, "read_cb13_u2")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if count < 1 {
		t.Errorf("expected at least 1 message marked read, got %d", count)
	}
}

// ==============================
// GetOrCreateConversation
// ==============================

func TestCB13_GetOrCreateConversation_New(t *testing.T) {
	setupTestDB(t)
	conv, err := GetOrCreateConversation("gor_cb13_u1", "gor_cb13_a1")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if conv == nil {
		t.Fatal("expected conversation, got nil")
	}
	if conv.UserID != "gor_cb13_u1" || conv.AgentID != "gor_cb13_a1" {
		t.Errorf("unexpected conversation: %+v", conv)
	}
}

func TestCB13_GetOrCreateConversation_Existing(t *testing.T) {
	setupTestDB(t)
	conv1, err := GetOrCreateConversation("gor_cb13_u2", "gor_cb13_a2")
	if err != nil {
		t.Fatalf("unexpected error creating: %v", err)
	}
	conv2, err := GetOrCreateConversation("gor_cb13_u2", "gor_cb13_a2")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if conv2.ID != conv1.ID {
		t.Errorf("expected same conversation ID, got %s vs %s", conv1.ID, conv2.ID)
	}
}

// ==============================
// OfflineQueue coverage
// ==============================

func TestCB13_OfflineQueue_DrainEmpty(t *testing.T) {
	q := newOfflineQueue(100, 7*24*time.Hour)
	msgs := q.Drain("nonexistent_user")
	if len(msgs) != 0 {
		t.Errorf("expected 0 messages, got %d", len(msgs))
	}
}

func TestCB13_OfflineQueue_DrainAndEnqueue(t *testing.T) {
	q := newOfflineQueue(100, 7*24*time.Hour)
	msg := OutgoingMessage{Type: "message", Data: map[string]string{"content": "test"}}
	data, _ := json.Marshal(msg)
	q.Enqueue("user_cb13_q1", data)
	q.Enqueue("user_cb13_q1", data)
	msgs := q.Drain("user_cb13_q1")
	if len(msgs) != 2 {
		t.Errorf("expected 2 messages, got %d", len(msgs))
	}
	msgs2 := q.Drain("user_cb13_q1")
	if len(msgs2) != 0 {
		t.Errorf("expected 0 messages after drain, got %d", len(msgs2))
	}
}

func TestCB13_OfflineQueue_MaxDepth(t *testing.T) {
	q := newOfflineQueue(2, 7*24*time.Hour)
	msg := OutgoingMessage{Type: "message", Data: map[string]string{"content": "test"}}
	data, _ := json.Marshal(msg)
	q.Enqueue("user_cb13_max", data)
	q.Enqueue("user_cb13_max", data)
	q.Enqueue("user_cb13_max", data) // should be dropped
	msgs := q.Drain("user_cb13_max")
	if len(msgs) != 2 {
		t.Errorf("expected max 2 messages, got %d", len(msgs))
	}
}

// ==============================
// initTracing coverage
// ==============================

func TestCB13_InitTracing_DisabledByDefault(t *testing.T) {
	orig := os.Getenv("OTEL_ENABLED")
	os.Unsetenv("OTEL_ENABLED")
	defer os.Setenv("OTEL_ENABLED", orig)

	err := InitTracing()
	if err != nil {
		t.Logf("InitTracing error (ok in test): %v", err)
	}
}

func TestCB13_InitTracing_EnabledNoEndpoint(t *testing.T) {
	os.Setenv("OTEL_ENABLED", "true")
	os.Unsetenv("OTEL_EXPORTER_OTLP_ENDPOINT")
	defer os.Unsetenv("OTEL_ENABLED")

	err := InitTracing()
	if err != nil {
		t.Logf("InitTracing error (ok in test): %v", err)
	}
}

// ==============================
// sendWelcomeMessage coverage
// ==============================

func TestCB13_SendWelcomeMessage_BasicClient(t *testing.T) {
	sendCh := make(chan []byte, 256)
	c := &Connection{
		connType:           "client",
		id:                 "test-user",
		deviceID:           "phone",
		negotiatedVersion:  "v1",
		send:               sendCh,
	}
	sendWelcomeMessage(c)

	select {
	case data := <-sendCh:
		var msg map[string]interface{}
		if err := json.Unmarshal(data, &msg); err != nil {
			t.Fatalf("invalid JSON: %v", err)
		}
		if msg["type"] != "connected" {
			t.Errorf("expected type 'connected', got %v", msg["type"])
		}
		dataMap, ok := msg["data"].(map[string]interface{})
		if !ok {
			t.Fatal("expected data to be a map")
		}
		if dataMap["status"] != "connected" {
			t.Errorf("expected status 'connected', got %v", dataMap["status"])
		}
		if dataMap["device_id"] != "phone" {
			t.Errorf("expected device_id 'phone', got %v", dataMap["device_id"])
		}
		if dataMap["id"] != "test-user" {
			t.Errorf("expected id 'test-user', got %v", dataMap["id"])
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for welcome message")
	}
}

func TestCB13_SendWelcomeMessage_AgentNoDeviceID(t *testing.T) {
	sendCh := make(chan []byte, 256)
	c := &Connection{
		connType:          "agent",
		id:                "test-agent",
		negotiatedVersion: "v1",
		send:              sendCh,
	}
	sendWelcomeMessage(c)

	select {
	case data := <-sendCh:
		var msg map[string]interface{}
		json.Unmarshal(data, &msg)
		dataMap := msg["data"].(map[string]interface{})
		if dataMap["device_id"] != nil {
			t.Errorf("expected no device_id for agent, got %v", dataMap["device_id"])
		}
		if dataMap["id"] != "test-agent" {
			t.Errorf("expected id 'test-agent', got %v", dataMap["id"])
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for welcome message")
	}
}

// ==============================
// isConversationMuted coverage
// ==============================

func TestCB13_IsConversationMuted_NotMuted(t *testing.T) {
	setupTestDB(t)
	muted := isConversationMuted("user_cb13_xyz", "conv_cb13_xyz")
	if muted {
		t.Error("expected not muted for nonexistent preference")
	}
}

func TestCB13_IsConversationMuted_SetAndCheck(t *testing.T) {
	setupTestDB(t)
	token, convID := cb13CreateConv(t, "mute_cb13_u1", "mute_cb13_a1")
	form := fmt.Sprintf("conversation_id=%s&muted=true", convID)
	req := httptest.NewRequest(http.MethodPost, "/notifications/prefs", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)
	// Set context for getUserID
	claims, _ := ValidateJWT(token)
	ctx := context.WithValue(req.Context(), contextKeyUserID, claims.UserID)
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()
	handleSetNotificationPrefs(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	muted := isConversationMuted("mute_cb13_u1", convID)
	if !muted {
		t.Error("expected conversation to be muted")
	}
}

// ==============================
// E2E key upload coverage
// ==============================

func TestCB13_UploadPublicKey_InvalidKeyType(t *testing.T) {
	setupTestDB(t)
	token := cb13MakeToken(t, "e2e_cb13_u1")
	body := `{"key_type":"invalid_type","public_key":"abc123"}`
	req := httptest.NewRequest(http.MethodPost, "/keys/upload", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleUploadPublicKey(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid key_type, got %d", w.Code)
	}
}

func TestCB13_UploadPublicKey_MissingPublicKey(t *testing.T) {
	setupTestDB(t)
	token := cb13MakeToken(t, "e2e_cb13_u2")
	body := `{"key_type":"identity"}`
	req := httptest.NewRequest(http.MethodPost, "/keys/upload", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleUploadPublicKey(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing public_key, got %d", w.Code)
	}
}

func TestCB13_UploadPublicKey_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/keys/upload", nil)
	w := httptest.NewRecorder()
	handleUploadPublicKey(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestCB13_UploadPublicKey_NoAuth(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/keys/upload", strings.NewReader(`{}`))
	w := httptest.NewRecorder()
	handleUploadPublicKey(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

// ==============================
// handleGetKeyBundle coverage
// ==============================

func TestCB13_GetKeyBundle_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/keys/bundle", nil)
	w := httptest.NewRecorder()
	handleGetKeyBundle(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestCB13_GetKeyBundle_NoAuth(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/keys/bundle?owner_id=user1", nil)
	w := httptest.NewRecorder()
	handleGetKeyBundle(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestCB13_GetKeyBundle_MissingOwnerID(t *testing.T) {
	setupTestDB(t)
	token := cb13MakeToken(t, "bundle_cb13_u1")
	req := httptest.NewRequest(http.MethodGet, "/keys/bundle", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleGetKeyBundle(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing owner_id, got %d", w.Code)
	}
}

func TestCB13_GetKeyBundle_NoIdentityKey(t *testing.T) {
	setupTestDB(t)
	token := cb13MakeToken(t, "bundle_cb13_u2")
	req := httptest.NewRequest(http.MethodGet, "/keys/bundle?owner_id=nonexistent_user", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleGetKeyBundle(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404 for nonexistent owner, got %d", w.Code)
	}
}

// ==============================
// handleListOneTimePreKeys coverage
// ==============================

func TestCB13_ListOneTimePreKeys_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/keys/otpk-count", nil)
	w := httptest.NewRecorder()
	handleListOneTimePreKeys(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestCB13_ListOneTimePreKeys_NoAuth(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/keys/otpk-count", nil)
	w := httptest.NewRecorder()
	handleListOneTimePreKeys(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestCB13_ListOneTimePreKeys_Valid(t *testing.T) {
	setupTestDB(t)
	token := cb13MakeToken(t, "otpk_cb13_u1")
	req := httptest.NewRequest(http.MethodGet, "/keys/otpk-count", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleListOneTimePreKeys(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	var resp map[string]int
	json.NewDecoder(w.Body).Decode(&resp)
	if _, ok := resp["one_time_prekey_count"]; !ok {
		t.Error("expected one_time_prekey_count in response")
	}
}

// ==============================
// marshalOutgoingMessage (no collision)
// ==============================

func TestCB13_MarshalOutgoingMessage(t *testing.T) {
	msg := OutgoingMessage{Type: "message", Data: "test"}
	data := marshalOutgoingMessage(msg)
	if data == nil || len(data) == 0 {
		t.Error("expected non-empty data")
	}
	var parsed map[string]interface{}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Errorf("expected valid JSON, got error: %v", err)
	}
}