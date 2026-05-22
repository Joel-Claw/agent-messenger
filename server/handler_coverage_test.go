package main

import (
	"bytes"
	"encoding/json"
	"mime/multipart"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
)

// TestRegisterAgentOnConnectNewAgent tests creating a brand new agent on connect
func TestRegisterAgentOnConnectNewAgent(t *testing.T) {
	setupTestDB(t)

	err := RegisterAgentOnConnect("new-agent-1", "New Agent", "gpt-4", "friendly", "coding")
	if err != nil {
		t.Fatalf("RegisterAgentOnConnect failed: %v", err)
	}

	var name, model, personality, specialty string
	err = db.QueryRow("SELECT name, model, personality, specialty FROM agents WHERE id = ?", "new-agent-1").Scan(&name, &model, &personality, &specialty)
	if err != nil {
		t.Fatalf("Failed to query agent: %v", err)
	}
	if name != "New Agent" {
		t.Errorf("Expected name 'New Agent', got %s", name)
	}
	if model != "gpt-4" {
		t.Errorf("Expected model 'gpt-4', got %s", model)
	}
	if personality != "friendly" {
		t.Errorf("Expected personality 'friendly', got %s", personality)
	}
	if specialty != "coding" {
		t.Errorf("Expected specialty 'coding', got %s", specialty)
	}
}

// TestRegisterAgentOnConnectDefaultName tests that agentID is used as name when name is empty
func TestRegisterAgentOnConnectDefaultName(t *testing.T) {
	setupTestDB(t)

	err := RegisterAgentOnConnect("my-agent", "", "", "", "")
	if err != nil {
		t.Fatalf("RegisterAgentOnConnect failed: %v", err)
	}

	var name string
	err = db.QueryRow("SELECT name FROM agents WHERE id = ?", "my-agent").Scan(&name)
	if err != nil {
		t.Fatalf("Failed to query agent: %v", err)
	}
	if name != "my-agent" {
		t.Errorf("Expected name to default to agentID 'my-agent', got %s", name)
	}
}

// TestRegisterAgentOnConnectUpdateMetadata tests updating metadata for existing agent
func TestRegisterAgentOnConnectUpdateMetadata(t *testing.T) {
	setupTestDB(t)

	// Create agent first
	err := RegisterAgentOnConnect("existing-agent", "Original", "", "", "")
	if err != nil {
		t.Fatalf("First RegisterAgentOnConnect failed: %v", err)
	}

	// Update with new metadata
	err = RegisterAgentOnConnect("existing-agent", "Updated", "claude-3", "professional", "writing")
	if err != nil {
		t.Fatalf("Second RegisterAgentOnConnect failed: %v", err)
	}

	var model, personality, specialty string
	err = db.QueryRow("SELECT model, personality, specialty FROM agents WHERE id = ?", "existing-agent").Scan(&model, &personality, &specialty)
	if err != nil {
		t.Fatalf("Failed to query agent: %v", err)
	}
	if model != "claude-3" {
		t.Errorf("Expected model 'claude-3', got %s", model)
	}
	if personality != "professional" {
		t.Errorf("Expected personality 'professional', got %s", personality)
	}
	if specialty != "writing" {
		t.Errorf("Expected specialty 'writing', got %s", specialty)
	}
}

// TestRegisterAgentOnConnectPreservesMetadata tests that empty fields don't overwrite existing data
func TestRegisterAgentOnConnectPreservesMetadata(t *testing.T) {
	setupTestDB(t)

	// Create agent with all metadata
	err := RegisterAgentOnConnect("preserve-agent", "Agent", "gpt-4", "friendly", "coding")
	if err != nil {
		t.Fatalf("First RegisterAgentOnConnect failed: %v", err)
	}

	// Reconnect with empty metadata — should NOT overwrite
	err = RegisterAgentOnConnect("preserve-agent", "Agent", "", "", "")
	if err != nil {
		t.Fatalf("Second RegisterAgentOnConnect failed: %v", err)
	}

	var model, personality, specialty string
	err = db.QueryRow("SELECT model, personality, specialty FROM agents WHERE id = ?", "preserve-agent").Scan(&model, &personality, &specialty)
	if err != nil {
		t.Fatalf("Failed to query agent: %v", err)
	}
	if model != "gpt-4" {
		t.Errorf("Expected model 'gpt-4' preserved, got %s", model)
	}
	if personality != "friendly" {
		t.Errorf("Expected personality 'friendly' preserved, got %s", personality)
	}
	if specialty != "coding" {
		t.Errorf("Expected specialty 'coding' preserved, got %s", specialty)
	}
}

// TestRegisterAgentOnConnectNameUpdate tests that name is updated when explicitly provided
func TestRegisterAgentOnConnectNameUpdate(t *testing.T) {
	setupTestDB(t)

	// Create with default name (agentID)
	err := RegisterAgentOnConnect("rename-agent", "", "", "", "")
	if err != nil {
		t.Fatalf("First RegisterAgentOnConnect failed: %v", err)
	}

	// Update with a real name (different from agentID)
	err = RegisterAgentOnConnect("rename-agent", "Renamed Agent", "", "", "")
	if err != nil {
		t.Fatalf("Second RegisterAgentOnConnect failed: %v", err)
	}

	var name string
	err = db.QueryRow("SELECT name FROM agents WHERE id = ?", "rename-agent").Scan(&name)
	if err != nil {
		t.Fatalf("Failed to query agent: %v", err)
	}
	if name != "Renamed Agent" {
		t.Errorf("Expected name 'Renamed Agent', got %s", name)
	}
}

// TestRegisterAgentOnConnectNameNotOverwrittenByDefault tests that name=agentID doesn't overwrite existing name
func TestRegisterAgentOnConnectNameNotOverwrittenByDefault(t *testing.T) {
	setupTestDB(t)

	// Create with explicit name
	err := RegisterAgentOnConnect("nametest-agent", "Good Name", "", "", "")
	if err != nil {
		t.Fatalf("First RegisterAgentOnConnect failed: %v", err)
	}

	// Reconnect with default name (agentID) — should NOT overwrite
	err = RegisterAgentOnConnect("nametest-agent", "nametest-agent", "", "", "")
	if err != nil {
		t.Fatalf("Second RegisterAgentOnConnect failed: %v", err)
	}

	var name string
	err = db.QueryRow("SELECT name FROM agents WHERE id = ?", "nametest-agent").Scan(&name)
	if err != nil {
		t.Fatalf("Failed to query agent: %v", err)
	}
	if name != "Good Name" {
		t.Errorf("Expected name 'Good Name' preserved (not overwritten by agentID), got %s", name)
	}
}

// TestHandleUploadSuccess tests successful file upload
func TestHandleUploadSuccess(t *testing.T) {
	setupTestDB(t)
	hub = newHub()
	go hub.run()

	token := registerUserAndGetToken(t, "uploaduser", "pass123")

	// Create a test file
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	part, err := writer.CreateFormFile("file", "test.txt")
	if err != nil {
		t.Fatalf("Failed to create form file: %v", err)
	}
	_, err = part.Write([]byte("Hello, World!"))
	if err != nil {
		t.Fatalf("Failed to write to part: %v", err)
	}
	writer.Close()

	req := httptest.NewRequest("POST", "/attachments/upload", body)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleUpload(w, req)

	if w.Code != 200 {
		t.Fatalf("Expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var attachment Attachment
	json.Unmarshal(w.Body.Bytes(), &attachment)
	if attachment.ID == "" {
		t.Error("Expected attachment ID to be set")
	}
	if attachment.Filename != "test.txt" {
		t.Errorf("Expected filename 'test.txt', got %s", attachment.Filename)
	}
	if attachment.ContentType != "text/plain; charset=utf-8" && attachment.ContentType != "application/octet-stream" {
		t.Logf("Content type: %s (may vary by system)", attachment.ContentType)
	}
	if attachment.Size != 13 {
		t.Errorf("Expected size 13, got %d", attachment.Size)
	}
	if attachment.Sha256 == "" {
		t.Error("Expected sha256 to be set")
	}

	// Verify attachment metadata was stored in DB
	var attachCount int
	db.QueryRow("SELECT COUNT(*) FROM attachments WHERE user_id = ?", getUserIDFromToken(t, token)).Scan(&attachCount)
	if attachCount != 1 {
		t.Errorf("Expected 1 attachment in DB, got %d", attachCount)
	}

	// Clean up upload dir if created
	uploadDir := getUploadDir()
	if uploadDir != "" {
		os.RemoveAll(uploadDir)
	}
}

// TestHandleUploadUnauthorized tests upload without auth
func TestHandleUploadNoAuth(t *testing.T) {
	setupTestDB(t)

	req := httptest.NewRequest("POST", "/attachments/upload", nil)
	w := httptest.NewRecorder()
	handleUpload(w, req)

	if w.Code != 401 {
		t.Errorf("Expected 401, got %d", w.Code)
	}
}

// TestHandleUploadWrongMethod tests upload with wrong HTTP method
func TestHandleUploadWrongMethod(t *testing.T) {
	setupTestDB(t)

	req := httptest.NewRequest("GET", "/attachments/upload", nil)
	w := httptest.NewRecorder()
	handleUpload(w, req)

	if w.Code != 405 {
		t.Errorf("Expected 405, got %d", w.Code)
	}
}

// TestHandleUploadInvalidToken tests upload with invalid JWT
func TestHandleUploadInvalidToken(t *testing.T) {
	setupTestDB(t)

	req := httptest.NewRequest("POST", "/attachments/upload", nil)
	req.Header.Set("Authorization", "Bearer invalid-token")
	w := httptest.NewRecorder()
	handleUpload(w, req)

	if w.Code != 401 {
		t.Errorf("Expected 401, got %d", w.Code)
	}
}

// TestHandleUploadMissingFile tests upload without a file
func TestHandleUploadMissingFile(t *testing.T) {
	setupTestDB(t)
	hub = newHub()
	go hub.run()

	token := registerUserAndGetToken(t, "nofileuser", "pass123")

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	writer.Close() // No file field

	req := httptest.NewRequest("POST", "/attachments/upload", body)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleUpload(w, req)

	if w.Code != 400 {
		t.Errorf("Expected 400 for missing file, got %d: %s", w.Code, w.Body.String())
	}
}

// TestHandleListAttachments tests listing attachments for a conversation
func TestHandleListAttachments(t *testing.T) {
	setupTestDB(t)
	hub = newHub()
	go hub.run()

	token := registerUserAndGetToken(t, "listattuser", "pass123")
	createTestAgent(t, "listatt-agent", "Bot")
	convID := createTestConversation(t, token, "listatt-agent")

	req := httptest.NewRequest("GET", "/attachments/list?conversation_id="+convID, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleListAttachments(w, req)

	if w.Code != 200 {
		t.Fatalf("Expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var attachments []Attachment
	json.Unmarshal(w.Body.Bytes(), &attachments)
	// Empty is fine — we haven't uploaded anything
	if attachments == nil {
		attachments = []Attachment{}
	}
	t.Logf("List attachments: %d attachments", len(attachments))
}

// TestHandleListAttachmentsUnauthorized tests listing without auth
func TestHandleListAttachmentsNoAuth(t *testing.T) {
	setupTestDB(t)

	req := httptest.NewRequest("GET", "/attachments/list?conversation_id=conv-1", nil)
	w := httptest.NewRecorder()
	handleListAttachments(w, req)

	if w.Code != 401 {
		t.Errorf("Expected 401, got %d", w.Code)
	}
}

// TestHandleListAttachmentsMissingConvID tests listing without conversation_id
func TestHandleListAttachmentsMissingConvID(t *testing.T) {
	setupTestDB(t)
	hub = newHub()
	go hub.run()

	token := registerUserAndGetToken(t, "listnomiduser", "pass123")

	req := httptest.NewRequest("GET", "/attachments/list", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleListAttachments(w, req)

	if w.Code != 400 {
		t.Errorf("Expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

// TestHandleListAttachmentsWrongMethod tests listing with wrong method
func TestHandleListAttachmentsWrongMethod(t *testing.T) {
	setupTestDB(t)

	req := httptest.NewRequest("POST", "/attachments/list", nil)
	w := httptest.NewRecorder()
	handleListAttachments(w, req)

	if w.Code != 405 {
		t.Errorf("Expected 405, got %d", w.Code)
	}
}

// TestGetMaxUploadSizeConfig tests the upload size configuration
func TestGetMaxUploadSizeConfig(t *testing.T) {
	orig := maxUploadSize
	defer func() { maxUploadSize = orig }()

	// Default should be 50MB
	maxUploadSize = MaxUploadSize
	if size := getMaxUploadSize(); size != 50*1024*1024 {
		t.Errorf("Expected default max upload size 50MB, got %d", size)
	}

	// Test setting a custom size
	maxUploadSize = 5 * 1024 * 1024
	if size := getMaxUploadSize(); size != 5*1024*1024 {
		t.Errorf("Expected 5MB, got %d", size)
	}

	// Test 1GB
	maxUploadSize = 1024 * 1024 * 1024
	if size := getMaxUploadSize(); size != 1024*1024*1024 {
		t.Errorf("Expected 1GB, got %d", size)
	}
}

// TestHandleGetAttachment tests downloading an attachment
func TestHandleGetAttachmentNotFound(t *testing.T) {
	setupTestDB(t)
	hub = newHub()
	go hub.run()

	token := registerUserAndGetToken(t, "getattuser", "pass123")

	req := httptest.NewRequest("GET", "/attachments/att-nonexistent", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleGetAttachment(w, req)

	if w.Code != 404 {
		t.Errorf("Expected 404 for nonexistent attachment, got %d", w.Code)
	}
}

// TestHandleGetAttachmentWrongMethod tests downloading with wrong method
func TestHandleGetAttachmentWrongMethod(t *testing.T) {
	setupTestDB(t)

	req := httptest.NewRequest("POST", "/attachments/att-123", nil)
	w := httptest.NewRecorder()
	handleGetAttachment(w, req)

	if w.Code != 405 {
		t.Errorf("Expected 405, got %d", w.Code)
	}
}

// TestHandleGetTagsEmpty tests getting tags when none exist
func TestHandleGetTagsEmpty(t *testing.T) {
	setupTestDB(t)
	hub = newHub()
	go hub.run()

	token := registerUserAndGetToken(t, "emptytagsuser", "pass123")
	createTestAgent(t, "emptytags-agent", "Bot")
	convID := createTestConversation(t, token, "emptytags-agent")

	req := httptest.NewRequest("GET", "/conversations/tags?conversation_id="+convID, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleGetTags(w, req)

	if w.Code != 200 {
		t.Fatalf("Expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var tags []ConversationTag
	json.Unmarshal(w.Body.Bytes(), &tags)
	if tags == nil {
		t.Error("Expected empty array, got nil")
	}
	if len(tags) != 0 {
		t.Errorf("Expected 0 tags, got %d", len(tags))
	}
}

// TestHandleGetTagsUnauthorized tests getting tags for another user's conversation
func TestHandleGetTagsOtherUser(t *testing.T) {
	setupTestDB(t)
	hub = newHub()
	go hub.run()

	token := registerUserAndGetToken(t, "tagowner2", "pass123")
	otherToken := registerUserAndGetToken(t, "tagother2", "pass123")
	createTestAgent(t, "tagowner2-agent", "Bot")
	convID := createTestConversation(t, token, "tagowner2-agent")

	req := httptest.NewRequest("GET", "/conversations/tags?conversation_id="+convID, nil)
	req.Header.Set("Authorization", "Bearer "+otherToken)
	w := httptest.NewRecorder()
	handleGetTags(w, req)

	if w.Code != 401 {
		t.Errorf("Expected 401 for unauthorized tag access, got %d", w.Code)
	}
}

// TestHandleGetTagsMissingConvID tests getting tags without conversation_id
func TestHandleGetTagsMissingConvID(t *testing.T) {
	setupTestDB(t)
	hub = newHub()
	go hub.run()

	token := registerUserAndGetToken(t, "nomidtaguser", "pass123")

	req := httptest.NewRequest("GET", "/conversations/tags", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleGetTags(w, req)

	if w.Code != 400 {
		t.Errorf("Expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

// TestHandleAddTagEmptyTag tests adding a tag with empty name
func TestHandleAddTagEmptyTag(t *testing.T) {
	setupTestDB(t)
	hub = newHub()
	go hub.run()

	token := registerUserAndGetToken(t, "emptytaguser", "pass123")
	createTestAgent(t, "emptytag-agent", "Bot")
	convID := createTestConversation(t, token, "emptytag-agent")

	form := url.Values{
		"conversation_id": {convID},
		"tag":             {""},
	}
	req := httptest.NewRequest("POST", "/conversations/tags/add", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleAddTag(w, req)

	if w.Code != 400 {
		t.Errorf("Expected 400 for empty tag, got %d", w.Code)
	}
}

// TestHandleAddTagTooLong tests adding a tag that exceeds 50 chars
func TestHandleAddTagTooLong(t *testing.T) {
	setupTestDB(t)
	hub = newHub()
	go hub.run()

	token := registerUserAndGetToken(t, "longtaguser", "pass123")
	createTestAgent(t, "longtag-agent", "Bot")
	convID := createTestConversation(t, token, "longtag-agent")

	longTag := strings.Repeat("a", 51)
	form := url.Values{
		"conversation_id": {convID},
		"tag":             {longTag},
	}
	req := httptest.NewRequest("POST", "/conversations/tags/add", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleAddTag(w, req)

	if w.Code != 400 {
		t.Errorf("Expected 400 for tag > 50 chars, got %d", w.Code)
	}
}

// TestHandleRemoveTagUnauthorized tests removing a tag from another user's conversation
func TestHandleRemoveTagOtherUser(t *testing.T) {
	setupTestDB(t)
	hub = newHub()
	go hub.run()

	token := registerUserAndGetToken(t, "rmtagowner", "pass123")
	otherToken := registerUserAndGetToken(t, "rmtagother", "pass123")
	userID := getUserIDFromToken(t, token)
	createTestAgent(t, "rmtag3-agent", "Bot")
	convID := createTestConversation(t, token, "rmtag3-agent")

	// Add tag as owner
	addConversationTag(convID, userID, "mine")

	// Try to remove as different user
	form := url.Values{
		"conversation_id": {convID},
		"tag":             {"mine"},
	}
	req := httptest.NewRequest("POST", "/conversations/tags/remove", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+otherToken)
	w := httptest.NewRecorder()
	handleRemoveTag(w, req)

	if w.Code != 401 {
		t.Errorf("Expected 401 for unauthorized tag removal, got %d", w.Code)
	}
}

// TestHandleAddTagMethodNotAllowed tests adding tag with wrong HTTP method
func TestHandleAddTagMethodNotAllowed(t *testing.T) {
	setupTestDB(t)

	req := httptest.NewRequest("GET", "/conversations/tags/add", nil)
	w := httptest.NewRecorder()
	handleAddTag(w, req)

	if w.Code != 405 {
		t.Errorf("Expected 405, got %d", w.Code)
	}
}

// TestHandleRemoveTagMethodNotAllowed tests removing tag with wrong HTTP method
func TestHandleRemoveTagMethodNotAllowed(t *testing.T) {
	setupTestDB(t)

	req := httptest.NewRequest("GET", "/conversations/tags/remove", nil)
	w := httptest.NewRecorder()
	handleRemoveTag(w, req)

	if w.Code != 405 {
		t.Errorf("Expected 405, got %d", w.Code)
	}
}

// TestHandleGetTagsMethodNotAllowed tests getting tags with wrong HTTP method
func TestHandleGetTagsMethodNotAllowed(t *testing.T) {
	setupTestDB(t)

	req := httptest.NewRequest("POST", "/conversations/tags", nil)
	w := httptest.NewRecorder()
	handleGetTags(w, req)

	if w.Code != 405 {
		t.Errorf("Expected 405, got %d", w.Code)
	}
}
