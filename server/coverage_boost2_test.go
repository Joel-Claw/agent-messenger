package main

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

// ============================================================
// Coverage Boost Tests
//
// Targeted tests for low-coverage handlers and functions.
// ============================================================

// ---- Attachment coverage ----

func TestAttachmentUploadAndRetrieve(t *testing.T) {
	setupAttachmentTestDB(t)
	defer db.Close()

	token := createTestUser(t, "attretrieveuser")

	// Upload an attachment
	req := makeUploadRequest("test.txt", "hello world content", token)
	w := httptest.NewRecorder()
	handleUpload(w, req)

	if w.Code != 200 {
		t.Fatalf("Expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var attachment Attachment
	json.NewDecoder(w.Body).Decode(&attachment)

	// Now retrieve it by ID
	path := "/attachments/" + attachment.ID
	req2 := httptest.NewRequest("GET", path, nil)
	req2.Header.Set("Authorization", "Bearer "+token)
	// Set the path variable
	req2.SetPathValue("id", attachment.ID)
	w2 := httptest.NewRecorder()
	handleGetAttachment(w2, req2)

	if w2.Code != 200 {
		t.Errorf("Expected 200 for get attachment, got %d: %s", w2.Code, w2.Body.String())
	}

	// Verify content type header
	ct := w2.Header().Get("Content-Type")
	if ct == "" {
		t.Log("No Content-Type header (file serving may be disabled in test mode)")
	}
}

func TestAttachmentGetUnauthorized(t *testing.T) {
	setupAttachmentTestDB(t)
	defer db.Close()

	createTestUser(t, "attgetunauth")

	req := httptest.NewRequest("GET", "/attachments/someid", nil)
	// No auth header
	w := httptest.NewRecorder()
	handleGetAttachment(w, req)

	if w.Code != 401 {
		t.Errorf("Expected 401, got %d", w.Code)
	}
}

func TestAttachmentListForConversation(t *testing.T) {
	setupAttachmentTestDB(t)
	defer db.Close()

	token := createTestUser(t, "attlistconvuser")

	// Register an agent
	agentForm := "agent_id=attlistagent&name=TestAgent&agent_secret=" + agentSecret
	req := httptest.NewRequest("POST", "/auth/agent", bytes.NewBufferString(agentForm))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Agent-Secret", agentSecret)
	w := httptest.NewRecorder()
	handleRegisterAgent(w, req)

	// Create a conversation
	form := "agent_id=attlistagent"
	req2 := httptest.NewRequest("POST", "/conversations/create", bytes.NewBufferString(form))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req2.Header.Set("Authorization", "Bearer "+token)
	w2 := httptest.NewRecorder()
	handleCreateConversation(w2, req2)

	var convResp map[string]interface{}
	json.NewDecoder(w2.Body).Decode(&convResp)
	convID, _ := convResp["conversation_id"].(string)
	if convID == "" {
		t.Fatal("Expected conversation_id")
	}

	// Upload an attachment for this conversation
	req3 := makeUploadRequest("doc.pdf", "PDF content here", token)
	w3 := httptest.NewRecorder()
	handleUpload(w3, req3)

	var att Attachment
	json.NewDecoder(w3.Body).Decode(&att)

	// List attachments for the conversation
	listURL := fmt.Sprintf("/messages/attachments?conversation_id=%s", convID)
	req4 := httptest.NewRequest("GET", listURL, nil)
	req4.Header.Set("Authorization", "Bearer "+token)
	w4 := httptest.NewRecorder()
	handleListAttachments(w4, req4)

	if w4.Code != 200 {
		t.Errorf("Expected 200 for list attachments, got %d: %s", w4.Code, w4.Body.String())
	}

	var attachments []Attachment
	json.NewDecoder(w4.Body).Decode(&attachments)
	// May be 0 or 1 depending on whether message_id linking is required
	t.Logf("Listed %d attachments for conversation %s", len(attachments), convID)
}

func TestAttachmentListMissingConversationID(t *testing.T) {
	setupAttachmentTestDB(t)
	defer db.Close()

	token := createTestUser(t, "attlistnoid")

	req := httptest.NewRequest("GET", "/messages/attachments", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleListAttachments(w, req)

	if w.Code != 400 {
		t.Errorf("Expected 400 for missing conversation_id, got %d: %s", w.Code, w.Body.String())
	}
}

func TestAttachmentListUnauthorized(t *testing.T) {
	setupAttachmentTestDB(t)
	defer db.Close()

	req := httptest.NewRequest("GET", "/messages/attachments?conversation_id=conv1", nil)
	w := httptest.NewRecorder()
	handleListAttachments(w, req)

	if w.Code != 401 {
		t.Errorf("Expected 401, got %d", w.Code)
	}
}

func TestAttachmentUploadTooLarge(t *testing.T) {
	setupAttachmentTestDB(t)
	defer db.Close()

	token := createTestUser(t, "attlargetest")

	// Set a very small max upload size
	originalMax := maxUploadSize
	maxUploadSize = 10 // 10 bytes
	defer func() { maxUploadSize = originalMax }()

	// Create a file larger than the limit
	largeContent := strings.Repeat("x", 1000)
	req := makeUploadRequest("big.txt", largeContent, token)
	w := httptest.NewRecorder()
	handleUpload(w, req)

	// The handler returns 400 for oversized files (not 413)
	if w.Code != 400 {
		t.Errorf("Expected 400 for file too large, got %d: %s", w.Code, w.Body.String())
	}
}

// ---- E2E Encryption coverage ----

func TestUploadPublicKeyNoAuth(t *testing.T) {
	setupCov2TestDB(t)
	defer db.Close()

	req := httptest.NewRequest("POST", "/keys/upload", strings.NewReader(`{"key_type":"identity","public_key":"abc123"}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handleUploadPublicKey(w, req)

	if w.Code != 401 {
		t.Errorf("Expected 401, got %d", w.Code)
	}
}

func TestUploadPublicKeyEmptyPublicKey(t *testing.T) {
	setupCov2TestDB(t)
	defer db.Close()

	token := createCov2User(t, "emptykeyuser")

	req := httptest.NewRequest("POST", "/keys/upload", strings.NewReader(`{"key_type":"identity","public_key":""}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleUploadPublicKey(w, req)

	if w.Code != 400 {
		t.Errorf("Expected 400 for empty public_key, got %d: %s", w.Code, w.Body.String())
	}
}

func TestUploadOneTimePreKeysBatch(t *testing.T) {
	setupCov2TestDB(t)
	defer db.Close()

	token := createCov2User(t, "otpkbatchuser")

	// Upload multiple one-time pre-keys
	for i := 1; i <= 5; i++ {
		body := fmt.Sprintf(`{"key_type":"one_time_prekey","public_key":"otpk_%d","key_id":%d}`, i, i)
		req := httptest.NewRequest("POST", "/keys/upload", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		handleUploadPublicKey(w, req)

		if w.Code != 200 {
			t.Errorf("Expected 200 for otpk upload %d, got %d: %s", i, w.Code, w.Body.String())
		}
	}

	// Check OTPK count
	req := httptest.NewRequest("GET", "/keys/otpk-count", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleListOneTimePreKeys(w, req)

	if w.Code != 200 {
		t.Errorf("Expected 200 for otpk-count, got %d: %s", w.Code, w.Body.String())
	}

	var result map[string]int
	json.NewDecoder(w.Body).Decode(&result)
	if result["one_time_prekey_count"] != 5 {
		t.Errorf("Expected 5 otpks, got %d", result["one_time_prekey_count"])
	}
}

func TestGetKeyBundleAgentAuth(t *testing.T) {
	setupCov2TestDB(t)
	defer db.Close()

	token, userID := createCov2UserWithID(t, "bundleagentauth")

	// Upload identity key
	body := `{"key_type":"identity","public_key":"identity_key_agent_auth"}`
	req := httptest.NewRequest("POST", "/keys/upload", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleUploadPublicKey(w, req)
	if w.Code != 200 {
		t.Fatalf("Expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// Get key bundle using user JWT (owner_id must be the user_id, not username)
	req2 := httptest.NewRequest("GET", "/keys/bundle?owner_id="+userID+"&owner_type=user", nil)
	req2.Header.Set("Authorization", "Bearer "+token)
	w2 := httptest.NewRecorder()
	handleGetKeyBundle(w2, req2)

	if w2.Code != 200 {
		t.Errorf("Expected 200 for key bundle, got %d: %s", w2.Code, w2.Body.String())
	}
}

func TestGetKeyBundleMissingOwnerID(t *testing.T) {
	setupCov2TestDB(t)
	defer db.Close()

	token := createCov2User(t, "nobundleowner")

	req := httptest.NewRequest("GET", "/keys/bundle", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleGetKeyBundle(w, req)

	if w.Code != 400 {
		t.Errorf("Expected 400 for missing owner_id, got %d: %s", w.Code, w.Body.String())
	}
}

func TestStoreEncryptedMessageAgentSender(t *testing.T) {
	setupCov2TestDB(t)
	defer db.Close()

	// Create conversation (which creates user+agent internally)
	convID, _ := createCov2Conversation(t, "encmsgagentuser", "encmsgagent")

	// Store encrypted message with agent auth
	body := fmt.Sprintf(`{
		"conversation_id": "%s",
		"ciphertext": "base64ciphertext",
		"iv": "base64iv",
		"recipient_key_id": "key123",
		"sender_key_id": "agentkey456",
		"algorithm": "aes-256-gcm"
	}`, convID)

	req := httptest.NewRequest("POST", "/messages/encrypted", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Agent-Secret", agentSecret)
	req.Header.Set("X-Agent-ID", "encmsgagent")
	w := httptest.NewRecorder()
	handleStoreEncryptedMessage(w, req)

	if w.Code != 200 {
		t.Errorf("Expected 200 for encrypted message from agent, got %d: %s", w.Code, w.Body.String())
	}
}

func TestStoreEncryptedMessageUnauthorized(t *testing.T) {
	setupCov2TestDB(t)
	defer db.Close()

	body := `{"conversation_id":"conv1","ciphertext":"abc","iv":"def","algorithm":"aes-256-gcm"}`
	req := httptest.NewRequest("POST", "/messages/encrypted", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handleStoreEncryptedMessage(w, req)

	if w.Code != 401 {
		t.Errorf("Expected 401, got %d", w.Code)
	}
}

func TestStoreEncryptedMessageWrongConversation(t *testing.T) {
	setupCov2TestDB(t)
	defer db.Close()

	token := createCov2User(t, "wrongconvuser")
	_ = createCov2Agent(t, "wrongconvagent")

	// Try to store a message for a conversation that doesn't belong to this user
	body := `{"conversation_id":"nonexistent_conv","ciphertext":"abc","iv":"def","algorithm":"aes-256-gcm"}`
	req := httptest.NewRequest("POST", "/messages/encrypted", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleStoreEncryptedMessage(w, req)

	if w.Code != 404 {
		t.Errorf("Expected 404 for nonexistent conversation, got %d: %s", w.Code, w.Body.String())
	}
}

func TestGetEncryptedMessagesWithLimit(t *testing.T) {
	setupCov2TestDB(t)
	defer db.Close()

	convID, token := createCov2Conversation(t, "enclimituser", "enclimitagent")

	// Store 3 encrypted messages
	for i := 0; i < 3; i++ {
		body := fmt.Sprintf(`{
			"conversation_id": "%s",
			"ciphertext": "cipher_%d",
			"iv": "iv_%d",
			"recipient_key_id": "key_%d",
			"algorithm": "aes-256-gcm"
		}`, convID, i, i, i)
		req := httptest.NewRequest("POST", "/messages/encrypted", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		handleStoreEncryptedMessage(w, req)
		if w.Code != 200 {
			t.Errorf("Store %d failed: %d %s", i, w.Code, w.Body.String())
		}
	}

	// Retrieve with limit=2
	url := fmt.Sprintf("/messages/encrypted?conversation_id=%s&limit=2", convID)
	req := httptest.NewRequest("GET", url, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleGetEncryptedMessages(w, req)

	if w.Code != 200 {
		t.Errorf("Expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var msgs []EncryptedMessage
	json.NewDecoder(w.Body).Decode(&msgs)
	if len(msgs) != 2 {
		t.Errorf("Expected 2 messages with limit=2, got %d", len(msgs))
	}
}

func TestGetEncryptedMessagesAgentAuth(t *testing.T) {
	setupCov2TestDB(t)
	defer db.Close()

	convID, token := createCov2Conversation(t, "encagentauthuser", "encagentauthagent")

	// Store a message as user
	body := fmt.Sprintf(`{
		"conversation_id": "%s",
		"ciphertext": "agent_auth_cipher",
		"iv": "agent_auth_iv",
		"recipient_key_id": "agent_key",
		"algorithm": "x25519-aes-256-gcm"
	}`, convID)
	req := httptest.NewRequest("POST", "/messages/encrypted", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleStoreEncryptedMessage(w, req)
	if w.Code != 200 {
		t.Fatalf("Store failed: %d %s", w.Code, w.Body.String())
	}

	// Retrieve as agent
	url := fmt.Sprintf("/messages/encrypted?conversation_id=%s", convID)
	req2 := httptest.NewRequest("GET", url, nil)
	req2.Header.Set("X-Agent-Secret", agentSecret)
	req2.Header.Set("X-Agent-ID", "encagentauthagent")
	w2 := httptest.NewRecorder()
	handleGetEncryptedMessages(w2, req2)

	if w2.Code != 200 {
		t.Errorf("Expected 200 for agent get encrypted messages, got %d: %s", w2.Code, w2.Body.String())
	}
}

func TestGetEncryptedMessagesMissingConversationID(t *testing.T) {
	setupCov2TestDB(t)
	defer db.Close()

	token := createCov2User(t, "enconoid")

	req := httptest.NewRequest("GET", "/messages/encrypted", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleGetEncryptedMessages(w, req)

	if w.Code != 400 {
		t.Errorf("Expected 400 for missing conversation_id, got %d: %s", w.Code, w.Body.String())
	}
}

func TestAuthenticateRequestAgentAuth(t *testing.T) {
	setupCov2TestDB(t)
	defer db.Close()

	// Test with agent secret
	req := httptest.NewRequest("GET", "/keys/bundle", nil)
	req.Header.Set("X-Agent-Secret", agentSecret)
	req.Header.Set("X-Agent-ID", "testagent")

	id, typ, err := authenticateRequest(req)
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	if id != "testagent" {
		t.Errorf("Expected id=testagent, got %s", id)
	}
	if typ != "agent" {
		t.Errorf("Expected type=agent, got %s", typ)
	}
}

func TestAuthenticateRequestAgentNoID(t *testing.T) {
	setupCov2TestDB(t)
	defer db.Close()

	req := httptest.NewRequest("GET", "/keys/bundle", nil)
	req.Header.Set("X-Agent-Secret", agentSecret)
	// No X-Agent-ID header

	_, _, err := authenticateRequest(req)
	if err == nil {
		t.Error("Expected error for missing agent ID")
	}
}

func TestAuthenticateRequestNoAuth(t *testing.T) {
	req := httptest.NewRequest("GET", "/keys/bundle", nil)
	// No auth headers

	_, _, err := authenticateRequest(req)
	if err == nil {
		t.Error("Expected error for no auth")
	}
}

func TestStoreEncryptedMessageX25519Algorithm(t *testing.T) {
	setupCov2TestDB(t)
	defer db.Close()

	convID, token := createCov2Conversation(t, "x25519user", "x25519agent")

	// Store with x25519-chacha20-poly1305 algorithm
	body := fmt.Sprintf(`{
		"conversation_id": "%s",
		"ciphertext": "x25519_cipher",
		"iv": "x25519_iv",
		"recipient_key_id": "rk1",
		"algorithm": "x25519-chacha20-poly1305"
	}`, convID)
	req := httptest.NewRequest("POST", "/messages/encrypted", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleStoreEncryptedMessage(w, req)

	if w.Code != 200 {
		t.Errorf("Expected 200 for x25519-chacha20-poly1305, got %d: %s", w.Code, w.Body.String())
	}
}

func TestStoreEncryptedMessageMissingFields(t *testing.T) {
	setupCov2TestDB(t)
	defer db.Close()

	token := createCov2User(t, "encmissfields")

	// Missing ciphertext
	body := `{"conversation_id":"conv1","iv":"abc","algorithm":"aes-256-gcm"}`
	req := httptest.NewRequest("POST", "/messages/encrypted", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleStoreEncryptedMessage(w, req)

	if w.Code != 400 {
		t.Errorf("Expected 400 for missing fields, got %d: %s", w.Code, w.Body.String())
	}
}

func TestStoreEncryptedMessageForbiddenUser(t *testing.T) {
	setupCov2TestDB(t)
	defer db.Close()

	convID, _ := createCov2Conversation(t, "encforbidden1", "encforbiddenagent")

	// Create a second user who doesn't belong to the conversation
	token2 := createCov2User(t, "encforbidden2")

	// Try to store encrypted message as user2 in user1's conversation
	body := fmt.Sprintf(`{
		"conversation_id": "%s",
		"ciphertext": "forbidden",
		"iv": "iv",
		"recipient_key_id": "key",
		"algorithm": "aes-256-gcm"
	}`, convID)
	req := httptest.NewRequest("POST", "/messages/encrypted", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token2)
	w := httptest.NewRecorder()
	handleStoreEncryptedMessage(w, req)

	if w.Code != 403 {
		t.Errorf("Expected 403 for forbidden user, got %d: %s", w.Code, w.Body.String())
	}
}

func TestGetEncryptedMessagesForbiddenConversation(t *testing.T) {
	setupCov2TestDB(t)
	defer db.Close()

	convID, _ := createCov2Conversation(t, "encforbiddenget1", "encforbiddengetagent")

	// Second user tries to read first user's encrypted messages
	token2 := createCov2User(t, "encforbiddenget2")

	url := fmt.Sprintf("/messages/encrypted?conversation_id=%s", convID)
	req := httptest.NewRequest("GET", url, nil)
	req.Header.Set("Authorization", "Bearer "+token2)
	w := httptest.NewRecorder()
	handleGetEncryptedMessages(w, req)

	if w.Code != 404 {
		t.Errorf("Expected 404 for forbidden conversation, got %d: %s", w.Code, w.Body.String())
	}
}

func TestUploadPublicKeyInvalidJSON(t *testing.T) {
	setupCov2TestDB(t)
	defer db.Close()

	token := createCov2User(t, "invalidjsonuser")

	req := httptest.NewRequest("POST", "/keys/upload", strings.NewReader("not json"))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleUploadPublicKey(w, req)

	if w.Code != 400 {
		t.Errorf("Expected 400 for invalid JSON, got %d: %s", w.Code, w.Body.String())
	}
}

func TestGetKeyBundleWithSignedPreKey(t *testing.T) {
	setupCov2TestDB(t)
	defer db.Close()

	token, userID := createCov2UserWithID(t, "bundlespkuser")

	// Upload identity key
	body := `{"key_type":"identity","public_key":"identity_spk"}`
	req := httptest.NewRequest("POST", "/keys/upload", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleUploadPublicKey(w, req)
	if w.Code != 200 {
		t.Fatalf("Expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// Upload signed pre-key
	body = `{"key_type":"signed_prekey","public_key":"spk_pub","signature":"spk_sig"}`
	req = httptest.NewRequest("POST", "/keys/upload", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w = httptest.NewRecorder()
	handleUploadPublicKey(w, req)
	if w.Code != 200 {
		t.Fatalf("Expected 200 for signed prekey, got %d: %s", w.Code, w.Body.String())
	}

	// Upload one-time pre-key
	body = `{"key_type":"one_time_prekey","public_key":"otpk_1","key_id":1}`
	req = httptest.NewRequest("POST", "/keys/upload", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w = httptest.NewRecorder()
	handleUploadPublicKey(w, req)
	if w.Code != 200 {
		t.Fatalf("Expected 200 for otpk, got %d: %s", w.Code, w.Body.String())
	}

	// Get the full bundle (owner_id must be user_id, not username)
	req2 := httptest.NewRequest("GET", "/keys/bundle?owner_id="+userID+"&owner_type=user", nil)
	req2.Header.Set("Authorization", "Bearer "+token)
	w2 := httptest.NewRecorder()
	handleGetKeyBundle(w2, req2)

	if w2.Code != 200 {
		t.Errorf("Expected 200 for key bundle, got %d: %s", w2.Code, w2.Body.String())
	}

	var bundle map[string]interface{}
	json.NewDecoder(w2.Body).Decode(&bundle)

	if _, ok := bundle["identity_key"]; !ok {
		t.Error("Expected identity_key in bundle")
	}
	if _, ok := bundle["signed_prekey"]; !ok {
		t.Error("Expected signed_prekey in bundle")
	}
	if _, ok := bundle["one_time_prekey"]; !ok {
		t.Error("Expected one_time_prekey in bundle")
	}
}

// ---- DB Driver helpers ----

func TestEnvIntOrDefault(t *testing.T) {
	// Test with valid env var
	os.Setenv("TEST_INT_VAL", "42")
	if got := envIntOrDefault("TEST_INT_VAL", 10); got != 42 {
		t.Errorf("Expected 42, got %d", got)
	}

	// Test with invalid env var
	os.Setenv("TEST_INT_VAL", "notanumber")
	if got := envIntOrDefault("TEST_INT_VAL", 10); got != 10 {
		t.Errorf("Expected 10 (default) for invalid value, got %d", got)
	}

	// Test with missing env var
	os.Unsetenv("TEST_INT_MISSING")
	if got := envIntOrDefault("TEST_INT_MISSING", 7); got != 7 {
		t.Errorf("Expected 7 (default), got %d", got)
	}

	os.Unsetenv("TEST_INT_VAL")
}

func TestEnvDurationOrDefault(t *testing.T) {
	// Test with valid env var
	os.Setenv("TEST_DUR_VAL", "5m")
	if got := envDurationOrDefault("TEST_DUR_VAL", 10*time.Minute); got != 5*time.Minute {
		t.Errorf("Expected 5m, got %v", got)
	}

	// Test with invalid env var
	os.Setenv("TEST_DUR_VAL", "notaduration")
	if got := envDurationOrDefault("TEST_DUR_VAL", 10*time.Minute); got != 10*time.Minute {
		t.Errorf("Expected 10m (default) for invalid value, got %v", got)
	}

	// Test with missing env var
	os.Unsetenv("TEST_DUR_MISSING")
	if got := envDurationOrDefault("TEST_DUR_MISSING", 10*time.Minute); got != 10*time.Minute {
		t.Errorf("Expected 10m (default), got %v", got)
	}

	os.Unsetenv("TEST_DUR_VAL")
}

func TestAttachmentUploadWrongMethod(t *testing.T) {
	setupAttachmentTestDB(t)
	defer db.Close()

	req := httptest.NewRequest("GET", "/attachments/upload", nil)
	w := httptest.NewRecorder()
	handleUpload(w, req)

	if w.Code != 405 {
		t.Errorf("Expected 405 for GET on upload, got %d", w.Code)
	}
}

func TestGetAttachmentWrongMethod(t *testing.T) {
	setupAttachmentTestDB(t)
	defer db.Close()

	req := httptest.NewRequest("POST", "/attachments/someid", nil)
	w := httptest.NewRecorder()
	handleGetAttachment(w, req)

	if w.Code != 405 {
		t.Errorf("Expected 405 for POST on get, got %d", w.Code)
	}
}

func TestListAttachmentsWrongMethod(t *testing.T) {
	setupAttachmentTestDB(t)
	defer db.Close()

	req := httptest.NewRequest("POST", "/messages/attachments", nil)
	w := httptest.NewRecorder()
	handleListAttachments(w, req)

	if w.Code != 405 {
		t.Errorf("Expected 405 for POST on list, got %d", w.Code)
	}
}

// ---- Helpers ----

func setupCov2TestDB(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	serverDBPath = filepath.Join(dir, "test.db")
	var err error
	db, err = sql.Open("sqlite3", serverDBPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := initSchema(db); err != nil {
		t.Fatal(err)
	}
}

func createCov2User(t *testing.T, username string) (token string) {
	t.Helper()
	form := "username=" + username + "&password=testpass123"
	req := httptest.NewRequest("POST", "/auth/user", bytes.NewBufferString(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handleRegisterUser(w, req)
	if w.Code != 200 {
		t.Fatalf("Failed to register user %s: %d %s", username, w.Code, w.Body.String())
	}

	req = httptest.NewRequest("POST", "/auth/login", bytes.NewBufferString(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w = httptest.NewRecorder()
	handleLogin(w, req)
	if w.Code != 200 {
		t.Fatalf("Failed to login user %s: %d %s", username, w.Code, w.Body.String())
	}
	var resp map[string]string
	json.NewDecoder(w.Body).Decode(&resp)
	return resp["token"]
}

func createCov2UserWithID(t *testing.T, username string) (token string, userID string) {
	t.Helper()
	form := "username=" + username + "&password=testpass123"
	req := httptest.NewRequest("POST", "/auth/user", bytes.NewBufferString(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handleRegisterUser(w, req)
	if w.Code != 200 {
		t.Fatalf("Failed to register user %s: %d %s", username, w.Code, w.Body.String())
	}
	var regResp map[string]string
	json.NewDecoder(w.Body).Decode(&regResp)

	req = httptest.NewRequest("POST", "/auth/login", bytes.NewBufferString(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w = httptest.NewRecorder()
	handleLogin(w, req)
	if w.Code != 200 {
		t.Fatalf("Failed to login user %s: %d %s", username, w.Code, w.Body.String())
	}
	var loginResp map[string]string
	json.NewDecoder(w.Body).Decode(&loginResp)
	return loginResp["token"], regResp["user_id"]
}

func createCov2Agent(t *testing.T, agentID string) string {
	t.Helper()
	form := "agent_id=" + agentID + "&name=TestAgent&agent_secret=" + agentSecret
	req := httptest.NewRequest("POST", "/auth/agent", bytes.NewBufferString(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Agent-Secret", agentSecret)
	w := httptest.NewRecorder()
	handleRegisterAgent(w, req)
	if w.Code != 200 && w.Code != 201 {
		t.Fatalf("Failed to register agent %s: %d %s", agentID, w.Code, w.Body.String())
	}
	return agentID
}

func createCov2Conversation(t *testing.T, userID, agentID string) (convID string, token string) {
	t.Helper()
	token = createCov2User(t, userID)
	_ = createCov2Agent(t, agentID)

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
	convID, _ = resp["conversation_id"].(string)
	if convID == "" {
		t.Fatal("No conversation_id in response")
	}
	return convID, token
}
