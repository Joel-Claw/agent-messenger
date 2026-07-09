package main

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// --- Helper ---
func setupTestDB_CB54(t *testing.T) *sql.DB {
	testDB, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("Failed to open test DB: %v", err)
	}
	if err := initSchema(testDB); err != nil {
		t.Fatalf("Failed to init schema: %v", err)
	}
	return testDB
}

func setupTestServer_CB54(t *testing.T) (*sql.DB, func()) {
	testDB := setupTestDB_CB54(t)
	oldDB := db
	db = testDB

	h := newHub()
	oldHub := hub
	hub = h

	cleanup := func() {
		db = oldDB
		hub = oldHub
		if h.done != nil {
			close(h.done)
		}
	}
	return testDB, cleanup
}

// Helper to create user and get JWT
func cb54CreateUserAndGetToken(t *testing.T, db *sql.DB, username, password string) (string, string) {
	req := httptest.NewRequest(http.MethodPost, "/auth/register", strings.NewReader(
		"username="+username+"&password="+password))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handleRegisterUser(w, req)
	if w.Code != http.StatusCreated && w.Code != http.StatusOK && w.Code != http.StatusConflict {
		t.Fatalf("Failed to register user: %d - %s", w.Code, w.Body.String())
	}
	var regResp map[string]string
	json.NewDecoder(w.Body).Decode(&regResp)
	userID := regResp["user_id"]

	req = httptest.NewRequest(http.MethodPost, "/auth/login", strings.NewReader(
		"username="+username+"&password="+password))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w = httptest.NewRecorder()
	handleLogin(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("Failed to login: %d - %s", w.Code, w.Body.String())
	}
	var resp map[string]string
	json.NewDecoder(w.Body).Decode(&resp)
	return resp["token"], userID
}

// Helper to create conversation
func cb54CreateConversation(t *testing.T, db *sql.DB, username, agentID string) string {
	// Look up actual user_id from username
	var userID string
	err := db.QueryRow("SELECT id FROM users WHERE username = ?", username).Scan(&userID)
	if err != nil {
		t.Fatalf("Failed to find user by username '%s': %v", username, err)
	}
	convID := generateID("conv")
	_, err = db.Exec("INSERT INTO conversations (id, user_id, agent_id, created_at) VALUES (?, ?, ?, datetime('now'))",
		convID, userID, agentID)
	if err != nil {
		t.Fatalf("Failed to create conversation: %v", err)
	}
	return convID
}

// Helper to create agent
func cb54CreateAgent(t *testing.T, db *sql.DB, agentID string) {
	_, err := db.Exec("INSERT OR IGNORE INTO agents (id, name, status, created_at) VALUES (?, ?, 'offline', datetime('now'))",
		agentID, "Agent "+agentID)
	if err != nil {
		t.Fatalf("Failed to create agent: %v", err)
	}
}

// =========================================================================
// handleWebPushUnsubscribe (push.go:480)
// =========================================================================

func TestCB54_WebPushUnsubscribe_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/push/web-unsubscribe", nil)
	w := httptest.NewRecorder()
	handleWebPushUnsubscribe(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected 405, got %d", w.Code)
	}
}

func TestCB54_WebPushUnsubscribe_Unauthorized(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/push/web-unsubscribe", strings.NewReader("{}"))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handleWebPushUnsubscribe(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected 401, got %d", w.Code)
	}
}

func TestCB54_WebPushUnsubscribe_InvalidJSON(t *testing.T) {
	testDB, cleanup := setupTestServer_CB54(t)
	defer cleanup()
	token, _ := cb54CreateUserAndGetToken(t, testDB, "user_wp_unsub", "pass123")

	req := httptest.NewRequest(http.MethodPost, "/push/web-unsubscribe", strings.NewReader("invalid json"))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleWebPushUnsubscribe(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected 400, got %d", w.Code)
	}
}

func TestCB54_WebPushUnsubscribe_EmptyEndpoint(t *testing.T) {
	testDB, cleanup := setupTestServer_CB54(t)
	defer cleanup()
	token, _ := cb54CreateUserAndGetToken(t, testDB, "user_wp_unsub2", "pass123")

	body := `{"endpoint":""}`
	req := httptest.NewRequest(http.MethodPost, "/push/web-unsubscribe", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleWebPushUnsubscribe(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected 400, got %d", w.Code)
	}
}

func TestCB54_WebPushUnsubscribe_Success(t *testing.T) {
	testDB, cleanup := setupTestServer_CB54(t)
	defer cleanup()
	token, _ := cb54CreateUserAndGetToken(t, testDB, "user_wp_unsub3", "pass123")

	// First subscribe
	subBody := `{"endpoint":"https://fcm.googleapis.com/fcm/send/abc123","keys":{"p256dh":"p256key","auth":"authkey"}}`
	req := httptest.NewRequest(http.MethodPost, "/push/web-subscribe", strings.NewReader(subBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleWebPushSubscribe(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("Subscribe failed: %d - %s", w.Code, w.Body.String())
	}

	// Now unsubscribe
	unsubBody := `{"endpoint":"https://fcm.googleapis.com/fcm/send/abc123"}`
	req = httptest.NewRequest(http.MethodPost, "/push/web-unsubscribe", strings.NewReader(unsubBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w = httptest.NewRecorder()
	handleWebPushUnsubscribe(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d - %s", w.Code, w.Body.String())
	}
	var resp map[string]string
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["status"] != "unsubscribed" {
		t.Errorf("Expected status 'unsubscribed', got '%s'", resp["status"])
	}
}

// =========================================================================
// handleUploadPublicKey — identity key replace path (e2e.go:46)
// =========================================================================

func TestCB54_UploadPublicKey_IdentityKeyReplace(t *testing.T) {
	testDB, cleanup := setupTestServer_CB54(t)
	defer cleanup()
	token, _ := cb54CreateUserAndGetToken(t, testDB, "user_key_replace", "pass123")

	// Upload first identity key
	body := `{"key_type":"identity","public_key":"base64key1"}`
	req := httptest.NewRequest(http.MethodPost, "/keys/upload", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleUploadPublicKey(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("First upload failed: %d - %s", w.Code, w.Body.String())
	}

	// Upload replacement identity key
	body = `{"key_type":"identity","public_key":"base64key2"}`
	req = httptest.NewRequest(http.MethodPost, "/keys/upload", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w = httptest.NewRecorder()
	handleUploadPublicKey(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("Replace upload failed: %d - %s", w.Code, w.Body.String())
	}

	// Verify only one identity key exists
	var count int
	testDB.QueryRow("SELECT COUNT(*) FROM key_bundles kb JOIN users u ON u.username = 'user_key_replace' WHERE kb.owner_id = u.id AND kb.owner_type = 'user' AND kb.key_type = 'identity'").Scan(&count)
	if count != 1 {
		t.Errorf("Expected 1 identity key after replace, got %d", count)
	}

	// Verify it's the new key
	var pubKey string
	testDB.QueryRow("SELECT kb.public_key FROM key_bundles kb JOIN users u ON u.username = 'user_key_replace' WHERE kb.owner_id = u.id AND kb.owner_type = 'user' AND kb.key_type = 'identity'").Scan(&pubKey)
	if pubKey != "base64key2" {
		t.Errorf("Expected public_key 'base64key2', got '%s'", pubKey)
	}
}

func TestCB54_UploadPublicKey_OneTimePreKey(t *testing.T) {
	testDB, cleanup := setupTestServer_CB54(t)
	defer cleanup()
	token, _ := cb54CreateUserAndGetToken(t, testDB, "user_otpk", "pass123")

	body := `{"key_type":"one_time_prekey","public_key":"otpk1","key_id":1}`
	req := httptest.NewRequest(http.MethodPost, "/keys/upload", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleUploadPublicKey(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("Upload failed: %d - %s", w.Code, w.Body.String())
	}
	var resp KeyBundle
	json.NewDecoder(w.Body).Decode(&resp)
	if resp.KeyType != "one_time_prekey" {
		t.Errorf("Expected key_type 'one_time_prekey', got '%s'", resp.KeyType)
	}
	if resp.KeyID != 1 {
		t.Errorf("Expected key_id 1, got %d", resp.KeyID)
	}
}

func TestCB54_UploadPublicKey_SignedPreKey(t *testing.T) {
	testDB, cleanup := setupTestServer_CB54(t)
	defer cleanup()
	token, _ := cb54CreateUserAndGetToken(t, testDB, "user_spk", "pass123")

	body := `{"key_type":"signed_prekey","public_key":"spk1","signature":"sig1"}`
	req := httptest.NewRequest(http.MethodPost, "/keys/upload", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleUploadPublicKey(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("Upload failed: %d - %s", w.Code, w.Body.String())
	}
	var resp KeyBundle
	json.NewDecoder(w.Body).Decode(&resp)
	if resp.Signature != "sig1" {
		t.Errorf("Expected signature 'sig1', got '%s'", resp.Signature)
	}
}

func TestCB54_UploadPublicKey_AgentAuth(t *testing.T) {
	_, cleanup := setupTestServer_CB54(t)
	defer cleanup()

	body := `{"key_type":"identity","public_key":"agentkey1"}`
	req := httptest.NewRequest(http.MethodPost, "/keys/upload", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Agent-Secret", getAgentSecret())
	req.Header.Set("X-Agent-ID", "agent-key-test")
	w := httptest.NewRecorder()
	handleUploadPublicKey(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("Agent upload failed: %d - %s", w.Code, w.Body.String())
	}
	var resp KeyBundle
	json.NewDecoder(w.Body).Decode(&resp)
	if resp.OwnerType != "agent" {
		t.Errorf("Expected owner_type 'agent', got '%s'", resp.OwnerType)
	}
	if resp.OwnerID != "agent-key-test" {
		t.Errorf("Expected owner_id 'agent-key-test', got '%s'", resp.OwnerID)
	}
}

func TestCB54_UploadPublicKey_EmptyPublicKey(t *testing.T) {
	testDB, cleanup := setupTestServer_CB54(t)
	defer cleanup()
	token, _ := cb54CreateUserAndGetToken(t, testDB, "user_empty_key", "pass123")

	body := `{"key_type":"identity","public_key":""}`
	req := httptest.NewRequest(http.MethodPost, "/keys/upload", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleUploadPublicKey(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected 400, got %d", w.Code)
	}
}

func TestCB54_UploadPublicKey_InvalidKeyType(t *testing.T) {
	testDB, cleanup := setupTestServer_CB54(t)
	defer cleanup()
	token, _ := cb54CreateUserAndGetToken(t, testDB, "user_bad_keytype", "pass123")

	body := `{"key_type":"bad_type","public_key":"key1"}`
	req := httptest.NewRequest(http.MethodPost, "/keys/upload", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleUploadPublicKey(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected 400, got %d", w.Code)
	}
}

// =========================================================================
// handleGetKeyBundle (e2e.go:132)
// =========================================================================

func TestCB54_GetKeyBundle_NoIdentityKey(t *testing.T) {
	testDB, cleanup := setupTestServer_CB54(t)
	defer cleanup()
	token, _ := cb54CreateUserAndGetToken(t, testDB, "user_bundle1", "pass123")

	req := httptest.NewRequest(http.MethodGet, "/keys/bundle?owner_id=user_nonexistent&owner_type=user", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleGetKeyBundle(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("Expected 404, got %d", w.Code)
	}
}

func TestCB54_GetKeyBundle_WithSignedPreKeyAndOTP(t *testing.T) {
	testDB, cleanup := setupTestServer_CB54(t)
	defer cleanup()
	token, userID := cb54CreateUserAndGetToken(t, testDB, "user_bundle2", "pass123")

	// Upload identity, signed pre-key, and one-time pre-key
	for _, body := range []string{
		`{"key_type":"identity","public_key":"idkey1"}`,
		`{"key_type":"signed_prekey","public_key":"spk1","signature":"sig1"}`,
		`{"key_type":"one_time_prekey","public_key":"otpk1","key_id":1}`,
		`{"key_type":"one_time_prekey","public_key":"otpk2","key_id":2}`,
	} {
		req := httptest.NewRequest(http.MethodPost, "/keys/upload", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		handleUploadPublicKey(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("Upload failed for body %s: %d", body, w.Code)
		}
	}

	// Get bundle — should consume one OTP key
	req := httptest.NewRequest(http.MethodGet, "/keys/bundle?owner_id="+userID+"&owner_type=user", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleGetKeyBundle(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("GetKeyBundle failed: %d - %s", w.Code, w.Body.String())
	}
	var bundle map[string]json.RawMessage
	json.NewDecoder(w.Body).Decode(&bundle)
	if _, ok := bundle["identity_key"]; !ok {
		t.Error("Missing identity_key in bundle")
	}
	if _, ok := bundle["signed_prekey"]; !ok {
		t.Error("Missing signed_prekey in bundle")
	}
	if _, ok := bundle["one_time_prekey"]; !ok {
		t.Error("Missing one_time_prekey in bundle")
	}

	// Verify one OTP was consumed (should have 1 remaining)
	var count int
	testDB.QueryRow("SELECT COUNT(*) FROM key_bundles kb JOIN users u ON u.username = 'user_bundle2' WHERE kb.owner_id = u.id AND kb.owner_type = 'user' AND kb.key_type = 'one_time_prekey'").Scan(&count)
	if count != 1 {
		t.Errorf("Expected 1 remaining OTP key, got %d", count)
	}
}

func TestCB54_GetKeyBundle_IdentityOnly(t *testing.T) {
	testDB, cleanup := setupTestServer_CB54(t)
	defer cleanup()
	token, userID := cb54CreateUserAndGetToken(t, testDB, "user_bundle3", "pass123")

	// Upload only identity key
	body := `{"key_type":"identity","public_key":"idkey-only"}`
	req := httptest.NewRequest(http.MethodPost, "/keys/upload", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleUploadPublicKey(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("Upload failed: %d", w.Code)
	}

	// Get bundle
	req = httptest.NewRequest(http.MethodGet, "/keys/bundle?owner_id="+userID+"&owner_type=user", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w = httptest.NewRecorder()
	handleGetKeyBundle(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("GetKeyBundle failed: %d - %s", w.Code, w.Body.String())
	}
	var bundle map[string]json.RawMessage
	json.NewDecoder(w.Body).Decode(&bundle)
	if _, ok := bundle["identity_key"]; !ok {
		t.Error("Missing identity_key in bundle")
	}
	if _, ok := bundle["signed_prekey"]; ok {
		t.Error("Should not have signed_prekey")
	}
	if _, ok := bundle["one_time_prekey"]; ok {
		t.Error("Should not have one_time_prekey")
	}
}

func TestCB54_GetKeyBundle_DefaultOwnerType(t *testing.T) {
	testDB, cleanup := setupTestServer_CB54(t)
	defer cleanup()
	token, userID := cb54CreateUserAndGetToken(t, testDB, "user_bundle4", "pass123")

	// Upload identity key
	body := `{"key_type":"identity","public_key":"idkey-default"}`
	req := httptest.NewRequest(http.MethodPost, "/keys/upload", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleUploadPublicKey(w, req)

	// Get bundle without owner_type — should default to "user"
	req = httptest.NewRequest(http.MethodGet, "/keys/bundle?owner_id="+userID, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w = httptest.NewRecorder()
	handleGetKeyBundle(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("Expected 200 with default owner_type, got %d", w.Code)
	}
}

func TestCB54_GetKeyBundle_MissingOwnerID(t *testing.T) {
	testDB, cleanup := setupTestServer_CB54(t)
	defer cleanup()
	token, _ := cb54CreateUserAndGetToken(t, testDB, "user_bundle5", "pass123")

	req := httptest.NewRequest(http.MethodGet, "/keys/bundle", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleGetKeyBundle(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected 400, got %d", w.Code)
	}
}

func TestCB54_GetKeyBundle_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/keys/bundle", nil)
	w := httptest.NewRecorder()
	handleGetKeyBundle(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected 405, got %d", w.Code)
	}
}

func TestCB54_GetKeyBundle_Unauthorized(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/keys/bundle?owner_id=foo", nil)
	w := httptest.NewRecorder()
	handleGetKeyBundle(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected 401, got %d", w.Code)
	}
}

// =========================================================================
// handleListOneTimePreKeys (e2e.go:197)
// =========================================================================

func TestCB54_ListOneTimePreKeys_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/keys/otpk-count", nil)
	w := httptest.NewRecorder()
	handleListOneTimePreKeys(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected 405, got %d", w.Code)
	}
}

func TestCB54_ListOneTimePreKeys_Unauthorized(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/keys/otpk-count", nil)
	w := httptest.NewRecorder()
	handleListOneTimePreKeys(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected 401, got %d", w.Code)
	}
}

func TestCB54_ListOneTimePreKeys_Success(t *testing.T) {
	testDB, cleanup := setupTestServer_CB54(t)
	defer cleanup()
	token, _ := cb54CreateUserAndGetToken(t, testDB, "user_otpk_count", "pass123")

	// Upload 3 one-time pre-keys
	for i := 1; i <= 3; i++ {
		body := `{"key_type":"one_time_prekey","public_key":"otpk` + string(rune('0'+i)) + `","key_id":` + string(rune('0'+i)) + `}`
		req := httptest.NewRequest(http.MethodPost, "/keys/upload", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		handleUploadPublicKey(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("Upload %d failed: %d", i, w.Code)
		}
	}

	req := httptest.NewRequest(http.MethodGet, "/keys/otpk-count", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleListOneTimePreKeys(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d", w.Code)
	}
	var resp map[string]int
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["one_time_prekey_count"] != 3 {
		t.Errorf("Expected count 3, got %d", resp["one_time_prekey_count"])
	}
}

func TestCB54_ListOneTimePreKeys_ZeroCount(t *testing.T) {
	testDB, cleanup := setupTestServer_CB54(t)
	defer cleanup()
	token, _ := cb54CreateUserAndGetToken(t, testDB, "user_otpk_zero", "pass123")

	req := httptest.NewRequest(http.MethodGet, "/keys/otpk-count", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleListOneTimePreKeys(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d", w.Code)
	}
	var resp map[string]int
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["one_time_prekey_count"] != 0 {
		t.Errorf("Expected count 0, got %d", resp["one_time_prekey_count"])
	}
}

// =========================================================================
// handleStoreEncryptedMessage — delivery paths (e2e.go:218)
// =========================================================================

func TestCB54_StoreEncryptedMessage_Success(t *testing.T) {
	testDB, cleanup := setupTestServer_CB54(t)
	defer cleanup()
	token, _ := cb54CreateUserAndGetToken(t, testDB, "user_encmsg1", "pass123")
	cb54CreateAgent(t, testDB, "agent-encmsg1")
	convID := cb54CreateConversation(t, testDB, "user_encmsg1", "agent-encmsg1")

	body := `{"conversation_id":"` + convID + `","ciphertext":"encdata","iv":"initvec","recipient_key_id":"rk1","algorithm":"aes-256-gcm"}`
	req := httptest.NewRequest(http.MethodPost, "/messages/encrypted", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleStoreEncryptedMessage(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d - %s", w.Code, w.Body.String())
	}
	var resp map[string]string
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["status"] != "stored" {
		t.Errorf("Expected status 'stored', got '%s'", resp["status"])
	}
	if resp["id"] == "" {
		t.Error("Expected non-empty id")
	}
}

func TestCB54_StoreEncryptedMessage_AgentSender(t *testing.T) {
	testDB, cleanup := setupTestServer_CB54(t)
	defer cleanup()
	_, _ = cb54CreateUserAndGetToken(t, testDB, "user_encmsg2", "pass123")
	cb54CreateAgent(t, testDB, "agent-encmsg2")
	convID := cb54CreateConversation(t, testDB, "user_encmsg2", "agent-encmsg2")

	body := `{"conversation_id":"` + convID + `","ciphertext":"encdata2","iv":"initvec2","recipient_key_id":"rk2","algorithm":"x25519-aes-256-gcm"}`
	req := httptest.NewRequest(http.MethodPost, "/messages/encrypted", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Agent-Secret", getAgentSecret())
	req.Header.Set("X-Agent-ID", "agent-encmsg2")
	w := httptest.NewRecorder()
	handleStoreEncryptedMessage(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d - %s", w.Code, w.Body.String())
	}
}

func TestCB54_StoreEncryptedMessage_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/messages/encrypted", nil)
	w := httptest.NewRecorder()
	handleStoreEncryptedMessage(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected 405, got %d", w.Code)
	}
}

func TestCB54_StoreEncryptedMessage_Unauthorized(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/messages/encrypted", strings.NewReader("{}"))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handleStoreEncryptedMessage(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected 401, got %d", w.Code)
	}
}

func TestCB54_StoreEncryptedMessage_InvalidJSON(t *testing.T) {
	testDB, cleanup := setupTestServer_CB54(t)
	defer cleanup()
	token, _ := cb54CreateUserAndGetToken(t, testDB, "user_encmsg3", "pass123")

	req := httptest.NewRequest(http.MethodPost, "/messages/encrypted", strings.NewReader("bad json"))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleStoreEncryptedMessage(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected 400, got %d", w.Code)
	}
}

func TestCB54_StoreEncryptedMessage_MissingFields(t *testing.T) {
	testDB, cleanup := setupTestServer_CB54(t)
	defer cleanup()
	token, _ := cb54CreateUserAndGetToken(t, testDB, "user_encmsg4", "pass123")

	body := `{"conversation_id":"conv1","ciphertext":"data"}`
	req := httptest.NewRequest(http.MethodPost, "/messages/encrypted", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleStoreEncryptedMessage(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected 400 for missing iv/algorithm, got %d", w.Code)
	}
}

func TestCB54_StoreEncryptedMessage_UnsupportedAlgorithm(t *testing.T) {
	testDB, cleanup := setupTestServer_CB54(t)
	defer cleanup()
	token, _ := cb54CreateUserAndGetToken(t, testDB, "user_encmsg5", "pass123")
	cb54CreateAgent(t, testDB, "agent-encmsg5")
	convID := cb54CreateConversation(t, testDB, "user_encmsg5", "agent-encmsg5")

	body := `{"conversation_id":"` + convID + `","ciphertext":"encdata","iv":"initvec","algorithm":"des-ede3"}`
	req := httptest.NewRequest(http.MethodPost, "/messages/encrypted", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleStoreEncryptedMessage(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected 400 for unsupported algorithm, got %d", w.Code)
	}
}

func TestCB54_StoreEncryptedMessage_ConversationNotFound(t *testing.T) {
	testDB, cleanup := setupTestServer_CB54(t)
	defer cleanup()
	token, _ := cb54CreateUserAndGetToken(t, testDB, "user_encmsg6", "pass123")

	body := `{"conversation_id":"nonexistent","ciphertext":"encdata","iv":"initvec","algorithm":"aes-256-gcm"}`
	req := httptest.NewRequest(http.MethodPost, "/messages/encrypted", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleStoreEncryptedMessage(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("Expected 404, got %d", w.Code)
	}
}

func TestCB54_StoreEncryptedMessage_UserNotParticipant(t *testing.T) {
	testDB, cleanup := setupTestServer_CB54(t)
	defer cleanup()
	token, _ := cb54CreateUserAndGetToken(t, testDB, "user_encmsg7", "pass123")
	cb54CreateAgent(t, testDB, "agent-encmsg7")
	_, _ = cb54CreateUserAndGetToken(t, testDB, "user_other", "pass123")
	convID := cb54CreateConversation(t, testDB, "user_other", "agent-encmsg7")

	body := `{"conversation_id":"` + convID + `","ciphertext":"encdata","iv":"initvec","algorithm":"aes-256-gcm"}`
	req := httptest.NewRequest(http.MethodPost, "/messages/encrypted", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleStoreEncryptedMessage(w, req)
	if w.Code != http.StatusForbidden {
		t.Errorf("Expected 403, got %d", w.Code)
	}
}

func TestCB54_StoreEncryptedMessage_AgentNotParticipant(t *testing.T) {
	testDB, cleanup := setupTestServer_CB54(t)
	defer cleanup()
	_, _ = cb54CreateUserAndGetToken(t, testDB, "user_encmsg8", "pass123")
	cb54CreateAgent(t, testDB, "agent-encmsg8")
	cb54CreateAgent(t, testDB, "agent-other")
	convID := cb54CreateConversation(t, testDB, "user_encmsg8", "agent-encmsg8")

	body := `{"conversation_id":"` + convID + `","ciphertext":"encdata","iv":"initvec","algorithm":"aes-256-gcm"}`
	req := httptest.NewRequest(http.MethodPost, "/messages/encrypted", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Agent-Secret", getAgentSecret())
	req.Header.Set("X-Agent-ID", "agent-other")
	w := httptest.NewRecorder()
	handleStoreEncryptedMessage(w, req)
	if w.Code != http.StatusForbidden {
		t.Errorf("Expected 403, got %d", w.Code)
	}
}

func TestCB54_StoreEncryptedMessage_ChaCha20Algorithm(t *testing.T) {
	testDB, cleanup := setupTestServer_CB54(t)
	defer cleanup()
	token, _ := cb54CreateUserAndGetToken(t, testDB, "user_encmsg9", "pass123")
	cb54CreateAgent(t, testDB, "agent-encmsg9")
	convID := cb54CreateConversation(t, testDB, "user_encmsg9", "agent-encmsg9")

	body := `{"conversation_id":"` + convID + `","ciphertext":"encdata","iv":"initvec","algorithm":"x25519-chacha20-poly1305"}`
	req := httptest.NewRequest(http.MethodPost, "/messages/encrypted", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleStoreEncryptedMessage(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("Expected 200 for chacha20 algorithm, got %d - %s", w.Code, w.Body.String())
	}
}

// =========================================================================
// handleGetEncryptedMessages — additional paths (e2e.go:336)
// =========================================================================

func TestCB54_GetEncryptedMessages_Success(t *testing.T) {
	testDB, cleanup := setupTestServer_CB54(t)
	defer cleanup()
	token, _ := cb54CreateUserAndGetToken(t, testDB, "user_getenc1", "pass123")
	cb54CreateAgent(t, testDB, "agent-getenc1")
	convID := cb54CreateConversation(t, testDB, "user_getenc1", "agent-getenc1")

	// Store a message first
	storeBody := `{"conversation_id":"` + convID + `","ciphertext":"encdata","iv":"initvec","algorithm":"aes-256-gcm"}`
	req := httptest.NewRequest(http.MethodPost, "/messages/encrypted", strings.NewReader(storeBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleStoreEncryptedMessage(w, req)

	// Now retrieve
	req = httptest.NewRequest(http.MethodGet, "/messages/encrypted?conversation_id="+convID, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w = httptest.NewRecorder()
	handleGetEncryptedMessages(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d", w.Code)
	}
	var messages []EncryptedMessage
	json.NewDecoder(w.Body).Decode(&messages)
	if len(messages) != 1 {
		t.Errorf("Expected 1 message, got %d", len(messages))
	}
	if messages[0].Ciphertext != "encdata" {
		t.Errorf("Expected ciphertext 'encdata', got '%s'", messages[0].Ciphertext)
	}
}

func TestCB54_GetEncryptedMessages_AgentAccess(t *testing.T) {
	testDB, cleanup := setupTestServer_CB54(t)
	defer cleanup()
	token, _ := cb54CreateUserAndGetToken(t, testDB, "user_getenc2", "pass123")
	cb54CreateAgent(t, testDB, "agent-getenc2")
	convID := cb54CreateConversation(t, testDB, "user_getenc2", "agent-getenc2")

	// Store a message as user
	storeBody := `{"conversation_id":"` + convID + `","ciphertext":"encdata","iv":"initvec","algorithm":"aes-256-gcm"}`
	req := httptest.NewRequest(http.MethodPost, "/messages/encrypted", strings.NewReader(storeBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleStoreEncryptedMessage(w, req)

	// Agent retrieves
	req = httptest.NewRequest(http.MethodGet, "/messages/encrypted?conversation_id="+convID, nil)
	req.Header.Set("X-Agent-Secret", getAgentSecret())
	req.Header.Set("X-Agent-ID", "agent-getenc2")
	w = httptest.NewRecorder()
	handleGetEncryptedMessages(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d", w.Code)
	}
	var messages []EncryptedMessage
	json.NewDecoder(w.Body).Decode(&messages)
	if len(messages) != 1 {
		t.Errorf("Expected 1 message, got %d", len(messages))
	}
}

func TestCB54_GetEncryptedMessages_WrongAgent(t *testing.T) {
	testDB, cleanup := setupTestServer_CB54(t)
	defer cleanup()
	token, _ := cb54CreateUserAndGetToken(t, testDB, "user_getenc3", "pass123")
	cb54CreateAgent(t, testDB, "agent-getenc3")
	cb54CreateAgent(t, testDB, "agent-wrong")
	convID := cb54CreateConversation(t, testDB, "user_getenc3", "agent-getenc3")

	// Store a message
	storeBody := `{"conversation_id":"` + convID + `","ciphertext":"encdata","iv":"initvec","algorithm":"aes-256-gcm"}`
	req := httptest.NewRequest(http.MethodPost, "/messages/encrypted", strings.NewReader(storeBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleStoreEncryptedMessage(w, req)

	// Wrong agent tries to access
	req = httptest.NewRequest(http.MethodGet, "/messages/encrypted?conversation_id="+convID, nil)
	req.Header.Set("X-Agent-Secret", getAgentSecret())
	req.Header.Set("X-Agent-ID", "agent-wrong")
	w = httptest.NewRecorder()
	handleGetEncryptedMessages(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("Expected 404 for wrong agent, got %d", w.Code)
	}
}

func TestCB54_GetEncryptedMessages_ConversationNotFound(t *testing.T) {
	testDB, cleanup := setupTestServer_CB54(t)
	defer cleanup()
	token, _ := cb54CreateUserAndGetToken(t, testDB, "user_getenc4", "pass123")

	req := httptest.NewRequest(http.MethodGet, "/messages/encrypted?conversation_id=nonexistent", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleGetEncryptedMessages(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("Expected 404, got %d", w.Code)
	}
}

func TestCB54_GetEncryptedMessages_WrongUser(t *testing.T) {
	testDB, cleanup := setupTestServer_CB54(t)
	defer cleanup()
	token1, _ := cb54CreateUserAndGetToken(t, testDB, "user_getenc5a", "pass123")
	cb54CreateUserAndGetToken(t, testDB, "user_getenc5b", "pass123")
	cb54CreateAgent(t, testDB, "agent-getenc5")
	convID := cb54CreateConversation(t, testDB, "user_getenc5a", "agent-getenc5")

	// Store a message as user A
	storeBody := `{"conversation_id":"` + convID + `","ciphertext":"encdata","iv":"initvec","algorithm":"aes-256-gcm"}`
	req := httptest.NewRequest(http.MethodPost, "/messages/encrypted", strings.NewReader(storeBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token1)
	w := httptest.NewRecorder()
	handleStoreEncryptedMessage(w, req)

	// User B tries to access (same DB, different user)
	token2, _ := cb54CreateUserAndGetToken(t, testDB, "user_getenc5b", "pass123")
	req = httptest.NewRequest(http.MethodGet, "/messages/encrypted?conversation_id="+convID, nil)
	req.Header.Set("Authorization", "Bearer "+token2)
	w = httptest.NewRecorder()
	handleGetEncryptedMessages(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("Expected 404 for wrong user, got %d", w.Code)
	}
}

func TestCB54_GetEncryptedMessages_LimitOver200(t *testing.T) {
	testDB, cleanup := setupTestServer_CB54(t)
	defer cleanup()
	token, _ := cb54CreateUserAndGetToken(t, testDB, "user_getenc6", "pass123")
	cb54CreateAgent(t, testDB, "agent-getenc6")
	convID := cb54CreateConversation(t, testDB, "user_getenc6", "agent-getenc6")

	// Store a message
	storeBody := `{"conversation_id":"` + convID + `","ciphertext":"encdata","iv":"initvec","algorithm":"aes-256-gcm"}`
	req := httptest.NewRequest(http.MethodPost, "/messages/encrypted", strings.NewReader(storeBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleStoreEncryptedMessage(w, req)

	// Request with limit > 200 — should default to 50
	req = httptest.NewRequest(http.MethodGet, "/messages/encrypted?conversation_id="+convID+"&limit=500", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w = httptest.NewRecorder()
	handleGetEncryptedMessages(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d", w.Code)
	}
}

func TestCB54_GetEncryptedMessages_NegativeLimit(t *testing.T) {
	testDB, cleanup := setupTestServer_CB54(t)
	defer cleanup()
	token, _ := cb54CreateUserAndGetToken(t, testDB, "user_getenc7", "pass123")
	cb54CreateAgent(t, testDB, "agent-getenc7")
	convID := cb54CreateConversation(t, testDB, "user_getenc7", "agent-getenc7")

	// Store a message
	storeBody := `{"conversation_id":"` + convID + `","ciphertext":"encdata","iv":"initvec","algorithm":"aes-256-gcm"}`
	req := httptest.NewRequest(http.MethodPost, "/messages/encrypted", strings.NewReader(storeBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleStoreEncryptedMessage(w, req)

	// Request with negative limit — should default to 50
	req = httptest.NewRequest(http.MethodGet, "/messages/encrypted?conversation_id="+convID+"&limit=-5", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w = httptest.NewRecorder()
	handleGetEncryptedMessages(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d", w.Code)
	}
}

func TestCB54_GetEncryptedMessages_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/messages/encrypted", nil)
	w := httptest.NewRecorder()
	handleGetEncryptedMessages(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected 405, got %d", w.Code)
	}
}

func TestCB54_GetEncryptedMessages_Unauthorized(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/messages/encrypted?conversation_id=x", nil)
	w := httptest.NewRecorder()
	handleGetEncryptedMessages(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected 401, got %d", w.Code)
	}
}

func TestCB54_GetEncryptedMessages_MissingConversationID(t *testing.T) {
	testDB, cleanup := setupTestServer_CB54(t)
	defer cleanup()
	token, _ := cb54CreateUserAndGetToken(t, testDB, "user_getenc8", "pass123")

	req := httptest.NewRequest(http.MethodGet, "/messages/encrypted", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleGetEncryptedMessages(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected 400, got %d", w.Code)
	}
}

// =========================================================================
// authenticateRequest (e2e.go:409)
// =========================================================================

func TestCB54_AuthenticateRequest_AgentNoID(t *testing.T) {
	_, cleanup := setupTestServer_CB54(t)
	defer cleanup()

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("X-Agent-Secret", getAgentSecret())
	// No X-Agent-ID header
	id, typ, err := authenticateRequest(req)
	if err == nil {
		t.Error("Expected error for agent auth without ID")
	}
	if id != "" {
		t.Errorf("Expected empty id, got '%s'", id)
	}
	if typ != "" {
		t.Errorf("Expected empty type, got '%s'", typ)
	}
}

func TestCB54_AuthenticateRequest_NoAuth(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	id, typ, err := authenticateRequest(req)
	if err == nil {
		t.Error("Expected error for no auth")
	}
	if id != "" || typ != "" {
		t.Errorf("Expected empty id/type, got '%s'/'%s'", id, typ)
	}
}

func TestCB54_AuthenticateRequest_InvalidBearer(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer invalidtoken123")
	id, typ, err := authenticateRequest(req)
	if err == nil {
		t.Error("Expected error for invalid bearer token")
	}
	if id != "" || typ != "" {
		t.Errorf("Expected empty id/type, got '%s'/'%s'", id, typ)
	}
}

func TestCB54_AuthenticateRequest_WrongAgentSecret(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("X-Agent-Secret", "wrong-secret")
	req.Header.Set("X-Agent-ID", "agent-test")
	id, typ, err := authenticateRequest(req)
	if err == nil {
		t.Error("Expected error for wrong agent secret")
	}
	if id != "" || typ != "" {
		t.Errorf("Expected empty id/type, got '%s'/'%s'", id, typ)
	}
}

func TestCB54_AuthenticateRequest_ValidAgent(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("X-Agent-Secret", getAgentSecret())
	req.Header.Set("X-Agent-ID", "agent-valid")
	id, typ, err := authenticateRequest(req)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if id != "agent-valid" {
		t.Errorf("Expected id 'agent-valid', got '%s'", id)
	}
	if typ != "agent" {
		t.Errorf("Expected type 'agent', got '%s'", typ)
	}
}

func TestCB54_AuthenticateRequest_ValidUser(t *testing.T) {
	testDB, cleanup := setupTestServer_CB54(t)
	defer cleanup()
	token, userID := cb54CreateUserAndGetToken(t, testDB, "user_auth_test", "pass123")

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	id, typ, err := authenticateRequest(req)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if id != userID {
		t.Errorf("Expected id '%s', got '%s'", userID, id)
	}
	if typ != "user" {
		t.Errorf("Expected type 'user', got '%s'", typ)
	}
}

// =========================================================================
// handleWebPushSubscribe — additional paths (push.go:410)
// =========================================================================

func TestCB54_WebPushSubscribe_MissingFields(t *testing.T) {
	testDB, cleanup := setupTestServer_CB54(t)
	defer cleanup()
	token, _ := cb54CreateUserAndGetToken(t, testDB, "user_wp_missing", "pass123")

	body := `{"endpoint":"https://example.com/push","keys":{"p256dh":"","auth":""}}`
	req := httptest.NewRequest(http.MethodPost, "/push/web-subscribe", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleWebPushSubscribe(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected 400 for missing keys, got %d", w.Code)
	}
}

func TestCB54_WebPushSubscribe_Success(t *testing.T) {
	testDB, cleanup := setupTestServer_CB54(t)
	defer cleanup()
	token, _ := cb54CreateUserAndGetToken(t, testDB, "user_wp_success", "pass123")

	body := `{"endpoint":"https://fcm.googleapis.com/fcm/send/test123","keys":{"p256dh":"p256key123","auth":"authkey123"}}`
	req := httptest.NewRequest(http.MethodPost, "/push/web-subscribe", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleWebPushSubscribe(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d - %s", w.Code, w.Body.String())
	}
	var resp map[string]string
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["status"] != "subscribed" {
		t.Errorf("Expected status 'subscribed', got '%s'", resp["status"])
	}

	// Verify device token was stored
	var count int
	testDB.QueryRow("SELECT COUNT(*) FROM device_tokens dt JOIN users u ON u.username = 'user_wp_success' WHERE dt.user_id = u.id AND dt.platform = 'web'").Scan(&count)
	if count != 1 {
		t.Errorf("Expected 1 device token, got %d", count)
	}
}

func TestCB54_WebPushSubscribe_InvalidJSON(t *testing.T) {
	testDB, cleanup := setupTestServer_CB54(t)
	defer cleanup()
	token, _ := cb54CreateUserAndGetToken(t, testDB, "user_wp_badjson", "pass123")

	req := httptest.NewRequest(http.MethodPost, "/push/web-subscribe", strings.NewReader("bad json"))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleWebPushSubscribe(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected 400, got %d", w.Code)
	}
}

// =========================================================================
// handleRegisterDeviceToken — additional paths (push.go:228)
// =========================================================================

func TestCB54_RegisterDeviceToken_DefaultPlatform(t *testing.T) {
	testDB, cleanup := setupTestServer_CB54(t)
	defer cleanup()
	token, _ := cb54CreateUserAndGetToken(t, testDB, "user_dt_default", "pass123")

	body := `{"device_token":"token123"}`
	req := httptest.NewRequest(http.MethodPost, "/push/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleRegisterDeviceToken(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d - %s", w.Code, w.Body.String())
	}

	// Verify platform defaulted to ios
	var platform string
	testDB.QueryRow("SELECT dt.platform FROM device_tokens dt JOIN users u ON u.username = 'user_dt_default' WHERE dt.user_id = u.id AND dt.device_token = 'token123'").Scan(&platform)
	if platform != "ios" {
		t.Errorf("Expected default platform 'ios', got '%s'", platform)
	}
}

func TestCB54_RegisterDeviceToken_AndroidPlatform(t *testing.T) {
	testDB, cleanup := setupTestServer_CB54(t)
	defer cleanup()
	token, _ := cb54CreateUserAndGetToken(t, testDB, "user_dt_android", "pass123")

	body := `{"device_token":"android-token-1","platform":"android"}`
	req := httptest.NewRequest(http.MethodPost, "/push/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleRegisterDeviceToken(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d - %s", w.Code, w.Body.String())
	}

	var platform string
	testDB.QueryRow("SELECT dt.platform FROM device_tokens dt JOIN users u ON u.username = 'user_dt_android' WHERE dt.user_id = u.id AND dt.device_token = 'android-token-1'").Scan(&platform)
	if platform != "android" {
		t.Errorf("Expected platform 'android', got '%s'", platform)
	}
}

func TestCB54_RegisterDeviceToken_DuplicateUpdate(t *testing.T) {
	testDB, cleanup := setupTestServer_CB54(t)
	defer cleanup()
	token, _ := cb54CreateUserAndGetToken(t, testDB, "user_dt_dup", "pass123")

	// First registration
	body := `{"device_token":"dup-token","platform":"ios"}`
	req := httptest.NewRequest(http.MethodPost, "/push/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleRegisterDeviceToken(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("First registration failed: %d", w.Code)
	}

	// Second registration with same token, different platform
	body = `{"device_token":"dup-token","platform":"android"}`
	req = httptest.NewRequest(http.MethodPost, "/push/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w = httptest.NewRecorder()
	handleRegisterDeviceToken(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("Second registration failed: %d", w.Code)
	}

	// Verify platform was updated
	var platform string
	testDB.QueryRow("SELECT dt.platform FROM device_tokens dt JOIN users u ON u.username = 'user_dt_dup' WHERE dt.user_id = u.id AND dt.device_token = 'dup-token'").Scan(&platform)
	if platform != "android" {
		t.Errorf("Expected updated platform 'android', got '%s'", platform)
	}
}

func TestCB54_RegisterDeviceToken_InvalidJSON(t *testing.T) {
	testDB, cleanup := setupTestServer_CB54(t)
	defer cleanup()
	token, _ := cb54CreateUserAndGetToken(t, testDB, "user_dt_badjson", "pass123")

	req := httptest.NewRequest(http.MethodPost, "/push/register", strings.NewReader("bad json"))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleRegisterDeviceToken(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected 400, got %d", w.Code)
	}
}

func TestCB54_RegisterDeviceToken_EmptyToken(t *testing.T) {
	testDB, cleanup := setupTestServer_CB54(t)
	defer cleanup()
	token, _ := cb54CreateUserAndGetToken(t, testDB, "user_dt_empty", "pass123")

	body := `{"device_token":"","platform":"ios"}`
	req := httptest.NewRequest(http.MethodPost, "/push/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleRegisterDeviceToken(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected 400, got %d", w.Code)
	}
}

func TestCB54_RegisterDeviceToken_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/push/register", nil)
	w := httptest.NewRecorder()
	handleRegisterDeviceToken(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected 405, got %d", w.Code)
	}
}

// =========================================================================
// handleUnregisterDeviceToken — additional paths (push.go:283)
// =========================================================================

func TestCB54_UnregisterDeviceToken_Success(t *testing.T) {
	testDB, cleanup := setupTestServer_CB54(t)
	defer cleanup()
	token, _ := cb54CreateUserAndGetToken(t, testDB, "user_unreg", "pass123")

	// Register first
	body := `{"device_token":"token-to-remove","platform":"ios"}`
	req := httptest.NewRequest(http.MethodPost, "/push/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleRegisterDeviceToken(w, req)

	// Unregister
	body = `{"device_token":"token-to-remove"}`
	req = httptest.NewRequest(http.MethodDelete, "/push/unregister", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w = httptest.NewRecorder()
	handleUnregisterDeviceToken(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d - %s", w.Code, w.Body.String())
	}

	// Verify removed
	var count int
	testDB.QueryRow("SELECT COUNT(*) FROM device_tokens dt JOIN users u ON u.username = 'user_unreg' WHERE dt.user_id = u.id AND dt.device_token = 'token-to-remove'").Scan(&count)
	if count != 0 {
		t.Errorf("Expected 0 tokens after unregister, got %d", count)
	}
}

func TestCB54_UnregisterDeviceToken_EmptyToken(t *testing.T) {
	testDB, cleanup := setupTestServer_CB54(t)
	defer cleanup()
	token, _ := cb54CreateUserAndGetToken(t, testDB, "user_unreg_empty", "pass123")

	body := `{"device_token":""}`
	req := httptest.NewRequest(http.MethodDelete, "/push/unregister", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleUnregisterDeviceToken(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected 400, got %d", w.Code)
	}
}

func TestCB54_UnregisterDeviceToken_InvalidJSON(t *testing.T) {
	testDB, cleanup := setupTestServer_CB54(t)
	defer cleanup()
	token, _ := cb54CreateUserAndGetToken(t, testDB, "user_unreg_bad", "pass123")

	req := httptest.NewRequest(http.MethodDelete, "/push/unregister", strings.NewReader("bad json"))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleUnregisterDeviceToken(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected 400, got %d", w.Code)
	}
}

func TestCB54_UnregisterDeviceToken_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/push/unregister", nil)
	w := httptest.NewRecorder()
	handleUnregisterDeviceToken(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected 405, got %d", w.Code)
	}
}

// =========================================================================
// handleGetVAPIDKey (push.go:386)
// =========================================================================

func TestCB54_GetVAPIDKey_Success(t *testing.T) {
	testDB, cleanup := setupTestServer_CB54(t)
	defer cleanup()
	token, _ := cb54CreateUserAndGetToken(t, testDB, "user_vapid", "pass123")

	// Set VAPID public key via env
	oldKey := vapidPublicKey
	vapidPublicKey = "test-vapid-key-123"

	defer func() { vapidPublicKey = oldKey }()

	req := httptest.NewRequest(http.MethodGet, "/push/vapid-key", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleGetVAPIDKey(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d", w.Code)
	}
	var resp map[string]string
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["public_key"] != "test-vapid-key-123" {
		t.Errorf("Expected 'test-vapid-key-123', got '%s'", resp["public_key"])
	}
}

func TestCB54_GetVAPIDKey_Unauthorized(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/push/vapid-key", nil)
	w := httptest.NewRecorder()
	handleGetVAPIDKey(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected 401, got %d", w.Code)
	}
}

func TestCB54_GetVAPIDKey_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/push/vapid-key", nil)
	w := httptest.NewRecorder()
	handleGetVAPIDKey(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected 405, got %d", w.Code)
	}
}

// =========================================================================
// getDeviceTokensForUser — with platform (push.go:349)
// =========================================================================

func TestCB54_GetDeviceTokensForUser_MultiplePlatforms(t *testing.T) {
	testDB, cleanup := setupTestServer_CB54(t)
	defer cleanup()
	token, userID := cb54CreateUserAndGetToken(t, testDB, "user_multi_tokens", "pass123")

	// Register iOS, Android, and Web tokens
	for _, body := range []string{
		`{"device_token":"ios-token-1","platform":"ios"}`,
		`{"device_token":"android-token-1","platform":"android"}`,
	} {
		req := httptest.NewRequest(http.MethodPost, "/push/register", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		handleRegisterDeviceToken(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("Registration failed: %d", w.Code)
		}
	}

	// Also add a web push subscription
	webBody := `{"endpoint":"https://web-push.example.com/send","keys":{"p256dh":"p256","auth":"auth"}}`
	req := httptest.NewRequest(http.MethodPost, "/push/web-subscribe", strings.NewReader(webBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleWebPushSubscribe(w, req)

	tokens, err := getDeviceTokensForUser(userID)
	if err != nil {
		t.Fatalf("getDeviceTokensForUser error: %v", err)
	}
	if len(tokens) != 3 {
		t.Errorf("Expected 3 tokens, got %d", len(tokens))
	}

	// Verify platforms
	platforms := map[string]bool{}
	for _, tk := range tokens {
		platforms[tk.Platform] = true
	}
	if !platforms["ios"] {
		t.Error("Missing ios platform")
	}
	if !platforms["android"] {
		t.Error("Missing android platform")
	}
	if !platforms["web"] {
		t.Error("Missing web platform")
	}
}

func TestCB54_GetDeviceTokensForUser_Empty(t *testing.T) {
	_, cleanup := setupTestServer_CB54(t)
	defer cleanup()

	tokens, err := getDeviceTokensForUser("user_no_tokens")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if len(tokens) != 0 {
		t.Errorf("Expected 0 tokens, got %d", len(tokens))
	}
}

// =========================================================================
// safeTruncate (push.go:524)
// =========================================================================

func TestCB54_SafeTruncate_ShortString(t *testing.T) {
	if result := safeTruncate("abc", 8); result != "abc" {
		t.Errorf("Expected 'abc', got '%s'", result)
	}
}

func TestCB54_SafeTruncate_ExactLength(t *testing.T) {
	if result := safeTruncate("12345678", 8); result != "12345678" {
		t.Errorf("Expected '12345678', got '%s'", result)
	}
}

func TestCB54_SafeTruncate_LongString(t *testing.T) {
	if result := safeTruncate("123456789", 8); result != "12345678" {
		t.Errorf("Expected '12345678', got '%s'", result)
	}
}

func TestCB54_SafeTruncate_EmptyString(t *testing.T) {
	if result := safeTruncate("", 8); result != "" {
		t.Errorf("Expected '', got '%s'", result)
	}
}