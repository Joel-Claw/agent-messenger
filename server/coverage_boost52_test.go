package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

// --- Helper ---
func setupTestDB_CB52(t *testing.T) *sql.DB {
	testDB, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("Failed to open test DB: %v", err)
	}
	if err := initSchema(testDB); err != nil {
		t.Fatalf("Failed to init schema: %v", err)
	}
	return testDB
}

func generateTestJWT_CB52(t *testing.T, userID string) string {
	return generateTestToken(t, userID)
}

// =========================================================================
// handleStoreEncryptedMessage: various error paths
// =========================================================================

func TestCB52_HandleStoreEncryptedMessage_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/messages/encrypted", nil)
	w := httptest.NewRecorder()
	handleStoreEncryptedMessage(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected 405, got %d", w.Code)
	}
}

func TestCB52_HandleStoreEncryptedMessage_Unauthorized(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/messages/encrypted", strings.NewReader("{}"))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handleStoreEncryptedMessage(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected 401, got %d", w.Code)
	}
}

func TestCB52_HandleStoreEncryptedMessage_InvalidJSON(t *testing.T) {
	os.Setenv("AGENT_SECRET", "test-secret-52")
	defer os.Unsetenv("AGENT_SECRET")

	req := httptest.NewRequest(http.MethodPost, "/messages/encrypted", strings.NewReader("not json"))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Agent-Secret", os.Getenv("AGENT_SECRET"))
	req.Header.Set("X-Agent-ID", "agent-52a")
	w := httptest.NewRecorder()
	handleStoreEncryptedMessage(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected 400, got %d", w.Code)
	}
}

func TestCB52_HandleStoreEncryptedMessage_MissingFields(t *testing.T) {
	os.Setenv("AGENT_SECRET", "test-secret-52")
	defer os.Unsetenv("AGENT_SECRET")

	body := `{"conversation_id":"","ciphertext":"","iv":"","algorithm":""}`
	req := httptest.NewRequest(http.MethodPost, "/messages/encrypted", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Agent-Secret", os.Getenv("AGENT_SECRET"))
	req.Header.Set("X-Agent-ID", "agent-52a")
	w := httptest.NewRecorder()
	handleStoreEncryptedMessage(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected 400, got %d", w.Code)
	}
}

func TestCB52_HandleStoreEncryptedMessage_InvalidAlgorithm(t *testing.T) {
	os.Setenv("AGENT_SECRET", "test-secret-52")
	defer os.Unsetenv("AGENT_SECRET")

	body := `{"conversation_id":"conv-52a","ciphertext":"cipher","iv":"iv123","algorithm":"invalid-algo"}`
	req := httptest.NewRequest(http.MethodPost, "/messages/encrypted", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Agent-Secret", os.Getenv("AGENT_SECRET"))
	req.Header.Set("X-Agent-ID", "agent-52a")
	w := httptest.NewRecorder()
	handleStoreEncryptedMessage(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected 400, got %d", w.Code)
	}
}

func TestCB52_HandleStoreEncryptedMessage_ConversationNotFound(t *testing.T) {
	oldDB := db
	testDB := setupTestDB_CB52(t)
	db = testDB
	defer func() {
		db = oldDB
		testDB.Close()
	}()

	os.Setenv("AGENT_SECRET", "test-secret-52")
	defer os.Unsetenv("AGENT_SECRET")

	body := `{"conversation_id":"nonexistent","ciphertext":"cipher","iv":"iv123","algorithm":"aes-256-gcm"}`
	req := httptest.NewRequest(http.MethodPost, "/messages/encrypted", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Agent-Secret", os.Getenv("AGENT_SECRET"))
	req.Header.Set("X-Agent-ID", "agent-52a")
	w := httptest.NewRecorder()
	handleStoreEncryptedMessage(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("Expected 404, got %d", w.Code)
	}
}

func TestCB52_HandleStoreEncryptedMessage_AgentNotParticipant(t *testing.T) {
	oldDB := db
	testDB := setupTestDB_CB52(t)
	db = testDB
	defer func() {
		db = oldDB
		testDB.Close()
	}()

	os.Setenv("AGENT_SECRET", "test-secret-52")
	defer os.Unsetenv("AGENT_SECRET")

	// Create conversation with a different agent
	_, err := testDB.Exec("INSERT INTO conversations (id, user_id, agent_id, created_at) VALUES (?, ?, ?, ?)",
		"conv-52b", "user-52b", "agent-52-owner", time.Now())
	if err != nil {
		t.Fatalf("Failed to insert conversation: %v", err)
	}

	body := `{"conversation_id":"conv-52b","ciphertext":"cipher","iv":"iv123","algorithm":"aes-256-gcm"}`
	req := httptest.NewRequest(http.MethodPost, "/messages/encrypted", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Agent-Secret", os.Getenv("AGENT_SECRET"))
	req.Header.Set("X-Agent-ID", "agent-52-wrong")
	w := httptest.NewRecorder()
	handleStoreEncryptedMessage(w, req)
	if w.Code != http.StatusForbidden {
		t.Errorf("Expected 403, got %d", w.Code)
	}
}

func TestCB52_HandleStoreEncryptedMessage_UserNotParticipant(t *testing.T) {
	oldDB := db
	testDB := setupTestDB_CB52(t)
	db = testDB
	defer func() {
		db = oldDB
		testDB.Close()
	}()

	// Create conversation owned by different user
	_, err := testDB.Exec("INSERT INTO conversations (id, user_id, agent_id, created_at) VALUES (?, ?, ?, ?)",
		"conv-52c", "user-52-owner", "agent-52c", time.Now())
	if err != nil {
		t.Fatalf("Failed to insert conversation: %v", err)
	}

	token := generateTestJWT_CB52(t, "user-52-wrong")
	body := `{"conversation_id":"conv-52c","ciphertext":"cipher","iv":"iv123","algorithm":"aes-256-gcm"}`
	req := httptest.NewRequest(http.MethodPost, "/messages/encrypted", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleStoreEncryptedMessage(w, req)
	if w.Code != http.StatusForbidden {
		t.Errorf("Expected 403, got %d", w.Code)
	}
}

func TestCB52_HandleStoreEncryptedMessage_DBError(t *testing.T) {
	oldDB := db
	testDB := setupTestDB_CB52(t)
	db = testDB
	defer func() {
		db = oldDB
	}()

	// Create conversation
	_, err := testDB.Exec("INSERT INTO conversations (id, user_id, agent_id, created_at) VALUES (?, ?, ?, ?)",
		"conv-52d", "user-52d", "agent-52d", time.Now())
	if err != nil {
		t.Fatalf("Failed to insert conversation: %v", err)
	}

	token := generateTestJWT_CB52(t, "user-52d")
	body := `{"conversation_id":"conv-52d","ciphertext":"cipher","iv":"iv123","algorithm":"aes-256-gcm"}`
	req := httptest.NewRequest(http.MethodPost, "/messages/encrypted", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	// Close DB to trigger INSERT error
	testDB.Close()

	handleStoreEncryptedMessage(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("Expected 404, got %d", w.Code)
	}
}

func TestCB52_HandleStoreEncryptedMessage_Success(t *testing.T) {
	oldDB := db
	testDB := setupTestDB_CB52(t)
	db = testDB
	defer func() {
		db = oldDB
		testDB.Close()
	}()

	_, err := testDB.Exec("INSERT INTO conversations (id, user_id, agent_id, created_at) VALUES (?, ?, ?, ?)",
		"conv-52e", "user-52e", "agent-52e", time.Now())
	if err != nil {
		t.Fatalf("Failed to insert conversation: %v", err)
	}

	token := generateTestJWT_CB52(t, "user-52e")
	body := `{"conversation_id":"conv-52e","ciphertext":"ciphertext-data","iv":"iv-data","algorithm":"aes-256-gcm","recipient_key_id":"rk1","sender_key_id":"sk1"}`
	req := httptest.NewRequest(http.MethodPost, "/messages/encrypted", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	handleStoreEncryptedMessage(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w.Code)
	}

	// Verify message stored
	var count int
	testDB.QueryRow("SELECT COUNT(*) FROM encrypted_messages WHERE conversation_id = ?", "conv-52e").Scan(&count)
	if count != 1 {
		t.Errorf("Expected 1 encrypted message, got %d", count)
	}
}

// =========================================================================
// handleGetKeyBundle: various paths
// =========================================================================

func TestCB52_HandleGetKeyBundle_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/keys/bundle", nil)
	w := httptest.NewRecorder()
	handleGetKeyBundle(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected 405, got %d", w.Code)
	}
}

func TestCB52_HandleGetKeyBundle_Unauthorized(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/keys/bundle", nil)
	w := httptest.NewRecorder()
	handleGetKeyBundle(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected 401, got %d", w.Code)
	}
}

func TestCB52_HandleGetKeyBundle_MissingOwnerID(t *testing.T) {
	os.Setenv("AGENT_SECRET", "test-secret-52")
	defer os.Unsetenv("AGENT_SECRET")

	req := httptest.NewRequest(http.MethodGet, "/keys/bundle", nil)
	req.Header.Set("X-Agent-Secret", os.Getenv("AGENT_SECRET"))
	req.Header.Set("X-Agent-ID", "agent-52a")
	w := httptest.NewRecorder()
	handleGetKeyBundle(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected 400, got %d", w.Code)
	}
}

func TestCB52_HandleGetKeyBundle_NoIdentityKey(t *testing.T) {
	oldDB := db
	testDB := setupTestDB_CB52(t)
	db = testDB
	defer func() {
		db = oldDB
		testDB.Close()
	}()

	token := generateTestJWT_CB52(t, "user-52f")
	req := httptest.NewRequest(http.MethodGet, "/keys/bundle?owner_id=user-nonexistent", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleGetKeyBundle(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("Expected 404, got %d", w.Code)
	}
}

func TestCB52_HandleGetKeyBundle_WithIdentityKeyOnly(t *testing.T) {
	oldDB := db
	testDB := setupTestDB_CB52(t)
	db = testDB
	defer func() {
		db = oldDB
		testDB.Close()
	}()

	// Insert identity key
	_, err := testDB.Exec("INSERT INTO key_bundles (id, owner_id, owner_type, key_type, public_key, created_at) VALUES (?, ?, ?, ?, ?, ?)",
		"kb-52a", "user-52g", "user", "identity", "identity-pub-key-52", time.Now())
	if err != nil {
		t.Fatalf("Failed to insert key: %v", err)
	}

	token := generateTestJWT_CB52(t, "user-52g")
	req := httptest.NewRequest(http.MethodGet, "/keys/bundle?owner_id=user-52g", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleGetKeyBundle(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w.Code)
	}

	var result map[string]interface{}
	json.NewDecoder(w.Body).Decode(&result)
	if result["identity_key"] == nil {
		t.Error("Expected identity_key in response")
	}
	if result["signed_prekey"] != nil {
		t.Error("Expected no signed_prekey")
	}
	if result["one_time_prekey"] != nil {
		t.Error("Expected no one_time_prekey")
	}
}

func TestCB52_HandleGetKeyBundle_FullBundle(t *testing.T) {
	oldDB := db
	testDB := setupTestDB_CB52(t)
	db = testDB
	defer func() {
		db = oldDB
		testDB.Close()
	}()

	// Insert identity, signed prekey, and one-time prekey
	_, err := testDB.Exec("INSERT INTO key_bundles (id, owner_id, owner_type, key_type, public_key, created_at) VALUES (?, ?, ?, ?, ?, ?)",
		"kb-52b", "user-52h", "user", "identity", "identity-pub-52h", time.Now())
	if err != nil {
		t.Fatalf("Failed to insert identity key: %v", err)
	}
	_, err = testDB.Exec("INSERT INTO key_bundles (id, owner_id, owner_type, key_type, public_key, signature, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
		"kb-52c", "user-52h", "user", "signed_prekey", "signed-pub-52h", "sig-52h", time.Now().Add(1*time.Second))
	if err != nil {
		t.Fatalf("Failed to insert signed prekey: %v", err)
	}
	_, err = testDB.Exec("INSERT INTO key_bundles (id, owner_id, owner_type, key_type, public_key, key_id, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
		"kb-52d", "user-52h", "user", "one_time_prekey", "otp-pub-52h", 0, time.Now().Add(2*time.Second))
	if err != nil {
		t.Fatalf("Failed to insert one-time prekey: %v", err)
	}

	token := generateTestJWT_CB52(t, "user-52h")
	req := httptest.NewRequest(http.MethodGet, "/keys/bundle?owner_id=user-52h", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleGetKeyBundle(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w.Code)
	}

	var result map[string]interface{}
	json.NewDecoder(w.Body).Decode(&result)
	if result["identity_key"] == nil {
		t.Error("Expected identity_key")
	}
	if result["signed_prekey"] == nil {
		t.Error("Expected signed_prekey")
	}
	if result["one_time_prekey"] == nil {
		t.Error("Expected one_time_prekey")
	}

	// Verify one-time prekey was consumed (deleted)
	var count int
	testDB.QueryRow("SELECT COUNT(*) FROM key_bundles WHERE owner_id = ? AND key_type = 'one_time_prekey'", "user-52h").Scan(&count)
	if count != 0 {
		t.Errorf("Expected one-time prekey to be consumed, got %d remaining", count)
	}
}

// =========================================================================
// handleListOneTimePreKeys
// =========================================================================

func TestCB52_HandleListOneTimePreKeys_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/keys/otpk-count", nil)
	w := httptest.NewRecorder()
	handleListOneTimePreKeys(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected 405, got %d", w.Code)
	}
}

func TestCB52_HandleListOneTimePreKeys_Unauthorized(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/keys/otpk-count", nil)
	w := httptest.NewRecorder()
	handleListOneTimePreKeys(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected 401, got %d", w.Code)
	}
}

func TestCB52_HandleListOneTimePreKeys_Success(t *testing.T) {
	oldDB := db
	testDB := setupTestDB_CB52(t)
	db = testDB
	defer func() {
		db = oldDB
		testDB.Close()
	}()

	// Insert 3 one-time prekeys
	for i := 0; i < 3; i++ {
		_, err := testDB.Exec("INSERT INTO key_bundles (id, owner_id, owner_type, key_type, public_key, key_id, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
			"kb-52otp-"+string(rune('a'+i)), "user-52i", "user", "one_time_prekey", "otp-pub-"+string(rune('a'+i)), "keyid-"+string(rune('a'+i)), time.Now())
		if err != nil {
			t.Fatalf("Failed to insert otpk: %v", err)
		}
	}

	token := generateTestJWT_CB52(t, "user-52i")
	req := httptest.NewRequest(http.MethodGet, "/keys/otpk-count", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleListOneTimePreKeys(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w.Code)
	}

	var result map[string]int
	json.NewDecoder(w.Body).Decode(&result)
	if result["one_time_prekey_count"] != 3 {
		t.Errorf("Expected 3 prekeys, got %d", result["one_time_prekey_count"])
	}
}

// =========================================================================
// handleRegisterDeviceToken: various paths
// =========================================================================

func TestCB52_HandleRegisterDeviceToken_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/devices/register", nil)
	w := httptest.NewRecorder()
	handleRegisterDeviceToken(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected 405, got %d", w.Code)
	}
}

func TestCB52_HandleRegisterDeviceToken_Unauthorized(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/devices/register", strings.NewReader("{}"))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handleRegisterDeviceToken(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected 401, got %d", w.Code)
	}
}

func TestCB52_HandleRegisterDeviceToken_InvalidJSON(t *testing.T) {
	token := generateTestJWT_CB52(t, "user-52j")
	req := httptest.NewRequest(http.MethodPost, "/devices/register", strings.NewReader("not json"))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleRegisterDeviceToken(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected 400, got %d", w.Code)
	}
}

func TestCB52_HandleRegisterDeviceToken_MissingFields(t *testing.T) {
	oldDB := db
	testDB := setupTestDB_CB52(t)
	db = testDB
	defer func() {
		db = oldDB
		testDB.Close()
	}()

	token := generateTestJWT_CB52(t, "user-52j")
	body := `{"device_token":"","platform":""}`
	req := httptest.NewRequest(http.MethodPost, "/devices/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleRegisterDeviceToken(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected 400, got %d", w.Code)
	}
}

func TestCB52_HandleRegisterDeviceToken_Success(t *testing.T) {
	oldDB := db
	testDB := setupTestDB_CB52(t)
	db = testDB
	defer func() {
		db = oldDB
		testDB.Close()
	}()

	token := generateTestJWT_CB52(t, "user-52k")
	body := `{"device_token":"token-52k","platform":"apns"}`
	req := httptest.NewRequest(http.MethodPost, "/devices/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleRegisterDeviceToken(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w.Code)
	}

	// Verify token stored
	var count int
	testDB.QueryRow("SELECT COUNT(*) FROM device_tokens WHERE user_id = ? AND device_token = ?", "user-52k", "token-52k").Scan(&count)
	if count != 1 {
		t.Errorf("Expected 1 token, got %d", count)
	}
}

func TestCB52_HandleRegisterDeviceToken_DBError(t *testing.T) {
	oldDB := db
	testDB := setupTestDB_CB52(t)
	db = testDB
	defer func() {
		db = oldDB
	}()

	token := generateTestJWT_CB52(t, "user-52l")
	body := `{"device_token":"token-52l","platform":"fcm"}`
	req := httptest.NewRequest(http.MethodPost, "/devices/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	testDB.Close()

	handleRegisterDeviceToken(w, req)
	if w.Code != http.StatusInternalServerError {
		t.Errorf("Expected 500, got %d", w.Code)
	}
}

// =========================================================================
// handleUnregisterDeviceToken: various paths
// =========================================================================

func TestCB52_HandleUnregisterDeviceToken_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/devices/unregister", nil)
	w := httptest.NewRecorder()
	handleUnregisterDeviceToken(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected 405, got %d", w.Code)
	}
}

func TestCB52_HandleUnregisterDeviceToken_Unauthorized(t *testing.T) {
	req := httptest.NewRequest(http.MethodDelete, "/devices/unregister", strings.NewReader("{}"))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handleUnregisterDeviceToken(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected 401, got %d", w.Code)
	}
}

func TestCB52_HandleUnregisterDeviceToken_InvalidJSON(t *testing.T) {
	token := generateTestJWT_CB52(t, "user-52m")
	req := httptest.NewRequest(http.MethodDelete, "/devices/unregister", strings.NewReader("bad json"))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleUnregisterDeviceToken(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected 400, got %d", w.Code)
	}
}

func TestCB52_HandleUnregisterDeviceToken_Success(t *testing.T) {
	oldDB := db
	testDB := setupTestDB_CB52(t)
	db = testDB
	defer func() {
		db = oldDB
		testDB.Close()
	}()

	// Insert a token first
	_, err := testDB.Exec("INSERT INTO device_tokens (user_id, device_token, platform, created_at) VALUES (?, ?, ?, ?)",
		"user-52n", "token-52n", "apns", time.Now())
	if err != nil {
		t.Fatalf("Failed to insert token: %v", err)
	}

	token := generateTestJWT_CB52(t, "user-52n")
	body := `{"device_token":"token-52n"}`
	req := httptest.NewRequest(http.MethodDelete, "/devices/unregister", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleUnregisterDeviceToken(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w.Code)
	}

	// Verify token removed
	var count int
	testDB.QueryRow("SELECT COUNT(*) FROM device_tokens WHERE user_id = ? AND device_token = ?", "user-52n", "token-52n").Scan(&count)
	if count != 0 {
		t.Errorf("Expected 0 tokens, got %d", count)
	}
}

// =========================================================================
// handleGetVAPIDKey: success path
// =========================================================================

func TestCB52_HandleGetVAPIDKey_Success(t *testing.T) {
	oldVapid := vapidPublicKey
	vapidPublicKey = "test-vapid-key-52"
	defer func() { vapidPublicKey = oldVapid }()

	token := generateTestJWT_CB52(t, "user-52vapid")
	req := httptest.NewRequest(http.MethodGet, "/push/vapid-key", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleGetVAPIDKey(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w.Code)
	}

	var result map[string]string
	json.NewDecoder(w.Body).Decode(&result)
	if result["public_key"] != "test-vapid-key-52" {
		t.Errorf("Expected test-vapid-key-52, got %s", result["public_key"])
	}
}

// =========================================================================
// handleGetEncryptedMessages: DB error and method not allowed
// =========================================================================

func TestCB52_HandleGetEncryptedMessages_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/messages/encrypted", nil)
	w := httptest.NewRecorder()
	handleGetEncryptedMessages(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected 405, got %d", w.Code)
	}
}

func TestCB52_HandleGetEncryptedMessages_Unauthorized(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/messages/encrypted?conversation_id=conv-52x", nil)
	w := httptest.NewRecorder()
	handleGetEncryptedMessages(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected 401, got %d", w.Code)
	}
}

func TestCB52_HandleGetEncryptedMessages_ConversationNotFound(t *testing.T) {
	oldDB := db
	testDB := setupTestDB_CB52(t)
	db = testDB
	defer func() {
		db = oldDB
		testDB.Close()
	}()

	token := generateTestJWT_CB52(t, "user-52z")
	req := httptest.NewRequest(http.MethodGet, "/messages/encrypted?conversation_id=nonexistent", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleGetEncryptedMessages(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("Expected 404, got %d", w.Code)
	}
}

func TestCB52_HandleGetEncryptedMessages_NotParticipant(t *testing.T) {
	oldDB := db
	testDB := setupTestDB_CB52(t)
	db = testDB
	defer func() {
		db = oldDB
		testDB.Close()
	}()

	_, err := testDB.Exec("INSERT INTO conversations (id, user_id, agent_id, created_at) VALUES (?, ?, ?, ?)",
		"conv-52np", "user-52-owner", "agent-52np", time.Now())
	if err != nil {
		t.Fatalf("Failed to insert conversation: %v", err)
	}

	token := generateTestJWT_CB52(t, "user-52-wrong")
	req := httptest.NewRequest(http.MethodGet, "/messages/encrypted?conversation_id=conv-52np", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleGetEncryptedMessages(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("Expected 404, got %d", w.Code)
	}
}

func TestCB52_HandleGetEncryptedMessages_DBError(t *testing.T) {
	oldDB := db
	testDB := setupTestDB_CB52(t)
	db = testDB
	defer func() {
		db = oldDB
	}()

	_, err := testDB.Exec("INSERT INTO conversations (id, user_id, agent_id, created_at) VALUES (?, ?, ?, ?)",
		"conv-52dbe", "user-52dbe", "agent-52dbe", time.Now())
	if err != nil {
		t.Fatalf("Failed to insert conversation: %v", err)
	}

	token := generateTestJWT_CB52(t, "user-52dbe")
	req := httptest.NewRequest(http.MethodGet, "/messages/encrypted?conversation_id=conv-52dbe", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	testDB.Close()

	handleGetEncryptedMessages(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("Expected 404, got %d", w.Code)
	}
}

// =========================================================================
// handleUploadPublicKey: method not allowed and missing fields
// =========================================================================

func TestCB52_HandleUploadPublicKey_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/keys/upload", nil)
	w := httptest.NewRecorder()
	handleUploadPublicKey(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected 405, got %d", w.Code)
	}
}

func TestCB52_HandleUploadPublicKey_Unauthorized(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/keys/upload", strings.NewReader("{}"))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handleUploadPublicKey(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected 401, got %d", w.Code)
	}
}

func TestCB52_HandleUploadPublicKey_InvalidJSON(t *testing.T) {
	token := generateTestJWT_CB52(t, "user-52p")
	req := httptest.NewRequest(http.MethodPost, "/keys/upload", strings.NewReader("bad json"))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleUploadPublicKey(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected 400, got %d", w.Code)
	}
}

func TestCB52_HandleUploadPublicKey_MissingKeyType(t *testing.T) {
	oldDB := db
	testDB := setupTestDB_CB52(t)
	db = testDB
	defer func() {
		db = oldDB
		testDB.Close()
	}()

	token := generateTestJWT_CB52(t, "user-52q")
	body := `{"key_type":"","public_key":"pub-key-52q"}`
	req := httptest.NewRequest(http.MethodPost, "/keys/upload", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleUploadPublicKey(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected 400, got %d", w.Code)
	}
}

func TestCB52_HandleUploadPublicKey_Success(t *testing.T) {
	oldDB := db
	testDB := setupTestDB_CB52(t)
	db = testDB
	defer func() {
		db = oldDB
		testDB.Close()
	}()

	token := generateTestJWT_CB52(t, "user-52r")
	body := `{"key_type":"identity","public_key":"identity-pub-52r","signature":"sig-52r"}`
	req := httptest.NewRequest(http.MethodPost, "/keys/upload", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleUploadPublicKey(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w.Code)
	}

	// Verify key stored
	var count int
	testDB.QueryRow("SELECT COUNT(*) FROM key_bundles WHERE owner_id = ? AND key_type = 'identity'", "user-52r").Scan(&count)
	if count != 1 {
		t.Errorf("Expected 1 key, got %d", count)
	}
}

// =========================================================================
// Additional handleGetEncryptedMessages: with messages
// =========================================================================

func TestCB52_HandleGetEncryptedMessages_WithMessages(t *testing.T) {
	oldDB := db
	testDB := setupTestDB_CB52(t)
	db = testDB
	defer func() {
		db = oldDB
		testDB.Close()
	}()

	// Create conversation
	_, err := testDB.Exec("INSERT INTO conversations (id, user_id, agent_id, created_at) VALUES (?, ?, ?, ?)",
		"conv-52msg", "user-52msg", "agent-52msg", time.Now())
	if err != nil {
		t.Fatalf("Failed to insert conversation: %v", err)
	}

	// Insert encrypted messages
	for i := 0; i < 3; i++ {
		_, err := testDB.Exec(`INSERT INTO encrypted_messages (id, conversation_id, sender_id, sender_type, ciphertext, iv, recipient_key_id, algorithm, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			"emsg-52msg-"+string(rune('a'+i)), "conv-52msg", "user-52msg", "user", "cipher-"+string(rune('a'+i)), "iv-"+string(rune('a'+i)), "rk-"+string(rune('a'+i)), "aes-256-gcm", time.Now())
		if err != nil {
			t.Fatalf("Failed to insert encrypted message: %v", err)
		}
	}

	token := generateTestJWT_CB52(t, "user-52msg")
	req := httptest.NewRequest(http.MethodGet, "/messages/encrypted?conversation_id=conv-52msg&limit=10", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleGetEncryptedMessages(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w.Code)
	}

	var result []map[string]interface{}
	json.NewDecoder(w.Body).Decode(&result)
	if len(result) != 3 {
		t.Errorf("Expected 3 messages, got %d", len(result))
	}
}

// =========================================================================
// handleSetNotificationPrefs: success path
// =========================================================================

func TestCB52_HandleSetNotificationPrefs_Success(t *testing.T) {
	oldDB := db
	testDB := setupTestDB_CB52(t)
	db = testDB
	defer func() {
		db = oldDB
		testDB.Close()
	}()

	// Create conversation
	_, err := testDB.Exec("INSERT INTO conversations (id, user_id, agent_id, created_at) VALUES (?, ?, ?, ?)",
		"conv-52pref", "user-52pref", "agent-52pref", time.Now())
	if err != nil {
		t.Fatalf("Failed to insert conversation: %v", err)
	}

	form := strings.NewReader("conversation_id=conv-52pref&muted=true")
	req := httptest.NewRequest(http.MethodPost, "/notifications/prefs", form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	ctx := context.WithValue(req.Context(), contextKeyUserID, "user-52pref")
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	handleSetNotificationPrefs(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w.Code)
	}

	// Verify preference stored
	var muted bool
	testDB.QueryRow("SELECT muted FROM notification_preferences WHERE user_id = ? AND conversation_id = ?", "user-52pref", "conv-52pref").Scan(&muted)
	if !muted {
		t.Error("Expected muted=true")
	}
}

func TestCB52_HandleSetNotificationPrefs_NotOwner(t *testing.T) {
	oldDB := db
	testDB := setupTestDB_CB52(t)
	db = testDB
	defer func() {
		db = oldDB
		testDB.Close()
	}()

	// Create conversation owned by different user
	_, err := testDB.Exec("INSERT INTO conversations (id, user_id, agent_id, created_at) VALUES (?, ?, ?, ?)",
		"conv-52forbid", "user-52-owner", "agent-52forbid", time.Now())
	if err != nil {
		t.Fatalf("Failed to insert conversation: %v", err)
	}

	form := strings.NewReader("conversation_id=conv-52forbid&muted=true")
	req := httptest.NewRequest(http.MethodPost, "/notifications/prefs", form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	ctx := context.WithValue(req.Context(), contextKeyUserID, "user-52-wrong")
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	handleSetNotificationPrefs(w, req)
	if w.Code != http.StatusForbidden {
		t.Errorf("Expected 403, got %d", w.Code)
	}
}

func TestCB52_HandleSetNotificationPrefs_ConversationNotFound(t *testing.T) {
	oldDB := db
	testDB := setupTestDB_CB52(t)
	db = testDB
	defer func() {
		db = oldDB
		testDB.Close()
	}()

	form := strings.NewReader("conversation_id=nonexistent&muted=false")
	req := httptest.NewRequest(http.MethodPost, "/notifications/prefs", form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	ctx := context.WithValue(req.Context(), contextKeyUserID, "user-52nf")
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	handleSetNotificationPrefs(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("Expected 404, got %d", w.Code)
	}
}

// =========================================================================
// handleGetNotificationPrefs: success path
// =========================================================================

func TestCB52_HandleGetNotificationPrefs_Success(t *testing.T) {
	oldDB := db
	testDB := setupTestDB_CB52(t)
	db = testDB
	defer func() {
		db = oldDB
		testDB.Close()
	}()

	// Insert a preference
	_, err := testDB.Exec("INSERT INTO notification_preferences (user_id, conversation_id, muted) VALUES (?, ?, ?)",
		"user-52gp", "conv-52gp", true)
	if err != nil {
		t.Fatalf("Failed to insert preference: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/notifications/prefs", nil)
	ctx := context.WithValue(req.Context(), contextKeyUserID, "user-52gp")
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	handleGetNotificationPrefs(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w.Code)
	}

	var prefs []NotificationPreferences
	json.NewDecoder(w.Body).Decode(&prefs)
	if len(prefs) != 1 {
		t.Errorf("Expected 1 pref, got %d", len(prefs))
	}
	if !prefs[0].Muted {
		t.Error("Expected muted=true")
	}
}

func TestCB52_HandleGetNotificationPrefs_Empty(t *testing.T) {
	oldDB := db
	testDB := setupTestDB_CB52(t)
	db = testDB
	defer func() {
		db = oldDB
		testDB.Close()
	}()

	req := httptest.NewRequest(http.MethodGet, "/notifications/prefs", nil)
	ctx := context.WithValue(req.Context(), contextKeyUserID, "user-52no-prefs")
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	handleGetNotificationPrefs(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w.Code)
	}

	var prefs []NotificationPreferences
	json.NewDecoder(w.Body).Decode(&prefs)
	if len(prefs) != 0 {
		t.Errorf("Expected 0 prefs, got %d", len(prefs))
	}
}

// =========================================================================
// handleDeleteNotificationPrefs: success path
// =========================================================================

func TestCB52_HandleDeleteNotificationPrefs_Success(t *testing.T) {
	oldDB := db
	testDB := setupTestDB_CB52(t)
	db = testDB
	defer func() {
		db = oldDB
		testDB.Close()
	}()

	// Insert a preference
	_, err := testDB.Exec("INSERT INTO notification_preferences (user_id, conversation_id, muted) VALUES (?, ?, ?)",
		"user-52del", "conv-52del", true)
	if err != nil {
		t.Fatalf("Failed to insert preference: %v", err)
	}

	form := strings.NewReader("conversation_id=conv-52del")
	req := httptest.NewRequest(http.MethodPost, "/notifications/prefs/delete", form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	ctx := context.WithValue(req.Context(), contextKeyUserID, "user-52del")
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	handleDeleteNotificationPrefs(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w.Code)
	}

	// Verify deleted
	var count int
	testDB.QueryRow("SELECT COUNT(*) FROM notification_preferences WHERE user_id = ? AND conversation_id = ?", "user-52del", "conv-52del").Scan(&count)
	if count != 0 {
		t.Errorf("Expected 0 prefs after delete, got %d", count)
	}
}

func TestCB52_HandleDeleteNotificationPrefs_MissingConvID(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/notifications/prefs/delete", strings.NewReader(""))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	ctx := context.WithValue(req.Context(), contextKeyUserID, "user-52del-noid")
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	handleDeleteNotificationPrefs(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected 400, got %d", w.Code)
	}
}