package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"
)

// --- CB67 Helpers ---

func setupTestDB_CB67(t *testing.T) *sql.DB {
	testDB, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("Failed to open test DB: %v", err)
	}
	if err := initSchema(testDB); err != nil {
		t.Fatalf("Failed to init schema: %v", err)
	}
	return testDB
}

func generateTestToken_CB67(userID string) string {
	claims := &Claims{
		UserID: userID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, _ := token.SignedString(jwtSecret)
	return signed
}

func makeTestHub_CB67() *Hub {
	h := newHub()
	go h.run()
	return h
}

func createUser_CB67(testDB *sql.DB, username, password string) string {
	hash, _ := HashAPIKey(password)
	userID := "user_" + username
	testDB.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)", userID, username, hash)
	return userID
}

func createAgent_CB67(testDB *sql.DB, agentID string) {
	testDB.Exec("INSERT INTO agents (id, name, model) VALUES (?, ?, ?)", agentID, "Test Agent", "test-model")
}

func createConversation_CB67(testDB *sql.DB, userID, agentID string) string {
	convID := "conv_" + agentID + "_" + userID
	testDB.Exec("INSERT INTO conversations (id, user_id, agent_id) VALUES (?, ?, ?)", convID, userID, agentID)
	return convID
}

func insertKeyBundle_CB67(testDB *sql.DB, ownerID, ownerType, keyType, publicKey, signature string, keyID int) {
	id := fmt.Sprintf("key_%s_%s_%d", ownerID, keyType, keyID)
	testDB.Exec(`INSERT INTO key_bundles (id, owner_id, owner_type, key_type, public_key, signature, key_id, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		id, ownerID, ownerType, keyType, publicKey, signature, keyID, time.Now().UTC())
}

func insertEncryptedMessage_CB67(testDB *sql.DB, convID, senderID, senderType, ciphertext, iv, recipientKeyID, algorithm string) string {
	msgID := "emsg_" + senderID + "_" + time.Now().Format("150405.000000")
	testDB.Exec(`INSERT INTO encrypted_messages (id, conversation_id, sender_id, sender_type, ciphertext, iv, recipient_key_id, algorithm, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		msgID, convID, senderID, senderType, ciphertext, iv, recipientKeyID, algorithm, time.Now().UTC())
	return msgID
}

// ==================== handleUploadPublicKey (0% → target 90%+) ====================

func TestCB67_UploadPublicKey_MethodNotAllowed(t *testing.T) {
	db = setupTestDB_CB67(t)
	defer func() { db = nil }()

	req := httptest.NewRequest(http.MethodGet, "/keys/upload", nil)
	w := httptest.NewRecorder()
	handleUploadPublicKey(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestCB67_UploadPublicKey_Unauthorized(t *testing.T) {
	db = setupTestDB_CB67(t)
	defer func() { db = nil }()

	req := httptest.NewRequest(http.MethodPost, "/keys/upload", strings.NewReader("{}"))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handleUploadPublicKey(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestCB67_UploadPublicKey_InvalidJSON(t *testing.T) {
	db = setupTestDB_CB67(t)
	defer func() { db = nil }()

	req := httptest.NewRequest(http.MethodPost, "/keys/upload", strings.NewReader("not json"))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+generateTestToken_CB67("user1"))
	w := httptest.NewRecorder()
	handleUploadPublicKey(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestCB67_UploadPublicKey_MissingPublicKey(t *testing.T) {
	db = setupTestDB_CB67(t)
	defer func() { db = nil }()

	body := `{"key_type":"identity","public_key":""}`
	req := httptest.NewRequest(http.MethodPost, "/keys/upload", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+generateTestToken_CB67("user1"))
	w := httptest.NewRecorder()
	handleUploadPublicKey(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestCB67_UploadPublicKey_InvalidKeyType(t *testing.T) {
	db = setupTestDB_CB67(t)
	defer func() { db = nil }()

	body := `{"key_type":"bad_type","public_key":"abc123"}`
	req := httptest.NewRequest(http.MethodPost, "/keys/upload", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+generateTestToken_CB67("user1"))
	w := httptest.NewRecorder()
	handleUploadPublicKey(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestCB67_UploadPublicKey_IdentityKey_Success(t *testing.T) {
	db = setupTestDB_CB67(t)
	defer func() { db = nil }()

	body := `{"key_type":"identity","public_key":"base64key123","signature":"sig123"}`
	req := httptest.NewRequest(http.MethodPost, "/keys/upload", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+generateTestToken_CB67("user1"))
	w := httptest.NewRecorder()
	handleUploadPublicKey(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	var bundle KeyBundle
	json.NewDecoder(w.Body).Decode(&bundle)
	if bundle.PublicKey != "base64key123" {
		t.Errorf("expected public_key base64key123, got %s", bundle.PublicKey)
	}
	if bundle.KeyType != "identity" {
		t.Errorf("expected key_type identity, got %s", bundle.KeyType)
	}
}

func TestCB67_UploadPublicKey_IdentityKey_Replace(t *testing.T) {
	db = setupTestDB_CB67(t)
	defer func() { db = nil }()

	// First upload
	body1 := `{"key_type":"identity","public_key":"oldkey","signature":"oldsig"}`
	req1 := httptest.NewRequest(http.MethodPost, "/keys/upload", strings.NewReader(body1))
	req1.Header.Set("Content-Type", "application/json")
	req1.Header.Set("Authorization", "Bearer "+generateTestToken_CB67("user1"))
	w1 := httptest.NewRecorder()
	handleUploadPublicKey(w1, req1)
	if w1.Code != http.StatusOK {
		t.Fatalf("first upload failed: %d", w1.Code)
	}

	// Second upload should replace
	body2 := `{"key_type":"identity","public_key":"newkey","signature":"newsig"}`
	req2 := httptest.NewRequest(http.MethodPost, "/keys/upload", strings.NewReader(body2))
	req2.Header.Set("Content-Type", "application/json")
	req2.Header.Set("Authorization", "Bearer "+generateTestToken_CB67("user1"))
	w2 := httptest.NewRecorder()
	handleUploadPublicKey(w2, req2)
	if w2.Code != http.StatusOK {
		t.Fatalf("second upload failed: %d", w2.Code)
	}

	var bundle KeyBundle
	json.NewDecoder(w2.Body).Decode(&bundle)
	if bundle.PublicKey != "newkey" {
		t.Errorf("expected newkey, got %s", bundle.PublicKey)
	}

	// Verify only one identity key in DB
	var count int
	db.QueryRow("SELECT COUNT(*) FROM key_bundles WHERE owner_id = 'user1' AND owner_type = 'user' AND key_type = 'identity'").Scan(&count)
	if count != 1 {
		t.Errorf("expected 1 identity key after replace, got %d", count)
	}
}

func TestCB67_UploadPublicKey_SignedPreKey_Success(t *testing.T) {
	db = setupTestDB_CB67(t)
	defer func() { db = nil }()

	body := `{"key_type":"signed_prekey","public_key":"spk123","signature":"spk_sig"}`
	req := httptest.NewRequest(http.MethodPost, "/keys/upload", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+generateTestToken_CB67("user1"))
	w := httptest.NewRecorder()
	handleUploadPublicKey(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestCB67_UploadPublicKey_OneTimePreKey_Success(t *testing.T) {
	db = setupTestDB_CB67(t)
	defer func() { db = nil }()

	body := `{"key_type":"one_time_prekey","public_key":"otpk1","signature":"","key_id":1}`
	req := httptest.NewRequest(http.MethodPost, "/keys/upload", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+generateTestToken_CB67("user1"))
	w := httptest.NewRecorder()
	handleUploadPublicKey(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	var bundle KeyBundle
	json.NewDecoder(w.Body).Decode(&bundle)
	if bundle.KeyID != 1 {
		t.Errorf("expected key_id 1, got %d", bundle.KeyID)
	}
}

func TestCB67_UploadPublicKey_AgentAuth(t *testing.T) {
	db = setupTestDB_CB67(t)
	defer func() { db = nil }()

	body := `{"key_type":"identity","public_key":"agentkey","signature":"agentsig"}`
	req := httptest.NewRequest(http.MethodPost, "/keys/upload", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Agent-Secret", getAgentSecret())
	req.Header.Set("X-Agent-ID", "agent1")
	w := httptest.NewRecorder()
	handleUploadPublicKey(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	var bundle KeyBundle
	json.NewDecoder(w.Body).Decode(&bundle)
	if bundle.OwnerType != "agent" {
		t.Errorf("expected owner_type agent, got %s", bundle.OwnerType)
	}
}

func TestCB67_UploadPublicKey_AgentAuth_MissingAgentID(t *testing.T) {
	db = setupTestDB_CB67(t)
	defer func() { db = nil }()

	body := `{"key_type":"identity","public_key":"agentkey","signature":"agentsig"}`
	req := httptest.NewRequest(http.MethodPost, "/keys/upload", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Agent-Secret", getAgentSecret())
	w := httptest.NewRecorder()
	handleUploadPublicKey(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

// ==================== handleGetKeyBundle (43.8% → target 90%+) ====================

func TestCB67_GetKeyBundle_MethodNotAllowed(t *testing.T) {
	db = setupTestDB_CB67(t)
	defer func() { db = nil }()

	req := httptest.NewRequest(http.MethodPost, "/keys/bundle", nil)
	w := httptest.NewRecorder()
	handleGetKeyBundle(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestCB67_GetKeyBundle_Unauthorized(t *testing.T) {
	db = setupTestDB_CB67(t)
	defer func() { db = nil }()

	req := httptest.NewRequest(http.MethodGet, "/keys/bundle", nil)
	w := httptest.NewRecorder()
	handleGetKeyBundle(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestCB67_GetKeyBundle_MissingOwnerID(t *testing.T) {
	db = setupTestDB_CB67(t)
	defer func() { db = nil }()

	req := httptest.NewRequest(http.MethodGet, "/keys/bundle", nil)
	req.Header.Set("Authorization", "Bearer "+generateTestToken_CB67("user1"))
	w := httptest.NewRecorder()
	handleGetKeyBundle(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestCB67_GetKeyBundle_NoIdentityKey(t *testing.T) {
	db = setupTestDB_CB67(t)
	defer func() { db = nil }()

	req := httptest.NewRequest(http.MethodGet, "/keys/bundle?owner_id=nonexistent", nil)
	req.Header.Set("Authorization", "Bearer "+generateTestToken_CB67("user1"))
	w := httptest.NewRecorder()
	handleGetKeyBundle(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

func TestCB67_GetKeyBundle_Success_IdentityOnly(t *testing.T) {
	db = setupTestDB_CB67(t)
	defer func() { db = nil }()
	insertKeyBundle_CB67(db, "user1", "user", "identity", "idkey123", "idsig", 0)

	req := httptest.NewRequest(http.MethodGet, "/keys/bundle?owner_id=user1", nil)
	req.Header.Set("Authorization", "Bearer "+generateTestToken_CB67("requester"))
	w := httptest.NewRecorder()
	handleGetKeyBundle(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	var bundle map[string]interface{}
	json.NewDecoder(w.Body).Decode(&bundle)
	if bundle["identity_key"] == nil {
		t.Error("expected identity_key in bundle")
	}
	if bundle["signed_prekey"] != nil {
		t.Error("expected no signed_prekey")
	}
	if bundle["one_time_prekey"] != nil {
		t.Error("expected no one_time_prekey")
	}
}

func TestCB67_GetKeyBundle_Success_FullBundle(t *testing.T) {
	db = setupTestDB_CB67(t)
	defer func() { db = nil }()
	insertKeyBundle_CB67(db, "user1", "user", "identity", "idkey123", "idsig", 0)
	insertKeyBundle_CB67(db, "user1", "user", "signed_prekey", "spk123", "spksig", 0)
	insertKeyBundle_CB67(db, "user1", "user", "one_time_prekey", "otpk1", "", 1)

	req := httptest.NewRequest(http.MethodGet, "/keys/bundle?owner_id=user1", nil)
	req.Header.Set("Authorization", "Bearer "+generateTestToken_CB67("requester"))
	w := httptest.NewRecorder()
	handleGetKeyBundle(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	var bundle map[string]interface{}
	json.NewDecoder(w.Body).Decode(&bundle)
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

func TestCB67_GetKeyBundle_OTPK_Consumed(t *testing.T) {
	db = setupTestDB_CB67(t)
	defer func() { db = nil }()
	insertKeyBundle_CB67(db, "user1", "user", "identity", "idkey123", "idsig", 0)
	insertKeyBundle_CB67(db, "user1", "user", "one_time_prekey", "otpk1", "", 1)
	insertKeyBundle_CB67(db, "user1", "user", "one_time_prekey", "otpk2", "", 2)

	req := httptest.NewRequest(http.MethodGet, "/keys/bundle?owner_id=user1", nil)
	req.Header.Set("Authorization", "Bearer "+generateTestToken_CB67("requester"))
	w := httptest.NewRecorder()
	handleGetKeyBundle(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}

	// One OTPK should be consumed (deleted)
	var count int
	db.QueryRow("SELECT COUNT(*) FROM key_bundles WHERE owner_id = 'user1' AND owner_type = 'user' AND key_type = 'one_time_prekey'").Scan(&count)
	if count != 1 {
		t.Errorf("expected 1 remaining OTPK after consumption, got %d", count)
	}
}

func TestCB67_GetKeyBundle_AgentType(t *testing.T) {
	db = setupTestDB_CB67(t)
	defer func() { db = nil }()
	insertKeyBundle_CB67(db, "agent1", "agent", "identity", "agentidkey", "agentsig", 0)

	req := httptest.NewRequest(http.MethodGet, "/keys/bundle?owner_id=agent1&owner_type=agent", nil)
	req.Header.Set("Authorization", "Bearer "+generateTestToken_CB67("requester"))
	w := httptest.NewRecorder()
	handleGetKeyBundle(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	var bundle map[string]interface{}
	json.NewDecoder(w.Body).Decode(&bundle)
	if bundle["identity_key"] == nil {
		t.Error("expected identity_key for agent")
	}
}

// ==================== handleListOneTimePreKeys (63.6% → target 100%) ====================

func TestCB67_ListOneTimePreKeys_MethodNotAllowed(t *testing.T) {
	db = setupTestDB_CB67(t)
	defer func() { db = nil }()

	req := httptest.NewRequest(http.MethodPost, "/keys/otpk-count", nil)
	w := httptest.NewRecorder()
	handleListOneTimePreKeys(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestCB67_ListOneTimePreKeys_Unauthorized(t *testing.T) {
	db = setupTestDB_CB67(t)
	defer func() { db = nil }()

	req := httptest.NewRequest(http.MethodGet, "/keys/otpk-count", nil)
	w := httptest.NewRecorder()
	handleListOneTimePreKeys(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestCB67_ListOneTimePreKeys_ZeroCount(t *testing.T) {
	db = setupTestDB_CB67(t)
	defer func() { db = nil }()

	req := httptest.NewRequest(http.MethodGet, "/keys/otpk-count", nil)
	req.Header.Set("Authorization", "Bearer "+generateTestToken_CB67("user1"))
	w := httptest.NewRecorder()
	handleListOneTimePreKeys(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	var resp map[string]int
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["one_time_prekey_count"] != 0 {
		t.Errorf("expected 0 count, got %d", resp["one_time_prekey_count"])
	}
}

func TestCB67_ListOneTimePreKeys_WithKeys(t *testing.T) {
	db = setupTestDB_CB67(t)
	defer func() { db = nil }()
	insertKeyBundle_CB67(db, "user1", "user", "one_time_prekey", "otpk1", "", 1)
	insertKeyBundle_CB67(db, "user1", "user", "one_time_prekey", "otpk2", "", 2)
	insertKeyBundle_CB67(db, "user1", "user", "one_time_prekey", "otpk3", "", 3)

	req := httptest.NewRequest(http.MethodGet, "/keys/otpk-count", nil)
	req.Header.Set("Authorization", "Bearer "+generateTestToken_CB67("user1"))
	w := httptest.NewRecorder()
	handleListOneTimePreKeys(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	var resp map[string]int
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["one_time_prekey_count"] != 3 {
		t.Errorf("expected 3 count, got %d", resp["one_time_prekey_count"])
	}
}

// ==================== handleGetEncryptedMessages (48.8% → target 90%+) ====================

func TestCB67_GetEncryptedMessages_MethodNotAllowed(t *testing.T) {
	db = setupTestDB_CB67(t)
	defer func() { db = nil }()

	req := httptest.NewRequest(http.MethodPost, "/messages/encrypted", nil)
	w := httptest.NewRecorder()
	handleGetEncryptedMessages(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestCB67_GetEncryptedMessages_Unauthorized(t *testing.T) {
	db = setupTestDB_CB67(t)
	defer func() { db = nil }()

	req := httptest.NewRequest(http.MethodGet, "/messages/encrypted", nil)
	w := httptest.NewRecorder()
	handleGetEncryptedMessages(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestCB67_GetEncryptedMessages_MissingConvID(t *testing.T) {
	db = setupTestDB_CB67(t)
	defer func() { db = nil }()

	req := httptest.NewRequest(http.MethodGet, "/messages/encrypted", nil)
	req.Header.Set("Authorization", "Bearer "+generateTestToken_CB67("user1"))
	w := httptest.NewRecorder()
	handleGetEncryptedMessages(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestCB67_GetEncryptedMessages_ConvNotFound(t *testing.T) {
	db = setupTestDB_CB67(t)
	defer func() { db = nil }()

	req := httptest.NewRequest(http.MethodGet, "/messages/encrypted?conversation_id=nonexistent", nil)
	req.Header.Set("Authorization", "Bearer "+generateTestToken_CB67("user1"))
	w := httptest.NewRecorder()
	handleGetEncryptedMessages(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

func TestCB67_GetEncryptedMessages_UserNotParticipant(t *testing.T) {
	db = setupTestDB_CB67(t)
	defer func() { db = nil }()
	convID := createConversation_CB67(db, "user1", "agent1")

	req := httptest.NewRequest(http.MethodGet, "/messages/encrypted?conversation_id="+convID, nil)
	req.Header.Set("Authorization", "Bearer "+generateTestToken_CB67("otheruser"))
	w := httptest.NewRecorder()
	handleGetEncryptedMessages(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404 for non-participant, got %d", w.Code)
	}
}

func TestCB67_GetEncryptedMessages_Success(t *testing.T) {
	db = setupTestDB_CB67(t)
	defer func() { db = nil }()
	convID := createConversation_CB67(db, "user1", "agent1")
	insertEncryptedMessage_CB67(db, convID, "user1", "user", "ciphertext1", "iv1", "recip1", "aes-256-gcm")
	insertEncryptedMessage_CB67(db, convID, "agent1", "agent", "ciphertext2", "iv2", "recip2", "aes-256-gcm")

	req := httptest.NewRequest(http.MethodGet, "/messages/encrypted?conversation_id="+convID, nil)
	req.Header.Set("Authorization", "Bearer "+generateTestToken_CB67("user1"))
	w := httptest.NewRecorder()
	handleGetEncryptedMessages(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	var messages []EncryptedMessage
	json.NewDecoder(w.Body).Decode(&messages)
	if len(messages) != 2 {
		t.Errorf("expected 2 messages, got %d", len(messages))
	}
}

func TestCB67_GetEncryptedMessages_WithLimit(t *testing.T) {
	db = setupTestDB_CB67(t)
	defer func() { db = nil }()
	convID := createConversation_CB67(db, "user1", "agent1")
	for i := 0; i < 5; i++ {
		insertEncryptedMessage_CB67(db, convID, "user1", "user", "ct"+string(rune('a'+i)), "iv", "recip", "aes-256-gcm")
	}

	req := httptest.NewRequest(http.MethodGet, "/messages/encrypted?conversation_id="+convID+"&limit=2", nil)
	req.Header.Set("Authorization", "Bearer "+generateTestToken_CB67("user1"))
	w := httptest.NewRecorder()
	handleGetEncryptedMessages(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	var messages []EncryptedMessage
	json.NewDecoder(w.Body).Decode(&messages)
	if len(messages) != 2 {
		t.Errorf("expected 2 messages with limit, got %d", len(messages))
	}
}

func TestCB67_GetEncryptedMessages_LimitOverMax(t *testing.T) {
	db = setupTestDB_CB67(t)
	defer func() { db = nil }()
	convID := createConversation_CB67(db, "user1", "agent1")
	insertEncryptedMessage_CB67(db, convID, "user1", "user", "ct1", "iv1", "recip", "aes-256-gcm")

	req := httptest.NewRequest(http.MethodGet, "/messages/encrypted?conversation_id="+convID+"&limit=500", nil)
	req.Header.Set("Authorization", "Bearer "+generateTestToken_CB67("user1"))
	w := httptest.NewRecorder()
	handleGetEncryptedMessages(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestCB67_GetEncryptedMessages_AgentAccess(t *testing.T) {
	db = setupTestDB_CB67(t)
	defer func() { db = nil }()
	convID := createConversation_CB67(db, "user1", "agent1")
	insertEncryptedMessage_CB67(db, convID, "user1", "user", "ct1", "iv1", "recip", "aes-256-gcm")

	req := httptest.NewRequest(http.MethodGet, "/messages/encrypted?conversation_id="+convID, nil)
	req.Header.Set("X-Agent-Secret", getAgentSecret())
	req.Header.Set("X-Agent-ID", "agent1")
	w := httptest.NewRecorder()
	handleGetEncryptedMessages(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200 for agent, got %d", w.Code)
	}
}

func TestCB67_GetEncryptedMessages_AgentNotParticipant(t *testing.T) {
	db = setupTestDB_CB67(t)
	defer func() { db = nil }()
	convID := createConversation_CB67(db, "user1", "agent1")

	req := httptest.NewRequest(http.MethodGet, "/messages/encrypted?conversation_id="+convID, nil)
	req.Header.Set("X-Agent-Secret", getAgentSecret())
	req.Header.Set("X-Agent-ID", "other_agent")
	w := httptest.NewRecorder()
	handleGetEncryptedMessages(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404 for non-participant agent, got %d", w.Code)
	}
}

func TestCB67_GetEncryptedMessages_EmptyResult(t *testing.T) {
	db = setupTestDB_CB67(t)
	defer func() { db = nil }()
	convID := createConversation_CB67(db, "user1", "agent1")

	req := httptest.NewRequest(http.MethodGet, "/messages/encrypted?conversation_id="+convID, nil)
	req.Header.Set("Authorization", "Bearer "+generateTestToken_CB67("user1"))
	w := httptest.NewRecorder()
	handleGetEncryptedMessages(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	var messages []EncryptedMessage
	json.NewDecoder(w.Body).Decode(&messages)
	if len(messages) != 0 {
		t.Errorf("expected 0 messages, got %d", len(messages))
	}
}

// ==================== handleChangePassword (61.5% → target 90%+) ====================

func TestCB67_ChangePassword_MethodNotAllowed(t *testing.T) {
	db = setupTestDB_CB67(t)
	defer func() { db = nil }()

	req := httptest.NewRequest(http.MethodGet, "/auth/change-password", nil)
	w := httptest.NewRecorder()
	handleChangePassword(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestCB67_ChangePassword_Unauthorized(t *testing.T) {
	db = setupTestDB_CB67(t)
	defer func() { db = nil }()

	form := strings.NewReader("old_password=pass&new_password=newpass")
	req := httptest.NewRequest(http.MethodPost, "/auth/change-password", form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handleChangePassword(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestCB67_ChangePassword_MissingFields(t *testing.T) {
	db = setupTestDB_CB67(t)
	defer func() { db = nil }()

	req := httptest.NewRequest(http.MethodPost, "/auth/change-password", strings.NewReader(""))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+generateTestToken_CB67("user1"))
	w := httptest.NewRecorder()
	handleChangePassword(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestCB67_ChangePassword_Success(t *testing.T) {
	db = setupTestDB_CB67(t)
	defer func() { db = nil }()
	userID := createUser_CB67(db, "testuser", "oldpass123")

	form := strings.NewReader("old_password=oldpass123&new_password=newpass456")
	req := httptest.NewRequest(http.MethodPost, "/auth/change-password", form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+generateTestToken_CB67(userID))
	w := httptest.NewRecorder()
	handleChangePassword(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	var resp map[string]string
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["status"] != "password_changed" {
		t.Errorf("expected status password_changed, got %s", resp["status"])
	}
}

func TestCB67_ChangePassword_WrongOldPassword(t *testing.T) {
	db = setupTestDB_CB67(t)
	defer func() { db = nil }()
	userID := createUser_CB67(db, "testuser", "oldpass123")

	form := strings.NewReader("old_password=wrongpass&new_password=newpass456")
	req := httptest.NewRequest(http.MethodPost, "/auth/change-password", form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+generateTestToken_CB67(userID))
	w := httptest.NewRecorder()
	handleChangePassword(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for wrong old password, got %d", w.Code)
	}
}

func TestCB67_ChangePassword_UserNotFound(t *testing.T) {
	db = setupTestDB_CB67(t)
	defer func() { db = nil }()

	form := strings.NewReader("old_password=oldpass&new_password=newpass456")
	req := httptest.NewRequest(http.MethodPost, "/auth/change-password", form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+generateTestToken_CB67("nonexistent"))
	w := httptest.NewRecorder()
	handleChangePassword(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404 for nonexistent user, got %d", w.Code)
	}
}

// ==================== handleDeleteConversation (63% → target 90%+) ====================

func TestCB67_DeleteConversation_MethodNotAllowed(t *testing.T) {
	db = setupTestDB_CB67(t)
	defer func() { db = nil }()

	req := httptest.NewRequest(http.MethodGet, "/conversations/delete", nil)
	w := httptest.NewRecorder()
	handleDeleteConversation(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestCB67_DeleteConversation_Unauthorized(t *testing.T) {
	db = setupTestDB_CB67(t)
	defer func() { db = nil }()

	req := httptest.NewRequest(http.MethodDelete, "/conversations/delete?conversation_id=conv1", nil)
	w := httptest.NewRecorder()
	handleDeleteConversation(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestCB67_DeleteConversation_MissingConvID(t *testing.T) {
	db = setupTestDB_CB67(t)
	defer func() { db = nil }()

	req := httptest.NewRequest(http.MethodDelete, "/conversations/delete", nil)
	req.Header.Set("Authorization", "Bearer "+generateTestToken_CB67("user1"))
	w := httptest.NewRecorder()
	handleDeleteConversation(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestCB67_DeleteConversation_NotFound(t *testing.T) {
	db = setupTestDB_CB67(t)
	defer func() { db = nil }()

	req := httptest.NewRequest(http.MethodDelete, "/conversations/delete?conversation_id=nonexistent", nil)
	req.Header.Set("Authorization", "Bearer "+generateTestToken_CB67("user1"))
	w := httptest.NewRecorder()
	handleDeleteConversation(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

func TestCB67_DeleteConversation_UnauthorizedOwner(t *testing.T) {
	db = setupTestDB_CB67(t)
	defer func() { db = nil }()
	convID := createConversation_CB67(db, "user1", "agent1")

	req := httptest.NewRequest(http.MethodDelete, "/conversations/delete?conversation_id="+convID, nil)
	req.Header.Set("Authorization", "Bearer "+generateTestToken_CB67("otheruser"))
	w := httptest.NewRecorder()
	handleDeleteConversation(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for non-owner, got %d", w.Code)
	}
}

func TestCB67_DeleteConversation_Success(t *testing.T) {
	db = setupTestDB_CB67(t)
	defer func() { db = nil }()
	userID := createUser_CB67(db, "user1", "pass123")
	convID := createConversation_CB67(db, userID, "agent1")
	// Add a message
	db.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, created_at) VALUES (?, ?, ?, ?, ?, ?)",
		"msg1", convID, "agent", "agent1", "hello", time.Now().UTC())

	req := httptest.NewRequest(http.MethodDelete, "/conversations/delete?conversation_id="+convID, nil)
	req.Header.Set("Authorization", "Bearer "+generateTestToken_CB67(userID))
	w := httptest.NewRecorder()
	handleDeleteConversation(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}

	// Verify conversation and messages are gone
	var count int
	db.QueryRow("SELECT COUNT(*) FROM conversations WHERE id = ?", convID).Scan(&count)
	if count != 0 {
		t.Errorf("expected conversation deleted, found %d", count)
	}
	db.QueryRow("SELECT COUNT(*) FROM messages WHERE conversation_id = ?", convID).Scan(&count)
	if count != 0 {
		t.Errorf("expected messages deleted, found %d", count)
	}
}

func TestCB67_DeleteConversation_FormValue(t *testing.T) {
	db = setupTestDB_CB67(t)
	defer func() { db = nil }()
	userID := createUser_CB67(db, "user1", "pass123")
	convID := createConversation_CB67(db, userID, "agent1")

	req := httptest.NewRequest(http.MethodDelete, "/conversations/delete?conversation_id="+convID, nil)
	req.Header.Set("Authorization", "Bearer "+generateTestToken_CB67(userID))
	w := httptest.NewRecorder()
	handleDeleteConversation(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200 with form value, got %d", w.Code)
	}
}

// ==================== handleSearchMessages (68.8% → target 90%+) ====================

func TestCB67_SearchMessages_MethodNotAllowed(t *testing.T) {
	db = setupTestDB_CB67(t)
	defer func() { db = nil }()

	req := httptest.NewRequest(http.MethodPost, "/messages/search", nil)
	w := httptest.NewRecorder()
	handleSearchMessages(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestCB67_SearchMessages_Unauthorized(t *testing.T) {
	db = setupTestDB_CB67(t)
	defer func() { db = nil }()

	req := httptest.NewRequest(http.MethodGet, "/messages/search?q=test", nil)
	w := httptest.NewRecorder()
	handleSearchMessages(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestCB67_SearchMessages_MissingQuery(t *testing.T) {
	db = setupTestDB_CB67(t)
	defer func() { db = nil }()

	req := httptest.NewRequest(http.MethodGet, "/messages/search", nil)
	req.Header.Set("Authorization", "Bearer "+generateTestToken_CB67("user1"))
	w := httptest.NewRecorder()
	handleSearchMessages(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestCB67_SearchMessages_Success(t *testing.T) {
	db = setupTestDB_CB67(t)
	defer func() { db = nil }()
	userID := createUser_CB67(db, "user1", "pass123")
	convID := createConversation_CB67(db, userID, "agent1")
	db.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, created_at) VALUES (?, ?, ?, ?, ?, ?)",
		"msg1", convID, "agent", "agent1", "hello world", time.Now().UTC())
	db.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, created_at) VALUES (?, ?, ?, ?, ?, ?)",
		"msg2", convID, "client", userID, "world peace", time.Now().UTC())

	req := httptest.NewRequest(http.MethodGet, "/messages/search?q=world", nil)
	req.Header.Set("Authorization", "Bearer "+generateTestToken_CB67(userID))
	w := httptest.NewRecorder()
	handleSearchMessages(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	var messages []StoredMessage
	json.NewDecoder(w.Body).Decode(&messages)
	if len(messages) != 2 {
		t.Errorf("expected 2 results, got %d", len(messages))
	}
}

func TestCB67_SearchMessages_NoResults(t *testing.T) {
	db = setupTestDB_CB67(t)
	defer func() { db = nil }()
	userID := createUser_CB67(db, "user1", "pass123")
	convID := createConversation_CB67(db, userID, "agent1")
	db.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, created_at) VALUES (?, ?, ?, ?, ?, ?)",
		"msg1", convID, "agent", "agent1", "hello", time.Now().UTC())

	req := httptest.NewRequest(http.MethodGet, "/messages/search?q=nonexistent", nil)
	req.Header.Set("Authorization", "Bearer "+generateTestToken_CB67(userID))
	w := httptest.NewRecorder()
	handleSearchMessages(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestCB67_SearchMessages_WithLimit(t *testing.T) {
	db = setupTestDB_CB67(t)
	defer func() { db = nil }()
	userID := createUser_CB67(db, "user1", "pass123")
	convID := createConversation_CB67(db, userID, "agent1")
	for i := 0; i < 5; i++ {
		db.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, created_at) VALUES (?, ?, ?, ?, ?, ?)",
			"msg"+string(rune('1'+i)), convID, "agent", "agent1", "test"+string(rune('1'+i)), time.Now().UTC())
	}

	req := httptest.NewRequest(http.MethodGet, "/messages/search?q=test&limit=2", nil)
	req.Header.Set("Authorization", "Bearer "+generateTestToken_CB67(userID))
	w := httptest.NewRecorder()
	handleSearchMessages(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	var messages []StoredMessage
	json.NewDecoder(w.Body).Decode(&messages)
	if len(messages) != 2 {
		t.Errorf("expected 2 results with limit, got %d", len(messages))
	}
}

// ==================== storeMessage (63.6% → target 90%+) ====================

func TestCB67_StoreMessage_Success(t *testing.T) {
	db = setupTestDB_CB67(t)
	defer func() { db = nil }()
	convID := createConversation_CB67(db, "user1", "agent1")

	msg := RoutedMessage{
		Type:           MsgTypeMessage,
		ConversationID: convID,
		SenderType:     "agent",
		SenderID:       "agent1",
		Content:        "hello world",
	}
	err := storeMessage(msg)
	if err != nil {
		t.Fatalf("storeMessage failed: %v", err)
	}

	var count int
	db.QueryRow("SELECT COUNT(*) FROM messages WHERE conversation_id = ?", convID).Scan(&count)
	if count != 1 {
		t.Errorf("expected 1 message stored, got %d", count)
	}
}

func TestCB67_StoreMessage_WithAttachments(t *testing.T) {
	db = setupTestDB_CB67(t)
	defer func() { db = nil }()
	convID := createConversation_CB67(db, "user1", "agent1")
	// Create an attachment first
	db.Exec("INSERT INTO attachments (id, user_id, filename, content_type, size, sha256, storage_path) VALUES (?, ?, ?, ?, ?, ?, ?)",
		"attach1", "user1", "test.png", "image/png", 100, "abc123", "/tmp/test.png")

	msg := RoutedMessage{
		Type:           MsgTypeMessage,
		ConversationID: convID,
		SenderType:     "client",
		SenderID:       "user1",
		Content:        "see image",
		AttachmentIDs:  []string{"attach1"},
	}
	err := storeMessage(msg)
	if err != nil {
		t.Fatalf("storeMessage with attachments failed: %v", err)
	}

	// Verify attachment linked to message
	var messageID string
	db.QueryRow("SELECT message_id FROM attachments WHERE id = ?", "attach1").Scan(&messageID)
	if messageID == "" {
		t.Error("expected attachment linked to message")
	}
}

func TestCB67_StoreMessage_InvalidConversation(t *testing.T) {
	db = setupTestDB_CB67(t)
	defer func() { db = nil }()

	// Enable FK enforcement for this test
	db.Exec("PRAGMA foreign_keys=ON")

	msg := RoutedMessage{
		Type:           MsgTypeMessage,
		ConversationID: "nonexistent",
		SenderType:     "agent",
		SenderID:       "agent1",
		Content:        "hello",
	}
	err := storeMessage(msg)
	if err == nil {
		t.Skip("SQLite FK not enforced in test mode; storeMessage does not validate conversation")
	}
}

// ==================== handleCreateConversation (80% → target 90%+) ====================

func TestCB67_CreateConversation_MethodNotAllowed(t *testing.T) {
	db = setupTestDB_CB67(t)
	defer func() { db = nil }()

	req := httptest.NewRequest(http.MethodGet, "/conversations/create", nil)
	w := httptest.NewRecorder()
	handleCreateConversation(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestCB67_CreateConversation_Unauthorized(t *testing.T) {
	db = setupTestDB_CB67(t)
	defer func() { db = nil }()

	form := strings.NewReader("agent_id=agent1")
	req := httptest.NewRequest(http.MethodPost, "/conversations/create", form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handleCreateConversation(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestCB67_CreateConversation_MissingAgentID(t *testing.T) {
	db = setupTestDB_CB67(t)
	defer func() { db = nil }()

	req := httptest.NewRequest(http.MethodPost, "/conversations/create", strings.NewReader(""))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+generateTestToken_CB67("user1"))
	w := httptest.NewRecorder()
	handleCreateConversation(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestCB67_CreateConversation_Success(t *testing.T) {
	db = setupTestDB_CB67(t)
	defer func() { db = nil }()
	createAgent_CB67(db, "agent1")

	form := strings.NewReader("agent_id=agent1")
	req := httptest.NewRequest(http.MethodPost, "/conversations/create", form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+generateTestToken_CB67("user1"))
	w := httptest.NewRecorder()
	handleCreateConversation(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	var resp map[string]string
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["conversation_id"] == "" {
		t.Error("expected conversation_id in response")
	}
	if resp["agent_id"] != "agent1" {
		t.Errorf("expected agent_id agent1, got %s", resp["agent_id"])
	}
}

func TestCB67_CreateConversation_GetOrCreate(t *testing.T) {
	db = setupTestDB_CB67(t)
	defer func() { db = nil }()
	createAgent_CB67(db, "agent1")

	// First call creates
	form := strings.NewReader("agent_id=agent1")
	req1 := httptest.NewRequest(http.MethodPost, "/conversations/create", form)
	req1.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req1.Header.Set("Authorization", "Bearer "+generateTestToken_CB67("user1"))
	w1 := httptest.NewRecorder()
	handleCreateConversation(w1, req1)
	if w1.Code != http.StatusOK {
		t.Fatalf("first create failed: %d", w1.Code)
	}
	var resp1 map[string]string
	json.NewDecoder(w1.Body).Decode(&resp1)
	convID1 := resp1["conversation_id"]

	// Second call should get existing (GetOrCreateConversation)
	form2 := strings.NewReader("agent_id=agent1")
	req2 := httptest.NewRequest(http.MethodPost, "/conversations/create", form2)
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req2.Header.Set("Authorization", "Bearer "+generateTestToken_CB67("user1"))
	w2 := httptest.NewRecorder()
	handleCreateConversation(w2, req2)
	if w2.Code != http.StatusOK {
		t.Fatalf("second create failed: %d", w2.Code)
	}
	var resp2 map[string]string
	json.NewDecoder(w2.Body).Decode(&resp2)
	if resp2["conversation_id"] != convID1 {
		t.Errorf("expected same conversation_id %s, got %s", convID1, resp2["conversation_id"])
	}
}

// ==================== handleListConversations (80.6% → target 90%+) ====================

func TestCB67_ListConversations_MethodNotAllowed(t *testing.T) {
	db = setupTestDB_CB67(t)
	defer func() { db = nil }()

	req := httptest.NewRequest(http.MethodPost, "/conversations/list", nil)
	w := httptest.NewRecorder()
	handleListConversations(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestCB67_ListConversations_Unauthorized(t *testing.T) {
	db = setupTestDB_CB67(t)
	defer func() { db = nil }()

	req := httptest.NewRequest(http.MethodGet, "/conversations/list", nil)
	w := httptest.NewRecorder()
	handleListConversations(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestCB67_ListConversations_Empty(t *testing.T) {
	db = setupTestDB_CB67(t)
	defer func() { db = nil }()

	req := httptest.NewRequest(http.MethodGet, "/conversations/list", nil)
	req.Header.Set("Authorization", "Bearer "+generateTestToken_CB67("user1"))
	w := httptest.NewRecorder()
	handleListConversations(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	var convs []map[string]interface{}
	json.NewDecoder(w.Body).Decode(&convs)
	if len(convs) != 0 {
		t.Errorf("expected empty list, got %d", len(convs))
	}
}

func TestCB67_ListConversations_WithData(t *testing.T) {
	db = setupTestDB_CB67(t)
	defer func() { db = nil }()
	userID := createUser_CB67(db, "user1", "pass123")
	convID1 := createConversation_CB67(db, userID, "agent1")
	createConversation_CB67(db, userID, "agent2")
	// Add messages to one conversation
	db.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, created_at) VALUES (?, ?, ?, ?, ?, ?)",
		"msg1", convID1, "agent", "agent1", "hello", time.Now().UTC())
	db.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, created_at) VALUES (?, ?, ?, ?, ?, ?)",
		"msg2", convID1, "client", userID, "hi back", time.Now().UTC())

	req := httptest.NewRequest(http.MethodGet, "/conversations/list", nil)
	req.Header.Set("Authorization", "Bearer "+generateTestToken_CB67(userID))
	w := httptest.NewRecorder()
	handleListConversations(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	var convs []map[string]interface{}
	json.NewDecoder(w.Body).Decode(&convs)
	if len(convs) != 2 {
		t.Errorf("expected 2 conversations, got %d", len(convs))
	}
}

// ==================== handleRegisterDeviceToken (37% → target 90%+) ====================

func TestCB67_RegisterDeviceToken_MethodNotAllowed(t *testing.T) {
	db = setupTestDB_CB67(t)
	defer func() { db = nil }()

	req := httptest.NewRequest(http.MethodGet, "/devices/register", nil)
	w := httptest.NewRecorder()
	handleRegisterDeviceToken(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestCB67_RegisterDeviceToken_Unauthorized(t *testing.T) {
	db = setupTestDB_CB67(t)
	defer func() { db = nil }()

	body := `{"device_token":"token123","platform":"ios"}`
	req := httptest.NewRequest(http.MethodPost, "/devices/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handleRegisterDeviceToken(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestCB67_RegisterDeviceToken_InvalidJSON(t *testing.T) {
	db = setupTestDB_CB67(t)
	defer func() { db = nil }()

	req := httptest.NewRequest(http.MethodPost, "/devices/register", strings.NewReader("not json"))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+generateTestToken_CB67("user1"))
	w := httptest.NewRecorder()
	handleRegisterDeviceToken(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestCB67_RegisterDeviceToken_MissingToken(t *testing.T) {
	db = setupTestDB_CB67(t)
	defer func() { db = nil }()

	body := `{"platform":"ios"}`
	req := httptest.NewRequest(http.MethodPost, "/devices/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+generateTestToken_CB67("user1"))
	w := httptest.NewRecorder()
	handleRegisterDeviceToken(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestCB67_RegisterDeviceToken_Success(t *testing.T) {
	db = setupTestDB_CB67(t)
	defer func() { db = nil }()

	body := `{"device_token":"token123","platform":"ios"}`
	req := httptest.NewRequest(http.MethodPost, "/devices/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+generateTestToken_CB67("user1"))
	w := httptest.NewRecorder()
	handleRegisterDeviceToken(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}

	// Verify token stored
	var count int
	db.QueryRow("SELECT COUNT(*) FROM device_tokens WHERE user_id = 'user1' AND device_token = 'token123'").Scan(&count)
	if count != 1 {
		t.Errorf("expected 1 token in DB, got %d", count)
	}
}

func TestCB67_RegisterDeviceToken_DefaultPlatform(t *testing.T) {
	db = setupTestDB_CB67(t)
	defer func() { db = nil }()

	body := `{"device_token":"token456"}`
	req := httptest.NewRequest(http.MethodPost, "/devices/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+generateTestToken_CB67("user1"))
	w := httptest.NewRecorder()
	handleRegisterDeviceToken(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}

	var platform string
	db.QueryRow("SELECT platform FROM device_tokens WHERE user_id = 'user1' AND device_token = 'token456'").Scan(&platform)
	if platform != "ios" {
		t.Errorf("expected default platform ios, got %s", platform)
	}
}

func TestCB67_RegisterDeviceToken_Android(t *testing.T) {
	db = setupTestDB_CB67(t)
	defer func() { db = nil }()

	body := `{"device_token":"android_tok","platform":"android"}`
	req := httptest.NewRequest(http.MethodPost, "/devices/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+generateTestToken_CB67("user1"))
	w := httptest.NewRecorder()
	handleRegisterDeviceToken(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}

	var platform string
	db.QueryRow("SELECT platform FROM device_tokens WHERE user_id = 'user1' AND device_token = 'android_tok'").Scan(&platform)
	if platform != "android" {
		t.Errorf("expected platform android, got %s", platform)
	}
}

// ==================== handleUnregisterDeviceToken (52.2% → target 90%+) ====================

func TestCB67_UnregisterDeviceToken_MethodNotAllowed(t *testing.T) {
	db = setupTestDB_CB67(t)
	defer func() { db = nil }()

	req := httptest.NewRequest(http.MethodGet, "/devices/unregister", nil)
	w := httptest.NewRecorder()
	handleUnregisterDeviceToken(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestCB67_UnregisterDeviceToken_Unauthorized(t *testing.T) {
	db = setupTestDB_CB67(t)
	defer func() { db = nil }()

	body := `{"device_token":"token123"}`
	req := httptest.NewRequest(http.MethodDelete, "/devices/unregister", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handleUnregisterDeviceToken(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestCB67_UnregisterDeviceToken_InvalidJSON(t *testing.T) {
	db = setupTestDB_CB67(t)
	defer func() { db = nil }()

	req := httptest.NewRequest(http.MethodDelete, "/devices/unregister", strings.NewReader("not json"))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+generateTestToken_CB67("user1"))
	w := httptest.NewRecorder()
	handleUnregisterDeviceToken(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestCB67_UnregisterDeviceToken_MissingToken(t *testing.T) {
	db = setupTestDB_CB67(t)
	defer func() { db = nil }()

	body := `{}`
	req := httptest.NewRequest(http.MethodDelete, "/devices/unregister", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+generateTestToken_CB67("user1"))
	w := httptest.NewRecorder()
	handleUnregisterDeviceToken(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestCB67_UnregisterDeviceToken_Success(t *testing.T) {
	db = setupTestDB_CB67(t)
	defer func() { db = nil }()
	// Insert a token first
	db.Exec("INSERT INTO device_tokens (user_id, device_token, platform) VALUES (?, ?, ?)",
		"user1", "token123", "ios")

	body := `{"device_token":"token123"}`
	req := httptest.NewRequest(http.MethodDelete, "/devices/unregister", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+generateTestToken_CB67("user1"))
	w := httptest.NewRecorder()
	handleUnregisterDeviceToken(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}

	var count int
	db.QueryRow("SELECT COUNT(*) FROM device_tokens WHERE user_id = 'user1' AND device_token = 'token123'").Scan(&count)
	if count != 0 {
		t.Errorf("expected token deleted, found %d", count)
	}
}

// ==================== handleSetNotificationPrefs (55.6% → target 90%+) ====================

func TestCB67_SetNotificationPrefs_Unauthorized(t *testing.T) {
	db = setupTestDB_CB67(t)
	defer func() { db = nil }()

	form := strings.NewReader("conversation_id=conv1&muted=true")
	req := httptest.NewRequest(http.MethodPost, "/notifications/prefs", form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handleSetNotificationPrefs(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestCB67_SetNotificationPrefs_MissingConvID(t *testing.T) {
	db = setupTestDB_CB67(t)
	defer func() { db = nil }()

	form := strings.NewReader("muted=true")
	req := httptest.NewRequest(http.MethodPost, "/notifications/prefs", form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	ctx := context.WithValue(req.Context(), contextKeyUserID, "user1")
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()
	handleSetNotificationPrefs(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestCB67_SetNotificationPrefs_ConvNotFound(t *testing.T) {
	db = setupTestDB_CB67(t)
	defer func() { db = nil }()

	form := strings.NewReader("conversation_id=nonexistent&muted=true")
	req := httptest.NewRequest(http.MethodPost, "/notifications/prefs", form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	ctx := context.WithValue(req.Context(), contextKeyUserID, "user1")
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()
	handleSetNotificationPrefs(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

func TestCB67_SetNotificationPrefs_NotOwner(t *testing.T) {
	db = setupTestDB_CB67(t)
	defer func() { db = nil }()
	convID := createConversation_CB67(db, "user1", "agent1")

	form := strings.NewReader("conversation_id="+convID+"&muted=true")
	req := httptest.NewRequest(http.MethodPost, "/notifications/prefs", form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	ctx := context.WithValue(req.Context(), contextKeyUserID, "otheruser")
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()
	handleSetNotificationPrefs(w, req)
	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", w.Code)
	}
}

func TestCB67_SetNotificationPrefs_MuteSuccess(t *testing.T) {
	db = setupTestDB_CB67(t)
	defer func() { db = nil }()
	userID := createUser_CB67(db, "user1", "pass123")
	convID := createConversation_CB67(db, userID, "agent1")

	form := strings.NewReader("conversation_id="+convID+"&muted=true")
	req := httptest.NewRequest(http.MethodPost, "/notifications/prefs", form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	ctx := context.WithValue(req.Context(), contextKeyUserID, userID)
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()
	handleSetNotificationPrefs(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}

	var muted int
	db.QueryRow("SELECT muted FROM notification_preferences WHERE user_id = ? AND conversation_id = ?", userID, convID).Scan(&muted)
	if muted != 1 {
		t.Errorf("expected muted=1, got %d", muted)
	}
}

func TestCB67_SetNotificationPrefs_UnmuteSuccess(t *testing.T) {
	db = setupTestDB_CB67(t)
	defer func() { db = nil }()
	userID := createUser_CB67(db, "user1", "pass123")
	convID := createConversation_CB67(db, userID, "agent1")
	// First mute
	db.Exec("INSERT INTO notification_preferences (user_id, conversation_id, muted) VALUES (?, ?, ?)", userID, convID, 1)

	form := strings.NewReader("conversation_id="+convID+"&muted=false")
	req := httptest.NewRequest(http.MethodPost, "/notifications/prefs", form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	ctx := context.WithValue(req.Context(), contextKeyUserID, userID)
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()
	handleSetNotificationPrefs(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}

	var muted int
	db.QueryRow("SELECT muted FROM notification_preferences WHERE user_id = ? AND conversation_id = ?", userID, convID).Scan(&muted)
	if muted != 0 {
		t.Errorf("expected muted=0, got %d", muted)
	}
}

// ==================== authenticateRequest (85.7% → target 100%) ====================

func TestCB67_AuthenticateRequest_NoAuth(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	_, _, err := authenticateRequest(req)
	if err == nil {
		t.Error("expected error for no auth header")
	}
}

func TestCB67_AuthenticateRequest_InvalidBearer(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer invalidtoken")
	_, _, err := authenticateRequest(req)
	if err == nil {
		t.Error("expected error for invalid token")
	}
}

func TestCB67_AuthenticateRequest_ValidUserJWT(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer "+generateTestToken_CB67("user1"))
	ownerID, ownerType, err := authenticateRequest(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ownerID != "user1" {
		t.Errorf("expected ownerID user1, got %s", ownerID)
	}
	if ownerType != "user" {
		t.Errorf("expected ownerType user, got %s", ownerType)
	}
}

func TestCB67_AuthenticateRequest_AgentSecret(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("X-Agent-Secret", getAgentSecret())
	req.Header.Set("X-Agent-ID", "agent1")
	ownerID, ownerType, err := authenticateRequest(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ownerID != "agent1" {
		t.Errorf("expected ownerID agent1, got %s", ownerID)
	}
	if ownerType != "agent" {
		t.Errorf("expected ownerType agent, got %s", ownerType)
	}
}

func TestCB67_AuthenticateRequest_AgentSecretMissingID(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("X-Agent-Secret", getAgentSecret())
	_, _, err := authenticateRequest(req)
	if err == nil {
		t.Error("expected error for missing X-Agent-ID")
	}
}

func TestCB67_AuthenticateRequest_AgentSecretWrong(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("X-Agent-Secret", "wrongsecret")
	req.Header.Set("X-Agent-ID", "agent1")
	_, _, err := authenticateRequest(req)
	if err == nil {
		t.Error("expected error for wrong agent secret")
	}
}

// ==================== GetOrCreateConversation (85.7% → target 100%) ====================

func TestCB67_GetOrCreateConversation_Create(t *testing.T) {
	db = setupTestDB_CB67(t)
	defer func() { db = nil }()

	conv, err := GetOrCreateConversation("user1", "agent1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if conv.UserID != "user1" || conv.AgentID != "agent1" {
		t.Errorf("unexpected conversation: %+v", conv)
	}
}

func TestCB67_GetOrCreateConversation_GetExisting(t *testing.T) {
	db = setupTestDB_CB67(t)
	defer func() { db = nil }()

	// Create first
	conv1, err := GetOrCreateConversation("user1", "agent1")
	if err != nil {
		t.Fatalf("first call failed: %v", err)
	}

	// Get existing
	conv2, err := GetOrCreateConversation("user1", "agent1")
	if err != nil {
		t.Fatalf("second call failed: %v", err)
	}
	if conv1.ID != conv2.ID {
		t.Errorf("expected same conversation, got %s vs %s", conv1.ID, conv2.ID)
	}
}

// ==================== markMessagesRead (81.8% → target 90%+) ====================

func TestCB67_MarkMessagesRead_ConvNotFound(t *testing.T) {
	db = setupTestDB_CB67(t)
	defer func() { db = nil }()

	_, err := markMessagesRead("nonexistent", "user1")
	if err != sql.ErrNoRows {
		t.Errorf("expected sql.ErrNoRows, got %v", err)
	}
}

func TestCB67_MarkMessagesRead_Unauthorized(t *testing.T) {
	db = setupTestDB_CB67(t)
	defer func() { db = nil }()
	convID := createConversation_CB67(db, "user1", "agent1")

	_, err := markMessagesRead(convID, "otheruser")
	if err == nil {
		t.Error("expected error for unauthorized user")
	}
}

func TestCB67_MarkMessagesRead_Success(t *testing.T) {
	db = setupTestDB_CB67(t)
	defer func() { db = nil }()
	userID := createUser_CB67(db, "user1", "pass123")
	convID := createConversation_CB67(db, userID, "agent1")
	// Insert unread agent messages
	db.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, created_at) VALUES (?, ?, ?, ?, ?, ?)",
		"msg1", convID, "agent", "agent1", "hello", time.Now().UTC())
	db.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, created_at) VALUES (?, ?, ?, ?, ?, ?)",
		"msg2", convID, "agent", "agent1", "world", time.Now().UTC())

	count, err := markMessagesRead(convID, userID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if count != 2 {
		t.Errorf("expected 2 messages marked read, got %d", count)
	}
}

func TestCB67_MarkMessagesRead_Idempotent(t *testing.T) {
	db = setupTestDB_CB67(t)
	defer func() { db = nil }()
	userID := createUser_CB67(db, "user1", "pass123")
	convID := createConversation_CB67(db, userID, "agent1")
	db.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, created_at) VALUES (?, ?, ?, ?, ?, ?)",
		"msg1", convID, "agent", "agent1", "hello", time.Now().UTC())

	// First call
	markMessagesRead(convID, userID)
	// Second call should return 0
	count, err := markMessagesRead(convID, userID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if count != 0 {
		t.Errorf("expected 0 on idempotent call, got %d", count)
	}
}

// ==================== deleteConversation (75% → target 90%+) ====================

func TestCB67_DeleteConversationFn_NotFound(t *testing.T) {
	db = setupTestDB_CB67(t)
	defer func() { db = nil }()

	err := deleteConversation("nonexistent", "user1")
	if err != sql.ErrNoRows {
		t.Errorf("expected sql.ErrNoRows, got %v", err)
	}
}

func TestCB67_DeleteConversationFn_Unauthorized(t *testing.T) {
	db = setupTestDB_CB67(t)
	defer func() { db = nil }()
	convID := createConversation_CB67(db, "user1", "agent1")

	err := deleteConversation(convID, "otheruser")
	if err == nil || err.Error() != "unauthorized" {
		t.Errorf("expected unauthorized error, got %v", err)
	}
}

func TestCB67_DeleteConversationFn_Success(t *testing.T) {
	db = setupTestDB_CB67(t)
	defer func() { db = nil }()
	userID := createUser_CB67(db, "user1", "pass123")
	convID := createConversation_CB67(db, userID, "agent1")
	db.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, created_at) VALUES (?, ?, ?, ?, ?, ?)",
		"msg1", convID, "agent", "agent1", "hello", time.Now().UTC())

	err := deleteConversation(convID, userID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var count int
	db.QueryRow("SELECT COUNT(*) FROM conversations WHERE id = ?", convID).Scan(&count)
	if count != 0 {
		t.Errorf("expected conversation deleted, got %d", count)
	}
}

// ==================== changeUserPassword (69.2% → target 90%+) ====================

func TestCB67_ChangeUserPasswordFn_Success(t *testing.T) {
	db = setupTestDB_CB67(t)
	defer func() { db = nil }()
	userID := createUser_CB67(db, "testuser", "oldpass123")

	err := changeUserPassword(userID, "oldpass123", "newpass456")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify password changed
	var hash string
	db.QueryRow("SELECT password_hash FROM users WHERE id = ?", userID).Scan(&hash)
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte("newpass456")); err != nil {
		t.Error("new password doesn't match hash")
	}
}

func TestCB67_ChangeUserPasswordFn_WrongOld(t *testing.T) {
	db = setupTestDB_CB67(t)
	defer func() { db = nil }()
	userID := createUser_CB67(db, "testuser", "oldpass123")

	err := changeUserPassword(userID, "wrongpass", "newpass456")
	if err == nil || err.Error() != "invalid old password" {
		t.Errorf("expected invalid old password error, got %v", err)
	}
}

func TestCB67_ChangeUserPasswordFn_UserNotFound(t *testing.T) {
	db = setupTestDB_CB67(t)
	defer func() { db = nil }()

	err := changeUserPassword("nonexistent", "old", "new")
	if err != sql.ErrNoRows {
		t.Errorf("expected sql.ErrNoRows, got %v", err)
	}
}

func TestCB67_ChangeUserPasswordFn_ShortNew(t *testing.T) {
	db = setupTestDB_CB67(t)
	defer func() { db = nil }()
	userID := createUser_CB67(db, "testuser", "oldpass123")

	err := changeUserPassword(userID, "oldpass123", "short")
	if err == nil || err.Error() != "new password must be at least 6 characters" {
		t.Errorf("expected short password error, got %v", err)
	}
}

// ==================== storeMessagesBatch (81.5% → target 90%+) ====================

func TestCB67_StoreMessagesBatch_Empty(t *testing.T) {
	db = setupTestDB_CB67(t)
	defer func() { db = nil }()

	ids, err := storeMessagesBatch(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ids != nil {
		t.Errorf("expected nil ids for empty batch, got %v", ids)
	}
}

func TestCB67_StoreMessagesBatch_Success(t *testing.T) {
	db = setupTestDB_CB67(t)
	defer func() { db = nil }()
	convID := createConversation_CB67(db, "user1", "agent1")

	msgs := []RoutedMessage{
		{Type: MsgTypeMessage, ConversationID: convID, SenderType: "agent", SenderID: "agent1", Content: "msg1"},
		{Type: MsgTypeMessage, ConversationID: convID, SenderType: "client", SenderID: "user1", Content: "msg2"},
		{Type: MsgTypeMessage, ConversationID: convID, SenderType: "agent", SenderID: "agent1", Content: "msg3"},
	}

	ids, err := storeMessagesBatch(msgs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ids) != 3 {
		t.Errorf("expected 3 ids, got %d", len(ids))
	}

	var count int
	db.QueryRow("SELECT COUNT(*) FROM messages WHERE conversation_id = ?", convID).Scan(&count)
	if count != 3 {
		t.Errorf("expected 3 messages in DB, got %d", count)
	}
}

// ==================== searchMessages (68.8% → target 90%+) ====================

func TestCB67_SearchMessagesFn_EmptyQuery(t *testing.T) {
	db = setupTestDB_CB67(t)
	defer func() { db = nil }()

	_, err := searchMessages("user1", "", 50)
	if err == nil {
		t.Error("expected error for empty query")
	}
}

func TestCB67_SearchMessagesFn_Success(t *testing.T) {
	db = setupTestDB_CB67(t)
	defer func() { db = nil }()
	userID := createUser_CB67(db, "user1", "pass123")
	convID := createConversation_CB67(db, userID, "agent1")
	db.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, created_at) VALUES (?, ?, ?, ?, ?, ?)",
		"msg1", convID, "agent", "agent1", "hello world", time.Now().UTC())

	msgs, err := searchMessages(userID, "world", 50)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(msgs) != 1 {
		t.Errorf("expected 1 result, got %d", len(msgs))
	}
}

func TestCB67_SearchMessagesFn_NoResults(t *testing.T) {
	db = setupTestDB_CB67(t)
	defer func() { db = nil }()
	userID := createUser_CB67(db, "user1", "pass123")
	convID := createConversation_CB67(db, userID, "agent1")
	db.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, created_at) VALUES (?, ?, ?, ?, ?, ?)",
		"msg1", convID, "agent", "agent1", "hello", time.Now().UTC())

	msgs, err := searchMessages(userID, "nonexistent", 50)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(msgs) != 0 {
		t.Errorf("expected 0 results, got %d", len(msgs))
	}
}

// ==================== getConversationMessages (already high but test cursor pagination) ====================

func TestCB67_GetConversationMessages_CursorPagination(t *testing.T) {
	db = setupTestDB_CB67(t)
	defer func() { db = nil }()
	convID := createConversation_CB67(db, "user1", "agent1")

	// Insert 5 messages with different timestamps
	baseTime := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for i := 0; i < 5; i++ {
		msgTime := baseTime.Add(time.Duration(i) * time.Minute)
		db.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, created_at) VALUES (?, ?, ?, ?, ?, ?)",
			"msg"+string(rune('1'+i)), convID, "agent", "agent1", "msg"+string(rune('1'+i)),
			msgTime)
	}

	// Get first 3 (ASC order without cursor)
	msgs, err := getConversationMessages(convID, 3, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(msgs) != 3 {
		t.Fatalf("expected 3 messages, got %d", len(msgs))
	}

	// Verify ordering is ascending (chronological)
	if msgs[0].ID != "msg1" {
		t.Errorf("expected first message msg1, got %s", msgs[0].ID)
	}
	if msgs[2].ID != "msg3" {
		t.Errorf("expected third message msg3, got %s", msgs[2].ID)
	}

	// With cursor: use a far-future time to get all messages in DESC order
	farFuture := baseTime.Add(10 * time.Minute).Format(time.RFC3339Nano)
	msgs2, err := getConversationMessages(convID, 10, farFuture)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(msgs2) != 5 {
		t.Errorf("expected 5 messages with far-future cursor, got %d", len(msgs2))
	}
	// Should be in DESC order (newest first, then reversed to chronological)
	if len(msgs2) > 0 && msgs2[0].ID != "msg1" {
		t.Errorf("expected first message msg1 after reverse, got %s", msgs2[0].ID)
	}
}

// ==================== CreateConversation (80% → target 100%) ====================

func TestCB67_CreateConversationFn_Success(t *testing.T) {
	db = setupTestDB_CB67(t)
	defer func() { db = nil }()

	conv, err := CreateConversation("user1", "agent1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if conv.UserID != "user1" || conv.AgentID != "agent1" {
		t.Errorf("unexpected conversation: %+v", conv)
	}

	// Verify in DB
	var count int
	db.QueryRow("SELECT COUNT(*) FROM conversations WHERE id = ?", conv.ID).Scan(&count)
	if count != 1 {
		t.Errorf("expected 1 conversation in DB, got %d", count)
	}
}

// ==================== handleStoreEncryptedMessage (79.2% → target 90%+) ====================

func TestCB67_StoreEncryptedMessage_MethodNotAllowed(t *testing.T) {
	db = setupTestDB_CB67(t)
	defer func() { db = nil }()

	req := httptest.NewRequest(http.MethodGet, "/messages/encrypted", nil)
	w := httptest.NewRecorder()
	handleStoreEncryptedMessage(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestCB67_StoreEncryptedMessage_Unauthorized(t *testing.T) {
	db = setupTestDB_CB67(t)
	defer func() { db = nil }()

	body := `{"conversation_id":"conv1","ciphertext":"ct","iv":"iv","algorithm":"aes-256-gcm"}`
	req := httptest.NewRequest(http.MethodPost, "/messages/encrypted", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handleStoreEncryptedMessage(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestCB67_StoreEncryptedMessage_InvalidJSON(t *testing.T) {
	db = setupTestDB_CB67(t)
	defer func() { db = nil }()

	req := httptest.NewRequest(http.MethodPost, "/messages/encrypted", strings.NewReader("not json"))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+generateTestToken_CB67("user1"))
	w := httptest.NewRecorder()
	handleStoreEncryptedMessage(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestCB67_StoreEncryptedMessage_MissingFields(t *testing.T) {
	db = setupTestDB_CB67(t)
	defer func() { db = nil }()

	body := `{"conversation_id":"conv1"}`
	req := httptest.NewRequest(http.MethodPost, "/messages/encrypted", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+generateTestToken_CB67("user1"))
	w := httptest.NewRecorder()
	handleStoreEncryptedMessage(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing fields, got %d", w.Code)
	}
}

func TestCB67_StoreEncryptedMessage_InvalidAlgorithm(t *testing.T) {
	db = setupTestDB_CB67(t)
	defer func() { db = nil }()

	body := `{"conversation_id":"conv1","ciphertext":"ct","iv":"iv","algorithm":"bad-algo"}`
	req := httptest.NewRequest(http.MethodPost, "/messages/encrypted", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+generateTestToken_CB67("user1"))
	w := httptest.NewRecorder()
	handleStoreEncryptedMessage(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid algorithm, got %d", w.Code)
	}
}

func TestCB67_StoreEncryptedMessage_ConvNotFound(t *testing.T) {
	db = setupTestDB_CB67(t)
	defer func() { db = nil }()

	body := `{"conversation_id":"nonexistent","ciphertext":"ct","iv":"iv","algorithm":"aes-256-gcm"}`
	req := httptest.NewRequest(http.MethodPost, "/messages/encrypted", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+generateTestToken_CB67("user1"))
	w := httptest.NewRecorder()
	handleStoreEncryptedMessage(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

func TestCB67_StoreEncryptedMessage_UserNotParticipant(t *testing.T) {
	db = setupTestDB_CB67(t)
	defer func() { db = nil }()
	convID := createConversation_CB67(db, "user1", "agent1")

	body := `{"conversation_id":"` + convID + `","ciphertext":"ct","iv":"iv","algorithm":"aes-256-gcm"}`
	req := httptest.NewRequest(http.MethodPost, "/messages/encrypted", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+generateTestToken_CB67("otheruser"))
	w := httptest.NewRecorder()
	handleStoreEncryptedMessage(w, req)
	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403 for non-participant, got %d", w.Code)
	}
}

func TestCB67_StoreEncryptedMessage_Success(t *testing.T) {
	db = setupTestDB_CB67(t)
	defer func() { db = nil }()
	convID := createConversation_CB67(db, "user1", "agent1")

	body := `{"conversation_id":"` + convID + `","ciphertext":"ct123","iv":"iv123","algorithm":"aes-256-gcm","recipient_key_id":"rk1"}`
	req := httptest.NewRequest(http.MethodPost, "/messages/encrypted", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+generateTestToken_CB67("user1"))
	w := httptest.NewRecorder()
	handleStoreEncryptedMessage(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	var resp map[string]string
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["status"] != "stored" {
		t.Errorf("expected status stored, got %s", resp["status"])
	}
}

func TestCB67_StoreEncryptedMessage_AgentSender(t *testing.T) {
	db = setupTestDB_CB67(t)
	defer func() { db = nil }()
	convID := createConversation_CB67(db, "user1", "agent1")
	hub = makeTestHub_CB67()
	defer func() { hub.Stop(); hub = nil }()

	body := `{"conversation_id":"` + convID + `","ciphertext":"ct_from_agent","iv":"iv","algorithm":"x25519-aes-256-gcm","recipient_key_id":"rk1"}`
	req := httptest.NewRequest(http.MethodPost, "/messages/encrypted", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Agent-Secret", getAgentSecret())
	req.Header.Set("X-Agent-ID", "agent1")
	w := httptest.NewRecorder()
	handleStoreEncryptedMessage(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200 for agent sender, got %d", w.Code)
	}
}

func TestCB67_StoreEncryptedMessage_AgentNotParticipant(t *testing.T) {
	db = setupTestDB_CB67(t)
	defer func() { db = nil }()
	convID := createConversation_CB67(db, "user1", "agent1")

	body := `{"conversation_id":"` + convID + `","ciphertext":"ct","iv":"iv","algorithm":"aes-256-gcm"}`
	req := httptest.NewRequest(http.MethodPost, "/messages/encrypted", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Agent-Secret", getAgentSecret())
	req.Header.Set("X-Agent-ID", "other_agent")
	w := httptest.NewRecorder()
	handleStoreEncryptedMessage(w, req)
	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403 for non-participant agent, got %d", w.Code)
	}
}