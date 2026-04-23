package main

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"net/http/httptest"
	"path/filepath"
	"testing"

	_ "github.com/mattn/go-sqlite3"
)

func setupE2ETestDB(t *testing.T) {
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

func e2eCreateUser(t *testing.T, username string) string {
	t.Helper()
	form := "username=" + username + "&password=testpass123"
	req := httptest.NewRequest("POST", "/auth/user", bytes.NewBufferString(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handleRegisterUser(w, req)
	if w.Code != 200 {
		t.Fatalf("Failed to register user: %d %s", w.Code, w.Body.String())
	}
	// Login to get JWT
	req = httptest.NewRequest("POST", "/auth/login", bytes.NewBufferString(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w = httptest.NewRecorder()
	handleLogin(w, req)
	if w.Code != 200 {
		t.Fatalf("Failed to login: %d %s", w.Code, w.Body.String())
	}
	var resp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&resp)
	token, _ := resp["token"].(string)
	return token
}

func TestUploadIdentityKey(t *testing.T) {
	setupE2ETestDB(t)
	defer db.Close()

	token := e2eCreateUser(t, "keyuser")

	body := `{"key_type":"identity","public_key":"dGVzdF9pZGVudGl0eV9rZXk="}`
	req := httptest.NewRequest("POST", "/keys/upload", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	handleUploadPublicKey(w, req)

	if w.Code != 200 {
		t.Fatalf("Expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var bundle KeyBundle
	if err := json.NewDecoder(w.Body).Decode(&bundle); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}
	if bundle.KeyType != "identity" {
		t.Errorf("Expected key_type identity, got %s", bundle.KeyType)
	}
	if bundle.OwnerType != "user" {
		t.Errorf("Expected owner_type user, got %s", bundle.OwnerType)
	}
	if bundle.PublicKey != "dGVzdF9pZGVudGl0eV9rZXk=" {
		t.Errorf("Unexpected public key value")
	}
}

func TestUploadIdentityKeyReplaces(t *testing.T) {
	setupE2ETestDB(t)
	defer db.Close()

	token := e2eCreateUser(t, "replaceuser")

	// Upload first identity key
	body := `{"key_type":"identity","public_key":"a2V5MQ=="}`
	req := httptest.NewRequest("POST", "/keys/upload", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleUploadPublicKey(w, req)
	if w.Code != 200 {
		t.Fatalf("First upload failed: %d", w.Code)
	}

	// Upload replacement identity key
	body = `{"key_type":"identity","public_key":"a2V5Mg=="}`
	req = httptest.NewRequest("POST", "/keys/upload", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w = httptest.NewRecorder()
	handleUploadPublicKey(w, req)
	if w.Code != 200 {
		t.Fatalf("Second upload failed: %d", w.Code)
	}

	// Should only have one identity key
	var count int
	db.QueryRow("SELECT COUNT(*) FROM key_bundles WHERE owner_type = 'user' AND key_type = 'identity'").Scan(&count)
	if count != 1 {
		t.Errorf("Expected 1 identity key, got %d", count)
	}
}

func TestUploadSignedPreKey(t *testing.T) {
	setupE2ETestDB(t)
	defer db.Close()

	token := e2eCreateUser(t, "prekeyuser")

	body := `{"key_type":"signed_prekey","public_key":"c3BrXzE=","signature":"c2lnXzE="}`
	req := httptest.NewRequest("POST", "/keys/upload", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	handleUploadPublicKey(w, req)

	if w.Code != 200 {
		t.Fatalf("Expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestUploadOneTimePreKeys(t *testing.T) {
	setupE2ETestDB(t)
	defer db.Close()

	token := e2eCreateUser(t, "otpkuser")

	// Upload multiple one-time pre-keys
	for i := 1; i <= 5; i++ {
		body := `{"key_type":"one_time_prekey","public_key":"b3Rwa18=` + string(rune('0'+i)) + `","key_id":` + string(rune('0'+i)) + `}`
		req := httptest.NewRequest("POST", "/keys/upload", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		handleUploadPublicKey(w, req)
		if w.Code != 200 {
			t.Fatalf("OTPK upload %d failed: %d", i, w.Code)
		}
	}

	var count int
	db.QueryRow("SELECT COUNT(*) FROM key_bundles WHERE key_type = 'one_time_prekey'").Scan(&count)
	if count != 5 {
		t.Errorf("Expected 5 one-time pre-keys, got %d", count)
	}
}

func TestUploadKeyNoAuth(t *testing.T) {
	setupE2ETestDB(t)
	defer db.Close()

	body := `{"key_type":"identity","public_key":"a2V5"}`
	req := httptest.NewRequest("POST", "/keys/upload", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	handleUploadPublicKey(w, req)

	if w.Code != 401 {
		t.Errorf("Expected 401, got %d", w.Code)
	}
}

func TestUploadKeyInvalidType(t *testing.T) {
	setupE2ETestDB(t)
	defer db.Close()

	token := e2eCreateUser(t, "badtypeuser")

	body := `{"key_type":"invalid","public_key":"a2V5"}`
	req := httptest.NewRequest("POST", "/keys/upload", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	handleUploadPublicKey(w, req)

	if w.Code != 400 {
		t.Errorf("Expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestGetKeyBundle(t *testing.T) {
	setupE2ETestDB(t)
	defer db.Close()

	token := e2eCreateUser(t, "bundleuser")

	// Upload identity key + signed pre-key + one-time pre-keys
	for _, body := range []string{
		`{"key_type":"identity","public_key":"aWRfa2V5"}`,
		`{"key_type":"signed_prekey","public_key":"c3Br","signature":"c2ln"}`,
		`{"key_type":"one_time_prekey","public_key":"b3Rwa18x","key_id":1}`,
		`{"key_type":"one_time_prekey","public_key":"b3Rwa18y","key_id":2}`,
	} {
		req := httptest.NewRequest("POST", "/keys/upload", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		handleUploadPublicKey(w, req)
		if w.Code != 200 {
			t.Fatalf("Key upload failed: %d %s", w.Code, w.Body.String())
		}
	}

	// Get user ID
	var userID string
	db.QueryRow("SELECT id FROM users WHERE username = 'bundleuser'").Scan(&userID)

	// Fetch key bundle
	req := httptest.NewRequest("GET", "/keys/bundle?owner_id="+userID+"&owner_type=user", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleGetKeyBundle(w, req)

	if w.Code != 200 {
		t.Fatalf("Expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var bundle map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&bundle); err != nil {
		t.Fatalf("Failed to decode bundle: %v", err)
	}

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

func TestGetKeyBundleConsumesOTPK(t *testing.T) {
	setupE2ETestDB(t)
	defer db.Close()

	token := e2eCreateUser(t, "consumeuser")

	// Upload identity + 2 OTPKs
	for _, body := range []string{
		`{"key_type":"identity","public_key":"aWQ="}`,
		`{"key_type":"one_time_prekey","public_key":"b3RwazE=","key_id":1}`,
		`{"key_type":"one_time_prekey","public_key":"b3RwazI=","key_id":2}`,
	} {
		req := httptest.NewRequest("POST", "/keys/upload", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		handleUploadPublicKey(w, req)
	}

	var userID string
	db.QueryRow("SELECT id FROM users WHERE username = 'consumeuser'").Scan(&userID)

	// Fetch bundle (consumes 1 OTPK)
	req := httptest.NewRequest("GET", "/keys/bundle?owner_id="+userID+"&owner_type=user", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleGetKeyBundle(w, req)

	var count int
	db.QueryRow("SELECT COUNT(*) FROM key_bundles WHERE key_type = 'one_time_prekey'").Scan(&count)
	if count != 1 {
		t.Errorf("Expected 1 remaining OTPK after consumption, got %d", count)
	}
}

func TestGetKeyBundleNoIdentity(t *testing.T) {
	setupE2ETestDB(t)
	defer db.Close()

	token := e2eCreateUser(t, "nokeyuser")

	var userID string
	db.QueryRow("SELECT id FROM users WHERE username = 'nokeyuser'").Scan(&userID)

	req := httptest.NewRequest("GET", "/keys/bundle?owner_id="+userID+"&owner_type=user", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleGetKeyBundle(w, req)

	if w.Code != 404 {
		t.Errorf("Expected 404, got %d", w.Code)
	}
}

func TestOTPKCount(t *testing.T) {
	setupE2ETestDB(t)
	defer db.Close()

	token := e2eCreateUser(t, "countuser")

	req := httptest.NewRequest("GET", "/keys/otpk-count", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleListOneTimePreKeys(w, req)

	if w.Code != 200 {
		t.Fatalf("Expected 200, got %d", w.Code)
	}

	var resp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&resp)
	count := int(resp["one_time_prekey_count"].(float64))
	if count != 0 {
		t.Errorf("Expected 0 OTPK count, got %d", count)
	}

	// Upload some OTPKs
	for i := 0; i < 3; i++ {
		body := `{"key_type":"one_time_prekey","public_key":"aw==","key_id":` + string(rune('0'+i)) + `}`
		req := httptest.NewRequest("POST", "/keys/upload", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		handleUploadPublicKey(w, req)
	}

	req = httptest.NewRequest("GET", "/keys/otpk-count", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w = httptest.NewRecorder()
	handleListOneTimePreKeys(w, req)

	json.NewDecoder(w.Body).Decode(&resp)
	count = int(resp["one_time_prekey_count"].(float64))
	if count != 3 {
		t.Errorf("Expected 3 OTPK count, got %d", count)
	}
}

func TestStoreEncryptedMessage(t *testing.T) {
	setupE2ETestDB(t)
	defer db.Close()

	token := e2eCreateUser(t, "encuser")

	// Create a conversation first
	var userID string
	db.QueryRow("SELECT id FROM users WHERE username = 'encuser'").Scan(&userID)

	convID := generateID("conv")
	_, err := db.Exec(
		"INSERT INTO conversations (id, user_id, agent_id, created_at) VALUES (?, ?, ?, datetime('now'))",
		convID, userID, "agent_test",
	)
	if err != nil {
		t.Fatal(err)
	}

	body := `{"conversation_id":"` + convID + `","ciphertext":"YWVzLTI1Ni1nY20tY2lwaGVydGV4dA==","iv":"aXZfMTI=","recipient_key_id":"key_1","algorithm":"aes-256-gcm"}`
	req := httptest.NewRequest("POST", "/messages/encrypted", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	handleStoreEncryptedMessage(w, req)

	if w.Code != 200 {
		t.Fatalf("Expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]string
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["status"] != "stored" {
		t.Errorf("Expected status stored, got %s", resp["status"])
	}

	// Verify stored in DB
	var count int
	db.QueryRow("SELECT COUNT(*) FROM encrypted_messages WHERE conversation_id = ?", convID).Scan(&count)
	if count != 1 {
		t.Errorf("Expected 1 encrypted message, got %d", count)
	}
}

func TestStoreEncryptedMessageInvalidAlgorithm(t *testing.T) {
	setupE2ETestDB(t)
	defer db.Close()

	token := e2eCreateUser(t, "badalguser")

	var userID string
	db.QueryRow("SELECT id FROM users WHERE username = 'badalguser'").Scan(&userID)

	convID := generateID("conv")
	db.Exec("INSERT INTO conversations (id, user_id, agent_id, created_at) VALUES (?, ?, ?, datetime('now'))", convID, userID, "agent_test")

	body := `{"conversation_id":"` + convID + `","ciphertext":"Y2k=","iv":"aXY=","recipient_key_id":"k1","algorithm":"rsa-4096"}`
	req := httptest.NewRequest("POST", "/messages/encrypted", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	handleStoreEncryptedMessage(w, req)

	if w.Code != 400 {
		t.Errorf("Expected 400 for invalid algorithm, got %d: %s", w.Code, w.Body.String())
	}
}

func TestGetEncryptedMessages(t *testing.T) {
	setupE2ETestDB(t)
	defer db.Close()

	token := e2eCreateUser(t, "getencuser")

	var userID string
	db.QueryRow("SELECT id FROM users WHERE username = 'getencuser'").Scan(&userID)

	convID := generateID("conv")
	db.Exec("INSERT INTO conversations (id, user_id, agent_id, created_at) VALUES (?, ?, ?, datetime('now'))", convID, userID, "agent_test")

	// Store 2 encrypted messages
	for i := 0; i < 2; i++ {
		body := `{"conversation_id":"` + convID + `","ciphertext":"Y2lwaGVydGV4dA` + string(rune('0'+i)) + `","iv":"aXY=","recipient_key_id":"k1","algorithm":"aes-256-gcm"}`
		req := httptest.NewRequest("POST", "/messages/encrypted", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		handleStoreEncryptedMessage(w, req)
	}

	// Retrieve encrypted messages
	req := httptest.NewRequest("GET", "/messages/encrypted/list?conversation_id="+convID, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleGetEncryptedMessages(w, req)

	if w.Code != 200 {
		t.Fatalf("Expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var messages []EncryptedMessage
	if err := json.NewDecoder(w.Body).Decode(&messages); err != nil {
		t.Fatalf("Failed to decode messages: %v", err)
	}
	if len(messages) != 2 {
		t.Errorf("Expected 2 encrypted messages, got %d", len(messages))
	}
}

func TestAuthenticateRequest(t *testing.T) {
	setupE2ETestDB(t)
	defer db.Close()

	// Test with no auth
	req := httptest.NewRequest("GET", "/test", nil)
	_, _, err := authenticateRequest(req)
	if err == nil {
		t.Error("Expected error with no auth")
	}

	// Test with JWT
	token := e2eCreateUser(t, "authtest")
	req = httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	ownerID, ownerType, err := authenticateRequest(req)
	if err != nil {
		t.Errorf("JWT auth failed: %v", err)
	}
	if ownerType != "user" {
		t.Errorf("Expected owner_type user, got %s", ownerType)
	}
	if ownerID == "" {
		t.Error("Expected non-empty ownerID")
	}
}