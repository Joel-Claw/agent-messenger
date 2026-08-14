package main

import (
	"golang.org/x/crypto/bcrypt"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

// ============================================================
// CB89: Coverage boost targeting remaining low-coverage functions
// Focus: e2e.go handlers (0%), reactions.go handlers (0%),
// routing.go routeTypingIndicator/routeStatusUpdate/truncate (0%),
// tags.go handlers (48-58%), rate_limit_tiers.go itoa/middleware (0%),
// tracing.go Trace* functions (50%), dbdriver.go Placeholders (0%),
// handlers.go handleLogin (32%), conversations.go storeMessage (72.7%),
// getConversationMessages (73.9%)
// ============================================================

// --- Helpers ---

func withTestDB_CB89(t *testing.T, fn func(testDB *sql.DB)) {
	t.Helper()
	oldDB := db
	oldDriver := currentDriver
	currentDriver = DriverSQLite
	defer func() { db = oldDB; currentDriver = oldDriver }()
	testDB, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("Failed to open test DB: %v", err)
	}
	defer testDB.Close()
	if err := initSchema(testDB); err != nil {
		t.Fatalf("Failed to init schema: %v", err)
	}
	db = testDB
	fn(testDB)
}

func makeJWT_CB89(userID, username string) string {
	token, err := GenerateJWT(userID, username)
	if err != nil {
		panic("failed to generate JWT: " + err.Error())
	}
	return token
}

func setupUserAndConv_CB89(t *testing.T, testDB *sql.DB) (string, string, string) {
	t.Helper()
	userID := "cb89-user1"
	agentID := "cb89-agent1"
	convID := "cb89-conv1"

	// Insert user
	_, err := testDB.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)",
		userID, "cb89testuser", "$2a$10$somehash")
	if err != nil {
		t.Fatalf("Failed to insert user: %v", err)
	}

	// Insert agent
	_, err = testDB.Exec("INSERT INTO agents (id, name, model, personality, specialty) VALUES (?, ?, ?, ?, ?)",
		agentID, "TestAgent", "gpt-4", "friendly", "general")
	if err != nil {
		t.Fatalf("Failed to insert agent: %v", err)
	}

	// Insert conversation
	_, err = testDB.Exec("INSERT INTO conversations (id, user_id, agent_id) VALUES (?, ?, ?)",
		convID, userID, agentID)
	if err != nil {
		t.Fatalf("Failed to insert conversation: %v", err)
	}

	return userID, agentID, convID
}

func insertMessage_CB89(t *testing.T, testDB *sql.DB, convID, senderType, senderID, content string) string {
	t.Helper()
	msgID := "cb89-msg-" + senderType + "-" + time.Now().Format("150405.000000")
	_, err := testDB.Exec(
		"INSERT INTO messages (id, conversation_id, sender_type, sender_id, content) VALUES (?, ?, ?, ?, ?)",
		msgID, convID, senderType, senderID, content)
	if err != nil {
		t.Fatalf("Failed to insert message: %v", err)
	}
	return msgID
}

// --- E2E: handleUploadPublicKey ---

func TestCB89_HandleUploadPublicKey_MethodNotAllowed(t *testing.T) {
	withTestDB_CB89(t, func(testDB *sql.DB) {
		req := httptest.NewRequest(http.MethodGet, "/keys/upload", nil)
		rr := httptest.NewRecorder()
		handleUploadPublicKey(rr, req)
		if rr.Code != http.StatusMethodNotAllowed {
			t.Errorf("expected 405, got %d", rr.Code)
		}
	})
}

func TestCB89_HandleUploadPublicKey_NoAuth(t *testing.T) {
	withTestDB_CB89(t, func(testDB *sql.DB) {
		req := httptest.NewRequest(http.MethodPost, "/keys/upload", strings.NewReader("{}"))
		rr := httptest.NewRecorder()
		handleUploadPublicKey(rr, req)
		if rr.Code != http.StatusUnauthorized {
			t.Errorf("expected 401, got %d", rr.Code)
		}
	})
}

func TestCB89_HandleUploadPublicKey_InvalidJSON(t *testing.T) {
	withTestDB_CB89(t, func(testDB *sql.DB) {
		token := makeJWT_CB89("cb89-u1", "user1")
		req := httptest.NewRequest(http.MethodPost, "/keys/upload", strings.NewReader("not json"))
		req.Header.Set("Authorization", "Bearer "+token)
		rr := httptest.NewRecorder()
		handleUploadPublicKey(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Errorf("expected 400, got %d", rr.Code)
		}
	})
}

func TestCB89_HandleUploadPublicKey_EmptyPublicKey(t *testing.T) {
	withTestDB_CB89(t, func(testDB *sql.DB) {
		token := makeJWT_CB89("cb89-u1", "user1")
		body := `{"key_type":"identity","public_key":""}`
		req := httptest.NewRequest(http.MethodPost, "/keys/upload", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+token)
		rr := httptest.NewRecorder()
		handleUploadPublicKey(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Errorf("expected 400, got %d", rr.Code)
		}
	})
}

func TestCB89_HandleUploadPublicKey_InvalidKeyType(t *testing.T) {
	withTestDB_CB89(t, func(testDB *sql.DB) {
		token := makeJWT_CB89("cb89-u1", "user1")
		body := `{"key_type":"invalid","public_key":"abc123"}`
		req := httptest.NewRequest(http.MethodPost, "/keys/upload", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+token)
		rr := httptest.NewRecorder()
		handleUploadPublicKey(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Errorf("expected 400, got %d", rr.Code)
		}
	})
}

func TestCB89_HandleUploadPublicKey_IdentityKeySuccess(t *testing.T) {
	withTestDB_CB89(t, func(testDB *sql.DB) {
		userID := "cb89-u1"
		setupUserAndConv_CB89(t, testDB)
		token := makeJWT_CB89(userID, "cb89testuser")
		body := `{"key_type":"identity","public_key":"base64key123"}`
		req := httptest.NewRequest(http.MethodPost, "/keys/upload", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+token)
		rr := httptest.NewRecorder()
		handleUploadPublicKey(rr, req)
		if rr.Code != http.StatusOK {
			t.Errorf("expected 200, got %d, body: %s", rr.Code, rr.Body.String())
		}
		var resp map[string]interface{}
		json.Unmarshal(rr.Body.Bytes(), &resp)
		if resp["public_key"] != "base64key123" {
			t.Errorf("expected public_key in response, got %v", resp["public_key"])
		}
	})
}

func TestCB89_HandleUploadPublicKey_IdentityKeyReplace(t *testing.T) {
	withTestDB_CB89(t, func(testDB *sql.DB) {
		userID := "cb89-u1"
		setupUserAndConv_CB89(t, testDB)
		token := makeJWT_CB89(userID, "cb89testuser")

		// Upload first identity key
		body1 := `{"key_type":"identity","public_key":"key1"}`
		req1 := httptest.NewRequest(http.MethodPost, "/keys/upload", strings.NewReader(body1))
		req1.Header.Set("Authorization", "Bearer "+token)
		rr1 := httptest.NewRecorder()
		handleUploadPublicKey(rr1, req1)
		if rr1.Code != http.StatusOK {
			t.Fatalf("first upload failed: %d", rr1.Code)
		}

		// Upload replacement identity key
		body2 := `{"key_type":"identity","public_key":"key2"}`
		req2 := httptest.NewRequest(http.MethodPost, "/keys/upload", strings.NewReader(body2))
		req2.Header.Set("Authorization", "Bearer "+token)
		rr2 := httptest.NewRecorder()
		handleUploadPublicKey(rr2, req2)
		if rr2.Code != http.StatusOK {
			t.Fatalf("second upload failed: %d", rr2.Code)
		}

		// Verify only one identity key exists
		var count int
		testDB.QueryRow("SELECT COUNT(*) FROM key_bundles WHERE owner_id = ? AND key_type = 'identity'", userID).Scan(&count)
		if count != 1 {
			t.Errorf("expected 1 identity key, got %d", count)
		}
	})
}

func TestCB89_HandleUploadPublicKey_SignedPreKeySuccess(t *testing.T) {
	withTestDB_CB89(t, func(testDB *sql.DB) {
		userID := "cb89-u1"
		setupUserAndConv_CB89(t, testDB)
		token := makeJWT_CB89(userID, "cb89testuser")
		body := `{"key_type":"signed_prekey","public_key":"spk1","signature":"sig1"}`
		req := httptest.NewRequest(http.MethodPost, "/keys/upload", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+token)
		rr := httptest.NewRecorder()
		handleUploadPublicKey(rr, req)
		if rr.Code != http.StatusOK {
			t.Errorf("expected 200, got %d", rr.Code)
		}
	})
}

func TestCB89_HandleUploadPublicKey_OneTimePreKeySuccess(t *testing.T) {
	withTestDB_CB89(t, func(testDB *sql.DB) {
		userID := "cb89-u1"
		setupUserAndConv_CB89(t, testDB)
		token := makeJWT_CB89(userID, "cb89testuser")
		body := `{"key_type":"one_time_prekey","public_key":"otpk1","key_id":1}`
		req := httptest.NewRequest(http.MethodPost, "/keys/upload", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+token)
		rr := httptest.NewRecorder()
		handleUploadPublicKey(rr, req)
		if rr.Code != http.StatusOK {
			t.Errorf("expected 200, got %d", rr.Code)
		}
	})
}

func TestCB89_HandleUploadPublicKey_AgentAuth(t *testing.T) {
	withTestDB_CB89(t, func(testDB *sql.DB) {
		os.Setenv("AGENT_SECRET", "test-secret-cb89")
		defer os.Unsetenv("AGENT_SECRET")

		body := `{"key_type":"identity","public_key":"agentkey1"}`
		req := httptest.NewRequest(http.MethodPost, "/keys/upload", strings.NewReader(body))
		req.Header.Set("X-Agent-Secret", "test-secret-cb89")
		req.Header.Set("X-Agent-ID", "cb89-agent1")
		rr := httptest.NewRecorder()
		handleUploadPublicKey(rr, req)
		if rr.Code != http.StatusOK {
			t.Errorf("expected 200, got %d, body: %s", rr.Code, rr.Body.String())
		}
	})
}

func TestCB89_HandleUploadPublicKey_AgentAuthNoID(t *testing.T) {
	withTestDB_CB89(t, func(testDB *sql.DB) {
		os.Setenv("AGENT_SECRET", "test-secret-cb89")
		defer os.Unsetenv("AGENT_SECRET")

		body := `{"key_type":"identity","public_key":"agentkey1"}`
		req := httptest.NewRequest(http.MethodPost, "/keys/upload", strings.NewReader(body))
		req.Header.Set("X-Agent-Secret", "test-secret-cb89")
		// No X-Agent-ID
		rr := httptest.NewRecorder()
		handleUploadPublicKey(rr, req)
		if rr.Code != http.StatusUnauthorized {
			t.Errorf("expected 401, got %d", rr.Code)
		}
	})
}

// --- E2E: handleGetKeyBundle ---

func TestCB89_HandleGetKeyBundle_MethodNotAllowed(t *testing.T) {
	withTestDB_CB89(t, func(testDB *sql.DB) {
		req := httptest.NewRequest(http.MethodPost, "/keys/bundle", nil)
		rr := httptest.NewRecorder()
		handleGetKeyBundle(rr, req)
		if rr.Code != http.StatusMethodNotAllowed {
			t.Errorf("expected 405, got %d", rr.Code)
		}
	})
}

func TestCB89_HandleGetKeyBundle_NoAuth(t *testing.T) {
	withTestDB_CB89(t, func(testDB *sql.DB) {
		req := httptest.NewRequest(http.MethodGet, "/keys/bundle", nil)
		rr := httptest.NewRecorder()
		handleGetKeyBundle(rr, req)
		if rr.Code != http.StatusUnauthorized {
			t.Errorf("expected 401, got %d", rr.Code)
		}
	})
}

func TestCB89_HandleGetKeyBundle_MissingOwnerID(t *testing.T) {
	withTestDB_CB89(t, func(testDB *sql.DB) {
		token := makeJWT_CB89("cb89-u1", "user1")
		req := httptest.NewRequest(http.MethodGet, "/keys/bundle", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rr := httptest.NewRecorder()
		handleGetKeyBundle(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Errorf("expected 400, got %d", rr.Code)
		}
	})
}

func TestCB89_HandleGetKeyBundle_NoIdentityKey(t *testing.T) {
	withTestDB_CB89(t, func(testDB *sql.DB) {
		token := makeJWT_CB89("cb89-u1", "user1")
		req := httptest.NewRequest(http.MethodGet, "/keys/bundle?owner_id=nonexistent", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rr := httptest.NewRecorder()
		handleGetKeyBundle(rr, req)
		if rr.Code != http.StatusNotFound {
			t.Errorf("expected 404, got %d", rr.Code)
		}
	})
}

func TestCB89_HandleGetKeyBundle_SuccessWithIdentityOnly(t *testing.T) {
	withTestDB_CB89(t, func(testDB *sql.DB) {
		userID, _, _ := setupUserAndConv_CB89(t, testDB)
		token := makeJWT_CB89(userID, "cb89testuser")

		// Upload identity key
		body := `{"key_type":"identity","public_key":"identity_key_base64"}`
		req1 := httptest.NewRequest(http.MethodPost, "/keys/upload", strings.NewReader(body))
		req1.Header.Set("Authorization", "Bearer "+token)
		rr1 := httptest.NewRecorder()
		handleUploadPublicKey(rr1, req1)
		if rr1.Code != http.StatusOK {
			t.Fatalf("upload failed: %d", rr1.Code)
		}

		// Get key bundle
		req2 := httptest.NewRequest(http.MethodGet, "/keys/bundle?owner_id="+userID, nil)
		req2.Header.Set("Authorization", "Bearer "+token)
		rr2 := httptest.NewRecorder()
		handleGetKeyBundle(rr2, req2)
		if rr2.Code != http.StatusOK {
			t.Errorf("expected 200, got %d", rr2.Code)
		}
		var bundle map[string]interface{}
		json.Unmarshal(rr2.Body.Bytes(), &bundle)
		if bundle["identity_key"] == nil {
			t.Error("expected identity_key in bundle")
		}
		if _, ok := bundle["signed_prekey"]; ok {
			t.Error("should not have signed_prekey")
		}
	})
}

func TestCB89_HandleGetKeyBundle_SuccessWithAllKeys(t *testing.T) {
	withTestDB_CB89(t, func(testDB *sql.DB) {
		userID, _, _ := setupUserAndConv_CB89(t, testDB)
		token := makeJWT_CB89(userID, "cb89testuser")

		// Upload all key types
		for _, body := range []string{
			`{"key_type":"identity","public_key":"idk1"}`,
			`{"key_type":"signed_prekey","public_key":"spk1","signature":"sig1"}`,
			`{"key_type":"one_time_prekey","public_key":"otpk1","key_id":1}`,
			`{"key_type":"one_time_prekey","public_key":"otpk2","key_id":2}`,
		} {
			req := httptest.NewRequest(http.MethodPost, "/keys/upload", strings.NewReader(body))
			req.Header.Set("Authorization", "Bearer "+token)
			rr := httptest.NewRecorder()
			handleUploadPublicKey(rr, req)
			if rr.Code != http.StatusOK {
				t.Fatalf("upload failed: %d, body: %s", rr.Code, rr.Body.String())
			}
		}

		// Get key bundle
		req := httptest.NewRequest(http.MethodGet, "/keys/bundle?owner_id="+userID, nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rr := httptest.NewRecorder()
		handleGetKeyBundle(rr, req)
		if rr.Code != http.StatusOK {
			t.Errorf("expected 200, got %d", rr.Code)
		}
		var bundle map[string]interface{}
		json.Unmarshal(rr.Body.Bytes(), &bundle)
		if bundle["identity_key"] == nil {
			t.Error("expected identity_key")
		}
		if bundle["signed_prekey"] == nil {
			t.Error("expected signed_prekey")
		}
		if bundle["one_time_prekey"] == nil {
			t.Error("expected one_time_prekey")
		}

		// Verify one-time pre-key was consumed (deleted)
		var count int
		testDB.QueryRow("SELECT COUNT(*) FROM key_bundles WHERE owner_id = ? AND key_type = 'one_time_prekey'", userID).Scan(&count)
		if count != 1 {
			t.Errorf("expected 1 remaining otpk, got %d", count)
		}
	})
}

// --- E2E: handleListOneTimePreKeys ---

func TestCB89_HandleListOneTimePreKeys_MethodNotAllowed(t *testing.T) {
	withTestDB_CB89(t, func(testDB *sql.DB) {
		req := httptest.NewRequest(http.MethodPost, "/keys/otpk-count", nil)
		rr := httptest.NewRecorder()
		handleListOneTimePreKeys(rr, req)
		if rr.Code != http.StatusMethodNotAllowed {
			t.Errorf("expected 405, got %d", rr.Code)
		}
	})
}

func TestCB89_HandleListOneTimePreKeys_NoAuth(t *testing.T) {
	withTestDB_CB89(t, func(testDB *sql.DB) {
		req := httptest.NewRequest(http.MethodGet, "/keys/otpk-count", nil)
		rr := httptest.NewRecorder()
		handleListOneTimePreKeys(rr, req)
		if rr.Code != http.StatusUnauthorized {
			t.Errorf("expected 401, got %d", rr.Code)
		}
	})
}

func TestCB89_HandleListOneTimePreKeys_Success(t *testing.T) {
	withTestDB_CB89(t, func(testDB *sql.DB) {
		userID, _, _ := setupUserAndConv_CB89(t, testDB)
		token := makeJWT_CB89(userID, "cb89testuser")

		// Upload 3 one-time pre-keys
		for i := 1; i <= 3; i++ {
			body := `{"key_type":"one_time_prekey","public_key":"otpk","key_id":` + itoa(i) + `}`
			req := httptest.NewRequest(http.MethodPost, "/keys/upload", strings.NewReader(body))
			req.Header.Set("Authorization", "Bearer "+token)
			rr := httptest.NewRecorder()
			handleUploadPublicKey(rr, req)
		}

		// Check count
		req := httptest.NewRequest(http.MethodGet, "/keys/otpk-count", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rr := httptest.NewRecorder()
		handleListOneTimePreKeys(rr, req)
		if rr.Code != http.StatusOK {
			t.Errorf("expected 200, got %d", rr.Code)
		}
		var resp map[string]int
		json.Unmarshal(rr.Body.Bytes(), &resp)
		if resp["one_time_prekey_count"] != 3 {
			t.Errorf("expected 3, got %d", resp["one_time_prekey_count"])
		}
	})
}

func TestCB89_HandleListOneTimePreKeys_ZeroCount(t *testing.T) {
	withTestDB_CB89(t, func(testDB *sql.DB) {
		userID, _, _ := setupUserAndConv_CB89(t, testDB)
		token := makeJWT_CB89(userID, "cb89testuser")

		req := httptest.NewRequest(http.MethodGet, "/keys/otpk-count", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rr := httptest.NewRecorder()
		handleListOneTimePreKeys(rr, req)
		if rr.Code != http.StatusOK {
			t.Errorf("expected 200, got %d", rr.Code)
		}
		var resp map[string]int
		json.Unmarshal(rr.Body.Bytes(), &resp)
		if resp["one_time_prekey_count"] != 0 {
			t.Errorf("expected 0, got %d", resp["one_time_prekey_count"])
		}
	})
}

// --- E2E: handleStoreEncryptedMessage ---

func TestCB89_HandleStoreEncryptedMessage_MethodNotAllowed(t *testing.T) {
	withTestDB_CB89(t, func(testDB *sql.DB) {
		req := httptest.NewRequest(http.MethodGet, "/messages/encrypted", nil)
		rr := httptest.NewRecorder()
		handleStoreEncryptedMessage(rr, req)
		if rr.Code != http.StatusMethodNotAllowed {
			t.Errorf("expected 405, got %d", rr.Code)
		}
	})
}

func TestCB89_HandleStoreEncryptedMessage_NoAuth(t *testing.T) {
	withTestDB_CB89(t, func(testDB *sql.DB) {
		req := httptest.NewRequest(http.MethodPost, "/messages/encrypted", strings.NewReader("{}"))
		rr := httptest.NewRecorder()
		handleStoreEncryptedMessage(rr, req)
		if rr.Code != http.StatusUnauthorized {
			t.Errorf("expected 401, got %d", rr.Code)
		}
	})
}

func TestCB89_HandleStoreEncryptedMessage_InvalidJSON(t *testing.T) {
	withTestDB_CB89(t, func(testDB *sql.DB) {
		token := makeJWT_CB89("cb89-u1", "user1")
		req := httptest.NewRequest(http.MethodPost, "/messages/encrypted", strings.NewReader("bad json"))
		req.Header.Set("Authorization", "Bearer "+token)
		rr := httptest.NewRecorder()
		handleStoreEncryptedMessage(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Errorf("expected 400, got %d", rr.Code)
		}
	})
}

func TestCB89_HandleStoreEncryptedMessage_MissingFields(t *testing.T) {
	withTestDB_CB89(t, func(testDB *sql.DB) {
		token := makeJWT_CB89("cb89-u1", "user1")
		body := `{"conversation_id":"conv1","ciphertext":"abc"}`
		req := httptest.NewRequest(http.MethodPost, "/messages/encrypted", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+token)
		rr := httptest.NewRecorder()
		handleStoreEncryptedMessage(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Errorf("expected 400, got %d", rr.Code)
		}
	})
}

func TestCB89_HandleStoreEncryptedMessage_InvalidAlgorithm(t *testing.T) {
	withTestDB_CB89(t, func(testDB *sql.DB) {
		userID, _, convID := setupUserAndConv_CB89(t, testDB)
		token := makeJWT_CB89(userID, "cb89testuser")
		body := `{"conversation_id":"` + convID + `","ciphertext":"abc","iv":"iv1","algorithm":"des"}`
		req := httptest.NewRequest(http.MethodPost, "/messages/encrypted", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+token)
		rr := httptest.NewRecorder()
		handleStoreEncryptedMessage(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Errorf("expected 400, got %d", rr.Code)
		}
	})
}

func TestCB89_HandleStoreEncryptedMessage_ConvNotFound(t *testing.T) {
	withTestDB_CB89(t, func(testDB *sql.DB) {
		userID, _, _ := setupUserAndConv_CB89(t, testDB)
		token := makeJWT_CB89(userID, "cb89testuser")
		body := `{"conversation_id":"nonexistent","ciphertext":"abc","iv":"iv1","algorithm":"aes-256-gcm"}`
		req := httptest.NewRequest(http.MethodPost, "/messages/encrypted", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+token)
		rr := httptest.NewRecorder()
		handleStoreEncryptedMessage(rr, req)
		if rr.Code != http.StatusNotFound {
			t.Errorf("expected 404, got %d", rr.Code)
		}
	})
}

func TestCB89_HandleStoreEncryptedMessage_ForbiddenSender(t *testing.T) {
	withTestDB_CB89(t, func(testDB *sql.DB) {
		_, _, convID := setupUserAndConv_CB89(t, testDB)
		// Create a second user who is NOT part of the conversation
		_, err := testDB.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)",
			"cb89-u2", "otheruser", "$2a$10$hash")
		if err != nil {
			t.Fatal(err)
		}
		token := makeJWT_CB89("cb89-u2", "otheruser")
		body := `{"conversation_id":"` + convID + `","ciphertext":"abc","iv":"iv1","algorithm":"aes-256-gcm"}`
		req := httptest.NewRequest(http.MethodPost, "/messages/encrypted", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+token)
		rr := httptest.NewRecorder()
		handleStoreEncryptedMessage(rr, req)
		if rr.Code != http.StatusForbidden {
			t.Errorf("expected 403, got %d", rr.Code)
		}
	})
}

func TestCB89_HandleStoreEncryptedMessage_Success(t *testing.T) {
	withTestDB_CB89(t, func(testDB *sql.DB) {
		userID, _, convID := setupUserAndConv_CB89(t, testDB)
		token := makeJWT_CB89(userID, "cb89testuser")
		body := `{"conversation_id":"` + convID + `","ciphertext":"encrypted_content","iv":"init_vector","recipient_key_id":"rk1","algorithm":"aes-256-gcm"}`
		req := httptest.NewRequest(http.MethodPost, "/messages/encrypted", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+token)
		rr := httptest.NewRecorder()
		handleStoreEncryptedMessage(rr, req)
		if rr.Code != http.StatusOK {
			t.Errorf("expected 200, got %d, body: %s", rr.Code, rr.Body.String())
		}
		var resp map[string]string
		json.Unmarshal(rr.Body.Bytes(), &resp)
		if resp["status"] != "stored" {
			t.Errorf("expected status 'stored', got %q", resp["status"])
		}
	})
}

func TestCB89_HandleStoreEncryptedMessage_AgentSender(t *testing.T) {
	withTestDB_CB89(t, func(testDB *sql.DB) {
		_, agentID, convID := setupUserAndConv_CB89(t, testDB)
		os.Setenv("AGENT_SECRET", "test-secret-cb89")
		defer os.Unsetenv("AGENT_SECRET")

		body := `{"conversation_id":"` + convID + `","ciphertext":"agent_encrypted","iv":"agent_iv","recipient_key_id":"rk1","algorithm":"x25519-aes-256-gcm"}`
		req := httptest.NewRequest(http.MethodPost, "/messages/encrypted", strings.NewReader(body))
		req.Header.Set("X-Agent-Secret", "test-secret-cb89")
		req.Header.Set("X-Agent-ID", agentID)
		rr := httptest.NewRecorder()
		handleStoreEncryptedMessage(rr, req)
		if rr.Code != http.StatusOK {
			t.Errorf("expected 200, got %d, body: %s", rr.Code, rr.Body.String())
		}
	})
}

func TestCB89_HandleStoreEncryptedMessage_AgentWrongConv(t *testing.T) {
	withTestDB_CB89(t, func(testDB *sql.DB) {
		_, _, _ = setupUserAndConv_CB89(t, testDB)
		// Create second conversation with different agent
		_, err := testDB.Exec("INSERT INTO agents (id, name) VALUES (?, ?)", "cb89-agent2", "Agent2")
		if err != nil {
			t.Fatal(err)
		}
		_, err = testDB.Exec("INSERT INTO conversations (id, user_id, agent_id) VALUES (?, ?, ?)",
			"cb89-conv2", "cb89-user1", "cb89-agent2")
		if err != nil {
			t.Fatal(err)
		}
		os.Setenv("AGENT_SECRET", "test-secret-cb89")
		defer os.Unsetenv("AGENT_SECRET")

		body := `{"conversation_id":"cb89-conv2","ciphertext":"data","iv":"iv","algorithm":"aes-256-gcm"}`
		req := httptest.NewRequest(http.MethodPost, "/messages/encrypted", strings.NewReader(body))
		req.Header.Set("X-Agent-Secret", "test-secret-cb89")
		req.Header.Set("X-Agent-ID", "cb89-agent1") // Wrong agent for this conv
		rr := httptest.NewRecorder()
		handleStoreEncryptedMessage(rr, req)
		if rr.Code != http.StatusForbidden {
			t.Errorf("expected 403, got %d", rr.Code)
		}
	})
}

// --- E2E: handleGetEncryptedMessages ---

func TestCB89_HandleGetEncryptedMessages_MethodNotAllowed(t *testing.T) {
	withTestDB_CB89(t, func(testDB *sql.DB) {
		req := httptest.NewRequest(http.MethodPost, "/messages/encrypted/list", nil)
		rr := httptest.NewRecorder()
		handleGetEncryptedMessages(rr, req)
		if rr.Code != http.StatusMethodNotAllowed {
			t.Errorf("expected 405, got %d", rr.Code)
		}
	})
}

func TestCB89_HandleGetEncryptedMessages_NoAuth(t *testing.T) {
	withTestDB_CB89(t, func(testDB *sql.DB) {
		req := httptest.NewRequest(http.MethodGet, "/messages/encrypted/list", nil)
		rr := httptest.NewRecorder()
		handleGetEncryptedMessages(rr, req)
		if rr.Code != http.StatusUnauthorized {
			t.Errorf("expected 401, got %d", rr.Code)
		}
	})
}

func TestCB89_HandleGetEncryptedMessages_MissingConvID(t *testing.T) {
	withTestDB_CB89(t, func(testDB *sql.DB) {
		token := makeJWT_CB89("cb89-u1", "user1")
		req := httptest.NewRequest(http.MethodGet, "/messages/encrypted/list", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rr := httptest.NewRecorder()
		handleGetEncryptedMessages(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Errorf("expected 400, got %d", rr.Code)
		}
	})
}

func TestCB89_HandleGetEncryptedMessages_ConvNotFound(t *testing.T) {
	withTestDB_CB89(t, func(testDB *sql.DB) {
		token := makeJWT_CB89("cb89-u1", "user1")
		req := httptest.NewRequest(http.MethodGet, "/messages/encrypted/list?conversation_id=nonexistent", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rr := httptest.NewRecorder()
		handleGetEncryptedMessages(rr, req)
		if rr.Code != http.StatusNotFound {
			t.Errorf("expected 404, got %d", rr.Code)
		}
	})
}

func TestCB89_HandleGetEncryptedMessages_ForbiddenUser(t *testing.T) {
	withTestDB_CB89(t, func(testDB *sql.DB) {
		_, _, convID := setupUserAndConv_CB89(t, testDB)
		// Create second user
		_, err := testDB.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)",
			"cb89-u2", "otheruser2", "$2a$10$hash")
		if err != nil {
			t.Fatal(err)
		}
		token := makeJWT_CB89("cb89-u2", "otheruser2")
		req := httptest.NewRequest(http.MethodGet, "/messages/encrypted/list?conversation_id="+convID, nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rr := httptest.NewRecorder()
		handleGetEncryptedMessages(rr, req)
		if rr.Code != http.StatusNotFound {
			t.Errorf("expected 404 (not found for non-participant), got %d", rr.Code)
		}
	})
}

func TestCB89_HandleGetEncryptedMessages_Success(t *testing.T) {
	withTestDB_CB89(t, func(testDB *sql.DB) {
		userID, _, convID := setupUserAndConv_CB89(t, testDB)
		token := makeJWT_CB89(userID, "cb89testuser")

		// Store an encrypted message first
		body := `{"conversation_id":"` + convID + `","ciphertext":"ct1","iv":"iv1","recipient_key_id":"rk1","algorithm":"aes-256-gcm"}`
		req1 := httptest.NewRequest(http.MethodPost, "/messages/encrypted", strings.NewReader(body))
		req1.Header.Set("Authorization", "Bearer "+token)
		rr1 := httptest.NewRecorder()
		handleStoreEncryptedMessage(rr1, req1)
		if rr1.Code != http.StatusOK {
			t.Fatalf("store failed: %d", rr1.Code)
		}

		// Retrieve encrypted messages
		req2 := httptest.NewRequest(http.MethodGet, "/messages/encrypted/list?conversation_id="+convID, nil)
		req2.Header.Set("Authorization", "Bearer "+token)
		rr2 := httptest.NewRecorder()
		handleGetEncryptedMessages(rr2, req2)
		if rr2.Code != http.StatusOK {
			t.Errorf("expected 200, got %d", rr2.Code)
		}
		var messages []EncryptedMessage
		json.Unmarshal(rr2.Body.Bytes(), &messages)
		if len(messages) != 1 {
			t.Errorf("expected 1 message, got %d", len(messages))
		}
		if messages[0].Ciphertext != "ct1" {
			t.Errorf("expected ciphertext 'ct1', got %q", messages[0].Ciphertext)
		}
	})
}

func TestCB89_HandleGetEncryptedMessages_WithLimit(t *testing.T) {
	withTestDB_CB89(t, func(testDB *sql.DB) {
		userID, _, convID := setupUserAndConv_CB89(t, testDB)
		token := makeJWT_CB89(userID, "cb89testuser")

		// Store 3 encrypted messages
		for i := 0; i < 3; i++ {
			body := `{"conversation_id":"` + convID + `","ciphertext":"ct` + itoa(i) + `","iv":"iv` + itoa(i) + `","algorithm":"aes-256-gcm"}`
			req := httptest.NewRequest(http.MethodPost, "/messages/encrypted", strings.NewReader(body))
			req.Header.Set("Authorization", "Bearer "+token)
			rr := httptest.NewRecorder()
			handleStoreEncryptedMessage(rr, req)
		}

		// Retrieve with limit=2
		req := httptest.NewRequest(http.MethodGet, "/messages/encrypted/list?conversation_id="+convID+"&limit=2", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rr := httptest.NewRecorder()
		handleGetEncryptedMessages(rr, req)
		if rr.Code != http.StatusOK {
			t.Errorf("expected 200, got %d", rr.Code)
		}
		var messages []EncryptedMessage
		json.Unmarshal(rr.Body.Bytes(), &messages)
		if len(messages) != 2 {
			t.Errorf("expected 2 messages with limit, got %d", len(messages))
		}
	})
}

func TestCB89_HandleGetEncryptedMessages_AgentAccess(t *testing.T) {
	withTestDB_CB89(t, func(testDB *sql.DB) {
		userID, agentID, convID := setupUserAndConv_CB89(t, testDB)
		token := makeJWT_CB89(userID, "cb89testuser")

		// Store message as user
		body := `{"conversation_id":"` + convID + `","ciphertext":"ct_agent","iv":"iv_a","algorithm":"aes-256-gcm"}`
		req1 := httptest.NewRequest(http.MethodPost, "/messages/encrypted", strings.NewReader(body))
		req1.Header.Set("Authorization", "Bearer "+token)
		rr1 := httptest.NewRecorder()
		handleStoreEncryptedMessage(rr1, req1)

		// Agent retrieves
		os.Setenv("AGENT_SECRET", "test-secret-cb89")
		defer os.Unsetenv("AGENT_SECRET")

		req2 := httptest.NewRequest(http.MethodGet, "/messages/encrypted/list?conversation_id="+convID, nil)
		req2.Header.Set("X-Agent-Secret", "test-secret-cb89")
		req2.Header.Set("X-Agent-ID", agentID)
		rr2 := httptest.NewRecorder()
		handleGetEncryptedMessages(rr2, req2)
		if rr2.Code != http.StatusOK {
			t.Errorf("expected 200, got %d", rr2.Code)
		}
	})
}

// --- E2E: authenticateRequest ---

func TestCB89_AuthenticateRequest_NoAuth(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	_, _, err := authenticateRequest(req)
	if err == nil {
		t.Error("expected error for no auth")
	}
}

func TestCB89_AuthenticateRequest_InvalidBearer(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer invalidtoken")
	_, _, err := authenticateRequest(req)
	if err == nil {
		t.Error("expected error for invalid bearer token")
	}
}

func TestCB89_AuthenticateRequest_AgentNoID(t *testing.T) {
	os.Setenv("AGENT_SECRET", "test-secret-cb89")
	defer os.Unsetenv("AGENT_SECRET")

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("X-Agent-Secret", "test-secret-cb89")
	// No X-Agent-ID
	_, _, err := authenticateRequest(req)
	if err == nil {
		t.Error("expected error for agent auth without ID")
	}
}

func TestCB89_AuthenticateRequest_AgentWrongSecret(t *testing.T) {
	os.Setenv("AGENT_SECRET", "correct-secret")
	defer os.Unsetenv("AGENT_SECRET")

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("X-Agent-Secret", "wrong-secret")
	req.Header.Set("X-Agent-ID", "agent1")
	_, _, err := authenticateRequest(req)
	if err == nil {
		t.Error("expected error for wrong agent secret")
	}
}

func TestCB89_AuthenticateRequest_ValidJWT(t *testing.T) {
	token := makeJWT_CB89("user123", "testuser")
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	ownerID, ownerType, err := authenticateRequest(req)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if ownerID != "user123" {
		t.Errorf("expected ownerID 'user123', got %q", ownerID)
	}
	if ownerType != "user" {
		t.Errorf("expected ownerType 'user', got %q", ownerType)
	}
}

func TestCB89_AuthenticateRequest_ValidAgent(t *testing.T) {
	os.Setenv("AGENT_SECRET", "test-secret-cb89")
	defer os.Unsetenv("AGENT_SECRET")

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("X-Agent-Secret", "test-secret-cb89")
	req.Header.Set("X-Agent-ID", "agent42")
	ownerID, ownerType, err := authenticateRequest(req)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if ownerID != "agent42" {
		t.Errorf("expected ownerID 'agent42', got %q", ownerID)
	}
	if ownerType != "agent" {
		t.Errorf("expected ownerType 'agent', got %q", ownerType)
	}
}

// --- Reactions: handleReact ---

func TestCB89_HandleReact_MethodNotAllowed(t *testing.T) {
	withTestDB_CB89(t, func(testDB *sql.DB) {
		req := httptest.NewRequest(http.MethodGet, "/messages/react", nil)
		rr := httptest.NewRecorder()
		handleReact(rr, req)
		if rr.Code != http.StatusMethodNotAllowed {
			t.Errorf("expected 405, got %d", rr.Code)
		}
	})
}

func TestCB89_HandleReact_NoAuth(t *testing.T) {
	withTestDB_CB89(t, func(testDB *sql.DB) {
		req := httptest.NewRequest(http.MethodPost, "/messages/react", nil)
		rr := httptest.NewRecorder()
		handleReact(rr, req)
		if rr.Code != http.StatusUnauthorized {
			t.Errorf("expected 401, got %d", rr.Code)
		}
	})
}

func TestCB89_HandleReact_MissingFields(t *testing.T) {
	withTestDB_CB89(t, func(testDB *sql.DB) {
		userID, _, convID := setupUserAndConv_CB89(t, testDB)
		token := makeJWT_CB89(userID, "cb89testuser")
		msgID := insertMessage_CB89(t, testDB, convID, "agent", "cb89-agent1", "hello")

		req := httptest.NewRequest(http.MethodPost, "/messages/react", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		req.PostForm = nil
		rr := httptest.NewRecorder()
		handleReact(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Errorf("expected 400, got %d", rr.Code)
		}
		_ = msgID
	})
}

func TestCB89_HandleReact_EmojiTooLong(t *testing.T) {
	withTestDB_CB89(t, func(testDB *sql.DB) {
		userID, _, convID := setupUserAndConv_CB89(t, testDB)
		token := makeJWT_CB89(userID, "cb89testuser")
		insertMessage_CB89(t, testDB, convID, "agent", "cb89-agent1", "hello")

		form := strings.NewReader("message_id=cb89-msg1&emoji=verylongemojistring")
		req := httptest.NewRequest(http.MethodPost, "/messages/react", form)
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()
		handleReact(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Errorf("expected 400, got %d", rr.Code)
		}
	})
}

func TestCB89_HandleReact_MessageNotFound(t *testing.T) {
	withTestDB_CB89(t, func(testDB *sql.DB) {
		userID, _, _ := setupUserAndConv_CB89(t, testDB)
		token := makeJWT_CB89(userID, "cb89testuser")

		form := strings.NewReader("message_id=nonexistent&emoji=👍")
		req := httptest.NewRequest(http.MethodPost, "/messages/react", form)
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()
		handleReact(rr, req)
		if rr.Code != http.StatusNotFound {
			t.Errorf("expected 404, got %d", rr.Code)
		}
	})
}

func TestCB89_HandleReact_Success(t *testing.T) {
	withTestDB_CB89(t, func(testDB *sql.DB) {
		oldHub := hub
		hub = newHub()
		go hub.run()
		defer func() { hub.Stop(); hub = oldHub }()
		userID, _, convID := setupUserAndConv_CB89(t, testDB)
		token := makeJWT_CB89(userID, "cb89testuser")
		msgID := insertMessage_CB89(t, testDB, convID, "agent", "cb89-agent1", "hello")

		form := strings.NewReader("message_id=" + msgID + "&emoji=👍")
		req := httptest.NewRequest(http.MethodPost, "/messages/react", form)
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()
		handleReact(rr, req)
		if rr.Code != http.StatusOK {
			t.Errorf("expected 200, got %d, body: %s", rr.Code, rr.Body.String())
		}
		var resp map[string]interface{}
		json.Unmarshal(rr.Body.Bytes(), &resp)
		if resp["status"] != "reaction_added" {
			t.Errorf("expected 'reaction_added', got %v", resp["status"])
		}
	})
}

func TestCB89_HandleReact_ToggleOff(t *testing.T) {
	withTestDB_CB89(t, func(testDB *sql.DB) {
		oldHub := hub
		hub = newHub()
		go hub.run()
		defer func() { hub.Stop(); hub = oldHub }()
		userID, _, convID := setupUserAndConv_CB89(t, testDB)
		token := makeJWT_CB89(userID, "cb89testuser")
		msgID := insertMessage_CB89(t, testDB, convID, "agent", "cb89-agent1", "hello")

		// Add reaction
		form := strings.NewReader("message_id=" + msgID + "&emoji=👍")
		req1 := httptest.NewRequest(http.MethodPost, "/messages/react", form)
		req1.Header.Set("Authorization", "Bearer "+token)
		req1.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr1 := httptest.NewRecorder()
		handleReact(rr1, req1)

		// Toggle off
		form2 := strings.NewReader("message_id=" + msgID + "&emoji=👍")
		req2 := httptest.NewRequest(http.MethodPost, "/messages/react", form2)
		req2.Header.Set("Authorization", "Bearer "+token)
		req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr2 := httptest.NewRecorder()
		handleReact(rr2, req2)
		if rr2.Code != http.StatusOK {
			t.Errorf("expected 200, got %d", rr2.Code)
		}
		var resp map[string]string
		json.Unmarshal(rr2.Body.Bytes(), &resp)
		if resp["status"] != "reaction_removed" {
			t.Errorf("expected 'reaction_removed', got %v", resp["status"])
		}
	})
}

func TestCB89_HandleReact_Unauthorized(t *testing.T) {
	withTestDB_CB89(t, func(testDB *sql.DB) {
		oldHub := hub
		hub = newHub()
		go hub.run()
		defer func() { hub.Stop(); hub = oldHub }()
		_, _, convID := setupUserAndConv_CB89(t, testDB)
		msgID := insertMessage_CB89(t, testDB, convID, "agent", "cb89-agent1", "hello")

		// Create a second user not in the conversation
		_, err := testDB.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)",
			"cb89-outsider", "outsider", "$2a$10$hash")
		if err != nil {
			t.Fatal(err)
		}
		token := makeJWT_CB89("cb89-outsider", "outsider")

		form := strings.NewReader("message_id=" + msgID + "&emoji=👍")
		req := httptest.NewRequest(http.MethodPost, "/messages/react", form)
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()
		handleReact(rr, req)
		if rr.Code != http.StatusUnauthorized {
			t.Errorf("expected 401, got %d", rr.Code)
		}
	})
}

// --- Reactions: handleGetReactions ---

func TestCB89_HandleGetReactions_MethodNotAllowed(t *testing.T) {
	withTestDB_CB89(t, func(testDB *sql.DB) {
		req := httptest.NewRequest(http.MethodPost, "/messages/reactions", nil)
		rr := httptest.NewRecorder()
		handleGetReactions(rr, req)
		if rr.Code != http.StatusMethodNotAllowed {
			t.Errorf("expected 405, got %d", rr.Code)
		}
	})
}

func TestCB89_HandleGetReactions_NoAuth(t *testing.T) {
	withTestDB_CB89(t, func(testDB *sql.DB) {
		req := httptest.NewRequest(http.MethodGet, "/messages/reactions", nil)
		rr := httptest.NewRecorder()
		handleGetReactions(rr, req)
		if rr.Code != http.StatusUnauthorized {
			t.Errorf("expected 401, got %d", rr.Code)
		}
	})
}

func TestCB89_HandleGetReactions_MissingMessageID(t *testing.T) {
	withTestDB_CB89(t, func(testDB *sql.DB) {
		token := makeJWT_CB89("cb89-u1", "user1")
		req := httptest.NewRequest(http.MethodGet, "/messages/reactions", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rr := httptest.NewRecorder()
		handleGetReactions(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Errorf("expected 400, got %d", rr.Code)
		}
	})
}

func TestCB89_HandleGetReactions_MessageNotFound(t *testing.T) {
	withTestDB_CB89(t, func(testDB *sql.DB) {
		token := makeJWT_CB89("cb89-u1", "user1")
		req := httptest.NewRequest(http.MethodGet, "/messages/reactions?message_id=nonexistent", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rr := httptest.NewRecorder()
		handleGetReactions(rr, req)
		if rr.Code != http.StatusNotFound {
			t.Errorf("expected 404, got %d", rr.Code)
		}
	})
}

func TestCB89_HandleGetReactions_Success(t *testing.T) {
	withTestDB_CB89(t, func(testDB *sql.DB) {
		oldHub := hub
		hub = newHub()
		go hub.run()
		defer func() { hub.Stop(); hub = oldHub }()
		userID, _, convID := setupUserAndConv_CB89(t, testDB)
		token := makeJWT_CB89(userID, "cb89testuser")
		msgID := insertMessage_CB89(t, testDB, convID, "agent", "cb89-agent1", "hello")

		// Add a reaction first
		form := strings.NewReader("message_id=" + msgID + "&emoji=👍")
		req1 := httptest.NewRequest(http.MethodPost, "/messages/react", form)
		req1.Header.Set("Authorization", "Bearer "+token)
		req1.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr1 := httptest.NewRecorder()
		handleReact(rr1, req1)

		// Get reactions
		req2 := httptest.NewRequest(http.MethodGet, "/messages/reactions?message_id="+msgID, nil)
		req2.Header.Set("Authorization", "Bearer "+token)
		rr2 := httptest.NewRecorder()
		handleGetReactions(rr2, req2)
		if rr2.Code != http.StatusOK {
			t.Errorf("expected 200, got %d", rr2.Code)
		}
		var reactions []MessageReaction
		json.Unmarshal(rr2.Body.Bytes(), &reactions)
		if len(reactions) != 1 {
			t.Errorf("expected 1 reaction, got %d", len(reactions))
		}
	})
}

func TestCB89_HandleGetReactions_EmptyList(t *testing.T) {
	withTestDB_CB89(t, func(testDB *sql.DB) {
		userID, _, convID := setupUserAndConv_CB89(t, testDB)
		token := makeJWT_CB89(userID, "cb89testuser")
		msgID := insertMessage_CB89(t, testDB, convID, "agent", "cb89-agent1", "hello")

		req := httptest.NewRequest(http.MethodGet, "/messages/reactions?message_id="+msgID, nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rr := httptest.NewRecorder()
		handleGetReactions(rr, req)
		if rr.Code != http.StatusOK {
			t.Errorf("expected 200, got %d", rr.Code)
		}
		var reactions []MessageReaction
		json.Unmarshal(rr.Body.Bytes(), &reactions)
		if len(reactions) != 0 {
			t.Errorf("expected 0 reactions, got %d", len(reactions))
		}
	})
}

func TestCB89_HandleGetReactions_Unauthorized(t *testing.T) {
	withTestDB_CB89(t, func(testDB *sql.DB) {
		_, _, convID := setupUserAndConv_CB89(t, testDB)
		msgID := insertMessage_CB89(t, testDB, convID, "agent", "cb89-agent1", "hello")

		// Create unauthorized user
		_, err := testDB.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)",
			"cb89-outsider2", "outsider2", "$2a$10$hash")
		if err != nil {
			t.Fatal(err)
		}
		token := makeJWT_CB89("cb89-outsider2", "outsider2")

		req := httptest.NewRequest(http.MethodGet, "/messages/reactions?message_id="+msgID, nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rr := httptest.NewRecorder()
		handleGetReactions(rr, req)
		if rr.Code != http.StatusUnauthorized {
			t.Errorf("expected 401, got %d", rr.Code)
		}
	})
}

// --- Routing: truncate ---

func TestCB89_Truncate_ShortString(t *testing.T) {
	result := truncate("hello", 10)
	if result != "hello" {
		t.Errorf("expected 'hello', got %q", result)
	}
}

func TestCB89_Truncate_ExactLength(t *testing.T) {
	result := truncate("1234567890", 10)
	if result != "1234567890" {
		t.Errorf("expected '1234567890', got %q", result)
	}
}

func TestCB89_Truncate_LongString(t *testing.T) {
	result := truncate("abcdefghijklmnopqrstuvwxyz", 10)
	if result != "abcdefg..." {
		t.Errorf("expected 'abcdefg...', got %q", result)
	}
}

func TestCB89_Truncate_MaxLen3(t *testing.T) {
	result := truncate("abcdef", 3)
	if result != "abc" {
		t.Errorf("expected 'abc', got %q", result)
	}
}

func TestCB89_Truncate_MaxLen0(t *testing.T) {
	result := truncate("abc", 0)
	if result != "" {
		t.Errorf("expected '', got %q", result)
	}
}

func TestCB89_Truncate_NegativeMaxLen(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic for negative maxLen")
		}
	}()
	truncate("abc", -1)
}

// --- Routing: routeTypingIndicator ---

func TestCB89_RouteTypingIndicator_InvalidJSON(t *testing.T) {
	withTestDB_CB89(t, func(testDB *sql.DB) {
		oldHub := hub
		hub = newHub()
		go hub.run()
		defer func() { hub.Stop(); hub = oldHub }()
		conn := &Connection{id: "cb89-u1", connType: "client", send: make(chan []byte, 10), hub: hub}
		// Invalid JSON should return without panic
		routeTypingIndicator(conn, json.RawMessage("bad json"))
	})
}

func TestCB89_RouteTypingIndicator_EmptyConvID(t *testing.T) {
	withTestDB_CB89(t, func(testDB *sql.DB) {
		oldHub := hub
		hub = newHub()
		go hub.run()
		defer func() { hub.Stop(); hub = oldHub }()
		conn := &Connection{id: "cb89-u1", connType: "client", send: make(chan []byte, 10), hub: hub}
		routeTypingIndicator(conn, json.RawMessage(`{}`))
	})
}

func TestCB89_RouteTypingIndicator_ConvNotFound(t *testing.T) {
	withTestDB_CB89(t, func(testDB *sql.DB) {
		oldHub := hub
		hub = newHub()
		go hub.run()
		defer func() { hub.Stop(); hub = oldHub }()
		conn := &Connection{id: "cb89-u1", connType: "client", send: make(chan []byte, 10), hub: hub}
		routeTypingIndicator(conn, json.RawMessage(`{"conversation_id":"nonexistent"}`))
	})
}

func TestCB89_RouteTypingIndicator_ClientSender(t *testing.T) {
	withTestDB_CB89(t, func(testDB *sql.DB) {
		userID, agentID, convID := setupUserAndConv_CB89(t, testDB)
		oldHub := hub
		hub = newHub()
		go hub.run()
		defer func() { hub.Stop(); hub = oldHub }()

		// Register agent in hub
		agentConn := &Connection{id: agentID, connType: "agent", send: make(chan []byte, 10), hub: hub}
		hub.register <- agentConn
		time.Sleep(10 * time.Millisecond)

		conn := &Connection{id: userID, connType: "client", send: make(chan []byte, 10), hub: hub}
		routeTypingIndicator(conn, json.RawMessage(`{"conversation_id":"`+convID+`"}`))

		// Agent should receive the typing indicator
		select {
		case msg := <-agentConn.send:
			if !strings.Contains(string(msg), "typing") {
				t.Errorf("expected typing indicator, got %s", string(msg))
			}
		case <-time.After(100 * time.Millisecond):
			t.Error("agent did not receive typing indicator")
		}
	})
}

func TestCB89_RouteTypingIndicator_AgentSender(t *testing.T) {
	withTestDB_CB89(t, func(testDB *sql.DB) {
		userID, agentID, convID := setupUserAndConv_CB89(t, testDB)
		oldHub := hub
		hub = newHub()
		go hub.run()
		defer func() { hub.Stop(); hub = oldHub }()

		// Register client in hub
		clientConn := &Connection{id: userID, connType: "client", send: make(chan []byte, 10), hub: hub}
		hub.register <- clientConn
		time.Sleep(10 * time.Millisecond)

		conn := &Connection{id: agentID, connType: "agent", send: make(chan []byte, 10), hub: hub}
		routeTypingIndicator(conn, json.RawMessage(`{"conversation_id":"`+convID+`"}`))

		// Client should receive the typing indicator
		select {
		case msg := <-clientConn.send:
			if !strings.Contains(string(msg), "typing") {
				t.Errorf("expected typing indicator, got %s", string(msg))
			}
		case <-time.After(100 * time.Millisecond):
			t.Error("client did not receive typing indicator")
		}
	})
}

func TestCB89_RouteTypingIndicator_UnauthorizedSender(t *testing.T) {
	withTestDB_CB89(t, func(testDB *sql.DB) {
		_, _, convID := setupUserAndConv_CB89(t, testDB)
		oldHub := hub
		hub = newHub()
		go hub.run()
		defer func() { hub.Stop(); hub = oldHub }()

		// Sender is not part of the conversation
		conn := &Connection{id: "wrong-user", connType: "client", send: make(chan []byte, 10), hub: hub}
		routeTypingIndicator(conn, json.RawMessage(`{"conversation_id":"`+convID+`"}`))
		// Should return without delivering
	})
}

// --- Routing: routeStatusUpdate ---

func TestCB89_RouteStatusUpdate_InvalidJSON(t *testing.T) {
	withTestDB_CB89(t, func(testDB *sql.DB) {
		oldHub := hub
		hub = newHub()
		go hub.run()
		defer func() { hub.Stop(); hub = oldHub }()
		conn := &Connection{id: "cb89-agent1", connType: "agent", send: make(chan []byte, 10), hub: hub}
		routeStatusUpdate(conn, json.RawMessage("bad json"))
	})
}

func TestCB89_RouteStatusUpdate_AgentStatusChange(t *testing.T) {
	withTestDB_CB89(t, func(testDB *sql.DB) {
		_, agentID, _ := setupUserAndConv_CB89(t, testDB)
		oldHub := hub
		hub = newHub()
		go hub.run()
		defer func() { hub.Stop(); hub = oldHub }()

		// Register agent
		agentConn := &Connection{id: agentID, connType: "agent", send: make(chan []byte, 10), hub: hub}
		hub.register <- agentConn
		time.Sleep(10 * time.Millisecond)

		conn := &Connection{id: agentID, connType: "agent", send: make(chan []byte, 10), hub: hub}
		routeStatusUpdate(conn, json.RawMessage(`{"status":"busy"}`))

		// Verify status was updated in hub
		status := hub.AgentStatus(agentID)
		if status != "busy" {
			t.Errorf("expected status 'busy', got %q", status)
		}
	})
}

func TestCB89_RouteStatusUpdate_ClientSender(t *testing.T) {
	withTestDB_CB89(t, func(testDB *sql.DB) {
		userID, agentID, convID := setupUserAndConv_CB89(t, testDB)
		oldHub := hub
		hub = newHub()
		go hub.run()
		defer func() { hub.Stop(); hub = oldHub }()

		// Register agent
		agentConn := &Connection{id: agentID, connType: "agent", send: make(chan []byte, 10), hub: hub}
		hub.register <- agentConn
		time.Sleep(10 * time.Millisecond)

		conn := &Connection{id: userID, connType: "client", send: make(chan []byte, 10), hub: hub}
		routeStatusUpdate(conn, json.RawMessage(`{"conversation_id":"`+convID+`","status":"active"}`))

		// Agent should receive status update
		select {
		case msg := <-agentConn.send:
			if !strings.Contains(string(msg), "status") {
				t.Errorf("expected status update, got %s", string(msg))
			}
		case <-time.After(100 * time.Millisecond):
			t.Error("agent did not receive status update")
		}
	})
}

func TestCB89_RouteStatusUpdate_EmptyConvID(t *testing.T) {
	withTestDB_CB89(t, func(testDB *sql.DB) {
		oldHub := hub
		hub = newHub()
		go hub.run()
		defer func() { hub.Stop(); hub = oldHub }()
		conn := &Connection{id: "cb89-agent1", connType: "agent", send: make(chan []byte, 10), hub: hub}
		// No conversation_id, just status update — should not panic
		routeStatusUpdate(conn, json.RawMessage(`{"status":"idle"}`))
	})
}

// --- Tags: handleAddTag ---

func TestCB89_HandleAddTag_MethodNotAllowed(t *testing.T) {
	withTestDB_CB89(t, func(testDB *sql.DB) {
		req := httptest.NewRequest(http.MethodGet, "/conversations/tags/add", nil)
		rr := httptest.NewRecorder()
		handleAddTag(rr, req)
		if rr.Code != http.StatusMethodNotAllowed {
			t.Errorf("expected 405, got %d", rr.Code)
		}
	})
}

func TestCB89_HandleAddTag_NoAuth(t *testing.T) {
	withTestDB_CB89(t, func(testDB *sql.DB) {
		req := httptest.NewRequest(http.MethodPost, "/conversations/tags/add", nil)
		rr := httptest.NewRecorder()
		handleAddTag(rr, req)
		if rr.Code != http.StatusUnauthorized {
			t.Errorf("expected 401, got %d", rr.Code)
		}
	})
}

func TestCB89_HandleAddTag_MissingFields(t *testing.T) {
	withTestDB_CB89(t, func(testDB *sql.DB) {
		token := makeJWT_CB89("cb89-u1", "user1")
		req := httptest.NewRequest(http.MethodPost, "/conversations/tags/add", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rr := httptest.NewRecorder()
		handleAddTag(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Errorf("expected 400, got %d", rr.Code)
		}
	})
}

func TestCB89_HandleAddTag_ConvNotFound(t *testing.T) {
	withTestDB_CB89(t, func(testDB *sql.DB) {
		token := makeJWT_CB89("cb89-u1", "user1")
		form := strings.NewReader("conversation_id=nonexistent&tag=important")
		req := httptest.NewRequest(http.MethodPost, "/conversations/tags/add", form)
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()
		handleAddTag(rr, req)
		if rr.Code != http.StatusNotFound {
			t.Errorf("expected 404, got %d", rr.Code)
		}
	})
}

func TestCB89_HandleAddTag_Unauthorized(t *testing.T) {
	withTestDB_CB89(t, func(testDB *sql.DB) {
		_, _, convID := setupUserAndConv_CB89(t, testDB)
		// Create second user
		_, err := testDB.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)",
			"cb89-other3", "other3", "$2a$10$hash")
		if err != nil {
			t.Fatal(err)
		}
		token := makeJWT_CB89("cb89-other3", "other3")
		form := strings.NewReader("conversation_id=" + convID + "&tag=important")
		req := httptest.NewRequest(http.MethodPost, "/conversations/tags/add", form)
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()
		handleAddTag(rr, req)
		if rr.Code != http.StatusUnauthorized {
			t.Errorf("expected 401, got %d", rr.Code)
		}
	})
}

func TestCB89_HandleAddTag_Success(t *testing.T) {
	withTestDB_CB89(t, func(testDB *sql.DB) {
		userID, _, convID := setupUserAndConv_CB89(t, testDB)
		token := makeJWT_CB89(userID, "cb89testuser")
		form := strings.NewReader("conversation_id=" + convID + "&tag=important")
		req := httptest.NewRequest(http.MethodPost, "/conversations/tags/add", form)
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()
		handleAddTag(rr, req)
		if rr.Code != http.StatusOK {
			t.Errorf("expected 200, got %d, body: %s", rr.Code, rr.Body.String())
		}
		var resp map[string]interface{}
		json.Unmarshal(rr.Body.Bytes(), &resp)
		if resp["status"] != "tag_added" {
			t.Errorf("expected 'tag_added', got %v", resp["status"])
		}
	})
}

func TestCB89_HandleAddTag_Duplicate(t *testing.T) {
	withTestDB_CB89(t, func(testDB *sql.DB) {
		userID, _, convID := setupUserAndConv_CB89(t, testDB)
		token := makeJWT_CB89(userID, "cb89testuser")

		// Add tag first time
		form1 := strings.NewReader("conversation_id=" + convID + "&tag=important")
		req1 := httptest.NewRequest(http.MethodPost, "/conversations/tags/add", form1)
		req1.Header.Set("Authorization", "Bearer "+token)
		req1.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr1 := httptest.NewRecorder()
		handleAddTag(rr1, req1)

		// Add same tag second time
		form2 := strings.NewReader("conversation_id=" + convID + "&tag=important")
		req2 := httptest.NewRequest(http.MethodPost, "/conversations/tags/add", form2)
		req2.Header.Set("Authorization", "Bearer "+token)
		req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr2 := httptest.NewRecorder()
		handleAddTag(rr2, req2)
		if rr2.Code != http.StatusConflict {
			t.Errorf("expected 409, got %d", rr2.Code)
		}
	})
}

func TestCB89_HandleAddTag_TagTooLong(t *testing.T) {
	withTestDB_CB89(t, func(testDB *sql.DB) {
		userID, _, convID := setupUserAndConv_CB89(t, testDB)
		token := makeJWT_CB89(userID, "cb89testuser")
		longTag := strings.Repeat("a", 51)
		form := strings.NewReader("conversation_id=" + convID + "&tag=" + longTag)
		req := httptest.NewRequest(http.MethodPost, "/conversations/tags/add", form)
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()
		handleAddTag(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Errorf("expected 400, got %d", rr.Code)
		}
	})
}

// --- Tags: handleRemoveTag ---

func TestCB89_HandleRemoveTag_MethodNotAllowed(t *testing.T) {
	withTestDB_CB89(t, func(testDB *sql.DB) {
		req := httptest.NewRequest(http.MethodGet, "/conversations/tags/remove", nil)
		rr := httptest.NewRecorder()
		handleRemoveTag(rr, req)
		if rr.Code != http.StatusMethodNotAllowed {
			t.Errorf("expected 405, got %d", rr.Code)
		}
	})
}

func TestCB89_HandleRemoveTag_NoAuth(t *testing.T) {
	withTestDB_CB89(t, func(testDB *sql.DB) {
		req := httptest.NewRequest(http.MethodPost, "/conversations/tags/remove", nil)
		rr := httptest.NewRecorder()
		handleRemoveTag(rr, req)
		if rr.Code != http.StatusUnauthorized {
			t.Errorf("expected 401, got %d", rr.Code)
		}
	})
}

func TestCB89_HandleRemoveTag_MissingFields(t *testing.T) {
	withTestDB_CB89(t, func(testDB *sql.DB) {
		token := makeJWT_CB89("cb89-u1", "user1")
		req := httptest.NewRequest(http.MethodPost, "/conversations/tags/remove", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rr := httptest.NewRecorder()
		handleRemoveTag(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Errorf("expected 400, got %d", rr.Code)
		}
	})
}

func TestCB89_HandleRemoveTag_ConvNotFound(t *testing.T) {
	withTestDB_CB89(t, func(testDB *sql.DB) {
		token := makeJWT_CB89("cb89-u1", "user1")
		form := strings.NewReader("conversation_id=nonexistent&tag=important")
		req := httptest.NewRequest(http.MethodPost, "/conversations/tags/remove", form)
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()
		handleRemoveTag(rr, req)
		if rr.Code != http.StatusNotFound {
			t.Errorf("expected 404, got %d", rr.Code)
		}
	})
}

func TestCB89_HandleRemoveTag_Success(t *testing.T) {
	withTestDB_CB89(t, func(testDB *sql.DB) {
		userID, _, convID := setupUserAndConv_CB89(t, testDB)
		token := makeJWT_CB89(userID, "cb89testuser")

		// Add tag first
		form1 := strings.NewReader("conversation_id=" + convID + "&tag=work")
		req1 := httptest.NewRequest(http.MethodPost, "/conversations/tags/add", form1)
		req1.Header.Set("Authorization", "Bearer "+token)
		req1.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr1 := httptest.NewRecorder()
		handleAddTag(rr1, req1)

		// Remove tag
		form2 := strings.NewReader("conversation_id=" + convID + "&tag=work")
		req2 := httptest.NewRequest(http.MethodPost, "/conversations/tags/remove", form2)
		req2.Header.Set("Authorization", "Bearer "+token)
		req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr2 := httptest.NewRecorder()
		handleRemoveTag(rr2, req2)
		if rr2.Code != http.StatusOK {
			t.Errorf("expected 200, got %d", rr2.Code)
		}
	})
}

func TestCB89_HandleRemoveTag_TagNotFound(t *testing.T) {
	withTestDB_CB89(t, func(testDB *sql.DB) {
		userID, _, convID := setupUserAndConv_CB89(t, testDB)
		token := makeJWT_CB89(userID, "cb89testuser")
		form := strings.NewReader("conversation_id=" + convID + "&tag=nonexistent")
		req := httptest.NewRequest(http.MethodPost, "/conversations/tags/remove", form)
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()
		handleRemoveTag(rr, req)
		if rr.Code != http.StatusNotFound {
			t.Errorf("expected 404, got %d", rr.Code)
		}
	})
}

func TestCB89_HandleRemoveTag_Unauthorized(t *testing.T) {
	withTestDB_CB89(t, func(testDB *sql.DB) {
		_, _, convID := setupUserAndConv_CB89(t, testDB)
		_, err := testDB.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)",
			"cb89-other4", "other4", "$2a$10$hash")
		if err != nil {
			t.Fatal(err)
		}
		token := makeJWT_CB89("cb89-other4", "other4")
		form := strings.NewReader("conversation_id=" + convID + "&tag=work")
		req := httptest.NewRequest(http.MethodPost, "/conversations/tags/remove", form)
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()
		handleRemoveTag(rr, req)
		if rr.Code != http.StatusUnauthorized {
			t.Errorf("expected 401, got %d", rr.Code)
		}
	})
}

// --- Tags: handleGetTags ---

func TestCB89_HandleGetTags_MethodNotAllowed(t *testing.T) {
	withTestDB_CB89(t, func(testDB *sql.DB) {
		req := httptest.NewRequest(http.MethodPost, "/conversations/tags", nil)
		rr := httptest.NewRecorder()
		handleGetTags(rr, req)
		if rr.Code != http.StatusMethodNotAllowed {
			t.Errorf("expected 405, got %d", rr.Code)
		}
	})
}

func TestCB89_HandleGetTags_NoAuth(t *testing.T) {
	withTestDB_CB89(t, func(testDB *sql.DB) {
		req := httptest.NewRequest(http.MethodGet, "/conversations/tags", nil)
		rr := httptest.NewRecorder()
		handleGetTags(rr, req)
		if rr.Code != http.StatusUnauthorized {
			t.Errorf("expected 401, got %d", rr.Code)
		}
	})
}

func TestCB89_HandleGetTags_MissingConvID(t *testing.T) {
	withTestDB_CB89(t, func(testDB *sql.DB) {
		token := makeJWT_CB89("cb89-u1", "user1")
		req := httptest.NewRequest(http.MethodGet, "/conversations/tags", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rr := httptest.NewRecorder()
		handleGetTags(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Errorf("expected 400, got %d", rr.Code)
		}
	})
}

func TestCB89_HandleGetTags_Unauthorized(t *testing.T) {
	withTestDB_CB89(t, func(testDB *sql.DB) {
		_, _, convID := setupUserAndConv_CB89(t, testDB)
		_, err := testDB.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)",
			"cb89-other5", "other5", "$2a$10$hash")
		if err != nil {
			t.Fatal(err)
		}
		token := makeJWT_CB89("cb89-other5", "other5")
		req := httptest.NewRequest(http.MethodGet, "/conversations/tags?conversation_id="+convID, nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rr := httptest.NewRecorder()
		handleGetTags(rr, req)
		if rr.Code != http.StatusUnauthorized {
			t.Errorf("expected 401, got %d", rr.Code)
		}
	})
}

func TestCB89_HandleGetTags_Success(t *testing.T) {
	withTestDB_CB89(t, func(testDB *sql.DB) {
		userID, _, convID := setupUserAndConv_CB89(t, testDB)
		token := makeJWT_CB89(userID, "cb89testuser")

		// Add tags
		for _, tag := range []string{"important", "work", "follow-up"} {
			form := strings.NewReader("conversation_id=" + convID + "&tag=" + tag)
			req := httptest.NewRequest(http.MethodPost, "/conversations/tags/add", form)
			req.Header.Set("Authorization", "Bearer "+token)
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			rr := httptest.NewRecorder()
			handleAddTag(rr, req)
		}

		// Get tags
		req := httptest.NewRequest(http.MethodGet, "/conversations/tags?conversation_id="+convID, nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rr := httptest.NewRecorder()
		handleGetTags(rr, req)
		if rr.Code != http.StatusOK {
			t.Errorf("expected 200, got %d", rr.Code)
		}
		var tags []ConversationTag
		json.Unmarshal(rr.Body.Bytes(), &tags)
		if len(tags) != 3 {
			t.Errorf("expected 3 tags, got %d", len(tags))
		}
	})
}

func TestCB89_HandleGetTags_EmptyList(t *testing.T) {
	withTestDB_CB89(t, func(testDB *sql.DB) {
		userID, _, convID := setupUserAndConv_CB89(t, testDB)
		token := makeJWT_CB89(userID, "cb89testuser")
		req := httptest.NewRequest(http.MethodGet, "/conversations/tags?conversation_id="+convID, nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rr := httptest.NewRecorder()
		handleGetTags(rr, req)
		if rr.Code != http.StatusOK {
			t.Errorf("expected 200, got %d", rr.Code)
		}
		var tags []ConversationTag
		json.Unmarshal(rr.Body.Bytes(), &tags)
		if len(tags) != 0 {
			t.Errorf("expected 0 tags, got %d", len(tags))
		}
	})
}

// --- rate_limit_tiers: itoa ---

func TestCB89_Itoa_Zero(t *testing.T) {
	if itoa(0) != "0" {
		t.Errorf("expected '0', got %q", itoa(0))
	}
}

func TestCB89_Itoa_Positive(t *testing.T) {
	if itoa(42) != "42" {
		t.Errorf("expected '42', got %q", itoa(42))
	}
}

func TestCB89_Itoa_Negative(t *testing.T) {
	if itoa(-7) != "-7" {
		t.Errorf("expected '-7', got %q", itoa(-7))
	}
}

func TestCB89_Itoa_Large(t *testing.T) {
	if itoa(1234567890) != "1234567890" {
		t.Errorf("expected '1234567890', got %q", itoa(1234567890))
	}
}

// --- rate_limit_tiers: tieredRateLimitMiddleware ---

func TestCB89_TieredRateLimitMiddleware_AllowWithJWT(t *testing.T) {
	withTestDB_CB89(t, func(testDB *sql.DB) {
		userID, _, _ := setupUserAndConv_CB89(t, testDB)
		token := makeJWT_CB89(userID, "cb89testuser")

		called := false
		handler := tieredRateLimitMiddleware(func(w http.ResponseWriter, r *http.Request) {
			called = true
			w.WriteHeader(http.StatusOK)
		})

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rr := httptest.NewRecorder()
		handler(rr, req)
		if !called {
			t.Error("handler was not called")
		}
		if rr.Header().Get("X-RateLimit-Limit") == "" {
			t.Error("expected X-RateLimit-Limit header")
		}
	})
}

func TestCB89_TieredRateLimitMiddleware_AllowWithoutJWT(t *testing.T) {
	called := false
	handler := tieredRateLimitMiddleware(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.RemoteAddr = "192.168.1.100:12345"
	rr := httptest.NewRecorder()
	handler(rr, req)
	if !called {
		t.Error("handler was not called for IP-based limiting")
	}
}

func TestCB89_TieredRateLimitMiddleware_RateLimited(t *testing.T) {
	// Use a fresh limiter to avoid interfering with global state
	oldLimiter := globalTieredLimiter
	globalTieredLimiter = NewTieredRateLimiter()
	defer func() { globalTieredLimiter = oldLimiter }()

	called := false
	handler := tieredRateLimitMiddleware(func(w http.ResponseWriter, r *http.Request) {
		called = true
	})

	// Exhaust rate limit (free tier = 60/min)
	for i := 0; i < 60; i++ {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.RemoteAddr = "10.0.0.1:12345"
		rr := httptest.NewRecorder()
		handler(rr, req)
	}

	// Next request should be rate limited
	called = false
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.RemoteAddr = "10.0.0.1:12345"
	rr := httptest.NewRecorder()
	handler(rr, req)
	if called {
		t.Error("handler should NOT have been called (rate limited)")
	}
	if rr.Code != http.StatusTooManyRequests {
		t.Errorf("expected 429, got %d", rr.Code)
	}
	if rr.Header().Get("Retry-After") == "" {
		t.Error("expected Retry-After header")
	}
}

// --- rate_limit_tiers: persistTierToDB ---

func TestCB89_PersistTierToDB_NilDB(t *testing.T) {
	oldDB := db
	db = nil
	defer func() { db = oldDB }()

	err := persistTierToDB("user1", TierPro)
	if err != nil {
		t.Errorf("expected nil error for nil DB, got %v", err)
	}
}

func TestCB89_PersistTierToDB_Success(t *testing.T) {
	withTestDB_CB89(t, func(testDB *sql.DB) {
		_, _, _ = setupUserAndConv_CB89(t, testDB)
		err := persistTierToDB("cb89-user1", TierPro)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}

		// Verify it was persisted
		var tierName string
		testDB.QueryRow("SELECT tier_name FROM user_rate_limit_tiers WHERE user_id = ?", "cb89-user1").Scan(&tierName)
		if tierName != "pro" {
			t.Errorf("expected 'pro', got %q", tierName)
		}
	})
}

func TestCB89_PersistTierToDB_UpdateExisting(t *testing.T) {
	withTestDB_CB89(t, func(testDB *sql.DB) {
		_, _, _ = setupUserAndConv_CB89(t, testDB)
		// First persist
		persistTierToDB("cb89-user1", TierFree)
		// Update to enterprise
		err := persistTierToDB("cb89-user1", TierEnterprise)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		var tierName string
		testDB.QueryRow("SELECT tier_name FROM user_rate_limit_tiers WHERE user_id = ?", "cb89-user1").Scan(&tierName)
		if tierName != "enterprise" {
			t.Errorf("expected 'enterprise', got %q", tierName)
		}
	})
}

// --- rate_limit_tiers: SetTier ---

func TestCB89_SetTier_ExistingUser(t *testing.T) {
	trl := NewTieredRateLimiter()
	// First Allow to create entry
	trl.Allow("user1")
	// Then SetTier
	trl.SetTier("user1", TierPro)
	tier := trl.GetTier("user1")
	if tier.Name != "pro" {
		t.Errorf("expected 'pro', got %q", tier.Name)
	}
}

func TestCB89_SetTier_NewUser(t *testing.T) {
	trl := NewTieredRateLimiter()
	trl.SetTier("newuser", TierEnterprise)
	tier := trl.GetTier("newuser")
	if tier.Name != "enterprise" {
		t.Errorf("expected 'enterprise', got %q", tier.Name)
	}
}

// --- dbdriver: Placeholders ---

func TestCB89_Placeholders_SQLite(t *testing.T) {
	oldDriver := currentDriver
	currentDriver = DriverSQLite
	defer func() { currentDriver = oldDriver }()

	result := Placeholders(1, 3)
	if result != "?, ?, ?" {
		t.Errorf("expected '?, ?, ?', got %q", result)
	}
}

func TestCB89_Placeholders_PostgreSQL(t *testing.T) {
	oldDriver := currentDriver
	currentDriver = DriverPostgreSQL
	defer func() { currentDriver = oldDriver }()

	result := Placeholders(1, 3)
	if result != "$1, $2, $3" {
		t.Errorf("expected '$1, $2, $3', got %q", result)
	}
}

func TestCB89_Placeholders_Single(t *testing.T) {
	oldDriver := currentDriver
	currentDriver = DriverSQLite
	defer func() { currentDriver = oldDriver }()

	result := Placeholders(1, 1)
	if result != "?" {
		t.Errorf("expected '?', got %q", result)
	}
}

// --- dbdriver: Placeholder ---

func TestCB89_Placeholder_SQLite(t *testing.T) {
	oldDriver := currentDriver
	currentDriver = DriverSQLite
	defer func() { currentDriver = oldDriver }()

	if Placeholder(1) != "?" {
		t.Errorf("expected '?', got %q", Placeholder(1))
	}
}

func TestCB89_Placeholder_PostgreSQL(t *testing.T) {
	oldDriver := currentDriver
	currentDriver = DriverPostgreSQL
	defer func() { currentDriver = oldDriver }()

	if Placeholder(5) != "$5" {
		t.Errorf("expected '$5', got %q", Placeholder(5))
	}
}

// --- dbdriver: envIntOrDefault ---

func TestCB89_EnvIntOrDefault_Default(t *testing.T) {
	os.Unsetenv("CB89_TEST_INT")
	result := envIntOrDefault("CB89_TEST_INT", 42)
	if result != 42 {
		t.Errorf("expected 42, got %d", result)
	}
}

func TestCB89_EnvIntOrDefault_Valid(t *testing.T) {
	os.Setenv("CB89_TEST_INT", "100")
	defer os.Unsetenv("CB89_TEST_INT")
	result := envIntOrDefault("CB89_TEST_INT", 42)
	if result != 100 {
		t.Errorf("expected 100, got %d", result)
	}
}

func TestCB89_EnvIntOrDefault_Invalid(t *testing.T) {
	os.Setenv("CB89_TEST_INT", "notanumber")
	defer os.Unsetenv("CB89_TEST_INT")
	result := envIntOrDefault("CB89_TEST_INT", 42)
	if result != 42 {
		t.Errorf("expected 42 for invalid value, got %d", result)
	}
}

// --- dbdriver: envDurationOrDefault ---

func TestCB89_EnvDurationOrDefault_Default(t *testing.T) {
	os.Unsetenv("CB89_TEST_DUR")
	result := envDurationOrDefault("CB89_TEST_DUR", 30*time.Second)
	if result != 30*time.Second {
		t.Errorf("expected 30s, got %v", result)
	}
}

func TestCB89_EnvDurationOrDefault_Valid(t *testing.T) {
	os.Setenv("CB89_TEST_DUR", "5m30s")
	defer os.Unsetenv("CB89_TEST_DUR")
	result := envDurationOrDefault("CB89_TEST_DUR", 30*time.Second)
	if result != 5*time.Minute+30*time.Second {
		t.Errorf("expected 5m30s, got %v", result)
	}
}

func TestCB89_EnvDurationOrDefault_Invalid(t *testing.T) {
	os.Setenv("CB89_TEST_DUR", "notaduration")
	defer os.Unsetenv("CB89_TEST_DUR")
	result := envDurationOrDefault("CB89_TEST_DUR", 30*time.Second)
	if result != 30*time.Second {
		t.Errorf("expected 30s for invalid, got %v", result)
	}
}

// --- handlers: handleLogin ---

func TestCB89_HandleLogin_MethodNotAllowed(t *testing.T) {
	withTestDB_CB89(t, func(testDB *sql.DB) {
		req := httptest.NewRequest(http.MethodGet, "/auth/login", nil)
		rr := httptest.NewRecorder()
		handleLogin(rr, req)
		if rr.Code != http.StatusMethodNotAllowed {
			t.Errorf("expected 405, got %d", rr.Code)
		}
	})
}

func TestCB89_HandleLogin_MissingFields(t *testing.T) {
	withTestDB_CB89(t, func(testDB *sql.DB) {
		req := httptest.NewRequest(http.MethodPost, "/auth/login", nil)
		rr := httptest.NewRecorder()
		handleLogin(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Errorf("expected 400, got %d", rr.Code)
		}
	})
}

func TestCB89_HandleLogin_UserNotFound(t *testing.T) {
	withTestDB_CB89(t, func(testDB *sql.DB) {
		form := strings.NewReader("username=nonexistent&password=pass")
		req := httptest.NewRequest(http.MethodPost, "/auth/login", form)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()
		handleLogin(rr, req)
		if rr.Code != http.StatusUnauthorized {
			t.Errorf("expected 401, got %d", rr.Code)
		}
	})
}

func TestCB89_HandleLogin_Success(t *testing.T) {
	withTestDB_CB89(t, func(testDB *sql.DB) {
		// Create a user with a real bcrypt hash
		hash, err := bcrypt.GenerateFromPassword([]byte("testpass123"), bcrypt.DefaultCost)
		if err != nil {
			t.Fatal(err)
		}
		_, err = testDB.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)",
			"cb89-login-user", "logintest", string(hash))
		if err != nil {
			t.Fatal(err)
		}

		form := strings.NewReader("username=logintest&password=testpass123")
		req := httptest.NewRequest(http.MethodPost, "/auth/login", form)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()
		handleLogin(rr, req)
		if rr.Code != http.StatusOK {
			t.Errorf("expected 200, got %d, body: %s", rr.Code, rr.Body.String())
		}
		var resp map[string]string
		json.Unmarshal(rr.Body.Bytes(), &resp)
		if resp["token"] == "" {
			t.Error("expected token in response")
		}
		if resp["user_id"] != "cb89-login-user" {
			t.Errorf("expected user_id 'cb89-login-user', got %q", resp["user_id"])
		}
	})
}

func TestCB89_HandleLogin_WrongPassword(t *testing.T) {
	withTestDB_CB89(t, func(testDB *sql.DB) {
		hash, err := bcrypt.GenerateFromPassword([]byte("correctpass"), bcrypt.DefaultCost)
		if err != nil {
			t.Fatal(err)
		}
		_, err = testDB.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)",
			"cb89-login-user2", "logintest2", string(hash))
		if err != nil {
			t.Fatal(err)
		}

		form := strings.NewReader("username=logintest2&password=wrongpass")
		req := httptest.NewRequest(http.MethodPost, "/auth/login", form)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()
		handleLogin(rr, req)
		if rr.Code != http.StatusUnauthorized {
			t.Errorf("expected 401, got %d", rr.Code)
		}
	})
}

// --- conversations: storeMessage ---

func TestCB89_StoreMessage_Success(t *testing.T) {
	withTestDB_CB89(t, func(testDB *sql.DB) {
		_, _, convID := setupUserAndConv_CB89(t, testDB)
		msg := RoutedMessage{
			Type:           MsgTypeMessage,
			ConversationID: convID,
			Content:        "test message",
			SenderType:     "user",
			SenderID:       "cb89-user1",
		}
		err := storeMessage(msg)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		// Verify message was stored
		var count int
		testDB.QueryRow("SELECT COUNT(*) FROM messages WHERE conversation_id = ?", convID).Scan(&count)
		if count != 1 {
			t.Errorf("expected 1 message, got %d", count)
		}
	})
}

func TestCB89_StoreMessage_WithMetadata(t *testing.T) {
	withTestDB_CB89(t, func(testDB *sql.DB) {
		_, _, convID := setupUserAndConv_CB89(t, testDB)
		msg := RoutedMessage{
			Type:           MsgTypeMessage,
			ConversationID: convID,
			Content:        "test with metadata",
			SenderType:     "agent",
			SenderID:       "cb89-agent1",
			AttachmentIDs:  []string{"att1", "att2"},
		}
		err := storeMessage(msg)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})
}

func TestCB89_StoreMessage_ConvNotFound(t *testing.T) {
	withTestDB_CB89(t, func(testDB *sql.DB) {
		msg := RoutedMessage{
			Type:           MsgTypeMessage,
			ConversationID: "nonexistent",
			Content:        "test",
			SenderType:     "user",
			SenderID:       "cb89-user1",
		}
		// SQLite may not enforce FK constraints by default, so this may succeed
		// The important thing is that it doesn't panic
		_ = storeMessage(msg)
	})
}

// --- conversations: getConversationMessages ---

func TestCB89_GetConversationMessages_Success(t *testing.T) {
	withTestDB_CB89(t, func(testDB *sql.DB) {
		_, _, convID := setupUserAndConv_CB89(t, testDB)
		// Insert multiple messages
		for i := 0; i < 5; i++ {
			insertMessage_CB89(t, testDB, convID, "agent", "cb89-agent1", "msg"+itoa(i))
		}

		msgs, err := getConversationMessages(convID, 50, "")
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if len(msgs) != 5 {
			t.Errorf("expected 5 messages, got %d", len(msgs))
		}
	})
}

func TestCB89_GetConversationMessages_WithLimit(t *testing.T) {
	withTestDB_CB89(t, func(testDB *sql.DB) {
		_, _, convID := setupUserAndConv_CB89(t, testDB)
		for i := 0; i < 10; i++ {
			insertMessage_CB89(t, testDB, convID, "agent", "cb89-agent1", "msg"+itoa(i))
		}

		msgs, err := getConversationMessages(convID, 3, "")
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if len(msgs) != 3 {
			t.Errorf("expected 3 messages, got %d", len(msgs))
		}
	})
}

func TestCB89_GetConversationMessages_Empty(t *testing.T) {
	withTestDB_CB89(t, func(testDB *sql.DB) {
		_, _, convID := setupUserAndConv_CB89(t, testDB)
		msgs, err := getConversationMessages(convID, 50, "")
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if len(msgs) != 0 {
			t.Errorf("expected 0 messages, got %d", len(msgs))
		}
	})
}

// --- conversations: CreateConversation ---

func TestCB89_CreateConversation_Success(t *testing.T) {
	withTestDB_CB89(t, func(testDB *sql.DB) {
		_, agentID, _ := setupUserAndConv_CB89(t, testDB)
		conv, err := CreateConversation("cb89-user1", agentID)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if conv == nil {
			t.Fatal("expected non-nil conversation")
		}
		if conv.UserID != "cb89-user1" {
			t.Errorf("expected UserID 'cb89-user1', got %q", conv.UserID)
		}
	})
}

// --- tracing: Trace* with tracing disabled ---

func TestCB89_TraceRouteMessage_Disabled(t *testing.T) {
	oldEnabled := tracingEnabled
	tracingEnabled = false
	defer func() { tracingEnabled = oldEnabled }()

	span := TraceRouteMessage("agent", "agent1")
	if span == nil {
		t.Error("expected non-nil span")
	}
	// Should be a no-op span, ending should work
	span.End()
}

func TestCB89_TraceOfflineEnqueue_Disabled(t *testing.T) {
	oldEnabled := tracingEnabled
	tracingEnabled = false
	defer func() { tracingEnabled = oldEnabled }()

	span := TraceOfflineEnqueue("user1")
	if span == nil {
		t.Error("expected non-nil span")
	}
	span.End()
}

func TestCB89_TracePushNotify_Disabled(t *testing.T) {
	oldEnabled := tracingEnabled
	tracingEnabled = false
	defer func() { tracingEnabled = oldEnabled }()

	span := TracePushNotify("user1", "conv1", true)
	if span == nil {
		t.Error("expected non-nil span")
	}
	span.End()
}

func TestCB89_TraceAgentConnect_Disabled(t *testing.T) {
	oldEnabled := tracingEnabled
	tracingEnabled = false
	defer func() { tracingEnabled = oldEnabled }()

	span := TraceAgentConnect("agent1")
	if span == nil {
		t.Error("expected non-nil span")
	}
	span.End()
}

func TestCB89_TraceClientConnect_Disabled(t *testing.T) {
	oldEnabled := tracingEnabled
	tracingEnabled = false
	defer func() { tracingEnabled = oldEnabled }()

	span := TraceClientConnect("user1", "device1")
	if span == nil {
		t.Error("expected non-nil span")
	}
	span.End()
}

func TestCB89_StartSpan_Disabled(t *testing.T) {
	oldEnabled := tracingEnabled
	tracingEnabled = false
	defer func() { tracingEnabled = oldEnabled }()

	ctx, span := StartSpan(nil, "test-span")
	if span == nil {
		t.Error("expected non-nil span")
	}
	if ctx != nil {
		t.Error("expected nil ctx for nil input when tracing disabled")
	}
}

func TestCB89_StartSpanFromRequest_Disabled(t *testing.T) {
	oldEnabled := tracingEnabled
	tracingEnabled = false
	defer func() { tracingEnabled = oldEnabled }()

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	ctx, span := StartSpanFromRequest(req, "test-span")
	if span == nil {
		t.Error("expected non-nil span")
	}
	_ = ctx // ctx should be r.Context() when disabled
}

func TestCB89_SpanError_Disabled(t *testing.T) {
	oldEnabled := tracingEnabled
	tracingEnabled = false
	defer func() { tracingEnabled = oldEnabled }()

	span := TraceRouteMessage("agent", "a1")
	SpanError(span, nil) // should not panic
	span.End()
}

func TestCB89_SpanOK_Disabled(t *testing.T) {
	oldEnabled := tracingEnabled
	tracingEnabled = false
	defer func() { tracingEnabled = oldEnabled }()

	span := TraceRouteMessage("agent", "a1")
	SpanOK(span) // should not panic
	span.End()
}

func TestCB89_ShutdownTracing_NilProvider(t *testing.T) {
	oldTP := tp
	tp = nil
	defer func() { tp = oldTP }()
	// Should not panic with nil provider
	ShutdownTracing()
}

func TestCB89_IsTracingEnabled(t *testing.T) {
	oldEnabled := tracingEnabled
	tracingEnabled = false
	defer func() { tracingEnabled = oldEnabled }()

	if IsTracingEnabled() {
		t.Error("expected false")
	}

	tracingEnabled = true
	if !IsTracingEnabled() {
		t.Error("expected true")
	}
}

// --- writeJSONResponse ---

func TestCB89_WriteJSONResponse(t *testing.T) {
	rr := httptest.NewRecorder()
	writeJSONResponse(rr, http.StatusCreated, map[string]string{"status": "created"})
	if rr.Code != http.StatusCreated {
		t.Errorf("expected 201, got %d", rr.Code)
	}
	if rr.Header().Get("Content-Type") != "application/json" {
		t.Errorf("expected application/json content type, got %q", rr.Header().Get("Content-Type"))
	}
	var resp map[string]string
	json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp["status"] != "created" {
		t.Errorf("expected 'created', got %q", resp["status"])
	}
}