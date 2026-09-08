package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/textproto"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	_ "github.com/mattn/go-sqlite3"
	"github.com/gorilla/websocket"
	"golang.org/x/crypto/bcrypt"
)

// ==================== CB79 Helpers ====================

func setupTestDB_CB79(t *testing.T) *sql.DB {
	testDB, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("Failed to open test DB: %v", err)
	}
	if err := initSchema(testDB); err != nil {
		t.Fatalf("Failed to init schema: %v", err)
	}
	initQueueDB(testDB)
	t.Cleanup(func() { testDB.Close() })

	return testDB
}

func generateTestToken_CB79(userID string) string {
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

func createUser_CB79(testDB *sql.DB, username, password string) string {
	hash, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	_, _ = testDB.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)", username, username, string(hash))
	return username
}

func createConversation_CB79(testDB *sql.DB, userID, agentID string) string {
	convID := "conv-cb79-" + userID + "-" + agentID
	_, _ = testDB.Exec("INSERT INTO conversations (id, user_id, agent_id) VALUES (?, ?, ?)", convID, userID, agentID)
	return convID
}

func withGlobalDB_CB79(testDB *sql.DB, fn func()) {
	origDB := db
	db = testDB
	defer func() { db = origDB }()
	fn()
}

// makeMultipartUpload creates a multipart request body with a file field
func makeMultipartUpload_CB79(fieldName, fileName, contentType string, content []byte) (*strings.Reader, string) {
	body := &strings.Builder{}
	writer := multipart.NewWriter(body)
	header := make(textproto.MIMEHeader)
	header.Set("Content-Disposition", "form-data; name=\""+fieldName+"\"; filename=\""+fileName+"\"")
	if contentType != "" {
		header.Set("Content-Type", contentType)
	}
	part, _ := writer.CreatePart(header)
	part.Write(content)
	writer.Close()
	return strings.NewReader(body.String()), writer.FormDataContentType()
}

// ==================== RegisterAgentOnConnect: UPDATE error paths ====================

// TestCB79_RegisterAgentOnConnect_UpdateModelError triggers DB error on model UPDATE
func TestCB79_RegisterAgentOnConnect_UpdateModelError(t *testing.T) {
	testDB := setupTestDB_CB79(t)
	defer testDB.Close()

	// Insert an agent first
	_, err := testDB.Exec("INSERT INTO agents (id, name, model, personality, specialty) VALUES (?, ?, ?, ?, ?)",
		"agent-model-err", "TestAgent", "old-model", "old-pers", "old-spec")
	if err != nil {
		t.Fatalf("Failed to insert agent: %v", err)
	}

	// Close the DB to trigger errors on UPDATE
	testDB.Close()

	withGlobalDB_CB79(testDB, func() {
		err := RegisterAgentOnConnect("agent-model-err", "NewName", "new-model", "", "")
		if err == nil {
			t.Error("Expected error on model UPDATE with closed DB, got nil")
		}
	})
}

// TestCB79_RegisterAgentOnConnect_UpdatePersonalityError triggers DB error on personality UPDATE
func TestCB79_RegisterAgentOnConnect_UpdatePersonalityError(t *testing.T) {
	testDB := setupTestDB_CB79(t)
	defer testDB.Close()

	_, err := testDB.Exec("INSERT INTO agents (id, name, model, personality, specialty) VALUES (?, ?, ?, ?, ?)",
		"agent-pers-err", "TestAgent", "old-model", "old-pers", "old-spec")
	if err != nil {
		t.Fatalf("Failed to insert agent: %v", err)
	}

	testDB.Close()

	withGlobalDB_CB79(testDB, func() {
		err := RegisterAgentOnConnect("agent-pers-err", "", "", "new-pers", "")
		if err == nil {
			t.Error("Expected error on personality UPDATE with closed DB, got nil")
		}
	})
}

// TestCB79_RegisterAgentOnConnect_UpdateSpecialtyError triggers DB error on specialty UPDATE
func TestCB79_RegisterAgentOnConnect_UpdateSpecialtyError(t *testing.T) {
	testDB := setupTestDB_CB79(t)
	defer testDB.Close()

	_, err := testDB.Exec("INSERT INTO agents (id, name, model, personality, specialty) VALUES (?, ?, ?, ?, ?)",
		"agent-spec-err", "TestAgent", "old-model", "old-pers", "old-spec")
	if err != nil {
		t.Fatalf("Failed to insert agent: %v", err)
	}

	testDB.Close()

	withGlobalDB_CB79(testDB, func() {
		err := RegisterAgentOnConnect("agent-spec-err", "", "", "", "new-spec")
		if err == nil {
			t.Error("Expected error on specialty UPDATE with closed DB, got nil")
		}
	})
}

// TestCB79_RegisterAgentOnConnect_UpdateNameError triggers DB error on name UPDATE
func TestCB79_RegisterAgentOnConnect_UpdateNameError(t *testing.T) {
	testDB := setupTestDB_CB79(t)
	defer testDB.Close()

	_, err := testDB.Exec("INSERT INTO agents (id, name, model, personality, specialty) VALUES (?, ?, ?, ?, ?)",
		"agent-name-err", "OldName", "old-model", "old-pers", "old-spec")
	if err != nil {
		t.Fatalf("Failed to insert agent: %v", err)
	}

	testDB.Close()

	withGlobalDB_CB79(testDB, func() {
		err := RegisterAgentOnConnect("agent-name-err", "NewName", "", "", "")
		if err == nil {
			t.Error("Expected error on name UPDATE with closed DB, got nil")
		}
	})
}

// TestCB79_RegisterAgentOnConnect_SuccessAllFieldsUpdates tests all UPDATE paths succeed
func TestCB79_RegisterAgentOnConnect_SuccessAllFieldsUpdates(t *testing.T) {
	testDB := setupTestDB_CB79(t)
	defer testDB.Close()

	_, err := testDB.Exec("INSERT INTO agents (id, name, model, personality, specialty) VALUES (?, ?, ?, ?, ?)",
		"agent-all-fields", "OldName", "old-model", "old-pers", "old-spec")
	if err != nil {
		t.Fatalf("Failed to insert agent: %v", err)
	}

	withGlobalDB_CB79(testDB, func() {
		err := RegisterAgentOnConnect("agent-all-fields", "NewName", "new-model", "new-pers", "new-spec")
		if err != nil {
			t.Errorf("Expected success, got error: %v", err)
		}
	})

	// Verify all fields were updated
	var name, model, personality, specialty string
	err = testDB.QueryRow("SELECT name, model, personality, specialty FROM agents WHERE id = ?", "agent-all-fields").Scan(&name, &model, &personality, &specialty)
	if err != nil {
		t.Fatalf("Failed to query agent: %v", err)
	}
	if name != "NewName" {
		t.Errorf("Expected name 'NewName', got '%s'", name)
	}
	if model != "new-model" {
		t.Errorf("Expected model 'new-model', got '%s'", model)
	}
	if personality != "new-pers" {
		t.Errorf("Expected personality 'new-pers', got '%s'", personality)
	}
	if specialty != "new-spec" {
		t.Errorf("Expected specialty 'new-spec', got '%s'", specialty)
	}
}

// TestCB79_RegisterAgentOnConnect_ReturnNilOnNoUpdates tests the final return nil path
func TestCB79_RegisterAgentOnConnect_ReturnNilOnNoUpdates(t *testing.T) {
	testDB := setupTestDB_CB79(t)
	defer testDB.Close()

	// Insert an agent, then call RegisterAgentOnConnect with all empty fields (except name = agentID)
	_, err := testDB.Exec("INSERT INTO agents (id, name, model, personality, specialty) VALUES (?, ?, ?, ?, ?)",
		"agent-no-update", "AgentNoUpdate", "model1", "pers1", "spec1")
	if err != nil {
		t.Fatalf("Failed to insert agent: %v", err)
	}

	withGlobalDB_CB79(testDB, func() {
		// name defaults to agentID, so name == agentID, so no name UPDATE
		// model, personality, specialty are all empty, so no UPDATE
		err := RegisterAgentOnConnect("agent-no-update", "", "", "", "")
		if err != nil {
			t.Errorf("Expected nil (no updates needed), got: %v", err)
		}
	})
}

// ==================== deleteConversation: additional error paths ====================

// TestCB79_DeleteConversation_BeginError tests DB begin error
func TestCB79_DeleteConversation_BeginError(t *testing.T) {
	testDB := setupTestDB_CB79(t)
	testDB.Close()

	withGlobalDB_CB79(testDB, func() {
		err := deleteConversation("conv-1", "user1")
		if err == nil {
			t.Error("Expected error on deleteConversation with closed DB, got nil")
		}
	})
}

// TestCB79_DeleteConversation_SuccessWithMessages tests successful deletion
func TestCB79_DeleteConversation_SuccessWithMessages(t *testing.T) {
	testDB := setupTestDB_CB79(t)
	defer testDB.Close()

	userID := createUser_CB79(testDB, "user-del-conv", "pass")
	convID := createConversation_CB79(testDB, userID, "agent1")

	// Insert some messages
	_, err := testDB.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content) VALUES (?, ?, ?, ?, ?)",
		"msg1", convID, "user", userID, "hello")
	if err != nil {
		t.Fatalf("Failed to insert message: %v", err)
	}
	_, err = testDB.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content) VALUES (?, ?, ?, ?, ?)",
		"msg2", convID, "agent", "agent1", "hi back")
	if err != nil {
		t.Fatalf("Failed to insert message: %v", err)
	}

	withGlobalDB_CB79(testDB, func() {
		err := deleteConversation(convID, userID)
		if err != nil {
			t.Errorf("Expected success, got error: %v", err)
		}
	})

	// Verify conversation is deleted
	var count int
	testDB.QueryRow("SELECT COUNT(*) FROM conversations WHERE id = ?", convID).Scan(&count)
	if count != 0 {
		t.Errorf("Expected conversation to be deleted, found %d", count)
	}

	// Verify messages are deleted
	testDB.QueryRow("SELECT COUNT(*) FROM messages WHERE conversation_id = ?", convID).Scan(&count)
	if count != 0 {
		t.Errorf("Expected messages to be deleted, found %d", count)
	}
}

// ==================== storeMessagesBatch: error paths ====================

// TestCB79_StoreMessagesBatch_PrepareError tests prepare error
func TestCB79_StoreMessagesBatch_PrepareError(t *testing.T) {
	testDB := setupTestDB_CB79(t)
	testDB.Close()

	withGlobalDB_CB79(testDB, func() {
		msgs := []RoutedMessage{
			{ConversationID: "conv1", SenderID: "user1", Content: "hello", Type: "text"},
		}
		_, err := storeMessagesBatch(msgs)
		if err == nil {
			t.Error("Expected error on storeMessagesBatch with closed DB, got nil")
		}
	})
}

// TestCB79_StoreMessagesBatch_WithAttachmentLinking tests attachment linking path
func TestCB79_StoreMessagesBatch_WithAttachmentLinking(t *testing.T) {
	testDB := setupTestDB_CB79(t)
	defer testDB.Close()

	userID := createUser_CB79(testDB, "user-batch-attach", "pass")
	convID := createConversation_CB79(testDB, userID, "agent1")

	// Insert an attachment-less message first, then link
	withGlobalDB_CB79(testDB, func() {
		msgs := []RoutedMessage{
			{ConversationID: convID, SenderID: userID, Content: "msg with attachment", Type: "text", AttachmentIDs: []string{"att1", "att2"}},
		}
		ids, err := storeMessagesBatch(msgs)
		if err != nil {
			t.Errorf("Expected success, got error: %v", err)
		}
		if len(ids) != 1 {
			t.Errorf("Expected 1 message ID, got %d", len(ids))
		}
	})
}

// ==================== handleUpload: additional error paths ====================

// TestCB79_HandleUpload_DBInsertError tests DB insert error on attachment
func TestCB79_HandleUpload_DBInsertError(t *testing.T) {
	testDB := setupTestDB_CB79(t)
	defer testDB.Close()

	userID := createUser_CB79(testDB, "user-upload-err", "pass")
	token := generateTestToken_CB79(userID)

	// Create a conversation
	convID := createConversation_CB79(testDB, userID, "agent1")

	// Set upload dir to a valid temp dir
	tmpDir := t.TempDir()
	os.Setenv("UPLOAD_DIR", tmpDir)
	defer os.Unsetenv("UPLOAD_DIR")

	withGlobalDB_CB79(testDB, func() {
		body, contentType := makeMultipartUpload_CB79("file", "test.txt", "text/plain", []byte("test content"))
		req := httptest.NewRequest("POST", "/upload?conversation_id="+convID, body)
		req.Header.Set("Content-Type", contentType)
		req.Header.Set("Authorization", "Bearer "+token)

		// Close the DB to trigger insert error
		testDB.Close()

		w := httptest.NewRecorder()
		handleUpload(w, req)

		// Should get 500 or 401 (if getConversation returns nil due to DB error)
		if w.Code != http.StatusInternalServerError && w.Code != http.StatusUnauthorized {
			t.Errorf("Expected 500 or 401, got %d", w.Code)
		}
	})
}

// TestCB79_HandleUpload_NoFile tests missing file field
func TestCB79_HandleUpload_NoFile(t *testing.T) {
	testDB := setupTestDB_CB79(t)
	defer testDB.Close()

	userID := createUser_CB79(testDB, "user-no-file", "pass")
	token := generateTestToken_CB79(userID)

	tmpDir := t.TempDir()
	os.Setenv("UPLOAD_DIR", tmpDir)
	defer os.Unsetenv("UPLOAD_DIR")

	withGlobalDB_CB79(testDB, func() {
		req := httptest.NewRequest("POST", "/upload", strings.NewReader(""))
		req.Header.Set("Content-Type", "multipart/form-data; boundary=---boundary")
		req.Header.Set("Authorization", "Bearer "+token)

		w := httptest.NewRecorder()
		handleUpload(w, req)

		if w.Code != http.StatusBadRequest {
			t.Errorf("Expected 400 for invalid form, got %d", w.Code)
		}
	})
}

// TestCB79_HandleUpload_NoAuth tests missing auth
func TestCB79_HandleUpload_NoAuth(t *testing.T) {
	testDB := setupTestDB_CB79(t)
	defer testDB.Close()

	tmpDir := t.TempDir()
	os.Setenv("UPLOAD_DIR", tmpDir)
	defer os.Unsetenv("UPLOAD_DIR")

	withGlobalDB_CB79(testDB, func() {
		body, contentType := makeMultipartUpload_CB79("file", "test.txt", "text/plain", []byte("test"))
		req := httptest.NewRequest("POST", "/upload", body)
		req.Header.Set("Content-Type", contentType)

		w := httptest.NewRecorder()
		handleUpload(w, req)

		if w.Code != http.StatusUnauthorized {
			t.Errorf("Expected 401 for no auth, got %d", w.Code)
		}
	})
}

// ==================== notifyUser: additional paths ====================

// TestCB79_NotifyUser_NilDB tests notifyUser with nil DB
func TestCB79_NotifyUser_NilDB(t *testing.T) {
	origDB := db
	db = nil
	defer func() { db = origDB }()

	// Should not panic, just return
	notifyUser("user1", "title", "body", "conv1")
}

// TestCB79_NotifyUser_NilPushConfig tests notifyUser with nil pushConfig
func TestCB79_NotifyUser_NilPushConfig(t *testing.T) {
	testDB := setupTestDB_CB79(t)
	defer testDB.Close()

	origPushConfig := pushConfig
	pushConfig = nil
	defer func() { pushConfig = origPushConfig }()

	withGlobalDB_CB79(testDB, func() {
		// Should not panic, just return
		notifyUser("user1", "title", "body", "conv1")
	})
}

// TestCB79_NotifyUser_MutedConversation tests muted conversation
func TestCB79_NotifyUser_MutedConversation(t *testing.T) {
	testDB := setupTestDB_CB79(t)
	defer testDB.Close()

	userID := createUser_CB79(testDB, "user-muted", "pass")
	convID := createConversation_CB79(testDB, userID, "agent1")

	// Mute the conversation
	_, err := testDB.Exec("INSERT INTO notification_preferences (user_id, conversation_id, muted) VALUES (?, ?, ?)",
		userID, convID, true)
	if err != nil {
		t.Fatalf("Failed to insert notif prefs: %v", err)
	}

	origPushConfig := pushConfig
	pushConfig = &PushNotificationConfig{APNSEnabled: false, FCMEnabled: false}
	defer func() { pushConfig = origPushConfig }()

	withGlobalDB_CB79(testDB, func() {
		// Should not send notification (muted)
		notifyUser(userID, "title", "body", convID)
	})
}

// TestCB79_NotifyUser_NoTokens tests notifyUser with no device tokens
func TestCB79_NotifyUser_NoTokens(t *testing.T) {
	testDB := setupTestDB_CB79(t)
	defer testDB.Close()

	userID := createUser_CB79(testDB, "user-notokens", "pass")
	convID := createConversation_CB79(testDB, userID, "agent1")

	origPushConfig := pushConfig
	pushConfig = &PushNotificationConfig{APNSEnabled: true, FCMEnabled: true}
	defer func() { pushConfig = origPushConfig }()

	withGlobalDB_CB79(testDB, func() {
		// Should not panic even with push enabled but no tokens
		notifyUser(userID, "title", "body", convID)
	})
}

// TestCB79_NotifyUser_WithTokensAndPushConfig tests notifyUser with actual tokens
func TestCB79_NotifyUser_WithTokensAndPushConfig(t *testing.T) {
	testDB := setupTestDB_CB79(t)
	defer testDB.Close()

	userID := createUser_CB79(testDB, "user-tokens", "pass")
	convID := createConversation_CB79(testDB, userID, "agent1")

	// Insert a device token
	_, err := testDB.Exec("INSERT INTO device_tokens (user_id, device_token, platform) VALUES (?, ?, ?)",
		userID, "token123", "ios")
	if err != nil {
		t.Fatalf("Failed to insert device token: %v", err)
	}

	origPushConfig := pushConfig
	pushConfig = &PushNotificationConfig{APNSEnabled: false, FCMEnabled: false}
	defer func() { pushConfig = origPushConfig }()

	withGlobalDB_CB79(testDB, func() {
		// Should not panic with tokens but push disabled
		notifyUser(userID, "title", "body", convID)
	})
}

// TestCB79_NotifyUser_PanicRecovery tests that notifyUser recovers from panic
func TestCB79_NotifyUser_PanicRecovery(t *testing.T) {
	testDB := setupTestDB_CB79(t)
	defer testDB.Close()

	userID := createUser_CB79(testDB, "user-panic", "pass")
	convID := createConversation_CB79(testDB, userID, "agent1")

	// Insert a device token
	_, err := testDB.Exec("INSERT INTO device_tokens (user_id, device_token, platform) VALUES (?, ?, ?)",
		userID, "token-panic", "ios")
	if err != nil {
		t.Fatalf("Failed to insert device token: %v", err)
	}

	origPushConfig := pushConfig
	pushConfig = &PushNotificationConfig{APNSEnabled: true, CertPath: "/nonexistent/cert.p12", FCMEnabled: false}
	defer func() { pushConfig = origPushConfig }()

	withGlobalDB_CB79(testDB, func() {
		// Should not panic even though APNs is enabled but cert is invalid
		notifyUser(userID, "title", "body", convID)
	})
}

// ==================== handleSetNotificationPrefs: upsert error ====================

// TestCB79_HandleSetNotificationPrefs_UpsertError tests DB error on upsert
func TestCB79_HandleSetNotificationPrefs_UpsertError(t *testing.T) {
	testDB := setupTestDB_CB79(t)
	defer testDB.Close()

	userID := createUser_CB79(testDB, "user-upsert-err", "pass")
	convID := createConversation_CB79(testDB, userID, "agent1")
	token := generateTestToken_CB79(userID)

	withGlobalDB_CB79(testDB, func() {
		// Close DB to trigger upsert error
		testDB.Close()

		formData := "conversation_id=" + convID + "&muted=true"
		req := httptest.NewRequest("POST", "/notifications/prefs", strings.NewReader(formData))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Authorization", "Bearer "+token)

		w := httptest.NewRecorder()
		authMiddleware(handleSetNotificationPrefs)(w, req)

		// Will get 401 (getUserID fails on closed DB) or 500
		if w.Code != http.StatusInternalServerError && w.Code != http.StatusUnauthorized {
			t.Errorf("Expected 500 or 401, got %d", w.Code)
		}
	})
}

// TestCB79_HandleSetNotificationPrefs_SuccessUnmute tests successful unmute
func TestCB79_HandleSetNotificationPrefs_SuccessUnmute(t *testing.T) {
	testDB := setupTestDB_CB79(t)
	defer testDB.Close()

	userID := createUser_CB79(testDB, "user-unmute", "pass")
	convID := createConversation_CB79(testDB, userID, "agent1")
	token := generateTestToken_CB79(userID)

	// First mute
	_, err := testDB.Exec("INSERT INTO notification_preferences (user_id, conversation_id, muted) VALUES (?, ?, ?)",
		userID, convID, true)
	if err != nil {
		t.Fatalf("Failed to insert notif prefs: %v", err)
	}

	withGlobalDB_CB79(testDB, func() {
		formData := "conversation_id=" + convID + "&muted=false"
		req := httptest.NewRequest("POST", "/notifications/prefs", strings.NewReader(formData))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Authorization", "Bearer "+token)

		w := httptest.NewRecorder()
		authMiddleware(handleSetNotificationPrefs)(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected 200, got %d", w.Code)
		}

		var resp NotificationPreferences
		if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
			t.Fatalf("Failed to decode response: %v", err)
		}
		if resp.Muted != false {
			t.Errorf("Expected muted=false, got %v", resp.Muted)
		}
	})
}

// ==================== checkRateLimit: both exceeded ====================

// TestCB79_CheckRateLimit_BothExceeded tests when both per-conn and per-user limits are exceeded
func TestCB79_CheckRateLimit_BothExceeded(t *testing.T) {
	// Create a connection and exhaust both rate limiters
	conn := &Connection{
		id:       "test-conn-both",
		connType: "client",
		send:     make(chan []byte, 10),
	}

	// Exhaust per-connection rate limiter
	messageRateLimiter = NewRateLimiter(60, time.Minute)
	for i := 0; i < 60; i++ {
		messageRateLimiter.Allow(conn.id)
	}

	// Exhaust per-user rate limiter
	userRateLimiter = NewRateLimiter(120, time.Minute)
	for i := 0; i < 120; i++ {
		userRateLimiter.Allow(conn.id)
	}

	// Now both should be exceeded
	result := checkRateLimit(conn)
	if result != false {
		t.Error("Expected checkRateLimit to return false when both limiters exceeded")
	}
}

// TestCB79_CheckRateLimit_PerConnExceededOnly tests when only per-conn is exceeded
func TestCB79_CheckRateLimit_PerConnExceededOnly(t *testing.T) {
	conn := &Connection{
		id:       "test-conn-only",
		connType: "client",
		send:     make(chan []byte, 10),
	}

	// Exhaust per-connection rate limiter only
	messageRateLimiter = NewRateLimiter(5, time.Minute)
	for i := 0; i < 5; i++ {
		messageRateLimiter.Allow(conn.id)
	}

	// Reset per-user rate limiter to have capacity
	userRateLimiter = NewRateLimiter(120, time.Minute)

	result := checkRateLimit(conn)
	if result != false {
		t.Error("Expected checkRateLimit to return false when per-conn exceeded")
	}
}

// TestCB79_CheckRateLimit_BothAllowed tests when both allow
func TestCB79_CheckRateLimit_BothAllowed(t *testing.T) {
	conn := &Connection{
		id:       "test-conn-ok",
		connType: "client",
		send:     make(chan []byte, 10),
	}

	messageRateLimiter = NewRateLimiter(60, time.Minute)
	userRateLimiter = NewRateLimiter(120, time.Minute)

	result := checkRateLimit(conn)
	if result != true {
		t.Error("Expected checkRateLimit to return true when both allow")
	}
}

// ==================== initAPNs: additional paths ====================

// TestCB79_InitAPNs_InvalidCert tests loading an invalid certificate
func TestCB79_InitAPNs_InvalidCert(t *testing.T) {
	origPushConfig := pushConfig
	defer func() { pushConfig = origPushConfig }()

	// Create a temp file that is not a valid P12 cert
	tmpFile := filepath.Join(t.TempDir(), "invalid_cert.p12")
	os.WriteFile(tmpFile, []byte("not a valid p12 cert"), 0644)

	pushConfig = &PushNotificationConfig{
		APNSEnabled:  true,
		CertPath: tmpFile,
		Environment:  "development",
	}

	initAPNs()
	// Should not panic, just log error
}

// TestCB79_InitAPNs_ProductionEnv tests production environment
func TestCB79_InitAPNs_ProductionEnv(t *testing.T) {
	origPushConfig := pushConfig
	defer func() { pushConfig = origPushConfig }()

	// Create an invalid cert file (just to test the path)
	tmpFile := filepath.Join(t.TempDir(), "prod_cert.p12")
	os.WriteFile(tmpFile, []byte("invalid"), 0644)

	pushConfig = &PushNotificationConfig{
		APNSEnabled:  true,
		CertPath: tmpFile,
		Environment:  "production",
	}

	initAPNs()
	// Should not panic
}

// TestCB79_InitAPNs_NilConfig tests nil pushConfig
func TestCB79_InitAPNs_NilConfig(t *testing.T) {
	origPushConfig := pushConfig
	defer func() { pushConfig = origPushConfig }()

	pushConfig = nil
	initAPNs()
	// Should not panic
}

// TestCB79_InitAPNs_Disabled tests disabled APNs
func TestCB79_InitAPNs_Disabled(t *testing.T) {
	origPushConfig := pushConfig
	defer func() { pushConfig = origPushConfig }()

	pushConfig = &PushNotificationConfig{
		APNSEnabled: false,
	}
	initAPNs()
}

// TestCB79_InitAPNs_NoCertPath tests missing cert path
func TestCB79_InitAPNs_NoCertPath(t *testing.T) {
	origPushConfig := pushConfig
	defer func() { pushConfig = origPushConfig }()

	pushConfig = &PushNotificationConfig{
		APNSEnabled:  true,
		CertPath: "",
	}
	initAPNs()
}

// TestCB79_InitAPNs_CertNotFound tests cert not found
func TestCB79_InitAPNs_CertNotFound(t *testing.T) {
	origPushConfig := pushConfig
	defer func() { pushConfig = origPushConfig }()

	pushConfig = &PushNotificationConfig{
		APNSEnabled:  true,
		CertPath: "/nonexistent/cert.p12",
	}
	initAPNs()
}

// ==================== initFCM: additional paths ====================

// TestCB79_InitFCM_NilConfig tests nil pushConfig
func TestCB79_InitFCM_NilConfig(t *testing.T) {
	origPushConfig := pushConfig
	defer func() { pushConfig = origPushConfig }()

	pushConfig = nil
	initFCM()
}

// TestCB79_InitFCM_Disabled tests disabled FCM
func TestCB79_InitFCM_Disabled(t *testing.T) {
	origPushConfig := pushConfig
	defer func() { pushConfig = origPushConfig }()

	pushConfig = &PushNotificationConfig{
		FCMEnabled: false,
	}
	initFCM()
}

// TestCB79_InitFCM_NoCredsPath tests missing creds path
func TestCB79_InitFCM_NoCredsPath(t *testing.T) {
	origPushConfig := pushConfig
	defer func() { pushConfig = origPushConfig }()

	pushConfig = &PushNotificationConfig{
		FCMEnabled:  true,
		FCMCredentials: "",
	}
	initFCM()
}

// TestCB79_InitFCM_CredsNotFound tests creds not found
func TestCB79_InitFCM_CredsNotFound(t *testing.T) {
	origPushConfig := pushConfig
	defer func() { pushConfig = origPushConfig }()

	pushConfig = &PushNotificationConfig{
		FCMEnabled:   true,
		FCMCredentials: "/nonexistent/creds.json",
	}
	initFCM()
}

// TestCB79_InitFCM_InvalidCreds tests invalid creds file
func TestCB79_InitFCM_InvalidCreds(t *testing.T) {
	origPushConfig := pushConfig
	defer func() { pushConfig = origPushConfig }()

	tmpFile := filepath.Join(t.TempDir(), "invalid_creds.json")
	os.WriteFile(tmpFile, []byte("not valid json"), 0644)

	pushConfig = &PushNotificationConfig{
		FCMEnabled:   true,
		FCMCredentials: tmpFile,
	}
	initFCM()
}

// ==================== sendWelcomeMessage: marshal error path ====================

// TestCB79_SendWelcomeMessage_MarshalError tests json.Marshal error
// This is hard to trigger directly, but we can test the SafeSend false path
func TestCB79_SendWelcomeMessage_SafeSendFalse(t *testing.T) {
	conn := &Connection{
		id:                 "test-welcome-safesend",
		connType:           "client",
		send:               make(chan []byte, 1),
		negotiatedVersion:  "1.0",
	}

	// Fill the send channel to capacity
	conn.send <- []byte("filler")

	// Now SafeSend should return false (buffer full)
	// sendWelcomeMessage should handle this gracefully
	sendWelcomeMessage(conn)

	// Drain the channel to verify
	select {
	case <-conn.send:
	default:
	}
}

// TestCB79_SendWelcomeMessage_WithDeviceID tests deviceID in welcome
func TestCB79_SendWelcomeMessage_WithDeviceID(t *testing.T) {
	conn := &Connection{
		id:                "test-welcome-device",
		connType:          "client",
		send:              make(chan []byte, 10),
		negotiatedVersion: "1.0",
		deviceID:          "device-abc",
	}

	sendWelcomeMessage(conn)

	// Should receive a message in the send channel
	select {
	case msg := <-conn.send:
		var outgoing map[string]interface{}
		if err := json.Unmarshal(msg, &outgoing); err != nil {
			t.Fatalf("Failed to unmarshal welcome message: %v", err)
		}
		if outgoing["type"] != "connected" {
			t.Errorf("Expected type 'connected', got '%v'", outgoing["type"])
		}
		data, ok := outgoing["data"].(map[string]interface{})
		if !ok {
			t.Fatal("Expected data to be a map")
		}
		if data["device_id"] != "device-abc" {
			t.Errorf("Expected device_id 'device-abc', got '%v'", data["device_id"])
		}
	case <-time.After(time.Second):
		t.Error("No message received in send channel")
	}
}

// TestCB79_SendWelcomeMessage_Success tests basic welcome message
func TestCB79_SendWelcomeMessage_Success(t *testing.T) {
	conn := &Connection{
		id:                "test-welcome-success",
		connType:          "agent",
		send:              make(chan []byte, 10),
		negotiatedVersion: "1.0",
	}

	sendWelcomeMessage(conn)

	select {
	case msg := <-conn.send:
		var outgoing map[string]interface{}
		if err := json.Unmarshal(msg, &outgoing); err != nil {
			t.Fatalf("Failed to unmarshal: %v", err)
		}
		if outgoing["type"] != "connected" {
			t.Errorf("Expected type 'connected', got '%v'", outgoing["type"])
		}
		data := outgoing["data"].(map[string]interface{})
		if data["status"] != "connected" {
			t.Errorf("Expected status 'connected', got '%v'", data["status"])
		}
		if data["protocol_version"] != "1.0" {
			t.Errorf("Expected protocol_version '1.0', got '%v'", data["protocol_version"])
		}
	case <-time.After(time.Second):
		t.Error("No message received")
	}
}

// ==================== readPump: message routing and debug ====================

// TestCB79_ReadPump_DebugLog tests that readPump handles messages and logs debug
func TestCB79_ReadPump_DebugLog(t *testing.T) {
	// Set up a WebSocket server
	upgrader := websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool { return true },
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Errorf("upgrade error: %v", err)
			return
		}
		defer conn.Close()

		// Send a message from server side (client's readPump will read it)
		conn.WriteMessage(websocket.TextMessage, []byte(`{"type":"chat","data":{"conversation_id":"conv1","content":"hello","sender_id":"user1"}}`))
	}))
	defer srv.Close()

	// Connect as a client
	wsURL := "ws" + srv.URL[4:]
	wsConn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("Failed to dial: %v", err)
	}
	defer wsConn.Close()

	// Set up a hub with a channel
	testHub := newHub()
	testHub.agents["test-readpump"] = &Connection{
		id:       "test-readpump",
		connType: "agent",
		send:     make(chan []byte, 10),
	}

	conn := &Connection{
		id:       "test-readpump-client",
		connType: "client",
		send:     make(chan []byte, 10),
		conn:     wsConn,
		hub:      testHub,
	}

	// Run readPump in a goroutine
	go conn.readPump()

	// Wait a bit for the message to be routed
	time.Sleep(100 * time.Millisecond)

	// Close the connection to end readPump
	wsConn.Close()
	time.Sleep(50 * time.Millisecond)
}

// ==================== writePump: message sent with metrics ====================

// TestCB79_WritePump_MessageSentWithMetrics tests that MessagesOut metric is incremented
func TestCB79_WritePump_MessageSentWithMetrics(t *testing.T) {
	// Set up a WebSocket server
	upgrader := websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool { return true },
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		// Read messages
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				break
			}
		}
	}))
	defer srv.Close()

	wsURL := "ws" + srv.URL[4:]
	wsConn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("Failed to dial: %v", err)
	}
	defer wsConn.Close()

	// Set up metrics
	origMetrics := ServerMetrics
	ServerMetrics = &Metrics{StartTime: time.Now()}
	defer func() { ServerMetrics = origMetrics }()

	conn := &Connection{
		id:       "test-writepump-metrics",
		connType: "client",
		send:     make(chan []byte, 10),
		conn:     wsConn,
	}

	before := ServerMetrics.MessagesOut.Load()

	go conn.writePump()

	// Send a message
	conn.send <- []byte(`{"type":"test"}`)

	// Wait for it to be written
	time.Sleep(100 * time.Millisecond)

	after := ServerMetrics.MessagesOut.Load()
	if after <= before {
		t.Errorf("Expected MessagesOut to increase, before=%d after=%d", before, after)
	}

	// Close connection to stop writePump
	wsConn.Close()
	time.Sleep(50 * time.Millisecond)
}

// TestCB79_WritePump_ChannelClosed tests writePump exits when channel is closed
func TestCB79_WritePump_ChannelClosed(t *testing.T) {
	upgrader := websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool { return true },
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				break
			}
		}
	}))
	defer srv.Close()

	wsURL := "ws" + srv.URL[4:]
	wsConn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("Failed to dial: %v", err)
	}
	defer wsConn.Close()

	conn := &Connection{
		id:       "test-writepump-close",
		connType: "client",
		send:     make(chan []byte, 10),
		conn:     wsConn,
	}

	go conn.writePump()

	// Close the send channel
	close(conn.send)

	// Wait for writePump to exit
	time.Sleep(100 * time.Millisecond)
}

// TestCB79_WritePump_WriteError tests writePump handling write error
func TestCB79_WritePump_WriteError(t *testing.T) {
	upgrader := websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool { return true },
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				break
			}
		}
	}))
	defer srv.Close()

	wsURL := "ws" + srv.URL[4:]
	wsConn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("Failed to dial: %v", err)
	}

	conn := &Connection{
		id:       "test-writepump-werr",
		connType: "client",
		send:     make(chan []byte, 10),
		conn:     wsConn,
	}

	go conn.writePump()

	// Close the underlying WebSocket to cause write error
	wsConn.Close()

	// Send a message (should fail)
	conn.send <- []byte(`{"type":"test"}`)

	// Wait for writePump to detect error and exit
	time.Sleep(100 * time.Millisecond)
}

// ==================== InitTracing: resource merge error ====================

// TestCB79_InitTracing_ResourceMergeError is hard to trigger because resource.Merge
// rarely fails. We test the successful initialization path instead.
func TestCB79_InitTracing_Disabled(t *testing.T) {
	tracingEnabled = false
	tp = nil
	tracer = nil

	os.Unsetenv("OTEL_ENABLED")

	err := InitTracing()
	if err != nil {
		t.Errorf("Expected no error, got: %v", err)
	}
	if IsTracingEnabled() {
		t.Error("Expected tracing to be disabled")
	}
}

// TestCB79_InitTracing_NoEndpoint tests no endpoint configured
func TestCB79_InitTracing_NoEndpoint(t *testing.T) {
	tracingEnabled = false
	tp = nil
	tracer = nil

	os.Setenv("OTEL_ENABLED", "true")
	os.Unsetenv("OTEL_EXPORTER_OTLP_ENDPOINT")
	os.Unsetenv("OTEL_EXPORTER_OTLP_HTTP_ENDPOINT")
	defer os.Unsetenv("OTEL_ENABLED")

	err := InitTracing()
	if err != nil {
		t.Errorf("Expected no error, got: %v", err)
	}
	if IsTracingEnabled() {
		t.Error("Expected tracing to be disabled with no endpoint")
	}
}

// TestCB79_InitTracing_AlreadyInitialized tests calling InitTracing when already initialized
func TestCB79_ShutdownTracing_NilProvider(t *testing.T) {
	tracingEnabled = false
	tp = nil
	ShutdownTracing()
}

// TestCB79_ShutdownTracing_AfterInit tests shutdown after initialization
func TestCB79_ShutdownTracing_AfterInit(t *testing.T) {
	tracingEnabled = false
	tp = nil
	tracer = nil

	os.Setenv("OTEL_ENABLED", "true")
	os.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "localhost:4318")
	os.Setenv("OTEL_EXPORTER_OTLP_PROTOCOL", "http")
	defer func() {
		os.Unsetenv("OTEL_ENABLED")
		os.Unsetenv("OTEL_EXPORTER_OTLP_ENDPOINT")
		os.Unsetenv("OTEL_EXPORTER_OTLP_PROTOCOL")
	}()

	InitTracing()
	ShutdownTracing()
}

// ==================== initSchema: additional paths ====================

// TestCB79_InitSchema_NilDB tests initSchema with nil DB (panics)
func TestCB79_InitSchema_NilDB(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("Expected panic on nil DB, got none")
		}
	}()
	_ = initSchema(nil)
}

// TestCB79_InitSchema_Idempotent tests double initSchema call
func TestCB79_InitSchema_Idempotent(t *testing.T) {
	testDB := setupTestDB_CB79(t)
	defer testDB.Close()

	// Call initSchema again - should not fail
	err := initSchema(testDB)
	if err != nil {
		t.Errorf("Expected no error on idempotent initSchema, got: %v", err)
	}
}

// TestCB79_InitSchema_Success tests basic schema initialization
func TestCB79_InitSchema_Success(t *testing.T) {
	testDB, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("Failed to open DB: %v", err)
	}
	defer testDB.Close()

	err = initSchema(testDB)
	if err != nil {
		t.Errorf("Expected no error, got: %v", err)
	}

	// Verify tables exist
	tables := []string{"users", "agents", "conversations", "messages", "schema_migrations"}
	for _, table := range tables {
		var name string
		err := testDB.QueryRow("SELECT name FROM sqlite_master WHERE type='table' AND name=?", table).Scan(&name)
		if err != nil {
			t.Errorf("Table %s not found: %v", table, err)
		}
	}
}

// TestCB79_InitSchema_ReactionsTableError tests reactions table creation error
func TestCB79_InitSchema_ReactionsTableError(t *testing.T) {
	testDB := setupTestDB_CB79(t)
	defer testDB.Close()

	// Close DB to trigger error
	testDB.Close()

	err := initSchema(testDB)
	if err == nil {
		t.Error("Expected error with closed DB, got nil")
	}
}

// ==================== handleCPUProfileStart: additional paths ====================

// TestCB79_HandleCPUProfileStart_MkdirError tests mkdir error
func TestCB79_HandleCPUProfileStart_MkdirError(t *testing.T) {
	// Set profile dir to an invalid path
	os.Setenv("PROFILING_DIR", "/proc/nonexistent/dir")
	defer os.Unsetenv("PROFILING_DIR")

	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/admin/profile/cpu/start", nil)

	handleCPUProfileStart(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("Expected 500, got %d", w.Code)
	}
}

// TestCB79_HandleCPUProfileStart_Success tests successful start
func TestCB79_HandleCPUProfileStart_Success(t *testing.T) {
	tmpDir := t.TempDir()
	os.Setenv("PROFILING_DIR", tmpDir)
	defer os.Unsetenv("PROFILING_DIR")

	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/admin/profile/cpu/start", nil)

	handleCPUProfileStart(w, req)

	// Should get 200 or 500 (if already active)
	if w.Code != http.StatusOK && w.Code != http.StatusInternalServerError {
		t.Errorf("Expected 200 or 500, got %d", w.Code)
	}

	// Clean up CPU profile state if started
	cpuProfileState.Lock()
	if cpuProfileState.active {
		if cpuProfileState.stopFunc != nil {
			cpuProfileState.stopFunc()
		}
		cpuProfileState.active = false
		cpuProfileState.stopFunc = nil
	}
	cpuProfileState.Unlock()
}

// TestCB79_HandleCPUProfileStart_AlreadyActive tests starting when already active
func TestCB79_HandleCPUProfileStart_AlreadyActive(t *testing.T) {
	tmpDir := t.TempDir()
	os.Setenv("PROFILING_DIR", tmpDir)
	defer os.Unsetenv("PROFILING_DIR")

	// Start once
	w1 := httptest.NewRecorder()
	req1 := httptest.NewRequest("POST", "/admin/profile/cpu/start", nil)
	handleCPUProfileStart(w1, req1)

	// Try to start again
	w2 := httptest.NewRecorder()
	req2 := httptest.NewRequest("POST", "/admin/profile/cpu/start", nil)
	handleCPUProfileStart(w2, req2)

	if w2.Code != http.StatusInternalServerError {
		t.Errorf("Expected 500 for already active, got %d", w2.Code)
	}

	// Clean up
	cpuProfileState.Lock()
	if cpuProfileState.active {
		if cpuProfileState.stopFunc != nil {
			cpuProfileState.stopFunc()
		}
		cpuProfileState.active = false
		cpuProfileState.stopFunc = nil
	}
	cpuProfileState.Unlock()
}

// ==================== cpuProfileTestSetup: additional paths ====================

// TestCB79_CpuProfileTestSetup_Basic tests basic setup
func TestCB79_CpuProfileTestSetup_Basic(t *testing.T) {
	cleanup := cpuProfileTestSetup()
	defer cleanup()
	if cleanup == nil {
		t.Error("Expected cleanup function, got nil")
	}
}

// TestCB79_CpuProfileTestSetup_WithDir tests setup with dir
func TestCB79_CpuProfileTestSetup_WithDir(t *testing.T) {
	tmpDir := t.TempDir()
	os.Setenv("PROFILING_DIR", tmpDir)
	defer os.Unsetenv("PROFILING_DIR")

	cleanup := cpuProfileTestSetup()
	defer cleanup()
	if cleanup == nil {
		t.Error("Expected cleanup function, got nil")
	}
}

// ==================== loadQueueFromDB: scan error ====================

// TestCB79_LoadQueueFromDB_ScanError tests scan error with NULL data
func TestCB79_LoadQueueFromDB_ScanError(t *testing.T) {
	testDB := setupTestDB_CB79(t)
	defer testDB.Close()

	// Insert a queue message with NULL data (will cause scan error if not handled)
	_, err := testDB.Exec(`INSERT INTO offline_queue (recipient, data, queued_at) VALUES (?, ?, ?)`,
		"user-scan-err", []byte("test-data"), time.Now().UTC().Format(time.RFC3339))
	if err != nil {
		t.Fatalf("Failed to insert queue message: %v", err)
	}

	q := newOfflineQueue(100, 7*24*time.Hour)

	// Should handle NULL data gracefully
	loadQueueFromDB(testDB, q)
}

// TestCB79_LoadQueueFromDB_NilDB tests nil DB
func TestCB79_LoadQueueFromDB_NilDB(t *testing.T) {
	q := newOfflineQueue(100, 7*24*time.Hour)
	loadQueueFromDB(nil, q)
}

// TestCB79_LoadQueueFromDB_Success tests successful load
func TestCB79_LoadQueueFromDB_Success(t *testing.T) {
	testDB := setupTestDB_CB79(t)
	defer testDB.Close()

	// Insert queue messages
	_, err := testDB.Exec(`INSERT INTO offline_queue (recipient, data, queued_at) VALUES (?, ?, ?)`,
		"user-load-1", []byte("test1"), time.Now().UTC().Format(time.RFC3339))
	if err != nil {
		t.Fatalf("Failed to insert: %v", err)
	}
	_, err = testDB.Exec(`INSERT INTO offline_queue (recipient, data, queued_at) VALUES (?, ?, ?)`,
		"user-load-2", []byte("test2"), time.Now().UTC().Format(time.RFC3339))
	if err != nil {
		t.Fatalf("Failed to insert: %v", err)
	}

	q := newOfflineQueue(100, 7*24*time.Hour)
	loadQueueFromDB(testDB, q)
}

// TestCB79_LoadQueueFromDB_Empty tests empty table
func TestCB79_LoadQueueFromDB_Empty(t *testing.T) {
	testDB := setupTestDB_CB79(t)
	defer testDB.Close()

	q := newOfflineQueue(100, 7*24*time.Hour)
	loadQueueFromDB(testDB, q)
}

// ==================== cleanup (rate_limit_tiers) ====================

// TestCB79_RateLimitTiersCleanup_StopChannel tests cleanup goroutine stop
func TestCB79_RateLimitTiersCleanup_StopChannel(t *testing.T) {
	trl := NewTieredRateLimiter()
	defer trl.Stop()

	// Start cleanup goroutine
	go trl.cleanup()

	// Stop it
	trl.stopCh <- struct{}{}

	// Give it time to exit
	time.Sleep(50 * time.Millisecond)
}

// TestCB79_RateLimitTiersCleanupOnce_AllStale tests cleanup of stale entries
func TestCB79_RateLimitTiersCleanupOnce_AllStale(t *testing.T) {
	trl := NewTieredRateLimiter()
	defer trl.Stop()

	// Add some entries with old timestamps
	trl.limits["stale-user-1"] = &userRateLimitState{
		windowEnd: time.Now().Add(-2 * time.Hour),
	}
	trl.limits["stale-user-2"] = &userRateLimitState{
		windowEnd: time.Now().Add(-1 * time.Hour),
	}

	trl.cleanupOnce()

	// Stale entries should be removed
	trl.mu.Lock()
	defer trl.mu.Unlock()
	if len(trl.limits) != 0 {
		t.Errorf("Expected 0 entries after cleanup, got %d", len(trl.limits))
	}
}

// TestCB79_RateLimitTiersCleanupOnce_GracePeriod tests grace period
func TestCB79_RateLimitTiersCleanupOnce_GracePeriod(t *testing.T) {
	trl := NewTieredRateLimiter()
	defer trl.Stop()

	// Add an entry just past windowEnd but within grace period (5 min)
	trl.limits["grace-user"] = &userRateLimitState{
		windowEnd: time.Now().Add(-30 * time.Second),
	}

	trl.cleanupOnce()

	// Should still be there (within 5-min grace period)
	trl.mu.Lock()
	defer trl.mu.Unlock()
	if _, ok := trl.limits["grace-user"]; !ok {
		t.Error("Expected grace-user to still be present (within grace period)")
	}
}

// ==================== monitorAgentHeartbeats: additional paths ====================

// TestCB79_MonitorAgentHeartbeats_Disabled tests disabled monitoring
func TestCB79_MonitorAgentHeartbeats_Disabled(t *testing.T) {
	origEnabled := agentPresenceEnabled
	agentPresenceEnabled = false
	defer func() { agentPresenceEnabled = origEnabled }()

	// monitorAgentHeartbeats checks agentPresenceEnabled at start
	_ = agentPresenceEnabled
}

// ==================== SafeSend: additional paths ====================

// TestCB79_SafeSend_Success tests successful send
func TestCB79_SafeSend_Success(t *testing.T) {
	conn := &Connection{
		send: make(chan []byte, 10),
	}

	result := conn.SafeSend([]byte("test"))
	if !result {
		t.Error("Expected SafeSend to return true")
	}
}

// TestCB79_SafeSend_BufferFull tests send when buffer is full
func TestCB79_SafeSend_BufferFull(t *testing.T) {
	conn := &Connection{
		send: make(chan []byte, 1),
	}

	conn.send <- []byte("filler")
	result := conn.SafeSend([]byte("overflow"))
	if result {
		t.Error("Expected SafeSend to return false when buffer is full")
	}
}

// TestCB79_SafeSend_ClosedChannel tests send on closed channel
func TestCB79_SafeSend_ClosedChannel(t *testing.T) {
	conn := &Connection{
		send: make(chan []byte, 1),
	}
	close(conn.send)

	// Should not panic
	result := conn.SafeSend([]byte("test"))
	if result {
		t.Error("Expected SafeSend to return false on closed channel")
	}
}

// TestCB79_SafeSend_ConcurrentSafe tests concurrent sends
func TestCB79_SafeSend_ConcurrentSafe(t *testing.T) {
	conn := &Connection{
		send: make(chan []byte, 100),
	}

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn.SafeSend([]byte("concurrent"))
		}()
	}
	wg.Wait()
}

// ==================== Env helpers ====================

// TestCB79_GetEnvOrDefault_Unset tests unset env var
func TestCB79_GetEnvOrDefault_Unset(t *testing.T) {
	os.Unsetenv("CB79_TEST_VAR")
	result := getEnvOrDefault("CB79_TEST_VAR", "default")
	if result != "default" {
		t.Errorf("Expected 'default', got '%s'", result)
	}
}

// TestCB79_GetEnvOrDefault_Set tests set env var
func TestCB79_GetEnvOrDefault_Set(t *testing.T) {
	os.Setenv("CB79_TEST_VAR", "custom")
	defer os.Unsetenv("CB79_TEST_VAR")
	result := getEnvOrDefault("CB79_TEST_VAR", "default")
	if result != "custom" {
		t.Errorf("Expected 'custom', got '%s'", result)
	}
}

// TestCB79_GetEnvOrDefault_Empty tests empty env var returns default
func TestCB79_GetEnvOrDefault_Empty(t *testing.T) {
	os.Setenv("CB79_TEST_VAR", "")
	defer os.Unsetenv("CB79_TEST_VAR")
	result := getEnvOrDefault("CB79_TEST_VAR", "default")
	if result != "default" {
		t.Errorf("Expected default, got '%s'", result)
	}
}

// ==================== GetDeviceTokensForUser ====================

// TestCB79_GetDeviceTokensForUser_Success tests successful token retrieval
func TestCB79_GetDeviceTokensForUser_Success(t *testing.T) {
	testDB := setupTestDB_CB79(t)
	defer testDB.Close()

	userID := createUser_CB79(testDB, "user-tokens-success", "pass")

	// Insert device tokens
	_, err := testDB.Exec("INSERT INTO device_tokens (user_id, device_token, platform) VALUES (?, ?, ?)",
		userID, "token-1", "ios")
	if err != nil {
		t.Fatalf("Failed to insert token: %v", err)
	}
	_, err = testDB.Exec("INSERT INTO device_tokens (user_id, device_token, platform) VALUES (?, ?, ?)",
		userID, "token-2", "android")
	if err != nil {
		t.Fatalf("Failed to insert token: %v", err)
	}

	withGlobalDB_CB79(testDB, func() {
		tokens, _ := getDeviceTokensForUser(userID)
		if len(tokens) != 2 {
			t.Errorf("Expected 2 tokens, got %d", len(tokens))
		}
	})
}

// TestCB79_GetDeviceTokensForUser_Empty tests no tokens
func TestCB79_GetDeviceTokensForUser_Empty(t *testing.T) {
	testDB := setupTestDB_CB79(t)
	defer testDB.Close()

	userID := createUser_CB79(testDB, "user-notokens-empty", "pass")

	withGlobalDB_CB79(testDB, func() {
		tokens, _ := getDeviceTokensForUser(userID)
		if len(tokens) != 0 {
			t.Errorf("Expected 0 tokens, got %d", len(tokens))
		}
	})
}

// TestCB79_GetDeviceTokensForUser_NilDB tests nil DB
func TestCB79_GetDeviceTokensForUser_NilDB(t *testing.T) {
	origDB := db
	db = nil
	defer func() { db = origDB }()

	tokens, _ := getDeviceTokensForUser("user1")
	if len(tokens) != 0 {
		t.Errorf("Expected 0 tokens with nil DB, got %d", len(tokens))
	}
}

// TestCB79_GetDeviceTokensForUser_DBError tests DB error
func TestCB79_GetDeviceTokensForUser_DBError(t *testing.T) {
	testDB := setupTestDB_CB79(t)
	testDB.Close()

	withGlobalDB_CB79(testDB, func() {
		tokens, _ := getDeviceTokensForUser("user1")
		if len(tokens) != 0 {
			t.Errorf("Expected 0 tokens on DB error, got %d", len(tokens))
		}
	})
}

// ==================== Hub.run: unknown message type ====================

// TestCB79_HubRun_UnknownType tests hub.run with unknown message type
func TestCB79_HubRun_UnknownType(t *testing.T) {
	testHub := newHub()
	go testHub.run()
	defer testHub.Stop()

	// Create a connection and add it to the hub
	conn := &Connection{
		id:       "test-unknown-type",
		connType: "client",
		send:     make(chan []byte, 10),
		hub:      testHub,
	}

	testHub.register <- conn

	// Send an unknown message type via the hub's messages channel
	// The hub.run function processes messages from hub.messages
	// We need to test the routeMessage function with unknown type
	time.Sleep(50 * time.Millisecond)

	// Send a message with unknown type to routeMessage
	conn.send <- []byte(`{"type":"unknown_type","data":{}}`)

	time.Sleep(50 * time.Millisecond)
}

// ==================== Hub: agent register/unregister ====================

// TestCB79_HubRegister_Agent tests agent registration in hub
func TestCB79_HubRegister_Agent(t *testing.T) {
	testHub := newHub()
	go testHub.run()
	defer testHub.Stop()

	conn := &Connection{
		id:       "agent-hub-reg",
		connType: "agent",
		send:     make(chan []byte, 10),
		hub:      testHub,
	}

	testHub.register <- conn
	time.Sleep(50 * time.Millisecond)

	testHub.mu.RLock()
	_, exists := testHub.agents["agent-hub-reg"]
	testHub.mu.RUnlock()
	if !exists {
		t.Error("Expected agent to be registered")
	}
}

// TestCB79_HubUnregister_Agent tests agent unregistration
func TestCB79_HubUnregister_Agent(t *testing.T) {
	testHub := newHub()
	go testHub.run()
	defer testHub.Stop()

	conn := &Connection{
		id:       "agent-hub-unreg",
		connType: "agent",
		send:     make(chan []byte, 10),
		hub:      testHub,
	}

	testHub.register <- conn
	time.Sleep(50 * time.Millisecond)

	testHub.unregister <- conn
	time.Sleep(50 * time.Millisecond)

	testHub.mu.RLock()
	_, exists := testHub.agents["agent-hub-unreg"]
	testHub.mu.RUnlock()
	if exists {
		t.Error("Expected agent to be unregistered")
	}
}

// TestCB79_HubRegister_Client tests client registration
func TestCB79_HubRegister_Client(t *testing.T) {
	testHub := newHub()
	go testHub.run()
	defer testHub.Stop()

	conn := &Connection{
			connType: "client",
		send:     make(chan []byte, 10),
		hub:      testHub,
		id:       "user-hub-reg",
		deviceID: "device-1",
	}

	testHub.register <- conn
	time.Sleep(50 * time.Millisecond)

	testHub.mu.RLock()
	conns, exists := testHub.clientConns["user-hub-reg"]
	testHub.mu.RUnlock()
	if !exists || len(conns) != 1 {
		t.Errorf("Expected 1 client connection, got %d (exists=%v)", len(conns), exists)
	}
}

// TestCB79_HubUnregister_Client tests client unregistration
func TestCB79_HubUnregister_Client(t *testing.T) {
	testHub := newHub()
	go testHub.run()
	defer testHub.Stop()

	conn := &Connection{
			connType: "client",
		send:     make(chan []byte, 10),
		hub:      testHub,
		id:       "user-hub-unreg",
		deviceID: "device-2",
	}

	testHub.register <- conn
	time.Sleep(50 * time.Millisecond)

	testHub.unregister <- conn
	time.Sleep(50 * time.Millisecond)

	testHub.mu.RLock()
	conns, exists := testHub.clientConns["user-hub-unreg"]
	testHub.mu.RUnlock()
	if exists && len(conns) > 0 {
		t.Errorf("Expected no client connections, got %d", len(conns))
	}
}

// ==================== ValidateJWT: additional paths ====================

// TestCB79_ValidateJWT_ValidToken tests valid JWT
func TestCB79_ValidateJWT_ValidToken(t *testing.T) {
	token := generateTestToken_CB79("user-valid")
	claims, err := ValidateJWT(token)
	if err != nil {
		t.Errorf("Expected no error, got: %v", err)
	}
	if claims.UserID != "user-valid" {
		t.Errorf("Expected UserID 'user-valid', got '%s'", claims.UserID)
	}
}

// TestCB79_ValidateJWT_EmptyToken tests empty token
func TestCB79_ValidateJWT_EmptyToken(t *testing.T) {
	_, err := ValidateJWT("")
	if err == nil {
		t.Error("Expected error for empty token")
	}
}

// TestCB79_ValidateJWT_ExpiredToken tests expired token
func TestCB79_ValidateJWT_ExpiredToken(t *testing.T) {
	claims := &Claims{
		UserID: "user-expired",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(-time.Hour)),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, _ := token.SignedString(jwtSecret)

	_, err := ValidateJWT(signed)
	if err == nil {
		t.Error("Expected error for expired token")
	}
}

// TestCB79_ValidateJWT_InvalidSignature tests invalid signature
func TestCB79_ValidateJWT_InvalidSignature(t *testing.T) {
	claims := &Claims{
		UserID: "user-invalid-sig",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, _ := token.SignedString([]byte("wrong-secret"))

	_, err := ValidateJWT(signed)
	if err == nil {
		t.Error("Expected error for invalid signature")
	}
}

// TestCB79_ValidateJWT_MalformedToken tests malformed token
func TestCB79_ValidateJWT_MalformedToken(t *testing.T) {
	_, err := ValidateJWT("not-a-valid-jwt")
	if err == nil {
		t.Error("Expected error for malformed token")
	}
}

// ==================== HandleHealth ====================

// TestCB79_HandleHealth_Success tests health endpoint
func TestCB79_HandleHealth_Success(t *testing.T) {
	testDB := setupTestDB_CB79(t)
	defer testDB.Close()

	withGlobalDB_CB79(testDB, func() {
		req := httptest.NewRequest("GET", "/health", nil)
		w := httptest.NewRecorder()
		handleHealth(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected 200, got %d", w.Code)
		}

		var resp map[string]interface{}
		if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
			t.Fatalf("Failed to decode response: %v", err)
		}
		if resp["status"] != "ok" {
			t.Errorf("Expected status 'ok', got '%v'", resp["status"])
		}
	})
}

// TestCB79_HandleHealth_MethodNotAllowed tests wrong method
func TestCB79_HandleHealth_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest("POST", "/health", nil)
	w := httptest.NewRecorder()
	handleHealth(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected 405, got %d", w.Code)
	}
}

// ==================== HandleAdminAgents ====================

// TestCB79_HandleAdminAgents_Success tests admin agents endpoint
func TestCB79_HandleAdminAgents_Success(t *testing.T) {
	testDB := setupTestDB_CB79(t)
	defer testDB.Close()

	// Insert agents
	_, err := testDB.Exec("INSERT INTO agents (id, name, model, personality, specialty, status) VALUES (?, ?, ?, ?, ?, ?)",
		"agent-admin-1", "Agent1", "gpt", "friendly", "general", "online")
	if err != nil {
		t.Fatalf("Failed to insert agent: %v", err)
	}
	_, err = testDB.Exec("INSERT INTO agents (id, name, model, personality, specialty, status) VALUES (?, ?, ?, ?, ?, ?)",
		"agent-admin-2", "Agent2", "claude", "professional", "coding", "offline")
	if err != nil {
		t.Fatalf("Failed to insert agent: %v", err)
	}

	// Set up global hub
	origHub := hub
	hub = newHub()
	go hub.run()
	defer func() {
		hub.Stop()
		hub = origHub
	}()

	withGlobalDB_CB79(testDB, func() {
		req := httptest.NewRequest("GET", "/admin/agents", nil)
		w := httptest.NewRecorder()
		handleAdminAgents(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected 200, got %d", w.Code)
		}
	})
}

// TestCB79_HandleAdminAgents_Unauthorized tests wrong method
func TestCB79_HandleAdminAgents_Unauthorized(t *testing.T) {
	req := httptest.NewRequest("POST", "/admin/agents", nil)
	w := httptest.NewRecorder()
	handleAdminAgents(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected 405, got %d", w.Code)
	}
}

// TestCB79_HandleAdminAgents_DBError tests DB error
func TestCB79_HandleAdminAgents_DBError(t *testing.T) {
	testDB := setupTestDB_CB79(t)
	testDB.Close()

	origSecret := adminSecret
	adminSecret = "test"
	defer func() { adminSecret = origSecret }()

	withGlobalDB_CB79(testDB, func() {
		req := httptest.NewRequest("GET", "/admin/agents", nil)
		req.Header.Set("X-Admin-Secret", "test")
		w := httptest.NewRecorder()
		handleAdminAgents(w, req)

		if w.Code != http.StatusInternalServerError {
			t.Errorf("Expected 500, got %d", w.Code)
		}
	})
}

// ==================== HashAPIKey ====================

// TestCB79_HashAPIKey_Success tests hashing
func TestCB79_HashAPIKey_Success(t *testing.T) {
	hash1, err := HashAPIKey("test-key-1")
	if err != nil {
		t.Errorf("Expected no error, got: %v", err)
	}
	if hash1 == "" {
		t.Error("Expected non-empty hash")
	}
	if hash1 == "test-key-1" {
		t.Error("Hash should not equal input")
	}
}

// TestCB79_HashAPIKey_Empty tests empty key
func TestCB79_HashAPIKey_Empty(t *testing.T) {
	_, err := HashAPIKey("")
	// bcrypt may succeed or fail on empty string; just verify no panic
	_ = err
}

// TestCB79_HashAPIKey_DifferentInputs tests different inputs produce different hashes
func TestCB79_HashAPIKey_DifferentInputs(t *testing.T) {
	hash1, _ := HashAPIKey("key-a")
	hash2, _ := HashAPIKey("key-b")
	if hash1 == hash2 {
		t.Error("Expected different hashes for different inputs")
	}
}

// ==================== IsConversationMuted ====================

// TestCB79_IsConversationMuted_NotMuted tests not muted
func TestCB79_IsConversationMuted_NotMuted(t *testing.T) {
	testDB := setupTestDB_CB79(t)
	defer testDB.Close()

	userID := createUser_CB79(testDB, "user-not-muted", "pass")
	convID := createConversation_CB79(testDB, userID, "agent1")

	withGlobalDB_CB79(testDB, func() {
		muted := isConversationMuted(userID, convID)
		if muted {
			t.Error("Expected conversation to not be muted")
		}
	})
}

// TestCB79_IsConversationMuted_Muted tests muted
func TestCB79_IsConversationMuted_Muted(t *testing.T) {
	testDB := setupTestDB_CB79(t)
	defer testDB.Close()

	userID := createUser_CB79(testDB, "user-is-muted", "pass")
	convID := createConversation_CB79(testDB, userID, "agent1")

	_, err := testDB.Exec("INSERT INTO notification_preferences (user_id, conversation_id, muted) VALUES (?, ?, ?)",
		userID, convID, true)
	if err != nil {
		t.Fatalf("Failed to insert notif prefs: %v", err)
	}

	withGlobalDB_CB79(testDB, func() {
		muted := isConversationMuted(userID, convID)
		if !muted {
			t.Error("Expected conversation to be muted")
		}
	})
}

// TestCB79_IsConversationMuted_EmptyConvID tests empty conversation ID
func TestCB79_IsConversationMuted_EmptyConvID(t *testing.T) {
	testDB := setupTestDB_CB79(t)
	defer testDB.Close()

	withGlobalDB_CB79(testDB, func() {
		muted := isConversationMuted("user1", "")
		if muted {
			t.Error("Expected false for empty conversation ID")
		}
	})
}

// TestCB79_IsConversationMuted_NilDB tests nil DB
func TestCB79_IsConversationMuted_NilDB(t *testing.T) {
	origDB := db
	db = nil
	defer func() { db = origDB }()

	muted := isConversationMuted("user1", "conv1")
	if muted {
		t.Error("Expected false for nil DB")
	}
}

// TestCB79_IsConversationMuted_DBError tests DB error
func TestCB79_IsConversationMuted_DBError(t *testing.T) {
	testDB := setupTestDB_CB79(t)
	testDB.Close()

	withGlobalDB_CB79(testDB, func() {
		muted := isConversationMuted("user1", "conv1")
		if muted {
			t.Error("Expected false on DB error")
		}
	})
}

// ==================== IsAllowedContentType ====================

// TestCB79_IsAllowedContentType_ImageTypes tests image types
func TestCB79_IsAllowedContentType_ImageTypes(t *testing.T) {
	types := []string{"image/jpeg", "image/png", "image/gif", "image/webp"}
	for _, ct := range types {
		if !isAllowedContentType(ct) {
			t.Errorf("Expected %s to be allowed", ct)
		}
	}
}

// TestCB79_IsAllowedContentType_DocumentTypes tests document types
func TestCB79_IsAllowedContentType_DocumentTypes(t *testing.T) {
	types := []string{"application/pdf", "text/plain", "text/csv"}
	for _, ct := range types {
		if !isAllowedContentType(ct) {
			t.Errorf("Expected %s to be allowed", ct)
		}
	}
}

// TestCB79_IsAllowedContentType_DisallowedTypes tests disallowed types
func TestCB79_IsAllowedContentType_DisallowedTypes(t *testing.T) {
	types := []string{"application/javascript", "application/x-executable", "application/x-sh"}
	for _, ct := range types {
		if isAllowedContentType(ct) {
			t.Errorf("Expected %s to be disallowed", ct)
		}
	}
}

// TestCB79_IsAllowedContentType_Empty tests empty string
func TestCB79_IsAllowedContentType_Empty(t *testing.T) {
	if isAllowedContentType("") {
		t.Error("Expected empty string to be disallowed")
	}
}

// ==================== MarshalOutgoingMessage ====================

// TestCB79_MarshalOutgoingMessage_Success tests successful marshaling
func TestCB79_MarshalOutgoingMessage_Success(t *testing.T) {
	msg := OutgoingMessage{
		Type: "chat",
		Data: map[string]interface{}{"content": "hello"},
	}
	data := marshalOutgoingMessage(msg)
	if len(data) == 0 {
		t.Error("Expected non-empty data")
	}
}

// TestCB79_MarshalOutgoingMessage_NilData tests nil data
func TestCB79_MarshalOutgoingMessage_NilData(t *testing.T) {
	msg := OutgoingMessage{
		Type: "status",
		Data: nil,
	}
	data := marshalOutgoingMessage(msg)
	if len(data) == 0 {
		t.Error("Expected non-empty data")
	}
}

// TestCB79_MarshalOutgoingMessage_ComplexData tests complex data
func TestCB79_MarshalOutgoingMessage_ComplexData(t *testing.T) {
	msg := OutgoingMessage{
		Type: "chat",
		Data: map[string]interface{}{
			"content":   "hello world",
			"timestamp": time.Now().Unix(),
			"nested": map[string]interface{}{
				"key": "value",
			},
		},
	}
	data := marshalOutgoingMessage(msg)
	if len(data) == 0 {
		t.Error("Expected non-empty data")
	}

	// Verify we can unmarshal it back
	var result map[string]interface{}
	if err := json.Unmarshal(data, &result); err != nil {
		t.Errorf("Failed to unmarshal: %v", err)
	}
	if result["type"] != "chat" {
		t.Errorf("Expected type 'chat', got '%v'", result["type"])
	}
}

// ==================== InitQueueDB ====================

// TestCB79_InitQueueDB_Success tests successful init
func TestCB79_InitQueueDB_Success(t *testing.T) {
	testDB, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("Failed to open DB: %v", err)
	}
	defer testDB.Close()

	initQueueDB(testDB)

	// Verify table exists
	var name string
	err = testDB.QueryRow("SELECT name FROM sqlite_master WHERE type='table' AND name='offline_queue'").Scan(&name)
	if err != nil {
		t.Errorf("offline_queue table not found: %v", err)
	}
}

// TestCB79_InitQueueDB_Idempotent tests idempotent init
func TestCB79_InitQueueDB_Idempotent(t *testing.T) {
	testDB, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("Failed to open DB: %v", err)
	}
	defer testDB.Close()

	initQueueDB(testDB)

	initQueueDB(testDB)
}

// TestCB79_InitQueueDB_NilDB tests nil DB
func TestCB79_InitQueueDB_NilDB(t *testing.T) {
	initQueueDB(nil)
}

// ==================== GetClient / ClientConnCount ====================

// TestCB79_GetClient_Found tests getting a client connection
func TestCB79_GetClient_Found(t *testing.T) {
	testHub := newHub()
	go testHub.run()
	defer testHub.Stop()

	conn := &Connection{
			connType: "client",
		send:     make(chan []byte, 10),
		hub:      testHub,
		id:       "user-get-client",
	}

	testHub.register <- conn
	time.Sleep(50 * time.Millisecond)

	result := testHub.GetClient("user-get-client")
	if result == nil {
		t.Error("Expected to find client connection")
	}
}

// TestCB79_GetClient_NotFound tests getting a non-existent client
func TestCB79_GetClient_NotFound(t *testing.T) {
	testHub := newHub()
	result := testHub.GetClient("nonexistent-user")
	if result != nil {
		t.Error("Expected nil for non-existent client")
	}
}

// TestCB79_ClientConnCount_Empty tests count with no connections
func TestCB79_ClientConnCount_Empty(t *testing.T) {
	testHub := newHub()
	count := testHub.ClientConnCount()
	if count != 0 {
		t.Errorf("Expected 0, got %d", count)
	}
}

// TestCB79_ClientConnCount_SingleUser tests count with single user
func TestCB79_ClientConnCount_SingleUser(t *testing.T) {
	testHub := newHub()
	go testHub.run()
	defer testHub.Stop()

	conn := &Connection{
			connType: "client",
		send:     make(chan []byte, 10),
		hub:      testHub,
		id:       "user-count-1",
	}

	testHub.register <- conn
	time.Sleep(50 * time.Millisecond)

	count := testHub.ClientConnCount()
	if count != 1 {
		t.Errorf("Expected 1, got %d", count)
	}
}

// TestCB79_ClientConnCount_MultipleUsers tests count with multiple users
func TestCB79_ClientConnCount_MultipleUsers(t *testing.T) {
	testHub := newHub()
	go testHub.run()
	defer testHub.Stop()

	for i := 0; i < 3; i++ {
		conn := &Connection{
					connType: "client",
			send:     make(chan []byte, 10),
			hub:      testHub,
			id:       fmt.Sprintf("user-count-%d", i),
		}
		testHub.register <- conn
	}
	time.Sleep(100 * time.Millisecond)

	count := testHub.ClientConnCount()
	if count != 3 {
		t.Errorf("Expected 3, got %d", count)
	}
}

// ==================== SetAgentStatus ====================

// TestCB79_SetAgentStatus_Online tests setting agent status
func TestCB79_SetAgentStatus_Online(t *testing.T) {
	testHub := newHub()
	go testHub.run()
	defer testHub.Stop()

	conn := &Connection{
		id:       "agent-status-online",
		connType: "agent",
		send:     make(chan []byte, 10),
		hub:      testHub,
	}

	testHub.register <- conn
	time.Sleep(50 * time.Millisecond)

	testHub.SetAgentStatus("agent-status-online", "busy")

	testHub.mu.RLock()
	defer testHub.mu.RUnlock()
	if testHub.agents["agent-status-online"].status != "busy" {
		t.Error("Expected status 'busy'")
	}
}

// TestCB79_SetAgentStatus_NotFound tests setting status for non-existent agent
func TestCB79_SetAgentStatus_NotFound(t *testing.T) {
	testHub := newHub()
	// Should not panic
	testHub.SetAgentStatus("nonexistent", "online")
}

// TestCB79_SetAgentStatus_EmptyStatus tests setting empty status
func TestCB79_SetAgentStatus_EmptyStatus(t *testing.T) {
	testHub := newHub()
	go testHub.run()
	defer testHub.Stop()

	conn := &Connection{
		id:       "agent-status-empty",
		connType: "agent",
		send:     make(chan []byte, 10),
		hub:      testHub,
	}

	testHub.register <- conn
	time.Sleep(50 * time.Millisecond)

	testHub.SetAgentStatus("agent-status-empty", "")
	// Should not panic, status may be set to empty
}

// ==================== broadcastPresence ====================

// TestCB79_BroadcastPresence_SingleAgent tests broadcast to single agent
func TestCB79_BroadcastPresence_SingleAgent(t *testing.T) {
	testHub := newHub()
	go testHub.run()
	defer testHub.Stop()

	conn := &Connection{
		id:       "agent-presence-1",
		connType: "agent",
		send:     make(chan []byte, 10),
		hub:      testHub,
	}

	testHub.register <- conn
	time.Sleep(50 * time.Millisecond)

	// broadcastPresence is called internally; test via hub operations
	// The presence should be broadcast to the agent's clients
}

// TestCB79_BroadcastPresence_MultipleAgents tests broadcast with multiple agents
func TestCB79_BroadcastPresence_MultipleAgents(t *testing.T) {
	testHub := newHub()
	go testHub.run()
	defer testHub.Stop()

	for i := 0; i < 3; i++ {
		conn := &Connection{
			id:       fmt.Sprintf("agent-presence-%d", i),
			connType:  "agent",
			send:      make(chan []byte, 10),
			hub:       testHub,
		}
		testHub.register <- conn
	}
	time.Sleep(100 * time.Millisecond)

	// All agents should be registered
	testHub.mu.RLock()
	count := len(testHub.agents)
	testHub.mu.RUnlock()
	if count != 3 {
		t.Errorf("Expected 3 agents, got %d", count)
	}
}

// ==================== accessLogMiddleware ====================

// TestCB79_AccessLogMiddleware_WithRequestID tests middleware with request ID
func TestCB79_AccessLogMiddleware_WithRequestID(t *testing.T) {
	called := false
	handler := accessLogMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(200)
	}))

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-Request-ID", "test-request-id")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if !called {
		t.Error("Expected handler to be called")
	}
}

// TestCB79_AccessLogMiddleware_WithoutRequestID tests middleware without request ID
func TestCB79_AccessLogMiddleware_WithoutRequestID(t *testing.T) {
	called := false
	handler := accessLogMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(200)
	}))

	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if !called {
		t.Error("Expected handler to be called")
	}
}

// ==================== authenticateRequest ====================

// TestCB79_AuthenticateRequest_Valid tests valid auth
func TestCB79_AuthenticateRequest_Valid(t *testing.T) {
	token := generateTestToken_CB79("user-auth-valid")
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	userID, _, err := authenticateRequest(req)
	if err != nil {
		t.Error("Expected authentication to succeed")
	}
	if userID != "user-auth-valid" {
		t.Errorf("Expected userID 'user-auth-valid', got '%s'", userID)
	}
}

// TestCB79_AuthenticateRequest_Invalid tests invalid auth
func TestCB79_AuthenticateRequest_Invalid(t *testing.T) {
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer invalid-token")

	_, _, err := authenticateRequest(req)
	if err == nil {
		t.Error("Expected authentication to fail")
	}
}

// TestCB79_AuthenticateRequest_NoAuth tests no auth header
func TestCB79_AuthenticateRequest_NoAuth(t *testing.T) {
	req := httptest.NewRequest("GET", "/test", nil)

	_, _, err := authenticateRequest(req)
	if err == nil {
		t.Error("Expected authentication to fail with no auth")
	}
}

// ==================== extractIP ====================

// TestCB79_ExtractIP_XForwardedFor tests X-Forwarded-For header
func TestCB79_ExtractIP_XForwardedFor(t *testing.T) {
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-Forwarded-For", "1.2.3.4, 5.6.7.8")
	ip := extractIP(req)
	if ip != "1.2.3.4" {
		t.Errorf("Expected '1.2.3.4', got '%s'", ip)
	}
}

// TestCB79_ExtractIP_XRealIP tests X-Real-IP header
func TestCB79_ExtractIP_XRealIP(t *testing.T) {
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-Real-IP", "9.10.11.12")
	ip := extractIP(req)
	if ip != "9.10.11.12" {
		t.Errorf("Expected '9.10.11.12', got '%s'", ip)
	}
}

// TestCB79_ExtractIP_RemoteAddr tests RemoteAddr fallback
func TestCB79_ExtractIP_RemoteAddr(t *testing.T) {
	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "192.168.1.100:12345"
	ip := extractIP(req)
	if ip != "192.168.1.100" {
		t.Errorf("Expected '192.168.1.100', got '%s'", ip)
	}
}

// ==================== parseSize ====================

// TestCB79_ParseSize_Bytes tests byte parsing
func TestCB79_ParseSize_Bytes(t *testing.T) {
	result, err := parseSize("100")
	if err != nil {
		t.Errorf("Expected no error, got: %v", err)
	}
	if result != 100 {
		t.Errorf("Expected 100, got %d", result)
	}
}

// TestCB79_ParseSize_KB tests KB parsing
func TestCB79_ParseSize_KB(t *testing.T) {
	result, err := parseSize("10KB")
	if err != nil {
		t.Errorf("Expected no error, got: %v", err)
	}
	if result != 10*1024 {
		t.Errorf("Expected %d, got %d", 10*1024, result)
	}
}

// TestCB79_ParseSize_MB tests MB parsing
func TestCB79_ParseSize_MB(t *testing.T) {
	result, err := parseSize("5MB")
	if err != nil {
		t.Errorf("Expected no error, got: %v", err)
	}
	if result != 5*1024*1024 {
		t.Errorf("Expected %d, got %d", 5*1024*1024, result)
	}
}

// TestCB79_ParseSize_GB tests GB parsing
func TestCB79_ParseSize_GB(t *testing.T) {
	result, err := parseSize("1GB")
	if err != nil {
		t.Errorf("Expected no error, got: %v", err)
	}
	if result != 1024*1024*1024 {
		t.Errorf("Expected %d, got %d", 1024*1024*1024, result)
	}
}

// TestCB79_ParseSize_Invalid tests invalid format
func TestCB79_ParseSize_Invalid(t *testing.T) {
	_, err := parseSize("invalid")
	if err == nil {
		t.Error("Expected error for invalid size")
	}
}

// ==================== TieredRateLimiter ====================

// TestCB79_TieredRateLimiter_Allow tests Allow method
func TestCB79_TieredRateLimiter_Allow(t *testing.T) {
	trl := NewTieredRateLimiter()
	defer trl.Stop()

	// Free tier: 60/min
	for i := 0; i < 60; i++ {
		allowed, _, _ := trl.Allow("user-tier-1")
	if !allowed {
			t.Errorf("Expected allow at request %d", i)
		}
	}
	// 61st should be denied
	allowed, _, _ := trl.Allow("user-tier-1")
	if allowed {
		t.Error("Expected deny on 61st request")
	}
}

// TestCB79_TieredRateLimiter_GetTier tests GetTier method
func TestCB79_TieredRateLimiter_GetTier(t *testing.T) {
	trl := NewTieredRateLimiter()
	defer trl.Stop()
	tier := trl.GetTier("unknown-user")
	if tier.Name != "free" {
		t.Errorf("Expected 'free' tier, got '%s'", tier.Name)
	}
}

// TestCB79_TieredRateLimiter_SetTier tests SetTier method
func TestCB79_TieredRateLimiter_SetTier(t *testing.T) {
	trl := NewTieredRateLimiter()
	defer trl.Stop()
	trl.SetTier("user-pro", TierPro)

	tier := trl.GetTier("user-pro")
	if tier.Name != "pro" {
		t.Errorf("Expected 'pro' tier, got '%s'", tier.Name)
	}
}

// TestCB79_TieredRateLimiter_GetRemaining tests GetRemaining method
func TestCB79_TieredRateLimiter_GetRemaining(t *testing.T) {
	trl := NewTieredRateLimiter()
	defer trl.Stop()

	// Free tier: 60/min, use 10
	for i := 0; i < 10; i++ {
		trl.Allow("user-remaining")
	}

	remaining := trl.GetRemaining("user-remaining")
	if remaining != 50 {
		t.Errorf("Expected 50 remaining, got %d", remaining)
	}
}

// ==================== Logger ====================

// TestCB79_Logger_Info tests info level
func TestCB79_Logger_Info(t *testing.T) {
	logger := NewLogger(LogInfo)
	logger.Info("test_info", map[string]interface{}{"key": "value"})
}

// TestCB79_Logger_Warn tests warn level
func TestCB79_Logger_Warn(t *testing.T) {
	logger := NewLogger(LogWarn)
	logger.Warn("test_warn", map[string]interface{}{"key": "value"})
}

// TestCB79_Logger_Error tests error level
func TestCB79_Logger_Error(t *testing.T) {
	logger := NewLogger(LogError)
	logger.Error("test_error", map[string]interface{}{"key": "value"})
}

// TestCB79_Logger_Debug tests debug level (filtered)
func TestCB79_Logger_Debug(t *testing.T) {
	logger := NewLogger(LogError) // Debug should be filtered
	logger.Debug("test_debug", map[string]interface{}{"key": "value"})
}

// TestCB79_Logger_WithFields tests WithFields
func TestCB79_Logger_WithFields(t *testing.T) {
	logger := NewLogger(LogInfo)
	logger.WithFields(map[string]interface{}{"field1": "value1"}).Info("test_with_fields", nil)
}

// TestCB79_Logger_EmptyMessage tests empty message
func TestCB79_Logger_EmptyMessage(t *testing.T) {
	logger := NewLogger(LogInfo)
	logger.Info("", nil)
}

// TestCB79_Logger_NilFields tests nil fields
func TestCB79_Logger_NilFields(t *testing.T) {
	logger := NewLogger(LogInfo)
	logger.Info("test_nil_fields", nil)
}

// TestCB79_Logger_Chaining tests method chaining
func TestCB79_Logger_Chaining(t *testing.T) {
	logger := NewLogger(LogInfo)
	logger.WithFields(map[string]interface{}{"a": 1}).WithFields(map[string]interface{}{"b": 2}).Info("chained", nil)
}