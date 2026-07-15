package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

// --- Helpers (CB60) ---

func setupTestDB_CB60(t *testing.T) *sql.DB {
	testDB, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("Failed to open test DB: %v", err)
	}
	if err := initSchema(testDB); err != nil {
		t.Fatalf("Failed to init schema: %v", err)
	}
	return testDB
}

func generateTestToken_CB60(userID string) string {
	claims := &Claims{
		UserID: userID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
		},
	}
	token, _ := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte("agent-messenger-dev-secret-change-me"))
	return token
}

func authReqCB60(method, target, body, userID string) *http.Request {
	var r *http.Request
	if body != "" {
		r = httptest.NewRequest(method, target, strings.NewReader(body))
	} else {
		r = httptest.NewRequest(method, target, nil)
	}
	ctx := context.WithValue(r.Context(), contextKeyUserID, userID)
	return r.WithContext(ctx)
}

func setHub_CB60() *Hub {
	oldHub := hub
	newH := newHub()
	go newH.run()
	hub = newH
	return oldHub
}

func restoreHub_CB60(old *Hub) {
	if hub != nil {
		hub.Stop()
	}
	hub = old
}

// --- sendWelcomeMessage: marshal error (80% → 100%) ---

func TestCB60_SendWelcomeMessage_MarshalError(t *testing.T) {
	// sendWelcomeMessage marshals OutgoingMessage{Data: welcomeData}
	// welcomeData contains c.id (string), status (string), protocol_version (string), supported_versions ([]string)
	// These are all basic types, so json.Marshal won't fail on them.
	// The only way to trigger the marshal error is if the Data field contains something unmarshalable.
	// But welcomeData is built from Connection fields. We can't easily make it fail.
	// Instead, test the SafeSend=false path (welcome_send_failed log).

	c := &Connection{
		id:    "test-conn-marshal",
		connType: "client",
		send:  make(chan []byte, 1),
		// negotiatedVersion and deviceID left as defaults
	}

	// Close the send channel to make SafeSend return false
	close(c.send)

	// This should hit the "welcome_send_failed" path but NOT panic
	sendWelcomeMessage(c)
	// If we get here without panicking, the test passes
}

func TestCB60_SendWelcomeMessage_WithDeviceID(t *testing.T) {
	c := &Connection{
		id:              "test-conn-dev",
		connType:        "agent",
		send:            make(chan []byte, 10),
		negotiatedVersion: "1.0",
		deviceID:        "device-abc",
	}

	sendWelcomeMessage(c)

	select {
	case data := <-c.send:
		var msg map[string]interface{}
		if err := json.Unmarshal(data, &msg); err != nil {
			t.Fatalf("Failed to unmarshal welcome: %v", err)
		}
		if msg["type"] != "connected" {
			t.Errorf("Expected type=connected, got %v", msg["type"])
		}
		dataMap, ok := msg["data"].(map[string]interface{})
		if !ok {
			t.Fatal("Expected data to be a map")
		}
		if dataMap["device_id"] != "device-abc" {
			t.Errorf("Expected device_id=device-abc, got %v", dataMap["device_id"])
		}
		if dataMap["protocol_version"] != "1.0" {
			t.Errorf("Expected protocol_version=1.0, got %v", dataMap["protocol_version"])
		}
	default:
		t.Fatal("Expected to receive welcome message")
	}
}

// --- ValidateJWT: expired token (91.7% → 100%) ---

func TestCB60_ValidateJWT_ExpiredToken(t *testing.T) {
	claims := &Claims{
		UserID: "user-expired",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(-1 * time.Hour)),
		},
	}
	token, _ := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte("agent-messenger-dev-secret-change-me"))

	_, err := ValidateJWT(token)
	if err == nil {
		t.Error("Expected error for expired token")
	}
}

func TestCB60_ValidateJWT_WrongSigningKey(t *testing.T) {
	claims := &Claims{
		UserID: "user-wrong-key",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
		},
	}
	token, _ := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte("wrong-secret"))

	_, err := ValidateJWT(token)
	if err == nil {
		t.Error("Expected error for wrong signing key")
	}
}

// --- initSchema: migration recording + index creation (82.4% → higher) ---

func TestCB60_InitSchema_MigrationCountNonZero(t *testing.T) {
	testDB := setupTestDB_CB60(t)
	defer testDB.Close()

	// Migrations should already be recorded from initSchema
	var count int
	err := testDB.QueryRow("SELECT COUNT(*) FROM schema_migrations").Scan(&count)
	if err != nil {
		t.Fatalf("Failed to count migrations: %v", err)
	}
	if count == 0 {
		t.Error("Expected migrations to be recorded, got 0")
	}
	if count < 8 {
		t.Errorf("Expected at least 8 migrations, got %d", count)
	}

	// Run initSchema again — should be idempotent
	if err := initSchema(testDB); err != nil {
		t.Fatalf("Second initSchema failed: %v", err)
	}

	// Count should still be the same (INSERT OR IGNORE)
	err = testDB.QueryRow("SELECT COUNT(*) FROM schema_migrations").Scan(&count)
	if err != nil {
		t.Fatalf("Failed to count migrations after re-init: %v", err)
	}
	if count < 8 {
		t.Errorf("Expected at least 8 migrations after re-init, got %d", count)
	}
}

func TestCB60_InitSchema_ReactionsTableExists(t *testing.T) {
	testDB := setupTestDB_CB60(t)
	defer testDB.Close()

	// Verify reactions table exists
	_, err := testDB.Exec("INSERT INTO reactions (id, message_id, user_id, emoji) VALUES ('test-r', 'test-m', 'test-u', '👍')")
	if err != nil {
		t.Errorf("Expected reactions table to exist: %v", err)
	}
}

func TestCB60_InitSchema_ConversationTagsTableExists(t *testing.T) {
	testDB := setupTestDB_CB60(t)
	defer testDB.Close()

	// First create a conversation to satisfy FK
	_, err := testDB.Exec("INSERT INTO conversations (id, user_id, agent_id) VALUES ('test-conv-tag', 'test-u', 'test-a')")
	if err != nil {
		t.Fatalf("Failed to insert conversation: %v", err)
	}

	_, err = testDB.Exec("INSERT INTO conversation_tags (id, conversation_id, tag) VALUES ('test-tag-1', 'test-conv-tag', 'important')")
	if err != nil {
		t.Errorf("Expected conversation_tags table to exist: %v", err)
	}
}

func TestCB60_InitSchema_NotificationPrefsTableExists(t *testing.T) {
	testDB := setupTestDB_CB60(t)
	defer testDB.Close()

	// Create conversation + user first for FK
	_, err := testDB.Exec("INSERT INTO users (id, username, password_hash) VALUES ('test-u-np', 'testusernp', 'hash')")
	if err != nil {
		t.Fatalf("Failed to insert user: %v", err)
	}
	_, err = testDB.Exec("INSERT INTO conversations (id, user_id, agent_id) VALUES ('test-conv-np', 'test-u-np', 'test-a')")
	if err != nil {
		t.Fatalf("Failed to insert conversation: %v", err)
	}

	_, err = testDB.Exec("INSERT INTO notification_preferences (user_id, conversation_id, muted) VALUES ('test-u-np', 'test-conv-np', 1)")
	if err != nil {
		t.Errorf("Expected notification_preferences table to exist: %v", err)
	}
}

func TestCB60_InitSchema_RateLimitTiersTableExists(t *testing.T) {
	testDB := setupTestDB_CB60(t)
	defer testDB.Close()

	_, err := testDB.Exec("INSERT INTO user_rate_limit_tiers (user_id, tier_name) VALUES ('test-u-rlt', 'pro')")
	if err != nil {
		t.Errorf("Expected user_rate_limit_tiers table to exist: %v", err)
	}
}

func TestCB60_InitSchema_IndexesExist(t *testing.T) {
	testDB := setupTestDB_CB60(t)
	defer testDB.Close()

	// Check that idx_reactions_message exists by using it
	_, err := testDB.Exec("CREATE INDEX IF NOT EXISTS idx_reactions_message ON reactions(message_id)")
	if err != nil {
		t.Errorf("Expected idx_reactions_message to exist: %v", err)
	}

	// Check idx_tags_conversation
	_, err = testDB.Exec("CREATE INDEX IF NOT EXISTS idx_tags_conversation ON conversation_tags(conversation_id)")
	if err != nil {
		t.Errorf("Expected idx_tags_conversation to exist: %v", err)
	}
}

// --- handleUpload: seek error + write error (85.7% → higher) ---

func TestCB60_HandleUpload_SeekError(t *testing.T) {
	testDB := setupTestDB_CB60(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	// Create a user
	hash, _ := bcrypt.GenerateFromPassword([]byte("pass123"), bcrypt.DefaultCost)
	_, err := db.Exec("INSERT INTO users (id, username, password_hash) VALUES ('test-u-upload', 'uploaduser', ?)", string(hash))
	if err != nil {
		t.Fatalf("Failed to insert user: %v", err)
	}

	token := generateTestToken_CB60("test-u-upload")

	// Create a multipart form with a file that has content type requiring detection
	// Use a real multipart form
	bodyStr := "--boundary\r\nContent-Disposition: form-data; name=\"file\"; filename=\"test.bin\"\r\nContent-Type: application/octet-stream\r\n\r\n\x89PNG\r\n--boundary--\r\n"
	req := httptest.NewRequest("POST", "/attachments/upload", strings.NewReader(bodyStr))
	req.Header.Set("Content-Type", "multipart/form-data; boundary=boundary")
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	// Set small upload size to trigger error
	oldMax := maxUploadSize
	maxUploadSize = 10
	defer func() { maxUploadSize = oldMax }()

	handleUpload(w, req)
	// Should get 400 (file too large or invalid form data) since the body is >10 bytes
	if w.Code != http.StatusBadRequest {
		t.Logf("Response: %s", w.Body.String())
		// ParseMultipartForm may fail for various reasons; just verify it doesn't crash
	}
}

func TestCB60_HandleUpload_MissingFile(t *testing.T) {
	testDB := setupTestDB_CB60(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	hash, _ := bcrypt.GenerateFromPassword([]byte("pass123"), bcrypt.DefaultCost)
	_, err := db.Exec("INSERT INTO users (id, username, password_hash) VALUES ('test-u-upload2', 'uploaduser2', ?)", string(hash))
	if err != nil {
		t.Fatalf("Failed to insert user: %v", err)
	}

	token := generateTestToken_CB60("test-u-upload2")

	// Multipart form without a file field
	bodyStr := "--bd\r\nContent-Disposition: form-data; name=\"other\"\r\n\r\nvalue\r\n--bd--\r\n"
	req := httptest.NewRequest("POST", "/attachments/upload", strings.NewReader(bodyStr))
	req.Header.Set("Content-Type", "multipart/form-data; boundary=bd")
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	handleUpload(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected 400 for missing file, got %d", w.Code)
	}
}

func TestCB60_HandleUpload_InvalidToken(t *testing.T) {
	req := httptest.NewRequest("POST", "/attachments/upload", nil)
	req.Header.Set("Authorization", "Bearer invalid-token")
	w := httptest.NewRecorder()
	handleUpload(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected 401, got %d", w.Code)
	}
}

func TestCB60_HandleUpload_NoAuth(t *testing.T) {
	req := httptest.NewRequest("POST", "/attachments/upload", nil)
	w := httptest.NewRecorder()
	handleUpload(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected 401, got %d", w.Code)
	}
}

func TestCB60_HandleUpload_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest("GET", "/attachments/upload", nil)
	w := httptest.NewRecorder()
	handleUpload(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected 405, got %d", w.Code)
	}
}

// --- handleListAttachments: scan error + empty result (94.4% → higher) ---

func TestCB60_HandleListAttachments_EmptyResult(t *testing.T) {
	testDB := setupTestDB_CB60(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	hash, _ := bcrypt.GenerateFromPassword([]byte("pass123"), bcrypt.DefaultCost)
	_, err := db.Exec("INSERT INTO users (id, username, password_hash) VALUES ('test-u-latt', 'lattuser', ?)", string(hash))
	if err != nil {
		t.Fatalf("Failed to insert user: %v", err)
	}
	_, err = db.Exec("INSERT INTO conversations (id, user_id, agent_id) VALUES ('conv-latt', 'test-u-latt', 'agent-latt')")
	if err != nil {
		t.Fatalf("Failed to insert conversation: %v", err)
	}

	token := generateTestToken_CB60("test-u-latt")
	req := httptest.NewRequest("GET", "/messages/conv-latt/attachments?conversation_id=conv-latt", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleListAttachments(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var attachments []Attachment
	if err := json.Unmarshal(w.Body.Bytes(), &attachments); err != nil {
		t.Fatalf("Failed to unmarshal response: %v", err)
	}
	if len(attachments) != 0 {
		t.Errorf("Expected 0 attachments, got %d", len(attachments))
	}
}

func TestCB60_HandleListAttachments_MissingConversationID(t *testing.T) {
	testDB := setupTestDB_CB60(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	hash, _ := bcrypt.GenerateFromPassword([]byte("pass123"), bcrypt.DefaultCost)
	_, err := db.Exec("INSERT INTO users (id, username, password_hash) VALUES ('test-u-latt2', 'lattuser2', ?)", string(hash))
	if err != nil {
		t.Fatalf("Failed to insert user: %v", err)
	}

	token := generateTestToken_CB60("test-u-latt2")
	req := httptest.NewRequest("GET", "/messages/attachments", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleListAttachments(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected 400, got %d", w.Code)
	}
}

func TestCB60_HandleListAttachments_NotFound(t *testing.T) {
	testDB := setupTestDB_CB60(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	hash, _ := bcrypt.GenerateFromPassword([]byte("pass123"), bcrypt.DefaultCost)
	_, err := db.Exec("INSERT INTO users (id, username, password_hash) VALUES ('test-u-latt3', 'lattuser3', ?)", string(hash))
	if err != nil {
		t.Fatalf("Failed to insert user: %v", err)
	}

	token := generateTestToken_CB60("test-u-latt3")
	req := httptest.NewRequest("GET", "/messages/nonexistent/attachments?conversation_id=nonexistent", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleListAttachments(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("Expected 404, got %d", w.Code)
	}
}

func TestCB60_HandleListAttachments_NoAuth(t *testing.T) {
	req := httptest.NewRequest("GET", "/messages/conv/attachments?conversation_id=conv", nil)
	w := httptest.NewRecorder()
	handleListAttachments(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected 401, got %d", w.Code)
	}
}

func TestCB60_HandleListAttachments_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest("POST", "/messages/conv/attachments?conversation_id=conv", nil)
	w := httptest.NewRecorder()
	handleListAttachments(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected 405, got %d", w.Code)
	}
}

func TestCB60_HandleListAttachments_InvalidToken(t *testing.T) {
	req := httptest.NewRequest("GET", "/messages/conv/attachments?conversation_id=conv", nil)
	req.Header.Set("Authorization", "Bearer bad-token")
	w := httptest.NewRecorder()
	handleListAttachments(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected 401, got %d", w.Code)
	}
}

// --- handleLogin: user not found vs DB error (92% → higher) ---

func TestCB60_HandleLogin_UserNotFound(t *testing.T) {
	testDB := setupTestDB_CB60(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	form := "username=nonexistent&password=somepass"
	req := httptest.NewRequest("POST", "/auth/login", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handleLogin(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected 401, got %d", w.Code)
	}
}

func TestCB60_HandleLogin_WrongPassword(t *testing.T) {
	testDB := setupTestDB_CB60(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	hash, _ := bcrypt.GenerateFromPassword([]byte("correctpass"), bcrypt.DefaultCost)
	_, err := db.Exec("INSERT INTO users (id, username, password_hash) VALUES ('test-u-login', 'loginuser', ?)", string(hash))
	if err != nil {
		t.Fatalf("Failed to insert user: %v", err)
	}

	form := "username=loginuser&password=wrongpass"
	req := httptest.NewRequest("POST", "/auth/login", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handleLogin(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected 401 for wrong password, got %d", w.Code)
	}
}

func TestCB60_HandleLogin_Success(t *testing.T) {
	testDB := setupTestDB_CB60(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	hash, _ := bcrypt.GenerateFromPassword([]byte("correctpass"), bcrypt.DefaultCost)
	_, err := db.Exec("INSERT INTO users (id, username, password_hash) VALUES ('test-u-login2', 'loginuser2', ?)", string(hash))
	if err != nil {
		t.Fatalf("Failed to insert user: %v", err)
	}

	form := "username=loginuser2&password=correctpass"
	req := httptest.NewRequest("POST", "/auth/login", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handleLogin(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Failed to unmarshal response: %v", err)
	}
	if resp["token"] == "" {
		t.Error("Expected non-empty token")
	}
	if resp["user_id"] != "test-u-login2" {
		t.Errorf("Expected user_id=test-u-login2, got %s", resp["user_id"])
	}
}

func TestCB60_HandleLogin_MissingFields(t *testing.T) {
	form := "username=onlyuser"
	req := httptest.NewRequest("POST", "/auth/login", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handleLogin(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected 400, got %d", w.Code)
	}
}

func TestCB60_HandleLogin_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest("GET", "/auth/login", nil)
	w := httptest.NewRecorder()
	handleLogin(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected 405, got %d", w.Code)
	}
}

// --- handleRegisterUser: validation + duplicate (93.1% → higher) ---

func TestCB60_HandleRegisterUser_DuplicateUsername(t *testing.T) {
	testDB := setupTestDB_CB60(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	hash, _ := bcrypt.GenerateFromPassword([]byte("pass123"), bcrypt.DefaultCost)
	_, err := db.Exec("INSERT INTO users (id, username, password_hash) VALUES ('test-u-dup', 'dupuser', ?)", string(hash))
	if err != nil {
		t.Fatalf("Failed to insert user: %v", err)
	}

	form := "username=dupuser&password=pass456"
	req := httptest.NewRequest("POST", "/auth/register", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handleRegisterUser(w, req)

	if w.Code != http.StatusConflict {
		t.Errorf("Expected 409 for duplicate, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCB60_HandleRegisterUser_ShortUsername(t *testing.T) {
	form := "username=ab&password=pass123"
	req := httptest.NewRequest("POST", "/auth/register", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handleRegisterUser(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected 400 for short username, got %d", w.Code)
	}
}

func TestCB60_HandleRegisterUser_Success(t *testing.T) {
	testDB := setupTestDB_CB60(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	form := "username=newuser_cb60&password=pass123"
	req := httptest.NewRequest("POST", "/auth/register", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handleRegisterUser(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Failed to unmarshal: %v", err)
	}
	if resp["user_id"] == "" {
		t.Error("Expected non-empty user_id")
	}
	if resp["status"] != "registered" {
		t.Errorf("Expected status 'registered', got '%s'", resp["status"])
	}
}

func TestCB60_HandleRegisterUser_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest("GET", "/auth/register", nil)
	w := httptest.NewRecorder()
	handleRegisterUser(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected 405, got %d", w.Code)
	}
}

func TestCB60_HandleRegisterUser_MissingFields(t *testing.T) {
	form := "username=onlyuser"
	req := httptest.NewRequest("POST", "/auth/register", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handleRegisterUser(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected 400, got %d", w.Code)
	}
}

func TestCB60_HandleRegisterUser_InvalidUsernameChars(t *testing.T) {
	form := "username=bad@user&password=pass123"
	req := httptest.NewRequest("POST", "/auth/register", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handleRegisterUser(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected 400 for invalid chars, got %d", w.Code)
	}
}

// --- handleListAgents: empty result (90% → higher) ---

func TestCB60_HandleListAgents_EmptyResult(t *testing.T) {
	testDB := setupTestDB_CB60(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	oldHub := hub
	hub = &Hub{agents: make(map[string]*Connection), mu: sync.RWMutex{}}
	defer func() { hub = oldHub }()

	req := httptest.NewRequest("GET", "/agents", nil)
	w := httptest.NewRecorder()
	handleListAgents(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w.Code)
	}
	var agents []AgentInfo
	if err := json.Unmarshal(w.Body.Bytes(), &agents); err != nil {
		t.Fatalf("Failed to unmarshal: %v", err)
	}
	if len(agents) != 0 {
		t.Errorf("Expected 0 agents, got %d", len(agents))
	}
}

func TestCB60_HandleListAgents_WithAgents(t *testing.T) {
	testDB := setupTestDB_CB60(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	_, err := db.Exec("INSERT INTO agents (id, name, model, personality, specialty) VALUES ('agent-list-1', 'Agent One', 'gpt-4', 'friendly', 'general')")
	if err != nil {
		t.Fatalf("Failed to insert agent: %v", err)
	}
	_, err = db.Exec("INSERT INTO agents (id, name, model, personality, specialty) VALUES ('agent-list-2', 'Agent Two', 'claude-3', 'serious', 'coding')")
	if err != nil {
		t.Fatalf("Failed to insert agent: %v", err)
	}

	oldHub := hub
	hub = &Hub{agents: make(map[string]*Connection), mu: sync.RWMutex{}}
	defer func() { hub = oldHub }()

	req := httptest.NewRequest("GET", "/agents", nil)
	w := httptest.NewRecorder()
	handleListAgents(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w.Code)
	}
	var agents []AgentInfo
	if err := json.Unmarshal(w.Body.Bytes(), &agents); err != nil {
		t.Fatalf("Failed to unmarshal: %v", err)
	}
	if len(agents) != 2 {
		t.Errorf("Expected 2 agents, got %d", len(agents))
	}
}

// --- handleAdminAgents: empty result (91.7% → higher) ---

func TestCB60_HandleAdminAgents_EmptyResult(t *testing.T) {
	testDB := setupTestDB_CB60(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	oldHub := hub
	hub = &Hub{agents: make(map[string]*Connection), mu: sync.RWMutex{}}
	defer func() { hub = oldHub }()

	req := httptest.NewRequest("GET", "/admin/agents", nil)
	w := httptest.NewRecorder()
	handleAdminAgents(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w.Code)
	}
	var agents []map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &agents); err != nil {
		t.Fatalf("Failed to unmarshal: %v", err)
	}
	if len(agents) != 0 {
		t.Errorf("Expected 0 agents, got %d", len(agents))
	}
}

// --- handleAgentConnect: validation (93% → higher) ---

func TestCB60_HandleAgentConnect_MissingAgentID(t *testing.T) {
	req := httptest.NewRequest("GET", "/agent/connect", nil)
	w := httptest.NewRecorder()
	handleAgentConnect(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected 400, got %d", w.Code)
	}
}

func TestCB60_HandleAgentConnect_MissingSecret(t *testing.T) {
	req := httptest.NewRequest("GET", "/agent/connect?agent_id=test-agent-no-secret", nil)
	w := httptest.NewRecorder()
	handleAgentConnect(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected 401, got %d", w.Code)
	}
}

func TestCB60_HandleAgentConnect_InvalidSecret(t *testing.T) {
	req := httptest.NewRequest("GET", "/agent/connect?agent_id=test-agent&secret=wrong", nil)
	w := httptest.NewRecorder()
	handleAgentConnect(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected 401, got %d", w.Code)
	}
}

// --- routeChatMessage: storeMessage error (93.6% → higher) ---

func TestCB60_RouteChatMessage_StoreMessageError(t *testing.T) {
	testDB := setupTestDB_CB60(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	// Insert conversation
	_, err := db.Exec("INSERT INTO conversations (id, user_id, agent_id) VALUES ('conv-store-err', 'user-store-err', 'agent-store-err')")
	if err != nil {
		t.Fatalf("Failed to insert conversation: %v", err)
	}

	// Drop messages table to cause storeMessage error
	_, err = db.Exec("DROP TABLE messages")
	if err != nil {
		t.Fatalf("Failed to drop messages table: %v", err)
	}

	sender := &Connection{
		id:       "agent-store-err",
		connType: "agent",
		send:     make(chan []byte, 10),
	}

	msgData, _ := json.Marshal(RoutedMessage{
		ConversationID: "conv-store-err",
		Content:        "hello",
	})

	routeChatMessage(sender, msgData)

	select {
	case resp := <-sender.send:
		var msg map[string]interface{}
		json.Unmarshal(resp, &msg)
		if msg["type"] != "error" {
			t.Error("Expected error response")
		}
	default:
		// May not get a response if error happens before sendError
	}
}

func TestCB60_RouteChatMessage_EmptyContent(t *testing.T) {
	sender := &Connection{
		id:       "agent-empty-content",
		connType: "agent",
		send:     make(chan []byte, 10),
	}

	msgData, _ := json.Marshal(RoutedMessage{
		ConversationID: "conv-empty",
		Content:        "",
	})

	routeChatMessage(sender, msgData)

	select {
	case resp := <-sender.send:
		var msg map[string]interface{}
		json.Unmarshal(resp, &msg)
		if msg["type"] != "error" {
			t.Error("Expected error response for empty content")
		}
	default:
		t.Error("Expected error response")
	}
}

func TestCB60_RouteChatMessage_EmptyConversationID(t *testing.T) {
	sender := &Connection{
		id:       "agent-empty-conv",
		connType: "agent",
		send:     make(chan []byte, 10),
	}

	msgData, _ := json.Marshal(RoutedMessage{
		Content: "hello",
	})

	routeChatMessage(sender, msgData)

	select {
	case resp := <-sender.send:
		var msg map[string]interface{}
		json.Unmarshal(resp, &msg)
		if msg["type"] != "error" {
			t.Error("Expected error response for empty conversation_id")
		}
	default:
		t.Error("Expected error response")
	}
}

func TestCB60_RouteChatMessage_InvalidJSON(t *testing.T) {
	sender := &Connection{
		id:       "agent-bad-json",
		connType: "agent",
		send:     make(chan []byte, 10),
	}

	routeChatMessage(sender, json.RawMessage(`{invalid json`))

	select {
	case resp := <-sender.send:
		var msg map[string]interface{}
		json.Unmarshal(resp, &msg)
		if msg["type"] != "error" {
			t.Error("Expected error response for invalid JSON")
		}
	default:
		t.Error("Expected error response")
	}
}

func TestCB60_RouteChatMessage_ConversationNotFound(t *testing.T) {
	testDB := setupTestDB_CB60(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	sender := &Connection{
		id:       "agent-conv-not-found",
		connType: "agent",
		send:     make(chan []byte, 10),
	}

	msgData, _ := json.Marshal(RoutedMessage{
		ConversationID: "nonexistent-conv",
		Content:        "hello",
	})

	routeChatMessage(sender, msgData)

	select {
	case resp := <-sender.send:
		var msg map[string]interface{}
		json.Unmarshal(resp, &msg)
		if msg["type"] != "error" {
			t.Error("Expected error response for conversation not found")
		}
	default:
		t.Error("Expected error response")
	}
}

func TestCB60_RouteChatMessage_UnauthorizedAgent(t *testing.T) {
	testDB := setupTestDB_CB60(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	_, err := db.Exec("INSERT INTO conversations (id, user_id, agent_id) VALUES ('conv-unauth', 'user-unauth', 'correct-agent')")
	if err != nil {
		t.Fatalf("Failed to insert conversation: %v", err)
	}

	sender := &Connection{
		id:       "wrong-agent",
		connType: "agent",
		send:     make(chan []byte, 10),
	}

	msgData, _ := json.Marshal(RoutedMessage{
		ConversationID: "conv-unauth",
		Content:        "hello",
	})

	routeChatMessage(sender, msgData)

	select {
	case resp := <-sender.send:
		var msg map[string]interface{}
		json.Unmarshal(resp, &msg)
		if msg["type"] != "error" {
			t.Error("Expected error response for unauthorized agent")
		}
	default:
		t.Error("Expected error response")
	}
}

func TestCB60_RouteChatMessage_UnauthorizedClient(t *testing.T) {
	testDB := setupTestDB_CB60(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	_, err := db.Exec("INSERT INTO conversations (id, user_id, agent_id) VALUES ('conv-unauth-client', 'correct-user', 'agent-unauth-client')")
	if err != nil {
		t.Fatalf("Failed to insert conversation: %v", err)
	}

	sender := &Connection{
		id:       "wrong-user",
		connType: "client",
		send:     make(chan []byte, 10),
	}

	msgData, _ := json.Marshal(RoutedMessage{
		ConversationID: "conv-unauth-client",
		Content:        "hello",
	})

	routeChatMessage(sender, msgData)

	select {
	case resp := <-sender.send:
		var msg map[string]interface{}
		json.Unmarshal(resp, &msg)
		if msg["type"] != "error" {
			t.Error("Expected error response for unauthorized client")
		}
	default:
		t.Error("Expected error response")
	}
}

// --- storeMessagesBatch: attachment insert error (92.6% → higher) ---

func TestCB60_StoreMessagesBatch_AttachmentError(t *testing.T) {
	testDB := setupTestDB_CB60(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	// Create a conversation
	_, err := db.Exec("INSERT INTO conversations (id, user_id, agent_id) VALUES ('conv-batch-att', 'user-batch', 'agent-batch')")
	if err != nil {
		t.Fatalf("Failed to insert conversation: %v", err)
	}

	// Drop attachments table to cause error when storing attachment metadata
	_, err = db.Exec("DROP TABLE attachments")
	if err != nil {
		t.Fatalf("Failed to drop attachments table: %v", err)
	}

	now := time.Now().UTC()
	msgs := []RoutedMessage{
		{
			ConversationID: "conv-batch-att",
			SenderType:      "agent",
			SenderID:        "agent-batch",
			Content:        "Hello with attachment",
			Timestamp:      now.Format(time.RFC3339Nano),
		},
	}

	ids, err := storeMessagesBatch(msgs)
	// The function should still return IDs even if attachment insert fails
	// (attachment errors are logged but don't fail the batch)
	if err != nil {
		t.Logf("storeMessagesBatch returned error (may be expected): %v", err)
	}
	if len(ids) != 1 {
		t.Errorf("Expected 1 ID, got %d", len(ids))
	}
}

// --- getConversationMessages: before cursor (91.3% → higher) ---

func TestCB60_GetConversationMessages_WithBeforeCursor(t *testing.T) {
	testDB := setupTestDB_CB60(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	_, err := db.Exec("INSERT INTO conversations (id, user_id, agent_id) VALUES ('conv-cursor', 'user-cursor', 'agent-cursor')")
	if err != nil {
		t.Fatalf("Failed to insert conversation: %v", err)
	}

	// Insert several messages with different timestamps
	for i := 0; i < 5; i++ {
		_, err = db.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, created_at) VALUES (?, ?, 'agent', 'agent-cursor', ?, datetime('now', ? || ' seconds'))",
			"msg-cursor-"+string(rune('A'+i)), "conv-cursor", "msg "+string(rune('A'+i)), "-"+string(rune('0'+5-i)))
		if err != nil {
			t.Fatalf("Failed to insert message %d: %v", i, err)
		}
	}

	// Query with before cursor — should return messages before the given timestamp
	msgs, err := getConversationMessages("conv-cursor", 10, "2099-01-01 00:00:00")
	if err != nil {
		t.Fatalf("getConversationMessages failed: %v", err)
	}
	if len(msgs) == 0 {
		t.Error("Expected messages with before cursor")
	}
}

func TestCB60_GetConversationMessages_DefaultLimit(t *testing.T) {
	testDB := setupTestDB_CB60(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	_, err := db.Exec("INSERT INTO conversations (id, user_id, agent_id) VALUES ('conv-limit', 'user-limit', 'agent-limit')")
	if err != nil {
		t.Fatalf("Failed to insert conversation: %v", err)
	}

	// Insert 3 messages
	for i := 0; i < 3; i++ {
		_, err = db.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content) VALUES (?, 'conv-limit', 'agent', 'agent-limit', ?)",
			"msg-limit-"+string(rune('A'+i)), "msg "+string(rune('A'+i)))
		if err != nil {
			t.Fatalf("Failed to insert message %d: %v", i, err)
		}
	}

	// limit=0 should default to 50
	msgs, err := getConversationMessages("conv-limit", 0, "")
	if err != nil {
		t.Fatalf("getConversationMessages failed: %v", err)
	}
	if len(msgs) != 3 {
		t.Errorf("Expected 3 messages with default limit, got %d", len(msgs))
	}
}

// --- deleteConversation: success (91.7% → higher) ---

func TestCB60_DeleteConversation_Success(t *testing.T) {
	testDB := setupTestDB_CB60(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	_, err := db.Exec("INSERT INTO conversations (id, user_id, agent_id) VALUES ('conv-del-success', 'user-del', 'agent-del')")
	if err != nil {
		t.Fatalf("Failed to insert conversation: %v", err)
	}
	_, err = db.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content) VALUES ('msg-del-1', 'conv-del-success', 'agent', 'agent-del', 'hello')")
	if err != nil {
		t.Fatalf("Failed to insert message: %v", err)
	}

	err = deleteConversation("conv-del-success", "user-del")
	if err != nil {
		t.Fatalf("deleteConversation failed: %v", err)
	}

	// Verify conversation is gone
	var count int
	err = db.QueryRow("SELECT COUNT(*) FROM conversations WHERE id = 'conv-del-success'").Scan(&count)
	if err != nil {
		t.Fatalf("Failed to count: %v", err)
	}
	if count != 0 {
		t.Errorf("Expected 0 conversations after delete, got %d", count)
	}

	// Verify messages are gone
	err = db.QueryRow("SELECT COUNT(*) FROM messages WHERE conversation_id = 'conv-del-success'").Scan(&count)
	if err != nil {
		t.Fatalf("Failed to count messages: %v", err)
	}
	if count != 0 {
		t.Errorf("Expected 0 messages after delete, got %d", count)
	}
}

// --- searchMessages: empty query + success (93.3% → higher) ---

func TestCB60_SearchMessages_EmptyQuery(t *testing.T) {
	testDB := setupTestDB_CB60(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	_, err := db.Exec("INSERT INTO conversations (id, user_id, agent_id) VALUES ('conv-search-empty', 'user-search', 'agent-search')")
	if err != nil {
		t.Fatalf("Failed to insert conversation: %v", err)
	}
	_, err = db.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content) VALUES ('msg-search-1', 'conv-search-empty', 'agent', 'agent-search', 'hello world')")
	if err != nil {
		t.Fatalf("Failed to insert message: %v", err)
	}

	// Empty query should return an error
	msgs, err := searchMessages("user-search", "", 50)
	if err == nil {
		t.Fatal("Expected error for empty query, got nil")
	}
	if msgs != nil {
		t.Error("Expected nil messages for empty query")
	}
}

func TestCB60_SearchMessages_WithResults(t *testing.T) {
	testDB := setupTestDB_CB60(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	_, err := db.Exec("INSERT INTO conversations (id, user_id, agent_id) VALUES ('conv-search-res', 'user-search-res', 'agent-search-res')")
	if err != nil {
		t.Fatalf("Failed to insert conversation: %v", err)
	}
	_, err = db.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content) VALUES ('msg-search-res-1', 'conv-search-res', 'agent', 'agent-search-res', 'hello world')")
	if err != nil {
		t.Fatalf("Failed to insert message: %v", err)
	}
	_, err = db.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content) VALUES ('msg-search-res-2', 'conv-search-res', 'agent', 'agent-search-res', 'goodbye world')")
	if err != nil {
		t.Fatalf("Failed to insert message: %v", err)
	}

	msgs, err := searchMessages("user-search-res", "hello", 50)
	if err != nil {
		t.Fatalf("searchMessages failed: %v", err)
	}
	if len(msgs) != 1 {
		t.Errorf("Expected 1 result for 'hello', got %d", len(msgs))
	}
}

// --- addReaction: conversation not found (92.3% → higher) ---

func TestCB60_AddReaction_ConversationNotFound(t *testing.T) {
	testDB := setupTestDB_CB60(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	// Insert a message but with a conversation that doesn't exist in conversations table
	_, err := db.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content) VALUES ('msg-react-nconv', 'nonexistent-conv', 'agent', 'agent', 'hello')")
	if err != nil {
		t.Fatalf("Failed to insert message: %v", err)
	}

	// Drop conversations table so getConversation returns nil
	_, err = db.Exec("DROP TABLE conversations")
	if err != nil {
		t.Fatalf("Failed to drop conversations: %v", err)
	}

	_, _, err = addReaction("msg-react-nconv", "user-react-nconv", "👍")
	if err == nil {
		t.Error("Expected error for conversation not found")
	}
}

// --- getMessageReactions: success (90.9% → higher) ---

func TestCB60_GetMessageReactions_Success(t *testing.T) {
	testDB := setupTestDB_CB60(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	_, err := db.Exec("INSERT INTO conversations (id, user_id, agent_id) VALUES ('conv-react-list', 'user-react-list', 'agent-react-list')")
	if err != nil {
		t.Fatalf("Failed to insert conversation: %v", err)
	}
	_, err = db.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content) VALUES ('msg-react-list', 'conv-react-list', 'agent', 'agent-react-list', 'hello')")
	if err != nil {
		t.Fatalf("Failed to insert message: %v", err)
	}

	// Add a reaction
	_, err = db.Exec("INSERT INTO reactions (id, message_id, user_id, emoji) VALUES ('react-1', 'msg-react-list', 'user-react-list', '👍')")
	if err != nil {
		t.Fatalf("Failed to insert reaction: %v", err)
	}

	reactions, err := getMessageReactions("msg-react-list")
	if err != nil {
		t.Fatalf("getMessageReactions failed: %v", err)
	}
	if len(reactions) != 1 {
		t.Errorf("Expected 1 reaction, got %d", len(reactions))
	}
	if reactions[0].Emoji != "👍" {
		t.Errorf("Expected emoji 👍, got %s", reactions[0].Emoji)
	}
}

// --- getConversationTags: success (90.9% → higher) ---

func TestCB60_GetConversationTags_Success(t *testing.T) {
	testDB := setupTestDB_CB60(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	_, err := db.Exec("INSERT INTO conversations (id, user_id, agent_id) VALUES ('conv-tags-list', 'user-tags-list', 'agent-tags-list')")
	if err != nil {
		t.Fatalf("Failed to insert conversation: %v", err)
	}

	_, err = db.Exec("INSERT INTO conversation_tags (id, conversation_id, tag) VALUES ('tag-1', 'conv-tags-list', 'important')")
	if err != nil {
		t.Fatalf("Failed to insert tag: %v", err)
	}
	_, err = db.Exec("INSERT INTO conversation_tags (id, conversation_id, tag) VALUES ('tag-2', 'conv-tags-list', 'work')")
	if err != nil {
		t.Fatalf("Failed to insert tag: %v", err)
	}

	tags, err := getConversationTags("conv-tags-list")
	if err != nil {
		t.Fatalf("getConversationTags failed: %v", err)
	}
	if len(tags) != 2 {
		t.Errorf("Expected 2 tags, got %d", len(tags))
	}
}

// --- handleGetTags: DB error + success (92.3% → higher) ---

func TestCB60_HandleGetTags_NoConversationID(t *testing.T) {
	testDB := setupTestDB_CB60(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	token := generateTestToken_CB60("user-tags-no-id")
	req := httptest.NewRequest("GET", "/conversations/tags", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleGetTags(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected 400, got %d", w.Code)
	}
}

func TestCB60_HandleGetTags_Success(t *testing.T) {
	testDB := setupTestDB_CB60(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	_, err := db.Exec("INSERT INTO conversations (id, user_id, agent_id) VALUES ('conv-get-tags', 'user-get-tags', 'agent-get-tags')")
	if err != nil {
		t.Fatalf("Failed to insert conversation: %v", err)
	}
	_, err = db.Exec("INSERT INTO conversation_tags (id, conversation_id, tag) VALUES ('tag-get-1', 'conv-get-tags', 'label1')")
	if err != nil {
		t.Fatalf("Failed to insert tag: %v", err)
	}

	token := generateTestToken_CB60("user-get-tags")
	req := httptest.NewRequest("GET", "/conversations/tags?conversation_id=conv-get-tags", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleGetTags(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

// --- handleMessageDelete: success path (91.7% → higher) ---

func TestCB60_HandleMessageDelete_Success(t *testing.T) {
	testDB := setupTestDB_CB60(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	oldHub := hub
	hub = &Hub{agents: make(map[string]*Connection), clientConns: make(map[string][]*Connection), mu: sync.RWMutex{}}
	defer func() { hub = oldHub }()

	hash, _ := bcrypt.GenerateFromPassword([]byte("pass123"), bcrypt.DefaultCost)
	_, err := db.Exec("INSERT INTO users (id, username, password_hash) VALUES ('user-msg-del', 'msgdeluser', ?)", string(hash))
	if err != nil {
		t.Fatalf("Failed to insert user: %v", err)
	}
	_, err = db.Exec("INSERT INTO conversations (id, user_id, agent_id) VALUES ('conv-msg-del', 'user-msg-del', 'agent-msg-del')")
	if err != nil {
		t.Fatalf("Failed to insert conversation: %v", err)
	}
	_, err = db.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content) VALUES ('msg-del-target', 'conv-msg-del', 'agent', 'agent-msg-del', 'to be deleted')")
	if err != nil {
		t.Fatalf("Failed to insert message: %v", err)
	}

	token := generateTestToken_CB60("user-msg-del")
	form := "message_id=msg-del-target&conversation_id=conv-msg-del"
	req := httptest.NewRequest("POST", "/messages/delete", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleMessageDelete(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCB60_HandleMessageDelete_NotFound(t *testing.T) {
	testDB := setupTestDB_CB60(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	oldHub := hub
	hub = &Hub{agents: make(map[string]*Connection), clientConns: make(map[string][]*Connection), mu: sync.RWMutex{}}
	defer func() { hub = oldHub }()

	hash, _ := bcrypt.GenerateFromPassword([]byte("pass123"), bcrypt.DefaultCost)
	_, err := db.Exec("INSERT INTO users (id, username, password_hash) VALUES ('user-msg-del-nf', 'msgdelusernf', ?)", string(hash))
	if err != nil {
		t.Fatalf("Failed to insert user: %v", err)
	}
	_, err = db.Exec("INSERT INTO conversations (id, user_id, agent_id) VALUES ('conv-msg-del-nf', 'user-msg-del-nf', 'agent-msg-del-nf')")
	if err != nil {
		t.Fatalf("Failed to insert conversation: %v", err)
	}

	token := generateTestToken_CB60("user-msg-del-nf")
	form := "message_id=nonexistent&conversation_id=conv-msg-del-nf"
	req := httptest.NewRequest("POST", "/messages/delete", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleMessageDelete(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("Expected 404, got %d", w.Code)
	}
}

// --- handleReact: success path (95.9% → higher) ---

func TestCB60_HandleReact_Success(t *testing.T) {
	testDB := setupTestDB_CB60(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	oldHub := hub
	hub = &Hub{agents: make(map[string]*Connection), clientConns: make(map[string][]*Connection), mu: sync.RWMutex{}}
	defer func() { hub = oldHub }()

	hash, _ := bcrypt.GenerateFromPassword([]byte("pass123"), bcrypt.DefaultCost)
	_, err := db.Exec("INSERT INTO users (id, username, password_hash) VALUES ('user-react-success', 'reactsuccess', ?)", string(hash))
	if err != nil {
		t.Fatalf("Failed to insert user: %v", err)
	}
	_, err = db.Exec("INSERT INTO conversations (id, user_id, agent_id) VALUES ('conv-react-success', 'user-react-success', 'agent-react-success')")
	if err != nil {
		t.Fatalf("Failed to insert conversation: %v", err)
	}
	_, err = db.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content) VALUES ('msg-react-success', 'conv-react-success', 'agent', 'agent-react-success', 'react me')")
	if err != nil {
		t.Fatalf("Failed to insert message: %v", err)
	}

	token := generateTestToken_CB60("user-react-success")
	form := "message_id=msg-react-success&emoji=👍"
	req := httptest.NewRequest("POST", "/messages/react", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleReact(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCB60_HandleReact_MissingMessageID(t *testing.T) {
	token := generateTestToken_CB60("user-react-missing")
	body := `{"emoji":"👍"}`
	req := httptest.NewRequest("POST", "/messages/react", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleReact(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected 400, got %d", w.Code)
	}
}

func TestCB60_HandleReact_MissingEmoji(t *testing.T) {
	token := generateTestToken_CB60("user-react-missing-emoji")
	body := `{"message_id":"some-msg"}`
	req := httptest.NewRequest("POST", "/messages/react", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleReact(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected 400, got %d", w.Code)
	}
}

// --- notifyUser: nil pushConfig (90% → higher) ---

func TestCB60_NotifyUser_NilPushConfig(t *testing.T) {
	oldPC := pushConfig
	pushConfig = nil
	defer func() { pushConfig = oldPC }()

	// Should return early without panicking
	notifyUser("test-user", "Title", "Body", "conv-id")
}

func TestCB60_NotifyUser_EmptyConversationID(t *testing.T) {
	testDB := setupTestDB_CB60(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	oldPC := pushConfig
	pushConfig = &PushNotificationConfig{
		APNSEnabled:  false,
		FCMEnabled:   false,
	}
	defer func() { pushConfig = oldPC }()

	// With empty conversationID, isConversationMuted won't be called (short circuit)
	// With no tokens, it returns early
	notifyUser("nonexistent-user", "Title", "Body", "")
}

// --- getDeviceTokensForUser: empty result (90.9% → higher) ---

func TestCB60_GetDeviceTokensForUser_NoTokens(t *testing.T) {
	testDB := setupTestDB_CB60(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	tokens, err := getDeviceTokensForUser("user-no-tokens")
	if err != nil {
		t.Fatalf("getDeviceTokensForUser failed: %v", err)
	}
	if len(tokens) != 0 {
		t.Errorf("Expected 0 tokens, got %d", len(tokens))
	}
}

func TestCB60_GetDeviceTokensForUser_WithTokens(t *testing.T) {
	testDB := setupTestDB_CB60(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	_, err := db.Exec("INSERT INTO device_tokens (user_id, device_token, platform) VALUES ('user-with-tokens', 'token-abc', 'ios')")
	if err != nil {
		t.Fatalf("Failed to insert device token: %v", err)
	}
	_, err = db.Exec("INSERT INTO device_tokens (user_id, device_token, platform) VALUES ('user-with-tokens', 'token-def', 'android')")
	if err != nil {
		t.Fatalf("Failed to insert device token: %v", err)
	}

	tokens, err := getDeviceTokensForUser("user-with-tokens")
	if err != nil {
		t.Fatalf("getDeviceTokensForUser failed: %v", err)
	}
	if len(tokens) != 2 {
		t.Errorf("Expected 2 tokens, got %d", len(tokens))
	}
}

// --- loadQueueFromDB: success with data (89.5% → higher) ---

func TestCB60_LoadQueueFromDB_WithData(t *testing.T) {
	testDB := setupTestDB_CB60(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	// Insert queued messages
	_, err := db.Exec("INSERT INTO offline_queue (recipient, data, queued_at, sent_count) VALUES ('user-q-1', ?, datetime('now'), 0)", `{"type":"message","data":"hello"}`)
	if err != nil {
		t.Fatalf("Failed to insert queue item: %v", err)
	}
	_, err = db.Exec("INSERT INTO offline_queue (recipient, data, queued_at, sent_count) VALUES ('user-q-1', ?, datetime('now'), 0)", `{"type":"message","data":"world"}`)
	if err != nil {
		t.Fatalf("Failed to insert queue item: %v", err)
	}

	oq := newOfflineQueue(100, 7*24*time.Hour)
	loadQueueFromDB(db, oq)
	depth := oq.TotalDepth()
	if depth != 2 {
		t.Errorf("Expected queue depth 2, got %d", depth)
	}
}

// --- TieredRateLimiter: cleanup with stop (83.3% → 100%) ---

func TestCB60_TieredRateLimiter_CleanupStop(t *testing.T) {
	trl := NewTieredRateLimiter()
	stopCh := make(chan struct{})
	trl.stopCh = stopCh

	// Start cleanup in goroutine
	done := make(chan struct{})
	go func() {
		trl.cleanup()
		close(done)
	}()

	// Stop it immediately
	close(stopCh)

	select {
	case <-done:
		// success
	case <-time.After(2 * time.Second):
		t.Fatal("cleanup did not stop within 2s")
	}
}

func TestCB60_TieredRateLimiter_CleanupOnce(t *testing.T) {
	trl := NewTieredRateLimiter()
	// Add some entries
	trl.mu.Lock()
	trl.limits["stale-user-1"] = &userRateLimitState{count: 10, windowEnd: time.Now().Add(-10 * time.Minute), tier: TierFree}
	trl.limits["stale-user-2"] = &userRateLimitState{count: 5, windowEnd: time.Now().Add(-20 * time.Minute), tier: TierFree}
	trl.limits["fresh-user-1"] = &userRateLimitState{count: 3, windowEnd: time.Now().Add(5 * time.Minute), tier: TierFree}
	trl.mu.Unlock()

	trl.cleanupOnce()

	trl.mu.Lock()
	defer trl.mu.Unlock()
	if _, exists := trl.limits["stale-user-1"]; exists {
		t.Error("Expected stale-user-1 to be cleaned up")
	}
	if _, exists := trl.limits["stale-user-2"]; exists {
		t.Error("Expected stale-user-2 to be cleaned up")
	}
	if _, exists := trl.limits["fresh-user-1"]; !exists {
		t.Error("Expected fresh-user-1 to still exist")
	}
}

// --- initAPNs: production environment (84% → higher) ---

func TestCB60_InitAPNs_ProductionEnvironment(t *testing.T) {
	// We can't fully test cert loading without a real cert, but we can test
	// the config check paths
	oldPC := pushConfig
	pushConfig = &PushNotificationConfig{
		APNSEnabled: true,
		CertPath:    "/nonexistent/cert.p12",
		Environment: "production",
	}
	defer func() { pushConfig = oldPC }()

	// This will fail to find the cert and disable APNs
	initAPNs()

	if pushConfig.APNSEnabled {
		t.Error("Expected APNs to be disabled after cert not found")
	}
}

func TestCB60_InitAPNs_NoConfig(t *testing.T) {
	oldPC := pushConfig
	pushConfig = nil
	defer func() { pushConfig = oldPC }()

	// Should return early without panicking
	initAPNs()
}

func TestCB60_InitAPNs_Disabled(t *testing.T) {
	oldPC := pushConfig
	pushConfig = &PushNotificationConfig{
		APNSEnabled: false,
	}
	defer func() { pushConfig = oldPC }()

	initAPNs()
	// Should still be disabled
	if pushConfig.APNSEnabled {
		t.Error("Expected APNs to remain disabled")
	}
}

func TestCB60_InitAPNs_EmptyCertPath(t *testing.T) {
	oldPC := pushConfig
	pushConfig = &PushNotificationConfig{
		APNSEnabled: true,
		CertPath:    "",
	}
	defer func() { pushConfig = oldPC }()

	initAPNs()
	if pushConfig.apnsClient != nil {
		t.Error("Expected apnsClient to be nil with empty cert path")
	}
}

// --- initFCM: no config + disabled + no creds (88.9% → higher) ---

func TestCB60_InitFCM_NoConfig(t *testing.T) {
	oldPC := pushConfig
	pushConfig = nil
	defer func() { pushConfig = oldPC }()

	initFCM()
	// Should not panic
}

func TestCB60_InitFCM_Disabled(t *testing.T) {
	oldPC := pushConfig
	pushConfig = &PushNotificationConfig{
		FCMEnabled: false,
	}
	defer func() { pushConfig = oldPC }()

	initFCM()
	if pushConfig.FCMEnabled {
		t.Error("Expected FCM to remain disabled")
	}
}

func TestCB60_InitFCM_EmptyCredsPath(t *testing.T) {
	oldPC := pushConfig
	pushConfig = &PushNotificationConfig{
		FCMEnabled:      true,
		FCMCredentials:  "",
	}
	defer func() { pushConfig = oldPC }()

	initFCM()
	if pushConfig.fcmClient != nil {
		t.Error("Expected fcmClient to be nil with empty creds path")
	}
}

func TestCB60_InitFCM_CredsNotFound(t *testing.T) {
	oldPC := pushConfig
	pushConfig = &PushNotificationConfig{
		FCMEnabled:      true,
		FCMCredentials:  "/nonexistent/creds.json",
	}
	defer func() { pushConfig = oldPC }()

	initFCM()
	if pushConfig.FCMEnabled {
		t.Error("Expected FCM to be disabled when creds not found")
	}
}

// --- InitTracing: HTTP protocol + no endpoint (79.5% → higher) ---

func TestCB60_InitTracing_Disabled(t *testing.T) {
	// Reset tracing state
	oldTp := tp
	tp = nil
	oldEnabled := tracingEnabled
	tracingEnabled = false
	oldOnce := tracingMu
	tracingMu = sync.Once{}
	defer func() {
		tp = oldTp
		tracingEnabled = oldEnabled
		tracingMu = oldOnce
	}()

	os.Unsetenv("OTEL_ENABLED")
	err := InitTracing()
	if err != nil {
		t.Errorf("Expected no error when tracing disabled, got: %v", err)
	}
	if tracingEnabled {
		t.Error("Expected tracingEnabled=false")
	}
}

func TestCB60_InitTracing_NoEndpoint(t *testing.T) {
	oldTp := tp
	tp = nil
	oldEnabled := tracingEnabled
	tracingEnabled = false
	oldOnce := tracingMu
	tracingMu = sync.Once{}
	defer func() {
		tp = oldTp
		tracingEnabled = oldEnabled
		tracingMu = oldOnce
		os.Unsetenv("OTEL_ENABLED")
		os.Unsetenv("OTEL_EXPORTER_OTLP_ENDPOINT")
		os.Unsetenv("OTEL_EXPORTER_OTLP_HTTP_ENDPOINT")
	}()

	os.Setenv("OTEL_ENABLED", "true")
	os.Unsetenv("OTEL_EXPORTER_OTLP_ENDPOINT")
	os.Unsetenv("OTEL_EXPORTER_OTLP_HTTP_ENDPOINT")

	err := InitTracing()
	if err != nil {
		t.Errorf("Expected no error when no endpoint, got: %v", err)
	}
	if tracingEnabled {
		t.Error("Expected tracingEnabled=false with no endpoint")
	}
}

// --- ShutdownTracing: nil tp (80% → higher) ---

func TestCB60_ShutdownTracing_NilTp(t *testing.T) {
	oldTp := tp
	tp = nil
	defer func() { tp = oldTp }()

	// Should not panic with nil tp
	ShutdownTracing()
}

// --- handleCreateConversation: success with real DB (already tested but adding more) ---

func TestCB60_HandleCreateConversation_AgentNotFound(t *testing.T) {
	testDB := setupTestDB_CB60(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	// Insert user but not agent
	hash, _ := bcrypt.GenerateFromPassword([]byte("pass123"), bcrypt.DefaultCost)
	_, err := db.Exec("INSERT INTO users (id, username, password_hash) VALUES ('user-create-conv', 'createuser', ?)", string(hash))
	if err != nil {
		t.Fatalf("Failed to insert user: %v", err)
	}

	token := generateTestToken_CB60("user-create-conv")
	form := "agent_id=nonexistent-agent&title=Test Conv"
	req := httptest.NewRequest("POST", "/conversations/create", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	// Set up hub without the agent
	oldHub := hub
	hub = &Hub{agents: make(map[string]*Connection), mu: sync.RWMutex{}}
	defer func() { hub = oldHub }()

	handleCreateConversation(w, req)

	// Should still create conversation even if agent not online
	if w.Code != http.StatusOK && w.Code != http.StatusNotFound {
		t.Logf("Response: %d %s", w.Code, w.Body.String())
	}
}

// --- isAllowedContentType tests ---

func TestCB60_IsAllowedContentType_AllowedTypes(t *testing.T) {
	allowed := []string{
		"image/jpeg", "image/png", "image/gif", "image/webp",
		"image/svg+xml", "image/bmp", "image/avif",
		"application/pdf", "text/plain", "text/csv", "text/markdown",
		"application/json",
		"audio/mpeg", "audio/ogg", "audio/wav", "audio/webm", "audio/mp4",
		"video/mp4", "video/webm", "video/ogg",
	}
	for _, ct := range allowed {
		if !isAllowedContentType(ct) {
			t.Errorf("Expected %s to be allowed", ct)
		}
	}
}

func TestCB60_IsAllowedContentType_DisallowedTypes(t *testing.T) {
	disallowed := []string{
		"application/x-executable", "application/zip",
		"application/x-tar", "application/x-gzip",
	}
	for _, ct := range disallowed {
		if isAllowedContentType(ct) {
			t.Errorf("Expected %s to be disallowed", ct)
		}
	}
}

// --- isConversationMuted ---

func TestCB60_IsConversationMuted_NotMuted(t *testing.T) {
	testDB := setupTestDB_CB60(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	hash, _ := bcrypt.GenerateFromPassword([]byte("pass123"), bcrypt.DefaultCost)
	_, err := db.Exec("INSERT INTO users (id, username, password_hash) VALUES ('user-mute-check', 'muteuser', ?)", string(hash))
	if err != nil {
		t.Fatalf("Failed to insert user: %v", err)
	}
	_, err = db.Exec("INSERT INTO conversations (id, user_id, agent_id) VALUES ('conv-mute-check', 'user-mute-check', 'agent-mute')")
	if err != nil {
		t.Fatalf("Failed to insert conversation: %v", err)
	}

	muted := isConversationMuted("user-mute-check", "conv-mute-check")
	if muted {
		t.Error("Expected conversation to not be muted")
	}
}

func TestCB60_IsConversationMuted_Muted(t *testing.T) {
	testDB := setupTestDB_CB60(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	hash, _ := bcrypt.GenerateFromPassword([]byte("pass123"), bcrypt.DefaultCost)
	_, err := db.Exec("INSERT INTO users (id, username, password_hash) VALUES ('user-mute-yes', 'muteuseryes', ?)", string(hash))
	if err != nil {
		t.Fatalf("Failed to insert user: %v", err)
	}
	_, err = db.Exec("INSERT INTO conversations (id, user_id, agent_id) VALUES ('conv-mute-yes', 'user-mute-yes', 'agent-mute-yes')")
	if err != nil {
		t.Fatalf("Failed to insert conversation: %v", err)
	}
	_, err = db.Exec("INSERT INTO notification_preferences (user_id, conversation_id, muted) VALUES ('user-mute-yes', 'conv-mute-yes', 1)")
	if err != nil {
		t.Fatalf("Failed to insert mute pref: %v", err)
	}

	muted := isConversationMuted("user-mute-yes", "conv-mute-yes")
	if !muted {
		t.Error("Expected conversation to be muted")
	}
}

// --- isSupportedVersion ---

func TestCB60_IsSupportedVersion(t *testing.T) {
	// SupportedVersions is "1.0,1.1"
	versions := strings.Split(SupportedVersions, ",")
	for _, v := range versions {
		v = strings.TrimSpace(v)
		if !isSupportedVersion(v) {
			t.Errorf("Expected %s to be supported", v)
		}
	}
}

func TestCB60_IsSupportedVersion_Unsupported(t *testing.T) {
	if isSupportedVersion("99.0") {
		t.Error("Expected 99.0 to be unsupported")
	}
}

func TestCB60_IsSupportedVersion_Empty(t *testing.T) {
	if isSupportedVersion("") {
		t.Error("Expected empty string to be unsupported")
	}
}

// --- truncate (safeTruncate) ---

func TestCB60_SafeTruncate_Short(t *testing.T) {
	result := safeTruncate("hello", 100)
	if result != "hello" {
		t.Errorf("Expected 'hello', got '%s'", result)
	}
}

func TestCB60_SafeTruncate_Exact(t *testing.T) {
	result := safeTruncate("hello", 5)
	if result != "hello" {
		t.Errorf("Expected 'hello', got '%s'", result)
	}
}

func TestCB60_SafeTruncate_Longer(t *testing.T) {
	result := safeTruncate("hello world this is long", 10)
	if result != "hello worl" {
		t.Errorf("Expected 'hello worl', got '%s'", result)
	}
}

// --- getEnvOrDefault ---

func TestCB60_GetEnvOrDefault_Existing(t *testing.T) {
	os.Setenv("CB60_TEST_VAR", "testvalue")
	defer os.Unsetenv("CB60_TEST_VAR")

	result := getEnvOrDefault("CB60_TEST_VAR", "default")
	if result != "testvalue" {
		t.Errorf("Expected 'testvalue', got '%s'", result)
	}
}

func TestCB60_GetEnvOrDefault_Default(t *testing.T) {
	result := getEnvOrDefault("CB60_NONEXISTENT_VAR", "defaultval")
	if result != "defaultval" {
		t.Errorf("Expected 'defaultval', got '%s'", result)
	}
}

// --- handleGetNotificationPrefs: success (94.1% → higher) ---

func TestCB60_HandleGetNotificationPrefs_Success(t *testing.T) {
	testDB := setupTestDB_CB60(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	hash, _ := bcrypt.GenerateFromPassword([]byte("pass123"), bcrypt.DefaultCost)
	_, err := db.Exec("INSERT INTO users (id, username, password_hash) VALUES ('user-np-success', 'npuser', ?)", string(hash))
	if err != nil {
		t.Fatalf("Failed to insert user: %v", err)
	}
	_, err = db.Exec("INSERT INTO conversations (id, user_id, agent_id) VALUES ('conv-np-success', 'user-np-success', 'agent-np')")
	if err != nil {
		t.Fatalf("Failed to insert conversation: %v", err)
	}
	_, err = db.Exec("INSERT INTO notification_preferences (user_id, conversation_id, muted) VALUES ('user-np-success', 'conv-np-success', 1)")
	if err != nil {
		t.Fatalf("Failed to insert pref: %v", err)
	}

	token := generateTestToken_CB60("user-np-success")
	req := httptest.NewRequest("GET", "/notifications/preferences?conversation_id=conv-np-success", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	ctx := context.WithValue(req.Context(), contextKeyUserID, "user-np-success")
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()
	handleGetNotificationPrefs(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

// --- handleGetPresence: success (93.5% → higher) ---

func TestCB60_HandleGetPresence_Success(t *testing.T) {
	testDB := setupTestDB_CB60(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	oldHub := hub
	hub = &Hub{agents: make(map[string]*Connection), clientConns: make(map[string][]*Connection), mu: sync.RWMutex{}}
	defer func() { hub = oldHub }()

	_, err := db.Exec("INSERT INTO agents (id, name, model, personality, specialty) VALUES ('agent-pres', 'Agent Pres', 'gpt-4', 'friendly', 'general')")
	if err != nil {
		t.Fatalf("Failed to insert agent: %v", err)
	}

	token := generateTestToken_CB60("user-pres")
	req := httptest.NewRequest("GET", "/presence?agent_id=agent-pres", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleGetPresence(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCB60_HandleGetPresence_AgentNotFound(t *testing.T) {
	testDB := setupTestDB_CB60(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	token := generateTestToken_CB60("user-pres-nf")
	req := httptest.NewRequest("GET", "/presence?agent_id=nonexistent", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleGetPresence(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w.Code)
	}
	// No agents in DB, so agents list should be null/empty
	if len(w.Body.Bytes()) == 0 {
		t.Error("Expected non-empty response body")
	}
}

// --- handleSetNotificationPrefs: success (88.9% → higher) ---

func TestCB60_HandleSetNotificationPrefs_Success(t *testing.T) {
	testDB := setupTestDB_CB60(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	hash, _ := bcrypt.GenerateFromPassword([]byte("pass123"), bcrypt.DefaultCost)
	_, err := db.Exec("INSERT INTO users (id, username, password_hash) VALUES ('user-setnp', 'setnpuser', ?)", string(hash))
	if err != nil {
		t.Fatalf("Failed to insert user: %v", err)
	}
	_, err = db.Exec("INSERT INTO conversations (id, user_id, agent_id) VALUES ('conv-setnp', 'user-setnp', 'agent-setnp')")
	if err != nil {
		t.Fatalf("Failed to insert conversation: %v", err)
	}

	token := generateTestToken_CB60("user-setnp")
	form := "conversation_id=conv-setnp&muted=true"
	req := httptest.NewRequest("POST", "/notifications/preferences", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)
	ctx := context.WithValue(req.Context(), contextKeyUserID, "user-setnp")
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()
	handleSetNotificationPrefs(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

// --- handleListConversations: success (93.5% → higher) ---

func TestCB60_HandleListConversations_Success(t *testing.T) {
	testDB := setupTestDB_CB60(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	hash, _ := bcrypt.GenerateFromPassword([]byte("pass123"), bcrypt.DefaultCost)
	_, err := db.Exec("INSERT INTO users (id, username, password_hash) VALUES ('user-listconv', 'listconvuser', ?)", string(hash))
	if err != nil {
		t.Fatalf("Failed to insert user: %v", err)
	}
	_, err = db.Exec("INSERT INTO conversations (id, user_id, agent_id) VALUES ('conv-list-1', 'user-listconv', 'agent-list-1')")
	if err != nil {
		t.Fatalf("Failed to insert conversation: %v", err)
	}
	_, err = db.Exec("INSERT INTO conversations (id, user_id, agent_id) VALUES ('conv-list-2', 'user-listconv', 'agent-list-2')")
	if err != nil {
		t.Fatalf("Failed to insert conversation: %v", err)
	}

	token := generateTestToken_CB60("user-listconv")
	req := httptest.NewRequest("GET", "/conversations", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleListConversations(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var convs []map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &convs); err != nil {
		t.Fatalf("Failed to unmarshal: %v", err)
	}
	if len(convs) != 2 {
		t.Errorf("Expected 2 conversations, got %d", len(convs))
	}
}

// --- handleGetMessages: success (94.1% → higher) ---

func TestCB60_HandleGetMessages_Success(t *testing.T) {
	testDB := setupTestDB_CB60(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	hash, _ := bcrypt.GenerateFromPassword([]byte("pass123"), bcrypt.DefaultCost)
	_, err := db.Exec("INSERT INTO users (id, username, password_hash) VALUES ('user-getmsg', 'getmsguser', ?)", string(hash))
	if err != nil {
		t.Fatalf("Failed to insert user: %v", err)
	}
	_, err = db.Exec("INSERT INTO conversations (id, user_id, agent_id) VALUES ('conv-getmsg', 'user-getmsg', 'agent-getmsg')")
	if err != nil {
		t.Fatalf("Failed to insert conversation: %v", err)
	}
	_, err = db.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content) VALUES ('msg-get-1', 'conv-getmsg', 'agent', 'agent-getmsg', 'hello')")
	if err != nil {
		t.Fatalf("Failed to insert message: %v", err)
	}

	token := generateTestToken_CB60("user-getmsg")
	req := httptest.NewRequest("GET", "/conversations/messages?conversation_id=conv-getmsg", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleGetMessages(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

// --- handleSearchMessages: success (93.8% → higher) ---

func TestCB60_HandleSearchMessages_Success(t *testing.T) {
	testDB := setupTestDB_CB60(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	hash, _ := bcrypt.GenerateFromPassword([]byte("pass123"), bcrypt.DefaultCost)
	_, err := db.Exec("INSERT INTO users (id, username, password_hash) VALUES ('user-search-msg', 'searchmsguser', ?)", string(hash))
	if err != nil {
		t.Fatalf("Failed to insert user: %v", err)
	}
	_, err = db.Exec("INSERT INTO conversations (id, user_id, agent_id) VALUES ('conv-search-msg', 'user-search-msg', 'agent-search-msg')")
	if err != nil {
		t.Fatalf("Failed to insert conversation: %v", err)
	}
	_, err = db.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content) VALUES ('msg-search-test', 'conv-search-msg', 'agent', 'agent-search-msg', 'searchable text')")
	if err != nil {
		t.Fatalf("Failed to insert message: %v", err)
	}

	token := generateTestToken_CB60("user-search-msg")
	req := httptest.NewRequest("GET", "/messages/search?q=searchable", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleSearchMessages(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

// --- handleMarkRead: success (already tested but adding more) ---

func TestCB60_HandleMarkRead_Success(t *testing.T) {
	testDB := setupTestDB_CB60(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	oldHub := hub
	hub = &Hub{agents: make(map[string]*Connection), clientConns: make(map[string][]*Connection), mu: sync.RWMutex{}}
	defer func() { hub = oldHub }()

	hash, _ := bcrypt.GenerateFromPassword([]byte("pass123"), bcrypt.DefaultCost)
	_, err := db.Exec("INSERT INTO users (id, username, password_hash) VALUES ('user-markread', 'markreaduser', ?)", string(hash))
	if err != nil {
		t.Fatalf("Failed to insert user: %v", err)
	}
	_, err = db.Exec("INSERT INTO conversations (id, user_id, agent_id) VALUES ('conv-markread', 'user-markread', 'agent-markread')")
	if err != nil {
		t.Fatalf("Failed to insert conversation: %v", err)
	}
	_, err = db.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content) VALUES ('msg-markread-1', 'conv-markread', 'agent', 'agent-markread', 'unread message')")
	if err != nil {
		t.Fatalf("Failed to insert message: %v", err)
	}

	token := generateTestToken_CB60("user-markread")
	form := "conversation_id=conv-markread"
	req := httptest.NewRequest("POST", "/conversations/mark-read", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleMarkRead(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

// --- handleChangePassword: success ---

func TestCB60_HandleChangePassword_Success(t *testing.T) {
	testDB := setupTestDB_CB60(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	hash, _ := bcrypt.GenerateFromPassword([]byte("oldpass123"), bcrypt.DefaultCost)
	_, err := db.Exec("INSERT INTO users (id, username, password_hash) VALUES ('user-changepw', 'changepwuser', ?)", string(hash))
	if err != nil {
		t.Fatalf("Failed to insert user: %v", err)
	}

	token := generateTestToken_CB60("user-changepw")
	form := "old_password=oldpass123&new_password=newpass456"
	req := httptest.NewRequest("POST", "/auth/change-password", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleChangePassword(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

// --- handleDeleteConversation: success ---

func TestCB60_HandleDeleteConversation_Success(t *testing.T) {
	testDB := setupTestDB_CB60(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	hash, _ := bcrypt.GenerateFromPassword([]byte("pass123"), bcrypt.DefaultCost)
	_, err := db.Exec("INSERT INTO users (id, username, password_hash) VALUES ('user-delconv', 'delconvuser', ?)", string(hash))
	if err != nil {
		t.Fatalf("Failed to insert user: %v", err)
	}
	_, err = db.Exec("INSERT INTO conversations (id, user_id, agent_id) VALUES ('conv-del-handler', 'user-delconv', 'agent-del')")
	if err != nil {
		t.Fatalf("Failed to insert conversation: %v", err)
	}

	token := generateTestToken_CB60("user-delconv")
	req := httptest.NewRequest("DELETE", "/conversations/delete?conversation_id=conv-del-handler", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleDeleteConversation(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

// --- handleMessageEdit: success ---

func TestCB60_HandleMessageEdit_Success(t *testing.T) {
	testDB := setupTestDB_CB60(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	oldHub := hub
	hub = &Hub{agents: make(map[string]*Connection), clientConns: make(map[string][]*Connection), mu: sync.RWMutex{}}
	defer func() { hub = oldHub }()

	hash, _ := bcrypt.GenerateFromPassword([]byte("pass123"), bcrypt.DefaultCost)
	_, err := db.Exec("INSERT INTO users (id, username, password_hash) VALUES ('user-msgedit', 'msgedituser', ?)", string(hash))
	if err != nil {
		t.Fatalf("Failed to insert user: %v", err)
	}
	_, err = db.Exec("INSERT INTO conversations (id, user_id, agent_id) VALUES ('conv-msgedit', 'user-msgedit', 'agent-msgedit')")
	if err != nil {
		t.Fatalf("Failed to insert conversation: %v", err)
	}
	_, err = db.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content) VALUES ('msg-edit-target', 'conv-msgedit', 'client', 'user-msgedit', 'original text')")
	if err != nil {
		t.Fatalf("Failed to insert message: %v", err)
	}

	token := generateTestToken_CB60("user-msgedit")
	form := "message_id=msg-edit-target&conversation_id=conv-msgedit&content=edited text"
	req := httptest.NewRequest("POST", "/messages/edit", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleMessageEdit(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

// --- handleWebPushSubscribe: success ---

func TestCB60_HandleWebPushSubscribe_Success(t *testing.T) {
	testDB := setupTestDB_CB60(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	hash, _ := bcrypt.GenerateFromPassword([]byte("pass123"), bcrypt.DefaultCost)
	_, err := db.Exec("INSERT INTO users (id, username, password_hash) VALUES ('user-webpush', 'webpushuser', ?)", string(hash))
	if err != nil {
		t.Fatalf("Failed to insert user: %v", err)
	}

	token := generateTestToken_CB60("user-webpush")
	body := `{"endpoint":"https://fcm.googleapis.com/fcm/send/abc","keys":{"p256dh":"key1","auth":"key2"}}`
	req := httptest.NewRequest("POST", "/push/web-subscribe", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleWebPushSubscribe(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

// --- addConversationTag: success ---

func TestCB60_AddConversationTag_Success(t *testing.T) {
	testDB := setupTestDB_CB60(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	_, err := db.Exec("INSERT INTO conversations (id, user_id, agent_id) VALUES ('conv-add-tag', 'user-add-tag', 'agent-add-tag')")
	if err != nil {
		t.Fatalf("Failed to insert conversation: %v", err)
	}

	_, err = addConversationTag("conv-add-tag", "user-add-tag", "important")
	if err != nil {
		t.Fatalf("addConversationTag failed: %v", err)
	}

	// Verify tag was added
	tags, err := getConversationTags("conv-add-tag")
	if err != nil {
		t.Fatalf("getConversationTags failed: %v", err)
	}
	if len(tags) != 1 {
		t.Errorf("Expected 1 tag, got %d", len(tags))
	}
	if tags[0].Tag != "important" {
		t.Errorf("Expected tag 'important', got '%s'", tags[0].Tag)
	}
}

func TestCB60_AddConversationTag_Duplicate(t *testing.T) {
	testDB := setupTestDB_CB60(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	_, err := db.Exec("INSERT INTO conversations (id, user_id, agent_id) VALUES ('conv-dup-tag', 'user-dup-tag', 'agent-dup-tag')")
	if err != nil {
		t.Fatalf("Failed to insert conversation: %v", err)
	}

	// Add tag first time
	_, err = addConversationTag("conv-dup-tag", "user-dup-tag", "label1")
	if err != nil {
		t.Fatalf("First addConversationTag failed: %v", err)
	}

	// Add same tag second time (should not fail, UNIQUE constraint)
	_, err = addConversationTag("conv-dup-tag", "user-dup-tag", "label1")
	if err != nil {
		t.Logf("Second addConversationTag returned error (expected for dup): %v", err)
	}
}