package main

import (
	"bytes"
	"context"

	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	firebase "firebase.google.com/go/v4"
	"firebase.google.com/go/v4/messaging"
	"google.golang.org/api/option"
	"golang.org/x/oauth2"
)

// generateTestJWT creates a JWT for testing
func generateTestJWT(t *testing.T, userID, username string) string {
	t.Helper()
	token, err := GenerateJWT(userID, username)
	if err != nil {
		t.Fatalf("failed to generate JWT: %v", err)
	}
	return token
}

// fakeTokenSource returns a fixed access token
type fakeTokenSource struct{}

func (fakeTokenSource) Token() (*oauth2.Token, error) {
	return &oauth2.Token{AccessToken: "fake-token", TokenType: "Bearer"}, nil
}

// newMockFCMClient creates a messaging.Client pointing at a mock server
func newMockFCMClient(t *testing.T, mockServer *httptest.Server) *messaging.Client {
	t.Helper()
	ctx := context.Background()
	app, err := firebase.NewApp(ctx, &firebase.Config{
		ProjectID: "test-project",
	},
		option.WithEndpoint(mockServer.URL),
		option.WithTokenSource(fakeTokenSource{}),
		option.WithScopes(), // override default scopes
	)
	if err != nil {
		t.Fatalf("failed to create Firebase app: %v", err)
	}
	client, err := app.Messaging(ctx)
	if err != nil {
		t.Fatalf("failed to create messaging client: %v", err)
	}
	return client
}

// CB34: sendFCMNotification coverage (22.2% -> target 100%)

func TestCB34_SendFCMNotification_MockServer_Success(t *testing.T) {
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Handle FCM send
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"name": "projects/test-project/messages/123"})
	}))
	defer mockServer.Close()

	client := newMockFCMClient(t, mockServer)

	oldConfig := pushConfig
	pushConfig = &PushNotificationConfig{
		FCMEnabled: true,
		fcmClient:  client,
	}
	t.Cleanup(func() { pushConfig = oldConfig })

	err := sendFCMNotification("device-token-abc", "Test Title", "Test Body", "conv-123")
	if err != nil {
		t.Errorf("expected nil error on success, got %v", err)
	}
}

func TestCB34_SendFCMNotification_MockServer_Error(t *testing.T) {
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error": map[string]interface{}{
				"status": "INTERNAL",
				"message": "internal server error",
			},
		})
	}))
	defer mockServer.Close()

	client := newMockFCMClient(t, mockServer)

	oldConfig := pushConfig
	pushConfig = &PushNotificationConfig{
		FCMEnabled: true,
		fcmClient:  client,
	}
	t.Cleanup(func() { pushConfig = oldConfig })

	err := sendFCMNotification("bad-token", "Title", "Body", "conv-err")
	if err == nil {
		t.Error("expected error on server error, got nil")
	}
	if !strings.Contains(err.Error(), "FCM send failed") {
		t.Errorf("expected FCM send failed error, got: %v", err)
	}
}

func TestCB34_SendFCMNotification_MockServer_InvalidArgument(t *testing.T) {
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error": map[string]interface{}{
				"status": "INVALID_ARGUMENT",
				"message": "invalid registration token",
			},
		})
	}))
	defer mockServer.Close()

	client := newMockFCMClient(t, mockServer)

	oldConfig := pushConfig
	pushConfig = &PushNotificationConfig{
		FCMEnabled: true,
		fcmClient:  client,
	}
	t.Cleanup(func() { pushConfig = oldConfig })

	err := sendFCMNotification("invalid-token", "Title", "Body", "conv-invalid")
	if err == nil {
		t.Error("expected error on invalid argument, got nil")
	}
}

func TestCB34_SendFCMNotification_NilPushConfig(t *testing.T) {
	oldConfig := pushConfig
	pushConfig = nil
	t.Cleanup(func() { pushConfig = oldConfig })

	err := sendFCMNotification("token", "Title", "Body", "conv")
	if err != nil {
		t.Errorf("expected nil error with nil pushConfig, got %v", err)
	}
}

func TestCB34_SendFCMNotification_FCMDisabled(t *testing.T) {
	oldConfig := pushConfig
	pushConfig = &PushNotificationConfig{
		FCMEnabled: false,
	}
	t.Cleanup(func() { pushConfig = oldConfig })

	err := sendFCMNotification("token", "Title", "Body", "conv")
	if err != nil {
		t.Errorf("expected nil error with FCM disabled, got %v", err)
	}
}

func TestCB34_SendFCMNotification_NilFCMClient(t *testing.T) {
	oldConfig := pushConfig
	pushConfig = &PushNotificationConfig{
		FCMEnabled: true,
		fcmClient:  nil,
	}
	t.Cleanup(func() { pushConfig = oldConfig })

	err := sendFCMNotification("token", "Title", "Body", "conv")
	if err != nil {
		t.Errorf("expected nil error with nil fcmClient, got %v", err)
	}
}

func TestCB34_SendFCMNotification_MockServer_ConnectionRefused(t *testing.T) {
	// Create a server that we immediately close to get connection errors
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	mockServer.Close() // close immediately

	client := newMockFCMClient(t, mockServer)

	oldConfig := pushConfig
	pushConfig = &PushNotificationConfig{
		FCMEnabled: true,
		fcmClient:  client,
	}
	t.Cleanup(func() { pushConfig = oldConfig })

	err := sendFCMNotification("token", "Title", "Body", "conv")
	if err == nil {
		t.Error("expected error on connection refused, got nil")
	}
	if !strings.Contains(err.Error(), "FCM send failed") {
		t.Errorf("expected FCM send failed error, got: %v", err)
	}
}

// CB34: sendFCMNotification with empty conversation ID (should still work)
func TestCB34_SendFCMNotification_MockServer_EmptyConversationID(t *testing.T) {
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"name": "projects/test-project/messages/456"})
	}))
	defer mockServer.Close()

	client := newMockFCMClient(t, mockServer)

	oldConfig := pushConfig
	pushConfig = &PushNotificationConfig{
		FCMEnabled: true,
		fcmClient:  client,
	}
	t.Cleanup(func() { pushConfig = oldConfig })

	err := sendFCMNotification("token-xyz", "Title", "Body", "")
	if err != nil {
		t.Errorf("expected nil error with empty conversation ID, got %v", err)
	}
}

// CB34: Verify the FCM message content sent to mock server
func TestCB34_SendFCMNotification_MockServer_VerifyRequest(t *testing.T) {
	var capturedBody map[string]interface{}
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&capturedBody)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"name": "projects/test-project/messages/789"})
	}))
	defer mockServer.Close()

	client := newMockFCMClient(t, mockServer)

	oldConfig := pushConfig
	pushConfig = &PushNotificationConfig{
		FCMEnabled: true,
		fcmClient:  client,
	}
	t.Cleanup(func() { pushConfig = oldConfig })

	err := sendFCMNotification("device-123", "Hello", "World", "conv-456")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify the message was sent with correct data
	msg, ok := capturedBody["message"].(map[string]interface{})
	if !ok {
		t.Fatal("expected 'message' field in request body")
	}

	data, ok := msg["data"].(map[string]interface{})
	if !ok {
		t.Fatal("expected 'data' field in message")
	}

	if data["title"] != "Hello" {
		t.Errorf("expected title 'Hello', got %v", data["title"])
	}
	if data["body"] != "World" {
		t.Errorf("expected body 'World', got %v", data["body"])
	}
	if data["conversation_id"] != "conv-456" {
		t.Errorf("expected conversation_id 'conv-456', got %v", data["conversation_id"])
	}

	// Verify notification
	notif, ok := msg["notification"].(map[string]interface{})
	if !ok {
		t.Fatal("expected 'notification' field in message")
	}
	if notif["title"] != "Hello" {
		t.Errorf("expected notification title 'Hello', got %v", notif["title"])
	}
	if notif["body"] != "World" {
		t.Errorf("expected notification body 'World', got %v", notif["body"])
	}

	// Verify Android config
	android, ok := msg["android"].(map[string]interface{})
	if !ok {
		t.Fatal("expected 'android' field in message")
	}
	if android["priority"] != "high" {
		t.Errorf("expected priority 'high', got %v", android["priority"])
	}
}

// CB34: deleteConversation coverage (75% -> target 90%+)

func TestCB34_DeleteConversation_NotFound(t *testing.T) {
	dbPath := ":memory:"
	testDB, err := openDatabase("sqlite3", dbPath)
	if err != nil {
		t.Fatalf("failed to open test db: %v", err)
	}
	t.Cleanup(func() { testDB.Close() })

	oldDB := db
	db = testDB
	t.Cleanup(func() { db = oldDB })

	if err := initSchema(testDB); err != nil {
		t.Fatalf("failed to init schema: %v", err)
	}

	err = deleteConversation("nonexistent-conv", "user-1")
	if err == nil {
		t.Error("expected error for nonexistent conversation, got nil")
	}
}

func TestCB34_DeleteConversation_Unauthorized(t *testing.T) {
	dbPath := ":memory:"
	testDB, err := openDatabase("sqlite3", dbPath)
	if err != nil {
		t.Fatalf("failed to open test db: %v", err)
	}
	t.Cleanup(func() { testDB.Close() })

	oldDB := db
	db = testDB
	t.Cleanup(func() { db = oldDB })

	if err := initSchema(testDB); err != nil {
		t.Fatalf("failed to init schema: %v", err)
	}

	// Create a user and conversation
	_, err = testDB.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)", "user-1", "alice", "hash")
	if err != nil {
		t.Fatalf("failed to insert user: %v", err)
	}
	_, err = testDB.Exec("INSERT INTO agents (id, name) VALUES (?, ?)", "agent-1", "TestAgent")
	if err != nil {
		t.Fatalf("failed to insert agent: %v", err)
	}
	_, err = testDB.Exec("INSERT INTO conversations (id, user_id, agent_id) VALUES (?, ?, ?)", "conv-1", "user-1", "agent-1")
	if err != nil {
		t.Fatalf("failed to insert conversation: %v", err)
	}

	// Try to delete as different user
	err = deleteConversation("conv-1", "wrong-user")
	if err == nil {
		t.Error("expected unauthorized error, got nil")
	}
	if !strings.Contains(err.Error(), "unauthorized") {
		t.Errorf("expected unauthorized error, got: %v", err)
	}
}

func TestCB34_DeleteConversation_Success(t *testing.T) {
	dbPath := ":memory:"
	testDB, err := openDatabase("sqlite3", dbPath)
	if err != nil {
		t.Fatalf("failed to open test db: %v", err)
	}
	t.Cleanup(func() { testDB.Close() })

	oldDB := db
	db = testDB
	t.Cleanup(func() { db = oldDB })

	if err := initSchema(testDB); err != nil {
		t.Fatalf("failed to init schema: %v", err)
	}

	// Setup
	_, err = testDB.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)", "user-1", "alice", "hash")
	if err != nil {
		t.Fatalf("failed to insert user: %v", err)
	}
	_, err = testDB.Exec("INSERT INTO agents (id, name) VALUES (?, ?)", "agent-1", "TestAgent")
	if err != nil {
		t.Fatalf("failed to insert agent: %v", err)
	}
	_, err = testDB.Exec("INSERT INTO conversations (id, user_id, agent_id) VALUES (?, ?, ?)", "conv-1", "user-1", "agent-1")
	if err != nil {
		t.Fatalf("failed to insert conversation: %v", err)
	}
	_, err = testDB.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, created_at) VALUES (?, ?, ?, ?, ?, ?)", "msg-1", "conv-1", "user", "user-1", "hello", time.Now().UTC())
	if err != nil {
		t.Fatalf("failed to insert message: %v", err)
	}

	err = deleteConversation("conv-1", "user-1")
	if err != nil {
		t.Errorf("expected nil error, got %v", err)
	}

	// Verify conversation is gone
	var count int
	testDB.QueryRow("SELECT COUNT(*) FROM conversations WHERE id = ?", "conv-1").Scan(&count)
	if count != 0 {
		t.Errorf("expected conversation to be deleted, found %d", count)
	}

	// Verify messages are also gone
	testDB.QueryRow("SELECT COUNT(*) FROM messages WHERE conversation_id = ?", "conv-1").Scan(&count)
	if count != 0 {
		t.Errorf("expected messages to be deleted, found %d", count)
	}
}

// CB34: sendWelcomeMessage with deviceID

func TestCB34_SendWelcomeMessage_WithDeviceID(t *testing.T) {
	conn := &Connection{
		id:                "conn-test-1",
		connType:          "client",
		deviceID:          "device-abc",
		negotiatedVersion: "1",
		send:              make(chan []byte, 10),
		closeMu:           sync.RWMutex{},
	}
	t.Cleanup(func() { close(conn.send) })

	// This should not block since send channel has buffer
	sendWelcomeMessage(conn)

	// Verify we got a message
	select {
	case data := <-conn.send:
		var msg map[string]interface{}
		if err := json.Unmarshal(data, &msg); err != nil {
			t.Fatalf("failed to unmarshal welcome: %v", err)
		}
		if msg["type"] != "connected" {
			t.Errorf("expected type 'connected', got %v", msg["type"])
		}
		dataMap, ok := msg["data"].(map[string]interface{})
		if !ok {
			t.Fatal("expected 'data' field")
		}
		if dataMap["device_id"] != "device-abc" {
			t.Errorf("expected device_id 'device-abc', got %v", dataMap["device_id"])
		}
	default:
		t.Error("expected welcome message in send channel")
	}
}

func TestCB34_SendWelcomeMessage_SendChannelClosed(t *testing.T) {
	conn := &Connection{
		id:                "conn-test-2",
		connType:          "agent",
		negotiatedVersion: "1",
		send:              make(chan []byte, 1),
		closeMu:           sync.RWMutex{},
	}
	close(conn.send)

	// Should not panic when send channel is closed
	sendWelcomeMessage(conn)
	// If we reach here, no panic occurred
}

// CB34: handleSetNotificationPrefs edge cases

func TestCB34_HandleSetNotificationPrefs_DBError(t *testing.T) {
	dbPath := ":memory:"
	testDB, err := openDatabase("sqlite3", dbPath)
	if err != nil {
		t.Fatalf("failed to open test db: %v", err)
	}
	t.Cleanup(func() { testDB.Close() })

	oldDB := db
	db = testDB
	t.Cleanup(func() { db = oldDB })

	if err := initSchema(testDB); err != nil {
		t.Fatalf("failed to init schema: %v", err)
	}

	// Create user and conversation
	_, err = testDB.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)", "user-1", "alice", "hash")
	if err != nil {
		t.Fatalf("failed to insert user: %v", err)
	}
	_, err = testDB.Exec("INSERT INTO agents (id, name) VALUES (?, ?)", "agent-1", "TestAgent")
	if err != nil {
		t.Fatalf("failed to insert agent: %v", err)
	}
	_, err = testDB.Exec("INSERT INTO conversations (id, user_id, agent_id) VALUES (?, ?, ?)", "conv-1", "user-1", "agent-1")
	if err != nil {
		t.Fatalf("failed to insert conversation: %v", err)
	}

	// Create notification_preferences table for the test
	testDB.Exec(`CREATE TABLE IF NOT EXISTS notification_preferences (
		user_id TEXT NOT NULL,
		conversation_id TEXT NOT NULL,
		muted BOOLEAN DEFAULT 0,
		PRIMARY KEY (user_id, conversation_id)
	)`)

	// Set valid JWT
	validToken := generateTestJWT(t, "user-1", "alice")
	req := httptest.NewRequest("POST", "/notif/prefs?conversation_id=conv-1&muted=true", nil)
	req.Header.Set("Authorization", "Bearer "+validToken)
	req.SetPathValue("userID", "user-1")

	// Use context-based auth
	ctx := context.WithValue(req.Context(), contextKeyUserID, "user-1")
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	handleSetNotificationPrefs(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestCB34_HandleSetNotificationPrefs_NotYourConversation(t *testing.T) {
	dbPath := ":memory:"
	testDB, err := openDatabase("sqlite3", dbPath)
	if err != nil {
		t.Fatalf("failed to open test db: %v", err)
	}
	t.Cleanup(func() { testDB.Close() })

	oldDB := db
	db = testDB
	t.Cleanup(func() { db = oldDB })

	if err := initSchema(testDB); err != nil {
		t.Fatalf("failed to init schema: %v", err)
	}

	// Create two users
	_, err = testDB.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)", "user-1", "alice", "hash")
	if err != nil {
		t.Fatalf("failed to insert user: %v", err)
	}
	_, err = testDB.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)", "user-2", "bob", "hash")
	if err != nil {
		t.Fatalf("failed to insert user: %v", err)
	}
	_, err = testDB.Exec("INSERT INTO agents (id, name) VALUES (?, ?)", "agent-1", "TestAgent")
	if err != nil {
		t.Fatalf("failed to insert agent: %v", err)
	}
	_, err = testDB.Exec("INSERT INTO conversations (id, user_id, agent_id) VALUES (?, ?, ?)", "conv-1", "user-1", "agent-1")
	if err != nil {
		t.Fatalf("failed to insert conversation: %v", err)
	}

	// user-2 tries to set prefs on user-1's conversation
	ctx := context.WithValue(context.Background(), contextKeyUserID, "user-2")
	req := httptest.NewRequest("POST", "/notif/prefs?conversation_id=conv-1&muted=true", nil)
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	handleSetNotificationPrefs(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d: %s", rr.Code, rr.Body.String())
	}
}

// CB34: initSchema edge cases

func TestCB34_InitSchema_AlreadyMigrated(t *testing.T) {
	dbPath := ":memory:"
	testDB, err := openDatabase("sqlite3", dbPath)
	if err != nil {
		t.Fatalf("failed to open test db: %v", err)
	}
	t.Cleanup(func() { testDB.Close() })

	// First migration
	if err := initSchema(testDB); err != nil {
		t.Fatalf("first initSchema failed: %v", err)
	}

	// Second call should be idempotent
	if err := initSchema(testDB); err != nil {
		t.Fatalf("second initSchema failed: %v", err)
	}

	// Verify schema_migrations has the right count
	var count int
	testDB.QueryRow("SELECT COUNT(*) FROM schema_migrations").Scan(&count)
	if count != 8 {
		t.Errorf("expected 8 migrations, got %d", count)
	}
}

// CB34: RegisterAgentOnConnect edge cases

func TestCB34_RegisterAgentOnConnect_AgentUpdateExisting(t *testing.T) {
	dbPath := ":memory:"
	testDB, err := openDatabase("sqlite3", dbPath)
	if err != nil {
		t.Fatalf("failed to open test db: %v", err)
	}
	t.Cleanup(func() { testDB.Close() })

	oldDB := db
	db = testDB
	t.Cleanup(func() { db = oldDB })

	if err := initSchema(testDB); err != nil {
		t.Fatalf("failed to init schema: %v", err)
	}

	// Pre-insert an agent
	_, err = testDB.Exec("INSERT INTO agents (id, name, model, personality, specialty) VALUES (?, ?, ?, ?, ?)",
		"agent-1", "OldName", "old-model", "old-personality", "old-specialty")
	if err != nil {
		t.Fatalf("failed to insert agent: %v", err)
	}

	// Register again with new metadata
	err = RegisterAgentOnConnect("agent-1", "NewName", "new-model", "new-personality", "new-specialty")
	if err != nil {
		t.Fatalf("RegisterAgentOnConnect failed: %v", err)
	}

	// Verify the agent was updated
	var name, model string
	testDB.QueryRow("SELECT name, model FROM agents WHERE id = ?", "agent-1").Scan(&name, &model)
	if name != "NewName" {
		t.Errorf("expected name 'NewName', got %s", name)
	}
	if model != "new-model" {
		t.Errorf("expected model 'new-model', got %s", model)
	}
}

func TestCB34_RegisterAgentOnConnect_PreservesExistingMetadata(t *testing.T) {
	dbPath := ":memory:"
	testDB, err := openDatabase("sqlite3", dbPath)
	if err != nil {
		t.Fatalf("failed to open test db: %v", err)
	}
	t.Cleanup(func() { testDB.Close() })

	oldDB := db
	db = testDB
	t.Cleanup(func() { db = oldDB })

	if err := initSchema(testDB); err != nil {
		t.Fatalf("failed to init schema: %v", err)
	}

	// Pre-insert an agent with metadata
	_, err = testDB.Exec("INSERT INTO agents (id, name, model, personality, specialty) VALUES (?, ?, ?, ?, ?)",
		"agent-1", "TestAgent", "gpt-4", "friendly", "general")
	if err != nil {
		t.Fatalf("failed to insert agent: %v", err)
	}

	// Register again with empty metadata - should preserve existing
	err = RegisterAgentOnConnect("agent-1", "", "", "", "")
	if err != nil {
		t.Fatalf("RegisterAgentOnConnect failed: %v", err)
	}

	// Verify metadata was preserved
	var name, model, personality string
	testDB.QueryRow("SELECT name, model, personality FROM agents WHERE id = ?", "agent-1").Scan(&name, &model, &personality)
	if name != "TestAgent" {
		t.Errorf("expected preserved name 'TestAgent', got %s", name)
	}
	if model != "gpt-4" {
		t.Errorf("expected preserved model 'gpt-4', got %s", model)
	}
	if personality != "friendly" {
		t.Errorf("expected preserved personality 'friendly', got %s", personality)
	}
}

// CB34: handleUpload edge cases

func TestCB34_HandleUpload_FileTooLarge(t *testing.T) {
	dbPath := ":memory:"
	testDB, err := openDatabase("sqlite3", dbPath)
	if err != nil {
		t.Fatalf("failed to open test db: %v", err)
	}
	t.Cleanup(func() { testDB.Close() })

	oldDB := db
	db = testDB
	t.Cleanup(func() { db = oldDB })

	if err := initSchema(testDB); err != nil {
		t.Fatalf("failed to init schema: %v", err)
	}

	// Create a user so FK constraint is satisfied
	_, err = testDB.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)", "user-1", "alice", "hash")
	if err != nil {
		t.Fatalf("failed to insert user: %v", err)
	}

	validToken := generateTestJWT(t, "user-1", "alice")

	// Set a very small max upload size
	oldMax := maxUploadSize
	maxUploadSize = 100 // 100 bytes
	t.Cleanup(func() { maxUploadSize = oldMax })

	// Create multipart form with a file larger than 100 bytes
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	part, err := writer.CreateFormFile("file", "large.txt")
	if err != nil {
		t.Fatalf("failed to create form file: %v", err)
	}
	part.Write(bytes.Repeat([]byte("A"), 200)) // 200 bytes, exceeds 100 byte limit
	writer.Close()

	req := httptest.NewRequest("POST", "/upload", body)
	req.Header.Set("Authorization", "Bearer "+validToken)
	req.Header.Set("Content-Type", writer.FormDataContentType())

	rr := httptest.NewRecorder()
	handleUpload(rr, req)

	// Should get 400 for file too large or invalid form data
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for file too large, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestCB34_HandleUpload_DisallowedContentType(t *testing.T) {
	dbPath := ":memory:"
	testDB, err := openDatabase("sqlite3", dbPath)
	if err != nil {
		t.Fatalf("failed to open test db: %v", err)
	}
	t.Cleanup(func() { testDB.Close() })

	oldDB := db
	db = testDB
	t.Cleanup(func() { db = oldDB })

	if err := initSchema(testDB); err != nil {
		t.Fatalf("failed to init schema: %v", err)
	}

	// Create a user
	_, err = testDB.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)", "user-1", "alice", "hash")
	if err != nil {
		t.Fatalf("failed to insert user: %v", err)
	}

	validToken := generateTestJWT(t, "user-1", "alice")

	// Create multipart form with an executable file type
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	part, err := writer.CreateFormFile("file", "malware.exe")
	if err != nil {
		t.Fatalf("failed to create form file: %v", err)
	}
	part.Write([]byte("MZ\x90\x00")) // PE header magic bytes
	writer.Close()

	req := httptest.NewRequest("POST", "/upload", body)
	req.Header.Set("Authorization", "Bearer "+validToken)
	req.Header.Set("Content-Type", writer.FormDataContentType())

	rr := httptest.NewRecorder()
	handleUpload(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for disallowed content type, got %d: %s", rr.Code, rr.Body.String())
	}
}
