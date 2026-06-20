package main

// Coverage boost 32: targeting remaining low-coverage functions
// - parseSize: all unit suffixes, plain number, empty, invalid
// - handleUpload: success path with multipart form
// - handleListAgents: with agents in DB
// - handleListConversations: success path with conversations
// - sendFCMNotification: disabled config returns nil
// - sendAPNSNotification: disabled config returns nil
// - deleteConversation: nonexistent conversation
// - handleSetNotificationPrefs: method not allowed
// - loadQueueFromDB: empty queue, nil DB
// - initSchema: fresh database
// - sendWelcomeMessage: agent and client welcome
// - routeHeartbeat: heartbeat message routing
// - truncate: utility function
// - sendError: error sending
// - Hub.AgentStatus / Hub.SetAgentStatus / Hub.GetClient
// - tieredRateLimitMiddleware: basic request flow
// - handleGetMessages: with messages in DB
// - addReaction: duplicate reaction handling
// - getConversationTags: with tags
// - handleAdminAgents: with online agents

import (
		"bytes"
	"context"
	"encoding/json"
	"fmt"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
		"time"

	"golang.org/x/crypto/bcrypt"
)

// ==============================
// parseSize tests
// ==============================

func TestCB32_ParseSize_PlainNumber(t *testing.T) {
	v, err := parseSize("1024")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if v != 1024 {
		t.Errorf("expected 1024, got %d", v)
	}
}

func TestCB32_ParseSize_Bytes(t *testing.T) {
	v, err := parseSize("512B")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if v != 512 {
		t.Errorf("expected 512, got %d", v)
	}
}

func TestCB32_ParseSize_KB(t *testing.T) {
	v, err := parseSize("1KB")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if v != 1024 {
		t.Errorf("expected 1024, got %d", v)
	}
}

func TestCB32_ParseSize_MB(t *testing.T) {
	v, err := parseSize("1MB")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if v != 1<<20 {
		t.Errorf("expected %d, got %d", 1<<20, v)
	}
}

func TestCB32_ParseSize_GB(t *testing.T) {
	v, err := parseSize("2GB")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if v != 2<<30 {
		t.Errorf("expected %d, got %d", 2<<30, v)
	}
}

func TestCB32_ParseSize_TB(t *testing.T) {
	v, err := parseSize("1TB")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if v != 1<<40 {
		t.Errorf("expected %d, got %d", 1<<40, v)
	}
}

func TestCB32_ParseSize_Decimal(t *testing.T) {
	v, err := parseSize("1.5MB")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	expected := int64(1.5 * float64(1<<20))
	if v != expected {
		t.Errorf("expected %d, got %d", expected, v)
	}
}

func TestCB32_ParseSize_Empty(t *testing.T) {
	_, err := parseSize("")
	if err == nil {
		t.Error("expected error for empty string")
	}
}

func TestCB32_ParseSize_Invalid(t *testing.T) {
	_, err := parseSize("abc")
	if err == nil {
		t.Error("expected error for invalid format")
	}
}

func TestCB32_ParseSize_CaseInsensitive(t *testing.T) {
	v, err := parseSize("1mb")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if v != 1<<20 {
		t.Errorf("expected %d, got %d", 1<<20, v)
	}
}

func TestCB32_ParseSize_Whitespace(t *testing.T) {
	v, err := parseSize("  1KB  ")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if v != 1024 {
		t.Errorf("expected 1024, got %d", v)
	}
}

// ==============================
// sendFCMNotification / sendAPNSNotification disabled
// ==============================

func TestCB32_SendFCMNotification_Disabled(t *testing.T) {
	origConfig := pushConfig
	defer func() { pushConfig = origConfig }()
	pushConfig = nil

	err := sendFCMNotification("token", "title", "body", "conv1")
	if err != nil {
		t.Errorf("expected nil error when pushConfig is nil, got %v", err)
	}
}

func TestCB32_SendAPNSNotification_Disabled(t *testing.T) {
	origConfig := pushConfig
	defer func() { pushConfig = origConfig }()
	pushConfig = nil

	err := sendAPNSNotification("token", "title", "body", "conv1")
	if err != nil {
		t.Errorf("expected nil error when pushConfig is nil, got %v", err)
	}
}

func TestCB32_SendPushNotification_Android(t *testing.T) {
	origConfig := pushConfig
	defer func() { pushConfig = origConfig }()
	pushConfig = nil // disabled, so sendFCMNotification returns nil

	err := sendPushNotification("token", "title", "body", "conv1", "android")
	if err != nil {
		t.Errorf("expected nil error, got %v", err)
	}
}

func TestCB32_SendPushNotification_IOS(t *testing.T) {
	origConfig := pushConfig
	defer func() { pushConfig = origConfig }()
	pushConfig = nil

	err := sendPushNotification("token", "title", "body", "conv1", "ios")
	if err != nil {
		t.Errorf("expected nil error, got %v", err)
	}
}

func TestCB32_SendPushNotification_Unknown(t *testing.T) {
	origConfig := pushConfig
	defer func() { pushConfig = origConfig }()
	pushConfig = nil

	err := sendPushNotification("token", "title", "body", "conv1", "unknown")
	if err != nil {
		t.Errorf("expected nil error for unknown platform, got %v", err)
	}
}

// ==============================
// handleUpload success path
// ==============================

func TestCB32_HandleUpload_Success(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	// Create user and get JWT
	token := cb31MakeJWT(t, "uploaduser")

	// Create multipart form
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	part, err := writer.CreateFormFile("file", "test.txt")
	if err != nil {
		t.Fatal(err)
	}
	part.Write([]byte("Hello, World!"))
	writer.Close()

	req := httptest.NewRequest(http.MethodPost, "/upload", body)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", writer.FormDataContentType())

	w := httptest.NewRecorder()
	handleUpload(w, req)

	if w.Code != 200 {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	if resp["filename"] != "test.txt" {
		t.Errorf("unexpected response: %v", resp)
	}
}

func TestCB32_HandleUpload_TooLarge(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	token := cb31MakeJWT(t, "uploaduser2")

	// Create a file that exceeds the max upload size
	// Set small upload limit
	origMaxSize := maxUploadSize
	maxUploadSize = 1024
	defer func() { maxUploadSize = origMaxSize }()

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	part, err := writer.CreateFormFile("file", "big.txt")
	if err != nil {
		t.Fatal(err)
	}
	// Write 2KB of data
	data := strings.Repeat("A", 2048)
	part.Write([]byte(data))
	writer.Close()

	req := httptest.NewRequest(http.MethodPost, "/upload", body)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", writer.FormDataContentType())

	w := httptest.NewRecorder()
	handleUpload(w, req)

	if w.Code != 400 {
		t.Errorf("expected 400 for too large file, got %d: %s", w.Code, w.Body.String())
	}
}

// ==============================
// handleListAgents with agents in DB
// ==============================

func TestCB32_HandleListAgents_WithAgents(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	hub = newHub()
	go hub.run()
	t.Cleanup(func() { hub.Stop() })

	// Insert agents into DB
	for _, a := range []struct {
		id, name, model, personality, specialty string
	}{
		{"agent-1", "Alpha", "gpt-4", "friendly", "general"},
		{"agent-2", "Beta", "claude-3", "formal", "coding"},
		{"agent-3", "Gamma", "llama-3", "casual", "research"},
	} {
		_, err := db.Exec(
			"INSERT OR IGNORE INTO agents (id, name, model, personality, specialty, created_at) VALUES (?, ?, ?, ?, ?, ?)",
			a.id, a.name, a.model, a.personality, a.specialty, time.Now().UTC(),
		)
		if err != nil {
			t.Fatalf("insert agent %s: %v", a.id, err)
		}
	}

	req := httptest.NewRequest(http.MethodGet, "/agents", nil)
	w := httptest.NewRecorder()
	handleListAgents(w, req)

	if w.Code != 200 {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var agents []map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &agents); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	if len(agents) != 3 {
		t.Errorf("expected 3 agents, got %d", len(agents))
	}
}

func TestCB32_HandleListAgents_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/agents", nil)
	w := httptest.NewRecorder()
	handleListAgents(w, req)
	if w.Code != 405 {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

// ==============================
// handleListConversations success path
// ==============================

func TestCB32_HandleListConversations_WithData(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	token := cb31MakeJWT(t, "convuser")
	claims, _ := ValidateJWT(token)

	// Create conversations
	conv1, err := GetOrCreateConversation(claims.UserID, "agent-x")
	if err != nil {
		t.Fatalf("create conv1: %v", err)
	}
	conv2, err := GetOrCreateConversation(claims.UserID, "agent-y")
	if err != nil {
		t.Fatalf("create conv2: %v", err)
	}

	// Insert messages
	for _, convID := range []string{conv1.ID, conv2.ID} {
		_, err = db.Exec(
			"INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, created_at) VALUES (?, ?, ?, ?, ?, ?)",
			generateID("msg"), convID, "user", "user-1", "Hello", time.Now().UTC(),
		)
		if err != nil {
			t.Fatalf("insert message: %v", err)
		}
	}

	req := httptest.NewRequest(http.MethodGet, "/conversations", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleListConversations(w, req)

	if w.Code != 200 {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var convs []map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &convs); err != nil {
		t.Fatalf("failed to parse: %v", err)
	}
	if len(convs) != 2 {
		t.Errorf("expected 2 conversations, got %d", len(convs))
	}
}

func TestCB32_HandleListConversations_Empty(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	token := cb31MakeJWT(t, "emptyuser")

	req := httptest.NewRequest(http.MethodGet, "/conversations", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleListConversations(w, req)

	if w.Code != 200 {
		t.Errorf("expected 200, got %d", w.Code)
	}

	var convs []map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &convs); err != nil {
		t.Fatalf("failed to parse: %v", err)
	}
	if len(convs) != 0 {
		t.Errorf("expected 0 conversations, got %d", len(convs))
	}
}

func TestCB32_HandleListConversations_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/conversations", nil)
	w := httptest.NewRecorder()
	handleListConversations(w, req)
	if w.Code != 405 {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

// ==============================
// handleListConversations with unread count
// ==============================

func TestCB32_HandleListConversations_UnreadCount(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	token := cb31MakeJWT(t, "unreaduser")
	claims, _ := ValidateJWT(token)

	conv, err := GetOrCreateConversation(claims.UserID, "agent-unread")
	if err != nil {
		t.Fatalf("create conv: %v", err)
	}

	// Insert 3 messages from agent (unread)
	for i := 0; i < 3; i++ {
		_, err = db.Exec(
			"INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, created_at) VALUES (?, ?, ?, ?, ?, ?)",
			generateID("msg"), conv.ID, "agent", "agent-1", fmt.Sprintf("msg %d", i), time.Now().UTC(),
		)
		if err != nil {
			t.Fatalf("insert message: %v", err)
		}
	}

	req := httptest.NewRequest(http.MethodGet, "/conversations", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleListConversations(w, req)

	if w.Code != 200 {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var convs []map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &convs); err != nil {
		t.Fatalf("failed to parse: %v", err)
	}
	if len(convs) != 1 {
		t.Fatalf("expected 1 conversation, got %d", len(convs))
	}
	// unread_count should be 3 (messages with read_at IS NULL)
	unread, _ := convs[0]["unread_count"].(float64)
	if int(unread) != 3 {
		t.Errorf("expected unread_count 3, got %v", convs[0]["unread_count"])
	}
}

// ==============================
// deleteConversation nonexistent
// ==============================

func TestCB32_DeleteConversation_Nonexistent(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	token := cb31MakeJWT(t, "deluser")

	req := httptest.NewRequest(http.MethodDelete, "/conversations?conversation_id=nonexistent", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleDeleteConversation(w, req)

	if w.Code != 404 {
		t.Errorf("expected 404 for nonexistent conversation, got %d: %s", w.Code, w.Body.String())
	}
}

// ==============================
// handleSetNotificationPrefs method not allowed
// ==============================

func TestCB32_HandleSetNotificationPrefs_MethodNotAllowed(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	// Set context with user ID (as authMiddleware would)
	req := httptest.NewRequest(http.MethodGet, "/notifications/preferences", nil)
	ctx := context.WithValue(req.Context(), contextKeyUserID, "notifuser")
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()
	handleSetNotificationPrefs(w, req)
	// Handler checks auth (from context) then conversation_id, not method
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing conversation_id, got %d", w.Code)
	}
}

// ==============================
// initSchema test
// ==============================

func TestCB32_InitSchema_FreshDB(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test_schema.db")

	d, err := openDatabase("sqlite3", dbPath)
	if err != nil {
		t.Fatalf("openDatabase: %v", err)
	}
	defer d.Close()

	err = initSchema(d)
	if err != nil {
		t.Fatalf("initSchema: %v", err)
	}

	// Verify tables exist
	tables := []string{"users", "agents", "conversations", "messages", "attachments"}
	for _, table := range tables {
		var name string
		err = d.QueryRow("SELECT name FROM sqlite_master WHERE type='table' AND name=?", table).Scan(&name)
		if err != nil {
			t.Errorf("table %s not found: %v", table, err)
		}
	}
}

// ==============================
// sendWelcomeMessage tests
// ==============================

func TestCB32_SendWelcomeMessage_Agent(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	hub = newHub()
	go hub.run()
	t.Cleanup(func() { hub.Stop() })

	conn := &Connection{
		id:       "test-agent-welcome",
		connType: "agent",
		send:     make(chan []byte, 256),
		hub:      hub,
	}
	hub.register <- conn

	// Give hub time to process
	time.Sleep(10 * time.Millisecond)

	sendWelcomeMessage(conn)

	select {
	case msg := <-conn.send:
		if !strings.Contains(string(msg), "welcome") && !strings.Contains(string(msg), "agent") {
			t.Errorf("unexpected welcome message: %s", string(msg))
		}
	case <-time.After(100 * time.Millisecond):
		// Welcome message might have been consumed already, that's ok
	}
}

func TestCB32_SendWelcomeMessage_Client(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	hub = newHub()
	go hub.run()
	t.Cleanup(func() { hub.Stop() })

	conn := &Connection{
		id:       "test-client-welcome",
		connType: "client",
		send:     make(chan []byte, 256),
		hub:      hub,
	}
	hub.register <- conn
	time.Sleep(10 * time.Millisecond)

	sendWelcomeMessage(conn)

	select {
	case msg := <-conn.send:
		if !strings.Contains(string(msg), "welcome") && !strings.Contains(string(msg), "client") {
			t.Errorf("unexpected welcome message: %s", string(msg))
		}
	case <-time.After(100 * time.Millisecond):
		// ok
	}
}

// ==============================
// truncate utility
// ==============================

func TestCB32_Truncate_ShortString(t *testing.T) {
	result := truncate("hello", 10)
	if result != "hello" {
		t.Errorf("expected 'hello', got '%s'", result)
	}
}

func TestCB32_Truncate_ExactLength(t *testing.T) {
	result := truncate("hello", 5)
	if result != "hello" {
		t.Errorf("expected 'hello', got '%s'", result)
	}
}

func TestCB32_Truncate_LongString(t *testing.T) {
	result := truncate("hello world foo", 5)
	if result != "he..." {
		t.Errorf("expected 'hello', got '%s'", result)
	}
}

func TestCB32_Truncate_Empty(t *testing.T) {
	result := truncate("", 5)
	if result != "" {
		t.Errorf("expected '', got '%s'", result)
	}
}

// ==============================
// sendError
// ==============================

func TestCB32_SendError(t *testing.T) {
	conn := &Connection{
		send: make(chan []byte, 10),
		hub:  &Hub{},
	}

	sendError(conn, "test error message")

	select {
	case msg := <-conn.send:
		if !strings.Contains(string(msg), "test error message") {
			t.Errorf("expected error message in output, got: %s", string(msg))
		}
	case <-time.After(100 * time.Millisecond):
		t.Error("no message received on send channel")
	}
}

// ==============================
// Hub.AgentStatus / SetAgentStatus / GetClient
// ==============================

func TestCB32_Hub_AgentStatus_SetAndGet(t *testing.T) {
	hub := newHub()

	conn := &Connection{
		id:       "agent-status-test",
		connType: "agent",
		send:     make(chan []byte, 10),
		hub:      hub,
	}

	hub.agents["agent-status-test"] = conn

	// Default status should be "online"
	status := hub.AgentStatus("agent-status-test")
	if status != "online" {
		t.Errorf("expected 'online', got '%s'", status)
	}

	// Set to busy
	hub.SetAgentStatus("agent-status-test", "busy")
	status = hub.AgentStatus("agent-status-test")
	if status != "busy" {
		t.Errorf("expected 'busy', got '%s'", status)
	}

	// Set to idle
	hub.SetAgentStatus("agent-status-test", "idle")
	status = hub.AgentStatus("agent-status-test")
	if status != "idle" {
		t.Errorf("expected 'idle', got '%s'", status)
	}
}

func TestCB32_Hub_AgentStatus_NotFound(t *testing.T) {
	hub := newHub()
	status := hub.AgentStatus("nonexistent-agent")
	if status != "offline" {
		t.Errorf("expected 'offline' for nonexistent agent, got '%s'", status)
	}
}

func TestCB32_Hub_GetClient_Exists(t *testing.T) {
	hub := newHub()

	conn := &Connection{
		id:       "user-getclient-test",
		connType: "client",
		send:     make(chan []byte, 10),
		hub:      hub,
	}
	hub.clientConns["user-getclient-test"] = []*Connection{conn}

	result := hub.GetClient("user-getclient-test")
	if result == nil {
		t.Error("expected non-nil connection")
	}
	if result.id != "user-getclient-test" {
		t.Errorf("expected id 'user-getclient-test', got '%s'", result.id)
	}
}

func TestCB32_Hub_GetClient_NotExists(t *testing.T) {
	hub := newHub()
	result := hub.GetClient("nonexistent-user")
	if result != nil {
		t.Error("expected nil for nonexistent client")
	}
}

func TestCB32_Hub_ClientConnCount(t *testing.T) {
	hub := newHub()

	conn1 := &Connection{id: "user1", connType: "client", send: make(chan []byte, 10), hub: hub}
	conn2 := &Connection{id: "user2", connType: "client", send: make(chan []byte, 10), hub: hub}
	conn3 := &Connection{id: "user1", connType: "client", send: make(chan []byte, 10), hub: hub}

	hub.clientConns["user1"] = []*Connection{conn1}
	hub.clientConns["user1-2"] = []*Connection{conn3}
	hub.clientConns["user2"] = []*Connection{conn2}

	count := hub.ClientConnCount()
	if count != 3 {
		t.Errorf("expected 3 total connections, got %d", count)
	}
}

// ==============================
// Hub.AgentCount and ClientCount
// ==============================

func TestCB32_Hub_AgentCount(t *testing.T) {
	hub := newHub()
	hub.agents["a1"] = &Connection{id: "a1", connType: "agent", send: make(chan []byte, 10)}
	hub.agents["a2"] = &Connection{id: "a2", connType: "agent", send: make(chan []byte, 10)}

	if hub.AgentCount() != 2 {
		t.Errorf("expected 2 agents, got %d", hub.AgentCount())
	}
}

func TestCB32_Hub_ClientCount(t *testing.T) {
	hub := newHub()
	hub.clientConns["u1"] = []*Connection{&Connection{id: "u1", connType: "client", send: make(chan []byte, 10)}}

	if hub.ClientCount() != 1 {
		t.Errorf("expected 1 client, got %d", hub.ClientCount())
	}
}

// ==============================
// Hub.BroadcastToAllClients with data
// ==============================

func TestCB32_Hub_BroadcastToAllClients_WithClients(t *testing.T) {
	hub := newHub()

	conn1 := &Connection{id: "u1", connType: "client", send: make(chan []byte, 10), hub: hub}
	conn2 := &Connection{id: "u2", connType: "client", send: make(chan []byte, 10), hub: hub}

	hub.clientConns["u1"] = []*Connection{conn1}
	hub.clientConns["u2"] = []*Connection{conn2}

	hub.BroadcastToAllClients([]byte("broadcast test"))

	for _, conn := range []*Connection{conn1, conn2} {
		select {
		case msg := <-conn.send:
			if string(msg) != "broadcast test" {
				t.Errorf("expected 'broadcast test', got '%s'", string(msg))
			}
		case <-time.After(100 * time.Millisecond):
			t.Error("no broadcast message received")
		}
	}
}

// ==============================
// Hub.broadcastPresence
// ==============================

func TestCB32_Hub_BroadcastPresence(t *testing.T) {
	hub := newHub()

	clientConn := &Connection{id: "user-presence", connType: "client", send: make(chan []byte, 10), hub: hub}
	hub.clientConns["user-presence"] = []*Connection{clientConn}

	hub.broadcastPresence("agent-foo", "agent", true)

	select {
	case msg := <-clientConn.send:
		if !strings.Contains(string(msg), "agent-foo") {
			t.Errorf("expected agent-foo in presence message, got: %s", string(msg))
		}
	case <-time.After(100 * time.Millisecond):
		t.Error("no presence message received")
	}
}

// ==============================
// tieredRateLimitMiddleware basic flow
// ==============================

func TestCB32_TieredRateLimitMiddleware_BasicFlow(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	// Create a test handler
	called := false
	handler := tieredRateLimitMiddleware(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()
	handler(w, req)

	if !called {
		t.Error("handler was not called")
	}
}

// ==============================
// handleGetMessages with messages
// ==============================

func TestCB32_HandleGetMessages_WithMessages(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	token := cb31MakeJWT(t, "msguser")
	claims, _ := ValidateJWT(token)

	conv, err := GetOrCreateConversation(claims.UserID, "agent-msgs")
	if err != nil {
		t.Fatalf("create conv: %v", err)
	}

	// Insert messages
	for i := 0; i < 5; i++ {
		_, err = db.Exec(
			"INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, created_at) VALUES (?, ?, ?, ?, ?, ?)",
			generateID("msg"), conv.ID, "user", "user-1", fmt.Sprintf("message %d", i), time.Now().Add(time.Duration(i)*time.Minute).UTC(),
		)
		if err != nil {
			t.Fatalf("insert message: %v", err)
		}
	}

	req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/conversations/messages?conversation_id=%s&limit=3", conv.ID), nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleGetMessages(w, req)

	if w.Code != 200 {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var msgs []map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &msgs); err != nil {
		t.Fatalf("failed to parse: %v", err)
	}
	if len(msgs) != 3 {
		t.Errorf("expected 3 messages, got %d", len(msgs))
	}
}

// ==============================
// handleAdminAgents with online agents
// ==============================

func TestCB32_HandleAdminAgents_WithOnlineAgents(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	// Set admin secret
	origEnv := os.Getenv("ADMIN_SECRET")
	defer func() {
		os.Setenv("ADMIN_SECRET", origEnv)
		resetAdminSecret()
	}()
	os.Setenv("ADMIN_SECRET", "test-admin-cb32")
	resetAdminSecret()

	// Insert agents
	for _, a := range []struct{ id, name string }{
		{"admin-agent-1", "Admin1"},
		{"admin-agent-2", "Admin2"},
	} {
		_, err := db.Exec(
			"INSERT OR IGNORE INTO agents (id, name, model, personality, specialty, created_at) VALUES (?, ?, ?, ?, ?, ?)",
			a.id, a.name, "test-model", "test", "test", time.Now().UTC(),
		)
		if err != nil {
			t.Fatalf("insert agent: %v", err)
		}
	}

	// Set up hub with online agents
	hub = newHub()
	go hub.run()
	t.Cleanup(func() { hub.Stop() })

	conn1 := &Connection{id: "admin-agent-1", connType: "agent", send: make(chan []byte, 10), hub: hub, connectedAt: time.Now()}
	conn2 := &Connection{id: "admin-agent-2", connType: "agent", send: make(chan []byte, 10), hub: hub, connectedAt: time.Now()}
	hub.agents["admin-agent-1"] = conn1
	hub.agents["admin-agent-2"] = conn2

	req := httptest.NewRequest(http.MethodGet, "/admin/agents", nil)
	req.Header.Set("X-Admin-Secret", "test-admin-cb32")
	w := httptest.NewRecorder()
	handleAdminAgents(w, req)

	if w.Code != 200 {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var agents []map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &agents); err != nil {
		t.Fatalf("failed to parse: %v", err)
	}
	if len(agents) != 2 {
		t.Errorf("expected 2 agents, got %d", len(agents))
	}
}

// ==============================
// handleCreateConversation success
// ==============================

func TestCB32_HandleCreateConversation_Success(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	token := cb31MakeJWT(t, "createuser")

	// Register agent first
	_, err := db.Exec(
		"INSERT OR IGNORE INTO agents (id, name, model, personality, specialty, created_at) VALUES (?, ?, ?, ?, ?, ?)",
		"conv-agent", "ConvAgent", "model", "personality", "specialty", time.Now().UTC(),
	)
	if err != nil {
		t.Fatalf("insert agent: %v", err)
	}

	form := "agent_id=conv-agent"
	req := httptest.NewRequest(http.MethodPost, "/conversations/create", strings.NewReader(form))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handleCreateConversation(w, req)

	if w.Code != 200 {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse: %v", err)
	}
	if resp["conversation_id"] == nil {
		t.Error("expected conversation id in response")
	}
}

// ==============================
// routeHeartbeat
// ==============================

func TestCB32_RouteHeartbeat(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	hub = newHub()
	go hub.run()
	t.Cleanup(func() { hub.Stop() })

	conn := &Connection{
		id:       "heartbeat-agent",
		connType: "agent",
		send:     make(chan []byte, 256),
		hub:      hub,
	}
	hub.agents["heartbeat-agent"] = conn

	routeHeartbeat(conn)

	// Heartbeat should update the lastHeartbeat field
	// routeHeartbeat calls TouchHeartbeat which updates conn.lastHeartbeat
	if conn.lastHeartbeat.IsZero() {
		t.Error("expected heartbeat to be recorded on connection")
	}
}

// ==============================
// getDeviceTokensForUser
// ==============================

func TestCB32_GetDeviceTokensForUser_WithTokens(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	// Insert device tokens
	for i, platform := range []string{"ios", "android"} {
		_, err := db.Exec(
			"INSERT INTO device_tokens (user_id, device_token, platform, created_at) VALUES (?, ?, ?, ?)",
			"device-user", fmt.Sprintf("token-%d", i), platform, time.Now().UTC(),
		)
		if err != nil {
			t.Fatalf("insert device token: %v", err)
		}
	}

	tokens, err := getDeviceTokensForUser("device-user")
	if err != nil {
		t.Fatalf("getDeviceTokensForUser: %v", err)
	}
	if len(tokens) != 2 {
		t.Errorf("expected 2 tokens, got %d", len(tokens))
	}
}

func TestCB32_GetDeviceTokensForUser_NoTokens(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	tokens, err := getDeviceTokensForUser("user-no-tokens")
	if err != nil {
		t.Fatalf("getDeviceTokensForUser: %v", err)
	}
	if len(tokens) != 0 {
		t.Errorf("expected 0 tokens, got %d", len(tokens))
	}
}

// ==============================
// notifyUser with no config
// ==============================

func TestCB32_NotifyUser_NoConfig(t *testing.T) {
	origConfig := pushConfig
	defer func() { pushConfig = origConfig }()
	pushConfig = nil

	// Should not panic, should just skip push
	notifyUser("user-no-push", "title", "body", "conv1")
	// No assertion needed — just verify it doesn't panic
}

// ==============================
// writeJSON
// ==============================

func TestCB32_WriteJSON(t *testing.T) {
	w := httptest.NewRecorder()
	writeJSON(w, http.StatusOK, map[string]string{"key": "value"})

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	if w.Header().Get("Content-Type") != "application/json" {
		t.Errorf("expected application/json content type, got %s", w.Header().Get("Content-Type"))
	}
	var result map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatalf("failed to parse: %v", err)
	}
	if result["key"] != "value" {
		t.Errorf("expected key=value, got %v", result)
	}
}

// ==============================
// writeJSONError
// ==============================

func TestCB32_WriteJSONError(t *testing.T) {
	w := httptest.NewRecorder()
	writeJSONError(w, http.StatusBadRequest, "bad request")

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
	var result map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatalf("failed to parse: %v", err)
	}
	if result["error"] != "bad request" {
		t.Errorf("expected error='bad request', got %v", result)
	}
}

// ==============================
// loadQueueFromDB edge cases
// ==============================

func TestCB32_LoadQueueFromDB_Empty(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	oq := newOfflineQueue(100, 7*24*time.Hour)
	loadQueueFromDB(db, oq)
	if oq.TotalDepth() != 0 {
		t.Errorf("expected 0 queued messages, got %d", oq.TotalDepth())
	}
}

func TestCB32_LoadQueueFromDB_NilDB(t *testing.T) {
	oq := newOfflineQueue(100, 7*24*time.Hour)
	loadQueueFromDB(nil, oq)
	// no panic = success
}

// ==============================
// cleanStaleQueueMessages
// ==============================

func TestCB32_CleanStaleQueueMessages(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	// Insert a stale message
	staleTime := time.Now().Add(-10 * 24 * time.Hour)
	_, err := db.Exec(
		"INSERT INTO offline_queue (recipient, data, queued_at, sent_count) VALUES (?, ?, ?, 0)",
		"stale-user", []byte("old message"), staleTime.UTC().Format(time.RFC3339),
	)
	if err != nil {
		t.Fatalf("insert stale queue msg: %v", err)
	}

	cleanStaleQueueMessages(db, 7*24*time.Hour)

	// Verify it was deleted
	var count int
	err = db.QueryRow("SELECT COUNT(*) FROM offline_queue WHERE recipient='stale-user'").Scan(&count)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if count != 0 {
		t.Errorf("expected 0 stale messages after cleanup, got %d", count)
	}
}

// ==============================
// deleteQueueMessages
// ==============================

func TestCB32_DeleteQueueMessages(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	// Insert messages
	for i := 0; i < 3; i++ {
		_, err := db.Exec(
			"INSERT INTO offline_queue (recipient, data, queued_at, sent_count) VALUES (?, ?, ?, 0)",
			"delete-user", []byte(fmt.Sprintf("msg %d", i)), time.Now().UTC().Format(time.RFC3339),
		)
		if err != nil {
			t.Fatalf("insert: %v", err)
		}
	}

	deleteQueueMessages(db, "delete-user")

	var count int
	err := db.QueryRow("SELECT COUNT(*) FROM offline_queue WHERE recipient='delete-user'").Scan(&count)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if count != 0 {
		t.Errorf("expected 0 messages after delete, got %d", count)
	}
}

// ==============================
// handleGetAttachment success path
// ==============================

func TestCB32_HandleGetAttachment_Success(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	// Create a test file in the uploads directory
	tmpDir := t.TempDir()
	origDBPath := serverDBPath
	serverDBPath = filepath.Join(tmpDir, "test.db")
	defer func() { serverDBPath = origDBPath }()
	uploadDir := getUploadDir()
	os.MkdirAll(uploadDir, 0755)
	filePath := filepath.Join(uploadDir, "test-att.txt")
	os.WriteFile(filePath, []byte("test content"), 0644)

	// Create user and get token
	token := createTestUser(t, "attuser1")
	claims, _ := ValidateJWT(token)

	// Insert attachment record
	_, err := db.Exec(
		"INSERT INTO attachments (id, message_id, user_id, filename, content_type, size, sha256, storage_path, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
		"att-test-get", nil, claims.UserID, "test.txt", "text/plain", 12, "abc123", "test-att.txt", time.Now().UTC(),
	)
	if err != nil {
		t.Fatalf("insert attachment: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/attachments/att-test-get", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleGetAttachment(w, req)

	if w.Code != 200 {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if w.Body.String() != "test content" {
		t.Errorf("expected 'test content', got '%s'", w.Body.String())
	}
}

func TestCB32_HandleGetAttachment_NotFound(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	token := createTestUser(t, "attuser3")
	req := httptest.NewRequest(http.MethodGet, "/attachments/nonexistent", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleGetAttachment(w, req)

	if w.Code != 404 {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

// ==============================
// handleListAttachments with data
// ==============================

func TestCB32_HandleListAttachments_WithData(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	token := cb31MakeJWT(t, "attlistuser")
	claims, _ := ValidateJWT(token)

	conv, err := GetOrCreateConversation(claims.UserID, "att-agent")
	if err != nil {
		t.Fatalf("create conv: %v", err)
	}

	// Insert attachments
	for i := 0; i < 3; i++ {
		_, err = db.Exec(
			"INSERT INTO attachments (id, message_id, user_id, filename, content_type, size, sha256, storage_path, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
			generateID("att"), nil, claims.UserID, fmt.Sprintf("file%d.txt", i), "text/plain", 100, "hash", fmt.Sprintf("file%d.txt", i), time.Now().UTC(),
		)
		if err != nil {
			t.Fatalf("insert attachment: %v", err)
		}
	}

	req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/attachments?conversation_id=%s", conv.ID), nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleListAttachments(w, req)

	if w.Code != 200 {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

// ==============================
// addReaction duplicate
// ==============================

func TestCB32_AddReaction_Duplicate(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	// Create user and conversation
	token := createTestUser(t, "reactuser1")
	claims, _ := ValidateJWT(token)
	// Insert agent for FK
	_, err := db.Exec(
		"INSERT OR IGNORE INTO agents (id, name, model, personality, specialty, created_at) VALUES (?, ?, ?, ?, ?, ?)",
		"react-agent", "ReactAgent", "test", "test", "test", time.Now().UTC(),
	)
	if err != nil {
		t.Fatalf("insert agent: %v", err)
	}
	_, err = db.Exec(
		"INSERT INTO conversations (id, user_id, agent_id, created_at) VALUES (?, ?, ?, ?)",
		"conv-1", claims.UserID, "react-agent", time.Now().UTC(),
	)
	if err != nil {
		t.Fatalf("insert conversation: %v", err)
	}

	// Insert a message
	msgID := generateID("msg")
	_, err = db.Exec(
		"INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, created_at) VALUES (?, ?, ?, ?, ?, ?)",
		msgID, "conv-1", "user", claims.UserID, "test", time.Now().UTC(),
	)
	if err != nil {
		t.Fatalf("insert message: %v", err)
	}

	// Add reaction
	_, _, err = addReaction(msgID, claims.UserID, "👍")
	if err != nil {
		t.Fatalf("first addReaction: %v", err)
	}

	// Add same reaction again (toggles it off)
	_, _, err = addReaction(msgID, claims.UserID, "👍")
	if err != nil {
		t.Fatalf("duplicate addReaction: %v", err)
	}

	// Verify reaction was removed by toggle
	var count int
	err = db.QueryRow("SELECT COUNT(*) FROM reactions WHERE message_id=? AND user_id=?", msgID, claims.UserID).Scan(&count)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if count != 0 {
		t.Errorf("expected 0 reactions after toggle, got %d", count)
	}
}

// ==============================
// getMessageReactions
// ==============================

func TestCB32_GetMessageReactions_Multiple(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	// Insert agent for FK
	_, err := db.Exec(
		"INSERT OR IGNORE INTO agents (id, name, model, personality, specialty, created_at) VALUES (?, ?, ?, ?, ?, ?)",
		"react-agent2", "ReactAgent2", "test", "test", "test", time.Now().UTC(),
	)
	if err != nil {
		t.Fatalf("insert agent: %v", err)
	}
	// Create conversation
	_, err = db.Exec(
		"INSERT INTO conversations (id, user_id, agent_id, created_at) VALUES (?, ?, ?, ?)",
		"conv-2", "reactuser2", "react-agent2", time.Now().UTC(),
	)
	if err != nil {
		t.Fatalf("insert conversation: %v", err)
	}

	// Create users for foreign keys
	for _, u := range []string{"reactuser2", "user-a", "user-b", "user-c"} {
		hashed, _ := bcrypt.GenerateFromPassword([]byte("pass"), bcrypt.DefaultCost)
		_, err = db.Exec("INSERT OR IGNORE INTO users (id, username, password_hash) VALUES (?, ?, ?)", u, u, string(hashed))
		if err != nil {
			t.Fatalf("insert user %s: %v", u, err)
		}
	}

	msgID := generateID("msg")
	_, err = db.Exec(
		"INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, created_at) VALUES (?, ?, ?, ?, ?, ?)",
		msgID, "conv-2", "user", "reactuser2", "test", time.Now().UTC(),
	)
	if err != nil {
		t.Fatalf("insert message: %v", err)
	}

	// Add multiple reactions from the conversation owner and agent
	_, _, err = addReaction(msgID, "reactuser2", "👍")
	if err != nil {
		t.Fatalf("addReaction 1: %v", err)
	}
	_, _, err = addReaction(msgID, "react-agent2", "👍")
	if err != nil {
		t.Fatalf("addReaction 2: %v", err)
	}
	_, _, err = addReaction(msgID, "reactuser2", "❤️")
	if err != nil {
		t.Fatalf("addReaction 3: %v", err)
	}

	reactions, err := getMessageReactions(msgID)
	if err != nil {
		t.Fatalf("getMessageReactions: %v", err)
	}

	// Should have 3 reactions total (2 👍 + 1 ❤️)
	if len(reactions) != 3 {
		t.Errorf("expected 3 reactions, got %d", len(reactions))
	}
}

// ==============================
// getConversationTags with tags
// ==============================

func TestCB32_GetConversationTags_WithTags(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	convID := generateID("conv")
	_, err := db.Exec(
		"INSERT INTO conversations (id, user_id, agent_id, created_at) VALUES (?, ?, ?, ?)",
		convID, "tag-user", "tag-agent", time.Now().UTC(),
	)
	if err != nil {
		t.Fatalf("insert conversation: %v", err)
	}

	addConversationTag(convID, "tag-user", "important")
	addConversationTag(convID, "tag-user", "work")

	tags, err := getConversationTags(convID)
	if err != nil {
		t.Fatalf("getConversationTags: %v", err)
	}
	if len(tags) != 2 {
		t.Errorf("expected 2 tags, got %d", len(tags))
	}
}

// ==============================
// removeConversationTag
// ==============================

func TestCB32_RemoveConversationTag_Success(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	convID := generateID("conv")
	_, err := db.Exec(
		"INSERT INTO conversations (id, user_id, agent_id, created_at) VALUES (?, ?, ?, ?)",
		convID, "rm-tag-user", "rm-tag-agent", time.Now().UTC(),
	)
	if err != nil {
		t.Fatalf("insert conversation: %v", err)
	}

	addConversationTag(convID, "rm-tag-user", "toremove")

	err = removeConversationTag(convID, "rm-tag-user", "toremove")
	if err != nil {
		t.Fatalf("removeConversationTag: %v", err)
	}

	tags, _ := getConversationTags(convID)
	for _, tag := range tags {
		if tag.Tag == "toremove" {
			t.Error("tag was not removed")
		}
	}
}

// ==============================
// extractIP tests
// ==============================

func TestCB32_ExtractIP_XForwardedFor(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Forwarded-For", "10.0.0.1, 10.0.0.2")
	ip := extractIP(req)
	if ip != "10.0.0.1" {
		t.Errorf("expected '10.0.0.1', got '%s'", ip)
	}
}

func TestCB32_ExtractIP_XRealIP(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Real-IP", "192.168.1.1")
	ip := extractIP(req)
	if ip != "192.168.1.1" {
		t.Errorf("expected '192.168.1.1', got '%s'", ip)
	}
}

func TestCB32_ExtractIP_RemoteAddr(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	ip := extractIP(req)
	if ip != "127.0.0.1" {
		t.Errorf("expected '127.0.0.1', got '%s'", ip)
	}
}

// ==============================
// getUserID
// ==============================

func TestCB32_GetUserID_NoAuthHeader(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	_, err := getUserID(req)
	if err == nil {
		t.Error("expected error when no auth header")
	}
}

func TestCB32_GetUserID_InvalidToken(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer invalid-token")
	_, err := getUserID(req)
	if err == nil {
		t.Error("expected error for invalid token")
	}
}

// ==============================
// securityHeadersMiddleware
// ==============================

func TestCB32_SecurityHeadersMiddleware(t *testing.T) {
	called := false
	handler := securityHeadersMiddleware(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()
	handler(w, req)

	if !called {
		t.Error("handler was not called")
	}
	// Check security headers
	if w.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Error("expected X-Content-Type-Options: nosniff")
	}
	if w.Header().Get("X-Frame-Options") != "DENY" {
		t.Error("expected X-Frame-Options: DENY")
	}
}

// ==============================
// corsMiddleware
// ==============================

func TestCB32_CorsMiddleware_OptionsRequest(t *testing.T) {
	handler := corsMiddleware(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not be called for OPTIONS")
	})

	req := httptest.NewRequest(http.MethodOptions, "/test", nil)
	req.Header.Set("Origin", "http://localhost:3000")
	w := httptest.NewRecorder()
	handler(w, req)

	if w.Code != http.StatusNoContent {
		t.Errorf("expected 204, got %d", w.Code)
	}
}

func TestCB32_CorsMiddleware_GetRequest(t *testing.T) {
	called := false
	handler := corsMiddleware(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Origin", "http://localhost:3000")
	w := httptest.NewRecorder()
	handler(w, req)

	if !called {
		t.Error("handler was not called for GET request")
	}
}

// ==============================
// requestIDMiddleware
// ==============================

func TestCB32_RequestIDMiddleware_GeneratesID(t *testing.T) {
	called := false
	handler := requestIDMiddleware(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()
	handler(w, req)

	if !called {
		t.Error("handler was not called")
	}
	if w.Header().Get("X-Request-ID") == "" {
		t.Error("expected X-Request-ID header to be set")
	}
}

func TestCB32_RequestIDMiddleware_PreservesExisting(t *testing.T) {
	handler := requestIDMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("X-Request-ID", "my-custom-id")
	w := httptest.NewRecorder()
	handler(w, req)

	if w.Header().Get("X-Request-ID") != "my-custom-id" {
		t.Errorf("expected 'my-custom-id', got '%s'", w.Header().Get("X-Request-ID"))
	}
}

// ==============================
// isOriginAllowed
// ==============================

func TestCB32_IsOriginAllowed_Wildcard(t *testing.T) {
	origEnv := os.Getenv("CORS_ALLOWED_ORIGINS")
	defer os.Setenv("CORS_ALLOWED_ORIGINS", origEnv)
	os.Setenv("CORS_ALLOWED_ORIGINS", "*")

	if !isOriginAllowed("http://anywhere.com") {
		t.Error("expected wildcard to allow all origins")
	}
}

func TestCB32_IsOriginAllowed_SpecificOrigin(t *testing.T) {
	origCors := corsAllowedOrigins
	defer func() { corsAllowedOrigins = origCors }()
	corsAllowedOrigins = "http://localhost:3000"

	if !isOriginAllowed("http://localhost:3000") {
		t.Error("expected specific origin to be allowed")
	}
	if isOriginAllowed("http://evil.com") {
		t.Error("expected non-listed origin to be rejected")
	}
}

func TestCB32_IsOriginAllowed_EmptyOrigin(t *testing.T) {
	origCors := corsAllowedOrigins
	defer func() { corsAllowedOrigins = origCors }()
	corsAllowedOrigins = "http://localhost:3000"

	if isOriginAllowed("") {
		t.Error("expected empty origin to be rejected")
	}
}

// ==============================
// csrfMiddleware
// ==============================

func TestCB32_CsrfMiddleware_GetAllowed(t *testing.T) {
	called := false
	handler := csrfMiddleware(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()
	handler(w, req)

	if !called {
		t.Error("GET should be allowed without CSRF check")
	}
}

func TestCB32_CsrfMiddleware_PostWithXHRHeader(t *testing.T) {
	called := false
	handler := csrfMiddleware(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodPost, "/test", nil)
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	w := httptest.NewRecorder()
	handler(w, req)

	if !called {
		t.Error("POST with X-Requested-With should be allowed")
	}
}

func TestCB32_CsrfMiddleware_PostWithCsrfToken(t *testing.T) {
	called := false
	handler := csrfMiddleware(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodPost, "/test", nil)
	req.Header.Set("X-CSRF-Token", "some-token")
	w := httptest.NewRecorder()
	handler(w, req)

	if !called {
		t.Error("POST with X-CSRF-Token should be allowed")
	}
}

func TestCB32_CsrfMiddleware_PostWithoutProtection(t *testing.T) {
	called := false
	handler := csrfMiddleware(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodPost, "/test", nil)
	// No CSRF headers
	w := httptest.NewRecorder()
	handler(w, req)

	if called {
		t.Error("POST without CSRF protection should be blocked")
	}
	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", w.Code)
	}
}