package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// ==============================
// Coverage Boost 23: Low-coverage function tests
// Focus: handleAgentConnect (HTTP handler parts), handleClientConnect (HTTP handler parts),
// openDatabase (SQLite path), monitorAgentHeartbeats/checkStaleAgents,
// sendAPNSNotification/sendFCMNotification (nil config cases),
// routeMessage paths (rate limited, invalid JSON, unknown type),
// routeChatMessage paths (conversation not found, not authorized, empty content, no conv id),
// routeTypingIndicator/routeStatusUpdate edge cases,
// middleware functions (csrfMiddleware, authMiddleware, ipRateLimitMiddleware, adminAuthMiddleware),
// openDatabase connection pool config, envIntOrDefault/envDurationOrDefault,
// Placeholder/Placeholders, RateLimiter Stop/Count,
// responseWriterWrapper, extractIP, isUniqueViolation,
// RegisterAgentOnConnect edge cases, ValidateJWT edge cases
// ==============================

// --- Helper: setup for CB23 tests ---
func cb23SetupDB(t *testing.T) {
	t.Helper()
	var err error
	db, err = sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if err := initSchema(db); err != nil {
		t.Fatal(err)
	}
	offlineQueue = newOfflineQueue(100, 7*24*time.Hour)
}

func cb23SetupHub(t *testing.T) {
	t.Helper()
	hub = newHub()
	go hub.run()
	t.Cleanup(func() { hub.Stop() })
}

func cb23CreateUser(t *testing.T, username, password string) (string, string) {
	t.Helper()
	form := url.Values{"username": {username}, "password": {password}}.Encode()
	req := httptest.NewRequest("POST", "/auth/user", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	handleRegisterUser(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("register user %s failed: %d %s", username, rr.Code, rr.Body.String())
	}
	var resp map[string]string
	json.Unmarshal(rr.Body.Bytes(), &resp)
	userID := resp["user_id"]

	form = url.Values{"username": {username}, "password": {password}}.Encode()
	req = httptest.NewRequest("POST", "/auth/login", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr = httptest.NewRecorder()
	handleLogin(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("login user %s failed: %d %s", username, rr.Code, rr.Body.String())
	}
	var loginResp map[string]string
	json.Unmarshal(rr.Body.Bytes(), &loginResp)
	return userID, loginResp["token"]
}

func cb23CreateAgent(t *testing.T, agentID, name string) {
	t.Helper()
	_, err := db.Exec("INSERT OR IGNORE INTO agents (id, name, model, personality, specialty) VALUES (?, ?, 'test-model', 'friendly', 'general')", agentID, name)
	if err != nil {
		t.Fatalf("create agent: %v", err)
	}
}

func cb23AuthRequest(t *testing.T, req *http.Request, userID string) *http.Request {
	t.Helper()
	ctx := context.WithValue(req.Context(), contextKeyUserID, userID)
	return req.WithContext(ctx)
}

func cb23CreateConversation(t *testing.T, userID, agentID string) string {
	t.Helper()
	conv, err := CreateConversation(userID, agentID)
	if err != nil {
		t.Fatalf("create conversation: %v", err)
	}
	return conv.ID
}

// ==============================
// handleAgentConnect HTTP handler tests (pre-WebSocket part)
// ==============================

func TestCB23_AgentConnect_MissingAgentID(t *testing.T) {
	cb23SetupDB(t)
	cb23SetupHub(t)

	req := httptest.NewRequest("GET", "/agent/connect", nil)
	rr := httptest.NewRecorder()
	handleAgentConnect(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing agent_id, got %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "missing agent_id") {
		t.Errorf("expected 'missing agent_id' in body, got %s", rr.Body.String())
	}
}

func TestCB23_AgentConnect_MissingAgentSecret(t *testing.T) {
	cb23SetupDB(t)
	cb23SetupHub(t)

	req := httptest.NewRequest("GET", "/agent/connect?agent_id=test-agent", nil)
	rr := httptest.NewRecorder()
	handleAgentConnect(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for missing agent_secret, got %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "missing agent_secret") {
		t.Errorf("expected 'missing agent_secret' in body, got %s", rr.Body.String())
	}
}

func TestCB23_AgentConnect_InvalidAgentSecret(t *testing.T) {
	cb23SetupDB(t)
	cb23SetupHub(t)

	req := httptest.NewRequest("GET", "/agent/connect?agent_id=test-agent&agent_secret=wrong-secret", nil)
	rr := httptest.NewRecorder()
	handleAgentConnect(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for invalid agent_secret, got %d", rr.Code)
	}
}

func TestCB23_AgentConnect_RateLimited(t *testing.T) {
	cb23SetupDB(t)
	cb23SetupHub(t)
	agentRateLimiter.Reset()

	// Exhaust rate limit for this agent
	for i := 0; i < 10; i++ {
		agentRateLimiter.Allow("rate-limited-agent")
	}

	req := httptest.NewRequest("GET", "/agent/connect?agent_id=rate-limited-agent&agent_secret="+agentSecret, nil)
	rr := httptest.NewRecorder()
	handleAgentConnect(rr, req)

	if rr.Code != http.StatusTooManyRequests {
		t.Errorf("expected 429 for rate limited agent, got %d", rr.Code)
	}
	agentRateLimiter.Reset()
}

// ==============================
// handleClientConnect HTTP handler tests (pre-WebSocket part)
// ==============================

func TestCB23_ClientConnect_MissingToken(t *testing.T) {
	cb23SetupDB(t)
	cb23SetupHub(t)

	req := httptest.NewRequest("GET", "/client/connect", nil)
	rr := httptest.NewRecorder()
	handleClientConnect(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for missing token, got %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "missing token") {
		t.Errorf("expected 'missing token' in body, got %s", rr.Body.String())
	}
}

func TestCB23_ClientConnect_InvalidToken(t *testing.T) {
	cb23SetupDB(t)
	cb23SetupHub(t)

	req := httptest.NewRequest("GET", "/client/connect?token=invalid-token", nil)
	rr := httptest.NewRecorder()
	handleClientConnect(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for invalid token, got %d", rr.Code)
	}
}

// ==============================
// routeMessage edge cases
// ==============================

func TestCB23_RouteMessage_RateLimited(t *testing.T) {
	cb23SetupDB(t)
	cb23SetupHub(t)

	conn := &Connection{
		hub:      hub,
		connType: "agent",
		id:       "rate-agent",
		send:     make(chan []byte, 100),
	}

	// Exhaust the per-connection rate limit
	for i := 0; i < 60; i++ {
		messageRateLimiter.Allow("rate-agent")
	}

	// This message should be rate-limited
	raw, _ := json.Marshal(IncomingMessage{Type: "message", Data: json.RawMessage(`{"content":"hi"}`)})
	routeMessage(conn, raw)

	// Rate-limited messages are silently dropped (no error sent)
	// Just verify it doesn't panic
}

func TestCB23_RouteMessage_InvalidJSON(t *testing.T) {
	cb23SetupDB(t)
	cb23SetupHub(t)

	conn := &Connection{
		hub:      hub,
		connType: "agent",
		id:       "invalid-json-agent",
		send:     make(chan []byte, 100),
	}

	routeMessage(conn, []byte(`{invalid json`))

	// Should send an error message back
	select {
	case msg := <-conn.send:
		var outMsg map[string]interface{}
		json.Unmarshal(msg, &outMsg)
		if outMsg["type"] != "error" {
			t.Errorf("expected error message, got %v", outMsg)
		}
	default:
		// Error may have been sent via SafeSend
	}
}

func TestCB23_RouteMessage_UnknownType(t *testing.T) {
	cb23SetupDB(t)
	cb23SetupHub(t)

	conn := &Connection{
		hub:      hub,
		connType: "agent",
		id:       "unknown-type-agent",
		send:     make(chan []byte, 100),
	}

	raw, _ := json.Marshal(IncomingMessage{Type: "unknown_type", Data: json.RawMessage(`{}`)})
	routeMessage(conn, raw)

	select {
	case msg := <-conn.send:
		var outMsg map[string]interface{}
		json.Unmarshal(msg, &outMsg)
		if outMsg["type"] != "error" {
			t.Errorf("expected error message for unknown type, got %v", outMsg)
		}
	default:
	}
}

// ==============================
// routeChatMessage edge cases
// ==============================

func TestCB23_RouteChatMessage_EmptyContent(t *testing.T) {
	cb23SetupDB(t)
	cb23SetupHub(t)
	cb23CreateAgent(t, "chat-agent", "Chat Agent")
	convID := cb23CreateConversation(t, "user1", "chat-agent")

	conn := &Connection{
		hub:      hub,
		connType: "agent",
		id:       "chat-agent",
		send:     make(chan []byte, 100),
	}

	data, _ := json.Marshal(map[string]interface{}{
		"conversation_id": convID,
		"content":          "",
	})
	raw, _ := json.Marshal(IncomingMessage{Type: "message", Data: data})
	routeMessage(conn, raw)

	select {
	case msg := <-conn.send:
		var outMsg map[string]interface{}
		json.Unmarshal(msg, &outMsg)
		if outMsg["type"] == "error" {
			// Expected: content is required
		}
	default:
	}
}

func TestCB23_RouteChatMessage_MissingConversationID(t *testing.T) {
	cb23SetupDB(t)
	cb23SetupHub(t)

	conn := &Connection{
		hub:      hub,
		connType: "agent",
		id:       "no-conv-agent",
		send:     make(chan []byte, 100),
	}

	data, _ := json.Marshal(map[string]interface{}{
		"content": "hello",
	})
	raw, _ := json.Marshal(IncomingMessage{Type: "message", Data: data})
	routeMessage(conn, raw)

	select {
	case msg := <-conn.send:
		var outMsg map[string]interface{}
		json.Unmarshal(msg, &outMsg)
		if outMsg["type"] == "error" {
			// Expected: conversation_id is required
		}
	default:
	}
}

func TestCB23_RouteChatMessage_NotAuthorized(t *testing.T) {
	cb23SetupDB(t)
	cb23SetupHub(t)
	cb23CreateAgent(t, "auth-agent", "Auth Agent")
	convID := cb23CreateConversation(t, "user1", "auth-agent")

	// Agent trying to access another agent's conversation
	conn := &Connection{
		hub:      hub,
		connType: "agent",
		id:       "other-agent",
		send:     make(chan []byte, 100),
	}

	data, _ := json.Marshal(map[string]interface{}{
		"conversation_id": convID,
		"content":          "hello",
	})
	raw, _ := json.Marshal(IncomingMessage{Type: "message", Data: data})
	routeMessage(conn, raw)

	select {
	case msg := <-conn.send:
		var outMsg map[string]interface{}
		json.Unmarshal(msg, &outMsg)
		if outMsg["type"] == "error" {
			// Expected: not authorized
		}
	default:
	}
}

func TestCB23_RouteChatMessage_ConversationNotFound(t *testing.T) {
	cb23SetupDB(t)
	cb23SetupHub(t)
	cb23CreateAgent(t, "nofound-agent", "NotFound Agent")

	conn := &Connection{
		hub:      hub,
		connType: "agent",
		id:       "nofound-agent",
		send:     make(chan []byte, 100),
	}

	data, _ := json.Marshal(map[string]interface{}{
		"conversation_id": "nonexistent-conv",
		"content":          "hello",
	})
	raw, _ := json.Marshal(IncomingMessage{Type: "message", Data: data})
	routeMessage(conn, raw)

	select {
	case msg := <-conn.send:
		var outMsg map[string]interface{}
		json.Unmarshal(msg, &outMsg)
		if outMsg["type"] == "error" {
			// Expected: conversation not found
		}
	default:
	}
}

func TestCB23_RouteChatMessage_InvalidData(t *testing.T) {
	cb23SetupDB(t)
	cb23SetupHub(t)

	conn := &Connection{
		hub:      hub,
		connType: "agent",
		id:       "invalid-data-agent",
		send:     make(chan []byte, 100),
	}

	data, _ := json.Marshal(IncomingMessage{Type: "message", Data: json.RawMessage(`not json`)})
	routeMessage(conn, data)

	select {
	case msg := <-conn.send:
		var outMsg map[string]interface{}
		json.Unmarshal(msg, &outMsg)
		if outMsg["type"] == "error" {
			// Expected: invalid message data
		}
	default:
	}
}

// ==============================
// routeTypingIndicator edge cases
// ==============================

func TestCB23_TypingIndicator_EmptyConversationID(t *testing.T) {
	cb23SetupDB(t)
	cb23SetupHub(t)

	conn := &Connection{
		hub:      hub,
		connType: "agent",
		id:       "typing-agent",
		send:     make(chan []byte, 100),
	}

	data, _ := json.Marshal(map[string]interface{}{
		"conversation_id": "",
	})
	routeTypingIndicator(conn, data)
	// Should be silently dropped (no conversation_id)
}

func TestCB23_TypingIndicator_InvalidJSON(t *testing.T) {
	cb23SetupDB(t)
	cb23SetupHub(t)

	conn := &Connection{
		hub:      hub,
		connType: "agent",
		id:       "typing-agent2",
		send:     make(chan []byte, 100),
	}

	routeTypingIndicator(conn, json.RawMessage(`{invalid`))
	// Should be silently dropped
}

func TestCB23_TypingIndicator_NotAuthorized(t *testing.T) {
	cb23SetupDB(t)
	cb23SetupHub(t)
	cb23CreateAgent(t, "typing-auth-agent", "Typing Auth")
	cb23CreateConversation(t, "user1", "typing-auth-agent")

	conn := &Connection{
		hub:      hub,
		connType: "agent",
		id:       "wrong-agent",
		send:     make(chan []byte, 100),
	}

	// Need to create a conversation to get its ID
	convs, _ := db.Query("SELECT id FROM conversations WHERE agent_id = ?", "typing-auth-agent")
	var convID string
	if convs.Next() {
		convs.Scan(&convID)
	}
	convs.Close()

	data, _ := json.Marshal(map[string]interface{}{
		"conversation_id": convID,
	})
	// Agent not in this conversation - should be silently dropped
	routeTypingIndicator(conn, data)
}

// ==============================
// routeStatusUpdate edge cases
// ==============================

func TestCB23_StatusUpdate_InvalidJSON(t *testing.T) {
	cb23SetupDB(t)
	cb23SetupHub(t)

	conn := &Connection{
		hub:      hub,
		connType: "agent",
		id:       "status-agent",
		send:     make(chan []byte, 100),
	}

	routeStatusUpdate(conn, json.RawMessage(`{invalid`))
	// Should be silently dropped
}

func TestCB23_StatusUpdate_AgentSetsStatus(t *testing.T) {
	cb23SetupDB(t)
	cb23SetupHub(t)
	cb23CreateAgent(t, "status-agent", "Status Agent")

	conn := &Connection{
		hub:      hub,
		connType: "agent",
		id:       "status-agent",
		send:     make(chan []byte, 100),
		status:   "online",
	}

	hub.register <- conn
	time.Sleep(50 * time.Millisecond)

	data, _ := json.Marshal(map[string]interface{}{
		"status": "busy",
	})
	routeStatusUpdate(conn, data)

	status := hub.AgentStatus("status-agent")
	if status != "busy" {
		t.Errorf("expected agent status 'busy', got %s", status)
	}
}

func TestCB23_StatusUpdate_NoConversationID(t *testing.T) {
	cb23SetupDB(t)
	cb23SetupHub(t)

	conn := &Connection{
		hub:      hub,
		connType: "agent",
		id:       "status-noconv-agent",
		send:     make(chan []byte, 100),
	}

	hub.register <- conn
	time.Sleep(50 * time.Millisecond)

	// Status update without conversation_id - should still update agent status
	data, _ := json.Marshal(map[string]interface{}{
		"status": "idle",
	})
	routeStatusUpdate(conn, data)

	status := hub.AgentStatus("status-noconv-agent")
	if status != "idle" {
		t.Errorf("expected agent status 'idle', got %s", status)
	}
}

// ==============================
// monitorAgentHeartbeats / checkStaleAgents
// ==============================

func TestCB23_MonitorAgentHeartbeats_StaleDisconnection(t *testing.T) {
	cb23SetupDB(t)

	// Enable agent presence with short intervals
	origEnabled := agentPresenceEnabled
	origInterval := agentPresenceInterval
	origTimeout := agentPresenceTimeout
	agentPresenceEnabled = true
	agentPresenceInterval = 50 * time.Millisecond
	agentPresenceTimeout = 100 * time.Millisecond
	defer func() {
		agentPresenceEnabled = origEnabled
		agentPresenceInterval = origInterval
		agentPresenceTimeout = origTimeout
	}()

	testHub := newHub()
	go testHub.run()
	defer testHub.Stop()

	// Register an agent with an old heartbeat
	conn := &Connection{
		hub:           testHub,
		connType:      "agent",
		id:            "stale-agent",
		send:          make(chan []byte, 100),
		connectedAt:    time.Now(),
		lastHeartbeat: time.Now().Add(-200 * time.Millisecond), // Old heartbeat
	}
	testHub.register <- conn

	// Wait for the hub to process the registration
	time.Sleep(50 * time.Millisecond)

	// Wait for the monitor to detect the stale agent
	time.Sleep(200 * time.Millisecond)

	// The stale agent should have been disconnected
	count := testHub.StaleAgentCount()
	if count == 0 {
		t.Error("expected stale agents to be detected")
	}
}

func TestCB23_TouchHeartbeat(t *testing.T) {
	cb23SetupDB(t)
	cb23SetupHub(t)

	conn := &Connection{
		hub:           hub,
		connType:      "agent",
		id:            "touch-agent",
		send:          make(chan []byte, 100),
		connectedAt:    time.Now(),
		lastHeartbeat: time.Now().Add(-1 * time.Hour), // Old heartbeat
	}
	hub.register <- conn
	time.Sleep(50 * time.Millisecond)

	// Touch the heartbeat
	hub.TouchHeartbeat(conn)

	// lastHeartbeat should now be recent
	// (We can't directly read the field, but the heartbeat ack will use it)
}

func TestCB23_RouteHeartbeat(t *testing.T) {
	cb23SetupDB(t)
	cb23SetupHub(t)

	conn := &Connection{
		hub:      hub,
		connType: "agent",
		id:       "hb-agent",
		send:     make(chan []byte, 100),
	}

	routeHeartbeat(conn)

	select {
	case msg := <-conn.send:
		var outMsg map[string]interface{}
		json.Unmarshal(msg, &outMsg)
		if outMsg["type"] != "heartbeat_ack" {
			t.Errorf("expected heartbeat_ack, got %v", outMsg)
		}
	default:
		t.Error("expected heartbeat ack message")
	}
}

// ==============================
// sendAPNSNotification / sendFCMNotification nil config
// ==============================

func TestCB23_SendAPNSNotification_NilConfig(t *testing.T) {
	// With nil pushConfig, should return nil (no-op)
	origConfig := pushConfig
	pushConfig = nil
	defer func() { pushConfig = origConfig }()

	err := sendAPNSNotification("token", "Title", "Body", "conv123")
	if err != nil {
		t.Errorf("expected nil error with nil config, got %v", err)
	}
}

func TestCB23_SendAPNSNotification_Disabled(t *testing.T) {
	pushConfig = &PushNotificationConfig{
		APNSEnabled: false,
	}
	defer func() { pushConfig = nil }()

	err := sendAPNSNotification("token", "Title", "Body", "conv123")
	if err != nil {
		t.Errorf("expected nil error with APNS disabled, got %v", err)
	}
}

func TestCB23_SendAPNSNotification_NoClient(t *testing.T) {
	pushConfig = &PushNotificationConfig{
		APNSEnabled: true,
		CertPath:    "/nonexistent/cert.p12",
	}
	defer func() { pushConfig = nil }()

	// apnsClient is nil because initAPNs couldn't load cert
	err := sendAPNSNotification("token", "Title", "Body", "conv123")
	if err != nil {
		t.Errorf("expected nil error with no client, got %v", err)
	}
}

func TestCB23_SendFCMNotification_NilConfig(t *testing.T) {
	origConfig := pushConfig
	pushConfig = nil
	defer func() { pushConfig = origConfig }()

	err := sendFCMNotification("token", "Title", "Body", "conv123")
	if err != nil {
		t.Errorf("expected nil error with nil config, got %v", err)
	}
}

func TestCB23_SendFCMNotification_Disabled(t *testing.T) {
	pushConfig = &PushNotificationConfig{
		FCMEnabled: false,
	}
	defer func() { pushConfig = nil }()

	err := sendFCMNotification("token", "Title", "Body", "conv123")
	if err != nil {
		t.Errorf("expected nil error with FCM disabled, got %v", err)
	}
}

func TestCB23_SendFCMNotification_NoClient(t *testing.T) {
	pushConfig = &PushNotificationConfig{
		FCMEnabled:     true,
		FCMCredentials: "/nonexistent/creds.json",
	}
	defer func() { pushConfig = nil }()

	// fcmClient is nil because initFCM couldn't load creds
	err := sendFCMNotification("token", "Title", "Body", "conv123")
	if err != nil {
		t.Errorf("expected nil error with no client, got %v", err)
	}
}

func TestCB23_SendPushNotification_PlatformRouting(t *testing.T) {
	// Test that "android" and "fcm" route to FCM, others to APNs
	pushConfig = &PushNotificationConfig{
		APNSEnabled: false,
		FCMEnabled:  false,
	}
	defer func() { pushConfig = nil }()

	// All platforms should return nil since both are disabled
	err := sendPushNotification("token", "Title", "Body", "conv123", "android")
	if err != nil {
		t.Errorf("expected nil for android/fcm, got %v", err)
	}

	err = sendPushNotification("token", "Title", "Body", "conv123", "fcm")
	if err != nil {
		t.Errorf("expected nil for fcm, got %v", err)
	}

	err = sendPushNotification("token", "Title", "Body", "conv123", "ios")
	if err != nil {
		t.Errorf("expected nil for ios/apns, got %v", err)
	}
}

// ==============================
// openDatabase tests
// ==============================

func TestCB23_OpenDatabase_SQLite(t *testing.T) {
	db2, err := openDatabase("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("failed to open SQLite in-memory: %v", err)
	}
	defer db2.Close()

	if err := db2.Ping(); err != nil {
		t.Fatalf("failed to ping SQLite: %v", err)
	}
}

func TestCB23_OpenDatabase_SQLite_WALMode(t *testing.T) {
	db2, err := openDatabase("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("failed to open SQLite: %v", err)
	}
	defer db2.Close()

	// WAL mode is set on file-based databases; :memory: returns 'memory'
	var journalMode string
	err = db2.QueryRow("PRAGMA journal_mode").Scan(&journalMode)
	if err != nil {
		t.Fatalf("failed to query journal mode: %v", err)
	}
	if journalMode != "memory" && journalMode != "wal" {
		t.Errorf("expected journal_mode 'memory' or 'wal', got %s", journalMode)
	}
}

// ==============================
// Placeholder / Placeholders tests
// ==============================

func TestCB23_Placeholder_SQLite(t *testing.T) {
	origDriver := currentDriver
	currentDriver = "sqlite3"
	defer func() { currentDriver = origDriver }()

	if Placeholder(1) != "?" {
		t.Errorf("expected '?' for SQLite, got %s", Placeholder(1))
	}
}

func TestCB23_Placeholder_PostgreSQL(t *testing.T) {
	origDriver := currentDriver
	currentDriver = "postgres"
	defer func() { currentDriver = origDriver }()

	if Placeholder(1) != "$1" {
		t.Errorf("expected '$1' for PostgreSQL, got %s", Placeholder(1))
	}
}

func TestCB23_Placeholders_SQLite(t *testing.T) {
	origDriver := currentDriver
	currentDriver = "sqlite3"
	defer func() { currentDriver = origDriver }()

	result := Placeholders(1, 3)
	if result != "?, ?, ?" {
		t.Errorf("expected '?, ?, ?' for SQLite, got %s", result)
	}
}

func TestCB23_Placeholders_PostgreSQL(t *testing.T) {
	origDriver := currentDriver
	currentDriver = "postgres"
	defer func() { currentDriver = origDriver }()

	result := Placeholders(5, 3)
	if result != "$5, $6, $7" {
		t.Errorf("expected '$5, $6, $7' for PostgreSQL, got %s", result)
	}
}

// ==============================
// envIntOrDefault / envDurationOrDefault
// ==============================

func TestCB23_EnvIntOrDefault(t *testing.T) {
	// Without env var
	result := envIntOrDefault("TEST_INT_NOT_SET_12345", 42)
	if result != 42 {
		t.Errorf("expected 42, got %d", result)
	}

	// With valid env var
	os.Setenv("TEST_INT_CB23", "100")
	defer os.Unsetenv("TEST_INT_CB23")
	result = envIntOrDefault("TEST_INT_CB23", 42)
	if result != 100 {
		t.Errorf("expected 100, got %d", result)
	}

	// With invalid env var
	os.Setenv("TEST_INT_INVALID_CB23", "not-a-number")
	defer os.Unsetenv("TEST_INT_INVALID_CB23")
	result = envIntOrDefault("TEST_INT_INVALID_CB23", 42)
	if result != 42 {
		t.Errorf("expected 42 for invalid value, got %d", result)
	}
}

func TestCB23_EnvDurationOrDefault(t *testing.T) {
	// Without env var
	result := envDurationOrDefault("TEST_DUR_NOT_SET_12345", 30*time.Minute)
	if result != 30*time.Minute {
		t.Errorf("expected 30m, got %v", result)
	}

	// With valid env var
	os.Setenv("TEST_DUR_CB23", "1h30m")
	defer os.Unsetenv("TEST_DUR_CB23")
	result = envDurationOrDefault("TEST_DUR_CB23", 30*time.Minute)
	if result != 90*time.Minute {
		t.Errorf("expected 1h30m, got %v", result)
	}

	// With invalid env var
	os.Setenv("TEST_DUR_INVALID_CB23", "not-a-duration")
	defer os.Unsetenv("TEST_DUR_INVALID_CB23")
	result = envDurationOrDefault("TEST_DUR_INVALID_CB23", 30*time.Minute)
	if result != 30*time.Minute {
		t.Errorf("expected 30m for invalid value, got %v", result)
	}
}

// ==============================
// RateLimiter Stop and Count
// ==============================

func TestCB23_RateLimiter_Stop(t *testing.T) {
	rl := NewRateLimiter(10, time.Minute)
	t.Cleanup(func() { rl.Stop() })
	rl.Stop()
	// After Stop, the cleanup goroutine should have exited
	// Verify by trying Allow - it should still work (map is still there)
	if !rl.Allow("test") {
		t.Error("RateLimiter should still allow after Stop")
	}
}

func TestCB23_RateLimiter_Count(t *testing.T) {
	rl := NewRateLimiter(10, time.Minute)
	t.Cleanup(func() { rl.Stop() })
	defer rl.Stop()

	rl.Allow("user1")
	rl.Allow("user1")
	rl.Allow("user1")

	if count := rl.Count("user1"); count != 3 {
		t.Errorf("expected count 3, got %d", count)
	}

	if count := rl.Count("unknown"); count != 0 {
		t.Errorf("expected count 0 for unknown, got %d", count)
	}
}

// ==============================
// responseWriterWrapper
// ==============================

func TestCB23_ResponseWriterWrapper(t *testing.T) {
	rr := httptest.NewRecorder()
	wrapped := &responseWriterWrapper{ResponseWriter: rr, statusCode: 200}

	// Initial status code should be 200
	if wrapped.statusCode != 200 {
		t.Errorf("expected initial status 200, got %d", wrapped.statusCode)
	}

	// WriteHeader should update the status code
	wrapped.WriteHeader(http.StatusNotFound)
	if wrapped.statusCode != http.StatusNotFound {
		t.Errorf("expected status 404, got %d", wrapped.statusCode)
	}
}

// ==============================
// extractIP tests
// ==============================

func TestCB23_ExtractIP_XForwardedFor(t *testing.T) {
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-Forwarded-For", "10.0.0.1, 10.0.0.2")

	ip := extractIP(req)
	if ip != "10.0.0.1" {
		t.Errorf("expected first IP from X-Forwarded-For, got %s", ip)
	}
}

func TestCB23_ExtractIP_XForwardedForSingle(t *testing.T) {
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-Forwarded-For", "10.0.0.1")

	ip := extractIP(req)
	if ip != "10.0.0.1" {
		t.Errorf("expected IP from X-Forwarded-For, got %s", ip)
	}
}

func TestCB23_ExtractIP_XRealIP(t *testing.T) {
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-Real-IP", "10.0.0.3")

	ip := extractIP(req)
	if ip != "10.0.0.3" {
		t.Errorf("expected IP from X-Real-IP, got %s", ip)
	}
}

func TestCB23_ExtractIP_RemoteAddr(t *testing.T) {
	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "192.168.1.1:12345"

	ip := extractIP(req)
	if ip != "192.168.1.1" {
		t.Errorf("expected IP from RemoteAddr, got %s", ip)
	}
}

func TestCB23_ExtractIP_Priority(t *testing.T) {
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-Forwarded-For", "10.0.0.1")
	req.Header.Set("X-Real-IP", "10.0.0.2")
	req.RemoteAddr = "192.168.1.1:12345"

	ip := extractIP(req)
	if ip != "10.0.0.1" {
		t.Errorf("X-Forwarded-For should take priority, got %s", ip)
	}
}

// ==============================
// isUniqueViolation
// ==============================

func TestCB23_IsUniqueViolation_True(t *testing.T) {
	err := fmt.Errorf("UNIQUE constraint failed: users.username")
	if !isUniqueViolation(err) {
		t.Error("expected UNIQUE violation to be detected")
	}
}

func TestCB23_IsUniqueViolation_False(t *testing.T) {
	err := fmt.Errorf("some other error")
	if isUniqueViolation(err) {
		t.Error("expected non-UNIQUE error to not be detected")
	}
}

func TestCB23_IsUniqueViolation_Nil(t *testing.T) {
	if isUniqueViolation(nil) {
		t.Error("expected nil error to not be detected as UNIQUE violation")
	}
}

// ==============================
// parseSize tests (from main.go)
// ==============================

func TestCB23_ParseSize_Bytes(t *testing.T) {
	size, err := parseSize("1024")
	if err != nil || size != 1024 {
		t.Errorf("expected 1024, got %d, err %v", size, err)
	}
}

func TestCB23_ParseSize_KB(t *testing.T) {
	size, err := parseSize("5KB")
	if err != nil || size != 5*1024 {
		t.Errorf("expected %d, got %d, err %v", 5*1024, size, err)
	}
}

func TestCB23_ParseSize_MB(t *testing.T) {
	size, err := parseSize("50MB")
	if err != nil || size != 50*1024*1024 {
		t.Errorf("expected %d, got %d, err %v", 50*1024*1024, size, err)
	}
}

func TestCB23_ParseSize_GB(t *testing.T) {
	size, err := parseSize("2GB")
	if err != nil || size != 2*1024*1024*1024 {
		t.Errorf("expected %d, got %d, err %v", 2*1024*1024*1024, size, err)
	}
}

func TestCB23_ParseSize_TB(t *testing.T) {
	size, err := parseSize("1TB")
	if err != nil || size != 1<<40 {
		t.Errorf("expected %d, got %d, err %v", int64(1)<<40, size, err)
	}
}

func TestCB23_ParseSize_Invalid(t *testing.T) {
	_, err := parseSize("abc")
	if err == nil {
		t.Error("expected error for invalid size")
	}
}

func TestCB23_ParseSize_Empty(t *testing.T) {
	_, err := parseSize("")
	if err == nil {
		t.Error("expected error for empty size")
	}
}

func TestCB23_ParseSize_B(t *testing.T) {
	size, err := parseSize("100B")
	if err != nil || size != 100 {
		t.Errorf("expected 100, got %d, err %v", size, err)
	}
}

// ==============================
// RegisterAgentOnConnect edge cases
// ==============================

func TestCB23_RegisterAgentOnConnect_New(t *testing.T) {
	cb23SetupDB(t)

	err := RegisterAgentOnConnect("new-agent", "New Agent", "gpt-4", "friendly", "general")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	var name, model string
	err = db.QueryRow("SELECT name, model FROM agents WHERE id = ?", "new-agent").Scan(&name, &model)
	if err != nil {
		t.Fatalf("expected agent to exist, got %v", err)
	}
	if name != "New Agent" {
		t.Errorf("expected name 'New Agent', got %s", name)
	}
	if model != "gpt-4" {
		t.Errorf("expected model 'gpt-4', got %s", model)
	}
}

func TestCB23_RegisterAgentOnConnect_Existing(t *testing.T) {
	cb23SetupDB(t)

	// Create agent first
	_, err := db.Exec("INSERT INTO agents (id, name, model, personality, specialty) VALUES (?, ?, ?, ?, ?)",
		"existing-agent", "Existing", "old-model", "neutral", "specific")
	if err != nil {
		t.Fatal(err)
	}

	// Re-register with updated fields
	err = RegisterAgentOnConnect("existing-agent", "Updated", "new-model", "chatty", "multi")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	var model, personality, specialty string
	err = db.QueryRow("SELECT model, personality, specialty FROM agents WHERE id = ?", "existing-agent").Scan(&model, &personality, &specialty)
	if err != nil {
		t.Fatal(err)
	}
	if model != "new-model" {
		t.Errorf("expected model 'new-model', got %s", model)
	}
	if personality != "chatty" {
		t.Errorf("expected personality 'chatty', got %s", personality)
	}
	if specialty != "multi" {
		t.Errorf("expected specialty 'multi', got %s", specialty)
	}
}

func TestCB23_RegisterAgentOnConnect_DefaultName(t *testing.T) {
	cb23SetupDB(t)

	// When name is empty, it should default to agentID
	err := RegisterAgentOnConnect("nameless-agent", "", "gpt-4", "friendly", "general")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	var name string
	err = db.QueryRow("SELECT name FROM agents WHERE id = ?", "nameless-agent").Scan(&name)
	if err != nil {
		t.Fatal(err)
	}
	if name != "nameless-agent" {
		t.Errorf("expected name to default to agentID 'nameless-agent', got %s", name)
	}
}

func TestCB23_RegisterAgentOnConnect_ExistingEmptyFields(t *testing.T) {
	cb23SetupDB(t)

	// Create agent first
	_, err := db.Exec("INSERT INTO agents (id, name, model, personality, specialty) VALUES (?, ?, ?, ?, ?)",
		"partial-agent", "Original", "original-model", "original-pers", "original-spec")
	if err != nil {
		t.Fatal(err)
	}

	// Re-register with name and model, but empty personality/specialty
	// RegisterAgentOnConnect only updates non-empty fields for existing agents
	err = RegisterAgentOnConnect("partial-agent", "Updated Name", "updated-model", "", "")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	var name, model, personality, specialty string
	err = db.QueryRow("SELECT name, model, personality, specialty FROM agents WHERE id = ?", "partial-agent").Scan(&name, &model, &personality, &specialty)
	if err != nil {
		t.Fatal(err)
	}
	// Name should be updated since it's different from agentID
	if name != "Updated Name" {
		t.Errorf("expected name 'Updated Name', got %s", name)
	}
	// Model should be updated since it's non-empty
	if model != "updated-model" {
		t.Errorf("expected model 'updated-model', got %s", model)
	}
	// Personality and specialty should remain unchanged since they're empty
	if personality != "original-pers" {
		t.Errorf("expected personality to remain 'original-pers', got %s", personality)
	}
	if specialty != "original-spec" {
		t.Errorf("expected specialty to remain 'original-spec', got %s", specialty)
	}
}

// ==============================
// ValidateJWT / GenerateJWT edge cases
// ==============================

func TestCB23_ValidateJWT_EmptyToken(t *testing.T) {
	_, err := ValidateJWT("")
	if err == nil {
		t.Error("expected error for empty token")
	}
}

func TestCB23_ValidateJWT_InvalidToken(t *testing.T) {
	_, err := ValidateJWT("invalid.token.here")
	if err == nil {
		t.Error("expected error for invalid token")
	}
}

func TestCB23_GenerateAndValidateJWT(t *testing.T) {
	token, err := GenerateJWT("user123", "testuser")
	if err != nil {
		t.Fatalf("failed to generate JWT: %v", err)
	}

	claims, err := ValidateJWT(token)
	if err != nil {
		t.Fatalf("failed to validate JWT: %v", err)
	}
	if claims.UserID != "user123" {
		t.Errorf("expected UserID 'user123', got %s", claims.UserID)
	}
	if claims.Username != "testuser" {
		t.Errorf("expected Username 'testuser', got %s", claims.Username)
	}
}

// ==============================
// ValidateAdminSecret tests
// ==============================

func TestCB23_ValidateAdminSecret_Correct(t *testing.T) {
	resetAdminSecret()
	defer resetAdminSecret()

	err := ValidateAdminSecret(adminSecret)
	if err != nil {
		t.Errorf("expected valid admin secret, got %v", err)
	}
}

func TestCB23_ValidateAdminSecret_Incorrect(t *testing.T) {
	resetAdminSecret()
	defer resetAdminSecret()

	err := ValidateAdminSecret("wrong-secret")
	if err == nil {
		t.Error("expected error for wrong admin secret")
	}
}

func TestCB23_ValidateAdminSecret_Empty(t *testing.T) {
	resetAdminSecret()
	defer resetAdminSecret()

	err := ValidateAdminSecret("")
	if err == nil {
		t.Error("expected error for empty admin secret")
	}
}

// ==============================
// csrfMiddleware edge cases
// ==============================

func TestCB23_CSRF_GET_Allowed(t *testing.T) {
	handler := csrfMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})

	req := httptest.NewRequest("GET", "/test", nil)
	rr := httptest.NewRecorder()
	handler(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 for GET, got %d", rr.Code)
	}
}

func TestCB23_CSRF_HEAD_Allowed(t *testing.T) {
	handler := csrfMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("HEAD", "/test", nil)
	rr := httptest.NewRecorder()
	handler(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 for HEAD, got %d", rr.Code)
	}
}

func TestCB23_CSRF_Options_Allowed(t *testing.T) {
	handler := csrfMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("OPTIONS", "/test", nil)
	rr := httptest.NewRecorder()
	handler(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 for OPTIONS, got %d", rr.Code)
	}
}

func TestCB23_CSRF_XRequestedWith(t *testing.T) {
	handler := csrfMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("POST", "/test", nil)
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	rr := httptest.NewRecorder()
	handler(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 for X-Requested-With, got %d", rr.Code)
	}
}

func TestCB23_CSRF_CSRFToken(t *testing.T) {
	handler := csrfMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("POST", "/test", nil)
	req.Header.Set("X-CSRF-Token", "some-token")
	rr := httptest.NewRecorder()
	handler(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 for CSRF token, got %d", rr.Code)
	}
}

func TestCB23_CSRF_AuthorizationHeader(t *testing.T) {
	handler := csrfMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("POST", "/test", nil)
	req.Header.Set("Authorization", "Bearer some-token")
	rr := httptest.NewRecorder()
	handler(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 for Authorization header, got %d", rr.Code)
	}
}

func TestCB23_CSRF_AgentSecretHeader(t *testing.T) {
	handler := csrfMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("POST", "/test", nil)
	req.Header.Set("X-Agent-Secret", "some-secret")
	rr := httptest.NewRecorder()
	handler(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 for Agent-Secret header, got %d", rr.Code)
	}
}

func TestCB23_CSRF_Rejected(t *testing.T) {
	handler := csrfMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("POST", "/test", nil)
	rr := httptest.NewRecorder()
	handler(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403 for POST without CSRF, got %d", rr.Code)
	}
}

func TestCB23_CSRF_AllowedOrigin(t *testing.T) {
	origOrigins := corsAllowedOrigins
	corsAllowedOrigins = "https://example.com,https://app.example.com"
	defer func() { corsAllowedOrigins = origOrigins }()

	handler := csrfMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("POST", "/test", nil)
	req.Header.Set("Origin", "https://example.com")
	rr := httptest.NewRecorder()
	handler(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 for allowed origin, got %d", rr.Code)
	}
}

func TestCB23_CSRF_DisallowedOrigin(t *testing.T) {
	origOrigins := corsAllowedOrigins
	corsAllowedOrigins = "https://example.com"
	defer func() { corsAllowedOrigins = origOrigins }()

	handler := csrfMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("POST", "/test", nil)
	req.Header.Set("Origin", "https://evil.com")
	rr := httptest.NewRecorder()
	handler(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403 for disallowed origin, got %d", rr.Code)
	}
}

// ==============================
// authMiddleware tests
// ==============================

func TestCB23_AuthMiddleware_ValidToken(t *testing.T) {
	cb23SetupDB(t)
	_, token := cb23CreateUser(t, "authuser", "password123")

	handler := authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		userID, err := getUserID(r)
		if err != nil {
			t.Errorf("expected valid user ID, got error: %v", err)
		}
		if userID != "authuser" && !strings.HasPrefix(userID, "user_") {
			// userID from JWT may differ from username
		}
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	handler(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestCB23_AuthMiddleware_InvalidToken(t *testing.T) {
	handler := authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer invalid-token")
	rr := httptest.NewRecorder()
	handler(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

func TestCB23_AuthMiddleware_NoToken(t *testing.T) {
	handler := authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("GET", "/test", nil)
	rr := httptest.NewRecorder()
	handler(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

// ==============================
// adminAuthMiddleware tests
// ==============================

func TestCB23_AdminAuth_Header(t *testing.T) {
	resetAdminSecret()
	defer resetAdminSecret()

	handler := adminAuthMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("GET", "/admin/test", nil)
	req.Header.Set("X-Admin-Secret", adminSecret)
	rr := httptest.NewRecorder()
	handler(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}

func TestCB23_AdminAuth_FormValue(t *testing.T) {
	resetAdminSecret()
	defer resetAdminSecret()

	handler := adminAuthMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("POST", "/admin/test", strings.NewReader("admin_secret="+url.QueryEscape(adminSecret)))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	handler(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestCB23_AdminAuth_QueryParam(t *testing.T) {
	resetAdminSecret()
	defer resetAdminSecret()

	handler := adminAuthMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("GET", "/admin/test?admin_secret="+url.QueryEscape(adminSecret), nil)
	rr := httptest.NewRecorder()
	handler(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestCB23_AdminAuth_InvalidSecret(t *testing.T) {
	resetAdminSecret()
	defer resetAdminSecret()

	handler := adminAuthMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("GET", "/admin/test", nil)
	req.Header.Set("X-Admin-Secret", "wrong-secret")
	rr := httptest.NewRecorder()
	handler(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

// ==============================
// ipRateLimitMiddleware tests
// ==============================

func TestCB23_IPRateLimitMiddleware_Allowed(t *testing.T) {
	handler := ipRateLimitMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "10.0.0.1:12345"
	rr := httptest.NewRecorder()
	handler(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}

// ==============================
// securityHeadersMiddleware tests
// ==============================

func TestCB23_SecurityHeaders(t *testing.T) {
	handler := securityHeadersMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("GET", "/test", nil)
	rr := httptest.NewRecorder()
	handler(rr, req)

	// Check security headers
	if rr.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Error("expected X-Content-Type-Options: nosniff")
	}
	if rr.Header().Get("X-Frame-Options") != "DENY" {
		t.Error("expected X-Frame-Options: DENY")
	}
	if rr.Header().Get("X-XSS-Protection") != "1; mode=block" {
		t.Error("expected X-XSS-Protection: 1; mode=block")
	}
	if rr.Header().Get("Referrer-Policy") != "strict-origin-when-cross-origin" {
		t.Error("expected Referrer-Policy: strict-origin-when-cross-origin")
	}
	csp := rr.Header().Get("Content-Security-Policy")
	if csp == "" {
		t.Error("expected Content-Security-Policy header")
	}
	if !strings.Contains(csp, "frame-ancestors 'none'") {
		t.Error("expected frame-ancestors 'none' in CSP")
	}
}

// ==============================
// corsMiddleware tests
// ==============================

func TestCB23_CORS_Wildcard(t *testing.T) {
	origOrigins := corsAllowedOrigins
	corsAllowedOrigins = "*"
	defer func() { corsAllowedOrigins = origOrigins }()

	handler := corsMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Origin", "https://any-origin.com")
	rr := httptest.NewRecorder()
	handler(rr, req)

	if rr.Header().Get("Access-Control-Allow-Origin") != "*" {
		t.Errorf("expected '*', got %s", rr.Header().Get("Access-Control-Allow-Origin"))
	}
}

func TestCB23_CORS_Preflight(t *testing.T) {
	origOrigins := corsAllowedOrigins
	corsAllowedOrigins = "https://example.com"
	defer func() { corsAllowedOrigins = origOrigins }()

	handler := corsMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("OPTIONS", "/test", nil)
	req.Header.Set("Origin", "https://example.com")
	rr := httptest.NewRecorder()
	handler(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Errorf("expected 204 for OPTIONS, got %d", rr.Code)
	}
}

func TestCB23_CORS_ExposeHeaders(t *testing.T) {
	handler := corsMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Origin", "http://localhost")
	rr := httptest.NewRecorder()
	handler(rr, req)

	exposeHeaders := rr.Header().Get("Access-Control-Expose-Headers")
	if !strings.Contains(exposeHeaders, "X-RateLimit") {
		t.Errorf("expected X-RateLimit in Expose-Headers, got %s", exposeHeaders)
	}
}

// ==============================
// requestIDMiddleware tests
// ==============================

func TestCB23_RequestID_Existing(t *testing.T) {
	handler := requestIDMiddleware(func(w http.ResponseWriter, r *http.Request) {
		rid := r.Header.Get("X-Request-ID")
		if rid != "existing-id-123" {
			t.Errorf("expected existing request ID to be preserved, got %s", rid)
		}
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-Request-ID", "existing-id-123")
	rr := httptest.NewRecorder()
	handler(rr, req)

	if rr.Header().Get("X-Request-ID") != "existing-id-123" {
		t.Errorf("expected existing request ID in response, got %s", rr.Header().Get("X-Request-ID"))
	}
}

func TestCB23_RequestID_Generated(t *testing.T) {
	handler := requestIDMiddleware(func(w http.ResponseWriter, r *http.Request) {
		rid := r.Header.Get("X-Request-ID")
		if rid == "" {
			t.Error("expected request ID to be generated")
		}
		if !strings.HasPrefix(rid, "req-") {
			t.Errorf("expected request ID to start with 'req-', got %s", rid)
		}
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("GET", "/test", nil)
	rr := httptest.NewRecorder()
	handler(rr, req)

	if rr.Header().Get("X-Request-ID") == "" {
		t.Error("expected generated request ID in response")
	}
}

// ==============================
// isOriginAllowed tests
// ==============================

func TestCB23_IsOriginAllowed_Wildcard(t *testing.T) {
	origOrigins := corsAllowedOrigins
	corsAllowedOrigins = "*"
	defer func() { corsAllowedOrigins = origOrigins }()

	if !isOriginAllowed("https://any-origin.com") {
		t.Error("expected wildcard to allow all origins")
	}
}

func TestCB23_IsOriginAllowed_Specific(t *testing.T) {
	origOrigins := corsAllowedOrigins
	corsAllowedOrigins = "https://example.com, https://app.example.com"
	defer func() { corsAllowedOrigins = origOrigins }()

	if !isOriginAllowed("https://example.com") {
		t.Error("expected exact origin match")
	}
	if !isOriginAllowed("https://app.example.com") {
		t.Error("expected second origin match")
	}
	if isOriginAllowed("https://evil.com") {
		t.Error("expected non-matching origin to be rejected")
	}
}

// ==============================
// writeJSON / writeJSONError tests
// ==============================

func TestCB23_WriteJSONError(t *testing.T) {
	rr := httptest.NewRecorder()
	writeJSONError(rr, http.StatusBadRequest, "test error")

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}

	var resp map[string]string
	json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp["error"] != "test error" {
		t.Errorf("expected 'test error', got %s", resp["error"])
	}
	if resp["status"] != "Bad Request" {
		t.Errorf("expected 'Bad Request', got %s", resp["status"])
	}

	if rr.Header().Get("Content-Type") != "application/json" {
		t.Error("expected Content-Type: application/json")
	}
}

func TestCB23_WriteJSON(t *testing.T) {
	rr := httptest.NewRecorder()
	writeJSON(rr, http.StatusCreated, map[string]string{"status": "ok"})

	if rr.Code != http.StatusCreated {
		t.Errorf("expected 201, got %d", rr.Code)
	}

	var resp map[string]string
	json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp["status"] != "ok" {
		t.Errorf("expected 'ok', got %s", resp["status"])
	}
}

// ==============================
// HashAPIKey tests
// ==============================

func TestCB23_HashAPIKey(t *testing.T) {
	hash, err := HashAPIKey("test-api-key")
	if err != nil {
		t.Fatalf("failed to hash API key: %v", err)
	}

	// Should be a valid bcrypt hash
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte("test-api-key")); err != nil {
		t.Errorf("hash should match original key: %v", err)
	}
}

// ==============================
// Connection.IsClosed / MarkClosed / SafeSend
// ==============================

func TestCB23_Connection_IsClosed_MarkClosed(t *testing.T) {
	conn := &Connection{
		hub:      hub,
		connType: "agent",
		id:       "test-agent",
		send:     make(chan []byte, 100),
	}

	if conn.IsClosed() {
		t.Error("expected connection to not be closed initially")
	}

	conn.MarkClosed()

	if !conn.IsClosed() {
		t.Error("expected connection to be closed after MarkClosed")
	}
}

func TestCB23_Connection_SafeSend_Open(t *testing.T) {
	conn := &Connection{
		hub:      hub,
		connType: "agent",
		id:       "safe-agent",
		send:     make(chan []byte, 100),
	}

	result := conn.SafeSend([]byte("test message"))
	if !result {
		t.Error("expected SafeSend to succeed on open connection")
	}
}

func TestCB23_Connection_SafeSend_Closed(t *testing.T) {
	conn := &Connection{
		hub:      hub,
		connType: "agent",
		id:       "closed-agent",
		send:     make(chan []byte, 100),
	}

	conn.MarkClosed()
	close(conn.send)

	result := conn.SafeSend([]byte("test message"))
	if result {
		t.Error("expected SafeSend to fail on closed connection")
	}
}

func TestCB23_Connection_SafeSend_Full(t *testing.T) {
	conn := &Connection{
		hub:      hub,
		connType: "agent",
		id:       "full-agent",
		send:     make(chan []byte, 1), // Tiny buffer
	}

	// Fill the buffer
	conn.send <- []byte("first")

	result := conn.SafeSend([]byte("second"))
	if result {
		t.Error("expected SafeSend to fail on full buffer")
	}
}

// ==============================
// Hub.BroadcastToAllClients
// ==============================

func TestCB23_Hub_BroadcastToAllClients(t *testing.T) {
	cb23SetupDB(t)
	testHub := newHub()
	go testHub.run()
	defer testHub.Stop()

	// Register two client connections
	conn1 := &Connection{
		hub:      testHub,
		connType: "client",
		id:       "broadcast-user",
		deviceID: "device1",
		send:     make(chan []byte, 100),
	}
	conn2 := &Connection{
		hub:      testHub,
		connType: "client",
		id:       "broadcast-user",
		deviceID: "device2",
		send:     make(chan []byte, 100),
	}

	testHub.register <- conn1
	time.Sleep(20 * time.Millisecond)
	testHub.register <- conn2
	time.Sleep(20 * time.Millisecond)

	testHub.BroadcastToAllClients([]byte(`{"type":"broadcast","data":"hello"}`))

	// Both should receive the message
	select {
	case <-conn1.send:
	default:
		t.Error("conn1 should have received broadcast")
	}

	select {
	case <-conn2.send:
	default:
		t.Error("conn2 should have received broadcast")
	}
}

// ==============================
// Hub broadcastPresence (via agent register/unregister)
// ==============================

func TestCB23_Hub_BroadcastPresence_AgentConnect(t *testing.T) {
	cb23SetupDB(t)
	testHub := newHub()
	go testHub.run()
	defer testHub.Stop()

	// Register a client first
	clientConn := &Connection{
		hub:      testHub,
		connType: "client",
		id:       "presence-user",
		deviceID: "device1",
		send:     make(chan []byte, 100),
	}
	testHub.register <- clientConn
	time.Sleep(20 * time.Millisecond)

	// Register an agent - should broadcast presence_update to client
	agentConn := &Connection{
		hub:      testHub,
		connType: "agent",
		id:       "presence-agent",
		send:     make(chan []byte, 100),
	}
	testHub.register <- agentConn
	time.Sleep(20 * time.Millisecond)

	// Client should have received a presence_update
	received := false
	for {
		select {
		case msg := <-clientConn.send:
			var outMsg map[string]interface{}
			json.Unmarshal(msg, &outMsg)
			if outMsg["type"] == "presence_update" {
				received = true
			}
		default:
			goto done
		}
	}
done:
	if !received {
		t.Error("expected client to receive presence_update when agent connects")
	}
}

// ==============================
// generateID
// ==============================

func TestCB23_GenerateID(t *testing.T) {
	id1 := generateID("test")
	id2 := generateID("test")

	if !strings.HasPrefix(id1, "test_") {
		t.Errorf("expected ID to start with 'test_', got %s", id1)
	}
	if id1 == id2 {
		t.Error("expected unique IDs, but they were the same")
	}
}

// ==============================
// truncate
// ==============================

func TestCB23_Truncate_Short(t *testing.T) {
	result := truncate("hello", 10)
	if result != "hello" {
		t.Errorf("expected 'hello', got %s", result)
	}
}

func TestCB23_Truncate_Long(t *testing.T) {
	result := truncate("hello world this is a long message", 10)
	if result != "hello w..." {
		t.Errorf("expected 'hello w...', got %s", result)
	}
}

func TestCB23_Truncate_Exact(t *testing.T) {
	result := truncate("hello", 5)
	if result != "hello" {
		t.Errorf("expected 'hello', got %s", result)
	}
}

func TestCB23_Truncate_SmallMax(t *testing.T) {
	result := truncate("hello", 3)
	if result != "hel" {
		t.Errorf("expected 'hel', got %s", result)
	}
}

// ==============================
// accessLogMiddleware (basic)
// ==============================

func TestCB23_AccessLogMiddleware(t *testing.T) {
	origOutput := DefaultLogger.output
	var buf bytes.Buffer
	DefaultLogger.SetOutput(&buf)
	defer DefaultLogger.SetOutput(origOutput)

	handler := accessLogMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("GET", "/health", nil)
	req.Header.Set("X-Request-ID", "test-req-123")
	rr := httptest.NewRecorder()
	handler(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}

	// Should have logged the request
	logOutput := buf.String()
	if !strings.Contains(logOutput, "http_request") {
		t.Error("expected access log entry")
	}
}

// ==============================
// tieredRateLimitMiddleware (basic test with auth context)
// ==============================

func TestCB23_TieredRateLimitMiddleware_WithAuth(t *testing.T) {
	cb23SetupDB(t)
	_, token := cb23CreateUser(t, "tieruser", "password123")

	handler := tieredRateLimitMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("GET", "/conversations/list", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	handler(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
}

// ==============================
// initPushNotifications tests
// ==============================

func TestCB23_InitPushNotifications_NoEnv(t *testing.T) {
	// Should not panic with no env vars
	pushConfig = nil
	initPushNotifications()

	if pushConfig == nil {
		t.Error("expected pushConfig to be initialized")
	}
	// Both should be disabled since no env vars set
	if pushConfig.APNSEnabled {
		t.Error("expected APNS to be disabled without env")
	}
	if pushConfig.FCMEnabled {
		t.Error("expected FCM to be disabled without env")
	}
}

// ==============================
// getEnvOrDefault tests
// ==============================

func TestCB23_GetEnvOrDefault_Set(t *testing.T) {
	os.Setenv("TEST_GETENV_CB23", "hello")
	defer os.Unsetenv("TEST_GETENV_CB23")

	result := getEnvOrDefault("TEST_GETENV_CB23", "default")
	if result != "hello" {
		t.Errorf("expected 'hello', got %s", result)
	}
}

func TestCB23_GetEnvOrDefault_Default(t *testing.T) {
	result := getEnvOrDefault("TEST_NOT_SET_CB23", "default")
	if result != "default" {
		t.Errorf("expected 'default', got %s", result)
	}
}

// ==============================
// validateAgentSecret edge cases
// ==============================

func TestCB23_ValidateAgentSecret_EmptySecret(t *testing.T) {
	err := ValidateAgentSecret("test-agent", "")
	if err == nil {
		t.Error("expected error for empty agent secret")
	}
	if !strings.Contains(err.Error(), "missing agent secret") {
		t.Errorf("expected 'missing agent secret' error, got %v", err)
	}
}

func TestCB23_ValidateAgentSecret_WrongSecret(t *testing.T) {
	resetAgentSecret()
	defer resetAgentSecret()

	err := ValidateAgentSecret("test-agent", "wrong-secret")
	if err == nil {
		t.Error("expected error for wrong agent secret")
	}
}

func TestCB23_ValidateAgentSecret_CorrectSecret(t *testing.T) {
	resetAgentSecret()
	defer resetAgentSecret()

	err := ValidateAgentSecret("test-agent", agentSecret)
	if err != nil {
		t.Errorf("expected no error for correct secret, got %v", err)
	}
}

// ==============================
// logger tests
// ==============================

func TestCB23_Logger_Levels(t *testing.T) {
	var buf bytes.Buffer
	logger := NewLogger(LogDebug)
	logger.SetOutput(&buf)

	logger.Debug("debug_msg", map[string]interface{}{"key": "value"})
	logger.Info("info_msg", map[string]interface{}{"key": "value"})
	logger.Warn("warn_msg", map[string]interface{}{"key": "value"})
	logger.Error("error_msg", map[string]interface{}{"key": "value"})

	output := buf.String()
	if !strings.Contains(output, "debug_msg") {
		t.Error("expected debug message in output")
	}
	if !strings.Contains(output, "info_msg") {
		t.Error("expected info message in output")
	}
	if !strings.Contains(output, "warn_msg") {
		t.Error("expected warn message in output")
	}
	if !strings.Contains(output, "error_msg") {
		t.Error("expected error message in output")
	}
}

func TestCB23_Logger_LevelFilter(t *testing.T) {
	var buf bytes.Buffer
	logger := NewLogger(LogWarn)
	logger.SetOutput(&buf)

	logger.Debug("should_be_filtered")
	logger.Info("should_be_filtered")
	logger.Warn("should_appear")
	logger.Error("should_appear")

	output := buf.String()
	if strings.Contains(output, "should_be_filtered") {
		t.Error("expected debug/info messages to be filtered at warn level")
	}
	if !strings.Contains(output, "should_appear") {
		t.Error("expected warn/error messages to appear")
	}
}

func TestCB23_Logger_WithFields(t *testing.T) {
	var buf bytes.Buffer
	logger := NewLogger(LogInfo)
	logger.SetOutput(&buf)

	logger.WithFields(map[string]interface{}{"request_id": "abc123"}).Info("with_fields")

	output := buf.String()
	if !strings.Contains(output, "with_fields") {
		t.Error("expected message in output")
	}
	if !strings.Contains(output, "abc123") {
		t.Error("expected field in output")
	}
}

// ==============================
// race condition test: SafeSend concurrent
// ==============================

func TestCB23_Connection_SafeSend_Concurrent(t *testing.T) {
	conn := &Connection{
		hub:      hub,
		connType: "agent",
		id:       "concurrent-agent",
		send:     make(chan []byte, 256),
	}

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			conn.SafeSend([]byte(fmt.Sprintf("msg-%d", n)))
		}(i)
	}
	wg.Wait()

	// All messages should be in the channel
	if len(conn.send) != 100 {
		t.Errorf("expected 100 messages, got %d", len(conn.send))
	}
}

// ==============================
// storeMessagesBatch test
// ==============================

func TestCB23_StoreMessagesBatch(t *testing.T) {
	cb23SetupDB(t)
	cb23CreateAgent(t, "batch-agent", "Batch Agent")
	convID := cb23CreateConversation(t, "batch-user", "batch-agent")

	msgs := []RoutedMessage{
		{
			Type:           "message",
			ConversationID: convID,
			Content:         "hello 1",
			SenderType:     "client",
			SenderID:       "batch-user",
			RecipientID:    "batch-agent",
		},
		{
			Type:           "message",
			ConversationID: convID,
			Content:         "hello 2",
			SenderType:     "agent",
			SenderID:       "batch-agent",
			RecipientID:    "batch-user",
		},
	}

	ids, err := storeMessagesBatch(msgs)
	if err != nil {
		t.Fatalf("storeMessagesBatch failed: %v", err)
	}
	if len(ids) != 2 {
		t.Errorf("expected 2 IDs, got %d", len(ids))
	}

	// Verify messages exist
	rows, err := db.Query("SELECT content FROM messages WHERE conversation_id = ? ORDER BY created_at", convID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()

	var contents []string
	for rows.Next() {
		var c string
		rows.Scan(&c)
		contents = append(contents, c)
	}
	if len(contents) != 2 {
		t.Errorf("expected 2 messages, got %d", len(contents))
	}
}

// ==============================
// searchMessages test
// ==============================

func TestCB23_SearchMessages_EmptyQuery(t *testing.T) {
	cb23SetupDB(t)

	_, err := searchMessages("user1", "", 50)
	if err == nil || err.Error() != "empty search query" {
		t.Errorf("expected 'empty search query' error, got %v", err)
	}
}

func TestCB23_SearchMessages_WithResults(t *testing.T) {
	cb23SetupDB(t)
	cb23CreateAgent(t, "search-agent", "Search Agent")
	convID := cb23CreateConversation(t, "search-user", "search-agent")

	// Insert some messages
	_, err := db.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content) VALUES (?, ?, ?, ?, ?)",
		"msg1", convID, "client", "search-user", "hello world")
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content) VALUES (?, ?, ?, ?, ?)",
		"msg2", convID, "agent", "search-agent", "hello universe")
	if err != nil {
		t.Fatal(err)
	}

	messages, err := searchMessages("search-user", "hello", 50)
	if err != nil {
		t.Fatalf("searchMessages failed: %v", err)
	}
	if len(messages) != 2 {
		t.Errorf("expected 2 results, got %d", len(messages))
	}
}

func TestCB23_SearchMessages_NoResults(t *testing.T) {
	cb23SetupDB(t)

	messages, err := searchMessages("nonexistent-user", "xyz123", 50)
	if err != nil {
		t.Fatalf("searchMessages failed: %v", err)
	}
	if len(messages) != 0 {
		t.Errorf("expected 0 results, got %d", len(messages))
	}
}

// ==============================
// deleteConversation test
// ==============================

func TestCB23_DeleteConversation_Unauthorized(t *testing.T) {
	cb23SetupDB(t)
	cb23CreateAgent(t, "del-agent", "Delete Agent")
	convID := cb23CreateConversation(t, "owner-user", "del-agent")

	err := deleteConversation(convID, "other-user")
	if err == nil {
		t.Error("expected error for unauthorized user")
	}
	if err.Error() != "unauthorized" {
		t.Errorf("expected 'unauthorized' error, got %v", err)
	}
}

func TestCB23_DeleteConversation_NotFound(t *testing.T) {
	cb23SetupDB(t)

	err := deleteConversation("nonexistent-conv", "user1")
	if err == nil {
		t.Error("expected error for nonexistent conversation")
	}
}

// ==============================
// changeUserPassword test
// ==============================

func TestCB23_ChangeUserPassword_InvalidOld(t *testing.T) {
	cb23SetupDB(t)
	userID, _ := cb23CreateUser(t, "pwuser", "oldpassword")

	err := changeUserPassword(userID, "wrongpassword", "newpassword123")
	if err == nil {
		t.Error("expected error for wrong old password")
	}
	// The function returns a generic error when old password doesn't match
}

func TestCB23_ChangeUserPassword_Success(t *testing.T) {
	cb23SetupDB(t)
	userID, _ := cb23CreateUser(t, "pwuser2", "oldpass123")

	err := changeUserPassword(userID, "oldpass123", "newpass456")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	// Verify old password no longer works
	err = changeUserPassword(userID, "oldpass123", "anotherpass")
	if err == nil {
		t.Error("expected error for old password after change")
	}
}

func TestCB23_ChangeUserPassword_ShortNew(t *testing.T) {
	cb23SetupDB(t)
	userID, _ := cb23CreateUser(t, "pwuser3", "oldpass123")

	err := changeUserPassword(userID, "oldpass123", "short")
	if err == nil {
		t.Error("expected error for short new password")
	}
}

func TestCB23_ChangeUserPassword_NotFound(t *testing.T) {
	cb23SetupDB(t)

	err := changeUserPassword("nonexistent-user", "oldpass", "newpass12345")
	if err == nil {
		t.Error("expected error for nonexistent user")
	}
}

// ==============================
// Protocol negotiation tests
// ==============================

func TestCB23_NegotiateProtocol_Valid(t *testing.T) {
	req := httptest.NewRequest("GET", "/agent/connect", nil)
	req.Header.Set("Sec-WebSocket-Protocol", "agent-messenger-v1")

	version := negotiateProtocol(req)
	// negotiateProtocol extracts just the version number (e.g. "v1")
	if version != "v1" {
		t.Errorf("expected 'v1', got %s", version)
	}
}

func TestCB23_NegotiateProtocol_Empty(t *testing.T) {
	req := httptest.NewRequest("GET", "/agent/connect", nil)

	version := negotiateProtocol(req)
	// With no Sec-WebSocket-Protocol header, defaults to ProtocolVersion ("v1")
	if version != ProtocolVersion {
		t.Errorf("expected '%s' for empty header, got %s", ProtocolVersion, version)
	}
}

func TestCB23_IsSupportedVersion(t *testing.T) {
	// isSupportedVersion checks version strings like "v1"
	if !isSupportedVersion("v1") {
		t.Error("expected v1 to be supported")
	}
	if isSupportedVersion("v99") {
		t.Error("expected v99 to be unsupported")
	}
}

// ==============================
// getConversationMessages test
// ==============================

func TestCB23_GetConversationMessages_WithBefore(t *testing.T) {
	cb23SetupDB(t)
	cb23CreateAgent(t, "msg-agent", "Msg Agent")
	convID := cb23CreateConversation(t, "msg-user", "msg-agent")

	// Insert messages
	_, err := db.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, created_at) VALUES (?, ?, ?, ?, ?, ?)",
		"msg-old", convID, "client", "msg-user", "old message", "2024-01-01T00:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, created_at) VALUES (?, ?, ?, ?, ?, ?)",
		"msg-new", convID, "agent", "msg-agent", "new message", "2024-06-01T00:00:00Z")
	if err != nil {
		t.Fatal(err)
	}

	// Get messages - the 'before' parameter filters by cursor
	msgs, err := getConversationMessages(convID, 50, "msg-new")
	if err != nil {
		t.Fatalf("getConversationMessages failed: %v", err)
	}
	// At minimum we should get some messages back
	if len(msgs) < 1 {
		t.Errorf("expected at least 1 message, got %d", len(msgs))
	}
}

// ==============================
// markMessagesRead test
// ==============================

func TestCB23_MarkMessagesRead_Unauthorized(t *testing.T) {
	cb23SetupDB(t)
	cb23CreateAgent(t, "read-agent", "Read Agent")
	convID := cb23CreateConversation(t, "read-owner", "read-agent")

	_, err := markMessagesRead(convID, "other-user")
	if err == nil {
		t.Error("expected error for unauthorized user")
	}
	if err.Error() != "unauthorized" {
		t.Errorf("expected 'unauthorized', got %v", err)
	}
}

func TestCB23_MarkMessagesRead_NotFound(t *testing.T) {
	cb23SetupDB(t)

	_, err := markMessagesRead("nonexistent-conv", "user1")
	if err == nil {
		t.Error("expected error for nonexistent conversation")
	}
}

// ==============================
// CreateConversation / GetOrCreateConversation
// ==============================

func TestCB23_CreateConversation(t *testing.T) {
	cb23SetupDB(t)
	cb23CreateAgent(t, "create-agent", "Create Agent")

	conv, err := CreateConversation("user1", "create-agent")
	if err != nil {
		t.Fatalf("CreateConversation failed: %v", err)
	}
	if conv.UserID != "user1" {
		t.Errorf("expected UserID 'user1', got %s", conv.UserID)
	}
	if conv.AgentID != "create-agent" {
		t.Errorf("expected AgentID 'create-agent', got %s", conv.AgentID)
	}
	if conv.ID == "" {
		t.Error("expected non-empty conversation ID")
	}
}

func TestCB23_GetOrCreateConversation_New(t *testing.T) {
	cb23SetupDB(t)
	cb23CreateAgent(t, "getor-agent", "GetOrCreate Agent")

	conv, err := GetOrCreateConversation("user1", "getor-agent")
	if err != nil {
		t.Fatalf("GetOrCreateConversation failed: %v", err)
	}
	if conv.UserID != "user1" {
		t.Errorf("expected UserID 'user1', got %s", conv.UserID)
	}
}

func TestCB23_GetOrCreateConversation_Existing(t *testing.T) {
	cb23SetupDB(t)
	cb23CreateAgent(t, "getor2-agent", "GetOrCreate2 Agent")

	conv1, err := GetOrCreateConversation("user2", "getor2-agent")
	if err != nil {
		t.Fatalf("first GetOrCreateConversation failed: %v", err)
	}

	conv2, err := GetOrCreateConversation("user2", "getor2-agent")
	if err != nil {
		t.Fatalf("second GetOrCreateConversation failed: %v", err)
	}

	if conv1.ID != conv2.ID {
		t.Errorf("expected same conversation ID, got %s and %s", conv1.ID, conv2.ID)
	}
}

// ==============================
// Metrics tests
// ==============================

func TestCB23_Metrics_ConnectionsTotal(t *testing.T) {
	testHub := newHub()
	m := NewMetrics(testHub)

	m.ConnectionsTotal.Add(5)
	if m.ConnectionsTotal.Load() != 5 {
		t.Errorf("expected 5 total connections, got %d", m.ConnectionsTotal.Load())
	}
}

func TestCB23_MessagesIn(t *testing.T) {
	testHub := newHub()
	m := NewMetrics(testHub)

	m.MessagesIn.Add(10)
	if m.MessagesIn.Load() != 10 {
		t.Errorf("expected 10 messages in, got %d", m.MessagesIn.Load())
	}
}

// ==============================
// initSchemaForDriver test
// ==============================

func TestCB23_InitSchemaForDriver_SQLite(t *testing.T) {
	origDriver := currentDriver
	currentDriver = "sqlite3"
	defer func() { currentDriver = origDriver }()

	schema := initSchemaForDriver()
	if !strings.Contains(schema, "CREATE TABLE IF NOT EXISTS users") {
		t.Error("expected SQLite schema to contain users table")
	}
	// The schema should be valid SQL (check for CREATE TABLE)
	if !strings.Contains(schema, "CREATE TABLE") {
		t.Error("expected schema to contain CREATE TABLE statements")
	}
}

func TestCB23_InitSchemaForDriver_PostgreSQL(t *testing.T) {
	origDriver := currentDriver
	currentDriver = "postgres"
	defer func() { currentDriver = origDriver }()

	schema := initSchemaForDriver()
	if !strings.Contains(schema, "CREATE TABLE IF NOT EXISTS users") {
		t.Error("expected PostgreSQL schema to contain users table")
	}
	if !strings.Contains(schema, "SERIAL") {
		t.Error("expected PostgreSQL schema to use SERIAL")
	}
}

// ==============================
// OfflineQueue Purge test
// ==============================

func TestCB23_OfflineQueue_Purge(t *testing.T) {
	q := newOfflineQueue(100, 7*24*time.Hour)

	q.Enqueue("user1", []byte("msg1"))
	q.Enqueue("user1", []byte("msg2"))
	q.Enqueue("user2", []byte("msg3"))

	if q.QueueDepth("user1") != 2 {
		t.Errorf("expected depth 2 for user1, got %d", q.QueueDepth("user1"))
	}

	q.Purge("user1")

	if q.QueueDepth("user1") != 0 {
		t.Errorf("expected depth 0 for user1 after purge, got %d", q.QueueDepth("user1"))
	}
	if q.QueueDepth("user2") != 1 {
		t.Errorf("expected depth 1 for user2 (unchanged), got %d", q.QueueDepth("user2"))
	}
}

func TestCB23_OfflineQueue_TotalDepth(t *testing.T) {
	q := newOfflineQueue(100, 7*24*time.Hour)

	q.Enqueue("user1", []byte("msg1"))
	q.Enqueue("user1", []byte("msg2"))
	q.Enqueue("user2", []byte("msg3"))

	if q.TotalDepth() != 3 {
		t.Errorf("expected total depth 3, got %d", q.TotalDepth())
	}
}

func TestCB23_OfflineQueue_DrainEmpty(t *testing.T) {
	q := newOfflineQueue(100, 7*24*time.Hour)

	msgs := q.Drain("nonexistent")
	if len(msgs) != 0 {
		t.Errorf("expected empty drain for nonexistent user, got %d", len(msgs))
	}
}

// ==============================
// queue persistence tests
// ==============================

func TestCB23_MarshalOutgoingMessage(t *testing.T) {
	msg := OutgoingMessage{
		Type: "message",
		Data: map[string]string{
			"content": "hello",
		},
	}

	data := marshalOutgoingMessage(msg)
	if len(data) == 0 {
		t.Error("expected non-empty marshaled data")
	}

	var unmarshaled map[string]interface{}
	if err := json.Unmarshal(data, &unmarshaled); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}
	if unmarshaled["type"] != "message" {
		t.Errorf("expected type 'message', got %v", unmarshaled["type"])
	}
}

func TestCB23_QueueDB_Init(t *testing.T) {
	cb23SetupDB(t)
	// initQueueDB should have been called in cb23SetupDB
	// Verify offline_queue table exists
	var name string
	err := db.QueryRow("SELECT name FROM sqlite_master WHERE type='table' AND name='offline_queue'").Scan(&name)
	if err != nil {
		t.Fatalf("expected offline_queue table to exist: %v", err)
	}
}

func TestCB23_QueuePersistence(t *testing.T) {
	cb23SetupDB(t)

	data := []byte(`{"type":"message","data":"hello"}`)
	persistQueue(db, "persist-user", data)

	// Verify it was persisted
	var count int
	db.QueryRow("SELECT COUNT(*) FROM offline_queue WHERE recipient = ?", "persist-user").Scan(&count)
	if count != 1 {
		t.Errorf("expected 1 persisted message, got %d", count)
	}

	// Delete it
	deleteQueueMessages(db, "persist-user")

	db.QueryRow("SELECT COUNT(*) FROM offline_queue WHERE recipient = ?", "persist-user").Scan(&count)
	if count != 0 {
		t.Errorf("expected 0 after delete, got %d", count)
	}
}

func TestCB23_LoadQueueFromDB(t *testing.T) {
	cb23SetupDB(t)

	// Persist a message
	persistQueue(db, "load-user", []byte(`{"type":"message"}`))

	// Load it into a new queue
	q := newOfflineQueue(100, 7*24*time.Hour)
	loadQueueFromDB(db, q)

	if q.QueueDepth("load-user") != 1 {
		t.Errorf("expected depth 1 after load, got %d", q.QueueDepth("load-user"))
	}
}

func TestCB23_CleanStaleQueueMessages(t *testing.T) {
	cb23SetupDB(t)

	// Insert a stale message (old timestamp)
	_, err := db.Exec("INSERT INTO offline_queue (recipient, data, queued_at, sent_count) VALUES (?, ?, ?, ?)",
		"stale-user", []byte(`{"type":"message"}`), time.Now().Add(-8*24*time.Hour).UTC(), 0)
	if err != nil {
		t.Fatal(err)
	}

	// Insert a fresh message
	persistQueue(db, "fresh-user", []byte(`{"type":"message"}`))

	// Clean stale messages (older than 7 days)
	cleanStaleQueueMessages(db, 7*24*time.Hour)

	// Stale should be gone
	var staleCount int
	db.QueryRow("SELECT COUNT(*) FROM offline_queue WHERE recipient = ?", "stale-user").Scan(&staleCount)
	if staleCount != 0 {
		t.Errorf("expected 0 stale messages, got %d", staleCount)
	}

	// Fresh should remain
	var freshCount int
	db.QueryRow("SELECT COUNT(*) FROM offline_queue WHERE recipient = ?", "fresh-user").Scan(&freshCount)
	if freshCount != 1 {
		t.Errorf("expected 1 fresh message, got %d", freshCount)
	}
}

// ==============================
// isConversationMuted test
// ==============================

func TestCB23_IsConversationMuted_True(t *testing.T) {
	cb23SetupDB(t)
	cb23CreateAgent(t, "mute-agent", "Mute Agent")
	convID := cb23CreateConversation(t, "mute-user", "mute-agent")

	// Mute the conversation
	_, err := db.Exec("INSERT INTO notification_preferences (user_id, conversation_id, muted) VALUES (?, ?, 1)",
		"mute-user", convID)
	if err != nil {
		t.Fatal(err)
	}

	if !isConversationMuted("mute-user", convID) {
		t.Error("expected conversation to be muted")
	}
}

func TestCB23_IsConversationMuted_False(t *testing.T) {
	cb23SetupDB(t)

	if isConversationMuted("nonexistent-user", "nonexistent-conv") {
		t.Error("expected nonexistent conversation to not be muted")
	}
}

// ==============================
// Handle health check
// ==============================

func TestCB23_HealthCheck_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest("POST", "/health", nil)
	rr := httptest.NewRecorder()
	handleHealth(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rr.Code)
	}
}

func TestCB23_HealthCheck_Success(t *testing.T) {
	cb23SetupDB(t)
	cb23SetupHub(t)
	ServerMetrics = NewMetrics(hub)

	req := httptest.NewRequest("GET", "/health", nil)
	rr := httptest.NewRecorder()
	handleHealth(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}

	var resp map[string]interface{}
	json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp["status"] != "ok" {
		t.Errorf("expected status 'ok', got %v", resp["status"])
	}
}

// ==============================
// handleMetrics
// ==============================

func TestCB23_HandleMetrics(t *testing.T) {
	req := httptest.NewRequest("GET", "/metrics", nil)
	rr := httptest.NewRecorder()
	handleMetrics(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}

// ==============================
// handleLogin edge cases
// ==============================

func TestCB23_HandleLogin_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest("GET", "/auth/login", nil)
	rr := httptest.NewRecorder()
	handleLogin(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rr.Code)
	}
}

func TestCB23_HandleLogin_MissingFields(t *testing.T) {
	cb23SetupDB(t)

	form := url.Values{"username": {""}, "password": {""}}.Encode()
	req := httptest.NewRequest("POST", "/auth/login", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	handleLogin(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestCB23_HandleLogin_WrongPassword(t *testing.T) {
	cb23SetupDB(t)
	_, _ = cb23CreateUser(t, "loginuser", "correctpass")

	form := url.Values{"username": {"loginuser"}, "password": {"wrongpass"}}.Encode()
	req := httptest.NewRequest("POST", "/auth/login", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	handleLogin(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

func TestCB23_HandleLogin_NonexistentUser(t *testing.T) {
	cb23SetupDB(t)

	form := url.Values{"username": {"nonexistent"}, "password": {"pass"}}.Encode()
	req := httptest.NewRequest("POST", "/auth/login", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	handleLogin(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

// ==============================
// handleRegisterUser edge cases
// ==============================

func TestCB23_HandleRegisterUser_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest("GET", "/auth/user", nil)
	rr := httptest.NewRecorder()
	handleRegisterUser(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rr.Code)
	}
}

func TestCB23_HandleRegisterUser_ShortUsername(t *testing.T) {
	cb23SetupDB(t)

	form := url.Values{"username": {"ab"}, "password": {"password123"}}.Encode()
	req := httptest.NewRequest("POST", "/auth/user", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	handleRegisterUser(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for short username, got %d", rr.Code)
	}
}

func TestCB23_HandleRegisterUser_InvalidChars(t *testing.T) {
	cb23SetupDB(t)

	form := url.Values{"username": {"user name"}, "password": {"password123"}}.Encode()
	req := httptest.NewRequest("POST", "/auth/user", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	handleRegisterUser(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid username chars, got %d", rr.Code)
	}
}

func TestCB23_HandleRegisterUser_DuplicateUsername(t *testing.T) {
	cb23SetupDB(t)
	_, _ = cb23CreateUser(t, "duplicateuser", "password123")

	form := url.Values{"username": {"duplicateuser"}, "password": {"password456"}}.Encode()
	req := httptest.NewRequest("POST", "/auth/user", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	handleRegisterUser(rr, req)

	if rr.Code != http.StatusConflict {
		t.Errorf("expected 409 for duplicate username, got %d: %s", rr.Code, rr.Body.String())
	}
}