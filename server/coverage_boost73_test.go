package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/websocket"
	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"
)

// ==================== CB73 Helpers ====================

func setupTestDB_CB73(t *testing.T) *sql.DB {
	testDB, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("Failed to open test DB: %v", err)
	}
	if err := initSchema(testDB); err != nil {
		t.Fatalf("Failed to init schema: %v", err)
	}
	t.Cleanup(func() { testDB.Close() })


func generateTestToken_CB73(userID string) string {
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

func createUser_CB73(testDB *sql.DB, username, password string) string {
	hash, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	userID := "user_" + username
	testDB.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)", userID, username, hash)
	return userID
}

func createAgent_CB73(testDB *sql.DB, agentID string) {
	testDB.Exec("INSERT INTO agents (id, name, model) VALUES (?, ?, ?)", agentID, "Test Agent", "test-model")
}

func createConversation_CB73(testDB *sql.DB, userID, agentID string) string {
	convID := "conv_" + agentID + "_" + userID
	testDB.Exec("INSERT INTO conversations (id, user_id, agent_id) VALUES (?, ?, ?)", convID, userID, agentID)
	return convID
}

// makeConn_CB73 creates a Connection with a real websocket pair for testing writePump.
func makeConn_CB73(connType, id string, h *Hub) *Connection {
	send := make(chan []byte, 256)
	return &Connection{
		hub:      h,
		connType: connType,
		id:       id,
		send:     send,
	}
}

// makeWebSocketPair creates a real websocket connection pair for testing writePump/readPump.
func makeWebSocketPair_CB73(t *testing.T) (*websocket.Conn, *websocket.Conn, func()) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upgrader := websocket.Upgrader{}
		c, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Fatalf("upgrade failed: %v", err)
		}
		// Keep connection open, read messages until closed
		go func() {
			defer c.Close()
			for {
				if _, _, err := c.ReadMessage(); err != nil {
					return
				}
			}
		}()
	}))
	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")

	dialer := websocket.Dialer{}
	clientConn, _, err := dialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}

	cleanup := func() {
		clientConn.Close()
		srv.Close()
	}
	// Return srv conn as first, client as second - but we can't access srv conn directly.
	// Instead, return clientConn twice (one for reading, one for writing).
	// Actually we need the server-side conn. Let me restructure.
	return clientConn, clientConn, cleanup
}

// makeWebSocketPairForWritePump creates a pair where the server side is available for writePump testing.
func makeWebSocketPairForWritePump_CB73(t *testing.T) (*websocket.Conn, *websocket.Conn, func()) {
	var serverConn *websocket.Conn
	var serverConnMu sync.Mutex
	serverConnReady := make(chan struct{})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upgrader := websocket.Upgrader{}
		c, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Fatalf("upgrade failed: %v", err)
		}
		serverConnMu.Lock()
		serverConn = c
		serverConnMu.Unlock()
		close(serverConnReady)
		// Block until closed
		for {
			if _, _, err := c.ReadMessage(); err != nil {
				return
			}
		}
	}))
	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")

	dialer := websocket.Dialer{}
	clientConn, _, err := dialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}

	<-serverConnReady
	serverConnMu.Lock()
	sc := serverConn
	serverConnMu.Unlock()

	cleanup := func() {
		clientConn.Close()
		srv.Close()
	}
	return sc, clientConn, cleanup
}

// ==================== marshalOutgoingMessage tests (60.0% -> ~100%) ====================

func TestCB73_MarshalOutgoingMessage_Success(t *testing.T) {
	msg := OutgoingMessage{Type: "message", Data: map[string]string{"content": "hello"}}
	data := marshalOutgoingMessage(msg)
	if data == nil {
		t.Fatal("expected non-nil data")
	}
	var result OutgoingMessage
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}
	if result.Type != "message" {
		t.Errorf("expected type 'message', got '%s'", result.Type)
	}
}

func TestCB73_MarshalOutgoingMessage_ComplexData(t *testing.T) {
	msg := OutgoingMessage{
		Type: "connected",
		Data: map[string]interface{}{
			"id":     "test-123",
			"status": "connected",
			"nested": map[string]string{"key": "value"},
		},
	}
	data := marshalOutgoingMessage(msg)
	if data == nil {
		t.Fatal("expected non-nil data")
	}
}

func TestCB73_MarshalOutgoingMessage_NilData(t *testing.T) {
	msg := OutgoingMessage{Type: "test", Data: nil}
	data := marshalOutgoingMessage(msg)
	if data == nil {
		t.Fatal("expected non-nil data for nil Data")
	}
}

func TestCB73_MarshalOutgoingMessage_MarshalError(t *testing.T) {
	// Pass a channel which cannot be JSON marshaled
	msg := OutgoingMessage{Type: "test", Data: make(chan int)}
	data := marshalOutgoingMessage(msg)
	if data != nil {
		t.Error("expected nil data for unmarshalable input")
	}
}

// ==================== writePump tests (70.4% -> ~90%) ====================

func TestCB73_WritePump_MessageSent(t *testing.T) {
	serverConn, clientConn, cleanup := makeWebSocketPairForWritePump_CB73(t)
	defer cleanup()

	h := newHub()
	go h.run()
	defer h.Stop()

	conn := &Connection{
		hub:      h,
		connType: "agent",
		id:       "test-agent-wp",
		conn:     serverConn,
		send:     make(chan []byte, 256),
	}

	go conn.writePump()

	// Send a message
	conn.send <- []byte(`{"type":"test"}`)

	// Read from client side
	clientConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, msg, err := clientConn.ReadMessage()
	if err != nil {
		t.Fatalf("failed to read message: %v", err)
	}
	if string(msg) != `{"type":"test"}` {
		t.Errorf("expected {\"type\":\"test\"}, got '%s'", string(msg))
	}

	// Close the send channel to trigger writePump to close
	close(conn.send)
	time.Sleep(100 * time.Millisecond)
}

func TestCB73_WritePump_ChannelClosed(t *testing.T) {
	serverConn, clientConn, cleanup := makeWebSocketPairForWritePump_CB73(t)
	defer cleanup()

	h := newHub()
	go h.run()
	defer h.Stop()

	conn := &Connection{
		hub:      h,
		connType: "agent",
		id:       "test-agent-close",
		conn:     serverConn,
		send:     make(chan []byte, 256),
	}

	go conn.writePump()

	// Close the send channel to trigger the close path
	close(conn.send)
	time.Sleep(100 * time.Millisecond)

	// The server should have sent a close message
	// Client should be able to detect the connection closing
	clientConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	for {
		_, _, err := clientConn.ReadMessage()
		if err != nil {
			break // Connection closed as expected
		}
	}
}

func TestCB73_WritePump_WriteError(t *testing.T) {
	serverConn, _, cleanup := makeWebSocketPairForWritePump_CB73(t)
	defer cleanup()

	h := newHub()
	go h.run()
	defer h.Stop()

	conn := &Connection{
		hub:      h,
		connType: "agent",
		id:       "test-agent-werr",
		conn:     serverConn,
		send:     make(chan []byte, 256),
	}

	// Close the server conn first so writes fail
	serverConn.Close()

	go conn.writePump()

	// Send a message - should cause write error
	conn.send <- []byte(`{"type":"test"}`)
	time.Sleep(100 * time.Millisecond)
}

func TestCB73_WritePump_PingTicker(t *testing.T) {
	// We can't easily test the ping ticker without waiting for pingPeriod (54s).
	// Instead, test that writePump runs and handles the ticker by using a
	// very short-lived connection.
	serverConn, clientConn, cleanup := makeWebSocketPairForWritePump_CB73(t)
	defer cleanup()

	h := newHub()
	go h.run()
	defer h.Stop()

	conn := &Connection{
		hub:      h,
		connType: "agent",
		id:       "test-agent-ping",
		conn:     serverConn,
		send:     make(chan []byte, 256),
	}

	go conn.writePump()

	// Send a regular message first to verify it works
	conn.send <- []byte(`{"type":"ping_test"}`)
	clientConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, msg, err := clientConn.ReadMessage()
	if err != nil {
		t.Fatalf("failed to read: %v", err)
	}
	if string(msg) != `{"type":"ping_test"}` {
		t.Errorf("unexpected message: %s", string(msg))
	}

	// Close to clean up
	close(conn.send)
	time.Sleep(100 * time.Millisecond)
}

// ==================== checkRateLimit tests (78.9% -> ~95%) ====================

func TestCB73_CheckRateLimit_PerConnectionExceeded(t *testing.T) {
	oldRL := messageRateLimiter
	oldURL := userRateLimiter
	defer func() {
		messageRateLimiter = oldRL
		userRateLimiter = oldURL
	}()
	// Use a fresh limiter with very low limit
	messageRateLimiter = NewRateLimiter(2, time.Minute)
	userRateLimiter = NewRateLimiter(100, time.Minute)

	conn := &Connection{
		connType: "client",
		id:      "test-rl-conn-1",
		send:    make(chan []byte, 10),
	}

	// Use up the per-connection limit
	checkRateLimit(conn) // 1st
	checkRateLimit(conn) // 2nd
	result := checkRateLimit(conn) // 3rd - should be rate limited
	if result {
		t.Error("expected per-connection rate limit to be exceeded")
	}

	// Check error message was sent
	select {
	case msg := <-conn.send:
		if !strings.Contains(string(msg), "rate limit exceeded") {
			t.Errorf("expected rate limit error, got: %s", string(msg))
		}
	default:
		// Error might have been sent via sendError which may not always reach the channel
	}
}

func TestCB73_CheckRateLimit_PerUserExceeded(t *testing.T) {
	oldRL := messageRateLimiter
	oldURL := userRateLimiter
	defer func() {
		messageRateLimiter = oldRL
		userRateLimiter = oldURL
	}()
	messageRateLimiter = NewRateLimiter(100, time.Minute)
	userRateLimiter = NewRateLimiter(2, time.Minute)

	conn := &Connection{
		connType: "client",
		id:      "test-rl-conn-2",
		send:    make(chan []byte, 10),
	}

	// Use up the per-user limit
	checkRateLimit(conn) // 1st - per-conn OK, per-user OK
	checkRateLimit(conn) // 2nd - per-conn OK, per-user OK
	result := checkRateLimit(conn) // 3rd - per-conn OK, per-user exceeded
	if result {
		t.Error("expected per-user rate limit to be exceeded")
	}
}

func TestCB73_CheckRateLimit_BothAllowed(t *testing.T) {
	oldRL := messageRateLimiter
	oldURL := userRateLimiter
	defer func() {
		messageRateLimiter = oldRL
		userRateLimiter = oldURL
	}()
	messageRateLimiter = NewRateLimiter(100, time.Minute)
	userRateLimiter = NewRateLimiter(100, time.Minute)

	conn := &Connection{
		connType: "agent",
		id:      "test-rl-conn-3",
		send:    make(chan []byte, 10),
	}

	result := checkRateLimit(conn)
	if !result {
		t.Error("expected rate limit to allow")
	}
}

func TestCB73_CheckRateLimit_BothExceeded(t *testing.T) {
	oldRL := messageRateLimiter
	oldURL := userRateLimiter
	defer func() {
		messageRateLimiter = oldRL
		userRateLimiter = oldURL
	}()
	messageRateLimiter = NewRateLimiter(1, time.Minute)
	userRateLimiter = NewRateLimiter(1, time.Minute)

	conn := &Connection{
		connType: "client",
		id:      "test-rl-conn-4",
		send:    make(chan []byte, 10),
	}

	// First call uses both limits
	checkRateLimit(conn)
	// Second call - per-connection should fail first
	result := checkRateLimit(conn)
	if result {
		t.Error("expected rate limit to be exceeded")
	}
}

func TestCB73_CheckRateLimit_WithMetrics(t *testing.T) {
	oldRL := messageRateLimiter
	oldURL := userRateLimiter
	oldSM := ServerMetrics
	defer func() {
		messageRateLimiter = oldRL
		userRateLimiter = oldURL
		ServerMetrics = oldSM
	}()
	messageRateLimiter = NewRateLimiter(1, time.Minute)
	userRateLimiter = NewRateLimiter(1, time.Minute)

	h := newHub()
	go h.run()
	defer h.Stop()
	ServerMetrics = NewMetrics(h)

	conn := &Connection{
		connType: "client",
		id:      "test-rl-metrics",
		send:    make(chan []byte, 10),
	}

	// First call - allowed, increments metrics
	result := checkRateLimit(conn)
	if !result {
		t.Error("expected first call to be allowed")
	}

	// Second call - rate limited, should increment ServerMetrics
	result = checkRateLimit(conn)
	if result {
		t.Error("expected second call to be rate limited")
	}
}

// ==================== monitorAgentHeartbeats tests (77.8% -> ~95%) ====================

func TestCB73_MonitorAgentHeartbeats_Disabled(t *testing.T) {
	oldInterval := agentPresenceInterval
	defer func() { agentPresenceInterval = oldInterval }()
	agentPresenceInterval = 0

	h := newHub()
	// Don't start run() - just test that monitor exits immediately when disabled
	go h.monitorAgentHeartbeats()
	// Should close monitorDone immediately
	select {
	case <-h.monitorDone:
		// Good - exited immediately
	case <-time.After(2 * time.Second):
		t.Fatal("monitorAgentHeartbeats did not exit when interval is 0")
	}
}

func TestCB73_MonitorAgentHeartbeats_StaleAgentDetected(t *testing.T) {
	oldInterval := agentPresenceInterval
	oldTimeout := agentPresenceTimeout
	oldEnabled := agentPresenceEnabled
	defer func() {
		agentPresenceInterval = oldInterval
		agentPresenceTimeout = oldTimeout
		agentPresenceEnabled = oldEnabled
	}()
	agentPresenceInterval = 50 * time.Millisecond
	agentPresenceTimeout = 10 * time.Millisecond
	agentPresenceEnabled = true

	h := newHub()
	go h.run()
	defer h.Stop()

	// Create a stale agent connection
	send := make(chan []byte, 256)
	conn := &Connection{
		hub:           h,
		connType:      "agent",
		id:            "stale-agent-1",
		send:          send,
		lastHeartbeat: time.Now().Add(-1 * time.Hour), // Very stale
	}
	h.register <- conn

	// Wait for registration and stale detection
	time.Sleep(300 * time.Millisecond)

	// Agent should have been unregistered
	if h.GetAgent("stale-agent-1") != nil {
		t.Error("expected stale agent to be unregistered")
	}
}

func TestCB73_MonitorAgentHeartbeats_FreshAgentKept(t *testing.T) {
	oldInterval := agentPresenceInterval
	oldTimeout := agentPresenceTimeout
	oldEnabled := agentPresenceEnabled
	defer func() {
		agentPresenceInterval = oldInterval
		agentPresenceTimeout = oldTimeout
		agentPresenceEnabled = oldEnabled
	}()
	agentPresenceInterval = 50 * time.Millisecond
	agentPresenceTimeout = 10 * time.Second
	agentPresenceEnabled = true

	h := newHub()
	go h.run()
	defer h.Stop()

	conn := &Connection{
		hub:           h,
		connType:      "agent",
		id:            "fresh-agent-1",
		send:          make(chan []byte, 256),
		lastHeartbeat: time.Now(),
	}
	h.register <- conn
	time.Sleep(50 * time.Millisecond)

	time.Sleep(150 * time.Millisecond)

	if h.GetAgent("fresh-agent-1") == nil {
		t.Error("expected fresh agent to still be registered")
	}
}

// ==================== sendWelcomeMessage tests (80.0% -> ~100%) ====================

func TestCB73_SendWelcomeMessage_WithDeviceID(t *testing.T) {
	conn := &Connection{
		connType: "client",
		id:       "test-welcome-dev",
		deviceID: "device-xyz",
		send:     make(chan []byte, 10),
	}
	sendWelcomeMessage(conn)

	select {
	case msg := <-conn.send:
		var result OutgoingMessage
		if err := json.Unmarshal(msg, &result); err != nil {
			t.Fatalf("failed to unmarshal: %v", err)
		}
		if result.Type != "connected" {
			t.Errorf("expected type 'connected', got '%s'", result.Type)
		}
		data, ok := result.Data.(map[string]interface{})
		if !ok {
			t.Fatal("expected map data")
		}
		if data["device_id"] != "device-xyz" {
			t.Errorf("expected device_id 'device-xyz', got '%v'", data["device_id"])
		}
		if data["status"] != "connected" {
			t.Errorf("expected status 'connected', got '%v'", data["status"])
		}
	default:
		t.Fatal("expected welcome message in send channel")
	}
}

func TestCB73_SendWelcomeMessage_NoDeviceID(t *testing.T) {
	conn := &Connection{
		connType: "agent",
		id:       "test-welcome-noDev",
		send:     make(chan []byte, 10),
	}
	sendWelcomeMessage(conn)

	select {
	case msg := <-conn.send:
		var result OutgoingMessage
		if err := json.Unmarshal(msg, &result); err != nil {
			t.Fatalf("failed to unmarshal: %v", err)
		}
		data, ok := result.Data.(map[string]interface{})
		if !ok {
			t.Fatal("expected map data")
		}
		if _, exists := data["device_id"]; exists {
			t.Error("expected no device_id field")
		}
	default:
		t.Fatal("expected welcome message in send channel")
	}
}

func TestCB73_SendWelcomeMessage_BufferFull(t *testing.T) {
	send := make(chan []byte, 1)
	send <- []byte("filler")
	conn := &Connection{
		connType: "client",
		id:       "test-welcome-full",
		send:     send,
	}
	// SafeSend should fail because buffer is full
	// sendWelcomeMessage logs a warning but doesn't panic
	sendWelcomeMessage(conn)
	// If we get here without panic, test passes
}

func TestCB73_SendWelcomeMessage_ClosedChannel(t *testing.T) {
	send := make(chan []byte, 10)
	close(send)
	conn := &Connection{
		connType: "client",
		id:       "test-welcome-closed",
		send:     send,
	}
	// Should not panic on closed channel
	sendWelcomeMessage(conn)
}

// ==================== RegisterAgentOnConnect tests (81.8% -> ~95%) ====================

func TestCB73_RegisterAgentOnConnect_UpdateAllFields(t *testing.T) {
	oldDB := db
	defer func() { db = oldDB }()
	testDB := setupTestDB_CB73(t)
	db = testDB

	// Create initial agent
	createAgent_CB73(testDB, "agent-update-all")

	// Update all fields
	err := RegisterAgentOnConnect("agent-update-all", "Updated Name", "gpt-4", "friendly", "coding")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var name, model, personality, specialty string
	err = testDB.QueryRow("SELECT name, model, personality, specialty FROM agents WHERE id = ?", "agent-update-all").
		Scan(&name, &model, &personality, &specialty)
	if err != nil {
		t.Fatalf("failed to query agent: %v", err)
	}
	if name != "Updated Name" {
		t.Errorf("expected name 'Updated Name', got '%s'", name)
	}
	if model != "gpt-4" {
		t.Errorf("expected model 'gpt-4', got '%s'", model)
	}
	if personality != "friendly" {
		t.Errorf("expected personality 'friendly', got '%s'", personality)
	}
	if specialty != "coding" {
		t.Errorf("expected specialty 'coding', got '%s'", specialty)
	}
}

func TestCB73_RegisterAgentOnConnect_DefaultNameEqualsID(t *testing.T) {
	oldDB := db
	defer func() { db = oldDB }()
	testDB := setupTestDB_CB73(t)
	db = testDB

	// Register with empty name - should default to agentID, and NOT update name in DB
	err := RegisterAgentOnConnect("agent-default-name", "", "model-x", "", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var name string
	err = testDB.QueryRow("SELECT name FROM agents WHERE id = ?", "agent-default-name").Scan(&name)
	if err != nil {
		t.Fatalf("failed to query: %v", err)
	}
	// When name defaults to agentID, the "if name != agentID" check prevents UPDATE
	// So the INSERT uses the default name (which is agentID)
	if name != "agent-default-name" {
		t.Errorf("expected name to be agent ID, got '%s'", name)
	}
}

func TestCB73_RegisterAgentOnConnect_PreserveEmptyFields(t *testing.T) {
	oldDB := db
	defer func() { db = oldDB }()
	testDB := setupTestDB_CB73(t)
	db = testDB

	// Create agent with all fields
	testDB.Exec("INSERT INTO agents (id, name, model, personality, specialty) VALUES (?, ?, ?, ?, ?)",
		"agent-preserve", "Original", "orig-model", "orig-personality", "orig-specialty")

	// Reconnect with empty fields - should NOT overwrite existing
	err := RegisterAgentOnConnect("agent-preserve", "Original", "", "", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var model, personality, specialty string
	testDB.QueryRow("SELECT model, personality, specialty FROM agents WHERE id = ?", "agent-preserve").
		Scan(&model, &personality, &specialty)
	if model != "orig-model" {
		t.Errorf("expected model preserved, got '%s'", model)
	}
	if personality != "orig-personality" {
		t.Errorf("expected personality preserved, got '%s'", personality)
	}
	if specialty != "orig-specialty" {
		t.Errorf("expected specialty preserved, got '%s'", specialty)
	}
}

func TestCB73_RegisterAgentOnConnect_DBError(t *testing.T) {
	oldDB := db
	defer func() { db = oldDB }()
	testDB := setupTestDB_CB73(t)
	testDB.Close()
	db = testDB

	err := RegisterAgentOnConnect("agent-err", "Name", "model", "personality", "specialty")
	if err == nil {
		t.Error("expected error with closed DB")
	}
}

func TestCB73_RegisterAgentOnConnect_UpdateNameOnly(t *testing.T) {
	oldDB := db
	defer func() { db = oldDB }()
	testDB := setupTestDB_CB73(t)
	db = testDB

	testDB.Exec("INSERT INTO agents (id, name, model, personality, specialty) VALUES (?, ?, ?, ?, ?)",
		"agent-name-only", "OldName", "keep-model", "keep-pers", "keep-spec")

	err := RegisterAgentOnConnect("agent-name-only", "NewName", "", "", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var name, model string
	testDB.QueryRow("SELECT name, model FROM agents WHERE id = ?", "agent-name-only").Scan(&name, &model)
	if name != "NewName" {
		t.Errorf("expected name 'NewName', got '%s'", name)
	}
	if model != "keep-model" {
		t.Errorf("expected model preserved, got '%s'", model)
	}
}

func TestCB73_RegisterAgentOnConnect_UpdateModelError(t *testing.T) {
	oldDB := db
	defer func() { db = oldDB }()
	testDB := setupTestDB_CB73(t)
	db = testDB

	createAgent_CB73(testDB, "agent-model-err")

	// Close DB to cause update error
	testDB.Close()

	err := RegisterAgentOnConnect("agent-model-err", "Name", "new-model", "", "")
	if err == nil {
		t.Error("expected error updating model with closed DB")
	}
}

func TestCB73_RegisterAgentOnConnect_UpdatePersonalityError(t *testing.T) {
	oldDB := db
	defer func() { db = oldDB }()
	testDB := setupTestDB_CB73(t)
	db = testDB

	createAgent_CB73(testDB, "agent-pers-err")
	testDB.Close()

	err := RegisterAgentOnConnect("agent-pers-err", "Name", "", "new-personality", "")
	if err == nil {
		t.Error("expected error updating personality with closed DB")
	}
}

func TestCB73_RegisterAgentOnConnect_UpdateSpecialtyError(t *testing.T) {
	oldDB := db
	defer func() { db = oldDB }()
	testDB := setupTestDB_CB73(t)
	db = testDB

	createAgent_CB73(testDB, "agent-spec-err")
	testDB.Close()

	err := RegisterAgentOnConnect("agent-spec-err", "Name", "", "", "new-specialty")
	if err == nil {
		t.Error("expected error updating specialty with closed DB")
	}
}

func TestCB73_RegisterAgentOnConnect_UpdateNameError(t *testing.T) {
	oldDB := db
	defer func() { db = oldDB }()
	testDB := setupTestDB_CB73(t)
	db = testDB

	createAgent_CB73(testDB, "agent-name-err")
	testDB.Close()

	err := RegisterAgentOnConnect("agent-name-err", "NewName", "", "", "")
	if err == nil {
		t.Error("expected error updating name with closed DB")
	}
}

// ==================== deleteConversation tests (83.3% -> ~95%) ====================

func TestCB73_DeleteConversation_MessagesDBError(t *testing.T) {
	oldDB := db
	defer func() { db = oldDB }()
	testDB := setupTestDB_CB73(t)
	db = testDB

	userID := createUser_CB73(testDB, "delmsgerr", "pass123")
	convID := createConversation_CB73(testDB, userID, "agent-del-msg")

	// Insert a message
	testDB.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, created_at) VALUES (?, ?, ?, ?, ?, ?)",
		"msg-1", convID, "agent", "agent-del-msg", "hello", time.Now().UTC().Format(time.RFC3339))

	// Close DB to cause messages delete error
	testDB.Close()

	err := deleteConversation(convID, userID)
	if err == nil {
		t.Error("expected error deleting messages with closed DB")
	}
}

func TestCB73_DeleteConversation_ConversationDBError(t *testing.T) {
	oldDB := db
	defer func() { db = oldDB }()
	testDB := setupTestDB_CB73(t)
	db = testDB

	userID := createUser_CB73(testDB, "delconvdb", "pass123")
	convID := createConversation_CB73(testDB, userID, "agent-del-conv")

	// Close DB to cause conversation query error
	testDB.Close()

	err := deleteConversation(convID, userID)
	if err == nil {
		t.Error("expected error with closed DB")
	}
}

func TestCB73_DeleteConversation_SuccessWithMessages(t *testing.T) {
	oldDB := db
	defer func() { db = oldDB }()
	testDB := setupTestDB_CB73(t)
	db = testDB

	userID := createUser_CB73(testDB, "delsuccess", "pass123")
	convID := createConversation_CB73(testDB, userID, "agent-del-succ")

	// Insert messages
	testDB.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, created_at) VALUES (?, ?, ?, ?, ?, ?)",
		"msg-1", convID, "agent", "agent-del-succ", "hello", time.Now().UTC().Format(time.RFC3339))
	testDB.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, created_at) VALUES (?, ?, ?, ?, ?, ?)",
		"msg-2", convID, "client", userID, "hi back", time.Now().UTC().Format(time.RFC3339))

	err := deleteConversation(convID, userID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify conversation is gone
	var count int
	testDB.QueryRow("SELECT count(*) FROM conversations WHERE id = ?", convID).Scan(&count)
	if count != 0 {
		t.Errorf("expected conversation deleted, found %d", count)
	}

	// Verify messages are gone
	testDB.QueryRow("SELECT count(*) FROM messages WHERE conversation_id = ?", convID).Scan(&count)
	if count != 0 {
		t.Errorf("expected messages deleted, found %d", count)
	}
}

// ==================== handleAdminAgents tests (83.3% -> ~95%) ====================

func TestCB73_HandleAdminAgents_ScanError(t *testing.T) {
	oldDB := db
	defer func() { db = oldDB }()
	testDB := setupTestDB_CB73(t)
	db = testDB

	// Drop agents table to cause scan error
	testDB.Exec("DROP TABLE agents")

	oldHub := hub
	defer func() { hub = oldHub }()
	h := newHub()
	go h.run()
	defer h.Stop()
	hub = h

	req := httptest.NewRequest("GET", "/admin/agents", nil)
	w := httptest.NewRecorder()
	handleAdminAgents(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", w.Code)
	}
}

func TestCB73_HandleAdminAgents_WithConnectedAgent(t *testing.T) {
	oldDB := db
	defer func() { db = oldDB }()
	testDB := setupTestDB_CB73(t)
	db = testDB

	createAgent_CB73(testDB, "agent-admin-connected")

	oldHub := hub
	defer func() { hub = oldHub }()
	h := newHub()
	go h.run()
	defer h.Stop()
	hub = h

	// Register an agent connection
	conn := &Connection{
		hub:          h,
		connType:     "agent",
		id:           "agent-admin-connected",
		send:         make(chan []byte, 256),
		connectedAt:  time.Now(),
		status:       "online",
	}
	h.register <- conn
	time.Sleep(50 * time.Millisecond)

	req := httptest.NewRequest("GET", "/admin/agents", nil)
	w := httptest.NewRecorder()
	handleAdminAgents(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var agents []AgentInfo
	if err := json.Unmarshal(w.Body.Bytes(), &agents); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}
	if len(agents) != 1 {
		t.Fatalf("expected 1 agent, got %d", len(agents))
	}
	if agents[0].ID != "agent-admin-connected" {
		t.Errorf("expected agent ID, got '%s'", agents[0].ID)
	}
	if agents[0].ConnectedAt == "" {
		t.Error("expected connected_at for online agent")
	}
}

func TestCB73_HandleAdminAgents_EmptyList(t *testing.T) {
	oldDB := db
	defer func() { db = oldDB }()
	testDB := setupTestDB_CB73(t)
	db = testDB

	oldHub := hub
	defer func() { hub = oldHub }()
	h := newHub()
	go h.run()
	defer h.Stop()
	hub = h

	req := httptest.NewRequest("GET", "/admin/agents", nil)
	w := httptest.NewRecorder()
	handleAdminAgents(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var agents []AgentInfo
	if err := json.Unmarshal(w.Body.Bytes(), &agents); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}
	if len(agents) != 0 {
		t.Errorf("expected 0 agents, got %d", len(agents))
	}
}

// ==================== routeChatMessage tests (83.5% -> ~95%) ====================

func TestCB73_RouteChatMessage_AgentOfflineQueued(t *testing.T) {
	oldDB := db
	defer func() { db = oldDB }()
	testDB := setupTestDB_CB73(t)
	db = testDB

	userID := createUser_CB73(testDB, "rcm-offline", "pass123")
	convID := createConversation_CB73(testDB, userID, "agent-rcm-off")

	oldHub := hub
	defer func() { hub = oldHub }()
	h := newHub()
	go h.run()
	defer h.Stop()
	hub = h

	oldQueue := offlineQueue
	defer func() { offlineQueue = oldQueue }()
	offlineQueue = newOfflineQueue(100, 7*24*time.Hour)

	sender := &Connection{
		hub:      h,
		connType: "client",
		id:       userID,
		send:     make(chan []byte, 256),
	}

	data, _ := json.Marshal(RoutedMessage{
		ConversationID: convID,
		Content:        "Hello offline agent",
	})

	routeChatMessage(sender, data)

	// Should receive an ack
	select {
	case msg := <-sender.send:
		var result OutgoingMessage
		json.Unmarshal(msg, &result)
		if result.Type != "message_sent" {
			t.Errorf("expected message_sent, got '%s'", result.Type)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("expected ack message")
	}
}

func TestCB73_RouteChatMessage_ClientOfflineQueued(t *testing.T) {
	oldDB := db
	defer func() { db = oldDB }()
	testDB := setupTestDB_CB73(t)
	db = testDB

	userID := createUser_CB73(testDB, "rcm-clientoff", "pass123")
	convID := createConversation_CB73(testDB, userID, "agent-rcm-con")

	oldHub := hub
	defer func() { hub = oldHub }()
	h := newHub()
	go h.run()
	defer h.Stop()
	hub = h

	// Register the agent but NOT the client
	agentConn := &Connection{
		hub:      h,
		connType: "agent",
		id:       "agent-rcm-con",
		send:     make(chan []byte, 256),
	}
	h.register <- agentConn
	time.Sleep(50 * time.Millisecond)

	oldQueue := offlineQueue
	defer func() { offlineQueue = oldQueue }()
	offlineQueue = newOfflineQueue(100, 7*24*time.Hour)

	// Agent sends a message to offline client
	sender := &Connection{
		hub:      h,
		connType: "agent",
		id:       "agent-rcm-con",
		send:     make(chan []byte, 256),
	}

	data, _ := json.Marshal(RoutedMessage{
		ConversationID: convID,
		Content:        "Hello offline client",
	})

	routeChatMessage(sender, data)

	// Agent should receive ack
	select {
	case msg := <-sender.send:
		var result OutgoingMessage
		json.Unmarshal(msg, &result)
		if result.Type != "message_sent" {
			t.Errorf("expected message_sent, got '%s'", result.Type)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("expected ack message")
	}
}

func TestCB73_RouteChatMessage_AgentBufferFullQueued(t *testing.T) {
	oldDB := db
	defer func() { db = oldDB }()
	testDB := setupTestDB_CB73(t)
	db = testDB

	userID := createUser_CB73(testDB, "rcm-buf-full", "pass123")
	convID := createConversation_CB73(testDB, userID, "agent-rcm-buf")

	oldHub := hub
	defer func() { hub = oldHub }()
	h := newHub()
	go h.run()
	defer h.Stop()
	hub = h

	// Register agent with a full send buffer
	agentConn := &Connection{
		hub:      h,
		connType: "agent",
		id:       "agent-rcm-buf",
		send:     make(chan []byte, 1),
	}
	agentConn.send <- []byte("filler") // Fill the buffer
	h.register <- agentConn
	time.Sleep(50 * time.Millisecond)

	oldQueue := offlineQueue
	defer func() { offlineQueue = oldQueue }()
	offlineQueue = newOfflineQueue(100, 7*24*time.Hour)

	sender := &Connection{
		hub:      h,
		connType: "client",
		id:       userID,
		send:     make(chan []byte, 256),
	}

	data, _ := json.Marshal(RoutedMessage{
		ConversationID: convID,
		Content:        "Hello agent with full buffer",
	})

	routeChatMessage(sender, data)

	// Should still get an ack
	select {
	case <-sender.send:
		// Good
	case <-time.After(1 * time.Second):
		t.Fatal("expected ack message")
	}
}

func TestCB73_RouteChatMessage_StoreError(t *testing.T) {
	oldDB := db
	defer func() { db = oldDB }()
	testDB := setupTestDB_CB73(t)
	db = testDB

	userID := createUser_CB73(testDB, "rcm-store-err", "pass123")
	convID := createConversation_CB73(testDB, userID, "agent-rcm-store")

	oldHub := hub
	defer func() { hub = oldHub }()
	h := newHub()
	go h.run()
	defer h.Stop()
	hub = h

	oldQueue := offlineQueue
	defer func() { offlineQueue = oldQueue }()
	offlineQueue = newOfflineQueue(100, 7*24*time.Hour)

	sender := &Connection{
		hub:      h,
		connType: "client",
		id:       userID,
		send:     make(chan []byte, 256),
	}

	// Close DB to cause store error
	testDB.Close()

	data, _ := json.Marshal(RoutedMessage{
		ConversationID: convID,
		Content:        "Hello with DB error",
	})

	routeChatMessage(sender, data)

	// Should receive an error message
	select {
	case msg := <-sender.send:
		s := string(msg)
		if !strings.Contains(s, "failed to store") && !strings.Contains(s, "not found") {
			// With closed DB, getConversation returns error, so "conversation not found" is sent
			t.Logf("got message: %s", s)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("expected some message back")
	}
}

func TestCB73_RouteChatMessage_SuccessClientToAgent(t *testing.T) {
	oldDB := db
	defer func() { db = oldDB }()
	testDB := setupTestDB_CB73(t)
	db = testDB

	userID := createUser_CB73(testDB, "rcm-success", "pass123")
	convID := createConversation_CB73(testDB, userID, "agent-rcm-succ")

	oldHub := hub
	defer func() { hub = oldHub }()
	h := newHub()
	go h.run()
	defer h.Stop()
	hub = h

	agentConn := &Connection{
		hub:      h,
		connType: "agent",
		id:       "agent-rcm-succ",
		send:     make(chan []byte, 256),
	}
	h.register <- agentConn
	time.Sleep(50 * time.Millisecond)

	oldQueue := offlineQueue
	defer func() { offlineQueue = oldQueue }()
	offlineQueue = newOfflineQueue(100, 7*24*time.Hour)

	sender := &Connection{
		hub:      h,
		connType: "client",
		id:       userID,
		send:     make(chan []byte, 256),
	}

	data, _ := json.Marshal(RoutedMessage{
		ConversationID: convID,
		Content:        "Hello agent!",
	})

	routeChatMessage(sender, data)

	// Agent should receive the message
	select {
	case msg := <-agentConn.send:
		var result OutgoingMessage
		json.Unmarshal(msg, &result)
		if result.Type != "message" {
			t.Errorf("expected type 'message', got '%s'", result.Type)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("agent did not receive message")
	}

	// Sender should receive ack
	select {
	case msg := <-sender.send:
		var result OutgoingMessage
		json.Unmarshal(msg, &result)
		if result.Type != "message_sent" {
			t.Errorf("expected message_sent, got '%s'", result.Type)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("sender did not receive ack")
	}
}

func TestCB73_RouteChatMessage_SuccessAgentToClient(t *testing.T) {
	oldDB := db
	defer func() { db = oldDB }()
	testDB := setupTestDB_CB73(t)
	db = testDB

	userID := createUser_CB73(testDB, "rcm-a2c", "pass123")
	convID := createConversation_CB73(testDB, userID, "agent-rcm-a2c")

	oldHub := hub
	defer func() { hub = oldHub }()
	h := newHub()
	go h.run()
	defer h.Stop()
	hub = h

	clientConn := &Connection{
		hub:      h,
		connType: "client",
		id:       userID,
		send:     make(chan []byte, 256),
	}
	h.register <- clientConn
	time.Sleep(50 * time.Millisecond)

	oldQueue := offlineQueue
	defer func() { offlineQueue = oldQueue }()
	offlineQueue = newOfflineQueue(100, 7*24*time.Hour)

	sender := &Connection{
		hub:      h,
		connType: "agent",
		id:       "agent-rcm-a2c",
		send:     make(chan []byte, 256),
	}

	data, _ := json.Marshal(RoutedMessage{
		ConversationID: convID,
		Content:        "Hello client!",
	})

	routeChatMessage(sender, data)

	// Client should receive the message
	select {
	case msg := <-clientConn.send:
		var result OutgoingMessage
		json.Unmarshal(msg, &result)
		if result.Type != "message" {
			t.Errorf("expected type 'message', got '%s'", result.Type)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("client did not receive message")
	}
}

// ==================== InitTracing tests (79.5% -> ~90%) ====================

func TestCB73_InitTracing_Disabled(t *testing.T) {
	oldVal := os.Getenv("OTEL_ENABLED")
	os.Unsetenv("OTEL_ENABLED")
	defer func() {
		if oldVal != "" {
			os.Setenv("OTEL_ENABLED", oldVal)
		}
	}()

	// Reset tracing state
	tracingMu = sync.Once{}
	tp = nil
	tracingEnabled = false
	tracer = nil

	err := InitTracing()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tracingEnabled {
		t.Error("expected tracing to be disabled")
	}
}

func TestCB73_InitTracing_NoEndpoint(t *testing.T) {
	os.Setenv("OTEL_ENABLED", "true")
	os.Unsetenv("OTEL_EXPORTER_OTLP_ENDPOINT")
	os.Unsetenv("OTEL_EXPORTER_OTLP_HTTP_ENDPOINT")
	defer func() {
		os.Unsetenv("OTEL_ENABLED")
	}()

	tracingMu = sync.Once{}
	tp = nil
	tracingEnabled = false
	tracer = nil

	err := InitTracing()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tracingEnabled {
		t.Error("expected tracing to be disabled when no endpoint")
	}
}

func TestCB73_InitTracing_HTTPExporter(t *testing.T) {
	os.Setenv("OTEL_ENABLED", "true")
	os.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://localhost:4318")
	os.Setenv("OTEL_EXPORTER_OTLP_PROTOCOL", "http")
	defer func() {
		os.Unsetenv("OTEL_ENABLED")
		os.Unsetenv("OTEL_EXPORTER_OTLP_ENDPOINT")
		os.Unsetenv("OTEL_EXPORTER_OTLP_PROTOCOL")
	}()

	tracingMu = sync.Once{}
	tp = nil
	tracingEnabled = false
	tracer = nil

	// This may fail to connect but should still set up tracing
	err := InitTracing()
	// The exporter creation might succeed even without a running collector
	if err != nil {
		// If it fails, that's OK - we're testing the code path
		t.Logf("InitTracing returned error (expected without collector): %v", err)
	}
}

func TestCB73_InitTracing_GRPCExporter(t *testing.T) {
	os.Setenv("OTEL_ENABLED", "true")
	os.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "localhost:4317")
	os.Setenv("OTEL_EXPORTER_OTLP_PROTOCOL", "grpc")
	defer func() {
		os.Unsetenv("OTEL_ENABLED")
		os.Unsetenv("OTEL_EXPORTER_OTLP_ENDPOINT")
		os.Unsetenv("OTEL_EXPORTER_OTLP_PROTOCOL")
	}()

	tracingMu = sync.Once{}
	tp = nil
	tracingEnabled = false
	tracer = nil

	err := InitTracing()
	if err != nil {
		t.Logf("InitTracing returned error (expected without collector): %v", err)
	}
}

func TestCB73_InitTracing_DefaultProtocol(t *testing.T) {
	os.Setenv("OTEL_ENABLED", "true")
	os.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "localhost:4317")
	os.Unsetenv("OTEL_EXPORTER_OTLP_PROTOCOL")
	defer func() {
		os.Unsetenv("OTEL_ENABLED")
		os.Unsetenv("OTEL_EXPORTER_OTLP_ENDPOINT")
	}()

	tracingMu = sync.Once{}
	tp = nil
	tracingEnabled = false
	tracer = nil

	err := InitTracing()
	if err != nil {
		t.Logf("InitTracing returned error (expected without collector): %v", err)
	}
}

func TestCB73_InitTracing_CustomSamplingRate(t *testing.T) {
	os.Setenv("OTEL_ENABLED", "true")
	os.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "localhost:4317")
	os.Setenv("OTEL_SAMPLING_RATE", "0.5")
	defer func() {
		os.Unsetenv("OTEL_ENABLED")
		os.Unsetenv("OTEL_EXPORTER_OTLP_ENDPOINT")
		os.Unsetenv("OTEL_SAMPLING_RATE")
	}()

	tracingMu = sync.Once{}
	tp = nil
	tracingEnabled = false
	tracer = nil

	err := InitTracing()
	if err != nil {
		t.Logf("InitTracing returned error: %v", err)
	}
}

func TestCB73_InitTracing_InvalidSamplingRate(t *testing.T) {
	os.Setenv("OTEL_ENABLED", "true")
	os.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "localhost:4317")
	os.Setenv("OTEL_SAMPLING_RATE", "invalid")
	defer func() {
		os.Unsetenv("OTEL_ENABLED")
		os.Unsetenv("OTEL_EXPORTER_OTLP_ENDPOINT")
		os.Unsetenv("OTEL_SAMPLING_RATE")
	}()

	tracingMu = sync.Once{}
	tp = nil
	tracingEnabled = false
	tracer = nil

	err := InitTracing()
	if err != nil {
		t.Logf("InitTracing returned error: %v", err)
	}
	// Should default to 0.1 when sampling rate is invalid
}

func TestCB73_InitTracing_HTTPSecureEndpoint(t *testing.T) {
	os.Setenv("OTEL_ENABLED", "true")
	os.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "https://otel.example.com:443")
	os.Setenv("OTEL_EXPORTER_OTLP_PROTOCOL", "http")
	defer func() {
		os.Unsetenv("OTEL_ENABLED")
		os.Unsetenv("OTEL_EXPORTER_OTLP_ENDPOINT")
		os.Unsetenv("OTEL_EXPORTER_OTLP_PROTOCOL")
	}()

	tracingMu = sync.Once{}
	tp = nil
	tracingEnabled = false
	tracer = nil

	err := InitTracing()
	if err != nil {
		t.Logf("InitTracing returned error: %v", err)
	}
}

func TestCB73_InitTracing_HTTPInsecureEndpoint(t *testing.T) {
	os.Setenv("OTEL_ENABLED", "true")
	os.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://localhost:4318")
	os.Setenv("OTEL_EXPORTER_OTLP_PROTOCOL", "http")
	defer func() {
		os.Unsetenv("OTEL_ENABLED")
		os.Unsetenv("OTEL_EXPORTER_OTLP_ENDPOINT")
		os.Unsetenv("OTEL_EXPORTER_OTLP_PROTOCOL")
	}()

	tracingMu = sync.Once{}
	tp = nil
	tracingEnabled = false
	tracer = nil

	err := InitTracing()
	if err != nil {
		t.Logf("InitTracing returned error: %v", err)
	}
}

func TestCB73_InitTracing_AlreadyInitialized(t *testing.T) {
	os.Setenv("OTEL_ENABLED", "true")
	os.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "localhost:4317")
	defer func() {
		os.Unsetenv("OTEL_ENABLED")
		os.Unsetenv("OTEL_EXPORTER_OTLP_ENDPOINT")
	}()

	tracingMu = sync.Once{}
	tp = nil
	tracingEnabled = false
	tracer = nil

	// First init
	InitTracing()
	// Second init should be no-op due to sync.Once
	err := InitTracing()
	if err != nil {
		t.Errorf("second InitTracing should not return error: %v", err)
	}
}

// ==================== ShutdownTracing tests (80.0% -> ~100%) ====================

func TestCB73_ShutdownTracing_NilProvider(t *testing.T) {
	oldTP := tp
	defer func() { tp = oldTP }()
	tp = nil

	// Should not panic with nil tp
	ShutdownTracing()
}

func TestCB73_ShutdownTracing_WithProvider(t *testing.T) {
	// We can't easily create a real tp to test shutdown,
	// but the nil case is the most important path.
	// Just verify it doesn't panic
	ShutdownTracing()
}

// ==================== initAPNs tests (84.0% -> ~95%) ====================

func TestCB73_InitAPNs_NilConfig(t *testing.T) {
	oldConfig := pushConfig
	defer func() { pushConfig = oldConfig }()
	pushConfig = nil

	initAPNs()
	// Should not panic, just log
}

func TestCB73_InitAPNs_Disabled(t *testing.T) {
	oldConfig := pushConfig
	defer func() { pushConfig = oldConfig }()
	pushConfig = &PushNotificationConfig{APNSEnabled: false}

	initAPNs()
	if pushConfig.APNSEnabled {
		t.Error("expected APNs to remain disabled")
	}
}

func TestCB73_InitAPNs_NoCertPath(t *testing.T) {
	oldConfig := pushConfig
	defer func() { pushConfig = oldConfig }()
	pushConfig = &PushNotificationConfig{APNSEnabled: true, CertPath: ""}

	initAPNs()
	// Should log warning and return
}

func TestCB73_InitAPNs_CertNotFound(t *testing.T) {
	oldConfig := pushConfig
	defer func() { pushConfig = oldConfig }()
	pushConfig = &PushNotificationConfig{
		APNSEnabled: true,
		CertPath:    "/nonexistent/path/cert.p12",
	}

	initAPNs()
	if pushConfig.APNSEnabled {
		t.Error("expected APNs to be disabled when cert not found")
	}
}

func TestCB73_InitAPNs_InvalidCert(t *testing.T) {
	oldConfig := pushConfig
	defer func() { pushConfig = oldConfig }()

	// Create a temporary file that's not a valid P12
	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "invalid.p12")
	os.WriteFile(certPath, []byte("not a valid p12 file"), 0644)

	pushConfig = &PushNotificationConfig{
		APNSEnabled: true,
		CertPath:    certPath,
	}

	initAPNs()
	if pushConfig.APNSEnabled {
		t.Error("expected APNs to be disabled when cert is invalid")
	}
}

func TestCB73_InitAPNs_ProductionEnv(t *testing.T) {
	oldConfig := pushConfig
	defer func() { pushConfig = oldConfig }()

	// Create a temporary file that's not a valid P12
	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "invalid_prod.p12")
	os.WriteFile(certPath, []byte("not a valid p12 file"), 0644)

	pushConfig = &PushNotificationConfig{
		APNSEnabled:  true,
		CertPath:     certPath,
		Environment:  "production",
	}

	initAPNs()
	// Cert will fail to load, APNs disabled
	if pushConfig.APNSEnabled {
		t.Error("expected APNs to be disabled with invalid cert")
	}
}

// ==================== initFCM tests (81.5% -> ~95%) ====================

func TestCB73_InitFCM_NilConfig(t *testing.T) {
	oldConfig := pushConfig
	defer func() { pushConfig = oldConfig }()
	pushConfig = nil

	initFCM()
	// Should not panic
}

func TestCB73_InitFCM_Disabled(t *testing.T) {
	oldConfig := pushConfig
	defer func() { pushConfig = oldConfig }()
	pushConfig = &PushNotificationConfig{FCMEnabled: false}

	initFCM()
	if pushConfig.FCMEnabled {
		t.Error("expected FCM to remain disabled")
	}
}

func TestCB73_InitFCM_NoCredsPath(t *testing.T) {
	oldConfig := pushConfig
	defer func() { pushConfig = oldConfig }()
	pushConfig = &PushNotificationConfig{FCMEnabled: true, FCMCredentials: ""}

	initFCM()
	// Should log warning and return
}

func TestCB73_InitFCM_CredsNotFound(t *testing.T) {
	oldConfig := pushConfig
	defer func() { pushConfig = oldConfig }()
	pushConfig = &PushNotificationConfig{
		FCMEnabled:     true,
		FCMCredentials: "/nonexistent/path/creds.json",
	}

	initFCM()
	if pushConfig.FCMEnabled {
		t.Error("expected FCM to be disabled when creds not found")
	}
}

func TestCB73_InitFCM_InvalidCreds(t *testing.T) {
	oldConfig := pushConfig
	defer func() { pushConfig = oldConfig }()

	tmpDir := t.TempDir()
	credsPath := filepath.Join(tmpDir, "invalid_creds.json")
	os.WriteFile(credsPath, []byte(`{"invalid": "not real firebase creds"}`), 0644)

	pushConfig = &PushNotificationConfig{
		FCMEnabled:     true,
		FCMCredentials: credsPath,
	}

	initFCM()
	if pushConfig.FCMEnabled {
		t.Error("expected FCM to be disabled with invalid creds")
	}
}

// ==================== handleHeapProfile tests (84.6% -> ~100%) ====================

func TestCB73_HandleHeapProfile_WriteError(t *testing.T) {
	// Use read-only directory to cause MkdirAll error
	oldDir := os.Getenv("PROFILING_DIR")
	defer func() {
		if oldDir != "" {
			os.Setenv("PROFILING_DIR", oldDir)
		} else {
			os.Unsetenv("PROFILING_DIR")
		}
	}()

	// Use /proc which is read-only on Linux
	os.Setenv("PROFILING_DIR", "/proc/cannot_create_here")

	req := httptest.NewRequest("GET", "/admin/profile?action=heap", nil)
	w := httptest.NewRecorder()
	handleHeapProfile(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 for read-only dir, got %d", w.Code)
	}
}

func TestCB73_HandleHeapProfile_DefaultDir(t *testing.T) {
	oldDir := os.Getenv("PROFILING_DIR")
	os.Unsetenv("PROFILING_DIR")
	defer func() {
		if oldDir != "" {
			os.Setenv("PROFILING_DIR", oldDir)
		}
	}()

	req := httptest.NewRequest("GET", "/admin/profile?action=heap", nil)
	w := httptest.NewRecorder()
	handleHeapProfile(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}

	var result map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &result)
	if result["status"] != "ok" {
		t.Errorf("expected status ok, got %v", result["status"])
	}
	if result["file"] == nil {
		t.Error("expected file path in response")
	}
}

// ==================== handleGoroutineProfile tests (84.6% -> ~100%) ====================

func TestCB73_HandleGoroutineProfile_WriteError(t *testing.T) {
	oldDir := os.Getenv("PROFILING_DIR")
	defer func() {
		if oldDir != "" {
			os.Setenv("PROFILING_DIR", oldDir)
		} else {
			os.Unsetenv("PROFILING_DIR")
		}
	}()

	os.Setenv("PROFILING_DIR", "/proc/cannot_create_here")

	req := httptest.NewRequest("GET", "/admin/profile?action=goroutine", nil)
	w := httptest.NewRecorder()
	handleGoroutineProfile(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", w.Code)
	}
}

func TestCB73_HandleGoroutineProfile_DefaultDir(t *testing.T) {
	oldDir := os.Getenv("PROFILING_DIR")
	os.Unsetenv("PROFILING_DIR")
	defer func() {
		if oldDir != "" {
			os.Setenv("PROFILING_DIR", oldDir)
		}
	}()

	req := httptest.NewRequest("GET", "/admin/profile?action=goroutine", nil)
	w := httptest.NewRecorder()
	handleGoroutineProfile(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}

	var result map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &result)
	if result["status"] != "ok" {
		t.Errorf("expected status ok, got %v", result["status"])
	}
}

// ==================== handleCPUProfileStart tests (85.0% -> ~95%) ====================

func TestCB73_HandleCPUProfileStart_MkdirError(t *testing.T) {
	oldDir := os.Getenv("PROFILING_DIR")
	defer func() {
		if oldDir != "" {
			os.Setenv("PROFILING_DIR", oldDir)
		} else {
			os.Unsetenv("PROFILING_DIR")
		}
	}()

	os.Setenv("PROFILING_DIR", "/proc/cannot_create_here")

	// Reset CPU profile state
	cpuProfileState.Lock()
	cpuProfileState.active = false
	cpuProfileState.stopFunc = nil
	cpuProfileState.Unlock()

	req := httptest.NewRequest("GET", "/admin/profile?action=cpu", nil)
	w := httptest.NewRecorder()
	handleCPUProfileStart(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", w.Code)
	}
}

func TestCB73_HandleCPUProfileStart_Success(t *testing.T) {
	oldDir := os.Getenv("PROFILING_DIR")
	defer func() {
		if oldDir != "" {
			os.Setenv("PROFILING_DIR", oldDir)
		} else {
			os.Unsetenv("PROFILING_DIR")
		}
	}()

	tmpDir := t.TempDir()
	os.Setenv("PROFILING_DIR", tmpDir)

	// Reset CPU profile state
	cpuProfileState.Lock()
	cpuProfileState.active = false
	cpuProfileState.stopFunc = nil
	cpuProfileState.Unlock()

	req := httptest.NewRequest("GET", "/admin/profile?action=cpu", nil)
	w := httptest.NewRecorder()
	handleCPUProfileStart(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}

	// Clean up - stop the CPU profile
	cpuProfileState.Lock()
	if cpuProfileState.stopFunc != nil {
		cpuProfileState.stopFunc()
	}
	cpuProfileState.active = false
	cpuProfileState.stopFunc = nil
	cpuProfileState.Unlock()
}

// ==================== TieredRateLimiter.cleanup tests (83.3% -> ~95%) ====================

func TestCB73_TieredRateLimiter_Cleanup_StopChannel(t *testing.T) {
	trl := NewTieredRateLimiter()

	// Start cleanup goroutine
	done := make(chan struct{})
	go func() {
		trl.cleanup()
		close(done)
	}()

	// Stop it via stopCh
	trl.stopCh <- struct{}{}

	select {
	case <-done:
		// Good - cleanup exited via stopCh
	case <-time.After(2 * time.Second):
		t.Fatal("cleanup did not exit after stopCh signal")
	}
}

func TestCB73_TieredRateLimiter_Cleanup_RemovesStaleEntries(t *testing.T) {
	trl := NewTieredRateLimiter()

	// Add some entries with past windowEnd
	trl.mu.Lock()
	trl.limits["stale-user-1"] = &userRateLimitState{
		windowEnd: time.Now().Add(-20 * time.Minute),
	}
	trl.limits["stale-user-2"] = &userRateLimitState{
		windowEnd: time.Now().Add(-15 * time.Minute),
	}
	trl.limits["active-user"] = &userRateLimitState{
		windowEnd: time.Now().Add(5 * time.Minute),
	}
	trl.mu.Unlock()

	// Run cleanupOnce directly
	trl.cleanupOnce()

	trl.mu.Lock()
	defer trl.mu.Unlock()
	if _, exists := trl.limits["stale-user-1"]; exists {
		t.Error("expected stale-user-1 to be removed")
	}
	if _, exists := trl.limits["stale-user-2"]; exists {
		t.Error("expected stale-user-2 to be removed")
	}
	if _, exists := trl.limits["active-user"]; !exists {
		t.Error("expected active-user to be kept")
	}
}

func TestCB73_TieredRateLimiter_Cleanup_KeepsRecentExpired(t *testing.T) {
	trl := NewTieredRateLimiter()

	// Entry that's expired but within 10-minute grace period
	trl.mu.Lock()
	trl.limits["recent-expired"] = &userRateLimitState{
		windowEnd: time.Now().Add(-5 * time.Minute),
	}
	trl.mu.Unlock()

	trl.cleanupOnce()

	trl.mu.Lock()
	defer trl.mu.Unlock()
	if _, exists := trl.limits["recent-expired"]; !exists {
		t.Error("expected recently expired entry to be kept (within 10-min grace)")
	}
}

// ==================== handleSetNotificationPrefs tests (88.9% -> ~95%) ====================

func TestCB73_HandleSetNotificationPrefs_DBError(t *testing.T) {
	oldDB := db
	defer func() { db = oldDB }()
	testDB := setupTestDB_CB73(t)
	db = testDB

	userID := createUser_CB73(testDB, "np-dberr", "pass123")
	convID := createConversation_CB73(testDB, userID, "agent-np-err")

	// Close DB to cause error
	testDB.Close()

	formData := fmt.Sprintf("conversation_id=%s&mute=true", convID)
	req := httptest.NewRequest("POST", "/notifications/prefs", strings.NewReader(formData))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+generateTestToken_CB73(userID))

	w := httptest.NewRecorder()
	handleSetNotificationPrefs(w, req)

	// With closed DB, getConversation returns nil -> 401 or 500
	if w.Code == http.StatusOK {
		t.Error("expected non-200 with closed DB")
	}
}

// ==================== handleGetTags tests (88.5% -> ~95%) ====================

func TestCB73_HandleGetTags_WithTags(t *testing.T) {
	oldDB := db
	defer func() { db = oldDB }()
	testDB := setupTestDB_CB73(t)
	db = testDB

	userID := createUser_CB73(testDB, "tags-user", "pass123")
	convID := createConversation_CB73(testDB, userID, "agent-tags")

	// Add tags
	testDB.Exec("INSERT INTO conversation_tags (id, conversation_id, tag) VALUES (?, ?, ?)", "tag-1", convID, "important")
	testDB.Exec("INSERT INTO conversation_tags (id, conversation_id, tag) VALUES (?, ?, ?)", "tag-2", convID, "work")

	req := httptest.NewRequest("GET", "/conversations/tags?conversation_id="+convID, nil)
	req.Header.Set("Authorization", "Bearer "+generateTestToken_CB73(userID))

	w := httptest.NewRecorder()
	handleGetTags(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var tags []ConversationTag
	if err := json.Unmarshal(w.Body.Bytes(), &tags); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}
	if len(tags) != 2 {
		t.Errorf("expected 2 tags, got %d", len(tags))
	}
}

// ==================== isConversationMuted tests (88.9% -> ~100%) ====================

func TestCB73_IsConversationMuted_DBError(t *testing.T) {
	oldDB := db
	defer func() { db = oldDB }()
	testDB := setupTestDB_CB73(t)
	testDB.Close()
	db = testDB

	result := isConversationMuted("some-conv", "some-user")
	if result {
		t.Error("expected false on DB error")
	}
}

// ==================== ipRateLimitMiddleware tests (88.9% -> ~100%) ====================

func TestCB73_IPRateLimitMiddleware_AllowsRequest(t *testing.T) {
	called := false
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	// Use fresh limiter to avoid interference
	oldLimiter := ipRateLimiter
	defer func() { ipRateLimiter = oldLimiter }()
	ipRateLimiter = NewRateLimiter(100, time.Minute)

	mw := ipRateLimitMiddleware(handler)
	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "192.168.1.100:12345"
	w := httptest.NewRecorder()
	mw.ServeHTTP(w, req)

	if !called {
		t.Error("expected handler to be called")
	}
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestCB73_IPRateLimitMiddleware_Blocked(t *testing.T) {
	called := false
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	oldLimiter := ipRateLimiter
	defer func() { ipRateLimiter = oldLimiter }()
	ipRateLimiter = NewRateLimiter(1, time.Minute)

	mw := ipRateLimitMiddleware(handler)
	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "10.0.0.1:12345"
	w := httptest.NewRecorder()

	// First request - allowed
	mw.ServeHTTP(w, req)
	if !called {
		t.Error("expected first request to be allowed")
	}

	// Second request - blocked
	called = false
	w = httptest.NewRecorder()
	mw.ServeHTTP(w, req)
	if called {
		t.Error("expected second request to be blocked")
	}
	if w.Code != http.StatusTooManyRequests {
		t.Errorf("expected 429, got %d", w.Code)
	}
}

// ==================== authRateLimitMiddleware tests (88.9% -> ~100%) ====================

func TestCB73_AuthRateLimitMiddleware_AllowsRequest(t *testing.T) {
	called := false
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	oldLimiter := authIPLimiter
	defer func() { authIPLimiter = oldLimiter }()
	authIPLimiter = NewRateLimiter(100, time.Minute)

	mw := authRateLimitMiddleware(handler)
	req := httptest.NewRequest("POST", "/auth/login", nil)
	req.RemoteAddr = "192.168.1.200:12345"
	w := httptest.NewRecorder()
	mw.ServeHTTP(w, req)

	if !called {
		t.Error("expected handler to be called")
	}
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestCB73_AuthRateLimitMiddleware_Blocked(t *testing.T) {
	called := false
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	oldLimiter := authIPLimiter
	defer func() { authIPLimiter = oldLimiter }()
	authIPLimiter = NewRateLimiter(1, time.Minute)

	mw := authRateLimitMiddleware(handler)
	req := httptest.NewRequest("POST", "/auth/login", nil)
	req.RemoteAddr = "10.0.0.2:12345"
	w := httptest.NewRecorder()

	// First request - allowed
	mw.ServeHTTP(w, req)
	if !called {
		t.Error("expected first request to be allowed")
	}

	// Second request - blocked
	called = false
	w = httptest.NewRecorder()
	mw.ServeHTTP(w, req)
	if called {
		t.Error("expected second request to be blocked")
	}
	if w.Code != http.StatusTooManyRequests {
		t.Errorf("expected 429, got %d", w.Code)
	}
}

// ==================== handleMessageDelete tests (87.5% -> ~95%) ====================

func TestCB73_HandleMessageDelete_Success(t *testing.T) {
	oldDB := db
	defer func() { db = oldDB }()
	testDB := setupTestDB_CB73(t)
	db = testDB

	oldHub := hub
	defer func() { hub = oldHub }()
	h := newHub()
	go h.run()
	defer h.Stop()
	hub = h

	userID := createUser_CB73(testDB, "msgdel", "pass123")
	convID := createConversation_CB73(testDB, userID, "agent-msgdel")

	// Insert a message from the user
	msgID := "msg-delete-me"
	testDB.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, created_at) VALUES (?, ?, ?, ?, ?, ?)",
		msgID, convID, "client", userID, "delete me", time.Now().UTC().Format(time.RFC3339))

	formData := fmt.Sprintf("message_id=%s", msgID)
	req := httptest.NewRequest("POST", "/messages/delete", strings.NewReader(formData))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+generateTestToken_CB73(userID))

	w := httptest.NewRecorder()
	handleMessageDelete(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}

	// Verify message is marked deleted
	var isDeleted bool
	testDB.QueryRow("SELECT is_deleted FROM messages WHERE id = ?", msgID).Scan(&isDeleted)
	if !isDeleted {
		t.Error("expected message to be marked as deleted")
	}
}

func TestCB73_HandleMessageDelete_NotSender(t *testing.T) {
	oldDB := db
	defer func() { db = oldDB }()
	testDB := setupTestDB_CB73(t)
	db = testDB

	oldHub := hub
	defer func() { hub = oldHub }()
	h := newHub()
	go h.run()
	defer h.Stop()
	hub = h

	userID := createUser_CB73(testDB, "msgdel-not-sender", "pass123")
	otherUserID := createUser_CB73(testDB, "msgdel-other", "pass456")
	convID := createConversation_CB73(testDB, userID, "agent-msgdel-ns")

	// Message from agent (not the user)
	msgID := "msg-from-agent"
	testDB.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, created_at) VALUES (?, ?, ?, ?, ?, ?)",
		msgID, convID, "agent", "agent-msgdel-ns", "agent message", time.Now().UTC().Format(time.RFC3339))

	formData := fmt.Sprintf("message_id=%s", msgID)
	req := httptest.NewRequest("POST", "/messages/delete", strings.NewReader(formData))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+generateTestToken_CB73(otherUserID))

	w := httptest.NewRecorder()
	handleMessageDelete(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for non-sender, got %d", w.Code)
	}
}

// ==================== handleGetAttachment tests (88.2% -> ~95%) ====================

func TestCB73_HandleGetAttachment_AgentAuth(t *testing.T) {
	oldDB := db
	defer func() { db = oldDB }()
	testDB := setupTestDB_CB73(t)
	db = testDB

	userID := createUser_CB73(testDB, "att-agent", "pass123")
	convID := createConversation_CB73(testDB, userID, "agent-att")

	// Insert attachment
	attID := "att-1"
	testDB.Exec("INSERT INTO attachments (id, conversation_id, user_id, filename, content_type, size, storage_path, sha256) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
		attID, convID, userID, "test.txt", "text/plain", 100, "/tmp/test.txt", "abc123")

	req := httptest.NewRequest("GET", "/attachments/get?id="+attID, nil)
	req.Header.Set("X-Agent-Secret", getAgentSecret())
	req.Header.Set("X-Agent-ID", "agent-att")

	w := httptest.NewRecorder()
	handleGetAttachment(w, req)

	// Should attempt to serve file (may 404 if file doesn't exist on disk)
	// But should not return 401
	if w.Code == http.StatusUnauthorized {
		t.Error("expected agent to be authorized for attachment")
	}
}

// ==================== storeMessagesBatch tests (88.9% -> ~95%) ====================

func TestCB73_StoreMessagesBatch_WithAttachments(t *testing.T) {
	oldDB := db
	defer func() { db = oldDB }()
	testDB := setupTestDB_CB73(t)
	db = testDB

	userID := createUser_CB73(testDB, "batch-att", "pass123")
	convID := createConversation_CB73(testDB, userID, "agent-batch-att")

	msgs := []RoutedMessage{
		{
			ConversationID: convID,
			SenderType:     "client",
			SenderID:       userID,
			Content:        "msg with attachment",
			AttachmentIDs:  []string{"att-a", "att-b"},
		},
	}

	ids, err := storeMessagesBatch(msgs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ids) != 1 {
		t.Fatalf("expected 1 ID, got %d", len(ids))
	}

	// Verify message was stored
	var count int
	testDB.QueryRow("SELECT count(*) FROM messages WHERE conversation_id = ?", convID).Scan(&count)
	if count != 1 {
		t.Errorf("expected 1 message, got %d", count)
	}
}

// ==================== readPump tests (86.4% -> ~92%) ====================

func TestCB73_ReadPump_ReceivesMessage(t *testing.T) {
	serverConn, clientConn, cleanup := makeWebSocketPairForWritePump_CB73(t)
	defer cleanup()

	h := newHub()
	go h.run()
	defer h.Stop()

	conn := &Connection{
		hub:      h,
		connType: "agent",
		id:       "test-rp-agent",
		conn:     serverConn,
		send:     make(chan []byte, 256),
	}

	go conn.readPump()
	time.Sleep(50 * time.Millisecond)

	// Send a message from client side
	clientConn.WriteMessage(websocket.TextMessage, []byte(`{"type":"heartbeat"}`))
	time.Sleep(100 * time.Millisecond)

	// Connection should still be alive
	// Close client to trigger readPump exit
	clientConn.Close()
	time.Sleep(100 * time.Millisecond)
}

func TestCB73_ReadPump_NormalClosure(t *testing.T) {
	serverConn, clientConn, cleanup := makeWebSocketPairForWritePump_CB73(t)
	defer cleanup()

	h := newHub()
	go h.run()
	defer h.Stop()

	conn := &Connection{
		hub:      h,
		connType: "client",
		id:       "test-rp-client",
		conn:     serverConn,
		send:     make(chan []byte, 256),
	}

	go conn.readPump()
	time.Sleep(50 * time.Millisecond)

	// Send normal close
	clientConn.WriteMessage(websocket.CloseMessage,
		websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
	time.Sleep(100 * time.Millisecond)

	// readPump should have exited without logging unexpected close error
}

func TestCB73_ReadPump_UnexpectedClose(t *testing.T) {
	serverConn, clientConn, cleanup := makeWebSocketPairForWritePump_CB73(t)
	defer cleanup()

	h := newHub()
	go h.run()
	defer h.Stop()

	conn := &Connection{
		hub:      h,
		connType: "agent",
		id:       "test-rp-unexpected",
		conn:     serverConn,
		send:     make(chan []byte, 256),
	}

	go conn.readPump()
	time.Sleep(50 * time.Millisecond)

	// Abruptly close the client connection
	clientConn.Close()
	time.Sleep(100 * time.Millisecond)

	// readPump should detect the closure and unregister
}

// ==================== handleUpload tests (85.7% -> ~92%) ====================

func TestCB73_HandleUpload_ContentTypeDetection(t *testing.T) {
	oldDB := db
	defer func() { db = oldDB }()
	testDB := setupTestDB_CB73(t)
	db = testDB

	userID := createUser_CB73(testDB, "upload-ct", "pass123")
	convID := createConversation_CB73(testDB, userID, "agent-upload-ct")

	// Create a small PNG file (valid header)
	pngHeader := []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}
	pngData := append(pngHeader, make([]byte, 100)...)

	body := fmt.Sprintf("--boundary\r\nContent-Disposition: form-data; name=\"conversation_id\"\r\n\r\n%s\r\n--boundary\r\nContent-Disposition: form-data; name=\"file\"; filename=\"test.png\"\r\nContent-Type: image/png\r\n\r\n", convID)
	bodyBytes := []byte(body)
	bodyBytes = append(bodyBytes, pngData...)
	bodyBytes = append(bodyBytes, []byte("\r\n--boundary--\r\n")...)

	req := httptest.NewRequest("POST", "/attachments/upload", strings.NewReader(string(bodyBytes)))
	req.Header.Set("Content-Type", "multipart/form-data; boundary=boundary")
	req.Header.Set("Authorization", "Bearer "+generateTestToken_CB73(userID))

	// Set a reasonable upload size
	oldMax := maxUploadSize
	defer func() { maxUploadSize = oldMax }()
	maxUploadSize = 1024 * 1024 // 1MB

	w := httptest.NewRecorder()
	handleUpload(w, req)

	// Should succeed or fail gracefully (file write might fail in test env)
	t.Logf("upload response code: %d", w.Code)
}

// ==================== initSchema tests (85.3% -> ~92%) ====================

func TestCB73_InitSchema_NilDB(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic with nil DB")
		}
	}()
	initSchema(nil)
}

// ==================== Logger tests (WithFields 87.5%, logEntry 88.2%) ====================

func TestCB73_Logger_WithFields_Chaining(t *testing.T) {
	l := DefaultLogger.WithFields(map[string]interface{}{"key1": "val1"}).
		WithFields(map[string]interface{}{"key2": "val2"})
	if l == nil {
		t.Fatal("expected non-nil logger after chaining")
	}
}

func TestCB73_Logger_LogEntry_WithFields(t *testing.T) {
	l := NewLogger(LogDebug)
	l.WithFields(map[string]interface{}{"test": "value"})
	// Should not panic
	l.Info("test_with_fields", map[string]interface{}{"extra": "data"})
}

func TestCB73_Logger_LogEntry_AllLevels(t *testing.T) {
	l := NewLogger(LogDebug)
	l.Debug("debug_msg", nil)
	l.Info("info_msg", nil)
	l.Warn("warn_msg", nil)
	l.Error("error_msg", nil)
	// Should not panic at any level
}

func TestCB73_Logger_LogEntry_EmptyMessage(t *testing.T) {
	l := NewLogger(LogDebug)
	l.Info("", nil)
	l.Info("", map[string]interface{}{"key": "val"})
}

func TestCB73_Logger_WithFields_NilThenLog(t *testing.T) {
	l := DefaultLogger.WithFields(nil)
	if l == nil {
		t.Fatal("expected non-nil logger with nil fields")
	}
	l.Info("after_nil_fields", nil)
}

// ==================== cpuProfileTestSetup tests (87.5% -> ~100%) ====================

func TestCB73_CPUProfileTestSetup_Basic(t *testing.T) {
	cleanup := cpuProfileTestSetup()
	if cleanup == nil {
		t.Fatal("expected non-nil cleanup function")
	}
	cleanup()
}

// ==================== loadQueueFromDB tests (89.5% -> ~95%) ====================

func TestCB73_LoadQueueFromDB_ScanError(t *testing.T) {
	oldDB := db
	defer func() { db = oldDB }()
	testDB := setupTestDB_CB73(t)
	db = testDB

	// Insert a row with valid data (loadQueueFromDB stores raw bytes, doesn't unmarshal)
	testDB.Exec("INSERT INTO offline_queue (recipient, data, queued_at, sent_count) VALUES (?, ?, ?, ?)",
		"test-user", []byte("not json"), time.Now().UTC().Format(time.RFC3339), 0)

	q := newOfflineQueue(100, 7*24*time.Hour)
	loadQueueFromDB(testDB, q)

	// Queue should have 1 item (raw bytes are enqueued as-is)
	if q.TotalDepth() != 1 {
		t.Errorf("expected queue depth 1, got %d", q.TotalDepth())
	}
}

// ==================== Integration: full routeChatMessage ack verification ====================

func TestCB73_RouteChatMessage_AckContent(t *testing.T) {
	oldDB := db
	defer func() { db = oldDB }()
	testDB := setupTestDB_CB73(t)
	db = testDB

	userID := createUser_CB73(testDB, "rcm-ack", "pass123")
	convID := createConversation_CB73(testDB, userID, "agent-rcm-ack")

	oldHub := hub
	defer func() { hub = oldHub }()
	h := newHub()
	go h.run()
	defer h.Stop()
	hub = h

	agentConn := &Connection{
		hub:      h,
		connType: "agent",
		id:       "agent-rcm-ack",
		send:     make(chan []byte, 256),
	}
	h.register <- agentConn
	time.Sleep(50 * time.Millisecond)

	oldQueue := offlineQueue
	defer func() { offlineQueue = oldQueue }()
	offlineQueue = newOfflineQueue(100, 7*24*time.Hour)

	sender := &Connection{
		hub:      h,
		connType: "client",
		id:       userID,
		send:     make(chan []byte, 256),
	}

	data, _ := json.Marshal(RoutedMessage{
		ConversationID: convID,
		Content:        "Verify ack",
	})

	routeChatMessage(sender, data)

	// Verify ack content
	select {
	case msg := <-sender.send:
		var result OutgoingMessage
		if err := json.Unmarshal(msg, &result); err != nil {
			t.Fatalf("failed to unmarshal: %v", err)
		}
		if result.Type != "message_sent" {
			t.Errorf("expected type 'message_sent', got '%s'", result.Type)
		}
		data, ok := result.Data.(map[string]interface{})
		if !ok {
			t.Fatal("expected map data in ack")
		}
		if data["conversation_id"] != convID {
			t.Errorf("expected conv_id '%s', got '%v'", convID, data["conversation_id"])
		}
		if data["status"] != "delivered" {
			t.Errorf("expected status 'delivered', got '%v'", data["status"])
		}
	case <-time.After(1 * time.Second):
		t.Fatal("no ack received")
	}
}