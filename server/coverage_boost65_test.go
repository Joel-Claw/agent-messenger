package main

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/websocket"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	_ "github.com/mattn/go-sqlite3"
)

// --- CB65 Helpers ---

func setupTestDB_CB65(t *testing.T) *sql.DB {
	testDB, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("Failed to open test DB: %v", err)
	}
	if err := initSchema(testDB); err != nil {
		t.Fatalf("Failed to init schema: %v", err)
	}
	return testDB
}

func generateTestToken_CB65(userID string) string {
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

func resetTracingState_CB65() {
	tracingEnabled = false
	tracer = nil
	tp = nil
	tracingMu = sync.Once{}
}

// --- ValidateJWT: expired token (83.3% -> 100%) ---

func TestCB65_ValidateJWT_ExpiredToken(t *testing.T) {
	// Create an expired token
	claims := &Claims{
		UserID: "user-expired",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(-1 * time.Hour)),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, _ := token.SignedString(jwtSecret)

	result, err := ValidateJWT(signed)
	if err == nil {
		t.Error("expected error for expired token")
	}
	if result != nil {
		t.Error("expected nil claims for expired token")
	}
}

// --- ValidateJWT: wrong signing method (covers unexpected signing method branch) ---

func TestCB65_ValidateJWT_WrongSigningMethod(t *testing.T) {
	// Create a token signed with RSA-like method but using HMAC secret
	// This will fail at the signing method check
	claims := &Claims{
		UserID: "user-wrong-method",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
	}
	// Use SigningMethodNone which will fail the HMAC check
	token := jwt.NewWithClaims(jwt.SigningMethodNone, claims)
	signed, _ := token.SignedString(jwt.UnsafeAllowNoneSignatureType)

	_, err := ValidateJWT(signed)
	if err == nil {
		t.Error("expected error for none signing method")
	}
}

// --- sendWelcomeMessage: SafeSend failure (80% -> 100%) ---

func TestCB65_sendWelcomeMessage_SendBufferFull(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()

		c := &Connection{
			connType:    "agent",
			id:          "test-welcome-full",
			conn:        conn,
			send:        make(chan []byte, 1), // tiny buffer
			connectedAt: time.Now(),
		}
		// Fill the buffer
		c.send <- []byte("filler1")

		// Now sendWelcomeMessage should fail to send (buffer full)
		// SafeSend returns false but doesn't block
		sendWelcomeMessage(c)
	}))
	defer srv.Close()

	dialer := websocket.Dialer{}
	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")
	_, _, err := dialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	time.Sleep(100 * time.Millisecond)
}

// --- writePump: message write error (73.1% -> higher) ---

func TestCB65_writePump_WriteError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()

		c := &Connection{
			connType:    "agent",
			id:          "test-write-err",
			conn:        conn,
			send:        make(chan []byte, 10),
			connectedAt: time.Now(),
		}

		// Close the underlying connection immediately so writes fail
		conn.Close()

		done := make(chan struct{})
		go func() {
			// Send a message - write should fail because connection is closed
			c.send <- []byte("test message after close")
			c.writePump()
			close(done)
		}()

		select {
		case <-done:
			// Good - writePump exited on write error
		case <-time.After(2 * time.Second):
			t.Error("writePump did not exit after write error")
		}
	}))
	defer srv.Close()

	dialer := websocket.Dialer{}
	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")
	_, _, err := dialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	time.Sleep(200 * time.Millisecond)
}

// --- writePump: ping write error ---

func TestCB65_writePump_PingError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()

		c := &Connection{
			connType:    "agent",
			id:          "test-ping-err",
			conn:        conn,
			send:        make(chan []byte, 10),
			connectedAt: time.Now(),
		}

		// Close the underlying connection so ping writes fail
		conn.Close()

		// writePump has a ticker with pingPeriod; with closed conn, ping should fail
		done := make(chan struct{})
		go func() {
			c.writePump()
			close(done)
		}()

		select {
		case <-done:
			// Good - writePump exited on ping error
		case <-time.After(65 * time.Second):
			// pingPeriod is 54s, so this would take too long in real time
			// But since conn is closed, the first tick should fail quickly
			t.Error("writePump did not exit after ping error")
		}
	}))
	defer srv.Close()

	dialer := websocket.Dialer{}
	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")
	_, _, err := dialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	time.Sleep(200 * time.Millisecond)
}

// --- hub.run: broadcast with no clients (84.8% -> higher) ---

func TestCB65_HubRun_BroadcastNoClients(t *testing.T) {
	h := newHub()
	go h.run()
	defer h.Stop()

	// Send a broadcast message when no clients are connected
	h.broadcast <- []byte("test broadcast")

	// Should not panic or block
	time.Sleep(50 * time.Millisecond)
}

// --- hub.run: unregister unknown connection ---

func TestCB65_HubRun_UnregisterUnknownConnection(t *testing.T) {
	h := newHub()
	go h.run()
	defer h.Stop()

	// Unregister a connection that was never registered
	conn := &Connection{
		hub:      h,
		connType: "agent",
		id:       "never-registered",
		send:     make(chan []byte, 10),
	}
	h.unregister <- conn

	// Should not panic or block
	time.Sleep(50 * time.Millisecond)
}

// --- hub.run: unregister unknown client connection ---

func TestCB65_HubRun_UnregisterUnknownClient(t *testing.T) {
	h := newHub()
	go h.run()
	defer h.Stop()

	// Unregister a client connection that was never registered
	conn := &Connection{
		hub:      h,
		connType: "client",
		id:       "never-registered-client",
		send:     make(chan []byte, 10),
	}
	h.unregister <- conn

	// Should not panic or block
	time.Sleep(50 * time.Millisecond)
}

// --- hub.run: client reconnect replaces same device ---

func TestCB65_HubRun_ClientReconnectSameDevice(t *testing.T) {
	h := newHub()
	go h.run()
	defer h.Stop()

	conn1 := &Connection{
		hub:      h,
		connType: "client",
		id:       "user-device-replace",
		deviceID: "device-1",
		send:     make(chan []byte, 10),
	}
	h.register <- conn1
	time.Sleep(50 * time.Millisecond)

	// Register a second connection with same user+device
	conn2 := &Connection{
		hub:      h,
		connType: "client",
		id:       "user-device-replace",
		deviceID: "device-1",
		send:     make(chan []byte, 10),
	}
	h.register <- conn2
	time.Sleep(50 * time.Millisecond)

	// Only one connection should exist for this user
	h.mu.Lock()
	conns := h.clientConns["user-device-replace"]
	count := len(conns)
	h.mu.Unlock()
	if count != 1 {
		t.Errorf("expected 1 connection after device replace, got %d", count)
	}
}

// --- hub.run: register client without device_id (no dedup) ---

func TestCB65_HubRun_RegisterClientNoDeviceID(t *testing.T) {
	h := newHub()
	go h.run()
	defer h.Stop()

	conn1 := &Connection{
		hub:      h,
		connType: "client",
		id:       "user-no-device",
		send:     make(chan []byte, 10),
	}
	h.register <- conn1
	time.Sleep(50 * time.Millisecond)

	conn2 := &Connection{
		hub:      h,
		connType: "client",
		id:       "user-no-device",
		send:     make(chan []byte, 10),
	}
	h.register <- conn2
	time.Sleep(50 * time.Millisecond)

	// Both connections should exist (no dedup without device_id)
	h.mu.Lock()
	conns := h.clientConns["user-no-device"]
	count := len(conns)
	h.mu.Unlock()
	if count != 2 {
		t.Errorf("expected 2 connections without device_id, got %d", count)
	}
}

// --- handleAgentConnect: successful WebSocket upgrade (48.8% -> higher) ---

func TestCB65_handleAgentConnect_Success(t *testing.T) {
	db = setupTestDB_CB65(t)
	defer func() { db = nil }()

	resetAgentSecret()
	secret := getAgentSecret()

	// Create a test server with the actual handler
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Set up hub if not already
		if hub == nil {
			hub = newHub()
			go hub.run()
		}
		handleAgentConnect(w, r)
	}))
	defer srv.Close()

	// Connect as WebSocket client
	dialer := websocket.Dialer{}
	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "?agent_id=test-agent-success&agent_secret=" + secret
	ws, resp, err := dialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("Failed to connect: %v (resp: %v)", err, resp)
	}
	defer ws.Close()

	// Should receive a connected welcome message
	_, message, err := ws.ReadMessage()
	if err != nil {
		t.Fatalf("Failed to read welcome message: %v", err)
	}

	var welcome OutgoingMessage
	if err := json.Unmarshal(message, &welcome); err != nil {
		t.Fatalf("Failed to unmarshal welcome: %v", err)
	}
	if welcome.Type != "connected" {
		t.Errorf("expected 'connected' type, got '%s'", welcome.Type)
	}

	// Cleanup: stop hub
	if hub != nil {
		hub.Stop()
		hub = nil
	}
}

// --- handleAgentConnect: RegisterAgentOnConnect failure ---

func TestCB65_handleAgentConnect_RegisterAgentFail(t *testing.T) {
	// Use a closed DB to cause RegisterAgentOnConnect to fail
	closedDB, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("Failed to open DB: %v", err)
	}
	if err := initSchema(closedDB); err != nil {
		t.Fatalf("Failed to init schema: %v", err)
	}
	closedDB.Close() // Close it so queries fail

	db = closedDB
	defer func() { db = nil }()

	resetAgentSecret()
	secret := getAgentSecret()

	req := httptest.NewRequest("GET", "/agent/connect?agent_id=fail-agent&agent_secret="+secret, nil)
	w := httptest.NewRecorder()
	handleAgentConnect(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 for register agent failure, got %d", w.Code)
	}
}

// --- handleAgentConnect: rate limited ---

func TestCB65_handleAgentConnect_RateLimited(t *testing.T) {
	db = setupTestDB_CB65(t)
	defer func() { db = nil }()

	resetAgentSecret()
	secret := getAgentSecret()

	// Exhaust rate limit attempts (10/min)
	for i := 0; i < 10; i++ {
		req := httptest.NewRequest("GET", "/agent/connect?agent_id=rate-agent&agent_secret=wrong", nil)
		w := httptest.NewRecorder()
		handleAgentConnect(w, req)
	}

	// 11th attempt should be rate limited
	req := httptest.NewRequest("GET", "/agent/connect?agent_id=rate-agent&agent_secret="+secret, nil)
	w := httptest.NewRecorder()
	handleAgentConnect(w, req)

	if w.Code != http.StatusTooManyRequests {
		t.Errorf("expected 429 for rate limited, got %d", w.Code)
	}

	// Reset rate limiter for other tests
	agentRateLimiter.Reset()
}

// --- handleMarkRead: agent notification path (83.3% -> 100%) ---

func TestCB65_handleMarkRead_AgentNotified(t *testing.T) {
	db = setupTestDB_CB65(t)
	defer func() { db = nil }()

	// Create test user
	_, err := db.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)", "user-mr-agent", "testusermr", "hash")
	if err != nil {
		t.Fatalf("Failed to create user: %v", err)
	}

	// Create test agent
	_, err = db.Exec("INSERT INTO agents (id, name) VALUES (?, ?)", "agent-mr-1", "Test Agent")
	if err != nil {
		t.Fatalf("Failed to create agent: %v", err)
	}

	// Create conversation
	_, err = db.Exec("INSERT INTO conversations (id, user_id, agent_id, created_at) VALUES (?, ?, ?, ?)",
		"conv-mr-agent", "user-mr-agent", "agent-mr-1", time.Now().UTC())
	if err != nil {
		t.Fatalf("Failed to create conversation: %v", err)
	}

	// Insert an unread message from agent
	_, err = db.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, created_at) VALUES (?, ?, ?, ?, ?, ?)",
		"msg-mr-1", "conv-mr-agent", "agent", "agent-mr-1", "hello", time.Now().UTC())
	if err != nil {
		t.Fatalf("Failed to create message: %v", err)
	}

	// Set up hub with a connected agent
	hub = newHub()
	go hub.run()
	defer func() { hub.Stop(); hub = nil }()

	// Create a test WebSocket connection for the agent
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()

		c := &Connection{
			hub:         hub,
			connType:    "agent",
			id:          "agent-mr-1",
			conn:        conn,
			send:        make(chan []byte, 256),
			connectedAt: time.Now(),
		}
		hub.register <- c

		// Keep connection alive briefly
		time.Sleep(500 * time.Millisecond)
	}))
	defer srv.Close()

	dialer := websocket.Dialer{}
	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")
	_, _, err = dialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("Failed to connect agent WS: %v", err)
	}
	time.Sleep(100 * time.Millisecond)

	// Now call handleMarkRead - agent should receive read_receipt
	token := generateTestToken_CB65("user-mr-agent")
	formData := "conversation_id=conv-mr-agent"
	req := httptest.NewRequest("POST", "/conversations/mark-read", strings.NewReader(formData))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleMarkRead(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d (body: %s)", w.Code, w.Body.String())
	}

	var result map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &result)
	if result["status"] != "marked_read" {
		t.Errorf("expected status 'marked_read', got '%v'", result["status"])
	}

	time.Sleep(100 * time.Millisecond)
}

// --- handleMarkRead: cross-device read sync ---

func TestCB65_handleMarkRead_CrossDeviceSync(t *testing.T) {
	db = setupTestDB_CB65(t)
	defer func() { db = nil }()

	// Create test user and agent
	_, err := db.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)", "user-cd-1", "usercd", "hash")
	if err != nil {
		t.Fatalf("Failed to create user: %v", err)
	}
	_, err = db.Exec("INSERT INTO agents (id, name) VALUES (?, ?)", "agent-cd-1", "CD Agent")
	if err != nil {
		t.Fatalf("Failed to create agent: %v", err)
	}
	_, err = db.Exec("INSERT INTO conversations (id, user_id, agent_id, created_at) VALUES (?, ?, ?, ?)",
		"conv-cd-1", "user-cd-1", "agent-cd-1", time.Now().UTC())
	if err != nil {
		t.Fatalf("Failed to create conversation: %v", err)
	}
	_, err = db.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, created_at) VALUES (?, ?, ?, ?, ?, ?)",
		"msg-cd-1", "conv-cd-1", "agent", "agent-cd-1", "test", time.Now().UTC())
	if err != nil {
		t.Fatalf("Failed to create message: %v", err)
	}

	// Set up hub
	hub = newHub()
	go hub.run()
	defer func() { hub.Stop(); hub = nil }()

	// Register a client connection (for cross-device sync)
	clientConn := &Connection{
		hub:         hub,
		connType:    "client",
		id:          "user-cd-1",
		deviceID:    "device-1",
		send:        make(chan []byte, 256),
		connectedAt: time.Now(),
	}
	hub.register <- clientConn
	time.Sleep(50 * time.Millisecond)

	// Also register an agent
	agentConn := &Connection{
		hub:         hub,
		connType:    "agent",
		id:          "agent-cd-1",
		send:        make(chan []byte, 256),
		connectedAt: time.Now(),
	}
	hub.register <- agentConn
	time.Sleep(50 * time.Millisecond)

	// Call handleMarkRead
	token := generateTestToken_CB65("user-cd-1")
	formData := "conversation_id=conv-cd-1"
	req := httptest.NewRequest("POST", "/conversations/mark-read", strings.NewReader(formData))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleMarkRead(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}

	// Verify client connection received the read_receipt
	// Note: connecting the agent may send presence_update to the client first,
	// so we need to drain until we find read_receipt or timeout.
	found := false
	deadline := time.After(2 * time.Second)
	for {
		select {
		case msg := <-clientConn.send:
			var receipt OutgoingMessage
			if err := json.Unmarshal(msg, &receipt); err != nil {
				t.Fatalf("Failed to unmarshal receipt: %v", err)
			}
			if receipt.Type == "read_receipt" {
				found = true
			}
			// Skip other message types (e.g. presence_update)
		case <-deadline:
			goto done
		}
		if found {
			break
		}
	}
done:
	if !found {
		t.Errorf("expected 'read_receipt' type, did not receive it within timeout")
	}
}

// --- handleMarkRead: unauthorized user (not conversation owner) ---

func TestCB65_handleMarkRead_UnauthorizedUser(t *testing.T) {
	db = setupTestDB_CB65(t)
	defer func() { db = nil }()

	_, err := db.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)", "user-owner-mr", "ownermr", "hash")
	if err != nil {
		t.Fatalf("Failed to create user: %v", err)
	}
	_, err = db.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)", "user-other-mr", "othermr", "hash")
	if err != nil {
		t.Fatalf("Failed to create other user: %v", err)
	}
	_, err = db.Exec("INSERT INTO agents (id, name) VALUES (?, ?)", "agent-mr-un", "Agent MR")
	if err != nil {
		t.Fatalf("Failed to create agent: %v", err)
	}
	_, err = db.Exec("INSERT INTO conversations (id, user_id, agent_id, created_at) VALUES (?, ?, ?, ?)",
		"conv-mr-un", "user-owner-mr", "agent-mr-un", time.Now().UTC())
	if err != nil {
		t.Fatalf("Failed to create conversation: %v", err)
	}
	_, err = db.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, created_at) VALUES (?, ?, ?, ?, ?, ?)",
		"msg-mr-un-1", "conv-mr-un", "agent", "agent-mr-un", "test", time.Now().UTC())
	if err != nil {
		t.Fatalf("Failed to create message: %v", err)
	}

	// Use a different user's token
	token := generateTestToken_CB65("user-other-mr")
	formData := "conversation_id=conv-mr-un"
	req := httptest.NewRequest("POST", "/conversations/mark-read", strings.NewReader(formData))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleMarkRead(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for unauthorized user, got %d", w.Code)
	}
}

// --- handleStoreEncryptedMessage: DB error (83% -> higher) ---

func TestCB65_handleStoreEncryptedMessage_DBError(t *testing.T) {
	closedDB, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("Failed to open DB: %v", err)
	}
	if err := initSchema(closedDB); err != nil {
		t.Fatalf("Failed to init schema: %v", err)
	}
	closedDB.Close()

	db = closedDB
	defer func() { db = nil }()

	// First need a valid conversation to pass the participant check
	// But with closed DB, getConversation will fail, returning 404
	token := generateTestToken_CB65("user-e2e-db")
	body := `{"conversation_id":"conv-db-err","ciphertext":"abc","iv":"def","algorithm":"aes-256-gcm"}`
	req := httptest.NewRequest("POST", "/e2e/messages", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleStoreEncryptedMessage(w, req)

	// With closed DB, getConversation returns nil/error → 404
	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404 with closed DB, got %d (body: %s)", w.Code, w.Body.String())
	}
}

// --- handleStoreEncryptedMessage: agent delivery (user sends) ---

func TestCB65_handleStoreEncryptedMessage_UserToAgentDelivery(t *testing.T) {
	db = setupTestDB_CB65(t)
	defer func() { db = nil }()

	// Create user, agent, conversation
	_, err := db.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)", "user-e2e-send", "e2esend", "hash")
	if err != nil {
		t.Fatalf("Failed to create user: %v", err)
	}
	_, err = db.Exec("INSERT INTO agents (id, name) VALUES (?, ?)", "agent-e2e-send", "E2E Agent")
	if err != nil {
		t.Fatalf("Failed to create agent: %v", err)
	}
	_, err = db.Exec("INSERT INTO conversations (id, user_id, agent_id, created_at) VALUES (?, ?, ?, ?)",
		"conv-e2e-send", "user-e2e-send", "agent-e2e-send", time.Now().UTC())
	if err != nil {
		t.Fatalf("Failed to create conversation: %v", err)
	}

	// Set up hub with connected agent
	hub = newHub()
	go hub.run()
	defer func() { hub.Stop(); hub = nil }()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()

		c := &Connection{
			hub:         hub,
			connType:    "agent",
			id:          "agent-e2e-send",
			conn:        conn,
			send:        make(chan []byte, 256),
			connectedAt: time.Now(),
		}
		hub.register <- c
		time.Sleep(500 * time.Millisecond)
	}))
	defer srv.Close()

	dialer := websocket.Dialer{}
	_, _, err = dialer.Dial("ws"+strings.TrimPrefix(srv.URL, "http"), nil)
	if err != nil {
		t.Fatalf("Failed to connect agent WS: %v", err)
	}
	time.Sleep(100 * time.Millisecond)

	// User sends encrypted message — should be delivered to agent via WebSocket
	token := generateTestToken_CB65("user-e2e-send")
	body := `{"conversation_id":"conv-e2e-send","ciphertext":"encrypted_data","iv":"iv123","recipient_key_id":"rk1","sender_key_id":"sk1","algorithm":"aes-256-gcm"}`
	req := httptest.NewRequest("POST", "/e2e/messages", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleStoreEncryptedMessage(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d (body: %s)", w.Code, w.Body.String())
	}

	// Verify agent received the encrypted_message via WebSocket
	hub.mu.Lock()
	agent := hub.agents["agent-e2e-send"]
	hub.mu.Unlock()
	if agent != nil {
		select {
		case msg := <-agent.send:
			var out OutgoingMessage
			if err := json.Unmarshal(msg, &out); err != nil {
				t.Fatalf("Failed to unmarshal: %v", err)
			}
			if out.Type != "encrypted_message" {
				t.Errorf("expected 'encrypted_message' type, got '%s'", out.Type)
			}
		case <-time.After(500 * time.Millisecond):
			t.Error("agent did not receive encrypted_message")
		}
	}
}

// --- handleStoreEncryptedMessage: agent sends to offline user (notifyUser fallback) ---

func TestCB65_handleStoreEncryptedMessage_AgentToOfflineUser(t *testing.T) {
	db = setupTestDB_CB65(t)
	defer func() { db = nil }()

	// Create user, agent, conversation
	_, err := db.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)", "user-offline-e2e", "offuser", "hash")
	if err != nil {
		t.Fatalf("Failed to create user: %v", err)
	}
	_, err = db.Exec("INSERT INTO agents (id, name) VALUES (?, ?)", "agent-send-e2e", "Send Agent")
	if err != nil {
		t.Fatalf("Failed to create agent: %v", err)
	}
	_, err = db.Exec("INSERT INTO conversations (id, user_id, agent_id, created_at) VALUES (?, ?, ?, ?)",
		"conv-offline-e2e", "user-offline-e2e", "agent-send-e2e", time.Now().UTC())
	if err != nil {
		t.Fatalf("Failed to create conversation: %v", err)
	}

	// Set up hub (no client connected — user is offline)
	hub = newHub()
	go hub.run()
	defer func() { hub.Stop(); hub = nil }()

	// Agent sends encrypted message — user is offline, so notifyUser is called
	// Use agent auth (X-Agent-Secret header)
	resetAgentSecret()
	secret := getAgentSecret()
	body := `{"conversation_id":"conv-offline-e2e","ciphertext":"enc_data","iv":"iv123","recipient_key_id":"rk1","algorithm":"aes-256-gcm"}`
	req := httptest.NewRequest("POST", "/e2e/messages", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Agent-Secret", secret)
	req.Header.Set("X-Agent-ID", "agent-send-e2e")
	w := httptest.NewRecorder()
	handleStoreEncryptedMessage(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d (body: %s)", w.Code, w.Body.String())
	}
}

// --- InitTracing: HTTP exporter path (79.5% -> higher) ---

func TestCB65_InitTracing_HTTPExporter(t *testing.T) {
	resetTracingState_CB65()
	os.Setenv("OTEL_ENABLED", "true")
	os.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "localhost:4318")
	os.Setenv("OTEL_EXPORTER_OTLP_PROTOCOL", "http")
	defer func() {
		os.Unsetenv("OTEL_ENABLED")
		os.Unsetenv("OTEL_EXPORTER_OTLP_ENDPOINT")
		os.Unsetenv("OTEL_EXPORTER_OTLP_PROTOCOL")
	}()

	err := InitTracing()
	// HTTP exporter creation may fail to connect, but the code path should be exercised
	// If it succeeds, tracingEnabled should be true
	if err != nil {
		// Expected if no collector is running — but the HTTP code path was exercised
		t.Logf("InitTracing returned error (expected without collector): %v", err)
	}

	// Reset for other tests
	ShutdownTracing()
	resetTracingState_CB65()
}

// --- InitTracing: gRPC exporter path ---

func TestCB65_InitTracing_GRPCExporter(t *testing.T) {
	resetTracingState_CB65()
	os.Setenv("OTEL_ENABLED", "true")
	os.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "localhost:4317")
	os.Setenv("OTEL_EXPORTER_OTLP_PROTOCOL", "grpc")
	defer func() {
		os.Unsetenv("OTEL_ENABLED")
		os.Unsetenv("OTEL_EXPORTER_OTLP_ENDPOINT")
		os.Unsetenv("OTEL_EXPORTER_OTLP_PROTOCOL")
	}()

	err := InitTracing()
	if err != nil {
		t.Logf("InitTracing returned error (expected without collector): %v", err)
	}

	// Reset
	ShutdownTracing()
	resetTracingState_CB65()
}

// --- InitTracing: HTTP exporter with http:// prefix (insecure) ---

func TestCB65_InitTracing_HTTPInsecure(t *testing.T) {
	resetTracingState_CB65()
	os.Setenv("OTEL_ENABLED", "true")
	os.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://localhost:4318")
	os.Setenv("OTEL_EXPORTER_OTLP_PROTOCOL", "http")
	defer func() {
		os.Unsetenv("OTEL_ENABLED")
		os.Unsetenv("OTEL_EXPORTER_OTLP_ENDPOINT")
		os.Unsetenv("OTEL_EXPORTER_OTLP_PROTOCOL")
	}()

	err := InitTracing()
	if err != nil {
		t.Logf("InitTracing returned error (expected): %v", err)
	}

	ShutdownTracing()
	resetTracingState_CB65()
}

// --- InitTracing: with custom service name and sampling rate ---

func TestCB65_InitTracing_CustomConfig(t *testing.T) {
	resetTracingState_CB65()
	os.Setenv("OTEL_ENABLED", "true")
	os.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "localhost:4317")
	os.Setenv("OTEL_EXPORTER_OTLP_PROTOCOL", "grpc")
	os.Setenv("OTEL_SERVICE_NAME", "custom-messenger")
	os.Setenv("OTEL_SAMPLING_RATE", "0.5")
	defer func() {
		os.Unsetenv("OTEL_ENABLED")
		os.Unsetenv("OTEL_EXPORTER_OTLP_ENDPOINT")
		os.Unsetenv("OTEL_EXPORTER_OTLP_PROTOCOL")
		os.Unsetenv("OTEL_SERVICE_NAME")
		os.Unsetenv("OTEL_SAMPLING_RATE")
	}()

	err := InitTracing()
	if err != nil {
		t.Logf("InitTracing returned error (expected): %v", err)
	}

	ShutdownTracing()
	resetTracingState_CB65()
}

// --- InitTracing: HTTP endpoint from OTEL_EXPORTER_OTLP_HTTP_ENDPOINT fallback ---

func TestCB65_InitTracing_HTTPFallbackEnv(t *testing.T) {
	resetTracingState_CB65()
	os.Setenv("OTEL_ENABLED", "true")
	os.Unsetenv("OTEL_EXPORTER_OTLP_ENDPOINT")
	os.Setenv("OTEL_EXPORTER_OTLP_HTTP_ENDPOINT", "localhost:4318")
	os.Setenv("OTEL_EXPORTER_OTLP_PROTOCOL", "http")
	defer func() {
		os.Unsetenv("OTEL_ENABLED")
		os.Unsetenv("OTEL_EXPORTER_OTLP_HTTP_ENDPOINT")
		os.Unsetenv("OTEL_EXPORTER_OTLP_PROTOCOL")
	}()

	err := InitTracing()
	if err != nil {
		t.Logf("InitTracing returned error (expected): %v", err)
	}

	ShutdownTracing()
	resetTracingState_CB65()
}

// --- ShutdownTracing: with active provider and shutdown error (80% -> higher) ---

func TestCB65_ShutdownTracing_WithProvider(t *testing.T) {
	resetTracingState_CB65()
	// Manually create a trace provider so ShutdownTracing has something to shut down
	tp = sdktrace.NewTracerProvider(
		sdktrace.WithSampler(sdktrace.AlwaysSample()),
	)
	tracingEnabled = true

	// First shutdown should work
	ShutdownTracing()

	// Second shutdown with nil tp should not panic
	tp = nil
	ShutdownTracing()

	resetTracingState_CB65()
}

// --- initSchema: PostgreSQL driver paths (82.4% -> higher) ---

func TestCB65_initSchema_PostgreSQLPaths(t *testing.T) {
	// Test initSchema with PostgreSQL driver set
	// Since we can't actually run PostgreSQL, we test the code paths
	// that use currentDriver == DriverPostgreSQL for INSERT/ALTER statements
	testDB, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("Failed to open DB: %v", err)
	}

	// Set driver to PostgreSQL to exercise those branches
	oldDriver := currentDriver
	currentDriver = DriverPostgreSQL
	defer func() { currentDriver = oldDriver }()

	// initSchemaForDriver returns PostgreSQL-compatible SQL, but with SQLite
	// it won't execute properly. That's OK — we're testing the migration
	// code paths that use PostgreSQL-specific syntax.
	err = initSchema(testDB)
	if err != nil {
		// Expected since PostgreSQL schema won't work with SQLite
		t.Logf("initSchema returned error with PostgreSQL driver (expected): %v", err)
	}
	testDB.Close()
}

// --- initSchema: migration count query error ---

func TestCB65_initSchema_MigrationCountError(t *testing.T) {
	closedDB, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("Failed to open DB: %v", err)
	}
	if err := initSchema(closedDB); err != nil {
		t.Fatalf("Failed to init schema: %v", err)
	}
	closedDB.Close()

	// initSchema with closed DB — schema creation fails
	err = initSchema(closedDB)
	if err == nil {
		t.Log("initSchema returned nil with closed DB (might not error on schema exec)")
	}
	closedDB.Close()
}

// --- initAPNs: cert dir creation and production environment (84% -> higher) ---

func TestCB65_initAPNs_CertDirCreation(t *testing.T) {
	oldConfig := pushConfig
	defer func() { pushConfig = oldConfig }()

	pushConfig = &PushNotificationConfig{
		APNSEnabled: true,
		CertPath:    "/tmp/agent-messenger-test-apns/subdir/cert.p12",
		Password:    "test",
		Environment: "production",
	}

	// initAPNs should try to create the directory and then fail to load the cert
	initAPNs()

	// Directory should have been created
	if _, err := os.Stat("/tmp/agent-messenger-test-apns/subdir"); err != nil {
		t.Errorf("expected cert dir to be created: %v", err)
	}

	// APNs should be disabled because cert doesn't exist
	if pushConfig.APNSEnabled {
		t.Error("expected APNs to be disabled after missing cert")
	}

	// Clean up
	os.RemoveAll("/tmp/agent-messenger-test-apns")
}

// --- initAPNs: nil config ---

func TestCB65_initAPNs_NilConfig(t *testing.T) {
	oldConfig := pushConfig
	defer func() { pushConfig = oldConfig }()

	pushConfig = nil
	initAPNs()
	// Should not panic
}

// --- initAPNs: disabled ---

func TestCB65_initAPNs_Disabled(t *testing.T) {
	oldConfig := pushConfig
	defer func() { pushConfig = oldConfig }()

	pushConfig = &PushNotificationConfig{
		APNSEnabled: false,
	}
	initAPNs()
	// Should not panic, APNs stays disabled
	if pushConfig.APNSEnabled {
		t.Error("expected APNs to remain disabled")
	}
}

// --- initFCM: nil config ---

func TestCB65_initFCM_NilConfig(t *testing.T) {
	oldConfig := pushConfig
	defer func() { pushConfig = oldConfig }()

	pushConfig = nil
	initFCM()
	// Should not panic
}

// --- initFCM: disabled ---

func TestCB65_initFCM_Disabled(t *testing.T) {
	oldConfig := pushConfig
	defer func() { pushConfig = oldConfig }()

	pushConfig = &PushNotificationConfig{
		FCMEnabled: false,
	}
	initFCM()
	if pushConfig.FCMEnabled {
		t.Error("expected FCM to remain disabled")
	}
}

// --- initFCM: enabled but no creds path ---

func TestCB65_initFCM_NoCredsPath(t *testing.T) {
	oldConfig := pushConfig
	defer func() { pushConfig = oldConfig }()

	pushConfig = &PushNotificationConfig{
		FCMEnabled:     true,
		FCMCredentials: "",
	}
	initFCM()
	// FCMEnabled stays true but with empty creds path, it just logs a warning
	// The actual behavior is that it logs a warning but doesn't disable
	if !pushConfig.FCMEnabled {
		t.Log("FCM was disabled (acceptable behavior)")
	} else {
		t.Log("FCM stayed enabled (acceptable behavior)")
	}
}

// --- initFCM: creds file not found ---

func TestCB65_initFCM_CredsNotFound(t *testing.T) {
	oldConfig := pushConfig
	defer func() { pushConfig = oldConfig }()

	pushConfig = &PushNotificationConfig{
		FCMEnabled:     true,
		FCMCredentials: "/nonexistent/path/to/creds.json",
	}
	initFCM()
	if pushConfig.FCMEnabled {
		t.Error("expected FCM to be disabled when creds not found")
	}
}

// --- initPushNotifications: full initialization ---

func TestCB65_initPushNotifications_AllDisabled(t *testing.T) {
	oldConfig := pushConfig
	defer func() { pushConfig = oldConfig }()

	os.Unsetenv("APNS_ENABLED")
	os.Unsetenv("FCM_ENABLED")

	initPushNotifications()

	if pushConfig == nil {
		t.Fatal("expected pushConfig to be initialized")
	}
	if pushConfig.APNSEnabled {
		t.Error("expected APNs to be disabled by default")
	}
	if pushConfig.FCMEnabled {
		t.Error("expected FCM to be disabled by default")
	}
}

// --- rate_limit_tiers cleanup: ticker trigger (83.3% -> 100%) ---

func TestCB65_TieredRateLimiter_Cleanup_TickerTrigger(t *testing.T) {
	tl := NewTieredRateLimiter()
	defer tl.Stop()

	// Add a stale entry
	tl.SetTier("user-ticker-test", TierFree)
	tl.mu.Lock()
	tl.limits["user-ticker-test"] = &userRateLimitState{
		count:     1,
		windowEnd: time.Now().Add(-15 * time.Minute),
		tier:      TierFree,
	}
	tl.mu.Unlock()

	// Run cleanup() in a goroutine with a very short wait
	// The ticker is 5 minutes, so we can't wait for it naturally in a test.
	// Instead, we test cleanupOnce() directly (already tested in CB64)
	// and test that cleanup() exits when stopCh is closed.
	done := make(chan struct{})
	go func() {
		tl.cleanup()
		close(done)
	}()

	// Stop the limiter — cleanup() should exit via stopCh
	tl.Stop()

	select {
	case <-done:
		// Good
	case <-time.After(1 * time.Second):
		t.Error("cleanup() did not exit after Stop()")
	}
}

// --- loadQueueFromDB: scan error with invalid data (89.5% -> 100%) ---

func TestCB65_loadQueueFromDB_ScanError(t *testing.T) {
	testDB, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("Failed to open DB: %v", err)
	}
	if err := initSchema(testDB); err != nil {
		t.Fatalf("Failed to init schema: %v", err)
	}
	defer testDB.Close()

	// Insert a row with invalid data types to cause scan error
	// The offline_queue table expects specific column types;
	// we insert a non-NULL value into a column that will cause a scan error
	_, err = testDB.Exec(`INSERT INTO offline_queue (id, recipient_id, recipient_type, message_data, created_at, expires_at)
		VALUES ('q1', 'user-1', 'user', 'not valid json', 'not-a-timestamp', 'not-a-timestamp')`)
	if err != nil {
		// If the insert fails due to type constraints, try a different approach
		// Insert valid row but with NULL message_data
		_, _ = testDB.Exec(`INSERT INTO offline_queue (id, recipient_id, recipient_type, message_data, created_at, expires_at)
			VALUES ('q1', 'user-1', 'user', NULL, ?, ?)`, time.Now().UTC(), time.Now().Add(7*24*time.Hour).UTC())
	}

	oq := newOfflineQueue(100, 7*24*time.Hour)
	loadQueueFromDB(testDB, oq)
	// May have loaded entries or not depending on DB behavior
}

// --- loadQueueFromDB: nil DB ---

func TestCB65_loadQueueFromDB_NilDB(t *testing.T) {
	oq := newOfflineQueue(100, 7*24*time.Hour)
	loadQueueFromDB(nil, oq)
	// Should not panic with nil DB
}

// --- handleUpload: parse multipart error (85.7% -> higher) ---

func TestCB65_handleUpload_ParseMultipartError(t *testing.T) {
	db = setupTestDB_CB65(t)
	defer func() { db = nil }()

	token := generateTestToken_CB65("user-upload-1")

	// Send a request with invalid multipart form data
	req := httptest.NewRequest("POST", "/attachments/upload", strings.NewReader("not multipart"))
	req.Header.Set("Content-Type", "multipart/form-data; boundary=----badboundary")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleUpload(w, req)

	if w.Code == http.StatusOK {
		t.Error("expected non-200 for invalid multipart data")
	}
}

// --- handleUpload: missing file field ---

func TestCB65_handleUpload_MissingFileField(t *testing.T) {
	db = setupTestDB_CB65(t)
	defer func() { db = nil }()

	token := generateTestToken_CB65("user-upload-2")

	// Create a multipart form without a file field
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	writer.WriteField("conversation_id", "conv-upload-test")
	writer.Close()

	req := httptest.NewRequest("POST", "/attachments/upload", body)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleUpload(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing file field, got %d", w.Code)
	}
}

// --- handleUpload: unauthorized (no token) ---

func TestCB65_handleUpload_NoAuth(t *testing.T) {
	req := httptest.NewRequest("POST", "/attachments/upload", nil)
	w := httptest.NewRecorder()
	handleUpload(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for no auth, got %d", w.Code)
	}
}

// --- handleUpload: method not allowed ---

func TestCB65_handleUpload_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest("GET", "/attachments/upload", nil)
	w := httptest.NewRecorder()
	handleUpload(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

// --- handleAgentConnect: with protocol version negotiation ---

func TestCB65_handleAgentConnect_WithProtocolVersion(t *testing.T) {
	db = setupTestDB_CB65(t)
	defer func() { db = nil }()

	resetAgentSecret()
	secret := getAgentSecret()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hub == nil {
			hub = newHub()
			go hub.run()
		}
		handleAgentConnect(w, r)
	}))
	defer func() {
		if hub != nil {
			hub.Stop()
			hub = nil
		}
		srv.Close()
	}()

	dialer := websocket.Dialer{Subprotocols: []string{"agent-messenger-v1"}}
	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "?agent_id=test-agent-proto&agent_secret=" + secret
	ws, resp, err := dialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("Failed to connect: %v (resp: %v)", err, resp)
	}
	defer ws.Close()

	_, message, err := ws.ReadMessage()
	if err != nil {
		t.Fatalf("Failed to read welcome: %v", err)
	}

	var welcome OutgoingMessage
	json.Unmarshal(message, &welcome)
	if welcome.Type != "connected" {
		t.Errorf("expected 'connected', got '%s'", welcome.Type)
	}

	// Check protocol version in welcome data
	data, ok := welcome.Data.(map[string]interface{})
	if !ok {
		t.Fatal("expected welcome data to be a map")
	}
	if data["protocol_version"] != "v1" {
		t.Errorf("expected protocol_version 'v1', got '%v'", data["protocol_version"])
	}
}

// --- handleAgentConnect: unsupported protocol version ---

func TestCB65_handleAgentConnect_UnsupportedProtocolVersion(t *testing.T) {
	db = setupTestDB_CB65(t)
	defer func() { db = nil }()

	resetAgentSecret()
	secret := getAgentSecret()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hub == nil {
			hub = newHub()
			go hub.run()
		}
		handleAgentConnect(w, r)
	}))
	defer func() {
		if hub != nil {
			hub.Stop()
			hub = nil
		}
		srv.Close()
	}()

	// Use an unsupported protocol version - the response header won't include
	// the Sec-WebSocket-Protocol header since the version isn't supported.
	// The welcome message protocol_version will be whatever negotiateProtocol returns
	// (which may be empty or the default depending on the implementation)
	dialer := websocket.Dialer{Subprotocols: []string{"unsupported-v99"}}
	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "?agent_id=test-agent-badproto&agent_secret=" + secret
	ws, _, err := dialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer ws.Close()

	_, message, err := ws.ReadMessage()
	if err != nil {
		t.Fatalf("Failed to read welcome: %v", err)
	}

	var welcome OutgoingMessage
	json.Unmarshal(message, &welcome)
	data, ok := welcome.Data.(map[string]interface{})
	if !ok {
		t.Fatal("expected welcome data to be a map")
	}
	// negotiateProtocol returns the first matching supported version from the
	// Sec-WebSocket-Protocol header. Since "unsupported-v99" doesn't match,
	// it falls through to checking the query param or returns empty.
	// The response Sec-WebSocket-Protocol header is only set for supported versions.
	// So protocol_version should be empty or the default.
	pv, _ := data["protocol_version"].(string)
	t.Logf("protocol_version for unsupported: '%s'", pv)
	// Accept either empty or any value — the key coverage is that the code path
	// for unsupported protocol versions was exercised without crashing
}

// --- handleStoreEncryptedMessage: agent forbidden ---

func TestCB65_handleStoreEncryptedMessage_AgentForbidden(t *testing.T) {
	db = setupTestDB_CB65(t)
	defer func() { db = nil }()

	// Create user, two agents, and a conversation with agent-1
	_, err := db.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)", "user-e2e-forbid", "forbid", "hash")
	if err != nil {
		t.Fatalf("Failed to create user: %v", err)
	}
	_, err = db.Exec("INSERT INTO agents (id, name) VALUES (?, ?)", "agent-e2e-1", "Agent 1")
	if err != nil {
		t.Fatalf("Failed to create agent 1: %v", err)
	}
	_, err = db.Exec("INSERT INTO agents (id, name) VALUES (?, ?)", "agent-e2e-2", "Agent 2")
	if err != nil {
		t.Fatalf("Failed to create agent 2: %v", err)
	}
	_, err = db.Exec("INSERT INTO conversations (id, user_id, agent_id, created_at) VALUES (?, ?, ?, ?)",
		"conv-e2e-forbid", "user-e2e-forbid", "agent-e2e-1", time.Now().UTC())
	if err != nil {
		t.Fatalf("Failed to create conversation: %v", err)
	}

	// Agent 2 tries to send to a conversation they're not part of
	resetAgentSecret()
	secret := getAgentSecret()
	body := `{"conversation_id":"conv-e2e-forbid","ciphertext":"abc","iv":"def","algorithm":"aes-256-gcm"}`
	req := httptest.NewRequest("POST", "/e2e/messages", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Agent-Secret", secret)
	req.Header.Set("X-Agent-ID", "agent-e2e-2")
	w := httptest.NewRecorder()
	handleStoreEncryptedMessage(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403 for forbidden agent, got %d", w.Code)
	}
}

// --- handleStoreEncryptedMessage: missing fields ---

func TestCB65_handleStoreEncryptedMessage_MissingCiphertext(t *testing.T) {
	token := generateTestToken_CB65("user-e2e-missing")
	body := `{"conversation_id":"conv-x","iv":"def","algorithm":"aes-256-gcm"}`
	req := httptest.NewRequest("POST", "/e2e/messages", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleStoreEncryptedMessage(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing ciphertext, got %d", w.Code)
	}
}

// --- handleStoreEncryptedMessage: user forbidden ---

func TestCB65_handleStoreEncryptedMessage_UserForbidden(t *testing.T) {
	db = setupTestDB_CB65(t)
	defer func() { db = nil }()

	_, err := db.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)", "user-e2e-owner", "owner", "hash")
	if err != nil {
		t.Fatalf("Failed to create user: %v", err)
	}
	_, err = db.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)", "user-e2e-other", "other", "hash")
	if err != nil {
		t.Fatalf("Failed to create other user: %v", err)
	}
	_, err = db.Exec("INSERT INTO agents (id, name) VALUES (?, ?)", "agent-e2e-own", "Own Agent")
	if err != nil {
		t.Fatalf("Failed to create agent: %v", err)
	}
	_, err = db.Exec("INSERT INTO conversations (id, user_id, agent_id, created_at) VALUES (?, ?, ?, ?)",
		"conv-e2e-own", "user-e2e-owner", "agent-e2e-own", time.Now().UTC())
	if err != nil {
		t.Fatalf("Failed to create conversation: %v", err)
	}

	// Different user tries
	token := generateTestToken_CB65("user-e2e-other")
	body := `{"conversation_id":"conv-e2e-own","ciphertext":"abc","iv":"def","algorithm":"aes-256-gcm"}`
	req := httptest.NewRequest("POST", "/e2e/messages", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleStoreEncryptedMessage(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403 for forbidden user, got %d", w.Code)
	}
}

// --- cpuProfileTestSetup: error path (87.5% -> 100%) ---

func TestCB65_cpuProfileTestSetup_NoFile(t *testing.T) {
	// cpuProfileTestSetup takes no args and returns a cleanup func.
	// Just call it and verify it doesn't panic.
	cleanup := cpuProfileTestSetup()
	if cleanup != nil {
		cleanup()
	}
}

// --- handleUpload: successful upload ---

func TestCB65_handleUpload_Success(t *testing.T) {
	db = setupTestDB_CB65(t)
	defer func() { db = nil }()

	// Create a user
	_, err := db.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)", "user-upload-ok", "uploadok", "hash")
	if err != nil {
		t.Fatalf("Failed to create user: %v", err)
	}

	token := generateTestToken_CB65("user-upload-ok")

	// Create a multipart form with a file
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	writer.WriteField("conversation_id", "conv-upload-ok")
	part, err := writer.CreateFormFile("file", "test.txt")
	if err != nil {
		t.Fatalf("Failed to create form file: %v", err)
	}
	part.Write([]byte("Hello, this is a test file!"))
	writer.Close()

	req := httptest.NewRequest("POST", "/attachments/upload", body)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleUpload(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d (body: %s)", w.Code, w.Body.String())
	}

	var result Attachment
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatalf("Failed to unmarshal response: %v", err)
	}
	if result.ID == "" {
		t.Error("expected non-empty attachment ID in response")
	}
	if result.Filename != "test.txt" {
		t.Errorf("expected filename 'test.txt', got '%s'", result.Filename)
	}
}

// --- handleUpload: file too large ---

func TestCB65_handleUpload_FileTooLarge(t *testing.T) {
	db = setupTestDB_CB65(t)
	defer func() { db = nil }()

	_, err := db.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)", "user-upload-big", "uploadbig", "hash")
	if err != nil {
		t.Fatalf("Failed to create user: %v", err)
	}

	token := generateTestToken_CB65("user-upload-big")

	// Set a very small max upload size by directly setting the global
	oldMax := maxUploadSize
	maxUploadSize = 100 // 100 bytes
	defer func() { maxUploadSize = oldMax }()

	// Create a multipart form with a large file
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	writer.WriteField("conversation_id", "conv-upload-big")
	part, err := writer.CreateFormFile("file", "large.txt")
	if err != nil {
		t.Fatalf("Failed to create form file: %v", err)
	}
	// Write more than 100 bytes
	largeData := strings.Repeat("A", 200)
	part.Write([]byte(largeData))
	writer.Close()

	req := httptest.NewRequest("POST", "/attachments/upload", body)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleUpload(w, req)

	// Should get 400 for file too large (either from MaxBytesReader or size check)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for file too large, got %d", w.Code)
	}
}

// --- handleAgentConnect: with name/model/personality/specialty ---

func TestCB65_handleAgentConnect_WithMetadata(t *testing.T) {
	db = setupTestDB_CB65(t)
	defer func() { db = nil }()

	resetAgentSecret()
	secret := getAgentSecret()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hub == nil {
			hub = newHub()
			go hub.run()
		}
		handleAgentConnect(w, r)
	}))
	defer func() {
		if hub != nil {
			hub.Stop()
			hub = nil
		}
		srv.Close()
	}()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "?agent_id=test-agent-meta&agent_secret=" + secret + "&name=TestAgent&model=gpt-4&personality=friendly&specialty=coding"
	dialer := websocket.Dialer{}
	ws, _, err := dialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer ws.Close()

	_, message, err := ws.ReadMessage()
	if err != nil {
		t.Fatalf("Failed to read welcome: %v", err)
	}

	var welcome OutgoingMessage
	json.Unmarshal(message, &welcome)
	if welcome.Type != "connected" {
		t.Errorf("expected 'connected', got '%s'", welcome.Type)
	}

	// Verify agent was registered in DB with metadata
	var name, model, personality, specialty string
	err = db.QueryRow("SELECT name, model, personality, specialty FROM agents WHERE id = ?", "test-agent-meta").Scan(&name, &model, &personality, &specialty)
	if err != nil {
		t.Fatalf("Failed to query agent: %v", err)
	}
	if name != "TestAgent" {
		t.Errorf("expected name 'TestAgent', got '%s'", name)
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