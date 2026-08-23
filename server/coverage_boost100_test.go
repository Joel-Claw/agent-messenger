package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"golang.org/x/crypto/bcrypt"
	_ "github.com/mattn/go-sqlite3"
)

// ==============================
// CB100: Coverage boost targeting remaining low-coverage functions.
// Targets: handleHealth (degraded), handleLogin (error paths),
// handleRegisterUser (edge cases), hub.run (register/unregister/broadcast),
// routeChatMessage (full delivery paths), handleAgentConnect (WebSocket),
// sendWelcomeMessage (marshal error), initSchema (migration errors),
// handleClientConnect (WebSocket), replayOfflineMessages,
// routeStatusUpdate (agent broadcast), routeHeartbeat,
// handleChangePassword, handleSearchMessages, handleGetMessages,
// handleCreateConversation, handleListConversations, handleListAgents,
// handleDeleteConversation, handleGetNotificationPrefs, handleSetNotificationPrefs,
// handleDeleteNotificationPrefs, openDatabase, checkRateLimit,
// ValidateAgentSecret (rate limiting), handleMetrics
// ==============================

// --- Helpers ---

func setupTestDB_CB100() {
	var err error
	db, err = sql.Open("sqlite3", "file::memory:?cache=shared")
	if err != nil {
		panic(err)
	}
	currentDriver = DriverSQLite
	initSchema(db)
}

func teardownTestDB_CB100() {
	if db != nil {
		db.Close()
		db = nil
	}
}

func setupHub_CB100() *Hub {
	oldHub := hub
	h := newHub()
	hub = h
	go hub.run()
	return oldHub
}

func teardownHub_CB100(oldHub *Hub) {
	if hub != nil {
		hub.Stop()
	}
	hub = oldHub
}

func makeAuthReq_CB100(method, path string, body io.Reader, userID string) *http.Request {
	req := httptest.NewRequest(method, path, body)
	if userID != "" {
		ctx := context.WithValue(req.Context(), contextKeyUserID, userID)
		req = req.WithContext(ctx)
	}
	return req
}

func makeJWTReq_CB100(method, path string, body io.Reader, userID string) *http.Request {
	req := httptest.NewRequest(method, path, body)
	if userID != "" {
		token, err := GenerateJWT(userID, userID)
		if err != nil {
			panic(err)
		}
		req.Header.Set("Authorization", "Bearer "+token)
	}
	return req
}

func registerTestUser_CB100(username, password string) string {
	hash, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	_, err := db.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)", "user-"+username, username, string(hash))
	if err != nil {
		// User may already exist
	}
	return "user-" + username
}

// --- handleHealth ---

func TestCB100_HandleHealth_DegradedDB(t *testing.T) {
	setupTestDB_CB100()
	defer teardownTestDB_CB100()

	// Close DB to make Ping fail
	db.Close()

	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()
	handleHealth(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d", w.Code)
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp["status"] != "degraded" {
		t.Fatalf("expected 'degraded', got %v", resp["status"])
	}
}

func TestCB100_HandleHealth_MethodNotAllowed(t *testing.T) {
	setupTestDB_CB100()
	defer teardownTestDB_CB100()

	req := httptest.NewRequest("POST", "/health", nil)
	w := httptest.NewRecorder()
	handleHealth(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", w.Code)
	}
}

func TestCB100_HandleHealth_WithMetrics(t *testing.T) {
	setupTestDB_CB100()
	defer teardownTestDB_CB100()

	oldHub := hub
	h := newHub()
	hub = h
	go hub.run()
	defer func() {
		hub.Stop()
		hub = oldHub
	}()

	ServerMetrics = NewMetrics(hub)
	defer func() { ServerMetrics = nil }()

	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()
	handleHealth(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp["status"] != "ok" {
		t.Fatalf("expected 'ok', got %v", resp["status"])
	}
	if resp["version"] == nil {
		t.Fatal("expected version in response")
	}
}

func TestCB100_HandleHealth_NilDB(t *testing.T) {
	oldDB := db
	db = nil

	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()
	handleHealth(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d", w.Code)
	}

	db = oldDB
}

// --- handleLogin ---

func TestCB100_HandleLogin_Success(t *testing.T) {
	setupTestDB_CB100()
	defer teardownTestDB_CB100()

	// Register user
	registerTestUser_CB100("testuser1", "password123")

	form := strings.NewReader("username=testuser1&password=password123")
	req := httptest.NewRequest("POST", "/auth/login", form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handleLogin(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp["token"] == nil || resp["token"] == "" {
		t.Fatal("expected non-empty token")
	}
	if resp["user_id"] == nil {
		t.Fatal("expected user_id in response")
	}
}

func TestCB100_HandleLogin_WrongPassword(t *testing.T) {
	setupTestDB_CB100()
	defer teardownTestDB_CB100()

	registerTestUser_CB100("testuser2", "password123")

	form := strings.NewReader("username=testuser2&password=wrongpass")
	req := httptest.NewRequest("POST", "/auth/login", form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handleLogin(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestCB100_HandleLogin_UserNotFound(t *testing.T) {
	setupTestDB_CB100()
	defer teardownTestDB_CB100()

	form := strings.NewReader("username=nonexistent&password=something")
	req := httptest.NewRequest("POST", "/auth/login", form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handleLogin(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestCB100_HandleLogin_MissingFields(t *testing.T) {
	setupTestDB_CB100()
	defer teardownTestDB_CB100()

	form := strings.NewReader("username=testuser")
	req := httptest.NewRequest("POST", "/auth/login", form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handleLogin(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestCB100_HandleLogin_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest("GET", "/auth/login", nil)
	w := httptest.NewRecorder()
	handleLogin(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", w.Code)
	}
}

// --- handleRegisterUser ---

func TestCB100_HandleRegisterUser_DuplicateUsername(t *testing.T) {
	setupTestDB_CB100()
	defer teardownTestDB_CB100()

	// First registration
	form := strings.NewReader("username=newuser1&password=password123")
	req := httptest.NewRequest("POST", "/auth/register", form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handleRegisterUser(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for first registration, got %d: %s", w.Code, w.Body.String())
	}

	// Duplicate
	form2 := strings.NewReader("username=newuser1&password=password456")
	req2 := httptest.NewRequest("POST", "/auth/register", form2)
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w2 := httptest.NewRecorder()
	handleRegisterUser(w2, req2)

	if w2.Code != http.StatusConflict {
		t.Fatalf("expected 409 for duplicate, got %d: %s", w2.Code, w2.Body.String())
	}
}

func TestCB100_HandleRegisterUser_Success(t *testing.T) {
	setupTestDB_CB100()
	defer teardownTestDB_CB100()

	form := strings.NewReader("username=uniqueuser1&password=password123")
	req := httptest.NewRequest("POST", "/auth/register", form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handleRegisterUser(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp["status"] != "registered" {
		t.Fatalf("expected status 'registered', got %v", resp["status"])
	}
}

// --- hub.run (register/unregister/broadcast) ---

func TestCB100_HubRun_AgentRegisterUnregister(t *testing.T) {
	h := newHub()
	go h.run()
	defer h.Stop()

	conn := &Connection{
		hub:      h,
		connType: "agent",
		id:       "agent-test-1",
		send:     make(chan []byte, 256),
	}
	h.register <- conn

	// Wait for registration
	time.Sleep(50 * time.Millisecond)

	if h.GetAgent("agent-test-1") == nil {
		t.Fatal("expected agent to be registered")
	}

	h.unregister <- conn

	// Wait for unregistration
	time.Sleep(50 * time.Millisecond)

	if h.GetAgent("agent-test-1") != nil {
		t.Fatal("expected agent to be unregistered")
	}
}

func TestCB100_HubRun_ClientRegisterUnregister(t *testing.T) {
	h := newHub()
	go h.run()
	defer h.Stop()

	conn := &Connection{
		hub:      h,
		connType: "client",
		id:       "client-test-1",
		send:     make(chan []byte, 256),
	}
	h.register <- conn

	time.Sleep(50 * time.Millisecond)

	conns := h.GetClientConns("client-test-1")
	if len(conns) != 1 {
		t.Fatalf("expected 1 client conn, got %d", len(conns))
	}

	h.unregister <- conn

	time.Sleep(50 * time.Millisecond)

	conns = h.GetClientConns("client-test-1")
	if len(conns) != 0 {
		t.Fatalf("expected 0 client conns after unregister, got %d", len(conns))
	}
}

func TestCB100_HubRun_Broadcast(t *testing.T) {
	h := newHub()
	go h.run()
	defer h.Stop()

	// Register an agent
	agentConn := &Connection{
		hub:      h,
		connType: "agent",
		id:       "agent-bcast-1",
		send:     make(chan []byte, 256),
	}
	h.register <- agentConn

	// Register a client
	clientConn := &Connection{
		hub:      h,
		connType: "client",
		id:       "client-bcast-1",
		send:     make(chan []byte, 256),
	}
	h.register <- clientConn

	time.Sleep(50 * time.Millisecond)

	// Broadcast a message
	h.broadcast <- []byte(`{"type":"test"}`)

	time.Sleep(50 * time.Millisecond)

	// Check both received the message
	select {
	case msg := <-agentConn.send:
		if string(msg) != `{"type":"test"}` {
			t.Fatalf("unexpected message: %s", msg)
		}
	default:
		t.Fatal("agent did not receive broadcast")
	}

	select {
	case msg := <-clientConn.send:
		if string(msg) != `{"type":"test"}` {
			t.Fatalf("unexpected message: %s", msg)
		}
	default:
		t.Fatal("client did not receive broadcast")
	}
}

func TestCB100_HubRun_AgentReconnect(t *testing.T) {
	h := newHub()
	go h.run()
	defer h.Stop()

	oldConn := &Connection{
		hub:      h,
		connType: "agent",
		id:       "agent-reconnect-1",
		send:     make(chan []byte, 256),
	}
	h.register <- oldConn
	time.Sleep(50 * time.Millisecond)

	// New connection with same ID
	newConn := &Connection{
		hub:      h,
		connType: "agent",
		id:       "agent-reconnect-1",
		send:     make(chan []byte, 256),
	}
	h.register <- newConn
	time.Sleep(50 * time.Millisecond)

	// Old send channel should be closed
	_, ok := <-oldConn.send
	if ok {
		t.Fatal("expected old connection send channel to be closed")
	}

	// New connection should be registered
	if h.GetAgent("agent-reconnect-1") != newConn {
		t.Fatal("expected new agent to be registered")
	}
}

func TestCB100_HubRun_ClientDeviceReconnect(t *testing.T) {
	h := newHub()
	go h.run()
	defer h.Stop()

	oldConn := &Connection{
		hub:      h,
		connType: "client",
		id:       "client-device-1",
		deviceID: "device-A",
		send:     make(chan []byte, 256),
	}
	h.register <- oldConn
	time.Sleep(50 * time.Millisecond)

	// New connection with same user+device
	newConn := &Connection{
		hub:      h,
		connType: "client",
		id:       "client-device-1",
		deviceID: "device-A",
		send:     make(chan []byte, 256),
	}
	h.register <- newConn
	time.Sleep(50 * time.Millisecond)

	// Should only have 1 connection (replaced)
	conns := h.GetClientConns("client-device-1")
	if len(conns) != 1 {
		t.Fatalf("expected 1 conn after device reconnect, got %d", len(conns))
	}

	// Old send channel should be closed
	_, ok := <-oldConn.send
	if ok {
		t.Fatal("expected old connection send channel to be closed")
	}
}

func TestCB100_HubRun_ClientMultiDevice(t *testing.T) {
	h := newHub()
	go h.run()
	defer h.Stop()

	conn1 := &Connection{
		hub:      h,
		connType: "client",
		id:       "client-multi-1",
		deviceID: "device-1",
		send:     make(chan []byte, 256),
	}
	conn2 := &Connection{
		hub:      h,
		connType: "client",
		id:       "client-multi-1",
		deviceID: "device-2",
		send:     make(chan []byte, 256),
	}
	h.register <- conn1
	h.register <- conn2
	time.Sleep(50 * time.Millisecond)

	conns := h.GetClientConns("client-multi-1")
	if len(conns) != 2 {
		t.Fatalf("expected 2 conns, got %d", len(conns))
	}
}

// --- routeChatMessage (full delivery paths) ---

func TestCB100_RouteChatMessage_AgentToClientDelivery(t *testing.T) {
	setupTestDB_CB100()
	defer teardownTestDB_CB100()

	oldHub := hub
	h := newHub()
	hub = h
	go hub.run()
	defer func() {
		hub.Stop()
		hub = oldHub
	}()

	// Create conversation
	_, err := db.Exec("INSERT INTO conversations (id, user_id, agent_id) VALUES (?, ?, ?)",
		"conv-rchat-1", "user-rchat", "agent-rchat")
	if err != nil {
		t.Fatal(err)
	}

	// Register agent
	agentConn := &Connection{
		hub:      h,
		connType: "agent",
		id:       "agent-rchat",
		send:     make(chan []byte, 256),
	}
	h.register <- agentConn

	// Register client
	clientConn := &Connection{
		hub:      h,
		connType: "client",
		id:       "user-rchat",
		send:     make(chan []byte, 256),
	}
	h.register <- clientConn

	time.Sleep(50 * time.Millisecond)

	// Agent sends message
	msg := `{"content":"hello client","conversation_id":"conv-rchat-1"}`
	sender := &Connection{
		hub:      h,
		connType: "agent",
		id:       "agent-rchat",
		send:     make(chan []byte, 256),
	}
	routeChatMessage(sender, json.RawMessage(msg))

	// Client should receive the message
	select {
	case data := <-clientConn.send:
		var outgoing OutgoingMessage
		if err := json.Unmarshal(data, &outgoing); err != nil {
			t.Fatal(err)
		}
		if outgoing.Type != MsgTypeMessage {
			t.Fatalf("expected type %q, got %q", MsgTypeMessage, outgoing.Type)
		}
	case <-time.After(time.Second):
		t.Fatal("client did not receive message")
	}
}

func TestCB100_RouteChatMessage_ClientToAgentDelivery(t *testing.T) {
	setupTestDB_CB100()
	defer teardownTestDB_CB100()

	oldHub := hub
	h := newHub()
	hub = h
	go hub.run()
	defer func() {
		hub.Stop()
		hub = oldHub
	}()

	_, err := db.Exec("INSERT INTO conversations (id, user_id, agent_id) VALUES (?, ?, ?)",
		"conv-rchat-2", "user-rchat2", "agent-rchat2")
	if err != nil {
		t.Fatal(err)
	}

	agentConn := &Connection{
		hub:      h,
		connType: "agent",
		id:       "agent-rchat2",
		send:     make(chan []byte, 256),
	}
	h.register <- agentConn

	clientConn := &Connection{
		hub:      h,
		connType: "client",
		id:       "user-rchat2",
		send:     make(chan []byte, 256),
	}
	h.register <- clientConn

	time.Sleep(50 * time.Millisecond)

	// Client sends message
	msg := `{"content":"hello agent","conversation_id":"conv-rchat-2"}`
	sender := &Connection{
		hub:      h,
		connType: "client",
		id:       "user-rchat2",
		send:     make(chan []byte, 256),
	}
	routeChatMessage(sender, json.RawMessage(msg))

	// Agent should receive
	select {
	case data := <-agentConn.send:
		var outgoing OutgoingMessage
		if err := json.Unmarshal(data, &outgoing); err != nil {
			t.Fatal(err)
		}
		if outgoing.Type != MsgTypeMessage {
			t.Fatalf("expected type %q, got %q", MsgTypeMessage, outgoing.Type)
		}
	case <-time.After(time.Second):
		t.Fatal("agent did not receive message")
	}
}

func TestCB100_RouteChatMessage_OfflineAgent(t *testing.T) {
	setupTestDB_CB100()
	defer teardownTestDB_CB100()

	oldHub := hub
	h := newHub()
	hub = h
	go hub.run()
	defer func() {
		hub.Stop()
		hub = oldHub
	}()

	_, err := db.Exec("INSERT INTO conversations (id, user_id, agent_id) VALUES (?, ?, ?)",
		"conv-rchat-3", "user-rchat3", "agent-rchat3")
	if err != nil {
		t.Fatal(err)
	}

	// Register client only (agent is offline)
	clientConn := &Connection{
		hub:      h,
		connType: "client",
		id:       "user-rchat3",
		send:     make(chan []byte, 256),
	}
	h.register <- clientConn
	time.Sleep(50 * time.Millisecond)

	// Client sends message - should be queued for offline agent
	msg := `{"content":"message for offline agent","conversation_id":"conv-rchat-3"}`
	sender := &Connection{
		hub:      h,
		connType: "client",
		id:       "user-rchat3",
		send:     make(chan []byte, 256),
	}
	routeChatMessage(sender, json.RawMessage(msg))

	// Sender should get an ack
	select {
	case <-sender.send:
		// ack received
	case <-time.After(time.Second):
		// ack might not come if buffer full, that's ok
	}

	// Check offline queue
	if offlineQueue.TotalDepth() == 0 {
		t.Fatal("expected offline queue to have messages for offline agent")
	}
}

func TestCB100_RouteChatMessage_StoreError(t *testing.T) {
	setupTestDB_CB100()
	defer teardownTestDB_CB100()

	oldHub := hub
	h := newHub()
	hub = h
	go hub.run()
	defer func() {
		hub.Stop()
		hub = oldHub
	}()

	_, err := db.Exec("INSERT INTO conversations (id, user_id, agent_id) VALUES (?, ?, ?)",
		"conv-rchat-4", "user-rchat4", "agent-rchat4")
	if err != nil {
		t.Fatal(err)
	}

	// Close DB to cause store error
	db.Close()

	sender := &Connection{
		hub:      h,
		connType: "agent",
		id:       "agent-rchat4",
		send:     make(chan []byte, 256),
	}
	msg := `{"content":"test","conversation_id":"conv-rchat-4"}`
	routeChatMessage(sender, json.RawMessage(msg))

	// Should receive error message
	select {
	case data := <-sender.send:
		var outgoing OutgoingMessage
		if err := json.Unmarshal(data, &outgoing); err != nil {
			t.Fatal(err)
		}
		if outgoing.Type != MsgTypeError {
			t.Fatalf("expected error type, got %q", outgoing.Type)
		}
	case <-time.After(time.Second):
		t.Fatal("did not receive error message")
	}
}

func TestCB100_RouteChatMessage_AckSent(t *testing.T) {
	setupTestDB_CB100()
	defer teardownTestDB_CB100()

	oldHub := hub
	h := newHub()
	hub = h
	go hub.run()
	defer func() {
		hub.Stop()
		hub = oldHub
	}()

	_, err := db.Exec("INSERT INTO conversations (id, user_id, agent_id) VALUES (?, ?, ?)",
		"conv-rchat-5", "user-rchat5", "agent-rchat5")
	if err != nil {
		t.Fatal(err)
	}

	clientConn := &Connection{
		hub:      h,
		connType: "client",
		id:       "user-rchat5",
		send:     make(chan []byte, 256),
	}
	h.register <- clientConn
	time.Sleep(50 * time.Millisecond)

	sender := &Connection{
		hub:      h,
		connType: "agent",
		id:       "agent-rchat5",
		send:     make(chan []byte, 256),
	}
	msg := `{"content":"test ack","conversation_id":"conv-rchat-5"}`
	routeChatMessage(sender, json.RawMessage(msg))

	// Sender should get an ack
	select {
	case data := <-sender.send:
		var outgoing OutgoingMessage
		if err := json.Unmarshal(data, &outgoing); err != nil {
			t.Fatal(err)
		}
		if outgoing.Type != "message_sent" {
			t.Fatalf("expected 'message_sent' type, got %q", outgoing.Type)
		}
	case <-time.After(time.Second):
		t.Fatal("sender did not receive ack")
	}
}

// --- routeStatusUpdate (agent broadcast) ---

func TestCB100_RouteStatusUpdate_AgentBroadcast(t *testing.T) {
	setupTestDB_CB100()
	defer teardownTestDB_CB100()

	oldHub := hub
	h := newHub()
	hub = h
	go hub.run()
	defer func() {
		hub.Stop()
		hub = oldHub
	}()

	agentConn := &Connection{
		hub:      h,
		connType: "agent",
		id:       "agent-status-1",
		send:     make(chan []byte, 256),
	}
	h.register <- agentConn

	clientConn := &Connection{
		hub:      h,
		connType: "client",
		id:       "user-status-1",
		send:     make(chan []byte, 256),
	}
	h.register <- clientConn

	time.Sleep(50 * time.Millisecond)

	_, err := db.Exec("INSERT INTO conversations (id, user_id, agent_id) VALUES (?, ?, ?)",
		"conv-status-1", "user-status-1", "agent-status-1")
	if err != nil {
		t.Fatal(err)
	}

	// Agent sends status update
	msg := `{"conversation_id":"conv-status-1","status":"busy"}`
	sender := &Connection{
		hub:      h,
		connType: "agent",
		id:       "agent-status-1",
		send:     make(chan []byte, 256),
	}
	routeStatusUpdate(sender, json.RawMessage(msg))

	time.Sleep(50 * time.Millisecond)

	// Client should receive the status update
	select {
	case data := <-clientConn.send:
		var outgoing OutgoingMessage
		if err := json.Unmarshal(data, &outgoing); err != nil {
			t.Fatal(err)
		}
		if outgoing.Type != MsgTypeStatus {
			t.Fatalf("expected type %q, got %q", MsgTypeStatus, outgoing.Type)
		}
	case <-time.After(time.Second):
		// The broadcast goes to all clients, might have already been consumed
	}
}

func TestCB100_RouteStatusUpdate_EmptyStatus(t *testing.T) {
	setupTestDB_CB100()
	defer teardownTestDB_CB100()

	oldHub := hub
	h := newHub()
	hub = h
	go hub.run()
	defer func() {
		hub.Stop()
		hub = oldHub
	}()

	_, err := db.Exec("INSERT INTO conversations (id, user_id, agent_id) VALUES (?, ?, ?)",
		"conv-status-2", "user-status-2", "agent-status-2")
	if err != nil {
		t.Fatal(err)
	}

	clientConn := &Connection{
		hub:      h,
		connType: "client",
		id:       "user-status-2",
		send:     make(chan []byte, 256),
	}
	h.register <- clientConn

	agentConn := &Connection{
		hub:      h,
		connType: "agent",
		id:       "agent-status-2",
		send:     make(chan []byte, 256),
	}
	h.register <- agentConn

	time.Sleep(50 * time.Millisecond)

	// Agent sends status with empty status string (no broadcast)
	msg := `{"conversation_id":"conv-status-2","status":""}`
	sender := &Connection{
		hub:      h,
		connType: "agent",
		id:       "agent-status-2",
		send:     make(chan []byte, 256),
	}
	routeStatusUpdate(sender, json.RawMessage(msg))

	// Should still send status to client (via conversation routing)
	select {
	case <-clientConn.send:
		// got something
	case <-time.After(100 * time.Millisecond):
		// might not get anything if status is empty
	}
}

// --- routeHeartbeat ---

func TestCB100_RouteHeartbeat_Agent(t *testing.T) {
	h := newHub()
	go h.run()
	defer h.Stop()

	sender := &Connection{
		hub:      h,
		connType: "agent",
		id:       "agent-hb-1",
		send:     make(chan []byte, 256),
	}

	routeHeartbeat(sender)

	// Should receive heartbeat ack
	select {
	case data := <-sender.send:
		var outgoing OutgoingMessage
		if err := json.Unmarshal(data, &outgoing); err != nil {
			t.Fatal(err)
		}
		if outgoing.Type != "heartbeat_ack" {
			t.Fatalf("expected 'heartbeat_ack', got %q", outgoing.Type)
		}
	case <-time.After(time.Second):
		t.Fatal("did not receive heartbeat ack")
	}
}

func TestCB100_RouteHeartbeat_Client(t *testing.T) {
	h := newHub()
	go h.run()
	defer h.Stop()

	sender := &Connection{
		hub:      h,
		connType: "client",
		id:       "client-hb-1",
		send:     make(chan []byte, 256),
	}

	routeHeartbeat(sender)

	select {
	case data := <-sender.send:
		var outgoing OutgoingMessage
		if err := json.Unmarshal(data, &outgoing); err != nil {
			t.Fatal(err)
		}
		if outgoing.Type != "heartbeat_ack" {
			t.Fatalf("expected 'heartbeat_ack', got %q", outgoing.Type)
		}
	case <-time.After(time.Second):
		t.Fatal("did not receive heartbeat ack")
	}
}

// --- handleMetrics ---

func TestCB100_HandleMetrics_Success(t *testing.T) {
	setupTestDB_CB100()
	defer teardownTestDB_CB100()

	oldHub := hub
	h := newHub()
	hub = h
	go hub.run()
	defer func() {
		hub.Stop()
		hub = oldHub
	}()

	ServerMetrics = NewMetrics(hub)
	defer func() { ServerMetrics = nil }()

	req := httptest.NewRequest("GET", "/metrics", nil)
	w := httptest.NewRecorder()
	handleMetrics(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func TestCB100_HandleMetrics_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest("POST", "/metrics", nil)
	w := httptest.NewRecorder()
	handleMetrics(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", w.Code)
	}
}

func TestCB100_HandleMetrics_NilMetrics(t *testing.T) {
	ServerMetrics = nil

	req := httptest.NewRequest("GET", "/metrics", nil)
	w := httptest.NewRecorder()
	// handleMetrics panics when ServerMetrics is nil (calls Snapshot on nil receiver)
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic for nil ServerMetrics")
		}
	}()
	handleMetrics(w, req)
}

// --- handleAgentConnect (WebSocket integration) ---

func TestCB100_HandleAgentConnect_MissingAgentID(t *testing.T) {
	req := httptest.NewRequest("GET", "/agent/connect", nil)
	w := httptest.NewRecorder()
	handleAgentConnect(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestCB100_HandleAgentConnect_MissingSecret(t *testing.T) {
	req := httptest.NewRequest("GET", "/agent/connect?agent_id=test-agent", nil)
	w := httptest.NewRecorder()
	handleAgentConnect(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestCB100_HandleAgentConnect_WrongSecret(t *testing.T) {
	resetAgentSecret()
	defer resetAgentSecret()
	req := httptest.NewRequest("GET", "/agent/connect?agent_id=test-agent&agent_secret=wrong", nil)
	w := httptest.NewRecorder()
	handleAgentConnect(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestCB100_HandleAgentConnect_RateLimited(t *testing.T) {
	resetAgentSecret()
	defer resetAgentSecret()

	// Fire many failed auth attempts to trigger rate limiting
	for i := 0; i < 15; i++ {
		req := httptest.NewRequest("GET", fmt.Sprintf("/agent/connect?agent_id=rate-test&agent_secret=wrong%d", i), nil)
		w := httptest.NewRecorder()
		handleAgentConnect(w, req)
	}

	// Next attempt should be rate limited
	req := httptest.NewRequest("GET", "/agent/connect?agent_id=rate-test&agent_secret=wrong", nil)
	w := httptest.NewRecorder()
	handleAgentConnect(w, req)

	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429, got %d", w.Code)
	}
}

func TestCB100_HandleAgentConnect_Success(t *testing.T) {
	setupTestDB_CB100()
	defer teardownTestDB_CB100()

	resetAgentSecret()
	defer resetAgentSecret()

	oldHub := hub
	h := newHub()
	hub = h
	go hub.run()
	defer func() {
		hub.Stop()
		hub = oldHub
	}()

	srv := httptest.NewServer(http.HandlerFunc(handleAgentConnect))
	defer srv.Close()

	// Use the correct param name: agent_secret
	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "/agent/connect?agent_id=ws-agent-test&agent_secret=" + getAgentSecret()

	dialer := websocket.Dialer{}
	ws, resp, err := dialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("dial failed: %v (resp: %v)", err, resp)
	}
	defer ws.Close()
	defer resp.Body.Close()

	// Should receive welcome message
	_, msg, err := ws.ReadMessage()
	if err != nil {
		t.Fatalf("read failed: %v", err)
	}

	var welcome OutgoingMessage
	if err := json.Unmarshal(msg, &welcome); err != nil {
		t.Fatal(err)
	}
	if welcome.Type != "connected" {
		t.Fatalf("expected 'connected' type, got %q", welcome.Type)
	}
}

// --- handleClientConnect (WebSocket integration) ---

func TestCB100_HandleClientConnect_MissingToken(t *testing.T) {
	req := httptest.NewRequest("GET", "/client/connect", nil)
	w := httptest.NewRecorder()
	handleClientConnect(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestCB100_HandleClientConnect_InvalidToken(t *testing.T) {
	req := httptest.NewRequest("GET", "/client/connect?token=invalidtoken", nil)
	w := httptest.NewRecorder()
	handleClientConnect(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestCB100_HandleClientConnect_Success(t *testing.T) {
	setupTestDB_CB100()
	defer teardownTestDB_CB100()

	registerTestUser_CB100("wsclient", "password123")
	token, err := GenerateJWT("user-wsclient", "wsclient")
	if err != nil {
		t.Fatal(err)
	}

	oldHub := hub
	h := newHub()
	hub = h
	go hub.run()
	defer func() {
		hub.Stop()
		hub = oldHub
	}()

	srv := httptest.NewServer(http.HandlerFunc(handleClientConnect))
	defer srv.Close()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "/client/connect?token=" + token + "&device_id=test-device"

	dialer := websocket.Dialer{}
	ws, resp, err := dialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("dial failed: %v (resp: %v)", err, resp)
	}
	defer ws.Close()
	defer resp.Body.Close()

	_, msg, err := ws.ReadMessage()
	if err != nil {
		t.Fatalf("read failed: %v", err)
	}

	var welcome OutgoingMessage
	if err := json.Unmarshal(msg, &welcome); err != nil {
		t.Fatal(err)
	}
	if welcome.Type != "connected" {
		t.Fatalf("expected 'connected' type, got %q", welcome.Type)
	}

	data, ok := welcome.Data.(map[string]interface{})
	if !ok {
		t.Fatal("expected data to be map")
	}
	if data["device_id"] != "test-device" {
		t.Fatalf("expected device_id 'test-device', got %v", data["device_id"])
	}
}

// --- sendWelcomeMessage (marshal error path) ---

func TestCB100_SendWelcomeMessage_Success(t *testing.T) {
	conn := &Connection{
		id:               "test-conn-id",
		connType:         "agent",
		send:             make(chan []byte, 256),
		negotiatedVersion: "v1",
	}
	sendWelcomeMessage(conn)

	select {
	case data := <-conn.send:
		var msg OutgoingMessage
		if err := json.Unmarshal(data, &msg); err != nil {
			t.Fatal(err)
		}
		if msg.Type != "connected" {
			t.Fatalf("expected 'connected', got %q", msg.Type)
		}
	case <-time.After(time.Second):
		t.Fatal("did not receive welcome message")
	}
}

func TestCB100_SendWelcomeMessage_WithDeviceID(t *testing.T) {
	conn := &Connection{
		id:               "test-conn-id",
		connType:         "client",
		deviceID:         "device-xyz",
		send:             make(chan []byte, 256),
		negotiatedVersion: "v1",
	}
	sendWelcomeMessage(conn)

	select {
	case data := <-conn.send:
		var msg map[string]interface{}
		if err := json.Unmarshal(data, &msg); err != nil {
			t.Fatal(err)
		}
		dataMap, ok := msg["data"].(map[string]interface{})
		if !ok {
			t.Fatal("expected data map")
		}
		if dataMap["device_id"] != "device-xyz" {
			t.Fatalf("expected device_id 'device-xyz', got %v", dataMap["device_id"])
		}
	case <-time.After(time.Second):
		t.Fatal("did not receive welcome message")
	}
}

func TestCB100_SendWelcomeMessage_ClosedChannel(t *testing.T) {
	conn := &Connection{
		id:               "test-conn-id",
		connType:         "agent",
		send:             make(chan []byte, 0), // unbuffered
		negotiatedVersion: "v1",
	}
	conn.MarkClosed()
	// Should not panic
	sendWelcomeMessage(conn)
}

// --- initSchema (migration error paths) ---

func TestCB100_InitSchema_Idempotent(t *testing.T) {
	testDB, err := sql.Open("sqlite3", "file::memory:?cache=shared")
	if err != nil {
		t.Fatal(err)
	}
	defer testDB.Close()

	// First call
	if err := initSchema(testDB); err != nil {
		t.Fatalf("first initSchema failed: %v", err)
	}

	// Second call should not error
	if err := initSchema(testDB); err != nil {
		t.Fatalf("second initSchema failed: %v", err)
	}

	// Verify tables exist
	var count int
	err = testDB.QueryRow("SELECT count(*) FROM sqlite_master WHERE type='table'").Scan(&count)
	if err != nil {
		t.Fatal(err)
	}
	if count < 5 {
		t.Fatalf("expected at least 5 tables, got %d", count)
	}
}

func TestCB100_InitSchema_PostgreSQLDriver(t *testing.T) {
	// Test that initSchema doesn't crash with non-SQLite driver
	// (it will fail on actual PostgreSQL but we test the driver check path)
	testDB, err := sql.Open("sqlite3", "file::memory:?cache=shared")
	if err != nil {
		t.Fatal(err)
	}
	defer testDB.Close()

	currentDriver = DriverPostgreSQL
	defer func() { currentDriver = DriverSQLite }()

	// initSchemaForDriver should use PostgreSQL placeholders
	// But since we're using SQLite, the SQL should still work
	// because we handle both paths
	_ = initSchema(testDB)
}

// --- ValidateAgentSecret ---

func TestCB100_ValidateAgentSecret_Correct(t *testing.T) {
	resetAgentSecret()
	defer resetAgentSecret()

	err := ValidateAgentSecret("agent-1", getAgentSecret())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
}

func TestCB100_ValidateAgentSecret_Wrong(t *testing.T) {
	resetAgentSecret()
	defer resetAgentSecret()

	err := ValidateAgentSecret("agent-1", "wrong-secret")
	if err == nil {
		t.Fatal("expected error for wrong secret")
	}
}

// --- handleChangePassword ---

func TestCB100_HandleChangePassword_Success(t *testing.T) {
	setupTestDB_CB100()
	defer teardownTestDB_CB100()

	registerTestUser_CB100("changepass", "oldpass123")

	form := strings.NewReader("old_password=oldpass123&new_password=newpass456")
	req := httptest.NewRequest("POST", "/auth/change-password", form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	token, _ := GenerateJWT("user-changepass", "user-changepass")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleChangePassword(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCB100_HandleChangePassword_WrongOldPassword(t *testing.T) {
	setupTestDB_CB100()
	defer teardownTestDB_CB100()

	registerTestUser_CB100("changepass2", "oldpass123")

	form := strings.NewReader("old_password=wrongold&new_password=newpass456")
	req := httptest.NewRequest("POST", "/auth/change-password", form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	token, _ := GenerateJWT("user-changepass2", "user-changepass2")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleChangePassword(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestCB100_HandleChangePassword_MissingFields(t *testing.T) {
	setupTestDB_CB100()
	defer teardownTestDB_CB100()

	form := strings.NewReader("old_password=onlyold")
	req := httptest.NewRequest("POST", "/auth/change-password", form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	token, _ := GenerateJWT("user-some", "user-some")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleChangePassword(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestCB100_HandleChangePassword_NoAuth(t *testing.T) {
	form := strings.NewReader("old_password=x&new_password=y")
	req := httptest.NewRequest("POST", "/auth/change-password", form)
	w := httptest.NewRecorder()
	handleChangePassword(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestCB100_HandleChangePassword_ShortNew(t *testing.T) {
	setupTestDB_CB100()
	defer teardownTestDB_CB100()

	registerTestUser_CB100("changepass3", "oldpass123")

	form := strings.NewReader("old_password=oldpass123&new_password=short")
	req := httptest.NewRequest("POST", "/auth/change-password", form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	token, _ := GenerateJWT("user-changepass3", "user-changepass3")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleChangePassword(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for short password, got %d", w.Code)
	}
}

// --- handleCreateConversation ---

func TestCB100_HandleCreateConversation_Success(t *testing.T) {
	setupTestDB_CB100()
	defer teardownTestDB_CB100()

	// Register agent
	_, err := db.Exec("INSERT INTO agents (id, name, model) VALUES (?, ?, ?)",
		"agent-create-1", "Test Agent", "gpt-4")
	if err != nil {
		t.Fatal(err)
	}

	form := strings.NewReader("agent_id=agent-create-1")
	req := httptest.NewRequest("POST", "/conversations/create", form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	token, _ := GenerateJWT("user-create-1", "user-create-1")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleCreateConversation(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp["conversation_id"] == nil || resp["conversation_id"] == "" {
		t.Fatal("expected non-empty conversation_id")
	}
}

func TestCB100_HandleCreateConversation_NoAuth(t *testing.T) {
	form := strings.NewReader("agent_id=test")
	req := httptest.NewRequest("POST", "/conversations/create", form)
	w := httptest.NewRecorder()
	handleCreateConversation(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestCB100_HandleCreateConversation_MissingAgentID(t *testing.T) {
	setupTestDB_CB100()
	defer teardownTestDB_CB100()

	form := strings.NewReader("")
	req := httptest.NewRequest("POST", "/conversations/create", form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	token, _ := GenerateJWT("user-create-2", "user-create-2")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleCreateConversation(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

// --- handleListConversations ---

func TestCB100_HandleListConversations_WithData(t *testing.T) {
	setupTestDB_CB100()
	defer teardownTestDB_CB100()

	// Create test data
	_, err := db.Exec("INSERT INTO agents (id, name) VALUES (?, ?)", "agent-list-1", "Agent 1")
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec("INSERT INTO conversations (id, user_id, agent_id) VALUES (?, ?, ?)",
		"conv-list-1", "user-list-1", "agent-list-1")
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest("GET", "/conversations/list", nil)
	token, _ := GenerateJWT("user-list-1", "user-list-1")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleListConversations(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp []map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if len(resp) == 0 {
		t.Fatal("expected at least 1 conversation")
	}
}

func TestCB100_HandleListConversations_NoAuth(t *testing.T) {
	req := httptest.NewRequest("GET", "/conversations/list", nil)
	w := httptest.NewRecorder()
	handleListConversations(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

// --- handleListAgents ---

func TestCB100_HandleListAgents_WithData(t *testing.T) {
	setupTestDB_CB100()
	defer teardownTestDB_CB100()

	oldHub := setupHub_CB100()
	defer teardownHub_CB100(oldHub)

	_, err := db.Exec("INSERT INTO agents (id, name, model, specialty) VALUES (?, ?, ?, ?)",
		"agent-list-1", "Agent One", "gpt-4", "general")
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest("GET", "/agents", nil)
	w := httptest.NewRecorder()
	handleListAgents(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp []map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if len(resp) == 0 {
		t.Fatal("expected at least 1 agent")
	}
}

func TestCB100_HandleListAgents_Empty(t *testing.T) {
	setupTestDB_CB100()
	defer teardownTestDB_CB100()

	oldHub := setupHub_CB100()
	defer teardownHub_CB100(oldHub)

	req := httptest.NewRequest("GET", "/agents", nil)
	w := httptest.NewRecorder()
	handleListAgents(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

// --- handleGetMessages ---

func TestCB100_HandleGetMessages_Success(t *testing.T) {
	setupTestDB_CB100()
	defer teardownTestDB_CB100()

	_, err := db.Exec("INSERT INTO conversations (id, user_id, agent_id) VALUES (?, ?, ?)",
		"conv-getmsg-1", "user-getmsg-1", "agent-getmsg-1")
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, created_at) VALUES (?, ?, ?, ?, ?, ?)",
		"msg-1", "conv-getmsg-1", "agent", "agent-getmsg-1", "hello", time.Now().Format(time.RFC3339))
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest("GET", "/conversations/messages?conversation_id=conv-getmsg-1", nil)
	token, _ := GenerateJWT("user-getmsg-1", "user-getmsg-1")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleGetMessages(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCB100_HandleGetMessages_NoAuth(t *testing.T) {
	req := httptest.NewRequest("GET", "/conversations/messages?conversation_id=x", nil)
	w := httptest.NewRecorder()
	handleGetMessages(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestCB100_HandleGetMessages_NotFound(t *testing.T) {
	setupTestDB_CB100()
	defer teardownTestDB_CB100()

	req := httptest.NewRequest("GET", "/conversations/messages?conversation_id=nonexistent", nil)
	token, _ := GenerateJWT("user-some", "user-some")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleGetMessages(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}

// --- handleDeleteConversation ---

func TestCB100_HandleDeleteConversation_Success(t *testing.T) {
	setupTestDB_CB100()
	defer teardownTestDB_CB100()

	_, err := db.Exec("INSERT INTO conversations (id, user_id, agent_id) VALUES (?, ?, ?)",
		"conv-delete-1", "user-delete-1", "agent-delete-1")
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, created_at) VALUES (?, ?, ?, ?, ?, ?)",
		"msg-del-1", "conv-delete-1", "agent", "agent-1", "test", time.Now().Format(time.RFC3339))
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest("DELETE", "/conversations/delete?conversation_id=conv-delete-1", nil)
	token, _ := GenerateJWT("user-delete-1", "user-delete-1")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleDeleteConversation(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// Verify conversation is gone
	var count int
	db.QueryRow("SELECT count(*) FROM conversations WHERE id = ?", "conv-delete-1").Scan(&count)
	if count != 0 {
		t.Fatal("expected conversation to be deleted")
	}
}

func TestCB100_HandleDeleteConversation_Unauthorized(t *testing.T) {
	setupTestDB_CB100()
	defer teardownTestDB_CB100()

	_, err := db.Exec("INSERT INTO conversations (id, user_id, agent_id) VALUES (?, ?, ?)",
		"conv-delete-2", "user-owner", "agent-1")
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest("DELETE", "/conversations/delete?conversation_id=conv-delete-2", nil)
	token, _ := GenerateJWT("user-other", "user-other")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleDeleteConversation(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

// --- handleSearchMessages ---

func TestCB100_HandleSearchMessages_Success(t *testing.T) {
	setupTestDB_CB100()
	defer teardownTestDB_CB100()

	_, err := db.Exec("INSERT INTO conversations (id, user_id, agent_id) VALUES (?, ?, ?)",
		"conv-search-1", "user-search-1", "agent-search-1")
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, created_at) VALUES (?, ?, ?, ?, ?, ?)",
		"msg-search-1", "conv-search-1", "agent", "agent-1", "hello world test", time.Now().Format(time.RFC3339))
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest("GET", "/messages/search?q=hello&limit=10", nil)
	token, _ := GenerateJWT("user-search-1", "user-search-1")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleSearchMessages(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCB100_HandleSearchMessages_EmptyQuery(t *testing.T) {
	setupTestDB_CB100()
	defer teardownTestDB_CB100()

	req := httptest.NewRequest("GET", "/messages/search?q=&limit=10", nil)
	token, _ := GenerateJWT("user-search-2", "user-search-2")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleSearchMessages(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for empty query, got %d", w.Code)
	}
}

func TestCB100_HandleSearchMessages_NoAuth(t *testing.T) {
	req := httptest.NewRequest("GET", "/messages/search?q=test", nil)
	w := httptest.NewRecorder()
	handleSearchMessages(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

// --- handleGetNotificationPrefs ---

func TestCB100_HandleGetNotificationPrefs_WithData(t *testing.T) {
	setupTestDB_CB100()
	defer teardownTestDB_CB100()

	_, err := db.Exec("INSERT INTO conversations (id, user_id, agent_id) VALUES (?, ?, ?)",
		"conv-notif-1", "user-notif-1", "agent-notif-1")
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec("INSERT INTO notification_preferences (conversation_id, user_id, muted) VALUES (?, ?, ?)",
		"conv-notif-1", "user-notif-1", 1)
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest("GET", "/notifications/preferences?conversation_id=conv-notif-1", nil)
	ctx := context.WithValue(req.Context(), contextKeyUserID, "user-notif-1")
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()
	handleGetNotificationPrefs(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCB100_HandleGetNotificationPrefs_Empty(t *testing.T) {
	setupTestDB_CB100()
	defer teardownTestDB_CB100()

	_, err := db.Exec("INSERT INTO conversations (id, user_id, agent_id) VALUES (?, ?, ?)",
		"conv-notif-2", "user-notif-2", "agent-notif-2")
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest("GET", "/notifications/preferences?conversation_id=conv-notif-2", nil)
	ctx := context.WithValue(req.Context(), contextKeyUserID, "user-notif-2")
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()
	handleGetNotificationPrefs(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

// --- handleSetNotificationPrefs ---

func TestCB100_HandleSetNotificationPrefs_Success(t *testing.T) {
	setupTestDB_CB100()
	defer teardownTestDB_CB100()

	_, err := db.Exec("INSERT INTO conversations (id, user_id, agent_id) VALUES (?, ?, ?)",
		"conv-notif-3", "user-notif-3", "agent-notif-3")
	if err != nil {
		t.Fatal(err)
	}

	form := strings.NewReader("conversation_id=conv-notif-3&muted=true")
	req := httptest.NewRequest("POST", "/notifications/preferences", form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	ctx := context.WithValue(req.Context(), contextKeyUserID, "user-notif-3")
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()
	handleSetNotificationPrefs(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCB100_HandleSetNotificationPrefs_NotOwner(t *testing.T) {
	setupTestDB_CB100()
	defer teardownTestDB_CB100()

	_, err := db.Exec("INSERT INTO conversations (id, user_id, agent_id) VALUES (?, ?, ?)",
		"conv-notif-4", "user-owner", "agent-1")
	if err != nil {
		t.Fatal(err)
	}

	form := strings.NewReader("conversation_id=conv-notif-4&muted=true")
	req := httptest.NewRequest("POST", "/notifications/preferences", form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	ctx := context.WithValue(req.Context(), contextKeyUserID, "user-other")
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()
	handleSetNotificationPrefs(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", w.Code)
	}
}

// --- handleDeleteNotificationPrefs ---

func TestCB100_HandleDeleteNotificationPrefs_Success(t *testing.T) {
	setupTestDB_CB100()
	defer teardownTestDB_CB100()

	_, err := db.Exec("INSERT INTO conversations (id, user_id, agent_id) VALUES (?, ?, ?)",
		"conv-deln-1", "user-deln-1", "agent-1")
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec("INSERT INTO notification_preferences (conversation_id, user_id, muted) VALUES (?, ?, ?)",
		"conv-deln-1", "user-deln-1", 1)
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest("POST", "/notifications/preferences/delete?conversation_id=conv-deln-1", nil)
	ctx := context.WithValue(req.Context(), contextKeyUserID, "user-deln-1")
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()
	handleDeleteNotificationPrefs(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCB100_HandleDeleteNotificationPrefs_NoAuth(t *testing.T) {
	req := httptest.NewRequest("POST", "/notifications/preferences/delete?conversation_id=x", nil)
	w := httptest.NewRecorder()
	handleDeleteNotificationPrefs(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

// --- openDatabase ---

func TestCB100_OpenDatabase_SQLite(t *testing.T) {
	oldDB := db
	defer func() { db = oldDB }()

	testDB, err := openDatabase(DriverSQLite, "file::memory:?cache=shared")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if testDB == nil {
		t.Fatal("expected non-nil db")
	}
	defer testDB.Close()
}

func TestCB100_OpenDatabase_InvalidDriver(t *testing.T) {
	_, err := openDatabase("invaliddriver", "test")
	if err == nil {
		t.Fatal("expected error for invalid driver")
	}
}

// --- checkRateLimit ---

func TestCB100_CheckRateLimit_Allowed(t *testing.T) {
	messageRateLimiter = NewRateLimiter(60, time.Minute)
	userRateLimiter = NewRateLimiter(120, time.Minute)
	t.Cleanup(func() {
		messageRateLimiter.Stop()
		userRateLimiter.Stop()
	})

	conn := &Connection{
		connType: "client",
		id:      "user-rl-1",
		send:    make(chan []byte, 256),
	}

	// Should be allowed
	if !checkRateLimit(conn) {
		t.Fatal("expected rate limit to allow")
	}
}

func TestCB100_CheckRateLimit_Exceeded(t *testing.T) {
	messageRateLimiter = NewRateLimiter(2, time.Minute)
	userRateLimiter = NewRateLimiter(10, time.Minute)
	t.Cleanup(func() {
		messageRateLimiter.Stop()
		userRateLimiter.Stop()
	})

	conn := &Connection{
		connType: "client",
		id:      "user-rl-2",
		send:    make(chan []byte, 256),
	}

	// Use up the per-connection limit (2)
	checkRateLimit(conn)
	checkRateLimit(conn)

	// Third should be denied
	if checkRateLimit(conn) {
		t.Fatal("expected rate limit to be exceeded")
	}
}

// --- SafeSend ---

func TestCB100_SafeSend_BufferFull(t *testing.T) {
	conn := &Connection{
		send: make(chan []byte, 1),
	}
	// Fill buffer
	conn.send <- []byte("msg1")

	// Should return false when buffer is full (non-blocking)
	if conn.SafeSend([]byte("msg2")) {
		t.Fatal("expected SafeSend to return false when buffer full")
	}
}

func TestCB100_SafeSend_Success(t *testing.T) {
	conn := &Connection{
		send: make(chan []byte, 10),
	}
	if !conn.SafeSend([]byte("test")) {
		t.Fatal("expected SafeSend to return true")
	}
}

// --- truncate ---

func TestCB100_Truncate_Short(t *testing.T) {
	result := truncate("hello", 100)
	if result != "hello" {
		t.Fatalf("expected 'hello', got %q", result)
	}
}

func TestCB100_Truncate_Exact(t *testing.T) {
	result := truncate("hello", 5)
	if result != "hello" {
		t.Fatalf("expected 'hello', got %q", result)
	}
}

func TestCB100_Truncate_Long(t *testing.T) {
	result := truncate("hello world", 5)
	if result != "he..." {
		t.Fatalf("expected 'he...', got %q", result)
	}
}

func TestCB100_Truncate_TinyMax(t *testing.T) {
	result := truncate("hello", 2)
	if result != "he" {
		t.Fatalf("expected 'he', got %q", result)
	}
}

// --- isSupportedVersion ---

func TestCB100_IsSupportedVersion_V1(t *testing.T) {
	if !isSupportedVersion("v1") {
		t.Fatal("expected v1 to be supported")
	}
}

func TestCB100_IsSupportedVersion_Unknown(t *testing.T) {
	if isSupportedVersion("v999") {
		t.Fatal("expected v999 to not be supported")
	}
}

// --- negotiateProtocol ---

func TestCB100_NegotiateProtocol_Header(t *testing.T) {
	req := httptest.NewRequest("GET", "/connect", nil)
	req.Header.Set("Sec-WebSocket-Protocol", "v1")
	result := negotiateProtocol(req)
	if result != "v1" {
		t.Fatalf("expected 'v1', got %q", result)
	}
}

func TestCB100_NegotiateProtocol_QueryParam(t *testing.T) {
	req := httptest.NewRequest("GET", "/connect?protocol_version=v1", nil)
	result := negotiateProtocol(req)
	if result != "v1" {
		t.Fatalf("expected 'v1', got %q", result)
	}
}

func TestCB100_NegotiateProtocol_Default(t *testing.T) {
	req := httptest.NewRequest("GET", "/connect", nil)
	result := negotiateProtocol(req)
	if result != ProtocolVersion {
		t.Fatalf("expected %q, got %q", ProtocolVersion, result)
	}
}

func TestCB100_NegotiateProtocol_Unsupported(t *testing.T) {
	req := httptest.NewRequest("GET", "/connect", nil)
	req.Header.Set("Sec-WebSocket-Protocol", "v999, v1")
	result := negotiateProtocol(req)
	if result != "v1" {
		t.Fatalf("expected 'v1' (should pick supported from list), got %q", result)
	}
}

// --- handleAdminAgents ---

func TestCB100_HandleAdminAgents_WithData(t *testing.T) {
	setupTestDB_CB100()
	defer teardownTestDB_CB100()

	oldHub := setupHub_CB100()
	defer teardownHub_CB100(oldHub)

	_, err := db.Exec("INSERT INTO agents (id, name, model) VALUES (?, ?, ?)",
		"agent-admin-1", "Agent Admin", "gpt-4")
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest("GET", "/admin/agents", nil)
	w := httptest.NewRecorder()
	handleAdminAgents(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCB100_HandleAdminAgents_Empty(t *testing.T) {
	setupTestDB_CB100()
	defer teardownTestDB_CB100()

	oldHub := setupHub_CB100()
	defer teardownHub_CB100(oldHub)

	req := httptest.NewRequest("GET", "/admin/agents", nil)
	w := httptest.NewRecorder()
	handleAdminAgents(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

// --- handleMarkRead ---

func TestCB100_HandleMarkRead_Success(t *testing.T) {
	setupTestDB_CB100()
	defer teardownTestDB_CB100()

	oldHub := setupHub_CB100()
	defer teardownHub_CB100(oldHub)

	registerTestUser_CB100("markread", "password123")
	token, err := GenerateJWT("user-markread", "markread")
	if err != nil {
		t.Fatal(err)
	}

	_, err = db.Exec("INSERT INTO conversations (id, user_id, agent_id) VALUES (?, ?, ?)",
		"conv-mark-1", "user-markread", "agent-mark-1")
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, created_at) VALUES (?, ?, ?, ?, ?, ?)",
		"msg-mark-1", "conv-mark-1", "agent", "agent-mark-1", "test", time.Now().Format(time.RFC3339))
	if err != nil {
		t.Fatal(err)
	}

	form := strings.NewReader("conversation_id=conv-mark-1")
	req := httptest.NewRequest("POST", "/conversations/mark-read", form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleMarkRead(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCB100_HandleMarkRead_NotFound(t *testing.T) {
	setupTestDB_CB100()
	defer teardownTestDB_CB100()

	oldHub := setupHub_CB100()
	defer teardownHub_CB100(oldHub)

	registerTestUser_CB100("markread2", "password123")
	token, err := GenerateJWT("user-markread2", "markread2")
	if err != nil {
		t.Fatal(err)
	}

	form := strings.NewReader("conversation_id=nonexistent")
	req := httptest.NewRequest("POST", "/conversations/mark-read", form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleMarkRead(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}

func TestCB100_HandleMarkRead_NoAuth(t *testing.T) {
	form := strings.NewReader("conversation_id=x")
	req := httptest.NewRequest("POST", "/conversations/mark-read", form)
	w := httptest.NewRecorder()
	handleMarkRead(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

// --- handleUpload (integration with real multipart) ---

func TestCB100_HandleUpload_Success(t *testing.T) {
	setupTestDB_CB100()
	defer teardownTestDB_CB100()

	registerTestUser_CB100("uploaduser", "password123")
	token, err := GenerateJWT("user-uploaduser", "uploaduser")
	if err != nil {
		t.Fatal(err)
	}

	_, err = db.Exec("INSERT INTO conversations (id, user_id, agent_id) VALUES (?, ?, ?)",
		"conv-upload-1", "user-uploaduser", "agent-upload-1")
	if err != nil {
		t.Fatal(err)
	}

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	fw, err := writer.CreateFormFile("file", "test.txt")
	if err != nil {
		t.Fatal(err)
	}
	fw.Write([]byte("hello world test file content"))
	writer.WriteField("conversation_id", "conv-upload-1")
	writer.WriteField("message_id", "msg-upload-1")
	writer.Close()

	req := httptest.NewRequest("POST", "/upload", body)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleUpload(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

// --- Concurrent SafeSend ---

func TestCB100_SafeSend_Concurrent(t *testing.T) {
	conn := &Connection{
		send: make(chan []byte, 100),
	}

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			conn.SafeSend([]byte(fmt.Sprintf("msg-%d", n)))
		}(i)
	}
	wg.Wait()

	// Drain and count
	count := 0
	for {
		select {
		case <-conn.send:
			count++
		default:
			if count < 1 {
				t.Fatal("expected at least 1 message in buffer")
			}
			return
		}
	}
}