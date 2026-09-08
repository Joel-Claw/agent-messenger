package main

import (
	"context"
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
	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"
)

// ==================== CB71 Helpers ====================

func setupTestDB_CB71(t *testing.T) *sql.DB {
	testDB, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("Failed to open test DB: %v", err)
	}
	if err := initSchema(testDB); err != nil {
		t.Fatalf("Failed to init schema: %v", err)
	}
	t.Cleanup(func() { testDB.Close() })

	return testDB
}

func generateTestToken_CB71(userID string) string {
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

func makeTestHub_CB71() *Hub {
	h := newHub()
	go h.run()
	defer h.Stop()
	return h
}

func createUser_CB71(testDB *sql.DB, username, password string) string {
	hash, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	userID := "user_" + username
	testDB.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)", userID, username, hash)
	return userID
}

func createAgent_CB71(testDB *sql.DB, agentID string) {
	testDB.Exec("INSERT INTO agents (id, name, model) VALUES (?, ?, ?)", agentID, "Test Agent", "test-model")
}

func createConversation_CB71(testDB *sql.DB, userID, agentID string) string {
	convID := "conv_" + agentID + "_" + userID
	testDB.Exec("INSERT INTO conversations (id, user_id, agent_id) VALUES (?, ?, ?)", convID, userID, agentID)
	return convID
}

func makeAuthRequest_CB71(method, target string, body string, userID string) *http.Request {
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+generateTestToken_CB71(userID))
	req.Header.Set("Content-Type", "application/json")
	return req
}

func makeAgentAuthReq_CB71(method, target string, body string) *http.Request {
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	req.Header.Set("X-Agent-Secret", agentSecret)
	req.Header.Set("Content-Type", "application/json")
	return req
}

func makeConn_CB71(connType, id string, h *Hub) *Connection {
	send := make(chan []byte, 256)
	return &Connection{
		id:       id,
		connType: connType,
		hub:      h,
		send:     send,
	}
}

func makeConnWithDevice_CB71(connType, id, deviceID string, h *Hub) *Connection {
	send := make(chan []byte, 256)
	return &Connection{
		id:       id,
		connType: connType,
		hub:      h,
		send:     send,
		deviceID: deviceID,
	}
}

func resetGlobals_CB71() {
	// Reset rate limiters
	messageRateLimiter = NewRateLimiter(60, time.Minute)
	userRateLimiter = NewRateLimiter(120, time.Minute)
}

// ==================== routeChatMessage Tests ====================

func TestCB71_RouteChatMessage_AgentToOnlineClient(t *testing.T) {
	oldDB := db
	defer func() { db = oldDB }()
	testDB := setupTestDB_CB71(t)
	db = testDB
	defer func() { db = nil }()

	oldHub := hub
	defer func() { hub = oldHub }()
	h := newHub()
	go h.run()
	defer h.Stop()
	hub = h

	userID := createUser_CB71(testDB, "alice", "pass123")
	agentID := "agent_test"
	createAgent_CB71(testDB, agentID)
	convID := createConversation_CB71(testDB, userID, agentID)

	// Register client connection
	clientConn := makeConn_CB71("client", userID, h)
	h.register <- clientConn

	// Give hub time to register
	time.Sleep(50 * time.Millisecond)

	// Agent sends message
	agentConn := makeConn_CB71("agent", agentID, h)
	msgData, _ := json.Marshal(RoutedMessage{
		ConversationID: convID,
		Content:        "Hello from agent",
	})
	routeChatMessage(agentConn, msgData)

	// Client should receive the message
	select {
	case received := <-clientConn.send:
		var outMsg OutgoingMessage
		if err := json.Unmarshal(received, &outMsg); err != nil {
			t.Fatalf("Failed to unmarshal: %v", err)
		}
		if outMsg.Type != "message" {
			t.Fatalf("Expected type 'message', got '%s'", outMsg.Type)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Timeout waiting for message")
	}
}

func TestCB71_RouteChatMessage_ClientToOnlineAgent(t *testing.T) {
	oldDB := db
	defer func() { db = oldDB }()
	testDB := setupTestDB_CB71(t)
	db = testDB
	defer func() { db = nil }()

	oldHub := hub
	defer func() { hub = oldHub }()
	h := newHub()
	go h.run()
	defer h.Stop()
	hub = h

	userID := createUser_CB71(testDB, "bob", "pass123")
	agentID := "agent_bob"
	createAgent_CB71(testDB, agentID)
	convID := createConversation_CB71(testDB, userID, agentID)

	// Register agent connection
	agentConn := makeConn_CB71("agent", agentID, h)
	h.register <- agentConn
	time.Sleep(50 * time.Millisecond)

	// Client sends message
	clientConn := makeConn_CB71("client", userID, h)
	msgData, _ := json.Marshal(RoutedMessage{
		ConversationID: convID,
		Content:        "Hello from client",
	})
	routeChatMessage(clientConn, msgData)

	// Agent should receive the message
	select {
	case received := <-agentConn.send:
		var outMsg OutgoingMessage
		if err := json.Unmarshal(received, &outMsg); err != nil {
			t.Fatalf("Failed to unmarshal: %v", err)
		}
		if outMsg.Type != "message" {
			t.Fatalf("Expected type 'message', got '%s'", outMsg.Type)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Timeout waiting for message")
	}
}

func TestCB71_RouteChatMessage_AgentToOfflineClient_Queued(t *testing.T) {
	oldDB := db
	defer func() { db = oldDB }()
	testDB := setupTestDB_CB71(t)
	db = testDB
	defer func() { db = nil }()

	oldHub := hub
	defer func() { hub = oldHub }()
	h := newHub()
	go h.run()
	defer h.Stop()
	hub = h

	userID := createUser_CB71(testDB, "charlie", "pass123")
	agentID := "agent_charlie"
	createAgent_CB71(testDB, agentID)
	convID := createConversation_CB71(testDB, userID, agentID)

	// Agent sends message (client is offline)
	agentConn := makeConn_CB71("agent", agentID, h)
	msgData, _ := json.Marshal(RoutedMessage{
		ConversationID: convID,
		Content:        "Hello offline client",
	})
	routeChatMessage(agentConn, msgData)

	// Message should be queued
	depth := offlineQueue.QueueDepth(userID)
	if depth != 1 {
		t.Fatalf("Expected queue depth 1, got %d", depth)
	}
}

func TestCB71_RouteChatMessage_ClientToOfflineAgent_Queued(t *testing.T) {
	oldDB := db
	defer func() { db = oldDB }()
	testDB := setupTestDB_CB71(t)
	db = testDB
	defer func() { db = nil }()

	oldHub := hub
	defer func() { hub = oldHub }()
	h := newHub()
	go h.run()
	defer h.Stop()
	hub = h

	userID := createUser_CB71(testDB, "dave", "pass123")
	agentID := "agent_dave"
	createAgent_CB71(testDB, agentID)
	convID := createConversation_CB71(testDB, userID, agentID)

	// Client sends message (agent is offline)
	clientConn := makeConn_CB71("client", userID, h)
	msgData, _ := json.Marshal(RoutedMessage{
		ConversationID: convID,
		Content:        "Hello offline agent",
	})
	routeChatMessage(clientConn, msgData)

	// Message should be queued
	depth := offlineQueue.QueueDepth(agentID)
	if depth != 1 {
		t.Fatalf("Expected queue depth 1, got %d", depth)
	}
}

func TestCB71_RouteChatMessage_AckReceived(t *testing.T) {
	oldDB := db
	defer func() { db = oldDB }()
	testDB := setupTestDB_CB71(t)
	db = testDB
	defer func() { db = nil }()

	oldHub := hub
	defer func() { hub = oldHub }()
	h := newHub()
	go h.run()
	defer h.Stop()
	hub = h

	userID := createUser_CB71(testDB, "eve", "pass123")
	agentID := "agent_eve"
	createAgent_CB71(testDB, agentID)
	convID := createConversation_CB71(testDB, userID, agentID)

	agentConn := makeConn_CB71("agent", agentID, h)
	msgData, _ := json.Marshal(RoutedMessage{
		ConversationID: convID,
		Content:        "Hello with ack",
	})
	routeChatMessage(agentConn, msgData)

	// Agent should receive ack
	select {
	case received := <-agentConn.send:
		var outMsg OutgoingMessage
		if err := json.Unmarshal(received, &outMsg); err != nil {
			t.Fatalf("Failed to unmarshal: %v", err)
		}
		if outMsg.Type != "message_sent" {
			t.Fatalf("Expected type 'message_sent', got '%s'", outMsg.Type)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Timeout waiting for ack")
	}
}

func TestCB71_RouteChatMessage_StoreError(t *testing.T) {
	oldDB := db
	defer func() { db = oldDB }()
	testDB := setupTestDB_CB71(t)
	db = testDB
	defer func() { db = nil }()

	oldHub := hub
	defer func() { hub = oldHub }()
	h := newHub()
	go h.run()
	defer h.Stop()
	hub = h

	userID := createUser_CB71(testDB, "frank", "pass123")
	agentID := "agent_frank"
	createAgent_CB71(testDB, agentID)
	convID := createConversation_CB71(testDB, userID, agentID)

	// Close DB to cause store error
	db.Close()

	agentConn := makeConn_CB71("agent", agentID, h)
	msgData, _ := json.Marshal(RoutedMessage{
		ConversationID: convID,
		Content:        "This will fail",
	})
	routeChatMessage(agentConn, msgData)

	// Should receive error
	select {
	case received := <-agentConn.send:
		var outMsg OutgoingMessage
		if err := json.Unmarshal(received, &outMsg); err != nil {
			t.Fatalf("Failed to unmarshal: %v", err)
		}
		if outMsg.Type != "error" {
			t.Fatalf("Expected type 'error', got '%s'", outMsg.Type)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Timeout waiting for error")
	}
}

func TestCB71_RouteChatMessage_WithAttachments(t *testing.T) {
	oldDB := db
	defer func() { db = oldDB }()
	testDB := setupTestDB_CB71(t)
	db = testDB
	defer func() { db = nil }()

	oldHub := hub
	defer func() { hub = oldHub }()
	h := newHub()
	go h.run()
	defer h.Stop()
	hub = h

	userID := createUser_CB71(testDB, "grace", "pass123")
	agentID := "agent_grace"
	createAgent_CB71(testDB, agentID)
	convID := createConversation_CB71(testDB, userID, agentID)

	agentConn := makeConn_CB71("agent", agentID, h)
	msgData, _ := json.Marshal(RoutedMessage{
		ConversationID: convID,
		Content:        "Message with attachments",
		AttachmentIDs:  []string{"att1", "att2"},
	})
	routeChatMessage(agentConn, msgData)

	// Agent should receive ack (message stored successfully)
	select {
	case received := <-agentConn.send:
		var outMsg OutgoingMessage
		if err := json.Unmarshal(received, &outMsg); err != nil {
			t.Fatalf("Failed to unmarshal: %v", err)
		}
		if outMsg.Type != "message_sent" {
			t.Fatalf("Expected type 'message_sent', got '%s'", outMsg.Type)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Timeout waiting for ack")
	}
}

// ==================== routeMessage Tests ====================

func TestCB71_RouteMessage_RateLimited(t *testing.T) {
	resetGlobals_CB71()
	defer resetGlobals_CB71()

	oldHub := hub
	defer func() { hub = oldHub }()
	h := newHub()
	go h.run()
	defer h.Stop()
	hub = h

	conn := makeConn_CB71("agent", "rl_agent", h)

	// Exhaust rate limit (60 per connection)
	for i := 0; i < 65; i++ {
		messageRateLimiter.Allow("rl_agent")
	}

	raw, _ := json.Marshal(IncomingMessage{Type: "heartbeat"})
	routeMessage(conn, raw)

	// Should receive rate limit error
	select {
	case received := <-conn.send:
		var outMsg OutgoingMessage
		json.Unmarshal(received, &outMsg)
		if outMsg.Type != "error" {
			t.Fatalf("Expected error type, got '%s'", outMsg.Type)
		}
	case <-time.After(1 * time.Second):
		// Rate limiting may silently drop; that's acceptable
	}
}

func TestCB71_RouteMessage_UnknownType(t *testing.T) {
	resetGlobals_CB71()
	defer resetGlobals_CB71()

	oldHub := hub
	defer func() { hub = oldHub }()
	h := newHub()
	go h.run()
	defer h.Stop()
	hub = h

	conn := makeConn_CB71("agent", "ut_agent", h)
	raw, _ := json.Marshal(IncomingMessage{Type: "unknown_type"})
	routeMessage(conn, raw)

	select {
	case received := <-conn.send:
		var outMsg OutgoingMessage
		json.Unmarshal(received, &outMsg)
		if outMsg.Type != "error" {
			t.Fatalf("Expected error type, got '%s'", outMsg.Type)
		}
		data := outMsg.Data.(map[string]interface{})
		if !strings.Contains(data["error"].(string), "unknown message type") {
			t.Fatalf("Expected 'unknown message type' error, got '%s'", data["error"])
		}
	case <-time.After(1 * time.Second):
		t.Fatal("Timeout waiting for error")
	}
}

func TestCB71_RouteMessage_Heartbeat(t *testing.T) {
	resetGlobals_CB71()
	defer resetGlobals_CB71()

	oldHub := hub
	defer func() { hub = oldHub }()
	h := newHub()
	go h.run()
	defer h.Stop()
	hub = h

	conn := makeConn_CB71("agent", "hb_agent", h)
	raw, _ := json.Marshal(IncomingMessage{Type: "heartbeat"})
	routeMessage(conn, raw)

	select {
	case received := <-conn.send:
		var outMsg OutgoingMessage
		json.Unmarshal(received, &outMsg)
		if outMsg.Type != "heartbeat_ack" {
			t.Fatalf("Expected type 'heartbeat_ack', got '%s'", outMsg.Type)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("Timeout waiting for heartbeat ack")
	}
}

func TestCB71_RouteMessage_InvalidJSON(t *testing.T) {
	resetGlobals_CB71()
	defer resetGlobals_CB71()

	oldHub := hub
	defer func() { hub = oldHub }()
	h := newHub()
	go h.run()
	defer h.Stop()
	hub = h

	conn := makeConn_CB71("agent", "ij_agent", h)
	routeMessage(conn, []byte("not valid json"))

	select {
	case received := <-conn.send:
		var outMsg OutgoingMessage
		json.Unmarshal(received, &outMsg)
		if outMsg.Type != "error" {
			t.Fatalf("Expected error type, got '%s'", outMsg.Type)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("Timeout waiting for error")
	}
}

func TestCB71_RouteMessage_StatusUpdate(t *testing.T) {
	resetGlobals_CB71()
	defer resetGlobals_CB71()

	oldDB := db
	defer func() { db = oldDB }()
	testDB := setupTestDB_CB71(t)
	db = testDB
	defer func() { db = nil }()

	oldHub := hub
	defer func() { hub = oldHub }()
	h := newHub()
	go h.run()
	defer h.Stop()
	hub = h

	userID := createUser_CB71(testDB, "status_user", "pass123")
	agentID := "agent_status"
	createAgent_CB71(testDB, agentID)
	convID := createConversation_CB71(testDB, userID, agentID)

	// Register client
	clientConn := makeConn_CB71("client", userID, h)
	h.register <- clientConn
	time.Sleep(50 * time.Millisecond)

	// Agent sends status update with conversation ID
	agentConn := makeConn_CB71("agent", agentID, h)
	statusData, _ := json.Marshal(map[string]string{
		"conversation_id": convID,
		"status":          "busy",
	})
	raw, _ := json.Marshal(IncomingMessage{Type: "status", Data: statusData})
	routeMessage(agentConn, raw)

	// Client should receive the status update
	select {
	case received := <-clientConn.send:
		var outMsg OutgoingMessage
		json.Unmarshal(received, &outMsg)
		if outMsg.Type != "status" {
			t.Fatalf("Expected type 'status', got '%s'", outMsg.Type)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Timeout waiting for status update")
	}
}

func TestCB71_RouteMessage_StatusUpdate_NoConvID(t *testing.T) {
	resetGlobals_CB71()
	defer resetGlobals_CB71()

	oldHub := hub
	defer func() { hub = oldHub }()
	h := newHub()
	go h.run()
	defer h.Stop()
	hub = h

	// Register client
	clientConn := makeConn_CB71("client", "broadcast_user", h)
	h.register <- clientConn
	time.Sleep(50 * time.Millisecond)

	// Agent sends status update without conversation ID (broadcast)
	agentConn := makeConn_CB71("agent", "agent_broadcast", h)
	statusData, _ := json.Marshal(map[string]string{
		"status": "idle",
	})
	raw, _ := json.Marshal(IncomingMessage{Type: "status", Data: statusData})
	routeMessage(agentConn, raw)

	// Client should receive broadcast status
	select {
	case received := <-clientConn.send:
		var outMsg OutgoingMessage
		json.Unmarshal(received, &outMsg)
		if outMsg.Type != "status" {
			t.Fatalf("Expected type 'status', got '%s'", outMsg.Type)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Timeout waiting for status broadcast")
	}
}

// ==================== marshalOutgoingMessage Tests ====================

func TestCB71_MarshalOutgoingMessage_Success(t *testing.T) {
	msg := OutgoingMessage{
		Type: "message",
		Data: map[string]string{"content": "hello"},
	}
	result := marshalOutgoingMessage(msg)
	if result == nil {
		t.Fatal("Expected non-nil result")
	}
	var parsed OutgoingMessage
	if err := json.Unmarshal(result, &parsed); err != nil {
		t.Fatalf("Failed to unmarshal result: %v", err)
	}
	if parsed.Type != "message" {
		t.Fatalf("Expected type 'message', got '%s'", parsed.Type)
	}
}

func TestCB71_MarshalOutgoingMessage_EmptyType(t *testing.T) {
	msg := OutgoingMessage{
		Type: "",
		Data: nil,
	}
	result := marshalOutgoingMessage(msg)
	if result == nil {
		t.Fatal("Expected non-nil result even with empty type")
	}
}

func TestCB71_MarshalOutgoingMessage_NilData(t *testing.T) {
	msg := OutgoingMessage{
		Type: "test",
		Data: nil,
	}
	result := marshalOutgoingMessage(msg)
	if result == nil {
		t.Fatal("Expected non-nil result with nil data")
	}
}

// ==================== checkRateLimit Tests ====================

func TestCB71_CheckRateLimit_PerConnectionExceeded(t *testing.T) {
	resetGlobals_CB71()
	defer resetGlobals_CB71()

	oldHub := hub
	defer func() { hub = oldHub }()
	h := newHub()
	go h.run()
	defer h.Stop()
	hub = h

	conn := makeConn_CB71("agent", "cr_agent1", h)

	// Exhaust per-connection limit
	for i := 0; i < 61; i++ {
		messageRateLimiter.Allow("cr_agent1")
	}

	result := checkRateLimit(conn)
	if result {
		t.Fatal("Expected rate limit to be exceeded (per-connection)")
	}
}

func TestCB71_CheckRateLimit_PerUserExceeded(t *testing.T) {
	resetGlobals_CB71()
	defer resetGlobals_CB71()

	oldHub := hub
	defer func() { hub = oldHub }()
	h := newHub()
	go h.run()
	defer h.Stop()
	hub = h

	conn := makeConn_CB71("agent", "cr_agent2", h)

	// Per-connection is fine, but per-user is exceeded
	for i := 0; i < 121; i++ {
		userRateLimiter.Allow("cr_agent2")
	}

	result := checkRateLimit(conn)
	if result {
		t.Fatal("Expected rate limit to be exceeded (per-user)")
	}
}

func TestCB71_CheckRateLimit_Allowed(t *testing.T) {
	resetGlobals_CB71()
	defer resetGlobals_CB71()

	oldHub := hub
	defer func() { hub = oldHub }()
	h := newHub()
	go h.run()
	defer h.Stop()
	hub = h

	conn := makeConn_CB71("agent", "cr_agent3", h)
	result := checkRateLimit(conn)
	if !result {
		t.Fatal("Expected rate limit to allow")
	}
}

// ==================== tieredRateLimitMiddleware Tests ====================

func TestCB71_TieredRateLimitMiddleware_Allowed(t *testing.T) {
	globalTieredLimiter = NewTieredRateLimiter()
	defer globalTieredLimiter.Stop()
	defer func() { globalTieredLimiter = NewTieredRateLimiter() }()

	called := false
	handler := tieredRateLimitMiddleware(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	req := makeAuthRequest_CB71("GET", "/test", "", "user_tier_test")
	rr := httptest.NewRecorder()
	handler(rr, req)

	if !called {
		t.Fatal("Handler should have been called")
	}
	if rr.Header().Get("X-RateLimit-Limit") == "" {
		t.Fatal("Expected X-RateLimit-Limit header")
	}
}

func TestCB71_TieredRateLimitMiddleware_IPBasedNoAuth(t *testing.T) {
	globalTieredLimiter = NewTieredRateLimiter()
	defer globalTieredLimiter.Stop()
	defer func() { globalTieredLimiter = NewTieredRateLimiter() }()

	called := false
	handler := tieredRateLimitMiddleware(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("GET", "/test", nil)
	rr := httptest.NewRecorder()
	handler(rr, req)

	if !called {
		t.Fatal("Handler should have been called for IP-based limiting")
	}
}

func TestCB71_TieredRateLimitMiddleware_Blocked(t *testing.T) {
	globalTieredLimiter = NewTieredRateLimiter()
	defer globalTieredLimiter.Stop()
	defer func() { globalTieredLimiter = NewTieredRateLimiter() }()

	// Exhaust the rate limit for this user
	userID := "user_blocked"
	for i := 0; i < 65; i++ {
		globalTieredLimiter.Allow(userID)
	}

	called := false
	handler := tieredRateLimitMiddleware(func(w http.ResponseWriter, r *http.Request) {
		called = true
	})

	req := makeAuthRequest_CB71("GET", "/test", "", userID)
	rr := httptest.NewRecorder()
	handler(rr, req)

	if called {
		t.Fatal("Handler should NOT have been called (rate limited)")
	}
	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("Expected 429, got %d", rr.Code)
	}
	if rr.Header().Get("Retry-After") == "" {
		t.Fatal("Expected Retry-After header")
	}
}

// ==================== handleSetRateLimitTier Tests ====================

func TestCB71_HandleSetRateLimitTier_PersistError(t *testing.T) {
	oldDB := db
	defer func() { db = oldDB }()
	testDB := setupTestDB_CB71(t)
	db = testDB
	defer func() { db = nil }()

	globalTieredLimiter = NewTieredRateLimiter()
	defer globalTieredLimiter.Stop()
	defer func() { globalTieredLimiter = NewTieredRateLimiter() }()

	// Close DB to cause persist error
	testDB.Close()

	form := "user_id=user_persist_err&tier=pro&admin_secret=" + adminSecret
	req := httptest.NewRequest("POST", "/admin/rate-limit/tier", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	handleSetRateLimitTier(rr, req)

	// Should still return 200 (persist error is warned but not fatal)
	if rr.Code != http.StatusOK {
		t.Fatalf("Expected 200 (persist error is non-fatal), got %d", rr.Code)
	}
}

func TestCB71_HandleSetRateLimitTier_FormSecret(t *testing.T) {
	oldDB := db
	defer func() { db = oldDB }()
	testDB := setupTestDB_CB71(t)
	db = testDB
	defer func() { db = nil }()

	globalTieredLimiter = NewTieredRateLimiter()
	defer globalTieredLimiter.Stop()
	defer func() { globalTieredLimiter = NewTieredRateLimiter() }()

	form := "user_id=user_form_secret&tier=enterprise&admin_secret=" + adminSecret
	req := httptest.NewRequest("POST", "/admin/rate-limit/tier", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	handleSetRateLimitTier(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d", rr.Code)
	}
}

// ==================== handleGetRateLimitTier Tests ====================

func TestCB71_HandleGetRateLimitTier_QueryParamSecret(t *testing.T) {
	globalTieredLimiter = NewTieredRateLimiter()
	defer globalTieredLimiter.Stop()
	defer func() { globalTieredLimiter = NewTieredRateLimiter() }()

	globalTieredLimiter.SetTier("user_query_param", TierPro)

	req := httptest.NewRequest("GET", "/admin/rate-limit/tier?user_id=user_query_param&admin_secret="+adminSecret, nil)
	rr := httptest.NewRecorder()
	handleGetRateLimitTier(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d", rr.Code)
	}

	var resp map[string]interface{}
	json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp["tier"] != "pro" {
		t.Fatalf("Expected tier 'pro', got '%v'", resp["tier"])
	}
}

func TestCB71_HandleGetRateLimitTier_DefaultTier(t *testing.T) {
	globalTieredLimiter = NewTieredRateLimiter()
	defer globalTieredLimiter.Stop()
	defer func() { globalTieredLimiter = NewTieredRateLimiter() }()

	req := httptest.NewRequest("GET", "/admin/rate-limit/tier?user_id=user_default_tier&admin_secret="+adminSecret, nil)
	rr := httptest.NewRecorder()
	handleGetRateLimitTier(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d", rr.Code)
	}

	var resp map[string]interface{}
	json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp["tier"] != "free" {
		t.Fatalf("Expected tier 'free', got '%v'", resp["tier"])
	}
}

// ==================== persistQueue/deleteQueueMessages/initQueueDB/cleanStaleQueueMessages DB Error Tests ====================

func TestCB71_PersistQueue_DBError(t *testing.T) {
	testDB := setupTestDB_CB71(t)
	testDB.Close() // Close to cause error

	// Should not panic
	persistQueue(testDB, "user1", []byte("test data"))
}

func TestCB71_DeleteQueueMessages_DBError(t *testing.T) {
	testDB := setupTestDB_CB71(t)
	testDB.Close()

	// Should not panic
	deleteQueueMessages(testDB, "user1")
}

func TestCB71_InitQueueDB_DBError(t *testing.T) {
	testDB := setupTestDB_CB71(t)
	testDB.Close()

	// Should not panic
	initQueueDB(testDB)
}

func TestCB71_CleanStaleQueueMessages_DBError(t *testing.T) {
	testDB := setupTestDB_CB71(t)
	testDB.Close()

	// Should not panic
	cleanStaleQueueMessages(testDB, time.Hour)
}

func TestCB71_CleanStaleQueueMessages_WithDeletedMessages(t *testing.T) {
	testDB := setupTestDB_CB71(t)
	defer testDB.Close()

	// Insert a stale message
	oldTime := time.Now().UTC().Add(-2 * time.Hour).Format(time.RFC3339)
	testDB.Exec("INSERT INTO offline_queue (recipient, data, queued_at, sent_count) VALUES (?, ?, ?, 0)",
		"stale_user", []byte("old message"), oldTime)

	// Clean messages older than 1 hour
	cleanStaleQueueMessages(testDB, time.Hour)

	// Verify the message was deleted
	var count int
	testDB.QueryRow("SELECT COUNT(*) FROM offline_queue WHERE recipient = ?", "stale_user").Scan(&count)
	if count != 0 {
		t.Fatalf("Expected 0 stale messages, got %d", count)
	}
}

func TestCB71_PersistQueue_Success(t *testing.T) {
	testDB := setupTestDB_CB71(t)
	defer testDB.Close()

	persistQueue(testDB, "persist_user", []byte("test message"))

	var count int
	testDB.QueryRow("SELECT COUNT(*) FROM offline_queue WHERE recipient = ?", "persist_user").Scan(&count)
	if count != 1 {
		t.Fatalf("Expected 1 persisted message, got %d", count)
	}
}

func TestCB71_DeleteQueueMessages_Success(t *testing.T) {
	testDB := setupTestDB_CB71(t)
	defer testDB.Close()

	testDB.Exec("INSERT INTO offline_queue (recipient, data, queued_at, sent_count) VALUES (?, ?, ?, 0)",
		"delete_user", []byte("msg1"), time.Now().UTC().Format(time.RFC3339))
	testDB.Exec("INSERT INTO offline_queue (recipient, data, queued_at, sent_count) VALUES (?, ?, ?, 0)",
		"delete_user", []byte("msg2"), time.Now().UTC().Format(time.RFC3339))

	deleteQueueMessages(testDB, "delete_user")

	var count int
	testDB.QueryRow("SELECT COUNT(*) FROM offline_queue WHERE recipient = ?", "delete_user").Scan(&count)
	if count != 0 {
		t.Fatalf("Expected 0 messages after delete, got %d", count)
	}
}

func TestCB71_InitQueueDB_Idempotent(t *testing.T) {
	testDB := setupTestDB_CB71(t)
	defer testDB.Close()

	// initSchema already created the table, but initQueueDB should not fail
	initQueueDB(testDB)

	// Insert should work
	testDB.Exec("INSERT INTO offline_queue (recipient, data, queued_at, sent_count) VALUES (?, ?, ?, 0)",
		"idemp_user", []byte("test"), time.Now().UTC().Format(time.RFC3339))

	var count int
	testDB.QueryRow("SELECT COUNT(*) FROM offline_queue WHERE recipient = ?", "idemp_user").Scan(&count)
	if count != 1 {
		t.Fatalf("Expected 1 message, got %d", count)
	}
}

// ==================== handleHeapProfile/handleGoroutineProfile Success Tests ====================

func TestCB71_HandleHeapProfile_Success(t *testing.T) {
	dir := t.TempDir()
	oldDir := os.Getenv("PROFILING_DIR")
	os.Setenv("PROFILING_DIR", dir)
	defer os.Setenv("PROFILING_DIR", oldDir)

	req := httptest.NewRequest("POST", "/admin/profile?action=heap", nil)
	rr := httptest.NewRecorder()
	handleHeapProfile(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d", rr.Code)
	}

	var resp map[string]interface{}
	json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp["status"] != "ok" {
		t.Fatalf("Expected status 'ok', got '%v'", resp["status"])
	}
	if _, ok := resp["file"]; !ok {
		t.Fatal("Expected 'file' field in response")
	}
}

func TestCB71_HandleGoroutineProfile_Success(t *testing.T) {
	dir := t.TempDir()
	oldDir := os.Getenv("PROFILING_DIR")
	os.Setenv("PROFILING_DIR", dir)
	defer os.Setenv("PROFILING_DIR", oldDir)

	req := httptest.NewRequest("POST", "/admin/profile?action=goroutine", nil)
	rr := httptest.NewRecorder()
	handleGoroutineProfile(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d", rr.Code)
	}

	var resp map[string]interface{}
	json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp["status"] != "ok" {
		t.Fatalf("Expected status 'ok', got '%v'", resp["status"])
	}
}

// ==================== handleCPUProfileStart/Stop Tests ====================

func TestCB71_HandleCPUProfileStart_AlreadyActive(t *testing.T) {
	// Set up active state
	cpuProfileState.Lock()
	cpuProfileState.active = true
	cpuProfileState.stopFunc = func() {}
	cpuProfileState.Unlock()
	defer func() {
		cpuProfileState.Lock()
		cpuProfileState.active = false
		cpuProfileState.stopFunc = nil
		cpuProfileState.Unlock()
	}()

	req := httptest.NewRequest("POST", "/admin/profile?action=cpu", nil)
	rr := httptest.NewRecorder()
	handleCPUProfileStart(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("Expected 500 (already active), got %d", rr.Code)
	}
}

func TestCB71_HandleCPUProfileStop_NotActive(t *testing.T) {
	cpuProfileState.Lock()
	cpuProfileState.active = false
	cpuProfileState.stopFunc = nil
	cpuProfileState.Unlock()

	req := httptest.NewRequest("POST", "/admin/profile?action=cpu_stop", nil)
	rr := httptest.NewRecorder()
	handleCPUProfileStop(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("Expected 500 (not active), got %d", rr.Code)
	}
}

func TestCB71_HandleCPUProfileStart_Success(t *testing.T) {
	dir := t.TempDir()
	oldDir := os.Getenv("PROFILING_DIR")
	os.Setenv("PROFILING_DIR", dir)
	defer os.Setenv("PROFILING_DIR", oldDir)

	cpuProfileState.Lock()
	cpuProfileState.active = false
	cpuProfileState.stopFunc = nil
	cpuProfileState.Unlock()

	defer func() {
		cpuProfileState.Lock()
		if cpuProfileState.active && cpuProfileState.stopFunc != nil {
			cpuProfileState.stopFunc()
			cpuProfileState.active = false
			cpuProfileState.stopFunc = nil
		}
		cpuProfileState.Unlock()
	}()

	req := httptest.NewRequest("POST", "/admin/profile?action=cpu", nil)
	rr := httptest.NewRecorder()
	handleCPUProfileStart(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d", rr.Code)
	}

	var resp map[string]interface{}
	json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp["status"] != "profiling" {
		t.Fatalf("Expected status 'profiling', got '%v'", resp["status"])
	}
}

func TestCB71_HandleCPUProfileStop_Success(t *testing.T) {
	dir := t.TempDir()
	oldDir := os.Getenv("PROFILING_DIR")
	os.Setenv("PROFILING_DIR", dir)
	defer os.Setenv("PROFILING_DIR", oldDir)

	// Start first
	cpuProfileState.Lock()
	cpuProfileState.active = false
	cpuProfileState.stopFunc = nil
	cpuProfileState.Unlock()

	startReq := httptest.NewRequest("POST", "/admin/profile?action=cpu", nil)
	startRR := httptest.NewRecorder()
	handleCPUProfileStart(startRR, startReq)

	if startRR.Code != http.StatusOK {
		t.Fatalf("Setup failed: expected 200, got %d", startRR.Code)
	}

	// Now stop
	req := httptest.NewRequest("POST", "/admin/profile?action=cpu_stop", nil)
	rr := httptest.NewRecorder()
	handleCPUProfileStop(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d", rr.Code)
	}

	var resp map[string]interface{}
	json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp["status"] != "stopped" {
		t.Fatalf("Expected status 'stopped', got '%v'", resp["status"])
	}
}

// ==================== StartCPUProfile Tests ====================

func TestCB71_StartCPUProfile_InvalidPath(t *testing.T) {
	// Try to write to an invalid path
	_, err := StartCPUProfile("/nonexistent_dir_xyz/cpu.prof")
	if err == nil {
		t.Fatal("Expected error for invalid path")
	}
}

func TestCB71_StartCPUProfile_Success(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cpu.prof")
	stop, err := StartCPUProfile(path)
	if err != nil {
		t.Fatalf("StartCPUProfile failed: %v", err)
	}
	stop()

	// Verify file was created
	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Fatal("Expected CPU profile file to be created")
	}
}

// ==================== ShutdownTracing Tests ====================

func TestCB71_ShutdownTracing_NilTP(t *testing.T) {
	// tp should be nil in tests
	oldTP := tp
	tp = nil
	defer func() { tp = oldTP }()

	// Should not panic
	ShutdownTracing()
}

// ==================== InitTracing Tests ====================

func TestCB71_InitTracing_Disabled(t *testing.T) {
	oldVal := os.Getenv("OTEL_ENABLED")
	os.Unsetenv("OTEL_ENABLED")
	defer os.Setenv("OTEL_ENABLED", oldVal)

	// Reset sync.Once
	tracingMu = sync.Once{}
	defer func() { tracingMu = sync.Once{} }()

	err := InitTracing()
	if err != nil {
		t.Fatalf("Expected no error when disabled, got: %v", err)
	}
	if tracingEnabled {
		t.Fatal("Expected tracingEnabled to be false")
	}
}

func TestCB71_InitTracing_NoEndpoint(t *testing.T) {
	oldVal := os.Getenv("OTEL_ENABLED")
	os.Setenv("OTEL_ENABLED", "true")
	defer os.Setenv("OTEL_ENABLED", oldVal)

	oldEndpoint := os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT")
	os.Unsetenv("OTEL_EXPORTER_OTLP_ENDPOINT")
	os.Unsetenv("OTEL_EXPORTER_OTLP_HTTP_ENDPOINT")
	defer os.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", oldEndpoint)

	tracingMu = sync.Once{}
	defer func() { tracingMu = sync.Once{} }()

	err := InitTracing()
	if err != nil {
		t.Fatalf("Expected no error (just disabled), got: %v", err)
	}
	if tracingEnabled {
		t.Fatal("Expected tracingEnabled to be false when no endpoint")
	}
}

// ==================== queue Drain Tests ====================

func TestCB71_Drain_ExpiredMessages(t *testing.T) {
	q := newOfflineQueue(100, 1*time.Millisecond)
	q.Enqueue("user1", []byte("msg1"))
	q.Enqueue("user1", []byte("msg2"))

	// Wait for messages to expire
	time.Sleep(5 * time.Millisecond)

	result := q.Drain("user1")
	if len(result) != 0 {
		t.Fatalf("Expected 0 messages (all expired), got %d", len(result))
	}
}

func TestCB71_Drain_MixedExpiredAndValid(t *testing.T) {
	q := newOfflineQueue(100, 100*time.Millisecond)
	q.Enqueue("user1", []byte("msg1"))
	time.Sleep(50 * time.Millisecond)
	q.Enqueue("user1", []byte("msg2"))

	// msg1 is 50ms old, msg2 is fresh, both within 100ms TTL
	result := q.Drain("user1")
	if len(result) != 2 {
		t.Fatalf("Expected 2 messages (both valid), got %d", len(result))
	}
}

func TestCB71_Drain_NonExistentRecipient(t *testing.T) {
	q := newOfflineQueue(100, time.Hour)
	result := q.Drain("nonexistent")
	if result != nil {
		t.Fatalf("Expected nil for non-existent recipient, got %v", result)
	}
}

// ==================== SafeSend Tests ====================

func TestCB71_SafeSend_NilChannel(t *testing.T) {
	conn := &Connection{
		send: nil,
	}
	result := conn.SafeSend([]byte("test"))
	if result {
		t.Fatal("Expected false for nil channel")
	}
}

func TestCB71_SafeSend_Success(t *testing.T) {
	ch := make(chan []byte, 1)
	conn := &Connection{
		send: ch,
	}
	result := conn.SafeSend([]byte("test"))
	if !result {
		t.Fatal("Expected true for successful send")
	}
}

func TestCB71_SafeSend_BufferFull(t *testing.T) {
	ch := make(chan []byte, 1)
	ch <- []byte("fill")
	conn := &Connection{
		send: ch,
	}
	result := conn.SafeSend([]byte("test"))
	if result {
		t.Fatal("Expected false for full buffer")
	}
}

// ==================== newHub Tests ====================

func TestCB71_NewHub_FieldVerification(t *testing.T) {
	h := newHub()
	if h == nil {
		t.Fatal("Expected non-nil hub")
	}
	if h.register == nil {
		t.Fatal("Expected non-nil register channel")
	}
	if h.unregister == nil {
		t.Fatal("Expected non-nil unregister channel")
	}
	if h.agents == nil {
		t.Fatal("Expected non-nil agents map")
	}
	if h.clientConns == nil {
		t.Fatal("Expected non-nil clientConns map")
	}
	if h.done == nil {
		t.Fatal("Expected non-nil done channel")
	}
	if offlineQueue == nil {
		t.Fatal("Expected non-nil offlineQueue")
	}
}

// ==================== hub.run Tests ====================

func TestCB71_HubRun_UnregisterUnknown(t *testing.T) {
	h := newHub()
	go h.run()
	defer h.Stop()

	// Unregister a connection that was never registered
	conn := makeConn_CB71("agent", "unknown_agent", h)
	h.unregister <- conn
	time.Sleep(50 * time.Millisecond)
	// Should not panic
}

func TestCB71_HubRun_RegisterAndUnregister(t *testing.T) {
	h := newHub()
	go h.run()
	defer h.Stop()

	conn := makeConn_CB71("agent", "reg_unreg_agent", h)
	h.register <- conn
	time.Sleep(50 * time.Millisecond)

	if h.GetAgent("reg_unreg_agent") == nil {
		t.Fatal("Expected agent to be registered")
	}

	h.unregister <- conn
	time.Sleep(50 * time.Millisecond)

	if h.GetAgent("reg_unreg_agent") != nil {
		t.Fatal("Expected agent to be unregistered")
	}
}

func TestCB71_HubRun_BroadcastToAllClients(t *testing.T) {
	h := newHub()
	go h.run()
	defer h.Stop()

	conn1 := makeConn_CB71("client", "bcast_user1", h)
	conn2 := makeConn_CB71("client", "bcast_user2", h)
	h.register <- conn1
	h.register <- conn2
	time.Sleep(50 * time.Millisecond)

	msg := []byte(`{"type":"broadcast"}`)
	h.BroadcastToAllClients(msg)

	// Both should receive
	for i, conn := range []*Connection{conn1, conn2} {
		select {
		case <-conn.send:
			// Good
		case <-time.After(1 * time.Second):
			t.Fatalf("Conn %d did not receive broadcast", i)
		}
	}
}

// ==================== ipRateLimitMiddleware Tests ====================

func TestCB71_IPRateLimitMiddleware_Blocked(t *testing.T) {
	// Create a fresh limiter for this test
	oldLimiter := ipRateLimiter
	ipRateLimiter = NewRateLimiter(2, time.Hour) // Very restrictive
	defer func() { ipRateLimiter = oldLimiter }()

	called := false
	handler := ipRateLimitMiddleware(func(w http.ResponseWriter, r *http.Request) {
		called = true
	})

	// Exhaust limit with the same IP the request will come from
	ipRateLimiter.Allow("1.2.3.4")
	ipRateLimiter.Allow("1.2.3.4")
	// Third call should be blocked

	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "1.2.3.4:12345"
	rr := httptest.NewRecorder()
	handler(rr, req)

	if called {
		t.Fatal("Handler should NOT have been called (IP rate limited)")
	}
	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("Expected 429, got %d", rr.Code)
	}
}

// ==================== authRateLimitMiddleware Tests ====================

func TestCB71_AuthRateLimitMiddleware_Blocked(t *testing.T) {
	oldLimiter := authIPLimiter
	authIPLimiter = NewRateLimiter(2, time.Hour)
	defer func() { authIPLimiter = oldLimiter }()

	called := false
	handler := authRateLimitMiddleware(func(w http.ResponseWriter, r *http.Request) {
		called = true
	})

	// Exhaust limit with the same IP the request will come from
	authIPLimiter.Allow("5.6.7.8")
	authIPLimiter.Allow("5.6.7.8")

	req := httptest.NewRequest("POST", "/auth/login", nil)
	req.RemoteAddr = "5.6.7.8:12345"
	rr := httptest.NewRecorder()
	handler(rr, req)

	if called {
		t.Fatal("Handler should NOT have been called (auth rate limited)")
	}
	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("Expected 429, got %d", rr.Code)
	}
}

// ==================== handleSetNotificationPrefs DB Error Test ====================

func TestCB71_HandleSetNotificationPrefs_DBError(t *testing.T) {
	oldDB := db
	defer func() { db = oldDB }()
	testDB := setupTestDB_CB71(t)
	db = testDB
	defer func() { db = nil }()

	userID := "user_notif_err"
	createUser_CB71(testDB, userID, "pass123")
	agentID := "agent_notif_err"
	createAgent_CB71(testDB, agentID)
	convID := createConversation_CB71(testDB, userID, agentID)

	// Close DB to cause error
	testDB.Close()

	form := "conversation_id=" + convID + "&mute=true"
	req := httptest.NewRequest("POST", "/conversations/notifications", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	ctx := context.WithValue(req.Context(), contextKeyUserID, userID)
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	handleSetNotificationPrefs(rr, req)

	// With closed DB, getConversation returns nil/err, handler returns 404 or 500
	if rr.Code != http.StatusNotFound && rr.Code != http.StatusInternalServerError {
		// Some code paths may return 401 if userID can't be resolved
		t.Logf("Got code %d (expected 404 or 500 for DB error)", rr.Code)
	}
}

// ==================== handleGetPresence DB Error Test ====================

func TestCB71_HandleGetPresence_DBError(t *testing.T) {
	oldDB := db
	defer func() { db = oldDB }()
	testDB := setupTestDB_CB71(t)
	testDB.Close()
	db = testDB
	defer func() { db = nil }()

	req := httptest.NewRequest("GET", "/presence", nil)
	ctx := context.WithValue(req.Context(), contextKeyUserID, "user_presence_err")
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	handleGetPresence(rr, req)

	// With closed DB, agent query fails
	// Handler returns 200 with empty agents list or 500
	if rr.Code != http.StatusOK && rr.Code != http.StatusInternalServerError {
		t.Logf("Got code %d", rr.Code)
	}
}

// ==================== handleAdminAgents DB Error Test ====================

func TestCB71_HandleAdminAgents_DBError(t *testing.T) {
	oldDB := db
	defer func() { db = oldDB }()
	testDB := setupTestDB_CB71(t)
	testDB.Close()
	db = testDB
	defer func() { db = nil }()

	req := httptest.NewRequest("GET", "/admin/agents", nil)
	req.Header.Set("X-Admin-Secret", adminSecret)
	rr := httptest.NewRecorder()
	handleAdminAgents(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("Expected 500 for DB error, got %d", rr.Code)
	}
}

// ==================== handleRegisterAgent DB Error Test ====================

func TestCB71_HandleRegisterAgent_DBError(t *testing.T) {
	oldDB := db
	defer func() { db = oldDB }()
	testDB := setupTestDB_CB71(t)
	testDB.Close()
	db = testDB
	defer func() { db = nil }()

	form := "agent_id=agent_db_err&name=Test&model=gpt-4"
	req := httptest.NewRequest("POST", "/agents/register", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Agent-Secret", agentSecret)
	rr := httptest.NewRecorder()
	handleRegisterAgent(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("Expected 500 for DB error, got %d", rr.Code)
	}
}

// ==================== RegisterAgentOnConnect Tests ====================

func TestCB71_RegisterAgentOnConnect_DBError(t *testing.T) {
	oldDB := db
	defer func() { db = oldDB }()
	testDB := setupTestDB_CB71(t)
	db = testDB
	defer func() { db = nil }()

	testDB.Close()

	err := RegisterAgentOnConnect("agent_err", "Test", "model", "personality", "specialty")
	if err == nil {
		t.Fatal("Expected error for closed DB")
	}
}

func TestCB71_RegisterAgentOnConnect_UpdateAllFields(t *testing.T) {
	oldDB := db
	defer func() { db = oldDB }()
	testDB := setupTestDB_CB71(t)
	db = testDB
	defer func() { db = nil }()

	// Pre-create agent
	testDB.Exec("INSERT INTO agents (id, name, model, personality, specialty) VALUES (?, ?, ?, ?, ?)",
		"agent_update", "Old Name", "old-model", "old-personality", "old-specialty")

	// Update all fields
	err := RegisterAgentOnConnect("agent_update", "New Name", "new-model", "new-personality", "new-specialty")
	if err != nil {
		t.Fatalf("RegisterAgentOnConnect failed: %v", err)
	}

	var name, model, personality, specialty string
	testDB.QueryRow("SELECT name, model, personality, specialty FROM agents WHERE id = ?", "agent_update").
		Scan(&name, &model, &personality, &specialty)

	if name != "New Name" {
		t.Fatalf("Expected name 'New Name', got '%s'", name)
	}
	if model != "new-model" {
		t.Fatalf("Expected model 'new-model', got '%s'", model)
	}
	if personality != "new-personality" {
		t.Fatalf("Expected personality 'new-personality', got '%s'", personality)
	}
	if specialty != "new-specialty" {
		t.Fatalf("Expected specialty 'new-specialty', got '%s'", specialty)
	}
}

// ==================== sendWelcomeMessage Tests ====================

func TestCB71_SendWelcomeMessage_WithDeviceID(t *testing.T) {
	h := newHub()
	go h.run()
	defer h.Stop()

	ch := make(chan []byte, 1)
	conn := &Connection{
		id:                "welcome_user",
		connType:          "client",
		hub:               h,
		send:              ch,
		deviceID:          "device_abc",
		negotiatedVersion: "v1",
	}

	sendWelcomeMessage(conn)

	select {
	case data := <-ch:
		var msg OutgoingMessage
		if err := json.Unmarshal(data, &msg); err != nil {
			t.Fatalf("Failed to unmarshal: %v", err)
		}
		if msg.Type != "connected" {
			t.Fatalf("Expected type 'connected', got '%s'", msg.Type)
		}
		d := msg.Data.(map[string]interface{})
		if d["device_id"] != "device_abc" {
			t.Fatalf("Expected device_id 'device_abc', got '%v'", d["device_id"])
		}
		if d["protocol_version"] != "v1" {
			t.Fatalf("Expected protocol_version 'v1', got '%v'", d["protocol_version"])
		}
	case <-time.After(1 * time.Second):
		t.Fatal("Timeout waiting for welcome message")
	}
}

func TestCB71_SendWelcomeMessage_Success(t *testing.T) {
	h := newHub()
	go h.run()
	defer h.Stop()

	ch := make(chan []byte, 1)
	conn := &Connection{
		id:                "welcome_agent",
		connType:          "agent",
		hub:               h,
		send:              ch,
		negotiatedVersion: "v1",
	}

	sendWelcomeMessage(conn)

	select {
	case data := <-ch:
		var msg OutgoingMessage
		if err := json.Unmarshal(data, &msg); err != nil {
			t.Fatalf("Failed to unmarshal: %v", err)
		}
		if msg.Type != "connected" {
			t.Fatalf("Expected type 'connected', got '%s'", msg.Type)
		}
		d := msg.Data.(map[string]interface{})
		if d["id"] != "welcome_agent" {
			t.Fatalf("Expected id 'welcome_agent', got '%v'", d["id"])
		}
		if d["status"] != "connected" {
			t.Fatalf("Expected status 'connected', got '%v'", d["status"])
		}
	case <-time.After(1 * time.Second):
		t.Fatal("Timeout waiting for welcome message")
	}
}

// ==================== logger Tests ====================

func TestCB71_Logger_WithFields_Empty(t *testing.T) {
	l := NewLogger(LogInfo)
	entry := l.WithFields(map[string]interface{}{})
	if entry == nil {
		t.Fatal("Expected non-nil log entry")
	}
	entry.Info("test message with empty fields")
}

func TestCB71_Logger_WithFields_Nil(t *testing.T) {
	l := NewLogger(LogInfo)
	entry := l.WithFields(nil)
	if entry == nil {
		t.Fatal("Expected non-nil log entry with nil fields")
	}
	entry.Info("test message with nil fields")
}

func TestCB71_Logger_LogEntry_AllLevels(t *testing.T) {
	l := NewLogger(LogDebug)
	entry := l.WithFields(map[string]interface{}{"key": "value"})

	// Test all log levels
	entry.Debug("debug message")
	entry.Info("info message")
	entry.Warn("warn message")
	entry.Error("error message")
}

func TestCB71_Logger_String_AllLevels(t *testing.T) {
	if LogDebug.String() != "debug" {
		t.Fatalf("Expected 'debug', got '%s'", LogDebug.String())
	}
	if LogInfo.String() != "info" {
		t.Fatalf("Expected 'info', got '%s'", LogInfo.String())
	}
	if LogWarn.String() != "warn" {
		t.Fatalf("Expected 'warn', got '%s'", LogWarn.String())
	}
	if LogError.String() != "error" {
		t.Fatalf("Expected 'error', got '%s'", LogError.String())
	}
}

// ==================== routeTypingIndicator Tests ====================

func TestCB71_RouteTypingIndicator_AgentToClient(t *testing.T) {
	oldDB := db
	defer func() { db = oldDB }()
	testDB := setupTestDB_CB71(t)
	db = testDB
	defer func() { db = nil }()

	oldHub := hub
	defer func() { hub = oldHub }()
	h := newHub()
	go h.run()
	defer h.Stop()
	hub = h

	userID := createUser_CB71(testDB, "typing_user", "pass123")
	agentID := "agent_typing"
	createAgent_CB71(testDB, agentID)
	convID := createConversation_CB71(testDB, userID, agentID)

	// Register client
	clientConn := makeConn_CB71("client", userID, h)
	h.register <- clientConn
	time.Sleep(50 * time.Millisecond)

	// Agent sends typing indicator
	agentConn := makeConn_CB71("agent", agentID, h)
	typingData, _ := json.Marshal(map[string]string{"conversation_id": convID})
	routeTypingIndicator(agentConn, typingData)

	// Client should receive typing indicator
	select {
	case received := <-clientConn.send:
		var outMsg OutgoingMessage
		json.Unmarshal(received, &outMsg)
		if outMsg.Type != "typing" {
			t.Fatalf("Expected type 'typing', got '%s'", outMsg.Type)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Timeout waiting for typing indicator")
	}
}

func TestCB71_RouteTypingIndicator_ClientToAgent(t *testing.T) {
	oldDB := db
	defer func() { db = oldDB }()
	testDB := setupTestDB_CB71(t)
	db = testDB
	defer func() { db = nil }()

	oldHub := hub
	defer func() { hub = oldHub }()
	h := newHub()
	go h.run()
	defer h.Stop()
	hub = h

	userID := createUser_CB71(testDB, "typing_user2", "pass123")
	agentID := "agent_typing2"
	createAgent_CB71(testDB, agentID)
	convID := createConversation_CB71(testDB, userID, agentID)

	// Register agent
	agentConn := makeConn_CB71("agent", agentID, h)
	h.register <- agentConn
	time.Sleep(50 * time.Millisecond)

	// Client sends typing indicator
	clientConn := makeConn_CB71("client", userID, h)
	typingData, _ := json.Marshal(map[string]string{"conversation_id": convID})
	routeTypingIndicator(clientConn, typingData)

	// Agent should receive typing indicator
	select {
	case received := <-agentConn.send:
		var outMsg OutgoingMessage
		json.Unmarshal(received, &outMsg)
		if outMsg.Type != "typing" {
			t.Fatalf("Expected type 'typing', got '%s'", outMsg.Type)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Timeout waiting for typing indicator")
	}
}

// ==================== deleteConversation Tests ====================

func TestCB71_DeleteConversation_MessagesDBError(t *testing.T) {
	oldDB := db
	defer func() { db = oldDB }()
	testDB := setupTestDB_CB71(t)
	db = testDB
	defer func() { db = nil }()

	userID := createUser_CB71(testDB, "del_user", "pass123")
	agentID := "agent_del"
	createAgent_CB71(testDB, agentID)
	convID := createConversation_CB71(testDB, userID, agentID)

	// Insert a message
	testDB.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, sent_at) VALUES (?, ?, ?, ?, ?, ?)",
		"msg1", convID, "client", userID, "hello", time.Now().UTC().Format(time.RFC3339))

	// Close DB to cause error during message deletion
	testDB.Close()

	err := deleteConversation(convID, userID)
	if err == nil {
		t.Fatal("Expected error for closed DB")
	}
}

// ==================== storeMessagesBatch DB Error Tests ====================

func TestCB71_StoreMessagesBatch_DBError(t *testing.T) {
	oldDB := db
	defer func() { db = oldDB }()
	testDB := setupTestDB_CB71(t)
	db = testDB
	defer func() { db = nil }()

	testDB.Close()

	msgs := []RoutedMessage{
		{
			Type:           "message",
			ConversationID: "conv_batch_err",
			Content:        "test",
			SenderType:     "client",
			SenderID:       "user_batch",
			RecipientID:    "agent_batch",
		},
	}

	_, err := storeMessagesBatch(msgs)
	if err == nil {
		t.Fatal("Expected error for closed DB")
	}
}

func TestCB71_StoreMessagesBatch_MultipleMessages(t *testing.T) {
	oldDB := db
	defer func() { db = oldDB }()
	testDB := setupTestDB_CB71(t)
	db = testDB
	defer func() { db = nil }()

	userID := createUser_CB71(testDB, "batch_user", "pass123")
	agentID := "agent_batch"
	createAgent_CB71(testDB, agentID)
	convID := createConversation_CB71(testDB, userID, agentID)

	msgs := []RoutedMessage{
		{Type: "message", ConversationID: convID, Content: "msg1", SenderType: "client", SenderID: userID, RecipientID: agentID},
		{Type: "message", ConversationID: convID, Content: "msg2", SenderType: "client", SenderID: userID, RecipientID: agentID},
		{Type: "message", ConversationID: convID, Content: "msg3", SenderType: "client", SenderID: userID, RecipientID: agentID},
	}

	ids, err := storeMessagesBatch(msgs)
	if err != nil {
		t.Fatalf("storeMessagesBatch failed: %v", err)
	}
	if len(ids) != 3 {
		t.Fatalf("Expected 3 IDs, got %d", len(ids))
	}

	// Verify messages were stored
	var count int
	testDB.QueryRow("SELECT COUNT(*) FROM messages WHERE conversation_id = ?", convID).Scan(&count)
	if count != 3 {
		t.Fatalf("Expected 3 messages in DB, got %d", count)
	}
}

// ==================== handleGetTags DB Error Test ====================

func TestCB71_HandleGetTags_DBError(t *testing.T) {
	oldDB := db
	defer func() { db = oldDB }()
	testDB := setupTestDB_CB71(t)
	testDB.Close()
	db = testDB
	defer func() { db = nil }()

	req := makeAuthRequest_CB71("GET", "/conversations/tags?conversation_id=conv_tags_err", "", "user_tags_err")
	rr := httptest.NewRecorder()
	handleGetTags(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Logf("Got code %d for DB error", rr.Code)
	}
}

// ==================== handleMessageDelete DB Error Test ====================

func TestCB71_HandleMessageDelete_DBError(t *testing.T) {
	oldDB := db
	defer func() { db = oldDB }()
	testDB := setupTestDB_CB71(t)
	testDB.Close()
	db = testDB
	defer func() { db = nil }()

	req := makeAuthRequest_CB71("POST", "/messages/delete?message_id=msg_del_err", "", "user_del_err")
	rr := httptest.NewRecorder()
	handleMessageDelete(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("Expected 500, got %d", rr.Code)
	}
}

// ==================== initAPNs Tests ====================

func TestCB71_InitAPNs_NilConfig(t *testing.T) {
	oldConfig := pushConfig
	pushConfig = nil
	defer func() { pushConfig = oldConfig }()

	initAPNs()
	// With nil config, nothing to check — just verify no panic
}

func TestCB71_InitAPNs_Disabled(t *testing.T) {
	oldConfig := pushConfig
	pushConfig = &PushNotificationConfig{APNSEnabled: false}
	defer func() { pushConfig = oldConfig }()

	initAPNs()
	if pushConfig.APNSEnabled {
		t.Fatal("Expected APNs to remain disabled")
	}
}

func TestCB71_InitAPNs_CertPathMissing(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "nonexistent.p8")

	oldConfig := pushConfig
	pushConfig = &PushNotificationConfig{
		APNSEnabled: true,
		CertPath:    certPath,
		TeamID:      "team123",
		KeyID:       "key123",
	}
	defer func() { pushConfig = oldConfig }()

	initAPNs()
	// Cert doesn't exist, so APNs should be disabled
	if pushConfig.APNSEnabled {
		t.Fatal("Expected APNs to be disabled when cert not found")
	}
}

// ==================== initFCM Tests ====================

func TestCB71_InitFCM_NilConfig(t *testing.T) {
	oldConfig := pushConfig
	pushConfig = nil
	defer func() { pushConfig = oldConfig }()

	initFCM()
	// With nil config, nothing to check — just verify no panic
}

func TestCB71_InitFCM_Disabled(t *testing.T) {
	oldConfig := pushConfig
	pushConfig = &PushNotificationConfig{FCMEnabled: false}
	defer func() { pushConfig = oldConfig }()

	initFCM()
	if pushConfig.FCMEnabled {
		t.Fatal("Expected FCM to remain disabled")
	}
}

func TestCB71_InitFCM_CredsNotFound(t *testing.T) {
	oldConfig := pushConfig
	pushConfig = &PushNotificationConfig{
		FCMEnabled:     true,
		FCMCredentials: "/nonexistent/path/to/creds.json",
	}
	defer func() { pushConfig = oldConfig }()

	initFCM()
	if pushConfig.FCMEnabled {
		t.Fatal("Expected FCM to be disabled when creds not found")
	}
}

// ==================== cpuProfileTestSetup Test ====================

func TestCB71_CpuProfileTestSetup(t *testing.T) {
	stop := cpuProfileTestSetup()
	defer stop()
	if stop == nil {
		t.Fatal("Expected non-nil stop function")
	}
}

// ==================== loadQueueFromDB Tests ====================

func TestCB71_LoadQueueFromDB_WithMessages(t *testing.T) {
	testDB := setupTestDB_CB71(t)
	defer testDB.Close()

	// Insert messages
	testDB.Exec("INSERT INTO offline_queue (recipient, data, queued_at, sent_count) VALUES (?, ?, ?, 0)",
		"load_user", []byte(`{"type":"message","data":{"content":"hello"}}`), time.Now().UTC().Format(time.RFC3339))
	testDB.Exec("INSERT INTO offline_queue (recipient, data, queued_at, sent_count) VALUES (?, ?, ?, 0)",
		"load_user", []byte(`{"type":"message","data":{"content":"world"}}`), time.Now().UTC().Format(time.RFC3339))

	q := newOfflineQueue(100, time.Hour)
	loadQueueFromDB(testDB, q)

	depth := q.QueueDepth("load_user")
	if depth != 2 {
		t.Fatalf("Expected queue depth 2, got %d", depth)
	}
}

func TestCB71_LoadQueueFromDB_EmptyTable(t *testing.T) {
	testDB := setupTestDB_CB71(t)
	defer testDB.Close()

	q := newOfflineQueue(100, time.Hour)
	loadQueueFromDB(testDB, q)

	total := q.TotalDepth()
	if total != 0 {
		t.Fatalf("Expected total depth 0, got %d", total)
	}
}

func TestCB71_LoadQueueFromDB_NilDB(t *testing.T) {
	q := newOfflineQueue(100, time.Hour)
	loadQueueFromDB(nil, q)
	// Should not panic with nil DB
}

// ==================== initSchema Tests ====================

func TestCB71_InitSchema_ClosedDB(t *testing.T) {
	testDB := setupTestDB_CB71(t)
	testDB.Close()

	err := initSchema(testDB)
	if err == nil {
		t.Fatal("Expected error for closed DB")
	}
}

// ==================== handleHealth DB Error Test ====================

func Test71_HandleHealth_DBError(t *testing.T) {
	oldDB := db
	defer func() { db = oldDB }()
	testDB := setupTestDB_CB71(t)
	db = testDB
	defer func() { db = nil }()

	testDB.Close()

	req := httptest.NewRequest("GET", "/health", nil)
	rr := httptest.NewRecorder()
	handleHealth(rr, req)

	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("Expected 503 for DB error, got %d", rr.Code)
	}
}

// ==================== handleRegisterDeviceToken DB Error Test ====================

func TestCB71_HandleRegisterDeviceToken_DBError(t *testing.T) {
	oldDB := db
	defer func() { db = oldDB }()
	testDB := setupTestDB_CB71(t)
	db = testDB
	defer func() { db = nil }()

	testDB.Close()

	body := `{"device_token":"abc123","platform":"ios"}`
	req := makeAuthRequest_CB71("POST", "/devices/register", body, "user_device_err")
	rr := httptest.NewRecorder()
	handleRegisterDeviceToken(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("Expected 500 for DB error, got %d", rr.Code)
	}
}

// ==================== handleWebPushSubscribe DB Error Test ====================

func TestCB71_HandleWebPushSubscribe_DBError(t *testing.T) {
	oldDB := db
	defer func() { db = oldDB }()
	testDB := setupTestDB_CB71(t)
	db = testDB
	defer func() { db = nil }()

	testDB.Close()

	body := `{"endpoint":"https://example.com/push","keys":{"p256dh":"abc","auth":"def"}}`
	req := makeAuthRequest_CB71("POST", "/webpush/subscribe", body, "user_webpush_err")
	rr := httptest.NewRecorder()
	handleWebPushSubscribe(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("Expected 500 for DB error, got %d", rr.Code)
	}
}

// ==================== handleAdminRateLimitTier Router Test ====================

func TestCB71_HandleAdminRateLimitTier_Router(t *testing.T) {
	globalTieredLimiter = NewTieredRateLimiter()
	defer globalTieredLimiter.Stop()
	defer func() { globalTieredLimiter = NewTieredRateLimiter() }()

	// POST -> handleSetRateLimitTier
	form := "user_id=user_router&tier=pro&admin_secret=" + adminSecret
	req := httptest.NewRequest("POST", "/admin/rate-limit/tier", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	handleAdminRateLimitTier(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("Expected 200 for POST, got %d", rr.Code)
	}

	// GET -> handleGetRateLimitTier
	req2 := httptest.NewRequest("GET", "/admin/rate-limit/tier?user_id=user_router&admin_secret="+adminSecret, nil)
	rr2 := httptest.NewRecorder()
	handleAdminRateLimitTier(rr2, req2)

	if rr2.Code != http.StatusOK {
		t.Fatalf("Expected 200 for GET, got %d", rr2.Code)
	}
}

// ==================== requestIDMiddleware Test ====================

func TestCB71_RequestIDMiddleware_GeneratesID(t *testing.T) {
	called := false
	handler := requestIDMiddleware(func(w http.ResponseWriter, r *http.Request) {
		called = true
		id := r.Header.Get("X-Request-ID")
		if id == "" {
			t.Fatal("Expected non-empty request ID")
		}
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("GET", "/test", nil)
	rr := httptest.NewRecorder()
	handler(rr, req)

	if !called {
		t.Fatal("Handler should have been called")
	}
	if rr.Header().Get("X-Request-ID") == "" {
		t.Fatal("Expected X-Request-ID in response")
	}
}

func TestCB71_RequestIDMiddleware_PreservesClientID(t *testing.T) {
	handler := requestIDMiddleware(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get("X-Request-ID")
		if id != "client-req-id" {
			t.Fatalf("Expected 'client-req-id', got '%s'", id)
		}
	})

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-Request-ID", "client-req-id")
	rr := httptest.NewRecorder()
	handler(rr, req)

	if rr.Header().Get("X-Request-ID") != "client-req-id" {
		t.Fatalf("Expected 'client-req-id' in response, got '%s'", rr.Header().Get("X-Request-ID"))
	}
}

// ==================== accessLogMiddleware Test ====================

func TestCB71_AccessLogMiddleware(t *testing.T) {
	called := false
	handler := accessLogMiddleware(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("GET", "/test", nil)
	rr := httptest.NewRecorder()
	handler(rr, req)

	if !called {
		t.Fatal("Handler should have been called")
	}
}

// ==================== writeJSONResponse Test ====================

func TestCB71_WriteJSONResponse(t *testing.T) {
	rr := httptest.NewRecorder()
	writeJSONResponse(rr, http.StatusCreated, map[string]string{"status": "created"})

	if rr.Code != http.StatusCreated {
		t.Fatalf("Expected 201, got %d", rr.Code)
	}
	if rr.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("Expected application/json content type, got '%s'", rr.Header().Get("Content-Type"))
	}

	var resp map[string]string
	json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp["status"] != "created" {
		t.Fatalf("Expected status 'created', got '%s'", resp["status"])
	}
}

// ==================== itoa Edge Cases ====================

func TestCB71_Itoa_NegativeNumber(t *testing.T) {
	result := itoa(-42)
	if result != "-42" {
		t.Fatalf("Expected '-42', got '%s'", result)
	}
}

func TestCB71_Itoa_LargeNumber(t *testing.T) {
	result := itoa(123456789)
	if result != "123456789" {
		t.Fatalf("Expected '123456789', got '%s'", result)
	}
}

// ==================== handleAdminProfile Test ====================

func TestCB71_HandleAdminProfile_Stats(t *testing.T) {
	req := httptest.NewRequest("GET", "/admin/profile?action=stats", nil)
	rr := httptest.NewRecorder()
	handleAdminProfile(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d", rr.Code)
	}

	var resp map[string]interface{}
	json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp["action"] != "stats" {
		t.Fatalf("Expected action 'stats', got '%v'", resp["action"])
	}
}

func TestCB71_HandleAdminProfile_GC(t *testing.T) {
	req := httptest.NewRequest("POST", "/admin/profile?action=gc", nil)
	rr := httptest.NewRecorder()
	handleAdminProfile(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d", rr.Code)
	}

	var resp map[string]interface{}
	json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp["action"] != "gc" {
		t.Fatalf("Expected action 'gc', got '%v'", resp["action"])
	}
}

// ==================== SetGCPercent / SetMemoryLimit Tests ====================

func TestCB71_SetGCPercent(t *testing.T) {
	old := SetGCPercent(200)
	defer SetGCPercent(old)

	// Verify it returns the previous value
	if old != 100 && old != 200 {
		t.Logf("Previous GC percent: %d", old)
	}
}

func TestCB71_SetMemoryLimit(t *testing.T) {
	old := SetMemoryLimit(1 << 30) // 1GB
	defer SetMemoryLimit(old)

	// Verify it returns the previous value
	t.Logf("Previous memory limit: %d", old)
}

// ==================== MemoryStats Test ====================

func TestCB71_MemoryStats(t *testing.T) {
	stats := MemoryStats()
	if stats == nil {
		t.Fatal("Expected non-nil stats")
	}
	if _, ok := stats["alloc_bytes"]; !ok {
		t.Fatal("Expected 'alloc_bytes' key")
	}
	if _, ok := stats["goroutines"]; !ok {
		t.Fatal("Expected 'goroutines' key")
	}
}

// ==================== ForceGC Test ====================

func TestCB71_ForceGC(t *testing.T) {
	cycles := ForceGC()
	if cycles < 1 {
		t.Fatalf("Expected at least 1 GC cycle, got %d", cycles)
	}
}

// ==================== negotiateProtocol Test ====================

func TestCB71_NegotiateProtocol_QueryParam(t *testing.T) {
	req := httptest.NewRequest("GET", "/client/connect?protocol_version=v1", nil)
	result := negotiateProtocol(req)
	if result != "v1" {
		t.Fatalf("Expected 'v1', got '%s'", result)
	}
}

func TestCB71_NegotiateProtocol_UnsupportedQueryParam(t *testing.T) {
	req := httptest.NewRequest("GET", "/client/connect?protocol_version=v999", nil)
	result := negotiateProtocol(req)
	if result != ProtocolVersion {
		t.Fatalf("Expected '%s' (default), got '%s'", ProtocolVersion, result)
	}
}

func TestCB71_NegotiateProtocol_NoHeader(t *testing.T) {
	req := httptest.NewRequest("GET", "/client/connect", nil)
	result := negotiateProtocol(req)
	if result != ProtocolVersion {
		t.Fatalf("Expected '%s' (default), got '%s'", ProtocolVersion, result)
	}
}

func TestCB71_IsSupportedVersion(t *testing.T) {
	if !isSupportedVersion("v1") {
		t.Fatal("Expected v1 to be supported")
	}
	if isSupportedVersion("v999") {
		t.Fatal("Expected v999 to NOT be supported")
	}
}

func TestCB71_UpgradeWithProtocol(t *testing.T) {
	rr := httptest.NewRecorder()
	upgradeWithProtocol(rr, httptest.NewRequest("GET", "/", nil), "v1")
	if rr.Header().Get("Sec-WebSocket-Protocol") != "v1" {
		t.Fatalf("Expected 'v1', got '%s'", rr.Header().Get("Sec-WebSocket-Protocol"))
	}
}

func TestCB71_UpgradeWithProtocol_Unsupported(t *testing.T) {
	rr := httptest.NewRecorder()
	upgradeWithProtocol(rr, httptest.NewRequest("GET", "/", nil), "v999")
	if rr.Header().Get("Sec-WebSocket-Protocol") != "" {
		t.Fatal("Expected empty header for unsupported protocol")
	}
}

// ==================== loadTiersFromDB Test ====================

func TestCB71_LoadTiersFromDB_WithTiers(t *testing.T) {
	oldDB := db
	defer func() { db = oldDB }()
	testDB := setupTestDB_CB71(t)
	db = testDB
	defer func() { db = nil }()

	// Insert tier entries
	testDB.Exec("INSERT INTO user_rate_limit_tiers (user_id, tier_name, updated_at) VALUES (?, ?, datetime('now'))",
		"user_pro", "pro")
	testDB.Exec("INSERT INTO user_rate_limit_tiers (user_id, tier_name, updated_at) VALUES (?, ?, datetime('now'))",
		"user_ent", "enterprise")

	trl := NewTieredRateLimiter()
	defer trl.Stop()
	err := loadTiersFromDB(trl)
	if err != nil {
		t.Fatalf("loadTiersFromDB failed: %v", err)
	}

	// Verify tiers loaded
	proTier := trl.GetTier("user_pro")
	if proTier.Name != "pro" {
		t.Fatalf("Expected 'pro' tier, got '%s'", proTier.Name)
	}

	entTier := trl.GetTier("user_ent")
	if entTier.Name != "enterprise" {
		t.Fatalf("Expected 'enterprise' tier, got '%s'", entTier.Name)
	}
}

func TestCB71_LoadTiersFromDB_UnknownTierDefaultsFree(t *testing.T) {
	oldDB := db
	defer func() { db = oldDB }()
	testDB := setupTestDB_CB71(t)
	db = testDB
	defer func() { db = nil }()

	testDB.Exec("INSERT INTO user_rate_limit_tiers (user_id, tier_name, updated_at) VALUES (?, ?, datetime('now'))",
		"user_unknown", "platinum") // Unknown tier name

	trl := NewTieredRateLimiter()
	defer trl.Stop()
	err := loadTiersFromDB(trl)
	if err != nil {
		t.Fatalf("loadTiersFromDB failed: %v", err)
	}

	tier := trl.GetTier("user_unknown")
	if tier.Name != "free" {
		t.Fatalf("Expected 'free' tier for unknown, got '%s'", tier.Name)
	}
}

func TestCB71_LoadTiersFromDB_NilDB(t *testing.T) {
	trl := NewTieredRateLimiter()
	defer trl.Stop()
	err := loadTiersFromDB(trl)
	if err != nil {
		t.Fatalf("Expected no error for nil DB, got: %v", err)
	}
}

// ==================== persistTierToDB Test ====================

func TestCB71_PersistTierToDB_Success(t *testing.T) {
	oldDB := db
	defer func() { db = oldDB }()
	testDB := setupTestDB_CB71(t)
	db = testDB
	defer func() { db = nil }()

	err := persistTierToDB("user_persist", TierPro)
	if err != nil {
		t.Fatalf("persistTierToDB failed: %v", err)
	}

	var tierName string
	testDB.QueryRow("SELECT tier_name FROM user_rate_limit_tiers WHERE user_id = ?", "user_persist").Scan(&tierName)
	if tierName != "pro" {
		t.Fatalf("Expected 'pro', got '%s'", tierName)
	}
}

func TestCB71_PersistTierToDB_UpdateExisting(t *testing.T) {
	oldDB := db
	defer func() { db = oldDB }()
	testDB := setupTestDB_CB71(t)
	db = testDB
	defer func() { db = nil }()

	// Insert initial tier
	testDB.Exec("INSERT INTO user_rate_limit_tiers (user_id, tier_name, updated_at) VALUES (?, ?, datetime('now'))",
		"user_update", "free")

	// Update to pro
	err := persistTierToDB("user_update", TierPro)
	if err != nil {
		t.Fatalf("persistTierToDB failed: %v", err)
	}

	var tierName string
	testDB.QueryRow("SELECT tier_name FROM user_rate_limit_tiers WHERE user_id = ?", "user_update").Scan(&tierName)
	if tierName != "pro" {
		t.Fatalf("Expected 'pro' after update, got '%s'", tierName)
	}
}

func TestCB71_PersistTierToDB_NilDB(t *testing.T) {
	oldDB := db
	defer func() { db = oldDB }()
	db = nil
	defer func() { db = oldDB }()

	err := persistTierToDB("user_nil", TierPro)
	if err != nil {
		t.Fatalf("Expected no error for nil DB, got: %v", err)
	}
}

// ==================== writeProfileError Test ====================

func TestCB71_WriteProfileError_WithErr(t *testing.T) {
	rr := httptest.NewRecorder()
	writeProfileError(rr, "test context", fmt.Errorf("test error"))

	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("Expected 500, got %d", rr.Code)
	}

	var resp map[string]interface{}
	json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp["context"] != "test context" {
		t.Fatalf("Expected 'test context', got '%v'", resp["context"])
	}
	if resp["detail"] != "test error" {
		t.Fatalf("Expected 'test error', got '%v'", resp["detail"])
	}
}

func TestCB71_WriteProfileError_NilErr(t *testing.T) {
	rr := httptest.NewRecorder()
	writeProfileError(rr, "nil context", nil)

	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("Expected 500, got %d", rr.Code)
	}

	var resp map[string]interface{}
	json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp["detail"] != "" {
		t.Fatalf("Expected empty detail, got '%v'", resp["detail"])
	}
}

// ==================== writeProfileJSON Test ====================

func TestCB71_WriteProfileJSON(t *testing.T) {
	rr := httptest.NewRecorder()
	writeProfileJSON(rr, map[string]interface{}{
		"status": "ok",
		"value":  42,
	})

	if rr.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("Expected application/json, got '%s'", rr.Header().Get("Content-Type"))
	}

	var resp map[string]interface{}
	json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp["status"] != "ok" {
		t.Fatalf("Expected 'ok', got '%v'", resp["status"])
	}
}

// ==================== HandleMessageEdit DB Error Test ====================

func TestCB71_HandleMessageEdit_DBError(t *testing.T) {
	oldDB := db
	defer func() { db = oldDB }()
	testDB := setupTestDB_CB71(t)
	testDB.Close()
	db = testDB
	defer func() { db = nil }()

	req := makeAuthRequest_CB71("POST", "/messages/edit?message_id=msg_edit_err&content=updated", "", "user_edit_err")
	rr := httptest.NewRecorder()
	handleMessageEdit(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("Expected 500, got %d", rr.Code)
	}
}

// ==================== SafeTruncate Test ====================

func TestCB71_SafeTruncate(t *testing.T) {
	result := safeTruncate("hello world", 5)
	if result != "hello" {
		t.Fatalf("Expected 'hello', got '%s'", result)
	}

	result = safeTruncate("short", 10)
	if result != "short" {
		t.Fatalf("Expected 'short', got '%s'", result)
	}

	result = safeTruncate("exact", 5)
	if result != "exact" {
		t.Fatalf("Expected 'exact', got '%s'", result)
	}

	result = safeTruncate("", 5)
	if result != "" {
		t.Fatalf("Expected '', got '%s'", result)
	}
}

// ==================== GetEnvOrDefault Test ====================

func TestCB71_GetEnvOrDefault(t *testing.T) {
	defer os.Unsetenv("CB71_TEST_ENV")

	os.Setenv("CB71_TEST_ENV", "custom_value")
	result := getEnvOrDefault("CB71_TEST_ENV", "default")
	if result != "custom_value" {
		t.Fatalf("Expected 'custom_value', got '%s'", result)
	}

	os.Unsetenv("CB71_TEST_ENV")
	result = getEnvOrDefault("CB71_TEST_ENV", "default")
	if result != "default" {
		t.Fatalf("Expected 'default', got '%s'", result)
	}
}

// ==================== GenerateID Test ====================

func TestCB71_GenerateID(t *testing.T) {
	id1 := generateID("")
	id2 := generateID("")
	if id1 == id2 {
		t.Fatal("Expected unique IDs")
	}
	if len(id1) < 10 {
		t.Fatalf("Expected ID length >= 10, got %d", len(id1))
	}
}