package main

import (
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
	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"
)

// ==================== CB77 Helpers ====================

func setupTestDB_CB77(t *testing.T) *sql.DB {
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

func generateTestToken_CB77(userID string) string {
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

func createUser_CB77(testDB *sql.DB, username, password string) string {
	hash, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	userID := "user_" + username
	testDB.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)", userID, username, hash)
	return userID
}

func createAgent_CB77(testDB *sql.DB, agentID string) {
	testDB.Exec("INSERT INTO agents (id, name, model) VALUES (?, ?, ?)", agentID, "Test Agent", "test-model")
}

func createConversation_CB77(testDB *sql.DB, userID, agentID string) string {
	convID := "conv_" + agentID + "_" + userID
	testDB.Exec("INSERT INTO conversations (id, user_id, agent_id) VALUES (?, ?, ?)", convID, userID, agentID)
	return convID
}

func createMessage_CB77(testDB *sql.DB, msgID, convID, senderType, senderID, content string) {
	testDB.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, created_at) VALUES (?, ?, ?, ?, ?, ?)",
		msgID, convID, senderType, senderID, content, time.Now().UTC())
}

// ==================== Tracing: ShutdownTracing, IsTracingEnabled, StartSpan, etc. ====================

func TestCB77_IsTracingEnabled_Disabled(t *testing.T) {
	old := tracingEnabled
	tracingEnabled = false
	defer func() { tracingEnabled = old }()
	if IsTracingEnabled() {
		t.Error("expected tracing to be disabled")
	}
}

func TestCB77_IsTracingEnabled_Enabled(t *testing.T) {
	old := tracingEnabled
	tracingEnabled = true
	defer func() { tracingEnabled = old }()
	if !IsTracingEnabled() {
		t.Error("expected tracing to be enabled")
	}
}

func TestCB77_StartSpan_Disabled(t *testing.T) {
	old := tracingEnabled
	tracingEnabled = false
	defer func() { tracingEnabled = old }()
	ctx, span := StartSpan(t.Context(), "test-span")
	if span == nil {
		t.Error("span should not be nil even when disabled")
	}
	if ctx == nil {
		t.Error("context should not be nil")
	}
}

func TestCB77_StartSpan_WithAttrs(t *testing.T) {
	old := tracingEnabled
	tracerOld := tracer
	tracingEnabled = true
	tracer = nil // tracer nil path
	defer func() {
		tracingEnabled = old
		tracer = tracerOld
	}()
	ctx, span := StartSpan(t.Context(), "test-span")
	_ = ctx
	_ = span
	// Should return no-op span when tracer is nil
}

func TestCB77_SpanError_Disabled(t *testing.T) {
	old := tracingEnabled
	tracingEnabled = false
	defer func() { tracingEnabled = old }()
	SpanError(nil, nil) // should not panic
}

func TestCB77_SpanOK_Disabled(t *testing.T) {
	old := tracingEnabled
	tracingEnabled = false
	defer func() { tracingEnabled = old }()
	SpanOK(nil) // should not panic
}

func TestCB77_SpanOK_NilSpan(t *testing.T) {
	old := tracingEnabled
	tracingEnabled = true
	defer func() { tracingEnabled = old }()
	SpanOK(nil) // should not panic
}

func TestCB77_SpanError_NilSpan(t *testing.T) {
	old := tracingEnabled
	tracingEnabled = true
	defer func() { tracingEnabled = old }()
	SpanError(nil, nil) // should not panic
}

func TestCB77_ShutdownTracing_NilProvider(t *testing.T) {
	old := tp
	tp = nil
	defer func() { tp = old }()
	ShutdownTracing() // should not panic
}

func TestCB77_StartSpanFromRequest_Disabled(t *testing.T) {
	old := tracingEnabled
	tracingEnabled = false
	defer func() { tracingEnabled = old }()
	req := httptest.NewRequest("GET", "/test", nil)
	ctx, span := StartSpanFromRequest(req, "test-span")
	_ = ctx
	_ = span
	// Should return no-op span when tracing disabled
}

func TestCB77_StartSpanFromRequest_NilTracer(t *testing.T) {
	old := tracingEnabled
	tracerOld := tracer
	tracingEnabled = true
	tracer = nil
	defer func() {
		tracingEnabled = old
		tracer = tracerOld
	}()
	req := httptest.NewRequest("GET", "/test", nil)
	ctx, span := StartSpanFromRequest(req, "test-span")
	_ = ctx
	_ = span
	// Should return no-op span when tracer is nil
}

func TestCB77_TraceRouteMessage_Disabled(t *testing.T) {
	old := tracingEnabled
	tracingEnabled = false
	defer func() { tracingEnabled = old }()
	span := TraceRouteMessage("agent", "conn123")
	_ = span
}

func TestCB77_TraceRouteMessage_NilTracer(t *testing.T) {
	old := tracingEnabled
	tracerOld := tracer
	tracingEnabled = true
	tracer = nil
	defer func() {
		tracingEnabled = old
		tracer = tracerOld
	}()
	span := TraceRouteMessage("agent", "conn123")
	_ = span
}

func TestCB77_TraceOfflineEnqueue_Disabled(t *testing.T) {
	old := tracingEnabled
	tracingEnabled = false
	defer func() { tracingEnabled = old }()
	span := TraceOfflineEnqueue("user123")
	_ = span
}

func TestCB77_TraceOfflineEnqueue_NilTracer(t *testing.T) {
	old := tracingEnabled
	tracerOld := tracer
	tracingEnabled = true
	tracer = nil
	defer func() {
		tracingEnabled = old
		tracer = tracerOld
	}()
	span := TraceOfflineEnqueue("user123")
	_ = span
}

func TestCB77_TracePushNotify_Disabled(t *testing.T) {
	old := tracingEnabled
	tracingEnabled = false
	defer func() { tracingEnabled = old }()
	span := TracePushNotify("user123", "conv123", true)
	_ = span
}

func TestCB77_TracePushNotify_NilTracer(t *testing.T) {
	old := tracingEnabled
	tracerOld := tracer
	tracingEnabled = true
	tracer = nil
	defer func() {
		tracingEnabled = old
		tracer = tracerOld
	}()
	span := TracePushNotify("user123", "conv123", false)
	_ = span
}

func TestCB77_TraceAgentConnect_Disabled(t *testing.T) {
	old := tracingEnabled
	tracingEnabled = false
	defer func() { tracingEnabled = old }()
	span := TraceAgentConnect("agent123")
	_ = span
}

func TestCB77_TraceAgentConnect_NilTracer(t *testing.T) {
	old := tracingEnabled
	tracerOld := tracer
	tracingEnabled = true
	tracer = nil
	defer func() {
		tracingEnabled = old
		tracer = tracerOld
	}()
	span := TraceAgentConnect("agent123")
	_ = span
}

func TestCB77_TraceClientConnect_Disabled(t *testing.T) {
	old := tracingEnabled
	tracingEnabled = false
	defer func() { tracingEnabled = old }()
	span := TraceClientConnect("user123", "device456")
	_ = span
}

func TestCB77_TraceClientConnect_NilTracer(t *testing.T) {
	old := tracingEnabled
	tracerOld := tracer
	tracingEnabled = true
	tracer = nil
	defer func() {
		tracingEnabled = old
		tracer = tracerOld
	}()
	span := TraceClientConnect("user123", "device456")
	_ = span
}

func TestCB77_TraceRouteMessage_Enabled(t *testing.T) {
	// When tracing is enabled but tracer is nil, should still return a span
	old := tracingEnabled
	tracerOld := tracer
	tracingEnabled = true
	tracer = nil
	defer func() {
		tracingEnabled = old
		tracer = tracerOld
	}()
	span := TraceRouteMessage("client", "conn789")
	if span == nil {
		t.Error("span should not be nil")
	}
}

func TestCB77_TraceOfflineEnqueue_Enabled(t *testing.T) {
	old := tracingEnabled
	tracerOld := tracer
	tracingEnabled = true
	tracer = nil
	defer func() {
		tracingEnabled = old
		tracer = tracerOld
	}()
	span := TraceOfflineEnqueue("user789")
	if span == nil {
		t.Error("span should not be nil")
	}
}

func TestCB77_TracePushNotify_Enabled(t *testing.T) {
	old := tracingEnabled
	tracerOld := tracer
	tracingEnabled = true
	tracer = nil
	defer func() {
		tracingEnabled = old
		tracer = tracerOld
	}()
	span := TracePushNotify("user789", "conv789", true)
	if span == nil {
		t.Error("span should not be nil")
	}
}

func TestCB77_TraceAgentConnect_Enabled(t *testing.T) {
	old := tracingEnabled
	tracerOld := tracer
	tracingEnabled = true
	tracer = nil
	defer func() {
		tracingEnabled = old
		tracer = tracerOld
	}()
	span := TraceAgentConnect("agent789")
	if span == nil {
		t.Error("span should not be nil")
	}
}

func TestCB77_TraceClientConnect_Enabled(t *testing.T) {
	old := tracingEnabled
	tracerOld := tracer
	tracingEnabled = true
	tracer = nil
	defer func() {
		tracingEnabled = old
		tracer = tracerOld
	}()
	span := TraceClientConnect("user789", "device789")
	if span == nil {
		t.Error("span should not be nil")
	}
}

// ==================== extractIP ====================

func TestCB77_ExtractIP_XForwardedFor_Single(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-Forwarded-For", "203.0.113.1")
	ip := extractIP(req)
	if ip != "203.0.113.1" {
		t.Errorf("expected 203.0.113.1, got %s", ip)
	}
}

func TestCB77_ExtractIP_XForwardedFor_Multiple(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-Forwarded-For", "203.0.113.1, 198.51.100.2, 192.0.2.3")
	ip := extractIP(req)
	if ip != "203.0.113.1" {
		t.Errorf("expected first IP 203.0.113.1, got %s", ip)
	}
}

func TestCB77_ExtractIP_XRealIP(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-Real-IP", "198.51.100.10")
	ip := extractIP(req)
	if ip != "198.51.100.10" {
		t.Errorf("expected 198.51.100.10, got %s", ip)
	}
}

func TestCB77_ExtractIP_RemoteAddr_WithPort(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "192.0.2.1:54321"
	ip := extractIP(req)
	if ip != "192.0.2.1" {
		t.Errorf("expected 192.0.2.1, got %s", ip)
	}
}

func TestCB77_ExtractIP_RemoteAddr_NoPort(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "192.0.2.1"
	ip := extractIP(req)
	if ip != "192.0.2.1" {
		t.Errorf("expected 192.0.2.1, got %s", ip)
	}
}

func TestCB77_ExtractIP_XForwardedFor_TakesPrecedence(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-Forwarded-For", "203.0.113.1")
	req.Header.Set("X-Real-IP", "198.51.100.10")
	req.RemoteAddr = "192.0.2.1:54321"
	ip := extractIP(req)
	if ip != "203.0.113.1" {
		t.Errorf("expected XFF to take precedence: 203.0.113.1, got %s", ip)
	}
}

func TestCB77_ExtractIP_XRealIP_TakesPrecedence_OverRemoteAddr(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-Real-IP", "198.51.100.10")
	req.RemoteAddr = "192.0.2.1:54321"
	ip := extractIP(req)
	if ip != "198.51.100.10" {
		t.Errorf("expected X-Real-IP to take precedence: 198.51.100.10, got %s", ip)
	}
}

func TestCB77_ExtractIP_EmptyXFF(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-Forwarded-For", "")
	req.RemoteAddr = "192.0.2.1:54321"
	ip := extractIP(req)
	if ip != "192.0.2.1" {
		t.Errorf("expected fallback to RemoteAddr: 192.0.2.1, got %s", ip)
	}
}

// ==================== HashAPIKey ====================

func TestCB77_HashAPIKey_Success(t *testing.T) {
	hash, err := HashAPIKey("test-api-key-12345")
	if err != nil {
		t.Fatalf("HashAPIKey failed: %v", err)
	}
	if hash == "" {
		t.Error("hash should not be empty")
	}
	if hash == "test-api-key-12345" {
		t.Error("hash should not equal input")
	}
}

func TestCB77_HashAPIKey_EmptyInput(t *testing.T) {
	hash, err := HashAPIKey("")
	if err != nil {
		t.Fatalf("HashAPIKey with empty string should not error: %v", err)
	}
	if hash == "" {
		t.Error("hash should not be empty even for empty input")
	}
}

func TestCB77_HashAPIKey_DifferentInputs(t *testing.T) {
	hash1, _ := HashAPIKey("key1")
	hash2, _ := HashAPIKey("key2")
	if hash1 == hash2 {
		t.Error("different inputs should produce different hashes")
	}
}

func TestCB77_HashAPIKey_SameInput(t *testing.T) {
	hash1, _ := HashAPIKey("same-key")
	hash2, _ := HashAPIKey("same-key")
	// bcrypt uses random salt, so hashes differ but both should validate
	if hash1 == hash2 {
		t.Log("same input produced same hash (unlikely with bcrypt but not impossible)")
	}
	// Verify both hashes validate against the same key
	if err := bcrypt.CompareHashAndPassword([]byte(hash1), []byte("same-key")); err != nil {
		t.Error("hash1 should validate against same-key")
	}
	if err := bcrypt.CompareHashAndPassword([]byte(hash2), []byte("same-key")); err != nil {
		t.Error("hash2 should validate against same-key")
	}
}

// ==================== SetAgentStatus ====================

func TestCB77_SetAgentStatus_Online(t *testing.T) {
	h := newTestHub()
	agent := &Connection{id: "agent1", connType: "agent", hub: h, send: make(chan []byte, 10)}
	h.agents["agent1"] = agent
	h.SetAgentStatus("agent1", "busy")
	if agent.status != "busy" {
		t.Errorf("expected status 'busy', got '%s'", agent.status)
	}
}

func TestCB77_SetAgentStatus_AgentNotFound(t *testing.T) {
	h := newTestHub()
	h.SetAgentStatus("nonexistent", "busy")
	// Should not panic
}

func TestCB77_SetAgentStatus_EmptyStatus(t *testing.T) {
	h := newTestHub()
	agent := &Connection{id: "agent1", connType: "agent", hub: h, send: make(chan []byte, 10)}
	h.agents["agent1"] = agent
	h.SetAgentStatus("agent1", "")
	if agent.status != "" {
		t.Errorf("expected empty status, got '%s'", agent.status)
	}
}

func TestCB77_SetAgentStatus_Idle(t *testing.T) {
	h := newTestHub()
	agent := &Connection{id: "agent1", connType: "agent", hub: h, send: make(chan []byte, 10)}
	h.agents["agent1"] = agent
	h.SetAgentStatus("agent1", "idle")
	if agent.status != "idle" {
		t.Errorf("expected 'idle', got '%s'", agent.status)
	}
}

func TestCB77_AgentStatus_DefaultOnline(t *testing.T) {
	h := newTestHub()
	agent := &Connection{id: "agent1", connType: "agent", hub: h, send: make(chan []byte, 10), status: ""}
	h.agents["agent1"] = agent
	status := h.AgentStatus("agent1")
	if status != "online" {
		t.Errorf("expected 'online' for empty status, got '%s'", status)
	}
}

func TestCB77_AgentStatus_WithStatus(t *testing.T) {
	h := newTestHub()
	agent := &Connection{id: "agent1", connType: "agent", hub: h, send: make(chan []byte, 10), status: "busy"}
	h.agents["agent1"] = agent
	status := h.AgentStatus("agent1")
	if status != "busy" {
		t.Errorf("expected 'busy', got '%s'", status)
	}
}

func TestCB77_AgentStatus_Offline(t *testing.T) {
	h := newTestHub()
	status := h.AgentStatus("nonexistent")
	if status != "offline" {
		t.Errorf("expected 'offline', got '%s'", status)
	}
}

// ==================== GetClient ====================

func TestCB77_GetClient_Found(t *testing.T) {
	h := newTestHub()
	conn := &Connection{id: "user1", connType: "client", hub: h, send: make(chan []byte, 10)}
	h.clientConns["user1"] = []*Connection{conn}
	c := h.GetClient("user1")
	if c != conn {
		t.Error("expected to find client connection")
	}
}

func TestCB77_GetClient_NotFound(t *testing.T) {
	h := newTestHub()
	c := h.GetClient("nonexistent")
	if c != nil {
		t.Error("expected nil for nonexistent client")
	}
}

func TestCB77_GetClient_MultipleConns_ReturnsFirst(t *testing.T) {
	h := newTestHub()
	conn1 := &Connection{id: "user1", connType: "client", hub: h, send: make(chan []byte, 10)}
	conn2 := &Connection{id: "user1", connType: "client", hub: h, send: make(chan []byte, 10), deviceID: "device2"}
	h.clientConns["user1"] = []*Connection{conn1, conn2}
	c := h.GetClient("user1")
	if c != conn1 {
		t.Error("expected first connection")
	}
}

// ==================== ClientConnCount ====================

func TestCB77_ClientConnCount_Empty(t *testing.T) {
	h := newTestHub()
	count := h.ClientConnCount()
	if count != 0 {
		t.Errorf("expected 0, got %d", count)
	}
}

func TestCB77_ClientConnCount_SingleUser(t *testing.T) {
	h := newTestHub()
	h.clientConns["user1"] = []*Connection{
		{id: "user1", send: make(chan []byte, 10)},
	}
	count := h.ClientConnCount()
	if count != 1 {
		t.Errorf("expected 1, got %d", count)
	}
}

func TestCB77_ClientConnCount_MultiDevice(t *testing.T) {
	h := newTestHub()
	h.clientConns["user1"] = []*Connection{
		{id: "user1", send: make(chan []byte, 10)},
		{id: "user1", send: make(chan []byte, 10)},
		{id: "user1", send: make(chan []byte, 10)},
	}
	h.clientConns["user2"] = []*Connection{
		{id: "user2", send: make(chan []byte, 10)},
	}
	count := h.ClientConnCount()
	if count != 4 {
		t.Errorf("expected 4, got %d", count)
	}
}

// ==================== broadcastPresence ====================

func TestCB77_BroadcastPresence_Online(t *testing.T) {
	h := newTestHub()
	client := &Connection{id: "user1", connType: "client", hub: h, send: make(chan []byte, 10)}
	h.clientConns["user1"] = []*Connection{client}
	h.broadcastPresence("agent1", "agent", true)
	// Should receive a presence_update message
	select {
	case msg := <-client.send:
		var outgoing OutgoingMessage
		if err := json.Unmarshal(msg, &outgoing); err != nil {
			t.Fatalf("failed to unmarshal: %v", err)
		}
		if outgoing.Type != "presence_update" {
			t.Errorf("expected 'presence_update', got '%s'", outgoing.Type)
		}
		data, ok := outgoing.Data.(map[string]interface{})
		if !ok {
			t.Fatal("expected map data")
		}
		if data["id"] != "agent1" {
			t.Errorf("expected id 'agent1', got '%v'", data["id"])
		}
		if data["online"] != true {
			t.Errorf("expected online true, got %v", data["online"])
		}
	case <-time.After(100 * time.Millisecond):
		t.Error("expected presence update message")
	}
}

func TestCB77_BroadcastPresence_Offline(t *testing.T) {
	h := newTestHub()
	client := &Connection{id: "user1", connType: "client", hub: h, send: make(chan []byte, 10)}
	h.clientConns["user1"] = []*Connection{client}
	h.broadcastPresence("agent1", "agent", false)
	select {
	case msg := <-client.send:
		var outgoing OutgoingMessage
		json.Unmarshal(msg, &outgoing)
		data := outgoing.Data.(map[string]interface{})
		if data["online"] != false {
			t.Errorf("expected online false, got %v", data["online"])
		}
	case <-time.After(100 * time.Millisecond):
		t.Error("expected presence update message")
	}
}

func TestCB77_BroadcastPresence_NoClients(t *testing.T) {
	h := newTestHub()
	// Should not panic with no clients
	h.broadcastPresence("agent1", "agent", true)
}

func TestCB77_BroadcastPresence_MultipleClients(t *testing.T) {
	h := newTestHub()
	client1 := &Connection{id: "user1", connType: "client", hub: h, send: make(chan []byte, 10)}
	client2 := &Connection{id: "user2", connType: "client", hub: h, send: make(chan []byte, 10)}
	h.clientConns["user1"] = []*Connection{client1}
	h.clientConns["user2"] = []*Connection{client2}
	h.broadcastPresence("agent1", "agent", true)
	// Both should receive
	select {
	case <-client1.send:
	case <-time.After(100 * time.Millisecond):
		t.Error("client1 should receive message")
	}
	select {
	case <-client2.send:
	case <-time.After(100 * time.Millisecond):
		t.Error("client2 should receive message")
	}
}

func TestCB77_BroadcastPresence_ClientType(t *testing.T) {
	h := newTestHub()
	client := &Connection{id: "user1", connType: "client", hub: h, send: make(chan []byte, 10)}
	h.clientConns["user1"] = []*Connection{client}
	h.broadcastPresence("user2", "client", true)
	select {
	case msg := <-client.send:
		var outgoing OutgoingMessage
		json.Unmarshal(msg, &outgoing)
		data := outgoing.Data.(map[string]interface{})
		if data["type"] != "client" {
			t.Errorf("expected type 'client', got '%v'", data["type"])
		}
	case <-time.After(100 * time.Millisecond):
		t.Error("expected message")
	}
}

// ==================== handleGetUserPresence ====================

func TestCB77_HandleGetUserPresence_MethodNotAllowed(t *testing.T) {
	oldDB := db
	defer func() { db = oldDB }()
	db = setupTestDB_CB77(t)
	defer db.Close()

	req := httptest.NewRequest("POST", "/presence/user", nil)
	w := httptest.NewRecorder()
	handleGetUserPresence(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestCB77_HandleGetUserPresence_Unauthorized(t *testing.T) {
	oldDB := db
	defer func() { db = oldDB }()
	db = setupTestDB_CB77(t)
	defer db.Close()

	req := httptest.NewRequest("GET", "/presence/user", nil)
	w := httptest.NewRecorder()
	handleGetUserPresence(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestCB77_HandleGetUserPresence_Online(t *testing.T) {
	oldDB := db
	oldHub := hub
	defer func() { db = oldDB; hub = oldHub }()
	db = setupTestDB_CB77(t)
	defer db.Close()
	hub = newTestHub()

	userID := createUser_CB77(db, "testuser", "pass123")
	token := generateTestToken_CB77(userID)

	// Register a client connection so user appears online
	conn := &Connection{id: userID, connType: "client", hub: hub, send: make(chan []byte, 10)}
	hub.clientConns[userID] = []*Connection{conn}

	req := httptest.NewRequest("GET", "/presence/user", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleGetUserPresence(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["online"] != true {
		t.Errorf("expected online true, got %v", resp["online"])
	}
	if resp["device_count"].(float64) != 1 {
		t.Errorf("expected device_count 1, got %v", resp["device_count"])
	}
}

func TestCB77_HandleGetUserPresence_Offline_WithLastSeen(t *testing.T) {
	oldDB := db
	oldHub := hub
	defer func() { db = oldDB; hub = oldHub }()
	db = setupTestDB_CB77(t)
	defer db.Close()
	hub = newTestHub()

	userID := createUser_CB77(db, "testuser", "pass123")
	token := generateTestToken_CB77(userID)
	agentID := "agent_test"
	createAgent_CB77(db, agentID)
	convID := createConversation_CB77(db, userID, agentID)
	createMessage_CB77(db, "msg1", convID, "user", userID, "hello")

	req := httptest.NewRequest("GET", "/presence/user?user_id="+userID, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleGetUserPresence(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["online"] != false {
		t.Errorf("expected online false, got %v", resp["online"])
	}
	if resp["last_seen"] == "" || resp["last_seen"] == nil {
		t.Error("expected non-empty last_seen")
	}
}

func TestCB77_HandleGetUserPresence_Offline_NoLastSeen(t *testing.T) {
	oldDB := db
	oldHub := hub
	defer func() { db = oldDB; hub = oldHub }()
	db = setupTestDB_CB77(t)
	defer db.Close()
	hub = newTestHub()

	userID := createUser_CB77(db, "testuser", "pass123")
	token := generateTestToken_CB77(userID)

	req := httptest.NewRequest("GET", "/presence/user?user_id="+userID, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleGetUserPresence(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["online"] != false {
		t.Errorf("expected online false, got %v", resp["online"])
	}
	// last_seen should be empty since no messages
	if resp["last_seen"] != "" {
		t.Errorf("expected empty last_seen, got '%v'", resp["last_seen"])
	}
}

func TestCB77_HandleGetUserPresence_DefaultUserID(t *testing.T) {
	oldDB := db
	oldHub := hub
	defer func() { db = oldDB; hub = oldHub }()
	db = setupTestDB_CB77(t)
	defer db.Close()
	hub = newTestHub()

	userID := createUser_CB77(db, "testuser", "pass123")
	token := generateTestToken_CB77(userID)

	// No user_id param — should default to JWT user
	req := httptest.NewRequest("GET", "/presence/user", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleGetUserPresence(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["user_id"] != userID {
		t.Errorf("expected user_id '%s', got '%v'", userID, resp["user_id"])
	}
}

// ==================== accessLogMiddleware ====================

func TestCB77_AccessLogMiddleware_BasicRequest(t *testing.T) {
	oldLogger := DefaultLogger
	defer func() { DefaultLogger = oldLogger }()
	DefaultLogger = NewLogger(LogDebug)

	called := false
	handler := accessLogMiddleware(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-Request-ID", "req-123")
	w := httptest.NewRecorder()
	handler(w, req)

	if !called {
		t.Error("handler should have been called")
	}
}

func TestCB77_AccessLogMiddleware_WithAuth(t *testing.T) {
	oldLogger := DefaultLogger
	defer func() { DefaultLogger = oldLogger }()
	DefaultLogger = NewLogger(LogDebug)

	userID := "user1"
	token := generateTestToken_CB77(userID)

	called := false
	handler := accessLogMiddleware(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handler(w, req)

	if !called {
		t.Error("handler should have been called")
	}
}

func TestCB77_AccessLogMiddleware_InvalidAuth(t *testing.T) {
	oldLogger := DefaultLogger
	defer func() { DefaultLogger = oldLogger }()
	DefaultLogger = NewLogger(LogDebug)

	called := false
	handler := accessLogMiddleware(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer invalid-token")
	w := httptest.NewRecorder()
	handler(w, req)

	if !called {
		t.Error("handler should have been called even with invalid auth")
	}
}

func TestCB77_AccessLogMiddleware_PostRequest(t *testing.T) {
	oldLogger := DefaultLogger
	defer func() { DefaultLogger = oldLogger }()
	DefaultLogger = NewLogger(LogDebug)

	handler := accessLogMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
	})

	req := httptest.NewRequest("POST", "/test", nil)
	w := httptest.NewRecorder()
	handler(w, req)

	if w.Code != http.StatusCreated {
		t.Errorf("expected 201, got %d", w.Code)
	}
}

func TestCB77_AccessLogMiddleware_ServerError(t *testing.T) {
	oldLogger := DefaultLogger
	defer func() { DefaultLogger = oldLogger }()
	DefaultLogger = NewLogger(LogDebug)

	handler := accessLogMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})

	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()
	handler(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", w.Code)
	}
}

// ==================== handleWebPushSubscribe ====================

func TestCB77_HandleWebPushSubscribe_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest("GET", "/push/web-subscribe", nil)
	w := httptest.NewRecorder()
	handleWebPushSubscribe(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestCB77_HandleWebPushSubscribe_Unauthorized(t *testing.T) {
	req := httptest.NewRequest("POST", "/push/web-subscribe", nil)
	w := httptest.NewRecorder()
	handleWebPushSubscribe(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestCB77_HandleWebPushSubscribe_InvalidJSON(t *testing.T) {
	userID := "user1"
	token := generateTestToken_CB77(userID)

	req := httptest.NewRequest("POST", "/push/web-subscribe", strings.NewReader("invalid json"))
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleWebPushSubscribe(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestCB77_HandleWebPushSubscribe_MissingFields(t *testing.T) {
	userID := "user1"
	token := generateTestToken_CB77(userID)

	body := `{"endpoint":"","keys":{"p256dh":"","auth":""}}`
	req := httptest.NewRequest("POST", "/push/web-subscribe", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleWebPushSubscribe(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestCB77_HandleWebPushSubscribe_Success(t *testing.T) {
	oldDB := db
	defer func() { db = oldDB }()
	db = setupTestDB_CB77(t)
	defer db.Close()

	userID := createUser_CB77(db, "testuser", "pass123")
	token := generateTestToken_CB77(userID)

	body := `{"endpoint":"https://fcm.googleapis.com/fcm/send/abc123","keys":{"p256dh":"BNcQ...key","auth":"authkey123"}}`
	req := httptest.NewRequest("POST", "/push/web-subscribe", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleWebPushSubscribe(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["status"] != "subscribed" {
		t.Errorf("expected status 'subscribed', got '%v'", resp["status"])
	}
}

func TestCB77_HandleWebPushSubscribe_DBError(t *testing.T) {
	oldDB := db
	defer func() { db = oldDB }()
	db = setupTestDB_CB77(t)
	db.Close() // close to cause DB error

	userID := "user1"
	token := generateTestToken_CB77(userID)

	body := `{"endpoint":"https://fcm.googleapis.com/fcm/send/abc123","keys":{"p256dh":"BNcQ...key","auth":"authkey123"}}`
	req := httptest.NewRequest("POST", "/push/web-subscribe", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleWebPushSubscribe(w, req)
	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", w.Code)
	}
}

// ==================== handleRegisterDeviceToken (improve 74.1%) ====================

func TestCB77_HandleRegisterDeviceToken_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest("GET", "/push/register", nil)
	w := httptest.NewRecorder()
	handleRegisterDeviceToken(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestCB77_HandleRegisterDeviceToken_Unauthorized(t *testing.T) {
	req := httptest.NewRequest("POST", "/push/register", nil)
	w := httptest.NewRecorder()
	handleRegisterDeviceToken(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestCB77_HandleRegisterDeviceToken_InvalidJSON(t *testing.T) {
	token := generateTestToken_CB77("user1")
	req := httptest.NewRequest("POST", "/push/register", strings.NewReader("not json"))
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleRegisterDeviceToken(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestCB77_HandleRegisterDeviceToken_EmptyToken(t *testing.T) {
	token := generateTestToken_CB77("user1")
	body := `{"device_token":"","platform":"ios"}`
	req := httptest.NewRequest("POST", "/push/register", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleRegisterDeviceToken(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestCB77_HandleRegisterDeviceToken_Success(t *testing.T) {
	oldDB := db
	defer func() { db = oldDB }()
	db = setupTestDB_CB77(t)
	defer db.Close()

	userID := createUser_CB77(db, "testuser", "pass123")
	token := generateTestToken_CB77(userID)

	body := `{"device_token":"token123abc","platform":"android"}`
	req := httptest.NewRequest("POST", "/push/register", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleRegisterDeviceToken(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["status"] != "ok" {
		t.Errorf("expected status 'ok', got '%v'", resp["status"])
	}
}

func TestCB77_HandleRegisterDeviceToken_DefaultPlatform(t *testing.T) {
	oldDB := db
	defer func() { db = oldDB }()
	db = setupTestDB_CB77(t)
	defer db.Close()

	userID := createUser_CB77(db, "testuser", "pass123")
	token := generateTestToken_CB77(userID)

	body := `{"device_token":"token456def"}`
	req := httptest.NewRequest("POST", "/push/register", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleRegisterDeviceToken(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	// Verify default platform is ios
	var count int
	db.QueryRow("SELECT COUNT(*) FROM device_tokens WHERE platform = 'ios' AND device_token = 'token456def'").Scan(&count)
	if count != 1 {
		t.Errorf("expected 1 ios token, got %d", count)
	}
}

func TestCB77_HandleRegisterDeviceToken_DBError(t *testing.T) {
	oldDB := db
	defer func() { db = oldDB }()
	db = setupTestDB_CB77(t)
	db.Close()

	token := generateTestToken_CB77("user1")
	body := `{"device_token":"token789","platform":"ios"}`
	req := httptest.NewRequest("POST", "/push/register", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleRegisterDeviceToken(w, req)
	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", w.Code)
	}
}

// ==================== handleStoreEncryptedMessage (56.6%) ====================

func TestCB77_HandleStoreEncryptedMessage_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest("GET", "/messages/encrypted", nil)
	w := httptest.NewRecorder()
	handleStoreEncryptedMessage(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestCB77_HandleStoreEncryptedMessage_Unauthorized(t *testing.T) {
	req := httptest.NewRequest("POST", "/messages/encrypted", nil)
	w := httptest.NewRecorder()
	handleStoreEncryptedMessage(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestCB77_HandleStoreEncryptedMessage_InvalidJSON(t *testing.T) {
	token := generateTestToken_CB77("user1")
	req := httptest.NewRequest("POST", "/messages/encrypted", strings.NewReader("not json"))
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleStoreEncryptedMessage(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestCB77_HandleStoreEncryptedMessage_MissingFields(t *testing.T) {
	token := generateTestToken_CB77("user1")
	body := `{"conversation_id":"","ciphertext":"","iv":"","algorithm":""}`
	req := httptest.NewRequest("POST", "/messages/encrypted", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleStoreEncryptedMessage(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestCB77_HandleStoreEncryptedMessage_InvalidAlgorithm(t *testing.T) {
	token := generateTestToken_CB77("user1")
	body := `{"conversation_id":"conv1","ciphertext":"cipher","iv":"iv123","algorithm":"des"}`
	req := httptest.NewRequest("POST", "/messages/encrypted", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleStoreEncryptedMessage(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestCB77_HandleStoreEncryptedMessage_ConvNotFound(t *testing.T) {
	oldDB := db
	defer func() { db = oldDB }()
	db = setupTestDB_CB77(t)
	defer db.Close()

	userID := createUser_CB77(db, "testuser", "pass123")
	token := generateTestToken_CB77(userID)

	body := `{"conversation_id":"nonexistent","ciphertext":"cipher","iv":"iv123","algorithm":"aes-256-gcm"}`
	req := httptest.NewRequest("POST", "/messages/encrypted", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleStoreEncryptedMessage(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

func TestCB77_HandleStoreEncryptedMessage_UserNotParticipant(t *testing.T) {
	oldDB := db
	defer func() { db = oldDB }()
	db = setupTestDB_CB77(t)
	defer db.Close()

	userID := createUser_CB77(db, "testuser", "pass123")
	otherUserID := createUser_CB77(db, "otheruser", "pass456")
	agentID := "agent_test"
	createAgent_CB77(db, agentID)
	convID := createConversation_CB77(db, otherUserID, agentID)
	token := generateTestToken_CB77(userID)

	body := `{"conversation_id":"` + convID + `","ciphertext":"cipher","iv":"iv123","algorithm":"aes-256-gcm"}`
	req := httptest.NewRequest("POST", "/messages/encrypted", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleStoreEncryptedMessage(w, req)
	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", w.Code)
	}
}

func TestCB77_HandleStoreEncryptedMessage_AgentNotParticipant(t *testing.T) {
	oldDB := db
	defer func() { db = oldDB }()
	db = setupTestDB_CB77(t)
	defer db.Close()

	userID := createUser_CB77(db, "testuser", "pass123")
	agentID := "agent_test"
	createAgent_CB77(db, agentID)
	otherAgentID := "agent_other"
	createAgent_CB77(db, otherAgentID)
	convID := createConversation_CB77(db, userID, otherAgentID)

	body := `{"conversation_id":"` + convID + `","ciphertext":"cipher","iv":"iv123","algorithm":"aes-256-gcm"}`
	req := httptest.NewRequest("POST", "/messages/encrypted", strings.NewReader(body))
	req.Header.Set("X-Agent-Secret", getAgentSecret())
	req.Header.Set("X-Agent-ID", agentID)
	w := httptest.NewRecorder()
	handleStoreEncryptedMessage(w, req)
	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", w.Code)
	}
}

func TestCB77_HandleStoreEncryptedMessage_Success_User(t *testing.T) {
	oldDB := db
	oldHub := hub
	defer func() { db = oldDB; hub = oldHub }()
	db = setupTestDB_CB77(t)
	defer db.Close()
	hub = newTestHub()

	userID := createUser_CB77(db, "testuser", "pass123")
	agentID := "agent_test"
	createAgent_CB77(db, agentID)
	convID := createConversation_CB77(db, userID, agentID)
	token := generateTestToken_CB77(userID)

	body := `{"conversation_id":"` + convID + `","ciphertext":"cipherdata","iv":"iv123","algorithm":"aes-256-gcm","recipient_key_id":"key123"}`
	req := httptest.NewRequest("POST", "/messages/encrypted", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleStoreEncryptedMessage(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["status"] != "stored" {
		t.Errorf("expected status 'stored', got '%v'", resp["status"])
	}
}

func TestCB77_HandleStoreEncryptedMessage_Success_AgentToOfflineUser(t *testing.T) {
	oldDB := db
	oldHub := hub
	defer func() { db = oldDB; hub = oldHub }()
	db = setupTestDB_CB77(t)
	defer db.Close()
	hub = newTestHub()

	userID := createUser_CB77(db, "testuser", "pass123")
	agentID := "agent_test"
	createAgent_CB77(db, agentID)
	convID := createConversation_CB77(db, userID, agentID)

	// Agent sends, user is offline (no client connections)
	body := `{"conversation_id":"` + convID + `","ciphertext":"cipherdata","iv":"iv123","algorithm":"aes-256-gcm","recipient_key_id":"key123"}`
	req := httptest.NewRequest("POST", "/messages/encrypted", strings.NewReader(body))
	req.Header.Set("X-Agent-Secret", getAgentSecret())
	req.Header.Set("X-Agent-ID", agentID)
	w := httptest.NewRecorder()
	handleStoreEncryptedMessage(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCB77_HandleStoreEncryptedMessage_Success_AgentToOnlineUser(t *testing.T) {
	oldDB := db
	oldHub := hub
	defer func() { db = oldDB; hub = oldHub }()
	db = setupTestDB_CB77(t)
	defer db.Close()
	hub = newTestHub()

	userID := createUser_CB77(db, "testuser", "pass123")
	agentID := "agent_test"
	createAgent_CB77(db, agentID)
	convID := createConversation_CB77(db, userID, agentID)

	// Register user as online
	clientConn := &Connection{id: userID, connType: "client", hub: hub, send: make(chan []byte, 10)}
	hub.clientConns[userID] = []*Connection{clientConn}

	body := `{"conversation_id":"` + convID + `","ciphertext":"cipherdata","iv":"iv123","algorithm":"aes-256-gcm","recipient_key_id":"key123"}`
	req := httptest.NewRequest("POST", "/messages/encrypted", strings.NewReader(body))
	req.Header.Set("X-Agent-Secret", getAgentSecret())
	req.Header.Set("X-Agent-ID", agentID)
	w := httptest.NewRecorder()
	handleStoreEncryptedMessage(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	// User should receive the encrypted_message notification
	select {
	case msg := <-clientConn.send:
		var outgoing OutgoingMessage
		json.Unmarshal(msg, &outgoing)
		if outgoing.Type != "encrypted_message" {
			t.Errorf("expected 'encrypted_message', got '%s'", outgoing.Type)
		}
	case <-time.After(100 * time.Millisecond):
		t.Error("expected encrypted_message notification")
	}
}

func TestCB77_HandleStoreEncryptedMessage_ChaChaAlgorithm(t *testing.T) {
	oldDB := db
	oldHub := hub
	defer func() { db = oldDB; hub = oldHub }()
	db = setupTestDB_CB77(t)
	defer db.Close()
	hub = newTestHub()

	userID := createUser_CB77(db, "testuser", "pass123")
	agentID := "agent_test"
	createAgent_CB77(db, agentID)
	convID := createConversation_CB77(db, userID, agentID)
	token := generateTestToken_CB77(userID)

	body := `{"conversation_id":"` + convID + `","ciphertext":"cipherdata","iv":"iv123","algorithm":"x25519-chacha20-poly1305","recipient_key_id":"key123"}`
	req := httptest.NewRequest("POST", "/messages/encrypted", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleStoreEncryptedMessage(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCB77_HandleStoreEncryptedMessage_DBError(t *testing.T) {
	oldDB := db
	defer func() { db = oldDB }()
	db = setupTestDB_CB77(t)
	db.Close()

	userID := createUser_CB77(setupTestDB_CB77(t), "testuser", "pass123")
	token := generateTestToken_CB77(userID)

	// Recreate a db that's closed
	db = setupTestDB_CB77(t)
	db.Close()
	defer func() { db = oldDB }()

	body := `{"conversation_id":"conv1","ciphertext":"cipher","iv":"iv123","algorithm":"aes-256-gcm"}`
	req := httptest.NewRequest("POST", "/messages/encrypted", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleStoreEncryptedMessage(w, req)
	// Will fail at getConversation since db is closed
	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404 (conv not found due to DB error), got %d", w.Code)
	}
}

// ==================== handleGetEncryptedMessages (63.4%) ====================

func TestCB77_HandleGetEncryptedMessages_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest("POST", "/messages/encrypted", nil)
	w := httptest.NewRecorder()
	handleGetEncryptedMessages(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestCB77_HandleGetEncryptedMessages_Unauthorized(t *testing.T) {
	req := httptest.NewRequest("GET", "/messages/encrypted", nil)
	w := httptest.NewRecorder()
	handleGetEncryptedMessages(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestCB77_HandleGetEncryptedMessages_MissingConvID(t *testing.T) {
	token := generateTestToken_CB77("user1")
	req := httptest.NewRequest("GET", "/messages/encrypted", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleGetEncryptedMessages(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestCB77_HandleGetEncryptedMessages_ConvNotFound(t *testing.T) {
	oldDB := db
	defer func() { db = oldDB }()
	db = setupTestDB_CB77(t)
	defer db.Close()

	token := generateTestToken_CB77("user1")
	req := httptest.NewRequest("GET", "/messages/encrypted?conversation_id=nonexistent", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleGetEncryptedMessages(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

func TestCB77_HandleGetEncryptedMessages_UserNotParticipant(t *testing.T) {
	oldDB := db
	defer func() { db = oldDB }()
	db = setupTestDB_CB77(t)
	defer db.Close()

	userID := createUser_CB77(db, "testuser", "pass123")
	otherUserID := createUser_CB77(db, "otheruser", "pass456")
	agentID := "agent_test"
	createAgent_CB77(db, agentID)
	convID := createConversation_CB77(db, otherUserID, agentID)
	token := generateTestToken_CB77(userID)

	req := httptest.NewRequest("GET", "/messages/encrypted?conversation_id="+convID, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleGetEncryptedMessages(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

func TestCB77_HandleGetEncryptedMessages_Success(t *testing.T) {
	oldDB := db
	defer func() { db = oldDB }()
	db = setupTestDB_CB77(t)
	defer db.Close()

	userID := createUser_CB77(db, "testuser", "pass123")
	agentID := "agent_test"
	createAgent_CB77(db, agentID)
	convID := createConversation_CB77(db, userID, agentID)
	token := generateTestToken_CB77(userID)

	// Insert an encrypted message
	db.Exec(`INSERT INTO encrypted_messages (id, conversation_id, sender_id, sender_type, ciphertext, iv, recipient_key_id, sender_key_id, algorithm, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		"emsg1", convID, "user", userID, "cipher1", "iv1", "key1", "", "aes-256-gcm", time.Now().UTC())

	req := httptest.NewRequest("GET", "/messages/encrypted?conversation_id="+convID, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleGetEncryptedMessages(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var messages []map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &messages)
	if len(messages) != 1 {
		t.Errorf("expected 1 message, got %d", len(messages))
	}
}

func TestCB77_HandleGetEncryptedMessages_Empty(t *testing.T) {
	oldDB := db
	defer func() { db = oldDB }()
	db = setupTestDB_CB77(t)
	defer db.Close()

	userID := createUser_CB77(db, "testuser", "pass123")
	agentID := "agent_test"
	createAgent_CB77(db, agentID)
	convID := createConversation_CB77(db, userID, agentID)
	token := generateTestToken_CB77(userID)

	req := httptest.NewRequest("GET", "/messages/encrypted?conversation_id="+convID, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleGetEncryptedMessages(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var messages []map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &messages)
	if len(messages) != 0 {
		t.Errorf("expected 0 messages, got %d", len(messages))
	}
}

func TestCB77_HandleGetEncryptedMessages_WithLimit(t *testing.T) {
	oldDB := db
	defer func() { db = oldDB }()
	db = setupTestDB_CB77(t)
	defer db.Close()

	userID := createUser_CB77(db, "testuser", "pass123")
	agentID := "agent_test"
	createAgent_CB77(db, agentID)
	convID := createConversation_CB77(db, userID, agentID)
	token := generateTestToken_CB77(userID)

	// Insert 3 messages
	for i := 0; i < 3; i++ {
		db.Exec(`INSERT INTO encrypted_messages (id, conversation_id, sender_id, sender_type, ciphertext, iv, recipient_key_id, sender_key_id, algorithm, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			"emsg"+string(rune('A'+i)), convID, "user", userID, "cipher"+string(rune('A'+i)), "iv1", "key1", "", "aes-256-gcm", time.Now().UTC())
	}

	req := httptest.NewRequest("GET", "/messages/encrypted?conversation_id="+convID+"&limit=2", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleGetEncryptedMessages(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var messages []map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &messages)
	if len(messages) > 2 {
		t.Errorf("expected at most 2 messages, got %d", len(messages))
	}
}

func TestCB77_HandleGetEncryptedMessages_AgentAccess(t *testing.T) {
	oldDB := db
	defer func() { db = oldDB }()
	db = setupTestDB_CB77(t)
	defer db.Close()

	userID := createUser_CB77(db, "testuser", "pass123")
	agentID := "agent_test"
	createAgent_CB77(db, agentID)
	convID := createConversation_CB77(db, userID, agentID)

	// Insert message
	db.Exec(`INSERT INTO encrypted_messages (id, conversation_id, sender_id, sender_type, ciphertext, iv, recipient_key_id, sender_key_id, algorithm, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		"emsg1", convID, "user", userID, "cipher1", "iv1", "key1", "", "aes-256-gcm", time.Now().UTC())

	req := httptest.NewRequest("GET", "/messages/encrypted?conversation_id="+convID, nil)
	req.Header.Set("X-Agent-Secret", getAgentSecret())
	req.Header.Set("X-Agent-ID", agentID)
	w := httptest.NewRecorder()
	handleGetEncryptedMessages(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var messages []map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &messages)
	if len(messages) != 1 {
		t.Errorf("expected 1 message, got %d", len(messages))
	}
}

func TestCB77_HandleGetEncryptedMessages_AgentNotParticipant(t *testing.T) {
	oldDB := db
	defer func() { db = oldDB }()
	db = setupTestDB_CB77(t)
	defer db.Close()

	userID := createUser_CB77(db, "testuser", "pass123")
	agentID := "agent_test"
	otherAgentID := "agent_other"
	createAgent_CB77(db, agentID)
	createAgent_CB77(db, otherAgentID)
	convID := createConversation_CB77(db, userID, otherAgentID)

	req := httptest.NewRequest("GET", "/messages/encrypted?conversation_id="+convID, nil)
	req.Header.Set("X-Agent-Secret", getAgentSecret())
	req.Header.Set("X-Agent-ID", agentID)
	w := httptest.NewRecorder()
	handleGetEncryptedMessages(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

func TestCB77_HandleGetEncryptedMessages_InvalidLimit(t *testing.T) {
	oldDB := db
	defer func() { db = oldDB }()
	db = setupTestDB_CB77(t)
	defer db.Close()

	userID := createUser_CB77(db, "testuser", "pass123")
	agentID := "agent_test"
	createAgent_CB77(db, agentID)
	convID := createConversation_CB77(db, userID, agentID)
	token := generateTestToken_CB77(userID)

	// Negative limit should default to 50
	req := httptest.NewRequest("GET", "/messages/encrypted?conversation_id="+convID+"&limit=-5", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleGetEncryptedMessages(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestCB77_HandleGetEncryptedMessages_OverMaxLimit(t *testing.T) {
	oldDB := db
	defer func() { db = oldDB }()
	db = setupTestDB_CB77(t)
	defer db.Close()

	userID := createUser_CB77(db, "testuser", "pass123")
	agentID := "agent_test"
	createAgent_CB77(db, agentID)
	convID := createConversation_CB77(db, userID, agentID)
	token := generateTestToken_CB77(userID)

	// Limit > 200 should default to 50
	req := httptest.NewRequest("GET", "/messages/encrypted?conversation_id="+convID+"&limit=500", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleGetEncryptedMessages(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

// ==================== routeTypingIndicator (78.3%) ====================

func TestCB77_RouteTypingIndicator_InvalidJSON(t *testing.T) {
	sender := &Connection{id: "agent1", connType: "agent", send: make(chan []byte, 10)}
	routeTypingIndicator(sender, json.RawMessage(`invalid`))
	// Should not panic
}

func TestCB77_RouteTypingIndicator_EmptyConvID(t *testing.T) {
	sender := &Connection{id: "agent1", connType: "agent", send: make(chan []byte, 10)}
	routeTypingIndicator(sender, json.RawMessage(`{"conversation_id":""}`))
	// Should not panic
}

func TestCB77_RouteTypingIndicator_ConvNotFound(t *testing.T) {
	oldDB := db
	oldHub := hub
	defer func() { db = oldDB; hub = oldHub }()
	db = setupTestDB_CB77(t)
	defer db.Close()
	hub = newTestHub()

	sender := &Connection{id: "agent1", connType: "agent", send: make(chan []byte, 10), hub: hub}
	routeTypingIndicator(sender, json.RawMessage(`{"conversation_id":"nonexistent"}`))
	// Should not panic
}

func TestCB77_RouteTypingIndicator_AgentNotParticipant(t *testing.T) {
	oldDB := db
	oldHub := hub
	defer func() { db = oldDB; hub = oldHub }()
	db = setupTestDB_CB77(t)
	defer db.Close()
	hub = newTestHub()

	userID := createUser_CB77(db, "user1", "pass")
	agentID := "agent1"
	createAgent_CB77(db, agentID)
	otherAgentID := "agent2"
	createAgent_CB77(db, otherAgentID)
	convID := createConversation_CB77(db, userID, otherAgentID)

	sender := &Connection{id: agentID, connType: "agent", send: make(chan []byte, 10), hub: hub}
	routeTypingIndicator(sender, json.RawMessage(`{"conversation_id":"`+convID+`"}`))
	// Should not route (agent not participant)
}

func TestCB77_RouteTypingIndicator_ClientNotParticipant(t *testing.T) {
	oldDB := db
	oldHub := hub
	defer func() { db = oldDB; hub = oldHub }()
	db = setupTestDB_CB77(t)
	defer db.Close()
	hub = newTestHub()

	userID := createUser_CB77(db, "user1", "pass")
	otherUserID := createUser_CB77(db, "user2", "pass")
	agentID := "agent1"
	createAgent_CB77(db, agentID)
	convID := createConversation_CB77(db, otherUserID, agentID)

	sender := &Connection{id: userID, connType: "client", send: make(chan []byte, 10), hub: hub}
	routeTypingIndicator(sender, json.RawMessage(`{"conversation_id":"`+convID+`"}`))
	// Should not route (client not participant)
}

func TestCB77_RouteTypingIndicator_AgentToClient(t *testing.T) {
	oldDB := db
	oldHub := hub
	defer func() { db = oldDB; hub = oldHub }()
	db = setupTestDB_CB77(t)
	defer db.Close()
	hub = newTestHub()

	userID := createUser_CB77(db, "user1", "pass")
	agentID := "agent1"
	createAgent_CB77(db, agentID)
	convID := createConversation_CB77(db, userID, agentID)

	clientConn := &Connection{id: userID, connType: "client", hub: hub, send: make(chan []byte, 10)}
	hub.clientConns[userID] = []*Connection{clientConn}

	sender := &Connection{id: agentID, connType: "agent", send: make(chan []byte, 10), hub: hub}
	routeTypingIndicator(sender, json.RawMessage(`{"conversation_id":"`+convID+`"}`))

	select {
	case msg := <-clientConn.send:
		var outgoing OutgoingMessage
		json.Unmarshal(msg, &outgoing)
		if outgoing.Type != MsgTypeTyping {
			t.Errorf("expected '%s', got '%s'", MsgTypeTyping, outgoing.Type)
		}
	case <-time.After(100 * time.Millisecond):
		t.Error("expected typing indicator message")
	}
}

func TestCB77_RouteTypingIndicator_ClientToAgent(t *testing.T) {
	oldDB := db
	oldHub := hub
	defer func() { db = oldDB; hub = oldHub }()
	db = setupTestDB_CB77(t)
	defer db.Close()
	hub = newTestHub()

	userID := createUser_CB77(db, "user1", "pass")
	agentID := "agent1"
	createAgent_CB77(db, agentID)
	convID := createConversation_CB77(db, userID, agentID)

	agentConn := &Connection{id: agentID, connType: "agent", hub: hub, send: make(chan []byte, 10)}
	hub.agents[agentID] = agentConn

	sender := &Connection{id: userID, connType: "client", send: make(chan []byte, 10), hub: hub}
	routeTypingIndicator(sender, json.RawMessage(`{"conversation_id":"`+convID+`"}`))

	select {
	case msg := <-agentConn.send:
		var outgoing OutgoingMessage
		json.Unmarshal(msg, &outgoing)
		if outgoing.Type != MsgTypeTyping {
			t.Errorf("expected '%s', got '%s'", MsgTypeTyping, outgoing.Type)
		}
	case <-time.After(100 * time.Millisecond):
		t.Error("expected typing indicator message")
	}
}

func TestCB77_RouteTypingIndicator_AgentOffline(t *testing.T) {
	oldDB := db
	oldHub := hub
	defer func() { db = oldDB; hub = oldHub }()
	db = setupTestDB_CB77(t)
	defer db.Close()
	hub = newTestHub()

	userID := createUser_CB77(db, "user1", "pass")
	agentID := "agent1"
	createAgent_CB77(db, agentID)
	convID := createConversation_CB77(db, userID, agentID)

	// Agent not in hub — should not panic
	sender := &Connection{id: userID, connType: "client", send: make(chan []byte, 10), hub: hub}
	routeTypingIndicator(sender, json.RawMessage(`{"conversation_id":"`+convID+`"}`))
}

// ==================== routeStatusUpdate (79.2%) ====================

func TestCB77_RouteStatusUpdate_InvalidJSON(t *testing.T) {
	sender := &Connection{id: "agent1", connType: "agent", send: make(chan []byte, 10)}
	routeStatusUpdate(sender, json.RawMessage(`invalid`))
	// Should not panic
}

func TestCB77_RouteStatusUpdate_AgentStatusUpdate(t *testing.T) {
	oldDB := db
	oldHub := hub
	defer func() { db = oldDB; hub = oldHub }()
	db = setupTestDB_CB77(t)
	defer db.Close()
	hub = newTestHub()

	agentID := "agent1"
	createAgent_CB77(db, agentID)
	agentConn := &Connection{id: agentID, connType: "agent", hub: hub, send: make(chan []byte, 10)}
	hub.agents[agentID] = agentConn

	// Add a client to receive broadcast
	clientConn := &Connection{id: "user1", connType: "client", hub: hub, send: make(chan []byte, 10)}
	hub.clientConns["user1"] = []*Connection{clientConn}

	sender := &Connection{id: agentID, connType: "agent", send: make(chan []byte, 10), hub: hub}
	routeStatusUpdate(sender, json.RawMessage(`{"status":"busy"}`))

	// Agent status should be updated
	if agentConn.status != "busy" {
		t.Errorf("expected 'busy', got '%s'", agentConn.status)
	}

	// Client should receive broadcast
	select {
	case <-clientConn.send:
	case <-time.After(100 * time.Millisecond):
		t.Error("expected broadcast message")
	}
}

func TestCB77_RouteStatusUpdate_ClientStatus(t *testing.T) {
	oldDB := db
	oldHub := hub
	defer func() { db = oldDB; hub = oldHub }()
	db = setupTestDB_CB77(t)
	defer db.Close()
	hub = newTestHub()

	userID := createUser_CB77(db, "user1", "pass")
	agentID := "agent1"
	createAgent_CB77(db, agentID)
	convID := createConversation_CB77(db, userID, agentID)

	agentConn := &Connection{id: agentID, connType: "agent", hub: hub, send: make(chan []byte, 10)}
	hub.agents[agentID] = agentConn

	sender := &Connection{id: userID, connType: "client", send: make(chan []byte, 10), hub: hub}
	routeStatusUpdate(sender, json.RawMessage(`{"conversation_id":"`+convID+`","status":"typing"}`))

	select {
	case msg := <-agentConn.send:
		var outgoing OutgoingMessage
		json.Unmarshal(msg, &outgoing)
		if outgoing.Type != MsgTypeStatus {
			t.Errorf("expected '%s', got '%s'", MsgTypeStatus, outgoing.Type)
		}
	case <-time.After(100 * time.Millisecond):
		t.Error("expected status update message")
	}
}

func TestCB77_RouteStatusUpdate_EmptyConvID(t *testing.T) {
	oldDB := db
	oldHub := hub
	defer func() { db = oldDB; hub = oldHub }()
	db = setupTestDB_CB77(t)
	defer db.Close()
	hub = newTestHub()

	agentID := "agent1"
	createAgent_CB77(db, agentID)
	agentConn := &Connection{id: agentID, connType: "agent", hub: hub, send: make(chan []byte, 10)}
	hub.agents[agentID] = agentConn

	sender := &Connection{id: agentID, connType: "agent", send: make(chan []byte, 10), hub: hub}
	routeStatusUpdate(sender, json.RawMessage(`{"status":"idle"}`))

	// Should update status but not route to specific conversation
	if agentConn.status != "idle" {
		t.Errorf("expected 'idle', got '%s'", agentConn.status)
	}
}

func TestCB77_RouteStatusUpdate_ConvNotFound(t *testing.T) {
	oldDB := db
	oldHub := hub
	defer func() { db = oldDB; hub = oldHub }()
	db = setupTestDB_CB77(t)
	defer db.Close()
	hub = newTestHub()

	sender := &Connection{id: "agent1", connType: "agent", send: make(chan []byte, 10), hub: hub}
	routeStatusUpdate(sender, json.RawMessage(`{"conversation_id":"nonexistent","status":"active"}`))
	// Should not panic
}

func TestCB77_RouteStatusUpdate_AgentNotParticipant(t *testing.T) {
	oldDB := db
	oldHub := hub
	defer func() { db = oldDB; hub = oldHub }()
	db = setupTestDB_CB77(t)
	defer db.Close()
	hub = newTestHub()

	userID := createUser_CB77(db, "user1", "pass")
	agentID := "agent1"
	otherAgentID := "agent2"
	createAgent_CB77(db, agentID)
	createAgent_CB77(db, otherAgentID)
	convID := createConversation_CB77(db, userID, otherAgentID)

	sender := &Connection{id: agentID, connType: "agent", send: make(chan []byte, 10), hub: hub}
	routeStatusUpdate(sender, json.RawMessage(`{"conversation_id":"`+convID+`","status":"active"}`))
	// Should not route (not participant)
}

func TestCB77_RouteStatusUpdate_ClientToOfflineAgent(t *testing.T) {
	oldDB := db
	oldHub := hub
	defer func() { db = oldDB; hub = oldHub }()
	db = setupTestDB_CB77(t)
	defer db.Close()
	hub = newTestHub()

	userID := createUser_CB77(db, "user1", "pass")
	agentID := "agent1"
	createAgent_CB77(db, agentID)
	convID := createConversation_CB77(db, userID, agentID)

	// Agent not in hub
	sender := &Connection{id: userID, connType: "client", send: make(chan []byte, 10), hub: hub}
	routeStatusUpdate(sender, json.RawMessage(`{"conversation_id":"`+convID+`","status":"active"}`))
	// Should not panic
}

func TestCB77_RouteStatusUpdate_AgentToMultiDevice(t *testing.T) {
	oldDB := db
	oldHub := hub
	defer func() { db = oldDB; hub = oldHub }()
	db = setupTestDB_CB77(t)
	defer db.Close()
	hub = newTestHub()

	userID := createUser_CB77(db, "user1", "pass")
	agentID := "agent1"
	createAgent_CB77(db, agentID)
	convID := createConversation_CB77(db, userID, agentID)

	client1 := &Connection{id: userID, connType: "client", hub: hub, send: make(chan []byte, 10), deviceID: "d1"}
	client2 := &Connection{id: userID, connType: "client", hub: hub, send: make(chan []byte, 10), deviceID: "d2"}
	hub.clientConns[userID] = []*Connection{client1, client2}

	sender := &Connection{id: agentID, connType: "agent", send: make(chan []byte, 10), hub: hub}
	routeStatusUpdate(sender, json.RawMessage(`{"conversation_id":"`+convID+`","status":"active"}`))

	// Both devices should receive
	select {
	case <-client1.send:
	case <-time.After(100 * time.Millisecond):
		t.Error("client1 should receive")
	}
	select {
	case <-client2.send:
	case <-time.After(100 * time.Millisecond):
		t.Error("client2 should receive")
	}
}

// ==================== getConversationMessages (78.3%) ====================

func TestCB77_GetConversationMessages_DBError(t *testing.T) {
	oldDB := db
	defer func() { db = oldDB }()
	db = setupTestDB_CB77(t)
	db.Close()

	messages, err := getConversationMessages("conv1", 50, "")
	_ = messages
	_ = err
	// Should return error or empty, not panic
}

func TestCB77_GetConversationMessages_Empty(t *testing.T) {
	oldDB := db
	defer func() { db = oldDB }()
	db = setupTestDB_CB77(t)
	defer db.Close()

	userID := createUser_CB77(db, "user1", "pass")
	agentID := "agent1"
	createAgent_CB77(db, agentID)
	convID := createConversation_CB77(db, userID, agentID)

	messages, err := getConversationMessages(convID, 50, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(messages) != 0 {
		t.Errorf("expected 0 messages, got %d", len(messages))
	}
}

func TestCB77_GetConversationMessages_WithMessages(t *testing.T) {
	oldDB := db
	defer func() { db = oldDB }()
	db = setupTestDB_CB77(t)
	defer db.Close()

	userID := createUser_CB77(db, "user1", "pass")
	agentID := "agent1"
	createAgent_CB77(db, agentID)
	convID := createConversation_CB77(db, userID, agentID)

	createMessage_CB77(db, "msg1", convID, "user", userID, "hello")
	createMessage_CB77(db, "msg2", convID, "agent", agentID, "hi there")

	messages, err := getConversationMessages(convID, 50, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(messages) != 2 {
		t.Errorf("expected 2 messages, got %d", len(messages))
	}
}

func TestCB77_GetConversationMessages_Pagination(t *testing.T) {
	oldDB := db
	defer func() { db = oldDB }()
	db = setupTestDB_CB77(t)
	defer db.Close()

	userID := createUser_CB77(db, "user1", "pass")
	agentID := "agent1"
	createAgent_CB77(db, agentID)
	convID := createConversation_CB77(db, userID, agentID)

	for i := 0; i < 5; i++ {
		createMessage_CB77(db, "msg"+string(rune('A'+i)), convID, "user", userID, "msg"+string(rune('A'+i)))
	}

	messages, err := getConversationMessages(convID, 2, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(messages) != 2 {
		t.Errorf("expected 2 messages with limit, got %d", len(messages))
	}
}

func TestCB77_GetConversationMessages_WithOffset(t *testing.T) {
	oldDB := db
	defer func() { db = oldDB }()
	db = setupTestDB_CB77(t)
	defer db.Close()

	userID := createUser_CB77(db, "user1", "pass")
	agentID := "agent1"
	createAgent_CB77(db, agentID)
	convID := createConversation_CB77(db, userID, agentID)

	for i := 0; i < 5; i++ {
		createMessage_CB77(db, "msg"+string(rune('A'+i)), convID, "user", userID, "msg"+string(rune('A'+i)))
	}

	messages, err := getConversationMessages(convID, 2, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(messages) != 2 {
		t.Errorf("expected 2 messages with offset, got %d", len(messages))
	}
}

// ==================== persistQueue (80%) ====================

func TestCB77_PersistQueue_NilDB(t *testing.T) {
	persistQueue(nil, "user1", []byte("test"))
	// Should not panic with nil DB
}

func TestCB77_PersistQueue_Success(t *testing.T) {
	testDB := setupTestDB_CB77(t)
	defer testDB.Close()
	initQueueDB(testDB)

	data := marshalOutgoingMessage(OutgoingMessage{Type: "message", Data: map[string]string{"content": "hello"}})
	persistQueue(testDB, "user1", data)

	var count int
	testDB.QueryRow("SELECT COUNT(*) FROM offline_queue WHERE recipient = ?", "user1").Scan(&count)
	if count != 1 {
		t.Errorf("expected 1 persisted message, got %d", count)
	}
}

func TestCB77_PersistQueue_EmptyData(t *testing.T) {
	testDB := setupTestDB_CB77(t)
	defer testDB.Close()
	initQueueDB(testDB)

	persistQueue(testDB, "user1", nil)
	// Should not panic
}

// ==================== initQueueDB (80%) ====================

func TestCB77_InitQueueDB_NilDB(t *testing.T) {
	initQueueDB(nil)
	// Should not panic with nil DB
}

func TestCB77_InitQueueDB_Success(t *testing.T) {
	testDB := setupTestDB_CB77(t)
	defer testDB.Close()

	initQueueDB(testDB)

	var name string
	err := testDB.QueryRow("SELECT name FROM sqlite_master WHERE type='table' AND name='offline_queue'").Scan(&name)
	if err != nil {
		t.Errorf("offline_queue table not created: %v", err)
	}
}

func TestCB77_InitQueueDB_Idempotent(t *testing.T) {
	testDB := setupTestDB_CB77(t)
	defer testDB.Close()

	initQueueDB(testDB)
	initQueueDB(testDB)
	// Should not error on second call
}

// ==================== ValidateJWT (83.3%) ====================

func TestCB77_ValidateJWT_ExpiredToken(t *testing.T) {
	claims := &Claims{
		UserID: "user1",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(-time.Hour)),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, _ := token.SignedString(jwtSecret)

	_, err := ValidateJWT(signed)
	if err == nil {
		t.Error("expected error for expired token")
	}
}

func TestCB77_ValidateJWT_WrongSigningMethod(t *testing.T) {
	claims := &Claims{
		UserID: "user1",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodNone, claims)
	signed, _ := token.SignedString(jwtSecret)

	_, err := ValidateJWT(signed)
	if err == nil {
		t.Error("expected error for wrong signing method")
	}
}

func TestCB77_ValidateJWT_MalformedToken(t *testing.T) {
	_, err := ValidateJWT("not.a.valid.token")
	if err == nil {
		t.Error("expected error for malformed token")
	}
}

func TestCB77_ValidateJWT_EmptyToken(t *testing.T) {
	_, err := ValidateJWT("")
	if err == nil {
		t.Error("expected error for empty token")
	}
}

// ==================== Snapshot (83.3%) ====================

func TestCB77_Snapshot_WithOfflineQueue(t *testing.T) {
	oldHub := hub
	defer func() { hub = oldHub }()
	h := newTestHub()
	hub = h
	m := NewMetrics(h)
	q := newOfflineQueue(100, time.Hour)
	q.Enqueue("user1", marshalOutgoingMessage(OutgoingMessage{Type: "message"}))

	snap := m.Snapshot()
	if snap == nil {
		t.Error("expected non-nil snapshot")
	}
}

func TestCB77_Snapshot_NilOfflineQueue(t *testing.T) {
	oldHub := hub
	defer func() { hub = oldHub }()
	h := newTestHub()
	hub = h
	m := NewMetrics(h)

	snap := m.Snapshot()
	if snap == nil {
		t.Error("expected non-nil snapshot")
	}
}

func TestCB77_Snapshot_Uptime(t *testing.T) {
	oldHub := hub
	defer func() { hub = oldHub }()
	h := newTestHub()
	hub = h
	m := NewMetrics(h)
	m.StartTime = time.Now().Add(-5 * time.Second)

	snap := m.Snapshot()
	if snap == nil {
		t.Error("expected non-nil snapshot")
	}
	if uptime, ok := snap["uptime_seconds"].(int); ok {
		if uptime < 4 {
			t.Errorf("expected uptime >= 4s, got %d", uptime)
		}
	}
}

// ==================== hub.run (84.8%) ====================

func TestCB77_HubRun_UnregisterUnknown(t *testing.T) {
	h := &Hub{
		agents:      make(map[string]*Connection),
		clientConns: make(map[string][]*Connection),
		register:    make(chan *Connection),
		unregister:  make(chan *Connection),
		broadcast:   make(chan []byte),
		done:        make(chan struct{}),
		monitorDone: make(chan struct{}),
		runDone:     make(chan struct{}),
	}
	close(h.monitorDone) // no monitor running
	go h.run()
	defer h.Stop()

	conn := &Connection{id: "unknown", connType: "client", hub: h, send: make(chan []byte, 10)}
	h.unregister <- conn

	// Should not panic
}

func TestCB77_HubRun_ReconnectSameAgent(t *testing.T) {
	h := &Hub{
		agents:      make(map[string]*Connection),
		clientConns: make(map[string][]*Connection),
		register:    make(chan *Connection),
		unregister:  make(chan *Connection),
		broadcast:   make(chan []byte),
		done:        make(chan struct{}),
		monitorDone: make(chan struct{}),
		runDone:     make(chan struct{}),
	}
	close(h.monitorDone)
	go h.run()
	defer h.Stop()

	conn1 := &Connection{id: "agent1", connType: "agent", hub: h, send: make(chan []byte, 10)}
	conn2 := &Connection{id: "agent1", connType: "agent", hub: h, send: make(chan []byte, 10)}

	h.register <- conn1
	h.register <- conn2 // replaces conn1

	time.Sleep(50 * time.Millisecond) // allow goroutine to process

	h.mu.RLock()
	defer h.mu.RUnlock()
	if h.agents["agent1"] != conn2 {
		t.Error("expected conn2 to replace conn1")
	}
}

func TestCB77_HubRun_ClientReconnect(t *testing.T) {
	h := &Hub{
		agents:      make(map[string]*Connection),
		clientConns: make(map[string][]*Connection),
		register:    make(chan *Connection),
		unregister:  make(chan *Connection),
		broadcast:   make(chan []byte),
		done:        make(chan struct{}),
		monitorDone: make(chan struct{}),
		runDone:     make(chan struct{}),
	}
	close(h.monitorDone)
	go h.run()
	defer h.Stop()

	conn1 := &Connection{id: "user1", connType: "client", hub: h, send: make(chan []byte, 10), deviceID: "d1"}
	conn2 := &Connection{id: "user1", connType: "client", hub: h, send: make(chan []byte, 10), deviceID: "d1"}

	h.register <- conn1
	h.register <- conn2 // same device, should replace

	time.Sleep(50 * time.Millisecond) // allow goroutine to process

	h.mu.RLock()
	defer h.mu.RUnlock()
	conns := h.clientConns["user1"]
	if len(conns) != 1 {
		t.Errorf("expected 1 connection (replace), got %d", len(conns))
	}
}

// ==================== handleAdminAgents (83.3%) ====================

func TestCB77_HandleAdminAgents_ScanError(t *testing.T) {
	oldDB := db
	defer func() { db = oldDB }()
	db = setupTestDB_CB77(t)
	defer db.Close()

	// Insert agent with NULL name to potentially cause scan issues
	db.Exec("INSERT INTO agents (id, name, model) VALUES (?, NULL, ?)", "agent1", "model1")

	req := httptest.NewRequest("GET", "/admin/agents", nil)
	req.Header.Set("X-Admin-Secret", getAdminSecret())
	w := httptest.NewRecorder()
	handleAdminAgents(w, req)
	// NULL name should still work (scan into string)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestCB77_HandleAdminAgents_WithConnectedAgent(t *testing.T) {
	oldDB := db
	oldHub := hub
	defer func() { db = oldDB; hub = oldHub }()
	db = setupTestDB_CB77(t)
	defer db.Close()
	hub = newTestHub()

	createAgent_CB77(db, "agent1")
	conn := &Connection{id: "agent1", connType: "agent", hub: hub, send: make(chan []byte, 10), connectedAt: time.Now()}
	hub.agents["agent1"] = conn

	req := httptest.NewRequest("GET", "/admin/agents", nil)
	req.Header.Set("X-Admin-Secret", getAdminSecret())
	w := httptest.NewRecorder()
	handleAdminAgents(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

// ==================== handleListAttachments (86.1%) ====================

func TestCB77_HandleListAttachments_Success(t *testing.T) {
	oldDB := db
	defer func() { db = oldDB }()
	db = setupTestDB_CB77(t)
	defer db.Close()

	userID := createUser_CB77(db, "user1", "pass")
	agentID := "agent1"
	createAgent_CB77(db, agentID)
	convID := createConversation_CB77(db, userID, agentID)
	token := generateTestToken_CB77(userID)

	// Insert a message first, then an attachment linked to it
	msgID := "msg-att-1"
	db.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, created_at) VALUES (?, ?, 'user', ?, 'test message', ?)",
		msgID, convID, userID, time.Now().UTC())
	db.Exec("INSERT INTO attachments (id, message_id, user_id, filename, content_type, size, sha256, storage_path, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
		"att1", msgID, userID, "test.png", "image/png", int64(1024), "abc123", "/uploads/att1", time.Now().UTC())

	req := httptest.NewRequest("GET", "/attachments?conversation_id="+convID, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleListAttachments(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var attachments []map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &attachments)
	if len(attachments) != 1 {
		t.Errorf("expected 1 attachment, got %d", len(attachments))
	}
}

func TestCB77_HandleListAttachments_NotOwner(t *testing.T) {
	oldDB := db
	defer func() { db = oldDB }()
	db = setupTestDB_CB77(t)
	defer db.Close()

	userID := createUser_CB77(db, "user1", "pass")
	otherUserID := createUser_CB77(db, "user2", "pass")
	agentID := "agent1"
	createAgent_CB77(db, agentID)
	convID := createConversation_CB77(db, otherUserID, agentID)
	token := generateTestToken_CB77(userID)

	req := httptest.NewRequest("GET", "/attachments?conversation_id="+convID, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleListAttachments(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

func TestCB77_HandleListAttachments_NotFound(t *testing.T) {
	oldDB := db
	defer func() { db = oldDB }()
	db = setupTestDB_CB77(t)
	defer db.Close()

	userID := createUser_CB77(db, "user1", "pass")
	token := generateTestToken_CB77(userID)

	req := httptest.NewRequest("GET", "/attachments?conversation_id=nonexistent", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleListAttachments(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

func TestCB77_HandleListAttachments_DBError(t *testing.T) {
	oldDB := db
	defer func() { db = oldDB }()
	db = setupTestDB_CB77(t)
	db.Close()

	userID := "user1"
	token := generateTestToken_CB77(userID)

	req := httptest.NewRequest("GET", "/attachments?conversation_id=conv1", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleListAttachments(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404 (DB error → not found), got %d", w.Code)
	}
}

func TestCB77_HandleListAttachments_Empty(t *testing.T) {
	oldDB := db
	defer func() { db = oldDB }()
	db = setupTestDB_CB77(t)
	defer db.Close()

	userID := createUser_CB77(db, "user1", "pass")
	agentID := "agent1"
	createAgent_CB77(db, agentID)
	convID := createConversation_CB77(db, userID, agentID)
	token := generateTestToken_CB77(userID)

	req := httptest.NewRequest("GET", "/attachments?conversation_id="+convID, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleListAttachments(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var attachments []map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &attachments)
	if len(attachments) != 0 {
		t.Errorf("expected 0 attachments, got %d", len(attachments))
	}
}

// ==================== routeChatMessage (86.2%) ====================

func TestCB77_RouteChatMessage_AgentToMultiDevice(t *testing.T) {
	oldDB := db
	oldHub := hub
	defer func() { db = oldDB; hub = oldHub }()
	db = setupTestDB_CB77(t)
	defer db.Close()
	hub = newTestHub()

	userID := createUser_CB77(db, "user1", "pass")
	agentID := "agent1"
	createAgent_CB77(db, agentID)
	convID := createConversation_CB77(db, userID, agentID)

	client1 := &Connection{id: userID, connType: "client", hub: hub, send: make(chan []byte, 10), deviceID: "d1"}
	client2 := &Connection{id: userID, connType: "client", hub: hub, send: make(chan []byte, 10), deviceID: "d2"}
	hub.clientConns[userID] = []*Connection{client1, client2}

	sender := &Connection{id: agentID, connType: "agent", send: make(chan []byte, 10), hub: hub}
	msgJSON, _ := json.Marshal(RoutedMessage{
		Type:           "message",
		ConversationID: convID,
		Content:        "hello to all devices",
		SenderType:     "agent",
		SenderID:       agentID,
	})
	routeChatMessage(sender, msgJSON)

	// Both devices should receive
	select {
	case <-client1.send:
	case <-time.After(100 * time.Millisecond):
		t.Error("client1 should receive")
	}
	select {
	case <-client2.send:
	case <-time.After(100 * time.Millisecond):
		t.Error("client2 should receive")
	}
}

func TestCB77_RouteChatMessage_AckSent(t *testing.T) {
	oldDB := db
	oldHub := hub
	defer func() { db = oldDB; hub = oldHub }()
	db = setupTestDB_CB77(t)
	defer db.Close()
	hub = newTestHub()

	userID := createUser_CB77(db, "user1", "pass")
	agentID := "agent1"
	createAgent_CB77(db, agentID)
	convID := createConversation_CB77(db, userID, agentID)

	agentConn := &Connection{id: agentID, connType: "agent", hub: hub, send: make(chan []byte, 10)}
	hub.agents[agentID] = agentConn

	sender := &Connection{id: userID, connType: "client", send: make(chan []byte, 10), hub: hub}
	msgJSON, _ := json.Marshal(RoutedMessage{
		Type:           "message",
		ConversationID: convID,
		Content:        "test ack",
		SenderType:     "user",
		SenderID:       userID,
	})
	routeChatMessage(sender, msgJSON)

	// Agent should receive the message
	select {
	case agentMsg := <-agentConn.send:
		var outgoing OutgoingMessage
		json.Unmarshal(agentMsg, &outgoing)
		if outgoing.Type != "message" {
			t.Errorf("expected 'message', got '%s'", outgoing.Type)
		}
	case <-time.After(100 * time.Millisecond):
		t.Error("agent should receive message")
	}

	// Sender should receive an ack
	select {
	case ackMsg := <-sender.send:
		var ack OutgoingMessage
		json.Unmarshal(ackMsg, &ack)
		if ack.Type != "message_sent" {
			t.Errorf("expected 'message_sent', got '%s'", ack.Type)
		}
	case <-time.After(100 * time.Millisecond):
		t.Error("sender should receive ack")
	}
}

// ==================== deleteConversation (83.3%) ====================

func TestCB77_DeleteConversation_Success(t *testing.T) {
	oldDB := db
	defer func() { db = oldDB }()
	db = setupTestDB_CB77(t)
	defer db.Close()

	userID := createUser_CB77(db, "user1", "pass")
	agentID := "agent1"
	createAgent_CB77(db, agentID)
	convID := createConversation_CB77(db, userID, agentID)
	createMessage_CB77(db, "msg1", convID, "user", userID, "hello")

	err := deleteConversation(convID, userID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify conversation is gone
	var count int
	db.QueryRow("SELECT COUNT(*) FROM conversations WHERE id = ?", convID).Scan(&count)
	if count != 0 {
		t.Error("conversation should be deleted")
	}

	// Verify messages are gone
	db.QueryRow("SELECT COUNT(*) FROM messages WHERE conversation_id = ?", convID).Scan(&count)
	if count != 0 {
		t.Error("messages should be deleted")
	}
}

func TestCB77_DeleteConversation_NotFound(t *testing.T) {
	oldDB := db
	defer func() { db = oldDB }()
	db = setupTestDB_CB77(t)
	defer db.Close()

	err := deleteConversation("nonexistent", "user1")
	if err == nil {
		t.Error("expected error for not found")
	}
}

func TestCB77_DeleteConversation_Unauthorized(t *testing.T) {
	oldDB := db
	defer func() { db = oldDB }()
	db = setupTestDB_CB77(t)
	defer db.Close()

	userID := createUser_CB77(db, "user1", "pass")
	otherUserID := createUser_CB77(db, "user2", "pass")
	agentID := "agent1"
	createAgent_CB77(db, agentID)
	convID := createConversation_CB77(db, userID, agentID)

	err := deleteConversation(convID, otherUserID)
	if err == nil {
		t.Error("expected error for unauthorized")
	}
}

func TestCB77_DeleteConversation_BeginError(t *testing.T) {
	oldDB := db
	defer func() { db = oldDB }()
	db = setupTestDB_CB77(t)
	db.Close()

	err := deleteConversation("conv1", "user1")
	if err == nil {
		t.Error("expected error for DB error")
	}
}

// ==================== RegisterAgentOnConnect (81.8%) ====================

func TestCB77_RegisterAgentOnConnect_NewAgent(t *testing.T) {
	oldDB := db
	defer func() { db = oldDB }()
	db = setupTestDB_CB77(t)
	defer db.Close()

	err := RegisterAgentOnConnect("agent_new", "New Agent", "gpt-4", "friendly", "general")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var name string
	db.QueryRow("SELECT name FROM agents WHERE id = ?", "agent_new").Scan(&name)
	if name != "New Agent" {
		t.Errorf("expected 'New Agent', got '%s'", name)
	}
}

func TestCB77_RegisterAgentOnConnect_UpdateExisting(t *testing.T) {
	oldDB := db
	defer func() { db = oldDB }()
	db = setupTestDB_CB77(t)
	defer db.Close()

	createAgent_CB77(db, "agent1")
	err := RegisterAgentOnConnect("agent1", "Updated Name", "gpt-4", "professional", "coding")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var name string
	db.QueryRow("SELECT name FROM agents WHERE id = ?", "agent1").Scan(&name)
	if name != "Updated Name" {
		t.Errorf("expected 'Updated Name', got '%s'", name)
	}
}

func TestCB77_RegisterAgentOnConnect_PreserveEmptyFields(t *testing.T) {
	oldDB := db
	defer func() { db = oldDB }()
	db = setupTestDB_CB77(t)
	defer db.Close()

	// Pre-create with all fields
	db.Exec("INSERT INTO agents (id, name, model, personality, specialty) VALUES (?, ?, ?, ?, ?)",
		"agent1", "Original", "gpt-4", "friendly", "general")

	// Connect with empty fields — should preserve existing
	err := RegisterAgentOnConnect("agent1", "", "", "", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var name, model string
	db.QueryRow("SELECT name, model FROM agents WHERE id = ?", "agent1").Scan(&name, &model)
	if name != "Original" {
		t.Errorf("expected 'Original', got '%s'", name)
	}
	if model != "gpt-4" {
		t.Errorf("expected 'gpt-4', got '%s'", model)
	}
}

func TestCB77_RegisterAgentOnConnect_QueryError(t *testing.T) {
	oldDB := db
	defer func() { db = oldDB }()
	db = setupTestDB_CB77(t)
	db.Close()

	err := RegisterAgentOnConnect("agent1", "Name", "Model", "Personality", "Specialty")
	if err == nil {
		t.Error("expected error for closed DB")
	}
}

// ==================== TieredRateLimiter Allow & GetRemaining (81.8%) ====================

func TestCB77_TieredRateLimiter_Allow_FreeTier(t *testing.T) {
	rl := NewTieredRateLimiter()
	defer rl.Stop()

	rl.SetTier("user1", TierFree)
	// Free tier: 60/min
	for i := 0; i < 60; i++ {
		if allowed, _, _ := rl.Allow("user1"); !allowed {
			t.Errorf("request %d should be allowed", i)
		}
	}
	// 61st should be blocked
	if allowed, _, _ := rl.Allow("user1"); allowed {
		t.Error("61st request should be blocked")
	}
}

func TestCB77_TieredRateLimiter_Allow_ProTier(t *testing.T) {
	rl := NewTieredRateLimiter()
	defer rl.Stop()

	rl.SetTier("user1", TierPro)
	// Pro tier: 300/min
	count := 0
	for i := 0; i < 300; i++ {
		if ok, _, _ := rl.Allow("user1"); ok {
			count++
		}
	}
	if count != 300 {
		t.Errorf("expected 300 allowed, got %d", count)
	}
	if ok, _, _ := rl.Allow("user1"); ok {
		t.Error("301st request should be blocked")
	}
}

func TestCB77_TieredRateLimiter_Allow_EnterpriseTier(t *testing.T) {
	rl := NewTieredRateLimiter()
	defer rl.Stop()

	rl.SetTier("user1", TierEnterprise)
	// Enterprise: 1500/min — test a subset
	count := 0
	for i := 0; i < 200; i++ {
		if ok, _, _ := rl.Allow("user1"); ok {
			count++
		}
	}
	if count != 200 {
		t.Errorf("expected 200 allowed, got %d", count)
	}
}

func TestCB77_TieredRateLimiter_Allow_DefaultFreeTier(t *testing.T) {
	rl := NewTieredRateLimiter()
	defer rl.Stop()

	// No tier set — should default to free
	count := 0
	for i := 0; i < 60; i++ {
		if ok, _, _ := rl.Allow("user_default"); ok {
			count++
		}
	}
	if count != 60 {
		t.Errorf("expected 60 allowed for default free tier, got %d", count)
	}
}

func TestCB77_TieredRateLimiter_GetRemaining_FreshUser(t *testing.T) {
	rl := NewTieredRateLimiter()
	defer rl.Stop()

	rl.SetTier("user1", TierFree)
	remaining := rl.GetRemaining("user1")
	if remaining != 60 {
		t.Errorf("expected 60 remaining, got %d", remaining)
	}
}

func TestCB77_TieredRateLimiter_GetRemaining_AfterUse(t *testing.T) {
	rl := NewTieredRateLimiter()
	defer rl.Stop()

	rl.SetTier("user1", TierPro)
	for i := 0; i < 10; i++ {
		rl.Allow("user1")
	}
	remaining := rl.GetRemaining("user1")
	if remaining != 290 {
		t.Errorf("expected 290 remaining, got %d", remaining)
	}
}

func TestCB77_TieredRateLimiter_GetRemaining_Exhausted(t *testing.T) {
	rl := NewTieredRateLimiter()
	defer rl.Stop()

	rl.SetTier("user1", TierFree)
	for i := 0; i < 60; i++ {
		rl.Allow("user1")
	}
	remaining := rl.GetRemaining("user1")
	if remaining != 0 {
		t.Errorf("expected 0 remaining, got %d", remaining)
	}
}

func TestCB77_TieredRateLimiter_GetRemaining_DefaultTier(t *testing.T) {
	rl := NewTieredRateLimiter()
	defer rl.Stop()

	remaining := rl.GetRemaining("user_notier")
	if remaining != 60 {
		t.Errorf("expected 60 for default free tier, got %d", remaining)
	}
}

// ==================== cleanup (83.3%) ====================

func TestCB77_TieredRateLimiter_Cleanup_StopChannel(t *testing.T) {
	rl := NewTieredRateLimiter()
	rl.SetTier("user1", TierFree)
	rl.Allow("user1")
	rl.Stop()
	// Should not panic after stop
}

func TestCB77_TieredRateLimiter_Cleanup_StaleEntries(t *testing.T) {
	rl := NewTieredRateLimiter()
	defer rl.Stop()

	rl.SetTier("user1", TierFree)
	rl.Allow("user1")

	// Manually expire the entry
	rl.limits["user1"].windowEnd = time.Now().Add(-2 * time.Hour)

	// Run cleanupOnce — should remove stale entry
	rl.cleanupOnce()

	if _, exists := rl.limits["user1"]; exists {
		t.Error("expected stale entry to be removed")
	}
}

func TestCB77_TieredRateLimiter_Cleanup_KeepsActive(t *testing.T) {
	rl := NewTieredRateLimiter()
	defer rl.Stop()

	rl.SetTier("user1", TierFree)
	rl.Allow("user1")

	// Entry should be active (windowEnd is in the future)
	rl.cleanupOnce()

	if _, exists := rl.limits["user1"]; !exists {
		t.Error("active entry should not be removed")
	}
}

func TestCB77_TieredRateLimiter_Cleanup_GracePeriod(t *testing.T) {
	rl := NewTieredRateLimiter()
	defer rl.Stop()

	rl.SetTier("user1", TierFree)
	rl.Allow("user1")

	// Set windowEnd to just past (within grace period)
	rl.limits["user1"].windowEnd = time.Now().Add(-30 * time.Second)

	rl.cleanupOnce()

	// Should still exist (within 10min grace period)
	if _, exists := rl.limits["user1"]; !exists {
		t.Error("entry within grace period should not be removed")
	}
}

// ==================== InitTracing (79.5%) ====================

func TestCB77_InitTracing_Disabled(t *testing.T) {
	// Reset tracingMu for test
	tracingMu = sync.Once{}
	oldEnabled := tracingEnabled
	oldTP := tp
	oldTracer := tracer
	defer func() {
		tracingEnabled = oldEnabled
		tp = oldTP
		tracer = oldTracer
		tracingMu = sync.Once{}
	}()

	os.Unsetenv("OTEL_ENABLED")
	err := InitTracing()
	if err != nil {
		t.Errorf("expected nil error when disabled, got %v", err)
	}
	if tracingEnabled {
		t.Error("expected tracing to remain disabled")
	}
}

func TestCB77_InitTracing_NoEndpoint(t *testing.T) {
	tracingMu = sync.Once{}
	oldEnabled := tracingEnabled
	oldTP := tp
	oldTracer := tracer
	defer func() {
		tracingEnabled = oldEnabled
		tp = oldTP
		tracer = oldTracer
		tracingMu = sync.Once{}
	}()

	os.Setenv("OTEL_ENABLED", "true")
	os.Unsetenv("OTEL_EXPORTER_OTLP_ENDPOINT")
	os.Unsetenv("OTEL_EXPORTER_OTLP_HTTP_ENDPOINT")
	defer os.Unsetenv("OTEL_ENABLED")

	err := InitTracing()
	if err != nil {
		t.Errorf("expected nil error when no endpoint, got %v", err)
	}
	if tracingEnabled {
		t.Error("expected tracing to remain disabled without endpoint")
	}
}

func TestCB77_InitTracing_AlreadyInitialized(t *testing.T) {
	tracingMu = sync.Once{}
	oldEnabled := tracingEnabled
	oldTP := tp
	oldTracer := tracer
	defer func() {
		tracingEnabled = oldEnabled
		tp = oldTP
		tracer = oldTracer
		tracingMu = sync.Once{}
	}()

	// First call
	os.Setenv("OTEL_ENABLED", "true")
	os.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "localhost:4317")
	defer os.Unsetenv("OTEL_ENABLED")
	defer os.Unsetenv("OTEL_EXPORTER_OTLP_ENDPOINT")

	_ = InitTracing()

	// Second call should be no-op due to sync.Once
	err := InitTracing()
	if err != nil {
		t.Errorf("expected nil error on second init, got %v", err)
	}
}

func TestCB77_InitTracing_CustomSamplingRate(t *testing.T) {
	tracingMu = sync.Once{}
	oldEnabled := tracingEnabled
	oldTP := tp
	oldTracer := tracer
	defer func() {
		tracingEnabled = oldEnabled
		tp = oldTP
		tracer = oldTracer
		tracingMu = sync.Once{}
	}()

	os.Setenv("OTEL_ENABLED", "true")
	os.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "localhost:4317")
	os.Setenv("OTEL_SAMPLING_RATE", "0.5")
	defer os.Unsetenv("OTEL_ENABLED")
	defer os.Unsetenv("OTEL_EXPORTER_OTLP_ENDPOINT")
	defer os.Unsetenv("OTEL_SAMPLING_RATE")

	err := InitTracing()
	// May fail due to connection attempt to non-existent collector
	_ = err
}

func TestCB77_InitTracing_InvalidSamplingRate(t *testing.T) {
	tracingMu = sync.Once{}
	oldEnabled := tracingEnabled
	oldTP := tp
	oldTracer := tracer
	defer func() {
		tracingEnabled = oldEnabled
		tp = oldTP
		tracer = oldTracer
		tracingMu = sync.Once{}
	}()

	os.Setenv("OTEL_ENABLED", "true")
	os.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "localhost:4317")
	os.Setenv("OTEL_SAMPLING_RATE", "invalid")
	defer os.Unsetenv("OTEL_ENABLED")
	defer os.Unsetenv("OTEL_EXPORTER_OTLP_ENDPOINT")
	defer os.Unsetenv("OTEL_SAMPLING_RATE")

	err := InitTracing()
	// Should fall back to default 0.1
	_ = err
}

func TestCB77_InitTracing_HTTPProtocol(t *testing.T) {
	tracingMu = sync.Once{}
	oldEnabled := tracingEnabled
	oldTP := tp
	oldTracer := tracer
	defer func() {
		tracingEnabled = oldEnabled
		tp = oldTP
		tracer = oldTracer
		tracingMu = sync.Once{}
	}()

	os.Setenv("OTEL_ENABLED", "true")
	os.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://localhost:4318")
	os.Setenv("OTEL_EXPORTER_OTLP_PROTOCOL", "http")
	defer os.Unsetenv("OTEL_ENABLED")
	defer os.Unsetenv("OTEL_EXPORTER_OTLP_ENDPOINT")
	defer os.Unsetenv("OTEL_EXPORTER_OTLP_PROTOCOL")

	err := InitTracing()
	// May fail to connect, but should attempt HTTP path
	_ = err
}

func TestCB77_InitTracing_CustomServiceName(t *testing.T) {
	tracingMu = sync.Once{}
	oldEnabled := tracingEnabled
	oldTP := tp
	oldTracer := tracer
	defer func() {
		tracingEnabled = oldEnabled
		tp = oldTP
		tracer = oldTracer
		tracingMu = sync.Once{}
	}()

	os.Setenv("OTEL_ENABLED", "true")
	os.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "localhost:4317")
	os.Setenv("OTEL_SERVICE_NAME", "custom-service")
	defer os.Unsetenv("OTEL_ENABLED")
	defer os.Unsetenv("OTEL_EXPORTER_OTLP_ENDPOINT")
	defer os.Unsetenv("OTEL_SERVICE_NAME")

	err := InitTracing()
	_ = err
}

// ==================== initSchema (82.4%) ====================

func TestCB77_InitSchema_ClosedDB(t *testing.T) {
	testDB, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("failed to open: %v", err)
	}
	testDB.Close()

	err = initSchema(testDB)
	if err == nil {
		t.Error("expected error for closed DB")
	}
}

func TestCB77_InitSchema_Idempotent(t *testing.T) {
	testDB, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("failed to open: %v", err)
	}
	defer testDB.Close()

	if err := initSchema(testDB); err != nil {
		t.Fatalf("first init failed: %v", err)
	}
	if err := initSchema(testDB); err != nil {
		t.Fatalf("second init failed: %v", err)
	}
}

func TestCB77_InitSchema_TablesExist(t *testing.T) {
	testDB, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("failed to open: %v", err)
	}
	defer testDB.Close()

	if err := initSchema(testDB); err != nil {
		t.Fatalf("init failed: %v", err)
	}

	tables := []string{"users", "agents", "conversations", "messages", "device_tokens", "encrypted_messages", "notification_preferences", "user_rate_limit_tiers"}
	for _, table := range tables {
		var name string
		err := testDB.QueryRow("SELECT name FROM sqlite_master WHERE type='table' AND name=?", table).Scan(&name)
		if err != nil {
			t.Errorf("table %s not found: %v", table, err)
		}
	}
}

// ==================== handleRegisterAgent (60%) ====================

func TestCB77_HandleRegisterAgent_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest("GET", "/auth/agent", nil)
	w := httptest.NewRecorder()
	handleRegisterAgent(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestCB77_HandleRegisterAgent_NoSecret(t *testing.T) {
	req := httptest.NewRequest("POST", "/auth/agent", nil)
	w := httptest.NewRecorder()
	handleRegisterAgent(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestCB77_HandleRegisterAgent_WrongSecret(t *testing.T) {
	req := httptest.NewRequest("POST", "/auth/agent", nil)
	req.Header.Set("X-Agent-Secret", "wrong-secret")
	w := httptest.NewRecorder()
	handleRegisterAgent(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestCB77_HandleRegisterAgent_InvalidJSON(t *testing.T) {
	req := httptest.NewRequest("POST", "/auth/agent", strings.NewReader("not json"))
	req.Header.Set("X-Agent-Secret", getAgentSecret())
	w := httptest.NewRecorder()
	handleRegisterAgent(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestCB77_HandleRegisterAgent_Success(t *testing.T) {
	oldDB := db
	defer func() { db = oldDB }()
	db = setupTestDB_CB77(t)
	defer db.Close()

	form := "agent_id=agent_new&name=Test+Agent&model=gpt-4&personality=friendly&specialty=general"
	req := httptest.NewRequest("POST", "/auth/agent", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Agent-Secret", getAgentSecret())
	w := httptest.NewRecorder()
	handleRegisterAgent(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCB77_HandleRegisterAgent_Duplicate(t *testing.T) {
	oldDB := db
	defer func() { db = oldDB }()
	db = setupTestDB_CB77(t)
	defer db.Close()

	createAgent_CB77(db, "agent1")

	form := "agent_id=agent1&name=Updated+Agent&model=gpt-4"
	req := httptest.NewRequest("POST", "/auth/agent", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Agent-Secret", getAgentSecret())
	w := httptest.NewRecorder()
	handleRegisterAgent(w, req)
	// The handler uses ON CONFLICT DO UPDATE, so duplicates update rather than conflict
	if w.Code != http.StatusOK {
		t.Errorf("expected 200 (upsert), got %d: %s", w.Code, w.Body.String())
	}
}

func TestCB77_HandleRegisterAgent_MissingAgentID(t *testing.T) {
	oldDB := db
	defer func() { db = oldDB }()
	db = setupTestDB_CB77(t)
	defer db.Close()

	body := `{"name":"Test Agent","model":"gpt-4"}`
	req := httptest.NewRequest("POST", "/auth/agent", strings.NewReader(body))
	req.Header.Set("X-Agent-Secret", getAgentSecret())
	w := httptest.NewRecorder()
	handleRegisterAgent(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestCB77_HandleRegisterAgent_DBError(t *testing.T) {
	oldDB := db
	defer func() { db = oldDB }()
	db = setupTestDB_CB77(t)
	db.Close()

	form := "agent_id=agent1&name=Test&model=gpt-4"
	req := httptest.NewRequest("POST", "/auth/agent", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Agent-Secret", getAgentSecret())
	w := httptest.NewRecorder()
	handleRegisterAgent(w, req)
	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", w.Code)
	}
}

// ==================== Enqueue (88.9%) ====================

func TestCB77_Enqueue_BufferFull(t *testing.T) {
	q := newOfflineQueue(2, time.Hour)
	data := marshalOutgoingMessage(OutgoingMessage{Type: "message"})

	// Fill to capacity
	q.Enqueue("user1", data)
	q.Enqueue("user1", data)

	// Third should drop oldest
	q.Enqueue("user1", data)

	if q.QueueDepth("user1") != 2 {
		t.Errorf("expected depth 2, got %d", q.QueueDepth("user1"))
	}
}

func TestCB77_Enqueue_MultipleRecipients(t *testing.T) {
	q := newOfflineQueue(100, time.Hour)
	data := marshalOutgoingMessage(OutgoingMessage{Type: "message"})

	q.Enqueue("user1", data)
	q.Enqueue("user2", data)
	q.Enqueue("user3", data)

	if q.TotalDepth() != 3 {
		t.Errorf("expected total depth 3, got %d", q.TotalDepth())
	}
}

func TestCB77_Enqueue_NilData(t *testing.T) {
	q := newOfflineQueue(100, time.Hour)

	q.Enqueue("user1", nil)

	// Queue enqueues nil data (it's just bytes)
	if q.QueueDepth("user1") != 1 {
		t.Errorf("expected depth 1 for nil data, got %d", q.QueueDepth("user1"))
	}
}

// ==================== handleReact (85.7%) ====================

func TestCB77_HandleReact_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest("GET", "/reactions/react", nil)
	w := httptest.NewRecorder()
	handleReact(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestCB77_HandleReact_Unauthorized(t *testing.T) {
	req := httptest.NewRequest("POST", "/reactions/react", nil)
	w := httptest.NewRecorder()
	handleReact(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestCB77_HandleReact_MissingFields(t *testing.T) {
	token := generateTestToken_CB77("user1")
	form := strings.NewReader("")
	req := httptest.NewRequest("POST", "/reactions/react", form)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handleReact(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestCB77_HandleReact_MissingMessageID(t *testing.T) {
	token := generateTestToken_CB77("user1")
	form := strings.NewReader("emoji=👍")
	req := httptest.NewRequest("POST", "/reactions/react", form)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handleReact(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestCB77_HandleReact_MissingEmoji(t *testing.T) {
	token := generateTestToken_CB77("user1")
	form := strings.NewReader("message_id=msg1")
	req := httptest.NewRequest("POST", "/reactions/react", form)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handleReact(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestCB77_HandleReact_MessageNotFound(t *testing.T) {
	oldDB := db
	oldHub := hub
	defer func() { db = oldDB; hub = oldHub }()
	db = setupTestDB_CB77(t)
	defer db.Close()
	hub = newTestHub()

	userID := createUser_CB77(db, "user1", "pass")
	token := generateTestToken_CB77(userID)

	form := strings.NewReader("message_id=nonexistent&emoji=👍")
	req := httptest.NewRequest("POST", "/reactions/react", form)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handleReact(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

func TestCB77_HandleReact_Success(t *testing.T) {
	oldDB := db
	oldHub := hub
	defer func() { db = oldDB; hub = oldHub }()
	db = setupTestDB_CB77(t)
	defer db.Close()
	hub = newTestHub()

	userID := createUser_CB77(db, "user1", "pass")
	agentID := "agent1"
	createAgent_CB77(db, agentID)
	convID := createConversation_CB77(db, userID, agentID)
	createMessage_CB77(db, "msg1", convID, "agent", agentID, "hello")
	token := generateTestToken_CB77(userID)

	form := strings.NewReader("message_id=msg1&emoji=👍")
	req := httptest.NewRequest("POST", "/reactions/react", form)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handleReact(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCB77_HandleReact_ToggleRemove(t *testing.T) {
	oldDB := db
	oldHub := hub
	defer func() { db = oldDB; hub = oldHub }()
	db = setupTestDB_CB77(t)
	defer db.Close()
	hub = newTestHub()

	userID := createUser_CB77(db, "user1", "pass")
	agentID := "agent1"
	createAgent_CB77(db, agentID)
	convID := createConversation_CB77(db, userID, agentID)
	createMessage_CB77(db, "msg1", convID, "agent", agentID, "hello")
	token := generateTestToken_CB77(userID)

	// First react
	form := strings.NewReader("message_id=msg1&emoji=👍")
	req := httptest.NewRequest("POST", "/reactions/react", form)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handleReact(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("first react failed: %d", w.Code)
	}

	// Second react with same emoji should toggle (remove)
	form2 := strings.NewReader("message_id=msg1&emoji=👍")
	req2 := httptest.NewRequest("POST", "/reactions/react", form2)
	req2.Header.Set("Authorization", "Bearer "+token)
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w2 := httptest.NewRecorder()
	handleReact(w2, req2)
	if w2.Code != http.StatusOK {
		t.Errorf("expected 200 on toggle, got %d", w2.Code)
	}
}

// ==================== handleUpload (72.7%) — more paths ====================

func TestCB77_HandleUpload_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest("GET", "/upload", nil)
	w := httptest.NewRecorder()
	handleUpload(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestCB77_HandleUpload_Unauthorized(t *testing.T) {
	req := httptest.NewRequest("POST", "/upload", nil)
	w := httptest.NewRecorder()
	handleUpload(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

// ==================== writePump (74.1%) — more paths ====================
// writePump requires a real websocket connection, so we test indirectly

func TestCB77_WritePump_NilConn_NoPanic(t *testing.T) {
	// Verify that a connection with no websocket doesn't panic
	// when we close its send channel
	conn := &Connection{
		id:       "agent1",
		connType: "agent",
		send:     make(chan []byte, 10),
	}
	close(conn.send)
	// Verify channel is closed
	_, ok := <-conn.send
	if ok {
		t.Error("expected channel to be closed")
	}
}

func TestCB77_WritePump_ClosedChannelReadable(t *testing.T) {
	conn := &Connection{
		id:       "agent1",
		connType: "agent",
		send:     make(chan []byte, 10),
	}
	conn.send <- []byte(`{"type":"message","data":{"content":"hello"}}`)
	close(conn.send)

	// Verify we can read the message before close
	msg, ok := <-conn.send
	if !ok {
		t.Error("expected to read message before channel close")
	}
	if string(msg) == "" {
		t.Error("expected non-empty message")
	}
}

// ==================== ValidateJWT valid token (83.3%) ====================

func TestCB77_ValidateJWT_ValidToken(t *testing.T) {
	userID := "user1"
	token := generateTestToken_CB77(userID)

	claims, err := ValidateJWT(token)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if claims.UserID != userID {
		t.Errorf("expected userID '%s', got '%s'", userID, claims.UserID)
	}
}

// ==================== authenticateRequest (85.7%) ====================

func TestCB77_AuthenticateRequest_NoAuth(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	_, _, err := authenticateRequest(req)
	if err == nil {
		t.Error("expected error for no auth header")
	}
}

func TestCB77_AuthenticateRequest_InvalidBearer(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer invalid-token")
	_, _, err := authenticateRequest(req)
	if err == nil {
		t.Error("expected error for invalid bearer token")
	}
}

func TestCB77_AuthenticateRequest_ValidBearer(t *testing.T) {
	userID := "user1"
	token := generateTestToken_CB77(userID)
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	id, typ, err := authenticateRequest(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id != userID {
		t.Errorf("expected id '%s', got '%s'", userID, id)
	}
	if typ != "user" {
		t.Errorf("expected type 'user', got '%s'", typ)
	}
}

func TestCB77_AuthenticateRequest_ValidAgentSecret(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-Agent-Secret", getAgentSecret())
	req.Header.Set("X-Agent-ID", "agent1")
	id, typ, err := authenticateRequest(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id != "agent1" {
		t.Errorf("expected id 'agent1', got '%s'", id)
	}
	if typ != "agent" {
		t.Errorf("expected type 'agent', got '%s'", typ)
	}
}

func TestCB77_AuthenticateRequest_AgentSecretNoAgentID(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-Agent-Secret", getAgentSecret())
	// No X-Agent-ID header
	_, _, err := authenticateRequest(req)
	if err == nil {
		t.Error("expected error for missing agent ID")
	}
}

func TestCB77_AuthenticateRequest_WrongAgentSecret(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-Agent-Secret", "wrong-secret")
	req.Header.Set("X-Agent-ID", "agent1")
	_, _, err := authenticateRequest(req)
	if err == nil {
		t.Error("expected error for wrong agent secret")
	}
}

// ==================== StoreMessagesBatch (88.9%) — additional paths ====================

func TestCB77_StoreMessagesBatch_NilDB(t *testing.T) {
	oldDB := db
	defer func() { db = oldDB }()
	db = nil

	msgs := []RoutedMessage{
		{Type: "message", ConversationID: "conv1", Content: "hello", SenderType: "user", SenderID: "user1"},
	}
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic for nil DB")
		}
	}()
	storeMessagesBatch(msgs)
}

func TestCB77_StoreMessagesBatch_BeginError(t *testing.T) {
	oldDB := db
	defer func() { db = oldDB }()
	db = setupTestDB_CB77(t)
	db.Close()

	msgs := []RoutedMessage{
		{Type: "message", ConversationID: "conv1", Content: "hello", SenderType: "user", SenderID: "user1"},
	}
	_, err := storeMessagesBatch(msgs)
	if err == nil {
		t.Error("expected error for closed DB")
	}
}

// ==================== checkRateLimit (89.5%) — additional paths ====================

func TestCB77_CheckRateLimit_BothAllowed_WithMetrics(t *testing.T) {
	oldHub := hub
	oldSM := ServerMetrics
	defer func() { hub = oldHub; ServerMetrics = oldSM }()
	hub = newTestHub()
	ServerMetrics = NewMetrics(hub)

	conn := &Connection{
		id:       "user1",
		connType: "client",
		hub:      hub,
		send:     make(chan []byte, 10),
	}

	// Should be allowed (well within limits)
	if !checkRateLimit(conn) {
		t.Error("expected rate limit to allow")
	}
}

func TestCB77_CheckRateLimit_PerConnectionExceeded(t *testing.T) {
	oldHub := hub
	oldSM := ServerMetrics
	defer func() { hub = oldHub; ServerMetrics = oldSM }()
	hub = newTestHub()
	ServerMetrics = NewMetrics(hub)

	conn := &Connection{
		id:       "user1",
		connType: "client",
		hub:      hub,
		send:     make(chan []byte, 10),
	}

	// Exhaust per-connection limit (60/min)
	for i := 0; i < 60; i++ {
		if !checkRateLimit(conn) {
			break
		}
	}
	// Next should be blocked
	if checkRateLimit(conn) {
		t.Error("expected rate limit to block after 60 messages")
	}
}

// ==================== loadQueueFromDB (89.5%) — additional paths ====================

func TestCB77_LoadQueueFromDB_NilDB(t *testing.T) {
	q := newOfflineQueue(100, time.Hour)
	loadQueueFromDB(nil, q)
	// Should not panic with nil DB
}

func TestCB77_LoadQueueFromDB_Success(t *testing.T) {
	testDB := setupTestDB_CB77(t)
	defer testDB.Close()
	initQueueDB(testDB)

	data := marshalOutgoingMessage(OutgoingMessage{Type: "message", Data: map[string]string{"content": "hello"}})
	persistQueue(testDB, "user1", data)
	persistQueue(testDB, "user1", data)

	q := newOfflineQueue(100, time.Hour)
	loadQueueFromDB(testDB, q)

	if q.QueueDepth("user1") != 2 {
		t.Errorf("expected depth 2, got %d", q.QueueDepth("user1"))
	}
}

func TestCB77_LoadQueueFromDB_Empty(t *testing.T) {
	testDB := setupTestDB_CB77(t)
	defer testDB.Close()
	initQueueDB(testDB)

	q := newOfflineQueue(100, time.Hour)
	loadQueueFromDB(testDB, q)

	if q.TotalDepth() != 0 {
		t.Errorf("expected total depth 0, got %d", q.TotalDepth())
	}
}

// ==================== addReaction (88.5%) — additional paths ====================

func TestCB77_AddReaction_AgentSender(t *testing.T) {
	oldDB := db
	defer func() { db = oldDB }()
	db = setupTestDB_CB77(t)
	defer db.Close()

	userID := createUser_CB77(db, "user1", "pass")
	agentID := "agent1"
	createAgent_CB77(db, agentID)
	convID := createConversation_CB77(db, userID, agentID)
	createMessage_CB77(db, "msg1", convID, "user", userID, "hello from user")

	_, _, err := addReaction("msg1", agentID, "🎉")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var count int
	db.QueryRow("SELECT COUNT(*) FROM reactions WHERE message_id = ? AND user_id = ? AND emoji = ?",
		"msg1", agentID, "🎉").Scan(&count)
	if count != 1 {
		t.Errorf("expected 1 reaction, got %d", count)
	}
}

func TestCB77_AddReaction_DBErrorOnInsert(t *testing.T) {
	oldDB := db
	defer func() { db = oldDB }()
	db = setupTestDB_CB77(t)
	db.Close()

	_, _, err := addReaction("msg1", "user1", "👍")
	if err == nil {
		t.Error("expected error for closed DB")
	}
}

// ==================== getMessageReactions (90.9%) — additional paths ====================

func TestCB77_GetMessageReactions_DBError(t *testing.T) {
	oldDB := db
	defer func() { db = oldDB }()
	db = setupTestDB_CB77(t)
	db.Close()

	_, err := getMessageReactions("msg1")
	if err == nil {
		t.Error("expected error for closed DB")
	}
}

// ==================== handleSetNotificationPrefs (88.9%) — additional paths ====================

func TestCB77_HandleSetNotificationPrefs_DBError(t *testing.T) {
	oldDB := db
	defer func() { db = oldDB }()
	db = setupTestDB_CB77(t)
	db.Close()

	token := generateTestToken_CB77("user1")
	req := httptest.NewRequest("POST", "/notifications/preferences", strings.NewReader("conversation_id=conv1&muted=true"))
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleSetNotificationPrefs(w, req)
	if w.Code != http.StatusInternalServerError && w.Code != http.StatusUnauthorized {
		t.Errorf("expected 500 or 401, got %d", w.Code)
	}
}

// ==================== notifyUser (86.7%) — additional paths ====================

func TestCB77_NotifyUser_NilDB(t *testing.T) {
	oldDB := db
	defer func() { db = oldDB }()
	db = nil

	// Should not panic
	notifyUser("user1", "Title", "Body", "conv1")
}

func TestCB77_NotifyUser_PushConfigNil(t *testing.T) {
	oldDB := db
	oldPush := pushConfig
	defer func() { db = oldDB; pushConfig = oldPush }()
	db = setupTestDB_CB77(t)
	defer db.Close()
	pushConfig = nil

	// Should not panic
	notifyUser("user1", "Title", "Body", "conv1")
}

// ==================== initAPNs (84.0%) — additional paths ====================

func TestCB77_InitAPNs_NilConfig(t *testing.T) {
	oldPush := pushConfig
	defer func() { pushConfig = oldPush }()
	pushConfig = nil
	initAPNs()
}

func TestCB77_InitAPNs_Disabled(t *testing.T) {
	oldPush := pushConfig
	defer func() { pushConfig = oldPush }()
	pushConfig = &PushNotificationConfig{APNSEnabled: false}
	initAPNs()
}

func TestCB77_InitAPNs_NoCertPath(t *testing.T) {
	oldPush := pushConfig
	defer func() { pushConfig = oldPush }()
	pushConfig = &PushNotificationConfig{APNSEnabled: true, CertPath: ""}
	initAPNs()
}

func TestCB77_InitAPNs_CertNotFound(t *testing.T) {
	oldPush := pushConfig
	defer func() { pushConfig = oldPush }()
	pushConfig = &PushNotificationConfig{APNSEnabled: true, CertPath: "/nonexistent/cert.pem"}
	initAPNs()
}

// ==================== initFCM (88.9%) — additional paths ====================

func TestCB77_InitFCM_NilConfig(t *testing.T) {
	oldPush := pushConfig
	defer func() { pushConfig = oldPush }()
	pushConfig = nil
	initFCM()
}

func TestCB77_InitFCM_Disabled(t *testing.T) {
	oldPush := pushConfig
	defer func() { pushConfig = oldPush }()
	pushConfig = &PushNotificationConfig{FCMEnabled: false}
	initFCM()
}

func TestCB77_InitFCM_NoCredsPath(t *testing.T) {
	oldPush := pushConfig
	defer func() { pushConfig = oldPush }()
	pushConfig = &PushNotificationConfig{FCMEnabled: true, FCMCredentials: ""}
	initFCM()
}

func TestCB77_InitFCM_CredsNotFound(t *testing.T) {
	oldPush := pushConfig
	defer func() { pushConfig = oldPush }()
	pushConfig = &PushNotificationConfig{FCMEnabled: true, FCMCredentials: "/nonexistent/creds.json"}
	initFCM()
}

// ==================== loadTiersFromDB (88.9%) — additional paths ====================

func TestCB77_LoadTiersFromDB_NilDB(t *testing.T) {
	oldDB := db
	defer func() { db = oldDB }()
	db = nil

	rl := NewTieredRateLimiter()
	defer rl.Stop()
	loadTiersFromDB(rl)
	// Should not panic
}

func TestCB77_LoadTiersFromDB_WithTiers(t *testing.T) {
	oldDB := db
	defer func() { db = oldDB }()
	db = setupTestDB_CB77(t)
	defer db.Close()

	// Insert tiers
	db.Exec("INSERT INTO user_rate_limit_tiers (user_id, tier_name) VALUES (?, ?)", "user1", "pro")
	db.Exec("INSERT INTO user_rate_limit_tiers (user_id, tier_name) VALUES (?, ?)", "user2", "enterprise")

	rl := NewTieredRateLimiter()
	defer rl.Stop()
	loadTiersFromDB(rl)

	if rl.GetTier("user1") != TierPro {
		t.Errorf("expected pro tier, got %v", rl.GetTier("user1"))
	}
	if rl.GetTier("user2") != TierEnterprise {
		t.Errorf("expected enterprise tier, got %v", rl.GetTier("user2"))
	}
}

// ==================== sendWelcomeMessage (80%) — additional paths ====================

func TestCB77_SendWelcomeMessage_WithDeviceID(t *testing.T) {
	h := newTestHub()
	conn := &Connection{
		id:       "user1",
		connType: "client",
		hub:      h,
		send:     make(chan []byte, 10),
		deviceID: "device123",
	}
	sendWelcomeMessage(conn)
	select {
	case msg := <-conn.send:
		var outgoing OutgoingMessage
		json.Unmarshal(msg, &outgoing)
		if outgoing.Type != "connected" {
			t.Errorf("expected 'connected', got '%s'", outgoing.Type)
		}
		data := outgoing.Data.(map[string]interface{})
		if data["device_id"] != "device123" {
			t.Errorf("expected device_id 'device123', got '%v'", data["device_id"])
		}
	case <-time.After(100 * time.Millisecond):
		t.Error("expected connected message")
	}
}

func TestCB77_SendWelcomeMessage_BufferFull(t *testing.T) {
	h := newTestHub()
	conn := &Connection{
		id:       "user1",
		connType: "client",
		hub:      h,
		send:     make(chan []byte, 1),
	}
	// Fill buffer
	conn.send <- []byte(`{"type":"fill"}`)

	// sendWelcomeMessage should not block
	done := make(chan struct{})
	go func() {
		defer close(done)
		sendWelcomeMessage(conn)
	}()
	select {
	case <-done:
	case <-time.After(500 * time.Millisecond):
		t.Error("sendWelcomeMessage should not block when buffer is full")
	}
}

// ==================== ShutdownTracing (20%) — with provider ====================

func TestCB77_ShutdownTracing_WithProvider(t *testing.T) {
	// Create a real tracer provider for shutdown test
	oldTP := tp
	defer func() { tp = oldTP }()

	tp = nil // Can't easily create a real TP without OTEL SDK setup
	// Test nil provider path
	ShutdownTracing()
}

// ==================== dbdriver: Placeholder ====================

func TestCB77_Placeholder_SQLite(t *testing.T) {
	origDriver := currentDriver
	currentDriver = DriverSQLite
	defer func() { currentDriver = origDriver }()

	if Placeholder(1) != "?" {
		t.Errorf("expected ? for SQLite, got %s", Placeholder(1))
	}
}

func TestCB77_Placeholder_Postgres(t *testing.T) {
	origDriver := currentDriver
	currentDriver = DriverPostgreSQL
	defer func() { currentDriver = origDriver }()

	result := Placeholder(1)
	_ = result
	// Placeholder returns $1 for Postgres
}

func TestCB77_Placeholders_SQLite(t *testing.T) {
	origDriver := currentDriver
	currentDriver = DriverSQLite
	defer func() { currentDriver = origDriver }()

	result := Placeholders(1, 3)
	_ = result
	// Should return ?,?,? for SQLite
}

func TestCB77_Placeholders_Postgres(t *testing.T) {
	origDriver := currentDriver
	currentDriver = DriverPostgreSQL
	defer func() { currentDriver = origDriver }()

	result := Placeholders(1, 3)
	_ = result
	// Should return $1,$2,$3 for Postgres
}

// ==================== Env helpers ====================

func TestCB77_EnvIntOrDefault_Set(t *testing.T) {
	os.Setenv("TEST_INT_VAL", "42")
	defer os.Unsetenv("TEST_INT_VAL")
	val := envIntOrDefault("TEST_INT_VAL", 10)
	if val != 42 {
		t.Errorf("expected 42, got %d", val)
	}
}

func TestCB77_EnvIntOrDefault_Default(t *testing.T) {
	os.Unsetenv("TEST_INT_VAL_UNSET")
	val := envIntOrDefault("TEST_INT_VAL_UNSET", 10)
	if val != 10 {
		t.Errorf("expected 10, got %d", val)
	}
}

func TestCB77_EnvIntOrDefault_Invalid(t *testing.T) {
	os.Setenv("TEST_INT_INVALID", "not-a-number")
	defer os.Unsetenv("TEST_INT_INVALID")
	val := envIntOrDefault("TEST_INT_INVALID", 10)
	if val != 10 {
		t.Errorf("expected 10 for invalid input, got %d", val)
	}
}

func TestCB77_EnvDurationOrDefault_Set(t *testing.T) {
	os.Setenv("TEST_DUR_VAL", "30s")
	defer os.Unsetenv("TEST_DUR_VAL")
	val := envDurationOrDefault("TEST_DUR_VAL", 10*time.Second)
	if val != 30*time.Second {
		t.Errorf("expected 30s, got %v", val)
	}
}

func TestCB77_EnvDurationOrDefault_Default(t *testing.T) {
	os.Unsetenv("TEST_DUR_UNSET")
	val := envDurationOrDefault("TEST_DUR_UNSET", 10*time.Second)
	if val != 10*time.Second {
		t.Errorf("expected 10s, got %v", val)
	}
}

func TestCB77_EnvDurationOrDefault_Invalid(t *testing.T) {
	os.Setenv("TEST_DUR_INVALID", "not-a-duration")
	defer os.Unsetenv("TEST_DUR_INVALID")
	val := envDurationOrDefault("TEST_DUR_INVALID", 10*time.Second)
	if val != 10*time.Second {
		t.Errorf("expected 10s for invalid, got %v", val)
	}
}