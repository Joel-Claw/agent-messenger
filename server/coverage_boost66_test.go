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
	_ "github.com/mattn/go-sqlite3"
)

// --- CB66 Helpers ---

func setupTestDB_CB66(t *testing.T) *sql.DB {
	testDB, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("Failed to open test DB: %v", err)
	}
	if err := initSchema(testDB); err != nil {
		t.Fatalf("Failed to init schema: %v", err)
	}
	return testDB
}

func generateTestToken_CB66(userID string) string {
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

func makeTestHub_CB66() *Hub {
	return newHub()
}

// ==================== Metrics: NewMetrics, Uptime, Snapshot ====================

func TestCB66_NewMetrics(t *testing.T) {
	h := makeTestHub_CB66()
	m := NewMetrics(h)
	if m == nil {
		t.Fatal("expected non-nil Metrics")
	}
	if m.Version != "0.2.0" {
		t.Errorf("expected version 0.2.0, got %s", m.Version)
	}
	if m.AgentsConnected == nil {
		t.Error("expected AgentsConnected func to be set")
	}
	if m.ClientsConnected == nil {
		t.Error("expected ClientsConnected func to be set")
	}
	if m.ClientConnsTotal == nil {
		t.Error("expected ClientConnsTotal func to be set")
	}
	if m.StaleAgentCount == nil {
		t.Error("expected StaleAgentCount func to be set")
	}
	// Verify the funcs work
	if m.AgentsConnected() != 0 {
		t.Error("expected 0 agents connected")
	}
	if m.ClientsConnected() != 0 {
		t.Error("expected 0 clients connected")
	}
}

func TestCB66_Uptime(t *testing.T) {
	h := makeTestHub_CB66()
	m := NewMetrics(h)
	// Uptime should be a positive duration
	u := m.Uptime()
	if u <= 0 {
		t.Errorf("expected positive uptime, got %v", u)
	}
	// Wait a tiny bit and verify uptime increases
	time.Sleep(10 * time.Millisecond)
	u2 := m.Uptime()
	if u2 <= u {
		t.Errorf("expected uptime to increase: %v -> %v", u, u2)
	}
}

func TestCB66_Snapshot(t *testing.T) {
	h := makeTestHub_CB66()
	m := NewMetrics(h)
	snap := m.Snapshot()
	if snap == nil {
		t.Fatal("expected non-nil snapshot")
	}
	if snap["version"] != "0.2.0" {
		t.Errorf("expected version 0.2.0, got %v", snap["version"])
	}
	if _, ok := snap["uptime_seconds"]; !ok {
		t.Error("expected uptime_seconds in snapshot")
	}
	if _, ok := snap["messages_in"]; !ok {
		t.Error("expected messages_in in snapshot")
	}
	if _, ok := snap["messages_out"]; !ok {
		t.Error("expected messages_out in snapshot")
	}
	if _, ok := snap["goroutines"]; !ok {
		t.Error("expected goroutines in snapshot")
	}
	if _, ok := snap["memory_alloc_mb"]; !ok {
		t.Error("expected memory_alloc_mb in snapshot")
	}
	if _, ok := snap["offline_queue_depth"]; !ok {
		t.Error("expected offline_queue_depth in snapshot")
	}
	if _, ok := snap["agent_heartbeat"]; !ok {
		t.Error("expected agent_heartbeat in snapshot")
	}
	// Verify agent_heartbeat sub-map
	hb, ok := snap["agent_heartbeat"].(map[string]interface{})
	if !ok {
		t.Fatal("expected agent_heartbeat to be map[string]interface{}")
	}
	if _, ok := hb["enabled"]; !ok {
		t.Error("expected enabled in agent_heartbeat")
	}
}

func TestCB66_Snapshot_WithOfflineQueue(t *testing.T) {
	h := makeTestHub_CB66()
	m := NewMetrics(h)
	// Set up an offline queue
	offlineQueue = newOfflineQueue(100, 7*24*time.Hour)
	defer func() { offlineQueue = nil }()
	offlineQueue.Enqueue("recipient1", []byte("msg1"))
	offlineQueue.Enqueue("recipient2", []byte("msg2"))

	snap := m.Snapshot()
	depth := snap["offline_queue_depth"]
	if depth.(int) != 2 {
		t.Errorf("expected offline_queue_depth=2, got %v", depth)
	}
}

// ==================== handleMetrics (0% -> ~100%) ====================

func TestCB66_HandleMetrics_Get(t *testing.T) {
	h := makeTestHub_CB66()
	ServerMetrics = NewMetrics(h)
	defer func() { ServerMetrics = nil }()

	req := httptest.NewRequest("GET", "/metrics", nil)
	w := httptest.NewRecorder()
	handleMetrics(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, "agent_messenger_messages_in_total") {
		t.Error("expected messages_in_total metric in output")
	}
	if !strings.Contains(body, "agent_messenger_agents_connected") {
		t.Error("expected agents_connected metric in output")
	}
	if !strings.Contains(body, "agent_messenger_goroutines") {
		t.Error("expected goroutines metric in output")
	}
	if !strings.Contains(body, "agent_messenger_memory_alloc_bytes") {
		t.Error("expected memory_alloc_bytes metric in output")
	}
	if !strings.Contains(body, "agent_messenger_offline_queue_depth") {
		t.Error("expected offline_queue_depth metric in output")
	}
	if !strings.Contains(body, "agent_messenger_agent_heartbeat_enabled") {
		t.Error("expected agent_heartbeat_enabled metric in output")
	}
	if !strings.Contains(body, "agent_messenger_stale_agents") {
		t.Error("expected stale_agents metric in output")
	}
}

func TestCB66_HandleMetrics_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest("POST", "/metrics", nil)
	w := httptest.NewRecorder()
	handleMetrics(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestCB66_BoolToInt(t *testing.T) {
	if boolToInt(true) != 1 {
		t.Error("expected boolToInt(true) = 1")
	}
	if boolToInt(false) != 0 {
		t.Error("expected boolToInt(false) = 0")
	}
	if boolToInt("not a bool") != 0 {
		t.Error("expected boolToInt(non-bool) = 0")
	}
	if boolToInt(nil) != 0 {
		t.Error("expected boolToInt(nil) = 0")
	}
}

// ==================== Hub: TouchHeartbeat, StaleAgentCount, etc (0% -> 100%) ====================

func TestCB66_TouchHeartbeat(t *testing.T) {
	h := makeTestHub_CB66()
	conn := &Connection{
		id:        "agent1",
		connType:  "agent",
		hub:       h,
		send:      make(chan []byte, 10),
		closeMu:   sync.RWMutex{},
	}
	h.agents["agent1"] = conn

	original := conn.lastHeartbeat
	h.TouchHeartbeat(conn)

	if !conn.lastHeartbeat.After(original) {
		t.Error("expected lastHeartbeat to be updated")
	}
}

func TestCB66_StaleAgentCount(t *testing.T) {
	h := makeTestHub_CB66()
	if h.StaleAgentCount() != 0 {
		t.Error("expected 0 stale agents initially")
	}
	h.staleAgents.Add(3)
	if h.StaleAgentCount() != 3 {
		t.Errorf("expected 3 stale agents, got %d", h.StaleAgentCount())
	}
}

func TestCB66_GetClient(t *testing.T) {
	h := makeTestHub_CB66()
	// No clients: should return nil
	if h.GetClient("user1") != nil {
		t.Error("expected nil for non-existent user")
	}
	// Add a client connection
	conn := &Connection{
		id:       "user1",
		connType: "client",
		hub:      h,
		send:     make(chan []byte, 10),
		closeMu:  sync.RWMutex{},
	}
	h.clientConns["user1"] = []*Connection{conn}

	got := h.GetClient("user1")
	if got == nil || got.id != "user1" {
		t.Error("expected to get user1 connection")
	}
}

func TestCB66_GetClient_EmptyList(t *testing.T) {
	h := makeTestHub_CB66()
	h.clientConns["user1"] = []*Connection{}
	if h.GetClient("user1") != nil {
		t.Error("expected nil for empty connection list")
	}
}

func TestCB66_AgentCount(t *testing.T) {
	h := makeTestHub_CB66()
	if h.AgentCount() != 0 {
		t.Error("expected 0 agents")
	}
	h.agents["a1"] = &Connection{id: "a1"}
	h.agents["a2"] = &Connection{id: "a2"}
	if h.AgentCount() != 2 {
		t.Errorf("expected 2 agents, got %d", h.AgentCount())
	}
}

func TestCB66_ClientCount(t *testing.T) {
	h := makeTestHub_CB66()
	if h.ClientCount() != 0 {
		t.Error("expected 0 clients")
	}
	h.clientConns["u1"] = []*Connection{{id: "u1"}}
	h.clientConns["u2"] = []*Connection{{id: "u2"}, {id: "u2"}}
	if h.ClientCount() != 2 {
		t.Errorf("expected 2 unique clients, got %d", h.ClientCount())
	}
}

func TestCB66_ClientConnCount(t *testing.T) {
	h := makeTestHub_CB66()
	if h.ClientConnCount() != 0 {
		t.Error("expected 0 client connections")
	}
	h.clientConns["u1"] = []*Connection{{id: "u1"}, {id: "u1"}}
	h.clientConns["u2"] = []*Connection{{id: "u2"}}
	if h.ClientConnCount() != 3 {
		t.Errorf("expected 3 total client connections, got %d", h.ClientConnCount())
	}
}

func TestCB66_BroadcastToAllClients(t *testing.T) {
	h := makeTestHub_CB66()
	conn1 := &Connection{
		id:       "user1",
		connType: "client",
		hub:      h,
		send:     make(chan []byte, 10),
		closeMu:  sync.RWMutex{},
	}
	conn2 := &Connection{
		id:       "user2",
		connType: "client",
		hub:      h,
		send:     make(chan []byte, 10),
		closeMu:  sync.RWMutex{},
	}
	h.clientConns["user1"] = []*Connection{conn1}
	h.clientConns["user2"] = []*Connection{conn2}

	h.BroadcastToAllClients([]byte("broadcast-msg"))

	// Both clients should receive the message
	select {
	case msg := <-conn1.send:
		if string(msg) != "broadcast-msg" {
			t.Errorf("expected 'broadcast-msg', got %s", string(msg))
		}
	default:
		t.Error("conn1 did not receive broadcast")
	}
	select {
	case msg := <-conn2.send:
		if string(msg) != "broadcast-msg" {
			t.Errorf("expected 'broadcast-msg', got %s", string(msg))
		}
	default:
		t.Error("conn2 did not receive broadcast")
	}
}

func TestCB66_SetAgentStatus(t *testing.T) {
	h := makeTestHub_CB66()
	conn := &Connection{
		id:       "agent1",
		connType: "agent",
		hub:      h,
		send:     make(chan []byte, 10),
		closeMu:  sync.RWMutex{},
	}
	h.agents["agent1"] = conn

	h.SetAgentStatus("agent1", "busy")
	if conn.status != "busy" {
		t.Errorf("expected status 'busy', got '%s'", conn.status)
	}
	if h.AgentStatus("agent1") != "busy" {
		t.Errorf("expected AgentStatus='busy', got '%s'", h.AgentStatus("agent1"))
	}

	// Test default "online" when status is empty
	conn.status = ""
	if h.AgentStatus("agent1") != "online" {
		t.Errorf("expected 'online' for empty status, got '%s'", h.AgentStatus("agent1"))
	}

	// Test offline for non-existent agent
	if h.AgentStatus("nonexistent") != "offline" {
		t.Error("expected 'offline' for non-existent agent")
	}

	// SetAgentStatus on non-existent agent should be a no-op
	h.SetAgentStatus("nonexistent", "busy")
}

func TestCB66_AgentStatus_Offline(t *testing.T) {
	h := makeTestHub_CB66()
	if h.AgentStatus("nonexistent") != "offline" {
		t.Error("expected 'offline' for non-existent agent")
	}
}

// ==================== checkStaleAgents (0% -> ~100%) ====================

func TestCB66_CheckStaleAgents(t *testing.T) {
	h := makeTestHub_CB66()
	// Set short timeout for testing
	oldTimeout := agentPresenceTimeout
	agentPresenceTimeout = 1 * time.Millisecond
	defer func() { agentPresenceTimeout = oldTimeout }()

	// Start hub.run to handle unregister channel
	go h.run()
	defer h.Stop()

	conn := &Connection{
		id:        "stale-agent",
		connType:  "agent",
		hub:       h,
		send:      make(chan []byte, 10),
		closeMu:   sync.RWMutex{},
	}
	h.agents["stale-agent"] = conn

	// Wait for the heartbeat to be stale
	time.Sleep(5 * time.Millisecond)

	h.checkStaleAgents()

	if h.StaleAgentCount() != 1 {
		t.Errorf("expected 1 stale agent, got %d", h.StaleAgentCount())
	}
}

func TestCB66_CheckStaleAgents_NoStale(t *testing.T) {
	h := makeTestHub_CB66()
	conn := &Connection{
		id:             "fresh-agent",
		connType:       "agent",
		hub:            h,
		send:           make(chan []byte, 10),
		closeMu:        sync.RWMutex{},
		lastHeartbeat:  time.Now(),
	}
	h.agents["fresh-agent"] = conn

	h.checkStaleAgents()

	if h.StaleAgentCount() != 0 {
		t.Errorf("expected 0 stale agents, got %d", h.StaleAgentCount())
	}
}

// ==================== Routing: routeTypingIndicator, routeStatusUpdate, truncate, routeHeartbeat ====================

func TestCB66_Truncate(t *testing.T) {
	// Short string: no truncation
	if got := truncate("hello", 10); got != "hello" {
		t.Errorf("expected 'hello', got '%s'", got)
	}
	// Exact length
	if got := truncate("hello", 5); got != "hello" {
		t.Errorf("expected 'hello', got '%s'", got)
	}
	// Long string: truncate with ...
	if got := truncate("hello world", 8); got != "hello..." {
		t.Errorf("expected 'hello...', got '%s'", got)
	}
	// Very short maxLen (<=3): just cut
	if got := truncate("hello", 3); got != "hel" {
		t.Errorf("expected 'hel', got '%s'", got)
	}
}

func TestCB66_RouteTypingIndicator_InvalidJSON(t *testing.T) {
	h := makeTestHub_CB66()
	hub = h
	defer func() { hub = nil }()
	conn := &Connection{
		id:       "agent1",
		connType: "agent",
		hub:      h,
		send:     make(chan []byte, 10),
		closeMu:  sync.RWMutex{},
	}
	// Invalid JSON should return without panic
	routeTypingIndicator(conn, []byte("not json"))
}

func TestCB66_RouteTypingIndicator_EmptyConversationID(t *testing.T) {
	h := makeTestHub_CB66()
	hub = h
	defer func() { hub = nil }()
	conn := &Connection{
		id:       "agent1",
		connType: "agent",
		hub:      h,
		send:     make(chan []byte, 10),
		closeMu:  sync.RWMutex{},
	}
	routeTypingIndicator(conn, []byte(`{"conversation_id":""}`))
}

func TestCB66_RouteTypingIndicator_AgentNotFound(t *testing.T) {
	db = setupTestDB_CB66(t)
	defer db.Close()
	defer func() { db = nil }()

	h := makeTestHub_CB66()
	hub = h
	defer func() { hub = nil }()
	conn := &Connection{
		id:       "agent1",
		connType: "agent",
		hub:      h,
		send:     make(chan []byte, 10),
		closeMu:  sync.RWMutex{},
	}
	// Non-existent conversation
	routeTypingIndicator(conn, []byte(`{"conversation_id":"nonexistent"}`))
}

func TestCB66_RouteTypingIndicator_UnauthorizedAgent(t *testing.T) {
	db = setupTestDB_CB66(t)
	defer db.Close()
	defer func() { db = nil }()

	h := makeTestHub_CB66()
	hub = h
	defer func() { hub = nil }()

	// Create conversation owned by user1 with agent "correct-agent"
	_, err := db.Exec("INSERT INTO conversations (id, user_id, agent_id) VALUES (?, ?, ?)",
		"conv1", "user1", "correct-agent")
	if err != nil {
		t.Fatal(err)
	}

	conn := &Connection{
		id:       "wrong-agent",
		connType: "agent",
		hub:      h,
		send:     make(chan []byte, 10),
		closeMu:  sync.RWMutex{},
	}
	// Agent is not part of this conversation
	routeTypingIndicator(conn, []byte(`{"conversation_id":"conv1"}`))
}

func TestCB66_RouteTypingIndicator_Success(t *testing.T) {
	db = setupTestDB_CB66(t)
	defer db.Close()
	defer func() { db = nil }()

	h := makeTestHub_CB66()
	hub = h
	defer func() { hub = nil }()

	_, err := db.Exec("INSERT INTO conversations (id, user_id, agent_id) VALUES (?, ?, ?)",
		"conv1", "user1", "agent1")
	if err != nil {
		t.Fatal(err)
	}

	// Set up a client connection for user1
	clientConn := &Connection{
		id:       "user1",
		connType: "client",
		hub:      h,
		send:     make(chan []byte, 10),
		closeMu:  sync.RWMutex{},
	}
	h.clientConns["user1"] = []*Connection{clientConn}

	agentConn := &Connection{
		id:       "agent1",
		connType:  "agent",
		hub:       h,
		send:      make(chan []byte, 10),
		closeMu:   sync.RWMutex{},
	}
	h.agents["agent1"] = agentConn

	routeTypingIndicator(agentConn, []byte(`{"conversation_id":"conv1"}`))

	// Client should receive the typing indicator
	select {
	case msg := <-clientConn.send:
		var om OutgoingMessage
		if err := json.Unmarshal(msg, &om); err != nil {
			t.Fatalf("failed to unmarshal: %v", err)
		}
		if om.Type != MsgTypeTyping {
			t.Errorf("expected type '%s', got '%s'", MsgTypeTyping, om.Type)
		}
	case <-time.After(100 * time.Millisecond):
		t.Error("client did not receive typing indicator")
	}
}

func TestCB66_RouteStatusUpdate_InvalidJSON(t *testing.T) {
	h := makeTestHub_CB66()
	hub = h
	defer func() { hub = nil }()
	conn := &Connection{
		id:       "agent1",
		connType: "agent",
		hub:      h,
		send:     make(chan []byte, 10),
		closeMu:  sync.RWMutex{},
	}
	routeStatusUpdate(conn, []byte("not json"))
}

func TestCB66_RouteStatusUpdate_AgentStatusBroadcast(t *testing.T) {
	db = setupTestDB_CB66(t)
	defer db.Close()
	defer func() { db = nil }()

	h := makeTestHub_CB66()
	hub = h
	defer func() { hub = nil }()

	agentConn := &Connection{
		id:       "agent1",
		connType: "agent",
		hub:      h,
		send:     make(chan []byte, 10),
		closeMu:  sync.RWMutex{},
	}
	h.agents["agent1"] = agentConn

	clientConn := &Connection{
		id:       "user1",
		connType: "client",
		hub:      h,
		send:     make(chan []byte, 10),
		closeMu:  sync.RWMutex{},
	}
	h.clientConns["user1"] = []*Connection{clientConn}

	routeStatusUpdate(agentConn, []byte(`{"status":"busy"}`))

	if agentConn.status != "busy" {
		t.Errorf("expected agent status 'busy', got '%s'", agentConn.status)
	}

	// Client should receive the broadcast
	select {
	case msg := <-clientConn.send:
		var om OutgoingMessage
		if err := json.Unmarshal(msg, &om); err != nil {
			t.Fatalf("failed to unmarshal: %v", err)
		}
		if om.Type != MsgTypeStatus {
			t.Errorf("expected type '%s', got '%s'", MsgTypeStatus, om.Type)
		}
	case <-time.After(100 * time.Millisecond):
		t.Error("client did not receive status broadcast")
	}
}

func TestCB66_RouteStatusUpdate_WithConversationID(t *testing.T) {
	db = setupTestDB_CB66(t)
	defer db.Close()
	defer func() { db = nil }()

	h := makeTestHub_CB66()
	hub = h
	defer func() { hub = nil }()

	_, err := db.Exec("INSERT INTO conversations (id, user_id, agent_id) VALUES (?, ?, ?)",
		"conv1", "user1", "agent1")
	if err != nil {
		t.Fatal(err)
	}

	agentConn := &Connection{
		id:       "agent1",
		connType: "agent",
		hub:      h,
		send:     make(chan []byte, 10),
		closeMu:  sync.RWMutex{},
	}
	h.agents["agent1"] = agentConn

	clientConn := &Connection{
		id:       "user1",
		connType: "client",
		hub:      h,
		send:     make(chan []byte, 10),
		closeMu:  sync.RWMutex{},
	}
	h.clientConns["user1"] = []*Connection{clientConn}

	routeStatusUpdate(agentConn, []byte(`{"conversation_id":"conv1","status":"idle"}`))

	// Client should receive at least one status message (broadcast + conversation-specific)
	// Drain messages
	received := 0
	for {
		select {
		case <-clientConn.send:
			received++
		default:
			goto done
		}
	}
done:
	if received < 1 {
		t.Error("expected at least 1 status message to client")
	}
}

func TestCB66_RouteStatusUpdate_ClientToAgent(t *testing.T) {
	db = setupTestDB_CB66(t)
	defer db.Close()
	defer func() { db = nil }()

	h := makeTestHub_CB66()
	hub = h
	defer func() { hub = nil }()

	_, err := db.Exec("INSERT INTO conversations (id, user_id, agent_id) VALUES (?, ?, ?)",
		"conv1", "user1", "agent1")
	if err != nil {
		t.Fatal(err)
	}

	agentConn := &Connection{
		id:       "agent1",
		connType: "agent",
		hub:      h,
		send:     make(chan []byte, 10),
		closeMu:  sync.RWMutex{},
	}
	h.agents["agent1"] = agentConn

	clientConn := &Connection{
		id:       "user1",
		connType: "client",
		hub:      h,
		send:     make(chan []byte, 10),
		closeMu:  sync.RWMutex{},
	}

	routeStatusUpdate(clientConn, []byte(`{"conversation_id":"conv1","status":"typing"}`))

	// Agent should receive the status update
	select {
	case msg := <-agentConn.send:
		var om OutgoingMessage
		if err := json.Unmarshal(msg, &om); err != nil {
			t.Fatalf("failed to unmarshal: %v", err)
		}
		if om.Type != MsgTypeStatus {
			t.Errorf("expected type '%s', got '%s'", MsgTypeStatus, om.Type)
		}
	case <-time.After(100 * time.Millisecond):
		t.Error("agent did not receive status update")
	}
}

func TestCB66_RouteStatusUpdate_UnauthorizedClient(t *testing.T) {
	db = setupTestDB_CB66(t)
	defer db.Close()
	defer func() { db = nil }()

	h := makeTestHub_CB66()
	hub = h
	defer func() { hub = nil }()

	_, err := db.Exec("INSERT INTO conversations (id, user_id, agent_id) VALUES (?, ?, ?)",
		"conv1", "user1", "agent1")
	if err != nil {
		t.Fatal(err)
	}

	wrongClient := &Connection{
		id:       "user2",
		connType: "client",
		hub:      h,
		send:     make(chan []byte, 10),
		closeMu:  sync.RWMutex{},
	}

	// Client is not part of the conversation, should not route
	routeStatusUpdate(wrongClient, []byte(`{"conversation_id":"conv1","status":"idle"}`))
}

func TestCB66_RouteHeartbeat(t *testing.T) {
	h := makeTestHub_CB66()
	hub = h
	defer func() { hub = nil }()

	conn := &Connection{
		id:       "agent1",
		connType: "agent",
		hub:      h,
		send:     make(chan []byte, 10),
		closeMu:  sync.RWMutex{},
	}
	h.agents["agent1"] = conn

	routeHeartbeat(conn)

	// Should receive heartbeat_ack
	select {
	case msg := <-conn.send:
		var om OutgoingMessage
		if err := json.Unmarshal(msg, &om); err != nil {
			t.Fatalf("failed to unmarshal: %v", err)
		}
		if om.Type != "heartbeat_ack" {
			t.Errorf("expected 'heartbeat_ack', got '%s'", om.Type)
		}
	case <-time.After(100 * time.Millisecond):
		t.Error("did not receive heartbeat_ack")
	}

	// Verify heartbeat was touched
	if conn.lastHeartbeat.IsZero() {
		t.Error("expected lastHeartbeat to be set")
	}
}

// ==================== Tags: handleAddTag, handleRemoveTag, removeConversationTag ====================

func TestCB66_HandleAddTag_Success(t *testing.T) {
	db = setupTestDB_CB66(t)
	defer db.Close()
	defer func() { db = nil }()

	// Insert user and conversation
	_, err := db.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)",
		"user1", "testuser", "hash")
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec("INSERT INTO conversations (id, user_id, agent_id) VALUES (?, ?, ?)",
		"conv1", "user1", "agent1")
	if err != nil {
		t.Fatal(err)
	}

	token := generateTestToken_CB66("user1")
	form := strings.NewReader("conversation_id=conv1&tag=important")
	req := httptest.NewRequest("POST", "/conversations/tags/add", form)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	handleAddTag(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["status"] != "tag_added" {
		t.Errorf("expected 'tag_added', got %v", resp["status"])
	}
}

func TestCB66_HandleAddTag_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest("GET", "/conversations/tags/add", nil)
	w := httptest.NewRecorder()
	handleAddTag(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestCB66_HandleAddTag_Unauthorized(t *testing.T) {
	req := httptest.NewRequest("POST", "/conversations/tags/add", nil)
	req.Header.Set("Authorization", "Bearer invalid")
	w := httptest.NewRecorder()
	handleAddTag(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestCB66_HandleAddTag_MissingFields(t *testing.T) {
	db = setupTestDB_CB66(t)
	defer db.Close()
	defer func() { db = nil }()

	_, _ = db.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)",
		"user1", "testuser", "hash")

	token := generateTestToken_CB66("user1")
	form := strings.NewReader("conversation_id=conv1")
	req := httptest.NewRequest("POST", "/conversations/tags/add", form)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handleAddTag(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestCB66_HandleAddTag_NotFound(t *testing.T) {
	db = setupTestDB_CB66(t)
	defer db.Close()
	defer func() { db = nil }()

	_, _ = db.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)",
		"user1", "testuser", "hash")

	token := generateTestToken_CB66("user1")
	form := strings.NewReader("conversation_id=nonexistent&tag=test")
	req := httptest.NewRequest("POST", "/conversations/tags/add", form)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handleAddTag(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

func TestCB66_HandleAddTag_UnauthorizedUser(t *testing.T) {
	db = setupTestDB_CB66(t)
	defer db.Close()
	defer func() { db = nil }()

	_, _ = db.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)",
		"user1", "testuser", "hash")
	_, _ = db.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)",
		"user2", "other", "hash")
	_, _ = db.Exec("INSERT INTO conversations (id, user_id, agent_id) VALUES (?, ?, ?)",
		"conv1", "user1", "agent1")

	token := generateTestToken_CB66("user2")
	form := strings.NewReader("conversation_id=conv1&tag=test")
	req := httptest.NewRequest("POST", "/conversations/tags/add", form)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handleAddTag(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestCB66_HandleAddTag_TagTooLong(t *testing.T) {
	db = setupTestDB_CB66(t)
	defer db.Close()
	defer func() { db = nil }()

	_, _ = db.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)",
		"user1", "testuser", "hash")
	_, _ = db.Exec("INSERT INTO conversations (id, user_id, agent_id) VALUES (?, ?, ?)",
		"conv1", "user1", "agent1")

	token := generateTestToken_CB66("user1")
	longTag := strings.Repeat("a", 51)
	form := strings.NewReader("conversation_id=conv1&tag=" + longTag)
	req := httptest.NewRequest("POST", "/conversations/tags/add", form)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handleAddTag(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestCB66_HandleAddTag_Duplicate(t *testing.T) {
	db = setupTestDB_CB66(t)
	defer db.Close()
	defer func() { db = nil }()

	_, _ = db.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)",
		"user1", "testuser", "hash")
	_, _ = db.Exec("INSERT INTO conversations (id, user_id, agent_id) VALUES (?, ?, ?)",
		"conv1", "user1", "agent1")
	_, _ = db.Exec("INSERT INTO conversation_tags (id, conversation_id, tag, created_at) VALUES (?, ?, ?, ?)",
		"tag1", "conv1", "important", time.Now().UTC())

	token := generateTestToken_CB66("user1")
	form := strings.NewReader("conversation_id=conv1&tag=important")
	req := httptest.NewRequest("POST", "/conversations/tags/add", form)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handleAddTag(w, req)
	if w.Code != http.StatusConflict {
		t.Errorf("expected 409, got %d", w.Code)
	}
}

func TestCB66_HandleRemoveTag_Success(t *testing.T) {
	db = setupTestDB_CB66(t)
	defer db.Close()
	defer func() { db = nil }()

	_, _ = db.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)",
		"user1", "testuser", "hash")
	_, _ = db.Exec("INSERT INTO conversations (id, user_id, agent_id) VALUES (?, ?, ?)",
		"conv1", "user1", "agent1")
	_, _ = db.Exec("INSERT INTO conversation_tags (id, conversation_id, tag, created_at) VALUES (?, ?, ?, ?)",
		"tag1", "conv1", "important", time.Now().UTC())

	token := generateTestToken_CB66("user1")
	form := strings.NewReader("conversation_id=conv1&tag=important")
	req := httptest.NewRequest("POST", "/conversations/tags/remove", form)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handleRemoveTag(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCB66_HandleRemoveTag_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest("GET", "/conversations/tags/remove", nil)
	w := httptest.NewRecorder()
	handleRemoveTag(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestCB66_HandleRemoveTag_Unauthorized(t *testing.T) {
	req := httptest.NewRequest("POST", "/conversations/tags/remove", nil)
	req.Header.Set("Authorization", "Bearer invalid")
	w := httptest.NewRecorder()
	handleRemoveTag(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestCB66_HandleRemoveTag_NotFound(t *testing.T) {
	db = setupTestDB_CB66(t)
	defer db.Close()
	defer func() { db = nil }()

	_, _ = db.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)",
		"user1", "testuser", "hash")
	_, _ = db.Exec("INSERT INTO conversations (id, user_id, agent_id) VALUES (?, ?, ?)",
		"conv1", "user1", "agent1")

	token := generateTestToken_CB66("user1")
	form := strings.NewReader("conversation_id=conv1&tag=nonexistent")
	req := httptest.NewRequest("POST", "/conversations/tags/remove", form)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handleRemoveTag(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

func TestCB66_RemoveConversationTag_UnauthorizedUser(t *testing.T) {
	db = setupTestDB_CB66(t)
	defer db.Close()
	defer func() { db = nil }()

	_, _ = db.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)",
		"user1", "testuser", "hash")
	_, _ = db.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)",
		"user2", "other", "hash")
	_, _ = db.Exec("INSERT INTO conversations (id, user_id, agent_id) VALUES (?, ?, ?)",
		"conv1", "user1", "agent1")

	err := removeConversationTag("conv1", "user2", "test")
	if err == nil || err.Error() != "unauthorized" {
		t.Errorf("expected 'unauthorized', got %v", err)
	}
}

func TestCB66_RemoveConversationTag_NotFound(t *testing.T) {
	db = setupTestDB_CB66(t)
	defer db.Close()
	defer func() { db = nil }()

	_, _ = db.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)",
		"user1", "testuser", "hash")
	_, _ = db.Exec("INSERT INTO conversations (id, user_id, agent_id) VALUES (?, ?, ?)",
		"conv1", "user1", "agent1")

	err := removeConversationTag("nonexistent", "user1", "test")
	if err == nil || err.Error() != "conversation not found" {
		t.Errorf("expected 'conversation not found', got %v", err)
	}
}

// ==================== dbdriver: Placeholders, envIntOrDefault, envDurationOrDefault ====================

func TestCB66_Placeholders_SQLite(t *testing.T) {
	oldDriver := currentDriver
	currentDriver = DriverSQLite
	defer func() { currentDriver = oldDriver }()

	if Placeholder(1) != "?" {
		t.Errorf("expected '?', got '%s'", Placeholder(1))
	}
	ph := Placeholders(1, 3)
	if ph != "?, ?, ?" {
		t.Errorf("expected '?, ?, ?', got '%s'", ph)
	}
}

func TestCB66_Placeholders_PostgreSQL(t *testing.T) {
	oldDriver := currentDriver
	currentDriver = DriverPostgreSQL
	defer func() { currentDriver = oldDriver }()

	if Placeholder(1) != "$1" {
		t.Errorf("expected '$1', got '%s'", Placeholder(1))
	}
	ph := Placeholders(1, 3)
	if ph != "$1, $2, $3" {
		t.Errorf("expected '$1, $2, $3', got '%s'", ph)
	}
}

func TestCB66_EnvIntOrDefault_Valid(t *testing.T) {
	os.Setenv("TEST_INT_CB66", "42")
	defer os.Unsetenv("TEST_INT_CB66")

	if v := envIntOrDefault("TEST_INT_CB66", 10); v != 42 {
		t.Errorf("expected 42, got %d", v)
	}
}

func TestCB66_EnvIntOrDefault_Invalid(t *testing.T) {
	os.Setenv("TEST_INT_INVALID_CB66", "not-a-number")
	defer os.Unsetenv("TEST_INT_INVALID_CB66")

	if v := envIntOrDefault("TEST_INT_INVALID_CB66", 10); v != 10 {
		t.Errorf("expected default 10, got %d", v)
	}
}

func TestCB66_EnvIntOrDefault_Unset(t *testing.T) {
	if v := envIntOrDefault("UNSET_INT_CB66", 15); v != 15 {
		t.Errorf("expected default 15, got %d", v)
	}
}

func TestCB66_EnvDurationOrDefault_Valid(t *testing.T) {
	os.Setenv("TEST_DUR_CB66", "5m30s")
	defer os.Unsetenv("TEST_DUR_CB66")

	v := envDurationOrDefault("TEST_DUR_CB66", 10*time.Second)
	if v != 5*time.Minute+30*time.Second {
		t.Errorf("expected 5m30s, got %v", v)
	}
}

func TestCB66_EnvDurationOrDefault_Invalid(t *testing.T) {
	os.Setenv("TEST_DUR_INVALID_CB66", "not-a-duration")
	defer os.Unsetenv("TEST_DUR_INVALID_CB66")

	if v := envDurationOrDefault("TEST_DUR_INVALID_CB66", 10*time.Second); v != 10*time.Second {
		t.Errorf("expected default 10s, got %v", v)
	}
}

func TestCB66_EnvDurationOrDefault_Unset(t *testing.T) {
	if v := envDurationOrDefault("UNSET_DUR_CB66", 15*time.Second); v != 15*time.Second {
		t.Errorf("expected default 15s, got %v", v)
	}
}

// ==================== Logger: SetLevel, SetOutput, WithFields ====================

func TestCB66_Logger_SetLevel(t *testing.T) {
	l := NewLogger(LogInfo)
	l.SetLevel(LogDebug)
	if l.level != LogDebug {
		t.Errorf("expected LogDebug, got %v", l.level)
	}
	l.SetLevel(LogError)
	if l.level != LogError {
		t.Errorf("expected LogError, got %v", l.level)
	}
}

func TestCB66_Logger_SetOutput(t *testing.T) {
	l := NewLogger(LogInfo)
	var buf strings.Builder
	l.SetOutput(&buf)
	l.Info("test message from CB66", nil)
	output := buf.String()
	if !strings.Contains(output, "test message from CB66") {
		t.Errorf("expected output to contain log message, got: %s", output)
	}
}

func TestCB66_Logger_WithFields(t *testing.T) {
	l := NewLogger(LogInfo)
	var buf strings.Builder
	l.SetOutput(&buf)
	logger := l.WithFields(map[string]interface{}{"component": "test", "request_id": "abc123"})
	logger.Info("hello from WithFields", nil)
	output := buf.String()
	if !strings.Contains(output, "component") {
		t.Errorf("expected output to contain component, got: %s", output)
	}
	if !strings.Contains(output, "test") {
		t.Errorf("expected output to contain test value, got: %s", output)
	}
	if !strings.Contains(output, "request_id") {
		t.Errorf("expected output to contain request_id, got: %s", output)
	}
	if !strings.Contains(output, "abc123") {
		t.Errorf("expected output to contain abc123, got: %s", output)
	}
}

func TestCB66_Logger_LevelFiltering(t *testing.T) {
	l := NewLogger(LogWarn)
	var buf strings.Builder
	l.SetOutput(&buf)
	l.Debug("should not appear", nil)
	l.Info("should not appear", nil)
	l.Warn("should appear", nil)
	l.Error("should also appear", nil)
	output := buf.String()
	if strings.Contains(output, "should not appear") {
		t.Error("debug/info messages should be filtered at Warn level")
	}
	if !strings.Contains(output, "should appear") {
		t.Error("warn message should appear")
	}
	if !strings.Contains(output, "should also appear") {
		t.Error("error message should appear")
	}
}

// ==================== Profile handler: writeProfileJSON, writeProfileError, SetGCPercent, SetMemoryLimit ====================

func TestCB66_WriteProfileJSON(t *testing.T) {
	w := httptest.NewRecorder()
	writeProfileJSON(w, map[string]interface{}{
		"status": "ok",
		"value":  42,
	})
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	var resp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["status"] != "ok" {
		t.Errorf("expected 'ok', got %v", resp["status"])
	}
}

func TestCB66_WriteProfileError(t *testing.T) {
	w := httptest.NewRecorder()
	writeProfileError(w, "test error context", nil)
	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", w.Code)
	}
	var resp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["status"] != "error" {
		t.Errorf("expected 'error', got %v", resp["status"])
	}
	if resp["context"] != "test error context" {
		t.Errorf("expected 'test error context', got %v", resp["context"])
	}
}

func TestCB66_SetGCPercent(t *testing.T) {
	old := SetGCPercent(200)
	defer SetGCPercent(old)
	// Verify it was set (the return value is the previous setting)
	newOld := SetGCPercent(200)
	if newOld != 200 {
		t.Errorf("expected previous GC percent to be 200, got %d", newOld)
	}
}

func TestCB66_SetMemoryLimit(t *testing.T) {
	// Set a high memory limit to avoid interference
	old := SetMemoryLimit(1 << 40) // 1 TiB
	defer SetMemoryLimit(old)
	// Setting -1 disables the soft limit
	SetMemoryLimit(-1)
	// No panic = success
}

// ==================== Queue: Purge, QueueDepth ====================

func TestCB66_QueuePurge(t *testing.T) {
	q := newOfflineQueue(100, 7*24*time.Hour)
	q.Enqueue("r1", []byte("msg1"))
	q.Enqueue("r2", []byte("msg2"))
	if q.TotalDepth() != 2 {
		t.Errorf("expected depth 2, got %d", q.TotalDepth())
	}
	q.Purge("r1")
	q.Purge("r2")
	if q.TotalDepth() != 0 {
		t.Errorf("expected depth 0 after purge, got %d", q.TotalDepth())
	}
}

func TestCB66_QueuePurge_Recipient(t *testing.T) {
	q := newOfflineQueue(100, 7*24*time.Hour)
	q.Enqueue("r1", []byte("msg1"))
	q.Enqueue("r1", []byte("msg2"))
	q.Enqueue("r2", []byte("msg3"))
	q.Purge("r1")
	if q.TotalDepth() != 1 {
		t.Errorf("expected depth 1 after purging r1, got %d", q.TotalDepth())
	}
}

// ==================== Presence: handleGetUserPresence (0%) ====================

func TestCB66_HandleGetUserPresence_NotFound(t *testing.T) {
	db = setupTestDB_CB66(t)
	defer db.Close()
	defer func() { db = nil }()

	h := makeTestHub_CB66()
	hub = h
	defer func() { hub = nil }()

	token := generateTestToken_CB66("user1")
	req := httptest.NewRequest("GET", "/presence?user_id=nonexistent", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	handleGetUserPresence(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	var resp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["online"] != false {
		t.Errorf("expected online=false, got %v", resp["online"])
	}
	if resp["device_count"] != float64(0) {
		t.Errorf("expected device_count=0, got %v", resp["device_count"])
	}
}

func TestCB66_HandleGetUserPresence_Online(t *testing.T) {
	db = setupTestDB_CB66(t)
	defer db.Close()
	defer func() { db = nil }()

	h := makeTestHub_CB66()
	hub = h
	defer func() { hub = nil }()

	clientConn := &Connection{
		id:       "user1",
		connType: "client",
		hub:      h,
		send:     make(chan []byte, 10),
		closeMu:  sync.RWMutex{},
	}
	h.clientConns["user1"] = []*Connection{clientConn}

	token := generateTestToken_CB66("admin")
	req := httptest.NewRequest("GET", "/presence?user_id=user1", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	handleGetUserPresence(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	var resp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["online"] != true {
		t.Errorf("expected online=true, got %v", resp["online"])
	}
	if resp["device_count"] != float64(1) {
		t.Errorf("expected device_count=1, got %v", resp["device_count"])
	}
	if resp["last_seen"] == nil || resp["last_seen"] == "" {
		t.Error("expected non-empty last_seen")
	}
}

func TestCB66_HandleGetUserPresence_MissingUserID(t *testing.T) {
	db = setupTestDB_CB66(t)
	defer db.Close()
	defer func() { db = nil }()

	h := makeTestHub_CB66()
	hub = h
	defer func() { hub = nil }()

	token := generateTestToken_CB66("user1")
	req := httptest.NewRequest("GET", "/presence", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	handleGetUserPresence(w, req)

	// When no user_id param, it defaults to claims.UserID — should be online=false
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	var resp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["online"] != false {
		t.Errorf("expected online=false, got %v", resp["online"])
	}
}

func TestCB66_HandleGetUserPresence_Unauthorized(t *testing.T) {
	h := makeTestHub_CB66()
	hub = h
	defer func() { hub = nil }()

	req := httptest.NewRequest("GET", "/presence?user_id=agent1", nil)
	req.Header.Set("Authorization", "Bearer invalid")
	w := httptest.NewRecorder()

	handleGetUserPresence(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

// ==================== Notif Prefs: handleDeleteNotificationPrefs (0%) ====================

func TestCB66_HandleDeleteNotificationPrefs_Success(t *testing.T) {
	db = setupTestDB_CB66(t)
	defer db.Close()
	defer func() { db = nil }()

	_, _ = db.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)",
		"user1", "testuser", "hash")
	_, _ = db.Exec("INSERT INTO conversations (id, user_id, agent_id) VALUES (?, ?, ?)",
		"conv1", "user1", "agent1")
	_, _ = db.Exec("INSERT INTO notification_preferences (user_id, conversation_id, muted) VALUES (?, ?, ?)",
		"user1", "conv1", 1)

	req := httptest.NewRequest("POST", "/notifications/preferences/delete?conversation_id=conv1", nil)
	ctx := context.WithValue(req.Context(), contextKeyUserID, "user1")
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	handleDeleteNotificationPrefs(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCB66_HandleDeleteNotificationPrefs_NotFound(t *testing.T) {
	db = setupTestDB_CB66(t)
	defer db.Close()
	defer func() { db = nil }()

	req := httptest.NewRequest("POST", "/notifications/preferences/delete?conversation_id=nonexistent", nil)
	ctx := context.WithValue(req.Context(), contextKeyUserID, "user1")
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	handleDeleteNotificationPrefs(w, req)

	// Should still return 200 (idempotent delete)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestCB66_HandleDeleteNotificationPrefs_MissingConvID(t *testing.T) {
	db = setupTestDB_CB66(t)
	defer db.Close()
	defer func() { db = nil }()

	req := httptest.NewRequest("POST", "/notifications/preferences/delete", nil)
	ctx := context.WithValue(req.Context(), contextKeyUserID, "user1")
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	handleDeleteNotificationPrefs(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestCB66_HandleDeleteNotificationPrefs_Unauthorized(t *testing.T) {
	req := httptest.NewRequest("POST", "/notifications/preferences/delete?conversation_id=conv1", nil)
	// No context user ID set — getUserID will fail
	w := httptest.NewRecorder()

	handleDeleteNotificationPrefs(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestCB66_HandleDeleteNotificationPrefs_NoMethodCheck(t *testing.T) {
	// handleDeleteNotificationPrefs has no method check — it accepts any method
	db = setupTestDB_CB66(t)
	defer db.Close()
	defer func() { db = nil }()

	req := httptest.NewRequest("GET", "/notifications/preferences/delete?conversation_id=conv1", nil)
	ctx := context.WithValue(req.Context(), contextKeyUserID, "user1")
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()
	handleDeleteNotificationPrefs(w, req)
	// Should return 200 since there's no method check
	if w.Code != http.StatusOK {
		t.Errorf("expected 200 (no method check), got %d", w.Code)
	}
}

// ==================== Reactions: handleGetReactions (0%) ====================

func TestCB66_HandleGetReactions_Success(t *testing.T) {
	db = setupTestDB_CB66(t)
	defer db.Close()
	defer func() { db = nil }()

	_, _ = db.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)",
		"user1", "testuser", "hash")
	_, _ = db.Exec("INSERT INTO conversations (id, user_id, agent_id) VALUES (?, ?, ?)",
		"conv1", "user1", "agent1")
	_, _ = db.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content) VALUES (?, ?, ?, ?, ?)",
		"msg1", "conv1", "user", "user1", "hello")
	_, _ = db.Exec("INSERT INTO reactions (id, message_id, user_id, emoji, created_at) VALUES (?, ?, ?, ?, ?)",
		"r1", "msg1", "user1", "👍", time.Now().UTC())

	token := generateTestToken_CB66("user1")
	req := httptest.NewRequest("GET", "/messages/reactions?message_id=msg1", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	handleGetReactions(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCB66_HandleGetReactions_NoReactions(t *testing.T) {
	db = setupTestDB_CB66(t)
	defer db.Close()
	defer func() { db = nil }()

	_, _ = db.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)",
		"user1", "testuser", "hash")

	token := generateTestToken_CB66("user1")
	req := httptest.NewRequest("GET", "/messages/reactions?message_id=nonexistent", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	handleGetReactions(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404 for nonexistent message, got %d", w.Code)
	}
}

func TestCB66_HandleGetReactions_MissingMessageID(t *testing.T) {
	token := generateTestToken_CB66("user1")
	req := httptest.NewRequest("GET", "/messages/reactions", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	handleGetReactions(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestCB66_HandleGetReactions_Unauthorized(t *testing.T) {
	req := httptest.NewRequest("GET", "/messages/reactions?message_id=msg1", nil)
	req.Header.Set("Authorization", "Bearer invalid")
	w := httptest.NewRecorder()

	handleGetReactions(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestCB66_HandleGetReactions_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest("POST", "/messages/reactions?message_id=msg1", nil)
	w := httptest.NewRecorder()
	handleGetReactions(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

// ==================== replayOfflineMessages (22.2% -> higher) ====================

func TestCB66_ReplayOfflineMessages_WithMessages(t *testing.T) {
	h := makeTestHub_CB66()
	q := newOfflineQueue(100, 7*24*time.Hour)
	defer func() { offlineQueue = nil }()
	offlineQueue = q

	// Enqueue messages for a recipient — must be valid JSON with type "message"
	msg1, _ := json.Marshal(OutgoingMessage{Type: MsgTypeMessage, Data: "queued-msg-1"})
	msg2, _ := json.Marshal(OutgoingMessage{Type: MsgTypeMessage, Data: "queued-msg-2"})
	q.Enqueue("agent1", msg1)
	q.Enqueue("agent1", msg2)

	// Set up agent connection
	conn := &Connection{
		id:       "agent1",
		connType: "agent",
		hub:      h,
		send:     make(chan []byte, 10),
		closeMu:  sync.RWMutex{},
	}
	h.agents["agent1"] = conn

	replayOfflineMessages(conn)

	// Should receive the queued messages
	msgs := []string{}
	for {
		select {
		case m := <-conn.send:
			msgs = append(msgs, string(m))
		default:
			goto doneReplay
		}
	}
doneReplay:
	if len(msgs) != 2 {
		t.Errorf("expected 2 replayed messages, got %d", len(msgs))
	}
	if q.TotalDepth() != 0 {
		t.Errorf("expected queue depth 0 after replay, got %d", q.TotalDepth())
	}
}

func TestCB66_ReplayOfflineMessages_NoMessages(t *testing.T) {
	h := makeTestHub_CB66()
	q := newOfflineQueue(100, 7*24*time.Hour)
	defer func() { offlineQueue = nil }()
	offlineQueue = q

	conn := &Connection{
		id:       "agent1",
		connType: "agent",
		hub:      h,
		send:     make(chan []byte, 10),
		closeMu:  sync.RWMutex{},
	}

	replayOfflineMessages(conn)

	// No messages should be received
	select {
	case msg := <-conn.send:
		t.Errorf("expected no messages, got: %s", string(msg))
	default:
		// Good
	}
}

// ==================== handleHealth (0%) ====================

func TestCB66_HandleHealth_Success(t *testing.T) {
	db = setupTestDB_CB66(t)
	defer db.Close()
	defer func() { db = nil }()

	h := makeTestHub_CB66()
	hub = h
	defer func() { hub = nil }()
	ServerMetrics = NewMetrics(h)
	defer func() { ServerMetrics = nil }()

	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()
	handleHealth(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	var resp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["status"] != "ok" {
		t.Errorf("expected status 'ok', got %v", resp["status"])
	}
	if resp["version"] != ServerVersion {
		t.Errorf("expected version '%s', got %v", ServerVersion, resp["version"])
	}
	if resp["db"] != "ok" {
		t.Errorf("expected db 'ok', got %v", resp["db"])
	}
}

func TestCB66_HandleHealth_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest("POST", "/health", nil)
	w := httptest.NewRecorder()
	handleHealth(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

// ==================== handleRegisterAgent (0%) ====================

func TestCB66_HandleRegisterAgent_Success(t *testing.T) {
	db = setupTestDB_CB66(t)
	defer db.Close()
	defer func() { db = nil }()

	agentSecret = "test-secret"
	defer func() { agentSecret = "" }()

	form := strings.NewReader("agent_id=agent1&name=Test+Agent&model=gpt-4&personality=friendly&specialty=general")
	req := httptest.NewRequest("POST", "/auth/agent", form)
	req.Header.Set("X-Agent-Secret", "test-secret")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	handleRegisterAgent(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["agent_id"] != "agent1" {
		t.Errorf("expected agent_id=agent1, got %v", resp["agent_id"])
	}
	if resp["status"] != "registered" {
		t.Errorf("expected status=registered, got %v", resp["status"])
	}
}

func TestCB66_HandleRegisterAgent_WrongSecret(t *testing.T) {
	agentSecret = "test-secret"
	defer func() { agentSecret = "" }()

	form := strings.NewReader("agent_id=agent1&name=Test")
	req := httptest.NewRequest("POST", "/auth/agent", form)
	req.Header.Set("X-Agent-Secret", "wrong-secret")
	w := httptest.NewRecorder()

	handleRegisterAgent(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestCB66_HandleRegisterAgent_MissingSecret(t *testing.T) {
	agentSecret = "test-secret"
	defer func() { agentSecret = "" }()

	form := strings.NewReader("agent_id=agent1")
	req := httptest.NewRequest("POST", "/auth/agent", form)
	w := httptest.NewRecorder()

	handleRegisterAgent(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestCB66_HandleRegisterAgent_MissingAgentID(t *testing.T) {
	agentSecret = "test-secret"
	defer func() { agentSecret = "" }()

	db = setupTestDB_CB66(t)
	defer db.Close()
	defer func() { db = nil }()

	form := strings.NewReader("name=Test")
	req := httptest.NewRequest("POST", "/auth/agent", form)
	req.Header.Set("X-Agent-Secret", "test-secret")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	handleRegisterAgent(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestCB66_HandleRegisterAgent_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest("GET", "/auth/agent", nil)
	w := httptest.NewRecorder()
	handleRegisterAgent(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

// ==================== auth: resetAdminSecret (0%) ====================

func TestCB66_ResetAdminSecret(t *testing.T) {
	// Set a custom env var to verify resetAdminSecret re-reads it
	os.Setenv("ADMIN_SECRET", "new-test-admin-secret")
	defer os.Unsetenv("ADMIN_SECRET")

	resetAdminSecret()

	if adminSecret != "new-test-admin-secret" {
		t.Errorf("expected adminSecret='new-test-admin-secret', got '%s'", adminSecret)
	}
	if adminSecret == "" {
		t.Error("expected non-empty adminSecret after reset")
	}
}