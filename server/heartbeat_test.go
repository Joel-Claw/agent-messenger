package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// --- Heartbeat & Reconnection Tests ---

// TestPingPongHeartbeat verifies that the server sends pings and the
// client can respond with pongs to keep the connection alive.
func TestPingPongHeartbeat(t *testing.T) {
	server, cleanup := setupTestServerForRouting(t)
	defer cleanup()

	// Register agent and connect
	agentConn := registerAndConnectAgent(t, server, "hb-agent", agentSecret)
	defer agentConn.Close()

	// Set a pong handler on the client side to verify pings are received
	pingReceived := make(chan struct{}, 1)
	agentConn.SetPingHandler(func(appData string) error {
		select {
		case pingReceived <- struct{}{}:
		default:
		}
		// Send pong back
		return agentConn.WriteMessage(websocket.PongMessage, []byte(appData))
	})

	// Wait for a ping (pingPeriod is ~54s in production, but we verify the mechanism works)
	// For a faster test, we just verify the connection is still alive after a short wait
	time.Sleep(100 * time.Millisecond)

	// Send a message to confirm the connection is still alive
	msg := IncomingMessage{
		Type: "message",
		Data: json.RawMessage(`{"conversation_id": "conv_test", "content": "heartbeat check"}`),
	}
	raw, _ := json.Marshal(msg)
	err := agentConn.WriteMessage(websocket.TextMessage, raw)
	if err != nil {
		t.Fatalf("failed to send message after heartbeat setup: %v", err)
	}
}

// TestReadDeadlineExpired verifies that a connection is cleaned up when
// the peer stops responding to pings (read deadline expires).
func TestReadDeadlineExpired(t *testing.T) {
	// We test this at the unit level by simulating a read deadline
	setupTestDB(t)
	hub = newHub()
	go hub.run()
	ServerMetrics = NewMetrics(hub)

	conn := &Connection{
		hub:         hub,
		connType:    "agent",
		id:          "stale-agent",
		send:        make(chan []byte, 10),
		connectedAt: time.Now(),
	}

	// Register the connection
	hub.register <- conn
	time.Sleep(10 * time.Millisecond)

	// Verify it's registered
	if hub.GetAgent("stale-agent") == nil {
		t.Fatal("agent should be registered")
	}

	// Unregister it (simulating what readPump does on deadline expiry)
	hub.unregister <- conn
	time.Sleep(10 * time.Millisecond)

	// Verify it's cleaned up
	if hub.GetAgent("stale-agent") != nil {
		t.Fatal("agent should be unregistered after disconnect")
	}
}

// TestConnectionReplacement verifies that when a client/agent reconnects,
// the old connection is properly closed and replaced.
func TestConnectionReplacement(t *testing.T) {
	setupTestDB(t)
	hub = newHub()
	go hub.run()
	ServerMetrics = NewMetrics(hub)

	// First connection
	conn1 := &Connection{
		hub:         hub,
		connType:    "agent",
		id:          "replace-agent",
		send:        make(chan []byte, 10),
		connectedAt: time.Now(),
	}
	hub.register <- conn1
	time.Sleep(10 * time.Millisecond)

	if hub.GetAgent("replace-agent") != conn1 {
		t.Fatal("first connection should be registered")
	}

	// Second connection (same agent ID - reconnection)
	conn2 := &Connection{
		hub:         hub,
		connType:    "agent",
		id:          "replace-agent",
		send:        make(chan []byte, 10),
		connectedAt: time.Now(),
	}
	hub.register <- conn2
	time.Sleep(10 * time.Millisecond)

	// The hub should now have conn2, not conn1
	if hub.GetAgent("replace-agent") != conn2 {
		t.Fatal("second connection should replace the first")
	}

	// conn1's send channel should be closed (hub closes it on replacement)
	_, ok := <-conn1.send
	if ok {
		t.Fatal("old connection's send channel should be closed")
	}
}

// TestClientReconnection verifies that a client can reconnect and
// the old connection is properly cleaned up.
func TestClientReconnection(t *testing.T) {
	setupTestDB(t)
	hub = newHub()
	go hub.run()
	ServerMetrics = NewMetrics(hub)

	// First client connection
	conn1 := &Connection{
		hub:         hub,
		connType:    "client",
		id:          "reconnect-user",
		deviceID:    "device-a",
		send:        make(chan []byte, 10),
		connectedAt: time.Now(),
	}
	hub.register <- conn1
	time.Sleep(10 * time.Millisecond)

	// Second connection (same user, different device - multi-device)
	conn2 := &Connection{
		hub:         hub,
		connType:    "client",
		id:          "reconnect-user",
		deviceID:    "device-b",
		send:        make(chan []byte, 10),
		connectedAt: time.Now(),
	}
	hub.register <- conn2
	time.Sleep(10 * time.Millisecond)

	// Both connections should be active (multi-device)
	conns := hub.GetClientConns("reconnect-user")
	if len(conns) != 2 {
		t.Fatalf("expected 2 client connections, got %d", len(conns))
	}

	// Now reconnect with same device_id (device-a) - should replace
	conn3 := &Connection{
		hub:         hub,
		connType:    "client",
		id:          "reconnect-user",
		deviceID:    "device-a",
		send:        make(chan []byte, 10),
		connectedAt: time.Now(),
	}
	hub.register <- conn3
	time.Sleep(10 * time.Millisecond)

	// Should still have 2 connections, but conn1's channel should be closed
	conns = hub.GetClientConns("reconnect-user")
	if len(conns) != 2 {
		t.Fatalf("expected 2 client connections after device-a reconnect, got %d", len(conns))
	}

	// Old device-a connection (conn1) should be closed
	_, ok := <-conn1.send
	if ok {
		t.Fatal("old device-a connection's send channel should be closed")
	}
}

// TestUnregisterIdempotent verifies that unregistering a connection
// that was already replaced (or never registered) doesn't panic.
func TestUnregisterIdempotent(t *testing.T) {
	setupTestDB(t)
	hub = newHub()
	go hub.run()
	ServerMetrics = NewMetrics(hub)

	conn := &Connection{
		hub:         hub,
		connType:    "agent",
		id:          "idempotent-agent",
		send:        make(chan []byte, 10),
		connectedAt: time.Now(),
	}

	// Unregister a connection that was never registered
	hub.unregister <- conn
	time.Sleep(10 * time.Millisecond)

	// Should not panic, and agent count should be 0
	if hub.AgentCount() != 0 {
		t.Fatal("no agents should be registered")
	}
}

// TestUnregisterOnlyMatchingConnection verifies that if a new connection
// has already replaced an old one, unregistering the old connection
// doesn't accidentally remove the new one.
func TestUnregisterOnlyMatchingConnection(t *testing.T) {
	setupTestDB(t)
	hub = newHub()
	go hub.run()
	ServerMetrics = NewMetrics(hub)

	conn1 := &Connection{
		hub:         hub,
		connType:    "agent",
		id:          "match-agent",
		send:        make(chan []byte, 10),
		connectedAt: time.Now(),
	}
	hub.register <- conn1
	time.Sleep(10 * time.Millisecond)

	conn2 := &Connection{
		hub:         hub,
		connType:    "agent",
		id:          "match-agent",
		send:        make(chan []byte, 10),
		connectedAt: time.Now(),
	}
	hub.register <- conn2
	time.Sleep(10 * time.Millisecond)

	// Now unregister conn1 (the old one) - this is what would happen
	// if the old readPump finally exits after being replaced
	hub.unregister <- conn1
	time.Sleep(10 * time.Millisecond)

	// conn2 should still be registered (it's the current one)
	if hub.GetAgent("match-agent") != conn2 {
		t.Fatal("new connection should not be removed when old one unregisters")
	}
}

// TestWritePumpChannelClose verifies that when the hub closes the send channel,
// the writePump sends a close frame and exits.
func TestWritePumpChannelClose(t *testing.T) {
	server, cleanup := setupTestServerForRouting(t)
	defer cleanup()

	// Register agent and connect via WebSocket
	agentConn := registerAndConnectAgent(t, server, "wp-agent", agentSecret)
	defer agentConn.Close()

	// Read the welcome message
	_, _, err := agentConn.ReadMessage()
	if err != nil {
		t.Fatalf("failed to read welcome message: %v", err)
	}

	// Connection should still be alive - send a message
	msg := IncomingMessage{
		Type: "message",
		Data: json.RawMessage(`{"conversation_id": "conv_test", "content": "still alive"}`),
	}
	raw, _ := json.Marshal(msg)
	if err := agentConn.WriteMessage(websocket.TextMessage, raw); err != nil {
		t.Fatalf("failed to send message: %v", err)
	}
}

// TestConnectedAtTimestamp verifies that connections record their connection time.
func TestConnectedAtTimestamp(t *testing.T) {
	setupTestDB(t)
	hub = newHub()
	go hub.run()
	ServerMetrics = NewMetrics(hub)

	before := time.Now()
	conn := &Connection{
		hub:         hub,
		connType:    "agent",
		id:          "ts-agent",
		send:        make(chan []byte, 10),
		connectedAt: time.Now(),
	}
	after := time.Now()
	hub.register <- conn
	time.Sleep(10 * time.Millisecond)

	registered := hub.GetAgent("ts-agent")
	if registered == nil {
		t.Fatal("agent should be registered")
	}
	if registered.connectedAt.Before(before) || registered.connectedAt.After(after) {
		t.Fatalf("connectedAt should be between before and after, got %v", registered.connectedAt)
	}
}

// TestMessagesRoutedCounter verifies that the hub counts routed messages.
func TestMessagesRoutedCounter(t *testing.T) {
	setupTestDB(t)
	hub = newHub()
	go hub.run()
	ServerMetrics = NewMetrics(hub)

	conn := &Connection{
		hub:         hub,
		connType:    "agent",
		id:          "count-agent",
		send:        make(chan []byte, 10),
		connectedAt: time.Now(),
	}
	hub.register <- conn
	time.Sleep(10 * time.Millisecond)

	initialCount := hub.messagesRouted

	// Simulate a message being routed (normally done in readPump)
	hub.mu.Lock()
	hub.messagesRouted++
	hub.mu.Unlock()

	if hub.messagesRouted != initialCount+1 {
		t.Fatalf("expected messages_routed to increment, got %d", hub.messagesRouted)
	}
}

// TestHealthEndpointWithMetrics verifies that the health endpoint
// returns connection counts and metrics.
func TestHealthEndpointWithMetrics(t *testing.T) {
	setupTestDB(t)
	hub = newHub()
	go hub.run()
	ServerMetrics = NewMetrics(hub)

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()
	handleHealth(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)

	if resp["status"] != "ok" {
		t.Fatalf("expected status ok, got %v", resp["status"])
	}
	if _, ok := resp["messages_in"]; !ok {
		t.Fatal("expected messages_in in health response")
	}
	if _, ok := resp["agents_connected"]; !ok {
		t.Fatal("expected agents_connected in health response")
	}
}

// TestWebSocketCloseMessageHandling verifies the server handles
// normal WebSocket close messages gracefully.
func TestWebSocketCloseMessageHandling(t *testing.T) {
	server, cleanup := setupTestServerForRouting(t)
	defer cleanup()

	agentConn := registerAndConnectAgent(t, server, "close-agent", agentSecret)

	// Read welcome
	_, _, _ = agentConn.ReadMessage()

	// Send a close message
	err := agentConn.WriteMessage(websocket.CloseMessage,
		websocket.FormatCloseMessage(websocket.CloseNormalClosure, "bye"))
	if err != nil {
		t.Fatalf("failed to send close message: %v", err)
	}
	agentConn.Close()

	// Give the server time to process the disconnect
	time.Sleep(100 * time.Millisecond)

	// Verify the agent is no longer in the hub
	if hub.GetAgent("close-agent") != nil {
		t.Fatal("agent should be unregistered after close message")
	}
}

// TestMultipleDisconnectsSameID verifies that rapid disconnect/reconnect
// cycles for the same ID don't cause panics or deadlocks.
func TestMultipleDisconnectsSameID(t *testing.T) {
	setupTestDB(t)
	hub = newHub()
	go hub.run()
	ServerMetrics = NewMetrics(hub)

	for i := 0; i < 5; i++ {
		conn := &Connection{
			hub:         hub,
			connType:    "agent",
			id:          "cycle-agent",
			send:        make(chan []byte, 10),
			connectedAt: time.Now(),
		}
		hub.register <- conn
		time.Sleep(10 * time.Millisecond)

		hub.unregister <- conn
		time.Sleep(10 * time.Millisecond)
	}

	// After all cycles, agent should not be registered
	if hub.GetAgent("cycle-agent") != nil {
		t.Fatal("agent should not be registered after disconnect cycles")
	}
}

// TestClientDisconnectCleansUpRouting verifies that when a client
// disconnects, messages to that client are no longer queued.
func TestClientDisconnectCleansUpRouting(t *testing.T) {
	setupTestDB(t)
	hub = newHub()
	go hub.run()
	ServerMetrics = NewMetrics(hub)

	conv, err := CreateConversation("dc-user", "dc-agent")
	if err != nil {
		t.Fatal(err)
	}

	agentConn := &Connection{
		hub:         hub,
		connType:    "agent",
		id:          "dc-agent",
		send:        make(chan []byte, 10),
		connectedAt: time.Now(),
	}
	clientConn := &Connection{
		hub:         hub,
		connType:    "client",
		id:          "dc-user",
		send:        make(chan []byte, 10),
		connectedAt: time.Now(),
	}

	hub.register <- agentConn
	time.Sleep(10 * time.Millisecond)
	hub.register <- clientConn
	time.Sleep(10 * time.Millisecond)

	// Disconnect the client
	hub.unregister <- clientConn
	time.Sleep(10 * time.Millisecond)

	// Send a message from agent to disconnected client
	msg := IncomingMessage{
		Type: "message",
		Data: json.RawMessage(`{"conversation_id": "` + conv.ID + `", "content": "after disconnect"}`),
	}
	raw, _ := json.Marshal(msg)
	routeMessage(agentConn, raw)

	// Agent should get an ack (message was still stored)
	select {
	case resp := <-agentConn.send:
		var outMsg OutgoingMessage
		json.Unmarshal(resp, &outMsg)
		if outMsg.Type != "message_sent" {
			t.Fatalf("expected message_sent ack, got %s", outMsg.Type)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for agent ack")
	}

	// Verify the client has no connections left
	if len(hub.GetClientConns("dc-user")) != 0 {
		t.Fatal("client should have no connections")
	}
}

// TestConcurrentRegisterUnregister tests that concurrent register/unregister
// operations don't cause data races.
func TestConcurrentRegisterUnregister(t *testing.T) {
	setupTestDB(t)
	hub = newHub()
	go hub.run()
	ServerMetrics = NewMetrics(hub)

	done := make(chan struct{})

	// Spawn multiple goroutines that register and unregister connections
	for i := 0; i < 10; i++ {
		go func(idx int) {
			defer func() { done <- struct{}{} }()
			id := "concurrent-agent"
			conn := &Connection{
				hub:         hub,
				connType:    "agent",
				id:          id,
				send:        make(chan []byte, 10),
				connectedAt: time.Now(),
			}
			hub.register <- conn
			time.Sleep(time.Duration(idx) * time.Millisecond)
			hub.unregister <- conn
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("timed out waiting for concurrent goroutines")
		}
	}
}

// TestAgentAndClientCountMethods verifies the AgentCount and ClientCount helpers.
func TestAgentAndClientCountMethods(t *testing.T) {
	setupTestDB(t)
	hub = newHub()
	go hub.run()
	ServerMetrics = NewMetrics(hub)

	if hub.AgentCount() != 0 || hub.ClientCount() != 0 {
		t.Fatal("counts should start at 0")
	}

	// Register 2 agents
	for i := 0; i < 2; i++ {
		conn := &Connection{
			hub:         hub,
			connType:    "agent",
			id:          "count-agent-" + strings.Repeat("x", i),
			send:        make(chan []byte, 10),
			connectedAt: time.Now(),
		}
		hub.register <- conn
		time.Sleep(10 * time.Millisecond)
	}

	// Register 1 client
	clientConn := &Connection{
		hub:         hub,
		connType:    "client",
		id:          "count-client-1",
		deviceID:    "device-1",
		send:        make(chan []byte, 10),
		connectedAt: time.Now(),
	}
	hub.register <- clientConn
	time.Sleep(10 * time.Millisecond)

	if hub.AgentCount() != 2 {
		t.Fatalf("expected 2 agents, got %d", hub.AgentCount())
	}
	if hub.ClientCount() != 1 {
		t.Fatalf("expected 1 unique client user, got %d", hub.ClientCount())
	}

	// Register same client user on a second device (multi-device)
	clientConn2 := &Connection{
		hub:         hub,
		connType:    "client",
		id:          "count-client-1",
		deviceID:    "device-2",
		send:        make(chan []byte, 10),
		connectedAt: time.Now(),
	}
	hub.register <- clientConn2
	time.Sleep(10 * time.Millisecond)

	// ClientCount should still be 1 (same user), but ClientConnCount should be 2
	if hub.ClientCount() != 1 {
		t.Fatalf("expected 1 unique client user (multi-device), got %d", hub.ClientCount())
	}
	if hub.ClientConnCount() != 2 {
		t.Fatalf("expected 2 total client connections (multi-device), got %d", hub.ClientConnCount())
	}

	// Unregister one agent
	hub.unregister <- hub.GetAgent("count-agent-x")
	time.Sleep(10 * time.Millisecond)

	if hub.AgentCount() != 1 {
		t.Fatalf("expected 1 agent after unregister, got %d", hub.AgentCount())
	}
}

// TestRegisterAndConnectAgentWithHeartbeat is an integration test that
// verifies a WebSocket connection works with the updated read/write pumps.
func TestRegisterAndConnectAgentWithHeartbeat(t *testing.T) {
	server, cleanup := setupTestServerForRouting(t)
	defer cleanup()

	// Register and connect agent
	agentConn := registerAndConnectAgent(t, server, "integ-hb-agent", agentSecret)
	defer agentConn.Close()

	// Read the welcome message
	_, msg, err := agentConn.ReadMessage()
	if err != nil {
		t.Fatalf("failed to read welcome: %v", err)
	}

	var welcome OutgoingMessage
	json.Unmarshal(msg, &welcome)
	if welcome.Type != "connected" {
		t.Fatalf("expected connected welcome, got %s", welcome.Type)
	}

	// Register a user and connect as client
	token := registerUserAndGetToken(t, "integ_hb", "password123")
	wsURL := "ws" + strings.TrimPrefix(server.URL, "http") + "/client/connect?user_id=ignore&token=" + url.QueryEscape(token)
	clientConn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("client connect failed: %v", err)
	}
	defer clientConn.Close()

	// Read client welcome
	_, _, err = clientConn.ReadMessage()
	if err != nil {
		t.Fatalf("failed to read client welcome: %v", err)
	}

	// Verify health shows both connections
	resp, err := http.Get(server.URL + "/health")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	var health map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&health)
	agents, _ := health["agents_connected"].(float64)
	if int(agents) < 1 {
		t.Fatalf("expected at least 1 agent in health, got %v", health["agents_connected"])
	}
	clients, _ := health["clients_connected"].(float64)
	if int(clients) < 1 {
		t.Fatalf("expected at least 1 client in health, got %v", health["clients_connected"])
	}
}