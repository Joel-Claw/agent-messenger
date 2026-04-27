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

// setupHeartbeatTestServer creates a test server for heartbeat tests
func setupHeartbeatTestServer(t *testing.T) (*httptest.Server, func()) {
	t.Helper()
	setupTestDB(t)

	// Set a known agent secret for testing
	agentSecret = "test-heartbeat-secret"

	hub = newHub()
	go hub.run()

	ServerMetrics = NewMetrics(hub)

	mux := http.NewServeMux()
	mux.HandleFunc("/agent/connect", handleAgentConnect)
	mux.HandleFunc("/client/connect", handleClientConnect)
	mux.HandleFunc("/health", handleHealth)
	mux.HandleFunc("/auth/login", handleLogin)
	mux.HandleFunc("/auth/agent", handleRegisterAgent)
	mux.HandleFunc("/auth/user", handleRegisterUser)
	mux.HandleFunc("/conversations/create", handleCreateConversation)
	mux.HandleFunc("/conversations/list", handleListConversations)
	mux.HandleFunc("/conversations/messages", handleGetMessages)
	mux.HandleFunc("/agents", handleListAgents)
	mux.HandleFunc("/admin/agents", handleAdminAgents)
	mux.HandleFunc("/metrics", handleMetrics)

	server := httptest.NewServer(mux)
	cleanup := func() {
		server.Close()
		hub.Stop()
	}
	return server, cleanup
}

// connectHeartbeatAgent registers and connects an agent via WebSocket for heartbeat tests
func connectHeartbeatAgent(t *testing.T, server *httptest.Server, agentID string) *websocket.Conn {
	t.Helper()

	// Pre-register the agent
	form := url.Values{}
	form.Set("agent_id", agentID)
	form.Set("name", "Agent "+agentID)
	form.Set("agent_secret", agentSecret)

	req := httptest.NewRequest(http.MethodPost, "/auth/agent", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Agent-Secret", agentSecret)
	w := httptest.NewRecorder()
	handleRegisterAgent(w, req)
	if w.Code != http.StatusOK && w.Code != http.StatusConflict {
		t.Fatalf("register agent failed: %d %s", w.Code, w.Body.String())
	}

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http") + "/agent/connect?agent_id=" + agentID + "&agent_secret=" + url.QueryEscape(agentSecret)
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("agent connect failed: %v", err)
	}
	return conn
}

// connectHeartbeatClient registers and connects a client via WebSocket for heartbeat tests
func connectHeartbeatClient(t *testing.T, server *httptest.Server, username, password string) *websocket.Conn {
	t.Helper()
	token := registerUserAndGetToken(t, username, password)

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http") + "/client/connect?user_id=" + username + "&token=" + url.QueryEscape(token)
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("client connect failed: %v", err)
	}
	return conn
}

// readMessageOfType reads WebSocket messages until finding one of the given type
func readMessageOfType(t *testing.T, ws *websocket.Conn, msgType string, timeout time.Duration) (OutgoingMessage, bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	ws.SetReadDeadline(deadline)
	defer ws.SetReadDeadline(time.Time{})

	for time.Now().Before(deadline) {
		_, raw, err := ws.ReadMessage()
		if err != nil {
			return OutgoingMessage{}, false
		}
		var msg OutgoingMessage
		if err := json.Unmarshal(raw, &msg); err != nil {
			continue
		}
		if msg.Type == msgType {
			return msg, true
		}
	}
	return OutgoingMessage{}, false
}

// TestHeartbeatMessage tests that an agent can send a heartbeat message
// and receives a heartbeat_ack response.
func TestHeartbeatMessage(t *testing.T) {
	server, cleanup := setupHeartbeatTestServer(t)
	defer cleanup()

	ws := connectHeartbeatAgent(t, server, "hb-agent")
	defer ws.Close()

	// Send heartbeat message
	heartbeat := IncomingMessage{Type: "heartbeat", Data: json.RawMessage(`{}`)}
	data, err := json.Marshal(heartbeat)
	if err != nil {
		t.Fatalf("Failed to marshal heartbeat: %v", err)
	}
	if err := ws.WriteMessage(websocket.TextMessage, data); err != nil {
		t.Fatalf("Failed to send heartbeat: %v", err)
	}

	// Read heartbeat_ack
	msg, found := readMessageOfType(t, ws, "heartbeat_ack", 3*time.Second)
	if !found {
		t.Fatal("Timed out waiting for heartbeat_ack")
	}

	dataMap, ok := msg.Data.(map[string]interface{})
	if !ok {
		t.Fatal("heartbeat_ack data is not a map")
	}
	if _, ok := dataMap["server_time"]; !ok {
		t.Error("heartbeat_ack missing server_time")
	}
	if _, ok := dataMap["interval_s"]; !ok {
		t.Error("heartbeat_ack missing interval_s")
	}
	if _, ok := dataMap["timeout_s"]; !ok {
		t.Error("heartbeat_ack missing timeout_s")
	}
	if _, ok := dataMap["monitoring"]; !ok {
		t.Error("heartbeat_ack missing monitoring")
	}
}

// TestHeartbeatUpdatesTimestamp tests that sending a heartbeat
// updates the agent's lastHeartbeat field in the hub.
func TestHeartbeatUpdatesTimestamp(t *testing.T) {
	server, cleanup := setupHeartbeatTestServer(t)
	defer cleanup()

	ws := connectHeartbeatAgent(t, server, "hb-ts-agent")
	defer ws.Close()

	time.Sleep(100 * time.Millisecond)

	// Get initial heartbeat timestamp
	hub.mu.RLock()
	conn := hub.agents["hb-ts-agent"]
	hub.mu.RUnlock()
	if conn == nil {
		t.Fatal("Agent not found in hub")
	}
	initialHeartbeat := conn.lastHeartbeat

	// Wait and send heartbeat
	time.Sleep(50 * time.Millisecond)
	heartbeat := IncomingMessage{Type: "heartbeat", Data: json.RawMessage(`{}`)}
	data, _ := json.Marshal(heartbeat)
	ws.WriteMessage(websocket.TextMessage, data)

	// Wait for ack to be processed
	readMessageOfType(t, ws, "heartbeat_ack", 3*time.Second)

	// Verify timestamp was updated
	hub.mu.RLock()
	conn = hub.agents["hb-ts-agent"]
	hub.mu.RUnlock()
	if conn == nil {
		t.Fatal("Agent connection lost")
	}
	if !conn.lastHeartbeat.After(initialHeartbeat) {
		t.Errorf("Expected lastHeartbeat after initial; initial=%v, updated=%v", initialHeartbeat, conn.lastHeartbeat)
	}
}

// TestClientHeartbeat tests that clients can also send heartbeats
// and receive a heartbeat_ack (even though clients aren't monitored for staleness).
func TestClientHeartbeat(t *testing.T) {
	server, cleanup := setupHeartbeatTestServer(t)
	defer cleanup()

	ws := connectHeartbeatClient(t, server, "hbclient", "password123")
	defer ws.Close()

	// Send heartbeat from client
	heartbeat := IncomingMessage{Type: "heartbeat", Data: json.RawMessage(`{}`)}
	data, _ := json.Marshal(heartbeat)
	ws.WriteMessage(websocket.TextMessage, data)

	msg, found := readMessageOfType(t, ws, "heartbeat_ack", 3*time.Second)
	if !found {
		t.Fatal("Timed out waiting for heartbeat_ack from client heartbeat")
	}
	dataMap := msg.Data.(map[string]interface{})
	if dataMap["monitoring"].(bool) != agentPresenceEnabled {
		t.Logf("monitoring field = %v (expected: %v)", dataMap["monitoring"], agentPresenceEnabled)
	}
}

// TestStaleAgentDisconnected tests that an agent that hasn't sent a heartbeat
// within the timeout period gets disconnected by the monitor.
func TestStaleAgentDisconnected(t *testing.T) {
	origEnabled := agentPresenceEnabled
	origInterval := agentPresenceInterval
	origTimeout := agentPresenceTimeout

	agentPresenceEnabled = true
	agentPresenceInterval = 100 * time.Millisecond
	agentPresenceTimeout = 300 * time.Millisecond

	setupTestDB(t)
	agentSecret = "test-heartbeat-secret"

	hub = newHub()
	go hub.run()
	ServerMetrics = NewMetrics(hub)

	mux := http.NewServeMux()
	mux.HandleFunc("/agent/connect", handleAgentConnect)
	mux.HandleFunc("/health", handleHealth)
	mux.HandleFunc("/auth/agent", handleRegisterAgent)

	server := httptest.NewServer(mux)
	t.Cleanup(func() {
		server.Close()
	})

	// Start the monitor goroutine
	go hub.monitorAgentHeartbeats()

	ws := connectHeartbeatAgent(t, server, "stale-agent")
	defer ws.Close()

	// Verify agent is connected
	time.Sleep(50 * time.Millisecond)
	hub.mu.RLock()
	_, ok := hub.agents["stale-agent"]
	hub.mu.RUnlock()
	if !ok {
		t.Fatal("Agent should be connected initially")
	}

	// Don't send any heartbeats — wait for timeout
	time.Sleep(800 * time.Millisecond)

	// Agent should be disconnected
	hub.mu.RLock()
	_, stillConnected := hub.agents["stale-agent"]
	staleCount := hub.staleAgents
	hub.mu.RUnlock()

	if stillConnected {
		t.Error("Stale agent should have been disconnected")
	}
	if staleCount == 0 {
		t.Error("Expected staleAgents counter to be incremented")
	}

	// Stop hub and restore
	hub.Stop()
	agentPresenceEnabled = origEnabled
	agentPresenceInterval = origInterval
	agentPresenceTimeout = origTimeout
}

// TestAgentWithHeartbeatStaysConnected tests that an agent sending
// regular heartbeats stays connected even with monitoring enabled.
func TestAgentWithHeartbeatStaysConnected(t *testing.T) {
	origEnabled := agentPresenceEnabled
	origInterval := agentPresenceInterval
	origTimeout := agentPresenceTimeout

	agentPresenceEnabled = true
	agentPresenceInterval = 100 * time.Millisecond
	agentPresenceTimeout = 300 * time.Millisecond

	setupTestDB(t)
	agentSecret = "test-heartbeat-secret"

	hub = newHub()
	go hub.run()
	ServerMetrics = NewMetrics(hub)

	mux := http.NewServeMux()
	mux.HandleFunc("/agent/connect", handleAgentConnect)
	mux.HandleFunc("/auth/agent", handleRegisterAgent)

	server := httptest.NewServer(mux)
	t.Cleanup(func() {
		server.Close()
	})

	go hub.monitorAgentHeartbeats()

	ws := connectHeartbeatAgent(t, server, "fresh-agent")
	defer ws.Close()

	// Send heartbeats periodically for 600ms
	elapsed := time.After(600 * time.Millisecond)
	ticker := time.NewTicker(80 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-elapsed:
			// Verify agent still connected
			hub.mu.RLock()
			_, ok := hub.agents["fresh-agent"]
			hub.mu.RUnlock()
			if !ok {
				t.Error("Agent with regular heartbeats should still be connected")
			}
			hub.Stop()
			agentPresenceEnabled = origEnabled
			agentPresenceInterval = origInterval
			agentPresenceTimeout = origTimeout
			return
		case <-ticker.C:
			heartbeat := IncomingMessage{Type: "heartbeat", Data: json.RawMessage(`{}`)}
			data, _ := json.Marshal(heartbeat)
			ws.WriteMessage(websocket.TextMessage, data)
			// Drain ack
			ws.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
			for {
				_, msg, err := ws.ReadMessage()
				if err != nil {
					break
				}
				var outMsg OutgoingMessage
				if json.Unmarshal(msg, &outMsg) == nil && outMsg.Type == "heartbeat_ack" {
					break
				}
			}
			ws.SetReadDeadline(time.Time{})
		}
	}
}

// TestHeartbeatAckContainsConfig tests that the heartbeat_ack response
// contains the correct configuration values.
func TestHeartbeatAckContainsConfig(t *testing.T) {
	origEnabled := agentPresenceEnabled
	origInterval := agentPresenceInterval
	origTimeout := agentPresenceTimeout

	agentPresenceEnabled = true
	agentPresenceInterval = 45 * time.Second
	agentPresenceTimeout = 120 * time.Second

	server, cleanup := setupHeartbeatTestServer(t)
	defer cleanup()

	ws := connectHeartbeatAgent(t, server, "hb-config-agent")
	defer ws.Close()

	heartbeat := IncomingMessage{Type: "heartbeat", Data: json.RawMessage(`{}`)}
	data, _ := json.Marshal(heartbeat)
	ws.WriteMessage(websocket.TextMessage, data)

	msg, found := readMessageOfType(t, ws, "heartbeat_ack", 3*time.Second)
	if !found {
		t.Fatal("Timed out waiting for heartbeat_ack")
	}

	dataMap := msg.Data.(map[string]interface{})
	if int(dataMap["interval_s"].(float64)) != 45 {
		t.Errorf("Expected interval_s=45, got %v", dataMap["interval_s"])
	}
	if int(dataMap["timeout_s"].(float64)) != 120 {
		t.Errorf("Expected timeout_s=120, got %v", dataMap["timeout_s"])
	}
	if dataMap["monitoring"].(bool) != true {
		t.Errorf("Expected monitoring=true, got %v", dataMap["monitoring"])
	}

	agentPresenceEnabled = origEnabled
	agentPresenceInterval = origInterval
	agentPresenceTimeout = origTimeout
}

// TestHealthEndpointIncludesHeartbeat tests that the /health endpoint
// includes agent_heartbeat configuration in its response.
func TestHealthEndpointIncludesHeartbeat(t *testing.T) {
	_, cleanup := setupHeartbeatTestServer(t)
	defer cleanup()

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()
	handleHealth(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d", w.Code)
	}

	var health map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &health); err != nil {
		t.Fatalf("Failed to parse health response: %v", err)
	}

	hb, ok := health["agent_heartbeat"].(map[string]interface{})
	if !ok {
		t.Fatal("agent_heartbeat not found in health response")
	}
	if _, ok := hb["enabled"]; !ok {
		t.Error("agent_heartbeat missing 'enabled' field")
	}
	if _, ok := hb["interval_s"]; !ok {
		t.Error("agent_heartbeat missing 'interval_s' field")
	}
	if _, ok := hb["timeout_s"]; !ok {
		t.Error("agent_heartbeat missing 'timeout_s' field")
	}
	if _, ok := hb["stale_agents"]; !ok {
		t.Error("agent_heartbeat missing 'stale_agents' field")
	}
}

// TestUnknownMessageTypeWithHeartbeat tests that unknown message types
// still return errors (heartbeat routing didn't break default case).
func TestUnknownMessageTypeWithHeartbeat(t *testing.T) {
	server, cleanup := setupHeartbeatTestServer(t)
	defer cleanup()

	ws := connectHeartbeatAgent(t, server, "msg-type-agent")
	defer ws.Close()

	// Send unknown message type
	msg := IncomingMessage{Type: "unknown_type", Data: json.RawMessage(`{}`)}
	data, _ := json.Marshal(msg)
	ws.WriteMessage(websocket.TextMessage, data)

	result, found := readMessageOfType(t, ws, "error", 3*time.Second)
	if !found {
		t.Fatal("Timed out waiting for error message")
	}
	errData := result.Data.(map[string]interface{})
	errStr := errData["error"].(string)
	if !strings.Contains(errStr, "unknown message type") {
		t.Errorf("Expected 'unknown message type' error, got: %v", errStr)
	}
}

// TestTouchHeartbeatMethod tests the TouchHeartbeat method directly.
func TestTouchHeartbeatMethod(t *testing.T) {
	server, cleanup := setupHeartbeatTestServer(t)
	defer cleanup()

	ws := connectHeartbeatAgent(t, server, "touch-agent")
	defer ws.Close()

	time.Sleep(50 * time.Millisecond)

	hub.mu.RLock()
	conn := hub.agents["touch-agent"]
	hub.mu.RUnlock()

	if conn == nil {
		t.Fatal("Agent not connected")
	}

	initialTime := conn.lastHeartbeat
	time.Sleep(50 * time.Millisecond)

	hub.TouchHeartbeat(conn)

	hub.mu.RLock()
	conn = hub.agents["touch-agent"]
	hub.mu.RUnlock()

	if conn.lastHeartbeat.Before(initialTime) {
		t.Errorf("lastHeartbeat should not go backwards: initial=%v, updated=%v", initialTime, conn.lastHeartbeat)
	}
}

// TestStaleAgentCountIncrements tests that the stale agent counter increments
// when checkStaleAgents disconnects an agent.
func TestStaleAgentCountIncrements(t *testing.T) {
	origEnabled := agentPresenceEnabled
	origInterval := agentPresenceInterval
	origTimeout := agentPresenceTimeout

	agentPresenceEnabled = true
	agentPresenceInterval = 100 * time.Millisecond
	agentPresenceTimeout = 300 * time.Millisecond

	setupTestDB(t)
	agentSecret = "test-heartbeat-secret"

	hub = newHub()
	go hub.run()
	ServerMetrics = NewMetrics(hub)

	mux := http.NewServeMux()
	mux.HandleFunc("/agent/connect", handleAgentConnect)
	mux.HandleFunc("/auth/agent", handleRegisterAgent)

	server := httptest.NewServer(mux)
	t.Cleanup(func() {
		server.Close()
		hub.Stop()
	})

	initialCount := hub.StaleAgentCount()

	ws := connectHeartbeatAgent(t, server, "stale-count-agent")
	defer ws.Close()

	time.Sleep(50 * time.Millisecond)

	// Set heartbeat to long ago to simulate staleness
	hub.mu.Lock()
	if conn, ok := hub.agents["stale-count-agent"]; ok {
		conn.lastHeartbeat = time.Now().Add(-5 * time.Minute)
	}
	hub.mu.Unlock()

	// Run stale check
	hub.checkStaleAgents()

	// Wait for unregister to be processed
	time.Sleep(100 * time.Millisecond)

	count := hub.StaleAgentCount()
	if count <= initialCount {
		t.Errorf("Expected stale agent count to increase, initial=%d, current=%d", initialCount, count)
	}

	agentPresenceEnabled = origEnabled
	agentPresenceInterval = origInterval
	agentPresenceTimeout = origTimeout
}

// TestHeartbeatDisabledByDefault tests that heartbeat monitoring is disabled
// by default (AGENT_HEARTBEAT_ENABLED not set).
func TestHeartbeatDisabledByDefault(t *testing.T) {
	server, cleanup := setupHeartbeatTestServer(t)
	defer cleanup()

	ws := connectHeartbeatAgent(t, server, "default-hb-agent")
	defer ws.Close()

	// Even when disabled, heartbeat messages should still work (ack responds with monitoring=false)
	heartbeat := IncomingMessage{Type: "heartbeat", Data: json.RawMessage(`{}`)}
	data, _ := json.Marshal(heartbeat)
	ws.WriteMessage(websocket.TextMessage, data)

	msg, found := readMessageOfType(t, ws, "heartbeat_ack", 3*time.Second)
	if !found {
		t.Fatal("heartbeat_ack should still be sent when monitoring is disabled")
	}

	dataMap := msg.Data.(map[string]interface{})
	if dataMap["monitoring"].(bool) != false {
		t.Errorf("Expected monitoring=false when disabled, got %v", dataMap["monitoring"])
	}
}

// TestCheckStaleAgentsNoStale tests that checkStaleAgents doesn't disconnect
// agents that have recent heartbeats.
func TestCheckStaleAgentsNoStale(t *testing.T) {
	server, cleanup := setupHeartbeatTestServer(t)
	defer cleanup()

	ws := connectHeartbeatAgent(t, server, "fresh-check-agent")
	defer ws.Close()

	time.Sleep(50 * time.Millisecond)

	// Agent just connected, heartbeat should be fresh
	hub.checkStaleAgents()

	hub.mu.RLock()
	_, ok := hub.agents["fresh-check-agent"]
	staleCount := hub.staleAgents
	hub.mu.RUnlock()

	if !ok {
		t.Error("Fresh agent should not be disconnected")
	}
	if staleCount != 0 {
		t.Errorf("Expected 0 stale agents, got %d", staleCount)
	}
}