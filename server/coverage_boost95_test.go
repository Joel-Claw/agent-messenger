package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"golang.org/x/crypto/bcrypt"
)

// ==============================
// CB95: WebSocket Integration Tests for handleAgentConnect, handleClientConnect,
// readPump, writePump, and main() subprocess testing.
// ==============================

// setupTestServer_CB95 creates a full test HTTP server with WebSocket endpoints,
// real hub, in-memory DB, and proper cleanup. Returns the server URL.
func setupTestServer_CB95(t *testing.T) *httptest.Server {
	t.Helper()

	// Reset global state
	agentSecretMu.Lock()
	origSecret := agentSecret
	agentSecret = getAgentSecret()
	agentSecretMu.Unlock()
	t.Cleanup(func() {
		agentSecretMu.Lock()
		agentSecret = origSecret
		agentSecretMu.Unlock()
	})

	origPresence := agentPresenceEnabled
	agentPresenceEnabled = false
	t.Cleanup(func() { agentPresenceEnabled = origPresence })

	messageRateLimiter = NewRateLimiter(60, time.Minute)
	t.Cleanup(func() { messageRateLimiter.Stop() })
	userRateLimiter = NewRateLimiter(120, time.Minute)
	t.Cleanup(func() { userRateLimiter.Stop() })
	globalTieredLimiter = NewTieredRateLimiter()
	t.Cleanup(func() { globalTieredLimiter.Stop() })
	ipRateLimiter = NewRateLimiter(300, time.Minute)
	t.Cleanup(func() { ipRateLimiter.Stop() })
	authIPLimiter = NewRateLimiter(30, time.Minute)
	t.Cleanup(func() { authIPLimiter.Stop() })
	agentRateLimiter.Reset()

	// In-memory DB
	var err error
	db, err = sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1) // SQLite doesn't handle concurrent writes well
	t.Cleanup(func() { db.Close() })
	if err := initSchema(db); err != nil {
		t.Fatal(err)
	}
	currentDriver = DriverSQLite

	// Hub
	hub = newHub()
	go hub.run()
	ServerMetrics = NewMetrics(hub)

	mux := http.NewServeMux()
	mux.HandleFunc("/agent/connect", handleAgentConnect)
	mux.HandleFunc("/client/connect", handleClientConnect)
	mux.HandleFunc("/health", handleHealth)
	mux.HandleFunc("/auth/login", handleLogin)
	mux.HandleFunc("/auth/user", handleRegisterUser)
	mux.HandleFunc("/agents", handleListAgents)

	server := httptest.NewServer(mux)
	t.Cleanup(func() {
		// 1. Close the HTTP server (stops accepting new connections)
		server.Close()
		// 2. Force-close all WebSocket connections tracked by the hub.
		//    This causes readPump to exit its read loop and send to unregister.
		hub.mu.Lock()
		for _, c := range hub.agents {
			c.MarkClosed()
			c.conn.Close()
		}
		for _, conns := range hub.clientConns {
			for _, c := range conns {
				c.MarkClosed()
				c.conn.Close()
			}
		}
		hub.mu.Unlock()
		// 3. Wait for readPump goroutines to finish unregistering.
		time.Sleep(200 * time.Millisecond)
		// 4. Now safe to stop the hub.
		hub.Stop()
	})

	return server
}

// ==============================
// handleAgentConnect — WebSocket integration tests
// ==============================

func TestCB95_AgentConnect_MissingAgentID(t *testing.T) {
	server := setupTestServer_CB95(t)
	wsURL := strings.Replace(server.URL, "http://", "ws://", 1) + "/agent/connect"
	resp, err := http.Get(server.URL + "/agent/connect")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400 for missing agent_id, got %d", resp.StatusCode)
	}
	_ = wsURL // URL built for reference
}

func TestCB95_AgentConnect_MissingSecret(t *testing.T) {
	server := setupTestServer_CB95(t)
	resp, err := http.Get(server.URL + "/agent/connect?agent_id=test-agent")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401 for missing agent_secret, got %d", resp.StatusCode)
	}
}

func TestCB95_AgentConnect_WrongSecret(t *testing.T) {
	server := setupTestServer_CB95(t)
	resp, err := http.Get(server.URL + "/agent/connect?agent_id=test-agent&agent_secret=wrong")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401 for wrong agent_secret, got %d", resp.StatusCode)
	}
}

func TestCB95_AgentConnect_Success(t *testing.T) {
	server := setupTestServer_CB95(t)
	wsURL := strings.Replace(server.URL, "http://", "ws://", 1) + "/agent/connect?agent_id=int-agent-1&agent_secret=" + getAgentSecret_CB95()

	dialer := websocket.Dialer{}
	ws, resp, err := dialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("dial failed: %v (resp: %v)", err, resp)
	}
	defer ws.Close()

	// Should receive a welcome/connected message
	_, msg, err := ws.ReadMessage()
	if err != nil {
		t.Fatalf("read welcome: %v", err)
	}

	var welcome OutgoingMessage
	if err := json.Unmarshal(msg, &welcome); err != nil {
		t.Fatalf("unmarshal welcome: %v", err)
	}
	if welcome.Type != "connected" {
		t.Errorf("expected type 'connected', got '%s'", welcome.Type)
	}

	// Verify agent is registered in hub
	time.Sleep(50 * time.Millisecond)
	hub.mu.RLock()
	conn := hub.agents["int-agent-1"]
	hub.mu.RUnlock()
	if conn == nil {
		t.Error("agent should be registered in hub")
	}

	// Clean disconnect
	ws.Close()
	time.Sleep(100 * time.Millisecond)

	hub.mu.RLock()
	_, exists := hub.agents["int-agent-1"]
	hub.mu.RUnlock()
	if exists {
		t.Error("agent should be unregistered after disconnect")
	}
}

func TestCB95_AgentConnect_WithMetadata(t *testing.T) {
	server := setupTestServer_CB95(t)
	secret := getAgentSecret_CB95()
	wsURL := strings.Replace(server.URL, "http://", "ws://", 1) +
		"/agent/connect?agent_id=meta-agent&agent_secret=" + secret +
		"&name=MetaAgent&model=gpt-4&personality=helpful&specialty=coding"

	dialer := websocket.Dialer{}
	ws, _, err := dialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}
	defer ws.Close()

	// Read welcome
	_, _, err = ws.ReadMessage()
	if err != nil {
		t.Fatalf("read welcome: %v", err)
	}

	time.Sleep(50 * time.Millisecond)

	// Verify agent metadata in DB
	var name, model, personality, specialty string
	err = db.QueryRow("SELECT name, model, personality, specialty FROM agents WHERE id = ?", "meta-agent").
		Scan(&name, &model, &personality, &specialty)
	if err != nil {
		t.Fatalf("query agent: %v", err)
	}
	if name != "MetaAgent" {
		t.Errorf("expected name 'MetaAgent', got '%s'", name)
	}
	if model != "gpt-4" {
		t.Errorf("expected model 'gpt-4', got '%s'", model)
	}
	if personality != "helpful" {
		t.Errorf("expected personality 'helpful', got '%s'", personality)
	}
	if specialty != "coding" {
		t.Errorf("expected specialty 'coding', got '%s'", specialty)
	}
}

func TestCB95_AgentConnect_ProtocolNegotiation(t *testing.T) {
	server := setupTestServer_CB95(t)
	secret := getAgentSecret_CB95()
	wsURL := strings.Replace(server.URL, "http://", "ws://", 1) +
		"/agent/connect?agent_id=proto-agent&agent_secret=" + secret

	dialer := websocket.Dialer{
		Subprotocols: []string{"v1"},
	}
	ws, resp, err := dialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}
	defer ws.Close()

	if resp.Header.Get("Sec-WebSocket-Protocol") != "v1" {
		t.Errorf("expected Sec-WebSocket-Protocol 'v1', got '%s'", resp.Header.Get("Sec-WebSocket-Protocol"))
	}

	// Read welcome and verify protocol_version
	_, msg, err := ws.ReadMessage()
	if err != nil {
		t.Fatalf("read welcome: %v", err)
	}
	var welcome OutgoingMessage
	json.Unmarshal(msg, &welcome)
	data, ok := welcome.Data.(map[string]interface{})
	if !ok {
		t.Fatal("welcome data is not a map")
	}
	if data["protocol_version"] != "v1" {
		t.Errorf("expected protocol_version 'v1', got '%v'", data["protocol_version"])
	}
}

func TestCB95_AgentConnect_RateLimited(t *testing.T) {
	server := setupTestServer_CB95(t)
	// Make many failed connection attempts to trigger rate limiting
	for i := 0; i < 15; i++ {
		resp, err := http.Get(server.URL + "/agent/connect?agent_id=rate-agent&agent_secret=wrong")
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode == http.StatusTooManyRequests {
			// Rate limit hit
			return
		}
	}
	t.Error("expected rate limiting to kick in after 15 failed attempts")
}

func TestCB95_AgentConnect_HeartbeatMessage(t *testing.T) {
	server := setupTestServer_CB95(t)
	secret := getAgentSecret_CB95()
	wsURL := strings.Replace(server.URL, "http://", "ws://", 1) +
		"/agent/connect?agent_id=hb-agent&agent_secret=" + secret

	dialer := websocket.Dialer{}
	ws, _, err := dialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}
	defer ws.Close()

	// Read welcome
	_, _, err = ws.ReadMessage()
	if err != nil {
		t.Fatalf("read welcome: %v", err)
	}

	// Send heartbeat
	err = ws.WriteMessage(websocket.TextMessage, []byte(`{"type":"heartbeat"}`))
	if err != nil {
		t.Fatalf("write heartbeat: %v", err)
	}

	time.Sleep(100 * time.Millisecond)

	// Verify messagesRouted counter incremented
	if hub.messagesRouted.Load() < 1 {
		t.Error("expected messagesRouted to be incremented after heartbeat")
	}
}

func TestCB95_AgentConnect_InvalidJSON(t *testing.T) {
	server := setupTestServer_CB95(t)
	secret := getAgentSecret_CB95()
	wsURL := strings.Replace(server.URL, "http://", "ws://", 1) +
		"/agent/connect?agent_id=badjson-agent&agent_secret=" + secret

	dialer := websocket.Dialer{}
	ws, _, err := dialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}
	defer ws.Close()

	// Read welcome
	_, _, err = ws.ReadMessage()
	if err != nil {
		t.Fatalf("read welcome: %v", err)
	}

	// Send invalid JSON
	err = ws.WriteMessage(websocket.TextMessage, []byte(`{invalid json`))
	if err != nil {
		t.Fatalf("write invalid json: %v", err)
	}

	time.Sleep(100 * time.Millisecond)
	// Connection should still be alive (invalid JSON is handled gracefully)
}

// ==============================
// handleClientConnect — WebSocket integration tests
// ==============================

func TestCB95_ClientConnect_MissingToken(t *testing.T) {
	server := setupTestServer_CB95(t)
	resp, err := http.Get(server.URL + "/client/connect")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401 for missing token, got %d", resp.StatusCode)
	}
}

func TestCB95_ClientConnect_InvalidToken(t *testing.T) {
	server := setupTestServer_CB95(t)
	resp, err := http.Get(server.URL + "/client/connect?token=invalidjwt")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401 for invalid token, got %d", resp.StatusCode)
	}
}

func TestCB95_ClientConnect_Success(t *testing.T) {
	server := setupTestServer_CB95(t)

	// Register a user and get JWT
	userID := registerTestUser_CB95(t, "ws-client-user")
	token := generateTestJWT_CB95(t, userID)

	wsURL := strings.Replace(server.URL, "http://", "ws://", 1) +
		"/client/connect?token=" + token

	dialer := websocket.Dialer{}
	ws, _, err := dialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}
	defer ws.Close()

	// Read welcome
	_, msg, err := ws.ReadMessage()
	if err != nil {
		t.Fatalf("read welcome: %v", err)
	}

	var welcome OutgoingMessage
	if err := json.Unmarshal(msg, &welcome); err != nil {
		t.Fatalf("unmarshal welcome: %v", err)
	}
	if welcome.Type != "connected" {
		t.Errorf("expected type 'connected', got '%s'", welcome.Type)
	}

	// Verify client is registered in hub
	time.Sleep(50 * time.Millisecond)
	hub.mu.RLock()
	conns := hub.clientConns[userID]
	hub.mu.RUnlock()
	if len(conns) == 0 {
		t.Error("client should be registered in hub")
	}

	// Disconnect
	ws.Close()
	time.Sleep(100 * time.Millisecond)

	hub.mu.RLock()
	conns = hub.clientConns[userID]
	hub.mu.RUnlock()
	if len(conns) != 0 {
		t.Error("client should be unregistered after disconnect")
	}
}

func TestCB95_ClientConnect_WithDeviceID(t *testing.T) {
	server := setupTestServer_CB95(t)

	userID := registerTestUser_CB95(t, "device-user")
	token := generateTestJWT_CB95(t, userID)

	wsURL := strings.Replace(server.URL, "http://", "ws://", 1) +
		"/client/connect?token=" + token + "&device_id=phone-123"

	dialer := websocket.Dialer{}
	ws, _, err := dialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}
	defer ws.Close()

	// Read welcome and verify device_id
	_, msg, err := ws.ReadMessage()
	if err != nil {
		t.Fatalf("read welcome: %v", err)
	}

	var welcome OutgoingMessage
	json.Unmarshal(msg, &welcome)
	data, ok := welcome.Data.(map[string]interface{})
	if !ok {
		t.Fatal("welcome data is not a map")
	}
	if data["device_id"] != "phone-123" {
		t.Errorf("expected device_id 'phone-123', got '%v'", data["device_id"])
	}
}

func TestCB95_ClientConnect_MultiDevice(t *testing.T) {
	server := setupTestServer_CB95(t)

	userID := registerTestUser_CB95(t, "multi-device-user")
	token := generateTestJWT_CB95(t, userID)

	// Connect device 1
	wsURL1 := strings.Replace(server.URL, "http://", "ws://", 1) +
		"/client/connect?token=" + token + "&device_id=device-1"
	dialer := websocket.Dialer{}
	ws1, _, err := dialer.Dial(wsURL1, nil)
	if err != nil {
		t.Fatalf("dial device 1: %v", err)
	}
	defer ws1.Close()
	_, _, _ = ws1.ReadMessage() // welcome

	// Connect device 2
	wsURL2 := strings.Replace(server.URL, "http://", "ws://", 1) +
		"/client/connect?token=" + token + "&device_id=device-2"
	ws2, _, err := dialer.Dial(wsURL2, nil)
	if err != nil {
		t.Fatalf("dial device 2: %v", err)
	}
	defer ws2.Close()
	_, _, _ = ws2.ReadMessage() // welcome

	time.Sleep(50 * time.Millisecond)

	// Both connections should be registered
	hub.mu.RLock()
	conns := hub.clientConns[userID]
	hub.mu.RUnlock()
	if len(conns) != 2 {
		t.Errorf("expected 2 client connections, got %d", len(conns))
	}

	// Disconnect device 1 — device 2 should remain
	ws1.Close()
	time.Sleep(100 * time.Millisecond)

	hub.mu.RLock()
	conns = hub.clientConns[userID]
	hub.mu.RUnlock()
	if len(conns) != 1 {
		t.Errorf("expected 1 client connection after device 1 disconnect, got %d", len(conns))
	}
}

func TestCB95_ClientConnect_SameDeviceReconnect(t *testing.T) {
	server := setupTestServer_CB95(t)

	userID := registerTestUser_CB95(t, "reconnect-user")
	token := generateTestJWT_CB95(t, userID)

	wsURL := strings.Replace(server.URL, "http://", "ws://", 1) +
		"/client/connect?token=" + token + "&device_id=same-device"

	dialer := websocket.Dialer{}

	// First connection
	ws1, _, err := dialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("dial 1: %v", err)
	}
	_, _, _ = ws1.ReadMessage() // welcome
	time.Sleep(50 * time.Millisecond)

	// Second connection with same device_id
	ws2, _, err := dialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("dial 2: %v", err)
	}
	defer ws2.Close()
	_, _, _ = ws2.ReadMessage() // welcome
	time.Sleep(50 * time.Millisecond)

	// Should have 1 connection (same device replaces, not duplicates)
	hub.mu.RLock()
	conns := hub.clientConns[userID]
	hub.mu.RUnlock()
	if len(conns) != 1 {
		t.Errorf("expected 1 connection (same device dedup), got %d", len(conns))
	}

	ws1.Close()
	ws2.Close()
	time.Sleep(100 * time.Millisecond)
}

func TestCB95_ClientConnect_ProtocolNegotiation(t *testing.T) {
	server := setupTestServer_CB95(t)

	userID := registerTestUser_CB95(t, "proto-client-user")
	token := generateTestJWT_CB95(t, userID)

	wsURL := strings.Replace(server.URL, "http://", "ws://", 1) +
		"/client/connect?token=" + token

	dialer := websocket.Dialer{
		Subprotocols: []string{"v1"},
	}
	ws, resp, err := dialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}
	defer ws.Close()

	if resp.Header.Get("Sec-WebSocket-Protocol") != "v1" {
		t.Errorf("expected Sec-WebSocket-Protocol 'v1', got '%s'", resp.Header.Get("Sec-WebSocket-Protocol"))
	}
}

// ==============================
// readPump — WebSocket integration via real connect
// ==============================

func TestCB95_ReadPump_RoutesChatMessage(t *testing.T) {
	server := setupTestServer_CB95(t)

	// Register agent
	agentSecret := getAgentSecret_CB95()
	agentWsURL := strings.Replace(server.URL, "http://", "ws://", 1) +
		"/agent/connect?agent_id=route-agent&agent_secret=" + agentSecret
	dialer := websocket.Dialer{}
	agentWs, _, err := dialer.Dial(agentWsURL, nil)
	if err != nil {
		t.Fatalf("agent dial: %v", err)
	}
	defer agentWs.Close()
	_, _, _ = agentWs.ReadMessage() // welcome

	// Register user and connect client
	userID := registerTestUser_CB95(t, "route-client-user")
	token := generateTestJWT_CB95(t, userID)
	clientWsURL := strings.Replace(server.URL, "http://", "ws://", 1) +
		"/client/connect?token=" + token
	clientWs, _, err := dialer.Dial(clientWsURL, nil)
	if err != nil {
		t.Fatalf("client dial: %v", err)
	}
	defer clientWs.Close()
	_, _, _ = clientWs.ReadMessage() // welcome

	// Create conversation
	convID := createTestConversation_CB95(t, userID, "route-agent")

	time.Sleep(50 * time.Millisecond)

	// Client sends a chat message
	chatMsg := `{"type":"message","data":{"conversation_id":"` + convID + `","content":"Hello from client!"}}`
	err = clientWs.WriteMessage(websocket.TextMessage, []byte(chatMsg))
	if err != nil {
		t.Fatalf("write chat message: %v", err)
	}

	// Agent should receive the message
	_, msg, err := agentWs.ReadMessage()
	if err != nil {
		t.Fatalf("agent read: %v", err)
	}

	var received OutgoingMessage
	if err := json.Unmarshal(msg, &received); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if received.Type != "message" {
		t.Errorf("expected type 'message', got '%s'", received.Type)
	}
}

func TestCB95_ReadPump_RoutesTypingIndicator(t *testing.T) {
	server := setupTestServer_CB95(t)

	agentSecret := getAgentSecret_CB95()
	agentWsURL := strings.Replace(server.URL, "http://", "ws://", 1) +
		"/agent/connect?agent_id=typing-agent&agent_secret=" + agentSecret
	dialer := websocket.Dialer{}
	agentWs, _, err := dialer.Dial(agentWsURL, nil)
	if err != nil {
		t.Fatalf("agent dial: %v", err)
	}
	defer agentWs.Close()
	_, _, _ = agentWs.ReadMessage()

	userID := registerTestUser_CB95(t, "typing-client-user")
	token := generateTestJWT_CB95(t, userID)
	clientWsURL := strings.Replace(server.URL, "http://", "ws://", 1) +
		"/client/connect?token=" + token
	clientWs, _, err := dialer.Dial(clientWsURL, nil)
	if err != nil {
		t.Fatalf("client dial: %v", err)
	}
	defer clientWs.Close()
	_, _, _ = clientWs.ReadMessage()

	convID := createTestConversation_CB95(t, userID, "typing-agent")
	time.Sleep(50 * time.Millisecond)

	// Send typing indicator
	typingMsg := `{"type":"typing","data":{"conversation_id":"` + convID + `"}}`
	err = clientWs.WriteMessage(websocket.TextMessage, []byte(typingMsg))
	if err != nil {
		t.Fatalf("write typing: %v", err)
	}

	// Agent should receive typing indicator
	_, msg, err := agentWs.ReadMessage()
	if err != nil {
		t.Fatalf("agent read typing: %v", err)
	}

	var received OutgoingMessage
	json.Unmarshal(msg, &received)
	if received.Type != "typing" {
		t.Errorf("expected type 'typing', got '%s'", received.Type)
	}
}

func TestCB95_ReadPump_RoutesStatusUpdate(t *testing.T) {
	server := setupTestServer_CB95(t)

	agentSecret := getAgentSecret_CB95()
	agentWsURL := strings.Replace(server.URL, "http://", "ws://", 1) +
		"/agent/connect?agent_id=status-agent&agent_secret=" + agentSecret
	dialer := websocket.Dialer{}
	agentWs, _, err := dialer.Dial(agentWsURL, nil)
	if err != nil {
		t.Fatalf("agent dial: %v", err)
	}
	defer agentWs.Close()
	_, _, _ = agentWs.ReadMessage()

	userID := registerTestUser_CB95(t, "status-client-user")
	token := generateTestJWT_CB95(t, userID)
	clientWsURL := strings.Replace(server.URL, "http://", "ws://", 1) +
		"/client/connect?token=" + token
	clientWs, _, err := dialer.Dial(clientWsURL, nil)
	if err != nil {
		t.Fatalf("client dial: %v", err)
	}
	defer clientWs.Close()
	_, _, _ = clientWs.ReadMessage()

	convID := createTestConversation_CB95(t, userID, "status-agent")
	time.Sleep(50 * time.Millisecond)

	// Agent sends status update
	statusMsg := `{"type":"status","data":{"conversation_id":"` + convID + `","status":"busy"}}`
	err = agentWs.WriteMessage(websocket.TextMessage, []byte(statusMsg))
	if err != nil {
		t.Fatalf("write status: %v", err)
	}

	// Client should receive status update
	_, msg, err := clientWs.ReadMessage()
	if err != nil {
		t.Fatalf("client read status: %v", err)
	}

	var received OutgoingMessage
	json.Unmarshal(msg, &received)
	if received.Type != "status" {
		t.Errorf("expected type 'status', got '%s'", received.Type)
	}
}

func TestCB95_ReadPump_AgentToClientMessage(t *testing.T) {
	server := setupTestServer_CB95(t)

	agentSecret := getAgentSecret_CB95()
	agentWsURL := strings.Replace(server.URL, "http://", "ws://", 1) +
		"/agent/connect?agent_id=a2c-agent&agent_secret=" + agentSecret
	dialer := websocket.Dialer{}
	agentWs, _, err := dialer.Dial(agentWsURL, nil)
	if err != nil {
		t.Fatalf("agent dial: %v", err)
	}
	defer agentWs.Close()
	_, _, _ = agentWs.ReadMessage()

	userID := registerTestUser_CB95(t, "a2c-client-user")
	token := generateTestJWT_CB95(t, userID)
	clientWsURL := strings.Replace(server.URL, "http://", "ws://", 1) +
		"/client/connect?token=" + token
	clientWs, _, err := dialer.Dial(clientWsURL, nil)
	if err != nil {
		t.Fatalf("client dial: %v", err)
	}
	defer clientWs.Close()
	_, _, _ = clientWs.ReadMessage()

	convID := createTestConversation_CB95(t, userID, "a2c-agent")
	time.Sleep(50 * time.Millisecond)

	// Agent sends message to client
	chatMsg := `{"type":"message","data":{"conversation_id":"` + convID + `","content":"Hello from agent!"}}`
	err = agentWs.WriteMessage(websocket.TextMessage, []byte(chatMsg))
	if err != nil {
		t.Fatalf("write agent message: %v", err)
	}

	// Client should receive the message
	_, msg, err := clientWs.ReadMessage()
	if err != nil {
		t.Fatalf("client read: %v", err)
	}

	var received OutgoingMessage
	json.Unmarshal(msg, &received)
	if received.Type != "message" {
		t.Errorf("expected type 'message', got '%s'", received.Type)
	}
}

func TestCB95_ReadPump_UnexpectedCloseError(t *testing.T) {
	server := setupTestServer_CB95(t)

	agentSecret := getAgentSecret_CB95()
	agentWsURL := strings.Replace(server.URL, "http://", "ws://", 1) +
		"/agent/connect?agent_id=close-agent&agent_secret=" + agentSecret
	dialer := websocket.Dialer{}
	ws, _, err := dialer.Dial(agentWsURL, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	_, _, _ = ws.ReadMessage() // welcome

	// Abnormal close (no close frame)
	ws.Close()
	time.Sleep(200 * time.Millisecond)

	// Agent should be unregistered
	hub.mu.RLock()
	_, exists := hub.agents["close-agent"]
	hub.mu.RUnlock()
	if exists {
		t.Error("agent should be unregistered after abnormal close")
	}
}

// ==============================
// writePump — WebSocket integration via real connect
// ==============================

func TestCB95_WritePump_SendsWelcomeMessage(t *testing.T) {
	server := setupTestServer_CB95(t)
	agentSecret := getAgentSecret_CB95()
	wsURL := strings.Replace(server.URL, "http://", "ws://", 1) +
		"/agent/connect?agent_id=wp-welcome-agent&agent_secret=" + agentSecret

	dialer := websocket.Dialer{}
	ws, _, err := dialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer ws.Close()

	// The welcome message is sent by writePump
	_, msg, err := ws.ReadMessage()
	if err != nil {
		t.Fatalf("read welcome: %v", err)
	}

	var welcome OutgoingMessage
	if err := json.Unmarshal(msg, &welcome); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if welcome.Type != "connected" {
		t.Errorf("expected 'connected', got '%s'", welcome.Type)
	}
}

func TestCB95_WritePump_BroadcastMessage(t *testing.T) {
	server := setupTestServer_CB95(t)

	agentSecret := getAgentSecret_CB95()
	agentWsURL := strings.Replace(server.URL, "http://", "ws://", 1) +
		"/agent/connect?agent_id=broadcast-agent&agent_secret=" + agentSecret
	dialer := websocket.Dialer{}
	agentWs, _, err := dialer.Dial(agentWsURL, nil)
	if err != nil {
		t.Fatalf("agent dial: %v", err)
	}
	defer agentWs.Close()
	_, _, _ = agentWs.ReadMessage()

	userID := registerTestUser_CB95(t, "broadcast-user")
	token := generateTestJWT_CB95(t, userID)
	clientWsURL := strings.Replace(server.URL, "http://", "ws://", 1) +
		"/client/connect?token=" + token
	clientWs, _, err := dialer.Dial(clientWsURL, nil)
	if err != nil {
		t.Fatalf("client dial: %v", err)
	}
	defer clientWs.Close()
	_, _, _ = clientWs.ReadMessage()

	convID := createTestConversation_CB95(t, userID, "broadcast-agent")
	time.Sleep(50 * time.Millisecond)

	// Send a message from client to agent — this goes through writePump to the agent
	chatMsg := `{"type":"message","data":{"conversation_id":"` + convID + `","content":"broadcast test"}}`
	err = clientWs.WriteMessage(websocket.TextMessage, []byte(chatMsg))
	if err != nil {
		t.Fatalf("write: %v", err)
	}

	// Agent should receive via writePump
	_, msg, err := agentWs.ReadMessage()
	if err != nil {
		t.Fatalf("agent read: %v", err)
	}

	var received OutgoingMessage
	json.Unmarshal(msg, &received)
	if received.Type != "message" {
		t.Errorf("expected 'message', got '%s'", received.Type)
	}
}

func TestCB95_WritePump_ChannelClosedOnUnregister(t *testing.T) {
	server := setupTestServer_CB95(t)

	agentSecret := getAgentSecret_CB95()
	agentWsURL := strings.Replace(server.URL, "http://", "ws://", 1) +
		"/agent/connect?agent_id=unregister-agent&agent_secret=" + agentSecret
	dialer := websocket.Dialer{}
	ws, _, err := dialer.Dial(agentWsURL, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	_, _, _ = ws.ReadMessage()

	time.Sleep(50 * time.Millisecond)

	// Force unregister via hub
	hub.mu.RLock()
	conn := hub.agents["unregister-agent"]
	hub.mu.RUnlock()
	if conn == nil {
		t.Fatal("agent not found")
	}

	hub.unregister <- conn

	// The writePump should close the connection
	time.Sleep(200 * time.Millisecond)

	// WebSocket should be closed
	_, _, err = ws.ReadMessage()
	if err == nil {
		t.Error("expected error reading from closed connection")
	}
}

// ==============================
// main() — subprocess testing
// ==============================

func TestCB95_Main_VersionFlag(t *testing.T) {
	// Build the server binary
	tmpDir, err := os.MkdirTemp("", "cb95_main_*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	binaryPath := tmpDir + "/am-server"
	cmd := exec.Command("go", "build", "-o", binaryPath, ".")
	cmd.Dir = "."
	if err := cmd.Run(); err != nil {
		t.Fatalf("build: %v", err)
	}

	// Run with -version
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd = exec.CommandContext(ctx, binaryPath, "-version")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("run -version: %v (output: %s)", err, output)
	}

	outputStr := strings.TrimSpace(string(output))
	if !strings.Contains(outputStr, "Agent Messenger") {
		t.Errorf("expected 'Agent Messenger' in version output, got: %s", outputStr)
	}
}

func TestCB95_Main_StartsAndStopsGracefully(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "cb95_main_graceful_*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	binaryPath := tmpDir + "/am-server"
	cmd := exec.Command("go", "build", "-o", binaryPath, ".")
	if err := cmd.Run(); err != nil {
		t.Fatalf("build: %v", err)
	}

	// Start server on a random port
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd = exec.CommandContext(ctx, binaryPath, "-port", "18099", "-db", tmpDir+"/test.db")
	if err := cmd.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}

	// Wait for server to start
	time.Sleep(500 * time.Millisecond)

	// Check health endpoint
	resp, err := http.Get("http://localhost:18099/health")
	if err != nil {
		t.Fatalf("health check: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200 from /health, got %d", resp.StatusCode)
	}

	// Send SIGTERM for graceful shutdown
	cmd.Process.Signal(os.Interrupt)
	err = cmd.Wait()
	if err != nil {
		// SIGTERM causes non-zero exit, which is expected
		t.Logf("server exited with: %v (expected for signal)", err)
	}
}

// ==============================
// Helpers
// ==============================

func getAgentSecret_CB95() string {
	// The dev default agent secret
	return "dev-agent-secret-change-me"
}

func registerTestUser_CB95(t *testing.T, username string) string {
	t.Helper()
	id := generateID("usr")
	hash, _ := bcrypt.GenerateFromPassword([]byte("testpass123"), bcrypt.MinCost)
	_, err := db.Exec("INSERT INTO users (id, username, password_hash, created_at) VALUES (?, ?, ?, ?)",
		id, username, string(hash), time.Now().UTC().Format(time.RFC3339))
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	return id
}

func generateTestJWT_CB95(t *testing.T, userID string) string {
	t.Helper()
	token, err := GenerateJWT(userID, userID)
	if err != nil {
		t.Fatalf("generate JWT: %v", err)
	}
	return token
}

func createTestConversation_CB95(t *testing.T, userID, agentID string) string {
	t.Helper()
	convID := generateID("conv")
	_, err := db.Exec("INSERT INTO conversations (id, user_id, agent_id, created_at) VALUES (?, ?, ?, ?)",
		convID, userID, agentID, time.Now().UTC().Format(time.RFC3339))
	if err != nil {
		t.Fatalf("create conversation: %v", err)
	}
	return convID
}

// ==============================
// Concurrent connection stress test
// ==============================

func TestCB95_ConcurrentConnections(t *testing.T) {
	server := setupTestServer_CB95(t)
	agentSecret := getAgentSecret_CB95()

	const numAgents = 5
	const numClients = 5

	var wg sync.WaitGroup
	var mu sync.Mutex
	errors := make([]string, 0)

	// Pre-register users to avoid concurrent DB writes
	userIDs := make([]string, numClients)
	tokens := make([]string, numClients)
	for i := 0; i < numClients; i++ {
		userIDs[i] = registerTestUser_CB95(t, "stress-user-"+fmt.Sprintf("%d", i))
		tokens[i] = generateTestJWT_CB95(t, userIDs[i])
	}

	// Connect agents
	for i := 0; i < numAgents; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			agentID := fmt.Sprintf("stress-agent-%d", idx)
			wsURL := strings.Replace(server.URL, "http://", "ws://", 1) +
				"/agent/connect?agent_id=" + agentID + "&agent_secret=" + agentSecret
			dialer := websocket.Dialer{}
			ws, _, err := dialer.Dial(wsURL, nil)
			if err != nil {
				mu.Lock()
				errors = append(errors, "agent "+agentID+": "+err.Error())
				mu.Unlock()
				return
			}
			defer ws.Close()
			_, _, _ = ws.ReadMessage() // welcome
			time.Sleep(500 * time.Millisecond)
		}(i)
	}

	// Connect clients
	for i := 0; i < numClients; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			wsURL := strings.Replace(server.URL, "http://", "ws://", 1) +
				"/client/connect?token=" + tokens[idx]
			dialer := websocket.Dialer{}
			ws, _, err := dialer.Dial(wsURL, nil)
			if err != nil {
				mu.Lock()
				errors = append(errors, fmt.Sprintf("client %d: %s", idx, err.Error()))
				mu.Unlock()
				return
			}
			defer ws.Close()
			_, _, _ = ws.ReadMessage()
			time.Sleep(500 * time.Millisecond)
		}(i)
	}

	wg.Wait()

	if len(errors) > 0 {
		t.Errorf("connection errors: %s", strings.Join(errors, "; "))
	}
	// All 10 connections should have succeeded without errors.
}

// ==============================
// Offline message replay on connect
// ==============================

func TestCB95_OfflineReplay_OnAgentConnect(t *testing.T) {
	server := setupTestServer_CB95(t)

	// First, connect an agent and client, create a conversation, then disconnect the agent
	agentSecret := getAgentSecret_CB95()
	userID := registerTestUser_CB95(t, "replay-user")
	convID := createTestConversation_CB95(t, userID, "replay-agent")

	// Store a message in DB while agent is offline
	_, err := db.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, created_at) VALUES (?, ?, ?, ?, ?, ?)",
		generateID("msg"), convID, "client", userID, "Offline message for agent", time.Now().UTC().Format(time.RFC3339))
	if err != nil {
		t.Fatalf("insert message: %v", err)
	}

	// Queue an offline message for the agent
	// Queue an offline message for the agent (must be in OutgoingMessage format)
	queuedMsg, _ := json.Marshal(OutgoingMessage{Type: MsgTypeMessage, Data: map[string]string{"content": "queued message"}})
	offlineQueue.Enqueue("replay-agent", queuedMsg)

	// Now connect the agent — should get replay
	agentWsURL := strings.Replace(server.URL, "http://", "ws://", 1) +
		"/agent/connect?agent_id=replay-agent&agent_secret=" + agentSecret
	dialer := websocket.Dialer{}
	ws, _, err := dialer.Dial(agentWsURL, nil)
	if err != nil {
		t.Fatalf("agent dial: %v", err)
	}
	defer ws.Close()

	// Read welcome
	_, _, err = ws.ReadMessage()
	if err != nil {
		t.Fatalf("read welcome: %v", err)
	}

	// Read queued message (may arrive within a short time)
	ws.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, msg, err := ws.ReadMessage()
	if err != nil {
		t.Fatalf("read queued message: %v", err)
	}

	var received OutgoingMessage
	json.Unmarshal(msg, &received)
	if received.Type != "message" {
		t.Errorf("expected type 'message', got '%s'", received.Type)
	}
}