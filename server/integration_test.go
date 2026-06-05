package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// setupIntegrationServer creates a full test server with all routes for integration testing.
func setupIntegrationServer(t *testing.T) (*httptest.Server, func()) {
	t.Helper()

	// Save and restore global state that heartbeat tests may have changed
	origPresenceEnabled := agentPresenceEnabled
	agentPresenceEnabled = false

	// Reset global rate limiters to avoid cross-test interference
	// Recreate to ensure correct limits (other tests may replace them with different values)
	messageRateLimiter = NewRateLimiter(60, time.Minute)
	userRateLimiter = NewRateLimiter(120, time.Minute)
	globalTieredLimiter = NewTieredRateLimiter()
	ipRateLimiter = NewRateLimiter(300, time.Minute)
	authIPLimiter = NewRateLimiter(30, time.Minute)
	agentRateLimiter.Reset()

	// Give goroutines from previous tests time to exit and rate limiters to settle
	// Stop previous hub if still running
	if hub != nil {
		select {
		case <-hub.done:
			// hub already stopped
		default:
			hub.Stop()
		}
	}
	runtime.Gosched()
	time.Sleep(200 * time.Millisecond)
	runtime.Gosched()

	setupTestDB(t)

	hub = newHub()
	go hub.run()
	ServerMetrics = NewMetrics(hub)

	mux := http.NewServeMux()
	mux.HandleFunc("/agent/connect", handleAgentConnect)
	mux.HandleFunc("/client/connect", handleClientConnect)
	mux.HandleFunc("/health", handleHealth)
	mux.HandleFunc("/metrics", handleMetrics)
	mux.HandleFunc("/auth/login", handleLogin)
	mux.HandleFunc("/auth/agent", handleRegisterAgent)
	mux.HandleFunc("/auth/user", handleRegisterUser)
	mux.HandleFunc("/conversations/create", handleCreateConversation)
	mux.HandleFunc("/conversations/list", handleListConversations)
	mux.HandleFunc("/conversations/messages", handleGetMessages)
	mux.HandleFunc("/conversations/mark-read", handleMarkRead)
	mux.HandleFunc("/conversations/delete", handleDeleteConversation)
	mux.HandleFunc("/agents", handleListAgents)

	server := httptest.NewServer(mux)
	cleanup := func() {
		server.Close()
		hub.Stop()
		agentPresenceEnabled = origPresenceEnabled
	}
	return server, cleanup
}

// intTestUser registers a user and returns their JWT token.
func intTestUser(t *testing.T, server *httptest.Server, username string) string {
	t.Helper()
	form := url.Values{"username": {username}, "password": {"testpass123"}}
	resp, err := http.PostForm(server.URL+"/auth/user", form)
	if err != nil {
		t.Fatalf("register user failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("register user returned %d", resp.StatusCode)
	}

	form2 := url.Values{"username": {username}, "password": {"testpass123"}}
	resp2, err := http.PostForm(server.URL+"/auth/login", form2)
	if err != nil {
		t.Fatalf("login failed: %v", err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != 200 {
		t.Fatalf("login returned %d", resp2.StatusCode)
	}

	var result map[string]string
	json.NewDecoder(resp2.Body).Decode(&result)
	return result["token"]
}

// intTestAgent registers an agent via REST and returns the agent_id.
func intTestAgent(t *testing.T, server *httptest.Server, agentID, name string) string {
	t.Helper()
	form := url.Values{
		"agent_id":     {agentID},
		"name":         {name},
		"agent_secret": {agentSecret},
	}
	resp, err := http.PostForm(server.URL+"/auth/agent", form)
	if err != nil {
		t.Fatalf("register agent failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("register agent returned %d", resp.StatusCode)
	}
	return agentID
}

// intWsDialAgent dials a WebSocket for an agent connection and returns the conn.
func intWsDialAgent(t *testing.T, server *httptest.Server, agentID string) *websocket.Conn {
	t.Helper()
	wsURL := "ws" + strings.TrimPrefix(server.URL, "http") + "/agent/connect?agent_id=" + agentID + "&agent_secret=" + url.QueryEscape(agentSecret)
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("agent WebSocket connect failed: %v", err)
	}
	return conn
}

// intWsDialClient dials a WebSocket for a client connection and returns the conn.
func intWsDialClient(t *testing.T, server *httptest.Server, token string) *websocket.Conn {
	t.Helper()
	wsURL := "ws" + strings.TrimPrefix(server.URL, "http") + "/client/connect?user_id=inttest&token=" + url.QueryEscape(token)
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("client WebSocket connect failed: %v", err)
	}
	return conn
}

// readWSMessage reads a single WebSocket message with a timeout, returning its type.
func readWSMessage(t *testing.T, conn *websocket.Conn, timeout time.Duration) (string, map[string]interface{}) {
	t.Helper()
	conn.SetReadDeadline(time.Now().Add(timeout))
	_, raw, err := conn.ReadMessage()
	if err != nil {
		t.Fatalf("read WebSocket message failed: %v", err)
	}
	var msg map[string]interface{}
	if err := json.Unmarshal(raw, &msg); err != nil {
		t.Fatalf("unmarshal WebSocket message failed: %v", err)
	}
	msgType, _ := msg["type"].(string)
	data, _ := msg["data"].(map[string]interface{})
	return msgType, data
}

// readWSMessageRaw reads a raw WebSocket message bytes with a timeout.
func readWSMessageRaw(t *testing.T, conn *websocket.Conn, timeout time.Duration) []byte {
	t.Helper()
	conn.SetReadDeadline(time.Now().Add(timeout))
	_, raw, err := conn.ReadMessage()
	if err != nil {
		t.Fatalf("read WebSocket message failed: %v", err)
	}
	return raw
}

// tryReadWSMessage attempts to read a WebSocket message, returning (nil, false) if timeout.
func tryReadWSMessage(conn *websocket.Conn, timeout time.Duration) ([]byte, error) {
	conn.SetReadDeadline(time.Now().Add(timeout))
	_, raw, err := conn.ReadMessage()
	return raw, err
}

// ============================================================
// Integration Tests: Full WebSocket lifecycle
// ============================================================

// TestIntegration_AgentConnectAuth tests that an agent can connect with valid credentials
// and receives a welcome message.
func TestIntegration_AgentConnectAuth(t *testing.T) {
	server, cleanup := setupIntegrationServer(t)
	defer cleanup()

	intTestAgent(t, server, "int-auth-agent", "Auth Test Agent")
	conn := intWsDialAgent(t, server, "int-auth-agent")
	defer conn.Close()

	// Should receive welcome message
	msgType, data := readWSMessage(t, conn, 2*time.Second)
	if msgType != "connected" {
		t.Fatalf("expected welcome type 'connected', got %q", msgType)
	}
	if data["id"] != "int-auth-agent" {
		t.Fatalf("expected id 'int-auth-agent', got %v", data["id"])
	}
	if data["status"] != "connected" {
		t.Fatalf("expected status 'connected', got %v", data["status"])
	}
}

// TestIntegration_AgentConnectBadSecret tests that an agent with wrong secret is rejected.
func TestIntegration_AgentConnectBadSecret(t *testing.T) {
	server, cleanup := setupIntegrationServer(t)
	defer cleanup()

	intTestAgent(t, server, "bad-secret-agent", "Bad Secret Agent")
	wsURL := "ws" + strings.TrimPrefix(server.URL, "http") + "/agent/connect?agent_id=bad-secret-agent&agent_secret=wrongsecret"
	_, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err == nil {
		t.Fatal("expected connection to be rejected with bad secret")
	}
}

// TestIntegration_ClientConnectAuth tests that a client can connect with a valid JWT
// and receives a welcome message with their user ID.
func TestIntegration_ClientConnectAuth(t *testing.T) {
	server, cleanup := setupIntegrationServer(t)
	defer cleanup()

	token := intTestUser(t, server, "intauthuser")
	conn := intWsDialClient(t, server, token)
	defer conn.Close()

	msgType, data := readWSMessage(t, conn, 2*time.Second)
	if msgType != "connected" {
		t.Fatalf("expected welcome type 'connected', got %q", msgType)
	}
	if data["status"] != "connected" {
		t.Fatalf("expected status 'connected', got %v", data["status"])
	}
	// The user ID should come from JWT, not query param
	if data["id"] == "" {
		t.Fatal("expected non-empty id in welcome")
	}
}

// TestIntegration_ClientConnectBadToken tests that a client with an invalid JWT is rejected.
func TestIntegration_ClientConnectBadToken(t *testing.T) {
	server, cleanup := setupIntegrationServer(t)
	defer cleanup()

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http") + "/client/connect?user_id=fake&token=invalidtoken"
	_, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err == nil {
		t.Fatal("expected connection to be rejected with invalid token")
	}
}

// TestIntegration_BidirectionalMessaging tests the full message flow:
// client sends message → agent receives → agent replies → client receives reply.
func TestIntegration_BidirectionalMessaging(t *testing.T) {
	server, cleanup := setupIntegrationServer(t)
	defer cleanup()

	agentID := intTestAgent(t, server, "bidir-agent", "Bidir Agent")
	token := intTestUser(t, server, "bidiruser")

	// Connect agent
	agentConn := intWsDialAgent(t, server, agentID)
	defer agentConn.Close()
	readWSMessage(t, agentConn, 2*time.Second) // consume welcome

	// Connect client
	clientConn := intWsDialClient(t, server, token)
	defer clientConn.Close()
	readWSMessage(t, clientConn, 2*time.Second) // consume welcome

	// Create a conversation via REST
	form := url.Values{"agent_id": {agentID}}
	resp, err := httpPostFormWithAuth(server.URL+"/conversations/create", form, token)
	if err != nil {
		t.Fatalf("create conversation failed: %v", err)
	}
	defer resp.Body.Close()
	var convResp map[string]string
	json.NewDecoder(resp.Body).Decode(&convResp)
	convID := convResp["conversation_id"]
	if convID == "" {
		t.Fatal("expected conversation_id in response")
	}

	// Client sends a message to the agent
	clientMsg := map[string]interface{}{
		"type": "message",
		"data": map[string]interface{}{
			"conversation_id": convID,
			"content":         "Hello Agent!",
		},
	}
	clientMsgBytes, _ := json.Marshal(clientMsg)
	if err := clientConn.WriteMessage(websocket.TextMessage, clientMsgBytes); err != nil {
		t.Fatalf("client write message failed: %v", err)
	}

	// Agent should receive the message
	msgType, data := readWSMessage(t, agentConn, 3*time.Second)
	if msgType != "message" {
		// It might be a message_sent ack for the client; skip if needed
		t.Fatalf("expected 'message' type on agent, got %q", msgType)
	}
	if data["content"] != "Hello Agent!" {
		t.Fatalf("expected content 'Hello Agent!', got %v", data["content"])
	}

	// Agent replies to the client
	agentReply := map[string]interface{}{
		"type": "message",
		"data": map[string]interface{}{
			"conversation_id": convID,
			"content":         "Hello User!",
		},
	}
	agentReplyBytes, _ := json.Marshal(agentReply)
	if err := agentConn.WriteMessage(websocket.TextMessage, agentReplyBytes); err != nil {
		t.Fatalf("agent write message failed: %v", err)
	}

	// Client should receive the agent's reply
	msgType, data = readWSMessage(t, clientConn, 3*time.Second)
	// Skip the client's own message_sent ack if it arrives first
	for msgType == "message_sent" {
		msgType, data = readWSMessage(t, clientConn, 3*time.Second)
	}
	if msgType != "message" {
		t.Fatalf("expected 'message' type on client, got %q", msgType)
	}
	if data["content"] != "Hello User!" {
		t.Fatalf("expected content 'Hello User!', got %v", data["content"])
	}
}

// TestIntegration_TypingIndicator tests that typing indicators are relayed
// between client and agent.
func TestIntegration_TypingIndicator(t *testing.T) {
	server, cleanup := setupIntegrationServer(t)
	defer cleanup()

	agentID := intTestAgent(t, server, "typing-agent", "Typing Agent")
	token := intTestUser(t, server, "typinguser")

	agentConn := intWsDialAgent(t, server, agentID)
	defer agentConn.Close()
	readWSMessage(t, agentConn, 2*time.Second)

	clientConn := intWsDialClient(t, server, token)
	defer clientConn.Close()
	readWSMessage(t, clientConn, 2*time.Second)

	// Create conversation
	form := url.Values{"agent_id": {agentID}}
	resp, _ := httpPostFormWithAuth(server.URL+"/conversations/create", form, token)
	defer resp.Body.Close()
	var convResp map[string]string
	json.NewDecoder(resp.Body).Decode(&convResp)
	convID := convResp["conversation_id"]

	// Agent sends typing indicator
	typingMsg := map[string]interface{}{
		"type": "typing",
		"data": map[string]interface{}{
			"conversation_id": convID,
		},
	}
	typingBytes, _ := json.Marshal(typingMsg)
	if err := agentConn.WriteMessage(websocket.TextMessage, typingBytes); err != nil {
		t.Fatalf("agent write typing failed: %v", err)
	}

	// Client should receive the typing indicator
	msgType, data := readWSMessage(t, clientConn, 2*time.Second)
	if msgType != "typing" {
		t.Fatalf("expected 'typing' type on client, got %q", msgType)
	}
	if data["conversation_id"] != convID {
		t.Fatalf("expected conversation_id=%s, got %v", convID, data["conversation_id"])
	}
	if data["sender_type"] != "agent" {
		t.Fatalf("expected sender_type=agent, got %v", data["sender_type"])
	}
	if data["sender_id"] != "typing-agent" {
		t.Fatalf("expected sender_id=typing-agent, got %v", data["sender_id"])
	}
}

// TestIntegration_PresenceStatus tests that agent status changes are
// reflected via WebSocket and the REST /agents endpoint.
func TestIntegration_PresenceStatus(t *testing.T) {
	server, cleanup := setupIntegrationServer(t)
	defer cleanup()

	agentID := intTestAgent(t, server, "presence-agent", "Presence Agent")

	// Before connecting, agent should be offline
	resp, err := http.Get(server.URL + "/agents")
	if err != nil {
		t.Fatal(err)
	}
	var agents []AgentInfo
	json.NewDecoder(resp.Body).Decode(&agents)
	resp.Body.Close()
	for _, a := range agents {
		if a.ID == "presence-agent" && a.Status != "offline" {
			t.Fatalf("expected offline before connect, got %s", a.Status)
		}
	}

	// Connect agent
	agentConn := intWsDialAgent(t, server, agentID)
	defer agentConn.Close()
	readWSMessage(t, agentConn, 2*time.Second)
	time.Sleep(50 * time.Millisecond) // let hub register

	// Now should be online
	resp, err = http.Get(server.URL + "/agents")
	if err != nil {
		t.Fatal(err)
	}
	json.NewDecoder(resp.Body).Decode(&agents)
	resp.Body.Close()
	found := false
	for _, a := range agents {
		if a.ID == "presence-agent" {
			found = true
			if a.Status != "online" {
				t.Fatalf("expected online after connect, got %s", a.Status)
			}
		}
	}
	if !found {
		t.Fatal("presence-agent not found in agent list")
	}
}

// TestIntegration_DisconnectReconnect tests that an agent can disconnect and reconnect,
// and that messages are properly routed after reconnection.
func TestIntegration_DisconnectReconnect(t *testing.T) {
	server, cleanup := setupIntegrationServer(t)
	defer cleanup()

	agentID := intTestAgent(t, server, "reconnect-agent", "Reconnect Agent")
	token := intTestUser(t, server, "reconnectuser")

	// Connect agent (first time)
	agentConn := intWsDialAgent(t, server, agentID)
	readWSMessage(t, agentConn, 2*time.Second) // consume welcome

	// Create conversation while agent is connected
	form := url.Values{"agent_id": {agentID}}
	resp, _ := httpPostFormWithAuth(server.URL+"/conversations/create", form, token)
	defer resp.Body.Close()
	var convResp map[string]string
	json.NewDecoder(resp.Body).Decode(&convResp)
	convID := convResp["conversation_id"]

	// Disconnect agent
	agentConn.Close()
	time.Sleep(100 * time.Millisecond) // let hub unregister

	// Verify agent is offline
	resp2, _ := http.Get(server.URL + "/agents")
	var agents []AgentInfo
	json.NewDecoder(resp2.Body).Decode(&agents)
	resp2.Body.Close()
	for _, a := range agents {
		if a.ID == "reconnect-agent" && a.Status != "offline" {
			t.Fatalf("expected offline after disconnect, got %s", a.Status)
		}
	}

	// Reconnect agent
	agentConn2 := intWsDialAgent(t, server, agentID)
	defer agentConn2.Close()
	readWSMessage(t, agentConn2, 2*time.Second) // consume welcome
	time.Sleep(50 * time.Millisecond)

	// Connect client and send message
	clientConn := intWsDialClient(t, server, token)
	defer clientConn.Close()
	readWSMessage(t, clientConn, 2*time.Second) // consume welcome

	clientMsg := map[string]interface{}{
		"type": "message",
		"data": map[string]interface{}{
			"conversation_id": convID,
			"content":         "After reconnect!",
		},
	}
	msgBytes, _ := json.Marshal(clientMsg)
	if err := clientConn.WriteMessage(websocket.TextMessage, msgBytes); err != nil {
		t.Fatalf("client write failed: %v", err)
	}

	// Agent should receive message after reconnect
	msgType, data := readWSMessage(t, agentConn2, 3*time.Second)
	if msgType != "message" {
		t.Fatalf("expected 'message' after reconnect, got %q", msgType)
	}
	if data["content"] != "After reconnect!" {
		t.Fatalf("expected 'After reconnect!', got %v", data["content"])
	}
}

// TestIntegration_OfflineBufferAndReplay tests that messages sent while a client
// is offline are delivered when the client reconnects.
func TestIntegration_OfflineBufferAndReplay(t *testing.T) {
	server, cleanup := setupIntegrationServer(t)
	defer cleanup()

	agentID := intTestAgent(t, server, "offline-agent", "Offline Agent")
	token := intTestUser(t, server, "offlineuser")

	// Connect agent
	agentConn := intWsDialAgent(t, server, agentID)
	defer agentConn.Close()
	readWSMessage(t, agentConn, 2*time.Second)

	// Create conversation
	form := url.Values{"agent_id": {agentID}}
	resp, _ := httpPostFormWithAuth(server.URL+"/conversations/create", form, token)
	defer resp.Body.Close()
	var convResp map[string]string
	json.NewDecoder(resp.Body).Decode(&convResp)
	convID := convResp["conversation_id"]

	// Agent sends a message while the client is NOT connected
	agentMsg := map[string]interface{}{
		"type": "message",
		"data": map[string]interface{}{
			"conversation_id": convID,
			"content":         "You were offline!",
		},
	}
	msgBytes, _ := json.Marshal(agentMsg)
	if err := agentConn.WriteMessage(websocket.TextMessage, msgBytes); err != nil {
		t.Fatalf("agent write failed: %v", err)
	}
	// Read the message_sent ack
	readWSMessage(t, agentConn, 2*time.Second)

	// Now connect the client — should receive the buffered message
	clientConn := intWsDialClient(t, server, token)
	defer clientConn.Close()
	readWSMessage(t, clientConn, 2*time.Second) // consume welcome

	// The offline-queued message should be replayed
	msgType, data := readWSMessage(t, clientConn, 3*time.Second)
	if msgType != "message" {
		t.Fatalf("expected buffered 'message' on reconnect, got %q", msgType)
	}
	if data["content"] != "You were offline!" {
		t.Fatalf("expected 'You were offline!', got %v", data["content"])
	}
}

// TestIntegration_MultiDeviceClient tests that a user connecting from two devices
// receives messages on both.
func TestIntegration_MultiDeviceClient(t *testing.T) {
	server, cleanup := setupIntegrationServer(t)
	defer cleanup()

	agentID := intTestAgent(t, server, "multidev-agent", "Multi-Device Agent")
	token := intTestUser(t, server, "multidevuser")

	// Connect agent
	agentConn := intWsDialAgent(t, server, agentID)
	defer agentConn.Close()
	readWSMessage(t, agentConn, 2*time.Second)

	// Connect client device 1
	wsURL1 := "ws" + strings.TrimPrefix(server.URL, "http") + "/client/connect?user_id=multidevuser&token=" + url.QueryEscape(token) + "&device_id=phone"
	conn1, _, err := websocket.DefaultDialer.Dial(wsURL1, nil)
	if err != nil {
		t.Fatalf("device 1 connect failed: %v", err)
	}
	defer conn1.Close()
	readWSMessage(t, conn1, 2*time.Second) // welcome

	// Connect client device 2
	wsURL2 := "ws" + strings.TrimPrefix(server.URL, "http") + "/client/connect?user_id=multidevuser&token=" + url.QueryEscape(token) + "&device_id=laptop"
	conn2, _, err := websocket.DefaultDialer.Dial(wsURL2, nil)
	if err != nil {
		t.Fatalf("device 2 connect failed: %v", err)
	}
	defer conn2.Close()
	readWSMessage(t, conn2, 2*time.Second) // welcome

	// Create conversation
	form := url.Values{"agent_id": {agentID}}
	resp, _ := httpPostFormWithAuth(server.URL+"/conversations/create", form, token)
	defer resp.Body.Close()
	var convResp map[string]string
	json.NewDecoder(resp.Body).Decode(&convResp)
	convID := convResp["conversation_id"]

	// Agent sends message — both devices should receive it
	agentMsg := map[string]interface{}{
		"type": "message",
		"data": map[string]interface{}{
			"conversation_id": convID,
			"content":         "Hello both devices!",
		},
	}
	msgBytes, _ := json.Marshal(agentMsg)
	if err := agentConn.WriteMessage(websocket.TextMessage, msgBytes); err != nil {
		t.Fatalf("agent write failed: %v", err)
	}

	// Both devices should receive the message
	msgType, data := readWSMessage(t, conn1, 3*time.Second)
	if msgType != "message" {
		t.Fatalf("device 1 expected 'message', got %q", msgType)
	}
	if data["content"] != "Hello both devices!" {
		t.Fatalf("device 1 content mismatch: %v", data["content"])
	}

	msgType, data = readWSMessage(t, conn2, 3*time.Second)
	if msgType != "message" {
		t.Fatalf("device 2 expected 'message', got %q", msgType)
	}
	if data["content"] != "Hello both devices!" {
		t.Fatalf("device 2 content mismatch: %v", data["content"])
	}
}

// TestIntegration_HealthEndpoint verifies the health check returns expected fields.
func TestIntegration_HealthEndpoint(t *testing.T) {
	server, cleanup := setupIntegrationServer(t)
	defer cleanup()

	resp, err := http.Get(server.URL + "/health")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var health map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&health)
	if health["status"] != "ok" {
		t.Fatalf("expected status ok, got %v", health["status"])
	}
	if _, ok := health["version"]; !ok {
		t.Fatal("expected version in health response")
	}
}

// TestIntegration_MessageHistoryPersistence tests that messages sent via WebSocket
// are persisted and retrievable via REST.
func TestIntegration_MessageHistoryPersistence(t *testing.T) {
	server, cleanup := setupIntegrationServer(t)
	defer cleanup()

	agentID := intTestAgent(t, server, "history-agent", "History Agent")
	token := intTestUser(t, server, "historyuser")

	agentConn := intWsDialAgent(t, server, agentID)
	defer agentConn.Close()
	readWSMessage(t, agentConn, 2*time.Second)

	clientConn := intWsDialClient(t, server, token)
	defer clientConn.Close()
	readWSMessage(t, clientConn, 2*time.Second)

	// Create conversation
	form := url.Values{"agent_id": {agentID}}
	resp, _ := httpPostFormWithAuth(server.URL+"/conversations/create", form, token)
	defer resp.Body.Close()
	var convResp map[string]string
	json.NewDecoder(resp.Body).Decode(&convResp)
	convID := convResp["conversation_id"]

	// Send a message from client
	clientMsg := map[string]interface{}{
		"type": "message",
		"data": map[string]interface{}{
			"conversation_id": convID,
			"content":         "Persisted message",
		},
	}
	msgBytes, _ := json.Marshal(clientMsg)
	if err := clientConn.WriteMessage(websocket.TextMessage, msgBytes); err != nil {
		t.Fatalf("client write failed: %v", err)
	}
	time.Sleep(100 * time.Millisecond) // let server persist

	// Fetch message history via REST
	req, _ := http.NewRequest("GET", server.URL+"/conversations/messages?conversation_id="+convID, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp2, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("get messages failed: %v", err)
	}
	defer resp2.Body.Close()

	if resp2.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp2.StatusCode)
	}

	var messages []map[string]interface{}
	json.NewDecoder(resp2.Body).Decode(&messages)

	found := false
	for _, m := range messages {
		if m["content"] == "Persisted message" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected to find persisted message in history, got %v", messages)
	}
}

// TestIntegration_ConcurrentMessaging tests that multiple messages in rapid succession
// are all delivered without loss.
func TestIntegration_ConcurrentMessaging(t *testing.T) {
	server, cleanup := setupIntegrationServer(t)
	defer cleanup()

	agentID := intTestAgent(t, server, "concurrent-agent", "Concurrent Agent")
	token := intTestUser(t, server, "concurrentuser")

	agentConn := intWsDialAgent(t, server, agentID)
	defer agentConn.Close()
	readWSMessage(t, agentConn, 2*time.Second)

	clientConn := intWsDialClient(t, server, token)
	defer clientConn.Close()
	readWSMessage(t, clientConn, 2*time.Second)

	// Create conversation
	form := url.Values{"agent_id": {agentID}}
	resp, _ := httpPostFormWithAuth(server.URL+"/conversations/create", form, token)
	defer resp.Body.Close()
	var convResp map[string]string
	json.NewDecoder(resp.Body).Decode(&convResp)
	convID := convResp["conversation_id"]

	// Verify hub state before sending
	if agent := hub.GetAgent(agentID); agent == nil {
		t.Fatalf("agent %q not found in hub", agentID)
	}

	// Start agent reader goroutine BEFORE sending messages to avoid race
	numMessages := 5
	type wsMsg struct {
		data []byte
		err  error
	}
	msgCh := make(chan wsMsg, numMessages+10)
	agentDone := make(chan struct{})
	go func() {
		defer close(agentDone)
		for {
			agentConn.SetReadDeadline(time.Now().Add(10 * time.Second))
			_, raw, err := agentConn.ReadMessage()
			if err != nil {
				msgCh <- wsMsg{data: raw, err: err}
				return
			}
			msgCh <- wsMsg{data: raw, err: err}
		}
	}()

	// Start client reader goroutine to check for rate-limit errors
	clientErrCh := make(chan string, numMessages+5)
	go func() {
		for {
			clientConn.SetReadDeadline(time.Now().Add(10 * time.Second))
			_, raw, err := clientConn.ReadMessage()
			if err != nil {
				return
			}
			var msg map[string]interface{}
			if json.Unmarshal(raw, &msg) == nil {
				if msg["type"] == "error" {
					if data, ok := msg["data"].(map[string]interface{}); ok {
						clientErrCh <- fmt.Sprintf("%v", data["message"])
					}
				}
			}
		}
	}()

	// Send 5 messages from the client with delays to stay well under rate limits
	// (60/min per-connection = 1/sec avg; 150ms gap gives ~7/sec which should be fine
	// given the token-bucket burst allowance of 60)
	for i := 0; i < numMessages; i++ {
		msg := map[string]interface{}{
			"type": "message",
			"data": map[string]interface{}{
				"conversation_id": convID,
				"content":         fmt.Sprintf("rapid-%d", i),
			},
		}
		msgBytes, _ := json.Marshal(msg)
		if err := clientConn.WriteMessage(websocket.TextMessage, msgBytes); err != nil {
			t.Fatalf("client write %d failed: %v", i, err)
		}
		t.Logf("sent message %d", i)
		if i < numMessages-1 {
			time.Sleep(150 * time.Millisecond)
		}
	}

	// Collect messages from agent
	received := 0
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) && received < numMessages {
		select {
		case m := <-msgCh:
			if m.err != nil {
				t.Fatalf("agent read failed after %d messages: %v", received, m.err)
			}
			var msg map[string]interface{}
			json.Unmarshal(m.data, &msg)
			msgType, _ := msg["type"].(string)
			t.Logf("agent received message type=%s", msgType)
			if msgType == "message" {
				received++
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("timed out waiting for messages, got %d of %d", received, numMessages)
		}
	}
	if received != numMessages {
		// Check if client received rate-limit errors
		select {
		case errMsg := <-clientErrCh:
			t.Fatalf("expected %d messages on agent, got %d (client error: %s)", numMessages, received, errMsg)
		default:
		}
		t.Fatalf("expected %d messages on agent, got %d", numMessages, received)
	}

	// Verify no rate-limit errors were received by the client
	select {
	case errMsg := <-clientErrCh:
		t.Errorf("unexpected rate-limit error on client: %s", errMsg)
	default:
	}
}

// TestIntegration_ReadReceipt tests that marking messages as read sends a
// read_receipt WebSocket event to the agent.
func TestIntegration_ReadReceipt(t *testing.T) {
	server, cleanup := setupIntegrationServer(t)
	defer cleanup()

	agentID := intTestAgent(t, server, "receipt-agent", "Receipt Agent")
	token := intTestUser(t, server, "receiptuser")

	agentConn := intWsDialAgent(t, server, agentID)
	defer agentConn.Close()
	readWSMessage(t, agentConn, 2*time.Second)

	clientConn := intWsDialClient(t, server, token)
	defer clientConn.Close()
	readWSMessage(t, clientConn, 2*time.Second)

	// Create conversation
	form := url.Values{"agent_id": {agentID}}
	resp, _ := httpPostFormWithAuth(server.URL+"/conversations/create", form, token)
	defer resp.Body.Close()
	var convResp map[string]string
	json.NewDecoder(resp.Body).Decode(&convResp)
	convID := convResp["conversation_id"]

	// Agent sends a message
	agentMsg := map[string]interface{}{
		"type": "message",
		"data": map[string]interface{}{
			"conversation_id": convID,
			"content":         "Read me!",
		},
	}
	msgBytes, _ := json.Marshal(agentMsg)
	agentConn.WriteMessage(websocket.TextMessage, msgBytes)
	readWSMessage(t, clientConn, 3*time.Second) // client receives message

	// Client marks messages as read via REST
	formMark := url.Values{"conversation_id": {convID}}
	resp2, _ := httpPostFormWithAuth(server.URL+"/conversations/mark-read", formMark, token)
	defer resp2.Body.Close()
	if resp2.StatusCode != 200 {
		t.Fatalf("mark-read returned %d", resp2.StatusCode)
	}

	// Agent should receive read_receipt event (may come after message_sent ack)
	var gotReadReceipt bool
	for i := 0; i < 5; i++ {
		var rmsgType string
		var rdata map[string]interface{}
		agentConn.SetReadDeadline(time.Now().Add(3 * time.Second))
		_, raw, err := agentConn.ReadMessage()
		if err != nil {
			t.Fatalf("agent read failed waiting for read_receipt: %v", err)
		}
		var rmsg map[string]interface{}
		json.Unmarshal(raw, &rmsg)
		rmsgType, _ = rmsg["type"].(string)
		rdata, _ = rmsg["data"].(map[string]interface{})
		if rmsgType == "read_receipt" {
			if rdata["conversation_id"] != convID {
				t.Fatalf("expected conv_id %s, got %v", convID, rdata["conversation_id"])
			}
			gotReadReceipt = true
			break
		}
	}
	if !gotReadReceipt {
		t.Fatal("expected 'read_receipt' event on agent, but none received")
	}
}

// TestIntegration_AgentUnauthorizedMessage tests that an agent cannot send a message
// to a conversation they are not a participant of.
func TestIntegration_AgentUnauthorizedMessage(t *testing.T) {
	server, cleanup := setupIntegrationServer(t)
	defer cleanup()

	// Setup: agent1, agent2, and a conversation between user and agent1
	agent1ID := intTestAgent(t, server, "auth-agent1", "Auth Agent 1")
	agent2ID := intTestAgent(t, server, "auth-agent2", "Auth Agent 2")
	token := intTestUser(t, server, "authuser")

	// Connect both agents
	agent1Conn := intWsDialAgent(t, server, agent1ID)
	defer agent1Conn.Close()
	readWSMessage(t, agent1Conn, 2*time.Second)

	agent2Conn := intWsDialAgent(t, server, agent2ID)
	defer agent2Conn.Close()
	readWSMessage(t, agent2Conn, 2*time.Second)

	// Create conversation between user and agent1
	form := url.Values{"agent_id": {agent1ID}}
	resp, _ := httpPostFormWithAuth(server.URL+"/conversations/create", form, token)
	defer resp.Body.Close()
	var convResp map[string]string
	json.NewDecoder(resp.Body).Decode(&convResp)
	convID := convResp["conversation_id"]

	// Agent2 tries to send a message to this conversation (unauthorized)
	badMsg := map[string]interface{}{
		"type": "message",
		"data": map[string]interface{}{
			"conversation_id": convID,
			"content":         "Unauthorized!",
		},
	}
	msgBytes, _ := json.Marshal(badMsg)
	agent2Conn.WriteMessage(websocket.TextMessage, msgBytes)

	// Agent2 should receive an error
	msgType, _ := readWSMessage(t, agent2Conn, 2*time.Second)
	if msgType != "error" {
		t.Fatalf("expected 'error' for unauthorized message, got %q", msgType)
	}
}

// httpPostFormWithAuth is a helper for POST with Authorization header.
func httpPostFormWithAuth(url string, data url.Values, token string) (*http.Response, error) {
	req, err := http.NewRequest("POST", url, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	return http.DefaultClient.Do(req)
}
