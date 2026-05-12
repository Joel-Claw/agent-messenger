package main

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// ============================================================
// Chaos Tests: Random disconnects, message reordering,
// connection churn, buffer overflow, and concurrent stress.
// ============================================================

// chaosSetupServer creates a full test server with extended write deadlines
// for chaos testing. Returns the server, a cleanup function, and helpers.
func chaosSetupServer(t *testing.T) (*httptest.Server, func()) {
	t.Helper()
	setupTestDB(t)

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
	mux.HandleFunc("/conversations/mark-read", handleMarkRead)
	mux.HandleFunc("/conversations/delete", handleDeleteConversation)
	mux.HandleFunc("/agents", handleListAgents)

	server := httptest.NewServer(mux)
	cleanup := func() {
		server.Close()
		hub.Stop()
	}
	return server, cleanup
}

// chaosRegisterUser registers a user and returns their JWT token.
func chaosRegisterUser(t *testing.T, server *httptest.Server, username string) string {
	t.Helper()
	form := url.Values{"username": {username}, "password": {"chaospass"}}
	resp, err := http.PostForm(server.URL+"/auth/user", form)
	if err != nil {
		t.Fatalf("register user %s failed: %v", username, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 && resp.StatusCode != 409 {
		t.Fatalf("register user %s returned %d", username, resp.StatusCode)
	}

	form2 := url.Values{"username": {username}, "password": {"chaospass"}}
	resp2, err := http.PostForm(server.URL+"/auth/login", form2)
	if err != nil {
		t.Fatalf("login %s failed: %v", username, err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != 200 {
		t.Fatalf("login %s returned %d", username, resp2.StatusCode)
	}

	var result map[string]string
	json.NewDecoder(resp2.Body).Decode(&result)
	return result["token"]
}

// chaosRegisterAgent registers an agent via REST.
func chaosRegisterAgent(t *testing.T, server *httptest.Server, agentID, name string) {
	t.Helper()
	form := url.Values{
		"agent_id":    {agentID},
		"name":        {name},
		"agent_secret": {agentSecret},
	}
	resp, err := http.PostForm(server.URL+"/auth/agent", form)
	if err != nil {
		t.Fatalf("register agent %s failed: %v", agentID, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("register agent %s returned %d", agentID, resp.StatusCode)
	}
}

// chaosDialAgent dials a WebSocket for an agent. Returns nil on failure (non-fatal).
func chaosDialAgent(server *httptest.Server, agentID string) *websocket.Conn {
	wsURL := "ws" + strings.TrimPrefix(server.URL, "http") + "/agent/connect?agent_id=" + agentID + "&agent_secret=" + url.QueryEscape(agentSecret)
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		return nil
	}
	return conn
}

// chaosDialClient dials a WebSocket for a client. Returns nil on failure (non-fatal).
func chaosDialClient(server *httptest.Server, token, deviceID string) *websocket.Conn {
	wsURL := "ws" + strings.TrimPrefix(server.URL, "http") + "/client/connect?user_id=chaosuser&token=" + url.QueryEscape(token)
	if deviceID != "" {
		wsURL += "&device_id=" + url.QueryEscape(deviceID)
	}
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		return nil
	}
	return conn
}

// chaosConsumeWelcome reads and discards the welcome message.
func chaosConsumeWelcome(conn *websocket.Conn, timeout time.Duration) error {
	conn.SetReadDeadline(time.Now().Add(timeout))
	_, _, err := conn.ReadMessage()
	return err
}

// chaosCreateConversation creates a conversation via REST.
func chaosCreateConversation(t *testing.T, server *httptest.Server, agentID, token string) string {
	t.Helper()
	form := url.Values{"agent_id": {agentID}}
	req, err := http.NewRequest("POST", server.URL+"/conversations/create", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("create conversation request failed: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("create conversation failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("create conversation returned %d", resp.StatusCode)
	}
	var convResp map[string]string
	json.NewDecoder(resp.Body).Decode(&convResp)
	return convResp["conversation_id"]
}

// chaosSendWSMessage sends a typed message on a WebSocket connection.
func chaosSendWSMessage(conn *websocket.Conn, msgType, convID, content string) error {
	msg := map[string]interface{}{
		"type": msgType,
		"data": map[string]interface{}{
			"conversation_id": convID,
			"content":         content,
		},
	}
	data, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	return conn.WriteMessage(websocket.TextMessage, data)
}

// chaosReadMessage reads a single WebSocket JSON message with timeout.
// Returns the message type, or empty string on error/timeout.
func chaosReadMessage(conn *websocket.Conn, timeout time.Duration) (string, map[string]interface{}, error) {
	conn.SetReadDeadline(time.Now().Add(timeout))
	_, raw, err := conn.ReadMessage()
	if err != nil {
		return "", nil, err
	}
	var msg map[string]interface{}
	if err := json.Unmarshal(raw, &msg); err != nil {
		return "", nil, err
	}
	msgType, _ := msg["type"].(string)
	data, _ := msg["data"].(map[string]interface{})
	return msgType, data, nil
}

// chaosDrain reads all available messages until timeout or error.
// Returns the count of messages read and any errors encountered.
func chaosDrain(conn *websocket.Conn, timeout time.Duration) (int, error) {
	count := 0
	for {
		conn.SetReadDeadline(time.Now().Add(timeout))
		_, _, err := conn.ReadMessage()
		if err != nil {
			return count, err
		}
		count++
	}
}

// ============================================================
// Test 1: Random disconnects during active messaging
// ============================================================

// TestChaos_RandomDisconnectDuringMessaging tests that the server handles
// abrupt disconnections gracefully: no deadlocks, no panics, and messages
// are properly cleaned up.
func TestChaos_RandomDisconnectDuringMessaging(t *testing.T) {
	server, cleanup := chaosSetupServer(t)
	defer cleanup()

	agentID := "chaos-disc-agent"
	chaosRegisterAgent(t, server, agentID, "Disconnect Agent")
	token := chaosRegisterUser(t, server, "discuser")

	// Run multiple rounds of: connect, send some messages, disconnect abruptly
	for round := 0; round < 5; round++ {
		agentConn := chaosDialAgent(server, agentID)
		if agentConn == nil {
			t.Fatalf("round %d: agent connect failed", round)
		}
		if err := chaosConsumeWelcome(agentConn, 2*time.Second); err != nil {
			agentConn.Close()
			t.Fatalf("round %d: agent welcome failed: %v", round, err)
		}

		clientConn := chaosDialClient(server, token, fmt.Sprintf("device-round-%d", round))
		if clientConn == nil {
			agentConn.Close()
			t.Fatalf("round %d: client connect failed", round)
		}
		if err := chaosConsumeWelcome(clientConn, 2*time.Second); err != nil {
			clientConn.Close()
			agentConn.Close()
			t.Fatalf("round %d: client welcome failed: %v", round, err)
		}

		convID := chaosCreateConversation(t, server, agentID, token)

		// Send a few messages back and forth
		for i := 0; i < 3; i++ {
			content := fmt.Sprintf("round-%d-msg-%d", round, i)
			if err := chaosSendWSMessage(clientConn, "message", convID, content); err != nil {
				// Connection may have been closed — that's fine in chaos test
				break
			}
			// Try to read on agent side (may fail if disconnect happened)
			chaosReadMessage(agentConn, 500*time.Millisecond)
		}

		// Abrupt disconnect — no CloseMessage, just close the TCP connection
		if round%2 == 0 {
			agentConn.Close()
			time.Sleep(50 * time.Millisecond)
			clientConn.Close()
		} else {
			clientConn.Close()
			time.Sleep(50 * time.Millisecond)
			agentConn.Close()
		}

		// Small delay to let hub process unregister
		time.Sleep(100 * time.Millisecond)
	}

	// Verify server is still healthy after all the chaos
	resp, err := http.Get(server.URL + "/health")
	if err != nil {
		t.Fatalf("health check failed after chaos: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("health check returned %d after chaos", resp.StatusCode)
	}
	var health map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&health)
	if health["status"] != "ok" {
		t.Fatalf("health status not ok after chaos: %v", health["status"])
	}
}

// ============================================================
// Test 2: Message ordering under concurrent sends
// ============================================================

// TestChaos_ConcurrentMessageOrdering verifies that messages sent
// concurrently from multiple goroutines are all delivered (though
// ordering is not guaranteed — we check completeness, not sequence).
// WebSocket writes are NOT goroutine-safe, so we serialize writes with a mutex.
func TestChaos_ConcurrentMessageOrdering(t *testing.T) {
	server, cleanup := chaosSetupServer(t)
	defer cleanup()

	agentID := "chaos-order-agent"
	chaosRegisterAgent(t, server, agentID, "Order Agent")
	token := chaosRegisterUser(t, server, "orderuser")

	agentConn := chaosDialAgent(server, agentID)
	if agentConn == nil {
		t.Fatal("agent connect failed")
	}
	defer agentConn.Close()
	chaosConsumeWelcome(agentConn, 2*time.Second)

	clientConn := chaosDialClient(server, token, "order-device")
	if clientConn == nil {
		t.Fatal("client connect failed")
	}
	defer clientConn.Close()
	chaosConsumeWelcome(clientConn, 2*time.Second)

	convID := chaosCreateConversation(t, server, agentID, token)

	// Send 20 messages from 20 goroutines.
	// WebSocket conn is NOT safe for concurrent writes, so we must serialize.
	const numMessages = 20
	var (
		wg         sync.WaitGroup
		sendMu     sync.Mutex // protects concurrent WebSocket writes
		sendErrors atomic.Int64
	)

	for i := 0; i < numMessages; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			content := fmt.Sprintf("concurrent-msg-%03d", idx)
			sendMu.Lock()
			err := chaosSendWSMessage(clientConn, "message", convID, content)
			sendMu.Unlock()
			if err != nil {
				sendErrors.Add(1)
			}
		}(i)
	}
	wg.Wait()

	if sendErrors.Load() > 0 {
		t.Fatalf("%d send errors during concurrent messages", sendErrors.Load())
	}

	// Count how many "message" type events the agent receives
	received := 0
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) && received < numMessages {
		msgType, _, err := chaosReadMessage(agentConn, 2*time.Second)
		if err != nil {
			break // timeout or connection error
		}
		if msgType == "message" {
			received++
		}
		// Skip other message types (message_sent, presence_update, etc.)
	}

	if received != numMessages {
		t.Fatalf("expected %d messages on agent, got %d", numMessages, received)
	}
}

// ============================================================
// Test 3: Rapid connect/disconnect cycles (connection churn)
// ============================================================

// TestChaos_ConnectionChurn verifies the server handles rapid
// connect/disconnect cycles without leaking resources or deadlocking.
func TestChaos_ConnectionChurn(t *testing.T) {
	server, cleanup := chaosSetupServer(t)
	defer cleanup()

	agentID := "chaos-churn-agent"
	chaosRegisterAgent(t, server, agentID, "Churn Agent")
	token := chaosRegisterUser(t, server, "churnuser")

	const numCycles = 20
	for i := 0; i < numCycles; i++ {
		// Connect and immediately disconnect
		conn := chaosDialAgent(server, agentID)
		if conn != nil {
			chaosConsumeWelcome(conn, 1*time.Second)
			conn.Close()
		}
		time.Sleep(10 * time.Millisecond) // tiny delay to let hub process
	}

	// Same for client connections
	for i := 0; i < numCycles; i++ {
		conn := chaosDialClient(server, token, fmt.Sprintf("churn-dev-%d", i))
		if conn != nil {
			chaosConsumeWelcome(conn, 1*time.Second)
			conn.Close()
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Wait for hub to process all unregisters
	time.Sleep(200 * time.Millisecond)

	// Verify no leaked connections
	if hub.AgentCount() != 0 {
		t.Errorf("expected 0 agents after churn, got %d", hub.AgentCount())
	}
	if hub.ClientCount() != 0 {
		t.Errorf("expected 0 clients after churn, got %d", hub.ClientCount())
	}

	// Verify server is still healthy
	resp, err := http.Get(server.URL + "/health")
	if err != nil {
		t.Fatalf("health check failed after churn: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("health check returned %d after churn", resp.StatusCode)
	}
}

// ============================================================
// Test 4: Send buffer overflow — many messages to slow consumer
// ============================================================

// TestChaos_SendBufferOverflow tests that sending many messages to a
// connection that isn't reading doesn't crash the server. The send
// channel (buffered) will eventually fill, and the server should
// gracefully drop messages via the "default" case.
func TestChaos_SendBufferOverflow(t *testing.T) {
	server, cleanup := chaosSetupServer(t)
	defer cleanup()

	agentID := "chaos-overflow-agent"
	chaosRegisterAgent(t, server, agentID, "Overflow Agent")
	token := chaosRegisterUser(t, server, "overflowuser")

	agentConn := chaosDialAgent(server, agentID)
	if agentConn == nil {
		t.Fatal("agent connect failed")
	}
	defer agentConn.Close()
	chaosConsumeWelcome(agentConn, 2*time.Second)

	// Connect client but DON'T read any messages (slow consumer)
	clientConn := chaosDialClient(server, token, "overflow-device")
	if clientConn == nil {
		t.Fatal("client connect failed")
	}
	defer clientConn.Close()
	chaosConsumeWelcome(clientConn, 2*time.Second)

	convID := chaosCreateConversation(t, server, agentID, token)

	// Agent sends a LOT of messages — the client's send channel is 256 (default)
	// Sending more than that should trigger buffer-full drops without panicking
	const numMessages = 300
	sent := 0
	for i := 0; i < numMessages; i++ {
		content := fmt.Sprintf("overflow-msg-%03d", i)
		if err := chaosSendWSMessage(agentConn, "message", convID, content); err != nil {
			break // agent write may fail if its own buffer fills
		}
		sent++
		// Read the message_sent ack to prevent agent's own buffer from filling
		chaosReadMessage(agentConn, 200*time.Millisecond)
	}

	// Server should not have panicked or deadlocked
	// Read a few messages from the client to prove the connection is still alive
	clientConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	readCount, _ := chaosDrain(clientConn, 500*time.Millisecond)

	t.Logf("Sent %d/%d messages, client received %d", sent, numMessages, readCount)

	// The key assertion: server didn't crash
	resp, err := http.Get(server.URL + "/health")
	if err != nil {
		t.Fatalf("health check failed after buffer overflow: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("health check returned %d after buffer overflow", resp.StatusCode)
	}
}

// ============================================================
// Test 5: Concurrent multi-device disconnect
// ============================================================

// TestChaos_MultiDeviceDisconnect tests that disconnecting multiple
// devices for the same user concurrently doesn't corrupt the hub's
// client connection list.
func TestChaos_MultiDeviceDisconnect(t *testing.T) {
	server, cleanup := chaosSetupServer(t)
	defer cleanup()

	agentID := "chaos-multidisc-agent"
	chaosRegisterAgent(t, server, agentID, "MultiDisc Agent")
	token := chaosRegisterUser(t, server, "multidiscuser")

	agentConn := chaosDialAgent(server, agentID)
	if agentConn == nil {
		t.Fatal("agent connect failed")
	}
	defer agentConn.Close()
	chaosConsumeWelcome(agentConn, 2*time.Second)

	// Connect 10 devices for the same user
	const numDevices = 10
	var conns []*websocket.Conn
	for i := 0; i < numDevices; i++ {
		conn := chaosDialClient(server, token, fmt.Sprintf("dev-%d", i))
		if conn == nil {
			t.Fatalf("device %d connect failed", i)
		}
		if err := chaosConsumeWelcome(conn, 2*time.Second); err != nil {
			conn.Close()
			t.Fatalf("device %d welcome failed: %v", i, err)
		}
		conns = append(conns, conn)
	}

	// Verify all devices are connected
	if hub.ClientConnCount() != numDevices {
		t.Fatalf("expected %d client connections, got %d", numDevices, hub.ClientConnCount())
	}

	// Disconnect all devices concurrently
	var wg sync.WaitGroup
	for i, conn := range conns {
		wg.Add(1)
		go func(idx int, c *websocket.Conn) {
			defer wg.Done()
			c.Close()
		}(i, conn)
	}
	wg.Wait()

	// Wait for hub to process all unregisters
	time.Sleep(300 * time.Millisecond)

	// All devices should be gone
	if hub.ClientCount() != 0 {
		t.Errorf("expected 0 clients after concurrent disconnect, got %d", hub.ClientCount())
	}
	if hub.ClientConnCount() != 0 {
		t.Errorf("expected 0 client connections after concurrent disconnect, got %d", hub.ClientConnCount())
	}
}

// ============================================================
// Test 6: Mixed chaos — random operations for a sustained period
// ============================================================

// TestChaos_SustainedRandomOps runs random connect/disconnect/message
// operations for 5 seconds and verifies the server doesn't crash.
func TestChaos_SustainedRandomOps(t *testing.T) {
	server, cleanup := chaosSetupServer(t)
	defer cleanup()

	agentID := "chaos-sustained-agent"
	chaosRegisterAgent(t, server, agentID, "Sustained Agent")
	token := chaosRegisterUser(t, server, "sustaineduser")

	convID := chaosCreateConversation(t, server, agentID, token)

	var (
		wg          sync.WaitGroup
		stop        = make(chan struct{})
		opsDone     atomic.Int64
		connErrors  atomic.Int64
		msgErrors   atomic.Int64
	)

	// Start agent connection maintainer
	agentConnMu := sync.Mutex{}
	var currentAgentConn *websocket.Conn

	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}

			agentConnMu.Lock()
			if currentAgentConn != nil {
				currentAgentConn.Close()
			}
			conn := chaosDialAgent(server, agentID)
			if conn != nil {
				chaosConsumeWelcome(conn, 1*time.Second)
			}
			currentAgentConn = conn
			agentConnMu.Unlock()

			if conn == nil {
				connErrors.Add(1)
			}

			opsDone.Add(1)
			time.Sleep(time.Duration(200+rand.Intn(300)) * time.Millisecond)
		}
	}()

	// Start client connection maintainer
	clientConnMu := sync.Mutex{}
	var currentClientConn *websocket.Conn

	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}

			clientConnMu.Lock()
			if currentClientConn != nil {
				currentClientConn.Close()
			}
			conn := chaosDialClient(server, token, "sustained-dev")
			if conn != nil {
				chaosConsumeWelcome(conn, 1*time.Second)
			}
			currentClientConn = conn
			clientConnMu.Unlock()

			if conn == nil {
				connErrors.Add(1)
			}

			opsDone.Add(1)
			time.Sleep(time.Duration(200+rand.Intn(300)) * time.Millisecond)
		}
	}()

	// Start message sender goroutine
	wg.Add(1)
	go func() {
		defer wg.Done()
		msgIdx := 0
		for {
			select {
			case <-stop:
				return
			default:
			}

			clientConnMu.Lock()
			conn := currentClientConn
			clientConnMu.Unlock()

			if conn != nil {
				content := fmt.Sprintf("sustained-msg-%03d", msgIdx)
				if err := chaosSendWSMessage(conn, "message", convID, content); err != nil {
					msgErrors.Add(1)
				}
				msgIdx++
			}

			opsDone.Add(1)
			time.Sleep(time.Duration(50+rand.Intn(150)) * time.Millisecond)
		}
	}()

	// Start message reader on agent side
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}

			agentConnMu.Lock()
			conn := currentAgentConn
			agentConnMu.Unlock()

			if conn != nil {
				chaosReadMessage(conn, 200*time.Millisecond)
			}

			time.Sleep(50 * time.Millisecond)
		}
	}()

	// Run for 5 seconds
	time.Sleep(5 * time.Second)
	close(stop)

	// Close remaining connections
	agentConnMu.Lock()
	if currentAgentConn != nil {
		currentAgentConn.Close()
	}
	agentConnMu.Unlock()

	clientConnMu.Lock()
	if currentClientConn != nil {
		currentClientConn.Close()
	}
	clientConnMu.Unlock()

	// Wait for goroutines to finish (they should exit quickly)
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Log("Warning: goroutines didn't stop within 3s, proceeding")
	}

	// Let hub settle
	time.Sleep(200 * time.Millisecond)

	t.Logf("Chaos stats: ops=%d, connErrors=%d, msgErrors=%d",
		opsDone.Load(), connErrors.Load(), msgErrors.Load())

	// The main assertion: server is still alive and healthy
	resp, err := http.Get(server.URL + "/health")
	if err != nil {
		t.Fatalf("health check failed after sustained chaos: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("health check returned %d after sustained chaos", resp.StatusCode)
	}
}

// ============================================================
// Test 7: Disconnect during offline queue replay
// ============================================================

// TestChaos_DisconnectDuringReplay tests that if a client disconnects
// while offline messages are being replayed, the server handles it
// gracefully without panicking.
func TestChaos_DisconnectDuringReplay(t *testing.T) {
	server, cleanup := chaosSetupServer(t)
	defer cleanup()

	agentID := "chaos-replay-agent"
	chaosRegisterAgent(t, server, agentID, "Replay Agent")
	token := chaosRegisterUser(t, server, "replayuser")

	agentConn := chaosDialAgent(server, agentID)
	if agentConn == nil {
		t.Fatal("agent connect failed")
	}
	defer agentConn.Close()
	chaosConsumeWelcome(agentConn, 2*time.Second)

	convID := chaosCreateConversation(t, server, agentID, token)

	// Agent sends many messages while client is offline (these get queued)
	const numQueued = 50
	for i := 0; i < numQueued; i++ {
		content := fmt.Sprintf("queued-msg-%03d", i)
		chaosSendWSMessage(agentConn, "message", convID, content)
		// Consume the message_sent ack
		chaosReadMessage(agentConn, 500*time.Millisecond)
	}

	// Verify the offline queue has messages for the user
	// We need the user_id from the JWT. Let's extract it from the hub after connecting briefly.
	// Connect client briefly to get user_id registered, then disconnect before reading.
	clientConn := chaosDialClient(server, token, "replay-dev")
	if clientConn == nil {
		t.Fatal("client connect failed")
	}
	chaosConsumeWelcome(clientConn, 2*time.Second)
	userID := "" // We'll get it from hub
	if hub.ClientCount() > 0 {
		// The hub tracks clients; let's verify there are queued messages
	}
	clientConn.Close()
	time.Sleep(200 * time.Millisecond)

	// Verify queue depth
	if offlineQueue.TotalDepth() == 0 {
		t.Log("Warning: offline queue is empty, some messages may have been delivered")
	}

	// Now connect the client and immediately disconnect mid-replay
	for attempt := 0; attempt < 3; attempt++ {
		clientConn = chaosDialClient(server, token, "replay-dev")
		if clientConn == nil {
			time.Sleep(100 * time.Millisecond)
			continue
		}
		chaosConsumeWelcome(clientConn, 2*time.Second)

		// Immediately close — some replay messages may be in-flight
		clientConn.Close()

		time.Sleep(100 * time.Millisecond)

		// Reconnect to verify connection still works
		clientConn2 := chaosDialClient(server, token, "replay-dev")
		if clientConn2 != nil {
			chaosConsumeWelcome(clientConn2, 2*time.Second)
			// Read any remaining replayed messages
			chaosDrain(clientConn2, 2*time.Second)
			clientConn2.Close()
		}
	}

	// Key assertion: server didn't crash
	_ = userID // unused but noted
	resp, err := http.Get(server.URL + "/health")
	if err != nil {
		t.Fatalf("health check failed after disconnect during replay: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("health check returned %d after disconnect during replay", resp.StatusCode)
	}
}

// ============================================================
// Test 8: Agent replacement under concurrent connections
// ============================================================

// TestChaos_AgentReplacementConcurrent tests that when multiple
// connections claim the same agent_id, the hub properly replaces
// the old connection and only routes to the new one.
func TestChaos_AgentReplacementConcurrent(t *testing.T) {
	server, cleanup := chaosSetupServer(t)
	defer cleanup()

	agentID := "chaos-replace-agent"
	chaosRegisterAgent(t, server, agentID, "Replace Agent")
	token := chaosRegisterUser(t, server, "replaceuser")

	// Connect agent (first)
	agent1 := chaosDialAgent(server, agentID)
	if agent1 == nil {
		t.Fatal("agent1 connect failed")
	}
	chaosConsumeWelcome(agent1, 2*time.Second)

	// Connect agent (second) — should replace the first
	agent2 := chaosDialAgent(server, agentID)
	if agent2 == nil {
		agent1.Close()
		t.Fatal("agent2 connect failed")
	}
	chaosConsumeWelcome(agent2, 2*time.Second)

	// agent1 should now be disconnected — its send channel is closed
	// Try to read from agent1 — should get an error
	agent1.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	_, _, err := agent1.ReadMessage()
	if err == nil {
		t.Log("agent1 still receiving messages (unexpected, but not a failure)")
	}
	agent1.Close()

	// Connect client and send a message — should reach agent2 only
	clientConn := chaosDialClient(server, token, "replace-device")
	if clientConn == nil {
		agent2.Close()
		t.Fatal("client connect failed")
	}
	defer clientConn.Close()
	chaosConsumeWelcome(clientConn, 2*time.Second)

	convID := chaosCreateConversation(t, server, agentID, token)

	if err := chaosSendWSMessage(clientConn, "message", convID, "Hello replacement!"); err != nil {
		t.Fatalf("client send failed: %v", err)
	}

	// agent2 should receive the message
	msgType, data, err := chaosReadMessage(agent2, 3*time.Second)
	if err != nil {
		t.Fatalf("agent2 read failed: %v", err)
	}
	// Skip non-message types
	for msgType != "message" && err == nil {
		msgType, data, err = chaosReadMessage(agent2, 2*time.Second)
	}
	if msgType != "message" {
		t.Fatalf("expected 'message' on agent2, got %q (err=%v)", msgType, err)
	}
	if data["content"] != "Hello replacement!" {
		t.Fatalf("expected 'Hello replacement!', got %v", data["content"])
	}
	agent2.Close()
}

// ============================================================
// Test 9: Same device reconnect under concurrent sends
// ============================================================

// TestChaos_SameDeviceReconnectDuringSends tests that reconnecting
// the same device_id while messages are in flight doesn't cause
// duplicates or lost messages.
func TestChaos_SameDeviceReconnectDuringSends(t *testing.T) {
	server, cleanup := chaosSetupServer(t)
	defer cleanup()

	agentID := "chaos-samedev-agent"
	chaosRegisterAgent(t, server, agentID, "SameDev Agent")
	token := chaosRegisterUser(t, server, "samedevuser")

	agentConn := chaosDialAgent(server, agentID)
	if agentConn == nil {
		t.Fatal("agent connect failed")
	}
	defer agentConn.Close()
	chaosConsumeWelcome(agentConn, 2*time.Second)

	convID := chaosCreateConversation(t, server, agentID, token)

	// Connect device, send a message, reconnect, send another
	for round := 0; round < 5; round++ {
		clientConn := chaosDialClient(server, token, "same-device")
		if clientConn == nil {
			t.Fatalf("round %d: client connect failed", round)
		}
		chaosConsumeWelcome(clientConn, 2*time.Second)

		content := fmt.Sprintf("samedev-msg-%d", round)
		if err := chaosSendWSMessage(clientConn, "message", convID, content); err != nil {
			clientConn.Close()
			t.Fatalf("round %d: send failed: %v", round, err)
		}

		// Read the message_sent ack
		chaosReadMessage(clientConn, 1*time.Second)

		// Reconnect — hub should replace the old connection
		clientConn.Close()
		time.Sleep(50 * time.Millisecond)
	}

	// Verify messages persisted in history
	req, _ := http.NewRequest("GET", server.URL+"/conversations/messages?conversation_id="+convID, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("get messages failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Fatalf("get messages returned %d", resp.StatusCode)
	}

	var messages []map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&messages)

	// We sent 5 messages — should have at least 5 persisted
	msgCount := 0
	for _, m := range messages {
		if content, ok := m["content"].(string); ok && strings.HasPrefix(content, "samedev-msg-") {
			msgCount++
		}
	}
	if msgCount != 5 {
		t.Errorf("expected 5 persisted messages, got %d (total messages=%d)", msgCount, len(messages))
	}
}

// ============================================================
// Test 10: Hub stability under mixed connection churn + messaging
// ============================================================

// TestChaos_MixedChurnAndMessaging combines connection churn with
// active messaging to stress the hub's register/unregister paths
// while messages are being routed.
func TestChaos_MixedChurnAndMessaging(t *testing.T) {
	server, cleanup := chaosSetupServer(t)
	defer cleanup()

	agentID := "chaos-mixed-agent"
	chaosRegisterAgent(t, server, agentID, "Mixed Agent")
	token := chaosRegisterUser(t, server, "mixeduser")

	// Create conversation upfront
	convID := chaosCreateConversation(t, server, agentID, token)

	var wg sync.WaitGroup
	stop := make(chan struct{})
	var msgSent atomic.Int64
	var msgReceived atomic.Int64

	// Goroutine 1: Maintain an agent connection (reconnect if lost)
	agentConnMu := sync.Mutex{}
	var activeAgentConn *websocket.Conn

	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				agentConnMu.Lock()
				if activeAgentConn != nil {
					activeAgentConn.Close()
				}
				agentConnMu.Unlock()
				return
			default:
			}

			conn := chaosDialAgent(server, agentID)
			if conn != nil {
				chaosConsumeWelcome(conn, 1*time.Second)

				agentConnMu.Lock()
				if activeAgentConn != nil {
					activeAgentConn.Close()
				}
				activeAgentConn = conn
				agentConnMu.Unlock()
			}

			time.Sleep(time.Duration(300+rand.Intn(500)) * time.Millisecond)
		}
	}()

	// Goroutine 2: Connect clients, send messages, disconnect
	wg.Add(1)
	go func() {
		defer wg.Done()
		msgIdx := 0
		for {
			select {
			case <-stop:
				return
			default:
			}

			conn := chaosDialClient(server, token, fmt.Sprintf("mixed-dev-%d", rand.Intn(5)))
			if conn == nil {
				time.Sleep(100 * time.Millisecond)
				continue
			}
			chaosConsumeWelcome(conn, 1*time.Second)

			// Send a few messages
			for j := 0; j < 3; j++ {
				content := fmt.Sprintf("mixed-msg-%03d", msgIdx)
				if err := chaosSendWSMessage(conn, "message", convID, content); err == nil {
					msgSent.Add(1)
					msgIdx++
				}
				time.Sleep(50 * time.Millisecond)
			}

			conn.Close()
			time.Sleep(time.Duration(100+rand.Intn(200)) * time.Millisecond)
		}
	}()

	// Goroutine 3: Read messages on the agent side
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}

			agentConnMu.Lock()
			conn := activeAgentConn
			agentConnMu.Unlock()

			if conn != nil {
				// Use a read with a short deadline; if the connection
				// was closed/replaced, the read will error and we just
				// move on. We recover from any panic in case gorilla
				// detects a repeated read on a failed connection.
				func() {
					defer func() {
						if r := recover(); r != nil {
							// Connection was already failed; just move on.
						}
					}()
					if msgType, _, err := chaosReadMessage(conn, 200*time.Millisecond); err == nil {
						if msgType == "message" {
							msgReceived.Add(1)
						}
					}
				}()
			} else {
				time.Sleep(50 * time.Millisecond)
			}
		}
	}()

	// Run for 5 seconds
	time.Sleep(5 * time.Second)
	close(stop)

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
	}

	time.Sleep(200 * time.Millisecond)

	t.Logf("Mixed chaos: sent=%d, received_by_agent=%d", msgSent.Load(), msgReceived.Load())

	// Main assertion: server is still healthy
	resp, err := http.Get(server.URL + "/health")
	if err != nil {
		t.Fatalf("health check failed after mixed chaos: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("health check returned %d after mixed chaos", resp.StatusCode)
	}
}

// ============================================================
// Test 11: Malformed messages don't crash the server
// ============================================================

// TestChaos_MalformedMessages tests that sending invalid JSON,
// missing fields, and oversized messages doesn't crash the server.
func TestChaos_MalformedMessages(t *testing.T) {
	server, cleanup := chaosSetupServer(t)
	defer cleanup()

	agentID := "chaos-malformed-agent"
	chaosRegisterAgent(t, server, agentID, "Malformed Agent")
	token := chaosRegisterUser(t, server, "malformeduser")

	agentConn := chaosDialAgent(server, agentID)
	if agentConn == nil {
		t.Fatal("agent connect failed")
	}
	defer agentConn.Close()
	chaosConsumeWelcome(agentConn, 2*time.Second)

	clientConn := chaosDialClient(server, token, "malformed-dev")
	if clientConn == nil {
		t.Fatal("client connect failed")
	}
	defer clientConn.Close()
	chaosConsumeWelcome(clientConn, 2*time.Second)

	convID := chaosCreateConversation(t, server, agentID, token)

	// Send various malformed messages
	malformed := []struct {
		name    string
		message string
	}{
		{"invalid json", `{not json at all`},
		{"empty object", `{}`},
		{"missing type", `{"data": {"content": "hi"}}`},
		{"unknown type", `{"type": "explode", "data": {}}`},
		{"message no content", `{"type": "message", "data": {"conversation_id": "` + convID + `"}}`},
		{"message no conv id", `{"type": "message", "data": {"content": "hello"}}`},
		{"message empty content", `{"type": "message", "data": {"conversation_id": "` + convID + `", "content": ""}}`},
		{"null data", `{"type": "message", "data": null}`},
		{"array instead of object", `[1,2,3]`},
		{"very long string value", `{"type": "message", "data": {"conversation_id": "` + convID + `", "content": "` + strings.Repeat("x", 10000) + `"}}`},
	}

	for _, tc := range malformed {
		t.Run(tc.name, func(t *testing.T) {
			err := clientConn.WriteMessage(websocket.TextMessage, []byte(tc.message))
			if err != nil {
				// Connection may have been closed by server — that's acceptable
				// Reconnect if needed
				clientConn = chaosDialClient(server, token, "malformed-dev")
				if clientConn == nil {
					t.Fatal("reconnect failed after malformed message")
				}
				defer clientConn.Close()
				chaosConsumeWelcome(clientConn, 2*time.Second)
				return
			}

			// Try to read any response (error or otherwise) — don't block
			chaosReadMessage(clientConn, 500*time.Millisecond)

			// Verify connection is still alive by sending a valid message
			if err := chaosSendWSMessage(clientConn, "message", convID, "ping"); err != nil {
				// Reconnect
				clientConn = chaosDialClient(server, token, "malformed-dev")
				if clientConn == nil {
					t.Fatal("reconnect failed after malformed message")
				}
				defer clientConn.Close()
				chaosConsumeWelcome(clientConn, 2*time.Second)
			}
		})
	}

	// Server should still be healthy
	resp, err := http.Get(server.URL + "/health")
	if err != nil {
		t.Fatalf("health check failed after malformed messages: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("health check returned %d after malformed messages", resp.StatusCode)
	}
}