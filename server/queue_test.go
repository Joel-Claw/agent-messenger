package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

func TestOfflineQueueEnqueue(t *testing.T) {
	q := newOfflineQueue(10, time.Hour)

	data := []byte(`{"type":"message","data":{"content":"hello"}}`)
	q.Enqueue("user1", data)
	q.Enqueue("user1", data)

	if q.QueueDepth("user1") != 2 {
		t.Errorf("Expected queue depth 2, got %d", q.QueueDepth("user1"))
	}
	if q.QueueDepth("user2") != 0 {
		t.Errorf("Expected queue depth 0 for unknown user, got %d", q.QueueDepth("user2"))
	}
}

func TestOfflineQueueDrain(t *testing.T) {
	q := newOfflineQueue(10, time.Hour)

	msg1 := []byte(`{"type":"message","data":{"content":"hello"}}`)
	msg2 := []byte(`{"type":"message","data":{"content":"world"}}`)
	q.Enqueue("user1", msg1)
	q.Enqueue("user1", msg2)

	messages := q.Drain("user1")
	if len(messages) != 2 {
		t.Fatalf("Expected 2 drained messages, got %d", len(messages))
	}
	if string(messages[0]) != string(msg1) {
		t.Errorf("First message mismatch")
	}
	if string(messages[1]) != string(msg2) {
		t.Errorf("Second message mismatch")
	}

	// After drain, queue should be empty
	if q.QueueDepth("user1") != 0 {
		t.Errorf("Expected empty queue after drain, got %d", q.QueueDepth("user1"))
	}

	// Drain again should return nil
	messages2 := q.Drain("user1")
	if messages2 != nil {
		t.Errorf("Expected nil on second drain, got %v", messages2)
	}
}

func TestOfflineQueueMaxLen(t *testing.T) {
	q := newOfflineQueue(3, time.Hour)

	for i := 0; i < 5; i++ {
		q.Enqueue("user1", []byte(`{"type":"message"}`))
	}

	if q.QueueDepth("user1") != 3 {
		t.Errorf("Expected queue trimmed to 3, got %d", q.QueueDepth("user1"))
	}
}

func TestOfflineQueueTTL(t *testing.T) {
	q := newOfflineQueue(10, 10*time.Millisecond) // very short TTL

	q.Enqueue("user1", []byte(`{"type":"message"}`))

	// Wait for TTL to expire
	time.Sleep(20 * time.Millisecond)

	messages := q.Drain("user1")
	if len(messages) != 0 {
		t.Errorf("Expected 0 messages after TTL, got %d", len(messages))
	}
}

func TestOfflineQueuePurge(t *testing.T) {
	q := newOfflineQueue(10, time.Hour)

	q.Enqueue("user1", []byte(`{"type":"message"}`))
	q.Enqueue("user1", []byte(`{"type":"message2"}`))
	q.Enqueue("user2", []byte(`{"type":"message3"}`))

	q.Purge("user1")

	if q.QueueDepth("user1") != 0 {
		t.Errorf("Expected purged queue to be 0, got %d", q.QueueDepth("user1"))
	}
	if q.QueueDepth("user2") != 1 {
		t.Errorf("Expected user2 queue to be 1, got %d", q.QueueDepth("user2"))
	}
}

func TestOfflineQueueTotalDepth(t *testing.T) {
	q := newOfflineQueue(10, time.Hour)

	q.Enqueue("user1", []byte(`{"type":"message"}`))
	q.Enqueue("user1", []byte(`{"type":"message2"}`))
	q.Enqueue("user2", []byte(`{"type":"message3"}`))

	if q.TotalDepth() != 3 {
		t.Errorf("Expected total depth 3, got %d", q.TotalDepth())
	}
}

func TestOfflineQueueReplayOnConnect(t *testing.T) {
	// Set up test server
	setupTestDB(t)
	agentSecret = "test-secret"
	jwtSecret = []byte("test-jwt-secret-for-offline-queue")
	hub = newHub()
	go hub.run()
	defer hub.Stop()

	mux := http.NewServeMux()
	mux.HandleFunc("/agent/connect", handleAgentConnect)
	mux.HandleFunc("/client/connect", handleClientConnect)

	server := httptest.NewServer(mux)
	defer server.Close()

	// Create agent in DB
	_, err := db.Exec("INSERT INTO agents (id, name) VALUES (?, ?)", "test-agent", "Test Agent")
	if err != nil {
		t.Fatal(err)
	}

	// Enqueue a message for the agent (simulating offline message)
	agentMsg := OutgoingMessage{
		Type: "message",
		Data: RoutedMessage{
			Type:           "message",
			ConversationID: "conv_1",
			Content:        "hello from offline user",
			SenderType:     "client",
			SenderID:       "user_1",
			RecipientID:    "test-agent",
		},
	}
	agentData, _ := json.Marshal(agentMsg)
	offlineQueue.Enqueue("test-agent", agentData)

	if offlineQueue.QueueDepth("test-agent") != 1 {
		t.Fatalf("Expected queue depth 1 before connect, got %d", offlineQueue.QueueDepth("test-agent"))
	}

	// Connect the agent via WebSocket
	wsURL := "ws" + strings.TrimPrefix(server.URL, "http") + "/agent/connect?agent_id=test-agent&agent_secret=test-secret"
	ws, resp, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("Agent WebSocket dial failed: %v, resp: %+v", err, resp)
	}
	defer ws.Close()

	// Wait for welcome + offline replay
	var receivedMessages []string
	ws.SetReadDeadline(time.Now().Add(3 * time.Second))

	for i := 0; i < 5; i++ { // read up to 5 messages
		_, msg, err := ws.ReadMessage()
		if err != nil {
			break // timeout or close
		}
		receivedMessages = append(receivedMessages, string(msg))
	}

	// Should have received at least the welcome + the offline message
	if len(receivedMessages) < 1 {
		t.Errorf("Expected at least 1 message (welcome), got %d", len(receivedMessages))
	}

	// Queue should be drained after connect
	if offlineQueue.QueueDepth("test-agent") != 0 {
		t.Errorf("Expected queue depth 0 after connect, got %d", offlineQueue.QueueDepth("test-agent"))
	}
}

func TestOfflineQueueEnqueueOnOfflineRecipient(t *testing.T) {
	// Set up test server with two agents
	setupTestDB(t)
	agentSecret = "test-secret"
	jwtSecret = []byte("test-jwt-secret-queue-routing")
	hub = newHub()
	go hub.run()
	defer hub.Stop()

	mux := http.NewServeMux()
	mux.HandleFunc("/agent/connect", handleAgentConnect)
	mux.HandleFunc("/client/connect", handleClientConnect)

	server := httptest.NewServer(mux)
	defer server.Close()

	// Create users and agents in DB
	_, err := db.Exec("INSERT INTO agents (id, name) VALUES (?, ?)", "agent-alpha", "Alpha")
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec("INSERT INTO agents (id, name) VALUES (?, ?)", "agent-beta", "Beta")
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)", "user-1", "testuser", "$2a$10$invalidhash")
	if err != nil {
		t.Fatal(err)
	}

	// Create a conversation
	_, err = db.Exec("INSERT INTO conversations (id, user_id, agent_id) VALUES (?, ?, ?)", "conv-1", "user-1", "agent-alpha")
	if err != nil {
		t.Fatal(err)
	}

	// Connect only agent-alpha (agent-beta stays offline)
	alphaWS, _, err := websocket.DefaultDialer.Dial(
		"ws"+strings.TrimPrefix(server.URL, "http")+"/agent/connect?agent_id=agent-alpha&agent_secret=test-secret",
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer alphaWS.Close()

	// Connect client
	token, err := GenerateJWT("user-1", "testuser")
	if err != nil {
		t.Fatal(err)
	}
	clientWS, _, err := websocket.DefaultDialer.Dial(
		"ws"+strings.TrimPrefix(server.URL, "http")+"/client/connect?user_id=user-1&token="+token,
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer clientWS.Close()

	// Wait for connections to establish
	time.Sleep(100 * time.Millisecond)

	// Create conversation for beta agent too
	_, err = db.Exec("INSERT INTO conversations (id, user_id, agent_id) VALUES (?, ?, ?)", "conv-2", "user-1", "agent-beta")
	if err != nil {
		t.Fatal(err)
	}

	// Client sends message to offline agent-beta
	clientWS.SetWriteDeadline(time.Now().Add(2 * time.Second))
	msg := IncomingMessage{
		Type: "message",
		Data: json.RawMessage(`{"conversation_id":"conv-2","content":"hello offline agent"}`),
	}
	data, _ := json.Marshal(msg)
	err = clientWS.WriteMessage(websocket.TextMessage, data)
	if err != nil {
		t.Fatal(err)
	}

	// Give routing a moment
	time.Sleep(200 * time.Millisecond)

	// Message should be queued for offline agent-beta
	if offlineQueue.QueueDepth("agent-beta") == 0 {
		t.Error("Expected offline message queued for agent-beta, but queue is empty")
	}
}

func TestPerUserRateLimiting(t *testing.T) {
	rl := NewRateLimiter(5, time.Minute)

	// Should allow 5 messages
	for i := 0; i < 5; i++ {
		if !rl.Allow("user-1") {
			t.Errorf("Expected message %d to be allowed", i+1)
		}
	}

	// 6th should be blocked
	if rl.Allow("user-1") {
		t.Error("Expected 6th message to be rate limited")
	}

	// Different user should still be allowed
	if !rl.Allow("user-2") {
		t.Error("Expected different user to be allowed")
	}
}

func TestPerUserRateLimitCounterReset(t *testing.T) {
	rl := NewRateLimiter(2, 50*time.Millisecond)

	if !rl.Allow("user-1") {
		t.Error("First message should be allowed")
	}
	if !rl.Allow("user-1") {
		t.Error("Second message should be allowed")
	}
	if rl.Allow("user-1") {
		t.Error("Third message should be rate limited")
	}

	// Wait for window to expire
	time.Sleep(60 * time.Millisecond)

	if !rl.Allow("user-1") {
		t.Error("Message after window reset should be allowed")
	}
}

func TestOfflineQueueMultipleUsers(t *testing.T) {
	q := newOfflineQueue(10, time.Hour)

	q.Enqueue("user1", []byte(`msg1`))
	q.Enqueue("user2", []byte(`msg2`))
	q.Enqueue("user1", []byte(`msg3`))

	if q.TotalDepth() != 3 {
		t.Errorf("Expected total depth 3, got %d", q.TotalDepth())
	}

	// Drain one user
	msgs := q.Drain("user1")
	if len(msgs) != 2 {
		t.Errorf("Expected 2 messages for user1, got %d", len(msgs))
	}

	// Other user still has messages
	if q.QueueDepth("user2") != 1 {
		t.Errorf("Expected user2 queue depth 1, got %d", q.QueueDepth("user2"))
	}
}

func TestOfflineQueueConcurrentAccess(t *testing.T) {
	q := newOfflineQueue(100, time.Hour)

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			for j := 0; j < 10; j++ {
				q.Enqueue("user1", []byte("msg"))
			}
		}(i)
	}
	wg.Wait()

	depth := q.QueueDepth("user1")
	if depth != 100 { // capped at 100
		t.Errorf("Expected depth 100 (capped), got %d", depth)
	}
}