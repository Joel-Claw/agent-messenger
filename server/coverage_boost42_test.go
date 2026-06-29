package main

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// ===================================================================
// routeChatMessage: agent→client all buffers full → offline queue + notify
// ===================================================================

func TestRouteChatMessage_AgentToClientAllBuffersFull(t *testing.T) {
	setupTestDB(t)

	hub = newHub()
	go hub.run()
	t.Cleanup(func() { hub.Stop() })

	// Create agent
	agent := &Connection{
		id:       "agent-cb-full",
		connType: "agent",
		send:     make(chan []byte, 10),
		hub:      hub,
	}
	hub.mu.Lock()
	hub.agents["agent-cb-full"] = agent
	hub.mu.Unlock()

	// Create client with full buffer (capacity 1)
	client := &Connection{
		id:       "user-cb-full",
		connType: "client",
		deviceID: "dev1",
		send:     make(chan []byte, 1),
		hub:      hub,
	}
	client.send <- []byte("fill")
	hub.mu.Lock()
	hub.clientConns["user-cb-full"] = []*Connection{client}
	hub.mu.Unlock()

	// Create conversation
	db.Exec("INSERT OR IGNORE INTO agents (id, name) VALUES (?, ?)", "agent-cb-full", "AgentCBFull")
	db.Exec("INSERT OR IGNORE INTO users (id, username, password_hash) VALUES (?, ?, ?)", "user-cb-full", "user-cb-full", "$2a$10$hash")
	db.Exec("INSERT INTO conversations (id, user_id, agent_id) VALUES (?, ?, ?)", "conv-cb-full", "user-cb-full", "agent-cb-full")

	msg := RoutedMessage{
		ConversationID: "conv-cb-full",
		Content:       "test message",
	}
	data, _ := json.Marshal(msg)
	routeChatMessage(agent, data)

	// Message should be in offline queue
	if offlineQueue.TotalDepth() < 1 {
		t.Error("expected offline queue to have message")
	}
}

func TestRouteChatMessage_AgentToClientOffline(t *testing.T) {
	setupTestDB(t)

	hub = newHub()
	go hub.run()
	t.Cleanup(func() { hub.Stop() })

	// Agent connected, client NOT connected
	agent := &Connection{
		id:       "agent-offline-test",
		connType: "agent",
		send:     make(chan []byte, 10),
		hub:      hub,
	}
	hub.mu.Lock()
	hub.agents["agent-offline-test"] = agent
	hub.mu.Unlock()

	db.Exec("INSERT OR IGNORE INTO agents (id, name) VALUES (?, ?)", "agent-offline-test", "AgentOffline")
	db.Exec("INSERT OR IGNORE INTO users (id, username, password_hash) VALUES (?, ?, ?)", "user-offline-test", "user-offline-test", "$2a$10$hash")
	db.Exec("INSERT INTO conversations (id, user_id, agent_id) VALUES (?, ?, ?)", "conv-offline-client", "user-offline-test", "agent-offline-test")

	msg := RoutedMessage{
		ConversationID: "conv-offline-client",
		Content:       "hello offline client",
	}
	data, _ := json.Marshal(msg)
	routeChatMessage(agent, data)

	// Should be queued for offline client
	if offlineQueue.TotalDepth() < 1 {
		t.Error("expected message queued for offline client")
	}
}

func TestRouteChatMessage_ClientToAgentOnline(t *testing.T) {
	setupTestDB(t)

	hub = newHub()
	go hub.run()
	t.Cleanup(func() { hub.Stop() })

	// Agent connected
	agent := &Connection{
		id:       "agent-online-recv",
		connType: "agent",
		send:     make(chan []byte, 10),
		hub:      hub,
	}
	hub.mu.Lock()
	hub.agents["agent-online-recv"] = agent
	hub.mu.Unlock()

	// Client connected
	client := &Connection{
		id:       "user-sender",
		connType: "client",
		send:     make(chan []byte, 10),
		hub:      hub,
	}
	hub.mu.Lock()
	hub.clientConns["user-sender"] = []*Connection{client}
	hub.mu.Unlock()

	db.Exec("INSERT OR IGNORE INTO agents (id, name) VALUES (?, ?)", "agent-online-recv", "AgentOnline")
	db.Exec("INSERT OR IGNORE INTO users (id, username, password_hash) VALUES (?, ?, ?)", "user-sender", "user-sender", "$2a$10$hash")
	db.Exec("INSERT INTO conversations (id, user_id, agent_id) VALUES (?, ?, ?)", "conv-c2a-online", "user-sender", "agent-online-recv")

	msg := RoutedMessage{
		ConversationID: "conv-c2a-online",
		Content:       "hello agent",
	}
	data, _ := json.Marshal(msg)
	routeChatMessage(client, data)

	// Agent should receive the message
	select {
	case received := <-agent.send:
		if !strings.Contains(string(received), "hello agent") {
			t.Error("agent received wrong message")
		}
	default:
		t.Error("agent did not receive message")
	}
}

func TestRouteChatMessage_ClientToAgentOffline(t *testing.T) {
	setupTestDB(t)

	hub = newHub()
	go hub.run()
	t.Cleanup(func() { hub.Stop() })

	// Client connected, agent NOT connected
	client := &Connection{
		id:       "user-c2a-offline",
		connType: "client",
		send:     make(chan []byte, 10),
		hub:      hub,
	}
	hub.mu.Lock()
	hub.clientConns["user-c2a-offline"] = []*Connection{client}
	hub.mu.Unlock()

	db.Exec("INSERT OR IGNORE INTO agents (id, name) VALUES (?, ?)", "agent-c2a-offline", "AgentC2AOffline")
	db.Exec("INSERT OR IGNORE INTO users (id, username, password_hash) VALUES (?, ?, ?)", "user-c2a-offline", "user-c2a-offline", "$2a$10$hash")
	db.Exec("INSERT INTO conversations (id, user_id, agent_id) VALUES (?, ?, ?)", "conv-c2a-off", "user-c2a-offline", "agent-c2a-offline")

	msg := RoutedMessage{
		ConversationID: "conv-c2a-off",
		Content:       "hello offline agent",
	}
	data, _ := json.Marshal(msg)
	routeChatMessage(client, data)

	// Should be queued for offline agent
	if offlineQueue.TotalDepth() < 1 {
		t.Error("expected message queued for offline agent")
	}
}

func TestRouteChatMessage_ClientToAgentBufferFull(t *testing.T) {
	setupTestDB(t)

	hub = newHub()
	go hub.run()
	t.Cleanup(func() { hub.Stop() })

	// Agent connected with full buffer
	agent := &Connection{
		id:       "agent-buf-full-c2a",
		connType: "agent",
		send:     make(chan []byte, 1),
		hub:      hub,
	}
	agent.send <- []byte("fill")
	hub.mu.Lock()
	hub.agents["agent-buf-full-c2a"] = agent
	hub.mu.Unlock()

	// Client connected
	client := &Connection{
		id:       "user-c2a-bf",
		connType: "client",
		send:     make(chan []byte, 10),
		hub:      hub,
	}
	hub.mu.Lock()
	hub.clientConns["user-c2a-bf"] = []*Connection{client}
	hub.mu.Unlock()

	db.Exec("INSERT OR IGNORE INTO agents (id, name) VALUES (?, ?)", "agent-buf-full-c2a", "AgentBufFullC2A")
	db.Exec("INSERT OR IGNORE INTO users (id, username, password_hash) VALUES (?, ?, ?)", "user-c2a-bf", "user-c2a-bf", "$2a$10$hash")
	db.Exec("INSERT INTO conversations (id, user_id, agent_id) VALUES (?, ?, ?)", "conv-c2a-bf", "user-c2a-bf", "agent-buf-full-c2a")

	msg := RoutedMessage{
		ConversationID: "conv-c2a-bf",
		Content:       "agent buffer full test",
	}
	data, _ := json.Marshal(msg)
	routeChatMessage(client, data)

	// Should be queued for agent with full buffer
	if offlineQueue.TotalDepth() < 1 {
		t.Error("expected message queued when agent buffer full")
	}
}

func TestRouteChatMessage_InvalidJSON(t *testing.T) {
	setupTestDB(t)

	hub = newHub()
	go hub.run()
	t.Cleanup(func() { hub.Stop() })

	agent := &Connection{
		id:       "agent-invalid",
		connType: "agent",
		send:     make(chan []byte, 10),
		hub:      hub,
	}
	hub.mu.Lock()
	hub.agents["agent-invalid"] = agent
	hub.mu.Unlock()

	routeChatMessage(agent, []byte("{invalid json"))

	// Should receive error message
	select {
	case msg := <-agent.send:
		if !strings.Contains(string(msg), "error") {
			t.Error("expected error message")
		}
	default:
		t.Error("expected error response")
	}
}

func TestRouteChatMessage_EmptyContent(t *testing.T) {
	setupTestDB(t)

	hub = newHub()
	go hub.run()
	t.Cleanup(func() { hub.Stop() })

	agent := &Connection{
		id:       "agent-empty-content",
		connType: "agent",
		send:     make(chan []byte, 10),
		hub:      hub,
	}
	hub.mu.Lock()
	hub.agents["agent-empty-content"] = agent
	hub.mu.Unlock()

	msg := RoutedMessage{
		ConversationID: "conv-test",
		Content:       "",
	}
	data, _ := json.Marshal(msg)
	routeChatMessage(agent, data)

	// Should receive error about content
	select {
	case msg := <-agent.send:
		if !strings.Contains(string(msg), "content") {
			t.Error("expected content error")
		}
	default:
		t.Error("expected error response")
	}
}

func TestRouteChatMessage_EmptyConversationID(t *testing.T) {
	setupTestDB(t)

	hub = newHub()
	go hub.run()
	t.Cleanup(func() { hub.Stop() })

	agent := &Connection{
		id:       "agent-no-conv",
		connType: "agent",
		send:     make(chan []byte, 10),
		hub:      hub,
	}
	hub.mu.Lock()
	hub.agents["agent-no-conv"] = agent
	hub.mu.Unlock()

	msg := RoutedMessage{
		Content: "hello",
	}
	data, _ := json.Marshal(msg)
	routeChatMessage(agent, data)

	// Should receive error about conversation_id
	select {
	case msg := <-agent.send:
		if !strings.Contains(string(msg), "conversation_id") {
			t.Error("expected conversation_id error")
		}
	default:
		t.Error("expected error response")
	}
}

func TestRouteChatMessage_ConversationNotFound(t *testing.T) {
	setupTestDB(t)

	hub = newHub()
	go hub.run()
	t.Cleanup(func() { hub.Stop() })

	agent := &Connection{
		id:       "agent-conv-not-found",
		connType: "agent",
		send:     make(chan []byte, 10),
		hub:      hub,
	}
	hub.mu.Lock()
	hub.agents["agent-conv-not-found"] = agent
	hub.mu.Unlock()

	msg := RoutedMessage{
		ConversationID: "nonexistent-conv",
		Content:       "hello",
	}
	data, _ := json.Marshal(msg)
	routeChatMessage(agent, data)

	// Should receive error about conversation not found
	select {
	case msg := <-agent.send:
		if !strings.Contains(string(msg), "conversation not found") {
			t.Error("expected 'conversation not found' error")
		}
	default:
		t.Error("expected error response")
	}
}

func TestRouteChatMessage_AgentNotAuthorized(t *testing.T) {
	setupTestDB(t)

	hub = newHub()
	go hub.run()
	t.Cleanup(func() { hub.Stop() })

	agent := &Connection{
		id:       "agent-wrong-conv",
		connType: "agent",
		send:     make(chan []byte, 10),
		hub:      hub,
	}
	hub.mu.Lock()
	hub.agents["agent-wrong-conv"] = agent
	hub.mu.Unlock()

	db.Exec("INSERT OR IGNORE INTO agents (id, name) VALUES (?, ?)", "agent-wrong-conv", "AgentWrong")
	db.Exec("INSERT OR IGNORE INTO users (id, username, password_hash) VALUES (?, ?, ?)", "user-wrong", "user-wrong", "$2a$10$hash")
	db.Exec("INSERT INTO conversations (id, user_id, agent_id) VALUES (?, ?, ?)", "conv-wrong-agent", "user-wrong", "agent-different")

	msg := RoutedMessage{
		ConversationID: "conv-wrong-agent",
		Content:       "hello",
	}
	data, _ := json.Marshal(msg)
	routeChatMessage(agent, data)

	// Should receive "not authorized" error
	select {
	case msg := <-agent.send:
		if !strings.Contains(string(msg), "not authorized") {
			t.Error("expected 'not authorized' error")
		}
	default:
		t.Error("expected error response")
	}
}

func TestRouteChatMessage_ClientNotAuthorized(t *testing.T) {
	setupTestDB(t)

	hub = newHub()
	go hub.run()
	t.Cleanup(func() { hub.Stop() })

	client := &Connection{
		id:       "user-wrong-conv",
		connType: "client",
		send:     make(chan []byte, 10),
		hub:      hub,
	}
	hub.mu.Lock()
	hub.clientConns["user-wrong-conv"] = []*Connection{client}
	hub.mu.Unlock()

	db.Exec("INSERT OR IGNORE INTO agents (id, name) VALUES (?, ?)", "agent-owner", "AgentOwner")
	db.Exec("INSERT OR IGNORE INTO users (id, username, password_hash) VALUES (?, ?, ?)", "user-owner", "user-owner", "$2a$10$hash")
	db.Exec("INSERT INTO conversations (id, user_id, agent_id) VALUES (?, ?, ?)", "conv-owner-only", "user-owner", "agent-owner")

	msg := RoutedMessage{
		ConversationID: "conv-owner-only",
		Content:       "hello",
	}
	data, _ := json.Marshal(msg)
	routeChatMessage(client, data)

	// Should receive "not authorized" error
	select {
	case msg := <-client.send:
		if !strings.Contains(string(msg), "not authorized") {
			t.Error("expected 'not authorized' error for wrong user")
		}
	default:
		t.Error("expected error response")
	}
}

// ===================================================================
// routeTypingIndicator: agent→client multi-device, client→agent, unauthorized
// ===================================================================

func TestRouteTypingIndicator_AgentToClientMultiDevice(t *testing.T) {
	setupTestDB(t)

	hub = newHub()
	go hub.run()
	t.Cleanup(func() { hub.Stop() })

	agent := &Connection{
		id:       "agent-typing",
		connType: "agent",
		send:     make(chan []byte, 10),
		hub:      hub,
	}
	hub.mu.Lock()
	hub.agents["agent-typing"] = agent
	hub.mu.Unlock()

	client1 := &Connection{
		id:       "user-typing",
		connType: "client",
		deviceID: "dev1",
		send:     make(chan []byte, 10),
		hub:      hub,
	}
	client2 := &Connection{
		id:       "user-typing",
		connType: "client",
		deviceID: "dev2",
		send:     make(chan []byte, 10),
		hub:      hub,
	}
	hub.mu.Lock()
	hub.clientConns["user-typing"] = []*Connection{client1, client2}
	hub.mu.Unlock()

	db.Exec("INSERT OR IGNORE INTO agents (id, name) VALUES (?, ?)", "agent-typing", "AgentTyping")
	db.Exec("INSERT OR IGNORE INTO users (id, username, password_hash) VALUES (?, ?, ?)", "user-typing", "user-typing", "$2a$10$hash")
	db.Exec("INSERT INTO conversations (id, user_id, agent_id) VALUES (?, ?, ?)", "conv-typing", "user-typing", "agent-typing")

	payload := map[string]string{"conversation_id": "conv-typing"}
	data, _ := json.Marshal(payload)
	routeTypingIndicator(agent, data)

	// Both devices should receive typing indicator
	select {
	case <-client1.send:
	default:
		t.Error("client1 did not receive typing indicator")
	}
	select {
	case <-client2.send:
	default:
		t.Error("client2 did not receive typing indicator")
	}
}

func TestRouteTypingIndicator_ClientToAgent(t *testing.T) {
	setupTestDB(t)

	hub = newHub()
	go hub.run()
	t.Cleanup(func() { hub.Stop() })

	agent := &Connection{
		id:       "agent-typing-recv",
		connType: "agent",
		send:     make(chan []byte, 10),
		hub:      hub,
	}
	hub.mu.Lock()
	hub.agents["agent-typing-recv"] = agent
	hub.mu.Unlock()

	client := &Connection{
		id:       "user-typing-send",
		connType: "client",
		send:     make(chan []byte, 10),
		hub:      hub,
	}
	hub.mu.Lock()
	hub.clientConns["user-typing-send"] = []*Connection{client}
	hub.mu.Unlock()

	db.Exec("INSERT OR IGNORE INTO agents (id, name) VALUES (?, ?)", "agent-typing-recv", "AgentTypingRecv")
	db.Exec("INSERT OR IGNORE INTO users (id, username, password_hash) VALUES (?, ?, ?)", "user-typing-send", "user-typing-send", "$2a$10$hash")
	db.Exec("INSERT INTO conversations (id, user_id, agent_id) VALUES (?, ?, ?)", "conv-typing-c2a", "user-typing-send", "agent-typing-recv")

	payload := map[string]string{"conversation_id": "conv-typing-c2a"}
	data, _ := json.Marshal(payload)
	routeTypingIndicator(client, data)

	// Agent should receive typing indicator
	select {
	case msg := <-agent.send:
		if !strings.Contains(string(msg), "typing") {
			t.Error("expected typing indicator message")
		}
	default:
		t.Error("agent did not receive typing indicator")
	}
}

func TestRouteTypingIndicator_UnauthorizedAgent(t *testing.T) {
	setupTestDB(t)

	hub = newHub()
	go hub.run()
	t.Cleanup(func() { hub.Stop() })

	agent := &Connection{
		id:       "agent-wrong-typing",
		connType: "agent",
		send:     make(chan []byte, 10),
		hub:      hub,
	}
	hub.mu.Lock()
	hub.agents["agent-wrong-typing"] = agent
	hub.mu.Unlock()

	client := &Connection{
		id:       "user-typing-auth",
		connType: "client",
		send:     make(chan []byte, 10),
		hub:      hub,
	}
	hub.mu.Lock()
	hub.clientConns["user-typing-auth"] = []*Connection{client}
	hub.mu.Unlock()

	db.Exec("INSERT OR IGNORE INTO agents (id, name) VALUES (?, ?)", "agent-real", "AgentReal")
	db.Exec("INSERT OR IGNORE INTO agents (id, name) VALUES (?, ?)", "agent-wrong-typing", "AgentWrong")
	db.Exec("INSERT OR IGNORE INTO users (id, username, password_hash) VALUES (?, ?, ?)", "user-typing-auth", "user-typing-auth", "$2a$10$hash")
	db.Exec("INSERT INTO conversations (id, user_id, agent_id) VALUES (?, ?, ?)", "conv-typing-auth", "user-typing-auth", "agent-real")

	payload := map[string]string{"conversation_id": "conv-typing-auth"}
	data, _ := json.Marshal(payload)
	routeTypingIndicator(agent, data)

	// Client should NOT receive typing indicator (agent not authorized)
	select {
	case <-client.send:
		t.Error("client should not receive typing from unauthorized agent")
	default:
		// good — no message received
	}
}

func TestRouteTypingIndicator_EmptyConversationID(t *testing.T) {
	setupTestDB(t)

	hub = newHub()
	go hub.run()
	t.Cleanup(func() { hub.Stop() })

	agent := &Connection{
		id:       "agent-no-conv-typing",
		connType: "agent",
		send:     make(chan []byte, 10),
		hub:      hub,
	}
	hub.mu.Lock()
	hub.agents["agent-no-conv-typing"] = agent
	hub.mu.Unlock()

	payload := map[string]string{"conversation_id": ""}
	data, _ := json.Marshal(payload)
	routeTypingIndicator(agent, data)

	// No message should be sent (early return)
	select {
	case <-agent.send:
		t.Error("should not receive message for empty conversation_id")
	default:
		// good
	}
}

func TestRouteTypingIndicator_InvalidJSON(t *testing.T) {
	setupTestDB(t)

	hub = newHub()
	go hub.run()
	t.Cleanup(func() { hub.Stop() })

	agent := &Connection{
		id:       "agent-bad-json-typing",
		connType: "agent",
		send:     make(chan []byte, 10),
		hub:      hub,
	}
	hub.mu.Lock()
	hub.agents["agent-bad-json-typing"] = agent
	hub.mu.Unlock()

	routeTypingIndicator(agent, []byte("{invalid"))

	// Should silently return (no error sent)
	select {
	case <-agent.send:
		t.Error("should not receive message for invalid JSON")
	default:
		// good
	}
}

func TestRouteTypingIndicator_ConversationNotFound(t *testing.T) {
	setupTestDB(t)

	hub = newHub()
	go hub.run()
	t.Cleanup(func() { hub.Stop() })

	agent := &Connection{
		id:       "agent-conv-missing-typing",
		connType: "agent",
		send:     make(chan []byte, 10),
		hub:      hub,
	}
	hub.mu.Lock()
	hub.agents["agent-conv-missing-typing"] = agent
	hub.mu.Unlock()

	payload := map[string]string{"conversation_id": "nonexistent"}
	data, _ := json.Marshal(payload)
	routeTypingIndicator(agent, data)

	// Should silently return
	select {
	case <-agent.send:
		t.Error("should not receive message for nonexistent conversation")
	default:
		// good
	}
}

// ===================================================================
// routeStatusUpdate: agent broadcast, client→agent, with conv_id
// ===================================================================

func TestRouteStatusUpdate_AgentBroadcast(t *testing.T) {
	setupTestDB(t)

	hub = newHub()
	go hub.run()
	t.Cleanup(func() { hub.Stop() })

	agent := &Connection{
		id:       "agent-status-bc",
		connType: "agent",
		send:     make(chan []byte, 10),
		hub:      hub,
	}
	hub.mu.Lock()
	hub.agents["agent-status-bc"] = agent
	hub.mu.Unlock()

	client1 := &Connection{
		id:       "user-status-bc",
		connType: "client",
		deviceID: "dev1",
		send:     make(chan []byte, 10),
		hub:      hub,
	}
	client2 := &Connection{
		id:       "user-status-bc",
		connType: "client",
		deviceID: "dev2",
		send:     make(chan []byte, 10),
		hub:      hub,
	}
	hub.mu.Lock()
	hub.clientConns["user-status-bc"] = []*Connection{client1, client2}
	hub.mu.Unlock()

	payload := map[string]string{
		"conversation_id": "",
		"status":          "busy",
	}
	data, _ := json.Marshal(payload)
	routeStatusUpdate(agent, data)

	// Both clients should receive the status broadcast
	select {
	case <-client1.send:
	default:
		t.Error("client1 did not receive status broadcast")
	}
	select {
	case <-client2.send:
	default:
		t.Error("client2 did not receive status broadcast")
	}

	// Agent status should be updated
	if hub.AgentStatus("agent-status-bc") != "busy" {
		t.Error("agent status should be 'busy'")
	}
}

func TestRouteStatusUpdate_ClientToAgent(t *testing.T) {
	setupTestDB(t)

	hub = newHub()
	go hub.run()
	t.Cleanup(func() { hub.Stop() })

	agent := &Connection{
		id:       "agent-status-recv",
		connType: "agent",
		send:     make(chan []byte, 10),
		hub:      hub,
	}
	hub.mu.Lock()
	hub.agents["agent-status-recv"] = agent
	hub.mu.Unlock()

	client := &Connection{
		id:       "user-status-send",
		connType: "client",
		send:     make(chan []byte, 10),
		hub:      hub,
	}
	hub.mu.Lock()
	hub.clientConns["user-status-send"] = []*Connection{client}
	hub.mu.Unlock()

	db.Exec("INSERT OR IGNORE INTO agents (id, name) VALUES (?, ?)", "agent-status-recv", "AgentStatusRecv")
	db.Exec("INSERT OR IGNORE INTO users (id, username, password_hash) VALUES (?, ?, ?)", "user-status-send", "user-status-send", "$2a$10$hash")
	db.Exec("INSERT INTO conversations (id, user_id, agent_id) VALUES (?, ?, ?)", "conv-status", "user-status-send", "agent-status-recv")

	payload := map[string]string{
		"conversation_id": "conv-status",
		"status":          "idle",
	}
	data, _ := json.Marshal(payload)
	routeStatusUpdate(client, data)

	// Agent should receive status update
	select {
	case msg := <-agent.send:
		if !strings.Contains(string(msg), "status") {
			t.Error("expected status update message")
		}
	default:
		t.Error("agent did not receive status update")
	}
}

func TestRouteStatusUpdate_EmptyStatus(t *testing.T) {
	setupTestDB(t)

	hub = newHub()
	go hub.run()
	t.Cleanup(func() { hub.Stop() })

	agent := &Connection{
		id:       "agent-empty-status",
		connType: "agent",
		send:     make(chan []byte, 10),
		hub:      hub,
	}
	hub.mu.Lock()
	hub.agents["agent-empty-status"] = agent
	hub.mu.Unlock()

	payload := map[string]string{
		"conversation_id": "",
		"status":          "",
	}
	data, _ := json.Marshal(payload)
	routeStatusUpdate(agent, data)

	// With empty status and no conv_id, should return early (no broadcast)
	// Agent status should remain default ("online")
	if hub.AgentStatus("agent-empty-status") != "online" {
		t.Error("agent status should remain 'online' for empty status")
	}
}

func TestRouteStatusUpdate_InvalidJSON(t *testing.T) {
	setupTestDB(t)

	hub = newHub()
	go hub.run()
	t.Cleanup(func() { hub.Stop() })

	agent := &Connection{
		id:       "agent-bad-status",
		connType: "agent",
		send:     make(chan []byte, 10),
		hub:      hub,
	}
	hub.mu.Lock()
	hub.agents["agent-bad-status"] = agent
	hub.mu.Unlock()

	routeStatusUpdate(agent, []byte("{invalid"))

	// Should silently return
	if hub.AgentStatus("agent-bad-status") != "online" {
		t.Error("agent status should remain 'online' for invalid JSON")
	}
}

func TestRouteStatusUpdate_ConversationNotFound(t *testing.T) {
	setupTestDB(t)

	hub = newHub()
	go hub.run()
	t.Cleanup(func() { hub.Stop() })

	agent := &Connection{
		id:       "agent-conv-missing-status",
		connType: "agent",
		send:     make(chan []byte, 10),
		hub:      hub,
	}
	hub.mu.Lock()
	hub.agents["agent-conv-missing-status"] = agent
	hub.mu.Unlock()

	// Status set (non-empty) + conversation_id that doesn't exist
	// Should broadcast status (from agent) but NOT send conversation-specific update
	payload := map[string]string{
		"conversation_id": "nonexistent-conv",
		"status":          "idle",
	}
	data, _ := json.Marshal(payload)
	routeStatusUpdate(agent, data)

	// Agent status should be updated
	if hub.AgentStatus("agent-conv-missing-status") != "idle" {
		t.Error("agent status should be 'idle'")
	}
}

// ===================================================================
// routeHeartbeat: heartbeat ack
// ===================================================================

func TestRouteHeartbeat_AckSent(t *testing.T) {
	setupTestDB(t)

	hub = newHub()
	go hub.run()
	t.Cleanup(func() { hub.Stop() })

	agent := &Connection{
		id:            "agent-hb",
		connType:      "agent",
		send:          make(chan []byte, 10),
		hub:           hub,
		lastHeartbeat: time.Now(),
	}
	hub.mu.Lock()
	hub.agents["agent-hb"] = agent
	hub.mu.Unlock()

	routeHeartbeat(agent)

	// Should receive heartbeat_ack
	select {
	case msg := <-agent.send:
		if !strings.Contains(string(msg), "heartbeat_ack") {
			t.Errorf("expected heartbeat_ack, got: %s", string(msg))
		}
	default:
		t.Error("agent did not receive heartbeat_ack")
	}
}

func TestRouteHeartbeat_UpdatesTimestamp(t *testing.T) {
	setupTestDB(t)

	hub = newHub()
	go hub.run()
	t.Cleanup(func() { hub.Stop() })

	oldTime := time.Now().Add(-5 * time.Minute)
	agent := &Connection{
		id:            "agent-hb-time",
		connType:      "agent",
		send:          make(chan []byte, 10),
		hub:           hub,
		lastHeartbeat: oldTime,
	}
	hub.mu.Lock()
	hub.agents["agent-hb-time"] = agent
	hub.mu.Unlock()

	routeHeartbeat(agent)

	// lastHeartbeat should be updated
	hub.mu.RLock()
	newTime := hub.agents["agent-hb-time"].lastHeartbeat
	hub.mu.RUnlock()

	if newTime.Equal(oldTime) {
		t.Error("lastHeartbeat should be updated")
	}
	if newTime.Before(oldTime) {
		t.Error("lastHeartbeat should be newer than old time")
	}
}

// ===================================================================
// broadcastPresence: presence to multiple clients
// ===================================================================

func TestBroadcastPresence_MultipleClients(t *testing.T) {
	h := newHub()
	go h.run()
	defer h.Stop()

	client1 := &Connection{
		id:       "user-pres-1",
		connType: "client",
		send:     make(chan []byte, 10),
		hub:      h,
	}
	client2 := &Connection{
		id:       "user-pres-2",
		connType: "client",
		send:     make(chan []byte, 10),
		hub:      h,
	}
	h.mu.Lock()
	h.clientConns["user-pres-1"] = []*Connection{client1}
	h.clientConns["user-pres-2"] = []*Connection{client2}
	h.mu.Unlock()

	// Call broadcastPresence (must hold lock, as run() does)
	h.mu.Lock()
	h.broadcastPresence("agent-pres-test", "agent", true)
	h.mu.Unlock()

	// Both clients should receive presence update
	select {
	case msg := <-client1.send:
		if !strings.Contains(string(msg), "presence_update") {
			t.Error("expected presence_update message")
		}
	default:
		t.Error("client1 did not receive presence update")
	}
	select {
	case <-client2.send:
	default:
		t.Error("client2 did not receive presence update")
	}
}

func TestBroadcastPresence_OfflineEvent(t *testing.T) {
	h := newHub()
	go h.run()
	defer h.Stop()

	client := &Connection{
		id:       "user-pres-off",
		connType: "client",
		send:     make(chan []byte, 10),
		hub:      h,
	}
	h.mu.Lock()
	h.clientConns["user-pres-off"] = []*Connection{client}
	h.mu.Unlock()

	h.mu.Lock()
	h.broadcastPresence("agent-off-pres", "agent", false)
	h.mu.Unlock()

	select {
	case msg := <-client.send:
		if !strings.Contains(string(msg), "presence_update") {
			t.Error("expected presence_update message")
		}
		if !strings.Contains(string(msg), "false") {
			t.Error("expected online=false in presence update")
		}
	default:
		t.Error("client did not receive offline presence update")
	}
}

// ===================================================================
// Hub AgentStatus / SetAgentStatus
// ===================================================================

func TestAgentStatus_UnknownAgent(t *testing.T) {
	h := newHub()
	go h.run()
	defer h.Stop()

	if status := h.AgentStatus("nonexistent"); status != "offline" {
		t.Errorf("expected 'offline', got '%s'", status)
	}
}

func TestAgentStatus_ConnectedNoStatus(t *testing.T) {
	h := newHub()
	go h.run()
	defer h.Stop()

	agent := &Connection{
		id:       "agent-no-status",
		connType: "agent",
		send:     make(chan []byte, 10),
		hub:      h,
	}
	h.mu.Lock()
	h.agents["agent-no-status"] = agent
	h.mu.Unlock()

	if status := h.AgentStatus("agent-no-status"); status != "online" {
		t.Errorf("expected 'online', got '%s'", status)
	}
}

func TestAgentStatus_WithCustomStatus(t *testing.T) {
	h := newHub()
	go h.run()
	defer h.Stop()

	agent := &Connection{
		id:       "agent-custom",
		connType: "agent",
		send:     make(chan []byte, 10),
		hub:      h,
		status:   "busy",
	}
	h.mu.Lock()
	h.agents["agent-custom"] = agent
	h.mu.Unlock()

	if status := h.AgentStatus("agent-custom"); status != "busy" {
		t.Errorf("expected 'busy', got '%s'", status)
	}
}

func TestSetAgentStatus_UnknownAgent(t *testing.T) {
	h := newHub()
	go h.run()
	defer h.Stop()

	// Should not panic for unknown agent
	h.SetAgentStatus("nonexistent", "idle")
	// No panic = pass
}

func TestSetAgentStatus_UpdatesStatus(t *testing.T) {
	h := newHub()
	go h.run()
	defer h.Stop()

	agent := &Connection{
		id:       "agent-set-status",
		connType: "agent",
		send:     make(chan []byte, 10),
		hub:      h,
	}
	h.mu.Lock()
	h.agents["agent-set-status"] = agent
	h.mu.Unlock()

	h.SetAgentStatus("agent-set-status", "idle")
	if h.AgentStatus("agent-set-status") != "idle" {
		t.Error("expected status to be 'idle'")
	}
}

// ===================================================================
// Hub AgentCount / ClientCount / ClientConnCount
// ===================================================================

func TestAgentCount_WithConnections(t *testing.T) {
	h := newHub()
	go h.run()
	defer h.Stop()

	// Initially 0
	if count := h.AgentCount(); count != 0 {
		t.Errorf("expected 0 agents, got %d", count)
	}

	// Add agents
	h.mu.Lock()
	h.agents["a1"] = &Connection{id: "a1", connType: "agent", send: make(chan []byte, 1)}
	h.agents["a2"] = &Connection{id: "a2", connType: "agent", send: make(chan []byte, 1)}
	h.mu.Unlock()

	if count := h.AgentCount(); count != 2 {
		t.Errorf("expected 2 agents, got %d", count)
	}
}

func TestClientCount_WithConnections(t *testing.T) {
	h := newHub()
	go h.run()
	defer h.Stop()

	if count := h.ClientCount(); count != 0 {
		t.Errorf("expected 0 clients, got %d", count)
	}

	h.mu.Lock()
	h.clientConns["u1"] = []*Connection{{id: "u1", connType: "client", send: make(chan []byte, 1)}}
	h.clientConns["u2"] = []*Connection{{id: "u2", connType: "client", send: make(chan []byte, 1)}}
	h.mu.Unlock()

	if count := h.ClientCount(); count != 2 {
		t.Errorf("expected 2 clients, got %d", count)
	}
}

func TestClientConnCount_MultiDevice(t *testing.T) {
	h := newHub()
	go h.run()
	defer h.Stop()

	h.mu.Lock()
	h.clientConns["u1"] = []*Connection{
		{id: "u1", connType: "client", send: make(chan []byte, 1)},
		{id: "u1", connType: "client", send: make(chan []byte, 1)},
	}
	h.clientConns["u2"] = []*Connection{
		{id: "u2", connType: "client", send: make(chan []byte, 1)},
	}
	h.mu.Unlock()

	if count := h.ClientConnCount(); count != 3 {
		t.Errorf("expected 3 total connections (2+1), got %d", count)
	}
}

// ===================================================================
// Hub GetAgent / GetClient / GetClientConns
// ===================================================================

func TestGetAgent_UnknownReturnsNil(t *testing.T) {
	h := newHub()
	go h.run()
	defer h.Stop()
	if c := h.GetAgent("nonexistent"); c != nil {
		t.Error("expected nil for unknown agent")
	}
}

func TestGetAgent_ReturnsConnection(t *testing.T) {
	h := newHub()
	go h.run()
	defer h.Stop()

	agent := &Connection{id: "test-agent", connType: "agent", send: make(chan []byte, 1)}
	h.mu.Lock()
	h.agents["test-agent"] = agent
	h.mu.Unlock()

	if c := h.GetAgent("test-agent"); c != agent {
		t.Error("expected to get agent connection")
	}
}

func TestGetClient_UnknownReturnsNil(t *testing.T) {
	h := newHub()
	go h.run()
	defer h.Stop()
	if c := h.GetClient("nonexistent"); c != nil {
		t.Error("expected nil for unknown client")
	}
}

func TestGetClient_ReturnsFirstDevice(t *testing.T) {
	h := newHub()
	go h.run()
	defer h.Stop()

	c1 := &Connection{id: "u1", connType: "client", deviceID: "d1", send: make(chan []byte, 1)}
	c2 := &Connection{id: "u1", connType: "client", deviceID: "d2", send: make(chan []byte, 1)}
	h.mu.Lock()
	h.clientConns["u1"] = []*Connection{c1, c2}
	h.mu.Unlock()

	if c := h.GetClient("u1"); c != c1 {
		t.Error("expected first client connection")
	}
}

func TestGetClientConns_EmptyReturnsEmpty(t *testing.T) {
	h := newHub()
	go h.run()
	defer h.Stop()
	if conns := h.GetClientConns("nonexistent"); len(conns) != 0 {
		t.Errorf("expected empty slice, got %v", conns)
	}
}

func TestGetClientConns_ReturnsAllDevices(t *testing.T) {
	h := newHub()
	go h.run()
	defer h.Stop()

	c1 := &Connection{id: "u1", connType: "client", deviceID: "d1", send: make(chan []byte, 1)}
	c2 := &Connection{id: "u1", connType: "client", deviceID: "d2", send: make(chan []byte, 1)}
	h.mu.Lock()
	h.clientConns["u1"] = []*Connection{c1, c2}
	h.mu.Unlock()

	conns := h.GetClientConns("u1")
	if len(conns) != 2 {
		t.Errorf("expected 2 connections, got %d", len(conns))
	}
}

// ===================================================================
// negotiateProtocol / isSupportedVersion
// ===================================================================

func TestNegotiateProtocol_HeaderValid(t *testing.T) {
	req := httptest.NewRequest("GET", "/agent/connect", nil)
	req.Header.Set("Sec-WebSocket-Protocol", "v1")
	if v := negotiateProtocol(req); v != "v1" {
		t.Errorf("expected v1, got %s", v)
	}
}

func TestNegotiateProtocol_HeaderMultiple(t *testing.T) {
	req := httptest.NewRequest("GET", "/agent/connect", nil)
	req.Header.Set("Sec-WebSocket-Protocol", "v0,v1,v2")
	if v := negotiateProtocol(req); v != "v1" {
		t.Errorf("expected v1 (only supported), got %s", v)
	}
}

func TestNegotiateProtocol_HeaderUnsupported(t *testing.T) {
	req := httptest.NewRequest("GET", "/agent/connect", nil)
	req.Header.Set("Sec-WebSocket-Protocol", "v99")
	if v := negotiateProtocol(req); v != ProtocolVersion {
		t.Errorf("expected default %s, got %s", ProtocolVersion, v)
	}
}

func TestNegotiateProtocol_QueryParamFallback(t *testing.T) {
	req := httptest.NewRequest("GET", "/agent/connect?protocol_version=v1", nil)
	if v := negotiateProtocol(req); v != "v1" {
		t.Errorf("expected v1 from query, got %s", v)
	}
}

func TestNegotiateProtocol_NoHeaderQueryParam(t *testing.T) {
	req := httptest.NewRequest("GET", "/agent/connect", nil)
	if v := negotiateProtocol(req); v != ProtocolVersion {
		t.Errorf("expected default %s, got %s", ProtocolVersion, v)
	}
}

func TestIsSupportedVersion_V1(t *testing.T) {
	if !isSupportedVersion("v1") {
		t.Error("v1 should be supported")
	}
}

func TestIsSupportedVersion_Unknown(t *testing.T) {
	if isSupportedVersion("v99") {
		t.Error("v99 should not be supported")
	}
}

func TestIsSupportedVersion_Empty(t *testing.T) {
	if isSupportedVersion("") {
		t.Error("empty string should not be supported")
	}
}

// ===================================================================
// sendWelcomeMessage
// ===================================================================

func TestSendWelcomeMessage_WithDeviceID(t *testing.T) {
	c := &Connection{
		id:       "user-welcome",
		connType: "client",
		deviceID: "device-123",
		send:     make(chan []byte, 10),
	}

	sendWelcomeMessage(c)

	select {
	case msg := <-c.send:
		if !strings.Contains(string(msg), "connected") {
			t.Error("expected welcome message with 'connected' type")
		}
		if !strings.Contains(string(msg), "device-123") {
			t.Error("expected device_id in welcome message")
		}
	default:
		t.Error("did not receive welcome message")
	}
}

func TestSendWelcomeMessage_WithoutDeviceID(t *testing.T) {
	c := &Connection{
		id:       "user-welcome-no-dev",
		connType: "client",
		send:     make(chan []byte, 10),
	}

	sendWelcomeMessage(c)

	select {
	case msg := <-c.send:
		if strings.Contains(string(msg), "device_id") {
			t.Error("should not have device_id in welcome message")
		}
		if !strings.Contains(string(msg), "connected") {
			t.Error("expected 'connected' type")
		}
	default:
		t.Error("did not receive welcome message")
	}
}

func TestSendWelcomeMessage_ClosedChannel(t *testing.T) {
	c := &Connection{
		id:       "user-welcome-closed",
		connType: "client",
		send:     make(chan []byte, 1),
	}
	c.MarkClosed()
	close(c.send)

	// Should not panic
	sendWelcomeMessage(c)
}

// ===================================================================
// routeMessage dispatch
// ===================================================================

func TestRouteMessage_ChatType(t *testing.T) {
	setupTestDB(t)

	hub = newHub()
	go hub.run()
	t.Cleanup(func() { hub.Stop() })

	agent := &Connection{
		id:       "agent-route-msg",
		connType: "agent",
		send:     make(chan []byte, 10),
		hub:      hub,
	}
	hub.mu.Lock()
	hub.agents["agent-route-msg"] = agent
	hub.mu.Unlock()

	db.Exec("INSERT OR IGNORE INTO agents (id, name) VALUES (?, ?)", "agent-route-msg", "AgentRoute")
	db.Exec("INSERT OR IGNORE INTO users (id, username, password_hash) VALUES (?, ?, ?)", "user-route-msg", "user-route-msg", "$2a$10$hash")
	db.Exec("INSERT INTO conversations (id, user_id, agent_id) VALUES (?, ?, ?)", "conv-route-msg", "user-route-msg", "agent-route-msg")

	msg := map[string]interface{}{
		"type": "message",
		"data": map[string]interface{}{
			"conversation_id": "conv-route-msg",
			"content":         "via routeMessage",
			"sender_type":     "agent",
			"sender_id":       "agent-route-msg",
		},
	}
	data, _ := json.Marshal(msg)
	routeMessage(agent, data)

	// Message should be stored in DB
	var count int
	db.QueryRow("SELECT COUNT(*) FROM messages WHERE conversation_id = ?", "conv-route-msg").Scan(&count)
	if count < 1 {
		t.Error("expected message to be stored in DB")
	}
}

func TestRouteMessage_UnknownType(t *testing.T) {
	setupTestDB(t)

	hub = newHub()
	go hub.run()
	t.Cleanup(func() { hub.Stop() })

	agent := &Connection{
		id:       "agent-unknown-type",
		connType: "agent",
		send:     make(chan []byte, 10),
		hub:      hub,
	}
	hub.mu.Lock()
	hub.agents["agent-unknown-type"] = agent
	hub.mu.Unlock()

	msg := map[string]interface{}{
		"type": "unknown_type",
	}
	data, _ := json.Marshal(msg)
	routeMessage(agent, data)

	// Should receive an error about unknown message type
	select {
	case msg := <-agent.send:
		if !strings.Contains(string(msg), "unknown") {
			t.Error("expected unknown message type error")
		}
	default:
		t.Error("expected error response for unknown type")
	}
}

func TestRouteMessage_InvalidJSON(t *testing.T) {
	setupTestDB(t)

	hub = newHub()
	go hub.run()
	t.Cleanup(func() { hub.Stop() })

	agent := &Connection{
		id:       "agent-bad-route",
		connType: "agent",
		send:     make(chan []byte, 10),
		hub:      hub,
	}
	hub.mu.Lock()
	hub.agents["agent-bad-route"] = agent
	hub.mu.Unlock()

	routeMessage(agent, []byte("{invalid"))

	// Should receive error
	select {
	case msg := <-agent.send:
		if !strings.Contains(string(msg), "error") {
			t.Error("expected error for invalid JSON")
		}
	default:
		t.Error("expected error response")
	}
}

// ===================================================================
// truncate helper
// ===================================================================

func TestTruncate_ShortString(t *testing.T) {
	if s := truncate("hello", 100); s != "hello" {
		t.Errorf("expected 'hello', got '%s'", s)
	}
}

func TestTruncate_LongString(t *testing.T) {
	long := strings.Repeat("a", 200)
	result := truncate(long, 100)
	if len(result) != 100 {
		t.Errorf("expected length 100, got %d", len(result))
	}
}

func TestTruncate_ExactLength(t *testing.T) {
	s := "hello"
	if result := truncate(s, 5); result != s {
		t.Errorf("expected '%s', got '%s'", s, result)
	}
}

func TestTruncate_EmptyString(t *testing.T) {
	if s := truncate("", 100); s != "" {
		t.Errorf("expected '', got '%s'", s)
	}
}

// ===================================================================
// BroadcastToAllClients
// ===================================================================

func TestBroadcastToAllClients_NoClients(t *testing.T) {
	h := newHub()
	go h.run()
	defer h.Stop()

	// Should not panic with no clients
	h.BroadcastToAllClients([]byte(`{"type":"test"}`))
}

func TestBroadcastToAllClients_WithClients(t *testing.T) {
	h := newHub()
	go h.run()
	defer h.Stop()

	c1 := &Connection{id: "u1", connType: "client", send: make(chan []byte, 10), hub: h}
	c2 := &Connection{id: "u2", connType: "client", send: make(chan []byte, 10), hub: h}
	h.mu.Lock()
	h.clientConns["u1"] = []*Connection{c1}
	h.clientConns["u2"] = []*Connection{c2}
	h.mu.Unlock()

	h.BroadcastToAllClients([]byte(`{"type":"broadcast"}`))

	select {
	case <-c1.send:
	default:
		t.Error("c1 did not receive broadcast")
	}
	select {
	case <-c2.send:
	default:
		t.Error("c2 did not receive broadcast")
	}
}

// ===================================================================
// Hub run() unregister paths
// ===================================================================

func TestHubRun_UnregisterUnknownAgent(t *testing.T) {
	h := newHub()
	go h.run()
	defer h.Stop()

	// Send unregister for unknown agent (should not panic)
	h.unregister <- &Connection{
		id:       "unknown-agent",
		connType: "agent",
		send:     make(chan []byte, 1),
	}

	time.Sleep(50 * time.Millisecond)
	// No panic = pass
}

func TestHubRun_UnregisterUnknownClient(t *testing.T) {
	h := newHub()
	go h.run()
	defer h.Stop()

	h.unregister <- &Connection{
		id:       "unknown-client",
		connType: "client",
		send:     make(chan []byte, 1),
	}

	time.Sleep(50 * time.Millisecond)
	// No panic = pass
}

// ===================================================================
// Concurrent hub access (data race check)
// ===================================================================

func TestHub_ConcurrentAccess(t *testing.T) {
	h := newHub()
	go h.run()
	defer h.Stop()

	var wg sync.WaitGroup

	// Concurrent SetAgentStatus
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			h.SetAgentStatus("agent-concurrent", "busy")
		}(i)
	}

	// Concurrent AgentStatus reads
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			h.AgentStatus("agent-concurrent")
		}()
	}

	// Concurrent AgentCount reads
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			h.AgentCount()
		}()
	}

	wg.Wait()
}