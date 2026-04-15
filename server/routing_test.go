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

// setupTestServerForRouting creates a full test server with all routes
func setupTestServerForRouting(t *testing.T) (*httptest.Server, func()) {
	t.Helper()
	setupTestDB(t)

	hub = newHub()
	go hub.run()

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

	server := httptest.NewServer(mux)
	cleanup := func() {
		server.Close()
	}
	return server, cleanup
}

// registerAndConnectAgent is a helper to register an agent and connect via WebSocket
func registerAndConnectAgent(t *testing.T, server *httptest.Server, agentID, apiKey string) *websocket.Conn {
	t.Helper()
	form := url.Values{}
	form.Set("agent_id", agentID)
	form.Set("name", "Agent "+agentID)
	form.Set("api_key", apiKey)

	req := httptest.NewRequest(http.MethodPost, "/auth/agent", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handleRegisterAgent(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("register agent failed: %d", w.Code)
	}

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http") + "/agent/connect?agent_id=" + agentID + "&api_key=" + apiKey
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("agent connect failed: %v", err)
	}
	return conn
}

// registerUserAndGetToken is a helper to register a user and get JWT
func registerUserAndGetToken(t *testing.T, email, password string) string {
	t.Helper()
	form := url.Values{}
	form.Set("email", email)
	form.Set("password", password)

	req := httptest.NewRequest(http.MethodPost, "/auth/user", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handleRegisterUser(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("register user failed: %d %s", w.Code, w.Body.String())
	}

	// Login
	form2 := url.Values{}
	form2.Set("email", email)
	form2.Set("password", password)
	req2 := httptest.NewRequest(http.MethodPost, "/auth/login", strings.NewReader(form2.Encode()))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w2 := httptest.NewRecorder()
	handleLogin(w2, req2)

	var resp map[string]string
	json.Unmarshal(w2.Body.Bytes(), &resp)
	return resp["token"]
}

func TestCreateConversation(t *testing.T) {
	_, cleanup := setupTestServerForRouting(t)
	defer cleanup()

	token := registerUserAndGetToken(t, "conv-test@example.com", "password123")

	form := url.Values{}
	form.Set("agent_id", "conv-agent")

	req := httptest.NewRequest(http.MethodPost, "/conversations/create", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	// Need to use the server's handler through mux
	handleCreateConversation(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]string
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["conversation_id"] == "" {
		t.Fatal("expected conversation_id in response")
	}
	if resp["agent_id"] != "conv-agent" {
		t.Fatalf("expected agent_id conv-agent, got %s", resp["agent_id"])
	}
}

func TestCreateConversationUnauthorized(t *testing.T) {
	setupTestDB(t)
	hub = newHub()
	go hub.run()

	req := httptest.NewRequest(http.MethodPost, "/conversations/create", nil)
	w := httptest.NewRecorder()
	handleCreateConversation(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestListConversations(t *testing.T) {
	_, cleanup := setupTestServerForRouting(t)
	defer cleanup()

	token := registerUserAndGetToken(t, "list-conv@example.com", "password123")

	// Create a conversation first
	form := url.Values{}
	form.Set("agent_id", "list-agent")
	req := httptest.NewRequest(http.MethodPost, "/conversations/create", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleCreateConversation(w, req)

	// List conversations
	req2 := httptest.NewRequest(http.MethodGet, "/conversations/list", nil)
	req2.Header.Set("Authorization", "Bearer "+token)
	w2 := httptest.NewRecorder()
	handleListConversations(w2, req2)

	if w2.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w2.Code, w2.Body.String())
	}
}

func TestGetMessagesEmpty(t *testing.T) {
	setupTestDB(t)
	hub = newHub()
	go hub.run()

	token := registerUserAndGetToken(t, "msgs-test@example.com", "password123")

	// Create a conversation
	form := url.Values{}
	form.Set("agent_id", "msgs-agent")
	req := httptest.NewRequest(http.MethodPost, "/conversations/create", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleCreateConversation(w, req)

	var createResp map[string]string
	json.Unmarshal(w.Body.Bytes(), &createResp)
	convID := createResp["conversation_id"]

	// Get messages for this conversation
	req2 := httptest.NewRequest(http.MethodGet, "/conversations/messages?conversation_id="+convID, nil)
	req2.Header.Set("Authorization", "Bearer "+token)
	w2 := httptest.NewRecorder()
	handleGetMessages(w2, req2)

	if w2.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w2.Code, w2.Body.String())
	}
}

func TestRouteMessageRequiresConversationID(t *testing.T) {
	setupTestDB(t)
	hub = newHub()
	go hub.run()

	conn := &Connection{
		hub:      hub,
		connType: "agent",
		id:       "test-agent",
		send:     make(chan []byte, 10),
	}

	msg := IncomingMessage{
		Type: "message",
		Data: json.RawMessage(`{"content": "hello"}`),
	}
	raw, _ := json.Marshal(msg)
	routeMessage(conn, raw)

	// Should get an error response
	select {
	case resp := <-conn.send:
		var outMsg OutgoingMessage
		json.Unmarshal(resp, &outMsg)
		if outMsg.Type != "error" {
			t.Fatalf("expected error response, got %s", outMsg.Type)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for error response")
	}
}

func TestRouteMessageRequiresContent(t *testing.T) {
	setupTestDB(t)
	hub = newHub()
	go hub.run()

	conn := &Connection{
		hub:      hub,
		connType: "agent",
		id:       "test-agent",
		send:     make(chan []byte, 10),
	}

	msg := IncomingMessage{
		Type: "message",
		Data: json.RawMessage(`{"conversation_id": "conv_123"}`),
	}
	raw, _ := json.Marshal(msg)
	routeMessage(conn, raw)

	select {
	case resp := <-conn.send:
		var outMsg OutgoingMessage
		json.Unmarshal(resp, &outMsg)
		if outMsg.Type != "error" {
			t.Fatalf("expected error response, got %s", outMsg.Type)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for error response")
	}
}

func TestRouteMessageUnknownType(t *testing.T) {
	setupTestDB(t)
	hub = newHub()
	go hub.run()

	conn := &Connection{
		hub:      hub,
		connType: "agent",
		id:       "test-agent",
		send:     make(chan []byte, 10),
	}

	msg := IncomingMessage{
		Type: "unknown_type",
		Data: json.RawMessage(`{}`),
	}
	raw, _ := json.Marshal(msg)
	routeMessage(conn, raw)

	select {
	case resp := <-conn.send:
		var outMsg OutgoingMessage
		json.Unmarshal(resp, &outMsg)
		if outMsg.Type != "error" {
			t.Fatalf("expected error response, got %s", outMsg.Type)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for error response")
	}
}

func TestRouteMessageAgentToClient(t *testing.T) {
	setupTestDB(t)
	hub = newHub()
	go hub.run()

	// Create conversation in DB
	conv, err := CreateConversation("user_1", "agent_1")
	if err != nil {
		t.Fatal(err)
	}

	agentConn := &Connection{
		hub:      hub,
		connType: "agent",
		id:       "agent_1",
		send:     make(chan []byte, 10),
	}
	clientConn := &Connection{
		hub:      hub,
		connType: "client",
		id:       "user_1",
		send:     make(chan []byte, 10),
	}

	hub.register <- agentConn
	time.Sleep(10 * time.Millisecond)
	hub.register <- clientConn
	time.Sleep(10 * time.Millisecond)

	msg := IncomingMessage{
		Type: "message",
		Data: json.RawMessage(`{"conversation_id": "` + conv.ID + `", "content": "Hello client!"}`),
	}
	raw, _ := json.Marshal(msg)
	routeMessage(agentConn, raw)

	// Client should receive the message
	select {
	case resp := <-clientConn.send:
		var outMsg OutgoingMessage
		json.Unmarshal(resp, &outMsg)
		if outMsg.Type != "message" {
			t.Fatalf("expected message type, got %s", outMsg.Type)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for client to receive message")
	}

	// Agent should get an ack
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
}

func TestRouteMessageClientToAgent(t *testing.T) {
	setupTestDB(t)
	hub = newHub()
	go hub.run()

	conv, err := CreateConversation("user_2", "agent_2")
	if err != nil {
		t.Fatal(err)
	}

	agentConn := &Connection{
		hub:      hub,
		connType: "agent",
		id:       "agent_2",
		send:     make(chan []byte, 10),
	}
	clientConn := &Connection{
		hub:      hub,
		connType: "client",
		id:       "user_2",
		send:     make(chan []byte, 10),
	}

	hub.register <- agentConn
	time.Sleep(10 * time.Millisecond)
	hub.register <- clientConn
	time.Sleep(10 * time.Millisecond)

	msg := IncomingMessage{
		Type: "message",
		Data: json.RawMessage(`{"conversation_id": "` + conv.ID + `", "content": "Hello agent!"}`),
	}
	raw, _ := json.Marshal(msg)
	routeMessage(clientConn, raw)

	// Agent should receive the message
	select {
	case resp := <-agentConn.send:
		var outMsg OutgoingMessage
		json.Unmarshal(resp, &outMsg)
		if outMsg.Type != "message" {
			t.Fatalf("expected message type, got %s", outMsg.Type)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for agent to receive message")
	}

	// Client should get an ack
	select {
	case resp := <-clientConn.send:
		var outMsg OutgoingMessage
		json.Unmarshal(resp, &outMsg)
		if outMsg.Type != "message_sent" {
			t.Fatalf("expected message_sent ack, got %s", outMsg.Type)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for client ack")
	}
}

func TestRouteMessageUnauthorizedAgent(t *testing.T) {
	setupTestDB(t)
	hub = newHub()
	go hub.run()

	conv, err := CreateConversation("user_3", "agent_3")
	if err != nil {
		t.Fatal(err)
	}

	wrongAgent := &Connection{
		hub:      hub,
		connType: "agent",
		id:       "wrong_agent",
		send:     make(chan []byte, 10),
	}

	msg := IncomingMessage{
		Type: "message",
		Data: json.RawMessage(`{"conversation_id": "` + conv.ID + `", "content": "hack!"}`),
	}
	raw, _ := json.Marshal(msg)
	routeMessage(wrongAgent, raw)

	select {
	case resp := <-wrongAgent.send:
		var outMsg OutgoingMessage
		json.Unmarshal(resp, &outMsg)
		if outMsg.Type != "error" {
			t.Fatalf("expected error response, got %s", outMsg.Type)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for error response")
	}
}

func TestRouteTypingIndicator(t *testing.T) {
	setupTestDB(t)
	hub = newHub()
	go hub.run()

	conv, err := CreateConversation("user_4", "agent_4")
	if err != nil {
		t.Fatal(err)
	}

	agentConn := &Connection{
		hub:      hub,
		connType: "agent",
		id:       "agent_4",
		send:     make(chan []byte, 10),
	}
	clientConn := &Connection{
		hub:      hub,
		connType: "client",
		id:       "user_4",
		send:     make(chan []byte, 10),
	}

	hub.register <- agentConn
	time.Sleep(10 * time.Millisecond)
	hub.register <- clientConn
	time.Sleep(10 * time.Millisecond)

	msg := IncomingMessage{
		Type: "typing",
		Data: json.RawMessage(`{"conversation_id": "` + conv.ID + `"}`),
	}
	raw, _ := json.Marshal(msg)
	routeMessage(agentConn, raw)

	select {
	case resp := <-clientConn.send:
		var outMsg OutgoingMessage
		json.Unmarshal(resp, &outMsg)
		if outMsg.Type != "typing" {
			t.Fatalf("expected typing type, got %s", outMsg.Type)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for typing indicator")
	}
}

func TestGetOrCreateConversation(t *testing.T) {
	setupTestDB(t)

	conv1, err := GetOrCreateConversation("user_x", "agent_y")
	if err != nil {
		t.Fatal(err)
	}
	conv2, err := GetOrCreateConversation("user_x", "agent_y")
	if err != nil {
		t.Fatal(err)
	}
	if conv1.ID != conv2.ID {
		t.Fatalf("expected same conversation ID, got %s and %s", conv1.ID, conv2.ID)
	}
}

func TestStoreAndGetMessages(t *testing.T) {
	setupTestDB(t)

	conv, err := CreateConversation("user_m", "agent_m")
	if err != nil {
		t.Fatal(err)
	}

	msg := RoutedMessage{
		Type:           "message",
		ConversationID: conv.ID,
		Content:        "test message",
		SenderType:     "agent",
		SenderID:       "agent_m",
		RecipientID:    "user_m",
	}

	if err := storeMessage(msg); err != nil {
		t.Fatal(err)
	}

	messages, err := getConversationMessages(conv.ID, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(messages) != 1 {
		t.Fatalf("expected 1 message, got %d", len(messages))
	}
	if messages[0].Content != "test message" {
		t.Fatalf("expected 'test message', got %s", messages[0].Content)
	}
	if messages[0].SenderType != "agent" || messages[0].SenderID != "agent_m" {
		t.Fatalf("expected sender agent/agent_m, got %s/%s", messages[0].SenderType, messages[0].SenderID)
	}
}

func TestGetMessagesPagination(t *testing.T) {
	setupTestDB(t)

	conv, err := CreateConversation("user_p", "agent_p")
	if err != nil {
		t.Fatal(err)
	}

	// Store 5 messages
	for i := 0; i < 5; i++ {
		msg := RoutedMessage{
			Type:           "message",
			ConversationID: conv.ID,
			Content:        "msg " + string(rune('0'+i)),
			SenderType:     "agent",
			SenderID:       "agent_p",
			RecipientID:    "user_p",
		}
		if err := storeMessage(msg); err != nil {
			t.Fatal(err)
		}
		time.Sleep(time.Millisecond) // ensure ordering
	}

	// Limit to 3
	messages, err := getConversationMessages(conv.ID, 3)
	if err != nil {
		t.Fatal(err)
	}
	if len(messages) != 3 {
		t.Fatalf("expected 3 messages with limit, got %d", len(messages))
	}

	// Default limit (0 -> 50)
	all, err := getConversationMessages(conv.ID, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 5 {
		t.Fatalf("expected 5 messages with default limit, got %d", len(all))
	}

	// Verify ordering (oldest first)
	if all[0].Content != "msg 0" {
		t.Fatalf("expected oldest first, got %s", all[0].Content)
	}
}

func TestGetMessagesViaREST(t *testing.T) {
	_, cleanup := setupTestServerForRouting(t)
	defer cleanup()

	token := registerUserAndGetToken(t, "rest-msgs@example.com", "password123")

	// Create a conversation
	form := url.Values{}
	form.Set("agent_id", "rest-agent")
	req := httptest.NewRequest(http.MethodPost, "/conversations/create", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleCreateConversation(w, req)

	var createResp map[string]string
	json.Unmarshal(w.Body.Bytes(), &createResp)
	convID := createResp["conversation_id"]

	// Store messages directly
	for i := 0; i < 3; i++ {
		msg := RoutedMessage{
			Type:           "message",
			ConversationID: convID,
			Content:        "hello " + string(rune('A'+i)),
			SenderType:     "client",
			SenderID:       createResp["user_id"],
			RecipientID:    "rest-agent",
		}
		if err := storeMessage(msg); err != nil {
			t.Fatal(err)
		}
	}

	// Fetch messages via REST
	req2 := httptest.NewRequest(http.MethodGet, "/conversations/messages?conversation_id="+convID, nil)
	req2.Header.Set("Authorization", "Bearer "+token)
	w2 := httptest.NewRecorder()
	handleGetMessages(w2, req2)

	if w2.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w2.Code, w2.Body.String())
	}

	var messages []StoredMessage
	json.Unmarshal(w2.Body.Bytes(), &messages)
	if len(messages) != 3 {
		t.Fatalf("expected 3 messages, got %d", len(messages))
	}
}

func TestGetMessagesUnauthorizedUser(t *testing.T) {
	setupTestDB(t)
	hub = newHub()
	go hub.run()

	// User A creates a conversation
	tokenA := registerUserAndGetToken(t, "user-a@example.com", "password123")
	form := url.Values{}
	form.Set("agent_id", "shared-agent")
	req := httptest.NewRequest(http.MethodPost, "/conversations/create", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+tokenA)
	w := httptest.NewRecorder()
	handleCreateConversation(w, req)

	var createResp map[string]string
	json.Unmarshal(w.Body.Bytes(), &createResp)
	convID := createResp["conversation_id"]

	// User B tries to read User A's messages
	tokenB := registerUserAndGetToken(t, "user-b@example.com", "password456")
	req2 := httptest.NewRequest(http.MethodGet, "/conversations/messages?conversation_id="+convID, nil)
	req2.Header.Set("Authorization", "Bearer "+tokenB)
	w2 := httptest.NewRecorder()
	handleGetMessages(w2, req2)

	if w2.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for unauthorized user, got %d", w2.Code)
	}
}

func TestGetMessagesNonexistentConversation(t *testing.T) {
	setupTestDB(t)
	hub = newHub()
	go hub.run()

	token := registerUserAndGetToken(t, "no-conv@example.com", "password123")
	req := httptest.NewRequest(http.MethodGet, "/conversations/messages?conversation_id=conv_nonexistent", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleGetMessages(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}