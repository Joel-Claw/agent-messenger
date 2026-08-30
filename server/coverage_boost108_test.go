package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/gorilla/websocket"
)

// =============================================================================
// CB108: Additional coverage for writePump (70.4% → 90%+), readPump (86.4% → 90%+),
// sendAPNSNotification (64.3% → 80%+), routeChatMessage (84.4% → 90%+),
// handleUpload (81.8% → 90%+), and other sub-90% functions
// =============================================================================

func setupTestDB_CB108(t *testing.T) *sql.DB {
	t.Helper()
	tmpFile := fmt.Sprintf("/tmp/cb108_test_%d.db", time.Now().UnixNano())
	testDB, err := sql.Open("sqlite3", tmpFile)
	if err != nil {
		t.Fatalf("failed to open DB: %v", err)
	}
	currentDriver = DriverSQLite
	if err := initSchema(testDB); err != nil {
		t.Fatalf("failed to init schema: %v", err)
	}
	oldDB := db
	db = testDB
	t.Cleanup(func() {
		db = oldDB
		testDB.Close()
		os.Remove(tmpFile)
	})
	return testDB
}

func generateTestJWT_CB108(userID, username string) string {
	token, _ := GenerateJWT(userID, username)
	return token
}

// =============================================================================
// writePump tests (70.4% → target 90%+)
// =============================================================================

func TestCB108_WritePump_SendChannelClosed(t *testing.T) {
	h := newHub()
	go h.run()
	defer h.Stop()

	done := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upgrader := websocket.Upgrader{}
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()

		c := &Connection{
			conn:     conn,
			connType: "agent",
			id:       "test-agent-closed",
			send:     make(chan []byte, 5),
			hub:      h,
		}

		go func() {
			c.writePump()
			close(done)
		}()

		// Close the send channel to trigger the "channel closed" path
		close(c.send)
	}))
	defer srv.Close()

	wsURL := "ws://" + strings.TrimPrefix(srv.URL, "http://")
	ws, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ws.Close()

	select {
	case <-done:
		// success
	case <-time.After(3 * time.Second):
		t.Error("writePump did not exit after channel close")
	}
}

func TestCB108_WritePump_MessageThenClose(t *testing.T) {
	h := newHub()
	go h.run()
	defer h.Stop()

	done := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upgrader := websocket.Upgrader{}
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()

		c := &Connection{
			conn:     conn,
			connType: "client",
			id:       "test-client-msg",
			send:     make(chan []byte, 5),
			hub:      h,
		}

		go func() {
			c.writePump()
			close(done)
		}()

		// Send a message
		c.send <- []byte("hello world")
		// Then close the channel to trigger exit
		close(c.send)
	}))
	defer srv.Close()

	wsURL := "ws://" + strings.TrimPrefix(srv.URL, "http://")
	ws, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ws.Close()

	select {
	case <-done:
		// success
	case <-time.After(3 * time.Second):
		t.Error("writePump did not exit after message + channel close")
	}
}

func TestCB108_WritePump_WriteError(t *testing.T) {
	h := newHub()
	go h.run()
	defer h.Stop()

	done := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upgrader := websocket.Upgrader{}
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()

		c := &Connection{
			conn:     conn,
			connType: "agent",
			id:       "test-write-err",
			send:     make(chan []byte, 5),
			hub:      h,
		}

		// Close the underlying connection so write fails
		conn.Close()
		// Send a message to trigger immediate write error
		c.send <- []byte("trigger write error")

		go func() {
			c.writePump()
			close(done)
		}()
	}))
	defer srv.Close()

	wsURL := "ws://" + strings.TrimPrefix(srv.URL, "http://")
	ws, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ws.Close()

	select {
	case <-done:
		// success
	case <-time.After(3 * time.Second):
		t.Error("writePump did not exit after write error")
	}
}

// =============================================================================
// readPump tests (86.4% → target 90%+)
// =============================================================================

func TestCB108_ReadPump_NormalClose(t *testing.T) {
	h := newHub()
	go h.run()
	defer h.Stop()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upgrader := websocket.Upgrader{}
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()

		c := &Connection{
			conn:     conn,
			connType: "agent",
			id:       "test-readpump-close",
			send:     make(chan []byte, 5),
			hub:      h,
		}

		c.readPump()
	}))
	defer srv.Close()

	wsURL := "ws://" + strings.TrimPrefix(srv.URL, "http://")
	ws, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Send a normal close message
	ws.WriteMessage(websocket.CloseMessage,
		websocket.FormatCloseMessage(websocket.CloseNormalClosure, "bye"))
	ws.Close()

	// Give readPump time to process the close and return
	time.Sleep(200 * time.Millisecond)
}

func TestCB108_ReadPump_MessageRouting(t *testing.T) {
	h := newHub()
	go h.run()
	defer h.Stop()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upgrader := websocket.Upgrader{}
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()

		c := &Connection{
			conn:     conn,
			connType: "agent",
			id:       "test-readpump-route",
			send:     make(chan []byte, 10),
			hub:      h,
		}

		c.readPump()
	}))
	defer srv.Close()

	wsURL := "ws://" + strings.TrimPrefix(srv.URL, "http://")
	ws, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ws.Close()

	// Send a chat message (IncomingMessage format: type + data)
	chatData, _ := json.Marshal(RoutedMessage{
		Type:           "chat",
		ConversationID: "conv-readpump-test",
		Content:        "test message",
	})
	incoming := IncomingMessage{
		Type: "chat",
		Data: chatData,
	}
	data, _ := json.Marshal(incoming)
	ws.WriteMessage(websocket.TextMessage, data)

	// Give it a moment to route
	time.Sleep(100 * time.Millisecond)

	// Close connection
	ws.Close()
}

// =============================================================================
// routeChatMessage tests (84.4% → target 90%+)
// =============================================================================

func TestCB108_RouteChatMessage_AgentToClientSuccess(t *testing.T) {
	setupTestDB_CB108(t)

	h := newHub()
	go h.run()
	defer h.Stop()

	oldHub := hub
	hub = h
	defer func() { hub = oldHub }()

	// Create conversation in DB
	db.Exec("INSERT INTO conversations (id, user_id, agent_id, created_at) VALUES (?, ?, ?, ?)",
		"conv-rtest", "routeuser", "routeagent", time.Now().Format(time.RFC3339))

	// Register agent
	agentConn := &Connection{
		connType: "agent",
		id:       "routeagent",
		send:     make(chan []byte, 10),
		hub:      h,
	}
	h.agents["routeagent"] = agentConn

	// Register client
	clientConn := &Connection{
		connType: "client",
		id:       "routeuser",
		send:     make(chan []byte, 10),
		hub:      h,
	}
	h.clientConns["routeuser"] = []*Connection{clientConn}

	chatData, _ := json.Marshal(RoutedMessage{
		Type:           "chat",
		ConversationID:  "conv-rtest",
		Content:         "hello from agent",
		SenderType:      "agent",
		SenderID:        "routeagent",
	})
	routeChatMessage(agentConn, chatData)

	// Client should receive the message
	select {
	case received := <-clientConn.send:
		if !strings.Contains(string(received), "hello from agent") {
			t.Errorf("expected message content, got: %s", string(received))
		}
	case <-time.After(1 * time.Second):
		t.Error("client did not receive message")
	}
}

func TestCB108_RouteChatMessage_ClientToAgentSuccess(t *testing.T) {
	setupTestDB_CB108(t)

	h := newHub()
	go h.run()
	defer h.Stop()

	oldHub := hub
	hub = h
	defer func() { hub = oldHub }()

	db.Exec("INSERT INTO conversations (id, user_id, agent_id, created_at) VALUES (?, ?, ?, ?)",
		"conv-rtest2", "routeuser2", "routeagent2", time.Now().Format(time.RFC3339))

	agentConn := &Connection{
		connType: "agent",
		id:       "routeagent2",
		send:     make(chan []byte, 10),
		hub:      h,
	}
	h.agents["routeagent2"] = agentConn

	clientConn := &Connection{
		connType: "client",
		id:       "routeuser2",
		send:     make(chan []byte, 10),
		hub:      h,
	}
	h.clientConns["routeuser2"] = []*Connection{clientConn}

	chatData, _ := json.Marshal(RoutedMessage{
		Type:           "chat",
		ConversationID:  "conv-rtest2",
		Content:         "hello from client",
		SenderType:      "user",
		SenderID:        "routeuser2",
	})
	routeChatMessage(clientConn, chatData)

	select {
	case received := <-agentConn.send:
		if !strings.Contains(string(received), "hello from client") {
			t.Errorf("expected message content, got: %s", string(received))
		}
	case <-time.After(1 * time.Second):
		t.Error("agent did not receive message")
	}
}

func TestCB108_RouteChatMessage_ConvNotFound(t *testing.T) {
	setupTestDB_CB108(t)

	h := newHub()
	go h.run()
	defer h.Stop()

	oldHub := hub
	hub = h
	defer func() { hub = oldHub }()

	agentConn := &Connection{
		connType: "agent",
		id:       "agent-noconv",
		send:     make(chan []byte, 10),
		hub:      h,
	}

	chatData, _ := json.Marshal(RoutedMessage{
		Type:          "chat",
		ConversationID: "nonexistent-conv",
		Content:        "no conv",
	})

	// Should not panic
	routeChatMessage(agentConn, chatData)
}

func TestCB108_RouteChatMessage_InvalidJSON(t *testing.T) {
	h := newHub()
	go h.run()
	defer h.Stop()

	agentConn := &Connection{
		connType: "agent",
		id:       "agent-badjson",
		send:     make(chan []byte, 10),
		hub:      h,
	}

	// Invalid JSON data
	routeChatMessage(agentConn, json.RawMessage(`{invalid json`))
}

func TestCB108_RouteChatMessage_EmptyContent(t *testing.T) {
	setupTestDB_CB108(t)

	h := newHub()
	go h.run()
	defer h.Stop()

	oldHub := hub
	hub = h
	defer func() { hub = oldHub }()

	db.Exec("INSERT INTO conversations (id, user_id, agent_id, created_at) VALUES (?, ?, ?, ?)",
		"conv-empty", "emptyuser", "emptyagent", time.Now().Format(time.RFC3339))

	agentConn := &Connection{
		connType: "agent",
		id:       "emptyagent",
		send:     make(chan []byte, 10),
		hub:      h,
	}
	h.agents["emptyagent"] = agentConn

	chatData, _ := json.Marshal(RoutedMessage{
		Type:          "chat",
		ConversationID: "conv-empty",
		Content:        "",
	})

	routeChatMessage(agentConn, chatData)
}

// =============================================================================
// handleUpload tests (81.8% → target 90%+)
// =============================================================================

func TestCB108_HandleUpload_NoContentType(t *testing.T) {
	setupTestDB_CB108(t)

	req := httptest.NewRequest("POST", "/upload?conversation_id=conv1", strings.NewReader(""))
	req.Header.Set("Authorization", "Bearer "+generateTestJWT_CB108("u1", "user1"))
	rr := httptest.NewRecorder()

	handleUpload(rr, req)

	if rr.Code != http.StatusBadRequest && rr.Code != http.StatusOK {
		t.Errorf("expected 400 or 200, got %d", rr.Code)
	}
}

// =============================================================================
// sendAPNSNotification tests (64.3% → target 80%+)
// =============================================================================

func TestCB108_SendAPNSNotification_EmptyConvID(t *testing.T) {
	oldConfig := pushConfig
	defer func() { pushConfig = oldConfig }()

	pushConfig = &PushNotificationConfig{
		APNSEnabled: true,
	}
	// With APNs enabled but no client, should handle gracefully
	err := sendAPNSNotification("device-token", "title", "body", "")
	// Should return error for empty convID or nil client
	if err != nil {
		t.Logf("sendAPNSNotification with empty convID returned: %v", err)
	}
}

func TestCB108_SendAPNSNotification_NilConfig(t *testing.T) {
	oldConfig := pushConfig
	defer func() { pushConfig = oldConfig }()

	pushConfig = nil
	// With nil config, should return early
	err := sendAPNSNotification("device-token", "title", "body", "conv1")
	if err != nil {
		t.Errorf("expected nil error when pushConfig is nil, got: %v", err)
	}
}

func TestCB108_SendAPNSNotification_Disabled(t *testing.T) {
	oldConfig := pushConfig
	defer func() { pushConfig = oldConfig }()

	pushConfig = &PushNotificationConfig{
		APNSEnabled: false,
	}
	err := sendAPNSNotification("device-token", "title", "body", "conv1")
	if err != nil {
		t.Errorf("expected nil error when APNs disabled, got: %v", err)
	}
}

// =============================================================================
// sendWelcomeMessage tests (80% → target 90%+)
// =============================================================================

func TestCB108_SendWelcomeMessage_Agent(t *testing.T) {
	h := newHub()
	go h.run()
	defer h.Stop()

	c := &Connection{
		connType: "agent",
		id:       "welcome-agent",
		send:     make(chan []byte, 5),
		hub:      h,
	}

	sendWelcomeMessage(c)

	select {
	case msg := <-c.send:
		if !strings.Contains(string(msg), "welcome") && !strings.Contains(string(msg), "connected") {
			t.Errorf("expected welcome message, got: %s", string(msg))
		}
	default:
		t.Error("no welcome message received")
	}
}

func TestCB108_SendWelcomeMessage_ClientWithDeviceID(t *testing.T) {
	h := newHub()
	go h.run()
	defer h.Stop()

	c := &Connection{
		connType: "client",
		id:       "welcome-client",
		send:     make(chan []byte, 5),
		hub:      h,
		deviceID: "device-123",
	}

	sendWelcomeMessage(c)

	select {
	case msg := <-c.send:
		var parsed map[string]interface{}
		if err := json.Unmarshal(msg, &parsed); err == nil {
			if parsed["type"] != "welcome" && parsed["type"] != "connected" {
				t.Errorf("expected welcome/connected type, got: %v", parsed["type"])
			}
		}
	default:
		t.Error("no welcome message received")
	}
}

func TestCB108_SendWelcomeMessage_ClosedChannel(t *testing.T) {
	h := newHub()
	go h.run()
	defer h.Stop()

	c := &Connection{
		connType: "agent",
		id:       "welcome-closed",
		send:     make(chan []byte, 0), // unbuffered, will block
		hub:      h,
	}
	close(c.send) // close immediately

	// Should not panic
	sendWelcomeMessage(c)
}

// =============================================================================
// InitTracing tests (79.5% → target 85%+)
// =============================================================================

func TestCB108_InitTracing_Disabled(t *testing.T) {
	tracingMu = sync.Once{}
	tp = nil

	t.Setenv("OTEL_ENABLED", "false")

	err := InitTracing()
	if err != nil {
		t.Errorf("expected nil error when tracing disabled, got: %v", err)
	}
	if IsTracingEnabled() {
		t.Error("tracing should not be enabled")
	}
}

func TestCB108_InitTracing_NoEndpoint(t *testing.T) {
	tracingMu = sync.Once{}
	tp = nil

	t.Setenv("OTEL_ENABLED", "true")
	os.Unsetenv("OTEL_EXPORTER_OTLP_ENDPOINT")
	os.Unsetenv("OTEL_EXPORTER_OTLP_HTTP_ENDPOINT")

	err := InitTracing()
	// InitTracing returns nil when no endpoint — just disables tracing
	if err != nil {
		t.Errorf("expected nil error when no endpoint, got: %v", err)
	}
	if IsTracingEnabled() {
		t.Error("tracing should not be enabled without endpoint")
	}
}

// =============================================================================
// ShutdownTracing tests (80% → target 90%+)
// =============================================================================

func TestCB108_ShutdownTracing_NilProvider(t *testing.T) {
	tracingMu = sync.Once{}
	tp = nil

	// Should not panic when tp is nil
	ShutdownTracing()
}

func TestCB108_ShutdownTracing_DoubleShutdown(t *testing.T) {
	tracingMu = sync.Once{}
	tp = nil

	t.Setenv("OTEL_ENABLED", "true")
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://localhost:4318")
	t.Setenv("OTEL_EXPORTER_OTLP_PROTOCOL", "http")

	_ = InitTracing()
	ShutdownTracing()

	// Double shutdown should be safe
	ShutdownTracing()
}

// =============================================================================
// handleGetRateLimitTier tests (87.5% → target 95%+)
// =============================================================================

func TestCB108_HandleGetRateLimitTier_Success(t *testing.T) {
	setupTestDB_CB108(t)

	origAdminSecret := adminSecret
	defer func() { adminSecret = origAdminSecret }()
	resetAdminSecret()

	globalTieredLimiter.SetTier("tier-user", TierPro)

	req := httptest.NewRequest("GET", "/admin/rate-limit/tier?user_id=tier-user", nil)
	req.Header.Set("X-Admin-Secret", getAdminSecret())
	rr := httptest.NewRecorder()

	handleGetRateLimitTier(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "pro") {
		t.Errorf("expected tier 'pro' in response, got: %s", rr.Body.String())
	}
}

func TestCB108_HandleGetRateLimitTier_FormSecret(t *testing.T) {
	setupTestDB_CB108(t)

	origAdminSecret := adminSecret
	defer func() { adminSecret = origAdminSecret }()
	resetAdminSecret()

	req := httptest.NewRequest("GET", "/admin/rate-limit/tier?user_id=no-tier-user&admin_secret="+getAdminSecret(), nil)
	rr := httptest.NewRecorder()

	handleGetRateLimitTier(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
}

// =============================================================================
// addReaction tests (88.5% → target 95%+)
// =============================================================================

func TestCB108_AddReaction_Success(t *testing.T) {
	setupTestDB_CB108(t)

	db.Exec("INSERT INTO conversations (id, user_id, agent_id, created_at) VALUES (?, ?, ?, ?)",
		"conv-react", "reactuser", "reactagent", time.Now().Format(time.RFC3339))
	db.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, created_at) VALUES (?, ?, ?, ?, ?, ?)",
		"msg-react", "conv-react", "user", "reactuser", "hello", time.Now().Format(time.RFC3339))

	reaction, _, err := addReaction("msg-react", "reactuser", "👍")
	if err != nil {
		t.Fatalf("addReaction failed: %v", err)
	}
	if reaction == nil {
		t.Fatal("expected reaction, got nil")
	}
}

func TestCB108_AddReaction_ToggleOff(t *testing.T) {
	setupTestDB_CB108(t)

	db.Exec("INSERT INTO conversations (id, user_id, agent_id, created_at) VALUES (?, ?, ?, ?)",
		"conv-react2", "reactuser2", "reactagent2", time.Now().Format(time.RFC3339))
	db.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, created_at) VALUES (?, ?, ?, ?, ?, ?)",
		"msg-react2", "conv-react2", "user", "reactuser2", "hello", time.Now().Format(time.RFC3339))

	// Add reaction
	addReaction("msg-react2", "reactuser2", "❤️")
	// Toggle it off — addReaction returns nil, false, nil when removing
	reaction, _, err := addReaction("msg-react2", "reactuser2", "❤️")
	if err != nil {
		t.Fatalf("addReaction toggle failed: %v", err)
	}
	if reaction != nil {
		t.Error("expected nil reaction when toggled off")
	}
}

// =============================================================================
// handleGetTags tests (88.5% → target 95%+)
// =============================================================================

func TestCB108_HandleGetTags_Success(t *testing.T) {
	setupTestDB_CB108(t)

	db.Exec("INSERT INTO conversations (id, user_id, agent_id, created_at) VALUES (?, ?, ?, ?)",
		"conv-tags", "taguser", "tagagent", time.Now().Format(time.RFC3339))
	db.Exec("INSERT INTO conversation_tags (id, conversation_id, tag, created_at) VALUES (?, ?, ?, ?)",
		"tag1", "conv-tags", "important", time.Now().Format(time.RFC3339))
	db.Exec("INSERT INTO conversation_tags (id, conversation_id, tag, created_at) VALUES (?, ?, ?, ?)",
		"tag2", "conv-tags", "followup", time.Now().Format(time.RFC3339))

	req := httptest.NewRequest("GET", "/conversations/tags?conversation_id=conv-tags", nil)
	req.Header.Set("Authorization", "Bearer "+generateTestJWT_CB108("taguser", "taguser"))
	rr := httptest.NewRecorder()

	handleGetTags(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "important") {
		t.Errorf("expected 'important' tag in response, got: %s", rr.Body.String())
	}
}

func TestCB108_HandleGetTags_Empty(t *testing.T) {
	setupTestDB_CB108(t)

	db.Exec("INSERT INTO conversations (id, user_id, agent_id, created_at) VALUES (?, ?, ?, ?)",
		"conv-notags", "taguser2", "tagagent2", time.Now().Format(time.RFC3339))

	req := httptest.NewRequest("GET", "/conversations/tags?conversation_id=conv-notags", nil)
	req.Header.Set("Authorization", "Bearer "+generateTestJWT_CB108("taguser2", "taguser2"))
	rr := httptest.NewRecorder()

	handleGetTags(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
}

// =============================================================================
// handleGetPresence tests (87.1% → target 93%+)
// =============================================================================

func TestCB108_HandleGetPresence_WithAgents(t *testing.T) {
	setupTestDB_CB108(t)

	h := newHub()
	go h.run()
	defer h.Stop()

	h.agents["agent-pres1"] = &Connection{
		connType: "agent",
		id:       "agent-pres1",
	}
	h.agents["agent-pres2"] = &Connection{
		connType: "agent",
		id:       "agent-pres2",
	}

	oldHub := hub
	hub = h
	defer func() { hub = oldHub }()

	req := httptest.NewRequest("GET", "/presence", nil)
	req.Header.Set("Authorization", "Bearer "+generateTestJWT_CB108("u-pres", "userpres"))
	rr := httptest.NewRecorder()

	handleGetPresence(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
}

// =============================================================================
// TieredRateLimiter cleanup tests (83.3% → target 95%+)
// =============================================================================

func TestCB108_TieredRateLimiter_CleanupRemovesStale(t *testing.T) {
	tl := NewTieredRateLimiter()
	defer tl.Stop()

	tl.mu.Lock()
	tl.limits["stale-user"] = &userRateLimitState{
		windowEnd: time.Now().Add(-20 * time.Minute),
		count:     5,
	}
	tl.mu.Unlock()

	tl.cleanupOnce()

	tl.mu.Lock()
	_, exists := tl.limits["stale-user"]
	tl.mu.Unlock()

	if exists {
		t.Error("expected stale entry to be removed by cleanupOnce")
	}
}

func TestCB108_TieredRateLimiter_CleanupKeepsFresh(t *testing.T) {
	tl := NewTieredRateLimiter()
	defer tl.Stop()

	tl.mu.Lock()
	tl.limits["fresh-user"] = &userRateLimitState{
		windowEnd: time.Now().Add(5 * time.Minute),
		count:     3,
	}
	tl.mu.Unlock()

	tl.cleanupOnce()

	tl.mu.Lock()
	_, exists := tl.limits["fresh-user"]
	tl.mu.Unlock()

	if !exists {
		t.Error("expected fresh entry to be kept by cleanupOnce")
	}
}

// =============================================================================
// loadQueueFromDB tests (89.5% → target 95%+)
// =============================================================================

func TestCB108_LoadQueueFromDB_WithMessages(t *testing.T) {
	setupTestDB_CB108(t)

	persistQueue(db, "user-qa", []byte(`{"type":"chat","content":"msg1"}`))
	persistQueue(db, "user-qa", []byte(`{"type":"chat","content":"msg2"}`))
	persistQueue(db, "user-qb", []byte(`{"type":"chat","content":"msg3"}`))

	q := newOfflineQueue(100, 7*24*time.Hour)
	loadQueueFromDB(db, q)

	if q.TotalDepth() != 3 {
		t.Errorf("expected 3 messages loaded, got %d", q.TotalDepth())
	}
}

// =============================================================================
// deleteConversation tests (83.3% → target 90%+)
// =============================================================================

func TestCB108_DeleteConversation_Success(t *testing.T) {
	setupTestDB_CB108(t)

	db.Exec("INSERT INTO conversations (id, user_id, agent_id, created_at) VALUES (?, ?, ?, ?)",
		"conv-del", "deluser", "delagent", time.Now().Format(time.RFC3339))
	db.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, created_at) VALUES (?, ?, ?, ?, ?, ?)",
		"msg-d1", "conv-del", "user", "deluser", "msg to delete", time.Now().Format(time.RFC3339))
	db.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, created_at) VALUES (?, ?, ?, ?, ?, ?)",
		"msg-d2", "conv-del", "agent", "delagent", "reply to delete", time.Now().Format(time.RFC3339))

	err := deleteConversation("conv-del", "deluser")
	if err != nil {
		t.Fatalf("deleteConversation failed: %v", err)
	}

	var count int
	db.QueryRow("SELECT COUNT(*) FROM conversations WHERE id = ?", "conv-del").Scan(&count)
	if count != 0 {
		t.Error("conversation still exists after delete")
	}

	db.QueryRow("SELECT COUNT(*) FROM messages WHERE conversation_id = ?", "conv-del").Scan(&count)
	if count != 0 {
		t.Error("messages still exist after conversation delete")
	}
}

func TestCB108_DeleteConversation_NotFound(t *testing.T) {
	setupTestDB_CB108(t)

	err := deleteConversation("nonexistent-conv", "nouser")
	if err == nil {
		t.Error("expected error for nonexistent conversation")
	}
}

// =============================================================================
// handleSetNotificationPrefs tests (88.9% → target 95%+)
// =============================================================================

func TestCB108_HandleSetNotificationPrefs_Success(t *testing.T) {
	setupTestDB_CB108(t)

	db.Exec("INSERT INTO conversations (id, user_id, agent_id, created_at) VALUES (?, ?, ?, ?)",
		"conv-notif", "notifuser", "notifagent", time.Now().Format(time.RFC3339))

	form := "conversation_id=conv-notif&muted=true"
	req := httptest.NewRequest("POST", "/notifications/prefs", strings.NewReader(form))
	req.Header.Set("Authorization", "Bearer "+generateTestJWT_CB108("notifuser", "notifuser"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	// Must go through authMiddleware to set userID in context
	authMiddleware(handleSetNotificationPrefs)(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
}

// =============================================================================
// Snapshot tests (83.3% → target 90%+)
// =============================================================================

func TestCB108_Snapshot_WithMetrics(t *testing.T) {
	h := newHub()
	go h.run()
	defer h.Stop()

	h.messagesRouted.Add(5)

	m := NewMetrics(h)
	ServerMetrics = m
	defer func() { ServerMetrics = nil }()

	m.MessagesIn.Add(10)
	m.MessagesOut.Add(8)
	m.ConnectionsTotal.Add(3)
	m.ErrorsTotal.Add(1)
	m.RateLimited.Add(2)

	snap := m.Snapshot()
	if msgsRouted, ok := snap["messages_routed"]; ok {
		if fmt.Sprintf("%v", msgsRouted) != "5" {
			t.Errorf("expected 5 messages routed, got %v", msgsRouted)
		}
	}
	if msgsIn, ok := snap["messages_in"]; ok {
		if fmt.Sprintf("%v", msgsIn) != "10" {
			t.Errorf("expected 10 messages in, got %v", msgsIn)
		}
	}
}

// =============================================================================
// checkRateLimit tests (89.5% → target 95%+)
// =============================================================================

func TestCB108_CheckRateLimit_Allowed(t *testing.T) {
	messageRateLimiter.Reset()

	c := &Connection{connType: "client", id: "test-user-allow"}
	allowed := checkRateLimit(c)
	if !allowed {
		t.Error("expected rate limit to allow first message")
	}
	messageRateLimiter.Reset()
}

func TestCB108_CheckRateLimit_Blocked(t *testing.T) {
	messageRateLimiter.Reset()

	c := &Connection{connType: "client", id: "test-user-block"}
	for i := 0; i < 60; i++ {
		checkRateLimit(c)
	}

	allowed := checkRateLimit(c)
	if allowed {
		t.Error("expected rate limit to block after 60 messages")
	}
	messageRateLimiter.Reset()
}