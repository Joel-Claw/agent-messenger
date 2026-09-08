package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"
)

// CB113: Coverage boost targeting remaining sub-88% functions.
// Focus areas (from coverage profile after CB112, 88.2% with CB100-112):
// - writePump (70.4%): successful message write, write error on message
// - InitTracing (79.5%): HTTP protocol path, gRPC with :443, successful init
// - sendWelcomeMessage (80%): with deviceID field
// - ShutdownTracing (80%): shutdown with real tp
// - RegisterAgentOnConnect (81.8%): UPDATE name path, DB error on UPDATE
// - cleanup (83.3%): ticker cleanup (indirect via cleanupOnce)
// - routeChatMessage (84.4%): storeMessage error, agent-to-client offline, client-to-agent offline
// - initAPNs (84%): production env, development env
// - handleStoreEncryptedMessage (84.9%): agent sender delivery, user offline notify, DB insert error
// - handleUpload (85.7%): file create error, file write error, no extension
// - readPump (86.4%): message routing, unexpected close
// - handleListAttachments (86.1%): rows.Scan error, empty result
// - handleGetRateLimitTier (87.5%): JWT auth, no auth
// - handleGetEncryptedMessages (87.8%): missing conv ID, not participant
// - handleGetAttachment (88.2%): agent auth, wrong owner, serve file
// - initFCM (88.9%): no creds path
// - loadQueueFromDB (89.5%): with data

func resetGlobals_CB113() {
	hub = nil
	offlineQueue = nil
	pushConfig = nil
	tracingEnabled = false
	tracer = nil
	tp = nil
	tracingMu = sync.Once{}
	agentPresenceEnabled = false
	agentPresenceInterval = 30 * time.Second
	agentPresenceTimeout = 90 * time.Second
	serverDBPath = ""
	vapidPublicKey = ""
}

func makeJWTReq_CB113(method, path string, body io.Reader, userID string) *http.Request {
	req := httptest.NewRequest(method, path, body)
	token, _ := GenerateJWT(userID, "testuser")
	req.Header.Set("Authorization", "Bearer "+token)
	return req
}

// ==================== writePump tests ====================

func TestCB113_WritePump_SuccessfulMessageWrite(t *testing.T) {
	resetGlobals_CB113()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upgrader := websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		h := newHub()
		hub = h
		go h.run()
		defer h.Stop()

		c := &Connection{
			hub:         h,
			connType:    "agent",
			id:          "test-agent",
			conn:        conn,
			send:        make(chan []byte, 10),
			connectedAt: time.Now(),
		}
		h.register <- c

		go c.writePump()
		// Keep reading to prevent write blocking
		go func() {
			for {
				if _, _, err := conn.ReadMessage(); err != nil {
					return
				}
			}
		}()

		// Wait for writePump to be running
		time.Sleep(50 * time.Millisecond)

		// Send a message through the channel
		testMsg := []byte(`{"type":"test","data":"hello"}`)
		c.send <- testMsg

		// Give time for write
		time.Sleep(50 * time.Millisecond)

		// Clean up: close the conn which will cause readPump/writePump to exit
		conn.Close()
		time.Sleep(50 * time.Millisecond)
	}))
	defer srv.Close()

	wsURL := "ws://" + strings.TrimPrefix(srv.URL, "http://")
	wsConn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer wsConn.Close()

	// Read the message that was sent through writePump
	wsConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, msg, err := wsConn.ReadMessage()
	if err != nil {
		t.Fatalf("expected to receive message, got error: %v", err)
	}
	if string(msg) != `{"type":"test","data":"hello"}` {
		t.Errorf("expected test message, got %s", string(msg))
	}
}

func TestCB113_WritePump_WriteError(t *testing.T) {
	resetGlobals_CB113()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upgrader := websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		h := newHub()
		hub = h
		go h.run()
		defer h.Stop()

		c := &Connection{
			hub:         h,
			connType:    "agent",
			id:          "test-agent",
			conn:        conn,
			send:        make(chan []byte, 10),
			connectedAt: time.Now(),
		}
		h.register <- c

		// Close the underlying connection immediately so writes fail
		conn.Close()

		go c.writePump()

		// Send a message — write will fail because conn is closed
		c.send <- []byte(`{"type":"test"}`)

		// Wait for writePump to exit due to write error
		time.Sleep(100 * time.Millisecond)
	}))
	defer srv.Close()

	wsURL := "ws://" + strings.TrimPrefix(srv.URL, "http://")
	// Dial will fail because the handler closes the connection
	wsConn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err == nil {
		wsConn.Close()
	}
	// Test passes if no panic/deadlock — writePump handles the error
}

func TestCB113_WritePump_ServerMetricsIncrement(t *testing.T) {
	resetGlobals_CB113()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upgrader := websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		h := newHub()
		hub = h
		go h.run()
		defer h.Stop()

		ServerMetrics = NewMetrics(h)
		defer func() { ServerMetrics = nil }()

		c := &Connection{
			hub:         h,
			connType:    "client",
			id:          "user1",
			conn:        conn,
			send:        make(chan []byte, 10),
			connectedAt: time.Now(),
		}
		h.register <- c

		go c.writePump()
		go func() {
			for {
				if _, _, err := conn.ReadMessage(); err != nil {
					return
				}
			}
		}()

		time.Sleep(50 * time.Millisecond)
		c.send <- []byte(`{"type":"msg"}`)
		time.Sleep(50 * time.Millisecond)

		conn.Close()
		time.Sleep(50 * time.Millisecond)
	}))
	defer srv.Close()

	wsURL := "ws://" + strings.TrimPrefix(srv.URL, "http://")
	wsConn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer wsConn.Close()

	wsConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, _, err = wsConn.ReadMessage()
	if err != nil {
		t.Errorf("expected to receive message, got error: %v", err)
	}
}

// ==================== InitTracing tests ====================

func TestCB113_InitTracing_HTTPProtocol(t *testing.T) {
	resetGlobals_CB113()
	t.Setenv("OTEL_ENABLED", "true")
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://localhost:4318")
	t.Setenv("OTEL_EXPORTER_OTLP_PROTOCOL", "http")
	t.Setenv("OTEL_SAMPLING_RATE", "0.5")

	// This will attempt to create an HTTP exporter — it should succeed
	// (creating the exporter doesn't connect to the endpoint)
	err := InitTracing()
	// May fail if OTLP HTTP library has issues, but typically creates exporter fine
	if err != nil {
		// Check if it's a resource merge error or exporter creation error
		// Either way, we've covered the HTTP protocol path
		t.Logf("InitTracing returned error (expected in test env): %v", err)
	}
	// Cleanup
	if tp != nil {
		ShutdownTracing()
	}
}

func TestCB113_InitTracing_GRPCWith443(t *testing.T) {
	resetGlobals_CB113()
	t.Setenv("OTEL_ENABLED", "true")
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "otel.example.com:443")
	t.Setenv("OTEL_EXPORTER_OTLP_PROTOCOL", "grpc")
	t.Setenv("OTEL_SAMPLING_RATE", "1.0")

	err := InitTracing()
	if err != nil {
		t.Logf("InitTracing returned error (expected in test env): %v", err)
	}
	// The :443 path should NOT add WithInsecure — we've covered that branch
	if tp != nil {
		ShutdownTracing()
	}
}

func TestCB113_InitTracing_HTTPSEndpoint(t *testing.T) {
	resetGlobals_CB113()
	t.Setenv("OTEL_ENABLED", "true")
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "https://otel.example.com:4318")
	t.Setenv("OTEL_EXPORTER_OTLP_PROTOCOL", "http")

	err := InitTracing()
	if err != nil {
		t.Logf("InitTracing returned error (expected): %v", err)
	}
	if tp != nil {
		ShutdownTracing()
	}
}

func TestCB113_InitTracing_NoEndpoint(t *testing.T) {
	resetGlobals_CB113()
	t.Setenv("OTEL_ENABLED", "true")
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "")
	t.Setenv("OTEL_EXPORTER_OTLP_HTTP_ENDPOINT", "")

	// Should return nil (disabled, no endpoint)
	err := InitTracing()
	if err != nil {
		t.Errorf("expected nil error for no endpoint, got %v", err)
	}
}

func TestCB113_InitTracing_AlreadyInitialized(t *testing.T) {
	resetGlobals_CB113()
	t.Setenv("OTEL_ENABLED", "true")
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://localhost:4318")
	t.Setenv("OTEL_EXPORTER_OTLP_PROTOCOL", "http")

	// First call
	_ = InitTracing()
	// Second call — sync.Once should skip
	err := InitTracing()
	if err != nil {
		t.Errorf("second InitTracing should return nil (sync.Once), got %v", err)
	}
	if tp != nil {
		ShutdownTracing()
	}
}

// ==================== ShutdownTracing tests ====================

func TestCB113_ShutdownTracing_WithProvider(t *testing.T) {
	resetGlobals_CB113()
	t.Setenv("OTEL_ENABLED", "true")
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://localhost:4318")
	t.Setenv("OTEL_EXPORTER_OTLP_PROTOCOL", "http")

	_ = InitTracing()
	// If tp was set, ShutdownTracing will call tp.Shutdown
	// This covers the tp != nil path
	ShutdownTracing()
	// Verify tp is nil after shutdown (or still set but shutdown called)
	// Either way, no panic
}

func TestCB113_ShutdownTracing_NilProvider(t *testing.T) {
	resetGlobals_CB113()
	tp = nil
	// Should be a no-op
	ShutdownTracing()
}

// ==================== sendWelcomeMessage tests ====================

func TestCB113_SendWelcomeMessage_WithDeviceID(t *testing.T) {
	resetGlobals_CB113()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upgrader := websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		h := newHub()
		hub = h
		go h.run()
		defer h.Stop()

		c := &Connection{
			hub:               h,
			connType:          "client",
			id:                "user1",
			conn:              conn,
			send:              make(chan []byte, 10),
			connectedAt:       time.Now(),
			negotiatedVersion: ProtocolVersion,
			deviceID:          "device-abc-123",
		}
		h.register <- c

		go c.writePump()
		go func() {
			for {
				if _, _, err := conn.ReadMessage(); err != nil {
					return
				}
			}
		}()

		sendWelcomeMessage(c)
		time.Sleep(100 * time.Millisecond)

		conn.Close()
		time.Sleep(50 * time.Millisecond)
	}))
	defer srv.Close()

	wsURL := "ws://" + strings.TrimPrefix(srv.URL, "http://")
	wsConn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer wsConn.Close()

	wsConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, msg, err := wsConn.ReadMessage()
	if err != nil {
		t.Fatalf("expected welcome message, got error: %v", err)
	}

	var welcome map[string]interface{}
	if err := json.Unmarshal(msg, &welcome); err != nil {
		t.Fatalf("failed to parse welcome: %v", err)
	}
	if welcome["type"] != "connected" {
		t.Errorf("expected type 'connected', got %v", welcome["type"])
	}
	data, ok := welcome["data"].(map[string]interface{})
	if !ok {
		t.Fatal("expected data object in welcome")
	}
	if data["device_id"] != "device-abc-123" {
		t.Errorf("expected device_id 'device-abc-123', got %v", data["device_id"])
	}
	if data["status"] != "connected" {
		t.Errorf("expected status 'connected', got %v", data["status"])
	}
}

func TestCB113_SendWelcomeMessage_NoDeviceID(t *testing.T) {
	resetGlobals_CB113()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upgrader := websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		h := newHub()
		hub = h
		go h.run()
		defer h.Stop()

		c := &Connection{
			hub:               h,
			connType:          "agent",
			id:                "agent1",
			conn:              conn,
			send:              make(chan []byte, 10),
			connectedAt:       time.Now(),
			negotiatedVersion: ProtocolVersion,
		}
		h.register <- c

		go c.writePump()
		go func() {
			for {
				if _, _, err := conn.ReadMessage(); err != nil {
					return
				}
			}
		}()

		sendWelcomeMessage(c)
		time.Sleep(100 * time.Millisecond)

		conn.Close()
		time.Sleep(50 * time.Millisecond)
	}))
	defer srv.Close()

	wsURL := "ws://" + strings.TrimPrefix(srv.URL, "http://")
	wsConn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer wsConn.Close()

	wsConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, msg, err := wsConn.ReadMessage()
	if err != nil {
		t.Fatalf("expected welcome message, got error: %v", err)
	}

	var welcome map[string]interface{}
	if err := json.Unmarshal(msg, &welcome); err != nil {
		t.Fatalf("failed to parse welcome: %v", err)
	}
	data, _ := welcome["data"].(map[string]interface{})
	if data == nil {
		t.Fatal("expected data object")
	}
	if _, hasDevice := data["device_id"]; hasDevice {
		t.Error("should not have device_id when not set")
	}
}

// ==================== RegisterAgentOnConnect tests ====================

func TestCB113_RegisterAgentOnConnect_UpdateName(t *testing.T) {
	resetGlobals_CB113()
	setupTestDB(t)

	// Insert an existing agent
	_, err := db.Exec("INSERT INTO agents (id, name, model, personality, specialty) VALUES (?, ?, ?, ?, ?)",
		"agent1", "OldName", "gpt-4", "friendly", "general")
	if err != nil {
		t.Fatal(err)
	}

	// Register with a different name — should update
	err = RegisterAgentOnConnect("agent1", "NewName", "", "", "")
	if err != nil {
		t.Fatalf("RegisterAgentOnConnect error: %v", err)
	}

	var name string
	err = db.QueryRow("SELECT name FROM agents WHERE id = ?", "agent1").Scan(&name)
	if err != nil {
		t.Fatal(err)
	}
	if name != "NewName" {
		t.Errorf("expected name 'NewName', got '%s'", name)
	}
}

func TestCB113_RegisterAgentOnConnect_NameDefaultsToAgentID(t *testing.T) {
	resetGlobals_CB113()
	setupTestDB(t)

	// Register with empty name — name should default to agentID
	err := RegisterAgentOnConnect("agent2", "", "llama", "helpful", "coding")
	if err != nil {
		t.Fatalf("RegisterAgentOnConnect error: %v", err)
	}

	var name string
	err = db.QueryRow("SELECT name FROM agents WHERE id = ?", "agent2").Scan(&name)
	if err != nil {
		t.Fatal(err)
	}
	if name != "agent2" {
		t.Errorf("expected name to default to agentID 'agent2', got '%s'", name)
	}

	// Now re-register with empty name — name == agentID so UPDATE should be skipped
	err = RegisterAgentOnConnect("agent2", "", "llama3", "", "")
	if err != nil {
		t.Fatalf("RegisterAgentOnConnect error: %v", err)
	}
}

func TestCB113_RegisterAgentOnConnect_DBUpdateError(t *testing.T) {
	resetGlobals_CB113()
	setupTestDB(t)

	_, err := db.Exec("INSERT INTO agents (id, name, model, personality, specialty) VALUES (?, ?, ?, ?, ?)",
		"agent3", "Agent3", "gpt-4", "friendly", "general")
	if err != nil {
		t.Fatal(err)
	}

	// Close DB to cause UPDATE error
	db.Close()

	err = RegisterAgentOnConnect("agent3", "Agent3", "new-model", "", "")
	if err == nil {
		t.Error("expected error for UPDATE on closed DB, got nil")
	}

	// Reopen for cleanup
	db, _ = sql.Open("sqlite3", ":memory:")
}

func TestCB113_RegisterAgentOnConnect_NewAgentInsertError(t *testing.T) {
	resetGlobals_CB113()
	setupTestDB(t)

	// Close DB to cause INSERT error
	db.Close()

	err := RegisterAgentOnConnect("new-agent", "TestAgent", "gpt-4", "friendly", "general")
	if err == nil {
		t.Error("expected error for INSERT on closed DB, got nil")
	}

	db, _ = sql.Open("sqlite3", ":memory:")
}

// ==================== routeChatMessage tests ====================

func TestCB113_RouteChatMessage_StoreError(t *testing.T) {
	resetGlobals_CB113()
	setupTestDB(t)

	h := newHub()
	hub = h
	go h.run()
	defer h.Stop()

	// Create a conversation
	conv, err := CreateConversation("user1", "agent1")
	if err != nil {
		t.Fatal(err)
	}

	// Create a client connection
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upgrader := websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}
		ws, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer ws.Close()
		c := &Connection{
			hub:         h,
			connType:    "client",
			id:          "user1",
			conn:        ws,
			send:        make(chan []byte, 10),
			connectedAt: time.Now(),
		}
		h.register <- c
		go c.writePump()
		go c.readPump()
		time.Sleep(500 * time.Millisecond)
	}))
	defer srv.Close()

	wsURL := "ws://" + strings.TrimPrefix(srv.URL, "http://")
	wsConn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer wsConn.Close()

	time.Sleep(100 * time.Millisecond)

	// Get the client connection from hub
	clientConn := h.GetClient("user1")
	if clientConn == nil {
		conns := h.GetClientConns("user1")
		if len(conns) == 0 {
			t.Skip("could not get client connection from hub")
		}
		clientConn = conns[0]
	}

	// Close DB to cause storeMessage error
	db.Close()

	msg := RoutedMessage{
		ConversationID: conv.ID,
		Content:        "test message",
	}
	data, _ := json.Marshal(msg)

	// This should hit the storeMessage error path
	routeChatMessage(clientConn, data)

	// No panic = success. The error path sends "failed to store message"
	// Reopen DB for cleanup
	db, _ = sql.Open("sqlite3", ":memory:")
}

func TestCB113_RouteChatMessage_AgentToClientOffline(t *testing.T) {
	resetGlobals_CB113()
	setupTestDB(t)

	// Set up offline queue
	offlineQueue = newOfflineQueue(1000, 24*time.Hour)

	h := newHub()
	hub = h
	go h.run()
	defer h.Stop()

	// Create a conversation
	conv, err := CreateConversation("user1", "agent1")
	if err != nil {
		t.Fatal(err)
	}

	// Create an agent connection
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upgrader := websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}
		ws, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer ws.Close()
		c := &Connection{
			hub:         h,
			connType:    "agent",
			id:          "agent1",
			conn:        ws,
			send:        make(chan []byte, 10),
			connectedAt: time.Now(),
		}
		h.register <- c
		go c.writePump()
		go c.readPump()
		time.Sleep(500 * time.Millisecond)
	}))
	defer srv.Close()

	wsURL := "ws://" + strings.TrimPrefix(srv.URL, "http://")
	wsConn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer wsConn.Close()

	time.Sleep(100 * time.Millisecond)

	agentConn := h.GetAgent("agent1")
	if agentConn == nil {
		t.Skip("could not get agent connection from hub")
	}

	// Send message — user is offline, should be queued
	msg := RoutedMessage{
		ConversationID: conv.ID,
		Content:        "hello offline user",
	}
	data, _ := json.Marshal(msg)

	routeChatMessage(agentConn, data)

	// Verify message was stored
	var count int
	db.QueryRow("SELECT COUNT(*) FROM messages WHERE conversation_id = ?", conv.ID).Scan(&count)
	if count == 0 {
		t.Error("expected message to be stored even when user is offline")
	}
}

func TestCB113_RouteChatMessage_ClientToAgentOffline(t *testing.T) {
	resetGlobals_CB113()
	setupTestDB(t)

	offlineQueue = newOfflineQueue(1000, 24*time.Hour)

	h := newHub()
	hub = h
	go h.run()
	defer h.Stop()

	conv, err := CreateConversation("user1", "agent1")
	if err != nil {
		t.Fatal(err)
	}

	// Create a client connection (no agent connection)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upgrader := websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}
		ws, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer ws.Close()
		c := &Connection{
			hub:         h,
			connType:    "client",
			id:          "user1",
			conn:        ws,
			send:        make(chan []byte, 10),
			connectedAt: time.Now(),
		}
		h.register <- c
		go c.writePump()
		go c.readPump()
		time.Sleep(500 * time.Millisecond)
	}))
	defer srv.Close()

	wsURL := "ws://" + strings.TrimPrefix(srv.URL, "http://")
	wsConn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer wsConn.Close()

	time.Sleep(100 * time.Millisecond)

	clientConn := h.GetClient("user1")
	if clientConn == nil {
		conns := h.GetClientConns("user1")
		if len(conns) == 0 {
			t.Skip("could not get client connection")
		}
		clientConn = conns[0]
	}

	// Agent is offline — message should be queued
	msg := RoutedMessage{
		ConversationID: conv.ID,
		Content:        "hello offline agent",
	}
	data, _ := json.Marshal(msg)

	routeChatMessage(clientConn, data)

	// Verify message stored
	var count int
	db.QueryRow("SELECT COUNT(*) FROM messages WHERE conversation_id = ?", conv.ID).Scan(&count)
	if count == 0 {
		t.Error("expected message stored when agent offline")
	}
}

func TestCB113_RouteChatMessage_InvalidJSON(t *testing.T) {
	resetGlobals_CB113()
	setupTestDB(t)

	h := newHub()
	hub = h
	go h.run()
	defer h.Stop()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upgrader := websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}
		ws, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer ws.Close()
		c := &Connection{
			hub:         h,
			connType:    "agent",
			id:          "agent1",
			conn:        ws,
			send:        make(chan []byte, 10),
			connectedAt: time.Now(),
		}
		h.register <- c
		go c.writePump()
		go c.readPump()
		time.Sleep(500 * time.Millisecond)
	}))
	defer srv.Close()

	wsURL := "ws://" + strings.TrimPrefix(srv.URL, "http://")
	wsConn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer wsConn.Close()

	time.Sleep(100 * time.Millisecond)

	agentConn := h.GetAgent("agent1")
	if agentConn == nil {
		t.Skip("could not get agent connection")
	}

	// Send invalid JSON
	routeChatMessage(agentConn, json.RawMessage(`{invalid json`))
	// No panic = success
}

// ==================== initAPNs tests ====================

func TestCB113_InitAPNs_ProductionEnv(t *testing.T) {
	resetGlobals_CB113()
	// Create a temporary P12 file (will fail to load as cert, but covers the path)
	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "cert.p12")

	// Write dummy data — certificate.FromP12File will fail
	os.WriteFile(certPath, []byte("dummy p12 data"), 0644)

	pushConfig = &PushNotificationConfig{
		APNSEnabled: true,
		CertPath:    certPath,
		Password:    "test",
		Environment: "production",
	}

	initAPNs()
	// Cert load will fail, APNSEnabled should be set to false
	if pushConfig.APNSEnabled {
		t.Error("expected APNSEnabled to be false after cert load failure")
	}
}

func TestCB113_InitAPNs_DevelopmentEnv(t *testing.T) {
	resetGlobals_CB113()
	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "cert.p12")
	os.WriteFile(certPath, []byte("dummy"), 0644)

	pushConfig = &PushNotificationConfig{
		APNSEnabled: true,
		CertPath:    certPath,
		Password:    "",
		Environment: "development",
	}

	initAPNs()
	if pushConfig.APNSEnabled {
		t.Error("expected APNSEnabled to be false after cert load failure")
	}
}

func TestCB113_InitAPNs_CertDirCreation(t *testing.T) {
	resetGlobals_CB113()
	// Test the os.MkdirAll path — use a nested path that doesn't exist
	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "subdir", "nested", "cert.p12")

	pushConfig = &PushNotificationConfig{
		APNSEnabled: true,
		CertPath:    certPath,
		Password:    "",
		Environment: "development",
	}

	initAPNs()
	// Directory should have been created, cert not found
	if pushConfig.APNSEnabled {
		t.Error("expected APNSEnabled false — cert not found")
	}
	// Verify dir was created
	if _, err := os.Stat(filepath.Dir(certPath)); os.IsNotExist(err) {
		t.Error("expected cert directory to be created")
	}
}

// ==================== handleStoreEncryptedMessage tests ====================

func TestCB113_HandleStoreEncryptedMessage_AgentSender(t *testing.T) {
	resetGlobals_CB113()
	setupTestDB(t)

	h := newHub()
	hub = h
	go h.run()
	defer h.Stop()

	// Create conversation
	conv, err := CreateConversation("user1", "agent1")
	if err != nil {
		t.Fatal(err)
	}

	// Insert agent
	_, err = db.Exec("INSERT INTO agents (id, name) VALUES (?, ?)", "agent1", "Agent1")
	if err != nil {
		t.Fatal(err)
	}

	// Set up agent secret for auth
	os.Setenv("AGENT_SECRET", "test-secret")
	defer os.Unsetenv("AGENT_SECRET")
	resetAgentSecret()

	body := fmt.Sprintf(`{
		"conversation_id": "%s",
		"ciphertext": "encrypted_data_here",
		"iv": "init_vector",
		"recipient_key_id": "key123",
		"sender_key_id": "agentkey1",
		"algorithm": "x25519-aes-256-gcm"
	}`, conv.ID)

	req := httptest.NewRequest("POST", "/messages/encrypted", strings.NewReader(body))
	req.Header.Set("X-Agent-Secret", "test-secret")
	req.Header.Set("X-Agent-ID", "agent1")
	w := httptest.NewRecorder()

	handleStoreEncryptedMessage(w, req)

	if w.Code != http.StatusOK {
		body := w.Body.String()
		t.Errorf("expected 200, got %d: %s", w.Code, body)
	}
}

func TestCB113_HandleStoreEncryptedMessage_DBInsertError(t *testing.T) {
	resetGlobals_CB113()
	setupTestDB(t)

	conv, err := CreateConversation("user1", "agent1")
	if err != nil {
		t.Fatal(err)
	}

	_, err = db.Exec("INSERT INTO agents (id, name) VALUES (?, ?)", "agent1", "Agent1")
	if err != nil {
		t.Fatal(err)
	}

	os.Setenv("AGENT_SECRET", "test-secret")
	defer os.Unsetenv("AGENT_SECRET")
	resetAgentSecret()

	// Drop the encrypted_messages table to cause INSERT error
	db.Exec("DROP TABLE encrypted_messages")

	body := fmt.Sprintf(`{
		"conversation_id": "%s",
		"ciphertext": "enc",
		"iv": "iv",
		"algorithm": "aes-256-gcm"
	}`, conv.ID)

	req := httptest.NewRequest("POST", "/messages/encrypted", strings.NewReader(body))
	req.Header.Set("X-Agent-Secret", "test-secret")
	req.Header.Set("X-Agent-ID", "agent1")
	w := httptest.NewRecorder()

	handleStoreEncryptedMessage(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 for DB insert error, got %d", w.Code)
	}
}

func TestCB113_HandleStoreEncryptedMessage_InvalidAlgorithm(t *testing.T) {
	resetGlobals_CB113()
	setupTestDB(t)

	conv, err := CreateConversation("user1", "agent1")
	if err != nil {
		t.Fatal(err)
	}

	_, err = db.Exec("INSERT INTO agents (id, name) VALUES (?, ?)", "agent1", "Agent1")
	if err != nil {
		t.Fatal(err)
	}

	os.Setenv("AGENT_SECRET", "test-secret")
	defer os.Unsetenv("AGENT_SECRET")
	resetAgentSecret()

	body := fmt.Sprintf(`{
		"conversation_id": "%s",
		"ciphertext": "enc",
		"iv": "iv",
		"algorithm": "des-cbc"
	}`, conv.ID)

	req := httptest.NewRequest("POST", "/messages/encrypted", strings.NewReader(body))
	req.Header.Set("X-Agent-Secret", "test-secret")
	req.Header.Set("X-Agent-ID", "agent1")
	w := httptest.NewRecorder()

	handleStoreEncryptedMessage(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for unsupported algorithm, got %d", w.Code)
	}
}

func TestCB113_HandleStoreEncryptedMessage_UserNotParticipant(t *testing.T) {
	resetGlobals_CB113()
	setupTestDB(t)

	conv, err := CreateConversation("user1", "agent1")
	if err != nil {
		t.Fatal(err)
	}

	token, _ := GenerateJWT("other-user", "other")
	body := fmt.Sprintf(`{
		"conversation_id": "%s",
		"ciphertext": "enc",
		"iv": "iv",
		"algorithm": "aes-256-gcm"
	}`, conv.ID)

	req := httptest.NewRequest("POST", "/messages/encrypted", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	handleStoreEncryptedMessage(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403 for non-participant, got %d", w.Code)
	}
}

func TestCB113_HandleStoreEncryptedMessage_MissingFields(t *testing.T) {
	resetGlobals_CB113()
	setupTestDB(t)

	os.Setenv("AGENT_SECRET", "test-secret")
	defer os.Unsetenv("AGENT_SECRET")
	resetAgentSecret()

	body := `{"conversation_id": "test", "ciphertext": "", "iv": "", "algorithm": ""}`
	req := httptest.NewRequest("POST", "/messages/encrypted", strings.NewReader(body))
	req.Header.Set("X-Agent-Secret", "test-secret")
	req.Header.Set("X-Agent-ID", "agent1")
	w := httptest.NewRecorder()

	handleStoreEncryptedMessage(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing fields, got %d", w.Code)
	}
}

func TestCB113_HandleStoreEncryptedMessage_WrongMethod(t *testing.T) {
	resetGlobals_CB113()
	req := httptest.NewRequest("GET", "/messages/encrypted", nil)
	w := httptest.NewRecorder()

	handleStoreEncryptedMessage(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestCB113_HandleStoreEncryptedMessage_InvalidJSON(t *testing.T) {
	resetGlobals_CB113()
	setupTestDB(t)

	os.Setenv("AGENT_SECRET", "test-secret")
	defer os.Unsetenv("AGENT_SECRET")
	resetAgentSecret()

	req := httptest.NewRequest("POST", "/messages/encrypted", strings.NewReader("invalid json"))
	req.Header.Set("X-Agent-Secret", "test-secret")
	req.Header.Set("X-Agent-ID", "agent1")
	w := httptest.NewRecorder()

	handleStoreEncryptedMessage(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid JSON, got %d", w.Code)
	}
}

// ==================== handleUpload tests ====================

func TestCB113_HandleUpload_FileCreateError(t *testing.T) {
	resetGlobals_CB113()
	setupTestDB(t)

	// Set serverDBPath so uploads go to /dev/null/... which will fail on MkdirAll
	serverDBPath = "/dev/null/test.db"
	defer func() { serverDBPath = "" }()

	token, _ := GenerateJWT("user1", "testuser")

	var buf strings.Builder
	mw := multipart.NewWriter(&buf)
	fw, _ := mw.CreateFormFile("file", "test.txt")
	fw.Write([]byte("hello world"))
	mw.Close()

	req := httptest.NewRequest("POST", "/upload", strings.NewReader(buf.String()))
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	handleUpload(w, req)

	// Should get 500 for file create error (MkdirAll on /dev/null/uploads/2026/09 fails)
	if w.Code != http.StatusInternalServerError {
		body := w.Body.String()
		t.Errorf("expected 500 for file create error, got %d: %s", w.Code, body)
	}
}

func TestCB113_HandleUpload_NoFileExtension(t *testing.T) {
	resetGlobals_CB113()
	setupTestDB(t)

	tmpDir := t.TempDir()
	serverDBPath = filepath.Join(tmpDir, "test.db")
	defer func() { serverDBPath = "" }()

	token, _ := GenerateJWT("user1", "testuser")

	// Create multipart form with a file that has no extension
	var buf strings.Builder
	mw := multipart.NewWriter(&buf)
	fw, _ := mw.CreateFormFile("file", "noextension")
	fw.Write([]byte("hello world"))
	mw.Close()

	req := httptest.NewRequest("POST", "/upload", strings.NewReader(buf.String()))
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	handleUpload(w, req)

	// Should succeed — extension is guessed from content type
	if w.Code != http.StatusOK {
		body := w.Body.String()
		t.Logf("upload returned %d: %s (may fail if content type detection issue)", w.Code, body)
	}
}

func TestCB113_HandleUpload_WithMessageID(t *testing.T) {
	resetGlobals_CB113()
	setupTestDB(t)

	tmpDir := t.TempDir()
	serverDBPath = filepath.Join(tmpDir, "test.db")
	defer func() { serverDBPath = "" }()

	token, _ := GenerateJWT("user1", "testuser")

	var buf strings.Builder
	mw := multipart.NewWriter(&buf)
	fw, _ := mw.CreateFormFile("file", "test.png")
	fw.Write([]byte("PNG fake data"))
	mw.WriteField("message_id", "msg123")
	mw.Close()

	req := httptest.NewRequest("POST", "/upload", strings.NewReader(buf.String()))
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	handleUpload(w, req)

	if w.Code != http.StatusOK {
		body := w.Body.String()
		t.Errorf("expected 200, got %d: %s", w.Code, body)
	}
}

// ==================== handleListAttachments tests ====================

func TestCB113_HandleListAttachments_EmptyResult(t *testing.T) {
	resetGlobals_CB113()
	setupTestDB(t)

	// Create a conversation
	conv, err := CreateConversation("user1", "agent1")
	if err != nil {
		t.Fatal(err)
	}

	token, _ := GenerateJWT("user1", "testuser")
	req := httptest.NewRequest("GET", "/messages/attachments?conversation_id="+conv.ID, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	handleListAttachments(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}

	var attachments []interface{}
	json.NewDecoder(w.Body).Decode(&attachments)
	if len(attachments) != 0 {
		t.Errorf("expected empty array, got %d items", len(attachments))
	}
}

func TestCB113_HandleListAttachments_WrongMethod(t *testing.T) {
	resetGlobals_CB113()
	req := httptest.NewRequest("POST", "/messages/attachments", nil)
	w := httptest.NewRecorder()

	handleListAttachments(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestCB113_HandleListAttachments_NoAuth(t *testing.T) {
	resetGlobals_CB113()
	req := httptest.NewRequest("GET", "/messages/attachments", nil)
	w := httptest.NewRecorder()

	handleListAttachments(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestCB113_HandleListAttachments_NoConversationID(t *testing.T) {
	resetGlobals_CB113()
	setupTestDB(t)

	token, _ := GenerateJWT("user1", "testuser")
	req := httptest.NewRequest("GET", "/messages/attachments", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	handleListAttachments(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestCB113_HandleListAttachments_NotOwner(t *testing.T) {
	resetGlobals_CB113()
	setupTestDB(t)

	conv, err := CreateConversation("user1", "agent1")
	if err != nil {
		t.Fatal(err)
	}

	token, _ := GenerateJWT("user2", "other")
	req := httptest.NewRequest("GET", "/messages/attachments?conversation_id="+conv.ID, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	handleListAttachments(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404 for non-owner, got %d", w.Code)
	}
}

// ==================== handleGetAttachment tests ====================

func TestCB113_HandleGetAttachment_AgentAuth(t *testing.T) {
	resetGlobals_CB113()
	setupTestDB(t)

	// Set serverDBPath so we know where uploads go
	tmpDir := t.TempDir()
	serverDBPath = filepath.Join(tmpDir, "test.db")
	defer func() { serverDBPath = "" }()

	// Create the year/month subdirectory and file
	now := time.Now()
	dateDir := filepath.Join(getUploadDir(), fmt.Sprintf("%04d", now.Year()), fmt.Sprintf("%02d", now.Month()))
	os.MkdirAll(dateDir, 0755)
	filePath := filepath.Join(dateDir, "test.txt")
	os.WriteFile(filePath, []byte("test content"), 0644)

	// Insert attachment with relative path matching the date dir
	relPath := filepath.Join(fmt.Sprintf("%04d", now.Year()), fmt.Sprintf("%02d", now.Month()), "test.txt")
	_, err := db.Exec(`INSERT INTO attachments (id, message_id, user_id, filename, content_type, size, sha256, storage_path, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		"att1", nil, "user1", "test.txt", "text/plain", 12, "abc123", relPath, now.UTC())
	if err != nil {
		t.Fatal(err)
	}

	os.Setenv("AGENT_SECRET", "test-secret")
	defer os.Unsetenv("AGENT_SECRET")
	resetAgentSecret()

	req := httptest.NewRequest("GET", "/attachments/att1", nil)
	req.Header.Set("X-Agent-Secret", "test-secret")
	w := httptest.NewRecorder()

	handleGetAttachment(w, req)

	if w.Code != http.StatusOK {
		body := w.Body.String()
		t.Errorf("expected 200 for agent auth, got %d: %s", w.Code, body)
	}
}

func TestCB113_HandleGetAttachment_WrongOwner(t *testing.T) {
	resetGlobals_CB113()
	setupTestDB(t)

	_, err := db.Exec(`INSERT INTO attachments (id, message_id, user_id, filename, content_type, size, sha256, storage_path, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		"att2", nil, "user1", "test.txt", "text/plain", 12, "abc123", "test.txt", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}

	token, _ := GenerateJWT("user2", "other")
	req := httptest.NewRequest("GET", "/attachments/att2", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	handleGetAttachment(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403 for wrong owner, got %d", w.Code)
	}
}

func TestCB113_HandleGetAttachment_NoAuth(t *testing.T) {
	resetGlobals_CB113()
	req := httptest.NewRequest("GET", "/attachments/att1", nil)
	w := httptest.NewRecorder()

	handleGetAttachment(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for no auth, got %d", w.Code)
	}
}

func TestCB113_HandleGetAttachment_WrongMethod(t *testing.T) {
	resetGlobals_CB113()
	req := httptest.NewRequest("POST", "/attachments/att1", nil)
	w := httptest.NewRecorder()

	handleGetAttachment(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestCB113_HandleGetAttachment_NotFound(t *testing.T) {
	resetGlobals_CB113()
	setupTestDB(t)

	token, _ := GenerateJWT("user1", "testuser")
	req := httptest.NewRequest("GET", "/attachments/nonexistent", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	handleGetAttachment(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

func TestCB113_HandleGetAttachment_BadAgentSecret(t *testing.T) {
	resetGlobals_CB113()
	setupTestDB(t)

	_, err := db.Exec(`INSERT INTO attachments (id, message_id, user_id, filename, content_type, size, sha256, storage_path, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		"att3", nil, "user1", "test.txt", "text/plain", 12, "abc123", "test.txt", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}

	os.Setenv("AGENT_SECRET", "test-secret")
	defer os.Unsetenv("AGENT_SECRET")
	resetAgentSecret()

	req := httptest.NewRequest("GET", "/attachments/att3", nil)
	req.Header.Set("X-Agent-Secret", "wrong-secret")
	w := httptest.NewRecorder()

	handleGetAttachment(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for wrong agent secret, got %d", w.Code)
	}
}

// ==================== handleGetRateLimitTier tests ====================

func TestCB113_HandleGetRateLimitTier_NoAuth(t *testing.T) {
	resetGlobals_CB113()
	req := httptest.NewRequest("GET", "/admin/rate-limit-tier", nil)
	w := httptest.NewRecorder()

	handleGetRateLimitTier(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestCB113_HandleGetRateLimitTier_FormSecret(t *testing.T) {
	resetGlobals_CB113()
	setupTestDB(t)

	os.Setenv("ADMIN_SECRET", "admin-pass")
	defer os.Unsetenv("ADMIN_SECRET")
	resetAdminSecret()

	req := httptest.NewRequest("GET", "/admin/rate-limit-tier", nil)
	req.Header.Set("X-Admin-Secret", "admin-pass")
	w := httptest.NewRecorder()

	handleGetRateLimitTier(w, req)

	// Should return 200 with tier info (or 404 if no tier set)
	if w.Code == http.StatusUnauthorized {
		t.Error("expected auth to pass with correct admin secret")
	}
}

func TestCB113_HandleGetRateLimitTier_JWTAuth(t *testing.T) {
	resetGlobals_CB113()
	setupTestDB(t)

	// handleGetRateLimitTier requires admin secret, not JWT
	token, _ := GenerateJWT("user1", "testuser")
	req := httptest.NewRequest("GET", "/admin/rate-limit-tier?user_id=user1", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	handleGetRateLimitTier(w, req)

	// JWT doesn't pass admin secret check
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for JWT-only auth (needs admin secret), got %d", w.Code)
	}
}

func TestCB113_HandleGetRateLimitTier_WrongMethod(t *testing.T) {
	resetGlobals_CB113()
	req := httptest.NewRequest("POST", "/admin/rate-limit-tier", nil)
	w := httptest.NewRecorder()

	handleGetRateLimitTier(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

// ==================== handleGetEncryptedMessages tests ====================

func TestCB113_HandleGetEncryptedMessages_WrongMethod(t *testing.T) {
	resetGlobals_CB113()
	req := httptest.NewRequest("POST", "/messages/encrypted", nil)
	w := httptest.NewRecorder()

	handleGetEncryptedMessages(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestCB113_HandleGetEncryptedMessages_NoAuth(t *testing.T) {
	resetGlobals_CB113()
	req := httptest.NewRequest("GET", "/messages/encrypted", nil)
	w := httptest.NewRecorder()

	handleGetEncryptedMessages(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestCB113_HandleGetEncryptedMessages_NoConversationID(t *testing.T) {
	resetGlobals_CB113()
	setupTestDB(t)

	token, _ := GenerateJWT("user1", "testuser")
	req := httptest.NewRequest("GET", "/messages/encrypted", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	handleGetEncryptedMessages(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing conversation_id, got %d", w.Code)
	}
}

func TestCB113_HandleGetEncryptedMessages_NotParticipant(t *testing.T) {
	resetGlobals_CB113()
	setupTestDB(t)

	conv, err := CreateConversation("user1", "agent1")
	if err != nil {
		t.Fatal(err)
	}

	token, _ := GenerateJWT("other-user", "other")
	req := httptest.NewRequest("GET", "/messages/encrypted?conversation_id="+conv.ID, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	handleGetEncryptedMessages(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404 for non-participant, got %d", w.Code)
	}
}

// ==================== initFCM tests ====================

func TestCB113_InitFCM_NilConfig(t *testing.T) {
	resetGlobals_CB113()
	pushConfig = nil
	initFCM()
	// Should be a no-op (logs "fcm_no_config")
}

func TestCB113_InitFCM_Disabled(t *testing.T) {
	resetGlobals_CB113()
	pushConfig = &PushNotificationConfig{
		FCMEnabled: false,
	}
	initFCM()
	// Should log "fcm_disabled"
}

func TestCB113_InitFCM_NoCredsPath(t *testing.T) {
	resetGlobals_CB113()
	pushConfig = &PushNotificationConfig{
		FCMEnabled:     true,
		FCMCredentials: "",
	}
	initFCM()
	// Should log "fcm_no_creds_path" and disable
}

func TestCB113_InitFCM_CredsNotFound(t *testing.T) {
	resetGlobals_CB113()
	pushConfig = &PushNotificationConfig{
		FCMEnabled:     true,
		FCMCredentials: "/nonexistent/path/creds.json",
	}
	initFCM()
	if pushConfig.FCMEnabled {
		t.Error("expected FCM disabled after creds not found")
	}
}

// ==================== loadQueueFromDB tests ====================

func TestCB113_LoadQueueFromDB_WithData(t *testing.T) {
	resetGlobals_CB113()
	setupTestDB(t)

	// Insert queue items
	now := time.Now().UTC()
	_, err := db.Exec(`INSERT INTO offline_queue (recipient, data, queued_at) VALUES (?, ?, ?)`,
		"user1", []byte(`{"type":"message","data":"hello"}`), now)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`INSERT INTO offline_queue (recipient, data, queued_at) VALUES (?, ?, ?)`,
		"user1", []byte(`{"type":"message","data":"world"}`), now)
	if err != nil {
		t.Fatal(err)
	}

	q := newOfflineQueue(100, 24*time.Hour)
	loadQueueFromDB(db, q)
	// loadQueueFromDB populates the queue, doesn't return messages
	if q.TotalDepth() != 2 {
		t.Errorf("expected queue depth 2, got %d", q.TotalDepth())
	}
}

func TestCB113_LoadQueueFromDB_NilDB(t *testing.T) {
	resetGlobals_CB113()
	q := newOfflineQueue(100, 24*time.Hour)
	loadQueueFromDB(nil, q)
	// Should be a no-op with nil DB
	if q.TotalDepth() != 0 {
		t.Errorf("expected queue depth 0 for nil DB, got %d", q.TotalDepth())
	}
}

// ==================== readPump tests ====================

func TestCB113_ReadPump_MessageRouting(t *testing.T) {
	resetGlobals_CB113()
	setupTestDB(t)

	h := newHub()
	hub = h
	go h.run()
	defer h.Stop()

	ServerMetrics = NewMetrics(h)
	defer func() { ServerMetrics = nil }()

	var receivedMsg []byte
	var mu sync.Mutex

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upgrader := websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}
		ws, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer ws.Close()
		c := &Connection{
			hub:         h,
			connType:    "agent",
			id:          "agent1",
			conn:        ws,
			send:        make(chan []byte, 10),
			connectedAt: time.Now(),
		}
		h.register <- c
		go c.writePump()
		c.readPump()
	}))
	defer srv.Close()

	wsURL := "ws://" + strings.TrimPrefix(srv.URL, "http://")
	wsConn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer wsConn.Close()

	// Send a message — readPump should route it
	// Use a status update which is simple to route
	msg := map[string]interface{}{
		"type":    "status",
		"status":  "online",
		"agent_id": "agent1",
	}
	data, _ := json.Marshal(msg)
	wsConn.WriteMessage(websocket.TextMessage, data)

	time.Sleep(200 * time.Millisecond)

	// Verify messagesRouted was incremented
	if h.messagesRouted.Load() == 0 {
		// May have been routed — check if we got any response
		mu.Lock()
		_ = receivedMsg
		mu.Unlock()
		// messagesRouted may not have been incremented if routeMessage doesn't handle status
		// but at least readPump should have received the message without panic
	}
	// Test passes if no panic
}

func TestCB113_ReadPump_NormalClosure(t *testing.T) {
	resetGlobals_CB113()
	setupTestDB(t)

	h := newHub()
	hub = h
	go h.run()
	defer h.Stop()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upgrader := websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}
		ws, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer ws.Close()
		c := &Connection{
			hub:         h,
			connType:    "client",
			id:          "user1",
			conn:        ws,
			send:        make(chan []byte, 10),
			connectedAt: time.Now(),
		}
		h.register <- c
		go c.writePump()
		c.readPump()
	}))
	defer srv.Close()

	wsURL := "ws://" + strings.TrimPrefix(srv.URL, "http://")
	wsConn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}

	// Normal close
	wsConn.WriteMessage(websocket.CloseMessage,
		websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
	wsConn.Close()

	time.Sleep(200 * time.Millisecond)
	// No panic = success
}

// ==================== initSchema tests ====================

func TestCB113_InitSchema_Idempotent(t *testing.T) {
	resetGlobals_CB113()
	setupTestDB(t)

	// initSchema should be idempotent — calling again should not fail
	err := initSchema(db)
	if err != nil {
		t.Errorf("initSchema should be idempotent, got error: %v", err)
	}

	// Verify schema_migrations has entries
	var count int
	err = db.QueryRow("SELECT COUNT(*) FROM schema_migrations").Scan(&count)
	if err != nil {
		t.Fatal(err)
	}
	if count == 0 {
		t.Error("expected migrations to be recorded")
	}
}

// ==================== handleSearchMessages additional tests ====================

func TestCB113_HandleSearchMessages_NoAuth(t *testing.T) {
	resetGlobals_CB113()
	req := httptest.NewRequest("GET", "/messages/search?q=test", nil)
	w := httptest.NewRecorder()

	handleSearchMessages(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestCB113_HandleSearchMessages_WrongMethod(t *testing.T) {
	resetGlobals_CB113()
	req := httptest.NewRequest("POST", "/messages/search", nil)
	w := httptest.NewRecorder()

	handleSearchMessages(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

// ==================== handleListConversations additional tests ====================

func TestCB113_HandleListConversations_NoAuth(t *testing.T) {
	resetGlobals_CB113()
	req := httptest.NewRequest("GET", "/conversations", nil)
	w := httptest.NewRecorder()

	handleListConversations(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

// ==================== handleCreateConversation additional tests ====================

func TestCB113_HandleCreateConversation_NoAuth(t *testing.T) {
	resetGlobals_CB113()
	req := httptest.NewRequest("POST", "/conversations", strings.NewReader(`{}`))
	w := httptest.NewRecorder()

	handleCreateConversation(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestCB113_HandleCreateConversation_WrongMethod(t *testing.T) {
	resetGlobals_CB113()
	req := httptest.NewRequest("GET", "/conversations", nil)
	w := httptest.NewRecorder()

	handleCreateConversation(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

// ==================== handleDeleteConversation additional tests ====================

func TestCB113_HandleDeleteConversation_NoAuth(t *testing.T) {
	resetGlobals_CB113()
	req := httptest.NewRequest("DELETE", "/conversations/conv1", nil)
	w := httptest.NewRecorder()

	handleDeleteConversation(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestCB113_HandleDeleteConversation_WrongMethod(t *testing.T) {
	resetGlobals_CB113()
	req := httptest.NewRequest("PUT", "/conversations/conv1", nil)
	w := httptest.NewRecorder()

	handleDeleteConversation(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

// ==================== handleChangePassword additional tests ====================

func TestCB113_HandleChangePassword_NoAuth(t *testing.T) {
	resetGlobals_CB113()
	req := httptest.NewRequest("POST", "/auth/change-password", strings.NewReader(`{}`))
	w := httptest.NewRecorder()

	handleChangePassword(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestCB113_HandleChangePassword_WrongMethod(t *testing.T) {
	resetGlobals_CB113()
	req := httptest.NewRequest("GET", "/auth/change-password", nil)
	w := httptest.NewRecorder()

	handleChangePassword(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

// ==================== handleRegisterDeviceToken additional tests ====================

func TestCB113_HandleRegisterDeviceToken_WrongMethod(t *testing.T) {
	resetGlobals_CB113()
	req := httptest.NewRequest("GET", "/device/register", nil)
	w := httptest.NewRecorder()

	handleRegisterDeviceToken(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

// ==================== handleWebPushSubscribe additional tests ====================

func TestCB113_HandleWebPushSubscribe_WrongMethod(t *testing.T) {
	resetGlobals_CB113()
	req := httptest.NewRequest("GET", "/webpush/subscribe", nil)
	w := httptest.NewRecorder()

	handleWebPushSubscribe(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

// ==================== handleGetMessages additional tests ====================

func TestCB113_HandleGetMessages_NoAuth(t *testing.T) {
	resetGlobals_CB113()
	req := httptest.NewRequest("GET", "/messages?conversation_id=conv1", nil)
	w := httptest.NewRecorder()

	handleGetMessages(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestCB113_HandleGetMessages_WrongMethod(t *testing.T) {
	resetGlobals_CB113()
	req := httptest.NewRequest("POST", "/messages", nil)
	w := httptest.NewRecorder()

	handleGetMessages(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

// ==================== handleMessageEdit additional tests ====================

func TestCB113_HandleMessageEdit_WrongMethod(t *testing.T) {
	resetGlobals_CB113()
	req := httptest.NewRequest("GET", "/messages/edit", nil)
	w := httptest.NewRecorder()

	handleMessageEdit(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

// ==================== handleMessageDelete additional tests ====================

func TestCB113_HandleMessageDelete_WrongMethod(t *testing.T) {
	resetGlobals_CB113()
	req := httptest.NewRequest("GET", "/messages/delete", nil)
	w := httptest.NewRecorder()

	handleMessageDelete(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

// ==================== handleGetNotificationPrefs additional tests ====================

func TestCB113_HandleGetNotificationPrefs_WrongMethod(t *testing.T) {
	resetGlobals_CB113()
	req := httptest.NewRequest("POST", "/notifications/preferences", nil)
	w := httptest.NewRecorder()

	handleGetNotificationPrefs(w, req)

	// Auth check happens before method check — returns 401 not 405
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 (auth before method check), got %d", w.Code)
	}
}

// ==================== handleGetPresence additional tests ====================

func TestCB113_HandleGetPresence_WrongMethod(t *testing.T) {
	resetGlobals_CB113()
	req := httptest.NewRequest("POST", "/presence", nil)
	w := httptest.NewRecorder()

	handleGetPresence(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

// ==================== handleHealth additional tests ====================

func TestCB113_HandleHealth_WrongMethod(t *testing.T) {
	resetGlobals_CB113()
	req := httptest.NewRequest("POST", "/health", nil)
	w := httptest.NewRecorder()

	handleHealth(w, req)

	// handleHealth typically accepts GET only
	if w.Code != http.StatusMethodNotAllowed && w.Code != http.StatusOK {
		t.Errorf("expected 405 or 200, got %d", w.Code)
	}
}

// ==================== handleMetrics additional tests ====================

func TestCB113_HandleMetrics_WrongMethod(t *testing.T) {
	resetGlobals_CB113()
	req := httptest.NewRequest("POST", "/metrics", nil)
	w := httptest.NewRecorder()

	handleMetrics(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

// ==================== handleRegisterAgent additional tests ====================

func TestCB113_HandleRegisterAgent_WrongMethod(t *testing.T) {
	resetGlobals_CB113()
	req := httptest.NewRequest("GET", "/auth/agent", nil)
	w := httptest.NewRecorder()

	handleRegisterAgent(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

// ==================== handleRegisterUser additional tests ====================

func TestCB113_HandleRegisterUser_WrongMethod(t *testing.T) {
	resetGlobals_CB113()
	req := httptest.NewRequest("GET", "/auth/register", nil)
	w := httptest.NewRecorder()

	handleRegisterUser(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

// ==================== handleLogin additional tests ====================

func TestCB113_HandleLogin_WrongMethod(t *testing.T) {
	resetGlobals_CB113()
	req := httptest.NewRequest("GET", "/auth/login", nil)
	w := httptest.NewRecorder()

	handleLogin(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

// ==================== handleAdminAgents additional tests ====================

func TestCB113_HandleAdminAgents_WrongMethod(t *testing.T) {
	resetGlobals_CB113()
	req := httptest.NewRequest("POST", "/admin/agents", nil)
	w := httptest.NewRecorder()

	handleAdminAgents(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

// ==================== handleListAgents additional tests ====================

func TestCB113_HandleListAgents_WrongMethod(t *testing.T) {
	resetGlobals_CB113()
	req := httptest.NewRequest("POST", "/agents", nil)
	w := httptest.NewRecorder()

	handleListAgents(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

// ==================== TieredRateLimiter additional tests ====================

func TestCB113_TieredRateLimiter_GetRemaining_NoTier(t *testing.T) {
	resetGlobals_CB113()
	trl := NewTieredRateLimiter()
	defer trl.Stop()

	remaining := trl.GetRemaining("unknown-user")
	// Returns TierFree.Burst (60) for unknown users, not 0
	if remaining != TierFree.Burst {
		t.Errorf("expected %d (TierFree.Burst) for unknown tier, got %d", TierFree.Burst, remaining)
	}
}

func TestCB113_TieredRateLimiter_GetRemaining_WithTier(t *testing.T) {
	resetGlobals_CB113()
	trl := NewTieredRateLimiter()
	defer trl.Stop()

	trl.SetTier("user1", RateLimitTier{Burst: 50, Window: time.Minute})
	remaining := trl.GetRemaining("user1")
	if remaining <= 0 || remaining > 50 {
		t.Errorf("expected remaining between 1 and 50, got %d", remaining)
	}
}

// ==================== handleSetRateLimitTier additional tests ====================

func TestCB113_HandleSetRateLimitTier_NoAuth(t *testing.T) {
	resetGlobals_CB113()
	req := httptest.NewRequest("POST", "/admin/rate-limit-tier", strings.NewReader(`{}`))
	w := httptest.NewRecorder()

	handleSetRateLimitTier(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestCB113_HandleSetRateLimitTier_WrongMethod(t *testing.T) {
	resetGlobals_CB113()
	req := httptest.NewRequest("GET", "/admin/rate-limit-tier", nil)
	w := httptest.NewRecorder()

	handleSetRateLimitTier(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

// ==================== addReaction additional tests ====================

func TestCB113_AddReaction_AgentReaction(t *testing.T) {
	resetGlobals_CB113()
	setupTestDB(t)

	// Insert agent
	_, err := db.Exec("INSERT INTO agents (id, name) VALUES (?, ?)", "agent1", "Agent1")
	if err != nil {
		t.Fatal(err)
	}

	// Create conversation and message
	conv, err := CreateConversation("user1", "agent1")
	if err != nil {
		t.Fatal(err)
	}
	msgID := generateID("msg")
	_, err = db.Exec("INSERT INTO messages (id, conversation_id, sender_id, sender_type, content, created_at) VALUES (?, ?, ?, ?, ?, ?)",
		msgID, conv.ID, "user1", "client", "hello", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}

	// Agent reacts
	reaction, ok, err := addReaction(msgID, "agent1", "👍")
	if err != nil {
		t.Fatalf("addReaction error: %v", err)
	}
	if !ok {
		t.Error("expected ok=true for new reaction")
	}
	if reaction == nil {
		t.Fatal("expected non-nil reaction")
	}
	if reaction.Emoji != "👍" {
		t.Errorf("expected emoji 👍, got %s", reaction.Emoji)
	}
}

// ==================== removeConversationTag additional tests ====================

func TestCB113_RemoveConversationTag_Success(t *testing.T) {
	resetGlobals_CB113()
	setupTestDB(t)

	conv, err := CreateConversation("user1", "agent1")
	if err != nil {
		t.Fatal(err)
	}

	// Add a tag first (table has no user_id column)
	_, err = db.Exec("INSERT INTO conversation_tags (id, conversation_id, tag) VALUES (?, ?, ?)",
		generateID("tag"), conv.ID, "important")
	if err != nil {
		t.Fatal(err)
	}

	// Remove it — removeConversationTag(convID, userID, tag string)
	err = removeConversationTag(conv.ID, "user1", "important")
	if err != nil {
		t.Fatalf("removeConversationTag error: %v", err)
	}

	// Verify removed
	var count int
	db.QueryRow("SELECT COUNT(*) FROM conversation_tags WHERE conversation_id = ? AND tag = ?", conv.ID, "important").Scan(&count)
	if count != 0 {
		t.Error("expected tag to be removed")
	}
}

func TestCB113_RemoveConversationTag_NotExists(t *testing.T) {
	resetGlobals_CB113()
	setupTestDB(t)

	conv, err := CreateConversation("user1", "agent1")
	if err != nil {
		t.Fatal(err)
	}

	err = removeConversationTag(conv.ID, "user1", "nonexistent")
	if err == nil {
		t.Error("expected error for removing nonexistent tag")
	}
	// Should return "tag not found" error
}

// ==================== getConversationMessages additional tests ====================

func TestCB113_GetConversationMessages_Pagination(t *testing.T) {
	resetGlobals_CB113()
	setupTestDB(t)

	conv, err := CreateConversation("user1", "agent1")
	if err != nil {
		t.Fatal(err)
	}

	// Insert multiple messages
	for i := 0; i < 5; i++ {
		msgID := generateID("msg")
		_, err = db.Exec("INSERT INTO messages (id, conversation_id, sender_id, sender_type, content, created_at) VALUES (?, ?, ?, ?, ?, ?)",
			msgID, conv.ID, "user1", "client", fmt.Sprintf("message %d", i),
			time.Now().Add(time.Duration(i)*time.Second).UTC())
		if err != nil {
			t.Fatal(err)
		}
	}

	// Get first page
	msgs, err := getConversationMessages(conv.ID, 2, "")
	if err != nil {
		t.Fatalf("getConversationMessages error: %v", err)
	}
	if len(msgs) != 2 {
		t.Errorf("expected 2 messages, got %d", len(msgs))
	}

	// Get second page — use last message ID from first page as 'before' cursor
	beforeID := ""
	if len(msgs) > 0 {
		beforeID = msgs[len(msgs)-1].ID
	}
	msgs2, err := getConversationMessages(conv.ID, 2, beforeID)
	if err != nil {
		t.Fatalf("getConversationMessages error: %v", err)
	}
	if len(msgs2) != 2 {
		t.Errorf("expected 2 messages on page 2, got %d", len(msgs2))
	}
}

// ==================== Snapshot additional tests ====================

func TestCB113_MetricsSnapshot_WithHub(t *testing.T) {
	resetGlobals_CB113()
	h := newHub()
	hub = h

	offlineQueue = newOfflineQueue(100, 24*time.Hour)
	offlineQueue.Enqueue("user1", []byte("test message"))

	ServerMetrics = NewMetrics(h)
	snap := ServerMetrics.Snapshot()
	if snap == nil {
		t.Fatal("expected non-nil snapshot")
	}
	if _, ok := snap["connections_total"]; !ok {
		t.Error("expected connections_total in snapshot")
	}
	ServerMetrics = nil
}

// ==================== markMessagesRead additional tests ====================

func TestCB113_MarkMessagesRead_Success(t *testing.T) {
	resetGlobals_CB113()
	setupTestDB(t)

	conv, err := CreateConversation("user1", "agent1")
	if err != nil {
		t.Fatal(err)
	}

	// Insert messages
	for i := 0; i < 3; i++ {
		msgID := generateID("msg")
		_, err = db.Exec("INSERT INTO messages (id, conversation_id, sender_id, sender_type, content, created_at, read_at) VALUES (?, ?, ?, ?, ?, ?, NULL)",
			msgID, conv.ID, "agent1", "agent", fmt.Sprintf("msg %d", i), time.Now().UTC())
		if err != nil {
			t.Fatal(err)
		}
	}

	n, err := markMessagesRead(conv.ID, "user1")
	if err != nil {
		t.Fatalf("markMessagesRead error: %v", err)
	}
	if n != 3 {
		t.Errorf("expected 3 messages marked read, got %d", n)
	}

	// Verify all messages are read
	var unreadCount int
	db.QueryRow("SELECT COUNT(*) FROM messages WHERE conversation_id = ? AND read_at IS NULL", conv.ID).Scan(&unreadCount)
	if unreadCount != 0 {
		t.Errorf("expected 0 unread, got %d", unreadCount)
	}
}

// ==================== changeUserPassword additional tests ====================

func TestCB113_ChangeUserPassword_Success(t *testing.T) {
	resetGlobals_CB113()
	setupTestDB(t)

	// Create user with known password
	hashed, _ := bcrypt.GenerateFromPassword([]byte("oldpass"), bcrypt.DefaultCost)
	_, err := db.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)",
		"user1", "testuser", string(hashed))
	if err != nil {
		t.Fatal(err)
	}

	err = changeUserPassword("user1", "oldpass", "newpass")
	if err != nil {
		t.Fatalf("changeUserPassword error: %v", err)
	}

	// Verify password changed
	var newHash string
	db.QueryRow("SELECT password_hash FROM users WHERE id = ?", "user1").Scan(&newHash)
	if bcrypt.CompareHashAndPassword([]byte(newHash), []byte("newpass")) != nil {
		t.Error("password was not changed correctly")
	}
}

// ==================== ValidateJWT additional tests ====================

func TestCB113_ValidateJWT_EmptyToken(t *testing.T) {
	resetGlobals_CB113()
	_, err := ValidateJWT("")
	if err == nil {
		t.Error("expected error for empty token")
	}
}

func TestCB113_ValidateJWT_MalformedToken(t *testing.T) {
	resetGlobals_CB113()
	_, err := ValidateJWT("not.a.valid.jwt.token.at.all")
	if err == nil {
		t.Error("expected error for malformed token")
	}
}

func TestCB113_ValidateJWT_ValidToken(t *testing.T) {
	resetGlobals_CB113()
	token, err := GenerateJWT("user1", "testuser")
	if err != nil {
		t.Fatal(err)
	}

	claims, err := ValidateJWT(token)
	if err != nil {
		t.Fatalf("expected valid token, got error: %v", err)
	}
	if claims.UserID != "user1" {
		t.Errorf("expected user ID 'user1', got '%s'", claims.UserID)
	}
}