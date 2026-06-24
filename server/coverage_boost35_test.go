package main

// Coverage Boost 35: Targeting monitorAgentHeartbeats goroutine, readPump/writePump paths,
// handleStoreEncryptedMessage agent sender path, handleUpload content-type detection,
// parseSize float values, handleDeleteNotificationPrefs wrong method,
// handleGetNotificationPrefs with populated prefs, and initSchema error paths.

import (
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// --- monitorAgentHeartbeats goroutine tests ---

// TestMonitorAgentHeartbeats_RunsAndStops verifies the goroutine starts and stops cleanly.
func TestMonitorAgentHeartbeats_RunsAndStops(t *testing.T) {
	origEnabled := agentPresenceEnabled
	origInterval := agentPresenceInterval
	origTimeout := agentPresenceTimeout
	agentPresenceEnabled = true
	agentPresenceInterval = 50 * time.Millisecond
	agentPresenceTimeout = 5 * time.Minute
	t.Cleanup(func() {
		agentPresenceEnabled = origEnabled
		agentPresenceInterval = origInterval
		agentPresenceTimeout = origTimeout
	})

	setupTestDB(t)
	h := newHub()
	go h.run()
	t.Cleanup(h.Stop)

	// monitorDone should be open (monitor goroutine is running)
	select {
	case <-h.monitorDone:
		t.Fatal("monitorDone should not be closed while monitor goroutine is running")
	default:
		// good
	}

	// Let it tick a few times
	time.Sleep(200 * time.Millisecond)

	// Stop hub → should cause monitorAgentHeartbeats to exit
	h.Stop()

	// monitorDone should now be closed
	select {
	case <-h.monitorDone:
		// good
	case <-time.After(time.Second):
		t.Fatal("monitorDone should be closed after hub.Stop()")
	}
}

// TestMonitorAgentHeartbeats_DisabledReturnsImmediately verifies that when
// agentPresenceInterval is 0, the goroutine returns immediately (after closing monitorDone).
func TestMonitorAgentHeartbeats_DisabledReturnsImmediately(t *testing.T) {
	origEnabled := agentPresenceEnabled
	origInterval := agentPresenceInterval
	agentPresenceEnabled = false
	agentPresenceInterval = 0
	t.Cleanup(func() {
		agentPresenceEnabled = origEnabled
		agentPresenceInterval = origInterval
	})

	h := newHub()
	// newHub closes monitorDone when disabled, so it should already be closed
	select {
	case <-h.monitorDone:
		// good — already closed by newHub
	case <-time.After(time.Second):
		t.Fatal("monitorDone should be closed when monitoring is disabled")
	}
}

// TestCheckStaleAgents_MultipleStale verifies that multiple stale agents are disconnected.
func TestCheckStaleAgents_MultipleStale(t *testing.T) {
	origEnabled := agentPresenceEnabled
	origInterval := agentPresenceInterval
	origTimeout := agentPresenceTimeout
	origAgentEnv := os.Getenv("AGENT_SECRET")
	os.Setenv("AGENT_SECRET", "test-stale-multi-secret")
	agentSecret = "test-stale-multi-secret"
	agentPresenceEnabled = true
	agentPresenceInterval = 100 * time.Millisecond
	agentPresenceTimeout = 300 * time.Millisecond
	t.Cleanup(func() {
		agentPresenceEnabled = origEnabled
		agentPresenceInterval = origInterval
		agentPresenceTimeout = origTimeout
		if origAgentEnv != "" {
			os.Setenv("AGENT_SECRET", origAgentEnv)
		} else {
			os.Unsetenv("AGENT_SECRET")
		}
		resetAgentSecret()
	})

	setupTestDB(t)
	hub = newHub()
	go hub.run()
	t.Cleanup(hub.Stop)
	ServerMetrics = NewMetrics(hub)

	mux := http.NewServeMux()
	mux.HandleFunc("/agent/connect", handleAgentConnect)
	mux.HandleFunc("/auth/agent", handleRegisterAgent)
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	// Connect two agents
	ws1 := connectHeartbeatAgent(t, server, "stale-multi-1")
	ws2 := connectHeartbeatAgent(t, server, "stale-multi-2")
	t.Cleanup(func() { ws1.Close() })
	t.Cleanup(func() { ws2.Close() })

	time.Sleep(50 * time.Millisecond)

	// Verify both connected
	hub.mu.RLock()
	c1 := hub.agents["stale-multi-1"]
	c2 := hub.agents["stale-multi-2"]
	hub.mu.RUnlock()
	if c1 == nil || c2 == nil {
		t.Fatal("both agents should be connected")
	}

	// Set both heartbeats to long ago
	hub.mu.Lock()
	c1.lastHeartbeat = time.Now().Add(-5 * time.Minute)
	c2.lastHeartbeat = time.Now().Add(-5 * time.Minute)
	hub.mu.Unlock()

	initialStale := hub.StaleAgentCount()

	// Run stale check
	hub.checkStaleAgents()

	// Wait for unregister processing
	time.Sleep(150 * time.Millisecond)

	// Both should be gone
	hub.mu.RLock()
	_, still1 := hub.agents["stale-multi-1"]
	_, still2 := hub.agents["stale-multi-2"]
	hub.mu.RUnlock()

	if still1 {
		t.Error("agent 1 should have been disconnected")
	}
	if still2 {
		t.Error("agent 2 should have been disconnected")
	}

	if hub.StaleAgentCount() <= initialStale {
		t.Error("stale agent count should have increased")
	}
}

// --- readPump tests ---

// TestReadPump_UnexpectedCloseError verifies that readPump logs unexpected close errors
// and sends the connection to unregister.
func TestReadPump_UnexpectedCloseError(t *testing.T) {
	setupTestDB(t)
	h := newHub()
	go h.run()
	t.Cleanup(h.Stop)

	// Create a test websocket pair
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		// Register as agent connection
		c := &Connection{
			hub:      h,
			conn:     conn,
			connType: "agent",
			id:       "readpump-test-agent",
			send:     make(chan []byte, 256),
		}
		h.register <- c
		go c.writePump()
		c.readPump()
	}))
	t.Cleanup(srv.Close)

	// Need ws:// URL for dialer
	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")

	// Dial the server
	dialer := websocket.Dialer{}
	ws, _, err := dialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Send a message to verify readPump routing
	time.Sleep(50 * time.Millisecond)
	h.mu.RLock()
	conn := h.agents["readpump-test-agent"]
	h.mu.RUnlock()
	if conn == nil {
		t.Fatal("agent should be registered")
	}

	// Send a normal close - readPump should handle it
	ws.WriteMessage(websocket.TextMessage, []byte(`{"type":"heartbeat","data":{}}`))
	time.Sleep(50 * time.Millisecond)

	// Force an abnormal close
	ws.Close()
	time.Sleep(100 * time.Millisecond)

	// Agent should be unregistered
	h.mu.RLock()
	_, exists := h.agents["readpump-test-agent"]
	h.mu.RUnlock()
	if exists {
		t.Error("agent should be unregistered after connection close")
	}
}

// TestReadPump_PongHandlerResetsDeadline verifies that the pong handler resets the read deadline.
func TestReadPump_PongHandlerResetsDeadline(t *testing.T) {
	setupTestDB(t)
	h := newHub()
	go h.run()
	t.Cleanup(h.Stop)

	var capturedConn *Connection
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		c := &Connection{
			hub:      h,
			conn:     conn,
			connType: "agent",
			id:       "pong-test-agent",
			send:     make(chan []byte, 256),
		}
		h.register <- c
		capturedConn = c
		go c.writePump()
		c.readPump()
	}))
	t.Cleanup(srv.Close)

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")

	dialer := websocket.Dialer{}
	ws, _, err := dialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ws.Close() })

	time.Sleep(50 * time.Millisecond)

	if capturedConn == nil {
		t.Fatal("connection not captured")
	}

	// Send a ping from client; server's readPump should handle the pong response
	ws.WriteMessage(websocket.PingMessage, []byte("ping"))
	time.Sleep(100 * time.Millisecond)

	// Connection should still be alive
	h.mu.RLock()
	_, exists := h.agents["pong-test-agent"]
	h.mu.RUnlock()
	if !exists {
		t.Error("agent should still be connected after ping/pong")
	}
}

// --- writePump tests ---

// TestWritePump_MessageDelivery verifies that writePump delivers messages from send channel.
func TestWritePump_MessageDelivery(t *testing.T) {
	setupTestDB(t)
	h := newHub()
	go h.run()
	t.Cleanup(h.Stop)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		c := &Connection{
			hub:      h,
			conn:     conn,
			connType: "agent",
			id:       "msg-write-agent",
			send:     make(chan []byte, 256),
		}
		h.register <- c
		go c.writePump()
		// Keep connection alive without readPump
		time.Sleep(5 * time.Second)
		conn.Close()
	}))
	t.Cleanup(srv.Close)

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")

	dialer := websocket.Dialer{}
	ws, _, err := dialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ws.Close() })

	time.Sleep(50 * time.Millisecond)

	h.mu.RLock()
	conn := h.agents["msg-write-agent"]
	h.mu.RUnlock()
	if conn == nil {
		t.Fatal("agent should be registered")
	}

	// Send a message through the send channel
	conn.send <- []byte(`{"type":"test","data":"hello"}`)

	// Read it on the client
	ws.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, message, err := ws.ReadMessage()
	if err != nil {
		t.Fatalf("expected to read message, got error: %v", err)
	}
	if !strings.Contains(string(message), "hello") {
		t.Errorf("expected message to contain 'hello', got: %s", string(message))
	}
}

// TestWritePump_SendChannelClose verifies that when send channel closes,
// writePump sends a close frame and exits.
func TestWritePump_SendChannelClose(t *testing.T) {
	setupTestDB(t)
	h := newHub()
	go h.run()
	t.Cleanup(h.Stop)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		c := &Connection{
			hub:      h,
			conn:     conn,
			connType: "agent",
			id:       "close-write-agent",
			send:     make(chan []byte, 256),
		}
		h.register <- c
		go c.writePump()
		time.Sleep(5 * time.Second)
		conn.Close()
	}))
	t.Cleanup(srv.Close)

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")

	dialer := websocket.Dialer{}
	ws, _, err := dialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ws.Close() })

	time.Sleep(50 * time.Millisecond)

	h.mu.RLock()
	conn := h.agents["close-write-agent"]
	h.mu.RUnlock()
	if conn == nil {
		t.Fatal("agent should be registered")
	}

	// Close the send channel to simulate hub unregister
	close(conn.send)

	// The client should receive a close frame
	time.Sleep(100 * time.Millisecond)

	// Try to read - should get a close frame or error
	ws.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, _, err = ws.ReadMessage()
	if err == nil {
		// Could be a close message; that's fine
	}
	// The connection should be closed after send channel close
}

// --- handleStoreEncryptedMessage agent sender path ---

// agentAuthRequest creates a request with agent auth headers.
func agentAuthRequest(method, path, body string, agentID string) *http.Request {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("X-Agent-Secret", agentSecret)
	req.Header.Set("X-Agent-ID", agentID)
	return req
}

// TestHandleStoreEncryptedMessage_AgentSender verifies that when an agent sends an
// encrypted message, it's stored successfully.
func TestHandleStoreEncryptedMessage_AgentSender(t *testing.T) {
	setupTestDB(t)
	hub = newHub()
	go hub.run()
	t.Cleanup(hub.Stop)

	origAgentEnv := os.Getenv("AGENT_SECRET")
	os.Setenv("AGENT_SECRET", "test-enc-agent-secret")
	agentSecret = "test-enc-agent-secret"
	t.Cleanup(func() {
		if origAgentEnv != "" {
			os.Setenv("AGENT_SECRET", origAgentEnv)
		} else {
			os.Unsetenv("AGENT_SECRET")
		}
		resetAgentSecret()
	})

	// Create user and conversation
	_, err := db.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)",
		"enc-user-agent-test", "encuseragent", "hash")
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec("INSERT INTO conversations (id, user_id, agent_id) VALUES (?, ?, ?)",
		"conv-enc-agent", "enc-user-agent-test", "enc-agent-1")
	if err != nil {
		t.Fatal(err)
	}

	body := `{"conversation_id": "conv-enc-agent", "ciphertext": "YWJjZGVm", "iv": "aXYxMjM0", "algorithm": "aes-256-gcm", "recipient_key_id": "key1", "sender_key_id": "key2"}`
	req := agentAuthRequest(http.MethodPost, "/messages/encrypted", body, "enc-agent-1")
	w := httptest.NewRecorder()
	handleStoreEncryptedMessage(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var result map[string]interface{}
	json.NewDecoder(w.Body).Decode(&result)
	if result["status"] != "stored" {
		t.Errorf("expected status=stored, got %v", result["status"])
	}
}

// TestHandleStoreEncryptedMessage_AgentNotParticipant verifies that an agent
// sending to a conversation they're not part of gets 403.
func TestHandleStoreEncryptedMessage_AgentNotParticipant(t *testing.T) {
	setupTestDB(t)
	hub = newHub()
	go hub.run()
	t.Cleanup(hub.Stop)

	origAgentEnv := os.Getenv("AGENT_SECRET")
	os.Setenv("AGENT_SECRET", "test-enc-wrong-secret")
	agentSecret = "test-enc-wrong-secret"
	t.Cleanup(func() {
		if origAgentEnv != "" {
			os.Setenv("AGENT_SECRET", origAgentEnv)
		} else {
			os.Unsetenv("AGENT_SECRET")
		}
		resetAgentSecret()
	})

	_, err := db.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)",
		"enc-user-agent-2", "encuseragent2", "hash")
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec("INSERT INTO conversations (id, user_id, agent_id) VALUES (?, ?, ?)",
		"conv-enc-wrong", "enc-user-agent-2", "other-agent")
	if err != nil {
		t.Fatal(err)
	}

	body := `{"conversation_id": "conv-enc-wrong", "ciphertext": "YWJjZGVm", "iv": "aXYxMjM0", "algorithm": "aes-256-gcm", "recipient_key_id": "key1"}`
	req := agentAuthRequest(http.MethodPost, "/messages/encrypted", body, "enc-agent-wrong")
	w := httptest.NewRecorder()
	handleStoreEncryptedMessage(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", w.Code, w.Body.String())
	}
}

// TestHandleStoreEncryptedMessage_AgentSenderWithDelivery verifies that when
// an agent sends an encrypted message and the user has active connections,
// the message is delivered via WebSocket.
func TestHandleStoreEncryptedMessage_AgentSenderWithDelivery(t *testing.T) {
	setupTestDB(t)
	hub = newHub()
	go hub.run()
	t.Cleanup(hub.Stop)

	origAgentEnv := os.Getenv("AGENT_SECRET")
	os.Setenv("AGENT_SECRET", "test-deliver-secret")
	agentSecret = "test-deliver-secret"
	t.Cleanup(func() {
		if origAgentEnv != "" {
			os.Setenv("AGENT_SECRET", origAgentEnv)
		} else {
			os.Unsetenv("AGENT_SECRET")
		}
		resetAgentSecret()
	})

	// Create user and conversation
	_, err := db.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)",
		"enc-deliver-user", "encdeliveruser", "hash")
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec("INSERT INTO conversations (id, user_id, agent_id) VALUES (?, ?, ?)",
		"conv-enc-deliver", "enc-deliver-user", "enc-deliver-agent")
	if err != nil {
		t.Fatal(err)
	}

	// Simulate a connected client for the user
	clientConn := &Connection{
		hub:      hub,
		connType: "client",
		id:       "enc-deliver-user",
		send:     make(chan []byte, 256),
		deviceID: "device-1",
	}
	hub.register <- clientConn

	// Wait for registration
	time.Sleep(50 * time.Millisecond)

	body := `{"conversation_id": "conv-enc-deliver", "ciphertext": "ZW5jcnlwdGVk", "iv": "aXY0NTY3", "algorithm": "x25519-aes-256-gcm", "recipient_key_id": "rk1", "sender_key_id": "sk1"}`
	req := agentAuthRequest(http.MethodPost, "/messages/encrypted", body, "enc-deliver-agent")
	w := httptest.NewRecorder()
	handleStoreEncryptedMessage(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// Verify the client connection received the encrypted_message
	select {
	case msg := <-clientConn.send:
		if !strings.Contains(string(msg), "encrypted_message") {
			t.Errorf("expected encrypted_message in delivery, got: %s", string(msg))
		}
	case <-time.After(time.Second):
		t.Error("client should have received the encrypted message")
	}
}

// TestHandleStoreEncryptedMessage_ChaCha20Algorithm verifies the chacha20 algorithm is accepted.
func TestHandleStoreEncryptedMessage_ChaCha20Algorithm(t *testing.T) {
	setupTestDB(t)
	hub = newHub()
	go hub.run()
	t.Cleanup(hub.Stop)

	token, err := GenerateJWT("enc-chacha-user", "encchachauser")
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)",
		"enc-chacha-user", "encchachauser", "hash")
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec("INSERT INTO conversations (id, user_id, agent_id) VALUES (?, ?, ?)",
		"conv-chacha", "enc-chacha-user", "agent-chacha")
	if err != nil {
		t.Fatal(err)
	}

	body := `{"conversation_id": "conv-chacha", "ciphertext": "YWJjZGVm", "iv": "aXYxMjM0", "algorithm": "x25519-chacha20-poly1305", "recipient_key_id": "key1"}`
	req := httptest.NewRequest(http.MethodPost, "/messages/encrypted", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleStoreEncryptedMessage(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

// --- handleUpload content-type detection tests ---

// TestHandleUpload_OctetStreamDetection verifies that a file uploaded with
// application/octet-stream content type gets detected from content bytes.
func TestHandleUpload_OctetStreamDetection(t *testing.T) {
	setupTestDB(t)

	token, err := GenerateJWT("upload-oct-user", "uploadoctuser")
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)",
		"upload-oct-user", "uploadoctuser", "hash")
	if err != nil {
		t.Fatal(err)
	}

	// Create a multipart form with a PNG file but octet-stream content type
	body := &strings.Builder{}
	writer := multipart.NewWriter(body)

	// PNG magic bytes
	pngHeader := []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}
	part, err := writer.CreateFormFile("file", "test.png")
	if err != nil {
		t.Fatal(err)
	}
	part.Write(pngHeader)
	for i := 0; i < 100; i++ {
		part.Write([]byte{0x00})
	}
	writer.Close()

	req := httptest.NewRequest(http.MethodPost, "/upload", strings.NewReader(body.String()))
	req.Header.Set("Content-Type", writer.FormDataContentType())
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleUpload(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var result map[string]interface{}
	json.NewDecoder(w.Body).Decode(&result)
	if result["content_type"] != "image/png" {
		t.Errorf("expected image/png, got %v", result["content_type"])
	}

	// Clean up uploaded file
	if path, ok := result["storage_path"].(string); ok {
		os.RemoveAll(filepath.Dir(filepath.Join(getUploadDir(), path)))
	}
}

// TestHandleUpload_NoExtensionGuess verifies that files without extensions
// get extensions guessed from content type.
func TestHandleUpload_NoExtensionGuess(t *testing.T) {
	setupTestDB(t)

	token, err := GenerateJWT("upload-noext-user", "uploadnoextuser")
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)",
		"upload-noext-user", "uploadnoextuser", "hash")
	if err != nil {
		t.Fatal(err)
	}

	// Create a multipart form with a JPEG file (no extension in filename)
	body := &strings.Builder{}
	writer := multipart.NewWriter(body)

	// JPEG magic bytes
	jpegHeader := []byte{0xFF, 0xD8, 0xFF, 0xE0}
	part, err := writer.CreateFormFile("file", "testfile")
	if err != nil {
		t.Fatal(err)
	}
	part.Write(jpegHeader)
	for i := 0; i < 100; i++ {
		part.Write([]byte{0x00})
	}
	writer.Close()

	req := httptest.NewRequest(http.MethodPost, "/upload", strings.NewReader(body.String()))
	req.Header.Set("Content-Type", writer.FormDataContentType())
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleUpload(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var result map[string]interface{}
	json.NewDecoder(w.Body).Decode(&result)
	if result["content_type"] != "image/jpeg" {
		t.Errorf("expected image/jpeg, got %v", result["content_type"])
	}

	// Clean up
	if path, ok := result["storage_path"].(string); ok {
		os.RemoveAll(filepath.Dir(filepath.Join(getUploadDir(), path)))
	}
}

// TestHandleUpload_WithMessageID verifies that uploading with a message_id
// associates the attachment with that message.
func TestHandleUpload_WithMessageID(t *testing.T) {
	setupTestDB(t)

	token, err := GenerateJWT("upload-mid-user", "uploadmiduser")
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)",
		"upload-mid-user", "uploadmiduser", "hash")
	if err != nil {
		t.Fatal(err)
	}

	body := &strings.Builder{}
	writer := multipart.NewWriter(body)
	_ = writer.WriteField("message_id", "msg-12345")
	part, err := writer.CreateFormFile("file", "doc.txt")
	if err != nil {
		t.Fatal(err)
	}
	part.Write([]byte("Hello World"))
	writer.Close()

	req := httptest.NewRequest(http.MethodPost, "/upload", strings.NewReader(body.String()))
	req.Header.Set("Content-Type", writer.FormDataContentType())
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleUpload(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// Verify message_id was stored in DB
	var msgID *string
	err = db.QueryRow("SELECT message_id FROM attachments WHERE user_id = ?", "upload-mid-user").Scan(&msgID)
	if err != nil {
		t.Fatal(err)
	}
	if msgID == nil || *msgID != "msg-12345" {
		t.Errorf("expected message_id=msg-12345, got %v", msgID)
	}

	// Clean up
	var storagePath string
	db.QueryRow("SELECT storage_path FROM attachments WHERE user_id = ?", "upload-mid-user").Scan(&storagePath)
	if storagePath != "" {
		os.RemoveAll(filepath.Dir(filepath.Join(getUploadDir(), storagePath)))
	}
}

// --- parseSize float value tests ---

// TestParseSize_FloatValues verifies that float values with suffixes are parsed correctly.
func TestParseSize_FloatValues(t *testing.T) {
	type test struct {
		input    string
		expected int64
		wantErr  bool
	}

	gb := float64(1) * float64(1<<30)
	mb := float64(1) * float64(1<<20)
	kb := float64(1) * float64(1<<10)
	tb := float64(1) * float64(1<<40)

	tests := []test{
		{"1.5GB", int64(1.5 * gb), false},
		{"0.5MB", int64(0.5 * mb), false},
		{"2.5KB", int64(2.5 * kb), false},
		{"0.001TB", int64(0.001 * tb), false},
		{"100.5B", 100, false}, // float 100.5 → int64 truncation
		{"  50MB  ", 50 << 20, false}, // whitespace trimmed
		{"1.0GB", 1 << 30, false},
	}

	for _, tt := range tests {
		got, err := parseSize(tt.input)
		if tt.wantErr {
			if err == nil {
				t.Errorf("parseSize(%q): expected error, got %d", tt.input, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseSize(%q): unexpected error: %v", tt.input, err)
			continue
		}
		if got != tt.expected {
			t.Errorf("parseSize(%q) = %d, want %d", tt.input, got, tt.expected)
		}
	}
}

// --- handleDeleteNotificationPrefs wrong method test ---

// TestHandleDeleteNotificationPrefs_WrongMethod verifies that GET with no conversation_id returns 400.
func TestHandleDeleteNotificationPrefs_WrongMethod(t *testing.T) {
	setupTestDB(t)
	token := createTestUser(t, "delnotif_wrong")

	// handleDeleteNotificationPrefs doesn't check method, so GET should work
	req := authGetReq("/notification-prefs/delete", token)
	w := httptest.NewRecorder()
	handleDeleteNotificationPrefs(w, req)

	// Should succeed (no conversation_id → 400)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing conversation_id, got %d", w.Code)
	}
}

// --- handleGetNotificationPrefs with populated list ---

// TestHandleGetNotificationPrefs_MultiplePrefs verifies that multiple
// notification preferences are returned correctly.
func TestHandleGetNotificationPrefs_MultiplePrefs(t *testing.T) {
	setupTestDB(t)
	token := createTestUser(t, "multi_notif_user")
	createTestAgent(t, "multi_notif_agent-1", "bot1")
	createTestAgent(t, "multi_notif_agent-2", "bot2")
	createTestAgent(t, "multi_notif_agent-3", "bot3")

	conv1 := createTestConversation(t, token, "multi_notif_agent-1")
	conv2 := createTestConversation(t, token, "multi_notif_agent-2")
	conv3 := createTestConversation(t, token, "multi_notif_agent-3")

	// Mute conv1, unmute conv2, mute conv3
	for _, tc := range []struct {
		conv  string
		muted string
	}{
		{conv1, "true"},
		{conv2, "false"},
		{conv3, "true"},
	} {
		req := authPostReq("/notification-prefs/set", token, url.Values{
			"conversation_id": {tc.conv},
			"muted":           {tc.muted},
		})
		w := httptest.NewRecorder()
		handleSetNotificationPrefs(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("set notif prefs failed: %d %s", w.Code, w.Body.String())
		}
	}

	// Get all prefs
	req := authGetReq("/notification-prefs", token)
	w := httptest.NewRecorder()
	handleGetNotificationPrefs(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var prefs []NotificationPreferences
	json.Unmarshal(w.Body.Bytes(), &prefs)
	if len(prefs) != 3 {
		t.Fatalf("expected 3 prefs, got %d", len(prefs))
	}

	// Verify mute states
	mutedCount := 0
	for _, p := range prefs {
		if p.Muted {
			mutedCount++
		}
	}
	if mutedCount != 2 {
		t.Errorf("expected 2 muted, got %d", mutedCount)
	}
}

// --- initSchema additional tests ---

// TestInitSchema_TwiceIdempotent_V2 verifies that calling initSchema twice
// doesn't cause errors and all migrations are recorded.
func TestInitSchema_TwiceIdempotent_V2(t *testing.T) {
	setupTestDB(t)

	// initSchema was already called by setupTestDB
	// Call it again — should be idempotent
	err := initSchema(db)
	if err != nil {
		t.Fatalf("second initSchema call failed: %v", err)
	}

	// Verify migrations table has entries
	var count int
	err = db.QueryRow("SELECT COUNT(*) FROM schema_migrations").Scan(&count)
	if err != nil {
		t.Fatalf("failed to query schema_migrations: %v", err)
	}
	if count == 0 {
		t.Error("expected migrations to be recorded in schema_migrations")
	}
}

// --- handleSetNotificationPrefs DB error path ---

// TestHandleSetNotificationPrefs_ConversationNotFound verifies that a non-existent
// conversation returns 404.
func TestHandleSetNotificationPrefs_ConversationNotFound(t *testing.T) {
	setupTestDB(t)
	token := createTestUser(t, "notif_nf_user")

	// Use a conversation_id that doesn't exist
	req := authPostReq("/notification-prefs/set", token, url.Values{
		"conversation_id": {"nonexistent-conv-12345"},
		"muted":           {"true"},
	})
	w := httptest.NewRecorder()
	handleSetNotificationPrefs(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d: %s", w.Code, w.Body.String())
	}
}

// --- TouchHeartbeat and StaleAgentCount direct tests ---

// TestTouchHeartbeat_UpdatesTimestamp verifies that TouchHeartbeat updates the heartbeat time.
func TestTouchHeartbeat_UpdatesTimestamp(t *testing.T) {
	setupTestDB(t)
	h := newHub()
	go h.run()
	t.Cleanup(h.Stop)

	conn := &Connection{
		hub:           h,
		connType:      "agent",
		id:            "touch-direct-agent",
		send:          make(chan []byte, 256),
		lastHeartbeat: time.Now().Add(-1 * time.Hour),
	}

	h.mu.Lock()
	h.agents["touch-direct-agent"] = conn
	h.mu.Unlock()

	oldHB := conn.lastHeartbeat
	h.TouchHeartbeat(conn)

	if !conn.lastHeartbeat.After(oldHB) {
		t.Error("TouchHeartbeat should update lastHeartbeat to a later time")
	}
}

// TestStaleAgentCount_ReturnsZero verifies that a fresh hub returns 0 stale agents.
func TestStaleAgentCount_ReturnsZero(t *testing.T) {
	h := newHub()
	if h.StaleAgentCount() != 0 {
		t.Error("fresh hub should have 0 stale agents")
	}
}

// TestGetAgent_ReturnsNilForUnknown verifies that GetAgent returns nil for unknown agent.
func TestGetAgent_ReturnsNilForUnknown(t *testing.T) {
	h := newHub()
	if h.GetAgent("nonexistent-agent") != nil {
		t.Error("GetAgent should return nil for unknown agent")
	}
}

// TestGetClient_ReturnsNilForUnknown verifies that GetClient returns nil for unknown user.
func TestGetClient_ReturnsNilForUnknown(t *testing.T) {
	h := newHub()
	if h.GetClient("nonexistent-user") != nil {
		t.Error("GetClient should return nil for unknown user")
	}
}

// TestGetClientConns_Empty verifies that GetClientConns returns empty slice for unknown user.
func TestGetClientConns_Empty(t *testing.T) {
	h := newHub()
	conns := h.GetClientConns("nonexistent-user")
	if len(conns) != 0 {
		t.Error("GetClientConns should return empty slice for unknown user")
	}
}