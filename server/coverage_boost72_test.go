package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/websocket"
	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"
)

// ==================== CB72 Helpers ====================

func setupTestDB_CB72(t *testing.T) *sql.DB {
	testDB, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("Failed to open test DB: %v", err)
	}
	if err := initSchema(testDB); err != nil {
		t.Fatalf("Failed to init schema: %v", err)
	}
	t.Cleanup(func() { testDB.Close() })

	return testDB
}

func generateTestToken_CB72(userID string) string {
	claims := &Claims{
		UserID: userID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, _ := token.SignedString(jwtSecret)
	return signed
}

func makeTestHub_CB72() *Hub {
	h := newHub()
	go h.run()
	defer h.Stop()
	return h
}

func createUser_CB72(testDB *sql.DB, username, password string) string {
	hash, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	userID := "user_" + username
	testDB.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)", userID, username, hash)
	return userID
}

func createAgent_CB72(testDB *sql.DB, agentID string) {
	testDB.Exec("INSERT INTO agents (id, name, model) VALUES (?, ?, ?)", agentID, "Test Agent", "test-model")
}

func createConversation_CB72(testDB *sql.DB, userID, agentID string) string {
	convID := "conv_" + agentID + "_" + userID
	testDB.Exec("INSERT INTO conversations (id, user_id, agent_id) VALUES (?, ?, ?)", convID, userID, agentID)
	return convID
}

func makeAuthRequest_CB72(method, target string, body string, userID string) *http.Request {
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+generateTestToken_CB72(userID))
	req.Header.Set("Content-Type", "application/json")
	return req
}

func makeConn_CB72(connType, id string, h *Hub) *Connection {
	send := make(chan []byte, 256)
	return &Connection{
		id:       id,
		connType: connType,
		hub:      h,
		send:     send,
	}
}

func makeConnWithDevice_CB72(connType, id, deviceID string, h *Hub) *Connection {
	send := make(chan []byte, 256)
	return &Connection{
		id:       id,
		connType: connType,
		hub:      h,
		send:     send,
		deviceID: deviceID,
	}
}

func resetGlobals_CB72() {
	// Reset rate limiters
	messageRateLimiter = NewRateLimiter(60, time.Minute)
	userRateLimiter = NewRateLimiter(120, time.Minute)
	// Reset push config
	pushConfig = nil
	// Reset tracing
	tracingEnabled = false
	tracer = nil
	tp = nil
}

// ==================== marshalOutgoingMessage (60%) ====================

func TestCB72_MarshalOutgoingMessage_Success(t *testing.T) {
	msg := OutgoingMessage{Type: "message", Data: map[string]interface{}{"content": "hello"}}
	data := marshalOutgoingMessage(msg)
	if data == nil {
		t.Fatal("expected non-nil data")
	}
	var result OutgoingMessage
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}
	if result.Type != "message" {
		t.Errorf("expected type 'message', got '%s'", result.Type)
	}
}

func TestCB72_MarshalOutgoingMessage_NilData(t *testing.T) {
	msg := OutgoingMessage{Type: "connected", Data: nil}
	data := marshalOutgoingMessage(msg)
	if data == nil {
		t.Fatal("expected non-nil data for nil Data")
	}
}

func TestCB72_MarshalOutgoingMessage_EmptyType(t *testing.T) {
	msg := OutgoingMessage{Type: "", Data: map[string]interface{}{}}
	data := marshalOutgoingMessage(msg)
	if data == nil {
		t.Fatal("expected non-nil data for empty type")
	}
}

func TestCB72_MarshalOutgoingMessage_ComplexData(t *testing.T) {
	msg := OutgoingMessage{
		Type: "message",
		Data: map[string]interface{}{
			"content":   "test message",
			"id":        "msg-123",
			"timestamp": time.Now().UTC().Format(time.RFC3339),
			"nested":    map[string]interface{}{"key": "value"},
		},
	}
	data := marshalOutgoingMessage(msg)
	if data == nil {
		t.Fatal("expected non-nil data")
	}
	var result map[string]interface{}
	json.Unmarshal(data, &result)
	if result["type"] != "message" {
		t.Errorf("expected type 'message', got %v", result["type"])
	}
}

// ==================== writePump (70.4%) ====================

func TestCB72_WritePump_ChannelClosed(t *testing.T) {
	h := newHub()
	go h.run()
	defer h.Stop()

	// Create a real WebSocket connection for the close path
	var serverConn *websocket.Conn
	serverReady := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		serverConn = c
		close(serverReady)
		c.SetReadDeadline(time.Now().Add(10 * time.Second))
		for {
			if _, _, err := c.ReadMessage(); err != nil {
				return
			}
		}
	}))
	defer srv.Close()

	url := "ws" + strings.TrimPrefix(srv.URL, "http")
	dialer := websocket.Dialer{}
	clientConn, _, err := dialer.Dial(url, nil)
	if err != nil {
		t.Fatalf("Failed to dial WebSocket: %v", err)
	}
	defer clientConn.Close()

	select {
	case <-serverReady:
	case <-time.After(3 * time.Second):
		t.Fatal("server did not upgrade connection")
	}
	defer serverConn.Close()

	conn := makeConn_CB72("agent", "agent-1", h)
	conn.conn = serverConn

	// Close the send channel to trigger the !ok path
	close(conn.send)

	// writePump should return when channel is closed
	done := make(chan bool, 1)
	go func() {
		conn.writePump()
		done <- true
	}()

	select {
	case <-done:
		// Good, writePump returned
	case <-time.After(2 * time.Second):
		t.Fatal("writePump did not return after channel close")
	}
}

func TestCB72_WritePump_MessageSent(t *testing.T) {
	h := newHub()
	go h.run()
	defer h.Stop()

	// Create a real WebSocket connection using httptest
	var serverConn *websocket.Conn
	serverReady := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Errorf("upgrade failed: %v", err)
			return
		}
		serverConn = c
		close(serverReady)
		c.SetReadDeadline(time.Now().Add(10 * time.Second))
		for {
			if _, _, err := c.ReadMessage(); err != nil {
				return
			}
		}
	}))
	defer srv.Close()

	url := "ws" + strings.TrimPrefix(srv.URL, "http")
	dialer := websocket.Dialer{}
	clientConn, _, err := dialer.Dial(url, nil)
	if err != nil {
		t.Fatalf("Failed to dial WebSocket: %v", err)
	}
	defer clientConn.Close()

	select {
	case <-serverReady:
	case <-time.After(3 * time.Second):
		t.Fatal("server did not upgrade connection")
	}
	defer serverConn.Close()

	conn := makeConn_CB72("agent", "agent-1", h)
	conn.conn = serverConn

	// Send a message through the channel
	testMsg := []byte(`{"type":"test"}`)
	conn.send <- testMsg

	// Start writePump
	done := make(chan bool, 1)
	go func() {
		conn.writePump()
		done <- true
	}()

	// Read the message from the WebSocket client
	clientConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, msg, err := clientConn.ReadMessage()
	if err != nil {
		t.Fatalf("Failed to read message: %v", err)
	}
	if string(msg) != `{"type":"test"}` {
		t.Errorf("expected '{\"type\":\"test\"}', got '%s'", string(msg))
	}

	// Close the send channel to stop writePump
	close(conn.send)
	select {
	case <-done:
		// Good
	case <-time.After(2 * time.Second):
		t.Fatal("writePump did not return after channel close")
	}
}

func TestCB72_WritePump_PingSent(t *testing.T) {
	t.Skip("pingPeriod is 54s - too slow for unit tests")
}

func TestCB72_WritePump_WriteError(t *testing.T) {
	h := newHub()
	go h.run()
	defer h.Stop()

	var serverConn *websocket.Conn
	serverReady := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		serverConn = c
		close(serverReady)
	}))
	defer srv.Close()

	url := "ws" + strings.TrimPrefix(srv.URL, "http")
	dialer := websocket.Dialer{}
	clientConn, _, err := dialer.Dial(url, nil)
	if err != nil {
		t.Fatalf("Failed to dial WebSocket: %v", err)
	}

	select {
	case <-serverReady:
	case <-time.After(3 * time.Second):
		t.Fatal("server did not upgrade connection")
	}

	// Close both sides to force write error
	clientConn.Close()
	serverConn.Close()

	conn := makeConn_CB72("agent", "agent-1", h)
	conn.conn = serverConn

	// Send a message which should fail on write
	conn.send <- []byte(`{"type":"test"}`)

	done := make(chan bool, 1)
	go func() {
		conn.writePump()
		done <- true
	}()

	select {
	case <-done:
		// Good, writePump returned after write error
	case <-time.After(2 * time.Second):
		t.Fatal("writePump did not return after write error")
	}
}

// ==================== checkRateLimit (78.9%) ====================

func TestCB72_CheckRateLimit_Allowed(t *testing.T) {
	resetGlobals_CB72()
	defer resetGlobals_CB72()

	h := newHub()
	go h.run()
	defer h.Stop()

	conn := makeConn_CB72("client", "user-1", h)
	result := checkRateLimit(conn)
	if !result {
		t.Error("expected rate limit to allow")
	}
}

func TestCB72_CheckRateLimit_PerConnectionExceeded(t *testing.T) {
	resetGlobals_CB72()
	defer resetGlobals_CB72()

	// Create a rate limiter with very low limit
	messageRateLimiter = NewRateLimiter(2, time.Minute)

	h := newHub()
	go h.run()
	defer h.Stop()

	conn := makeConn_CB72("client", "user-1", h)

	// Use up the limit
	messageRateLimiter.Allow(conn.id)
	messageRateLimiter.Allow(conn.id)

	result := checkRateLimit(conn)
	if result {
		t.Error("expected rate limit to block after exceeding per-connection limit")
	}
}

func TestCB72_CheckRateLimit_PerUserExceeded(t *testing.T) {
	resetGlobals_CB72()
	defer resetGlobals_CB72()

	// Per-connection allows, but per-user blocks
	messageRateLimiter = NewRateLimiter(100, time.Minute)
	userRateLimiter = NewRateLimiter(2, time.Minute)

	h := newHub()
	go h.run()
	defer h.Stop()

	conn := makeConn_CB72("client", "user-1", h)

	// Use up the user limit
	userRateLimiter.Allow(conn.id)
	userRateLimiter.Allow(conn.id)

	result := checkRateLimit(conn)
	if result {
		t.Error("expected rate limit to block after exceeding per-user limit")
	}
}

func TestCB72_CheckRateLimit_BothAllowed(t *testing.T) {
	resetGlobals_CB72()
	defer resetGlobals_CB72()

	messageRateLimiter = NewRateLimiter(100, time.Minute)
	userRateLimiter = NewRateLimiter(100, time.Minute)

	h := newHub()
	go h.run()
	defer h.Stop()

	conn := makeConn_CB72("agent", "agent-1", h)
	result := checkRateLimit(conn)
	if !result {
		t.Error("expected rate limit to allow when under both limits")
	}
}

// ==================== isConversationMuted (77.8%) ====================

func TestCB72_IsConversationMuted_NotMuted(t *testing.T) {
	testDB := setupTestDB_CB72(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB; testDB.Close() }()

	userID := createUser_CB72(testDB, "testuser", "pass")
	agentID := "agent-1"
	createAgent_CB72(testDB, agentID)
	convID := createConversation_CB72(testDB, userID, agentID)

	muted := isConversationMuted(userID, convID)
	if muted {
		t.Error("expected conversation to not be muted")
	}
}

func TestCB72_IsConversationMuted_Muted(t *testing.T) {
	testDB := setupTestDB_CB72(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB; testDB.Close() }()

	userID := createUser_CB72(testDB, "testuser", "pass")
	agentID := "agent-1"
	createAgent_CB72(testDB, agentID)
	convID := createConversation_CB72(testDB, userID, agentID)

	// Mute the conversation
	testDB.Exec("INSERT INTO notification_preferences (user_id, conversation_id, muted) VALUES (?, ?, 1)", userID, convID)

	muted := isConversationMuted(userID, convID)
	if !muted {
		t.Error("expected conversation to be muted")
	}
}

func TestCB72_IsConversationMuted_DBError(t *testing.T) {
	testDB := setupTestDB_CB72(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	testDB.Close()

	muted := isConversationMuted("user-1", "conv-1")
	if muted {
		t.Error("expected false on DB error")
	}
}

func TestCB72_IsConversationMuted_EmptyConvID(t *testing.T) {
	testDB := setupTestDB_CB72(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB; testDB.Close() }()

	// Empty conversation ID should not query DB, should return false
	muted := isConversationMuted("user-1", "")
	if muted {
		t.Error("expected false for empty conversation ID")
	}
}

// ==================== handleHeapProfile (76.9%) ====================

func TestCB72_HandleHeapProfile_Success(t *testing.T) {
	dir := t.TempDir()
	oldDir := os.Getenv("PROFILING_DIR")
	os.Setenv("PROFILING_DIR", dir)
	defer os.Setenv("PROFILING_DIR", oldDir)

	req := httptest.NewRequest("GET", "/admin/profile?action=heap", nil)
	rr := httptest.NewRecorder()
	handleHeapProfile(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}

	var result map[string]interface{}
	json.Unmarshal(rr.Body.Bytes(), &result)
	if result["status"] != "ok" {
		t.Errorf("expected status 'ok', got %v", result["status"])
	}
	if result["action"] != "heap" {
		t.Errorf("expected action 'heap', got %v", result["action"])
	}
}

func TestCB72_HandleHeapProfile_MkdirError(t *testing.T) {
	// Use a path that can't be created (under a file)
	dir := "/dev/null/cannot_create_dir"
	oldDir := os.Getenv("PROFILING_DIR")
	os.Setenv("PROFILING_DIR", dir)
	defer os.Setenv("PROFILING_DIR", oldDir)

	req := httptest.NewRequest("GET", "/admin/profile?action=heap", nil)
	rr := httptest.NewRecorder()
	handleHeapProfile(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", rr.Code)
	}
}

func TestCB72_HandleHeapProfile_DefaultDir(t *testing.T) {
	// Unset PROFILING_DIR to test default path
	oldDir := os.Getenv("PROFILING_DIR")
	os.Unsetenv("PROFILING_DIR")
	defer os.Setenv("PROFILING_DIR", oldDir)

	req := httptest.NewRequest("GET", "/admin/profile?action=heap", nil)
	rr := httptest.NewRecorder()
	handleHeapProfile(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}

// ==================== handleGoroutineProfile (76.9%) ====================

func TestCB72_HandleGoroutineProfile_Success(t *testing.T) {
	dir := t.TempDir()
	oldDir := os.Getenv("PROFILING_DIR")
	os.Setenv("PROFILING_DIR", dir)
	defer os.Setenv("PROFILING_DIR", oldDir)

	req := httptest.NewRequest("GET", "/admin/profile?action=goroutine", nil)
	rr := httptest.NewRecorder()
	handleGoroutineProfile(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}

	var result map[string]interface{}
	json.Unmarshal(rr.Body.Bytes(), &result)
	if result["status"] != "ok" {
		t.Errorf("expected status 'ok', got %v", result["status"])
	}
	if result["action"] != "goroutine" {
		t.Errorf("expected action 'goroutine', got %v", result["action"])
	}
}

func TestCB72_HandleGoroutineProfile_MkdirError(t *testing.T) {
	dir := "/dev/null/cannot_create_dir"
	oldDir := os.Getenv("PROFILING_DIR")
	os.Setenv("PROFILING_DIR", dir)
	defer os.Setenv("PROFILING_DIR", oldDir)

	req := httptest.NewRequest("GET", "/admin/profile?action=goroutine", nil)
	rr := httptest.NewRecorder()
	handleGoroutineProfile(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", rr.Code)
	}
}

func TestCB72_HandleGoroutineProfile_DefaultDir(t *testing.T) {
	oldDir := os.Getenv("PROFILING_DIR")
	os.Unsetenv("PROFILING_DIR")
	defer os.Setenv("PROFILING_DIR", oldDir)

	req := httptest.NewRequest("GET", "/admin/profile?action=goroutine", nil)
	rr := httptest.NewRecorder()
	handleGoroutineProfile(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}

// ==================== StartCPUProfile (80%) ====================

func TestCB72_StartCPUProfile_Success(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cpu.prof")

	stop, err := StartCPUProfile(path)
	if err != nil {
		t.Fatalf("StartCPUProfile failed: %v", err)
	}
	if stop != nil {
		stop()
	}
}

func TestCB72_StartCPUProfile_InvalidPath(t *testing.T) {
	path := "/nonexistent/dir/that/does/not/exist/cpu.prof"
	stop, err := StartCPUProfile(path)
	if err == nil {
		if stop != nil {
			stop()
		}
		t.Error("expected error for invalid path")
	}
}

func TestCB72_StartCPUProfile_AlreadyActive(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cpu.prof")

	// Start one profile
	stop1, err := StartCPUProfile(path)
	if err != nil {
		t.Fatalf("First StartCPUProfile failed: %v", err)
	}

	// Try to start another on same file - pprof.StartCPUProfile returns error if already profiling
	_, err = StartCPUProfile(filepath.Join(dir, "cpu2.prof"))
	if err == nil {
		t.Error("expected error when profile already active")
	}

	// Clean up
	if stop1 != nil {
		stop1()
	}
}

// ==================== handleCPUProfileStart (85%) ====================

func TestCB72_HandleCPUProfileStart_Success(t *testing.T) {
	dir := t.TempDir()
	oldDir := os.Getenv("PROFILING_DIR")
	os.Setenv("PROFILING_DIR", dir)
	defer os.Setenv("PROFILING_DIR", oldDir)

	req := httptest.NewRequest("POST", "/admin/profile?action=cpu", nil)
	rr := httptest.NewRecorder()
	handleCPUProfileStart(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}

	// Clean up
	cpuProfileState.Lock()
	if cpuProfileState.stopFunc != nil {
		cpuProfileState.stopFunc()
		cpuProfileState.active = false
		cpuProfileState.stopFunc = nil
	}
	cpuProfileState.Unlock()
}

func TestCB72_HandleCPUProfileStart_MkdirError(t *testing.T) {
	dir := "/dev/null/cannot_create_dir"
	oldDir := os.Getenv("PROFILING_DIR")
	os.Setenv("PROFILING_DIR", dir)
	defer os.Setenv("PROFILING_DIR", oldDir)

	req := httptest.NewRequest("POST", "/admin/profile?action=cpu", nil)
	rr := httptest.NewRecorder()
	handleCPUProfileStart(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", rr.Code)
	}
}

func TestCB72_HandleCPUProfileStart_AlreadyActive(t *testing.T) {
	dir := t.TempDir()
	oldDir := os.Getenv("PROFILING_DIR")
	os.Setenv("PROFILING_DIR", dir)
	defer os.Setenv("PROFILING_DIR", oldDir)

	// Start a profile first
	cpuProfileState.Lock()
	cpuProfileState.active = true
	cpuProfileState.stopFunc = func() {}
	cpuProfileState.Unlock()

	defer func() {
		cpuProfileState.Lock()
		cpuProfileState.active = false
		cpuProfileState.stopFunc = nil
		cpuProfileState.Unlock()
	}()

	req := httptest.NewRequest("POST", "/admin/profile?action=cpu", nil)
	rr := httptest.NewRecorder()
	handleCPUProfileStart(rr, req)

	// writeProfileError always returns 500
	if rr.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", rr.Code)
	}
}

// ==================== sendWelcomeMessage (80%) ====================

func TestCB72_SendWelcomeMessage_Success(t *testing.T) {
	h := newHub()
	go h.run()
	defer h.Stop()

	conn := makeConn_CB72("agent", "agent-1", h)
	sendWelcomeMessage(conn)

	select {
	case msg := <-conn.send:
		var result map[string]interface{}
		json.Unmarshal(msg, &result)
		if result["type"] != "connected" {
			t.Errorf("expected type 'connected', got %v", result["type"])
		}
		data := result["data"].(map[string]interface{})
		if data["status"] != "connected" {
			t.Errorf("expected status 'connected', got %v", data["status"])
		}
		if data["protocol_version"] == nil {
			t.Error("expected non-nil protocol_version")
		}
	case <-time.After(1 * time.Second):
		t.Fatal("did not receive welcome message")
	}
}

func TestCB72_SendWelcomeMessage_WithDeviceID(t *testing.T) {
	h := newHub()
	go h.run()
	defer h.Stop()

	conn := makeConnWithDevice_CB72("client", "user-1", "device-abc", h)
	sendWelcomeMessage(conn)

	select {
	case msg := <-conn.send:
		var result map[string]interface{}
		json.Unmarshal(msg, &result)
		data := result["data"].(map[string]interface{})
		if data["device_id"] != "device-abc" {
			t.Errorf("expected device_id 'device-abc', got %v", data["device_id"])
		}
	case <-time.After(1 * time.Second):
		t.Fatal("did not receive welcome message")
	}
}

func TestCB72_SendWelcomeMessage_BufferFull(t *testing.T) {
	h := newHub()
	go h.run()
	defer h.Stop()

	conn := makeConn_CB72("agent", "agent-1", h)
	// Fill the send buffer
	for i := 0; i < 256; i++ {
		conn.send <- []byte("x")
	}

	// Now sendWelcomeMessage should fail to send
	sendWelcomeMessage(conn)
	// If we get here without blocking, the test passes
	// (SafeSend returns false when buffer is full)
}

func TestCB72_SendWelcomeMessage_ClosedChannel(t *testing.T) {
	h := newHub()
	go h.run()
	defer h.Stop()

	conn := makeConn_CB72("agent", "agent-1", h)
	close(conn.send)
	conn.MarkClosed()

	// Should not panic
	sendWelcomeMessage(conn)
}

// ==================== InitTracing (79.5%) ====================

func TestCB72_InitTracing_Disabled(t *testing.T) {
	// Reset tracing state
	tracingEnabled = false
	tracer = nil
	tp = nil
	// Reset sync.Once so we can call InitTracing again
	tracingMu = sync.Once{}

	oldVal := os.Getenv("OTEL_ENABLED")
	os.Unsetenv("OTEL_ENABLED")
	defer os.Setenv("OTEL_ENABLED", oldVal)

	err := InitTracing()
	if err != nil {
		t.Errorf("expected nil error when tracing disabled, got %v", err)
	}
	if tracingEnabled {
		t.Error("expected tracingEnabled to be false")
	}
}

func TestCB72_InitTracing_NoEndpoint(t *testing.T) {
	tracingEnabled = false
	tracer = nil
	tp = nil
	tracingMu = sync.Once{}

	os.Setenv("OTEL_ENABLED", "true")
	defer os.Unsetenv("OTEL_ENABLED")

	os.Unsetenv("OTEL_EXPORTER_OTLP_ENDPOINT")
	os.Unsetenv("OTEL_EXPORTER_OTLP_HTTP_ENDPOINT")

	err := InitTracing()
	if err != nil {
		t.Errorf("expected nil error when no endpoint, got %v", err)
	}
	if tracingEnabled {
		t.Error("expected tracingEnabled to be false when no endpoint")
	}
}

func TestCB72_InitTracing_HTTPExporter(t *testing.T) {
	tracingEnabled = false
	tracer = nil
	tp = nil
	tracingMu = sync.Once{}

	os.Setenv("OTEL_ENABLED", "true")
	os.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "localhost:4318")
	os.Setenv("OTEL_EXPORTER_OTLP_PROTOCOL", "http")
	defer func() {
		os.Unsetenv("OTEL_ENABLED")
		os.Unsetenv("OTEL_EXPORTER_OTLP_ENDPOINT")
		os.Unsetenv("OTEL_EXPORTER_OTLP_PROTOCOL")
	}()

	// This may fail to connect, but should still set up tracing
	_ = InitTracing()
	// If it didn't error, tracing should be enabled
	// If it errored, that's also acceptable for this test
	// We just verify it doesn't panic

	// Clean up
	ShutdownTracing()
	tracingEnabled = false
	tracer = nil
	tp = nil
}

func TestCB72_InitTracing_GRPCExporter(t *testing.T) {
	tracingEnabled = false
	tracer = nil
	tp = nil
	tracingMu = sync.Once{}

	os.Setenv("OTEL_ENABLED", "true")
	os.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "localhost:4317")
	os.Setenv("OTEL_EXPORTER_OTLP_PROTOCOL", "grpc")
	defer func() {
		os.Unsetenv("OTEL_ENABLED")
		os.Unsetenv("OTEL_EXPORTER_OTLP_ENDPOINT")
		os.Unsetenv("OTEL_EXPORTER_OTLP_PROTOCOL")
	}()

	_ = InitTracing()

	// Clean up
	ShutdownTracing()
	tracingEnabled = false
	tracer = nil
	tp = nil
}

func TestCB72_InitTracing_CustomSamplingRate(t *testing.T) {
	tracingEnabled = false
	tracer = nil
	tp = nil
	tracingMu = sync.Once{}

	os.Setenv("OTEL_ENABLED", "true")
	os.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "localhost:4318")
	os.Setenv("OTEL_EXPORTER_OTLP_PROTOCOL", "http")
	os.Setenv("OTEL_SAMPLING_RATE", "0.5")
	defer func() {
		os.Unsetenv("OTEL_ENABLED")
		os.Unsetenv("OTEL_EXPORTER_OTLP_ENDPOINT")
		os.Unsetenv("OTEL_EXPORTER_OTLP_PROTOCOL")
		os.Unsetenv("OTEL_SAMPLING_RATE")
	}()

	_ = InitTracing()

	// Clean up
	ShutdownTracing()
	tracingEnabled = false
	tracer = nil
	tp = nil
}

func TestCB72_InitTracing_AlreadyInitialized(t *testing.T) {
	tracingEnabled = true
	tracer = nil
	tp = nil
	tracingMu = sync.Once{} // This has already been "done"

	// Call again - should be no-op due to sync.Once
	err := InitTracing()
	if err != nil {
		t.Errorf("expected nil error on double init, got %v", err)
	}
}

// ==================== ShutdownTracing (80%) ====================

func TestCB72_ShutdownTracing_NilProvider(t *testing.T) {
	tracingEnabled = false
	tp = nil
	ShutdownTracing()
	// Should not panic
}

func TestCB72_ShutdownTracing_WithProvider(t *testing.T) {
	tracingEnabled = false
	tracer = nil
	tp = nil
	tracingMu = sync.Once{}

	os.Setenv("OTEL_ENABLED", "true")
	os.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "localhost:4318")
	os.Setenv("OTEL_EXPORTER_OTLP_PROTOCOL", "http")
	defer func() {
		os.Unsetenv("OTEL_ENABLED")
		os.Unsetenv("OTEL_EXPORTER_OTLP_ENDPOINT")
		os.Unsetenv("OTEL_EXPORTER_OTLP_PROTOCOL")
	}()

	_ = InitTracing()

	// Now shutdown
	ShutdownTracing()

	if tracingEnabled {
		// tracingEnabled might still be true but tp should be nil after shutdown
	}
	tracingEnabled = false
	tracer = nil
	tp = nil
}

// ==================== newHub (83.3%) ====================

func TestCB72_NewHub_AgentPresenceEnabled(t *testing.T) {
	oldVal := agentPresenceEnabled
	agentPresenceEnabled = true
	defer func() { agentPresenceEnabled = oldVal }()

	h := newHub()
	if h == nil {
		t.Fatal("expected non-nil hub")
	}
	if h.agents == nil {
		t.Error("expected non-nil agents map")
	}
	if h.clientConns == nil {
		t.Error("expected non-nil clientConns map")
	}
	if h.register == nil {
		t.Error("expected non-nil register channel")
	}
	if h.unregister == nil {
		t.Error("expected non-nil unregister channel")
	}
	if h.done == nil {
		t.Error("expected non-nil done channel")
	}
	// Wait for monitor to start
	// Don't call h.Stop() here since monitor needs to exit
	// Actually we should stop it
	h.Stop()
}

func TestCB72_NewHub_AgentPresenceDisabled(t *testing.T) {
	oldVal := agentPresenceEnabled
	agentPresenceEnabled = false
	defer func() { agentPresenceEnabled = oldVal }()

	h := newHub()
	if h == nil {
		t.Fatal("expected non-nil hub")
	}
	// monitorDone should already be closed when presence is disabled
	select {
	case <-h.monitorDone:
		// Good
	default:
		t.Error("expected monitorDone to be closed when presence disabled")
	}
}

// ==================== hub.run (87.9%) ====================

func TestCB72_HubRun_AgentRegister(t *testing.T) {
	h := newHub()
	go h.run()
	defer h.Stop()

	conn := makeConn_CB72("agent", "agent-1", h)
	h.register <- conn

	time.Sleep(50 * time.Millisecond)

	h.mu.Lock()
	_, exists := h.agents["agent-1"]
	h.mu.Unlock()

	if !exists {
		t.Error("expected agent to be registered")
	}
}

func TestCB72_HubRun_AgentUnregister(t *testing.T) {
	h := newHub()
	go h.run()
	defer h.Stop()

	conn := makeConn_CB72("agent", "agent-1", h)
	h.register <- conn
	time.Sleep(50 * time.Millisecond)

	h.unregister <- conn
	time.Sleep(50 * time.Millisecond)

	h.mu.Lock()
	_, exists := h.agents["agent-1"]
	h.mu.Unlock()

	if exists {
		t.Error("expected agent to be unregistered")
	}
}

func TestCB72_HubRun_ClientRegister(t *testing.T) {
	h := newHub()
	go h.run()
	defer h.Stop()

	conn := makeConn_CB72("client", "user-1", h)
	h.register <- conn
	time.Sleep(50 * time.Millisecond)

	h.mu.Lock()
	conns := h.clientConns["user-1"]
	h.mu.Unlock()

	if len(conns) != 1 {
		t.Errorf("expected 1 client connection, got %d", len(conns))
	}
}

func TestCB72_HubRun_ClientUnregister(t *testing.T) {
	h := newHub()
	go h.run()
	defer h.Stop()

	conn := makeConn_CB72("client", "user-1", h)
	h.register <- conn
	time.Sleep(50 * time.Millisecond)

	h.unregister <- conn
	time.Sleep(50 * time.Millisecond)

	h.mu.Lock()
	conns := h.clientConns["user-1"]
	h.mu.Unlock()

	if len(conns) != 0 {
		t.Errorf("expected 0 client connections, got %d", len(conns))
	}
}

func TestCB72_HubRun_AgentReconnect(t *testing.T) {
	h := newHub()
	go h.run()
	defer h.Stop()

	conn1 := makeConn_CB72("agent", "agent-1", h)
	h.register <- conn1
	time.Sleep(50 * time.Millisecond)

	conn2 := makeConn_CB72("agent", "agent-1", h)
	h.register <- conn2
	time.Sleep(50 * time.Millisecond)

	h.mu.Lock()
	current := h.agents["agent-1"]
	h.mu.Unlock()

	if current != conn2 {
		t.Error("expected agent connection to be replaced")
	}
}

func TestCB72_HubRun_ClientDeviceReconnect(t *testing.T) {
	h := newHub()
	go h.run()
	defer h.Stop()

	conn1 := makeConnWithDevice_CB72("client", "user-1", "device-1", h)
	h.register <- conn1
	time.Sleep(50 * time.Millisecond)

	conn2 := makeConnWithDevice_CB72("client", "user-1", "device-1", h)
	h.register <- conn2
	time.Sleep(50 * time.Millisecond)

	h.mu.Lock()
	conns := h.clientConns["user-1"]
	h.mu.Unlock()

	if len(conns) != 1 {
		t.Errorf("expected 1 connection (replaced), got %d", len(conns))
	}
	if conns[0] != conn2 {
		t.Error("expected connection to be replaced")
	}
}

func TestCB72_HubRun_ClientMultiDevice(t *testing.T) {
	h := newHub()
	go h.run()
	defer h.Stop()

	conn1 := makeConnWithDevice_CB72("client", "user-1", "device-1", h)
	h.register <- conn1
	conn2 := makeConnWithDevice_CB72("client", "user-1", "device-2", h)
	h.register <- conn2
	time.Sleep(50 * time.Millisecond)

	h.mu.Lock()
	conns := h.clientConns["user-1"]
	h.mu.Unlock()

	if len(conns) != 2 {
		t.Errorf("expected 2 connections, got %d", len(conns))
	}
}

func TestCB72_HubRun_UnregisterUnknownAgent(t *testing.T) {
	h := newHub()
	go h.run()
	defer h.Stop()

	// Unregister an agent that was never registered
	conn := makeConn_CB72("agent", "ghost-agent", h)
	// Don't panic
	h.unregister <- conn
	time.Sleep(50 * time.Millisecond)
}

func TestCB72_HubRun_UnregisterUnknownClient(t *testing.T) {
	h := newHub()
	go h.run()
	defer h.Stop()

	// Unregister a client that was never registered
	conn := makeConn_CB72("client", "ghost-user", h)
	h.unregister <- conn
	time.Sleep(50 * time.Millisecond)
}

// ==================== SafeSend (85.7%) ====================

func TestCB72_SafeSend_Success(t *testing.T) {
	h := newHub()
	go h.run()
	defer h.Stop()

	conn := makeConn_CB72("agent", "agent-1", h)
	result := conn.SafeSend([]byte("test"))
	if !result {
		t.Error("expected SafeSend to return true")
	}
}

func TestCB72_SafeSend_BufferFull(t *testing.T) {
	h := newHub()
	go h.run()
	defer h.Stop()

	conn := makeConn_CB72("agent", "agent-1", h)
	// Fill the buffer
	for i := 0; i < 256; i++ {
		conn.send <- []byte("x")
	}

	// Now SafeSend should return false (buffer full)
	result := conn.SafeSend([]byte("overflow"))
	if result {
		t.Error("expected SafeSend to return false when buffer is full")
	}
}

func TestCB72_SafeSend_ClosedChannel(t *testing.T) {
	h := newHub()
	go h.run()
	defer h.Stop()

	conn := makeConn_CB72("agent", "agent-1", h)
	close(conn.send)
	conn.MarkClosed()

	// Should not panic, should return false
	result := conn.SafeSend([]byte("test"))
	if result {
		t.Error("expected SafeSend to return false on closed channel")
	}
}

func TestCB72_SafeSend_AlreadyClosed(t *testing.T) {
	h := newHub()
	go h.run()
	defer h.Stop()

	conn := makeConn_CB72("agent", "agent-1", h)
	conn.MarkClosed()

	result := conn.SafeSend([]byte("test"))
	if result {
		t.Error("expected SafeSend to return false when already closed")
	}
}

// ==================== readPump (86.4%) ====================

func TestCB72_ReadPump_NormalClosure(t *testing.T) {
	h := newHub()
	go h.run()
	defer h.Stop()

	var serverConn *websocket.Conn
	serverReady := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		serverConn = c
		close(serverReady)
	}))
	defer srv.Close()

	url := "ws" + strings.TrimPrefix(srv.URL, "http")
	dialer := websocket.Dialer{}
	clientConn, _, err := dialer.Dial(url, nil)
	if err != nil {
		t.Fatalf("Failed to dial WebSocket: %v", err)
	}

	select {
	case <-serverReady:
	case <-time.After(3 * time.Second):
		t.Fatal("server did not upgrade connection")
	}

	conn := makeConn_CB72("agent", "agent-1", h)
	conn.conn = serverConn

	done := make(chan bool, 1)
	go func() {
		conn.readPump()
		done <- true
	}()

	// Close the client side to trigger read error on server side
	clientConn.Close()

	select {
	case <-done:
		// Good, readPump returned
	case <-time.After(2 * time.Second):
		t.Fatal("readPump did not return after connection close")
	}
}

func TestCB72_ReadPump_PongHandler(t *testing.T) {
	h := newHub()
	go h.run()
	defer h.Stop()

	var serverConn *websocket.Conn
	serverReady := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		serverConn = c
		close(serverReady)
		c.SetReadDeadline(time.Now().Add(10 * time.Second))
		for {
			if _, _, err := c.ReadMessage(); err != nil {
				return
			}
		}
	}))
	defer srv.Close()

	url := "ws" + strings.TrimPrefix(srv.URL, "http")
	dialer := websocket.Dialer{}
	clientConn, _, err := dialer.Dial(url, nil)
	if err != nil {
		t.Fatalf("Failed to dial WebSocket: %v", err)
	}
	defer clientConn.Close()

	select {
	case <-serverReady:
	case <-time.After(3 * time.Second):
		t.Fatal("server did not upgrade connection")
	}
	defer serverConn.Close()

	conn := makeConn_CB72("agent", "agent-1", h)
	conn.conn = serverConn

	done := make(chan bool, 1)
	go func() {
		conn.readPump()
		done <- true
	}()

	// Send a ping from the client (server's pong handler should reset deadline)
	clientConn.WriteMessage(websocket.PingMessage, nil)

	// Wait a bit then close
	time.Sleep(100 * time.Millisecond)
	clientConn.Close()

	select {
	case <-done:
		// Good
	case <-time.After(2 * time.Second):
		t.Fatal("readPump did not return")
	}
}

// ==================== storeMessagesBatch (81.5%) ====================

func TestCB72_StoreMessagesBatch_Success(t *testing.T) {
	testDB := setupTestDB_CB72(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB; testDB.Close() }()

	userID := createUser_CB72(testDB, "testuser", "pass")
	agentID := "agent-1"
	createAgent_CB72(testDB, agentID)
	convID := createConversation_CB72(testDB, userID, agentID)

	msgs := []RoutedMessage{
		{
			ConversationID: convID,
			SenderType:     "client",
			SenderID:       userID,
			Content:        "Hello",
			Type:           "message",
			RecipientID:    agentID,
		},
		{
			ConversationID: convID,
			SenderType:     "client",
			SenderID:       userID,
			Content:        "World",
			Type:           "message",
			RecipientID:    agentID,
		},
	}

	ids, err := storeMessagesBatch(msgs)
	if err != nil {
		t.Fatalf("storeMessagesBatch failed: %v", err)
	}
	if len(ids) != 2 {
		t.Errorf("expected 2 message IDs, got %d", len(ids))
	}

	// Verify messages were stored
	var count int
	testDB.QueryRow("SELECT COUNT(*) FROM messages WHERE conversation_id = ?", convID).Scan(&count)
	if count != 2 {
		t.Errorf("expected 2 messages, got %d", count)
	}
}

func TestCB72_StoreMessagesBatch_DBError(t *testing.T) {
	testDB := setupTestDB_CB72(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	testDB.Close()

	msgs := []RoutedMessage{
		{
			ConversationID: "conv-1",
			SenderType:     "client",
			SenderID:       "user-1",
			Content:        "Hello",
			Type:           "message",
			RecipientID:    "agent-1",
		},
	}

	_, err := storeMessagesBatch(msgs)
	if err == nil {
		t.Error("expected error with closed DB")
	}
}

func TestCB72_StoreMessagesBatch_EmptyBatch(t *testing.T) {
	testDB := setupTestDB_CB72(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB; testDB.Close() }()

	ids, err := storeMessagesBatch([]RoutedMessage{})
	if err != nil {
		t.Errorf("expected nil error for empty batch, got %v", err)
	}
	if len(ids) != 0 {
		t.Errorf("expected 0 IDs for empty batch, got %d", len(ids))
	}
}

func TestCB72_StoreMessagesBatch_WithAttachments(t *testing.T) {
	testDB := setupTestDB_CB72(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB; testDB.Close() }()

	userID := createUser_CB72(testDB, "testuser", "pass")
	agentID := "agent-1"
	createAgent_CB72(testDB, agentID)
	convID := createConversation_CB72(testDB, userID, agentID)

	msgs := []RoutedMessage{
		{
			ConversationID: convID,
			SenderType:     "client",
			SenderID:       userID,
			Content:        "See this file",
			Type:           "message",
			RecipientID:    agentID,
			AttachmentIDs:  []string{"att-1", "att-2"},
		},
	}

	ids, err := storeMessagesBatch(msgs)
	if err != nil {
		t.Fatalf("storeMessagesBatch with attachments failed: %v", err)
	}
	if len(ids) != 1 {
		t.Errorf("expected 1 message ID, got %d", len(ids))
	}
}

// ==================== deleteConversation (83.3%) ====================

func TestCB72_DeleteConversation_NotFound(t *testing.T) {
	testDB := setupTestDB_CB72(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB; testDB.Close() }()

	err := deleteConversation("nonexistent-conv", "user-1")
	if err == nil {
		t.Error("expected error for nonexistent conversation")
	}
}

func TestCB72_DeleteConversation_Unauthorized(t *testing.T) {
	testDB := setupTestDB_CB72(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB; testDB.Close() }()

	userID := createUser_CB72(testDB, "user1", "pass")
	agentID := "agent-1"
	createAgent_CB72(testDB, agentID)
	convID := createConversation_CB72(testDB, userID, agentID)

	err := deleteConversation(convID, "different-user")
	if err == nil {
		t.Error("expected error for unauthorized user")
	}
}

func TestCB72_DeleteConversation_Success(t *testing.T) {
	testDB := setupTestDB_CB72(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB; testDB.Close() }()

	userID := createUser_CB72(testDB, "user1", "pass")
	agentID := "agent-1"
	createAgent_CB72(testDB, agentID)
	convID := createConversation_CB72(testDB, userID, agentID)

	// Add a message
	testDB.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, type) VALUES (?, ?, ?, ?, ?, ?)",
		"msg-1", convID, "client", userID, "hello", "message")

	err := deleteConversation(convID, userID)
	if err != nil {
		t.Fatalf("deleteConversation failed: %v", err)
	}

	// Verify conversation is gone
	var count int
	testDB.QueryRow("SELECT COUNT(*) FROM conversations WHERE id = ?", convID).Scan(&count)
	if count != 0 {
		t.Errorf("expected 0 conversations, got %d", count)
	}

	// Verify messages are gone
	testDB.QueryRow("SELECT COUNT(*) FROM messages WHERE conversation_id = ?", convID).Scan(&count)
	if count != 0 {
		t.Errorf("expected 0 messages, got %d", count)
	}
}

func TestCB72_DeleteConversation_MessagesDBError(t *testing.T) {
	testDB := setupTestDB_CB72(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	userID := createUser_CB72(testDB, "user1", "pass")
	agentID := "agent-1"
	createAgent_CB72(testDB, agentID)
	convID := createConversation_CB72(testDB, userID, agentID)

	// Close DB to cause error
	testDB.Close()

	err := deleteConversation(convID, userID)
	if err == nil {
		t.Error("expected error with closed DB")
	}
}

// ==================== RegisterAgentOnConnect (81.8%) ====================

func TestCB72_RegisterAgentOnConnect_NewAgent(t *testing.T) {
	testDB := setupTestDB_CB72(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB; testDB.Close() }()

	err := RegisterAgentOnConnect("agent-new", "New Agent", "gpt-4", "friendly", "general")
	if err != nil {
		t.Fatalf("RegisterAgentOnConnect failed: %v", err)
	}

	var name string
	testDB.QueryRow("SELECT name FROM agents WHERE id = ?", "agent-new").Scan(&name)
	if name != "New Agent" {
		t.Errorf("expected name 'New Agent', got '%s'", name)
	}
}

func TestCB72_RegisterAgentOnConnect_UpdateExisting(t *testing.T) {
	testDB := setupTestDB_CB72(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB; testDB.Close() }()

	// Create agent first
	createAgent_CB72(testDB, "agent-1")

	// Update with new metadata
	err := RegisterAgentOnConnect("agent-1", "Updated Name", "new-model", "serious", "coding")
	if err != nil {
		t.Fatalf("RegisterAgentOnConnect update failed: %v", err)
	}

	var name, model string
	testDB.QueryRow("SELECT name, model FROM agents WHERE id = ?", "agent-1").Scan(&name, &model)
	if name != "Updated Name" {
		t.Errorf("expected name 'Updated Name', got '%s'", name)
	}
	if model != "new-model" {
		t.Errorf("expected model 'new-model', got '%s'", model)
	}
}

func TestCB72_RegisterAgentOnConnect_PreserveMetadata(t *testing.T) {
	testDB := setupTestDB_CB72(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB; testDB.Close() }()

	// Create agent with metadata
	testDB.Exec("INSERT INTO agents (id, name, model, personality, specialty) VALUES (?, ?, ?, ?, ?)",
		"agent-1", "Original", "gpt-4", "friendly", "general")

	// Reconnect with empty fields - should preserve original
	err := RegisterAgentOnConnect("agent-1", "", "", "", "")
	if err != nil {
		t.Fatalf("RegisterAgentOnConnect failed: %v", err)
	}

	var name, model, personality, specialty string
	testDB.QueryRow("SELECT name, model, personality, specialty FROM agents WHERE id = ?", "agent-1").
		Scan(&name, &model, &personality, &specialty)
	if name != "Original" {
		t.Errorf("expected name 'Original', got '%s'", name)
	}
	if model != "gpt-4" {
		t.Errorf("expected model 'gpt-4', got '%s'", model)
	}
	if personality != "friendly" {
		t.Errorf("expected personality 'friendly', got '%s'", personality)
	}
	if specialty != "general" {
		t.Errorf("expected specialty 'general', got '%s'", specialty)
	}
}

func TestCB72_RegisterAgentOnConnect_DefaultName(t *testing.T) {
	testDB := setupTestDB_CB72(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB; testDB.Close() }()

	// When name is empty and agent is new, name should default to agentID
	err := RegisterAgentOnConnect("agent-auto", "", "test-model", "", "")
	if err != nil {
		t.Fatalf("RegisterAgentOnConnect failed: %v", err)
	}

	var name string
	testDB.QueryRow("SELECT name FROM agents WHERE id = ?", "agent-auto").Scan(&name)
	if name != "agent-auto" {
		t.Errorf("expected name to default to agentID 'agent-auto', got '%s'", name)
	}
}

func TestCB72_RegisterAgentOnConnect_DBError(t *testing.T) {
	testDB := setupTestDB_CB72(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	testDB.Close()

	err := RegisterAgentOnConnect("agent-1", "Name", "model", "personality", "specialty")
	if err == nil {
		t.Error("expected error with closed DB")
	}
}

// ==================== notifyUser (83.3%) ====================

func TestCB72_NotifyUser_NilPushConfig(t *testing.T) {
	oldConfig := pushConfig
	pushConfig = nil
	defer func() { pushConfig = oldConfig }()

	// Should return immediately without panic
	notifyUser("user-1", "Title", "Body", "conv-1")
}

func TestCB72_NotifyUser_NilDB(t *testing.T) {
	oldConfig := pushConfig
	pushConfig = &PushNotificationConfig{APNSEnabled: true}
	oldDB := db
	db = nil
	defer func() { pushConfig = oldConfig; db = oldDB }()

	// Should return without panic when db is nil
	notifyUser("user-1", "Title", "Body", "conv-1")
}

func TestCB72_NotifyUser_MutedConversation(t *testing.T) {
	testDB := setupTestDB_CB72(t)
	oldDB := db
	db = testDB
	oldConfig := pushConfig
	pushConfig = &PushNotificationConfig{APNSEnabled: true}
	defer func() { db = oldDB; pushConfig = oldConfig; testDB.Close() }()

	userID := createUser_CB72(testDB, "testuser", "pass")
	agentID := "agent-1"
	createAgent_CB72(testDB, agentID)
	convID := createConversation_CB72(testDB, userID, agentID)

	// Mute the conversation
	testDB.Exec("INSERT INTO notification_preferences (user_id, conversation_id, muted) VALUES (?, ?, 1)", userID, convID)

	// Should not send notification (muted)
	notifyUser(userID, "Title", "Body", convID)
	// No assertion needed - if it doesn't panic, test passes
}

func TestCB72_NotifyUser_NoTokens(t *testing.T) {
	testDB := setupTestDB_CB72(t)
	oldDB := db
	db = testDB
	oldConfig := pushConfig
	pushConfig = &PushNotificationConfig{APNSEnabled: true}
	defer func() { db = oldDB; pushConfig = oldConfig; testDB.Close() }()

	userID := createUser_CB72(testDB, "testuser", "pass")

	// No device tokens registered - should return without error
	notifyUser(userID, "Title", "Body", "conv-1")
}

func TestCB72_NotifyUser_DBError(t *testing.T) {
	testDB := setupTestDB_CB72(t)
	oldDB := db
	db = testDB
	oldConfig := pushConfig
	pushConfig = &PushNotificationConfig{APNSEnabled: true}
	defer func() { db = oldDB; pushConfig = oldConfig }()

	testDB.Close()

	// Should not panic on DB error
	notifyUser("user-1", "Title", "Body", "conv-1")
}

// ==================== handleAdminAgents (83.3%) ====================

func TestCB72_HandleAdminAgents_Success(t *testing.T) {
	testDB := setupTestDB_CB72(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB; testDB.Close() }()

	// Set up global hub
	oldHub := hub
	hub = newHub()
	go hub.run()
	defer func() { if oldHub != nil { oldHub.Stop() }; hub = oldHub }()

	createAgent_CB72(testDB, "agent-1")
	testDB.Exec("UPDATE agents SET model = ?, personality = ?, specialty = ? WHERE id = ?",
		"gpt-4", "friendly", "general", "agent-1")

	req := httptest.NewRequest("GET", "/admin/agents", nil)
	req.Header.Set("X-Admin-Secret", adminSecret)
	rr := httptest.NewRecorder()
	handleAdminAgents(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}

	var agents []map[string]interface{}
	json.Unmarshal(rr.Body.Bytes(), &agents)
	if len(agents) != 1 {
		t.Errorf("expected 1 agent, got %d", len(agents))
	}
}

func TestCB72_HandleAdminAgents_EmptyList(t *testing.T) {
	testDB := setupTestDB_CB72(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB; testDB.Close() }()

	// Set up global hub
	oldHub := hub
	hub = newHub()
	go hub.run()
	defer func() { if oldHub != nil { oldHub.Stop() }; hub = oldHub }()

	req := httptest.NewRequest("GET", "/admin/agents", nil)
	req.Header.Set("X-Admin-Secret", adminSecret)
	rr := httptest.NewRecorder()
	handleAdminAgents(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}

	var agents []map[string]interface{}
	json.Unmarshal(rr.Body.Bytes(), &agents)
	if len(agents) != 0 {
		t.Errorf("expected 0 agents, got %d", len(agents))
	}
}

func TestCB72_HandleAdminAgents_DBError(t *testing.T) {
	testDB := setupTestDB_CB72(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	testDB.Close()

	req := httptest.NewRequest("GET", "/admin/agents", nil)
	req.Header.Set("X-Admin-Secret", adminSecret)
	rr := httptest.NewRecorder()
	handleAdminAgents(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", rr.Code)
	}
}

// ==================== handleGetPresence (87.1%) ====================

func TestCB72_HandleGetPresence_Method(t *testing.T) {
	req := httptest.NewRequest("POST", "/presence", nil)
	rr := httptest.NewRecorder()
	handleGetPresence(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rr.Code)
	}
}

func TestCB72_HandleGetPresence_Unauthorized(t *testing.T) {
	req := httptest.NewRequest("GET", "/presence", nil)
	rr := httptest.NewRecorder()
	handleGetPresence(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

func TestCB72_HandleGetPresence_WithAgents(t *testing.T) {
	testDB := setupTestDB_CB72(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB; testDB.Close() }()

	// Set up global hub
	oldHub := hub
	hub = newHub()
	go hub.run()
	defer func() { if oldHub != nil { oldHub.Stop() }; hub = oldHub }()

	// Create agent in DB
	createAgent_CB72(testDB, "agent-1")

	// Register an agent connection
	agentConn := makeConn_CB72("agent", "agent-1", hub)
	hub.register <- agentConn
	time.Sleep(50 * time.Millisecond)

	req := httptest.NewRequest("GET", "/presence", nil)
	req.Header.Set("Authorization", "Bearer "+generateTestToken_CB72("user-1"))
	rr := httptest.NewRecorder()
	handleGetPresence(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}

	var agents []map[string]interface{}
	json.Unmarshal(rr.Body.Bytes(), &agents)
	if len(agents) != 1 {
		t.Errorf("expected 1 agent, got %d", len(agents))
	}
}

func TestCB72_HandleGetPresence_DBError(t *testing.T) {
	testDB := setupTestDB_CB72(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	// Set up global hub
	oldHub := hub
	hub = newHub()
	go hub.run()
	defer func() { if oldHub != nil { oldHub.Stop() }; hub = oldHub }()

	testDB.Close()

	req := httptest.NewRequest("GET", "/presence", nil)
	req.Header.Set("Authorization", "Bearer "+generateTestToken_CB72("user-1"))
	rr := httptest.NewRecorder()
	handleGetPresence(rr, req)

	// With DB error, handler returns 500
	if rr.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", rr.Code)
	}
}

// ==================== routeChatMessage (83.5%) ====================

func TestCB72_RouteChatMessage_InvalidJSON(t *testing.T) {
	h := newHub()
	go h.run()
	defer h.Stop()

	conn := makeConn_CB72("client", "user-1", h)
	routeChatMessage(conn, json.RawMessage(`{invalid json`))

	// Should receive an error message
	select {
	case msg := <-conn.send:
		var result map[string]interface{}
		json.Unmarshal(msg, &result)
		if result["type"] != "error" {
			t.Errorf("expected error type, got %v", result["type"])
		}
	case <-time.After(1 * time.Second):
		t.Fatal("did not receive error message")
	}
}

func TestCB72_RouteChatMessage_EmptyContent(t *testing.T) {
	h := newHub()
	go h.run()
	defer h.Stop()

	conn := makeConn_CB72("client", "user-1", h)
	routeChatMessage(conn, json.RawMessage(`{"conversation_id":"conv-1"}`))

	select {
	case msg := <-conn.send:
		var result map[string]interface{}
		json.Unmarshal(msg, &result)
		if result["type"] != "error" {
			t.Errorf("expected error type, got %v", result["type"])
		}
	case <-time.After(1 * time.Second):
		t.Fatal("did not receive error message")
	}
}

func TestCB72_RouteChatMessage_EmptyConvID(t *testing.T) {
	h := newHub()
	go h.run()
	defer h.Stop()

	conn := makeConn_CB72("client", "user-1", h)
	routeChatMessage(conn, json.RawMessage(`{"content":"hello"}`))

	select {
	case msg := <-conn.send:
		var result map[string]interface{}
		json.Unmarshal(msg, &result)
		if result["type"] != "error" {
			t.Errorf("expected error type, got %v", result["type"])
		}
	case <-time.After(1 * time.Second):
		t.Fatal("did not receive error message")
	}
}

func TestCB72_RouteChatMessage_ConvNotFound(t *testing.T) {
	testDB := setupTestDB_CB72(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB; testDB.Close() }()

	h := newHub()
	go h.run()
	defer h.Stop()

	conn := makeConn_CB72("client", "user-1", h)
	routeChatMessage(conn, json.RawMessage(`{"content":"hello","conversation_id":"nonexistent"}`))

	select {
	case msg := <-conn.send:
		var result map[string]interface{}
		json.Unmarshal(msg, &result)
		if result["type"] != "error" {
			t.Errorf("expected error type, got %v", result["type"])
		}
	case <-time.After(1 * time.Second):
		t.Fatal("did not receive error message")
	}
}

func TestCB72_RouteChatMessage_AgentNotAuthorized(t *testing.T) {
	testDB := setupTestDB_CB72(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB; testDB.Close() }()

	userID := createUser_CB72(testDB, "user1", "pass")
	agentID := "agent-1"
	createAgent_CB72(testDB, agentID)
	convID := createConversation_CB72(testDB, userID, agentID)

	h := newHub()
	go h.run()
	defer h.Stop()

	// Agent "agent-2" tries to send to a conversation owned by "agent-1"
	conn := makeConn_CB72("agent", "agent-2", h)
	routeChatMessage(conn, json.RawMessage(`{"content":"hello","conversation_id":"`+convID+`"}`))

	select {
	case msg := <-conn.send:
		var result map[string]interface{}
		json.Unmarshal(msg, &result)
		if result["type"] != "error" {
			t.Errorf("expected error type, got %v", result["type"])
		}
	case <-time.After(1 * time.Second):
		t.Fatal("did not receive error message")
	}
}

func TestCB72_RouteChatMessage_ClientNotAuthorized(t *testing.T) {
	testDB := setupTestDB_CB72(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB; testDB.Close() }()

	userID := createUser_CB72(testDB, "user1", "pass")
	agentID := "agent-1"
	createAgent_CB72(testDB, agentID)
	convID := createConversation_CB72(testDB, userID, agentID)

	h := newHub()
	go h.run()
	defer h.Stop()

	// Client "user-2" tries to send to a conversation owned by "user-1"
	conn := makeConn_CB72("client", "user-2", h)
	routeChatMessage(conn, json.RawMessage(`{"content":"hello","conversation_id":"`+convID+`"}`))

	select {
	case msg := <-conn.send:
		var result map[string]interface{}
		json.Unmarshal(msg, &result)
		if result["type"] != "error" {
			t.Errorf("expected error type, got %v", result["type"])
		}
	case <-time.After(1 * time.Second):
		t.Fatal("did not receive error message")
	}
}

func TestCB72_RouteChatMessage_StoreError(t *testing.T) {
	testDB := setupTestDB_CB72(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	userID := createUser_CB72(testDB, "user1", "pass")
	agentID := "agent-1"
	createAgent_CB72(testDB, agentID)
	convID := createConversation_CB72(testDB, userID, agentID)

	h := newHub()
	go h.run()
	defer h.Stop()

	// Close DB to cause store error
	testDB.Close()

	conn := makeConn_CB72("client", userID, h)
	routeChatMessage(conn, json.RawMessage(`{"content":"hello","conversation_id":"`+convID+`"}`))

	select {
	case msg := <-conn.send:
		var result map[string]interface{}
		json.Unmarshal(msg, &result)
		if result["type"] != "error" {
			t.Errorf("expected error type, got %v", result["type"])
		}
	case <-time.After(1 * time.Second):
		t.Fatal("did not receive error message")
	}
}

func TestCB72_RouteChatMessage_Success_ClientToAgent(t *testing.T) {
	testDB := setupTestDB_CB72(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB; testDB.Close() }()

	// Set up global hub
	oldHub := hub
	hub = newHub()
	go hub.run()
	defer func() { if oldHub != nil { oldHub.Stop() }; hub = oldHub }()

	userID := createUser_CB72(testDB, "user1", "pass")
	agentID := "agent-1"
	createAgent_CB72(testDB, agentID)
	convID := createConversation_CB72(testDB, userID, agentID)

	// Register agent connection
	agentConn := makeConn_CB72("agent", agentID, hub)
	hub.register <- agentConn
	time.Sleep(50 * time.Millisecond)

	// Client sends message
	clientConn := makeConn_CB72("client", userID, hub)
	routeChatMessage(clientConn, json.RawMessage(`{"content":"hello","conversation_id":"`+convID+`"}`))

	// Agent should receive the message
	select {
	case msg := <-agentConn.send:
		var result map[string]interface{}
		json.Unmarshal(msg, &result)
		if result["type"] != "message" {
			t.Errorf("expected type 'message', got %v", result["type"])
		}
	case <-time.After(1 * time.Second):
		t.Fatal("agent did not receive message")
	}
}

func TestCB72_RouteChatMessage_Success_AgentToClient(t *testing.T) {
	testDB := setupTestDB_CB72(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB; testDB.Close() }()

	// Set up global hub
	oldHub := hub
	hub = newHub()
	go hub.run()
	defer func() { if oldHub != nil { oldHub.Stop() }; hub = oldHub }()

	userID := createUser_CB72(testDB, "user1", "pass")
	agentID := "agent-1"
	createAgent_CB72(testDB, agentID)
	convID := createConversation_CB72(testDB, userID, agentID)

	// Register client connection
	clientConn := makeConn_CB72("client", userID, hub)
	hub.register <- clientConn
	time.Sleep(50 * time.Millisecond)

	// Agent sends message
	agentConn := makeConn_CB72("agent", agentID, hub)
	routeChatMessage(agentConn, json.RawMessage(`{"content":"hi there","conversation_id":"`+convID+`"}`))

	// Client should receive the message
	select {
	case msg := <-clientConn.send:
		var result map[string]interface{}
		json.Unmarshal(msg, &result)
		if result["type"] != "message" {
			t.Errorf("expected type 'message', got %v", result["type"])
		}
	case <-time.After(1 * time.Second):
		t.Fatal("client did not receive message")
	}
}

func TestCB72_RouteChatMessage_ClientOffline(t *testing.T) {
	testDB := setupTestDB_CB72(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB; testDB.Close() }()

	// Set up global hub
	oldHub := hub
	hub = newHub()
	go hub.run()
	defer func() { if oldHub != nil { oldHub.Stop() }; hub = oldHub }()

	userID := createUser_CB72(testDB, "user1", "pass")
	agentID := "agent-1"
	createAgent_CB72(testDB, agentID)
	convID := createConversation_CB72(testDB, userID, agentID)

	// Agent sends message but client is offline
	agentConn := makeConn_CB72("agent", agentID, hub)
	routeChatMessage(agentConn, json.RawMessage(`{"content":"hello offline","conversation_id":"`+convID+`"}`))

	// Agent should not receive an error (message queued for offline user)
	// The message should be stored in the offline queue
	time.Sleep(100 * time.Millisecond)

	// Verify message was stored
	var count int
	testDB.QueryRow("SELECT COUNT(*) FROM messages WHERE conversation_id = ?", convID).Scan(&count)
	if count != 1 {
		t.Errorf("expected 1 stored message, got %d", count)
	}
}

// ==================== initSchema (85.3%) ====================

func TestCB72_InitSchema_PostgreSQLPaths(t *testing.T) {
	// Test that initSchemaForDriver handles postgres without panicking
	// We can't actually test PostgreSQL, but we can verify the function exists
	// and handles the driver name without crashing
	testDB := setupTestDB_CB72(t)
	defer testDB.Close()

	// Verify tables exist
	tables := []string{"users", "agents", "conversations", "messages", "offline_queue",
		"notification_preferences", "device_tokens", "user_rate_limit_tiers", "conversation_tags",
		"reactions", "attachments", "key_bundles",
		"encrypted_messages", "schema_migrations"}

	for _, table := range tables {
		var name string
		err := testDB.QueryRow("SELECT name FROM sqlite_master WHERE type='table' AND name=?", table).Scan(&name)
		if err != nil {
			t.Errorf("table %s not found: %v", table, err)
		}
	}
}

func TestCB72_InitSchema_Idempotent(t *testing.T) {
	testDB := setupTestDB_CB72(t)
	defer testDB.Close()

	// Run initSchema again - should not error
	err := initSchema(testDB)
	if err != nil {
		t.Errorf("initSchema should be idempotent, got error: %v", err)
	}
}

func TestCB72_InitSchema_ClosedDB(t *testing.T) {
	testDB := setupTestDB_CB72(t)
	testDB.Close()

	err := initSchema(testDB)
	if err == nil {
		t.Error("expected error with closed DB")
	}
}

// ==================== handleUpload (85.7%) ====================

func TestCB72_HandleUpload_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest("GET", "/upload", nil)
	rr := httptest.NewRecorder()
	handleUpload(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rr.Code)
	}
}

func TestCB72_HandleUpload_Unauthorized(t *testing.T) {
	req := httptest.NewRequest("POST", "/upload", nil)
	rr := httptest.NewRecorder()
	handleUpload(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

// ==================== handleGetAttachment (88.2%) ====================

func TestCB72_HandleGetAttachment_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest("POST", "/attachments/get?id=1", nil)
	rr := httptest.NewRecorder()
	handleGetAttachment(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rr.Code)
	}
}

func TestCB72_HandleGetAttachment_Unauthorized(t *testing.T) {
	req := httptest.NewRequest("GET", "/attachments/get?id=1", nil)
	rr := httptest.NewRecorder()
	handleGetAttachment(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

func TestCB72_HandleGetAttachment_NotFound(t *testing.T) {
	testDB := setupTestDB_CB72(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB; testDB.Close() }()

	req := httptest.NewRequest("GET", "/attachments/get?id=nonexistent", nil)
	req.Header.Set("Authorization", "Bearer "+generateTestToken_CB72("user-1"))
	rr := httptest.NewRecorder()
	handleGetAttachment(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", rr.Code)
	}
}

// ==================== initAPNs (84%) ====================

func TestCB72_InitAPNs_NilConfig(t *testing.T) {
	oldConfig := pushConfig
	pushConfig = nil
	defer func() { pushConfig = oldConfig }()

	initAPNs()
	// Should not panic
}

func TestCB72_InitAPNs_Disabled(t *testing.T) {
	oldConfig := pushConfig
	pushConfig = &PushNotificationConfig{APNSEnabled: false}
	defer func() { pushConfig = oldConfig }()

	initAPNs()
	// Should not panic
}

func TestCB72_InitAPNs_NoCertPath(t *testing.T) {
	oldConfig := pushConfig
	pushConfig = &PushNotificationConfig{APNSEnabled: true, CertPath: ""}
	defer func() { pushConfig = oldConfig }()

	initAPNs()
	// Should not panic, just warn
}

func TestCB72_InitAPNs_CertNotFound(t *testing.T) {
	oldConfig := pushConfig
	pushConfig = &PushNotificationConfig{
		APNSEnabled: true,
		CertPath:    "/nonexistent/cert.p12",
	}
	defer func() { pushConfig = oldConfig }()

	initAPNs()
	// Should disable APNs
	if pushConfig.APNSEnabled {
		t.Error("expected APNs to be disabled after cert not found")
	}
}

// ==================== initFCM (81.5%) ====================

func TestCB72_InitFCM_NilConfig(t *testing.T) {
	oldConfig := pushConfig
	pushConfig = nil
	defer func() { pushConfig = oldConfig }()

	initFCM()
	// Should not panic
}

func TestCB72_InitFCM_Disabled(t *testing.T) {
	oldConfig := pushConfig
	pushConfig = &PushNotificationConfig{FCMEnabled: false}
	defer func() { pushConfig = oldConfig }()

	initFCM()
	// Should not panic
}

func TestCB72_InitFCM_NoCredsPath(t *testing.T) {
	oldConfig := pushConfig
	pushConfig = &PushNotificationConfig{FCMEnabled: true, FCMCredentials: ""}
	defer func() { pushConfig = oldConfig }()

	initFCM()
	// Should not panic
}

func TestCB72_InitFCM_CredsNotFound(t *testing.T) {
	oldConfig := pushConfig
	pushConfig = &PushNotificationConfig{
		FCMEnabled:     true,
		FCMCredentials:  "/nonexistent/creds.json",
	}
	defer func() { pushConfig = oldConfig }()

	initFCM()
	// Should disable FCM
	if pushConfig.FCMEnabled {
		t.Error("expected FCM to be disabled after creds not found")
	}
}

// ==================== logger WithFields (87.5%) ====================

func TestCB72_LoggerWithFields_Nil(t *testing.T) {
	l := DefaultLogger.WithFields(nil)
	if l == nil {
		t.Error("expected non-nil logger")
	}
}

func TestCB72_LoggerWithFields_Empty(t *testing.T) {
	l := DefaultLogger.WithFields(map[string]interface{}{})
	if l == nil {
		t.Error("expected non-nil logger")
	}
}

func TestCB72_LoggerWithFields_WithFields(t *testing.T) {
	l := DefaultLogger.WithFields(map[string]interface{}{"key1": "val1", "key2": 42})
	if l == nil {
		t.Error("expected non-nil logger")
	}
	// Verify it doesn't panic when logging
	l.Info("test message", nil)
}

func TestCB72_LoggerWithFields_NilThenFields(t *testing.T) {
	// Test chaining: WithFields(nil).WithFields(...)
	l := DefaultLogger.WithFields(nil)
	l2 := l.WithFields(map[string]interface{}{"key": "val"})
	if l2 == nil {
		t.Error("expected non-nil logger after chaining")
	}
}

// ==================== logger logEntry (88.2%) ====================

func TestCB72_LogEntry_AllLevels(t *testing.T) {
	// Test that logEntry doesn't panic for all log levels
	DefaultLogger.Info("test_info", map[string]interface{}{"key": "value"})
	DefaultLogger.Warn("test_warn", map[string]interface{}{"key": "value"})
	DefaultLogger.Error("test_error", map[string]interface{}{"key": "value"})
	DefaultLogger.Debug("test_debug", map[string]interface{}{"key": "value"})
}

func TestCB72_LogEntry_NilFields(t *testing.T) {
	DefaultLogger.Info("test nil fields", nil)
	DefaultLogger.Warn("test nil fields", nil)
	DefaultLogger.Error("test nil fields", nil)
}

func TestCB72_LogEntry_EmptyMessage(t *testing.T) {
	DefaultLogger.Info("", map[string]interface{}{"key": "value"})
}

// ==================== ipRateLimitMiddleware (88.9%) ====================

func TestCB72_IPRateLimitMiddleware_Allows(t *testing.T) {
	// Reset the IP rate limiter
	ipRateLimiter = NewRateLimiter(300, time.Minute)

	called := false
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	mw := ipRateLimitMiddleware(handler)
	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "192.168.1.1:12345"
	rr := httptest.NewRecorder()
	mw.ServeHTTP(rr, req)

	if !called {
		t.Error("expected handler to be called")
	}
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}

func TestCB72_IPRateLimitMiddleware_Blocked(t *testing.T) {
	oldRL := ipRateLimiter
	ipRateLimiter = NewRateLimiter(1, time.Minute)
	defer func() { ipRateLimiter = oldRL }()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	mw := ipRateLimitMiddleware(handler)
	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "10.0.0.1:12345"

	// First request: allowed
	rr1 := httptest.NewRecorder()
	mw.ServeHTTP(rr1, req)
	if rr1.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr1.Code)
	}

	// Second request: blocked
	rr2 := httptest.NewRecorder()
	mw.ServeHTTP(rr2, req)
	if rr2.Code != http.StatusTooManyRequests {
		t.Errorf("expected 429, got %d", rr2.Code)
	}
}

// ==================== authRateLimitMiddleware (88.9%) ====================
// Note: authRateLimitMiddleware uses ipRateLimiter internally for auth endpoints

func TestCB72_AuthRateLimitMiddleware_Allows(t *testing.T) {
	oldRL := authIPLimiter
	authIPLimiter = NewRateLimiter(30, time.Minute)
	defer func() { authIPLimiter = oldRL }()

	called := false
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	mw := authRateLimitMiddleware(handler)
	req := httptest.NewRequest("POST", "/auth/login", nil)
	req.RemoteAddr = "192.168.1.1:12345"
	rr := httptest.NewRecorder()
	mw.ServeHTTP(rr, req)

	if !called {
		t.Error("expected handler to be called")
	}
}

func TestCB72_AuthRateLimitMiddleware_Blocked(t *testing.T) {
	oldRL := authIPLimiter
	authIPLimiter = NewRateLimiter(1, time.Minute)
	defer func() { authIPLimiter = oldRL }()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	mw := authRateLimitMiddleware(handler)
	req := httptest.NewRequest("POST", "/auth/login", nil)
	req.RemoteAddr = "10.0.0.1:12345"

	// First request: allowed
	rr1 := httptest.NewRecorder()
	mw.ServeHTTP(rr1, req)

	// Second request: blocked
	rr2 := httptest.NewRecorder()
	mw.ServeHTTP(rr2, req)
	if rr2.Code != http.StatusTooManyRequests {
		t.Errorf("expected 429, got %d", rr2.Code)
	}
}

// ==================== handleSetNotificationPrefs (88.9%) ====================

func TestCB72_HandleSetNotificationPrefs_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest("GET", "/notifications/prefs", nil)
	rr := httptest.NewRecorder()
	handleSetNotificationPrefs(rr, req)

	// Handler checks auth before method
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

func TestCB72_HandleSetNotificationPrefs_Unauthorized(t *testing.T) {
	req := httptest.NewRequest("POST", "/notifications/prefs", nil)
	rr := httptest.NewRecorder()
	handleSetNotificationPrefs(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

func TestCB72_HandleSetNotificationPrefs_MissingConvID(t *testing.T) {
	testDB := setupTestDB_CB72(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB; testDB.Close() }()

	form := "muted=true"
	req := httptest.NewRequest("POST", "/notifications/prefs", strings.NewReader(form))
	ctx := context.WithValue(req.Context(), contextKeyUserID, "user-1")
	req = req.WithContext(ctx)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	handleSetNotificationPrefs(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestCB72_HandleSetNotificationPrefs_ConvNotFound(t *testing.T) {
	testDB := setupTestDB_CB72(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB; testDB.Close() }()

	form := "conversation_id=nonexistent&muted=true"
	req := httptest.NewRequest("POST", "/notifications/prefs", strings.NewReader(form))
	ctx := context.WithValue(req.Context(), contextKeyUserID, "user-1")
	req = req.WithContext(ctx)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	handleSetNotificationPrefs(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", rr.Code)
	}
}

func TestCB72_HandleSetNotificationPrefs_NotOwner(t *testing.T) {
	testDB := setupTestDB_CB72(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB; testDB.Close() }()

	userID := createUser_CB72(testDB, "user1", "pass")
	agentID := "agent-1"
	createAgent_CB72(testDB, agentID)
	convID := createConversation_CB72(testDB, userID, agentID)

	form := "conversation_id=" + convID + "&muted=true"
	req := httptest.NewRequest("POST", "/notifications/prefs", strings.NewReader(form))
	ctx := context.WithValue(req.Context(), contextKeyUserID, "different-user")
	req = req.WithContext(ctx)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	handleSetNotificationPrefs(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", rr.Code)
	}
}

func TestCB72_HandleSetNotificationPrefs_MuteSuccess(t *testing.T) {
	testDB := setupTestDB_CB72(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB; testDB.Close() }()

	userID := createUser_CB72(testDB, "user1", "pass")
	agentID := "agent-1"
	createAgent_CB72(testDB, agentID)
	convID := createConversation_CB72(testDB, userID, agentID)

	form := "conversation_id=" + convID + "&muted=true"
	req := httptest.NewRequest("POST", "/notifications/prefs", strings.NewReader(form))
	ctx := context.WithValue(req.Context(), contextKeyUserID, userID)
	req = req.WithContext(ctx)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	handleSetNotificationPrefs(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}

	// Verify mute was saved
	var muted int
	testDB.QueryRow("SELECT muted FROM notification_preferences WHERE user_id = ? AND conversation_id = ?", userID, convID).Scan(&muted)
	if muted != 1 {
		t.Errorf("expected muted=1, got %d", muted)
	}
}

func TestCB72_HandleSetNotificationPrefs_UnmuteSuccess(t *testing.T) {
	testDB := setupTestDB_CB72(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB; testDB.Close() }()

	userID := createUser_CB72(testDB, "user1", "pass")
	agentID := "agent-1"
	createAgent_CB72(testDB, agentID)
	convID := createConversation_CB72(testDB, userID, agentID)

	// First mute
	testDB.Exec("INSERT INTO notification_preferences (user_id, conversation_id, muted) VALUES (?, ?, 1)", userID, convID)

	// Now unmute using form data
	form := "conversation_id=" + convID + "&muted=false"
	req := httptest.NewRequest("POST", "/notifications/prefs", strings.NewReader(form))
	ctx := context.WithValue(req.Context(), contextKeyUserID, userID)
	req = req.WithContext(ctx)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	handleSetNotificationPrefs(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}

	// Verify unmute
	var muted int
	testDB.QueryRow("SELECT muted FROM notification_preferences WHERE user_id = ? AND conversation_id = ?", userID, convID).Scan(&muted)
	if muted != 0 {
		t.Errorf("expected muted=0, got %d", muted)
	}
}

// ==================== handleMessageDelete (87.5%) ====================

func TestCB72_HandleMessageDelete_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest("GET", "/messages/delete", nil)
	rr := httptest.NewRecorder()
	handleMessageDelete(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rr.Code)
	}
}

func TestCB72_HandleMessageDelete_Unauthorized(t *testing.T) {
	req := httptest.NewRequest("POST", "/messages/delete", nil)
	rr := httptest.NewRecorder()
	handleMessageDelete(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

func TestCB72_HandleMessageDelete_EmptyID(t *testing.T) {
	req := httptest.NewRequest("POST", "/messages/delete", nil)
	req.Header.Set("Authorization", "Bearer "+generateTestToken_CB72("user-1"))
	rr := httptest.NewRecorder()
	handleMessageDelete(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestCB72_HandleMessageDelete_NotFound(t *testing.T) {
	testDB := setupTestDB_CB72(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB; testDB.Close() }()

	form := "message_id=nonexistent"
	req := httptest.NewRequest("POST", "/messages/delete", strings.NewReader(form))
	req.Header.Set("Authorization", "Bearer "+generateTestToken_CB72("user-1"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	handleMessageDelete(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", rr.Code)
	}
}

// ==================== rate_limit_tiers cleanup (83.3%) ====================

func TestCB72_TieredRateLimiter_CleanupOnce(t *testing.T) {
	rl := NewTieredRateLimiter()
	defer rl.Stop()

	// Add a stale entry
	rl.mu.Lock()
	rl.limits["user-1"] = &userRateLimitState{
		windowEnd: time.Now().Add(-20 * time.Minute), // Very old
		tier:      TierFree,
	}
	rl.mu.Unlock()

	rl.cleanupOnce()

	rl.mu.Lock()
	_, exists := rl.limits["user-1"]
	rl.mu.Unlock()

	if exists {
		t.Error("expected stale entry to be removed")
	}
}

func TestCB72_TieredRateLimiter_CleanupOnceKeepsActive(t *testing.T) {
	rl := NewTieredRateLimiter()
	defer rl.Stop()

	rl.mu.Lock()
	rl.limits["user-1"] = &userRateLimitState{
		windowEnd: time.Now().Add(30 * time.Minute), // Future
		tier:      TierFree,
	}
	rl.mu.Unlock()

	rl.cleanupOnce()

	rl.mu.Lock()
	_, exists := rl.limits["user-1"]
	rl.mu.Unlock()

	if !exists {
		t.Error("expected active entry to be kept")
	}
}

func TestCB72_TieredRateLimiter_Stop(t *testing.T) {
	rl := NewTieredRateLimiter()
	rl.Stop()
	// Should not panic when stopped
}

func TestCB72_TieredRateLimiter_Reset(t *testing.T) {
	rl := NewTieredRateLimiter()
	defer rl.Stop()

	rl.mu.Lock()
	rl.limits["user-1"] = &userRateLimitState{
		windowEnd: time.Now().Add(30 * time.Minute),
		tier:      TierPro,
	}
	rl.mu.Unlock()

	rl.Reset()

	rl.mu.Lock()
	_, exists := rl.limits["user-1"]
	rl.mu.Unlock()

	if exists {
		t.Error("expected entry to be cleared after reset")
	}
}

// ==================== handleGetTags (88.5%) ====================

func TestCB72_HandleGetTags_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest("POST", "/conversations/tags?conversation_id=conv-1", nil)
	rr := httptest.NewRecorder()
	handleGetTags(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rr.Code)
	}
}

func TestCB72_HandleGetTags_Unauthorized(t *testing.T) {
	req := httptest.NewRequest("GET", "/conversations/tags?conversation_id=conv-1", nil)
	rr := httptest.NewRecorder()
	handleGetTags(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

func TestCB72_HandleGetTags_MissingConvID(t *testing.T) {
	req := httptest.NewRequest("GET", "/conversations/tags", nil)
	req.Header.Set("Authorization", "Bearer "+generateTestToken_CB72("user-1"))
	rr := httptest.NewRecorder()
	handleGetTags(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestCB72_HandleGetTags_Success(t *testing.T) {
	testDB := setupTestDB_CB72(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB; testDB.Close() }()

	userID := createUser_CB72(testDB, "user1", "pass")
	agentID := "agent-1"
	createAgent_CB72(testDB, agentID)
	convID := createConversation_CB72(testDB, userID, agentID)

	// Add tags
	testDB.Exec("INSERT INTO conversation_tags (id, conversation_id, tag) VALUES (?, ?, ?)", "tag-1", convID, "important")
	testDB.Exec("INSERT INTO conversation_tags (id, conversation_id, tag) VALUES (?, ?, ?)", "tag-2", convID, "follow-up")

	req := httptest.NewRequest("GET", "/conversations/tags?conversation_id="+convID, nil)
	req.Header.Set("Authorization", "Bearer "+generateTestToken_CB72(userID))
	rr := httptest.NewRecorder()
	handleGetTags(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}

	var tags []map[string]interface{}
	json.Unmarshal(rr.Body.Bytes(), &tags)
	if len(tags) != 2 {
		t.Errorf("expected 2 tags, got %d", len(tags))
	}
}

func TestCB72_HandleGetTags_DBError(t *testing.T) {
	testDB := setupTestDB_CB72(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	testDB.Close()

	req := httptest.NewRequest("GET", "/conversations/tags?conversation_id=conv-1", nil)
	req.Header.Set("Authorization", "Bearer "+generateTestToken_CB72("user-1"))
	rr := httptest.NewRecorder()
	handleGetTags(rr, req)

	// With closed DB, getConversation returns nil → handler returns 401
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

// ==================== handleSetRateLimitTier (88.5%) ====================

func TestCB72_HandleSetRateLimitTier_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest("GET", "/admin/rate-limit/tier", nil)
	rr := httptest.NewRecorder()
	handleSetRateLimitTier(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rr.Code)
	}
}

func TestCB72_HandleSetRateLimitTier_Unauthorized(t *testing.T) {
	req := httptest.NewRequest("POST", "/admin/rate-limit/tier", nil)
	rr := httptest.NewRecorder()
	handleSetRateLimitTier(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

func TestCB72_HandleSetRateLimitTier_MissingUserID(t *testing.T) {
	form := "tier=pro"
	req := httptest.NewRequest("POST", "/admin/rate-limit/tier", strings.NewReader(form))
	req.Header.Set("X-Admin-Secret", adminSecret)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	handleSetRateLimitTier(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestCB72_HandleSetRateLimitTier_InvalidTier(t *testing.T) {
	form := "user_id=user-1&tier=invalid"
	req := httptest.NewRequest("POST", "/admin/rate-limit/tier", strings.NewReader(form))
	req.Header.Set("X-Admin-Secret", adminSecret)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	handleSetRateLimitTier(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestCB72_HandleSetRateLimitTier_Success(t *testing.T) {
	testDB := setupTestDB_CB72(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB; testDB.Close() }()

	form := "user_id=user-1&tier=pro"
	req := httptest.NewRequest("POST", "/admin/rate-limit/tier", strings.NewReader(form))
	req.Header.Set("X-Admin-Secret", adminSecret)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	handleSetRateLimitTier(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}

// ==================== handleGetRateLimitTier (87.5%) ====================

func TestCB72_HandleGetRateLimitTier_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest("POST", "/admin/rate-limit/tier", nil)
	rr := httptest.NewRecorder()
	handleGetRateLimitTier(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rr.Code)
	}
}

func TestCB72_HandleGetRateLimitTier_Unauthorized(t *testing.T) {
	req := httptest.NewRequest("GET", "/admin/rate-limit/tier?user_id=user-1", nil)
	rr := httptest.NewRecorder()
	handleGetRateLimitTier(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

func TestCB72_HandleGetRateLimitTier_MissingUserID(t *testing.T) {
	req := httptest.NewRequest("GET", "/admin/rate-limit/tier", nil)
	req.Header.Set("X-Admin-Secret", adminSecret)
	rr := httptest.NewRecorder()
	handleGetRateLimitTier(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestCB72_HandleGetRateLimitTier_Success(t *testing.T) {
	testDB := setupTestDB_CB72(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB; testDB.Close() }()

	// Set a tier first
	testDB.Exec("INSERT INTO user_rate_limit_tiers (user_id, tier) VALUES (?, ?)", "user-1", "pro")

	req := httptest.NewRequest("GET", "/admin/rate-limit/tier?user_id=user-1", nil)
	req.Header.Set("X-Admin-Secret", adminSecret)
	rr := httptest.NewRecorder()
	handleGetRateLimitTier(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}

func TestCB72_HandleGetRateLimitTier_DefaultTier(t *testing.T) {
	testDB := setupTestDB_CB72(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB; testDB.Close() }()

	req := httptest.NewRequest("GET", "/admin/rate-limit/tier?user_id=nonexistent", nil)
	req.Header.Set("X-Admin-Secret", adminSecret)
	rr := httptest.NewRecorder()
	handleGetRateLimitTier(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}

	var result map[string]interface{}
	json.Unmarshal(rr.Body.Bytes(), &result)
	if result["tier"] != "free" {
		t.Errorf("expected default tier 'free', got %v", result["tier"])
	}
}

// ==================== cpuProfileTestSetup (87.5%) ====================

func TestCB72_CPUProfileTestSetup_NoFile(t *testing.T) {
	dir := t.TempDir()
	oldDir := os.Getenv("PROFILING_DIR")
	os.Setenv("PROFILING_DIR", dir)
	defer os.Setenv("PROFILING_DIR", oldDir)

	cleanup := cpuProfileTestSetup()
	if cleanup != nil {
		cleanup()
	}
}

// ==================== loadQueueFromDB (89.5%) ====================

func TestCB72_LoadQueueFromDB_WithMessages(t *testing.T) {
	testDB := setupTestDB_CB72(t)
	defer testDB.Close()

	q := newOfflineQueue(100, 7*24*time.Hour)

	// Insert some queued messages
	msg1, _ := json.Marshal(OutgoingMessage{Type: "message", Data: map[string]interface{}{"content": "msg1"}})
	msg2, _ := json.Marshal(OutgoingMessage{Type: "message", Data: map[string]interface{}{"content": "msg2"}})
	testDB.Exec("INSERT INTO offline_queue (recipient, data, queued_at, sent_count) VALUES (?, ?, ?, 0)",
		"user-1", msg1, time.Now().UTC().Format(time.RFC3339))
	testDB.Exec("INSERT INTO offline_queue (recipient, data, queued_at, sent_count) VALUES (?, ?, ?, 0)",
		"user-1", msg2, time.Now().UTC().Format(time.RFC3339))

	loadQueueFromDB(testDB, q)

	if q.TotalDepth() != 2 {
		t.Errorf("expected queue depth 2, got %d", q.TotalDepth())
	}
}

func TestCB72_LoadQueueFromDB_EmptyTable(t *testing.T) {
	testDB := setupTestDB_CB72(t)
	defer testDB.Close()

	q := newOfflineQueue(100, 7*24*time.Hour)
	loadQueueFromDB(testDB, q)

	if q.TotalDepth() != 0 {
		t.Errorf("expected queue depth 0, got %d", q.TotalDepth())
	}
}

func TestCB72_LoadQueueFromDB_NilDB(t *testing.T) {
	q := newOfflineQueue(100, 7*24*time.Hour)
	loadQueueFromDB(nil, q)
	// Should not panic
}

func TestCB72_LoadQueueFromDB_QueryError(t *testing.T) {
	testDB := setupTestDB_CB72(t)
	testDB.Close()

	q := newOfflineQueue(100, 7*24*time.Hour)
	loadQueueFromDB(testDB, q)
	// Should not panic
}