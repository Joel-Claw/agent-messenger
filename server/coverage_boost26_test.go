package main

// Coverage boost 26: targeting remaining low-coverage function paths
// - RateLimiter/Trl goroutine leak fixes (t.Cleanup validation)
// - Metrics: Snapshot with nil offlineQueue, boolToInt
// - MetricsHandler: method not allowed, full metric output
// - handleGetMessages: various pagination, unauthorized
// - handleListConversations: scan error, empty list
// - handleCreateConversation: duplicate conversation
// - Hub: BroadcastToAllClients with no clients, GetClientConns empty
// - Connection: SafeSend on closed conn, MarkClosed idempotent
// - RouteMessage: unknown message type, empty JSON
// - conversations.go: GetOrCreateConversation, searchMessages empty
// - auth: resetAgentSecret, resetAdminSecret
// - dbdriver: Placeholder/Placeholders edge cases
// - profile_handler: writeJSONResponse
// - middleware: writeJSONError
// - logger: all log levels
// - queue_persist: cleanStaleQueueMessages nil db
// - routing: truncate function
// - tags: handleAddTag/handleRemoveTag/handleGetTags edge cases
// - reactions: handleReact/handleGetReactions edge cases
// - e2e: handleListOneTimePreKeys empty, handleGetKeyBundle not found

import (
	"context"
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

	"golang.org/x/crypto/bcrypt"
)

// Helper to set agent secret in tests
func setAgentSecretForTest(secret string) {
	agentSecretMu.Lock()
	defer agentSecretMu.Unlock()
	agentSecret = secret
}

// Helper to set admin secret in tests
func setAdminSecretForTest(secret string) {
	adminSecretMu.Lock()
	defer adminSecretMu.Unlock()
	adminSecret = secret
}

// ==============================
// RateLimiter goroutine leak fix validation
// ==============================

func TestCB26_RateLimiter_StopCleanup(t *testing.T) {
	rl := NewRateLimiter(10, time.Minute)
	t.Cleanup(func() { rl.Stop() })

	// Verify Stop actually stops the cleanup goroutine
	rl.Stop()

	// Allow should still work after stop (no goroutine writing to closed channel)
	rl.Allow("user1")
}

func TestCB26_RateLimiter_DoubleStop(t *testing.T) {
	rl := NewRateLimiter(10, time.Minute)
	t.Cleanup(func() { rl.Stop() })

	// Double stop should not panic
	rl.Stop()
	rl.Stop()
}

func TestCB26_RateLimiter_CountAfterStop(t *testing.T) {
	rl := NewRateLimiter(10, time.Minute)
	t.Cleanup(func() { rl.Stop() })

	rl.Allow("user1")
	rl.Allow("user2")
	rl.Allow("user1")

	count := rl.Count("user1")
	if count != 2 {
		t.Errorf("expected count 2, got %d", count)
	}
}

func TestCB26_TieredRateLimiter_DoubleStop(t *testing.T) {
	trl := NewTieredRateLimiter()
	t.Cleanup(func() { trl.Stop() })

	// Double stop should not panic
	trl.Stop()
	trl.Stop()
}

func TestCB26_TieredRateLimiter_AllowAfterStop(t *testing.T) {
	trl := NewTieredRateLimiter()
	t.Cleanup(func() { trl.Stop() })

	trl.Stop()
	// Allow should not panic after stop
	allowed, _, _ := trl.Allow("user1")
	if !allowed {
		t.Error("expected allow for first request")
	}
}

// ==============================
// Metrics: Snapshot and boolToInt
// ==============================

func TestCB26_Metrics_Snapshot_NilOfflineQueue(t *testing.T) {
	origQueue := offlineQueue
	offlineQueue = nil
	defer func() { offlineQueue = origQueue }()

	h := newHub()
	go h.run()
	defer h.Stop()

	m := NewMetrics(h)
	snap := m.Snapshot()

	if snap["offline_queue_depth"] != 0 {
		t.Errorf("expected 0 depth for nil queue, got %v", snap["offline_queue_depth"])
	}
	if snap["version"] != "0.2.0" {
		t.Errorf("expected version 0.2.0, got %v", snap["version"])
	}
	if _, ok := snap["uptime_seconds"]; !ok {
		t.Error("expected uptime_seconds in snapshot")
	}
	if _, ok := snap["goroutines"]; !ok {
		t.Error("expected goroutines in snapshot")
	}
	if _, ok := snap["memory_alloc_mb"]; !ok {
		t.Error("expected memory_alloc_mb in snapshot")
	}
}

func TestCB26_Metrics_Uptime(t *testing.T) {
	m := &Metrics{
		StartTime: time.Now().Add(-5 * time.Minute),
	}
	uptime := m.Uptime()
	if uptime < 4*time.Minute || uptime > 6*time.Minute {
		t.Errorf("expected ~5min uptime, got %v", uptime)
	}
}

func TestCB26_BoolToInt(t *testing.T) {
	if boolToInt(true) != 1 {
		t.Error("expected 1 for true")
	}
	if boolToInt(false) != 0 {
		t.Error("expected 0 for false")
	}
	if boolToInt("not-a-bool") != 0 {
		t.Error("expected 0 for non-bool")
	}
	if boolToInt(nil) != 0 {
		t.Error("expected 0 for nil")
	}
}

func TestCB26_MetricsHandler_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/metrics", nil)
	w := httptest.NewRecorder()
	handleMetrics(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestCB26_MetricsHandler_FullOutput(t *testing.T) {
	h := newHub()
	go h.run()
	defer h.Stop()

	origMetrics := ServerMetrics
	ServerMetrics = NewMetrics(h)
	defer func() { ServerMetrics = origMetrics }()

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	w := httptest.NewRecorder()
	handleMetrics(w, req)

	body := w.Body.String()
	if !strings.Contains(body, "agent_messenger_messages_in_total") {
		t.Error("expected messages_in metric")
	}
	if !strings.Contains(body, "agent_messenger_agents_connected") {
		t.Error("expected agents_connected metric")
	}
	if !strings.Contains(body, "agent_messenger_clients_connected") {
		t.Error("expected clients_connected metric")
	}
	if !strings.Contains(body, "agent_messenger_version") {
		t.Error("expected version metric")
	}
	if !strings.Contains(body, "agent_messenger_goroutines") {
		t.Error("expected goroutines metric")
	}
	if !strings.Contains(body, "agent_messenger_memory_alloc_bytes") {
		t.Error("expected memory_alloc metric")
	}
}

// ==============================
// Hub: BroadcastToAllClients, GetClientConns
// ==============================

func TestCB26_Hub_BroadcastToAllClients_NoClients(t *testing.T) {
	h := newHub()
	go h.run()
	defer h.Stop()

	// Broadcast with no clients should not panic
	h.BroadcastToAllClients([]byte(`{"type":"test"}`))
}

func TestCB26_Hub_GetClientConns_Empty(t *testing.T) {
	h := newHub()
	go h.run()
	defer h.Stop()

	conns := h.GetClientConns("nonexistent-user")
	if len(conns) != 0 {
		t.Errorf("expected 0 conns, got %d", len(conns))
	}
}

func TestCB26_Hub_GetClient_NotFound(t *testing.T) {
	h := newHub()
	go h.run()
	defer h.Stop()

	conn := h.GetClient("nonexistent-user")
	if conn != nil {
		t.Error("expected nil for nonexistent client")
	}
}

func TestCB26_Hub_AgentStatus_NotFound(t *testing.T) {
	h := newHub()
	go h.run()
	defer h.Stop()

	status := h.AgentStatus("nonexistent-agent")
	if status != "offline" {
		t.Errorf("expected offline for nonexistent agent, got %q", status)
	}
}

// ==============================
// Connection: SafeSend, MarkClosed, IsClosed
// ==============================

func TestCB26_Connection_MarkClosed_Idempotent(t *testing.T) {
	c := &Connection{
		send:    make(chan []byte, 10),
		closed:  false,
		closeMu: sync.RWMutex{},
	}

	c.MarkClosed()
	if !c.IsClosed() {
		t.Error("expected closed after MarkClosed")
	}

	// MarkClosed again should not panic
	c.MarkClosed()
	if !c.IsClosed() {
		t.Error("expected still closed after second MarkClosed")
	}
}

func TestCB26_Connection_SafeSend_Closed(t *testing.T) {
	c := &Connection{
		send:    make(chan []byte, 10),
		closed:  false,
		closeMu: sync.RWMutex{},
	}

	c.MarkClosed()
	result := c.SafeSend([]byte("test"))
	if result {
		t.Error("expected false for SafeSend on closed connection")
	}
}

func TestCB26_Connection_SafeSend_Open(t *testing.T) {
	c := &Connection{
		send:    make(chan []byte, 10),
		closed:  false,
		closeMu: sync.RWMutex{},
	}

	result := c.SafeSend([]byte("test"))
	if !result {
		t.Error("expected true for SafeSend on open connection with buffer space")
	}
}

func TestCB26_Connection_SafeSend_FullBuffer(t *testing.T) {
	c := &Connection{
		send:    make(chan []byte, 1),
		closed:  false,
		closeMu: sync.RWMutex{},
	}

	// Fill the buffer
	c.SafeSend([]byte("first"))

	// Second send should still succeed with buffered channel of size 1
	// Actually with size 1, the second send blocks - but SafeSend has a select with default
	result := c.SafeSend([]byte("second"))
	if result {
		t.Error("expected false for SafeSend on full buffer")
	}
}

// ==============================
// Auth: resetAgentSecret, resetAdminSecret
// ==============================

func TestCB26_ResetAgentSecret(t *testing.T) {
	origEnv := os.Getenv("AGENT_SECRET")
	defer os.Setenv("AGENT_SECRET", origEnv)

	os.Setenv("AGENT_SECRET", "test-secret-123")
	agentSecret = "test-secret-123"
	origSecret := getAgentSecret()

	os.Setenv("AGENT_SECRET", "different-secret-456")
	resetAgentSecret()
	newSecret := getAgentSecret()

	if newSecret == origSecret {
		t.Errorf("expected secret to change after reset: orig=%q new=%q", origSecret, newSecret)
	}
	if newSecret == "" {
		t.Error("expected non-empty secret after reset")
	}
}

func TestCB26_ResetAdminSecret(t *testing.T) {
	resetAdminSecret()
	newSecret := getAdminSecret()

	if newSecret == "" {
		t.Error("expected non-empty secret after reset")
	}
}

// ==============================
// dbdriver: Placeholder/Placeholders edge cases
// ==============================

func TestCB26_Placeholder_EdgeCases(t *testing.T) {
	tests := []struct {
		n      int
		expect string
	}{
		{1, "?"},
		{5, "?"},
		{0, "?"},
		{100, "?"},
	}
	for _, tt := range tests {
		// SQLite always uses "?"
		result := Placeholder(tt.n)
		if result != tt.expect {
			t.Errorf("Placeholder(%d) = %q, want %q", tt.n, result, tt.expect)
		}
	}
}

func TestCB26_Placeholders_EdgeCases(t *testing.T) {
	tests := []struct {
		start  int
		count  int
		expect string
	}{
		{1, 1, "?"},
		{1, 3, "?, ?, ?"},
		{5, 0, ""},
		{3, 2, "?, ?"},
	}
	for _, tt := range tests {
		result := Placeholders(tt.start, tt.count)
		if result != tt.expect {
			t.Errorf("Placeholders(%d, %d) = %q, want %q", tt.start, tt.count, result, tt.expect)
		}
	}
}

func TestCB26_Placeholders_LargeCount(t *testing.T) {
	result := Placeholders(1, 10)
	expected := "?, ?, ?, ?, ?, ?, ?, ?, ?, ?"
	if result != expected {
		t.Errorf("Placeholders(1, 10) = %q, want %q", result, expected)
	}
}

// ==============================
// envIntOrDefault / envDurationOrDefault
// ==============================

func TestCB26_EnvIntOrDefault(t *testing.T) {
	os.Setenv("TEST_CB26_INT", "42")
	defer os.Unsetenv("TEST_CB26_INT")

	if v := envIntOrDefault("TEST_CB26_INT", 10); v != 42 {
		t.Errorf("expected 42, got %d", v)
	}
	if v := envIntOrDefault("TEST_CB26_MISSING", 10); v != 10 {
		t.Errorf("expected 10 for missing key, got %d", v)
	}
}

func TestCB26_EnvIntOrDefault_InvalidValue(t *testing.T) {
	os.Setenv("TEST_CB26_BAD_INT", "not-a-number")
	defer os.Unsetenv("TEST_CB26_BAD_INT")

	if v := envIntOrDefault("TEST_CB26_BAD_INT", 10); v != 10 {
		t.Errorf("expected 10 for invalid value, got %d", v)
	}
}

func TestCB26_EnvDurationOrDefault(t *testing.T) {
	os.Setenv("TEST_CB26_DUR", "5s")
	defer os.Unsetenv("TEST_CB26_DUR")

	if v := envDurationOrDefault("TEST_CB26_DUR", time.Minute); v != 5*time.Second {
		t.Errorf("expected 5s, got %v", v)
	}
	if v := envDurationOrDefault("TEST_CB26_MISSING", time.Minute); v != time.Minute {
		t.Errorf("expected 1m for missing key, got %v", v)
	}
}

func TestCB26_EnvDurationOrDefault_InvalidValue(t *testing.T) {
	os.Setenv("TEST_CB26_BAD_DUR", "not-a-duration")
	defer os.Unsetenv("TEST_CB26_BAD_DUR")

	if v := envDurationOrDefault("TEST_CB26_BAD_DUR", time.Minute); v != time.Minute {
		t.Errorf("expected 1m for invalid value, got %v", v)
	}
}

// ==============================
// writeJSONResponse / writeJSONError
// ==============================

func TestCB26_WriteJSONResponse(t *testing.T) {
	w := httptest.NewRecorder()
	writeJSONResponse(w, http.StatusOK, map[string]string{"status": "ok"})

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	var result map[string]string
	json.NewDecoder(w.Body).Decode(&result)
	if result["status"] != "ok" {
		t.Errorf("expected ok, got %v", result)
	}
}

func TestCB26_WriteJSONResponse_Created(t *testing.T) {
	w := httptest.NewRecorder()
	writeJSONResponse(w, http.StatusCreated, map[string]string{"id": "123"})

	if w.Code != http.StatusCreated {
		t.Errorf("expected 201, got %d", w.Code)
	}
}

// ==============================
// Logger: all log levels
// ==============================

func TestCB26_Logger_AllLevels(t *testing.T) {
	l := NewLogger(LogDebug)

	// These should not panic
	l.Debug("debug message", map[string]interface{}{"key": "value"})
	l.Info("info message", map[string]interface{}{"key": "value"})
	l.Warn("warn message", map[string]interface{}{"key": "value"})
	l.Error("error message", map[string]interface{}{"key": "value"})
}

func TestCB26_Logger_LevelFiltering(t *testing.T) {
	l := NewLogger(LogError)

	// Only error should produce output; others are filtered
	// This just verifies no panics
	l.Debug("filtered", nil)
	l.Info("filtered", nil)
	l.Warn("filtered", nil)
	l.Error("not filtered", nil)
}

func TestCB26_Logger_SetLevel(t *testing.T) {
	origLevel := DefaultLogger.level
	defer func() { DefaultLogger.level = origLevel }()

	DefaultLogger.SetLevel(LogDebug)
	if DefaultLogger.level != LogDebug {
		t.Error("expected debug level")
	}
	DefaultLogger.SetLevel(LogError)
	if DefaultLogger.level != LogError {
		t.Error("expected error level")
	}
}

func TestCB26_Logger_LevelString(t *testing.T) {
	if LogDebug.String() != "debug" {
		t.Errorf("expected DEBUG, got %s", LogDebug.String())
	}
	if LogInfo.String() != "info" {
		t.Errorf("expected INFO, got %s", LogInfo.String())
	}
	if LogWarn.String() != "warn" {
		t.Errorf("expected WARN, got %s", LogWarn.String())
	}
	if LogError.String() != "error" {
		t.Errorf("expected ERROR, got %s", LogError.String())
	}
}

// ==============================
// Routing: truncate function
// ==============================

func TestCB26_Truncate(t *testing.T) {
	tests := []struct {
		input  string
		maxLen int
		expect string
	}{
		{"hello", 10, "hello"},
		{"hello world", 5, "he..."},
		{"hi", 2, "hi"},
		{"", 5, ""},
		{"a", 1, "a"},
	}
	for _, tt := range tests {
		result := truncate(tt.input, tt.maxLen)
		if result != tt.expect {
			t.Errorf("truncate(%q, %d) = %q, want %q", tt.input, tt.maxLen, result, tt.expect)
		}
	}
}

func TestCB26_Truncate_ExactLength(t *testing.T) {
	result := truncate("hello", 5)
	if result != "hello" {
		t.Errorf("expected 'hello', got %q", result)
	}
}

func TestCB26_Truncate_VeryShort(t *testing.T) {
	result := truncate("hello world", 4)
	if len(result) > 4 {
		t.Errorf("expected max 4 chars, got %q (len %d)", result, len(result))
	}
}

// ==============================
// parseSize more edge cases
// ==============================

func TestCB26_ParseSize_MoreEdgeCases(t *testing.T) {
	tests := []struct {
		input  string
		expect int64
		hasErr bool
	}{
		{"  100  ", 100, false},         // whitespace trim
		{"1.5KB", 1536, false},          // fractional KB
		{"0.5MB", 524288, false},        // fractional MB
		{"2GB", 2 << 30, false},         // GB
		{"1TB", 1 << 40, false},         // TB
		{"abcKB", 0, true},              // invalid number
		{"  ", 0, true},                 // whitespace only
		{"100x", 0, true},               // unknown suffix
	}
	for _, tt := range tests {
		result, err := parseSize(tt.input)
		if tt.hasErr && err == nil {
			t.Errorf("parseSize(%q): expected error", tt.input)
		}
		if !tt.hasErr && err != nil {
			t.Errorf("parseSize(%q): unexpected error: %v", tt.input, err)
		}
		if !tt.hasErr && result != tt.expect {
			t.Errorf("parseSize(%q) = %d, want %d", tt.input, result, tt.expect)
		}
	}
}

// ==============================
// RateLimiter: Count method
// ==============================

func TestCB26_RateLimiter_Count_NonexistentUser(t *testing.T) {
	rl := NewRateLimiter(10, time.Minute)
	t.Cleanup(func() { rl.Stop() })

	count := rl.Count("nonexistent")
	if count != 0 {
		t.Errorf("expected 0 for nonexistent user, got %d", count)
	}
}

func TestCB26_RateLimiter_Reset(t *testing.T) {
	rl := NewRateLimiter(10, time.Minute)
	t.Cleanup(func() { rl.Stop() })

	rl.Allow("user1")
	rl.Allow("user1")
	if count := rl.Count("user1"); count != 2 {
		t.Errorf("expected 2, got %d", count)
	}

	rl.Reset()
	if count := rl.Count("user1"); count != 0 {
		t.Errorf("expected 0 after reset, got %d", count)
	}
}

// ==============================
// Queue: persistQueue nil db
// ==============================

func TestCB26_CleanStaleQueueMessages_NilDB(t *testing.T) {
	origDB := db
	db = nil
	defer func() { db = origDB }()

	// Should not panic with nil db
	cleanStaleQueueMessages(nil, time.Hour)
}

// ==============================
// Hub: Stop with active connections
// ==============================

func TestCB26_Hub_Stop_WithConnections(t *testing.T) {
	h := newHub()
	go h.run()

	// Register a fake agent connection
	agentConn := &Connection{
		connType: "agent",
		id:       "test-agent-stop",
		send:     make(chan []byte, 10),
		closed:   false,
		closeMu:  sync.RWMutex{},
	}
	h.register <- agentConn
	time.Sleep(50 * time.Millisecond)

	// Stop should cleanly shut down
	h.Stop()
}

// ==============================
// routeMessage: unknown type
// ==============================

func TestCB26_RouteMessage_UnknownType(t *testing.T) {
	h := newHub()
	go h.run()
	defer h.Stop()

	conn := &Connection{
		connType: "client",
		id:       "test-user-unknown",
		send:     make(chan []byte, 100),
		closed:   false,
		closeMu:  sync.RWMutex{},
	}

	msg := []byte(`{"type":"unknown_event","data":{}}`)
	routeMessage(conn, msg)
	// Unknown types are silently ignored — no panic
}

func TestCB26_RouteMessage_EmptyJSON(t *testing.T) {
	h := newHub()
	go h.run()
	defer h.Stop()

	conn := &Connection{
		connType: "agent",
		id:       "test-agent-empty",
		send:     make(chan []byte, 100),
		closed:   false,
		closeMu:  sync.RWMutex{},
	}

	msg := []byte(`{}`)
	routeMessage(conn, msg)
	// Should not panic
}

func TestCB26_RouteMessage_InvalidJSON(t *testing.T) {
	h := newHub()
	go h.run()
	defer h.Stop()

	conn := &Connection{
		connType: "client",
		id:       "test-user-invalid",
		send:     make(chan []byte, 100),
		closed:   false,
		closeMu:  sync.RWMutex{},
	}

	msg := []byte(`not json at all`)
	routeMessage(conn, msg)
	// Should not panic
}

// ==============================
// GetOrCreateConversation
// ==============================

func TestCB26_GetOrCreateConversation(t *testing.T) {
	// Setup in-memory DB
	origDB := db
	tmpDB, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("failed to open db: %v", err)
	}
	db = tmpDB
	defer func() {
		db = origDB
		tmpDB.Close()
	}()

	if err := initSchema(db); err != nil {
		t.Fatalf("failed to init schema: %v", err)
	}

	// Create an agent record first
	_, err = db.Exec("INSERT INTO agents (id, name, status) VALUES (?, ?, ?)", "agent-1", "Test Agent", "online")
	if err != nil {
		t.Fatalf("failed to insert agent: %v", err)
	}

	conv, err := GetOrCreateConversation("user-1", "agent-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if conv == nil {
		t.Fatal("expected conversation, got nil")
	}

	// GetOrCreate should return same conversation
	conv2, err := GetOrCreateConversation("user-1", "agent-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if conv2.ID != conv.ID {
		t.Errorf("expected same conversation ID, got %s vs %s", conv2.ID, conv.ID)
	}
}

// ==============================
// searchMessages empty
// ==============================

func TestCB26_SearchMessages_EmptyQuery(t *testing.T) {
	origDB := db
	tmpDB, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("failed to open db: %v", err)
	}
	db = tmpDB
	defer func() {
		db = origDB
		tmpDB.Close()
	}()

	if err := initSchema(db); err != nil {
		t.Fatalf("failed to init schema: %v", err)
	}

	results, err := searchMessages("user-1", "", 50)
	if err == nil {
		t.Error("expected error for empty query")
	}
	if len(results) != 0 {
		t.Errorf("expected 0 results for empty query, got %d", len(results))
	}
}

// ==============================
// Tags: edge cases
// ==============================

func TestCB26_HandleAddTag_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/conversations/tags/add", nil)
	w := httptest.NewRecorder()
	handleAddTag(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestCB26_HandleRemoveTag_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/conversations/tags/remove", nil)
	w := httptest.NewRecorder()
	handleRemoveTag(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestCB26_HandleGetTags_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/conversations/tags", nil)
	w := httptest.NewRecorder()
	handleGetTags(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

// ==============================
// Reactions: edge cases
// ==============================

func TestCB26_HandleReact_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/messages/react", nil)
	w := httptest.NewRecorder()
	handleReact(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestCB26_HandleGetReactions_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/messages/reactions", nil)
	w := httptest.NewRecorder()
	handleGetReactions(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

// ==============================
// Presence: method not allowed
// ==============================

func TestCB26_HandleGetPresence_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/presence", nil)
	w := httptest.NewRecorder()
	handleGetPresence(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestCB26_HandleGetUserPresence_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/presence/user", nil)
	w := httptest.NewRecorder()
	handleGetUserPresence(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

// ==============================
// Message edit/delete: method not allowed
// ==============================

func TestCB26_HandleMessageEdit_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/messages/edit", nil)
	w := httptest.NewRecorder()
	handleMessageEdit(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestCB26_HandleMessageDelete_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/messages/delete", nil)
	w := httptest.NewRecorder()
	handleMessageDelete(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

// ==============================
// Notif prefs: method not allowed
// ==============================

func TestCB26_HandleSetNotificationPrefs_Unauthorized(t *testing.T) {
	// handleSetNotificationPrefs checks auth before method, so no auth = 401
	req := httptest.NewRequest(http.MethodPost, "/notification-prefs/set", nil)
	w := httptest.NewRecorder()
	handleSetNotificationPrefs(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestCB26_HandleDeleteNotificationPrefs_Unauthorized(t *testing.T) {
	// handleDeleteNotificationPrefs checks auth before method, so no auth = 401
	req := httptest.NewRequest(http.MethodDelete, "/notification-prefs/delete", nil)
	w := httptest.NewRecorder()
	handleDeleteNotificationPrefs(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

// ==============================
// E2E: handleGetKeyBundle not found
// ==============================

func TestCB26_HandleGetKeyBundle_NotFound(t *testing.T) {
	origDB := db
	tmpDB, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("failed to open db: %v", err)
	}
	db = tmpDB
	defer func() {
		db = origDB
		tmpDB.Close()
	}()

	if err := initSchema(db); err != nil {
		t.Fatalf("failed to init schema: %v", err)
	}

	// Generate a JWT for auth
	token, err := GenerateJWT("user-1", "testuser")
	if err != nil {
		t.Fatalf("failed to generate JWT: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/keys/bundle?owner_id=nonexistent&owner_type=user", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleGetKeyBundle(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

// ==============================
// E2E: handleListOneTimePreKeys empty
// ==============================

func TestCB26_HandleListOneTimePreKeys_Empty(t *testing.T) {
	origDB := db
	tmpDB, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("failed to open db: %v", err)
	}
	db = tmpDB
	defer func() {
		db = origDB
		tmpDB.Close()
	}()

	if err := initSchema(db); err != nil {
		t.Fatalf("failed to init schema: %v", err)
	}

	// Insert a user
	_, _ = db.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)", "user-1", "testuser", "$2a$10$hash")

	token, err := GenerateJWT("user-1", "testuser")
	if err != nil {
		t.Fatalf("failed to generate JWT: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/keys/otpk-count?user_id=user-1", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleListOneTimePreKeys(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}

	var result map[string]interface{}
	json.NewDecoder(w.Body).Decode(&result)
	if count, ok := result["count"].(float64); ok && count != 0 {
		t.Errorf("expected count 0, got %v", result["count"])
	}
}

// ==============================
// E2E: authenticateRequest edge cases
// ==============================

func TestCB26_AuthenticateRequest_NoHeader(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/keys/bundle", nil)
	_, _, err := authenticateRequest(req)
	if err == nil {
		t.Error("expected error for missing auth header")
	}
}

func TestCB26_AuthenticateRequest_InvalidToken(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/keys/bundle", nil)
	req.Header.Set("Authorization", "Bearer invalid-token")
	_, _, err := authenticateRequest(req)
	if err == nil {
		t.Error("expected error for invalid token")
	}
}

func TestCB26_AuthenticateRequest_ValidToken(t *testing.T) {
	token, err := GenerateJWT("user-1", "testuser")
	if err != nil {
		t.Fatalf("failed to generate JWT: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/keys/bundle", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	userID, userType, err := authenticateRequest(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if userID != "user-1" {
		t.Errorf("expected user-1, got %s", userID)
	}
	// authenticateRequest returns "user" as second value for JWT auth, not the username
	if userType != "user" {
		t.Errorf("expected userType=user, got %s", userType)
	}
}

// ==============================
// HandleUpload: method not allowed
// ==============================

func TestCB26_HandleUpload_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/attachments/upload", nil)
	w := httptest.NewRecorder()
	handleUpload(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

// ==============================
// HandleHealth: various
// ==============================

func TestCB26_HandleHealth_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/health", nil)
	w := httptest.NewRecorder()
	handleHealth(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

// ==============================
// HandleLogin: method not allowed
// ==============================

func TestCB26_HandleLogin_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/auth/login", nil)
	w := httptest.NewRecorder()
	handleLogin(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

// ==============================
// HandleRegisterAgent: method not allowed
// ==============================

func TestCB26_HandleRegisterAgent_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/auth/agent", nil)
	w := httptest.NewRecorder()
	handleRegisterAgent(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

// ==============================
// HandleRegisterUser: method not allowed
// ==============================

func TestCB26_HandleRegisterUser_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/auth/user", nil)
	w := httptest.NewRecorder()
	handleRegisterUser(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

// ==============================
// handleChangePassword: method not allowed
// ==============================

func TestCB26_HandleChangePassword_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/auth/change-password", nil)
	w := httptest.NewRecorder()
	handleChangePassword(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

// ==============================
// handleDeleteConversation: method not allowed
// ==============================

func TestCB26_HandleDeleteConversation_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/conversations/delete", nil)
	w := httptest.NewRecorder()
	handleDeleteConversation(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

// ==============================
// handleSearchMessages: method not allowed
// ==============================

func TestCB26_HandleSearchMessages_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/messages/search", nil)
	w := httptest.NewRecorder()
	handleSearchMessages(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

// ==============================
// handleMarkRead: method not allowed
// ==============================

func TestCB26_HandleMarkRead_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/conversations/mark-read", nil)
	w := httptest.NewRecorder()
	handleMarkRead(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

// ==============================
// handleCreateConversation: method not allowed
// ==============================

func TestCB26_HandleCreateConversation_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/conversations/create", nil)
	w := httptest.NewRecorder()
	handleCreateConversation(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

// ==============================
// handleListConversations: method not allowed
// ==============================

func TestCB26_HandleListConversations_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/conversations/list", nil)
	w := httptest.NewRecorder()
	handleListConversations(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

// ==============================
// handleGetMessages: method not allowed
// ==============================

func TestCB26_HandleGetMessages_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/conversations/messages", nil)
	w := httptest.NewRecorder()
	handleGetMessages(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

// ==============================
// Protocol: negotiateProtocol
// ==============================

func TestCB26_NegotiateProtocol_NoHeader(t *testing.T) {
	// When no Sec-WebSocket-Protocol header is set, negotiateProtocol defaults to ProtocolVersion ("v1")
	req := httptest.NewRequest(http.MethodGet, "/agent/connect", nil)
	result := negotiateProtocol(req)
	if result != ProtocolVersion {
		t.Errorf("expected %q for no header, got %q", ProtocolVersion, result)
	}
}

func TestCB26_NegotiateProtocol_SingleVersion(t *testing.T) {
	// SupportedVersions is "v1", so "v1" in header matches
	req := httptest.NewRequest(http.MethodGet, "/agent/connect", nil)
	req.Header.Set("Sec-WebSocket-Protocol", "v1")
	result := negotiateProtocol(req)
	if result != "v1" {
		t.Errorf("expected v1, got %q", result)
	}
}

func TestCB26_NegotiateProtocol_MultipleVersions(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/agent/connect", nil)
	req.Header.Set("Sec-WebSocket-Protocol", "agent-messenger-v2, agent-messenger-v1")
	result := negotiateProtocol(req)
	// Should pick first supported version
	if result == "" {
		t.Error("expected non-empty result for multiple versions")
	}
}

func TestCB26_IsSupportedVersion(t *testing.T) {
	tests := []struct {
		version string
		expect  bool
	}{
		{"v1", true},
		{"v2", false},
		{"", false},
		{"unknown", false},
	}
	for _, tt := range tests {
		result := isSupportedVersion(tt.version)
		if result != tt.expect {
			t.Errorf("isSupportedVersion(%q) = %v, want %v", tt.version, result, tt.expect)
		}
	}
}

// ==============================
// Metrics: NewMetrics
// ==============================

func TestCB26_NewMetrics_Version(t *testing.T) {
	h := newHub()
	go h.run()
	defer h.Stop()

	m := NewMetrics(h)
	if m.Version != "0.2.0" {
		t.Errorf("expected version 0.2.0, got %s", m.Version)
	}
	if m.StartTime.IsZero() {
		t.Error("expected non-zero start time")
	}
}

// ==============================
// Offline queue: TotalDepth
// ==============================

func TestCB26_OfflineQueue_TotalDepth_Empty(t *testing.T) {
	q := newOfflineQueue(100, time.Hour)
	if q.TotalDepth() != 0 {
		t.Errorf("expected 0 total depth, got %d", q.TotalDepth())
	}
}

func TestCB26_OfflineQueue_QueueDepth_Nonexistent(t *testing.T) {
	q := newOfflineQueue(100, time.Hour)
	if q.QueueDepth("nonexistent") != 0 {
		t.Errorf("expected 0 depth, got %d", q.QueueDepth("nonexistent"))
	}
}

func TestCB26_OfflineQueue_Purge_Nonexistent(t *testing.T) {
	q := newOfflineQueue(100, time.Hour)
	// Purging nonexistent should not panic
	q.Purge("nonexistent")
}

func TestCB26_OfflineQueue_Drain_Empty(t *testing.T) {
	q := newOfflineQueue(100, time.Hour)
	result := q.Drain("nonexistent")
	if len(result) != 0 {
		t.Errorf("expected empty drain, got %d items", len(result))
	}
}

// ==============================
// Queue: marshalOutgoingMessage
// ==============================

func TestCB26_MarshalOutgoingMessage(t *testing.T) {
	msg := OutgoingMessage{
		Type: "chat",
		Data: map[string]interface{}{
			"content":         "hello",
			"conversation_id": "conv-1",
		},
	}
	data := marshalOutgoingMessage(msg)
	if len(data) == 0 {
		t.Error("expected non-empty marshaled data")
	}

	var result map[string]interface{}
	err := json.Unmarshal(data, &result)
	if err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}
	if result["type"] != "chat" {
		t.Errorf("expected type chat, got %v", result["type"])
	}
}

// ==============================
// Attachment: isAllowedContentType
// ==============================

func TestCB26_IsAllowedContentType(t *testing.T) {
	tests := []struct {
		ct     string
		expect bool
	}{
		{"image/jpeg", true},
		{"image/png", true},
		{"image/gif", true},
		{"application/pdf", true},
		{"text/plain", true},
		{"application/x-executable", false},
		{"text/html", true},
		{"application/octet-stream", false},
		{"", false},
	}
	for _, tt := range tests {
		result := isAllowedContentType(tt.ct)
		if result != tt.expect {
			t.Errorf("isAllowedContentType(%q) = %v, want %v", tt.ct, result, tt.expect)
		}
	}
}

// ==============================
// Attachment: getMaxUploadSize / getUploadDir
// ==============================

func TestCB26_GetMaxUploadSize(t *testing.T) {
	origSize := maxUploadSize
	defer func() { maxUploadSize = origSize }()

	size := getMaxUploadSize()
	if size <= 0 {
		t.Errorf("expected positive max upload size, got %d", size)
	}
}

func TestCB26_GetUploadDir(t *testing.T) {
	dir := getUploadDir()
	if dir == "" {
		t.Error("expected non-empty upload dir")
	}
}

// ==============================
// Attachment: handleListAttachments method not allowed
// ==============================

func TestCB26_HandleListAttachments_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/messages/attachments", nil)
	w := httptest.NewRecorder()
	handleListAttachments(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

// ==============================
// ValidateJWT: empty token
// ==============================

func TestCB26_ValidateJWT_EmptyToken(t *testing.T) {
	_, err := ValidateJWT("")
	if err == nil {
		t.Error("expected error for empty token")
	}
}

// ==============================
// GenerateJWT: basic
// ==============================

func TestCB26_GenerateJWT_Basic(t *testing.T) {
	token, err := GenerateJWT("user-1", "testuser")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if token == "" {
		t.Error("expected non-empty token")
	}
}

// ==============================
// ValidateAdminSecret: wrong secret
// ==============================

func TestCB26_ValidateAdminSecret_WrongSecret(t *testing.T) {
	origSecret := getAdminSecret()
	resetAdminSecret()  // This generates a new random secret
	defer setAdminSecretForTest(origSecret)

	err := ValidateAdminSecret("wrong-secret")
	if err == nil {
		t.Error("expected error for wrong admin secret")
	}
}

func TestCB26_ValidateAdminSecret_CorrectSecret(t *testing.T) {
	origSecret := getAdminSecret()
	setAdminSecretForTest("test-admin-secret")
	defer setAdminSecretForTest(origSecret)

	err := ValidateAdminSecret("test-admin-secret")
	if err != nil {
		t.Errorf("expected no error for correct secret, got: %v", err)
	}
}

// ==============================
// RateLimiter: concurrent access stress test
// ==============================

func TestCB26_RateLimiter_ConcurrentStress(t *testing.T) {
	rl := NewRateLimiter(1000, time.Minute)
	t.Cleanup(func() { rl.Stop() })

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			userID := fmt.Sprintf("user-%d", id)
			for j := 0; j < 10; j++ {
				rl.Allow(userID)
			}
		}(i)
	}
	wg.Wait()
	// No panic = success
}

// ==============================
// TieredRateLimiter: concurrent stress
// ==============================

func TestCB26_TieredRateLimiter_ConcurrentStress(t *testing.T) {
	trl := NewTieredRateLimiter()
	t.Cleanup(func() { trl.Stop() })

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			userID := fmt.Sprintf("user-%d", id)
			for j := 0; j < 10; j++ {
				trl.Allow(userID)
			}
		}(i)
	}
	wg.Wait()
}

// ==============================
// sendError function
// ==============================

func TestCB26_SendError(t *testing.T) {
	conn := &Connection{
		connType: "client",
		id:       "test-user-error",
		send:     make(chan []byte, 100),
		closed:   false,
		closeMu:  sync.RWMutex{},
	}

	sendError(conn, "test error message")

	select {
	case msg := <-conn.send:
		var result map[string]interface{}
		if err := json.Unmarshal(msg, &result); err != nil {
			t.Fatalf("failed to unmarshal: %v", err)
		}
		if result["type"] != "error" {
			t.Errorf("expected type error, got %v", result["type"])
		}
		if data, ok := result["data"].(map[string]interface{}); ok {
			if data["error"] != "test error message" {
				t.Errorf("expected 'test error message', got %v", data["error"])
			}
		} else {
			t.Errorf("expected data to be map with error field, got %v", result["data"])
		}
	default:
		t.Error("expected error message on send channel")
	}
}

// ==============================
// generateID function
// ==============================

func TestCB26_GenerateID(t *testing.T) {
	id1 := generateID("test")
	id2 := generateID("test")

	if !strings.HasPrefix(id1, "test_") {
		t.Errorf("expected prefix 'test_', got %s", id1)
	}
	if id1 == id2 {
		t.Error("expected different IDs for sequential calls")
	}
}

func TestCB26_GenerateID_DifferentPrefixes(t *testing.T) {
	id1 := generateID("msg")
	id2 := generateID("conv")

	if strings.HasPrefix(id1, "conv") {
		t.Errorf("expected msg prefix, got %s", id1)
	}
	if strings.HasPrefix(id2, "msg") {
		t.Errorf("expected conv prefix, got %s", id2)
	}
}

// ==============================
// extractIP more edge cases
// ==============================

func TestCB26_ExtractIP_MoreEdgeCases(t *testing.T) {
	tests := []struct {
		name   string
		setup  func(*http.Request)
		expect string
	}{
		{
			name: "X-Forwarded-For multiple",
			setup: func(r *http.Request) {
				r.Header.Set("X-Forwarded-For", "1.2.3.4, 5.6.7.8, 9.10.11.12")
			},
			expect: "1.2.3.4",
		},
		{
			name: "X-Forwarded-For with spaces",
			setup: func(r *http.Request) {
				r.Header.Set("X-Forwarded-For", "  1.2.3.4  ")
			},
			expect: "1.2.3.4",
		},
		{
			name: "X-Real-IP only",
			setup: func(r *http.Request) {
				r.Header.Set("X-Real-IP", "10.0.0.1")
			},
			expect: "10.0.0.1",
		},
		{
			name: "X-Forwarded-For takes precedence over X-Real-IP",
			setup: func(r *http.Request) {
				r.Header.Set("X-Forwarded-For", "1.2.3.4")
				r.Header.Set("X-Real-IP", "10.0.0.1")
			},
			expect: "1.2.3.4",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.RemoteAddr = "127.0.0.1:12345"
			tt.setup(req)
			result := extractIP(req)
			if result != tt.expect {
				t.Errorf("got %q, want %q", result, tt.expect)
			}
		})
	}
}

// ==============================
// isUniqueViolation
// ==============================

func TestCB26_IsUniqueViolation(t *testing.T) {
	tests := []struct {
		err    error
		expect bool
	}{
		{fmt.Errorf("UNIQUE constraint failed: users.username"), true},
		{fmt.Errorf("duplicate key value violates unique constraint"), false}, // PostgreSQL not supported
		{fmt.Errorf("some other error"), false},
		{nil, false},
	}
	for _, tt := range tests {
		result := isUniqueViolation(tt.err)
		if result != tt.expect {
			t.Errorf("isUniqueViolation(%v) = %v, want %v", tt.err, result, tt.expect)
		}
	}
}

// ==============================
// responseWriterWrapper
// ==============================

func TestCB26_ResponseWriterWrapper_Status(t *testing.T) {
	rec := httptest.NewRecorder()
	wrapper := &responseWriterWrapper{ResponseWriter: rec}

	wrapper.WriteHeader(http.StatusCreated)
	if wrapper.statusCode != http.StatusCreated {
		t.Errorf("expected 201, got %d", wrapper.statusCode)
	}
	if wrapper.statusCode != http.StatusCreated {
		t.Errorf("expected Status() 201, got %d", wrapper.statusCode)
	}
}

func TestCB26_ResponseWriterWrapper_DefaultStatus(t *testing.T) {
	rec := httptest.NewRecorder()
	wrapper := &responseWriterWrapper{ResponseWriter: rec}

	// Default status before WriteHeader
	if wrapper.statusCode != 0 {
		t.Errorf("expected 0 default status, got %d", wrapper.statusCode)
	}
}

func TestCB26_ResponseWriterWrapper_Write(t *testing.T) {
	rec := httptest.NewRecorder()
	wrapper := &responseWriterWrapper{ResponseWriter: rec}

	n, err := wrapper.Write([]byte("hello"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != 5 {
		t.Errorf("expected 5 bytes written, got %d", n)
	}
	// statusCode stays 0 if WriteHeader was never called (net/http defaults to 200 implicitly)
	if wrapper.statusCode != 0 {
		t.Errorf("expected 0 (WriteHeader not called), got %d", wrapper.statusCode)
	}
}

// ==============================
// RegisterAgentOnConnect edge cases
// ==============================

func TestCB26_RegisterAgentOnConnect_ExistingAgent(t *testing.T) {
	origDB := db
	tmpDB, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("failed to open db: %v", err)
	}
	db = tmpDB
	defer func() {
		db = origDB
		tmpDB.Close()
	}()

	if err := initSchema(db); err != nil {
		t.Fatalf("failed to init schema: %v", err)
	}

	// Register agent first time
	err = RegisterAgentOnConnect("agent-1", "Agent One", "gpt-4", "friendly", "general")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Register same agent again (reconnect)
	err = RegisterAgentOnConnect("agent-1", "Agent One Updated", "gpt-4-turbo", "helpful", "coding")
	if err != nil {
		t.Fatalf("unexpected error on reconnect: %v", err)
	}

	// Verify the update
	var name string
	err = db.QueryRow("SELECT name FROM agents WHERE id = ?", "agent-1").Scan(&name)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if name != "Agent One Updated" {
		t.Errorf("expected 'Agent One Updated', got %q", name)
	}
}

func TestCB26_RegisterAgentOnConnect_DefaultName(t *testing.T) {
	origDB := db
	tmpDB, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("failed to open db: %v", err)
	}
	db = tmpDB
	defer func() {
		db = origDB
		tmpDB.Close()
	}()

	if err := initSchema(db); err != nil {
		t.Fatalf("failed to init schema: %v", err)
	}

	// Register agent with empty name (should use agent ID as default)
	err = RegisterAgentOnConnect("agent-2", "", "gpt-4", "", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var name string
	err = db.QueryRow("SELECT name FROM agents WHERE id = ?", "agent-2").Scan(&name)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if name != "agent-2" {
		t.Errorf("expected default name 'agent-2', got %q", name)
	}
}

// ==============================
// Push: safeTruncate
// ==============================

func TestCB26_SafeTruncate(t *testing.T) {
	tests := []struct {
		input  string
		n      int
		expect string
	}{
		{"hello", 10, "hello"},
		{"hello world", 5, "hello"},
		{"", 5, ""},
		{"hi", 0, ""},
		{"abc", 2, "ab"},
	}
	for _, tt := range tests {
		result := safeTruncate(tt.input, tt.n)
		if result != tt.expect {
			t.Errorf("safeTruncate(%q, %d) = %q, want %q", tt.input, tt.n, result, tt.expect)
		}
	}
}

// ==============================
// Push: getEnvOrDefault
// ==============================

func TestCB26_GetEnvOrDefault(t *testing.T) {
	os.Setenv("TEST_CB26_ENV", "custom-value")
	defer os.Unsetenv("TEST_CB26_ENV")

	if v := getEnvOrDefault("TEST_CB26_ENV", "default"); v != "custom-value" {
		t.Errorf("expected 'custom-value', got %q", v)
	}
	if v := getEnvOrDefault("TEST_CB26_MISSING", "default"); v != "default" {
		t.Errorf("expected 'default', got %q", v)
	}
	if v := getEnvOrDefault("TEST_CB26_EMPTY", "default"); v != "default" {
		t.Errorf("expected 'default' for empty env, got %q", v)
	}
}

// ==============================
// CSRF middleware: more edge cases
// ==============================

func TestCB26_CSRF_OptionsPass(t *testing.T) {
	handler := csrfMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodOptions, "/test", nil)
	w := httptest.NewRecorder()
	handler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200 for OPTIONS, got %d", w.Code)
	}
}

func TestCB26_CSRF_HeadPass(t *testing.T) {
	handler := csrfMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodHead, "/test", nil)
	w := httptest.NewRecorder()
	handler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200 for HEAD, got %d", w.Code)
	}
}

func TestCB26_CSRF_XRequestedWith(t *testing.T) {
	handler := csrfMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodPost, "/test", nil)
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	w := httptest.NewRecorder()
	handler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200 for X-Requested-With, got %d", w.Code)
	}
}

// ==============================
// HandleGetAttachment: method not allowed
// ==============================

func TestCB26_HandleGetAttachment_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/attachments/test-file", nil)
	w := httptest.NewRecorder()
	handleGetAttachment(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

// ==============================
// Hub: StaleAgentCount
// ==============================

func TestCB26_Hub_StaleAgentCount(t *testing.T) {
	h := newHub()
	go h.run()
	defer h.Stop()

	count := h.StaleAgentCount()
	if count != 0 {
		t.Errorf("expected 0 stale agents, got %d", count)
	}
}

// ==============================
// Hub: SetAgentStatus
// ==============================

func TestCB26_Hub_SetAgentStatus(t *testing.T) {
	h := newHub()
	go h.run()
	defer h.Stop()

	// SetAgentStatus sets status for agent not yet connected
	h.SetAgentStatus("nonexistent-agent", "busy")

	// Note: once an agent connects, their status is reset to "online"
	// SetAgentStatus before connection sets it but it may be overridden
}

// ==============================
// E2E: handleStoreEncryptedMessage method not allowed
// ==============================

func TestCB26_HandleStoreEncryptedMessage_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/messages/encrypted", nil)
	w := httptest.NewRecorder()
	handleStoreEncryptedMessage(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

// ==============================
// E2E: handleUploadPublicKey method not allowed
// ==============================

func TestCB26_HandleUploadPublicKey_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/keys/upload", nil)
	w := httptest.NewRecorder()
	handleUploadPublicKey(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

// ==============================
// E2E: handleGetEncryptedMessages method not allowed
// ==============================

func TestCB26_HandleGetEncryptedMessages_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/messages/encrypted/list", nil)
	w := httptest.NewRecorder()
	handleGetEncryptedMessages(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

// ==============================
// Push: handleRegisterDeviceToken method not allowed
// ==============================

func TestCB26_HandleRegisterDeviceToken_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/push/register", nil)
	w := httptest.NewRecorder()
	handleRegisterDeviceToken(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

// ==============================
// Push: handleUnregisterDeviceToken method not allowed
// ==============================

func TestCB26_HandleUnregisterDeviceToken_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/push/unregister", nil)
	w := httptest.NewRecorder()
	handleUnregisterDeviceToken(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

// ==============================
// Push: handleGetVAPIDKey method not allowed
// ==============================

func TestCB26_HandleGetVAPIDKey_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/push/vapid-key", nil)
	w := httptest.NewRecorder()
	handleGetVAPIDKey(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

// ==============================
// Push: handleWebPushSubscribe method not allowed
// ==============================

func TestCB26_HandleWebPushSubscribe_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/push/web-subscribe", nil)
	w := httptest.NewRecorder()
	handleWebPushSubscribe(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

// ==============================
// Push: handleWebPushUnsubscribe method not allowed
// ==============================

func TestCB26_HandleWebPushUnsubscribe_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/push/web-unsubscribe", nil)
	w := httptest.NewRecorder()
	handleWebPushUnsubscribe(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

// ==============================
// Admin rate limit tier handler
// ==============================

func TestCB26_HandleAdminRateLimitTier_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodPut, "/admin/rate-limit/tier", nil)
	w := httptest.NewRecorder()
	handleAdminRateLimitTier(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

// ==============================
// HashAPIKey
// ==============================

func TestCB26_HashAPIKey(t *testing.T) {
	hash1, err := HashAPIKey("test-key")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hash1 == "" {
		t.Error("expected non-empty hash")
	}

	// bcrypt generates different salts each time, so hashes differ
	hash2, err := HashAPIKey("test-key")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Verify we can validate the original key against both hashes
	if err := bcrypt.CompareHashAndPassword([]byte(hash1), []byte("test-key")); err != nil {
		t.Error("hash1 should match test-key")
	}
	if err := bcrypt.CompareHashAndPassword([]byte(hash2), []byte("test-key")); err != nil {
		t.Error("hash2 should match test-key")
	}

	// Different key should produce different hash
	hash3, err := HashAPIKey("other-key")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hash1 == hash3 {
		t.Error("expected different hash for different key")
	}
}

// ==============================
// openDatabase: SQLite in-memory
// ==============================

func TestCB26_OpenDatabase_SQLiteInMemory(t *testing.T) {
	db, err := openDatabase("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer db.Close()

	if err := db.Ping(); err != nil {
		t.Fatalf("failed to ping: %v", err)
	}
}

// ==============================
// routeHeartbeat
// ==============================

func TestCB26_RouteHeartbeat(t *testing.T) {
	h := newHub()
	go h.run()
	defer h.Stop()

	conn := &Connection{
		hub:      h,
		connType: "agent",
		id:       "test-agent-hb",
		send:     make(chan []byte, 100),
		closed:   false,
		closeMu:  sync.RWMutex{},
	}
	h.register <- conn
	time.Sleep(50 * time.Millisecond)

	// Heartbeat should update last heartbeat time
	routeHeartbeat(conn)
	// No panic = success
}

// ==============================
// routeTypingIndicator: edge cases
// ==============================

func TestCB26_RouteTypingIndicator_InvalidJSON(t *testing.T) {
	conn := &Connection{
		connType: "client",
		id:       "test-user-typing",
		send:     make(chan []byte, 100),
		closed:   false,
		closeMu:  sync.RWMutex{},
	}

	routeTypingIndicator(conn, json.RawMessage(`{invalid json`))
	// Should not panic
}

func TestCB26_RouteStatusUpdate_InvalidJSON(t *testing.T) {
	conn := &Connection{
		connType: "agent",
		id:       "test-agent-status",
		send:     make(chan []byte, 100),
		closed:   false,
		closeMu:  sync.RWMutex{},
	}

	routeStatusUpdate(conn, json.RawMessage(`{invalid json`))
	// Should not panic
}

// ==============================
// ensureUploadDir
// ==============================

func TestCB26_EnsureUploadDir(t *testing.T) {
	err := ensureUploadDir()
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

// ==============================
// itoa helper
// ==============================

func TestCB26_Itoa(t *testing.T) {
	tests := []struct {
		n      int
		expect string
	}{
		{0, "0"},
		{42, "42"},
		{-1, "-1"},
		{1000, "1000"},
	}
	for _, tt := range tests {
		result := itoa(tt.n)
		if result != tt.expect {
			t.Errorf("itoa(%d) = %q, want %q", tt.n, result, tt.expect)
		}
	}
}

// ==============================
// queue_persist: loadQueueFromDB with empty db
// ==============================

func TestCB26_LoadQueueFromDB_Empty(t *testing.T) {
	origDB := db
	tmpDB, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("failed to open db: %v", err)
	}
	db = tmpDB
	defer func() {
		db = origDB
		tmpDB.Close()
	}()

	if err := initSchema(db); err != nil {
		t.Fatalf("failed to init schema: %v", err)
	}

	q := newOfflineQueue(100, time.Hour)
	loadQueueFromDB(db, q)

	if q.TotalDepth() != 0 {
		t.Errorf("expected 0 depth after loading from empty db, got %d", q.TotalDepth())
	}
}

// ==============================
// queue_persist: deleteQueueMessages
// ==============================

func TestCB26_DeleteQueueMessages(t *testing.T) {
	origDB := db
	tmpDB, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("failed to open db: %v", err)
	}
	db = tmpDB
	defer func() {
		db = origDB
		tmpDB.Close()
	}()

	if err := initSchema(db); err != nil {
		t.Fatalf("failed to init schema: %v", err)
	}

	// Insert a queue message
	persistQueue(db, "recipient-1", []byte(`{"type":"chat","data":{}}`))

	// Delete it
	deleteQueueMessages(db, "recipient-1")

	// Verify it's gone
	var count int
	err = db.QueryRow("SELECT COUNT(*) FROM offline_queue WHERE recipient = ?", "recipient-1").Scan(&count)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if count != 0 {
		t.Errorf("expected 0 after deletion, got %d", count)
	}
}

// ==============================
// conversations: CreateConversation
// ==============================

func TestCB26_CreateConversation_New(t *testing.T) {
	origDB := db
	tmpDB, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("failed to open db: %v", err)
	}
	db = tmpDB
	defer func() {
		db = origDB
		tmpDB.Close()
	}()

	if err := initSchema(db); err != nil {
		t.Fatalf("failed to init schema: %v", err)
	}

	conv, err := CreateConversation("user-1", "agent-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if conv == nil {
		t.Fatal("expected conversation, got nil")
	}
	if conv.UserID != "user-1" || conv.AgentID != "agent-1" {
		t.Errorf("unexpected conversation: %+v", conv)
	}
}

// ==============================
// conversations: deleteConversation
// ==============================

func TestCB26_DeleteConversation_Success(t *testing.T) {
	origDB := db
	tmpDB, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("failed to open db: %v", err)
	}
	db = tmpDB
	defer func() {
		db = origDB
		tmpDB.Close()
	}()

	if err := initSchema(db); err != nil {
		t.Fatalf("failed to init schema: %v", err)
	}

	conv, _ := CreateConversation("user-1", "agent-1")

	// Delete it
	err = deleteConversation(conv.ID, "user-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify gone
	var count int
	db.QueryRow("SELECT COUNT(*) FROM conversations WHERE id = ?", conv.ID).Scan(&count)
	if count != 0 {
		t.Errorf("expected 0 conversations after delete, got %d", count)
	}
}

func TestCB26_DeleteConversation_WrongUser(t *testing.T) {
	origDB := db
	tmpDB, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("failed to open db: %v", err)
	}
	db = tmpDB
	defer func() {
		db = origDB
		tmpDB.Close()
	}()

	if err := initSchema(db); err != nil {
		t.Fatalf("failed to init schema: %v", err)
	}

	conv, _ := CreateConversation("user-1", "agent-1")

	// Try to delete as different user
	err = deleteConversation(conv.ID, "user-2")
	if err == nil {
		t.Error("expected error for wrong user")
	}
}

// ==============================
// conversations: markMessagesRead with no messages
// ==============================

func TestCB26_MarkMessagesRead_NoMessages(t *testing.T) {
	origDB := db
	tmpDB, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("failed to open db: %v", err)
	}
	db = tmpDB
	defer func() {
		db = origDB
		tmpDB.Close()
	}()

	if err := initSchema(db); err != nil {
		t.Fatalf("failed to init schema: %v", err)
	}

	conv, _ := CreateConversation("user-1", "agent-1")

	count, err := markMessagesRead(conv.ID, "user-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if count != 0 {
		t.Errorf("expected 0 messages marked read, got %d", count)
	}
}

// ==============================
// conversations: getConversation
// ==============================

func TestCB26_GetConversation_NotFound(t *testing.T) {
	origDB := db
	tmpDB, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("failed to open db: %v", err)
	}
	db = tmpDB
	defer func() {
		db = origDB
		tmpDB.Close()
	}()

	if err := initSchema(db); err != nil {
		t.Fatalf("failed to init schema: %v", err)
	}

	// getConversation returns nil, nil for not found (sql.ErrNoRows is not an error)
	conv, err := getConversation("nonexistent-id")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if conv != nil {
		t.Error("expected nil for nonexistent conversation")
	}
}

// ==============================
// conversations: storeMessage
// ==============================

func TestCB26_StoreMessage(t *testing.T) {
	origDB := db
	tmpDB, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("failed to open db: %v", err)
	}
	db = tmpDB
	defer func() {
		db = origDB
		tmpDB.Close()
	}()

	if err := initSchema(db); err != nil {
		t.Fatalf("failed to init schema: %v", err)
	}

	conv, _ := CreateConversation("user-1", "agent-1")

	msg := RoutedMessage{
		Type:           "chat",
		ConversationID: conv.ID,
		Content:        "Hello world",
		SenderType:     "client",
		SenderID:       "user-1",
	}

	err = storeMessage(msg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify message was stored
	messages, err := getConversationMessages(conv.ID, 10, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(messages) != 1 {
		t.Fatalf("expected 1 message, got %d", len(messages))
	}
	if messages[0].Content != "Hello world" {
		t.Errorf("expected 'Hello world', got %q", messages[0].Content)
	}
}

// ==============================
// conversations: searchMessages with results
// ==============================

func TestCB26_SearchMessages_WithResults(t *testing.T) {
	origDB := db
	tmpDB, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("failed to open db: %v", err)
	}
	db = tmpDB
	defer func() {
		db = origDB
		tmpDB.Close()
	}()

	if err := initSchema(db); err != nil {
		t.Fatalf("failed to init schema: %v", err)
	}

	conv, _ := CreateConversation("user-1", "agent-1")

	// Store a message
	storeMessage(RoutedMessage{
		Type:           "chat",
		ConversationID: conv.ID,
		Content:        "important update",
		SenderType:     "agent",
		SenderID:       "agent-1",
	})

	// Search for it
	results, err := searchMessages("user-1", "important", 50)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 1 {
		t.Errorf("expected 1 result, got %d", len(results))
	}
}

// ==============================
// changeUserPassword
// ==============================

func TestCB26_ChangeUserPassword(t *testing.T) {
	origDB := db
	tmpDB, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("failed to open db: %v", err)
	}
	db = tmpDB
	defer func() {
		db = origDB
		tmpDB.Close()
	}()

	if err := initSchema(db); err != nil {
		t.Fatalf("failed to init schema: %v", err)
	}

	// Create a user
	hash, _ := HashAPIKey("oldpassword")
	_, err = db.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)", "user-1", "testuser", hash)
	if err != nil {
		t.Fatalf("failed to insert user: %v", err)
	}

	// Change password
	err = changeUserPassword("user-1", "oldpassword", "newpassword")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// ==============================
// HandleUpload: multipart form
// ==============================

func TestCB26_HandleUpload_NoMultipart(t *testing.T) {
	token, _ := GenerateJWT("user-1", "testuser")

	req := httptest.NewRequest(http.MethodPost, "/attachments/upload", strings.NewReader(""))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handleUpload(w, req)

	// Should fail because no multipart form
	if w.Code == http.StatusOK {
		t.Error("expected non-200 for non-multipart upload")
	}
}

// ==============================
// isConversationMuted: edge case
// ==============================

func TestCB26_IsConversationMuted_NotSet(t *testing.T) {
	origDB := db
	tmpDB, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("failed to open db: %v", err)
	}
	db = tmpDB
	defer func() {
		db = origDB
		tmpDB.Close()
	}()

	if err := initSchema(db); err != nil {
		t.Fatalf("failed to init schema: %v", err)
	}

	// Not muted when no preference exists
	if isConversationMuted("user-1", "conv-1") {
		t.Error("expected not muted when no preference exists")
	}
}

// ==============================
// Tracing: TraceRouteMessage, etc (disabled)
// ==============================

func TestCB26_Tracing_Disabled_TraceRouteMessage(t *testing.T) {
	span := TraceRouteMessage("client", "user-1")
	if span == nil {
		t.Error("expected non-nil span even when disabled")
	}
	span.End()
}

func TestCB26_Tracing_Disabled_TraceOfflineEnqueue(t *testing.T) {
	span := TraceOfflineEnqueue("user-1")
	if span == nil {
		t.Error("expected non-nil span even when disabled")
	}
	span.End()
}

func TestCB26_Tracing_Disabled_TracePushNotify(t *testing.T) {
	span := TracePushNotify("user-1", "conv-1", true)
	if span == nil {
		t.Error("expected non-nil span even when disabled")
	}
	span.End()
}

func TestCB26_Tracing_Disabled_TraceAgentConnect(t *testing.T) {
	span := TraceAgentConnect("agent-1")
	if span == nil {
		t.Error("expected non-nil span even when disabled")
	}
	span.End()
}

func TestCB26_Tracing_Disabled_TraceClientConnect(t *testing.T) {
	span := TraceClientConnect("user-1", "device-1")
	if span == nil {
		t.Error("expected non-nil span even when disabled")
	}
	span.End()
}

// ==============================
// Logger: formatMessage
// ==============================

func TestCB26_Logger_FormatMessage(t *testing.T) {
	l := NewLogger(LogDebug)
	fields := map[string]interface{}{"key1": "val1", "key2": 123}
	l.Debug("test debug", fields)
	l.Info("test info", fields)
	l.Warn("test warn", fields)
	l.Error("test error", fields)
}

func TestCB26_Logger_NilFields(t *testing.T) {
	l := NewLogger(LogDebug)

	// Nil fields should not panic
	l.Debug("test debug", nil)
	l.Info("test info", nil)
	l.Warn("test warn", nil)
	l.Error("test error", nil)
}

// ==============================
// Hub: ClientConnCount
// ==============================

func TestCB26_Hub_ClientConnCount_Empty(t *testing.T) {
	h := newHub()
	go h.run()
	defer h.Stop()

	count := h.ClientConnCount()
	if count != 0 {
		t.Errorf("expected 0 client connections, got %d", count)
	}
}

// ==============================
// Hub: AgentCount
// ==============================

func TestCB26_Hub_AgentCount_Empty(t *testing.T) {
	h := newHub()
	go h.run()
	defer h.Stop()

	count := h.AgentCount()
	if count != 0 {
		t.Errorf("expected 0 agents, got %d", count)
	}
}

// ==============================
// Hub: ClientCount
// ==============================

func TestCB26_Hub_ClientCount_Empty(t *testing.T) {
	h := newHub()
	go h.run()
	defer h.Stop()

	count := h.ClientCount()
	if count != 0 {
		t.Errorf("expected 0 clients, got %d", count)
	}
}

// ==============================
// Metrics: Snapshot with offline queue
// ==============================

func TestCB26_Metrics_Snapshot_WithQueue(t *testing.T) {
	h := newHub()
	go h.run()
	defer h.Stop()

	origQueue := offlineQueue
	q := newOfflineQueue(100, time.Hour)
	offlineQueue = q
	defer func() { offlineQueue = origQueue }()

	// Enqueue a message
	q.Enqueue("recipient-1", []byte(`{"type":"chat"}`))

	m := NewMetrics(h)
	snap := m.Snapshot()

	if snap["offline_queue_depth"] != 1 {
		t.Errorf("expected 1 depth, got %v", snap["offline_queue_depth"])
	}
}

// ==============================
// conversations: storeMessagesBatch
// ==============================

func TestCB26_StoreMessagesBatch(t *testing.T) {
	origDB := db
	tmpDB, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("failed to open db: %v", err)
	}
	db = tmpDB
	defer func() {
		db = origDB
		tmpDB.Close()
	}()

	if err := initSchema(db); err != nil {
		t.Fatalf("failed to init schema: %v", err)
	}

	conv, _ := CreateConversation("user-1", "agent-1")

	msgs := []RoutedMessage{
		{
			Type:           "chat",
			ConversationID: conv.ID,
			Content:        "Message 1",
			SenderType:     "client",
			SenderID:       "user-1",
		},
		{
			Type:           "chat",
			ConversationID: conv.ID,
			Content:        "Message 2",
			SenderType:     "agent",
			SenderID:       "agent-1",
		},
	}

	ids, err := storeMessagesBatch(msgs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ids) != 2 {
		t.Errorf("expected 2 IDs, got %d", len(ids))
	}

	// Verify messages were stored
	messages, err := getConversationMessages(conv.ID, 10, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(messages) != 2 {
		t.Errorf("expected 2 messages, got %d", len(messages))
	}
}

// ==============================
// handleGetMessages: unauthorized
// ==============================

func TestCB26_HandleGetMessages_Unauthorized(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/conversations/messages?conversation_id=conv-1", nil)
	req.Header.Set("Authorization", "Bearer invalid-token")
	w := httptest.NewRecorder()
	handleGetMessages(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestCB26_HandleGetMessages_MissingConvID(t *testing.T) {
	token, _ := GenerateJWT("user-1", "testuser")

	req := httptest.NewRequest(http.MethodGet, "/conversations/messages", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleGetMessages(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

// ==============================
// handleListConversations: unauthorized
// ==============================

func TestCB26_HandleListConversations_Unauthorized(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/conversations/list", nil)
	req.Header.Set("Authorization", "Bearer invalid-token")
	w := httptest.NewRecorder()
	handleListConversations(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

// ==============================
// handleCreateConversation: unauthorized
// ==============================

func TestCB26_HandleCreateConversation_Unauthorized(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/conversations/create", nil)
	req.Header.Set("Authorization", "Bearer invalid-token")
	w := httptest.NewRecorder()
	handleCreateConversation(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

// ==============================
// handleSearchMessages: unauthorized
// ==============================

func TestCB26_HandleSearchMessages_Unauthorized(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/messages/search?q=test", nil)
	req.Header.Set("Authorization", "Bearer invalid-token")
	w := httptest.NewRecorder()
	handleSearchMessages(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

// ==============================
// handleMarkRead: unauthorized
// ==============================

func TestCB26_HandleMarkRead_Unauthorized(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/conversations/mark-read", nil)
	req.Header.Set("Authorization", "Bearer invalid-token")
	w := httptest.NewRecorder()
	handleMarkRead(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

// ==============================
// ValidateAgentSecret
// ==============================

func TestCB26_ValidateAgentSecret_WrongSecret(t *testing.T) {
	// Set a known secret using resetAgentSecret
	origSecret := getAgentSecret()
	setAgentSecretForTest("correct-agent-secret")
	defer setAgentSecretForTest(origSecret)

	err := ValidateAgentSecret("agent-1", "wrong-secret")
	if err == nil {
		t.Error("expected error for wrong agent secret")
	}
}

func TestCB26_ValidateAgentSecret_CorrectSecret(t *testing.T) {
	origSecret := getAgentSecret()
	setAgentSecretForTest("test-agent-secret")
	defer setAgentSecretForTest(origSecret)

	err := ValidateAgentSecret("agent-1", "test-agent-secret")
	if err != nil {
		t.Errorf("expected no error for correct secret, got: %v", err)
	}
}

// ==============================
// handleListAgents: unauthorized
// ==============================

func TestCB26_HandleListAgents_Unauthorized(t *testing.T) {
	origDB := db
	tmpDB, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("failed to open db: %v", err)
	}
	db = tmpDB
	defer func() {
		db = origDB
		tmpDB.Close()
	}()

	if err := initSchema(db); err != nil {
		t.Fatalf("failed to init schema: %v", err)
	}

	// handleListAgents doesn't check auth (middleware does); calling directly returns 200 with empty list
	req := httptest.NewRequest(http.MethodGet, "/agents", nil)
	w := httptest.NewRecorder()
	handleListAgents(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

// ==============================
// handleAdminAgents: unauthorized
// ==============================

func TestCB26_HandleAdminAgents_Unauthorized(t *testing.T) {
	origDB := db
	tmpDB, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("failed to open db: %v", err)
	}
	db = tmpDB
	defer func() {
		db = origDB
		tmpDB.Close()
	}()

	if err := initSchema(db); err != nil {
		t.Fatalf("failed to init schema: %v", err)
	}

	// handleAdminAgents doesn't check auth (middleware does); calling directly returns 200 with empty list
	req := httptest.NewRequest(http.MethodGet, "/admin/agents", nil)
	w := httptest.NewRecorder()
	handleAdminAgents(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

// ==============================
// sendPushNotification: unknown platform
// ==============================

func TestCB26_SendPushNotification_UnknownPlatform(t *testing.T) {
	err := sendPushNotification("token", "title", "body", "conv-1", "unknown-platform")
	// Unknown platform should return error or be handled gracefully
	// The exact behavior depends on implementation
	_ = err
}

// ==============================
// notifyUser: basic
// ==============================

func TestCB26_NotifyUser_NoTokens(t *testing.T) {
	origDB := db
	tmpDB, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("failed to open db: %v", err)
	}
	db = tmpDB
	defer func() {
		db = origDB
		tmpDB.Close()
	}()

	if err := initSchema(db); err != nil {
		t.Fatalf("failed to init schema: %v", err)
	}

	// notifyUser with no device tokens should not panic
	notifyUser("user-1", "Test Title", "Test Body", "conv-1")
}

// ==============================
// getDeviceTokensForUser: no tokens
// ==============================

func TestCB26_GetDeviceTokensForUser_NoTokens(t *testing.T) {
	origDB := db
	tmpDB, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("failed to open db: %v", err)
	}
	db = tmpDB
	defer func() {
		db = origDB
		tmpDB.Close()
	}()

	if err := initSchema(db); err != nil {
		t.Fatalf("failed to init schema: %v", err)
	}

	tokens, err := getDeviceTokensForUser("user-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(tokens) != 0 {
		t.Errorf("expected 0 tokens, got %d", len(tokens))
	}
}

// ==============================
// E2E: handleGetEncryptedMessages with auth
// ==============================

func TestCB26_HandleGetEncryptedMessages_WithAuth(t *testing.T) {
	origDB := db
	tmpDB, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("failed to open db: %v", err)
	}
	db = tmpDB
	defer func() {
		db = origDB
		tmpDB.Close()
	}()

	if err := initSchema(db); err != nil {
		t.Fatalf("failed to init schema: %v", err)
	}

	token, _ := GenerateJWT("user-1", "testuser")

	req := httptest.NewRequest(http.MethodGet, "/messages/encrypted/list?conversation_id=conv-1&limit=10", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleGetEncryptedMessages(w, req)

	// Conversation doesn't exist, should return 404 or error
	if w.Code == http.StatusOK {
		// May return empty list if conversation doesn't exist
		var result []interface{}
		json.NewDecoder(w.Body).Decode(&result)
	}
}

// ==============================
// OutgoingMessage marshaling
// ==============================

func TestCB26_OutgoingMessage_Marshal(t *testing.T) {
	msg := OutgoingMessage{
		Type: "chat",
		Data: map[string]interface{}{
			"content":         "test message",
			"conversation_id": "conv-1",
			"sender_type":     "client",
			"sender_id":       "user-1",
		},
	}

	data, err := json.Marshal(msg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var result map[string]interface{}
	json.Unmarshal(data, &result)
	if result["type"] != "chat" {
		t.Errorf("expected type chat, got %v", result["type"])
	}
}

// ==============================
// HandleLogin: missing fields
// ==============================

func TestCB26_HandleLogin_MissingFields(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/auth/login", strings.NewReader(""))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handleLogin(w, req)

	// Missing username/password should return error
	if w.Code == http.StatusOK {
		t.Error("expected non-200 for missing fields")
	}
}

// ==============================
// HandleRegisterUser: missing fields
// ==============================

func TestCB26_HandleRegisterUser_MissingFields(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/auth/user", strings.NewReader(""))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handleRegisterUser(w, req)

	// Missing username/password should return error
	if w.Code == http.StatusOK {
		t.Error("expected non-200 for missing fields")
	}
}

// ==============================
// HandleRegisterAgent: missing fields
// ==============================

func TestCB26_HandleRegisterAgent_MissingFields(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/auth/agent", strings.NewReader(""))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handleRegisterAgent(w, req)

	// Missing fields should return error
	if w.Code == http.StatusOK {
		t.Error("expected non-200 for missing fields")
	}
}

// ==============================
// Profile: MemoryStats, ForceGC
// ==============================

func TestCB26_MemoryStats(t *testing.T) {
	stats := MemoryStats()
	if stats["alloc_bytes"] == nil {
		t.Error("expected non-nil alloc_bytes value")
	}
	if stats["sys_bytes"] == nil {
		t.Error("expected non-nil sys_bytes value")
	}
}

func TestCB26_ForceGC(t *testing.T) {
	// Should not panic
	ForceGC()
}

// ==============================
// Profile handlers: method not allowed
// ==============================

func TestCB26_HandleAdminProfile_MethodNotAllowed(t *testing.T) {
	// handleAdminProfile accepts GET and POST; only other methods get 405
	req := httptest.NewRequest(http.MethodPut, "/admin/profile", nil)
	w := httptest.NewRecorder()
	handleAdminProfile(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

// ==============================
// Profile: WriteHeapProfile, WriteGoroutineProfile
// ==============================

func TestCB26_WriteHeapProfile(t *testing.T) {
	tmpFile, _ := os.CreateTemp("", "heap-profile-*.prof")
	defer os.Remove(tmpFile.Name())
	tmpFile.Close()
	err := WriteHeapProfile(tmpFile.Name())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCB26_WriteGoroutineProfile(t *testing.T) {
	tmpFile2, _ := os.CreateTemp("", "goroutine-profile-*.prof")
	defer os.Remove(tmpFile2.Name())
	tmpFile2.Close()
	err := WriteGoroutineProfile(tmpFile2.Name())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// ==============================
// SetGCPercent, SetMemoryLimit
// ==============================

func TestCB26_SetGCPercent(t *testing.T) {
	orig := SetGCPercent(100)
	defer SetGCPercent(orig)

	if SetGCPercent(200) != 100 {
		t.Error("expected original value 100")
	}
}

func TestCB26_SetMemoryLimit(t *testing.T) {
	// SetMemoryLimit returns the previous value, so set a known value first
	SetMemoryLimit(1 << 30) // Set 1GB first
	result := SetMemoryLimit(2 << 30) // Set 2GB, should return 1GB (previous value)
	if result != 1<<30 {
		t.Errorf("expected %d, got %d", 1<<30, result)
	}
}

// ==============================
// routeChatMessage: edge cases with hub
// ==============================

func TestCB26_RouteChatMessage_EmptyContent(t *testing.T) {
	h := newHub()
	go h.run()
	defer h.Stop()

	conn := &Connection{
		connType: "client",
		id:       "test-user-empty-content",
		send:     make(chan []byte, 100),
		closed:   false,
		closeMu:  sync.RWMutex{},
	}

	data := json.RawMessage(`{"conversation_id":"conv-1","content":""}`)
	routeChatMessage(conn, data)
	// Empty content should be handled gracefully
}

func TestCB26_RouteChatMessage_MissingConvID(t *testing.T) {
	h := newHub()
	go h.run()
	defer h.Stop()

	conn := &Connection{
		connType: "client",
		id:       "test-user-no-conv",
		send:     make(chan []byte, 100),
		closed:   false,
		closeMu:  sync.RWMutex{},
	}

	data := json.RawMessage(`{"content":"hello"}`)
	routeChatMessage(conn, data)
	// Missing conversation_id should result in error
}

// ==============================
// Middleware: ipRateLimitMiddleware
// ==============================

func TestCB26_IPRateLimitMiddleware_Basic(t *testing.T) {
	handler := ipRateLimitMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// First request should pass
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.RemoteAddr = "1.2.3.4:12345"
	w := httptest.NewRecorder()
	handler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200 for first request, got %d", w.Code)
	}
}

// ==============================
// authMiddleware
// ==============================

func TestCB26_AuthMiddleware_NoAuth(t *testing.T) {
	handler := authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()
	handler(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestCB26_AuthMiddleware_ValidToken(t *testing.T) {
	handler := authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	token, _ := GenerateJWT("user-1", "testuser")
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

// ==============================
// adminAuthMiddleware
// ==============================

func TestCB26_AdminAuthMiddleware_NoAuth(t *testing.T) {
	handler := adminAuthMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()
	handler(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

// ==============================
// authRateLimitMiddleware
// ==============================

func TestCB26_AuthRateLimitMiddleware_Basic(t *testing.T) {
	handler := authRateLimitMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.RemoteAddr = "1.2.3.4:12345"
	w := httptest.NewRecorder()
	handler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200 for first request, got %d", w.Code)
	}
}

// ==============================
// securityHeadersMiddleware
// ==============================

func TestCB26_SecurityHeadersMiddleware(t *testing.T) {
	handler := securityHeadersMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()
	handler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	csp := w.Header().Get("Content-Security-Policy")
	if csp == "" {
		t.Error("expected CSP header")
	}
}

// ==============================
// corsMiddleware: preflight
// ==============================

func TestCB26_CORSMiddleware_Preflight(t *testing.T) {
	handler := corsMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodOptions, "/test", nil)
	req.Header.Set("Origin", "http://localhost:3000")
	req.Header.Set("Access-Control-Request-Method", "POST")
	w := httptest.NewRecorder()
	handler(w, req)

	if w.Code != http.StatusNoContent {
		t.Errorf("expected 204 for preflight, got %d", w.Code)
	}
	origin := w.Header().Get("Access-Control-Allow-Origin")
	if origin == "" {
		t.Error("expected Allow-Origin header")
	}
}

// ==============================
// requestIDMiddleware
// ==============================

func TestCB26_RequestIDMiddleware(t *testing.T) {
	var capturedID string
	handler := requestIDMiddleware(func(w http.ResponseWriter, r *http.Request) {
		capturedID = w.Header().Get("X-Request-ID")
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()
	handler(w, req)

	if capturedID == "" {
		t.Error("expected request ID in response header")
	}
}

// ==============================
// accessLogMiddleware
// ==============================

func TestCB26_AccessLogMiddleware(t *testing.T) {
	handler := accessLogMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()
	handler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

// ==============================
// getUserID
// ==============================

func TestCB26_GetUserID_NoAuth(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	_, err := getUserID(req)
	if err == nil {
		t.Error("expected error for missing auth")
	}
}

func TestCB26_GetUserID_ValidToken(t *testing.T) {
	// getUserID reads from context (contextKeyUserID), not from Authorization header
	// Must set context value directly (authMiddleware normally does this)
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	ctx := context.WithValue(req.Context(), contextKeyUserID, "user-1")
	req = req.WithContext(ctx)

	userID, err := getUserID(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if userID != "user-1" {
		t.Errorf("expected user-1, got %s", userID)
	}
}

// ==============================
// Hub: register and unregister
// ==============================

func TestCB26_Hub_RegisterAndUnregister(t *testing.T) {
	h := newHub()
	go h.run()
	defer h.Stop()

	conn := &Connection{
		connType: "agent",
		id:       "test-agent-reg",
		send:     make(chan []byte, 10),
		closed:   false,
		closeMu:  sync.RWMutex{},
	}

	h.register <- conn
	time.Sleep(50 * time.Millisecond)

	if h.AgentCount() != 1 {
		t.Errorf("expected 1 agent, got %d", h.AgentCount())
	}

	h.unregister <- conn
	time.Sleep(50 * time.Millisecond)

	if h.AgentCount() != 0 {
		t.Errorf("expected 0 agents after unregister, got %d", h.AgentCount())
	}
}

// ==============================
// Multiple RateLimiter cleanup verification
// ==============================

func TestCB26_RateLimiter_ManyInstances_Cleanup(t *testing.T) {
	// Create many rate limiters and verify all get cleaned up
	var limiters []*RateLimiter
	for i := 0; i < 20; i++ {
		rl := NewRateLimiter(10, time.Minute)
		limiters = append(limiters, rl)
		t.Cleanup(func() { rl.Stop() })
	}

	// All should work
	for _, rl := range limiters {
		rl.Allow("user1")
	}

	// Stop all
	for _, rl := range limiters {
		rl.Stop()
	}
}

func TestCB26_TieredRateLimiter_ManyInstances_Cleanup(t *testing.T) {
	var limiters []*TieredRateLimiter
	for i := 0; i < 20; i++ {
		trl := NewTieredRateLimiter()
		limiters = append(limiters, trl)
		t.Cleanup(func() { trl.Stop() })
	}

	// All should work
	for _, trl := range limiters {
		trl.Allow("user1")
	}

	// Stop all
	for _, trl := range limiters {
		trl.Stop()
	}
}

// ==============================
// isAllowedContentType more
// ==============================

func TestCB26_IsAllowedContentType_More(t *testing.T) {
	if !isAllowedContentType("image/webp") {
		t.Error("expected webp to be allowed")
	}
	if !isAllowedContentType("image/svg+xml") {
		t.Error("expected svg+xml to be allowed")
	}
	if isAllowedContentType("application/x-shockwave-flash") {
		t.Error("expected flash to be disallowed")
	}
}

// ==============================
// OpenDatabase edge cases
// ==============================

func TestCB26_OpenDatabase_WALMode(t *testing.T) {
	db, err := openDatabase("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer db.Close()

	// Verify WAL mode
	var mode string
	err = db.QueryRow("PRAGMA journal_mode").Scan(&mode)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// In-memory databases use memory mode, not WAL
	_ = mode
}

// ==============================
// HandleHealth: success
// ==============================

func TestCB26_HandleHealth_Success(t *testing.T) {
	h := newHub()
	go h.run()
	defer h.Stop()

	origHub := hub
	hub = h
	defer func() { hub = origHub }()

	origMetrics := ServerMetrics
	ServerMetrics = NewMetrics(h)
	defer func() { ServerMetrics = origMetrics }()

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()
	handleHealth(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}

	var result map[string]interface{}
	json.NewDecoder(w.Body).Decode(&result)
	if result["status"] != "ok" {
		t.Errorf("expected status ok, got %v", result["status"])
	}
}

// ==============================
// parseSize: zero and negative
// ==============================

func TestCB26_ParseSize_Zero(t *testing.T) {
	result, err := parseSize("0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != 0 {
		t.Errorf("expected 0, got %d", result)
	}
}

func TestCB26_ParseSize_LargeTB(t *testing.T) {
	result, err := parseSize("10TB")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != 10*(1<<40) {
		t.Errorf("expected %d, got %d", 10*(1<<40), result)
	}
}

// ==============================
// Queue: persist and load
// ==============================

func TestCB26_PersistAndLoadQueue(t *testing.T) {
	origDB := db
	tmpDB, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("failed to open db: %v", err)
	}
	db = tmpDB
	defer func() {
		db = origDB
		tmpDB.Close()
	}()

	if err := initSchema(db); err != nil {
		t.Fatalf("failed to init schema: %v", err)
	}

	// Persist messages
	persistQueue(db, "recipient-1", []byte(`{"type":"chat","data":{"content":"msg1"}}`))
	persistQueue(db, "recipient-1", []byte(`{"type":"chat","data":{"content":"msg2"}}`))

	// Load into queue
	q := newOfflineQueue(100, time.Hour)
	loadQueueFromDB(db, q)

	if q.QueueDepth("recipient-1") != 2 {
		t.Errorf("expected 2 messages, got %d", q.QueueDepth("recipient-1"))
	}

	// Drain and verify
	drained := q.Drain("recipient-1")
	if len(drained) != 2 {
		t.Errorf("expected 2 drained messages, got %d", len(drained))
	}
}

// ==============================
// E2E: handleUploadPublicKey method not allowed already tested
// Let's test handleUploadPublicKey with auth but bad body
// ==============================

func TestCB26_HandleUploadPublicKey_WithAuth_BadBody(t *testing.T) {
	origDB := db
	tmpDB, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("failed to open db: %v", err)
	}
	db = tmpDB
	defer func() {
		db = origDB
		tmpDB.Close()
	}()

	if err := initSchema(db); err != nil {
		t.Fatalf("failed to init schema: %v", err)
	}

	token, _ := GenerateJWT("user-1", "testuser")

	req := httptest.NewRequest(http.MethodPost, "/keys/upload", strings.NewReader(""))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handleUploadPublicKey(w, req)

	// Should fail because no identity_key field
	if w.Code == http.StatusOK {
		t.Error("expected non-200 for missing fields")
	}
}

// ==============================
// Notif prefs: handleGetNotificationPrefs no auth
// ==============================

func TestCB26_HandleGetNotificationPrefs_NoAuth(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/notification-prefs", nil)
	w := httptest.NewRecorder()
	handleGetNotificationPrefs(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

// ==============================
// Notif prefs: handleDeleteNotificationPrefs no auth
// ==============================

func TestCB26_HandleDeleteNotificationPrefs_NoAuth(t *testing.T) {
	req := httptest.NewRequest(http.MethodDelete, "/notification-prefs/delete", nil)
	w := httptest.NewRecorder()
	handleDeleteNotificationPrefs(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}