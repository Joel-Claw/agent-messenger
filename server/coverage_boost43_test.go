package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// ===================================================================
// CB43: Coverage boost 43 — newHub, NewLogger, NewRateLimiter,
// NewTieredRateLimiter, handleMemoryStats, writeProfileJSON,
// and edge cases
// ===================================================================

// --- newHub ---

func TestCB43_NewHub_InitialState(t *testing.T) {
	// Save and restore global state
	origQueue := offlineQueue
	t.Cleanup(func() { offlineQueue = origQueue })

	h := newHub()
	if h == nil {
		t.Fatal("newHub returned nil")
	}
	if h.agents == nil {
		t.Error("agents map is nil")
	}
	if h.clientConns == nil {
		t.Error("clientConns map is nil")
	}
	if h.register == nil {
		t.Error("register channel is nil")
	}
	if h.unregister == nil {
		t.Error("unregister channel is nil")
	}
	if h.broadcast == nil {
		t.Error("broadcast channel is nil")
	}
	if h.done == nil {
		t.Error("done channel is nil")
	}
	if h.monitorDone == nil {
		t.Error("monitorDone channel is nil")
	}
	if h.runDone == nil {
		t.Error("runDone channel is nil")
	}
	if len(h.agents) != 0 {
		t.Errorf("expected 0 agents, got %d", len(h.agents))
	}
	if len(h.clientConns) != 0 {
		t.Errorf("expected 0 clientConns, got %d", len(h.clientConns))
	}
	// offlineQueue should be initialized
	if offlineQueue == nil {
		t.Error("offlineQueue is nil after newHub")
	}
}

func TestCB43_NewHub_MonitorDisabled(t *testing.T) {
	// When agentPresenceEnabled is false (default), monitorDone should be closed
	origEnabled := agentPresenceEnabled
	agentPresenceEnabled = false
	t.Cleanup(func() { agentPresenceEnabled = origEnabled })

	origQueue := offlineQueue
	t.Cleanup(func() { offlineQueue = origQueue })

	h := newHub()

	// monitorDone should already be closed (non-blocking read)
	select {
	case <-h.monitorDone:
		// expected: channel is closed
	default:
		t.Error("monitorDone should be closed when agentPresenceEnabled is false")
	}
}

func TestCB43_NewHub_StopWithoutRun(t *testing.T) {
	// Stopping a hub that was never started should not block
	origQueue := offlineQueue
	t.Cleanup(func() { offlineQueue = origQueue })

	h := newHub()

	// Start run in goroutine so runDone gets closed
	go h.run()

	// Stop should not block
	h.Stop()

	// After Stop, done channel should be closed
	select {
	case <-h.done:
		// expected
	default:
		t.Error("done channel should be closed after Stop")
	}

	// runDone should be closed after run exits
	select {
	case <-h.runDone:
		// expected
	default:
		t.Error("runDone channel should be closed after Stop")
	}
}

func TestCB43_NewHub_StopIsIdempotent(t *testing.T) {
	origQueue := offlineQueue
	t.Cleanup(func() { offlineQueue = origQueue })

	h := newHub()
	go h.run()

	// Multiple Stop calls should not panic
	h.Stop()
	h.Stop() // second call should be a no-op due to sync.Once
	h.Stop() // third call too
}

// --- NewLogger ---

func TestCB43_NewLogger_DefaultLevel(t *testing.T) {
	l := NewLogger(LogInfo)
	if l == nil {
		t.Fatal("NewLogger returned nil")
	}
	if l.level != LogInfo {
		t.Errorf("expected level LogInfo (%d), got %d", LogInfo, l.level)
	}
	if l.fields == nil {
		t.Error("fields map is nil")
	}
	if len(l.fields) != 0 {
		t.Errorf("expected empty fields, got %d", len(l.fields))
	}
}

func TestCB43_NewLogger_AllLevels(t *testing.T) {
	levels := []LogLevel{LogDebug, LogInfo, LogWarn, LogError}
	for _, level := range levels {
		l := NewLogger(level)
		if l.level != level {
			t.Errorf("expected level %d, got %d", level, l.level)
		}
	}
}

func TestCB43_NewLogger_WithFields(t *testing.T) {
	l := NewLogger(LogDebug)
	l2 := l.WithFields(map[string]interface{}{"service": "test", "version": "1.0"})
	if l2 == nil {
		t.Fatal("WithFields returned nil")
	}
	if l2.fields["service"] != "test" {
		t.Error("expected service field to be 'test'")
	}
	if l2.fields["version"] != "1.0" {
		t.Error("expected version field to be '1.0'")
	}
	// Original logger should not be modified
	if _, ok := l.fields["service"]; ok {
		t.Error("original logger should not have service field")
	}
}

func TestCB43_NewLogger_SetLevel(t *testing.T) {
	l := NewLogger(LogInfo)
	l.SetLevel(LogDebug)
	if l.level != LogDebug {
		t.Errorf("expected LogDebug after SetLevel, got %d", l.level)
	}
	l.SetLevel(LogError)
	if l.level != LogError {
		t.Errorf("expected LogError after SetLevel, got %d", l.level)
	}
}

func TestCB43_NewLogger_LevelsFilterCorrectly(t *testing.T) {
	// Logger at Warn level should not output Debug or Info messages
	l := NewLogger(LogWarn)
	l.SetOutput(&bytes.Buffer{})

	buf := &bytes.Buffer{}
	l.SetOutput(buf)

	l.Debug("debug message")
	if buf.Len() > 0 {
		t.Error("Debug should not be written at Warn level")
	}

	l.Info("info message")
	if buf.Len() > 0 {
		t.Error("Info should not be written at Warn level")
	}

	l.Warn("warn message")
	if buf.Len() == 0 {
		t.Error("Warn should be written at Warn level")
	}

	// Reset buffer for Error
	buf.Reset()
	l.Error("error message")
	if buf.Len() == 0 {
		t.Error("Error should be written at Warn level")
	}
}

func TestCB43_NewLogger_DebugLevelOutputsAll(t *testing.T) {
	l := NewLogger(LogDebug)
	buf := &bytes.Buffer{}
	l.SetOutput(buf)

	l.Debug("debug msg")
	l.Info("info msg")
	l.Warn("warn msg")
	l.Error("error msg")

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 4 {
		t.Errorf("expected 4 log lines at Debug level, got %d", len(lines))
	}

	// Verify each line has correct level
	for i, expected := range []string{"debug", "info", "warn", "error"} {
		var entry map[string]interface{}
		if err := json.Unmarshal([]byte(lines[i]), &entry); err != nil {
			t.Errorf("failed to parse log line %d: %v", i, err)
			continue
		}
		if entry["level"] != expected {
			t.Errorf("line %d: expected level %s, got %v", i, expected, entry["level"])
		}
	}
}

func TestCB43_NewLogger_StructuredFields(t *testing.T) {
	l := NewLogger(LogInfo)
	buf := &bytes.Buffer{}
	l.SetOutput(buf)

	l.Info("test message", map[string]interface{}{"user_id": "u123", "action": "login"})

	var entry map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &entry); err != nil {
		t.Fatalf("failed to parse log: %v", err)
	}
	if entry["msg"] != "test message" {
		t.Errorf("expected msg 'test message', got %v", entry["msg"])
	}
	if entry["user_id"] != "u123" {
		t.Errorf("expected user_id 'u123', got %v", entry["user_id"])
	}
	if entry["action"] != "login" {
		t.Errorf("expected action 'login', got %v", entry["action"])
	}
	if entry["level"] != "info" {
		t.Errorf("expected level 'info', got %v", entry["level"])
	}
	if _, ok := entry["ts"]; !ok {
		t.Error("expected ts field to be present")
	}
}

func TestCB43_NewLogger_MultipleFieldsMerged(t *testing.T) {
	l := NewLogger(LogInfo)
	buf := &bytes.Buffer{}
	l.SetOutput(buf)

	// Pass multiple field maps - they should be merged
	l.Info("msg", map[string]interface{}{"a": 1}, map[string]interface{}{"b": 2})

	var entry map[string]interface{}
	json.Unmarshal(buf.Bytes(), &entry)
	if entry["a"] != float64(1) {
		t.Errorf("expected a=1, got %v", entry["a"])
	}
	if entry["b"] != float64(2) {
		t.Errorf("expected b=2, got %v", entry["b"])
	}
}

func TestCB43_NewLogger_NoFields(t *testing.T) {
	l := NewLogger(LogInfo)
	buf := &bytes.Buffer{}
	l.SetOutput(buf)

	l.Info("plain message")

	var entry map[string]interface{}
	json.Unmarshal(buf.Bytes(), &entry)
	if entry["msg"] != "plain message" {
		t.Errorf("expected msg 'plain message', got %v", entry["msg"])
	}
}

func TestCB43_NewLogger_WithFieldsThenLog(t *testing.T) {
	l := NewLogger(LogInfo)
	buf := &bytes.Buffer{}
	l.SetOutput(buf)

	l2 := l.WithFields(map[string]interface{}{"component": "router"})
	l2.SetOutput(buf) // ensure same output
	l2.Info("routing message", map[string]interface{}{"route": "chat"})

	var entry map[string]interface{}
	json.Unmarshal(buf.Bytes(), &entry)
	if entry["component"] != "router" {
		t.Errorf("expected component 'router', got %v", entry["component"])
	}
	if entry["route"] != "chat" {
		t.Errorf("expected route 'chat', got %v", entry["route"])
	}
}

// --- NewRateLimiter ---

func TestCB43_NewRateLimiter_Constructor(t *testing.T) {
	rl := NewRateLimiter(100, time.Minute)
	defer rl.Stop()

	if rl == nil {
		t.Fatal("NewRateLimiter returned nil")
	}
	if rl.limit != 100 {
		t.Errorf("expected limit 100, got %d", rl.limit)
	}
	if rl.window != time.Minute {
		t.Errorf("expected window 1m, got %v", rl.window)
	}
	if rl.counters == nil {
		t.Error("counters map is nil")
	}
	if len(rl.counters) != 0 {
		t.Errorf("expected 0 counters, got %d", len(rl.counters))
	}
}

func TestCB43_NewRateLimiter_Allow(t *testing.T) {
	rl := NewRateLimiter(3, time.Minute)
	defer rl.Stop()

	for i := 0; i < 3; i++ {
		if !rl.Allow("user1") {
			t.Errorf("expected Allow to return true on call %d", i+1)
		}
	}
	// 4th call should be rate limited
	if rl.Allow("user1") {
		t.Error("expected Allow to return false on 4th call")
	}
}

func TestCB43_NewRateLimiter_DifferentIDs(t *testing.T) {
	rl := NewRateLimiter(2, time.Minute)
	defer rl.Stop()

	// Each ID has its own limit
	if !rl.Allow("user1") {
		t.Error("user1 should be allowed")
	}
	if !rl.Allow("user1") {
		t.Error("user1 should be allowed (2nd)")
	}
	if rl.Allow("user1") {
		t.Error("user1 should be rate limited (3rd)")
	}

	// user2 has separate limit
	if !rl.Allow("user2") {
		t.Error("user2 should be allowed")
	}
	if !rl.Allow("user2") {
		t.Error("user2 should be allowed (2nd)")
	}
}

func TestCB43_NewRateLimiter_StopIsIdempotent(t *testing.T) {
	rl := NewRateLimiter(5, time.Minute)

	rl.Stop()
	rl.Stop() // should not panic
	rl.Stop() // should not panic
}

func TestCB43_NewRateLimiter_AllowAfterStop(t *testing.T) {
	rl := NewRateLimiter(5, time.Minute)
	rl.Stop()

	// Allow after stop should still work (just no cleanup goroutine)
	if !rl.Allow("user1") {
		t.Error("Allow should work after Stop (no cleanup but still functional)")
	}
}

// --- NewTieredRateLimiter ---

func TestCB43_NewTieredRateLimiter_Constructor(t *testing.T) {
	trl := NewTieredRateLimiter()
	defer trl.Stop()

	if trl == nil {
		t.Fatal("NewTieredRateLimiter returned nil")
	}
	if trl.limits == nil {
		t.Error("limits map is nil")
	}
	if len(trl.limits) != 0 {
		t.Errorf("expected 0 limits, got %d", len(trl.limits))
	}
	if trl.stopCh == nil {
		t.Error("stopCh is nil")
	}
}

func TestCB43_NewTieredRateLimiter_DefaultTierIsFree(t *testing.T) {
	trl := NewTieredRateLimiter()
	defer trl.Stop()

	// New user should get TierFree by default
	allowed, remaining, retryAfter := trl.Allow("new-user")
	if !allowed {
		t.Error("expected first request to be allowed")
	}
	if remaining != TierFree.Burst-1 {
		t.Errorf("expected remaining %d, got %d", TierFree.Burst-1, remaining)
	}
	if retryAfter != 0 {
		t.Errorf("expected retryAfter 0, got %d", retryAfter)
	}
}

func TestCB43_NewTieredRateLimiter_StopIsIdempotent(t *testing.T) {
	trl := NewTieredRateLimiter()

	trl.Stop()
	trl.Stop() // should not panic
	trl.Stop() // should not panic
}

func TestCB43_NewTieredRateLimiter_StopThenAllow(t *testing.T) {
	trl := NewTieredRateLimiter()
	trl.Stop()

	// Allow after stop should still work
	allowed, _, _ := trl.Allow("user1")
	if !allowed {
		t.Error("Allow should work after Stop")
	}
}

// --- handleMemoryStats ---

func TestCB43_HandleMemoryStats_Success(t *testing.T) {
	req := httptest.NewRequest("GET", "/admin/memory", nil)
	w := httptest.NewRecorder()

	handleMemoryStats(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	if result["status"] != "ok" {
		t.Errorf("expected status 'ok', got %v", result["status"])
	}
	if result["action"] != "stats" {
		t.Errorf("expected action 'stats', got %v", result["action"])
	}
	if result["timestamp"] == nil {
		t.Error("expected timestamp to be present")
	}
	mem, ok := result["memory"].(map[string]interface{})
	if !ok {
		t.Fatal("expected memory to be a map")
	}
	// Verify expected memory stat fields
	expectedKeys := []string{"alloc_bytes", "total_alloc_bytes", "sys_bytes", "heap_alloc_bytes",
		"heap_sys_bytes", "heap_objects", "stack_inuse_bytes", "num_gc",
		"goroutines", "next_gc_bytes", "gc_pause_total_ns", "last_gc_ns"}
	for _, key := range expectedKeys {
		if _, exists := mem[key]; !exists {
			t.Errorf("expected memory field %s to be present", key)
		}
	}
}

func TestCB43_HandleMemoryStats_ContentType(t *testing.T) {
	req := httptest.NewRequest("GET", "/admin/memory", nil)
	w := httptest.NewRecorder()

	handleMemoryStats(w, req)

	ct := w.Header().Get("Content-Type")
	if ct != "application/json" {
		t.Errorf("expected Content-Type 'application/json', got %q", ct)
	}
}

func TestCB43_HandleMemoryStats_MultipleCalls(t *testing.T) {
	// Multiple calls should each produce valid responses
	for i := 0; i < 5; i++ {
		req := httptest.NewRequest("GET", "/admin/memory", nil)
		w := httptest.NewRecorder()

		handleMemoryStats(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("call %d: expected 200, got %d", i, w.Code)
		}

		var result map[string]interface{}
		if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
			t.Errorf("call %d: failed to parse: %v", i, err)
		}
		if result["status"] != "ok" {
			t.Errorf("call %d: expected status ok", i)
		}
	}
}

func TestCB43_HandleMemoryStats_AnyMethod(t *testing.T) {
	// handleMemoryStats doesn't check method — it should work for any method
	for _, method := range []string{"GET", "POST", "DELETE"} {
		req := httptest.NewRequest(method, "/admin/memory", nil)
		w := httptest.NewRecorder()

		handleMemoryStats(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("method %s: expected 200, got %d", method, w.Code)
		}
	}
}

// --- writeProfileJSON ---

func TestCB43_WriteProfileJSON_BasicOutput(t *testing.T) {
	w := httptest.NewRecorder()

	data := map[string]interface{}{
		"status": "ok",
		"count":  42,
		"name":   "test",
	}
	writeProfileJSON(w, data)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200 (default), got %d", w.Code)
	}
	ct := w.Header().Get("Content-Type")
	if ct != "application/json" {
		t.Errorf("expected Content-Type 'application/json', got %q", ct)
	}

	var result map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &result)
	if result["status"] != "ok" {
		t.Errorf("expected status 'ok', got %v", result["status"])
	}
	if result["count"] != float64(42) {
		t.Errorf("expected count 42, got %v", result["count"])
	}
	if result["name"] != "test" {
		t.Errorf("expected name 'test', got %v", result["name"])
	}
}

func TestCB43_WriteProfileJSON_EmptyMap(t *testing.T) {
	w := httptest.NewRecorder()

	writeProfileJSON(w, map[string]interface{}{})

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	if w.Body.String() != "{}\n" {
		t.Errorf("expected '{}\\n', got %q", w.Body.String())
	}
}

func TestCB43_WriteProfileJSON_NilValues(t *testing.T) {
	w := httptest.NewRecorder()

	writeProfileJSON(w, map[string]interface{}{
		"nil_val":  nil,
		"str_val":  "hello",
		"int_val":  100,
		"bool_val": true,
	})

	var result map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &result)
	// json.Marshal includes nil values as `null` in maps
	if v, ok := result["nil_val"]; ok && v != nil {
		t.Errorf("expected nil_val to be null, got %v", v)
	}
	if result["str_val"] != "hello" {
		t.Errorf("expected str_val 'hello', got %v", result["str_val"])
	}
	if result["int_val"] != float64(100) {
		t.Errorf("expected int_val 100, got %v", result["int_val"])
	}
	if result["bool_val"] != true {
		t.Errorf("expected bool_val true, got %v", result["bool_val"])
	}
}

func TestCB43_WriteProfileJSON_NestedMap(t *testing.T) {
	w := httptest.NewRecorder()

	writeProfileJSON(w, map[string]interface{}{
		"outer": map[string]interface{}{
			"inner": "value",
		},
	})

	var result map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &result)
	outer, ok := result["outer"].(map[string]interface{})
	if !ok {
		t.Fatal("expected outer to be a map")
	}
	if outer["inner"] != "value" {
		t.Errorf("expected inner 'value', got %v", outer["inner"])
	}
}

// --- mergeOpt edge cases ---

func TestCB43_MergeOpt_NilInput(t *testing.T) {
	result := mergeOpt(nil)
	if result != nil {
		t.Errorf("expected nil for nil input, got %v", result)
	}
}

func TestCB43_MergeOpt_EmptySlice(t *testing.T) {
	result := mergeOpt([]map[string]interface{}{})
	if result != nil {
		t.Errorf("expected nil for empty slice, got %v", result)
	}
}

func TestCB43_MergeOpt_SingleMap(t *testing.T) {
	result := mergeOpt([]map[string]interface{}{
		{"a": 1, "b": "two"},
	})
	if result["a"] != 1 {
		t.Errorf("expected a=1, got %v", result["a"])
	}
	if result["b"] != "two" {
		t.Errorf("expected b='two', got %v", result["b"])
	}
	if len(result) != 2 {
		t.Errorf("expected 2 keys, got %d", len(result))
	}
}

func TestCB43_MergeOpt_LaterOverrides(t *testing.T) {
	result := mergeOpt([]map[string]interface{}{
		{"key": "first"},
		{"key": "second"},
	})
	if result["key"] != "second" {
		t.Errorf("expected key='second' (later overrides), got %v", result["key"])
	}
}

func TestCB43_MergeOpt_ThreeMaps(t *testing.T) {
	result := mergeOpt([]map[string]interface{}{
		{"a": 1},
		{"b": 2},
		{"c": 3, "a": 10}, // overrides a
	})
	if result["a"] != 10 {
		t.Errorf("expected a=10, got %v", result["a"])
	}
	if result["b"] != 2 {
		t.Errorf("expected b=2, got %v", result["b"])
	}
	if result["c"] != 3 {
		t.Errorf("expected c=3, got %v", result["c"])
	}
}

// --- LogLevel String ---

func TestCB43_LogLevel_String_AllLevels(t *testing.T) {
	cases := []struct {
		level    LogLevel
		expected string
	}{
		{LogDebug, "debug"},
		{LogInfo, "info"},
		{LogWarn, "warn"},
		{LogError, "error"},
		{LogLevel(99), "unknown"},
		{LogLevel(-1), "unknown"},
	}
	for _, c := range cases {
		if got := c.level.String(); got != c.expected {
			t.Errorf("LogLevel(%d).String() = %q, expected %q", c.level, got, c.expected)
		}
	}
}

// --- newHub + run integration ---

func TestCB43_NewHub_RunAndStop_Lifecycle(t *testing.T) {
	origQueue := offlineQueue
	t.Cleanup(func() { offlineQueue = origQueue })

	h := newHub()
	go h.run()

	// Register an agent
	agent := &Connection{
		id:       "agent-lifecycle",
		connType: "agent",
		send:     make(chan []byte, 10),
		hub:      h,
	}
	h.register <- agent

	// Give hub time to process
	time.Sleep(10 * time.Millisecond)

	// Verify agent was registered
	h.mu.RLock()
	_, ok := h.agents["agent-lifecycle"]
	h.mu.RUnlock()
	if !ok {
		t.Error("agent was not registered")
	}

	// Unregister the agent
	h.unregister <- agent
	time.Sleep(10 * time.Millisecond)

	h.mu.RLock()
	_, ok = h.agents["agent-lifecycle"]
	h.mu.RUnlock()
	if ok {
		t.Error("agent should have been unregistered")
	}

	// Stop hub
	h.Stop()
}

func TestCB43_NewHub_BroadcastToAll(t *testing.T) {
	origQueue := offlineQueue
	t.Cleanup(func() { offlineQueue = origQueue })

	h := newHub()
	go h.run()
	t.Cleanup(func() { h.Stop() })

	// Register agent
	agent := &Connection{
		id:       "agent-bcast",
		connType: "agent",
		send:     make(chan []byte, 10),
		hub:      h,
	}
	h.register <- agent

	// Register client
	client := &Connection{
		id:       "user-bcast",
		connType: "client",
		deviceID: "dev1",
		send:     make(chan []byte, 10),
		hub:      h,
	}
	h.register <- client

	time.Sleep(10 * time.Millisecond)

	// Broadcast a message
	h.broadcast <- []byte(`{"type":"announcement"}`)
	time.Sleep(10 * time.Millisecond)

	// Both should have received the message
	select {
	case <-agent.send:
		// expected
	default:
		t.Error("agent did not receive broadcast")
	}
	select {
	case <-client.send:
		// expected
	default:
		t.Error("client did not receive broadcast")
	}
}

// --- handleMemoryStats with ServerMetrics ---

func TestCB43_HandleMemoryStats_GoroutineCount(t *testing.T) {
	beforeStats := MemoryStats()
	beforeGoroutines := beforeStats["goroutines"]

	req := httptest.NewRequest("GET", "/admin/memory", nil)
	w := httptest.NewRecorder()

	handleMemoryStats(w, req)

	var result map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &result)
	mem := result["memory"].(map[string]interface{})
	afterGoroutines := mem["goroutines"]

	// Goroutine count should be a positive number
	if goroutines, ok := afterGoroutines.(float64); ok {
		if goroutines < 1 {
			t.Errorf("expected at least 1 goroutine, got %v", goroutines)
		}
		_ = beforeGoroutines // just to use the variable
	} else {
		t.Errorf("goroutines field has unexpected type: %T", afterGoroutines)
	}
}

// --- writeProfileJSON content-type always set ---

func TestCB43_WriteProfileJSON_AlwaysSetsContentType(t *testing.T) {
	w := httptest.NewRecorder()
	writeProfileJSON(w, map[string]interface{}{"x": 1})

	ct := w.Header().Get("Content-Type")
	if ct != "application/json" {
		t.Errorf("expected 'application/json', got %q", ct)
	}

	// Verify the body is valid JSON
	var result map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Errorf("response body is not valid JSON: %v", err)
	}
}