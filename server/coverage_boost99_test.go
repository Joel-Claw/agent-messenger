package main

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// CB99: Coverage boost for tracing convenience functions, hub helpers,
// and other low-coverage paths.

// --- Tracing disabled paths (tracingEnabled = false) ---

func TestCB99_TraceRouteMessage_Disabled(t *testing.T) {
	span := TraceRouteMessage("agent", "conn123")
	if span == nil {
		t.Fatal("expected non-nil span even when tracing disabled")
	}
	span.End()
}

func TestCB99_TraceOfflineEnqueue_Disabled(t *testing.T) {
	span := TraceOfflineEnqueue("user1")
	if span == nil {
		t.Fatal("expected non-nil span even when tracing disabled")
	}
	span.End()
}

func TestCB99_TracePushNotify_Disabled(t *testing.T) {
	span := TracePushNotify("user1", "conv1", true)
	if span == nil {
		t.Fatal("expected non-nil span even when tracing disabled")
	}
	span.End()
}

func TestCB99_TraceAgentConnect_Disabled(t *testing.T) {
	span := TraceAgentConnect("agent1")
	if span == nil {
		t.Fatal("expected non-nil span even when tracing disabled")
	}
	span.End()
}

func TestCB99_TraceClientConnect_Disabled(t *testing.T) {
	span := TraceClientConnect("user1", "device1")
	if span == nil {
		t.Fatal("expected non-nil span even when tracing disabled")
	}
	span.End()
}

func TestCB99_TraceChatMessage_Disabled(t *testing.T) {
	ctx := context.Background()
	ctx, span := TraceChatMessage(ctx, "agent", "agent1", "conv1", "user1")
	if span == nil {
		t.Fatal("expected non-nil span even when tracing disabled")
	}
	span.End()
	_ = ctx
}

func TestCB99_TraceStoreMessage_Disabled(t *testing.T) {
	ctx := context.Background()
	ctx, span := TraceStoreMessage(ctx, "conv1", "agent1")
	if span == nil {
		t.Fatal("expected non-nil span even when tracing disabled")
	}
	span.End()
	_ = ctx
}

func TestCB99_TraceDeliverMessage_Disabled(t *testing.T) {
	ctx := context.Background()
	ctx, span := TraceDeliverMessage(ctx, "user1", "client", true)
	if span == nil {
		t.Fatal("expected non-nil span even when tracing disabled")
	}
	span.End()
	_ = ctx
}

func TestCB99_StartSpan_Disabled(t *testing.T) {
	ctx := context.Background()
	ctx, span := StartSpan(ctx, "test-span")
	if span == nil {
		t.Fatal("expected non-nil span even when tracing disabled")
	}
	span.End()
	_ = ctx
}

func TestCB99_StartSpanFromRequest_Disabled(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	ctx, span := StartSpanFromRequest(req, "test-span")
	if span == nil {
		t.Fatal("expected non-nil span even when tracing disabled")
	}
	span.End()
	_ = ctx
}

func TestCB99_SpanError_Disabled(t *testing.T) {
	span := TraceRouteMessage("agent", "conn1")
	SpanError(span, fmt.Errorf("test error"))
	span.End()
}

func TestCB99_SpanOK_Disabled(t *testing.T) {
	span := TraceRouteMessage("agent", "conn1")
	SpanOK(span)
	span.End()
}

func TestCB99_IsTracingEnabled_Default(t *testing.T) {
	// tracingEnabled should be false by default
	if IsTracingEnabled() {
		t.Fatal("tracing should be disabled by default")
	}
}

// --- Hub helper methods ---

func TestCB99_HubGetAgent_Nil(t *testing.T) {
	h := newHub()
	defer h.Stop()
	if c := h.GetAgent("nonexistent"); c != nil {
		t.Fatal("expected nil for nonexistent agent")
	}
}

func TestCB99_HubGetClient_Nil(t *testing.T) {
	h := newHub()
	defer h.Stop()
	if c := h.GetClient("nonexistent"); c != nil {
		t.Fatal("expected nil for nonexistent client")
	}
}

func TestCB99_HubGetClientConns_Empty(t *testing.T) {
	h := newHub()
	defer h.Stop()
	conns := h.GetClientConns("nonexistent")
	if len(conns) != 0 {
		t.Fatalf("expected 0 conns, got %d", len(conns))
	}
}

func TestCB99_HubAgentCount_Zero(t *testing.T) {
	h := newHub()
	defer h.Stop()
	if h.AgentCount() != 0 {
		t.Fatalf("expected 0 agents, got %d", h.AgentCount())
	}
}

func TestCB99_HubClientCount_Zero(t *testing.T) {
	h := newHub()
	defer h.Stop()
	if h.ClientCount() != 0 {
		t.Fatalf("expected 0 clients, got %d", h.ClientCount())
	}
}

func TestCB99_HubClientConnCount_Zero(t *testing.T) {
	h := newHub()
	defer h.Stop()
	if h.ClientConnCount() != 0 {
		t.Fatalf("expected 0 client conns, got %d", h.ClientConnCount())
	}
}

func TestCB99_HubStaleAgentCount_Zero(t *testing.T) {
	h := newHub()
	defer h.Stop()
	if h.StaleAgentCount() != 0 {
		t.Fatalf("expected 0 stale agents, got %d", h.StaleAgentCount())
	}
}

func TestCB99_HubAgentStatus_NotFound(t *testing.T) {
	h := newHub()
	defer h.Stop()
	status := h.AgentStatus("nonexistent")
	if status != "offline" {
		t.Fatalf("expected 'offline' for nonexistent agent, got %q", status)
	}
}

func TestCB99_HubSetAgentStatus_Nonexistent(t *testing.T) {
	h := newHub()
	defer h.Stop()
	// Should not panic when setting status for nonexistent agent
	h.SetAgentStatus("nonexistent", "busy")
}

func TestCB99_HubBroadcastToAllClients_NoClients(t *testing.T) {
	h := newHub()
	defer h.Stop()
	// Should not panic with no clients
	h.BroadcastToAllClients([]byte("test"))
}

func TestCB99_HubBroadcastPresence_NoConnections(t *testing.T) {
	h := newHub()
	defer h.Stop()
	// Should not panic with no connections
	h.broadcastPresence("nonexistent", "agent", true)
	h.broadcastPresence("nonexistent", "agent", false)
	h.broadcastPresence("nonexistent", "client", true)
	h.broadcastPresence("nonexistent", "client", false)
}

// --- Connection methods ---

func TestCB99_ConnectionIsClosed_Default(t *testing.T) {
	conn := &Connection{}
	if conn.IsClosed() {
		t.Fatal("expected IsClosed() to be false by default")
	}
}

func TestCB99_ConnectionMarkClosed(t *testing.T) {
	conn := &Connection{}
	conn.MarkClosed()
	if !conn.IsClosed() {
		t.Fatal("expected IsClosed() to be true after MarkClosed()")
	}
}

func TestCB99_ConnectionSafeSend_Closed(t *testing.T) {
	conn := &Connection{
		send: make(chan []byte, 1),
	}
	conn.MarkClosed()
	if conn.SafeSend([]byte("test")) {
		t.Fatal("expected SafeSend to return false on closed connection")
	}
}

func TestCB99_ConnectionSafeSend_Success(t *testing.T) {
	conn := &Connection{
		send: make(chan []byte, 1),
	}
	if !conn.SafeSend([]byte("test")) {
		t.Fatal("expected SafeSend to return true")
	}
}

// --- Queue functions ---

func TestCB99_NewOfflineQueue(t *testing.T) {
	q := newOfflineQueue(50, time.Hour)
	if q == nil {
		t.Fatal("expected non-nil queue")
	}
	if q.TotalDepth() != 0 {
		t.Fatalf("expected 0 depth, got %d", q.TotalDepth())
	}
}

func TestCB99_OfflineQueue_Purge(t *testing.T) {
	q := newOfflineQueue(50, time.Hour)
	q.Enqueue("user1", []byte("msg1"))
	if q.QueueDepth("user1") != 1 {
		t.Fatalf("expected depth 1, got %d", q.QueueDepth("user1"))
	}
	q.Purge("user1")
	if q.QueueDepth("user1") != 0 {
		t.Fatalf("expected depth 0 after purge, got %d", q.QueueDepth("user1"))
	}
}

func TestCB99_OfflineQueue_Drain_Empty(t *testing.T) {
	q := newOfflineQueue(50, time.Hour)
	msgs := q.Drain("nonexistent")
	if len(msgs) != 0 {
		t.Fatalf("expected 0 messages, got %d", len(msgs))
	}
}

func TestCB99_OfflineQueue_TotalDepth_Multiple(t *testing.T) {
	q := newOfflineQueue(100, time.Hour)
	q.Enqueue("user1", []byte("msg1"))
	q.Enqueue("user1", []byte("msg2"))
	q.Enqueue("user2", []byte("msg3"))
	if q.TotalDepth() != 3 {
		t.Fatalf("expected total depth 3, got %d", q.TotalDepth())
	}
}

func TestCB99_MarshalOutgoingMessage_Success(t *testing.T) {
	msg := OutgoingMessage{
		Type: "chat_message",
		Data: "hello world",
	}
	data := marshalOutgoingMessage(msg)
	if len(data) == 0 {
		t.Fatal("expected non-empty output")
	}
}

// --- safeSendToConn ---

func TestCB99_SafeSendToConn_NilConn(t *testing.T) {
	result := safeSendToConn(nil, []byte("test"))
	if result {
		t.Fatal("expected false for nil connection")
	}
}

// --- getEnvOrDefault ---

func TestCB99_GetEnvOrDefault_WithEnv(t *testing.T) {
	t.Setenv("TEST_CB99_VAR", "custom_value")
	result := getEnvOrDefault("TEST_CB99_VAR", "default")
	if result != "custom_value" {
		t.Fatalf("expected 'custom_value', got %q", result)
	}
}

func TestCB99_GetEnvOrDefault_Default(t *testing.T) {
	result := getEnvOrDefault("TEST_CB99_NONEXISTENT_VAR", "fallback")
	if result != "fallback" {
		t.Fatalf("expected 'fallback', got %q", result)
	}
}

// --- safeTruncate ---

func TestCB99_SafeTruncate_Short(t *testing.T) {
	result := safeTruncate("hello", 10)
	if result != "hello" {
		t.Fatalf("expected 'hello', got %q", result)
	}
}

func TestCB99_SafeTruncate_Exact(t *testing.T) {
	result := safeTruncate("hello", 5)
	if result != "hello" {
		t.Fatalf("expected 'hello', got %q", result)
	}
}

func TestCB99_SafeTruncate_Truncate(t *testing.T) {
	result := safeTruncate("hello world", 5)
	if result != "hello" {
		t.Fatalf("expected 'hello', got %q", result)
	}
}

func TestCB99_SafeTruncate_Empty(t *testing.T) {
	result := safeTruncate("", 5)
	if result != "" {
		t.Fatalf("expected '', got %q", result)
	}
}

func TestCB99_SafeTruncate_ZeroN(t *testing.T) {
	result := safeTruncate("hello", 0)
	if result != "" {
		t.Fatalf("expected '', got %q", result)
	}
}

// --- initQueueDB ---

func TestCB99_InitQueueDB_NilDB(t *testing.T) {
	// initQueueDB returns nothing; nil DB should not panic
	initQueueDB(nil)
}

// --- parseSize ---

func TestCB99_ParseSize_Bytes(t *testing.T) {
	size, err := parseSize("500B")
	if err != nil || size != 500 {
		t.Fatalf("expected 500, got %d, err: %v", size, err)
	}
}

func TestCB99_ParseSize_KB(t *testing.T) {
	size, err := parseSize("10KB")
	if err != nil || size != 10*1024 {
		t.Fatalf("expected %d, got %d, err: %v", 10*1024, size, err)
	}
}

func TestCB99_ParseSize_MB(t *testing.T) {
	size, err := parseSize("5MB")
	if err != nil || size != 5*1024*1024 {
		t.Fatalf("expected %d, got %d, err: %v", 5*1024*1024, size, err)
	}
}

func TestCB99_ParseSize_GB(t *testing.T) {
	size, err := parseSize("1GB")
	if err != nil || size != 1024*1024*1024 {
		t.Fatalf("expected %d, got %d, err: %v", 1024*1024*1024, size, err)
	}
}

func TestCB99_ParseSize_TB(t *testing.T) {
	size, err := parseSize("2TB")
	if err != nil || size != 2*1024*1024*1024*1024 {
		t.Fatalf("expected %d, got %d, err: %v", 2*1024*1024*1024*1024, size, err)
	}
}

func TestCB99_ParseSize_Invalid(t *testing.T) {
	_, err := parseSize("invalid")
	if err == nil {
		t.Fatal("expected error for invalid input")
	}
}

func TestCB99_ParseSize_Empty(t *testing.T) {
	_, err := parseSize("")
	if err == nil {
		t.Fatal("expected error for empty input")
	}
}

// --- monitorAgentHeartbeats / checkStaleAgents ---

func TestCB99_CheckStaleAgents_NoAgents(t *testing.T) {
	h := newHub()
	defer h.Stop()
	h.checkStaleAgents()
	// Should not panic with no agents
}