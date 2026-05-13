package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"
)

func TestTracingDisabledByDefault(t *testing.T) {
	// Ensure tracing is disabled when OTEL_ENABLED is not set
	os.Unsetenv("OTEL_ENABLED")
	os.Unsetenv("OTEL_EXPORTER_OTLP_ENDPOINT")

	// Reset the once so we can reinitialize
	tracingMu = sync.Once{}
	tracingEnabled = false
	tp = nil
	tracer = nil

	// InitTracing should succeed but not enable tracing
	if err := InitTracing(); err != nil {
		t.Fatalf("InitTracing failed: %v", err)
	}
	if tracingEnabled {
		t.Error("tracing should be disabled when OTEL_ENABLED is not set")
	}
	if IsTracingEnabled() {
		t.Error("IsTracingEnabled() should return false")
	}
}

func TestTracingDisabledWithoutEndpoint(t *testing.T) {
	os.Setenv("OTEL_ENABLED", "true")
	os.Unsetenv("OTEL_EXPORTER_OTLP_ENDPOINT")
	os.Unsetenv("OTEL_EXPORTER_OTLP_HTTP_ENDPOINT")

	// Reset
	tracingMu = sync.Once{}
	tracingEnabled = false
	tp = nil
	tracer = nil

	if err := InitTracing(); err != nil {
		t.Fatalf("InitTracing failed: %v", err)
	}
	if tracingEnabled {
		t.Error("tracing should be disabled when no endpoint is configured")
	}

	os.Unsetenv("OTEL_ENABLED")
}

func TestTracingStartSpanWhenDisabled(t *testing.T) {
	// Ensure spans are no-op when tracing is disabled
	tracingEnabled = false
	tracer = nil

	ctx, span := StartSpan(nil, "test_span")
	if ctx != nil {
		t.Error("StartSpan should return nil context when tracing is disabled")
	}
	if span == nil {
		t.Error("StartSpan should return a non-nil no-op span when tracing is disabled")
	}
	// Should not panic
	span.End()
}

func TestTraceRouteMessageWhenDisabled(t *testing.T) {
	tracingEnabled = false
	tracer = nil

	span := TraceRouteMessage("agent", "test-agent")
	if span == nil {
		t.Error("TraceRouteMessage should return a non-nil span even when disabled")
	}
	span.End() // Should not panic
}

func TestTraceChatMessageWhenDisabled(t *testing.T) {
	tracingEnabled = false
	tracer = nil

	_, span := TraceChatMessage(nil, "agent", "test", "conv-1", "user-1")
	if span == nil {
		t.Error("TraceChatMessage should return a non-nil span even when disabled")
	}
	span.End()
}

func TestTraceStoreMessageWhenDisabled(t *testing.T) {
	tracingEnabled = false
	tracer = nil

	_, span := TraceStoreMessage(nil, "conv-1", "user-1")
	if span == nil {
		t.Error("TraceStoreMessage should return a non-nil span even when disabled")
	}
	span.End()
}

func TestTraceDeliverMessageWhenDisabled(t *testing.T) {
	tracingEnabled = false
	tracer = nil

	_, span := TraceDeliverMessage(nil, "user-1", "client", true)
	if span == nil {
		t.Error("TraceDeliverMessage should return a non-nil span even when disabled")
	}
	span.End()
}

func TestTraceOfflineEnqueueWhenDisabled(t *testing.T) {
	tracingEnabled = false
	tracer = nil

	span := TraceOfflineEnqueue("user-1")
	if span == nil {
		t.Error("TraceOfflineEnqueue should return a non-nil span even when disabled")
	}
	span.End()
}

func TestTracePushNotifyWhenDisabled(t *testing.T) {
	tracingEnabled = false
	tracer = nil

	span := TracePushNotify("user-1", "conv-1", true)
	if span == nil {
		t.Error("TracePushNotify should return a non-nil span even when disabled")
	}
	span.End()
}

func TestTraceAgentConnectWhenDisabled(t *testing.T) {
	tracingEnabled = false
	tracer = nil

	span := TraceAgentConnect("agent-1")
	if span == nil {
		t.Error("TraceAgentConnect should return a non-nil span even when disabled")
	}
	span.End()
}

func TestTraceClientConnectWhenDisabled(t *testing.T) {
	tracingEnabled = false
	tracer = nil

	span := TraceClientConnect("user-1", "device-1")
	if span == nil {
		t.Error("TraceClientConnect should return a non-nil span even when disabled")
	}
	span.End()
}

func TestSpanErrorWhenDisabled(t *testing.T) {
	tracingEnabled = false
	tracer = nil

	span := TraceRouteMessage("agent", "test-agent")
	// Should not panic
	SpanError(span, os.ErrNotExist)
	SpanOK(span)
}

func TestStartSpanFromRequestWhenDisabled(t *testing.T) {
	tracingEnabled = false
	tracer = nil

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	ctx, span := StartSpanFromRequest(req, "http_request")
	if ctx == nil {
		t.Error("StartSpanFromRequest should return non-nil context")
	}
	if span == nil {
		t.Error("StartSpanFromRequest should return non-nil span")
	}
	span.End()
}

func TestTracingConstants(t *testing.T) {
	// Verify span name constants are defined correctly
	if spanRouteMessage != "route_message" {
		t.Errorf("expected spanRouteMessage = 'route_message', got %q", spanRouteMessage)
	}
	if spanRouteChatMessage != "route_chat_message" {
		t.Errorf("expected spanRouteChatMessage = 'route_chat_message', got %q", spanRouteChatMessage)
	}
	if spanAgentConnect != "ws.agent_connect" {
		t.Errorf("expected spanAgentConnect = 'ws.agent_connect', got %q", spanAgentConnect)
	}
	if spanClientConnect != "ws.client_connect" {
		t.Errorf("expected spanClientConnect = 'ws.client_connect', got %q", spanClientConnect)
	}
	if spanStoreMessage != "store_message" {
		t.Errorf("expected spanStoreMessage = 'store_message', got %q", spanStoreMessage)
	}
	if spanDeliverMessage != "deliver_message" {
		t.Errorf("expected spanDeliverMessage = 'deliver_message', got %q", spanDeliverMessage)
	}
	if spanOfflineEnqueue != "offline_enqueue" {
		t.Errorf("expected spanOfflineEnqueue = 'offline_enqueue', got %q", spanOfflineEnqueue)
	}
	if spanPushNotify != "push_notify" {
		t.Errorf("expected spanPushNotify = 'push_notify', got %q", spanPushNotify)
	}
}

func TestTracingEnvVars(t *testing.T) {
	// Test that OTEL_ENABLED=true is required for tracing
	os.Unsetenv("OTEL_ENABLED")
	tracingMu = sync.Once{}
	tracingEnabled = false

	if err := InitTracing(); err != nil {
		t.Fatalf("InitTracing failed: %v", err)
	}
	if IsTracingEnabled() {
		t.Error("tracing should be disabled without OTEL_ENABLED=true")
	}

	// Reset for next test
	tracingMu = sync.Once{}
	tracingEnabled = false
	tp = nil
	tracer = nil
}