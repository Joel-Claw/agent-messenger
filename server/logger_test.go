package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestLoggerLevels(t *testing.T) {
	var buf bytes.Buffer
	logger := NewLogger(LogInfo)
	logger.SetOutput(&buf)

	logger.Debug("should not appear")
	logger.Info("info message")
	logger.Warn("warn message")
	logger.Error("error message")

	output := buf.String()
	if strings.Contains(output, `"level":"debug"`) {
		t.Error("debug messages should not appear at Info level")
	}
	if !strings.Contains(output, `"level":"info"`) {
		t.Error("expected info level in output")
	}
	if !strings.Contains(output, `"level":"warn"`) {
		t.Error("expected warn level in output")
	}
	if !strings.Contains(output, `"level":"error"`) {
		t.Error("expected error level in output")
	}
}

func TestLoggerWithFields(t *testing.T) {
	var buf bytes.Buffer
	logger := NewLogger(LogDebug)
	logger.SetOutput(&buf)

	logger.Info("test message", map[string]interface{}{"key": "value", "count": 42})

	output := buf.String()
	var entry map[string]interface{}
	if err := json.Unmarshal([]byte(strings.TrimSpace(output)), &entry); err != nil {
		t.Fatalf("output is not valid JSON: %v, output: %q", err, output)
	}
	if entry["msg"] != "test message" {
		t.Errorf("expected msg='test message', got %v", entry["msg"])
	}
	if entry["key"] != "value" {
		t.Errorf("expected key='value', got %v", entry["key"])
	}
	if entry["count"] != float64(42) {
		t.Errorf("expected count=42, got %v", entry["count"])
	}
}

func TestLoggerSetLevel(t *testing.T) {
	var buf bytes.Buffer
	logger := NewLogger(LogWarn)
	logger.SetOutput(&buf)

	logger.Info("should not appear")
	logger.Warn("should appear")

	output := buf.String()
	if strings.Contains(output, "should not appear") {
		t.Error("Info messages should not appear at Warn level")
	}
	if !strings.Contains(output, "should appear") {
		t.Error("Warn messages should appear at Warn level")
	}
}

func TestLoggerWithFieldsChain(t *testing.T) {
	var buf bytes.Buffer
	logger := NewLogger(LogInfo)
	logger.SetOutput(&buf)

	contextLogger := logger.WithFields(map[string]interface{}{"request_id": "abc123"})
	contextLogger.Info("handled request")

	output := buf.String()
	var entry map[string]interface{}
	if err := json.Unmarshal([]byte(strings.TrimSpace(output)), &entry); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if entry["request_id"] != "abc123" {
		t.Errorf("expected request_id='abc123', got %v", entry["request_id"])
	}
}

func TestLogLevelString(t *testing.T) {
	tests := []struct {
		level    LogLevel
		expected string
	}{
		{LogDebug, "debug"},
		{LogInfo, "info"},
		{LogWarn, "warn"},
		{LogError, "error"},
		{LogLevel(99), "unknown"},
	}
	for _, tt := range tests {
		if got := tt.level.String(); got != tt.expected {
			t.Errorf("LogLevel(%d).String() = %q, want %q", tt.level, got, tt.expected)
		}
	}
}

func TestRequestIDMiddleware(t *testing.T) {
	var receivedID string
	handler := requestIDMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedID = r.Header.Get("X-Request-ID")
		w.WriteHeader(http.StatusOK)
	}))

	// Test: request without X-Request-ID should generate one
	req, _ := http.NewRequest("GET", "/test", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if receivedID == "" {
		t.Error("expected request ID to be generated")
	}
	respID := rec.Header().Get("X-Request-ID")
	if respID == "" {
		t.Error("expected X-Request-ID in response header")
	}
	if receivedID != respID {
		t.Errorf("request context ID %q != response header ID %q", receivedID, respID)
	}

	// Test: request with existing X-Request-ID should preserve it
	req2, _ := http.NewRequest("GET", "/test", nil)
	req2.Header.Set("X-Request-ID", "custom-id-123")
	rec2 := httptest.NewRecorder()
	handler.ServeHTTP(rec2, req2)

	if receivedID != "custom-id-123" {
		t.Errorf("expected preserved ID 'custom-id-123', got %q", receivedID)
	}
	respID2 := rec2.Header().Get("X-Request-ID")
	if respID2 != "custom-id-123" {
		t.Errorf("expected response header 'custom-id-123', got %q", respID2)
	}
}

func TestAccessLogMiddleware(t *testing.T) {
	var buf bytes.Buffer
	DefaultLogger.SetOutput(&buf)
	defer DefaultLogger.SetOutput(os.Stdout)

	handler := accessLogMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
	}))

	req, _ := http.NewRequest("POST", "/conversations/create", nil)
	req.Header.Set("X-Request-ID", "test-req-123")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	output := buf.String()
	if !strings.Contains(output, `"path":"/conversations/create"`) {
		t.Errorf("expected path in access log, got: %s", output)
	}
	if !strings.Contains(output, `"method":"POST"`) {
		t.Errorf("expected method in access log, got: %s", output)
	}
	if !strings.Contains(output, `"status":201`) {
		t.Errorf("expected status 201 in access log, got: %s", output)
	}
	if !strings.Contains(output, `"request_id":"test-req-123"`) {
		t.Errorf("expected request_id in access log, got: %s", output)
	}
}

func TestResponseWriterWrapper(t *testing.T) {
	rec := httptest.NewRecorder()
	wrapped := &responseWriterWrapper{ResponseWriter: rec, statusCode: 200}

	wrapped.WriteHeader(http.StatusNotFound)
	if wrapped.statusCode != http.StatusNotFound {
		t.Errorf("expected status 404, got %d", wrapped.statusCode)
	}

	// Test default status code (when WriteHeader is never called)
	rec2 := httptest.NewRecorder()
	wrapped2 := &responseWriterWrapper{ResponseWriter: rec2, statusCode: 200}
	wrapped2.Write([]byte("hello"))
	if wrapped2.statusCode != 200 {
		t.Errorf("expected default status 200, got %d", wrapped2.statusCode)
	}
}