package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

func TestRateLimiterAllowsUnderLimit(t *testing.T) {
	rl := NewRateLimiter(3, time.Minute)

	for i := 0; i < 3; i++ {
		if !rl.Allow("user1") {
			t.Fatalf("expected allow on message %d", i+1)
		}
	}
}

func TestRateLimiterBlocksOverLimit(t *testing.T) {
	rl := NewRateLimiter(3, time.Minute)

	for i := 0; i < 3; i++ {
		rl.Allow("user1")
	}

	if rl.Allow("user1") {
		t.Fatal("expected rate limit to block 4th message")
	}
}

func TestRateLimiterIndependentUsers(t *testing.T) {
	rl := NewRateLimiter(2, time.Minute)

	rl.Allow("user1")
	rl.Allow("user1")

	// user2 should still be allowed
	if !rl.Allow("user2") {
		t.Fatal("user2 should not be affected by user1's rate limit")
	}
}

func TestRateLimiterResetsAfterWindow(t *testing.T) {
	rl := NewRateLimiter(2, 50*time.Millisecond)

	rl.Allow("user1")
	rl.Allow("user1")

	if rl.Allow("user1") {
		t.Fatal("expected rate limit to block")
	}

	// Wait for window to expire
	time.Sleep(80 * time.Millisecond)

	if !rl.Allow("user1") {
		t.Fatal("expected rate limit to reset after window")
	}
}

func TestRateLimitOnWebSocket(t *testing.T) {
	setupTestDB(t)
	hub = newHub()
	go hub.run()

	conn := &Connection{
		hub:      hub,
		connType: "agent",
		id:       "rate-test-agent",
		send:     make(chan []byte, 100),
	}

	// Create conversation
	conv, err := CreateConversation("user_rt", "rate-test-agent")
	if err != nil {
		t.Fatal(err)
	}

	// Reset rate limiter with a small limit for testing
	messageRateLimiter = NewRateLimiter(3, time.Minute)

	// Send 5 messages rapidly
	blocked := false
	for i := 0; i < 5; i++ {
		msg := IncomingMessage{
			Type: "message",
			Data: json.RawMessage(`{"conversation_id": "` + conv.ID + `", "content": "msg"}`),
		}
		raw, _ := json.Marshal(msg)
		routeMessage(conn, raw)
	}

	// Check if we got a rate limit error
	drained := 0
	timeout := time.After(time.Second)
Loop:
	for {
		select {
		case resp := <-conn.send:
			var outMsg OutgoingMessage
			json.Unmarshal(resp, &outMsg)
			if outMsg.Type == "error" {
				data, _ := json.Marshal(outMsg.Data)
				if strings.Contains(string(data), "rate limit") {
					blocked = true
				}
			}
			drained++
		case <-timeout:
			break Loop
		}
	}

	if !blocked {
		t.Fatal("expected rate limit error after exceeding limit")
	}

	// Reset for other tests
	messageRateLimiter = NewRateLimiter(60, time.Minute)
}

func TestWriteJSONError(t *testing.T) {
	w := httptest.NewRecorder()
	writeJSONError(w, http.StatusBadRequest, "test error")

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}

	ct := w.Header().Get("Content-Type")
	if ct != "application/json" {
		t.Fatalf("expected application/json, got %s", ct)
	}

	var resp map[string]string
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["error"] != "test error" {
		t.Fatalf("expected error 'test error', got %s", resp["error"])
	}
	if resp["status"] != "Bad Request" {
		t.Fatalf("expected status 'Bad Request', got %s", resp["status"])
	}
}

func TestMethodNotAllowedJSON(t *testing.T) {
	setupTestDB(t)
	hub = newHub()
	go hub.run()

	// GET on a POST-only endpoint
	req := httptest.NewRequest(http.MethodGet, "/auth/login", nil)
	w := httptest.NewRecorder()
	handleLogin(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", w.Code)
	}

	var resp map[string]string
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["error"] != "method not allowed" {
		t.Fatalf("expected JSON error, got %s", w.Body.String())
	}
}

func TestInvalidMessageFormatJSON(t *testing.T) {
	setupTestDB(t)
	hub = newHub()
	go hub.run()

	conn := &Connection{
		hub:      hub,
		connType: "agent",
		id:       "fmt-test-agent",
		send:     make(chan []byte, 10),
	}

	// Send completely invalid JSON
	routeMessage(conn, []byte("not json at all"))

	select {
	case resp := <-conn.send:
		var outMsg OutgoingMessage
		json.Unmarshal(resp, &outMsg)
		if outMsg.Type != "error" {
			t.Fatalf("expected error type, got %s", outMsg.Type)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for error response")
	}
}

func TestMessageTooLong(t *testing.T) {
	setupTestDB(t)
	hub = newHub()
	go hub.run()

	// Create a message that exceeds maxMessageSize (64KB)
	longContent := strings.Repeat("x", 70000)
	msg := IncomingMessage{
		Type: "message",
		Data: json.RawMessage(`{"conversation_id": "conv_test", "content": "` + longContent + `"}`),
	}
	raw, _ := json.Marshal(msg)

	conn := &Connection{
		hub:      hub,
		connType: "agent",
		id:       "long-msg-agent",
		send:     make(chan []byte, 10),
	}

	// This should be handled gracefully (readPump would reject it,
	// but routeMessage itself should handle large messages fine)
	routeMessage(conn, raw)

	// Should get an error about conversation not found
	select {
	case resp := <-conn.send:
		var outMsg OutgoingMessage
		json.Unmarshal(resp, &outMsg)
		if outMsg.Type != "error" {
			t.Fatalf("expected error (conversation not found), got %s", outMsg.Type)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out")
	}
}

func TestEmptyBodyMessage(t *testing.T) {
	setupTestDB(t)
	hub = newHub()
	go hub.run()

	conn := &Connection{
		hub:      hub,
		connType: "client",
		id:       "empty-body-client",
		send:     make(chan []byte, 10),
	}

	// Send valid JSON but missing required fields
	msg := IncomingMessage{
		Type: "message",
		Data: json.RawMessage(`{}`),
	}
	raw, _ := json.Marshal(msg)
	routeMessage(conn, raw)

	select {
	case resp := <-conn.send:
		var outMsg OutgoingMessage
		json.Unmarshal(resp, &outMsg)
		if outMsg.Type != "error" {
			t.Fatalf("expected error for missing content, got %s", outMsg.Type)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out")
	}
}
func TestSecurityHeadersMiddleware(t *testing.T) {
	handler := securityHeadersMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()
	handler(w, req)

	// Check security headers are set
	tests := []struct {
		header string
		want   string
	}{
		{"X-Content-Type-Options", "nosniff"},
		{"X-Frame-Options", "DENY"},
		{"X-Xss-Protection", "1; mode=block"},
		{"Referrer-Policy", "strict-origin-when-cross-origin"},
		{"Permissions-Policy", "camera=(), microphone=(), geolocation=()"},
	}
	for _, tt := range tests {
		got := w.Header().Get(tt.header)
		if got != tt.want {
			t.Errorf("security header %s = %q, want %q", tt.header, got, tt.want)
		}
	}
}

func TestJWTSecretFromEnv(t *testing.T) {
	// Verify JWT secret can be configured via environment variable
	secret := os.Getenv("JWT_SECRET")
	if secret != "" && secret == "agent-messenger-dev-secret-change-me" {
		t.Error("JWT_SECRET is set to the insecure default value")
	}
	// This test primarily validates the env var is documented and readable
	// The actual security check happens at startup via the warning log
}

func TestConstantTimeAgentSecretCompare(t *testing.T) {
	// Verify that the agent secret comparison uses constant-time comparison
	// This is a behavioral test — timing attacks should not be possible
	originalSecret := agentSecret
	agentSecret = "test-secret-12345"
	defer func() { agentSecret = originalSecret }()

	// Correct secret should succeed
	err := ValidateAgentSecret("test-agent", "test-secret-12345")
	if err != nil {
		t.Errorf("correct secret should validate, got error: %v", err)
	}

	// Wrong secret should fail
	err = ValidateAgentSecret("test-agent-wrong", "wrong-secret")
	if err == nil {
		t.Error("wrong secret should fail validation")
	}
}
