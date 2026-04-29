package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// TestNegotiateProtocolDefault tests default protocol negotiation
func TestNegotiateProtocolDefault(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/agent/connect", nil)
	version := negotiateProtocol(req)
	if version != ProtocolVersion {
		t.Fatalf("expected default %s, got %s", ProtocolVersion, version)
	}
}

// TestNegotiateProtocolHeader tests Sec-WebSocket-Protocol header negotiation
func TestNegotiateProtocolHeader(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/agent/connect", nil)
	req.Header.Set("Sec-WebSocket-Protocol", "v1")
	version := negotiateProtocol(req)
	if version != "v1" {
		t.Fatalf("expected v1, got %s", version)
	}
}

// TestNegotiateProtocolHeaderMultiple tests negotiation with multiple protocols
func TestNegotiateProtocolHeaderMultiple(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/agent/connect", nil)
	req.Header.Set("Sec-WebSocket-Protocol", "v0, v1, v2")
	version := negotiateProtocol(req)
	if version != "v1" {
		t.Fatalf("expected v1 (first supported), got %s", version)
	}
}

// TestNegotiateProtocolQueryParam tests protocol version via query param
func TestNegotiateProtocolQueryParam(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/agent/connect?protocol_version=v1", nil)
	version := negotiateProtocol(req)
	if version != "v1" {
		t.Fatalf("expected v1, got %s", version)
	}
}

// TestNegotiateProtocolUnsupported tests fallback for unsupported version
func TestNegotiateProtocolUnsupported(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/agent/connect", nil)
	req.Header.Set("Sec-WebSocket-Protocol", "v99")
	version := negotiateProtocol(req)
	if version != ProtocolVersion {
		t.Fatalf("expected default %s for unsupported version, got %s", ProtocolVersion, version)
	}
}

// TestIsSupportedVersion tests version validation
func TestIsSupportedVersion(t *testing.T) {
	if !isSupportedVersion("v1") {
		t.Fatal("v1 should be supported")
	}
	if isSupportedVersion("v0") {
		t.Fatal("v0 should not be supported")
	}
	if isSupportedVersion("v2") {
		t.Fatal("v2 should not be supported")
	}
}

// TestWelcomeMessageIncludesProtocol tests that welcome messages include protocol version
func TestWelcomeMessageIncludesProtocol(t *testing.T) {
	setupTestDB(t)
	hub = newHub()
	go hub.run()
	ServerMetrics = NewMetrics(hub)

	token := registerUserAndGetToken(t, "protouser", "password123")
	userID := getUserIDFromToken(t, token)

	// Connect client with protocol version via query param
	_, err := db.Exec("INSERT OR IGNORE INTO agents (id, name) VALUES (?, ?)", "proto-agent", "Proto Agent")
	if err != nil {
		t.Fatal(err)
	}

	// Create conversation
	form := url.Values{}
	form.Set("agent_id", "proto-agent")
	req := httptest.NewRequest(http.MethodPost, "/conversations/create", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleCreateConversation(w, req)

	var createResp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &createResp)
	convID := createResp["conversation_id"].(string)

	// Send a message and check the welcome
	_ = convID
	_ = userID

	// Check sendWelcomeMessage output directly
	sendCh := make(chan []byte, 256)
	sendWelcomeMessage("client", "test-user", "phone", "v1", sendCh)

	var msg OutgoingMessage
	data := <-sendCh
	json.Unmarshal(data, &msg)

	if msg.Type != "connected" {
		t.Fatalf("expected type 'connected', got %s", msg.Type)
	}

	dataMap := msg.Data.(map[string]interface{})
	if dataMap["protocol_version"] != "v1" {
		t.Fatalf("expected protocol_version 'v1', got %v", dataMap["protocol_version"])
	}
	if dataMap["status"] != "connected" {
		t.Fatalf("expected status 'connected', got %v", dataMap["status"])
	}
	if dataMap["device_id"] != "phone" {
		t.Fatalf("expected device_id 'phone', got %v", dataMap["device_id"])
	}
	versions := dataMap["supported_versions"].([]interface{})
	if len(versions) == 0 {
		t.Fatal("expected at least one supported version")
	}
}

// TestUpgradeWithProtocolHeader tests that the response includes Sec-WebSocket-Protocol
func TestUpgradeWithProtocolHeader(t *testing.T) {
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/agent/connect", nil)

	upgradeWithProtocol(w, req, "v1")

	// Note: in a real upgrade the header would be set, but since we're not
	// actually upgrading, we just verify no error occurs
	header := w.Header().Get("Sec-WebSocket-Protocol")
	if header != "v1" {
		t.Fatalf("expected Sec-WebSocket-Protocol 'v1', got %q", header)
	}
}

func TestWebSocketOriginCheckAllowedOrigin(t *testing.T) {
	originalOrigins := corsAllowedOrigins
	corsAllowedOrigins = "https://app.example.com,https://chat.example.com"
	defer func() { corsAllowedOrigins = originalOrigins }()

	// Allowed origin
	req := httptest.NewRequest(http.MethodGet, "/agent/connect", nil)
	req.Header.Set("Origin", "https://app.example.com")
	if !upgrader.CheckOrigin(req) {
		t.Error("Expected allowed origin to pass CheckOrigin")
	}

	// Disallowed origin
	req2 := httptest.NewRequest(http.MethodGet, "/agent/connect", nil)
	req2.Header.Set("Origin", "https://evil.example.com")
	if upgrader.CheckOrigin(req2) {
		t.Error("Expected disallowed origin to fail CheckOrigin")
	}

	// No Origin header (non-browser client)
	req3 := httptest.NewRequest(http.MethodGet, "/agent/connect", nil)
	if !upgrader.CheckOrigin(req3) {
		t.Error("Expected no Origin header to pass CheckOrigin")
	}
}

func TestWebSocketOriginCheckWildcard(t *testing.T) {
	originalOrigins := corsAllowedOrigins
	corsAllowedOrigins = "*"
	defer func() { corsAllowedOrigins = originalOrigins }()

	req := httptest.NewRequest(http.MethodGet, "/agent/connect", nil)
	req.Header.Set("Origin", "https://any.example.com")
	if !upgrader.CheckOrigin(req) {
		t.Error("Expected wildcard to allow any origin")
	}
}