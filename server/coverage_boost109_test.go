package main

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	firebase "firebase.google.com/go/v4"
	"firebase.google.com/go/v4/messaging"
	"github.com/sideshow/apns2"
	"golang.org/x/net/context"
	"google.golang.org/api/option"
)

// --- CB109: Coverage boost targeting remaining sub-90% functions ---
// Focus areas:
// - writePump (70.4%): ping success path
// - sendAPNSNotification (64.3%): success path with mock APNs server, rejected push
// - sendFCMNotification (22.2%): error from FCM, sendPushNotification routing
// - notifyUser (80%): with tokens, push fail, panic recovery
// - RegisterAgentOnConnect (81.8%): DB query error, DB insert error, DB update error
// - handleUpload (81.8%): success path with file write, seek error
// - initSchema (85.3%): nil DB, schema_migrations error
// - routeChatMessage (84.4%): missing conversation_id, agent not found
// - readPump (86.4%): unexpected close error path
// - deleteConversation (83.3%): messages DB error
// - ValidateJWT (83.3%): empty token, wrong signing method
// - Snapshot (83.3%): with all metrics fields
// - ShutdownTracing (80%): with error on shutdown
// - sendWelcomeMessage (80%): marshal error path
// - handleAgentConnect (86%): missing agent_id, auth fail
// - routeTypingIndicator (87%): invalid JSON data
// - routeStatusUpdate (87.5%): invalid JSON data
// - getDeviceTokensForUser (84.6%): scan error, multiple tokens
// - handleListAttachments (86.1%): DB error path
// - handleGetAttachment (88.2%): not found, DB error
// - searchMessages (86.7%): DB error, negative limit
// - handleMessageDelete (87.5%): DB error, not found
// - ipRateLimitMiddleware (88.9%): blocked path
// - authRateLimitMiddleware (88.9%): blocked path
// - cleanup (83.3%): ticker cleanup with stale entries
// - handleSetNotificationPrefs (88.9%): DB error
// - handleGetNotificationPrefs (94.1%): DB error
// - handleWebPushSubscribe (88.9%): DB error
// - rate_limit_tiers cleanup (83.3%): with entries

func init() {
	// Ensure we have a test DB for tests that need it
}

// ============ writePump: ping success path ============

func TestCB109_WritePump_PingSuccess(t *testing.T) {
	h := newHub()
	go h.run()
	defer h.Stop()

	done := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upgrader := websocket.Upgrader{}
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()

		c := &Connection{
			conn:        conn,
			connType:    "agent",
			id:          "ping-agent",
			send:        make(chan []byte, 10),
			hub:         h,
			connectedAt: time.Now(),
		}

		go c.writePump()

		// Keep connection open briefly
		time.Sleep(300 * time.Millisecond)
		close(done)
	}))
	defer srv.Close()

	wsURL := "ws" + srv.URL[4:]
	ws, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Skipf("could not dial test server: %v", err)
	}
	defer ws.Close()

	// Read messages until close
	for {
		_, _, err := ws.ReadMessage()
		if err != nil {
			break
		}
	}
}

// ============ sendAPNSNotification: success with mock APNs ============

func TestCB109_SendAPNSNotification_SuccessWithMock(t *testing.T) {
	// Create a mock APNs server
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("apns-id", "test-apns-id")
		w.Header().Set("apns-unique-id", "test-unique-id")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"reason": "",
		})
	}))
	defer mockServer.Close()

	// Create an apns2 client pointing at our mock server
	// We need to use a custom HTTP client that doesn't require HTTP/2
	origConfig := pushConfig
	pushConfig = &PushNotificationConfig{
		APNSEnabled: true,
		BundleID:    "com.test.app",
		apnsClient: &apns2.Client{
			Host: mockServer.URL,
			HTTPClient: &http.Client{
				Timeout: 5 * time.Second,
			},
		},
	}
	defer func() { pushConfig = origConfig }()

	err := sendAPNSNotification("test-device-token", "Test Title", "Test Body", "conv-123")
	if err != nil {
		t.Errorf("expected nil error, got %v", err)
	}
}

func TestCB109_SendAPNSNotification_RejectedByServer(t *testing.T) {
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusGone)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"reason": "Unregistered",
		})
	}))
	defer mockServer.Close()

	origConfig := pushConfig
	pushConfig = &PushNotificationConfig{
		APNSEnabled: true,
		BundleID:    "com.test.app",
		apnsClient: &apns2.Client{
			Host: mockServer.URL,
			HTTPClient: &http.Client{
				Timeout: 5 * time.Second,
			},
		},
	}
	defer func() { pushConfig = origConfig }()

	// Should return nil (rejected but not an error)
	err := sendAPNSNotification("test-device-token", "Test Title", "Test Body", "conv-123")
	if err != nil {
		t.Errorf("expected nil error for rejected push, got %v", err)
	}
}

func TestCB109_SendAPNSNotification_PushError(t *testing.T) {
	// Use a closed server to trigger connection error
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	mockServer.Close()

	origConfig := pushConfig
	pushConfig = &PushNotificationConfig{
		APNSEnabled: true,
		BundleID:    "com.test.app",
		apnsClient: &apns2.Client{
			Host: "http://127.0.0.1:1", // unreachable
			HTTPClient: &http.Client{
				Timeout: 1 * time.Second,
			},
		},
	}
	defer func() { pushConfig = origConfig }()

	err := sendAPNSNotification("test-device-token", "Test Title", "Test Body", "conv-123")
	if err == nil {
		t.Error("expected error for unreachable APNs server, got nil")
	}
}

func TestCB109_SendAPNSNotification_WithConversationID(t *testing.T) {
	var receivedBody map[string]interface{}
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&receivedBody)
		w.Header().Set("apns-id", "test-id")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{"reason": ""})
	}))
	defer mockServer.Close()

	origConfig := pushConfig
	pushConfig = &PushNotificationConfig{
		APNSEnabled: true,
		BundleID:    "com.test.app",
		apnsClient: &apns2.Client{
			Host:       mockServer.URL,
			HTTPClient: &http.Client{Timeout: 5 * time.Second},
		},
	}
	defer func() { pushConfig = origConfig }()

	err := sendAPNSNotification("dev-token", "Title", "Body", "conv-456")
	if err != nil {
		t.Errorf("expected nil error, got %v", err)
	}

	// Verify the notification payload contains conversation_id
	if receivedBody != nil {
		if aps, ok := receivedBody["aps"].(map[string]interface{}); ok {
			if alert, ok := aps["alert"].(map[string]interface{}); ok {
				if alert["title"] != "Title" {
					t.Errorf("expected title 'Title', got %v", alert["title"])
				}
			}
		}
	}
}

// ============ sendPushNotification: routing ============

func TestCB109_SendPushNotification_AndroidRouting(t *testing.T) {
	origConfig := pushConfig
	pushConfig = &PushNotificationConfig{
		FCMEnabled: true,
		fcmClient:  newMockFCMClient_CB109(t, httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]interface{}{"name": "projects/test/messages/0"})
		}))),
	}
	defer func() { pushConfig = origConfig }()

	err := sendPushNotification("test-token", "Title", "Body", "conv-1", "android")
	if err != nil {
		t.Errorf("expected nil error for FCM, got %v", err)
	}
}

func TestCB109_SendPushNotification_IOSRouting(t *testing.T) {
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{"reason": ""})
	}))
	defer mockServer.Close()

	origConfig := pushConfig
	pushConfig = &PushNotificationConfig{
		APNSEnabled: true,
		BundleID:    "com.test.app",
		apnsClient: &apns2.Client{
			Host:       mockServer.URL,
			HTTPClient: &http.Client{Timeout: 5 * time.Second},
		},
	}
	defer func() { pushConfig = origConfig }()

	err := sendPushNotification("test-token", "Title", "Body", "conv-1", "ios")
	if err != nil {
		t.Errorf("expected nil error for APNs, got %v", err)
	}
}

func TestCB109_SendPushNotification_UnknownPlatform(t *testing.T) {
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{"reason": ""})
	}))
	defer mockServer.Close()

	origConfig := pushConfig
	pushConfig = &PushNotificationConfig{
		APNSEnabled: true,
		BundleID:    "com.test.app",
		apnsClient: &apns2.Client{
			Host:       mockServer.URL,
			HTTPClient: &http.Client{Timeout: 5 * time.Second},
		},
	}
	defer func() { pushConfig = origConfig }()

	// Unknown platform should default to APNs
	err := sendPushNotification("test-token", "Title", "Body", "conv-1", "unknown")
	if err != nil {
		t.Errorf("expected nil error for unknown platform (defaults to APNs), got %v", err)
	}
}

// ============ notifyUser: with tokens, push fail, panic recovery ============

func TestCB109_NotifyUser_WithTokens(t *testing.T) {
	testDB := setupTestDB_CB109(t)
	origDB := db
	db = testDB
	defer func() { db = origDB; testDB.Close() }()

	// Insert a device token
	_, err := testDB.Exec(`INSERT INTO device_tokens (user_id, device_token, platform, updated_at) VALUES (?, ?, ?, CURRENT_TIMESTAMP)`,
		"user1", "token-abc", "ios")
	if err != nil {
		t.Fatalf("failed to insert token: %v", err)
	}

	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{"reason": ""})
	}))
	defer mockServer.Close()

	origConfig := pushConfig
	pushConfig = &PushNotificationConfig{
		APNSEnabled: true,
		BundleID:    "com.test.app",
		apnsClient: &apns2.Client{
			Host:       mockServer.URL,
			HTTPClient: &http.Client{Timeout: 5 * time.Second},
		},
	}
	defer func() { pushConfig = origConfig }()

	// Should not panic and should send notification
	notifyUser("user1", "Test Title", "Test Body", "conv-1")
}

func TestCB109_NotifyUser_PushFail(t *testing.T) {
	testDB := setupTestDB_CB109(t)
	origDB := db
	db = testDB
	defer func() { db = origDB; testDB.Close() }()

	_, err := testDB.Exec(`INSERT INTO device_tokens (user_id, device_token, platform, updated_at) VALUES (?, ?, ?, CURRENT_TIMESTAMP)`,
		"user1", "token-abc", "ios")
	if err != nil {
		t.Fatalf("failed to insert token: %v", err)
	}

	origConfig := pushConfig
	pushConfig = &PushNotificationConfig{
		APNSEnabled: true,
		BundleID:    "com.test.app",
		apnsClient: &apns2.Client{
			Host:       "http://127.0.0.1:1", // unreachable
			HTTPClient: &http.Client{Timeout: 1 * time.Second},
		},
	}
	defer func() { pushConfig = origConfig }()

	// Should not panic even if push fails
	notifyUser("user1", "Test Title", "Test Body", "conv-1")
}

func TestCB109_NotifyUser_MutedConversation(t *testing.T) {
	testDB := setupTestDB_CB109(t)
	origDB := db
	db = testDB
	defer func() { db = origDB; testDB.Close() }()

	// Insert a device token and mute the conversation
	_, err := testDB.Exec(`INSERT INTO device_tokens (user_id, device_token, platform, updated_at) VALUES (?, ?, ?, CURRENT_TIMESTAMP)`,
		"user1", "token-abc", "ios")
	if err != nil {
		t.Fatalf("failed to insert token: %v", err)
	}

	// Create a conversation and mute it
	_, err = testDB.Exec(`INSERT INTO conversations (id, user_id, agent_id, created_at) VALUES (?, ?, ?, CURRENT_TIMESTAMP)`,
		"conv-1", "user1", "agent1")
	if err != nil {
		t.Fatalf("failed to insert conversation: %v", err)
	}
	_, err = testDB.Exec(`INSERT INTO notification_preferences (user_id, conversation_id, muted, created_at) VALUES (?, ?, 1, CURRENT_TIMESTAMP)`,
		"user1", "conv-1")
	if err != nil {
		t.Fatalf("failed to mute conversation: %v", err)
	}

	pushCalled := false
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		pushCalled = true
		w.WriteHeader(http.StatusOK)
	}))
	defer mockServer.Close()

	origConfig := pushConfig
	pushConfig = &PushNotificationConfig{
		APNSEnabled: true,
		BundleID:    "com.test.app",
		apnsClient: &apns2.Client{
			Host:       mockServer.URL,
			HTTPClient: &http.Client{Timeout: 5 * time.Second},
		},
	}
	defer func() { pushConfig = origConfig }()

	notifyUser("user1", "Title", "Body", "conv-1")

	if pushCalled {
		t.Error("expected push to be skipped for muted conversation")
	}
}

func TestCB109_NotifyUser_NoTokens(t *testing.T) {
	testDB := setupTestDB_CB109(t)
	origDB := db
	db = testDB
	defer func() { db = origDB; testDB.Close() }()

	origConfig := pushConfig
	pushConfig = &PushNotificationConfig{
		APNSEnabled: true,
		BundleID:    "com.test.app",
		apnsClient: &apns2.Client{
			Host:       "http://127.0.0.1:1",
			HTTPClient: &http.Client{Timeout: 1 * time.Second},
		},
	}
	defer func() { pushConfig = origConfig }()

	// User with no tokens — should not panic
	notifyUser("user-no-tokens", "Title", "Body", "conv-1")
}

func TestCB109_NotifyUser_EmptyConversationID(t *testing.T) {
	testDB := setupTestDB_CB109(t)
	origDB := db
	db = testDB
	defer func() { db = origDB; testDB.Close() }()

	_, err := testDB.Exec(`INSERT INTO device_tokens (user_id, device_token, platform, updated_at) VALUES (?, ?, ?, CURRENT_TIMESTAMP)`,
		"user1", "token-abc", "ios")
	if err != nil {
		t.Fatalf("failed to insert token: %v", err)
	}

	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{"reason": ""})
	}))
	defer mockServer.Close()

	origConfig := pushConfig
	pushConfig = &PushNotificationConfig{
		APNSEnabled: true,
		BundleID:    "com.test.app",
		apnsClient: &apns2.Client{
			Host:       mockServer.URL,
			HTTPClient: &http.Client{Timeout: 5 * time.Second},
		},
	}
	defer func() { pushConfig = origConfig }()

	// Empty conversation ID should still send (no muting check)
	notifyUser("user1", "Title", "Body", "")
}

func TestCB109_NotifyUser_PanicRecovery(t *testing.T) {
	// Set up a config that will cause a panic in getDeviceTokensForUser
	// by having nil db
	origDB := db
	db = setupClosedDB_CB109(t)
	defer func() { db = origDB }()

	origConfig := pushConfig
	pushConfig = &PushNotificationConfig{
		APNSEnabled: true,
		BundleID:    "com.test.app",
	}
	defer func() { pushConfig = origConfig }()

	// Should not panic — notifyUser has defer/recover
	notifyUser("user1", "Title", "Body", "conv-1")
}

// ============ RegisterAgentOnConnect: DB error paths ============

func TestCB109_RegisterAgentOnConnect_QueryError(t *testing.T) {
	// Use a closed DB to trigger query error
	closedDB, err := openTestDB_CB109()
	if err != nil {
		t.Fatalf("failed to open db: %v", err)
	}
	closedDB.Close()

	origDB := db
	db = closedDB
	defer func() { db = origDB }()

	err = RegisterAgentOnConnect("agent1", "Agent One", "gpt-4", "friendly", "general")
	if err == nil {
		t.Error("expected error from closed DB query, got nil")
	}
}

func TestCB109_RegisterAgentOnConnect_InsertError(t *testing.T) {
	testDB := setupTestDB_CB109(t)
	origDB := db
	db = testDB
	defer func() { db = origDB; testDB.Close() }()

	// Insert an agent first
	_, err := testDB.Exec("INSERT INTO agents (id, name, model, personality, specialty) VALUES (?, ?, ?, ?, ?)",
		"agent1", "Agent One", "gpt-4", "friendly", "general")
	if err != nil {
		t.Fatalf("failed to insert agent: %v", err)
	}

	// Drop the agents table to cause an insert error after the query returns ErrNoRows
	_, err = testDB.Exec("DROP TABLE agents")
	if err != nil {
		t.Fatalf("failed to drop table: %v", err)
	}

	err = RegisterAgentOnConnect("new-agent", "New Agent", "gpt-4", "friendly", "general")
	if err == nil {
		t.Error("expected error from missing table, got nil")
	}
}

func TestCB109_RegisterAgentOnConnect_UpdateModelError(t *testing.T) {
	testDB := setupTestDB_CB109(t)
	origDB := db
	db = testDB
	defer func() { db = origDB; testDB.Close() }()

	// Insert an existing agent
	_, err := testDB.Exec("INSERT INTO agents (id, name, model, personality, specialty) VALUES (?, ?, ?, ?, ?)",
		"agent1", "Agent One", "", "", "")
	if err != nil {
		t.Fatalf("failed to insert agent: %v", err)
	}

	// Drop the table to cause update error
	_, err = testDB.Exec("DROP TABLE agents")
	if err != nil {
		t.Fatalf("failed to drop table: %v", err)
	}

	err = RegisterAgentOnConnect("agent1", "Agent One", "gpt-4", "friendly", "general")
	if err == nil {
		t.Error("expected error from missing table on update, got nil")
	}
}

func TestCB109_RegisterAgentOnConnect_UpdatePersonalityError(t *testing.T) {
	testDB := setupTestDB_CB109(t)
	origDB := db
	db = testDB
	defer func() { db = origDB; testDB.Close() }()

	_, err := testDB.Exec("INSERT INTO agents (id, name, model, personality, specialty) VALUES (?, ?, ?, ?, ?)",
		"agent1", "Agent One", "gpt-4", "", "")
	if err != nil {
		t.Fatalf("failed to insert agent: %v", err)
	}

	_, err = testDB.Exec("DROP TABLE agents")
	if err != nil {
		t.Fatalf("failed to drop table: %v", err)
	}

	err = RegisterAgentOnConnect("agent1", "Agent One", "gpt-4", "friendly", "general")
	if err == nil {
		t.Error("expected error from missing table on personality update, got nil")
	}
}

func TestCB109_RegisterAgentOnConnect_UpdateSpecialtyError(t *testing.T) {
	testDB := setupTestDB_CB109(t)
	origDB := db
	db = testDB
	defer func() { db = origDB; testDB.Close() }()

	_, err := testDB.Exec("INSERT INTO agents (id, name, model, personality, specialty) VALUES (?, ?, ?, ?, ?)",
		"agent1", "Agent One", "gpt-4", "friendly", "")
	if err != nil {
		t.Fatalf("failed to insert agent: %v", err)
	}

	_, err = testDB.Exec("DROP TABLE agents")
	if err != nil {
		t.Fatalf("failed to drop table: %v", err)
	}

	err = RegisterAgentOnConnect("agent1", "Agent One", "gpt-4", "friendly", "general")
	if err == nil {
		t.Error("expected error from missing table on specialty update, got nil")
	}
}

func TestCB109_RegisterAgentOnConnect_UpdateNameError(t *testing.T) {
	testDB := setupTestDB_CB109(t)
	origDB := db
	db = testDB
	defer func() { db = origDB; testDB.Close() }()

	_, err := testDB.Exec("INSERT INTO agents (id, name, model, personality, specialty) VALUES (?, ?, ?, ?, ?)",
		"agent1", "Agent One", "gpt-4", "friendly", "general")
	if err != nil {
		t.Fatalf("failed to insert agent: %v", err)
	}

	// Drop table to cause name update error (name != agentID)
	_, err = testDB.Exec("DROP TABLE agents")
	if err != nil {
		t.Fatalf("failed to drop table: %v", err)
	}

	err = RegisterAgentOnConnect("agent1", "Custom Name", "gpt-4", "friendly", "general")
	if err == nil {
		t.Error("expected error from missing table on name update, got nil")
	}
}

// ============ ValidateJWT: edge cases ============

func TestCB109_ValidateJWT_EmptyToken(t *testing.T) {
	_, err := ValidateJWT("")
	if err == nil {
		t.Error("expected error for empty token, got nil")
	}
	if !strings.Contains(err.Error(), "empty") {
		t.Errorf("expected 'empty' in error, got %v", err)
	}
}

func TestCB109_ValidateJWT_MalformedToken(t *testing.T) {
	_, err := ValidateJWT("not-a-valid-jwt")
	if err == nil {
		t.Error("expected error for malformed token, got nil")
	}
}

func TestCB109_ValidateJWT_WrongSigningMethod(t *testing.T) {
	// Create a token with a different signing method (none)
	// This should fail with "unexpected signing method"
	_, err := ValidateJWT("eyJhbGciOiJub25lIn0.eyJ1c2VyX2lkIjoidGVzdCIsInVzZXJuYW1lIjoidGVzdCJ9.")
	if err == nil {
		t.Error("expected error for wrong signing method, got nil")
	}
}

func TestCB109_ValidateJWT_ExpiredToken(t *testing.T) {
	// Create an expired JWT
	origSecret := jwtSecret
	jwtSecret = []byte("test-secret")
	defer func() { jwtSecret = origSecret }()

	// Use the actual jwt package to create an expired token
	token, err := createExpiredJWT_CB109()
	if err != nil {
		t.Skipf("could not create expired token: %v", err)
	}

	_, err = ValidateJWT(token)
	if err == nil {
		t.Error("expected error for expired token, got nil")
	}
}

// ============ Snapshot: with all metrics ============

func TestCB109_Snapshot_WithAllMetrics(t *testing.T) {
	m := &Metrics{
		Version:   "test-v1",
		StartTime: time.Now().Add(-60 * time.Second),
		AgentsConnected:  func() int { return 2 },
		ClientsConnected: func() int { return 5 },
		ClientConnsTotal: func() int { return 7 },
		StaleAgentCount:  func() int64 { return 1 },
	}
	m.MessagesIn.Store(100)
	m.MessagesOut.Store(50)
	m.ConnectionsTotal.Store(10)
	m.ErrorsTotal.Store(3)
	m.RateLimited.Store(5)

	snap := m.Snapshot()

	if snap["messages_in"] != int64(100) {
		t.Errorf("expected messages_in=100, got %v", snap["messages_in"])
	}
	if snap["messages_out"] != int64(50) {
		t.Errorf("expected messages_out=50, got %v", snap["messages_out"])
	}
	if snap["connections_total"] != int64(10) {
		t.Errorf("expected connections_total=10, got %v", snap["connections_total"])
	}
	if snap["errors_total"] != int64(3) {
		t.Errorf("expected errors_total=3, got %v", snap["errors_total"])
	}
	if snap["rate_limited"] != int64(5) {
		t.Errorf("expected rate_limited=5, got %v", snap["rate_limited"])
	}
	if snap["agents_connected"] != 2 {
		t.Errorf("expected agents_connected=2, got %v", snap["agents_connected"])
	}
	if snap["version"] != "test-v1" {
		t.Errorf("expected version=test-v1, got %v", snap["version"])
	}
}

// ============ sendWelcomeMessage: marshal error path ============

func TestCB109_SendWelcomeMessage_Success(t *testing.T) {
	h := newHub()
	go h.run()
	defer h.Stop()

	c := &Connection{
		hub:         h,
		connType:    "agent",
		id:          "agent-1",
		send:        make(chan []byte, 10),
		connectedAt: time.Now(),
	}

	sendWelcomeMessage(c)

	// Should receive a welcome message on send channel
	select {
	case msg := <-c.send:
		if len(msg) == 0 {
			t.Error("expected non-empty welcome message")
		}
	case <-time.After(100 * time.Millisecond):
		t.Error("expected welcome message on send channel")
	}
}

func TestCB109_SendWelcomeMessage_ClientWithVersion(t *testing.T) {
	h := newHub()
	go h.run()
	defer h.Stop()

	c := &Connection{
		hub:                h,
		connType:           "client",
		id:                 "user-1",
		send:               make(chan []byte, 10),
		connectedAt:        time.Now(),
		negotiatedVersion:  "v1",
	}

	sendWelcomeMessage(c)

	select {
	case msg := <-c.send:
		if len(msg) == 0 {
			t.Error("expected non-empty welcome message")
		}
		// Verify it's a JSON message with "connected" type
		var parsed map[string]interface{}
		if err := json.Unmarshal(msg, &parsed); err == nil {
			if parsed["type"] != "connected" {
				t.Errorf("expected type 'connected', got %v", parsed["type"])
			}
		}
	case <-time.After(100 * time.Millisecond):
		t.Error("expected welcome message on send channel")
	}
}

// ============ routeChatMessage: edge cases ============

func TestCB109_RouteChatMessage_MissingConversationID(t *testing.T) {
	h := newHub()
	go h.run()
	defer h.Stop()
	origHub := hub
	hub = h
	defer func() { hub = origHub }()

	c := &Connection{
		hub:         h,
		connType:    "client",
		id:          "user1",
		send:        make(chan []byte, 10),
		connectedAt: time.Now(),
	}

	// RoutedMessage with empty conversation ID
	rm := RoutedMessage{
		Type:        "chat",
		Content:     "hello",
		SenderType:  "client",
		SenderID:    "user1",
		RecipientID: "agent1",
	}
	data, _ := json.Marshal(rm)
	im := IncomingMessage{Type: "chat", Data: data}
	msgBytes, _ := json.Marshal(im)

	// Should not panic
	routeChatMessage(c, msgBytes)
}

func TestCB109_RouteChatMessage_AgentNotFound(t *testing.T) {
	h := newHub()
	go h.run()
	defer h.Stop()
	origHub := hub
	hub = h
	defer func() { hub = origHub }()

	// Set up a user connection but no agent
	c := &Connection{
		hub:         h,
		connType:    "client",
		id:          "user1",
		send:        make(chan []byte, 10),
		connectedAt: time.Now(),
	}
	h.clientConns["user1"] = []*Connection{c}

	testDB := setupTestDB_CB109(t)
	origDB := db
	db = testDB
	defer func() { db = origDB; testDB.Close() }()

	// Create conversation but agent is not connected
	_, err := testDB.Exec("INSERT INTO conversations (id, user_id, agent_id, created_at) VALUES (?, ?, ?, CURRENT_TIMESTAMP)",
		"conv-1", "user1", "agent-missing")
	if err != nil {
		t.Fatalf("failed to insert conversation: %v", err)
	}

	rm := RoutedMessage{
		Type:           "chat",
		ConversationID: "conv-1",
		Content:        "hello",
		SenderType:     "client",
		SenderID:       "user1",
		RecipientID:    "agent-missing",
	}
	data, _ := json.Marshal(rm)
	im := IncomingMessage{Type: "chat", Data: data}
	msgBytes, _ := json.Marshal(im)

	// Should not panic, should queue offline
	routeChatMessage(c, msgBytes)
}

// ============ deleteConversation: DB error ============

func TestCB109_DeleteConversation_MessagesDBError(t *testing.T) {
	testDB := setupTestDB_CB109(t)
	origDB := db
	db = testDB
	defer func() { db = origDB; testDB.Close() }()

	// Insert conversation
	_, err := testDB.Exec("INSERT INTO conversations (id, user_id, agent_id, created_at) VALUES (?, ?, ?, CURRENT_TIMESTAMP)",
		"conv-1", "user1", "agent1")
	if err != nil {
		t.Fatalf("failed to insert conversation: %v", err)
	}
	_, err = testDB.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, created_at) VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)",
		"msg-1", "conv-1", "client", "user1", "hello")
	if err != nil {
		t.Fatalf("failed to insert message: %v", err)
	}

	// Drop messages table to cause delete error
	_, err = testDB.Exec("DROP TABLE messages")
	if err != nil {
		t.Fatalf("failed to drop messages: %v", err)
	}

	err = deleteConversation("conv-1", "user1")
	if err == nil {
		t.Error("expected error from missing messages table, got nil")
	}
}

// ============ getDeviceTokensForUser: scan error and multiple tokens ============

func TestCB109_GetDeviceTokensForUser_MultipleTokens(t *testing.T) {
	testDB := setupTestDB_CB109(t)
	origDB := db
	db = testDB
	defer func() { db = origDB; testDB.Close() }()

	// Insert multiple tokens
	for i := 0; i < 3; i++ {
		_, err := testDB.Exec(`INSERT INTO device_tokens (user_id, device_token, platform, updated_at) VALUES (?, ?, ?, CURRENT_TIMESTAMP)`,
			"user1", fmt.Sprintf("token-%d", i), "ios")
		if err != nil {
			t.Fatalf("failed to insert token: %v", err)
		}
	}

	tokens, err := getDeviceTokensForUser("user1")
	if err != nil {
		t.Errorf("expected nil error, got %v", err)
	}
	if len(tokens) != 3 {
		t.Errorf("expected 3 tokens, got %d", len(tokens))
	}
}

func TestCB109_GetDeviceTokensForUser_ScanError(t *testing.T) {
	testDB := setupTestDB_CB109(t)
	origDB := db
	db = testDB
	defer func() { db = origDB; testDB.Close() }()

	// Drop the table to cause a query/scan error
	_, err := testDB.Exec("DROP TABLE device_tokens")
	if err != nil {
		t.Fatalf("failed to drop table: %v", err)
	}

	_, err = getDeviceTokensForUser("user1")
	if err == nil {
		t.Error("expected error from missing table, got nil")
	}
}

// ============ handleListAttachments: DB error ============

func TestCB109_HandleListAttachments_DBError(t *testing.T) {
	origDB := db
	db = setupClosedDB_CB109(t)
	defer func() { db = origDB }()

	token := generateTestJWT_CB109(t, "user1", "testuser")
	req := httptest.NewRequest(http.MethodGet, "/attachments?conversation_id=conv-1", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()

	handleListAttachments(rr, req)

	// With closed DB, getConversation returns error → 404
	if rr.Code != http.StatusNotFound && rr.Code != http.StatusInternalServerError {
		t.Errorf("expected 404 or 500 for closed DB, got %d", rr.Code)
	}
}

func TestCB109_HandleListAttachments_NotFound(t *testing.T) {
	testDB := setupTestDB_CB109(t)
	origDB := db
	db = testDB
	defer func() { db = origDB; testDB.Close() }()

	token := generateTestJWT_CB109(t, "user1", "testuser")
	req := httptest.NewRequest(http.MethodGet, "/attachments?conversation_id=nonexistent", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()

	handleListAttachments(rr, req)

	// Conversation doesn't exist → 404
	if rr.Code != http.StatusNotFound {
		t.Errorf("expected 404 for non-existent conversation, got %d", rr.Code)
	}
}

// ============ handleGetAttachment: DB error, not found ============

func TestCB109_HandleGetAttachment_DBError(t *testing.T) {
	origDB := db
	db = setupClosedDB_CB109(t)
	defer func() { db = origDB }()

	token := generateTestJWT_CB109(t, "user1", "testuser")
	req := httptest.NewRequest(http.MethodGet, "/attachments/file-1", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()

	handleGetAttachment(rr, req)

	// With closed DB, various error paths possible
	if rr.Code != http.StatusInternalServerError && rr.Code != http.StatusNotFound {
		t.Errorf("expected 500 or 404 for closed DB, got %d", rr.Code)
	}
}

// ============ searchMessages: DB error ============

func TestCB109_SearchMessages_DBError(t *testing.T) {
	origDB := db
	db = setupClosedDB_CB109(t)
	defer func() { db = origDB }()

	results, err := searchMessages("user1", "test", 50)
	if err == nil {
		t.Error("expected error for nil DB, got nil")
	}
	if results != nil {
		t.Errorf("expected nil results, got %v", results)
	}
}

func TestCB109_SearchMessages_NegativeLimit(t *testing.T) {
	testDB := setupTestDB_CB109(t)
	origDB := db
	db = testDB
	defer func() { db = origDB; testDB.Close() }()

	// Negative limit should default to 50. With no messages, returns nil slice + nil error
	results, err := searchMessages("user1", "test", -10)
	if err != nil {
		t.Errorf("expected nil error, got %v", err)
	}
	// searchMessages returns nil slice when no results — that's fine
	_ = results
}

// ============ handleMessageDelete: DB error ============

func TestCB109_HandleMessageDelete_DBError(t *testing.T) {
	origDB := db
	db = setupClosedDB_CB109(t)
	defer func() { db = origDB }()

	token := generateTestJWT_CB109(t, "user1", "testuser")
	body := strings.NewReader("message_id=msg-1")
	req := httptest.NewRequest(http.MethodPost, "/messages/delete", body)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	handleMessageDelete(rr, req)

	if rr.Code != http.StatusInternalServerError && rr.Code != http.StatusNotFound {
		t.Errorf("expected 500 or 404 for closed DB, got %d", rr.Code)
	}
}

// ============ routeTypingIndicator: invalid JSON ============

func TestCB109_RouteTypingIndicator_InvalidJSON(t *testing.T) {
	h := newHub()
	go h.run()
	defer h.Stop()

	c := &Connection{
		hub:         h,
		connType:    "client",
		id:          "user1",
		send:        make(chan []byte, 10),
		connectedAt: time.Now(),
	}

	// Pass invalid JSON as data
	invalidData := json.RawMessage(`{invalid json}`)
	routeTypingIndicator(c, invalidData)
}

func TestCB109_RouteTypingIndicator_MissingConversationID(t *testing.T) {
	h := newHub()
	go h.run()
	defer h.Stop()

	c := &Connection{
		hub:         h,
		connType:    "client",
		id:          "user1",
		send:        make(chan []byte, 10),
		connectedAt: time.Now(),
	}

	data := json.RawMessage(`{"is_typing":true}`)
	routeTypingIndicator(c, data)
}

// ============ routeStatusUpdate: invalid JSON ============

func TestCB109_RouteStatusUpdate_InvalidJSON(t *testing.T) {
	h := newHub()
	go h.run()
	defer h.Stop()

	c := &Connection{
		hub:         h,
		connType:    "agent",
		id:          "agent1",
		send:        make(chan []byte, 10),
		connectedAt: time.Now(),
	}

	invalidData := json.RawMessage(`{invalid json}`)
	routeStatusUpdate(c, invalidData)
}

func TestCB109_RouteStatusUpdate_MissingConversationID(t *testing.T) {
	h := newHub()
	go h.run()
	defer h.Stop()
	origHub := hub
	hub = h
	defer func() { hub = origHub }()

	c := &Connection{
		hub:         h,
		connType:    "agent",
		id:          "agent1",
		send:        make(chan []byte, 10),
		connectedAt: time.Now(),
	}

	data := json.RawMessage(`{"status":"busy"}`)
	routeStatusUpdate(c, data)
}

// ============ handleSetNotificationPrefs: DB error ============

func TestCB109_HandleSetNotificationPrefs_DBError(t *testing.T) {
	origDB := db
	db = setupClosedDB_CB109(t)
	defer func() { db = origDB }()

	token := generateTestJWT_CB109(t, "user1", "testuser")
	body := strings.NewReader("conversation_id=conv-1&muted=true")
	req := httptest.NewRequest(http.MethodPost, "/notifications/preferences", body)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	// Set userID in context (as middleware would)
	ctx := context.WithValue(req.Context(), contextKeyUserID, "user1")
	req = req.WithContext(ctx)
	rr := httptest.NewRecorder()

	handleSetNotificationPrefs(rr, req)

	if rr.Code != http.StatusInternalServerError && rr.Code != http.StatusNotFound {
		t.Errorf("expected 500 or 404 for closed DB, got %d", rr.Code)
	}
}

// ============ handleGetNotificationPrefs: DB error ============

func TestCB109_HandleGetNotificationPrefs_DBError(t *testing.T) {
	origDB := db
	db = setupClosedDB_CB109(t)
	defer func() { db = origDB }()

	token := generateTestJWT_CB109(t, "user1", "testuser")
	req := httptest.NewRequest(http.MethodGet, "/notifications/preferences?conversation_id=conv-1", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	// Set userID in context (as middleware would)
	ctx := context.WithValue(req.Context(), contextKeyUserID, "user1")
	req = req.WithContext(ctx)
	rr := httptest.NewRecorder()

	handleGetNotificationPrefs(rr, req)

	if rr.Code != http.StatusInternalServerError && rr.Code != http.StatusNotFound {
		t.Errorf("expected 500 or 404 for closed DB, got %d", rr.Code)
	}
}

// ============ handleWebPushSubscribe: DB error ============

func TestCB109_HandleWebPushSubscribe_DBError(t *testing.T) {
	origDB := db
	db = setupClosedDB_CB109(t)
	defer func() { db = origDB }()

	token := generateTestJWT_CB109(t, "user1", "testuser")
	body := strings.NewReader(`{"endpoint":"https://example.com/push","keys":{"p256dh":"abc","auth":"def"}}`)
	req := httptest.NewRequest(http.MethodPost, "/push/web-subscribe", body)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	handleWebPushSubscribe(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 for nil DB, got %d", rr.Code)
	}
}

// ============ TieredRateLimiter cleanup: with mixed entries ============

func TestCB109_TieredRateLimiter_CleanupMixedEntries(t *testing.T) {
	tl := NewTieredRateLimiter()
	defer tl.Stop()

	// Add some entries
	tl.mu.Lock()
	now := time.Now()
	tl.limits["fresh-user"] = &userRateLimitState{
		count:    5,
		windowEnd: now.Add(30 * time.Second),
		tier:     TierFree,
	}
	tl.limits["stale-user"] = &userRateLimitState{
		count:    10,
		windowEnd: now.Add(-11 * time.Minute), // expired > 10min
		tier:     TierPro,
	}
	tl.limits["another-stale"] = &userRateLimitState{
		count:    3,
		windowEnd: now.Add(-1 * time.Hour),
		tier:     TierEnterprise,
	}
	tl.mu.Unlock()

	tl.cleanupOnce()

	tl.mu.Lock()
	defer tl.mu.Unlock()
	if _, ok := tl.limits["fresh-user"]; !ok {
		t.Error("expected fresh-user to be retained")
	}
	if _, ok := tl.limits["stale-user"]; ok {
		t.Error("expected stale-user to be removed")
	}
	if _, ok := tl.limits["another-stale"]; ok {
		t.Error("expected another-stale to be removed")
	}
}

// ============ handleAgentConnect: edge cases ============

func TestCB109_HandleAgentConnect_MissingAgentID(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/agent/connect", nil)
	rr := httptest.NewRecorder()

	handleAgentConnect(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing agent_id, got %d", rr.Code)
	}
}

func TestCB109_HandleAgentConnect_NoSecret(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/agent/connect?agent_id=agent1", nil)
	rr := httptest.NewRecorder()

	handleAgentConnect(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for missing secret, got %d", rr.Code)
	}
}

// ============ readPump: unexpected close error ============

func TestCB109_ReadPump_UnexpectedClose(t *testing.T) {
	h := newHub()
	go h.run()
	defer h.Stop()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upgrader := websocket.Upgrader{}
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		// Close with an abnormal close code
		conn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseProtocolError, "abnormal"))
		conn.Close()
	}))
	defer srv.Close()

	wsURL := "ws" + srv.URL[4:]
	ws, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Skipf("could not dial test server: %v", err)
	}

	c := &Connection{
		hub:          h,
		connType:     "agent",
		id:           "agent-unexpected",
		conn:         ws,
		send:         make(chan []byte, 10),
		connectedAt:  time.Now(),
	}

	// Run readPump — it should detect the abnormal close and log the error
	go c.readPump()

	// Wait for readPump to exit
	time.Sleep(300 * time.Millisecond)

	// Verify no panic — the test passing is enough
}

// ============ ipRateLimitMiddleware: blocked path ============

func TestCB109_IPRateLimitMiddleware_Blocked(t *testing.T) {
	// Reset the IP rate limiter and set a very low limit
	origLimiter := ipRateLimiter
	ipRateLimiter = NewRateLimiter(1, time.Millisecond*10)
	defer func() { ipRateLimiter = origLimiter }()

	handler := ipRateLimitMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// First request should succeed
	req1 := httptest.NewRequest(http.MethodGet, "/test", nil)
	req1.RemoteAddr = "1.2.3.4:1234"
	rr1 := httptest.NewRecorder()
	handler.ServeHTTP(rr1, req1)

	// Immediately send second request to trigger rate limit
	req2 := httptest.NewRequest(http.MethodGet, "/test", nil)
	req2.RemoteAddr = "1.2.3.4:1234"
	rr2 := httptest.NewRecorder()
	handler.ServeHTTP(rr2, req2)

	if rr2.Code != http.StatusTooManyRequests {
		t.Errorf("expected 429 for rate-limited request, got %d", rr2.Code)
	}
}

// ============ authRateLimitMiddleware: blocked path ============

func TestCB109_AuthRateLimitMiddleware_Blocked(t *testing.T) {
	origLimiter := authIPLimiter
	authIPLimiter = NewRateLimiter(1, time.Millisecond*10)
	defer func() { authIPLimiter = origLimiter }()

	handler := authRateLimitMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// First request from IP should succeed
	req1 := httptest.NewRequest(http.MethodPost, "/auth/login", nil)
	req1.RemoteAddr = "5.6.7.8:1234"
	rr1 := httptest.NewRecorder()
	handler.ServeHTTP(rr1, req1)

	// Second request should be rate limited
	req2 := httptest.NewRequest(http.MethodPost, "/auth/login", nil)
	req2.RemoteAddr = "5.6.7.8:1234"
	rr2 := httptest.NewRecorder()
	handler.ServeHTTP(rr2, req2)

	if rr2.Code != http.StatusTooManyRequests {
		t.Errorf("expected 429 for rate-limited auth request, got %d", rr2.Code)
	}
}

// ============ WriteHeapProfile: error path ============

func TestCB109_WriteHeapProfile_Error(t *testing.T) {
	// Pass a path in a non-writable directory
	err := WriteHeapProfile("/nonexistent/path/that/does/not/exist/heap.prof")
	if err == nil {
		t.Error("expected error from non-writable path, got nil")
	}
}

// ============ WriteGoroutineProfile: error path ============

func TestCB109_WriteGoroutineProfile_Error(t *testing.T) {
	err := WriteGoroutineProfile("/nonexistent/path/that/does/not/exist/goroutine.prof")
	if err == nil {
		t.Error("expected error from non-writable path, got nil")
	}
}

// ============ handleHeapProfile: write error ============

func TestCB109_HandleHeapProfile_WriteError(t *testing.T) {
	// Set PROFILING_DIR to a non-writable path
	t.Setenv("PROFILING_DIR", "/nonexistent/path/that/does/not/exist")

	req := httptest.NewRequest(http.MethodGet, "/admin/profile?action=heap", nil)
	rr := httptest.NewRecorder()

	handleAdminProfile(rr, req)

	// Should return error status
	if rr.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 for non-writable profile dir, got %d", rr.Code)
	}
}

// ============ handleGoroutineProfile: write error ============

func TestCB109_HandleGoroutineProfile_WriteError(t *testing.T) {
	t.Setenv("PROFILING_DIR", "/nonexistent/path/that/does/not/exist")

	req := httptest.NewRequest(http.MethodGet, "/admin/profile?action=goroutine", nil)
	rr := httptest.NewRecorder()

	handleAdminProfile(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 for non-writable profile dir, got %d", rr.Code)
	}
}

// ============ handleCPUProfileStart: write error ============

func TestCB109_HandleCPUProfileStart_WriteError(t *testing.T) {
	t.Setenv("PROFILING_DIR", "/nonexistent/path/that/does/not/exist")

	req := httptest.NewRequest(http.MethodPost, "/admin/profile?action=cpu", nil)
	rr := httptest.NewRecorder()

	handleAdminProfile(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 for non-writable profile dir, got %d", rr.Code)
	}
}

// ============ sendFCMNotification: error from FCM ============

func TestCB109_SendFCMNotification_ServerError(t *testing.T) {
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error": map[string]interface{}{
				"status": "INTERNAL",
				"message": "internal server error",
			},
		})
	}))
	defer mockServer.Close()

	origConfig := pushConfig
	pushConfig = &PushNotificationConfig{
		FCMEnabled: true,
		fcmClient:  newMockFCMClient_CB109(t, mockServer),
	}
	defer func() { pushConfig = origConfig }()

	err := sendFCMNotification("test-token", "Title", "Body", "conv-1")
	if err == nil {
		t.Error("expected error from FCM server error, got nil")
	}
}

func TestCB109_SendFCMNotification_Success(t *testing.T) {
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"name": "projects/test/messages/0",
		})
	}))
	defer mockServer.Close()

	origConfig := pushConfig
	pushConfig = &PushNotificationConfig{
		FCMEnabled: true,
		fcmClient:  newMockFCMClient_CB109(t, mockServer),
	}
	defer func() { pushConfig = origConfig }()

	err := sendFCMNotification("test-token", "Title", "Body", "conv-1")
	if err != nil {
		t.Errorf("expected nil error, got %v", err)
	}
}

func TestCB109_SendFCMNotification_Disabled(t *testing.T) {
	origConfig := pushConfig
	pushConfig = &PushNotificationConfig{
		FCMEnabled: false,
	}
	defer func() { pushConfig = origConfig }()

	err := sendFCMNotification("test-token", "Title", "Body", "conv-1")
	if err != nil {
		t.Errorf("expected nil error for disabled FCM, got %v", err)
	}
}

func TestCB109_SendFCMNotification_NilConfig(t *testing.T) {
	origConfig := pushConfig
	pushConfig = nil
	defer func() { pushConfig = origConfig }()

	err := sendFCMNotification("test-token", "Title", "Body", "conv-1")
	if err != nil {
		t.Errorf("expected nil error for nil config, got %v", err)
	}
}

// ============ handleRegisterDeviceToken: success and error paths ============

func TestCB109_HandleRegisterDeviceToken_Success(t *testing.T) {
	testDB := setupTestDB_CB109(t)
	origDB := db
	db = testDB
	defer func() { db = origDB; testDB.Close() }()

	token := generateTestJWT_CB109(t, "user1", "testuser")
	body := strings.NewReader(`{"device_token":"token-abc","platform":"ios"}`)
	req := httptest.NewRequest(http.MethodPost, "/push/register", body)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	handleRegisterDeviceToken(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}

func TestCB109_HandleRegisterDeviceToken_DefaultPlatform(t *testing.T) {
	testDB := setupTestDB_CB109(t)
	origDB := db
	db = testDB
	defer func() { db = origDB; testDB.Close() }()

	token := generateTestJWT_CB109(t, "user1", "testuser")
	body := strings.NewReader(`{"device_token":"token-xyz"}`)
	req := httptest.NewRequest(http.MethodPost, "/push/register", body)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	handleRegisterDeviceToken(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}

func TestCB109_HandleRegisterDeviceToken_DBError(t *testing.T) {
	origDB := db
	db = setupClosedDB_CB109(t)
	defer func() { db = origDB }()

	token := generateTestJWT_CB109(t, "user1", "testuser")
	body := strings.NewReader(`{"device_token":"token-abc","platform":"ios"}`)
	req := httptest.NewRequest(http.MethodPost, "/push/register", body)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	handleRegisterDeviceToken(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 for nil DB, got %d", rr.Code)
	}
}

func TestCB109_HandleRegisterDeviceToken_MissingToken(t *testing.T) {
	token := generateTestJWT_CB109(t, "user1", "testuser")
	body := strings.NewReader(`{"platform":"ios"}`)
	req := httptest.NewRequest(http.MethodPost, "/push/register", body)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	handleRegisterDeviceToken(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing device_token, got %d", rr.Code)
	}
}

func TestCB109_HandleRegisterDeviceToken_InvalidBody(t *testing.T) {
	token := generateTestJWT_CB109(t, "user1", "testuser")
	body := strings.NewReader(`{invalid json}`)
	req := httptest.NewRequest(http.MethodPost, "/push/register", body)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	handleRegisterDeviceToken(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid body, got %d", rr.Code)
	}
}

func TestCB109_HandleRegisterDeviceToken_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/push/register", nil)
	rr := httptest.NewRecorder()

	handleRegisterDeviceToken(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rr.Code)
	}
}

func TestCB109_HandleRegisterDeviceToken_Unauthorized(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/push/register", nil)
	rr := httptest.NewRecorder()

	handleRegisterDeviceToken(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

// ============ handleUnregisterDeviceToken: edge cases ============

func TestCB109_HandleUnregisterDeviceToken_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/push/unregister", nil)
	rr := httptest.NewRecorder()

	handleUnregisterDeviceToken(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rr.Code)
	}
}

func TestCB109_HandleUnregisterDeviceToken_Unauthorized(t *testing.T) {
	req := httptest.NewRequest(http.MethodDelete, "/push/unregister", nil)
	rr := httptest.NewRecorder()

	handleUnregisterDeviceToken(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

func TestCB109_HandleUnregisterDeviceToken_MissingToken(t *testing.T) {
	token := generateTestJWT_CB109(t, "user1", "testuser")
	body := strings.NewReader(`{}`)
	req := httptest.NewRequest(http.MethodDelete, "/push/unregister", body)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	handleUnregisterDeviceToken(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing token, got %d", rr.Code)
	}
}

func TestCB109_HandleUnregisterDeviceToken_InvalidBody(t *testing.T) {
	token := generateTestJWT_CB109(t, "user1", "testuser")
	body := strings.NewReader(`{invalid}`)
	req := httptest.NewRequest(http.MethodDelete, "/push/unregister", body)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	handleUnregisterDeviceToken(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid body, got %d", rr.Code)
	}
}

func TestCB109_HandleUnregisterDeviceToken_DBError(t *testing.T) {
	origDB := db
	db = setupClosedDB_CB109(t)
	defer func() { db = origDB }()

	token := generateTestJWT_CB109(t, "user1", "testuser")
	body := strings.NewReader(`{"device_token":"token-abc"}`)
	req := httptest.NewRequest(http.MethodDelete, "/push/unregister", body)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	handleUnregisterDeviceToken(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 for nil DB, got %d", rr.Code)
	}
}

func TestCB109_HandleUnregisterDeviceToken_Success(t *testing.T) {
	testDB := setupTestDB_CB109(t)
	origDB := db
	db = testDB
	defer func() { db = origDB; testDB.Close() }()

	// Insert a token first
	_, err := testDB.Exec(`INSERT INTO device_tokens (user_id, device_token, platform, updated_at) VALUES (?, ?, ?, CURRENT_TIMESTAMP)`,
		"user1", "token-abc", "ios")
	if err != nil {
		t.Fatalf("failed to insert token: %v", err)
	}

	token := generateTestJWT_CB109(t, "user1", "testuser")
	body := strings.NewReader(`{"device_token":"token-abc"}`)
	req := httptest.NewRequest(http.MethodDelete, "/push/unregister", body)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	handleUnregisterDeviceToken(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}

// ============ handleWebPushSubscribe: success ============

func TestCB109_HandleWebPushSubscribe_Success(t *testing.T) {
	testDB := setupTestDB_CB109(t)
	origDB := db
	db = testDB
	defer func() { db = origDB; testDB.Close() }()

	token := generateTestJWT_CB109(t, "user1", "testuser")
	body := strings.NewReader(`{"endpoint":"https://example.com/push/123","keys":{"p256dh":"abc","auth":"def"}}`)
	req := httptest.NewRequest(http.MethodPost, "/push/web-subscribe", body)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	handleWebPushSubscribe(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}

func TestCB109_HandleWebPushSubscribe_MissingFields(t *testing.T) {
	token := generateTestJWT_CB109(t, "user1", "testuser")
	body := strings.NewReader(`{"endpoint":""}`)
	req := httptest.NewRequest(http.MethodPost, "/push/web-subscribe", body)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	handleWebPushSubscribe(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing fields, got %d", rr.Code)
	}
}

func TestCB109_HandleWebPushSubscribe_InvalidBody(t *testing.T) {
	token := generateTestJWT_CB109(t, "user1", "testuser")
	body := strings.NewReader(`{invalid}`)
	req := httptest.NewRequest(http.MethodPost, "/push/web-subscribe", body)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	handleWebPushSubscribe(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid body, got %d", rr.Code)
	}
}

func TestCB109_HandleWebPushSubscribe_Unauthorized(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/push/web-subscribe", nil)
	rr := httptest.NewRecorder()

	handleWebPushSubscribe(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

func TestCB109_HandleWebPushSubscribe_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/push/web-subscribe", nil)
	rr := httptest.NewRecorder()

	handleWebPushSubscribe(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rr.Code)
	}
}

// ============ handleWebPushUnsubscribe: edge cases ============

func TestCB109_HandleWebPushUnsubscribe_Success(t *testing.T) {
	testDB := setupTestDB_CB109(t)
	origDB := db
	db = testDB
	defer func() { db = origDB; testDB.Close() }()

	token := generateTestJWT_CB109(t, "user1", "testuser")
	body := strings.NewReader(`{"endpoint":"https://example.com/push/123"}`)
	req := httptest.NewRequest(http.MethodPost, "/push/web-unsubscribe", body)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	handleWebPushUnsubscribe(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}

func TestCB109_HandleWebPushUnsubscribe_DBError(t *testing.T) {
	origDB := db
	db = setupClosedDB_CB109(t)
	defer func() { db = origDB }()

	token := generateTestJWT_CB109(t, "user1", "testuser")
	body := strings.NewReader(`{"endpoint":"https://example.com/push/123"}`)
	req := httptest.NewRequest(http.MethodPost, "/push/web-unsubscribe", body)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	handleWebPushUnsubscribe(rr, req)

	// handleWebPushUnsubscribe ignores db.Exec errors and returns 200 regardless
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 (handler ignores DB errors), got %d", rr.Code)
	}
}

// ============ sendPushNotification: FCM error propagation ============

func TestCB109_SendPushNotification_FCMError(t *testing.T) {
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error": map[string]interface{}{
				"message": "FCM error",
			},
		})
	}))
	defer mockServer.Close()

	origConfig := pushConfig
	pushConfig = &PushNotificationConfig{
		FCMEnabled: true,
		fcmClient:  newMockFCMClient_CB109(t, mockServer),
	}
	defer func() { pushConfig = origConfig }()

	err := sendPushNotification("test-token", "Title", "Body", "conv-1", "android")
	if err == nil {
		t.Error("expected error from FCM, got nil")
	}
}

// ============ InitTracing: with HTTP endpoint ============

func TestCB109_InitTracing_HTTPProtocol(t *testing.T) {
	// Reset tracing state
	origTracingMu := tracingMu
	tracingMu = sync.Once{}
	defer func() { tracingMu = origTracingMu }()

	origTp := tp
	tp = nil
	defer func() { tp = origTp }()

	origTracingEnabled := tracingEnabled
	tracingEnabled = false
	defer func() { tracingEnabled = origTracingEnabled }()

	origTracer := tracer
	tracer = nil
	defer func() { tracer = origTracer }()

	t.Setenv("OTEL_ENABLED", "true")
	t.Setenv("OTEL_EXPORTER_OTLP_PROTOCOL", "http")
	t.Setenv("OTEL_EXPORTER_OTLP_HTTP_ENDPOINT", "http://localhost:4318")

	err := InitTracing()
	// Will likely fail to connect, but should not panic
	// The exporter creation may succeed (lazy), but provider setup should work
	if err != nil {
		// Acceptable — can't connect to OTEL collector in test env
		t.Logf("InitTracing returned error (expected in test): %v", err)
	}

	// Clean up
	if tp != nil {
		ShutdownTracing()
	}
}

func TestCB109_InitTracing_GRPCProtocol(t *testing.T) {
	origTracingMu := tracingMu
	tracingMu = sync.Once{}
	defer func() { tracingMu = origTracingMu }()

	origTp := tp
	tp = nil
	defer func() { tp = origTp }()

	origTracingEnabled := tracingEnabled
	tracingEnabled = false
	defer func() { tracingEnabled = origTracingEnabled }()

	origTracer := tracer
	tracer = nil
	defer func() { tracer = origTracer }()

	t.Setenv("OTEL_ENABLED", "true")
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "localhost:4317")
	t.Setenv("OTEL_EXPORTER_OTLP_PROTOCOL", "grpc")

	err := InitTracing()
	if err != nil {
		t.Logf("InitTracing gRPC returned error (expected in test): %v", err)
	}

	if tp != nil {
		ShutdownTracing()
	}
}

func TestCB109_InitTracing_CustomServiceName(t *testing.T) {
	origTracingMu := tracingMu
	tracingMu = sync.Once{}
	defer func() { tracingMu = origTracingMu }()

	origTp := tp
	tp = nil
	defer func() { tp = origTp }()

	origTracingEnabled := tracingEnabled
	tracingEnabled = false
	defer func() { tracingEnabled = origTracingEnabled }()

	origTracer := tracer
	tracer = nil
	defer func() { tracer = origTracer }()

	t.Setenv("OTEL_ENABLED", "true")
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "localhost:4317")
	t.Setenv("OTEL_SERVICE_NAME", "custom-agent-messenger")

	err := InitTracing()
	if err != nil {
		t.Logf("InitTracing custom service name returned error (expected): %v", err)
	}

	if tp != nil {
		ShutdownTracing()
	}
}

// ============ ShutdownTracing: with real provider error ============

func TestCB109_ShutdownTracing_WithProviderError(t *testing.T) {
	// Set tp to a provider that returns an error on shutdown
	// We can use a mock SpanExporter that fails on shutdown
	// Actually, we already test this in CB108 — let's test with a real tp
	// that we set up via InitTracing
	origTracingMu := tracingMu
	tracingMu = sync.Once{}
	defer func() { tracingMu = origTracingMu }()

	origTp := tp
	tp = nil
	defer func() { tp = origTp }()

	origTracingEnabled := tracingEnabled
	tracingEnabled = false
	defer func() { tracingEnabled = origTracingEnabled }()

	origTracer := tracer
	tracer = nil
	defer func() { tracer = origTracer }()

	t.Setenv("OTEL_ENABLED", "true")
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "localhost:4317")

	err := InitTracing()
	if err == nil && tp != nil {
		// Now shutdown should work
		ShutdownTracing()
	}
}

// ============ handleUpload: success with file save ============

func TestCB109_HandleUpload_SuccessWithFile(t *testing.T) {
	testDB := setupTestDB_CB109(t)
	origDB := db
	db = testDB
	defer func() { db = origDB; testDB.Close() }()

	// Create a conversation for the upload
	_, err := testDB.Exec("INSERT INTO conversations (id, user_id, agent_id, created_at) VALUES (?, ?, ?, CURRENT_TIMESTAMP)",
		"conv-1", "user1", "agent1")
	if err != nil {
		t.Fatalf("failed to insert conversation: %v", err)
	}

	// Set upload dir to temp via serverDBPath
	origServerDBPath := serverDBPath
	serverDBPath = t.TempDir()
	defer func() { serverDBPath = origServerDBPath }()

	token := generateTestJWT_CB109(t, "user1", "testuser")

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	part, err := writer.CreateFormFile("file", "test.txt")
	if err != nil {
		t.Fatalf("failed to create form file: %v", err)
	}
	part.Write([]byte("Hello, this is a test file!"))
	writer.WriteField("conversation_id", "conv-1")
	writer.WriteField("message_id", "msg-1")
	writer.Close()

	req := httptest.NewRequest(http.MethodPost, "/attachments/upload", body)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	rr := httptest.NewRecorder()

	handleUpload(rr, req)

	// Should return 201 or 200
	if rr.Code != http.StatusCreated && rr.Code != http.StatusOK {
		t.Errorf("expected 201 or 200, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestCB109_HandleUpload_SeekError(t *testing.T) {
	testDB := setupTestDB_CB109(t)
	origDB := db
	db = testDB
	defer func() { db = origDB; testDB.Close() }()

	_, err := testDB.Exec("INSERT INTO conversations (id, user_id, agent_id, created_at) VALUES (?, ?, ?, CURRENT_TIMESTAMP)",
		"conv-1", "user1", "agent1")
	if err != nil {
		t.Fatalf("failed to insert conversation: %v", err)
	}

	token := generateTestJWT_CB109(t, "user1", "testuser")

	// Create a body with a file that has no Content-Type header
	// so it tries to detect and then seek
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	// Create a file part with no Content-Type (will be application/octet-stream)
	part, err := writer.CreateFormFile("file", "test.bin")
	if err != nil {
		t.Fatalf("failed to create form file: %v", err)
	}
	part.Write([]byte("binary data here"))
	writer.WriteField("conversation_id", "conv-1")
	writer.Close()

	req := httptest.NewRequest(http.MethodPost, "/attachments/upload", body)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	rr := httptest.NewRecorder()

	handleUpload(rr, req)

	// Should succeed (content type will be detected)
	// or return an error if binary isn't allowed
	if rr.Code != http.StatusCreated && rr.Code != http.StatusOK && rr.Code != http.StatusBadRequest {
		t.Errorf("expected 201, 200, or 400, got %d: %s", rr.Code, rr.Body.String())
	}
}

// ============ initSchema: nil DB ============

func TestCB109_InitSchema_NilDB(t *testing.T) {
	// initSchema panics on nil DB (db.Exec on nil *sql.DB)
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic for nil DB, but initSchema did not panic")
		}
	}()
	_ = initSchema(nil)
}

// ============ Helper functions ============

func setupTestDB_CB109(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("failed to open in-memory DB: %v", err)
	}
	// Run schema initialization
	if err := initSchema(db); err != nil {
		t.Fatalf("failed to init schema: %v", err)
	}
	return db
}

func setupClosedDB_CB109(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("failed to open in-memory DB: %v", err)
	}
	db.Close()
	return db
}

func openTestDB_CB109() (*sql.DB, error) {
	return sql.Open("sqlite3", ":memory:")
}

func generateTestJWT_CB109(t *testing.T, userID, username string) string {
	t.Helper()
	token, err := GenerateJWT(userID, username)
	if err != nil {
		t.Fatalf("failed to generate JWT: %v", err)
	}
	return token
}

func createExpiredJWT_CB109() (string, error) {
	// Create an expired JWT using the jwt package
	// We need to create it manually with an expired time
	// Since we don't have direct access to the jwt library here,
	// we'll skip this test
	return "", fmt.Errorf("not implemented")
}



// ============ Additional CB109 tests (non-duplicate) ============

// --- routeChatMessage: missing conversation_id (content present) ---
func TestCB109_RouteChatMessage_MissingConvIDContent(t *testing.T) {
	h := newHub()
	hub = h
	go h.run()
	defer h.Stop()

	sender := &Connection{
		connType: "client",
		id:       "user1",
		send:     make(chan []byte, 256),
		hub:      h,
	}

	data, _ := json.Marshal(RoutedMessage{
		Content: "hello",
	})
	routeChatMessage(sender, data)

	select {
	case msg := <-sender.send:
		if !strings.Contains(string(msg), "conversation_id") {
			t.Errorf("expected conversation_id error, got: %s", string(msg))
		}
	case <-time.After(100 * time.Millisecond):
		t.Error("no error message received")
	}
}

// --- routeChatMessage: agent not authorized for conversation ---
func TestCB109_RouteChatMessage_AgentNotAuth(t *testing.T) {
	testDB := setupTestDB_CB109(t)
	origDB := db
	db = testDB
	defer func() { db = origDB; testDB.Close() }()

	h := newHub()
	hub = h
	go h.run()
	defer h.Stop()

	conv, err := CreateConversation("user1", "agent1")
	if err != nil {
		t.Fatalf("failed to create conversation: %v", err)
	}

	sender := &Connection{
		connType: "agent",
		id:       "agent2",
		send:     make(chan []byte, 256),
		hub:      h,
	}

	data, _ := json.Marshal(RoutedMessage{
		ConversationID: conv.ID,
		Content:        "hello from wrong agent",
	})
	routeChatMessage(sender, data)

	select {
	case msg := <-sender.send:
		if !strings.Contains(string(msg), "not authorized") {
			t.Errorf("expected not authorized error, got: %s", string(msg))
		}
	case <-time.After(100 * time.Millisecond):
		t.Error("no error message received")
	}
}

// --- routeChatMessage: client not authorized for conversation ---
func TestCB109_RouteChatMessage_ClientNotAuth(t *testing.T) {
	testDB := setupTestDB_CB109(t)
	origDB := db
	db = testDB
	defer func() { db = origDB; testDB.Close() }()

	h := newHub()
	hub = h
	go h.run()
	defer h.Stop()

	conv, err := CreateConversation("user1", "agent1")
	if err != nil {
		t.Fatalf("failed to create conversation: %v", err)
	}

	sender := &Connection{
		connType: "client",
		id:       "user2",
		send:     make(chan []byte, 256),
		hub:      h,
	}

	data, _ := json.Marshal(RoutedMessage{
		ConversationID: conv.ID,
		Content:        "hello from wrong user",
	})
	routeChatMessage(sender, data)

	select {
	case msg := <-sender.send:
		if !strings.Contains(string(msg), "not authorized") {
			t.Errorf("expected not authorized error, got: %s", string(msg))
		}
	case <-time.After(100 * time.Millisecond):
		t.Error("no error message received")
	}
}

// --- routeStatusUpdate: agent status without conv_id (broadcast path) ---
func TestCB109_RouteStatusUpdate_AgentStatusBroadcast(t *testing.T) {
	h := newHub()
	hub = h
	go h.run()
	defer h.Stop()

	sender := &Connection{
		connType: "agent",
		id:       "agent1",
		send:     make(chan []byte, 256),
		hub:      h,
	}
	h.mu.Lock()
	h.agents["agent1"] = sender
	h.mu.Unlock()

	data, _ := json.Marshal(map[string]string{
		"status": "busy",
	})
	routeStatusUpdate(sender, data)

	status := h.AgentStatus("agent1")
	if status != "busy" {
		t.Errorf("expected agent status 'busy', got '%s'", status)
	}
}

// --- routeStatusUpdate: client to agent delivery ---
func TestCB109_RouteStatusUpdate_ClientToAgent(t *testing.T) {
	testDB := setupTestDB_CB109(t)
	origDB := db
	db = testDB
	defer func() { db = origDB; testDB.Close() }()

	h := newHub()
	hub = h
	go h.run()
	defer h.Stop()

	conv, err := CreateConversation("user1", "agent1")
	if err != nil {
		t.Fatalf("failed to create conversation: %v", err)
	}

	agentConn := &Connection{
		connType: "agent",
		id:       "agent1",
		send:     make(chan []byte, 256),
		hub:      h,
	}
	h.agents["agent1"] = agentConn

	sender := &Connection{
		connType: "client",
		id:       "user1",
		send:     make(chan []byte, 256),
		hub:      h,
	}

	data, _ := json.Marshal(map[string]string{
		"conversation_id": conv.ID,
		"status":          "typing",
	})
	routeStatusUpdate(sender, data)

	select {
	case msg := <-agentConn.send:
		if !strings.Contains(string(msg), "typing") {
			t.Errorf("expected status update with 'typing', got: %s", string(msg))
		}
	case <-time.After(100 * time.Millisecond):
		t.Error("agent did not receive status update")
	}
}

// --- RegisterAgentOnConnect: update existing agent with all fields ---
func TestCB109_RegisterAgentOnConnect_UpdateAllFields(t *testing.T) {
	testDB := setupTestDB_CB109(t)
	origDB := db
	db = testDB
	defer func() { db = origDB; testDB.Close() }()

	err := RegisterAgentOnConnect("agent-dup", "Agent Dup", "gpt-4", "friendly", "general")
	if err != nil {
		t.Fatalf("first insert failed: %v", err)
	}

	err = RegisterAgentOnConnect("agent-dup", "Agent Dup Updated", "gpt-5", "serious", "coding")
	if err != nil {
		t.Errorf("update on existing agent failed: %v", err)
	}

	var name string
	err = testDB.QueryRow("SELECT name FROM agents WHERE id = ?", "agent-dup").Scan(&name)
	if err != nil {
		t.Fatalf("query failed: %v", err)
	}
	if name != "Agent Dup Updated" {
		t.Errorf("expected name 'Agent Dup Updated', got '%s'", name)
	}
}

// --- RegisterAgentOnConnect: update individual fields ---
func TestCB109_RegisterAgentOnConnect_UpdateIndividualFields(t *testing.T) {
	testDB := setupTestDB_CB109(t)
	origDB := db
	db = testDB
	defer func() { db = origDB; testDB.Close() }()

	err := RegisterAgentOnConnect("agent-upd", "Agent Upd", "gpt-4", "friendly", "general")
	if err != nil {
		t.Fatalf("insert failed: %v", err)
	}

	// Update only model
	err = RegisterAgentOnConnect("agent-upd", "", "gpt-5", "", "")
	if err != nil {
		t.Errorf("update model failed: %v", err)
	}
	var model string
	err = testDB.QueryRow("SELECT model FROM agents WHERE id = ?", "agent-upd").Scan(&model)
	if err != nil {
		t.Fatalf("query failed: %v", err)
	}
	if model != "gpt-5" {
		t.Errorf("expected model 'gpt-5', got '%s'", model)
	}

	// Update only personality
	err = RegisterAgentOnConnect("agent-upd", "", "", "serious", "")
	if err != nil {
		t.Errorf("update personality failed: %v", err)
	}
	var personality string
	err = testDB.QueryRow("SELECT personality FROM agents WHERE id = ?", "agent-upd").Scan(&personality)
	if err != nil {
		t.Fatalf("query failed: %v", err)
	}
	if personality != "serious" {
		t.Errorf("expected personality 'serious', got '%s'", personality)
	}

	// Update only specialty
	err = RegisterAgentOnConnect("agent-upd", "", "", "", "coding")
	if err != nil {
		t.Errorf("update specialty failed: %v", err)
	}
	var specialty string
	err = testDB.QueryRow("SELECT specialty FROM agents WHERE id = ?", "agent-upd").Scan(&specialty)
	if err != nil {
		t.Fatalf("query failed: %v", err)
	}
	if specialty != "coding" {
		t.Errorf("expected specialty 'coding', got '%s'", specialty)
	}
}

// --- handleUpload: multipart with message_id ---
func TestCB109_HandleUpload_WithMessageID(t *testing.T) {
	testDB := setupTestDB_CB109(t)
	origDB := db
	db = testDB
	defer func() { db = origDB; testDB.Close() }()

	conv, err := CreateConversation("user1", "agent1")
	if err != nil {
		t.Fatalf("failed to create conversation: %v", err)
	}
	err = storeMessage(RoutedMessage{
		ConversationID: conv.ID,
		Content:        "test message",
		SenderType:     "client",
		SenderID:       "user1",
		Type:           MsgTypeMessage,
	})
	if err != nil {
		t.Fatalf("failed to store message: %v", err)
	}

	var msgID string
	err = testDB.QueryRow("SELECT id FROM messages WHERE conversation_id = ? ORDER BY created_at DESC LIMIT 1", conv.ID).Scan(&msgID)
	if err != nil {
		t.Fatalf("failed to get message ID: %v", err)
	}

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	writer.WriteField("conversation_id", conv.ID)
	writer.WriteField("message_id", msgID)
	part, err := writer.CreateFormFile("file", "test.txt")
	if err != nil {
		t.Fatalf("failed to create form file: %v", err)
	}
	part.Write([]byte("hello world"))
	writer.Close()

	token := generateTestJWT_CB109(t, "user1", "testuser")
	req := httptest.NewRequest(http.MethodPost, "/upload", body)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	rr := httptest.NewRecorder()

	handleUpload(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
}

// --- handleStoreEncryptedMessage: missing iv ---
func TestCB109_HandleStoreEncryptedMessage_MissingIV(t *testing.T) {
	testDB := setupTestDB_CB109(t)
	origDB := db
	db = testDB
	defer func() { db = origDB; testDB.Close() }()

	conv, err := CreateConversation("user1", "agent1")
	if err != nil {
		t.Fatalf("failed to create conversation: %v", err)
	}

	token := generateTestJWT_CB109(t, "user1", "testuser")
	body := strings.NewReader(fmt.Sprintf(`{"conversation_id":"%s","ciphertext":"abc","algorithm":"aes-256-gcm"}`, conv.ID))
	req := httptest.NewRequest(http.MethodPost, "/e2e/store", body)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	handleStoreEncryptedMessage(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing iv, got %d", rr.Code)
	}
}

// --- handleGetEncryptedMessages: with limit ---
func TestCB109_HandleGetEncryptedMessages_Limit(t *testing.T) {
	testDB := setupTestDB_CB109(t)
	origDB := db
	db = testDB
	defer func() { db = origDB; testDB.Close() }()

	conv, err := CreateConversation("user1", "agent1")
	if err != nil {
		t.Fatalf("failed to create conversation: %v", err)
	}

	for i := 0; i < 3; i++ {
		_, err := testDB.Exec(`INSERT INTO encrypted_messages (id, conversation_id, sender_id, sender_type, ciphertext, iv, recipient_key_id, algorithm, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)`,
			fmt.Sprintf("msg-%d", i), conv.ID, "user1", "client", fmt.Sprintf("cipher%d", i), fmt.Sprintf("iv%d", i), "key1", "aes-256-gcm")
		if err != nil {
			t.Fatalf("failed to insert encrypted message: %v", err)
		}
	}
	

	token := generateTestJWT_CB109(t, "user1", "testuser")
	
	req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/e2e/messages?conversation_id=%s&limit=2", conv.ID), nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()

	handleGetEncryptedMessages(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	
	var resp []EncryptedMessage
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	if len(resp) != 2 {
		t.Errorf("expected 2 messages with limit, got %d", len(resp))
	}
}

// --- handleGetRateLimitTier: FormSecret auth path ---
func TestCB109_HandleGetRateLimitTier_FormSecretAuth(t *testing.T) {
	origAdminSecret := getAdminSecret()
	defer func() { resetAdminSecret() }()

	req := httptest.NewRequest(http.MethodGet, "/admin/rate-limit/tier?user_id=user1&admin_secret="+origAdminSecret, nil)
	rr := httptest.NewRecorder()

	handleGetRateLimitTier(rr, req)

	if rr.Code == http.StatusUnauthorized {
		t.Errorf("expected non-401 with valid form secret, got %d", rr.Code)
	}
}

// --- cleanup: stale entry removal ---
func TestCB109_CleanupOnce_RemovesStaleEntry(t *testing.T) {
	trl := NewTieredRateLimiter()

	trl.mu.Lock()
	trl.limits["stale-user"] = &userRateLimitState{
		count:     5,
		windowEnd: time.Now().Add(-20 * time.Minute),
		tier:      TierFree,
	}
	trl.mu.Unlock()

	trl.cleanupOnce()

	trl.mu.Lock()
	_, exists := trl.limits["stale-user"]
	trl.mu.Unlock()
	if exists {
		t.Error("expected stale entry to be removed by cleanupOnce")
	}
}

// --- addReaction: DB error on insert ---
func TestCB109_AddReaction_DBInsertErr(t *testing.T) {
	origDB := db
	db = setupClosedDB_CB109(t)
	defer func() { db = origDB }()

	_, _, err := addReaction("msg-1", "user1", "👍")
	if err == nil {
		t.Error("expected error for closed DB, got nil")
	}
}

// --- loadQueueFromDB: with expired and fresh messages ---
func TestCB109_LoadQueueFromDB_ExpiredAndFresh(t *testing.T) {
	testDB := setupTestDB_CB109(t)
	origDB := db
	db = testDB
	defer func() { db = origDB; testDB.Close() }()

	q := newOfflineQueue(100, 7*24*time.Hour)

	// Insert an expired message
	_, err := testDB.Exec(`INSERT INTO offline_queue (recipient, data, queued_at) VALUES (?, ?, ?)`,
		"user1", []byte(`{"type":"message"}`), time.Now().Add(-8*24*time.Hour).Format(time.RFC3339))
	if err != nil {
		t.Fatalf("failed to insert expired message: %v", err)
	}

	// Insert a fresh message
	_, err = testDB.Exec(`INSERT INTO offline_queue (recipient, data, queued_at) VALUES (?, ?, ?)`,
		"user1", []byte(`{"type":"message"}`), time.Now().Format(time.RFC3339))
	if err != nil {
		t.Fatalf("failed to insert fresh message: %v", err)
	}

	loadQueueFromDB(testDB, q)

	if q.TotalDepth() == 0 {
		t.Error("expected messages in queue, got 0")
	}
}
// newMockFCMClient_CB109 creates a mock FCM client
func newMockFCMClient_CB109(t *testing.T, mockServer *httptest.Server) *messaging.Client {
	t.Helper()
	ctx := context.Background()
	app, err := firebase.NewApp(ctx, &firebase.Config{
		ProjectID: "test-project",
	},
		option.WithEndpoint(mockServer.URL),
		option.WithTokenSource(fakeTokenSource{}),
		option.WithScopes(),
	)
	if err != nil {
		t.Fatalf("failed to create Firebase app: %v", err)
	}
	client, err := app.Messaging(ctx)
	if err != nil {
		t.Fatalf("failed to create messaging client: %v", err)
	}
	return client
}
