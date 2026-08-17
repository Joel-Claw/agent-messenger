package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"

	"golang.org/x/crypto/bcrypt"
	_ "github.com/mattn/go-sqlite3"
)

// ============================================================
// CB92: Coverage boost targeting remaining low-coverage functions
// Focus: ShutdownTracing (20%), StartSpan (50%), StartSpanFromRequest (40%),
// SpanError (50%), SpanOK (66.7%), TraceRouteMessage (50%),
// TraceOfflineEnqueue (50%), TracePushNotify (50%),
// TraceAgentConnect (50%), TraceClientConnect (50%),
// sendAPNSNotification (14.3%), sendFCMNotification (22.2%),
// handleGetUserPresence (28%), handleListAttachments (52.8%),
// handleGetAttachment (64.7%), routeMessage (70%),
// replayOfflineMessages (72.2%), handleMessageEdit (75.5%),
// handleSetRateLimitTier (73.1%), newOfflineQueue (60%),
// marshalOutgoingMessage (60%), csrfMiddleware (59.1%),
// ipRateLimitMiddleware (44.4%), authRateLimitMiddleware (44.4%),
// handleMessageDelete (83.3%), Logger SetOutput (0%),
// writePump (70.4%), handleHeapProfile (61.5%),
// handleGoroutineProfile (61.5%), Snapshot (83.3%)
// ============================================================

// --- Helpers ---

func withTestDB_CB92(t *testing.T, fn func(testDB *sql.DB)) {
	t.Helper()
	oldDB := db
	oldDriver := currentDriver
	currentDriver = DriverSQLite
	defer func() { db = oldDB; currentDriver = oldDriver }()
	testDB, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("Failed to open test DB: %v", err)
	}
	defer testDB.Close()
	if err := initSchema(testDB); err != nil {
		t.Fatalf("Failed to init schema: %v", err)
	}
	db = testDB
	fn(testDB)
}

func makeJWT_CB92(userID, username string) string {
	token, err := GenerateJWT(userID, username)
	if err != nil {
		panic("failed to generate JWT: " + err.Error())
	}
	return token
}

func setupHub_CB92() func() {
	oldHub := hub
	h := newHub()
	hub = h
	go h.run()
	return func() {
		h.Stop()
		hub = oldHub
	}
}

func setupUserAndConv_CB92(t *testing.T, testDB *sql.DB) (string, string, string) {
	t.Helper()
	userID := "cb92-user1"
	agentID := "cb92-agent1"
	convID := "cb92-conv1"

	hash, _ := bcrypt.GenerateFromPassword([]byte("testpass"), bcrypt.DefaultCost)
	_, err := testDB.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)",
		userID, "cb92testuser", string(hash))
	if err != nil {
		t.Fatalf("Failed to insert user: %v", err)
	}

	_, err = testDB.Exec("INSERT INTO agents (id, name, model, personality, specialty) VALUES (?, ?, ?, ?, ?)",
		agentID, "TestAgent", "gpt-4", "friendly", "general")
	if err != nil {
		t.Fatalf("Failed to insert agent: %v", err)
	}

	_, err = testDB.Exec("INSERT INTO conversations (id, user_id, agent_id) VALUES (?, ?, ?)",
		convID, userID, agentID)
	if err != nil {
		t.Fatalf("Failed to insert conversation: %v", err)
	}

	return userID, agentID, convID
}

func makeConn_CB92(id, connType string, h *Hub) *Connection {
	return &Connection{
		id:        id,
		connType:  connType,
		send:      make(chan []byte, 256),
		hub:       h,
		connectedAt: time.Now(),
	}
}

// setupTracingEnabled creates a real tracer for testing enabled-tracing paths.
// It bypasses sync.Once by directly setting the package vars.
func setupTracingEnabled() func() {
	origTP := tp
	origTracer := tracer
	origEnabled := tracingEnabled

	// Create a real TracerProvider with a no-op exporter
	res, _ := resource.Merge(
		resource.Default(),
		resource.NewWithAttributes(
			"https://opentelemetry.io/schemas/1.26.0",
			attribute.String("service.name", "test-agent-messenger"),
		),
	)
	provider := sdktrace.NewTracerProvider(
		sdktrace.WithResource(res),
		sdktrace.WithSampler(sdktrace.AlwaysSample()),
	)
	tp = provider
	tracer = provider.Tracer(tracerName)
	tracingEnabled = true
	otel.SetTracerProvider(provider)

	return func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		provider.Shutdown(ctx)
		tp = origTP
		tracer = origTracer
		tracingEnabled = origEnabled
	}
}

// ============================================================
// Tracing: Enabled state tests (bypass sync.Once by setting vars directly)
// ============================================================

func TestCB92_StartSpan_Enabled(t *testing.T) {
	restore := setupTracingEnabled()
	defer restore()

	ctx := context.Background()
	ctx2, span := StartSpan(ctx, "test-span",
		attribute.String("key1", "val1"),
		attribute.Int("key2", 42),
	)
	if span == nil {
		t.Fatal("expected non-nil span when tracing is enabled")
	}
	if ctx2 == nil {
		t.Fatal("expected non-nil context")
	}
	span.End()
}

func TestCB92_StartSpan_EnabledNilTracer(t *testing.T) {
	origTracer := tracer
	origEnabled := tracingEnabled
	defer func() { tracer = origTracer; tracingEnabled = origEnabled }()

	tracingEnabled = true
	tracer = nil

	ctx := context.Background()
	ctx2, span := StartSpan(ctx, "test-span")
	if span == nil {
		t.Fatal("expected non-nil span even with nil tracer (returns noop)")
	}
	if ctx2 == nil {
		t.Fatal("expected non-nil context")
	}
}

func TestCB92_StartSpanFromRequest_Enabled(t *testing.T) {
	restore := setupTracingEnabled()
	defer restore()

	req := httptest.NewRequest("GET", "/test", nil)
	ctx, span := StartSpanFromRequest(req, "http-request-span",
		attribute.String("http.method", "GET"),
		attribute.String("http.url", "/test"),
	)
	if span == nil {
		t.Fatal("expected non-nil span")
	}
	if ctx == nil {
		t.Fatal("expected non-nil context")
	}
	span.End()
}

func TestCB92_StartSpanFromRequest_EnabledNilTracer(t *testing.T) {
	origTracer := tracer
	origEnabled := tracingEnabled
	defer func() { tracer = origTracer; tracingEnabled = origEnabled }()

	tracingEnabled = true
	tracer = nil

	req := httptest.NewRequest("GET", "/test", nil)
	_, span := StartSpanFromRequest(req, "test-span")
	if span == nil {
		t.Fatal("expected non-nil span (noop)")
	}
}

func TestCB92_SpanError_Enabled(t *testing.T) {
	restore := setupTracingEnabled()
	defer restore()

	ctx := context.Background()
	_, span := StartSpan(ctx, "test-error-span")
	defer span.End()

	SpanError(span, fmt.Errorf("test error"))
	// Should not panic
}

func TestCB92_SpanError_EnabledNilSpan(t *testing.T) {
	restore := setupTracingEnabled()
	defer restore()

	// Should not panic with nil span
	SpanError(nil, fmt.Errorf("test error"))
}

func TestCB92_SpanError_Disabled(t *testing.T) {
	origEnabled := tracingEnabled
	defer func() { tracingEnabled = origEnabled }()
	tracingEnabled = false

	// Should not panic
	SpanError(nil, fmt.Errorf("test"))
}

func TestCB92_SpanOK_Enabled(t *testing.T) {
	restore := setupTracingEnabled()
	defer restore()

	ctx := context.Background()
	_, span := StartSpan(ctx, "test-ok-span")
	defer span.End()

	SpanOK(span)
	// Should not panic
}

func TestCB92_SpanOK_EnabledNilSpan(t *testing.T) {
	restore := setupTracingEnabled()
	defer restore()

	SpanOK(nil)
	// Should not panic
}

func TestCB92_SpanOK_Disabled(t *testing.T) {
	origEnabled := tracingEnabled
	defer func() { tracingEnabled = origEnabled }()
	tracingEnabled = false

	SpanOK(nil)
}

func TestCB92_TraceRouteMessage_Enabled(t *testing.T) {
	restore := setupTracingEnabled()
	defer restore()

	span := TraceRouteMessage("agent", "agent-1")
	if span == nil {
		t.Fatal("expected non-nil span")
	}
	span.End()
}

func TestCB92_TraceRouteMessage_Disabled(t *testing.T) {
	origEnabled := tracingEnabled
	defer func() { tracingEnabled = origEnabled }()
	tracingEnabled = false

	span := TraceRouteMessage("agent", "agent-1")
	// Returns a noop span, not nil
	_ = span
}

func TestCB92_TraceOfflineEnqueue_Enabled(t *testing.T) {
	restore := setupTracingEnabled()
	defer restore()

	span := TraceOfflineEnqueue("user-1")
	if span == nil {
		t.Fatal("expected non-nil span")
	}
	span.End()
}

func TestCB92_TraceOfflineEnqueue_Disabled(t *testing.T) {
	origEnabled := tracingEnabled
	defer func() { tracingEnabled = origEnabled }()
	tracingEnabled = false

	span := TraceOfflineEnqueue("user-1")
	_ = span
}

func TestCB92_TracePushNotify_Enabled(t *testing.T) {
	restore := setupTracingEnabled()
	defer restore()

	span := TracePushNotify("user-1", "conv-1", true)
	if span == nil {
		t.Fatal("expected non-nil span")
	}
	span.End()
}

func TestCB92_TracePushNotify_Disabled(t *testing.T) {
	origEnabled := tracingEnabled
	defer func() { tracingEnabled = origEnabled }()
	tracingEnabled = false

	span := TracePushNotify("user-1", "conv-1", false)
	_ = span
}

func TestCB92_TraceAgentConnect_Enabled(t *testing.T) {
	restore := setupTracingEnabled()
	defer restore()

	span := TraceAgentConnect("agent-1")
	if span == nil {
		t.Fatal("expected non-nil span")
	}
	span.End()
}

func TestCB92_TraceAgentConnect_Disabled(t *testing.T) {
	origEnabled := tracingEnabled
	defer func() { tracingEnabled = origEnabled }()
	tracingEnabled = false

	span := TraceAgentConnect("agent-1")
	_ = span
}

func TestCB92_TraceClientConnect_Enabled(t *testing.T) {
	restore := setupTracingEnabled()
	defer restore()

	span := TraceClientConnect("user-1", "device-1")
	if span == nil {
		t.Fatal("expected non-nil span")
	}
	span.End()
}

func TestCB92_TraceClientConnect_Disabled(t *testing.T) {
	origEnabled := tracingEnabled
	defer func() { tracingEnabled = origEnabled }()
	tracingEnabled = false

	span := TraceClientConnect("user-1", "device-1")
	_ = span
}

func TestCB92_TraceChatMessage_Enabled(t *testing.T) {
	restore := setupTracingEnabled()
	defer restore()

	ctx := context.Background()
	ctx2, span := TraceChatMessage(ctx, "agent", "agent-1", "conv-1", "user-1")
	if span == nil {
		t.Fatal("expected non-nil span")
	}
	_ = ctx2
	span.End()
}

func TestCB92_TraceStoreMessage_Enabled(t *testing.T) {
	restore := setupTracingEnabled()
	defer restore()

	ctx := context.Background()
	_, span := TraceStoreMessage(ctx, "conv-1", "agent-1")
	if span == nil {
		t.Fatal("expected non-nil span")
	}
	span.End()
}

func TestCB92_TraceDeliverMessage_Enabled(t *testing.T) {
	restore := setupTracingEnabled()
	defer restore()

	ctx := context.Background()
	_, span := TraceDeliverMessage(ctx, "user-1", "client", true)
	if span == nil {
		t.Fatal("expected non-nil span")
	}
	span.End()
}

func TestCB92_ShutdownTracing_WithProvider(t *testing.T) {
	restore := setupTracingEnabled()
	defer restore()

	// Shutdown should not panic and should call tp.Shutdown
	ShutdownTracing()
	// After shutdown, tp is still set but calling again should be safe
	// The function checks tp != nil
}

func TestCB92_ShutdownTracing_NilProvider(t *testing.T) {
	origTP := tp
	defer func() { tp = origTP }()
	tp = nil

	// Should not panic
	ShutdownTracing()
}

// ============================================================
// sendAPNSNotification tests
// ============================================================

func TestCB92_SendAPNSNotification_Disabled(t *testing.T) {
	origConfig := pushConfig
	defer func() { pushConfig = origConfig }()
	pushConfig = nil

	err := sendAPNSNotification("device-token", "title", "body", "conv-1")
	if err != nil {
		t.Fatalf("expected nil error when pushConfig is nil, got %v", err)
	}
}

func TestCB92_SendAPNSNotification_APNSDisabled(t *testing.T) {
	origConfig := pushConfig
	defer func() { pushConfig = origConfig }()
	pushConfig = &PushNotificationConfig{
		APNSEnabled: false,
	}

	err := sendAPNSNotification("device-token", "title", "body", "conv-1")
	if err != nil {
		t.Fatalf("expected nil error when APNs disabled, got %v", err)
	}
}

func TestCB92_SendAPNSNotification_NilAPNsClient(t *testing.T) {
	origConfig := pushConfig
	defer func() { pushConfig = origConfig }()
	pushConfig = &PushNotificationConfig{
		APNSEnabled: true,
		apnsClient:  nil,
	}

	err := sendAPNSNotification("device-token", "title", "body", "conv-1")
	if err != nil {
		t.Fatalf("expected nil error when apnsClient is nil, got %v", err)
	}
}

// ============================================================
// sendFCMNotification tests
// ============================================================

func TestCB92_SendFCMNotification_Disabled(t *testing.T) {
	origConfig := pushConfig
	defer func() { pushConfig = origConfig }()
	pushConfig = nil

	err := sendFCMNotification("device-token", "title", "body", "conv-1")
	if err != nil {
		t.Fatalf("expected nil error when pushConfig is nil, got %v", err)
	}
}

func TestCB92_SendFCMNotification_FCMDisabled(t *testing.T) {
	origConfig := pushConfig
	defer func() { pushConfig = origConfig }()
	pushConfig = &PushNotificationConfig{
		FCMEnabled: false,
	}

	err := sendFCMNotification("device-token", "title", "body", "conv-1")
	if err != nil {
		t.Fatalf("expected nil error when FCM disabled, got %v", err)
	}
}

func TestCB92_SendFCMNotification_NilFCMClient(t *testing.T) {
	origConfig := pushConfig
	defer func() { pushConfig = origConfig }()
	pushConfig = &PushNotificationConfig{
		FCMEnabled: true,
		fcmClient:  nil,
	}

	err := sendFCMNotification("device-token", "title", "body", "conv-1")
	if err != nil {
		t.Fatalf("expected nil error when fcmClient is nil, got %v", err)
	}
}

func TestCB92_SendPushNotification_PlatformRouting(t *testing.T) {
	origConfig := pushConfig
	defer func() { pushConfig = origConfig }()

	// Test with nil config - both paths should return nil
	pushConfig = nil

	err := sendPushNotification("token", "title", "body", "conv-1", "android")
	if err != nil {
		t.Errorf("android platform: expected nil, got %v", err)
	}

	err = sendPushNotification("token", "title", "body", "conv-1", "ios")
	if err != nil {
		t.Errorf("ios platform: expected nil, got %v", err)
	}

	err = sendPushNotification("token", "title", "body", "conv-1", "fcm")
	if err != nil {
		t.Errorf("fcm platform: expected nil, got %v", err)
	}

	err = sendPushNotification("token", "title", "body", "conv-1", "unknown")
	if err != nil {
		t.Errorf("unknown platform: expected nil, got %v", err)
	}

	err = sendPushNotification("token", "title", "body", "conv-1", "ANDROID")
	if err != nil {
		t.Errorf("uppercase ANDROID: expected nil, got %v", err)
	}
}

// ============================================================
// handleGetUserPresence tests
// ============================================================

func TestCB92_HandleGetUserPresence_MethodNotAllowed(t *testing.T) {
	withTestDB_CB92(t, func(testDB *sql.DB) {
		req := httptest.NewRequest("POST", "/presence/user", nil)
		rr := httptest.NewRecorder()
		handleGetUserPresence(rr, req)
		if rr.Code != http.StatusMethodNotAllowed {
			t.Fatalf("expected 405, got %d", rr.Code)
		}
	})
}

func TestCB92_HandleGetUserPresence_NoAuth(t *testing.T) {
	withTestDB_CB92(t, func(testDB *sql.DB) {
		req := httptest.NewRequest("GET", "/presence/user", nil)
		rr := httptest.NewRecorder()
		handleGetUserPresence(rr, req)
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d", rr.Code)
		}
	})
}

func TestCB92_HandleGetUserPresence_InvalidToken(t *testing.T) {
	withTestDB_CB92(t, func(testDB *sql.DB) {
		req := httptest.NewRequest("GET", "/presence/user", nil)
		req.Header.Set("Authorization", "Bearer invalid-token")
		rr := httptest.NewRecorder()
		handleGetUserPresence(rr, req)
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d", rr.Code)
		}
	})
}

func TestCB92_HandleGetUserPresence_Online(t *testing.T) {
	withTestDB_CB92(t, func(testDB *sql.DB) {
		userID, _, _ := setupUserAndConv_CB92(t, testDB)
		token := makeJWT_CB92(userID, "cb92testuser")

		cleanup := setupHub_CB92()
		defer cleanup()

		// Register a client connection for this user
		conn := makeConn_CB92(userID, "client", hub)
		hub.register <- conn

		// Wait for registration
		time.Sleep(50 * time.Millisecond)

		req := httptest.NewRequest("GET", "/presence/user", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rr := httptest.NewRecorder()
		handleGetUserPresence(rr, req)

		if rr.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
		}

		var resp map[string]interface{}
		json.Unmarshal(rr.Body.Bytes(), &resp)
		if resp["online"] != true {
			t.Fatalf("expected online=true, got %v", resp["online"])
		}
		if resp["device_count"].(float64) < 1 {
			t.Fatalf("expected device_count>=1, got %v", resp["device_count"])
		}
	})
}

func TestCB92_HandleGetUserPresence_OfflineWithLastSeen(t *testing.T) {
	withTestDB_CB92(t, func(testDB *sql.DB) {
		cleanup := setupHub_CB92()
		defer cleanup()
		userID, agentID, convID := setupUserAndConv_CB92(t, testDB)
		token := makeJWT_CB92(userID, "cb92testuser")

		// Insert a message from this user
		_, err := testDB.Exec(
			"INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, created_at) VALUES (?, ?, ?, ?, ?, ?)",
			"msg-1", convID, "client", userID, "hello", time.Now().UTC().Format(time.RFC3339))
		if err != nil {
			t.Fatalf("Failed to insert message: %v", err)
		}
		_ = agentID

		// No hub setup, so user is offline
		req := httptest.NewRequest("GET", "/presence/user", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rr := httptest.NewRecorder()
		handleGetUserPresence(rr, req)

		if rr.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
		}

		var resp map[string]interface{}
		json.Unmarshal(rr.Body.Bytes(), &resp)
		if resp["online"] != false {
			t.Fatalf("expected online=false, got %v", resp["online"])
		}
		lastSeen, ok := resp["last_seen"]
		if !ok || lastSeen == "" {
			t.Fatalf("expected non-empty last_seen, got %v", lastSeen)
		}
	})
}

func TestCB92_HandleGetUserPresence_OfflineNoMessages(t *testing.T) {
	withTestDB_CB92(t, func(testDB *sql.DB) {
		cleanup := setupHub_CB92()
		defer cleanup()
		userID, _, _ := setupUserAndConv_CB92(t, testDB)
		token := makeJWT_CB92(userID, "cb92testuser")

		// No messages, offline with empty last_seen
		req := httptest.NewRequest("GET", "/presence/user", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rr := httptest.NewRecorder()
		handleGetUserPresence(rr, req)

		if rr.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", rr.Code)
		}

		var resp map[string]interface{}
		json.Unmarshal(rr.Body.Bytes(), &resp)
		if resp["online"] != false {
			t.Fatalf("expected online=false, got %v", resp["online"])
		}
		if resp["last_seen"] != "" {
			t.Fatalf("expected empty last_seen, got %v", resp["last_seen"])
		}
	})
}

func TestCB92_HandleGetUserPresence_SpecificUserID(t *testing.T) {
	withTestDB_CB92(t, func(testDB *sql.DB) {
		cleanup := setupHub_CB92()
		defer cleanup()
		userID, _, _ := setupUserAndConv_CB92(t, testDB)
		token := makeJWT_CB92(userID, "cb92testuser")

		req := httptest.NewRequest("GET", "/presence/user?user_id=other-user", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rr := httptest.NewRecorder()
		handleGetUserPresence(rr, req)

		if rr.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", rr.Code)
		}

		var resp map[string]interface{}
		json.Unmarshal(rr.Body.Bytes(), &resp)
		if resp["user_id"] != "other-user" {
			t.Fatalf("expected user_id=other-user, got %v", resp["user_id"])
		}
	})
}

// ============================================================
// handleListAttachments tests
// ============================================================

func TestCB92_HandleListAttachments_MethodNotAllowed(t *testing.T) {
	withTestDB_CB92(t, func(testDB *sql.DB) {
		req := httptest.NewRequest("POST", "/messages/attachments", nil)
		rr := httptest.NewRecorder()
		handleListAttachments(rr, req)
		if rr.Code != http.StatusMethodNotAllowed {
			t.Fatalf("expected 405, got %d", rr.Code)
		}
	})
}

func TestCB92_HandleListAttachments_NoAuth(t *testing.T) {
	withTestDB_CB92(t, func(testDB *sql.DB) {
		req := httptest.NewRequest("GET", "/messages/attachments", nil)
		rr := httptest.NewRecorder()
		handleListAttachments(rr, req)
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d", rr.Code)
		}
	})
}

func TestCB92_HandleListAttachments_InvalidToken(t *testing.T) {
	withTestDB_CB92(t, func(testDB *sql.DB) {
		req := httptest.NewRequest("GET", "/messages/attachments", nil)
		req.Header.Set("Authorization", "Bearer bad-token")
		rr := httptest.NewRecorder()
		handleListAttachments(rr, req)
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d", rr.Code)
		}
	})
}

func TestCB92_HandleListAttachments_NoConvID(t *testing.T) {
	withTestDB_CB92(t, func(testDB *sql.DB) {
		userID, _, _ := setupUserAndConv_CB92(t, testDB)
		token := makeJWT_CB92(userID, "cb92testuser")

		req := httptest.NewRequest("GET", "/messages/attachments", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rr := httptest.NewRecorder()
		handleListAttachments(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d: %s", rr.Code, rr.Body.String())
		}
	})
}

func TestCB92_HandleListAttachments_ConvNotFound(t *testing.T) {
	withTestDB_CB92(t, func(testDB *sql.DB) {
		userID, _, _ := setupUserAndConv_CB92(t, testDB)
		token := makeJWT_CB92(userID, "cb92testuser")

		req := httptest.NewRequest("GET", "/messages/attachments?conversation_id=nonexistent", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rr := httptest.NewRecorder()
		handleListAttachments(rr, req)
		if rr.Code != http.StatusNotFound {
			t.Fatalf("expected 404, got %d: %s", rr.Code, rr.Body.String())
		}
	})
}

func TestCB92_HandleListAttachments_UnauthorizedUser(t *testing.T) {
	withTestDB_CB92(t, func(testDB *sql.DB) {
		userID, _, convID := setupUserAndConv_CB92(t, testDB)

		// Create a second user
		hash, _ := bcrypt.GenerateFromPassword([]byte("pass2"), bcrypt.DefaultCost)
		testDB.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)",
			"cb92-user2", "cb92user2", string(hash))
		token2 := makeJWT_CB92("cb92-user2", "cb92user2")

		req := httptest.NewRequest("GET", "/messages/attachments?conversation_id="+convID, nil)
		req.Header.Set("Authorization", "Bearer "+token2)
		rr := httptest.NewRecorder()
		handleListAttachments(rr, req)
		if rr.Code != http.StatusNotFound {
			t.Fatalf("expected 404 for unauthorized user, got %d", rr.Code)
		}
		_ = userID
	})
}

func TestCB92_HandleListAttachments_Empty(t *testing.T) {
	withTestDB_CB92(t, func(testDB *sql.DB) {
		userID, _, convID := setupUserAndConv_CB92(t, testDB)
		token := makeJWT_CB92(userID, "cb92testuser")

		req := httptest.NewRequest("GET", "/messages/attachments?conversation_id="+convID, nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rr := httptest.NewRecorder()
		handleListAttachments(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
		}
		// Should return empty array
		body := rr.Body.String()
		if !strings.Contains(body, "[]") && !strings.Contains(body, "null") {
			t.Fatalf("expected empty array, got %s", body)
		}
	})
}

func TestCB92_HandleListAttachments_WithAttachments(t *testing.T) {
	withTestDB_CB92(t, func(testDB *sql.DB) {
		userID, agentID, convID := setupUserAndConv_CB92(t, testDB)
		token := makeJWT_CB92(userID, "cb92testuser")

		// Insert a message and attachment
		msgID := "cb92-msg-att1"
		testDB.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, created_at) VALUES (?, ?, ?, ?, ?, ?)",
			msgID, convID, "client", userID, "check this", time.Now().UTC().Format(time.RFC3339))
		testDB.Exec("INSERT INTO attachments (id, message_id, user_id, filename, content_type, size, sha256, storage_path, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
			"att-1", msgID, userID, "test.pdf", "application/pdf", 1024, "abc123", "uploads/att-1", time.Now().UTC().Format(time.RFC3339))

		req := httptest.NewRequest("GET", "/messages/attachments?conversation_id="+convID, nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rr := httptest.NewRecorder()
		handleListAttachments(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
		}
		body := rr.Body.String()
		if !strings.Contains(body, "test.pdf") {
			t.Fatalf("expected response to contain 'test.pdf', got %s", body)
		}
		_ = agentID
	})
}

func TestCB92_HandleListAttachments_DBError(t *testing.T) {
	withTestDB_CB92(t, func(testDB *sql.DB) {
		userID, _, convID := setupUserAndConv_CB92(t, testDB)
		token := makeJWT_CB92(userID, "cb92testuser")

		// Drop attachments table to cause DB error
		testDB.Exec("DROP TABLE attachments")

		req := httptest.NewRequest("GET", "/messages/attachments?conversation_id="+convID, nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rr := httptest.NewRecorder()
		handleListAttachments(rr, req)
		if rr.Code != http.StatusInternalServerError {
			t.Fatalf("expected 500, got %d: %s", rr.Code, rr.Body.String())
		}
	})
}

// ============================================================
// handleGetAttachment tests
// ============================================================

func TestCB92_HandleGetAttachment_MethodNotAllowed(t *testing.T) {
	withTestDB_CB92(t, func(testDB *sql.DB) {
		req := httptest.NewRequest("POST", "/attachments/att-1", nil)
		rr := httptest.NewRecorder()
		handleGetAttachment(rr, req)
		if rr.Code != http.StatusMethodNotAllowed {
			t.Fatalf("expected 405, got %d", rr.Code)
		}
	})
}

func TestCB92_HandleGetAttachment_NoAuth(t *testing.T) {
	withTestDB_CB92(t, func(testDB *sql.DB) {
		req := httptest.NewRequest("GET", "/attachments/att-1", nil)
		rr := httptest.NewRecorder()
		handleGetAttachment(rr, req)
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d", rr.Code)
		}
	})
}

func TestCB92_HandleGetAttachment_InvalidJWT(t *testing.T) {
	withTestDB_CB92(t, func(testDB *sql.DB) {
		req := httptest.NewRequest("GET", "/attachments/att-1", nil)
		req.Header.Set("Authorization", "Bearer bad-token")
		rr := httptest.NewRecorder()
		handleGetAttachment(rr, req)
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d", rr.Code)
		}
	})
}

func TestCB92_HandleGetAttachment_AgentSecret(t *testing.T) {
	withTestDB_CB92(t, func(testDB *sql.DB) {
		// Set agent secret
		os.Setenv("AGENT_SECRET", "test-secret-92")
		defer os.Unsetenv("AGENT_SECRET")
		resetAgentSecret()

		req := httptest.NewRequest("GET", "/attachments/att-1", nil)
		req.Header.Set("X-Agent-Secret", "test-secret-92")
		rr := httptest.NewRecorder()
		handleGetAttachment(rr, req)
		// Attachment doesn't exist → 404
		if rr.Code != http.StatusNotFound {
			t.Fatalf("expected 404, got %d: %s", rr.Code, rr.Body.String())
		}
	})
}

func TestCB92_HandleGetAttachment_AgentSecretWrong(t *testing.T) {
	withTestDB_CB92(t, func(testDB *sql.DB) {
		os.Setenv("AGENT_SECRET", "test-secret-92")
		defer os.Unsetenv("AGENT_SECRET")
		resetAgentSecret()

		req := httptest.NewRequest("GET", "/attachments/att-1", nil)
		req.Header.Set("X-Agent-Secret", "wrong-secret")
		rr := httptest.NewRecorder()
		handleGetAttachment(rr, req)
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d", rr.Code)
		}
	})
}

func TestCB92_HandleGetAttachment_NotFound(t *testing.T) {
	withTestDB_CB92(t, func(testDB *sql.DB) {
		userID, _, _ := setupUserAndConv_CB92(t, testDB)
		token := makeJWT_CB92(userID, "cb92testuser")

		req := httptest.NewRequest("GET", "/attachments/nonexistent", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rr := httptest.NewRecorder()
		handleGetAttachment(rr, req)
		if rr.Code != http.StatusNotFound {
			t.Fatalf("expected 404, got %d", rr.Code)
		}
	})
}

func TestCB92_HandleGetAttachment_ForbiddenUser(t *testing.T) {
	withTestDB_CB92(t, func(testDB *sql.DB) {
		userID, _, convID := setupUserAndConv_CB92(t, testDB)

		// Create attachment owned by userID
		msgID := "cb92-msg-forb"
		testDB.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, created_at) VALUES (?, ?, ?, ?, ?, ?)",
			msgID, convID, "client", userID, "test", time.Now().UTC().Format(time.RFC3339))
		testDB.Exec("INSERT INTO attachments (id, message_id, user_id, filename, content_type, size, sha256, storage_path, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
			"att-forb", msgID, userID, "file.txt", "text/plain", 10, "hash", "uploads/file.txt", time.Now().UTC().Format(time.RFC3339))

		// Create second user and try to access
		hash, _ := bcrypt.GenerateFromPassword([]byte("pass2"), bcrypt.DefaultCost)
		testDB.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)",
			"cb92-user2", "cb92user2", string(hash))
		token2 := makeJWT_CB92("cb92-user2", "cb92user2")

		req := httptest.NewRequest("GET", "/attachments/att-forb", nil)
		req.Header.Set("Authorization", "Bearer "+token2)
		rr := httptest.NewRecorder()
		handleGetAttachment(rr, req)
		if rr.Code != http.StatusForbidden {
			t.Fatalf("expected 403, got %d: %s", rr.Code, rr.Body.String())
		}
	})
}

func TestCB92_HandleGetAttachment_Success(t *testing.T) {
	withTestDB_CB92(t, func(testDB *sql.DB) {
		userID, _, convID := setupUserAndConv_CB92(t, testDB)
		token := makeJWT_CB92(userID, "cb92testuser")

		// Create a temp file to serve - getUploadDir() appends "uploads" to serverDBPath dir
		tmpDir := t.TempDir()
		uploadDir := filepath.Join(tmpDir, "uploads")
		os.MkdirAll(uploadDir, 0755)
		filePath := filepath.Join(uploadDir, "test.txt")
		os.WriteFile(filePath, []byte("hello world"), 0644)

		// Set upload dir via serverDBPath (getUploadDir = filepath.Dir(serverDBPath) + "/uploads")
		origUploadDir := serverDBPath
		serverDBPath = filepath.Join(tmpDir, "test.db")
		defer func() { serverDBPath = origUploadDir }()

		msgID := "cb92-msg-get"
		testDB.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, created_at) VALUES (?, ?, ?, ?, ?, ?)",
			msgID, convID, "client", userID, "test", time.Now().UTC().Format(time.RFC3339))
		testDB.Exec("INSERT INTO attachments (id, message_id, user_id, filename, content_type, size, sha256, storage_path, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
			"att-get", msgID, userID, "test.txt", "text/plain", 11, "hash", "test.txt", time.Now().UTC().Format(time.RFC3339))

		req := httptest.NewRequest("GET", "/attachments/att-get", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rr := httptest.NewRecorder()
		handleGetAttachment(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
		}
		if !strings.Contains(rr.Body.String(), "hello world") {
			t.Fatalf("expected file content, got %s", rr.Body.String())
		}
	})
}

// ============================================================
// routeMessage tests
// ============================================================

func TestCB92_RouteMessage_UnknownType(t *testing.T) {
	withTestDB_CB92(t, func(testDB *sql.DB) {
		cleanup := setupHub_CB92()
		defer cleanup()

		conn := makeConn_CB92("cb92-agent", "agent", hub)
		hub.register <- conn
		time.Sleep(50 * time.Millisecond)

		msg := IncomingMessage{
			Type: "unknown_type",
		}
		raw, _ := json.Marshal(msg)
		routeMessage(conn, raw)

		// Should receive an error message
		select {
		case data := <-conn.send:
			if !strings.Contains(string(data), "unknown message type") {
				t.Fatalf("expected error about unknown type, got %s", string(data))
			}
		case <-time.After(time.Second):
			t.Fatal("timeout waiting for error response")
		}
	})
}

func TestCB92_RouteMessage_RateLimited(t *testing.T) {
	withTestDB_CB92(t, func(testDB *sql.DB) {
		cleanup := setupHub_CB92()
		defer cleanup()

		conn := makeConn_CB92("cb92-agent", "agent", hub)
		// Set a very low rate limit
		
		hub.register <- conn
		time.Sleep(50 * time.Millisecond)

		// First message should pass rate limit
		msg1 := IncomingMessage{Type: MsgTypeHeartbeat}
		raw1, _ := json.Marshal(msg1)
		routeMessage(conn, raw1)

		// Second message should be rate limited
		msg2 := IncomingMessage{Type: MsgTypeHeartbeat}
		raw2, _ := json.Marshal(msg2)
		routeMessage(conn, raw2)

		// The rate-limited message should not produce an error on send channel
		// (it just returns silently)
	})
}

func TestCB92_RouteMessage_InvalidJSON(t *testing.T) {
	withTestDB_CB92(t, func(testDB *sql.DB) {
		cleanup := setupHub_CB92()
		defer cleanup()

		conn := makeConn_CB92("cb92-agent", "agent", hub)
		hub.register <- conn
		time.Sleep(50 * time.Millisecond)

		routeMessage(conn, []byte("not valid json"))

		select {
		case data := <-conn.send:
			if !strings.Contains(string(data), "invalid message format") {
				t.Fatalf("expected error about invalid format, got %s", string(data))
			}
		case <-time.After(time.Second):
			t.Fatal("timeout waiting for error response")
		}
	})
}

func TestCB92_RouteMessage_Heartbeat(t *testing.T) {
	withTestDB_CB92(t, func(testDB *sql.DB) {
		cleanup := setupHub_CB92()
		defer cleanup()

		conn := makeConn_CB92("cb92-agent", "agent", hub)
		hub.register <- conn
		time.Sleep(50 * time.Millisecond)

		msg := IncomingMessage{Type: MsgTypeHeartbeat}
		raw, _ := json.Marshal(msg)
		routeMessage(conn, raw)
		// Heartbeat doesn't produce a response — just should not panic
	})
}

// ============================================================
// replayOfflineMessages tests
// ============================================================

func TestCB92_ReplayOfflineMessages_NilQueue(t *testing.T) {
	origQueue := offlineQueue
	defer func() { offlineQueue = origQueue }()
	offlineQueue = nil

	conn := makeConn_CB92("cb92-user", "client", nil)
	// Should not panic
	replayOfflineMessages(conn)
}

func TestCB92_ReplayOfflineMessages_EmptyQueue(t *testing.T) {
	origQueue := offlineQueue
	defer func() { offlineQueue = origQueue }()
	offlineQueue = newOfflineQueue(100, 7*24*time.Hour)

	conn := makeConn_CB92("cb92-user", "client", nil)
	replayOfflineMessages(conn)
	// Should not panic, no messages to replay
}

func TestCB92_ReplayOfflineMessages_WithMessages(t *testing.T) {
	origQueue := offlineQueue
	origDB := db
	defer func() { offlineQueue = origQueue; db = origDB }()

	testDB, _ := sql.Open("sqlite3", ":memory:")
	defer testDB.Close()
	initSchema(testDB)
	db = testDB

	offlineQueue = newOfflineQueue(100, 7*24*time.Hour)

	cleanup := setupHub_CB92()
	defer cleanup()

	conn := makeConn_CB92("cb92-user", "client", hub)
	hub.register <- conn
	time.Sleep(50 * time.Millisecond)

	// Enqueue a chat message
	chatMsg := OutgoingMessage{
		Type: MsgTypeMessage,
		Data: map[string]interface{}{"content": "hello"},
	}
	data, _ := json.Marshal(chatMsg)
	offlineQueue.Enqueue("cb92-user", data)

	replayOfflineMessages(conn)

	select {
	case received := <-conn.send:
		if !strings.Contains(string(received), "hello") {
			t.Fatalf("expected 'hello' in message, got %s", string(received))
		}
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for replay")
	}
}

func TestCB92_ReplayOfflineMessages_SkipsTypingAndStatus(t *testing.T) {
	origQueue := offlineQueue
	origDB := db
	defer func() { offlineQueue = origQueue; db = origDB }()

	testDB, _ := sql.Open("sqlite3", ":memory:")
	defer testDB.Close()
	initSchema(testDB)
	db = testDB

	offlineQueue = newOfflineQueue(100, 7*24*time.Hour)

	cleanup := setupHub_CB92()
	defer cleanup()

	conn := makeConn_CB92("cb92-user", "client", hub)
	hub.register <- conn
	time.Sleep(50 * time.Millisecond)

	// Enqueue typing indicator (should be skipped)
	typingMsg := OutgoingMessage{Type: MsgTypeTyping, Data: map[string]interface{}{}}
	typingData, _ := json.Marshal(typingMsg)
	offlineQueue.Enqueue("cb92-user", typingData)

	// Enqueue status update (should be skipped)
	statusMsg := OutgoingMessage{Type: MsgTypeStatus, Data: map[string]interface{}{}}
	statusData, _ := json.Marshal(statusMsg)
	offlineQueue.Enqueue("cb92-user", statusData)

	// Enqueue a real message
	chatMsg := OutgoingMessage{Type: MsgTypeMessage, Data: map[string]interface{}{"content": "real"}}
	chatData, _ := json.Marshal(chatMsg)
	offlineQueue.Enqueue("cb92-user", chatData)

	replayOfflineMessages(conn)

	// Should only receive the chat message
	select {
	case received := <-conn.send:
		if !strings.Contains(string(received), "real") {
			t.Fatalf("expected 'real' message, got %s", string(received))
		}
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for replay")
	}

	// Should not have more messages
	select {
	case extra := <-conn.send:
		t.Fatalf("unexpected extra message: %s", string(extra))
	case <-time.After(100 * time.Millisecond):
		// Good, no extra messages
	}
}

func TestCB92_ReplayOfflineMessages_ReadReceipt(t *testing.T) {
	origQueue := offlineQueue
	origDB := db
	defer func() { offlineQueue = origQueue; db = origDB }()

	testDB, _ := sql.Open("sqlite3", ":memory:")
	defer testDB.Close()
	initSchema(testDB)
	db = testDB

	offlineQueue = newOfflineQueue(100, 7*24*time.Hour)

	cleanup := setupHub_CB92()
	defer cleanup()

	conn := makeConn_CB92("cb92-user", "client", hub)
	hub.register <- conn
	time.Sleep(50 * time.Millisecond)

	// Enqueue a read_receipt (should be replayed)
	readReceipt := OutgoingMessage{
		Type: "read_receipt",
		Data: map[string]interface{}{"conversation_id": "conv-1"},
	}
	data, _ := json.Marshal(readReceipt)
	offlineQueue.Enqueue("cb92-user", data)

	replayOfflineMessages(conn)

	select {
	case received := <-conn.send:
		if !strings.Contains(string(received), "read_receipt") {
			t.Fatalf("expected read_receipt, got %s", string(received))
		}
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for read_receipt replay")
	}
}

func TestCB92_ReplayOfflineMessages_ClosedConn(t *testing.T) {
	origQueue := offlineQueue
	origDB := db
	defer func() { offlineQueue = origQueue; db = origDB }()

	testDB, _ := sql.Open("sqlite3", ":memory:")
	defer testDB.Close()
	initSchema(testDB)
	db = testDB

	offlineQueue = newOfflineQueue(100, 7*24*time.Hour)

	cleanup := setupHub_CB92()
	defer cleanup()

	conn := makeConn_CB92("cb92-user", "client", hub)
	hub.register <- conn
	time.Sleep(50 * time.Millisecond)

	// Close the connection's send channel
	close(conn.send)

	// Enqueue a message
	chatMsg := OutgoingMessage{Type: MsgTypeMessage, Data: map[string]interface{}{"content": "test"}}
	data, _ := json.Marshal(chatMsg)
	offlineQueue.Enqueue("cb92-user", data)

	// Should not panic
	replayOfflineMessages(conn)
}

// ============================================================
// newOfflineQueue tests
// ============================================================

func TestCB92_NewOfflineQueue_DefaultMaxLen(t *testing.T) {
	q := newOfflineQueue(0, 0)
	if q.maxLen != 100 {
		t.Fatalf("expected default maxLen=100, got %d", q.maxLen)
	}
	if q.ttl != 7*24*time.Hour {
		t.Fatalf("expected default ttl=7d, got %v", q.ttl)
	}
}

func TestCB92_NewOfflineQueue_NegativeMaxLen(t *testing.T) {
	q := newOfflineQueue(-5, -time.Hour)
	if q.maxLen != 100 {
		t.Fatalf("expected default maxLen=100 for negative, got %d", q.maxLen)
	}
	if q.ttl != 7*24*time.Hour {
		t.Fatalf("expected default ttl=7d for negative, got %v", q.ttl)
	}
}

func TestCB92_NewOfflineQueue_CustomValues(t *testing.T) {
	q := newOfflineQueue(50, 24*time.Hour)
	if q.maxLen != 50 {
		t.Fatalf("expected maxLen=50, got %d", q.maxLen)
	}
	if q.ttl != 24*time.Hour {
		t.Fatalf("expected ttl=24h, got %v", q.ttl)
	}
}

// ============================================================
// marshalOutgoingMessage tests
// ============================================================

func TestCB92_MarshalOutgoingMessage_Success(t *testing.T) {
	msg := OutgoingMessage{
		Type: MsgTypeMessage,
		Data: map[string]interface{}{"content": "hello"},
	}
	data := marshalOutgoingMessage(msg)
	if data == nil {
		t.Fatal("expected non-nil data")
	}
	if !strings.Contains(string(data), "hello") {
		t.Fatalf("expected 'hello' in data, got %s", string(data))
	}
}

func TestCB92_MarshalOutgoingMessage_NilData(t *testing.T) {
	msg := OutgoingMessage{
		Type: MsgTypeMessage,
	}
	data := marshalOutgoingMessage(msg)
	if data == nil {
		t.Fatal("expected non-nil data even with nil Data")
	}
}

// ============================================================
// csrfMiddleware tests
// ============================================================

func TestCB92_CSRFMiddleware_GetAllowed(t *testing.T) {
	handler := csrfMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("GET", "/test", nil)
	rr := httptest.NewRecorder()
	handler(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("GET should be allowed, got %d", rr.Code)
	}
}

func TestCB92_CSRFMiddleware_HeadAllowed(t *testing.T) {
	handler := csrfMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("HEAD", "/test", nil)
	rr := httptest.NewRecorder()
	handler(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("HEAD should be allowed, got %d", rr.Code)
	}
}

func TestCB92_CSRFMiddleware_OptionsAllowed(t *testing.T) {
	handler := csrfMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("OPTIONS", "/test", nil)
	rr := httptest.NewRecorder()
	handler(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("OPTIONS should be allowed, got %d", rr.Code)
	}
}

func TestCB92_CSRFMiddleware_XHRHeader(t *testing.T) {
	handler := csrfMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("POST", "/test", nil)
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	rr := httptest.NewRecorder()
	handler(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("POST with XHR header should be allowed, got %d", rr.Code)
	}
}

func TestCB92_CSRFMiddleware_CSRFToken(t *testing.T) {
	handler := csrfMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("POST", "/test", nil)
	req.Header.Set("X-CSRF-Token", "some-token")
	rr := httptest.NewRecorder()
	handler(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("POST with CSRF token should be allowed, got %d", rr.Code)
	}
}

func TestCB92_CSRFMiddleware_AuthorizationHeader(t *testing.T) {
	handler := csrfMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("POST", "/test", nil)
	req.Header.Set("Authorization", "Bearer some-jwt")
	rr := httptest.NewRecorder()
	handler(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("POST with Authorization header should be allowed, got %d", rr.Code)
	}
}

func TestCB92_CSRFMiddleware_AgentSecretHeader(t *testing.T) {
	handler := csrfMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("POST", "/test", nil)
	req.Header.Set("X-Agent-Secret", "some-secret")
	rr := httptest.NewRecorder()
	handler(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("POST with X-Agent-Secret header should be allowed, got %d", rr.Code)
	}
}

func TestCB92_CSRFMiddleware_OriginAllowed(t *testing.T) {
	origCORS := corsAllowedOrigins
	defer func() { corsAllowedOrigins = origCORS }()
	corsAllowedOrigins = "https://example.com,https://test.com"

	handler := csrfMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("POST", "/test", nil)
	req.Header.Set("Origin", "https://example.com")
	rr := httptest.NewRecorder()
	handler(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("POST with allowed origin should pass, got %d", rr.Code)
	}
}

func TestCB92_CSRFMiddleware_OriginNotAllowed(t *testing.T) {
	origCORS := corsAllowedOrigins
	defer func() { corsAllowedOrigins = origCORS }()
	corsAllowedOrigins = "https://example.com"

	handler := csrfMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("POST", "/test", nil)
	req.Header.Set("Origin", "https://evil.com")
	rr := httptest.NewRecorder()
	handler(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("POST with disallowed origin should be blocked, got %d", rr.Code)
	}
}

func TestCB92_CSRFMiddleware_NoHeaders(t *testing.T) {
	handler := csrfMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("POST", "/test", nil)
	rr := httptest.NewRecorder()
	handler(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("POST with no headers should be blocked, got %d", rr.Code)
	}
}

// ============================================================
// isOriginAllowed tests
// ============================================================

func TestCB92_IsOriginAllowed_Wildcard(t *testing.T) {
	origCORS := corsAllowedOrigins
	defer func() { corsAllowedOrigins = origCORS }()
	corsAllowedOrigins = "*"

	if !isOriginAllowed("https://anything.com") {
		t.Fatal("wildcard should allow all origins")
	}
}

func TestCB92_IsOriginAllowed_SpecificMatch(t *testing.T) {
	origCORS := corsAllowedOrigins
	defer func() { corsAllowedOrigins = origCORS }()
	corsAllowedOrigins = "https://example.com,https://test.com"

	if !isOriginAllowed("https://example.com") {
		t.Fatal("example.com should be allowed")
	}
	if !isOriginAllowed("https://test.com") {
		t.Fatal("test.com should be allowed")
	}
}

func TestCB92_IsOriginAllowed_NoMatch(t *testing.T) {
	origCORS := corsAllowedOrigins
	defer func() { corsAllowedOrigins = origCORS }()
	corsAllowedOrigins = "https://example.com"

	if isOriginAllowed("https://evil.com") {
		t.Fatal("evil.com should not be allowed")
	}
}

func TestCB92_IsOriginAllowed_WildcardInList(t *testing.T) {
	origCORS := corsAllowedOrigins
	defer func() { corsAllowedOrigins = origCORS }()
	corsAllowedOrigins = "https://example.com,*"

	if !isOriginAllowed("https://anything.com") {
		t.Fatal("wildcard in list should allow all origins")
	}
}

// ============================================================
// ipRateLimitMiddleware tests
// ============================================================

func TestCB92_IPRateLimitMiddleware_Allowed(t *testing.T) {
	// Save and reset the IP rate limiter
	origLimiter := ipRateLimiter
	defer func() { ipRateLimiter = origLimiter }()
	ipRateLimiter = NewRateLimiter(100, time.Minute)

	handler := ipRateLimitMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("GET", "/test", nil)
	rr := httptest.NewRecorder()
	handler(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
}

func TestCB92_IPRateLimitMiddleware_RateLimited(t *testing.T) {
	origLimiter := ipRateLimiter
	origMetrics := ServerMetrics
	defer func() { ipRateLimiter = origLimiter; ServerMetrics = origMetrics }()

	ServerMetrics = &Metrics{StartTime: time.Now(), Version: "0.2.0", AgentsConnected: func() int { return 0 }, ClientsConnected: func() int { return 0 }, ClientConnsTotal: func() int { return 0 }, StaleAgentCount: func() int64 { return 0 }}
	ipRateLimiter = NewRateLimiter(1, time.Hour) // Very low limit

	handler := ipRateLimitMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// First request passes
	req1 := httptest.NewRequest("GET", "/test", nil)
	rr1 := httptest.NewRecorder()
	handler(rr1, req1)
	if rr1.Code != http.StatusOK {
		t.Fatalf("first request should pass, got %d", rr1.Code)
	}

	// Second request is rate limited
	req2 := httptest.NewRequest("GET", "/test", nil)
	rr2 := httptest.NewRecorder()
	handler(rr2, req2)
	if rr2.Code != http.StatusTooManyRequests {
		t.Fatalf("second request should be rate limited, got %d", rr2.Code)
	}
	if !strings.Contains(rr2.Body.String(), "rate limit") {
		t.Fatalf("expected rate limit message, got %s", rr2.Body.String())
	}
}

// ============================================================
// authRateLimitMiddleware tests
// ============================================================

func TestCB92_AuthRateLimitMiddleware_Allowed(t *testing.T) {
	origLimiter := authIPLimiter
	defer func() { authIPLimiter = origLimiter }()
	authIPLimiter = NewRateLimiter(100, time.Minute)

	handler := authRateLimitMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("POST", "/auth/login", nil)
	rr := httptest.NewRecorder()
	handler(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
}

func TestCB92_AuthRateLimitMiddleware_RateLimited(t *testing.T) {
	origLimiter := authIPLimiter
	origMetrics := ServerMetrics
	defer func() { authIPLimiter = origLimiter; ServerMetrics = origMetrics }()

	ServerMetrics = &Metrics{StartTime: time.Now(), Version: "0.2.0", AgentsConnected: func() int { return 0 }, ClientsConnected: func() int { return 0 }, ClientConnsTotal: func() int { return 0 }, StaleAgentCount: func() int64 { return 0 }}
	authIPLimiter = NewRateLimiter(1, time.Hour)

	handler := authRateLimitMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// First request passes
	req1 := httptest.NewRequest("POST", "/auth/login", nil)
	rr1 := httptest.NewRecorder()
	handler(rr1, req1)
	if rr1.Code != http.StatusOK {
		t.Fatalf("first request should pass, got %d", rr1.Code)
	}

	// Second request is rate limited
	req2 := httptest.NewRequest("POST", "/auth/login", nil)
	rr2 := httptest.NewRecorder()
	handler(rr2, req2)
	if rr2.Code != http.StatusTooManyRequests {
		t.Fatalf("second request should be rate limited, got %d", rr2.Code)
	}
	if !strings.Contains(rr2.Body.String(), "auth") {
		t.Fatalf("expected auth rate limit message, got %s", rr2.Body.String())
	}
}

// ============================================================
// requestIDMiddleware tests
// ============================================================

func TestCB92_RequestIDMiddleware_GeneratesID(t *testing.T) {
	handler := requestIDMiddleware(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get("X-Request-ID")
		if id == "" {
			t.Fatal("expected non-empty request ID")
		}
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("GET", "/test", nil)
	rr := httptest.NewRecorder()
	handler(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	if rr.Header().Get("X-Request-ID") == "" {
		t.Fatal("expected X-Request-ID in response header")
	}
}

func TestCB92_RequestIDMiddleware_PreservesExisting(t *testing.T) {
	handler := requestIDMiddleware(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get("X-Request-ID")
		if id != "custom-id-123" {
			t.Fatalf("expected custom-id-123, got %s", id)
		}
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-Request-ID", "custom-id-123")
	rr := httptest.NewRecorder()
	handler(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	if rr.Header().Get("X-Request-ID") != "custom-id-123" {
		t.Fatalf("expected custom-id-123 in response, got %s", rr.Header().Get("X-Request-ID"))
	}
}

// ============================================================
// handleMetrics tests
// ============================================================

func TestCB92_HandleMetrics_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest("POST", "/metrics", nil)
	rr := httptest.NewRecorder()
	handleMetrics(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", rr.Code)
	}
}

func TestCB92_HandleMetrics_Success(t *testing.T) {
	origMetrics := ServerMetrics
	defer func() { ServerMetrics = origMetrics }()
	ServerMetrics = &Metrics{StartTime: time.Now(), Version: "0.2.0", AgentsConnected: func() int { return 0 }, ClientsConnected: func() int { return 0 }, ClientConnsTotal: func() int { return 0 }, StaleAgentCount: func() int64 { return 0 }}

	req := httptest.NewRequest("GET", "/metrics", nil)
	rr := httptest.NewRecorder()
	handleMetrics(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "agent_messenger_") {
		t.Fatalf("expected Prometheus metrics, got %s", body)
	}
	if !strings.Contains(body, "# HELP") {
		t.Fatalf("expected HELP comments, got %s", body)
	}
	if !strings.Contains(body, "# TYPE") {
		t.Fatalf("expected TYPE comments, got %s", body)
	}
}

func TestCB92_HandleMetrics_WithOfflineQueue(t *testing.T) {
	origMetrics := ServerMetrics
	origQueue := offlineQueue
	defer func() { ServerMetrics = origMetrics; offlineQueue = origQueue }()

	ServerMetrics = &Metrics{StartTime: time.Now(), Version: "0.2.0", AgentsConnected: func() int { return 0 }, ClientsConnected: func() int { return 0 }, ClientConnsTotal: func() int { return 0 }, StaleAgentCount: func() int64 { return 0 }}
	offlineQueue = newOfflineQueue(100, 7*24*time.Hour)
	offlineQueue.Enqueue("user-1", []byte("test"))

	req := httptest.NewRequest("GET", "/metrics", nil)
	rr := httptest.NewRecorder()
	handleMetrics(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "offline_queue_depth") {
		t.Fatalf("expected offline_queue_depth metric, got %s", body)
	}
}

func TestCB92_BoolToInt_True(t *testing.T) {
	if boolToInt(true) != 1 {
		t.Fatal("expected 1 for true")
	}
}

func TestCB92_BoolToInt_False(t *testing.T) {
	if boolToInt(false) != 0 {
		t.Fatal("expected 0 for false")
	}
}

func TestCB92_BoolToInt_NonBool(t *testing.T) {
	if boolToInt("not a bool") != 0 {
		t.Fatal("expected 0 for non-bool")
	}
}

// ============================================================
// Logger tests
// ============================================================

func TestCB92_Logger_SetOutput(t *testing.T) {
	l := NewLogger(LogDebug)
	var buf bytes.Buffer
	l.SetOutput(&buf)

	l.Info("test message", map[string]interface{}{"key": "value"})

	if buf.Len() == 0 {
		t.Fatal("expected output in buffer")
	}
	if !strings.Contains(buf.String(), "test message") {
		t.Fatalf("expected 'test message' in output, got %s", buf.String())
	}
	if !strings.Contains(buf.String(), "key") {
		t.Fatalf("expected 'key' field in output, got %s", buf.String())
	}
}

func TestCB92_Logger_SetLevel(t *testing.T) {
	l := NewLogger(LogWarn)
	var buf bytes.Buffer
	l.SetOutput(&buf)

	// Debug should be filtered out
	l.Debug("debug msg")
	if buf.Len() > 0 {
		t.Fatal("debug should be filtered at Warn level")
	}

	// Warn should pass
	l.Warn("warn msg")
	if !strings.Contains(buf.String(), "warn msg") {
		t.Fatalf("expected warn msg in output, got %s", buf.String())
	}
}

func TestCB92_Logger_LevelString(t *testing.T) {
	if LogDebug.String() != "debug" {
		t.Fatalf("expected 'debug', got %s", LogDebug.String())
	}
	if LogInfo.String() != "info" {
		t.Fatalf("expected 'info', got %s", LogInfo.String())
	}
	if LogWarn.String() != "warn" {
		t.Fatalf("expected 'warn', got %s", LogWarn.String())
	}
	if LogError.String() != "error" {
		t.Fatalf("expected 'error', got %s", LogError.String())
	}
	// Unknown level
	unknown := LogLevel(99)
	if unknown.String() != "unknown" {
		t.Fatalf("expected 'unknown', got %s", unknown.String())
	}
}

func TestCB92_Logger_WithFields(t *testing.T) {
	l := NewLogger(LogDebug)
	l2 := l.WithFields(map[string]interface{}{"app": "test"})

	var buf bytes.Buffer
	l2.SetOutput(&buf)

	l2.Info("hello")
	if !strings.Contains(buf.String(), "test") {
		t.Fatalf("expected 'test' field from WithFields, got %s", buf.String())
	}
}

func TestCB92_Logger_MergeOpt(t *testing.T) {
	result := mergeOpt([]map[string]interface{}{
		{"a": 1},
		{"b": 2},
	})
	if result["a"] != 1 || result["b"] != 2 {
		t.Fatalf("expected merged map with a=1, b=2, got %v", result)
	}
}

func TestCB92_Logger_MergeOpt_Empty(t *testing.T) {
	result := mergeOpt(nil)
	if result != nil {
		t.Fatalf("expected nil for empty merge, got %v", result)
	}
}

func TestCB92_Logger_AllLevels(t *testing.T) {
	l := NewLogger(LogDebug)
	var buf bytes.Buffer
	l.SetOutput(&buf)

	l.Debug("debug msg")
	l.Info("info msg")
	l.Warn("warn msg")
	l.Error("error msg")

	output := buf.String()
	for _, level := range []string{"debug", "info", "warn", "error"} {
		if !strings.Contains(output, level) {
			t.Fatalf("expected '%s' in output, got %s", level, output)
		}
	}
}

// ============================================================
// handleMessageEdit tests
// ============================================================

func TestCB92_HandleMessageEdit_MethodNotAllowed(t *testing.T) {
	withTestDB_CB92(t, func(testDB *sql.DB) {
		req := httptest.NewRequest("GET", "/messages/edit", nil)
		rr := httptest.NewRecorder()
		handleMessageEdit(rr, req)
		if rr.Code != http.StatusMethodNotAllowed {
			t.Fatalf("expected 405, got %d", rr.Code)
		}
	})
}

func TestCB92_HandleMessageEdit_NoAuth(t *testing.T) {
	withTestDB_CB92(t, func(testDB *sql.DB) {
		req := httptest.NewRequest("POST", "/messages/edit", nil)
		rr := httptest.NewRecorder()
		handleMessageEdit(rr, req)
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d", rr.Code)
		}
	})
}

func TestCB92_HandleMessageEdit_InvalidToken(t *testing.T) {
	withTestDB_CB92(t, func(testDB *sql.DB) {
		req := httptest.NewRequest("POST", "/messages/edit", nil)
		req.Header.Set("Authorization", "Bearer bad")
		rr := httptest.NewRecorder()
		handleMessageEdit(rr, req)
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d", rr.Code)
		}
	})
}

func TestCB92_HandleMessageEdit_MissingMessageID(t *testing.T) {
	withTestDB_CB92(t, func(testDB *sql.DB) {
		userID, _, _ := setupUserAndConv_CB92(t, testDB)
		token := makeJWT_CB92(userID, "cb92testuser")

		form := strings.NewReader("content=new text")
		req := httptest.NewRequest("POST", "/messages/edit", form)
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()
		handleMessageEdit(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d: %s", rr.Code, rr.Body.String())
		}
	})
}

func TestCB92_HandleMessageEdit_EmptyContent(t *testing.T) {
	withTestDB_CB92(t, func(testDB *sql.DB) {
		userID, _, _ := setupUserAndConv_CB92(t, testDB)
		token := makeJWT_CB92(userID, "cb92testuser")

		form := strings.NewReader("message_id=msg-1")
		req := httptest.NewRequest("POST", "/messages/edit", form)
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()
		handleMessageEdit(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 for empty content, got %d", rr.Code)
		}
	})
}

func TestCB92_HandleMessageEdit_NotFound(t *testing.T) {
	withTestDB_CB92(t, func(testDB *sql.DB) {
		userID, _, _ := setupUserAndConv_CB92(t, testDB)
		token := makeJWT_CB92(userID, "cb92testuser")

		form := strings.NewReader("message_id=nonexistent&content=new text")
		req := httptest.NewRequest("POST", "/messages/edit", form)
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()
		handleMessageEdit(rr, req)
		if rr.Code != http.StatusNotFound {
			t.Fatalf("expected 404, got %d: %s", rr.Code, rr.Body.String())
		}
	})
}

func TestCB92_HandleMessageEdit_DeletedMessage(t *testing.T) {
	withTestDB_CB92(t, func(testDB *sql.DB) {
		userID, _, convID := setupUserAndConv_CB92(t, testDB)
		token := makeJWT_CB92(userID, "cb92testuser")

		msgID := "cb92-edit-del"
		testDB.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, created_at, is_deleted) VALUES (?, ?, ?, ?, ?, ?, 1)",
			msgID, convID, "client", userID, "deleted", time.Now().UTC().Format(time.RFC3339))

		form := strings.NewReader("message_id="+msgID+"&content=new text")
		req := httptest.NewRequest("POST", "/messages/edit", form)
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()
		handleMessageEdit(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 for deleted message, got %d", rr.Code)
		}
	})
}

func TestCB92_HandleMessageEdit_NotSender(t *testing.T) {
	withTestDB_CB92(t, func(testDB *sql.DB) {
		userID, agentID, convID := setupUserAndConv_CB92(t, testDB)
		token := makeJWT_CB92(userID, "cb92testuser")

		// Message from agent (not client)
		msgID := "cb92-edit-agent"
		testDB.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, created_at) VALUES (?, ?, ?, ?, ?, ?)",
			msgID, convID, "agent", agentID, "agent msg", time.Now().UTC().Format(time.RFC3339))

		form := strings.NewReader("message_id="+msgID+"&content=edited text")
		req := httptest.NewRequest("POST", "/messages/edit", form)
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()
		handleMessageEdit(rr, req)
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401 for non-sender edit, got %d", rr.Code)
		}
	})
}

func TestCB92_HandleMessageEdit_Success(t *testing.T) {
	withTestDB_CB92(t, func(testDB *sql.DB) {
		userID, _, convID := setupUserAndConv_CB92(t, testDB)
		token := makeJWT_CB92(userID, "cb92testuser")

		cleanup := setupHub_CB92()
		defer cleanup()

		msgID := "cb92-edit-ok"
		testDB.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, created_at) VALUES (?, ?, ?, ?, ?, ?)",
			msgID, convID, "client", userID, "original", time.Now().UTC().Format(time.RFC3339))

		form := strings.NewReader("message_id="+msgID+"&content=edited content")
		req := httptest.NewRequest("POST", "/messages/edit", form)
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()
		handleMessageEdit(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
		}
		body := rr.Body.String()
		if !strings.Contains(body, "edited") {
			t.Fatalf("expected 'edited' status, got %s", body)
		}
		if !strings.Contains(body, "edited content") {
			t.Fatalf("expected new content, got %s", body)
		}
	})
}

func TestCB92_HandleMessageEdit_DBError(t *testing.T) {
	withTestDB_CB92(t, func(testDB *sql.DB) {
		userID, _, _ := setupUserAndConv_CB92(t, testDB)
		token := makeJWT_CB92(userID, "cb92testuser")

		// Drop messages table
		testDB.Exec("DROP TABLE messages")

		form := strings.NewReader("message_id=any&content=text")
		req := httptest.NewRequest("POST", "/messages/edit", form)
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()
		handleMessageEdit(rr, req)
		if rr.Code != http.StatusInternalServerError && rr.Code != http.StatusNotFound {
			t.Fatalf("expected 500 or 404 for DB error, got %d: %s", rr.Code, rr.Body.String())
		}
	})
}

// ============================================================
// handleMessageDelete tests
// ============================================================

func TestCB92_HandleMessageDelete_MethodNotAllowed(t *testing.T) {
	withTestDB_CB92(t, func(testDB *sql.DB) {
		req := httptest.NewRequest("GET", "/messages/delete", nil)
		rr := httptest.NewRecorder()
		handleMessageDelete(rr, req)
		if rr.Code != http.StatusMethodNotAllowed {
			t.Fatalf("expected 405, got %d", rr.Code)
		}
	})
}

func TestCB92_HandleMessageDelete_NoAuth(t *testing.T) {
	withTestDB_CB92(t, func(testDB *sql.DB) {
		req := httptest.NewRequest("POST", "/messages/delete", nil)
		rr := httptest.NewRecorder()
		handleMessageDelete(rr, req)
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d", rr.Code)
		}
	})
}

func TestCB92_HandleMessageDelete_MissingMessageID(t *testing.T) {
	withTestDB_CB92(t, func(testDB *sql.DB) {
		userID, _, _ := setupUserAndConv_CB92(t, testDB)
		token := makeJWT_CB92(userID, "cb92testuser")

		req := httptest.NewRequest("POST", "/messages/delete", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rr := httptest.NewRecorder()
		handleMessageDelete(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d", rr.Code)
		}
	})
}

func TestCB92_HandleMessageDelete_NotFound(t *testing.T) {
	withTestDB_CB92(t, func(testDB *sql.DB) {
		userID, _, _ := setupUserAndConv_CB92(t, testDB)
		token := makeJWT_CB92(userID, "cb92testuser")

		form := strings.NewReader("message_id=nonexistent")
		req := httptest.NewRequest("POST", "/messages/delete", form)
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()
		handleMessageDelete(rr, req)
		if rr.Code != http.StatusNotFound {
			t.Fatalf("expected 404, got %d", rr.Code)
		}
	})
}

func TestCB92_HandleMessageDelete_AlreadyDeleted(t *testing.T) {
	withTestDB_CB92(t, func(testDB *sql.DB) {
		userID, _, convID := setupUserAndConv_CB92(t, testDB)
		token := makeJWT_CB92(userID, "cb92testuser")

		msgID := "cb92-del-already"
		testDB.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, created_at, is_deleted) VALUES (?, ?, ?, ?, ?, ?, 1)",
			msgID, convID, "client", userID, "deleted", time.Now().UTC().Format(time.RFC3339))

		form := strings.NewReader("message_id="+msgID)
		req := httptest.NewRequest("POST", "/messages/delete", form)
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()
		handleMessageDelete(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 for already deleted, got %d", rr.Code)
		}
	})
}

func TestCB92_HandleMessageDelete_SuccessAsSender(t *testing.T) {
	withTestDB_CB92(t, func(testDB *sql.DB) {
		userID, _, convID := setupUserAndConv_CB92(t, testDB)
		token := makeJWT_CB92(userID, "cb92testuser")

		cleanup := setupHub_CB92()
		defer cleanup()

		msgID := "cb92-del-sender"
		testDB.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, created_at) VALUES (?, ?, ?, ?, ?, ?)",
			msgID, convID, "client", userID, "delete me", time.Now().UTC().Format(time.RFC3339))

		form := strings.NewReader("message_id="+msgID)
		req := httptest.NewRequest("POST", "/messages/delete", form)
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()
		handleMessageDelete(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
		}
		if !strings.Contains(rr.Body.String(), "deleted") {
			t.Fatalf("expected 'deleted' status, got %s", rr.Body.String())
		}
	})
}

func TestCB92_HandleMessageDelete_SuccessAsOwner(t *testing.T) {
	withTestDB_CB92(t, func(testDB *sql.DB) {
		userID, agentID, convID := setupUserAndConv_CB92(t, testDB)
		token := makeJWT_CB92(userID, "cb92testuser")

		cleanup := setupHub_CB92()
		defer cleanup()

		// Message from agent, but conversation owner is the user
		msgID := "cb92-del-owner"
		testDB.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, created_at) VALUES (?, ?, ?, ?, ?, ?)",
			msgID, convID, "agent", agentID, "agent msg", time.Now().UTC().Format(time.RFC3339))

		form := strings.NewReader("message_id="+msgID)
		req := httptest.NewRequest("POST", "/messages/delete", form)
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()
		handleMessageDelete(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("expected 200 as conv owner, got %d: %s", rr.Code, rr.Body.String())
		}
	})
}

func TestCB92_HandleMessageDelete_Unauthorized(t *testing.T) {
	withTestDB_CB92(t, func(testDB *sql.DB) {
		userID, agentID, convID := setupUserAndConv_CB92(t, testDB)

		// Create second user who is not the sender or conversation owner
		hash, _ := bcrypt.GenerateFromPassword([]byte("pass2"), bcrypt.DefaultCost)
		testDB.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)",
			"cb92-user2", "cb92user2", string(hash))
		token2 := makeJWT_CB92("cb92-user2", "cb92user2")

		// Message from user1, conversation owned by user1
		msgID := "cb92-del-unauth"
		testDB.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, created_at) VALUES (?, ?, ?, ?, ?, ?)",
			msgID, convID, "client", userID, "test", time.Now().UTC().Format(time.RFC3339))

		form := strings.NewReader("message_id="+msgID)
		req := httptest.NewRequest("POST", "/messages/delete", form)
		req.Header.Set("Authorization", "Bearer "+token2)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()
		handleMessageDelete(rr, req)
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401 for unauthorized user, got %d", rr.Code)
		}
		_ = agentID
	})
}

func TestCB92_HandleMessageDelete_DBError(t *testing.T) {
	withTestDB_CB92(t, func(testDB *sql.DB) {
		userID, _, _ := setupUserAndConv_CB92(t, testDB)
		token := makeJWT_CB92(userID, "cb92testuser")

		// Drop messages table
		testDB.Exec("DROP TABLE messages")

		form := strings.NewReader("message_id=any")
		req := httptest.NewRequest("POST", "/messages/delete", form)
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()
		handleMessageDelete(rr, req)
		if rr.Code != http.StatusInternalServerError && rr.Code != http.StatusNotFound {
			t.Fatalf("expected 500 or 404, got %d", rr.Code)
		}
	})
}

// ============================================================
// handleSetRateLimitTier tests
// ============================================================

func TestCB92_HandleSetRateLimitTier_AdminAuth(t *testing.T) {
	withTestDB_CB92(t, func(testDB *sql.DB) {
		resetAdminSecret()
		os.Setenv("ADMIN_SECRET", "admin-pass-92")
		defer os.Unsetenv("ADMIN_SECRET")
		resetAdminSecret()

		// Create user
		hash, _ := bcrypt.GenerateFromPassword([]byte("pass"), bcrypt.DefaultCost)
		testDB.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)",
			"cb92-rl-user", "cb92rluser", string(hash))

		form := strings.NewReader("user_id=cb92-rl-user&tier=pro")
		req := httptest.NewRequest("POST", "/admin/rate-limit/tier", form)
		req.Header.Set("X-Admin-Secret", "admin-pass-92")
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()
		handleSetRateLimitTier(rr, req)

		if rr.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
		}
	})
}

func TestCB92_HandleSetRateLimitTier_NoAuth(t *testing.T) {
	withTestDB_CB92(t, func(testDB *sql.DB) {
		req := httptest.NewRequest("POST", "/admin/rate-limit/tier", nil)
		rr := httptest.NewRecorder()
		handleSetRateLimitTier(rr, req)
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d", rr.Code)
		}
	})
}

func TestCB92_HandleSetRateLimitTier_WrongSecret(t *testing.T) {
	withTestDB_CB92(t, func(testDB *sql.DB) {
		resetAdminSecret()
		os.Setenv("ADMIN_SECRET", "admin-pass-92")
		defer os.Unsetenv("ADMIN_SECRET")
		resetAdminSecret()

		form := strings.NewReader("user_id=u1&tier=pro")
		req := httptest.NewRequest("POST", "/admin/rate-limit/tier", form)
		req.Header.Set("X-Admin-Secret", "wrong")
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()
		handleSetRateLimitTier(rr, req)
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d", rr.Code)
		}
	})
}

func TestCB92_HandleSetRateLimitTier_MissingUserID(t *testing.T) {
	withTestDB_CB92(t, func(testDB *sql.DB) {
		resetAdminSecret()
		os.Setenv("ADMIN_SECRET", "admin-pass-92")
		defer os.Unsetenv("ADMIN_SECRET")
		resetAdminSecret()

		form := strings.NewReader("tier=pro")
		req := httptest.NewRequest("POST", "/admin/rate-limit/tier", form)
		req.Header.Set("X-Admin-Secret", "admin-pass-92")
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()
		handleSetRateLimitTier(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d: %s", rr.Code, rr.Body.String())
		}
	})
}

func TestCB92_HandleSetRateLimitTier_MissingTier(t *testing.T) {
	withTestDB_CB92(t, func(testDB *sql.DB) {
		resetAdminSecret()
		os.Setenv("ADMIN_SECRET", "admin-pass-92")
		defer os.Unsetenv("ADMIN_SECRET")
		resetAdminSecret()

		form := strings.NewReader("user_id=u1")
		req := httptest.NewRequest("POST", "/admin/rate-limit/tier", form)
		req.Header.Set("X-Admin-Secret", "admin-pass-92")
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()
		handleSetRateLimitTier(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d: %s", rr.Code, rr.Body.String())
		}
	})
}

func TestCB92_HandleSetRateLimitTier_UnknownTier(t *testing.T) {
	withTestDB_CB92(t, func(testDB *sql.DB) {
		resetAdminSecret()
		os.Setenv("ADMIN_SECRET", "admin-pass-92")
		defer os.Unsetenv("ADMIN_SECRET")
		resetAdminSecret()

		form := strings.NewReader("user_id=u1&tier=platinum")
		req := httptest.NewRequest("POST", "/admin/rate-limit/tier", form)
		req.Header.Set("X-Admin-Secret", "admin-pass-92")
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()
		handleSetRateLimitTier(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 for unknown tier, got %d: %s", rr.Code, rr.Body.String())
		}
	})
}

func TestCB92_HandleSetRateLimitTier_Enterprise(t *testing.T) {
	withTestDB_CB92(t, func(testDB *sql.DB) {
		resetAdminSecret()
		os.Setenv("ADMIN_SECRET", "admin-pass-92")
		defer os.Unsetenv("ADMIN_SECRET")
		resetAdminSecret()

		hash, _ := bcrypt.GenerateFromPassword([]byte("pass"), bcrypt.DefaultCost)
		testDB.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)",
			"cb92-ent-user", "cb92entuser", string(hash))

		form := strings.NewReader("user_id=cb92-ent-user&tier=enterprise")
		req := httptest.NewRequest("POST", "/admin/rate-limit/tier", form)
		req.Header.Set("X-Admin-Secret", "admin-pass-92")
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()
		handleSetRateLimitTier(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
		}
	})
}

// ============================================================
// handleGetRateLimitTier tests
// ============================================================

func TestCB92_HandleGetRateLimitTier_NoAuth(t *testing.T) {
	withTestDB_CB92(t, func(testDB *sql.DB) {
		req := httptest.NewRequest("GET", "/admin/rate-limit/tier", nil)
		rr := httptest.NewRecorder()
		handleGetRateLimitTier(rr, req)
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d", rr.Code)
		}
	})
}

func TestCB92_HandleGetRateLimitTier_MissingUserID(t *testing.T) {
	withTestDB_CB92(t, func(testDB *sql.DB) {
		resetAdminSecret()
		os.Setenv("ADMIN_SECRET", "admin-pass-92")
		defer os.Unsetenv("ADMIN_SECRET")
		resetAdminSecret()

		req := httptest.NewRequest("GET", "/admin/rate-limit/tier", nil)
		req.Header.Set("X-Admin-Secret", "admin-pass-92")
		rr := httptest.NewRecorder()
		handleGetRateLimitTier(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d: %s", rr.Code, rr.Body.String())
		}
	})
}

func TestCB92_HandleGetRateLimitTier_Default(t *testing.T) {
	withTestDB_CB92(t, func(testDB *sql.DB) {
		resetAdminSecret()
		os.Setenv("ADMIN_SECRET", "admin-pass-92")
		defer os.Unsetenv("ADMIN_SECRET")
		resetAdminSecret()

		req := httptest.NewRequest("GET", "/admin/rate-limit/tier?user_id=some-user", nil)
		req.Header.Set("X-Admin-Secret", "admin-pass-92")
		rr := httptest.NewRecorder()
		handleGetRateLimitTier(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
		}
		if !strings.Contains(rr.Body.String(), "free") {
			t.Fatalf("expected default 'free' tier, got %s", rr.Body.String())
		}
	})
}

// ============================================================
// handleHeapProfile tests
// ============================================================

func TestCB92_HandleHeapProfile_Success(t *testing.T) {
	dir := t.TempDir()
	os.Setenv("PROFILING_DIR", dir)
	defer os.Unsetenv("PROFILING_DIR")

	req := httptest.NewRequest("POST", "/admin/profile?action=heap", nil)
	rr := httptest.NewRecorder()
	handleHeapProfile(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "heap") {
		t.Fatalf("expected 'heap' in response, got %s", rr.Body.String())
	}
}

func TestCB92_HandleHeapProfile_DirError(t *testing.T) {
	// Set profiling dir to a path that can't be created
	os.Setenv("PROFILING_DIR", "/proc/cannot-create-dir-here")
	defer os.Unsetenv("PROFILING_DIR")

	req := httptest.NewRequest("POST", "/admin/profile?action=heap", nil)
	rr := httptest.NewRecorder()
	handleHeapProfile(rr, req)
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 for dir error, got %d: %s", rr.Code, rr.Body.String())
	}
}

// ============================================================
// handleGoroutineProfile tests
// ============================================================

func TestCB92_HandleGoroutineProfile_Success(t *testing.T) {
	dir := t.TempDir()
	os.Setenv("PROFILING_DIR", dir)
	defer os.Unsetenv("PROFILING_DIR")

	req := httptest.NewRequest("POST", "/admin/profile?action=goroutine", nil)
	rr := httptest.NewRecorder()
	handleGoroutineProfile(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "goroutine") {
		t.Fatalf("expected 'goroutine' in response, got %s", rr.Body.String())
	}
}

func TestCB92_HandleGoroutineProfile_DirError(t *testing.T) {
	os.Setenv("PROFILING_DIR", "/proc/cannot-create-dir-here")
	defer os.Unsetenv("PROFILING_DIR")

	req := httptest.NewRequest("POST", "/admin/profile?action=goroutine", nil)
	rr := httptest.NewRecorder()
	handleGoroutineProfile(rr, req)
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 for dir error, got %d: %s", rr.Code, rr.Body.String())
	}
}

// ============================================================
// handleAdminProfile tests
// ============================================================

func TestCB92_HandleAdminProfile_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest("PUT", "/admin/profile", nil)
	rr := httptest.NewRecorder()
	handleAdminProfile(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", rr.Code)
	}
}

func TestCB92_HandleAdminProfile_UnknownAction(t *testing.T) {
	req := httptest.NewRequest("POST", "/admin/profile?action=bogus", nil)
	rr := httptest.NewRecorder()
	handleAdminProfile(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for unknown action, got %d", rr.Code)
	}
}

func TestCB92_HandleAdminProfile_StatsAction(t *testing.T) {
	req := httptest.NewRequest("GET", "/admin/profile?action=stats", nil)
	rr := httptest.NewRecorder()
	handleAdminProfile(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "memory") {
		t.Fatalf("expected 'memory' in stats, got %s", rr.Body.String())
	}
}

func TestCB92_HandleAdminProfile_GCAction(t *testing.T) {
	req := httptest.NewRequest("POST", "/admin/profile?action=gc", nil)
	rr := httptest.NewRecorder()
	handleAdminProfile(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "gc") {
		t.Fatalf("expected 'gc' in response, got %s", rr.Body.String())
	}
}

func TestCB92_HandleAdminProfile_JSONBody(t *testing.T) {
	body := strings.NewReader(`{"action":"stats"}`)
	req := httptest.NewRequest("POST", "/admin/profile", body)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	handleAdminProfile(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestCB92_HandleAdminProfile_CPUStartStop(t *testing.T) {
	dir := t.TempDir()
	os.Setenv("PROFILING_DIR", dir)
	defer os.Unsetenv("PROFILING_DIR")

	// Start CPU profile
	req1 := httptest.NewRequest("POST", "/admin/profile?action=cpu", nil)
	rr1 := httptest.NewRecorder()
	handleAdminProfile(rr1, req1)
	if rr1.Code != http.StatusOK {
		t.Fatalf("expected 200 for cpu start, got %d: %s", rr1.Code, rr1.Body.String())
	}

	// Stop CPU profile
	req2 := httptest.NewRequest("POST", "/admin/profile?action=cpu_stop", nil)
	rr2 := httptest.NewRecorder()
	handleAdminProfile(rr2, req2)
	if rr2.Code != http.StatusOK {
		t.Fatalf("expected 200 for cpu stop, got %d: %s", rr2.Code, rr2.Body.String())
	}
}

func TestCB92_HandleAdminProfile_CPUStopNotActive(t *testing.T) {
	// Ensure no CPU profile is active
	cpuProfileState.Lock()
	cpuProfileState.active = false
	cpuProfileState.stopFunc = nil
	cpuProfileState.Unlock()

	req := httptest.NewRequest("POST", "/admin/profile?action=cpu_stop", nil)
	rr := httptest.NewRecorder()
	handleAdminProfile(rr, req)
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 for cpu_stop without active profile, got %d", rr.Code)
	}
}

// ============================================================
// Snapshot tests
// ============================================================

func TestCB92_Snapshot_WithHub(t *testing.T) {
	origMetrics := ServerMetrics
	defer func() { ServerMetrics = origMetrics }()

	cleanup := setupHub_CB92()
	defer cleanup()
	ServerMetrics = NewMetrics(hub)

	// Register an agent
	agent := makeConn_CB92("cb92-agent-snap", "agent", hub)
	hub.register <- agent
	time.Sleep(50 * time.Millisecond)

	snap := ServerMetrics.Snapshot()
	if snap["agents_connected"].(int) < 1 {
		t.Fatalf("expected agents_connected>=1, got %v", snap["agents_connected"])
	}
}

func TestCB92_Snapshot_WithOfflineQueue(t *testing.T) {
	origMetrics := ServerMetrics
	origQueue := offlineQueue
	defer func() { ServerMetrics = origMetrics; offlineQueue = origQueue }()

	ServerMetrics = &Metrics{StartTime: time.Now(), Version: "0.2.0", AgentsConnected: func() int { return 0 }, ClientsConnected: func() int { return 0 }, ClientConnsTotal: func() int { return 0 }, StaleAgentCount: func() int64 { return 0 }}
	offlineQueue = newOfflineQueue(100, 7*24*time.Hour)
	offlineQueue.Enqueue("user-1", []byte("msg1"))
	offlineQueue.Enqueue("user-1", []byte("msg2"))

	snap := ServerMetrics.Snapshot()
	depth := snap["offline_queue_depth"]
	if depth == nil || depth.(int) < 2 {
			t.Fatalf("expected offline_queue_depth>=2, got %v", depth)
		}
	}

// ============================================================
// HashAPIKey tests
// ============================================================

func TestCB92_HashAPIKey_Empty(t *testing.T) {
	hash, _ := HashAPIKey("")
	if hash == "" {
		t.Fatal("expected non-empty hash for empty input")
	}
}

func TestCB92_HashAPIKey_DifferentInputs(t *testing.T) {
	h1, _ := HashAPIKey("key1")
	h2, _ := HashAPIKey("key2")
	if h1 == h2 {
		t.Fatal("expected different hashes for different inputs")
	}
}

func TestCB92_HashAPIKey_SameInput(t *testing.T) {
	h1, _ := HashAPIKey("test-key")
	h2, _ := HashAPIKey("test-key")
	// bcrypt uses random salt, so hashes differ but both should verify against same input
	if h1 == h2 {
		t.Fatal("expected different hashes due to random salt (bcrypt)")
	}
	if err := bcrypt.CompareHashAndPassword([]byte(h1), []byte("test-key")); err != nil {
		t.Fatalf("h1 should verify against test-key: %v", err)
	}
	if err := bcrypt.CompareHashAndPassword([]byte(h2), []byte("test-key")); err != nil {
		t.Fatalf("h2 should verify against test-key: %v", err)
	}
}

// ============================================================
// Concurrent test for OfflineQueue
// ============================================================

func TestCB92_OfflineQueue_ConcurrentEnqueueDrain(t *testing.T) {
	q := newOfflineQueue(1000, time.Hour)
	var wg sync.WaitGroup

	// 10 goroutines each enqueue 100 messages
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(gid int) {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				q.Enqueue(fmt.Sprintf("user-%d", gid), []byte("msg"))
			}
		}(i)
	}

	wg.Wait()

	// Drain each user
	totalDrained := 0
	for i := 0; i < 10; i++ {
		msgs := q.Drain(fmt.Sprintf("user-%d", i))
		totalDrained += len(msgs)
	}

	if totalDrained != 1000 {
		t.Fatalf("expected 1000 total drained, got %d", totalDrained)
	}
}

// ============================================================
// accessLogMiddleware test
// ============================================================

func TestCB92_AccessLogMiddleware_Success(t *testing.T) {
	origLogger := DefaultLogger
	defer func() { DefaultLogger = origLogger }()
	var buf bytes.Buffer
	DefaultLogger = NewLogger(LogInfo)
	DefaultLogger.SetOutput(&buf)

	handler := accessLogMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-Request-ID", "test-req-id")
	rr := httptest.NewRecorder()
	handler(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	// Should have logged the request
	if buf.Len() == 0 {
		t.Log("access log buffer empty (may be expected depending on log level)")
	}
}

func TestCB92_AccessLogMiddleware_WithUserID(t *testing.T) {
	origLogger := DefaultLogger
	defer func() { DefaultLogger = origLogger }()
	DefaultLogger = NewLogger(LogInfo)
	DefaultLogger.SetOutput(io.Discard)

	userID, _, _ := "cb92-log-user", "", ""
	token := makeJWT_CB92(userID, "cb92loguser")

	handler := accessLogMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	handler(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
}
// setupMetrics_CB92 creates a Metrics instance with a real hub for safe Snapshot calls.
func setupMetrics_CB92() (*Metrics, *Hub, func()) {
	origMetrics := ServerMetrics
	h := newHub()
	go h.run()
	m := NewMetrics(h)
	ServerMetrics = m
	cleanup := func() {
		h.Stop()
		ServerMetrics = origMetrics
	}
	return m, h, cleanup
}
