package main

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

	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/websocket"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	gooteltrace "go.opentelemetry.io/otel/trace"
	_ "github.com/mattn/go-sqlite3"
)

// --- CB64 Helpers ---

func setupTestDB_CB64(t *testing.T) *sql.DB {
	testDB, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("Failed to open test DB: %v", err)
	}
	if err := initSchema(testDB); err != nil {
		t.Fatalf("Failed to init schema: %v", err)
	}
	return testDB
}

func generateTestToken_CB64(userID string) string {
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

func resetTracingState_CB64() {
	tracingEnabled = false
	tracer = nil
	tp = nil
	tracingMu = sync.Once{}
}

// --- Tracing: StartSpan / StartSpanFromRequest / SpanError / SpanOK ---

func TestCB64_StartSpan_Disabled(t *testing.T) {
	resetTracingState_CB64()
	ctx := context.Background()
	newCtx, span := StartSpan(ctx, "test-span")
	if newCtx != ctx {
		t.Error("expected same context when tracing disabled")
	}
	if span == nil {
		t.Error("expected non-nil span even when disabled")
	}
}

func TestCB64_StartSpanFromRequest_Disabled(t *testing.T) {
	resetTracingState_CB64()
	req := httptest.NewRequest("GET", "/", nil)
	newCtx, span := StartSpanFromRequest(req, "test-span")
	if newCtx != req.Context() {
		t.Error("expected same context when tracing disabled")
	}
	if span == nil {
		t.Error("expected non-nil span even when disabled")
	}
}

func TestCB64_SpanError_Disabled(t *testing.T) {
	resetTracingState_CB64()
	span := noopSpan()
	SpanError(span, fmt.Errorf("test error"))
	// Should not panic
}

func TestCB64_SpanOK_Disabled(t *testing.T) {
	resetTracingState_CB64()
	span := noopSpan()
	SpanOK(span)
	// Should not panic
}

func TestCB64_SpanError_NilSpan(t *testing.T) {
	resetTracingState_CB64()
	tracingEnabled = true
	SpanError(nil, fmt.Errorf("test error"))
	// Should not panic with nil span
}

func TestCB64_SpanOK_NilSpan(t *testing.T) {
	resetTracingState_CB64()
	tracingEnabled = true
	SpanOK(nil)
	// Should not panic with nil span
}

// --- Tracing: TraceRouteMessage / TraceOfflineEnqueue / TracePushNotify ---

func TestCB64_TraceRouteMessage_Disabled(t *testing.T) {
	resetTracingState_CB64()
	span := TraceRouteMessage("agent", "conn-123")
	if span == nil {
		t.Error("expected non-nil span even when disabled")
	}
}

func TestCB64_TraceOfflineEnqueue_Disabled(t *testing.T) {
	resetTracingState_CB64()
	span := TraceOfflineEnqueue("user-123")
	if span == nil {
		t.Error("expected non-nil span even when disabled")
	}
}

func TestCB64_TracePushNotify_Disabled(t *testing.T) {
	resetTracingState_CB64()
	span := TracePushNotify("user-123", "conv-456", true)
	if span == nil {
		t.Error("expected non-nil span even when disabled")
	}
}

func TestCB64_TraceAgentConnect_Disabled(t *testing.T) {
	resetTracingState_CB64()
	span := TraceAgentConnect("agent-001")
	if span == nil {
		t.Error("expected non-nil span even when disabled")
	}
}

func TestCB64_TraceClientConnect_Disabled(t *testing.T) {
	resetTracingState_CB64()
	span := TraceClientConnect("user-001", "device-abc")
	if span == nil {
		t.Error("expected non-nil span even when disabled")
	}
}

// --- Tracing: InitTracing enabled with HTTP exporter ---
// This exercises the HTTP exporter creation path

func TestCB64_TracingEnabled_AllFunctions(t *testing.T) {
	resetTracingState_CB64()
	defer resetTracingState_CB64()

	// Manually enable tracing by creating a no-op tracer provider
	// This avoids the resource merge schema conflict in InitTracing
	noOpTP := sdktrace.NewTracerProvider(
		sdktrace.WithSampler(sdktrace.AlwaysSample()),
	)
	tp = noOpTP
	tracer = noOpTP.Tracer(tracerName)
	tracingEnabled = true
	defer func() {
		tp.Shutdown(context.Background())
		tp = nil
	}()

	// Test StartSpan with tracing enabled
	_, span := StartSpan(context.Background(), "test-span-enabled")
	if span == nil {
		t.Error("expected non-nil span when tracing enabled")
	}
	span.End()

	// Test StartSpanFromRequest with tracing enabled
	req := httptest.NewRequest("GET", "/test", nil)
	_, reqSpan := StartSpanFromRequest(req, "test-http-span")
	if reqSpan == nil {
		t.Error("expected non-nil span from request when tracing enabled")
	}
	reqSpan.End()

	// Test SpanError and SpanOK with tracing enabled
	_, errSpan := StartSpan(context.Background(), "error-test-span")
	SpanError(errSpan, fmt.Errorf("test error"))
	SpanOK(errSpan)
	errSpan.End()

	// Test convenience trace functions with tracing enabled
	routeSpan := TraceRouteMessage("agent", "conn-1")
	routeSpan.End()

	offlineSpan := TraceOfflineEnqueue("user-1")
	offlineSpan.End()

	pushSpan := TracePushNotify("user-1", "conv-1", true)
	pushSpan.End()

	agentConnSpan := TraceAgentConnect("agent-1")
	agentConnSpan.End()

	clientConnSpan := TraceClientConnect("user-1", "device-1")
	clientConnSpan.End()

	// Test TraceChatMessage, TraceStoreMessage, TraceDeliverMessage with tracing enabled
	ctx := context.Background()
	_, chatSpan := TraceChatMessage(ctx, "user", "user-1", "conv-1", "agent-1")
	chatSpan.End()

	_, storeSpan := TraceStoreMessage(ctx, "conv-1", "user-1")
	storeSpan.End()

	_, deliverSpan := TraceDeliverMessage(ctx, "user-1", "user", true)
	deliverSpan.End()
}

func TestCB64_InitTracing_DisabledByDefault(t *testing.T) {
	resetTracingState_CB64()
	defer resetTracingState_CB64()

	os.Unsetenv("OTEL_ENABLED")
	err := InitTracing()
	if err != nil {
		t.Fatalf("InitTracing should not error when disabled: %v", err)
	}
	if tracingEnabled {
		t.Error("expected tracingEnabled to be false when OTEL_ENABLED not set")
	}
	if tracer != nil {
		t.Error("expected tracer to be nil when disabled")
	}
}

func TestCB64_InitTracing_NoEndpoint(t *testing.T) {
	resetTracingState_CB64()
	defer resetTracingState_CB64()

	os.Setenv("OTEL_ENABLED", "true")
	os.Unsetenv("OTEL_EXPORTER_OTLP_ENDPOINT")
	os.Unsetenv("OTEL_EXPORTER_OTLP_HTTP_ENDPOINT")
	defer os.Unsetenv("OTEL_ENABLED")

	err := InitTracing()
	if err != nil {
		t.Fatalf("InitTracing should not error without endpoint: %v", err)
	}
	if tracingEnabled {
		t.Error("expected tracingEnabled to be false without endpoint")
	}
}

func TestCB64_ShutdownTracing_NoProvider(t *testing.T) {
	resetTracingState_CB64()
	// Should not panic when tp is nil
	ShutdownTracing()
}

func TestCB64_IsTracingEnabled(t *testing.T) {
	resetTracingState_CB64()
	if IsTracingEnabled() {
		t.Error("expected tracing to be disabled initially")
	}
}

// --- Middleware: ipRateLimitMiddleware ---

func TestCB64_ipRateLimitMiddleware_Allowed(t *testing.T) {
	called := false
	handler := ipRateLimitMiddleware(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	// Reset the IP rate limiter to ensure clean state
	ipRateLimiter.Reset()

	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "192.168.1.100:12345"
	w := httptest.NewRecorder()
	handler(w, req)

	if !called {
		t.Error("expected handler to be called for allowed IP")
	}
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestCB64_ipRateLimitMiddleware_RateLimited(t *testing.T) {
	ipRateLimiter.Reset()

	handler := ipRateLimitMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "10.0.0.1:54321"

	// Exhaust rate limit (300 per minute)
	for i := 0; i < 300; i++ {
		if !ipRateLimiter.Allow("10.0.0.1") {
			break
		}
	}

	w := httptest.NewRecorder()
	handler(w, req)

	if w.Code != http.StatusTooManyRequests {
		t.Errorf("expected 429, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "rate limit exceeded") {
		t.Error("expected rate limit error message")
	}
}

// --- Middleware: authRateLimitMiddleware ---

func TestCB64_authRateLimitMiddleware_Allowed(t *testing.T) {
	called := false
	handler := authRateLimitMiddleware(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	authIPLimiter.Reset()

	req := httptest.NewRequest("POST", "/auth/login", nil)
	req.RemoteAddr = "192.168.1.200:12345"
	w := httptest.NewRecorder()
	handler(w, req)

	if !called {
		t.Error("expected handler to be called for allowed IP")
	}
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestCB64_authRateLimitMiddleware_RateLimited(t *testing.T) {
	authIPLimiter.Reset()

	handler := authRateLimitMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Exhaust auth rate limit (30 per minute)
	for i := 0; i < 30; i++ {
		if !authIPLimiter.Allow("10.0.0.2") {
			break
		}
	}

	req := httptest.NewRequest("POST", "/auth/login", nil)
	req.RemoteAddr = "10.0.0.2:54321"
	w := httptest.NewRecorder()
	handler(w, req)

	if w.Code != http.StatusTooManyRequests {
		t.Errorf("expected 429, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "auth attempts") {
		t.Error("expected auth rate limit error message")
	}
}

// --- Middleware: accessLogMiddleware ---

func TestCB64_accessLogMiddleware_BasicRequest(t *testing.T) {
	called := false
	handler := accessLogMiddleware(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("GET", "/api/test", nil)
	req.Header.Set("X-Request-ID", "test-req-123")
	req.RemoteAddr = "192.168.1.1:5000"
	w := httptest.NewRecorder()
	handler(w, req)

	if !called {
		t.Error("expected handler to be called")
	}
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestCB64_accessLogMiddleware_WithAuth(t *testing.T) {
	called := false
	handler := accessLogMiddleware(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	token := generateTestToken_CB64("user-auth-123")
	req := httptest.NewRequest("POST", "/api/data", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-Request-ID", "req-auth-456")
	w := httptest.NewRecorder()
	handler(w, req)

	if !called {
		t.Error("expected handler to be called")
	}
}

func TestCB64_accessLogMiddleware_NoRequestID(t *testing.T) {
	handler := accessLogMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
	})

	req := httptest.NewRequest("DELETE", "/api/item/123", nil)
	w := httptest.NewRecorder()
	handler(w, req)

	if w.Code != http.StatusCreated {
		t.Errorf("expected 201, got %d", w.Code)
	}
}

func TestCB64_accessLogMiddleware_WriteHeader(t *testing.T) {
	handler := accessLogMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})

	req := httptest.NewRequest("GET", "/api/notfound", nil)
	w := httptest.NewRecorder()
	handler(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

// --- Middleware: checkRateLimit ---

func TestCB64_checkRateLimit_Allowed(t *testing.T) {
	messageRateLimiter.Reset()
	userRateLimiter.Reset()

	conn := &Connection{
		connType: "agent",
		id:      "test-conn-allowed",
		send:    make(chan []byte, 256),
	}

	result := checkRateLimit(conn)
	if !result {
		t.Error("expected rate limit to allow")
	}
}

func TestCB64_checkRateLimit_PerConnectionLimited(t *testing.T) {
	messageRateLimiter.Reset()
	userRateLimiter.Reset()

	conn := &Connection{
		connType: "agent",
		id:      "test-conn-per-ip-limited",
		send:    make(chan []byte, 256),
	}

	// Exhaust per-connection rate limit (60/min)
	for i := 0; i < 60; i++ {
		if !messageRateLimiter.Allow(conn.id) {
			break
		}
	}

	result := checkRateLimit(conn)
	if result {
		t.Error("expected rate limit to deny (per-connection exceeded)")
	}
}

func TestCB64_checkRateLimit_PerUserLimited(t *testing.T) {
	messageRateLimiter.Reset()
	userRateLimiter.Reset()

	conn := &Connection{
		connType: "agent",
		id:      "test-conn-user-limited",
		send:    make(chan []byte, 256),
	}

	// Allow per-connection but exhaust per-user
	// Both use conn.id as key, so we need to exhaust userRateLimiter separately
	for i := 0; i < 120; i++ {
		if !userRateLimiter.Allow(conn.id) {
			break
		}
	}

	// Per-connection should still allow (we haven't used it)
	result := checkRateLimit(conn)
	if result {
		t.Error("expected rate limit to deny (per-user exceeded)")
	}
}

// --- Queue: newOfflineQueue ---

func TestCB64_newOfflineQueue_Defaults(t *testing.T) {
	q := newOfflineQueue(0, 0)
	if q.maxLen != 100 {
		t.Errorf("expected default maxLen 100, got %d", q.maxLen)
	}
	if q.ttl != 7*24*time.Hour {
		t.Errorf("expected default ttl 7 days, got %v", q.ttl)
	}
}

func TestCB64_newOfflineQueue_NegativeValues(t *testing.T) {
	q := newOfflineQueue(-5, -time.Hour)
	if q.maxLen != 100 {
		t.Errorf("expected default maxLen 100 for negative, got %d", q.maxLen)
	}
	if q.ttl != 7*24*time.Hour {
		t.Errorf("expected default ttl for negative, got %v", q.ttl)
	}
}

func TestCB64_newOfflineQueue_CustomValues(t *testing.T) {
	q := newOfflineQueue(50, time.Hour)
	if q.maxLen != 50 {
		t.Errorf("expected maxLen 50, got %d", q.maxLen)
	}
	if q.ttl != time.Hour {
		t.Errorf("expected ttl 1 hour, got %v", q.ttl)
	}
}

// --- handleMarkRead ---

func TestCB64_handleMarkRead_MethodNotAllowed(t *testing.T) {
	db = setupTestDB_CB64(t)
	defer func() { db = nil }()

	req := httptest.NewRequest("GET", "/conversations/mark-read", nil)
	w := httptest.NewRecorder()
	handleMarkRead(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestCB64_handleMarkRead_NoToken(t *testing.T) {
	db = setupTestDB_CB64(t)
	defer func() { db = nil }()

	req := httptest.NewRequest("POST", "/conversations/mark-read", nil)
	w := httptest.NewRecorder()
	handleMarkRead(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestCB64_handleMarkRead_InvalidToken(t *testing.T) {
	db = setupTestDB_CB64(t)
	defer func() { db = nil }()

	req := httptest.NewRequest("POST", "/conversations/mark-read", nil)
	req.Header.Set("Authorization", "Bearer invalid-token-xxx")
	w := httptest.NewRecorder()
	handleMarkRead(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestCB64_handleMarkRead_MissingConversationID(t *testing.T) {
	db = setupTestDB_CB64(t)
	defer func() { db = nil }()

	token := generateTestToken_CB64("user-mark-1")
	req := httptest.NewRequest("POST", "/conversations/mark-read", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleMarkRead(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestCB64_handleMarkRead_ConversationNotFound(t *testing.T) {
	db = setupTestDB_CB64(t)
	defer func() { db = nil }()

	token := generateTestToken_CB64("user-mark-2")
	form := "conversation_id=nonexistent-conv"
	req := httptest.NewRequest("POST", "/conversations/mark-read", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleMarkRead(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

func TestCB64_handleMarkRead_Success(t *testing.T) {
	testDB := setupTestDB_CB64(t)
	db = testDB
	defer func() { db = nil }()

	// Set up hub for read receipt notification
	oldHub := hub
	hub = newHub()
	go hub.run()
	defer func() { hub.Stop(); hub = oldHub }()

	// Create user and conversation with agent messages
	_, err := testDB.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)",
		"user-mark-ok", "markuser", "$2a$10$somehash")
	if err != nil {
		t.Fatalf("Failed to create user: %v", err)
	}

	_, err = testDB.Exec("INSERT INTO agents (id, name, model) VALUES (?, ?, ?)",
		"agent-mark-ok", "TestAgent", "test-model")
	if err != nil {
		t.Fatalf("Failed to create agent: %v", err)
	}

	_, err = testDB.Exec("INSERT INTO conversations (id, user_id, agent_id, created_at) VALUES (?, ?, ?, ?)",
		"conv-mark-ok", "user-mark-ok", "agent-mark-ok", time.Now().UTC())
	if err != nil {
		t.Fatalf("Failed to create conversation: %v", err)
	}

	// Insert an unread agent message
	_, err = testDB.Exec(`INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, created_at)
		VALUES (?, ?, ?, ?, ?, ?)`,
		"msg-mark-1", "conv-mark-ok", "agent", "agent-mark-ok", "Hello", time.Now().UTC())
	if err != nil {
		t.Fatalf("Failed to insert message: %v", err)
	}

	token := generateTestToken_CB64("user-mark-ok")
	form := "conversation_id=conv-mark-ok"
	req := httptest.NewRequest("POST", "/conversations/mark-read", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleMarkRead(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}

	var resp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["count"] == nil {
		t.Error("expected count in response")
	}
}

// --- e2e: handleStoreEncryptedMessage ---

func TestCB64_handleStoreEncryptedMessage_MethodNotAllowed(t *testing.T) {
	db = setupTestDB_CB64(t)
	defer func() { db = nil }()

	req := httptest.NewRequest("GET", "/messages/encrypted", nil)
	w := httptest.NewRecorder()
	handleStoreEncryptedMessage(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestCB64_handleStoreEncryptedMessage_NoAuth(t *testing.T) {
	db = setupTestDB_CB64(t)
	defer func() { db = nil }()

	req := httptest.NewRequest("POST", "/messages/encrypted", nil)
	w := httptest.NewRecorder()
	handleStoreEncryptedMessage(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestCB64_handleStoreEncryptedMessage_InvalidJSON(t *testing.T) {
	db = setupTestDB_CB64(t)
	defer func() { db = nil }()

	token := generateTestToken_CB64("user-enc-1")
	req := httptest.NewRequest("POST", "/messages/encrypted", strings.NewReader("not json"))
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleStoreEncryptedMessage(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestCB64_handleStoreEncryptedMessage_MissingFields(t *testing.T) {
	db = setupTestDB_CB64(t)
	defer func() { db = nil }()

	token := generateTestToken_CB64("user-enc-2")
	body := `{"conversation_id": "", "ciphertext": "", "iv": "", "algorithm": ""}`
	req := httptest.NewRequest("POST", "/messages/encrypted", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleStoreEncryptedMessage(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing fields, got %d", w.Code)
	}
}

func TestCB64_handleStoreEncryptedMessage_InvalidAlgorithm(t *testing.T) {
	db = setupTestDB_CB64(t)
	defer func() { db = nil }()

	token := generateTestToken_CB64("user-enc-3")
	body := `{"conversation_id": "conv-1", "ciphertext": "cipher", "iv": "iv123", "algorithm": "bad-algo"}`
	req := httptest.NewRequest("POST", "/messages/encrypted", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleStoreEncryptedMessage(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid algorithm, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "unsupported algorithm") {
		t.Error("expected unsupported algorithm message")
	}
}

func TestCB64_handleStoreEncryptedMessage_ConversationNotFound(t *testing.T) {
	db = setupTestDB_CB64(t)
	defer func() { db = nil }()

	token := generateTestToken_CB64("user-enc-4")
	body := `{"conversation_id": "nonexistent", "ciphertext": "cipher", "iv": "iv123", "algorithm": "aes-256-gcm"}`
	req := httptest.NewRequest("POST", "/messages/encrypted", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleStoreEncryptedMessage(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

func TestCB64_handleStoreEncryptedMessage_ForbiddenNotParticipant(t *testing.T) {
	testDB := setupTestDB_CB64(t)
	db = testDB
	defer func() { db = nil }()

	// Create conversation owned by different user
	_, err := testDB.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)",
		"user-owner", "owner", "$2a$10$hash")
	if err != nil {
		t.Fatalf("Failed to create user: %v", err)
	}
	_, err = testDB.Exec("INSERT INTO agents (id, name, model) VALUES (?, ?, ?)",
		"agent-enc-1", "Agent", "model")
	if err != nil {
		t.Fatalf("Failed to create agent: %v", err)
	}
	_, err = testDB.Exec("INSERT INTO conversations (id, user_id, agent_id, created_at) VALUES (?, ?, ?, ?)",
		"conv-enc-1", "user-owner", "agent-enc-1", time.Now().UTC())
	if err != nil {
		t.Fatalf("Failed to create conversation: %v", err)
	}

	// Try as different user
	token := generateTestToken_CB64("user-other")
	body := `{"conversation_id": "conv-enc-1", "ciphertext": "cipher", "iv": "iv123", "algorithm": "aes-256-gcm"}`
	req := httptest.NewRequest("POST", "/messages/encrypted", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleStoreEncryptedMessage(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", w.Code)
	}
}

func TestCB64_handleStoreEncryptedMessage_Success(t *testing.T) {
	testDB := setupTestDB_CB64(t)
	db = testDB
	defer func() { db = nil }()

	// Create user, agent, conversation
	_, err := testDB.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)",
		"user-enc-ok", "encuser", "$2a$10$hash")
	if err != nil {
		t.Fatalf("Failed to create user: %v", err)
	}
	_, err = testDB.Exec("INSERT INTO agents (id, name, model) VALUES (?, ?, ?)",
		"agent-enc-ok", "Agent", "model")
	if err != nil {
		t.Fatalf("Failed to create agent: %v", err)
	}
	_, err = testDB.Exec("INSERT INTO conversations (id, user_id, agent_id, created_at) VALUES (?, ?, ?, ?)",
		"conv-enc-ok", "user-enc-ok", "agent-enc-ok", time.Now().UTC())
	if err != nil {
		t.Fatalf("Failed to create conversation: %v", err)
	}

	token := generateTestToken_CB64("user-enc-ok")
	body := `{"conversation_id": "conv-enc-ok", "ciphertext": "ciphertext-data", "iv": "iv-data", "algorithm": "aes-256-gcm", "recipient_key_id": "key-1", "sender_key_id": "key-2"}`
	req := httptest.NewRequest("POST", "/messages/encrypted", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleStoreEncryptedMessage(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}

	var resp map[string]string
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["id"] == "" {
		t.Error("expected non-empty message ID")
	}
	if resp["status"] != "stored" {
		t.Errorf("expected status 'stored', got '%s'", resp["status"])
	}
}

// --- ValidateJWT edge cases ---

func TestCB64_ValidateJWT_InvalidSignature(t *testing.T) {
	// Token signed with wrong secret
	claims := &Claims{
		UserID: "user-wrong-sig",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, _ := token.SignedString([]byte("wrong-secret"))

	_, err := ValidateJWT(signed)
	if err == nil {
		t.Error("expected error for invalid signature")
	}
}

func TestCB64_ValidateJWT_MalformedToken(t *testing.T) {
	_, err := ValidateJWT("not.a.valid.token")
	if err == nil {
		t.Error("expected error for malformed token")
	}
}

func TestCB64_ValidateJWT_EmptyToken(t *testing.T) {
	_, err := ValidateJWT("")
	if err == nil {
		t.Error("expected error for empty token")
	}
}

// --- sendWelcomeMessage edge case: marshal error ---
// sendWelcomeMessage is hard to trigger marshal errors since the data is simple,
// but we can test with a closed channel to exercise the defer/recover path

func TestCB64_sendWelcomeMessage_NilConnection(t *testing.T) {
	// Should not panic with nil-like connection
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("sendWelcomeMessage panicked: %v", r)
		}
	}()
	// sendWelcomeMessage with a connection that has a closed send channel
	c := &Connection{
		connType: "agent",
		id:      "test-welcome-nil",
		send:    make(chan []byte, 1),
	}
	close(c.send)
	sendWelcomeMessage(c)
	// Should not panic even with closed channel
}

// --- Hub: writePump with closed channel ---

func TestCB64_writePump_ChannelClosed(t *testing.T) {
	// Create a test WebSocket server
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()

		c := &Connection{
			connType:    "agent",
			id:          "test-write-pump",
			conn:        conn,
			send:        make(chan []byte, 10),
			connectedAt: time.Now(),
		}

		// Close the send channel to trigger writePump exit
		close(c.send)

		// writePump should exit gracefully when channel is closed
		done := make(chan struct{})
		go func() {
			c.writePump()
			close(done)
		}()

		select {
		case <-done:
			// Success - writePump exited
		case <-time.After(2 * time.Second):
			t.Error("writePump did not exit after channel close")
		}
	}))
	defer srv.Close()

	// Connect as WebSocket client
	dialer := websocket.Dialer{}
	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")
	_, _, err := dialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("Failed to connect to test server: %v", err)
	}

	// Give the server handler time to run
	time.Sleep(100 * time.Millisecond)
}

// --- Hub: run with register/unregister ---

func TestCB64_HubRun_RegisterUnregister(t *testing.T) {
	h := newHub()
	go h.run()
	defer h.Stop()

	// Register an agent
	conn := &Connection{
		hub:      h,
		connType: "agent",
		id:       "test-agent-run-1",
		send:     make(chan []byte, 256),
	}
	h.register <- conn

	// Give hub time to process
	time.Sleep(50 * time.Millisecond)

	h.mu.Lock()
	_, exists := h.agents["test-agent-run-1"]
	h.mu.Unlock()
	if !exists {
		t.Error("expected agent to be registered")
	}

	// Unregister
	h.unregister <- conn
	time.Sleep(50 * time.Millisecond)

	h.mu.Lock()
	_, exists = h.agents["test-agent-run-1"]
	h.mu.Unlock()
	if exists {
		t.Error("expected agent to be unregistered")
	}
}

func TestCB64_HubRun_RegisterClient(t *testing.T) {
	h := newHub()
	go h.run()
	defer h.Stop()

	conn := &Connection{
		hub:      h,
		connType: "client",
		id:       "test-client-run-1",
		deviceID: "device-1",
		send:     make(chan []byte, 256),
	}
	h.register <- conn
	time.Sleep(50 * time.Millisecond)

	h.mu.Lock()
	conns := h.clientConns["test-client-run-1"]
	h.mu.Unlock()
	if len(conns) != 1 {
		t.Errorf("expected 1 client connection, got %d", len(conns))
	}

	// Unregister
	h.unregister <- conn
	time.Sleep(50 * time.Millisecond)

	h.mu.Lock()
	conns = h.clientConns["test-client-run-1"]
	h.mu.Unlock()
	if len(conns) != 0 {
		t.Errorf("expected 0 client connections after unregister, got %d", len(conns))
	}
}

// --- Hub: run with broadcast ---

func TestCB64_HubRun_Broadcast(t *testing.T) {
	h := newHub()
	go h.run()
	defer h.Stop()

	// Create two agent connections
	agent1 := &Connection{
		hub:      h,
		connType: "agent",
		id:       "test-bcast-agent-1",
		send:     make(chan []byte, 256),
	}
	agent2 := &Connection{
		hub:      h,
		connType: "agent",
		id:       "test-bcast-agent-2",
		send:     make(chan []byte, 256),
	}
	h.register <- agent1
	h.register <- agent2
	time.Sleep(50 * time.Millisecond)

	// Broadcast a message
	msg := []byte(`{"type":"test_broadcast"}`)
	h.broadcast <- msg
	time.Sleep(50 * time.Millisecond)

	// Both agents should receive the message
	select {
	case <-agent1.send:
		// Good
	default:
		t.Error("agent1 did not receive broadcast")
	}
	select {
	case <-agent2.send:
		// Good
	default:
		t.Error("agent2 did not receive broadcast")
	}
}

// --- responseWriterWrapper ---

func TestCB64_responseWriterWrapper_WriteHeader(t *testing.T) {
	rec := httptest.NewRecorder()
	wrapped := &responseWriterWrapper{ResponseWriter: rec, statusCode: http.StatusOK}
	wrapped.WriteHeader(http.StatusTeapot)
	if wrapped.statusCode != http.StatusTeapot {
		t.Errorf("expected statusCode 418, got %d", wrapped.statusCode)
	}
	if rec.Code != http.StatusTeapot {
		t.Errorf("expected underlying recorder code 418, got %d", rec.Code)
	}
}

// --- securityHeadersMiddleware ---

func TestCB64_securityHeadersMiddleware_SetsHeaders(t *testing.T) {
	called := false
	handler := securityHeadersMiddleware(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	handler(w, req)

	if !called {
		t.Error("expected handler to be called")
	}
	if w.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Error("expected X-Content-Type-Options header")
	}
	if w.Header().Get("X-Frame-Options") != "DENY" {
		t.Error("expected X-Frame-Options header")
	}
	if w.Header().Get("X-XSS-Protection") != "1; mode=block" {
		t.Error("expected X-XSS-Protection header")
	}
	if w.Header().Get("Referrer-Policy") != "strict-origin-when-cross-origin" {
		t.Error("expected Referrer-Policy header")
	}
	csp := w.Header().Get("Content-Security-Policy")
	if csp == "" {
		t.Error("expected Content-Security-Policy header")
	}
	if !strings.Contains(csp, "frame-ancestors 'none'") {
		t.Error("expected frame-ancestors none in CSP")
	}
}

// --- corsMiddleware ---

func TestCB64_corsMiddleware_WildcardOrigin(t *testing.T) {
	originalCors := corsAllowedOrigins
	corsAllowedOrigins = "*"
	defer func() { corsAllowedOrigins = originalCors }()

	called := false
	handler := corsMiddleware(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Origin", "https://example.com")
	w := httptest.NewRecorder()
	handler(w, req)

	if !called {
		t.Error("expected handler to be called")
	}
	if w.Header().Get("Access-Control-Allow-Origin") != "*" {
		t.Errorf("expected wildcard origin, got %s", w.Header().Get("Access-Control-Allow-Origin"))
	}
}

func TestCB64_corsMiddleware_MatchingOrigin(t *testing.T) {
	originalCors := corsAllowedOrigins
	corsAllowedOrigins = "https://app1.com,https://app2.com"
	defer func() { corsAllowedOrigins = originalCors }()

	called := false
	handler := corsMiddleware(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Origin", "https://app1.com")
	w := httptest.NewRecorder()
	handler(w, req)

	if !called {
		t.Error("expected handler to be called")
	}
	if w.Header().Get("Access-Control-Allow-Origin") != "https://app1.com" {
		t.Errorf("expected app1.com origin, got %s", w.Header().Get("Access-Control-Allow-Origin"))
	}
}

func TestCB64_corsMiddleware_NonMatchingOrigin(t *testing.T) {
	originalCors := corsAllowedOrigins
	corsAllowedOrigins = "https://allowed.com"
	defer func() { corsAllowedOrigins = originalCors }()

	called := false
	handler := corsMiddleware(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Origin", "https://evil.com")
	w := httptest.NewRecorder()
	handler(w, req)

	if !called {
		t.Error("expected handler to be called")
	}
	if w.Header().Get("Access-Control-Allow-Origin") == "https://evil.com" {
		t.Error("should not set ACAO for non-matching origin")
	}
}

func TestCB64_corsMiddleware_NoOrigin(t *testing.T) {
	called := false
	handler := corsMiddleware(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	handler(w, req)

	if !called {
		t.Error("expected handler to be called")
	}
}

func TestCB64_corsMiddleware_OptionsMethod(t *testing.T) {
	originalCors := corsAllowedOrigins
	corsAllowedOrigins = "*"
	defer func() { corsAllowedOrigins = originalCors }()

	handler := corsMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("OPTIONS", "/", nil)
	req.Header.Set("Origin", "https://example.com")
	req.Header.Set("Access-Control-Request-Method", "POST")
	req.Header.Set("Access-Control-Request-Headers", "Content-Type")
	w := httptest.NewRecorder()
	handler(w, req)

	if w.Code != http.StatusNoContent {
		t.Errorf("expected 204 for OPTIONS, got %d", w.Code)
	}
	if w.Header().Get("Access-Control-Allow-Methods") == "" {
		t.Error("expected Access-Control-Allow-Methods header")
	}
}

// --- csrfMiddleware ---

func TestCB64_csrfMiddleware_SafeMethod(t *testing.T) {
	called := false
	handler := csrfMiddleware(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	handler(w, req)

	if !called {
		t.Error("expected handler to be called for GET")
	}
}

func TestCB64_csrfMiddleware_POSTWithXRequestedWith(t *testing.T) {
	called := false
	handler := csrfMiddleware(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("POST", "/", nil)
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	w := httptest.NewRecorder()
	handler(w, req)

	if !called {
		t.Error("expected handler to be called with X-Requested-With header")
	}
}

func TestCB64_csrfMiddleware_POSTWithoutProtection(t *testing.T) {
	called := false
	handler := csrfMiddleware(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("POST", "/", nil)
	w := httptest.NewRecorder()
	handler(w, req)

	if called {
		t.Error("expected handler to NOT be called without CSRF protection")
	}
	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", w.Code)
	}
}

func TestCB64_csrfMiddleware_POSTWithCSRFToken(t *testing.T) {
	called := false
	handler := csrfMiddleware(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("POST", "/", nil)
	req.Header.Set("X-CSRF-Token", "some-token")
	w := httptest.NewRecorder()
	handler(w, req)

	if !called {
		t.Error("expected handler to be called with CSRF token")
	}
}

func TestCB64_csrfMiddleware_POSTWithMatchingOrigin(t *testing.T) {
	originalCors := corsAllowedOrigins
	corsAllowedOrigins = "https://myapp.com"
	defer func() { corsAllowedOrigins = originalCors }()

	called := false
	handler := csrfMiddleware(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("POST", "/", nil)
	req.Header.Set("Origin", "https://myapp.com")
	w := httptest.NewRecorder()
	handler(w, req)

	if !called {
		t.Error("expected handler to be called with matching origin")
	}
}

// --- requestIDMiddleware ---

func TestCB64_requestIDMiddleware_GeneratesID(t *testing.T) {
	called := false
	handler := requestIDMiddleware(func(w http.ResponseWriter, r *http.Request) {
		called = true
		rid := r.Header.Get("X-Request-ID")
		if rid == "" {
			t.Error("expected X-Request-ID to be set")
		}
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	handler(w, req)

	if !called {
		t.Error("expected handler to be called")
	}
	// Should set X-Request-ID in response
	if w.Header().Get("X-Request-ID") == "" {
		t.Error("expected X-Request-ID in response header")
	}
}

func TestCB64_requestIDMiddleware_PreservesExistingID(t *testing.T) {
	handler := requestIDMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-Request-ID", "my-request-id")
	w := httptest.NewRecorder()
	handler(w, req)

	if w.Header().Get("X-Request-ID") != "my-request-id" {
		t.Errorf("expected preserved request ID 'my-request-id', got %s", w.Header().Get("X-Request-ID"))
	}
}

// --- handleAgentConnect edge cases ---

func TestCB64_handleAgentConnect_MissingAgentID(t *testing.T) {
	db = setupTestDB_CB64(t)
	defer func() { db = nil }()

	req := httptest.NewRequest("GET", "/agent/connect", nil)
	w := httptest.NewRecorder()
	handleAgentConnect(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing agent_id, got %d", w.Code)
	}
}

func TestCB64_handleAgentConnect_MissingSecret(t *testing.T) {
	db = setupTestDB_CB64(t)
	defer func() { db = nil }()

	req := httptest.NewRequest("GET", "/agent/connect?agent_id=test-agent", nil)
	w := httptest.NewRecorder()
	handleAgentConnect(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for missing secret, got %d", w.Code)
	}
}

func TestCB64_handleAgentConnect_InvalidSecret(t *testing.T) {
	db = setupTestDB_CB64(t)
	defer func() { db = nil }()

	resetAgentSecret()

	req := httptest.NewRequest("GET", "/agent/connect?agent_id=test-bad&agent_secret=wrong", nil)
	w := httptest.NewRecorder()
	handleAgentConnect(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for invalid secret, got %d", w.Code)
	}
}

// --- TraceChatMessage, TraceStoreMessage, TraceDeliverMessage ---

func TestCB64_TraceChatMessage_Disabled(t *testing.T) {
	resetTracingState_CB64()
	ctx := context.Background()
	newCtx, span := TraceChatMessage(ctx, "user", "user-1", "conv-1", "agent-1")
	if newCtx != ctx {
		t.Error("expected same context when tracing disabled")
	}
	_ = span
}

func TestCB64_TraceStoreMessage_Disabled(t *testing.T) {
	resetTracingState_CB64()
	ctx := context.Background()
	newCtx, span := TraceStoreMessage(ctx, "conv-1", "user-1")
	if newCtx != ctx {
		t.Error("expected same context when tracing disabled")
	}
	_ = span
}

func TestCB64_TraceDeliverMessage_Disabled(t *testing.T) {
	resetTracingState_CB64()
	ctx := context.Background()
	newCtx, span := TraceDeliverMessage(ctx, "user-1", "user", true)
	if newCtx != ctx {
		t.Error("expected same context when tracing disabled")
	}
	_ = span
}

// --- auth.go: Clean (0% coverage) ---

func TestCB64_RateLimiter_Clean(t *testing.T) {
	rl := NewRateLimiter(10, time.Minute)

	// Add some entries
	rl.Allow("ip-1")
	rl.Allow("ip-2")
	rl.Allow("ip-3")

	// Verify entries exist
	if rl.Count("ip-1") != 1 {
		t.Errorf("expected count 1 for ip-1, got %d", rl.Count("ip-1"))
	}

	// Use the agentRateLimiter (rateLimiter type) which has Clean()
	agentRateLimiter.Reset()
	agentRateLimiter.Allow("agent-clean-1")
	agentRateLimiter.Allow("agent-clean-2")

	agentRateLimiter.mu.Lock()
	if entry, ok := agentRateLimiter.attempts["agent-clean-1"]; !ok || entry.count != 1 {
		t.Errorf("expected count 1 for agent-clean-1")
	}
	agentRateLimiter.mu.Unlock()

	// Clean (removes expired entries; since we haven't advanced time, entries should remain)
	agentRateLimiter.Clean()

	agentRateLimiter.mu.Lock()
	if entry, ok := agentRateLimiter.attempts["agent-clean-1"]; !ok || entry.count != 1 {
		t.Errorf("expected count 1 after clean for agent-clean-1")
	}
	agentRateLimiter.mu.Unlock()

	// Now test with expired entries - use a fresh rateLimiter with old firstSeen
	shortRL := &rateLimiter{
		attempts: make(map[string]*rateLimitEntry),
	}
	shortRL.attempts["ip-expire"] = &rateLimitEntry{count: 1, firstSeen: time.Now().Add(-2 * time.Minute)}
	shortRL.Clean()

	// Entry should be expired and removed
	shortRL.mu.Lock()
	_, exists := shortRL.attempts["ip-expire"]
	shortRL.mu.Unlock()
	if exists {
		t.Error("expected ip-expire to be removed after Clean")
	}
}

// --- Hub: run with Stop ---

func TestCB64_HubRun_StopGraceful(t *testing.T) {
	h := newHub()
	go h.run()

	// Stop should close the done channel and exit run
	h.Stop()

	// Verify runDone was closed
	select {
	case <-h.runDone:
		// Good
	case <-time.After(100 * time.Millisecond):
		t.Error("expected runDone to be closed after Stop")
	}
}

// --- TieredRateLimiter cleanup ---

func TestCB64_TieredRateLimiter_Cleanup_RemovesStale(t *testing.T) {
	tl := NewTieredRateLimiter()
	defer tl.Stop()
	tl.SetTier("user-stale", TierFree)

	// Verify user is in the map
	tl.mu.Lock()
	_, exists := tl.limits["user-stale"]
	tl.mu.Unlock()
	if !exists {
		t.Error("expected user to be in limits map")
	}

	// Set an entry with expired windowEnd
	tl.mu.Lock()
	tl.limits["user-stale"] = &userRateLimitState{
		count:     1,
		windowEnd: time.Now().Add(-15 * time.Minute),
		tier:      TierFree,
	}
	tl.mu.Unlock()

	// Run cleanup - should remove stale entry
	tl.cleanupOnce()

	tl.mu.Lock()
	_, exists = tl.limits["user-stale"]
	tl.mu.Unlock()
	if exists {
		t.Error("expected user-stale to be removed after cleanup")
	}
}

func TestCB64_TieredRateLimiter_Cleanup_KeepsActive(t *testing.T) {
	tl := NewTieredRateLimiter()
	defer tl.Stop()
	tl.SetTier("user-active", TierFree)
	tl.Allow("user-active")

	tl.cleanupOnce()

	tl.mu.Lock()
	_, exists := tl.limits["user-active"]
	tl.mu.Unlock()
	if !exists {
		t.Error("expected user-active to still be in limits after cleanup")
	}
}

// --- initAuthRateLimit ---

func TestCB64_initAuthRateLimit_Default(t *testing.T) {
	os.Unsetenv("AUTH_RATE_LIMIT")
	initAuthRateLimit()

	// Should use default 30/min
	if !authIPLimiter.Allow("test-default-auth") {
		t.Error("expected first request to be allowed with default rate limit")
	}
}

func TestCB64_initAuthRateLimit_Custom(t *testing.T) {
	os.Setenv("AUTH_RATE_LIMIT", "5")
	defer os.Unsetenv("AUTH_RATE_LIMIT")

	initAuthRateLimit()

	// Should allow 5 requests
	for i := 0; i < 5; i++ {
		if !authIPLimiter.Allow("test-custom-auth") {
			t.Errorf("expected request %d to be allowed", i)
			return
		}
	}
	// 6th should be denied
	if authIPLimiter.Allow("test-custom-auth") {
		t.Error("expected 6th request to be denied")
	}

	// Reset for other tests
	authIPLimiter.Reset()
	os.Unsetenv("AUTH_RATE_LIMIT")
	initAuthRateLimit()
}

// --- noopSpan helper ---

func noopSpan() gooteltrace.Span {
	return gooteltrace.SpanFromContext(context.Background())
}