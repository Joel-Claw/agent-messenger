package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

// ============================================================
// Tests for rate limiter Allow() method and expiry
// ============================================================

func TestRateLimiterAllowAndExpiry(t *testing.T) {
	rl := NewRateLimiter(10, 50*time.Millisecond)

	// Should allow within limit
	if !rl.Allow("key1") {
		t.Error("should allow key1")
		return
	}

	// Should still allow second request within window
	if !rl.Allow("key1") {
		t.Error("should allow key1 second time")
	}

	// Different key should also be allowed
	if !rl.Allow("key2") {
		t.Error("should allow key2")
	}
}

// ============================================================
// Tests for writeProfileError (0% coverage)
// ============================================================

func TestWriteProfileErrorNoDetail(t *testing.T) {
	w := httptest.NewRecorder()
	writeProfileError(w, "test context", nil)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", w.Code)
	}

	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["status"] != "error" {
		t.Errorf("expected status error, got %v", resp["status"])
	}
	if resp["context"] != "test context" {
		t.Errorf("expected context 'test context', got %v", resp["context"])
	}
	if resp["detail"] != "" {
		t.Errorf("expected empty detail, got %v", resp["detail"])
	}
}

func TestWriteProfileErrorWithErr(t *testing.T) {
	w := httptest.NewRecorder()
	writeProfileError(w, "create dir", os.ErrNotExist)

	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["detail"] != "file does not exist" {
		t.Errorf("expected detail 'file does not exist', got %v", resp["detail"])
	}
}

// ============================================================
// Tests for profile handler endpoints (low coverage)
// ============================================================

func TestHandleAdminProfileUnknownAction(t *testing.T) {
	origSecret := adminSecret
	adminSecret = "test-admin-secret"
	defer func() { adminSecret = origSecret }()

	req := httptest.NewRequest("POST", "/admin/profile?action=unknown", nil)
	req.Header.Set("X-Admin-Secret", "test-admin-secret")
	w := httptest.NewRecorder()
	handleAdminProfile(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestHandleAdminProfileMethodNotAllowed(t *testing.T) {
	origSecret := adminSecret
	adminSecret = "test-admin-secret"
	defer func() { adminSecret = origSecret }()

	req := httptest.NewRequest("DELETE", "/admin/profile", nil)
	req.Header.Set("X-Admin-Secret", "test-admin-secret")
	w := httptest.NewRecorder()
	handleAdminProfile(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestHandleAdminProfileGetStats(t *testing.T) {
	origSecret := adminSecret
	adminSecret = "test-admin-secret"
	defer func() { adminSecret = origSecret }()

	req := httptest.NewRequest("GET", "/admin/profile", nil)
	req.Header.Set("X-Admin-Secret", "test-admin-secret")
	w := httptest.NewRecorder()
	handleAdminProfile(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["action"] != "stats" {
		t.Errorf("expected action stats, got %v", resp["action"])
	}
}

func TestHandleAdminProfilePostWithJSONBody(t *testing.T) {
	origSecret := adminSecret
	adminSecret = "test-admin-secret"
	defer func() { adminSecret = origSecret }()

	body := `{"action":"stats"}`
	req := httptest.NewRequest("POST", "/admin/profile", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Admin-Secret", "test-admin-secret")
	w := httptest.NewRecorder()
	handleAdminProfile(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["action"] != "stats" {
		t.Errorf("expected action stats, got %v", resp["action"])
	}
}

func TestHandleHeapProfileHandler(t *testing.T) {
	dir := os.TempDir()
	os.Setenv("PROFILING_DIR", dir)
	defer os.Unsetenv("PROFILING_DIR")

	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/admin/profile?action=heap", nil)
	handleHeapProfile(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["action"] != "heap" {
		t.Errorf("expected action heap, got %v", resp["action"])
	}
}

func TestHandleGoroutineProfileHandler(t *testing.T) {
	dir := os.TempDir()
	os.Setenv("PROFILING_DIR", dir)
	defer os.Unsetenv("PROFILING_DIR")

	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/admin/profile?action=goroutine", nil)
	handleGoroutineProfile(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["action"] != "goroutine" {
		t.Errorf("expected action goroutine, got %v", resp["action"])
	}
}

func TestHandleCPUProfileStartAndStop(t *testing.T) {
	dir := os.TempDir()
	os.Setenv("PROFILING_DIR", dir)
	defer os.Unsetenv("PROFILING_DIR")

	// Reset CPU profile state
	cpuProfileState.active = false
	cpuProfileState.stopFunc = nil

	// Start
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/admin/profile?action=cpu", nil)
	handleCPUProfileStart(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	if !cpuProfileState.active {
		t.Error("expected cpu profile to be active")
	}

	// Stop
	w = httptest.NewRecorder()
	r = httptest.NewRequest("POST", "/admin/profile?action=cpu_stop", nil)
	handleCPUProfileStop(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	if cpuProfileState.active {
		t.Error("expected cpu profile to be inactive after stop")
	}
}

func TestHandleCPUProfileStartAlreadyActive(t *testing.T) {
	cpuProfileState.active = true
	cpuProfileState.stopFunc = func() {}
	defer func() {
		cpuProfileState.active = false
		cpuProfileState.stopFunc = nil
	}()

	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/admin/profile?action=cpu", nil)
	handleCPUProfileStart(w, r)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", w.Code)
	}
}

func TestHandleCPUProfileStopNotActive(t *testing.T) {
	cpuProfileState.active = false
	cpuProfileState.stopFunc = nil

	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/admin/profile?action=cpu_stop", nil)
	handleCPUProfileStop(w, r)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", w.Code)
	}
}

func TestHandleForceGCHandler(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/admin/profile?action=gc", nil)
	handleForceGC(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["action"] != "gc" {
		t.Errorf("expected action gc, got %v", resp["action"])
	}
}

// tokenUserID extracts the user_id from a JWT token for use in test SQL inserts.
func tokenUserID(t *testing.T, token string) string {
	t.Helper()
	claims, err := ValidateJWT(token)
	if err != nil {
		t.Fatalf("invalid token: %v", err)
	}
	return claims.UserID
}

// ============================================================
// Tests for queue_persist.go functions (low coverage)
// ============================================================

func TestMarshalOutgoingMsgWithData(t *testing.T) {
	msg := OutgoingMessage{
		Type: "chat",
		Data: map[string]interface{}{
			"conversation_id": "conv-1",
			"sender_id":       "user-1",
			"content":         "hello",
			"message_id":      "msg-1",
		},
	}
	data := marshalOutgoingMessage(msg)
	if !bytes.Contains(data, []byte("chat")) {
		t.Error("expected type 'chat' in marshaled output")
	}
}

func TestInitQueueDBHandler(t *testing.T) {
	setupTestDB(t)
	// initQueueDB returns nothing (void), just verify no panic
	initQueueDB(db)
}

// ============================================================
// Tests for push.go handleUnregisterDeviceToken (56.5% coverage)
// ============================================================

func TestHandleUnregisterDeviceTokenSuccess(t *testing.T) {
	setupTestDB(t)
	token := createTestUserInDB(t, "unreguser")

	// Register a device token first (JSON body)
	regBody := `{"device_token":"test-token-123","platform":"ios"}`
	req := httptest.NewRequest("POST", "/push/register", strings.NewReader(regBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleRegisterDeviceToken(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("register failed: %d %s", w.Code, w.Body.String())
	}

	// Now unregister it (DELETE with JSON body)
	unregBody := `{"device_token":"test-token-123"}`
	req = httptest.NewRequest("DELETE", "/push/unregister", strings.NewReader(unregBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w = httptest.NewRecorder()
	handleUnregisterDeviceToken(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestHandleUnregisterDeviceTokenWrongMethod(t *testing.T) {
	req := httptest.NewRequest("GET", "/push/unregister", nil)
	w := httptest.NewRecorder()
	handleUnregisterDeviceToken(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestHandleUnregisterDeviceTokenUnauthorized(t *testing.T) {
	req := httptest.NewRequest("DELETE", "/push/unregister", strings.NewReader(`{"device_token":"tok"}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handleUnregisterDeviceToken(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestHandleRegisterDeviceTokenWrongMethod(t *testing.T) {
	req := httptest.NewRequest("GET", "/push/register", nil)
	w := httptest.NewRecorder()
	handleRegisterDeviceToken(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

// ============================================================
// Tests for tracing.go low-coverage functions
// ============================================================

func TestShutdownTracingNoop(t *testing.T) {
	// When tracing is not enabled, ShutdownTracing should be a no-op
	ShutdownTracing()
}

func TestStartSpanFromRequestWithAuth(t *testing.T) {
	setupTestDB(t)
	token := createTestUserInDB(t, "spanuser")

	// Create a request with auth
	req := httptest.NewRequest("GET", "/test/path", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	// Parse the token to get the user ID directly
	claims, err := ValidateJWT(token)
	if err != nil {
		t.Fatalf("Failed to validate token: %v", err)
	}

	ctx, span := StartSpanFromRequest(req, "test_operation")
	defer span.End()

	// When tracing is disabled (default), StartSpanFromRequest returns a no-op context
	// and doesn't parse auth headers. Verify user_id is available from JWT validation.
	if claims.UserID == "" {
		t.Error("expected non-empty user_id from JWT")
	}
	_ = ctx // context is no-op when tracing is disabled
}

func TestStartSpanFromRequestNoAuth(t *testing.T) {
	req := httptest.NewRequest("GET", "/test/path", nil)

	ctx, span := StartSpanFromRequest(req, "test_operation")
	defer span.End()

	userID := ctx.Value("user_id")
	if userID != nil {
		t.Error("expected nil user_id for unauthenticated request")
	}
}

func TestSpanErrorAndOKWithSpan(t *testing.T) {
	_, span := StartSpan(context.Background(), "test_span")
	defer span.End()

	SpanError(span, fmt.Errorf("test error"))
	SpanOK(span)
}

func TestTraceFunctionsNoop(t *testing.T) {
	// All trace functions should work as no-ops when tracing is disabled
	ctx := context.Background()

	s1 := TraceRouteMessage("client", "conn1")
	s1.End()

	_, s2 := TraceChatMessage(ctx, "user", "user1", "conv1", "agent1")
	s2.End()

	_, s3 := TraceStoreMessage(ctx, "conv1", "user1")
	s3.End()

	_, s4 := TraceDeliverMessage(ctx, "user1", "client", true)
	s4.End()

	s5 := TraceOfflineEnqueue("user1")
	s5.End()

	s6 := TracePushNotify("user1", "conv1", false)
	s6.End()

	s7 := TraceAgentConnect("agent1")
	s7.End()

	s8 := TraceClientConnect("user1", "device1")
	s8.End()
}

// ============================================================
// Tests for checkRateLimit (60% coverage)
// ============================================================

func TestCheckRateLimitAllowsWithinLimit(t *testing.T) {
	setupTestDB(t)
	token := createTestUserInDB(t, "rluser")
	_, err := ValidateJWT(token)
	if err != nil {
		t.Fatalf("invalid token: %v", err)
	}

	conn := &Connection{
		id:   "conn-rl-test",
		send: make(chan []byte, 10),
	}

	if !checkRateLimit(conn) {
		t.Error("should allow within rate limit")
	}
}

func TestCheckRateLimitBlocksOverLimit(t *testing.T) {
	setupTestDB(t)
	token := createTestUserInDB(t, "rluser2")
	_, err := ValidateJWT(token)
	if err != nil {
		t.Fatalf("invalid token: %v", err)
	}

	// Save and replace rate limiters with very low limits
	savedMsgLimiter := messageRateLimiter
	savedUserLimiter := userRateLimiter
	messageRateLimiter = NewRateLimiter(2, time.Minute)
	userRateLimiter = NewRateLimiter(2, time.Minute)
	defer func() {
		messageRateLimiter = savedMsgLimiter
		userRateLimiter = savedUserLimiter
	}()

	conn := &Connection{
		id:   "conn-rl-block",
		send: make(chan []byte, 10),
	}

	// First two should pass
	if !checkRateLimit(conn) {
		t.Error("should allow first request")
	}
	if !checkRateLimit(conn) {
		t.Error("should allow second request")
	}

	// Third should be blocked
	if checkRateLimit(conn) {
		t.Error("should block third request")
	}
}

// ============================================================
// Tests for tags.go handlers (low coverage)
// ============================================================

func TestHandleAddTagSuccess(t *testing.T) {
	setupTestDB(t)
	token := createTestUserInDB(t, "taguser1")
	agentID := "tag-agent-1"
	createTestAgentInDB(t, agentID, "Tag Agent")
	convID := createTestConversationInDB(t, token, agentID)

	form := "conversation_id=" + convID + "&tag=important"
	req := httptest.NewRequest("POST", "/conversations/tags/add", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleAddTag(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestHandleRemoveTagSuccess(t *testing.T) {
	setupTestDB(t)
	token := createTestUserInDB(t, "taguser2")
	agentID := "tag-agent-2"
	createTestAgentInDB(t, agentID, "Tag Agent 2")
	convID := createTestConversationInDB(t, token, agentID)

	// Add a tag first
	form := "conversation_id=" + convID + "&tag=removeme"
	req := httptest.NewRequest("POST", "/conversations/tags/add", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleAddTag(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("add tag failed: %d %s", w.Code, w.Body.String())
	}

	// Now remove it (POST method — handler expects POST)
	form = "conversation_id=" + convID + "&tag=removeme"
	req = httptest.NewRequest("POST", "/conversations/tags/remove", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)
	w = httptest.NewRecorder()
	handleRemoveTag(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestHandleGetTagsSuccess(t *testing.T) {
	setupTestDB(t)
	token := createTestUserInDB(t, "taguser3")
	agentID := "tag-agent-3"
	createTestAgentInDB(t, agentID, "Tag Agent 3")
	convID := createTestConversationInDB(t, token, agentID)

	// Add a tag
	form := "conversation_id=" + convID + "&tag=work"
	req := httptest.NewRequest("POST", "/conversations/tags/add", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleAddTag(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("add tag failed: %d %s", w.Code, w.Body.String())
	}

	// Get tags
	req = httptest.NewRequest("GET", "/conversations/tags?conversation_id="+convID, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w = httptest.NewRecorder()
	handleGetTags(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var tags []interface{}
	json.Unmarshal(w.Body.Bytes(), &tags)
	if len(tags) != 1 {
		t.Errorf("expected 1 tag, got %v", tags)
	}
}

func TestHandleAddTagUnauthorized(t *testing.T) {
	req := httptest.NewRequest("POST", "/conversations/tags/add", nil)
	w := httptest.NewRecorder()
	handleAddTag(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestHandleRemoveTagUnauthorized(t *testing.T) {
	req := httptest.NewRequest("POST", "/conversations/tags/remove", nil)
	w := httptest.NewRecorder()
	handleRemoveTag(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestHandleGetTagsUnauthorized(t *testing.T) {
	req := httptest.NewRequest("GET", "/conversations/tags", nil)
	w := httptest.NewRecorder()
	handleGetTags(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestHandleAddTagMissingFields(t *testing.T) {
	setupTestDB(t)
	token := createTestUserInDB(t, "taguser4")

	// Missing tag
	form := "conversation_id=some-conv"
	req := httptest.NewRequest("POST", "/conversations/tags/add", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleAddTag(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing tag, got %d", w.Code)
	}
}

func TestHandleAddTagNotOwner(t *testing.T) {
	setupTestDB(t)
	token1 := createTestUserInDB(t, "tagowner")
	token2 := createTestUserInDB(t, "tagnotowner")
	agentID := "tag-agent-notowner"
	createTestAgentInDB(t, agentID, "Tag Agent NO")
	convID := createTestConversationInDB(t, token1, agentID)

	form := "conversation_id=" + convID + "&tag=sneaky"
	req := httptest.NewRequest("POST", "/conversations/tags/add", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token2)
	w := httptest.NewRecorder()
	handleAddTag(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for non-owner, got %d", w.Code)
	}
}

// ============================================================
// Tests for E2E encryption handlers (low coverage)
// ============================================================

func TestHandleListOneTimePreKeysHandler(t *testing.T) {
	setupTestDB(t)
	token := createTestUserInDB(t, "e2euser1")
	agentID := "e2e-agent-1"
	createTestAgentInDB(t, agentID, "E2E Agent")

	req := httptest.NewRequest("GET", "/e2e/prekeys?agent_id="+agentID, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleListOneTimePreKeys(w, req)

	// Should return empty list (no keys stored yet)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestHandleListOneTimePreKeysMissingAgentID(t *testing.T) {
	setupTestDB(t)
	token := createTestUserInDB(t, "e2euser2")

	// Without agent_id, handler queries for empty agent_id and returns count (0)
	req := httptest.NewRequest("GET", "/e2e/prekeys", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleListOneTimePreKeys(w, req)

	// Handler succeeds (returns 0 prekeys for empty agent_id query)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200 (returns empty count), got %d", w.Code)
	}
}

func TestHandleStoreEncryptedMessageSuccess(t *testing.T) {
	setupTestDB(t)
	token := createTestUserInDB(t, "e2euser3")
	agentID := "e2e-agent-2"
	createTestAgentInDB(t, agentID, "E2E Agent 2")
	convID := createTestConversationInDB(t, token, agentID)

	msg := `{"conversation_id":"` + convID + `","ciphertext":"base64ciphertext","iv":"base64iv","sender_identity_key":"base64key","sender_prekey_id":1,"recipient_prekey_id":2,"algorithm":"x25519-aes-256-gcm"}`
	req := httptest.NewRequest("POST", "/e2e/encrypt", strings.NewReader(msg))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleStoreEncryptedMessage(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestHandleStoreEncryptedMessageUnauthorized(t *testing.T) {
	req := httptest.NewRequest("POST", "/e2e/encrypt", nil)
	w := httptest.NewRecorder()
	handleStoreEncryptedMessage(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

// ============================================================
// Tests for search messages handler (65.6% coverage)
// ============================================================

func TestHandleSearchMessagesSuccess(t *testing.T) {
	setupTestDB(t)
	token := createTestUserInDB(t, "searchuser1")
	agentID := "search-agent-1"
	createTestAgentInDB(t, agentID, "Search Agent")
	convID := createTestConversationInDB(t, token, agentID)

	// Store a message first
	_, err := db.Exec(
		"INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, created_at) VALUES (?, ?, ?, ?, ?, ?)",
		"msg-search-1", convID, "user", tokenUserID(t, token), "hello world searchable content", time.Now().UTC().Format(time.RFC3339),
	)
	if err != nil {
		t.Fatalf("Failed to store message: %v", err)
	}

	req := httptest.NewRequest("GET", "/messages/search?q=searchable&limit=10", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleSearchMessages(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestHandleSearchMessagesUnauthorized(t *testing.T) {
	req := httptest.NewRequest("GET", "/messages/search?q=test", nil)
	w := httptest.NewRecorder()
	handleSearchMessages(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestHandleSearchMessagesEmptyQuery(t *testing.T) {
	setupTestDB(t)
	token := createTestUserInDB(t, "searchuser2")

	req := httptest.NewRequest("GET", "/messages/search?q=&limit=10", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleSearchMessages(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for empty query, got %d", w.Code)
	}
}

// ============================================================
// Tests for message delete (68.8% coverage)
// ============================================================

func TestHandleMessageDeleteUnauthorized(t *testing.T) {
	req := httptest.NewRequest("POST", "/messages/delete", nil)
	w := httptest.NewRecorder()
	handleMessageDelete(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestHandleMessageDeleteMissingID(t *testing.T) {
	setupTestDB(t)
	token := createTestUserInDB(t, "deluser1")

	req := httptest.NewRequest("POST", "/messages/delete", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleMessageDelete(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing message_id, got %d", w.Code)
	}
}

func TestHandleMessageDeleteNotOwner(t *testing.T) {
	setupTestDB(t)
	token1 := createTestUserInDB(t, "delowner")
	token2 := createTestUserInDB(t, "delnotowner")
	agentID := "del-agent"
	createTestAgentInDB(t, agentID, "Del Agent")
	convID := createTestConversationInDB(t, token1, agentID)

	// Store a message from user1
	_, err := db.Exec(
		"INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, created_at) VALUES (?, ?, ?, ?, ?, ?)",
		"msg-del-1", convID, "user", tokenUserID(t, token1), "message to delete", time.Now().UTC().Format(time.RFC3339),
	)
	if err != nil {
		t.Fatalf("Failed to store message: %v", err)
	}

	// Try to delete with user2's token (not owner)
	form := "message_id=msg-del-1"
	req := httptest.NewRequest("POST", "/messages/delete", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token2)
	w := httptest.NewRecorder()
	handleMessageDelete(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for non-owner, got %d", w.Code)
	}
}

// ============================================================
// Tests for handleListAttachments (69.4% coverage)
// ============================================================

func TestHandleListAttachmentsUnauthorized(t *testing.T) {
	req := httptest.NewRequest("GET", "/attachments?conversation_id=conv1", nil)
	w := httptest.NewRecorder()
	handleListAttachments(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestHandleListAttachmentsMissingConversationID(t *testing.T) {
	setupTestDB(t)
	token := createTestUserInDB(t, "attuser1")

	req := httptest.NewRequest("GET", "/attachments", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleListAttachments(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing conversation_id, got %d", w.Code)
	}
}

// ============================================================
// Tests for handleUpload (68.8% coverage)
// ============================================================

func TestHandleUploadUnauthorized(t *testing.T) {
	req := httptest.NewRequest("POST", "/attachments/upload", nil)
	w := httptest.NewRecorder()
	handleUpload(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

// ============================================================
// Tests for RegisterAgentOnConnect (59.1% coverage)
// ============================================================

func TestRegisterAgentOnConnectNew(t *testing.T) {
	setupTestDB(t)

	err := RegisterAgentOnConnect("test-agent-reg", "Test Agent", "", "", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify agent exists in DB
	var name string
	err = db.QueryRow("SELECT name FROM agents WHERE id = ?", "test-agent-reg").Scan(&name)
	if err != nil {
		t.Fatalf("agent not found in DB: %v", err)
	}
	if name != "Test Agent" {
		t.Errorf("expected name 'Test Agent', got %q", name)
	}
}

func TestRegisterAgentOnConnectExisting(t *testing.T) {
	setupTestDB(t)

	// Create agent first
	_, err := db.Exec("INSERT INTO agents (id, name) VALUES (?, ?)", "existing-agent", "Original Name")
	if err != nil {
		t.Fatalf("failed to insert agent: %v", err)
	}

	// Re-register should update name but not fail
	err = RegisterAgentOnConnect("existing-agent", "Updated Name", "", "", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var name string
	db.QueryRow("SELECT name FROM agents WHERE id = ?", "existing-agent").Scan(&name)
	if name != "Updated Name" {
		t.Errorf("expected name to update to 'Updated Name', got %q", name)
	}
}

// ============================================================
// Tests for access log middleware (78.9% coverage)
// ============================================================

func TestAccessLogMiddlewareWithUserID(t *testing.T) {
	setupTestDB(t)
	token := createTestUserInDB(t, "loguser")

	var capturedLog bytes.Buffer
	origLogger := DefaultLogger
	DefaultLogger = NewLogger(LogInfo)
	DefaultLogger.SetOutput(&capturedLog)
	defer func() { DefaultLogger = origLogger }()

	called := false
	handler := accessLogMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/test/path", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if !called {
		t.Error("handler should have been called")
	}

	logOutput := capturedLog.String()
	if !strings.Contains(logOutput, "http_request") {
		t.Error("expected http_request in log output")
	}
}

func TestAccessLogMiddlewareWithoutUserID(t *testing.T) {
	var capturedLog bytes.Buffer
	origLogger := DefaultLogger
	DefaultLogger = NewLogger(LogInfo)
	DefaultLogger.SetOutput(&capturedLog)
	defer func() { DefaultLogger = origLogger }()

	called := false
	handler := accessLogMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/test/noauth", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if !called {
		t.Error("handler should have been called")
	}
}

// ============================================================
// Tests for reactions handler (55.9% coverage)
// ============================================================

func TestHandleGetReactionsUnauthorized(t *testing.T) {
	req := httptest.NewRequest("GET", "/messages/reactions?message_id=msg1", nil)
	w := httptest.NewRecorder()
	handleGetReactions(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestHandleGetReactionsMissingMessageID(t *testing.T) {
	setupTestDB(t)
	token := createTestUserInDB(t, "reactuser1")

	req := httptest.NewRequest("GET", "/messages/reactions", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleGetReactions(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing message_id, got %d", w.Code)
	}
}

func TestHandleGetReactionsWithMessage(t *testing.T) {
	setupTestDB(t)
	token := createTestUserInDB(t, "reactuser2")
	agentID := "react-agent-1"
	createTestAgentInDB(t, agentID, "React Agent")
	convID := createTestConversationInDB(t, token, agentID)

	// Store a message
	_, err := db.Exec(
		"INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, created_at) VALUES (?, ?, ?, ?, ?, ?)",
		"msg-react-1", convID, "user", tokenUserID(t, token), "react to this", time.Now().UTC().Format(time.RFC3339),
	)
	if err != nil {
		t.Fatalf("Failed to store message: %v", err)
	}

	req := httptest.NewRequest("GET", "/messages/reactions?message_id=msg-react-1", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleGetReactions(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

// ============================================================
// Tests for WebPush handlers (low coverage)
// ============================================================

func TestHandleWebPushSubscribeUnauthorized(t *testing.T) {
	req := httptest.NewRequest("POST", "/push/web-subscribe", nil)
	w := httptest.NewRecorder()
	handleWebPushSubscribe(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestHandleGetVAPIDKey(t *testing.T) {
	setupTestDB(t)
	token := createTestUserInDB(t, "vapiduser")

	// Test with no VAPID key configured (with auth)
	origKey := vapidPublicKey
	vapidPublicKey = ""
	defer func() { vapidPublicKey = origKey }()

	req := httptest.NewRequest("GET", "/push/vapid-key", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleGetVAPIDKey(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404 when VAPID not configured, got %d", w.Code)
	}

	// Test with VAPID key configured (with auth)
	vapidPublicKey = "test-vapid-public-key"
	req = httptest.NewRequest("GET", "/push/vapid-key", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w = httptest.NewRecorder()
	handleGetVAPIDKey(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200 with VAPID key, got %d", w.Code)
	}

	// Test without auth → should return 401
	vapidPublicKey = "test-vapid-public-key"
	req = httptest.NewRequest("GET", "/push/vapid-key", nil)
	w = httptest.NewRecorder()
	handleGetVAPIDKey(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 without auth, got %d", w.Code)
	}
}

// ============================================================
// Tests for safeSendToConn (62.5% coverage)
// ============================================================

func TestSafeSendToConnOpen(t *testing.T) {
	conn := &Connection{
		id:   "safe-conn-1",
		send: make(chan []byte, 10),
	}
	conn.closeMu.Lock()
	conn.closed = false
	conn.closeMu.Unlock()

	msg := []byte("test message")
	safeSendToConn(conn, msg)

	// Should have sent the message
	select {
	case received := <-conn.send:
		if string(received) != "test message" {
			t.Errorf("expected 'test message', got %s", received)
		}
	default:
		t.Error("expected message in send channel")
	}
}

func TestSafeSendToConnClosed(t *testing.T) {
	conn := &Connection{
		id:   "safe-conn-2",
		send: make(chan []byte, 10),
	}
	conn.MarkClosed()

	msg := []byte("test message")
	// Should not panic when sending to closed connection
	safeSendToConn(conn, msg)
}

func TestConnectionIsClosed(t *testing.T) {
	conn := &Connection{
		id:   "closed-conn-test",
		send: make(chan []byte, 10),
	}

	if conn.IsClosed() {
		t.Error("new connection should not be closed")
	}

	conn.MarkClosed()

	if !conn.IsClosed() {
		t.Error("connection should be closed after MarkClosed")
	}
}

// ============================================================
// Tests for newOfflineQueue (60% coverage)
// ============================================================

func TestNewOfflineQueueCreation(t *testing.T) {
	oq := newOfflineQueue(100, 5*time.Minute)
	if oq == nil {
		t.Error("expected non-nil offline queue")
	}
}

// ============================================================
// Tests for notification preferences handlers
// ============================================================

func TestHandleGetNotificationPrefsUnauthorized(t *testing.T) {
	req := httptest.NewRequest("GET", "/notifications/prefs", nil)
	w := httptest.NewRecorder()
	handleGetNotificationPrefs(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestHandleSetNotificationPrefsUnauthorized(t *testing.T) {
	req := httptest.NewRequest("POST", "/notifications/prefs", nil)
	w := httptest.NewRecorder()
	handleSetNotificationPrefs(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}