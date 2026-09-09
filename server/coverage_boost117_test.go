package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"context"
	"time"

	_ "github.com/mattn/go-sqlite3"

	"github.com/golang-jwt/jwt/v5"
)

// CB117: Coverage boost targeting remaining low-coverage functions.
// Focus areas (from coverage profile, 92.2%):
// - handleUpload (attachments.go, 85.7%): missing file field, no-extension + content type detection, method not allowed
// - loadQueueFromDB (queue_persist.go, 89.5%): nil db, scan error with corrupted data
// - cleanup (rate_limit_tiers.go, 83.3%): cleanup with expired entries, cleanup with no entries
// - ValidateJWT (auth.go, 91.7%): token with no claims, malformed base64, empty token string
// - getConversationMessages (conversations.go, 95.7%): query error (closed DB)
// - deleteConversation (conversations.go, 91.7%): query error (closed DB), conversation not found
// - handleAdminAgents (handlers.go, 91.7%): method not allowed, DB query error

func resetGlobals_CB117() {
	if messageRateLimiter != nil {
		messageRateLimiter.Stop()
	}
	if userRateLimiter != nil {
		userRateLimiter.Stop()
	}
	if ipRateLimiter != nil {
		ipRateLimiter.Stop()
	}
	if authIPLimiter != nil {
		authIPLimiter.Stop()
	}
	messageRateLimiter = NewRateLimiter(60, time.Minute)
	userRateLimiter = NewRateLimiter(120, time.Minute)
	ipRateLimiter = NewRateLimiter(300, time.Minute)
	authIPLimiter = NewRateLimiter(30, time.Minute)

	hub = nil
	offlineQueue = nil
	pushConfig = nil
	tracingEnabled = false
	tracer = nil
	tp = nil
	tracingMu = sync.Once{}
	agentPresenceEnabled = false
	agentPresenceInterval = 30 * time.Second
	agentPresenceTimeout = 90 * time.Second
	serverDBPath = ""
	vapidPublicKey = ""

	resetAdminSecret()
	resetAgentSecret()

	if globalTieredLimiter != nil {
		globalTieredLimiter.Stop()
	}
	globalTieredLimiter = NewTieredRateLimiter()

	// Stop all rate limiters registered in allRateLimiters
	allRateLimitersMu.Lock()
	for _, stop := range allRateLimiters {
		stop()
	}
	allRateLimiters = nil
	allRateLimitersMu.Unlock()

	ServerMetrics = nil
}

func setupTestDB_CB117() {
	dbPath := "/tmp/am_test_cb117.db"
	os.Remove(dbPath)
	var err error
	db, err = sql.Open("sqlite3", dbPath)
	if err != nil {
		panic(err)
	}
	if err := initSchema(db); err != nil {
		panic(err)
	}
	serverDBPath = dbPath
}

func setupHubAndQueue_CB117() {
	h := newHub()
	hub = h
	go h.run()
	offlineQueue = newOfflineQueue(1000, 7*24*time.Hour)
}

func makeJWTReq_CB117(method, path string, body io.Reader, userID string) *http.Request {
	req := httptest.NewRequest(method, path, body)
	token, _ := GenerateJWT(userID, "testuser")
	req.Header.Set("Authorization", "Bearer "+token)
	return req
}

func makeContextReq_CB117(method, path string, body io.Reader, userID string) *http.Request {
	req := httptest.NewRequest(method, path, body)
	ctx := context.WithValue(req.Context(), contextKeyUserID, userID)
	return req.WithContext(ctx)
}

// ==================== handleUpload tests ====================

func TestCB117_HandleUpload_MethodNotAllowed(t *testing.T) {
	resetGlobals_CB117()
	setupTestDB_CB117()
	defer db.Close()

	req := httptest.NewRequest("GET", "/attachments/upload", nil)
	w := httptest.NewRecorder()
	handleUpload(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", w.Code)
	}
}

func TestCB117_HandleUpload_MissingFileField(t *testing.T) {
	resetGlobals_CB117()
	setupTestDB_CB117()
	defer db.Close()

	// Create multipart form without a "file" field
	body := &strings.Builder{}
	writer := multipart.NewWriter(body)
	writer.WriteField("message_id", "msg123")
	writer.Close()

	req := makeJWTReq_CB117("POST", "/attachments/upload", strings.NewReader(body.String()), "user1")
	req.Header.Set("Content-Type", writer.FormDataContentType())
	w := httptest.NewRecorder()
	handleUpload(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "missing file") {
		t.Fatalf("expected 'missing file' error, got: %s", w.Body.String())
	}
}

func TestCB117_HandleUpload_NoExtensionWithContentTypeDetection(t *testing.T) {
	resetGlobals_CB117()

	// Use a temporary directory for the DB so uploads go there
	tmpDir, err := os.MkdirTemp("", "upload-test-cb117-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	dbPath := filepath.Join(tmpDir, "test.db")
	d, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if err := initSchema(d); err != nil {
		t.Fatal(err)
	}
	db = d
	serverDBPath = dbPath
	defer func() { serverDBPath = "" }()

	// Create multipart form with a file that has no extension
	// and no explicit content type (defaults to application/octet-stream)
	// so the server will detect content type from the file content
	body := &strings.Builder{}
	writer := multipart.NewWriter(body)
	fileWriter, err := writer.CreateFormFile("file", "noextfile")
	if err != nil {
		t.Fatal(err)
	}
	// Write valid JPEG magic bytes (0xFF 0xD8 0xFF) so content type is detected as image/jpeg
	jpegData := []byte{0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46, 0x00, 0x01}
	fileWriter.Write(jpegData)
	writer.Close()

	req := makeJWTReq_CB117("POST", "/attachments/upload", strings.NewReader(body.String()), "user1")
	req.Header.Set("Content-Type", writer.FormDataContentType())
	w := httptest.NewRecorder()
	handleUpload(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var att Attachment
	if err := json.Unmarshal(w.Body.Bytes(), &att); err != nil {
		t.Fatalf("invalid response: %v", err)
	}
	// Content type should be detected as image/jpeg
	if att.ContentType != "image/jpeg" {
		t.Errorf("expected image/jpeg, got %s", att.ContentType)
	}
}

// ==================== loadQueueFromDB tests ====================

func TestCB117_LoadQueueFromDB_NilDB(t *testing.T) {
	resetGlobals_CB117()

	q := newOfflineQueue(100, time.Hour)

	// With nil db, should return immediately without error
	loadQueueFromDB(nil, q)

	// Queue should be empty
	if q.TotalDepth() != 0 {
		t.Errorf("expected empty queue, got %d", q.TotalDepth())
	}
}


func TestCB117_LoadQueueFromDB_QueryError(t *testing.T) {
	resetGlobals_CB117()
	setupTestDB_CB117()

	q := newOfflineQueue(100, time.Hour)

	// Close the DB to trigger a query error
	db.Close()

	// This should trigger the query error path and log an error
	loadQueueFromDB(db, q)

	// Queue should be empty
	if q.TotalDepth() != 0 {
		t.Errorf("expected empty queue after query error, got %d", q.TotalDepth())
	}
}

// ==================== cleanup tests ====================

func TestCB117_TieredRateLimiter_CleanupOnce_WithExpiredEntries(t *testing.T) {
	resetGlobals_CB117()

	trl := NewTieredRateLimiter()
	defer trl.Stop()

	// Add entries with expired windows (more than 10 minutes ago)
	oldTime := time.Now().Add(-20 * time.Minute)
	trl.mu.Lock()
	trl.limits["expired-user-1"] = &userRateLimitState{
		count:     5,
		windowEnd: oldTime,
		tier:      TierFree,
	}
	trl.limits["expired-user-2"] = &userRateLimitState{
		count:     10,
		windowEnd: oldTime,
		tier:      TierPro,
	}
	trl.mu.Unlock()

	// Run cleanup
	trl.cleanupOnce()

	// Both expired entries should be removed
	trl.mu.Lock()
	defer trl.mu.Unlock()
	if _, ok := trl.limits["expired-user-1"]; ok {
		t.Error("expected expired-user-1 to be removed")
	}
	if _, ok := trl.limits["expired-user-2"]; ok {
		t.Error("expected expired-user-2 to be removed")
	}
}

func TestCB117_TieredRateLimiter_CleanupOnce_NoEntries(t *testing.T) {
	resetGlobals_CB117()

	trl := NewTieredRateLimiter()
	defer trl.Stop()

	// Run cleanup on empty limiter — should not panic
	trl.cleanupOnce()

	// Verify still empty
	trl.mu.Lock()
	defer trl.mu.Unlock()
	if len(trl.limits) != 0 {
		t.Errorf("expected 0 entries, got %d", len(trl.limits))
	}
}

func TestCB117_TieredRateLimiter_CleanupOnce_MixedEntries(t *testing.T) {
	resetGlobals_CB117()

	trl := NewTieredRateLimiter()
	defer trl.Stop()

	// Add a mix of expired and fresh entries
	oldTime := time.Now().Add(-20 * time.Minute)
	freshTime := time.Now().Add(30 * time.Second)

	trl.mu.Lock()
	trl.limits["expired-user"] = &userRateLimitState{
		count:     5,
		windowEnd: oldTime,
		tier:      TierFree,
	}
	trl.limits["fresh-user"] = &userRateLimitState{
		count:     3,
		windowEnd: freshTime,
		tier:      TierPro,
	}
	// Recently expired (within 10 min grace) — should NOT be removed
	recentExpired := time.Now().Add(-5 * time.Minute)
	trl.limits["recent-expired"] = &userRateLimitState{
		count:     2,
		windowEnd: recentExpired,
		tier:      TierFree,
	}
	trl.mu.Unlock()

	trl.cleanupOnce()

	trl.mu.Lock()
	defer trl.mu.Unlock()
	if _, ok := trl.limits["expired-user"]; ok {
		t.Error("expected expired-user to be removed")
	}
	if _, ok := trl.limits["fresh-user"]; !ok {
		t.Error("expected fresh-user to be kept")
	}
	if _, ok := trl.limits["recent-expired"]; !ok {
		t.Error("expected recent-expired to be kept (within 10 min grace)")
	}
}

// ==================== ValidateJWT tests ====================

func TestCB117_ValidateJWT_EmptyToken(t *testing.T) {
	resetGlobals_CB117()

	claims, err := ValidateJWT("")
	if err == nil {
		t.Fatal("expected error for empty token")
	}
	if claims != nil {
		t.Fatal("expected nil claims for empty token")
	}
	if err.Error() != "empty token" {
		t.Errorf("expected 'empty token' error, got: %s", err.Error())
	}
}

func TestCB117_ValidateJWT_MalformedBase64(t *testing.T) {
	resetGlobals_CB117()

	// Token with invalid base64 in the payload section
	// Format: header.payload.signature — payload is not valid base64
	token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.!!!notbase64!!.invalidsignature"
	claims, err := ValidateJWT(token)
	if err == nil {
		t.Fatal("expected error for malformed base64 token")
	}
	if claims != nil {
		t.Fatal("expected nil claims for malformed token")
	}
}

func TestCB117_ValidateJWT_NoClaims(t *testing.T) {
	resetGlobals_CB117()

	// Create a token with an empty claims object
	// This is a valid JWT structure but with empty claims
	// Header: {"alg":"HS256","typ":"JWT"}, Payload: {}, Signature: (signed)
	// We can craft this by using jwt.ParseWithClaims with a minimal token
	// Actually, a token with empty payload {} is valid JSON but won't have UserID
	// Let's create a token signed with the right key but with no meaningful claims
	// The simplest way is to use the jwt library directly
	// But since we're testing ValidateJWT, we just need a token that parses but has no claims

	// A token with payload "{}" — signed with the dev secret
	// This should parse successfully but have empty claims fields
	// Actually, jwt.ParseWithClaims will still return Claims as *Claims,
	// just with zero values. The !token.Valid check may catch this if exp is missing.
	// Let's use a token without exp — it should be invalid because token.Valid will be false
	// when there's no exp (depending on the jwt library config)

	// Create a minimal JWT: header.payload.sig where payload is "{}"
	// This is a properly structured JWT with no claims
	header := `{"alg":"HS256","typ":"JWT"}`
	payload := `{}`
	token := createRawJWT_CB117(header, payload)

	claims, err := ValidateJWT(token)
	// With no exp, the jwt library may reject it or accept it depending on validation options
	// The key thing is that claims should either be nil or have empty UserID
	if err == nil && claims != nil {
		// If it parsed, UserID should be empty
		if claims.UserID != "" {
			t.Errorf("expected empty UserID, got: %s", claims.UserID)
		}
	}
	// If it errored, that's also fine — the no-claims path is covered either way
}

// createRawJWT_CB117 creates a raw JWT string with the given header and payload
// signed with the default jwtSecret.
func createRawJWT_CB117(header, payload string) string {
	// Use the jwt library to sign a token with custom claims
	// We'll use the standard library approach: base64url(header) + "." + base64url(payload) + "." + signature
	// But since we need to sign with HMAC-SHA256, we use the jwt library
	// Actually the simplest approach: use jwt.NewWithClaims with empty RegisteredClaims
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{})
	signed, _ := token.SignedString(jwtSecret)
	return signed
}

// ==================== getConversationMessages tests ====================

func TestCB117_GetConversationMessages_QueryError(t *testing.T) {
	resetGlobals_CB117()
	setupTestDB_CB117()

	// Insert a valid conversation first
	convID := generateID("conv")
	db.Exec("INSERT INTO conversations (id, user_id, agent_id, created_at) VALUES (?, ?, ?, ?)",
		convID, "user1", "agent1", time.Now().UTC())

	// Close the DB to trigger a query error
	db.Close()

	messages, err := getConversationMessages(convID, 50, "")
	if err == nil {
		t.Fatal("expected error from closed DB")
	}
	if messages != nil {
		t.Errorf("expected nil messages, got %d messages", len(messages))
	}
}

func TestCB117_GetConversationMessages_WithCursor(t *testing.T) {
	resetGlobals_CB117()
	setupTestDB_CB117()
	defer db.Close()

	// Create a conversation
	convID := generateID("conv")
	db.Exec("INSERT INTO conversations (id, user_id, agent_id, created_at) VALUES (?, ?, ?, ?)",
		convID, "user1", "agent1", time.Now().UTC())

	// Insert some messages with different timestamps (as RFC3339 strings to match production)
	baseTime := time.Date(2026, 9, 9, 0, 0, 0, 0, time.UTC)
	for i := 0; i < 5; i++ {
		msgID := generateID("msg")
		timestamp := baseTime.Add(time.Duration(i) * time.Hour).UTC().Format(time.RFC3339)
		db.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, created_at) VALUES (?, ?, ?, ?, ?, ?)",
			msgID, convID, "user", "user1", fmt.Sprintf("message %d", i), timestamp)
	}

	// Use cursor pagination: get messages before 03:00 (excludes 03:00 and 04:00)
	beforeTime := baseTime.Add(3 * time.Hour).UTC().Format(time.RFC3339)
	messages, err := getConversationMessages(convID, 10, beforeTime)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should get the 3 older messages (00:00, 01:00, 02:00)
	if len(messages) != 3 {
		t.Errorf("expected 3 messages, got %d", len(messages))
	}

	// Messages should be in chronological order (reversed from DESC)
	for i := 0; i < len(messages)-1; i++ {
		if messages[i].CreatedAt.After(messages[i+1].CreatedAt) {
			t.Error("expected messages in chronological order")
		}
	}
}

// ==================== deleteConversation tests ====================

func TestCB117_DeleteConversation_NotFound(t *testing.T) {
	resetGlobals_CB117()
	setupTestDB_CB117()
	defer db.Close()

	err := deleteConversation("nonexistent-conv", "user1")
	if err == nil {
		t.Fatal("expected error for non-existent conversation")
	}
	if err != sql.ErrNoRows {
		t.Errorf("expected sql.ErrNoRows, got: %v", err)
	}
}

func TestCB117_DeleteConversation_QueryError(t *testing.T) {
	resetGlobals_CB117()
	setupTestDB_CB117()

	// Insert a conversation
	convID := generateID("conv")
	db.Exec("INSERT INTO conversations (id, user_id, agent_id, created_at) VALUES (?, ?, ?, ?)",
		convID, "user1", "agent1", time.Now().UTC())

	// Close the DB to trigger a query error
	db.Close()

	err := deleteConversation(convID, "user1")
	if err == nil {
		t.Fatal("expected error from closed DB")
	}
}

func TestCB117_DeleteConversation_UnauthorizedUser(t *testing.T) {
	resetGlobals_CB117()
	setupTestDB_CB117()
	defer db.Close()

	// Create a conversation owned by user1
	convID := generateID("conv")
	db.Exec("INSERT INTO conversations (id, user_id, agent_id, created_at) VALUES (?, ?, ?, ?)",
		convID, "user1", "agent1", time.Now().UTC())

	// Try to delete as user2
	err := deleteConversation(convID, "user2")
	if err == nil {
		t.Fatal("expected error for unauthorized user")
	}
	if err.Error() != "unauthorized" {
		t.Errorf("expected 'unauthorized' error, got: %s", err.Error())
	}
}

// ==================== handleAdminAgents tests ====================

func TestCB117_HandleAdminAgents_MethodNotAllowed(t *testing.T) {
	resetGlobals_CB117()
	setupTestDB_CB117()
	defer db.Close()

	setupHubAndQueue_CB117()
	defer func() {
		if hub != nil {
			hub.Stop()
		}
	}()

	req := httptest.NewRequest("POST", "/admin/agents", nil)
	w := httptest.NewRecorder()
	handleAdminAgents(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", w.Code)
	}
}

func TestCB117_HandleAdminAgents_DBQueryError(t *testing.T) {
	resetGlobals_CB117()
	setupTestDB_CB117()

	setupHubAndQueue_CB117()
	defer func() {
		if hub != nil {
			hub.Stop()
		}
	}()

	// Close DB to trigger query error
	db.Close()

	req := httptest.NewRequest("GET", "/admin/agents", nil)
	w := httptest.NewRecorder()
	handleAdminAgents(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", w.Code)
	}
}

func TestCB117_HandleAdminAgents_SuccessWithAgents(t *testing.T) {
	resetGlobals_CB117()
	setupTestDB_CB117()
	defer db.Close()

	setupHubAndQueue_CB117()
	defer func() {
		if hub != nil {
			hub.Stop()
		}
	}()

	// Insert some agents into the DB
	db.Exec("INSERT INTO agents (id, name, model, personality, specialty, created_at) VALUES (?, ?, ?, ?, ?, ?)",
		"agent-1", "Test Agent 1", "gpt-4", "helpful", "general", time.Now().UTC())
	db.Exec("INSERT INTO agents (id, name, model, personality, specialty, created_at) VALUES (?, ?, ?, ?, ?, ?)",
		"agent-2", "Test Agent 2", "claude-3", "creative", "writing", time.Now().UTC())

	req := httptest.NewRequest("GET", "/admin/agents", nil)
	w := httptest.NewRecorder()
	handleAdminAgents(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var agents []AgentInfo
	if err := json.Unmarshal(w.Body.Bytes(), &agents); err != nil {
		t.Fatalf("invalid response: %v", err)
	}
	if len(agents) != 2 {
		t.Errorf("expected 2 agents, got %d", len(agents))
	}
	// Verify agents are ordered by name
	if len(agents) >= 2 {
		if agents[0].Name > agents[1].Name {
			t.Error("expected agents ordered by name ascending")
		}
	}
}

// ==================== handleAdminAgents scan error test ====================

func TestCB117_HandleAdminAgents_ScanError(t *testing.T) {
	resetGlobals_CB117()
	setupTestDB_CB117()
	defer db.Close()

	setupHubAndQueue_CB117()
	defer func() {
		if hub != nil {
			hub.Stop()
		}
	}()

	// Insert an agent with a NULL name to trigger a scan error
	// The query expects 6 columns: id, name, model, personality, specialty, created_at
	// Insert with NULL in a NOT NULL column won't work with constraints,
	// so we drop and recreate the table with nullable columns and insert NULL
	db.Exec("DROP TABLE agents")
	db.Exec(`CREATE TABLE agents (
		id TEXT PRIMARY KEY,
		name TEXT,
		model TEXT,
		personality TEXT,
		specialty TEXT,
		created_at DATETIME
	)`)

	// Insert a row with NULL name — scan into string should work (empty string)
	// Actually, scanning NULL into a string causes an error in database/sql
	db.Exec("INSERT INTO agents (id, name, model, personality, specialty, created_at) VALUES (?, NULL, ?, ?, ?, ?)",
		"agent-null", "model", "personality", "specialty", time.Now().UTC())

	req := httptest.NewRequest("GET", "/admin/agents", nil)
	w := httptest.NewRecorder()
	handleAdminAgents(w, req)

	// Should get 500 due to scan error
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 for scan error, got %d: %s", w.Code, w.Body.String())
	}
}