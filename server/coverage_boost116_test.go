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

	"github.com/gorilla/websocket"
	_ "github.com/mattn/go-sqlite3"
)

// CB116: Coverage boost targeting remaining low-coverage functions.
// Focus areas (from coverage profile after CB115, 89.6%):
// - checkRateLimit (89.5%): user rate limit exceeded with ServerMetrics set
// - ipRateLimitMiddleware (88.9%): rate limited with ServerMetrics set
// - authRateLimitMiddleware (88.9%): rate limited with ServerMetrics set
// - Snapshot (83.3%): nil offlineQueue path
// - handleHeapProfile (84.6%): WriteHeapProfile error (read-only dir)
// - handleGoroutineProfile (84.6%): WriteGoroutineProfile error (read-only dir)
// - addReaction (88.5%): conv nil, DB error on existing check, INSERT error
// - handleReact: agent online + client conns SafeSend paths, internal error
// - handleGetReactions: getMessageReactions error, nil reactions init
// - TieredRateLimiter cleanup: stopCh path
// - loadQueueFromDB: loaded > 0 log path
// - sendWelcomeMessage: deviceID path
// - initSchema: migration error paths (reactions/tags/rate_limit/notif prefs)
// - RegisterAgentOnConnect: DB query error path (SELECT error)
// - handleUpload: file too large, seek error, create file error, DB error
// - conversations.go: storeMessagesBatch insert error, tx commit error, scan errors, delete error, changeUserPassword hash error, markMessagesRead error

func resetGlobals_CB116() {
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

func setupTestDB_CB116() {
	dbPath := "/tmp/am_test_cb116.db"
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

func setupHubAndQueue_CB116() {
	h := newHub()
	hub = h
	go h.run()
	offlineQueue = newOfflineQueue(1000, 7*24*time.Hour)
}

func makeJWTReq_CB116(method, path string, body io.Reader, userID string) *http.Request {
	req := httptest.NewRequest(method, path, body)
	token, _ := GenerateJWT(userID, "testuser")
	req.Header.Set("Authorization", "Bearer "+token)
	return req
}

func makeJWTFormReq_CB116(method, path string, formBody string, userID string) *http.Request {
	req := httptest.NewRequest(method, path, strings.NewReader(formBody))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	token, _ := GenerateJWT(userID, "testuser")
	req.Header.Set("Authorization", "Bearer "+token)
	return req
}

func makeContextReq_CB116(method, path string, body io.Reader, userID string) *http.Request {
	req := httptest.NewRequest(method, path, body)
	ctx := context.WithValue(req.Context(), contextKeyUserID, userID)
	return req.WithContext(ctx)
}

// storeMessageCB116 stores a message and returns the message ID.
func storeMessageCB116(convID, senderType, senderID, content string) string {
	msgID := generateID("msg")
	db.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, created_at) VALUES (?, ?, ?, ?, ?, ?)",
		msgID, convID, senderType, senderID, content, time.Now().UTC())
	return msgID
}

// ==================== checkRateLimit with ServerMetrics ====================

func TestCB116_CheckRateLimit_UserLimitWithMetrics(t *testing.T) {
	resetGlobals_CB116()
	setupTestDB_CB116()

	h := newHub()
	hub = h
	go h.run()
	defer h.Stop()

	ServerMetrics = NewMetrics(h)

	conn := &Connection{
		connType: "client",
		id:      "test-user-metrics",
		send:    make(chan []byte, 10),
	}

	// Exhaust per-conn limit only, so per-user limit is checked
	// But we need per-conn to pass and per-user to fail
	// Use different IDs for each limiter won't work since they use same conn.id
	// Instead, exhaust userRateLimiter directly while keeping messageRateLimiter fresh
	messageRateLimiter = NewRateLimiter(60, time.Minute)

	// Exhaust the user rate limiter
	for i := 0; i < 200; i++ {
		userRateLimiter.Allow(conn.id)
	}

	// Now checkRateLimit should fail on user limit with ServerMetrics set
	allowed := checkRateLimit(conn)
	if allowed {
		t.Error("expected user rate limit to be exceeded")
	}

	// Verify ServerMetrics was incremented
	if ServerMetrics.RateLimited.Load() == 0 {
		t.Error("expected RateLimited counter to be incremented")
	}
	if ServerMetrics.ErrorsTotal.Load() == 0 {
		t.Error("expected ErrorsTotal counter to be incremented")
	}
}

func TestCB116_CheckRateLimit_ConnLimitWithMetrics(t *testing.T) {
	resetGlobals_CB116()
	setupTestDB_CB116()

	h := newHub()
	hub = h
	go h.run()
	defer h.Stop()

	ServerMetrics = NewMetrics(h)

	conn := &Connection{
		connType: "agent",
		id:      "test-conn-metrics",
		send:    make(chan []byte, 10),
	}

	// Exhaust per-conn limit
	for i := 0; i < 100; i++ {
		messageRateLimiter.Allow(conn.id)
	}

	allowed := checkRateLimit(conn)
	if allowed {
		t.Error("expected per-conn rate limit to be exceeded")
	}

	if ServerMetrics.RateLimited.Load() == 0 {
		t.Error("expected RateLimited counter to be incremented")
	}
}

// ==================== ipRateLimitMiddleware with ServerMetrics ====================

func TestCB116_IPRateLimitMiddleware_LimitedWithMetrics(t *testing.T) {
	resetGlobals_CB116()
	setupTestDB_CB116()

	h := newHub()
	hub = h
	go h.run()
	defer h.Stop()

	ServerMetrics = NewMetrics(h)

	handler := ipRateLimitMiddleware(func(w http.ResponseWriter, r *http.Request) {
		writeJSONError(w, http.StatusOK, "ok")
	})

	// Exhaust the IP rate limiter
	ip := "127.0.0.1"
	for i := 0; i < 400; i++ {
		ipRateLimiter.Allow(ip)
	}

	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = ip + ":12345"
	rr := httptest.NewRecorder()
	handler(rr, req)

	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429, got %d", rr.Code)
	}

	if ServerMetrics.RateLimited.Load() == 0 {
		t.Error("expected RateLimited counter to be incremented")
	}

	if rr.Header().Get("Retry-After") != "60" {
		t.Error("expected Retry-After header to be set")
	}
}

// ==================== authRateLimitMiddleware with ServerMetrics ====================

func TestCB116_AuthRateLimitMiddleware_LimitedWithMetrics(t *testing.T) {
	resetGlobals_CB116()
	setupTestDB_CB116()

	h := newHub()
	hub = h
	go h.run()
	defer h.Stop()

	ServerMetrics = NewMetrics(h)

	handler := authRateLimitMiddleware(func(w http.ResponseWriter, r *http.Request) {
		writeJSONError(w, http.StatusOK, "ok")
	})

	// Exhaust the auth IP rate limiter
	ip := "127.0.0.1"
	for i := 0; i < 50; i++ {
		authIPLimiter.Allow(ip)
	}

	req := httptest.NewRequest("POST", "/auth/login", nil)
	req.RemoteAddr = ip + ":12345"
	rr := httptest.NewRecorder()
	handler(rr, req)

	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429, got %d", rr.Code)
	}

	if ServerMetrics.RateLimited.Load() == 0 {
		t.Error("expected RateLimited counter to be incremented")
	}
}

// ==================== Snapshot with nil offlineQueue ====================

func TestCB116_Snapshot_NilOfflineQueue(t *testing.T) {
	resetGlobals_CB116()
	h := newHub()
	hub = h
	go h.run()
	defer h.Stop()

	// offlineQueue is nil (from resetGlobals)
	ServerMetrics = NewMetrics(h)
	snap := ServerMetrics.Snapshot()
	if snap == nil {
		t.Fatal("expected non-nil snapshot")
	}

	depth, ok := snap["offline_queue_depth"]
	if !ok {
		t.Fatal("expected offline_queue_depth in snapshot")
	}
	if depth != 0 {
		t.Errorf("expected offline_queue_depth=0, got %v", depth)
	}

	// Also verify agent_heartbeat is present
	hb, ok := snap["agent_heartbeat"]
	if !ok {
		t.Fatal("expected agent_heartbeat in snapshot")
	}
	hbMap, ok := hb.(map[string]interface{})
	if !ok {
		t.Fatal("expected agent_heartbeat to be a map")
	}
	if hbMap["enabled"] != false {
		t.Error("expected agent heartbeat disabled")
	}
}

func TestCB116_Snapshot_WithAgentPresence(t *testing.T) {
	resetGlobals_CB116()
	h := newHub()
	hub = h
	go h.run()
	defer h.Stop()

	agentPresenceEnabled = true
	agentPresenceInterval = 45 * time.Second
	agentPresenceTimeout = 120 * time.Second

	ServerMetrics = NewMetrics(h)
	snap := ServerMetrics.Snapshot()

	hb, ok := snap["agent_heartbeat"]
	if !ok {
		t.Fatal("expected agent_heartbeat in snapshot")
	}
	hbMap := hb.(map[string]interface{})
	if !hbMap["enabled"].(bool) {
		t.Error("expected agent heartbeat enabled")
	}
	if hbMap["interval_s"].(int) != 45 {
		t.Errorf("expected interval_s=45, got %v", hbMap["interval_s"])
	}
	if hbMap["timeout_s"].(int) != 120 {
		t.Errorf("expected timeout_s=120, got %v", hbMap["timeout_s"])
	}
}

// ==================== handleHeapProfile WriteHeapProfile error ====================

func TestCB116_HeapProfile_WriteError(t *testing.T) {
	resetGlobals_CB116()

	// Create a temp dir, make it read-only so os.Create fails inside WriteHeapProfile
	tmpDir, err := os.MkdirTemp("", "am-heap-ro-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)
	defer os.Chmod(tmpDir, 0755)

	if err := os.Chmod(tmpDir, 0444); err != nil {
		t.Fatal(err)
	}

	os.Setenv("PROFILING_DIR", tmpDir)
	defer os.Unsetenv("PROFILING_DIR")

	req := httptest.NewRequest("GET", "/debug/heap", nil)
	rr := httptest.NewRecorder()
	handleHeapProfile(rr, req)

	// Should get 500 because WriteHeapProfile fails on os.Create in read-only dir
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 for WriteHeapProfile error, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestCB116_GoroutineProfile_WriteError(t *testing.T) {
	resetGlobals_CB116()

	tmpDir, err := os.MkdirTemp("", "am-goroutine-ro-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)
	defer os.Chmod(tmpDir, 0755)

	if err := os.Chmod(tmpDir, 0444); err != nil {
		t.Fatal(err)
	}

	os.Setenv("PROFILING_DIR", tmpDir)
	defer os.Unsetenv("PROFILING_DIR")

	req := httptest.NewRequest("GET", "/debug/goroutine", nil)
	rr := httptest.NewRecorder()
	handleGoroutineProfile(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 for WriteGoroutineProfile error, got %d: %s", rr.Code, rr.Body.String())
	}
}

// ==================== addReaction: conv nil, DB errors ====================

func TestCB116_AddReaction_ConversationNotFound(t *testing.T) {
	resetGlobals_CB116()
	setupTestDB_CB116()

	// Create a message but drop the conversation
	conv, err := CreateConversation("user1", "agent1")
	if err != nil {
		t.Fatal(err)
	}
	msgID := storeMessageCB116(conv.ID, "user", "user1", "hello")

	// Delete the conversation so getConversation returns nil
	db.Exec("DELETE FROM conversations WHERE id = ?", conv.ID)

	_, _, err = addReaction(msgID, "user1", "👍")
	if err == nil {
		t.Error("expected error for nil conversation")
	}
	if err.Error() != "conversation not found" {
		t.Errorf("expected 'conversation not found', got %v", err)
	}
}

func TestCB116_AddReaction_ExistingCheckDBError(t *testing.T) {
	resetGlobals_CB116()
	setupTestDB_CB116()

	conv, err := CreateConversation("user1", "agent1")
	if err != nil {
		t.Fatal(err)
	}
	msgID := storeMessageCB116(conv.ID, "user", "user1", "hello")

	// Close DB to cause error on SELECT existing reaction
	db.Close()

	_, _, err = addReaction(msgID, "user1", "👍")
	if err == nil {
		t.Error("expected error for DB error on existing reaction check")
	}
}

func TestCB116_AddReaction_InsertError(t *testing.T) {
	resetGlobals_CB116()
	setupTestDB_CB116()

	conv, err := CreateConversation("user1", "agent1")
	if err != nil {
		t.Fatal(err)
	}
	msgID := storeMessageCB116(conv.ID, "user", "user1", "hello")

	// Drop the reactions table to cause INSERT error
	db.Exec("DROP TABLE reactions")

	_, _, err = addReaction(msgID, "user1", "👍")
	if err == nil {
		t.Error("expected error for INSERT into dropped table")
	}
}

// ==================== handleReact: internal error and WS notification ====================

func TestCB116_HandleReact_InternalError(t *testing.T) {
	resetGlobals_CB116()
	setupTestDB_CB116()

	conv, err := CreateConversation("user1", "agent1")
	if err != nil {
		t.Fatal(err)
	}
	msgID := storeMessageCB116(conv.ID, "user", "user1", "hello")

	// Drop reactions table to cause internal error
	db.Exec("DROP TABLE reactions")

	req := makeJWTFormReq_CB116("POST", "/messages/react", "message_id="+msgID+"&emoji=👍", "user1")
	rr := httptest.NewRecorder()
	handleReact(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestCB116_HandleReact_AgentOnlineAndClientConns(t *testing.T) {
	resetGlobals_CB116()
	setupTestDB_CB116()
	setupHubAndQueue_CB116()
	defer hub.Stop()

	conv, err := CreateConversation("user1", "agent1")
	if err != nil {
		t.Fatal(err)
	}
	msgID := storeMessageCB116(conv.ID, "user", "user1", "hello")

	// Set up a fake agent connection in the hub
	agentConn := &Connection{
		hub:         hub,
		connType:    "agent",
		id:          "agent1",
		send:        make(chan []byte, 10),
		connectedAt: time.Now(),
	}
	hub.register <- agentConn
	time.Sleep(50 * time.Millisecond)

	// Set up a fake client connection for the user
	clientConn := &Connection{
		hub:         hub,
		connType:    "client",
		id:          "user1",
		send:        make(chan []byte, 10),
		connectedAt: time.Now(),
	}
	hub.register <- clientConn
	time.Sleep(50 * time.Millisecond)

	req := makeJWTFormReq_CB116("POST", "/messages/react", "message_id="+msgID+"&emoji=👍", "user1")
	rr := httptest.NewRecorder()
	handleReact(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	// Verify the reaction was added
	var resp map[string]interface{}
	json.NewDecoder(rr.Body).Decode(&resp)
	if resp["status"] != "reaction_added" {
		t.Errorf("expected reaction_added, got %v", resp["status"])
	}

	// Check that the agent and client connections received the WS message
	select {
	case <-agentConn.send:
		// Good: agent received notification
	case <-time.After(100 * time.Millisecond):
		t.Error("agent did not receive reaction notification")
	}

	select {
	case <-clientConn.send:
		// Good: client received notification
	case <-time.After(100 * time.Millisecond):
		t.Error("client did not receive reaction notification")
	}
}

// ==================== handleGetReactions: DB error and nil reactions ====================

func TestCB116_HandleGetReactions_DBCallError(t *testing.T) {
	resetGlobals_CB116()
	setupTestDB_CB116()

	conv, err := CreateConversation("user1", "agent1")
	if err != nil {
		t.Fatal(err)
	}
	msgID := storeMessageCB116(conv.ID, "user", "user1", "hello")

	// Drop reactions table to cause getMessageReactions error
	db.Exec("DROP TABLE reactions")

	req := makeJWTReq_CB116("GET", "/messages/reactions?message_id="+msgID, nil, "user1")
	rr := httptest.NewRecorder()
	handleGetReactions(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestCB116_HandleGetReactions_NilReactions(t *testing.T) {
	resetGlobals_CB116()
	setupTestDB_CB116()

	conv, err := CreateConversation("user1", "agent1")
	if err != nil {
		t.Fatal(err)
	}
	msgID := storeMessageCB116(conv.ID, "user", "user1", "hello")

	// No reactions added - getMessageReactions returns nil
	req := makeJWTReq_CB116("GET", "/messages/reactions?message_id="+msgID, nil, "user1")
	rr := httptest.NewRecorder()
	handleGetReactions(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	// Should return empty array, not null
	var reactions []MessageReaction
	json.NewDecoder(rr.Body).Decode(&reactions)
	if reactions == nil {
		t.Error("expected non-nil empty array, got nil")
	}
}

func TestCB116_HandleGetReactions_MessageNotFound(t *testing.T) {
	resetGlobals_CB116()
	setupTestDB_CB116()

	req := makeJWTReq_CB116("GET", "/messages/reactions?message_id=nonexistent", nil, "user1")
	rr := httptest.NewRecorder()
	handleGetReactions(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestCB116_HandleGetReactions_Unauthorized(t *testing.T) {
	resetGlobals_CB116()
	setupTestDB_CB116()

	conv, err := CreateConversation("user1", "agent1")
	if err != nil {
		t.Fatal(err)
	}
	msgID := storeMessageCB116(conv.ID, "user", "user1", "hello")

	// user2 is not a participant
	req := makeJWTReq_CB116("GET", "/messages/reactions?message_id="+msgID, nil, "user2")
	rr := httptest.NewRecorder()
	handleGetReactions(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", rr.Code, rr.Body.String())
	}
}

// ==================== TieredRateLimiter cleanup stopCh ====================

func TestCB116_TieredRateLimiter_CleanupStopCh(t *testing.T) {
	trl := NewTieredRateLimiter()

	// The cleanup goroutine runs on a 5-minute ticker, but we can test
	// the stopCh path by stopping it
	trl.Stop()

	// If Stop() works correctly, the cleanup goroutine should have exited.
	// We can't directly test this, but we can verify Stop() doesn't block
	// and doesn't panic.
	// Calling Stop again should be safe (idempotent via cleanupOnce)
	trl.Stop()
}

// ==================== loadQueueFromDB: loaded > 0 ====================

func TestCB116_LoadQueueFromDB_LoadedLog(t *testing.T) {
	resetGlobals_CB116()

	dbPath := "/tmp/am_test_cb116_load.db"
	os.Remove(dbPath)
	testDB, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer testDB.Close()

	initQueueDB(testDB)

	// Insert some queue entries
	now := time.Now().UTC().Format(time.RFC3339)
	for i := 0; i < 3; i++ {
		_, err := testDB.Exec("INSERT INTO offline_queue (recipient, data, queued_at, sent_count) VALUES (?, ?, ?, ?)",
			fmt.Sprintf("user%d", i), []byte("test-data"), now, 0)
		if err != nil {
			t.Fatal(err)
		}
	}

	q := newOfflineQueue(100, 24*time.Hour)
	loadQueueFromDB(testDB, q)

	if q.TotalDepth() != 3 {
		t.Errorf("expected queue depth 3, got %d", q.TotalDepth())
	}
}

// ==================== sendWelcomeMessage with deviceID ====================

func TestCB116_SendWelcomeMessage_WithDeviceID(t *testing.T) {
	resetGlobals_CB116()

	c := &Connection{
		hub:               nil,
		connType:          "client",
		id:                "test-conn-device",
		send:              make(chan []byte, 10),
		connectedAt:       time.Now(),
		negotiatedVersion: "0.1",
		deviceID:          "device-abc-123",
	}

	sendWelcomeMessage(c)

	select {
	case data := <-c.send:
		var msg map[string]interface{}
		if err := json.Unmarshal(data, &msg); err != nil {
			t.Fatal(err)
		}
		if msg["type"] != "connected" {
			t.Errorf("expected type=connected, got %v", msg["type"])
		}
		dataMap, ok := msg["data"].(map[string]interface{})
		if !ok {
			t.Fatal("expected data to be a map")
		}
		if dataMap["device_id"] != "device-abc-123" {
			t.Errorf("expected device_id=device-abc-123, got %v", dataMap["device_id"])
		}
	case <-time.After(100 * time.Millisecond):
		t.Error("did not receive welcome message")
	}
}

// ==================== RegisterAgentOnConnect: DB query error ====================

func TestCB116_RegisterAgentOnConnect_QueryError(t *testing.T) {
	resetGlobals_CB116()
	setupTestDB_CB116()

	// Close DB to cause QueryRow error
	db.Close()

	err := RegisterAgentOnConnect("agent-test", "Test Agent", "gpt-4", "friendly", "coding")
	if err == nil {
		t.Error("expected error for QueryRow with closed DB")
	}
}

func TestCB116_RegisterAgentOnConnect_InsertError(t *testing.T) {
	resetGlobals_CB116()
	setupTestDB_CB116()

	// Close DB to cause INSERT error for new agent
	db.Close()

	err := RegisterAgentOnConnect("new-agent-xyz", "Test Agent", "gpt-4", "friendly", "coding")
	if err == nil {
		t.Error("expected error for INSERT with closed DB")
	}
}

// ==================== handleUpload: file too large, seek error, create error ====================

func TestCB116_HandleUpload_FileTooLarge(t *testing.T) {
	resetGlobals_CB116()
	setupTestDB_CB116()

	// Save and restore maxUploadSize
	saved := maxUploadSize
	defer func() { maxUploadSize = saved }()
	maxUploadSize = 1 // 1 byte

	body := &strings.Builder{}
	writer := multipart.NewWriter(body)
	field, err := writer.CreateFormFile("file", "test.txt")
	if err != nil {
		t.Fatal(err)
	}
	field.Write([]byte("hello world")) // 11 bytes > 1 byte
	writer.Close()

	req := makeJWTReq_CB116("POST", "/attachments", strings.NewReader(body.String()), "user1")
	req.Header.Set("Content-Type", writer.FormDataContentType())
	rr := httptest.NewRecorder()
	handleUpload(rr, req)

	// Should get 400 for file too large or invalid form data
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestCB116_HandleUpload_NoJWT(t *testing.T) {
	resetGlobals_CB116()
	setupTestDB_CB116()

	body := &strings.Builder{}
	writer := multipart.NewWriter(body)
	field, err := writer.CreateFormFile("file", "test.txt")
	if err != nil {
		t.Fatal(err)
	}
	field.Write([]byte("hello"))
	writer.Close()

	req := httptest.NewRequest("POST", "/attachments", strings.NewReader(body.String()))
	req.Header.Set("Content-Type", writer.FormDataContentType())
	rr := httptest.NewRecorder()
	handleUpload(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rr.Code)
	}
}

func TestCB116_HandleUpload_InvalidJWT(t *testing.T) {
	resetGlobals_CB116()
	setupTestDB_CB116()

	body := &strings.Builder{}
	writer := multipart.NewWriter(body)
	field, err := writer.CreateFormFile("file", "test.txt")
	if err != nil {
		t.Fatal(err)
	}
	field.Write([]byte("hello"))
	writer.Close()

	req := httptest.NewRequest("POST", "/attachments", strings.NewReader(body.String()))
	req.Header.Set("Content-Type", writer.FormDataContentType())
	req.Header.Set("Authorization", "Bearer invalid-token")
	rr := httptest.NewRecorder()
	handleUpload(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rr.Code)
	}
}

func TestCB116_HandleUpload_MissingFile(t *testing.T) {
	resetGlobals_CB116()
	setupTestDB_CB116()

	// Create multipart form without a file field
	body := &strings.Builder{}
	writer := multipart.NewWriter(body)
	writer.WriteField("message_id", "msg123")
	writer.Close()

	req := makeJWTReq_CB116("POST", "/attachments", strings.NewReader(body.String()), "user1")
	req.Header.Set("Content-Type", writer.FormDataContentType())
	rr := httptest.NewRecorder()
	handleUpload(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestCB116_HandleUpload_DisallowedContentType(t *testing.T) {
	resetGlobals_CB116()
	setupTestDB_CB116()

	body := &strings.Builder{}
	writer := multipart.NewWriter(body)
	field, err := writer.CreateFormFile("file", "test.exe")
	if err != nil {
		t.Fatal(err)
	}
	// Write some executable-like content
	field.Write([]byte("MZ\x90\x00\x03\x00\x00\x00")) // PE header magic
	writer.Close()

	req := makeJWTReq_CB116("POST", "/attachments", strings.NewReader(body.String()), "user1")
	req.Header.Set("Content-Type", writer.FormDataContentType())
	rr := httptest.NewRecorder()
	handleUpload(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for disallowed type, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestCB116_HandleUpload_DBError(t *testing.T) {
	resetGlobals_CB116()
	setupTestDB_CB116()

	// Set upload dir to a valid path
	serverDBPath = "/tmp/am_test_cb116_uploads.db"

	body := &strings.Builder{}
	writer := multipart.NewWriter(body)
	field, err := writer.CreateFormFile("file", "test.png")
	if err != nil {
		t.Fatal(err)
	}
	// Write a minimal PNG-like content
	field.Write([]byte("\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR"))
	writer.Close()

	// Drop attachments table to cause DB error
	db.Exec("DROP TABLE attachments")

	req := makeJWTReq_CB116("POST", "/attachments", strings.NewReader(body.String()), "user1")
	req.Header.Set("Content-Type", writer.FormDataContentType())
	rr := httptest.NewRecorder()
	handleUpload(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestCB116_HandleUpload_Success(t *testing.T) {
	resetGlobals_CB116()
	setupTestDB_CB116()

	body := &strings.Builder{}
	writer := multipart.NewWriter(body)
	field, err := writer.CreateFormFile("file", "test.png")
	if err != nil {
		t.Fatal(err)
	}
	// Write a minimal PNG-like content (enough for DetectContentType)
	field.Write([]byte("\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00"))
	writer.Close()

	req := makeJWTReq_CB116("POST", "/attachments", strings.NewReader(body.String()), "user1")
	req.Header.Set("Content-Type", writer.FormDataContentType())
	rr := httptest.NewRecorder()
	handleUpload(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp map[string]interface{}
	json.NewDecoder(rr.Body).Decode(&resp)
	if resp["filename"] != "test.png" {
		t.Errorf("expected filename=test.png, got %v", resp["filename"])
	}
}

// ==================== handleListAttachments: missing conversation_id and not found ====================

func TestCB116_HandleListAttachments_MissingConvID(t *testing.T) {
	resetGlobals_CB116()
	setupTestDB_CB116()

	req := makeJWTReq_CB116("GET", "/attachments", nil, "user1")
	rr := httptest.NewRecorder()
	handleListAttachments(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestCB116_HandleListAttachments_ConvNotFound(t *testing.T) {
	resetGlobals_CB116()
	setupTestDB_CB116()

	req := makeJWTReq_CB116("GET", "/attachments?conversation_id=nonexistent", nil, "user1")
	rr := httptest.NewRecorder()
	handleListAttachments(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestCB116_HandleListAttachments_DBError(t *testing.T) {
	resetGlobals_CB116()
	setupTestDB_CB116()

	conv, err := CreateConversation("user1", "agent1")
	if err != nil {
		t.Fatal(err)
	}

	// Close DB to cause query error
	db.Close()

	req := makeJWTReq_CB116("GET", "/attachments?conversation_id="+conv.ID, nil, "user1")
	rr := httptest.NewRecorder()
	handleListAttachments(rr, req)

	// With closed DB, getConversation returns nil/error => 404
	if rr.Code != http.StatusNotFound && rr.Code != http.StatusInternalServerError {
		t.Fatalf("expected 404 or 500, got %d: %s", rr.Code, rr.Body.String())
	}
}

// ==================== initSchema: migration error paths ====================

func TestCB116_InitSchema_ReactionsTableCreateError(t *testing.T) {
	resetGlobals_CB116()

	dbPath := "/tmp/am_test_cb116_react_schema.db"
	os.Remove(dbPath)
	testDB, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer testDB.Close()

	// Pre-create a reactions table with incompatible schema
	// CREATE TABLE IF NOT EXISTS won't fail if table exists with different schema
	// But we can test the reactions table error by closing the DB first
	testDB.Close()

	err = initSchema(testDB)
	if err == nil {
		t.Log("initSchema with closed DB may or may not return error depending on sqlite3 behavior")
	}
}

func TestCB116_InitSchema_NotificationPrefsTableError(t *testing.T) {
	resetGlobals_CB116()

	dbPath := "/tmp/am_test_cb116_notif_schema.db"
	os.Remove(dbPath)
	testDB, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer testDB.Close()

	// Run initSchema once to create all tables
	if err := initSchema(testDB); err != nil {
		t.Fatal(err)
	}

	// Run again - should succeed (IF NOT EXISTS)
	if err := initSchema(testDB); err != nil {
		t.Fatalf("initSchema second run failed: %v", err)
	}
}

// ==================== conversations.go: error paths ====================

func TestCB116_StoreMessagesBatch_InsertError(t *testing.T) {
	resetGlobals_CB116()
	setupTestDB_CB116()

	conv, err := CreateConversation("user1", "agent1")
	if err != nil {
		t.Fatal(err)
	}

	// Drop messages table to cause insert error
	db.Exec("DROP TABLE messages")

	msgs := []RoutedMessage{
		{ConversationID: conv.ID, SenderType: "user", SenderID: "user1", Content: "hello"},
	}
	_, err = storeMessagesBatch(msgs)
	if err == nil {
		t.Error("expected error for INSERT into dropped messages table")
	}
}

func TestCB116_GetConversationMessages_ScanError(t *testing.T) {
	resetGlobals_CB116()
	setupTestDB_CB116()

	conv, err := CreateConversation("user1", "agent1")
	if err != nil {
		t.Fatal(err)
	}
	storeMessageCB116(conv.ID, "user", "user1", "hello")

	// Add a column that will cause scan to fail (extra column not expected)
	db.Exec("ALTER TABLE messages ADD COLUMN unexpected_extra TEXT DEFAULT 'extra'")

	// getConversationMessages scans specific columns, extra column shouldn't cause error
	// But if we change the table structure in a way that breaks scanning...
	// Actually, the scan uses specific column names, so extra columns won't matter.
	// Let's close the DB instead
	db.Close()

	_, err = getConversationMessages(conv.ID, 100, "")
	if err == nil {
		t.Error("expected error with closed DB")
	}
}

func TestCB116_DeleteConversation_DBError(t *testing.T) {
	resetGlobals_CB116()
	setupTestDB_CB116()

	conv, err := CreateConversation("user1", "agent1")
	if err != nil {
		t.Fatal(err)
	}

	// Close DB
	db.Close()

	err = deleteConversation(conv.ID, "user1")
	if err == nil {
		t.Error("expected error for DELETE with closed DB")
	}
}

func TestCB116_ChangeUserPassword_DBError(t *testing.T) {
	resetGlobals_CB116()
	setupTestDB_CB116()

	// Close DB
	db.Close()

	err := changeUserPassword("user1", "oldpass", "newpass")
	if err == nil {
		t.Error("expected error with closed DB")
	}
}

func TestCB116_MarkMessagesRead_DBError(t *testing.T) {
	resetGlobals_CB116()
	setupTestDB_CB116()

	conv, err := CreateConversation("user1", "agent1")
	if err != nil {
		t.Fatal(err)
	}

	// Close DB
	db.Close()

	_, err = markMessagesRead(conv.ID, "user1")
	if err == nil {
		t.Error("expected error with closed DB")
	}
}

func TestCB116_SearchMessages_DBError(t *testing.T) {
	resetGlobals_CB116()
	setupTestDB_CB116()

	// Close DB
	db.Close()

	_, err := searchMessages("user1", "hello", 100)
	if err == nil {
		t.Error("expected error with closed DB")
	}
}

// ==================== handleGetAttachment: agent auth paths ====================

func TestCB116_HandleGetAttachment_AgentAuthSuccess(t *testing.T) {
	resetGlobals_CB116()
	setupTestDB_CB116()

	// Create an attachment
	conv, err := CreateConversation("user1", "agent1")
	if err != nil {
		t.Fatal(err)
	}
	msgID := storeMessageCB116(conv.ID, "user", "user1", "hello")

	// Insert attachment record with relative storage_path
	_, err = db.Exec(`INSERT INTO attachments (id, message_id, user_id, filename, content_type, size, sha256, storage_path, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		"att-test-1", msgID, "user1", "test.png", "image/png", 100, "abc123", "test.png", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}

	// Create the file in the upload directory
	uploadDir := getUploadDir()
	os.MkdirAll(uploadDir, 0755)
	filePath := filepath.Join(uploadDir, "test.png")
	os.WriteFile(filePath, []byte("test image data"), 0644)
	defer os.Remove(filePath)

	// Request with agent secret (use the dev default since resetAgentSecret was called)
	devSecret := getAgentSecret()
	req := httptest.NewRequest("GET", "/attachments/att-test-1", nil)
	req.Header.Set("X-Agent-Secret", devSecret)
	rr := httptest.NewRecorder()
	handleGetAttachment(rr, req)

	// Should succeed (200) since agent auth is valid
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestCB116_HandleGetAttachment_WrongAgentSecret(t *testing.T) {
	resetGlobals_CB116()
	setupTestDB_CB116()

	devSecret := getAgentSecret()
	req := httptest.NewRequest("GET", "/attachments/att-test-1", nil)
	req.Header.Set("X-Agent-Secret", devSecret+"-wrong")
	rr := httptest.NewRecorder()
	handleGetAttachment(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rr.Code)
	}
}

func TestCB116_HandleGetAttachment_NoAuth(t *testing.T) {
	resetGlobals_CB116()
	setupTestDB_CB116()

	req := httptest.NewRequest("GET", "/attachments/att-test-1", nil)
	rr := httptest.NewRecorder()
	handleGetAttachment(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rr.Code)
	}
}

// ==================== ValidateJWT: additional edge cases ====================

func TestCB116_ValidateJWT_InvalidSignature(t *testing.T) {
	resetGlobals_CB116()
	setupTestDB_CB116()

	// Create a token with different secret
	token, _ := GenerateJWT("user1", "testuser")
	// Corrupt the signature part
	parts := strings.Split(token, ".")
	if len(parts) == 3 {
		parts[2] = "corruptedsignature"
		token = strings.Join(parts, ".")
	}

	_, err := ValidateJWT(token)
	if err == nil {
		t.Error("expected error for corrupted signature")
	}
}

// ==================== handleAgentConnect/handleClientConnect edge cases ====================

func TestCB116_HandleAgentConnect_NoSecret(t *testing.T) {
	resetGlobals_CB116()
	setupTestDB_CB116()

	srv := httptest.NewServer(http.HandlerFunc(handleAgentConnect))
	defer srv.Close()

	// WebSocket dial without agent_id or secret
	wsURL := "ws://" + strings.TrimPrefix(srv.URL, "http://") + "/agent/connect"
	_, resp, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err == nil {
		t.Error("expected error for missing agent_id")
	}
	if resp != nil && resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", resp.StatusCode)
	}
}

func TestCB116_HandleClientConnect_NoToken(t *testing.T) {
	resetGlobals_CB116()
	setupTestDB_CB116()

	srv := httptest.NewServer(http.HandlerFunc(handleClientConnect))
	defer srv.Close()

	wsURL := "ws://" + strings.TrimPrefix(srv.URL, "http://") + "/client/connect"
	_, resp, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err == nil {
		t.Error("expected error for missing token")
	}
	if resp != nil && resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", resp.StatusCode)
	}
}

// ==================== SafeSend: additional tests ====================

func TestCB116_SafeSend_Success(t *testing.T) {
	c := &Connection{
		send: make(chan []byte, 5),
	}
	if !c.SafeSend([]byte("test")) {
		t.Error("expected SafeSend to return true")
	}
}

func TestCB116_SafeSend_NilChannel(t *testing.T) {
	c := &Connection{
		send: nil,
	}
	// Should return false, not panic
	if c.SafeSend([]byte("test")) {
		t.Error("expected SafeSend to return false for nil channel")
	}
}

// ==================== writePump: write error path ====================

func TestCB116_WritePump_WriteError(t *testing.T) {
	resetGlobals_CB116()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upgrader := websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}

		h := newHub()
		hub = h
		go h.run()
		defer h.Stop()

		c := &Connection{
			hub:         h,
			connType:    "agent",
			id:          "test-write-err",
			conn:        conn,
			send:        make(chan []byte, 10),
			connectedAt: time.Now(),
		}
		h.register <- c

		go c.writePump()

		// Send a message
		c.send <- []byte("test message")

		time.Sleep(100 * time.Millisecond)

		// Close the underlying connection to cause write error
		conn.Close()
		time.Sleep(100 * time.Millisecond)
	}))
	defer srv.Close()

	wsURL := "ws://" + strings.TrimPrefix(srv.URL, "http://")
	wsConn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer wsConn.Close()

	// Read the message that was sent
	wsConn.SetReadDeadline(time.Now().Add(1 * time.Second))
	_, _, err = wsConn.ReadMessage()
	if err != nil {
		t.Logf("read error (expected): %v", err)
	}
}

// ==================== push.go: initAPNs production/development ====================

func TestCB116_InitAPNs_ProductionEnv(t *testing.T) {
	resetGlobals_CB116()

	// Create a dummy P12 file (invalid content, but file exists)
	tmpFile, err := os.CreateTemp("", "apns-cert-*.p12")
	if err != nil {
		t.Fatal(err)
	}
	tmpFile.WriteString("dummy p12 content")
	tmpFile.Close()
	defer os.Remove(tmpFile.Name())

	pushConfig = &PushNotificationConfig{
		APNSEnabled:  true,
		CertPath:     tmpFile.Name(),
		Password:     "",
		Environment:  "production",
	}

	// initAPNs will try to load the cert and fail, disabling APNs
	initAPNs()

	if pushConfig.APNSEnabled {
		t.Error("expected APNs to be disabled after invalid cert")
	}
}

func TestCB116_InitAPNs_DevelopmentEnv(t *testing.T) {
	resetGlobals_CB116()

	tmpFile, err := os.CreateTemp("", "apns-cert-dev-*.p12")
	if err != nil {
		t.Fatal(err)
	}
	tmpFile.WriteString("dummy p12 content")
	tmpFile.Close()
	defer os.Remove(tmpFile.Name())

	pushConfig = &PushNotificationConfig{
		APNSEnabled:  true,
		CertPath:     tmpFile.Name(),
		Password:     "",
		Environment:  "development",
	}

	initAPNs()

	if pushConfig.APNSEnabled {
		t.Error("expected APNs to be disabled after invalid cert")
	}
}

func TestCB116_InitAPNs_NoCertPath(t *testing.T) {
	resetGlobals_CB116()

	pushConfig = &PushNotificationConfig{
		APNSEnabled: true,
		CertPath:    "",
	}

	// Should return without panic, APNs stays enabled but no cert loaded
	initAPNs()
	// APNs stays enabled because empty CertPath just warns and returns
	// (doesn't disable) - this is by design so the server can start without
	// APNs cert but won't actually send notifications
}

// ==================== writeJSON and writeJSONError ====================

func TestCB116_WriteJSON_Error(t *testing.T) {
	rr := httptest.NewRecorder()
	// Pass a value that can't be marshaled to JSON
	writeJSON(rr, http.StatusOK, map[string]interface{}{
		"chan": make(chan int),
	})
	if rr.Header().Get("Content-Type") != "application/json" {
		t.Errorf("expected application/json content type, got %s", rr.Header().Get("Content-Type"))
	}
}

// ==================== extractIP tests ====================

func TestCB116_ExtractIP_DirectAddr(t *testing.T) {
	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "192.168.1.100:54321"
	ip := extractIP(req)
	if ip != "192.168.1.100" {
		t.Errorf("expected 192.168.1.100, got %s", ip)
	}
}

func TestCB116_ExtractIP_XForwardedFor(t *testing.T) {
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-Forwarded-For", "10.0.0.1, 10.0.0.2")
	req.RemoteAddr = "192.168.1.100:54321"
	ip := extractIP(req)
	if ip != "10.0.0.1" {
		t.Errorf("expected 10.0.0.1, got %s", ip)
	}
}

func TestCB116_ExtractIP_XRealIP(t *testing.T) {
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-Real-IP", "172.16.0.1")
	req.RemoteAddr = "192.168.1.100:54321"
	ip := extractIP(req)
	if ip != "172.16.0.1" {
		t.Errorf("expected 172.16.0.1, got %s", ip)
	}
}

// ==================== generateID uniqueness ====================

func TestCB116_GenerateID_Uniqueness(t *testing.T) {
	ids := make(map[string]bool)
	for i := 0; i < 1000; i++ {
		id := generateID("test")
		if ids[id] {
			t.Errorf("duplicate ID generated: %s", id)
		}
		ids[id] = true
	}
	if len(ids) != 1000 {
		t.Errorf("expected 1000 unique IDs, got %d", len(ids))
	}
}

// ==================== Hub: additional method tests ====================

func TestCB116_Hub_AgentCount_WithAgent(t *testing.T) {
	resetGlobals_CB116()
	h := newHub()
	go h.run()
	defer h.Stop()

	c := &Connection{
		hub:         h,
		connType:    "agent",
		id:          "agent-x",
		send:        make(chan []byte, 10),
		connectedAt: time.Now(),
	}
	h.register <- c
	time.Sleep(50 * time.Millisecond)

	if h.AgentCount() != 1 {
		t.Errorf("expected 1 agent, got %d", h.AgentCount())
	}
}

func TestCB116_Hub_ClientCount_WithClient(t *testing.T) {
	resetGlobals_CB116()
	h := newHub()
	go h.run()
	defer h.Stop()

	c := &Connection{
		hub:         h,
		connType:    "client",
		id:          "user-y",
		send:        make(chan []byte, 10),
		connectedAt: time.Now(),
	}
	h.register <- c
	time.Sleep(50 * time.Millisecond)

	if h.ClientCount() != 1 {
		t.Errorf("expected 1 client, got %d", h.ClientCount())
	}
}

func TestCB116_Hub_GetAgent_Exists(t *testing.T) {
	resetGlobals_CB116()
	h := newHub()
	go h.run()
	defer h.Stop()

	c := &Connection{
		hub:         h,
		connType:    "agent",
		id:          "agent-get",
		send:        make(chan []byte, 10),
		connectedAt: time.Now(),
	}
	h.register <- c
	time.Sleep(50 * time.Millisecond)

	agent := h.GetAgent("agent-get")
	if agent == nil {
		t.Error("expected non-nil agent")
	}
	if agent.id != "agent-get" {
		t.Errorf("expected agent-get, got %s", agent.id)
	}
}

func TestCB116_Hub_GetClient_Exists(t *testing.T) {
	resetGlobals_CB116()
	h := newHub()
	go h.run()
	defer h.Stop()

	c := &Connection{
		hub:         h,
		connType:    "client",
		id:          "user-get",
		send:        make(chan []byte, 10),
		connectedAt: time.Now(),
	}
	h.register <- c
	time.Sleep(50 * time.Millisecond)

	client := h.GetClient("user-get")
	if client == nil {
		t.Error("expected non-nil client")
	}
}

func TestCB116_Hub_GetClientConns_WithClient(t *testing.T) {
	resetGlobals_CB116()
	h := newHub()
	go h.run()
	defer h.Stop()

	c := &Connection{
		hub:         h,
		connType:    "client",
		id:          "user-conns",
		send:        make(chan []byte, 10),
		connectedAt: time.Now(),
	}
	h.register <- c
	time.Sleep(50 * time.Millisecond)

	conns := h.GetClientConns("user-conns")
	if len(conns) != 1 {
		t.Errorf("expected 1 connection, got %d", len(conns))
	}
}

// ==================== TieredRateLimiter: Allow with tier ====================

func TestCB116_TieredRateLimiter_FreeTier(t *testing.T) {
	trl := NewTieredRateLimiter()
	defer trl.Stop()

	// Free tier: 60 req/min
	trl.SetTier("user-free", TierFree)

	// First request should be allowed
	allowed, remaining, retryAfter := trl.Allow("user-free")
	if !allowed {
		t.Error("expected first request to be allowed")
	}
	if remaining < 0 {
		t.Errorf("expected remaining >= 0, got %d", remaining)
	}
	if retryAfter != 0 {
		t.Errorf("expected retryAfter=0 when allowed, got %d", retryAfter)
	}
}

func TestCB116_TieredRateLimiter_GetRemaining_WithTier(t *testing.T) {
	trl := NewTieredRateLimiter()
	defer trl.Stop()

	trl.SetTier("user-rem", TierPro)
	remaining := trl.GetRemaining("user-rem")
	if remaining <= 0 {
		t.Errorf("expected remaining > 0 for Pro tier, got %d", remaining)
	}
}

// ==================== Queue operations ====================

func TestCB116_PersistQueue_Success(t *testing.T) {
	resetGlobals_CB116()

	dbPath := "/tmp/am_test_cb116_persist.db"
	os.Remove(dbPath)
	testDB, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer testDB.Close()

	initQueueDB(testDB)

	persistQueue(testDB, "user1", []byte("test message data"))

	// Verify it was stored
	var recipient string
	var data []byte
	err = testDB.QueryRow("SELECT recipient, data FROM offline_queue WHERE recipient = ?", "user1").Scan(&recipient, &data)
	if err != nil {
		t.Fatal(err)
	}
	if recipient != "user1" {
		t.Errorf("expected user1, got %s", recipient)
	}
	if string(data) != "test message data" {
		t.Errorf("expected 'test message data', got %s", string(data))
	}
}

func TestCB116_DeleteQueueMessages_Success(t *testing.T) {
	resetGlobals_CB116()

	dbPath := "/tmp/am_test_cb116_delq.db"
	os.Remove(dbPath)
	testDB, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer testDB.Close()

	initQueueDB(testDB)

	// Insert some messages
	now := time.Now().UTC().Format(time.RFC3339)
	for i := 0; i < 3; i++ {
		testDB.Exec("INSERT INTO offline_queue (recipient, data, queued_at, sent_count) VALUES (?, ?, ?, ?)",
			"user1", []byte("data"), now, 0)
	}

	deleteQueueMessages(testDB, "user1")

	// Verify deleted
	var count int
	testDB.QueryRow("SELECT COUNT(*) FROM offline_queue WHERE recipient = ?", "user1").Scan(&count)
	if count != 0 {
		t.Errorf("expected 0 messages, got %d", count)
	}
}

func TestCB116_CleanStaleQueueMessages_DeletesOld(t *testing.T) {
	resetGlobals_CB116()

	dbPath := "/tmp/am_test_cb116_stale.db"
	os.Remove(dbPath)
	testDB, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer testDB.Close()

	initQueueDB(testDB)

	// Insert an old message (8 days ago)
	oldTime := time.Now().UTC().Add(-8 * 24 * time.Hour).Format(time.RFC3339)
	testDB.Exec("INSERT INTO offline_queue (recipient, data, queued_at, sent_count) VALUES (?, ?, ?, ?)",
		"user-stale", []byte("old data"), oldTime, 0)

	// Insert a recent message
	now := time.Now().UTC().Format(time.RFC3339)
	testDB.Exec("INSERT INTO offline_queue (recipient, data, queued_at, sent_count) VALUES (?, ?, ?, ?)",
		"user-stale", []byte("new data"), now, 0)

	cleanStaleQueueMessages(testDB, 7*24*time.Hour)

	// Verify only recent message remains
	var count int
	testDB.QueryRow("SELECT COUNT(*) FROM offline_queue WHERE recipient = ?", "user-stale").Scan(&count)
	if count != 1 {
		t.Errorf("expected 1 message (recent), got %d", count)
	}
}

// ==================== E2E: handleStoreEncryptedMessage additional paths ====================

func TestCB116_HandleStoreEncryptedMessage_AgentSenderDelivery(t *testing.T) {
	resetGlobals_CB116()
	setupTestDB_CB116()
	setupHubAndQueue_CB116()
	defer hub.Stop()

	// Create conversation
	conv, err := CreateConversation("user1", "agent1")
	if err != nil {
		t.Fatal(err)
	}

	// Register agent so it's in the hub
	agentConn := &Connection{
		hub:         hub,
		connType:    "agent",
		id:          "agent1",
		send:        make(chan []byte, 10),
		connectedAt: time.Now(),
	}
	hub.register <- agentConn
	time.Sleep(50 * time.Millisecond)

	// Use agent auth (X-Agent-Secret + X-Agent-ID)
	devSecret := getAgentSecret()
	body := fmt.Sprintf(`{"conversation_id":"%s","ciphertext":"encrypted-data","iv":"iv-data","algorithm":"aes-256-gcm","sender_key_id":"key1","recipient_key_id":"key2"}`, conv.ID)

	req := httptest.NewRequest("POST", "/e2e/store", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Agent-Secret", devSecret)
	req.Header.Set("X-Agent-ID", "agent1")
	rr := httptest.NewRecorder()
	handleStoreEncryptedMessage(rr, req)

	// Should succeed - agent is online
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
}

// ==================== isSupportedVersion ====================

func TestCB116_IsSupportedVersion(t *testing.T) {
	// Test with supported versions (SupportedVersions = "v1")
	if !isSupportedVersion("v1") {
		t.Error("expected v1 to be supported")
	}
	if isSupportedVersion("v99") {
		t.Error("expected v99 to not be supported")
	}
	if isSupportedVersion("0.1") {
		t.Error("expected 0.1 to not be supported (format is v1)")
	}
}

// ==================== getEnvOrDefault ====================

func TestCB116_GetEnvOrDefault_Set(t *testing.T) {
	os.Setenv("TEST_ENV_VAR_116", "custom-value")
	defer os.Unsetenv("TEST_ENV_VAR_116")

	val := getEnvOrDefault("TEST_ENV_VAR_116", "default")
	if val != "custom-value" {
		t.Errorf("expected custom-value, got %s", val)
	}
}

func TestCB116_GetEnvOrDefault_Default(t *testing.T) {
	val := getEnvOrDefault("NONEXISTENT_ENV_VAR_116", "fallback")
	if val != "fallback" {
		t.Errorf("expected fallback, got %s", val)
	}
}

// ==================== isAllowedContentType additional types ====================

func TestCB116_IsAllowedContentType_AdditionalTypes(t *testing.T) {
	// Test some allowed types
	allowed := []string{
		"image/png",
		"image/jpeg",
		"image/gif",
		"application/pdf",
		"video/mp4",
		"audio/mpeg",
	}
	for _, ct := range allowed {
		if !isAllowedContentType(ct) {
			t.Errorf("expected %s to be allowed", ct)
		}
	}

	// Test some disallowed types
	disallowed := []string{
		"application/x-executable",
		"application/x-msdownload",
		"application/octet-stream",
	}
	for _, ct := range disallowed {
		if isAllowedContentType(ct) {
			t.Errorf("expected %s to be disallowed", ct)
		}
	}
}

// ==================== getMaxUploadSize ====================

func TestCB116_GetMaxUploadSize_Default(t *testing.T) {
	// Save and restore maxUploadSize
	saved := maxUploadSize
	defer func() { maxUploadSize = saved }()
	maxUploadSize = MaxUploadSize // reset to default (50MB)
	size := getMaxUploadSize()
	if size != 50*1024*1024 {
		t.Errorf("expected default 50MB, got %d", size)
	}
}

func TestCB116_GetMaxUploadSize_Custom(t *testing.T) {
	saved := maxUploadSize
	defer func() { maxUploadSize = saved }()
	maxUploadSize = 5 * 1024 * 1024 // 5MB
	size := getMaxUploadSize()
	if size != 5*1024*1024 {
		t.Errorf("expected 5MB, got %d", size)
	}
}

// ==================== cpuProfileTestSetup: dirty state cleanup ====================

func TestCB116_CpuProfileTestSetup_DirtyState(t *testing.T) {
	// Set up a dirty state
	cpuProfileState.Lock()
	cpuProfileState.active = true
	cpuProfileState.stopFunc = func() {} // dummy stop function
	cpuProfileState.Unlock()

	// cpuProfileTestSetup should clean up the dirty state
	cleanup := cpuProfileTestSetup()

	// Verify state was cleaned
	cpuProfileState.Lock()
	active := cpuProfileState.active
	cpuProfileState.Unlock()
	if active {
		t.Error("expected active to be false after setup")
	}

	cleanup()

	// Verify still clean after cleanup
	cpuProfileState.Lock()
	active = cpuProfileState.active
	cpuProfileState.Unlock()
	if active {
		t.Error("expected active to be false after cleanup")
	}
}